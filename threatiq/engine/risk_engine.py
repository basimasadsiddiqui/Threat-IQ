"""Deterministic risk scoring.

The LLM never picks the number. This module turns Evidence + Findings + asset
context into a 0-100 score through fixed, inspectable weights, and every factor
carries the rationale that produced it. Two identical inputs always score the
same, which is what makes the output defensible to an auditor.
"""
from __future__ import annotations

from dataclasses import dataclass

from threatiq.schemas import (
    Evidence, Finding, RiskAssessment, RiskFactor, Severity, ToolStatus, Verdict,
)

# Weights sum to 1.0. Raising one means lowering another, keep it explicit.
WEIGHTS: dict[str, float] = {
    "threat_intel_reputation": 0.24,   # what reputation feeds actually observed
    "exploitation_evidence": 0.20,     # KEV / active exploitation / live payload
    "finding_severity": 0.16,          # worst confirmed analyst finding
    "impersonation": 0.12,             # brand abuse / lookalike / spoofed sender
    "infrastructure": 0.10,            # domain age, hosting, redirect behaviour
    "exposure": 0.10,                  # internet reachable + asset criticality
    "corroboration": 0.08,             # how many independent sources agree
}

_CRITICALITY_VALUE = {"low": 0.25, "medium": 0.5, "high": 0.8, "critical": 1.0}


def _factor(name: str, weight_key: str, value: float, rationale: str,
            applicable: bool = True) -> RiskFactor:
    """Build a factor whose published numbers are self-consistent.

    Rounding `value` and `contribution` independently produced breakdowns where
    weight x value did not equal the stated contribution. Deriving the
    contribution from the rounded value keeps the arithmetic checkable by hand,
    which is the entire point of exposing the factors.
    """
    weight = WEIGHTS[weight_key]
    value = round(max(0.0, min(1.0, value)), 3)
    return RiskFactor(
        name=name, weight=weight, value=value,
        contribution=round(weight * value, 6),
        rationale=rationale, applicable=applicable,
    )

# Which evidence sources count as independent for corroboration purposes.
_INDEPENDENT_SOURCES = {
    "virustotal", "abuseipdb", "urlscan", "cisa_kev", "nvd",
    "rdap", "dns", "email", "lookalike", "http", "zap",
}


def _focus_indicators(findings: list[Finding]) -> set[str]:
    """Indicator keys that some agent has already raised a concern about."""
    return {
        key for f in findings
        for key in f.indicators
        if f.severity.rank >= Severity.MEDIUM.rank
    }


@dataclass
class RiskInput:
    evidence: list[Evidence]
    findings: list[Finding]
    asset_criticality: str = "medium"
    internet_exposed: bool = True


def _usable(evidence: list[Evidence]) -> list[Evidence]:
    """Skipped and failed lookups must not be read as 'nothing bad found'."""
    return [e for e in evidence if e.status in (ToolStatus.OK, ToolStatus.NOT_FOUND)]


_REPUTATION_SOURCES = ("virustotal", "abuseipdb", "urlscan")


def _reputation_factor(evidence: list[Evidence],
                       focus: set[str] | None = None) -> RiskFactor:
    """Worst credible reputation verdict, weighted by the source's confidence.

    Scoped to the indicators actually under suspicion when there are any. A
    clean verdict on some unrelated host that happened to appear in the input
    (a mail relay, a tracking domain) must not be read as exoneration of the
    indicator that other agents flagged.
    """
    if focus:
        scoped = [e for e in evidence if e.indicator in focus]
        if not any(e.source in _REPUTATION_SOURCES for e in scoped):
            # We have no reputation data about the thing we are actually
            # worried about. That is missing coverage, not a clean bill of
            # health, BEC in particular is sent from legitimate free-mail
            # infrastructure whose spotless reputation says nothing about the
            # message. Scoring it here would mask the attack.
            return _factor(
                "Threat intelligence reputation", "threat_intel_reputation", 0.0,
                "no reputation source covers the indicator under suspicion",
                applicable=False,
            )
        evidence = scoped
    best_value, rationale = 0.0, "no reputation data available"
    # A source that has simply never seen the indicator has not cleared it.
    # Requiring a real verdict here is what stops "unknown to VirusTotal" from
    # being scored as "VirusTotal says it is fine", the exact failure mode
    # that lets freshly registered phishing infrastructure look safe.
    answered = any(
        e.source in _REPUTATION_SOURCES and e.verdict != Verdict.UNKNOWN
        for e in evidence
    )
    for ev in evidence:
        if ev.source not in ("virustotal", "abuseipdb", "urlscan"):
            continue
        if ev.verdict == Verdict.MALICIOUS:
            value = 0.85 + 0.15 * ev.confidence
        elif ev.verdict == Verdict.SUSPICIOUS:
            value = 0.45 + 0.25 * ev.confidence
        elif ev.verdict == Verdict.BENIGN:
            value = 0.0
        else:
            continue
        if value > best_value:
            best_value = min(1.0, value)
            rationale = ev.summary[:200]

    if best_value == 0.0 and any(
        e.source in ("virustotal", "abuseipdb") and e.verdict == Verdict.BENIGN
        for e in evidence
    ):
        rationale = "reputation sources returned no detections"

    return _factor(
        "Threat intelligence reputation", "threat_intel_reputation", best_value,
        rationale if answered else
        "no reputation source was queried successfully "
        "(missing API key or lookup failure)",
        applicable=answered,
    )


def _exploitation_factor(evidence: list[Evidence]) -> RiskFactor:
    """KEV membership dominates; otherwise fall back to CVSS exploitability."""
    value, rationale = 0.0, "no evidence of active exploitation"
    # This dimension only means anything when a vulnerability is in scope.
    applicable = any(e.source in ("cisa_kev", "nvd") for e in evidence)
    for ev in evidence:
        if ev.source == "cisa_kev" and ev.signals.get("in_kev"):
            value = 1.0
            rationale = "listed in CISA KEV, confirmed exploited in the wild"
            if ev.signals.get("known_ransomware_use"):
                rationale += "; known ransomware campaign use"
            break
    else:
        for ev in evidence:
            if ev.source != "nvd":
                continue
            score = float(ev.signals.get("cvss_score", 0) or 0)
            if score <= 0:
                continue
            candidate = score / 10.0
            # Remotely reachable, unauthenticated, no-interaction bugs are the
            # ones that actually get mass-exploited.
            if ev.signals.get("network_exploitable"):
                candidate = min(1.0, candidate + 0.10)
            if ev.signals.get("no_privileges_required"):
                candidate = min(1.0, candidate + 0.05)
            if candidate > value:
                value = candidate
                rationale = (f"CVSS {score} with vector "
                             f"{ev.signals.get('cvss_vector', 'n/a')}")

    return _factor(
        "Exploitation evidence", "exploitation_evidence", value,
        rationale if applicable else
        "not applicable, no vulnerability in scope for this investigation",
        applicable=applicable,
    )


def _finding_factor(findings: list[Finding]) -> RiskFactor:
    if not findings:
        return _factor("Confirmed findings", "finding_severity", 0.0,
                       "no findings raised")
    worst = max(findings, key=lambda f: (f.severity.rank, f.confidence))
    # Scale by the finding's own confidence so a low-confidence critical does
    # not score the same as a confirmed one.
    base = worst.severity.rank / 4.0
    value = base * (0.6 + 0.4 * worst.confidence)
    return _factor(
        "Confirmed findings", "finding_severity", value,
        f"{len(findings)} finding(s); most severe: {worst.title} "
        f"({worst.severity.value}, confidence {worst.confidence:.0%})",
    )


def _impersonation_factor(evidence: list[Evidence]) -> RiskFactor:
    value, reasons = 0.0, []
    applicable = any(
        e.source in ("lookalike", "urlscan", "email") for e in evidence
    )
    for ev in evidence:
        if ev.source == "lookalike":
            score = float(ev.signals.get("score", 0) or 0)
            if score > value:
                value = score
            if ev.signals.get("matched_brand"):
                reasons.append(
                    f"impersonates {ev.signals['matched_brand']} via "
                    f"{str(ev.signals.get('technique', '')).replace('_', ' ')}"
                )
        elif ev.source == "urlscan" and ev.signals.get("brand_impersonation"):
            value = max(value, 0.9)
            reasons.append("urlscan.io detected brand impersonation")
        elif ev.source == "email":
            if ev.signals.get("display_name_spoof"):
                value = max(value, 0.7)
                reasons.append("sender display name is spoofed")
            if ev.signals.get("reply_to_mismatch"):
                value = max(value, 0.6)
                reasons.append("Reply-To does not match From")

    return _factor(
        "Brand / identity impersonation", "impersonation", value,
        ("; ".join(reasons) if reasons else
         "no impersonation detected" if applicable else
         "not applicable, no domain or sender to evaluate"),
        applicable=applicable,
    )


def _infrastructure_factor(evidence: list[Evidence]) -> RiskFactor:
    """Hosting and lifecycle signals: young domains, bad TLDs, odd redirects."""
    value, reasons = 0.0, []
    applicable = any(
        e.source in ("dns", "rdap", "http", "abuseipdb") for e in evidence
    )
    for ev in evidence:
        if ev.source == "rdap" and ev.tool == "domain":
            age = ev.signals.get("age_days")
            if isinstance(age, int):
                if age <= 7:
                    value = max(value, 0.95)
                    reasons.append(f"domain registered {age} day(s) ago")
                elif age <= 30:
                    value = max(value, 0.75)
                    reasons.append(f"domain registered {age} days ago")
                elif age <= 90:
                    value = max(value, 0.45)
                    reasons.append(f"domain registered {age} days ago")
        elif ev.source == "dns":
            if ev.signals.get("high_risk_tld"):
                value = max(value, 0.5)
                reasons.append(f".{ev.signals['high_risk_tld']} is a commonly abused TLD")
            if ev.signals.get("resolves") is False:
                value = max(value, 0.3)
                reasons.append("domain does not resolve")
        elif ev.source == "http":
            if ev.signals.get("https_downgrade"):
                value = max(value, 0.7)
                reasons.append("redirect chain downgrades HTTPS to HTTP")
            if ev.signals.get("cross_domain_redirect"):
                value = max(value, 0.55)
                reasons.append("redirects to a different domain")
            if ev.signals.get("shortener_used"):
                value = max(value, 0.5)
                reasons.append("destination is hidden behind a URL shortener")
        elif ev.source == "abuseipdb" and ev.signals.get("is_tor"):
            value = max(value, 0.6)
            reasons.append("hosted on a Tor exit node")

    return _factor(
        "Infrastructure characteristics", "infrastructure", value,
        ("; ".join(reasons) if reasons else
         "no adverse infrastructure signals" if applicable else
         "not applicable, no infrastructure data collected"),
        applicable=applicable,
    )


def _exposure_factor(criticality: str, internet_exposed: bool) -> RiskFactor:
    crit = _CRITICALITY_VALUE.get(criticality, 0.5)
    # Exposure is a multiplier on criticality, not an independent addend: a
    # critical asset that is not reachable is materially less risky.
    value = crit if internet_exposed else crit * 0.45
    return _factor(
        "Exposure and asset criticality", "exposure", value,
        f"asset criticality '{criticality}', "
        f"{'internet exposed' if internet_exposed else 'not internet exposed'}",
    )


def _corroboration_factor(evidence: list[Evidence]) -> tuple[RiskFactor, int]:
    """Independent sources agreeing is what separates a signal from an artifact."""
    agreeing = {
        ev.source for ev in evidence
        if ev.source in _INDEPENDENT_SOURCES
        and ev.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
    }
    count = len(agreeing)
    value = min(1.0, count / 4.0)  # 4+ independent sources = full weight
    return (
        _factor(
            "Independent corroboration", "corroboration", value,
            (f"{count} independent source(s) flagged this: "
             f"{', '.join(sorted(agreeing))}" if count
             else "no independent source flagged this indicator"),
        ),
        count,
    )


def _confidence(evidence: list[Evidence], corroborating: int) -> float:
    """How much we trust the score itself, separate from how bad the score is.

    Driven by coverage (did our tools actually run?) and agreement between them.
    """
    usable = _usable(evidence)
    if not usable:
        return 0.0
    attempted = len(evidence)
    coverage = len(usable) / attempted if attempted else 0.0
    mean_conf = sum(e.confidence for e in usable) / len(usable)
    corroboration_bonus = min(0.25, corroborating * 0.07)
    # A single source, however loud, caps out lower than several agreeing ones.
    return round(min(0.98, 0.35 * coverage + 0.45 * mean_conf + corroboration_bonus), 3)


def assess(inp: RiskInput) -> RiskAssessment:
    usable = _usable(inp.evidence)

    focus = _focus_indicators(inp.findings)
    corroboration, corroborating_count = _corroboration_factor(usable)
    factors = [
        _reputation_factor(usable, focus),
        _exploitation_factor(usable),
        _finding_factor(inp.findings),
        _impersonation_factor(usable),
        _infrastructure_factor(usable),
        _exposure_factor(inp.asset_criticality, inp.internet_exposed),
        corroboration,
    ]

    # Normalise over the weight that could actually be evaluated. Without this,
    # a textbook phishing email caps out in the 50s purely because the CVE and
    # reputation dimensions have nothing to say about it, the missing weight
    # would read as "evidence of safety", which it is not. Incomplete coverage
    # is reported through `confidence`, not by deflating the score.
    # Nothing was observed at all: we know nothing, which is a score of zero,
    # not a low-but-nonzero reading driven by asset metadata alone.
    if not usable and not inp.findings:
        return RiskAssessment(
            score=0.0, severity=Severity.INFO, confidence=0.0, factors=factors,
            evidence_count=0, corroborating_sources=0, coverage=0.0,
            explanation=("No evidence was collected, so no risk assessment is "
                         "possible. This is an absence of data, not a clean "
                         "result."),
        )

    applicable = [f for f in factors if f.applicable]
    applicable_weight = sum(f.weight for f in applicable)
    if applicable_weight <= 0:
        raw_score = 0.0
    else:
        raw_score = (sum(f.contribution for f in applicable)
                     / applicable_weight) * 100.0

    # Exposure alone should never imply a threat. If nothing adverse was found,
    # cap the score so a healthy critical asset doesn't read as "medium risk".
    threat_contribution = sum(
        f.contribution for f in applicable
        if f.name != "Exposure and asset criticality"
    )
    if threat_contribution < 0.02:
        raw_score = min(raw_score, 8.0)

    score = round(max(0.0, min(100.0, raw_score)), 1)
    confidence = _confidence(inp.evidence, corroborating_count)
    coverage = round(applicable_weight / sum(WEIGHTS.values()), 3)

    return RiskAssessment(
        score=score,
        severity=Severity.from_score(score),
        confidence=confidence,
        factors=factors,
        evidence_count=len(usable),
        corroborating_sources=corroborating_count,
        coverage=coverage,
        explanation=build_explanation(score, factors, confidence, coverage),
    )


def build_explanation(score: float, factors: list[RiskFactor],
                      confidence: float, coverage: float = 1.0) -> str:
    """Plain-language, fully derived from the factors, no model involved."""
    severity = Severity.from_score(score)
    drivers = sorted(
        [f for f in factors if f.applicable and f.contribution > 0.01],
        key=lambda f: -f.contribution,
    )[:4]
    skipped = [f for f in factors if not f.applicable]

    if not drivers:
        text = (f"Risk {score}/100 ({severity.value}). No adverse signals were "
                f"found across the sources queried. Confidence {confidence:.0%}.")
    else:
        lines = [
            f"Risk {score}/100 ({severity.value.upper()}), "
            f"confidence {confidence:.0%}.",
            "Primary drivers:",
        ]
        for f in drivers:
            lines.append(
                f"  - {f.name} scored {f.value:.0%} of its "
                f"{f.weight * 100:.0f}-point weight: {f.rationale}"
            )
        text = "\n".join(lines)

    if skipped:
        text += (
            f"\n\nScored on {coverage:.0%} of the model's weight. Not evaluated: "
            + "; ".join(f"{f.name} ({f.rationale})" for f in skipped) + "."
        )
    return text
