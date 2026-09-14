"""Threat intelligence agent, reputation and infrastructure for every IOC.

Runs the free tools always and the keyed tools when configured, fanning out
across indicators concurrently. It also *pivots*: an IP discovered in a DNS
answer becomes a new indicator that gets its own reputation lookup, which is
what turns a flat lookup into an investigation.
"""
from __future__ import annotations

import asyncio
import logging

from threatiq.agents.state import InvestigationState, timed_action
from threatiq.engine.indicators import domain_of, is_private_ip
from threatiq.schemas import (
    Evidence, Finding, Indicator, IndicatorType, Severity, ToolStatus, Verdict,
)
# Import the package, not just base: this is what registers the tools.
from threatiq.tools import registry

log = logging.getLogger(__name__)

# Which registered tools apply to each indicator type.
TOOLS_BY_TYPE: dict[IndicatorType, list[str]] = {
    IndicatorType.URL: ["virustotal_url", "http_probe", "urlscan_search"],
    IndicatorType.DOMAIN: ["dns_lookup", "rdap_domain", "virustotal_domain",
                           "urlscan_search", "lookalike_domain"],
    IndicatorType.IPV4: ["abuseipdb_check", "virustotal_ip", "rdap_ip"],
    IndicatorType.IPV6: ["abuseipdb_check", "virustotal_ip", "rdap_ip"],
    IndicatorType.FILE_HASH: ["virustotal_file"],
}

MAX_INDICATORS = 12   # budget guard: an email can carry dozens of links
MAX_PIVOTS = 4


async def _investigate(ctx, indicator: Indicator) -> list[Evidence]:
    tools = TOOLS_BY_TYPE.get(indicator.type, [])
    if not tools:
        return []
    return await registry.run_many(ctx, tools, indicator.value)


def _derive_findings(evidence: list[Evidence],
                     indicators: list[Indicator]) -> list[Finding]:
    """Turn raw evidence into analyst-level conclusions.

    Deliberately conservative: a finding is only raised when a source with real
    confidence says so, because every finding feeds the risk score.
    """
    findings: list[Finding] = []
    by_indicator: dict[str, list[Evidence]] = {}
    for ev in evidence:
        by_indicator.setdefault(ev.indicator, []).append(ev)

    for indicator_key, items in by_indicator.items():
        malicious = [e for e in items
                     if e.verdict == Verdict.MALICIOUS and e.confidence >= 0.6]
        suspicious = [e for e in items if e.verdict == Verdict.SUSPICIOUS]

        if malicious:
            sources = sorted({e.source for e in malicious})
            findings.append(Finding(
                title=f"Malicious indicator: {indicator_key.split(':', 1)[1]}",
                description=(
                    f"{len(sources)} source(s) classify this indicator as "
                    f"malicious.\n" + "\n".join(f"- {e.source}: {e.summary}"
                                                for e in malicious)
                ),
                category="malicious_infrastructure",
                severity=Severity.CRITICAL if len(sources) > 1 else Severity.HIGH,
                # Corroboration across independent feeds raises confidence.
                confidence=min(0.97, 0.65 + 0.15 * len(sources)),
                indicators=[indicator_key],
                evidence_ids=[e.id for e in malicious],
                agent="threat_intel",
            ))
        elif len(suspicious) >= 2:
            findings.append(Finding(
                title=f"Suspicious indicator: {indicator_key.split(':', 1)[1]}",
                description="Multiple sources raised concerns:\n" + "\n".join(
                    f"- {e.source}: {e.summary}" for e in suspicious
                ),
                category="suspicious_infrastructure",
                severity=Severity.MEDIUM,
                confidence=0.55,
                indicators=[indicator_key],
                evidence_ids=[e.id for e in suspicious],
                agent="threat_intel",
            ))

        # Newly registered domains are a finding in their own right even when
        # no reputation feed has caught up yet, that lag is the attack window.
        for ev in items:
            age = ev.signals.get("age_days")
            if ev.source == "rdap" and isinstance(age, int) and age <= 30:
                findings.append(Finding(
                    title=f"Newly registered domain: {indicator_key.split(':', 1)[1]}",
                    description=(
                        f"The domain was registered {age} day(s) ago. Reputation "
                        f"feeds frequently lag new phishing infrastructure, so a "
                        f"clean verdict from them is not exculpatory."
                    ),
                    category="suspicious_infrastructure",
                    severity=Severity.HIGH if age <= 7 else Severity.MEDIUM,
                    confidence=0.8,
                    indicators=[indicator_key],
                    evidence_ids=[ev.id],
                    agent="threat_intel",
                ))

        for ev in items:
            missing = ev.signals.get("missing_security_headers") or []
            if ev.source == "http" and len(missing) >= 3:
                findings.append(Finding(
                    title="Missing HTTP security headers",
                    description=(
                        "The endpoint does not return "
                        f"{len(missing)} recommended security headers: "
                        f"{', '.join(missing)}."
                    ),
                    category="misconfiguration",
                    severity=Severity.MEDIUM if len(missing) >= 4 else Severity.LOW,
                    confidence=0.9,
                    indicators=[indicator_key],
                    evidence_ids=[ev.id],
                    agent="threat_intel",
                ))
            if ev.source == "http" and ev.signals.get("https_downgrade"):
                findings.append(Finding(
                    title="HTTPS downgraded to HTTP in redirect chain",
                    description=(
                        "The request began over HTTPS but was redirected to "
                        "plaintext HTTP, exposing any submitted data to "
                        "interception."
                    ),
                    category="misconfiguration",
                    severity=Severity.HIGH, confidence=0.9,
                    indicators=[indicator_key],
                    evidence_ids=[ev.id], agent="threat_intel",
                ))
    return findings


async def run(state: InvestigationState) -> InvestigationState:
    with timed_action("threat_intel", "collect") as record:
        ctx = state["tool_ctx"]
        indicators = [
            i for i in state.get("indicators", [])
            if i.type in TOOLS_BY_TYPE
        ][:MAX_INDICATORS]

        if not indicators:
            record.detail = "no actionable indicators for threat intelligence"
            return {"actions": [record]}

        batches = await asyncio.gather(
            *(_investigate(ctx, ind) for ind in indicators),
            return_exceptions=True,
        )
        evidence: list[Evidence] = []
        for result in batches:
            if isinstance(result, list):
                evidence.extend(result)
            elif isinstance(result, BaseException):
                log.warning("threat_intel branch failed: %s", result)

        # --- pivot: resolved IPs become first-class indicators ---
        known = {i.key for i in state.get("indicators", [])}
        pivots: list[Indicator] = []
        for ev in evidence:
            if len(pivots) >= MAX_PIVOTS:
                break
            parent = next((i for i in indicators if i.key == ev.indicator), None)
            for ip in (ev.signals.get("ips") or [])[:2]:
                key = f"ipv4:{str(ip).lower()}"
                if key in known or is_private_ip(str(ip)):
                    continue
                known.add(key)
                pivots.append(Indicator(
                    type=IndicatorType.IPV4, value=str(ip),
                    source=f"pivot:{ev.source}",
                    parent_id=parent.id if parent else None,
                ))
            # A URL's final destination after redirects deserves its own look.
            final_url = ev.signals.get("final_url")
            if final_url and ev.source == "http":
                final_domain = domain_of(str(final_url))
                key = f"domain:{final_domain}" if final_domain else ""
                if key and key not in known:
                    known.add(key)
                    pivots.append(Indicator(
                        type=IndicatorType.DOMAIN, value=final_domain or "",
                        source="pivot:redirect",
                        parent_id=parent.id if parent else None,
                    ))

        if pivots:
            pivot_batches = await asyncio.gather(
                *(_investigate(ctx, p) for p in pivots[:MAX_PIVOTS]),
                return_exceptions=True,
            )
            for result in pivot_batches:
                if isinstance(result, list):
                    evidence.extend(result)

        findings = _derive_findings(evidence, indicators + pivots)
        ok = sum(1 for e in evidence if e.status == ToolStatus.OK)
        skipped = sum(1 for e in evidence if e.status == ToolStatus.SKIPPED)
        record.detail = (
            f"{len(indicators)} indicator(s), {len(pivots)} pivot(s); "
            f"{ok} tool result(s), {skipped} skipped (no API key), "
            f"{len(findings)} finding(s)"
        )

    return {
        "evidence": evidence,
        "findings": findings,
        "indicators": pivots,
        "actions": [record],
    }
