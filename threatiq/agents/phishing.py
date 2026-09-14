"""Phishing / BEC agent.

Handles two shapes of input: a full email message, and a bare URL/domain that
someone wants judged as a phishing lure. Both funnel into the same finding
vocabulary so the correlation and risk stages don't need to care which it was.
"""
from __future__ import annotations

import logging

from threatiq.agents.state import InvestigationState, timed_action
from threatiq.engine.indicators import domain_of
from threatiq.schemas import Evidence, Finding, IndicatorType, InputKind, Severity
from threatiq.tools.email_analysis import email_analyze
from threatiq.tools.lookalike import lookalike_domain

log = logging.getLogger(__name__)


def _email_findings(ev: Evidence) -> list[Finding]:
    s = ev.signals
    findings: list[Finding] = []
    score = float(s.get("phishing_score", 0) or 0)

    if score >= 0.45:
        severity = Severity.CRITICAL if score >= 0.7 else Severity.HIGH
        bullets: list[str] = []
        if s.get("reply_to_mismatch"):
            bullets.append(
                f"Reply-To ({s.get('reply_to_domain')}) differs from From "
                f"({s.get('from_domain')}), replies would leave the "
                f"apparent conversation."
            )
        if s.get("auth_failures"):
            bullets.append(
                "Email authentication failed for: "
                f"{', '.join(s['auth_failures'])}."
            )
        if s.get("display_name_spoof"):
            bullets.append(f"Display name spoofing: {s['display_name_spoof']}.")
        if s.get("mismatched_links"):
            bullets.append(
                f"{len(s['mismatched_links'])} link(s) show one domain but "
                f"navigate to another."
            )
        if s.get("social_engineering_patterns"):
            bullets.append(
                "Social-engineering patterns: "
                f"{', '.join(s['social_engineering_patterns'])}."
            )
        if s.get("risky_attachments"):
            bullets.append(
                f"High-risk attachments: {', '.join(s['risky_attachments'])}."
            )

        is_bec = any(
            p in (s.get("social_engineering_patterns") or [])
            for p in ("payment redirection (BEC)", "BEC pretext opener",
                      "secrecy request (BEC)", "gift-card / crypto fraud")
        )
        findings.append(Finding(
            title=("Business email compromise (BEC) attempt" if is_bec
                   else "Credential-phishing email"),
            description=(
                f"Composite phishing score {score:.2f}.\n"
                + "\n".join(f"- {b}" for b in bullets)
            ),
            category="bec" if is_bec else "phishing",
            severity=severity,
            confidence=min(0.95, 0.5 + score * 0.5),
            indicators=["email_message:submitted"],
            evidence_ids=[ev.id],
            agent="phishing",
        ))

    if s.get("auth_failures") and not findings:
        findings.append(Finding(
            title="Email authentication failure",
            description=(
                "The message failed "
                f"{', '.join(s['auth_failures'])}. The sending domain cannot be "
                f"verified, so the From address may be forged."
            ),
            category="phishing", severity=Severity.MEDIUM, confidence=0.7,
            indicators=["email_message:submitted"], evidence_ids=[ev.id],
            agent="phishing",
        ))
    return findings


def _lookalike_findings(ev: Evidence) -> list[Finding]:
    s = ev.signals
    score = float(s.get("score", 0) or 0)
    if score < 0.5:
        return []
    brand = s.get("matched_brand")
    technique = str(s.get("technique") or "").replace("_", " ")
    details = []
    if brand:
        details.append(f"The domain resembles '{brand}' via {technique}.")
    if s.get("lure_tokens"):
        details.append(
            "It contains credential-harvesting keywords: "
            f"{', '.join(s['lure_tokens'])}."
        )
    if s.get("homoglyph"):
        details.append(f"Homoglyph indicators present: {s['homoglyph']}.")

    return [Finding(
        title=f"Brand impersonation domain: {s.get('domain', '')}",
        description=" ".join(details),
        category="phishing",
        severity=Severity.CRITICAL if score >= 0.8 else Severity.HIGH,
        confidence=min(0.92, 0.5 + score * 0.45),
        indicators=[ev.indicator], evidence_ids=[ev.id], agent="phishing",
    )]


async def run(state: InvestigationState) -> InvestigationState:
    with timed_action("phishing", "analyze") as record:
        ctx = state["tool_ctx"]
        kind = state.get("kind")
        evidence: list[Evidence] = []
        findings: list[Finding] = []

        if kind == InputKind.EMAIL_MESSAGE:
            ev = await email_analyze(ctx, state["raw_input"])
            evidence.append(ev)
            findings.extend(_email_findings(ev))

            # The sender domain and every linked domain get impersonation checks.
            candidates = {
                d for d in ([ev.signals.get("from_domain")]
                            + list(ev.signals.get("link_domains") or []))
                if d
            }
        else:
            candidates = {
                i.value for i in state.get("indicators", [])
                if i.type == IndicatorType.DOMAIN
            }
            for i in state.get("indicators", []):
                if i.type == IndicatorType.URL:
                    d = domain_of(i.value)
                    if d:
                        candidates.add(d)

        for domain in sorted(candidates)[:8]:
            ev = await ctx.cached(
                f"lookalike_domain|{domain}",
                lambda d=domain: lookalike_domain(ctx, d),
            )
            evidence.append(ev)
            findings.extend(_lookalike_findings(ev))

        record.detail = (f"{len(candidates)} domain(s) checked for impersonation; "
                         f"{len(findings)} finding(s)")

    return {"evidence": evidence, "findings": findings, "actions": [record]}
