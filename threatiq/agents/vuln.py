"""Vulnerability agent, severity plus real-world exploitation context.

The point is prioritisation, not enumeration: "you have 127 vulnerabilities" is
useless, "fix this one first because it is internet-facing and in KEV" is not.
"""
from __future__ import annotations

import asyncio
import logging

from threatiq.agents.state import InvestigationState, timed_action
from threatiq.schemas import Evidence, Finding, IndicatorType, Severity

log = logging.getLogger(__name__)

MAX_CVES = 10


def _severity_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _build_finding(cve: str, nvd: Evidence | None, kev: Evidence | None,
                   internet_exposed: bool, criticality: str) -> Finding | None:
    if nvd is None and kev is None:
        return None

    cvss = float(nvd.signals.get("cvss_score", 0) or 0) if nvd else 0.0
    in_kev = bool(kev and kev.signals.get("in_kev"))
    ransomware = bool(kev and kev.signals.get("known_ransomware_use"))
    description = str(nvd.signals.get("description", "")) if nvd else ""

    severity = _severity_from_cvss(cvss)
    # Confirmed in-the-wild exploitation overrides CVSS: a 7.5 being actively
    # exploited outranks a theoretical 9.8.
    if in_kev and severity.rank < Severity.CRITICAL.rank:
        severity = Severity.CRITICAL

    reasons: list[str] = []
    if cvss:
        reasons.append(f"CVSS base score {cvss}")
    if in_kev:
        reasons.append("listed in CISA KEV (confirmed exploited in the wild)")
        if kev and kev.signals.get("due_date"):
            reasons.append(f"federal remediation due {kev.signals['due_date']}")
    if ransomware:
        reasons.append("known use in ransomware campaigns")
    if nvd and nvd.signals.get("network_exploitable"):
        reasons.append("remotely exploitable over the network")
    if nvd and nvd.signals.get("no_privileges_required"):
        reasons.append("requires no privileges")
    if nvd and nvd.signals.get("no_user_interaction"):
        reasons.append("requires no user interaction")
    if internet_exposed:
        reasons.append("affected asset is internet exposed")
    reasons.append(f"asset criticality is '{criticality}'")

    evidence_ids = [e.id for e in (nvd, kev) if e is not None]
    cwes = list(nvd.signals.get("cwe", [])) if nvd else []
    products = list(nvd.signals.get("affected_products", [])) if nvd else []

    return Finding(
        title=f"{cve}: {'actively exploited ' if in_kev else ''}vulnerability",
        description=(
            (description[:400] + "\n\n" if description else "")
            + "Prioritisation factors: " + "; ".join(reasons) + "."
            + (f"\nAffected products: {', '.join(products[:5])}." if products else "")
        ),
        category="vulnerability",
        severity=severity,
        confidence=0.95 if in_kev else (0.85 if cvss else 0.4),
        indicators=[f"cve:{cve}"],
        evidence_ids=evidence_ids,
        cwe=cwes,
        agent="vulnerability",
        references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
    )


async def run(state: InvestigationState) -> InvestigationState:
    with timed_action("vulnerability", "assess") as record:
        ctx = state["tool_ctx"]
        cves = [
            i.value.upper() for i in state.get("indicators", [])
            if i.type == IndicatorType.CVE
        ][:MAX_CVES]

        if not cves:
            record.detail = "no CVEs present in the input"
            return {"actions": [record]}

        from threatiq.tools.vuln_feeds import cisa_kev, nvd_cve

        async def for_cve(cve: str) -> tuple[str, Evidence, Evidence]:
            nvd, kev = await asyncio.gather(
                ctx.cached(f"nvd_cve|{cve}", lambda c=cve: nvd_cve(ctx, c)),
                ctx.cached(f"cisa_kev|{cve}", lambda c=cve: cisa_kev(ctx, c)),
            )
            return cve, nvd, kev

        results = await asyncio.gather(*(for_cve(c) for c in cves),
                                       return_exceptions=True)

        evidence: list[Evidence] = []
        findings: list[Finding] = []
        for result in results:
            if isinstance(result, BaseException):
                log.warning("CVE lookup failed: %s", result)
                continue
            cve, nvd, kev = result
            evidence.extend([nvd, kev])
            finding = _build_finding(
                cve, nvd, kev,
                bool(state.get("internet_exposed", True)),
                str(state.get("asset_criticality", "medium")),
            )
            if finding:
                findings.append(finding)

        # Ordering here becomes the remediation priority order downstream.
        findings.sort(key=lambda f: (-f.severity.rank, -f.confidence))
        kev_count = sum(
            1 for e in evidence if e.source == "cisa_kev" and e.signals.get("in_kev")
        )
        record.detail = (f"{len(cves)} CVE(s) assessed, {kev_count} in CISA KEV, "
                         f"{len(findings)} finding(s)")

    return {"evidence": evidence, "findings": findings, "actions": [record]}
