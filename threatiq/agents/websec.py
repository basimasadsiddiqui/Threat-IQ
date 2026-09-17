"""Web/API security agent.

Active scanning is the one capability in ThreatIQ that touches a target rather
than observing it, so it is gated three ways and every gate must pass:

  1. The request must set allow_active_scan.
  2. The host must appear in AUTHORIZED_SCAN_TARGETS (server-side config the
     requester cannot influence).
  3. A ZAP instance must actually be configured.

Without a ZAP instance the agent still runs a purely passive header review,
which is safe against any target because it is a single ordinary GET.
"""
from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

from threatiq.agents.state import InvestigationState, timed_action
from threatiq.schemas import (
    Evidence,
    Finding,
    IndicatorType,
    Severity,
    ToolStatus,
    Verdict,
)
from threatiq.tools.base import ToolContext
from threatiq.tools.http_probe import SECURITY_HEADERS, http_probe

log = logging.getLogger(__name__)

# ZAP risk labels -> ThreatIQ severities.
_ZAP_RISK = {
    "High": Severity.HIGH, "Medium": Severity.MEDIUM,
    "Low": Severity.LOW, "Informational": Severity.INFO,
}


def is_authorized(target: str, authorized: set[str]) -> bool:
    """Exact host match, or a subdomain of an authorized apex.

    Substring matching would let `evil-example.com` pass an `example.com`
    authorization, so it is not used.
    """
    host = (urlparse(target).hostname if "://" in target else target) or ""
    host = host.lower().strip().rstrip(".")
    if not host or not authorized:
        return False
    for entry in authorized:
        entry = entry.lower().strip().rstrip(".")
        if host == entry or host.endswith("." + entry):
            return True
    return False


async def _zap_scan(ctx: ToolContext, target: str) -> Evidence:
    """Drive an existing OWASP ZAP daemon through its REST API."""
    settings = ctx.settings
    base = settings.zap_base_url.rstrip("/")
    params = {"apikey": settings.zap_api_key} if settings.zap_api_key else {}
    assert ctx.client is not None
    indicator = f"url:{target.lower()}"

    try:
        # Passive spider first so the active scanner has a URL tree to work on.
        spider = await ctx.client.get(
            f"{base}/JSON/spider/action/scan/",
            params={**params, "url": target, "maxChildren": "10"}, timeout=30.0,
        )
        spider.raise_for_status()
        scan_id = spider.json().get("scan")

        for _ in range(60):  # ~2 minutes ceiling
            await asyncio.sleep(2)
            status = await ctx.client.get(
                f"{base}/JSON/spider/view/status/",
                params={**params, "scanId": scan_id}, timeout=15.0,
            )
            if int(status.json().get("status", 0)) >= 100:
                break

        alerts_resp = await ctx.client.get(
            f"{base}/JSON/core/view/alerts/",
            params={**params, "baseurl": target, "count": "100"}, timeout=30.0,
        )
        alerts_resp.raise_for_status()
        alerts = alerts_resp.json().get("alerts", [])
    except Exception as exc:
        return Evidence(
            source="zap", tool="scan", indicator=indicator,
            status=ToolStatus.ERROR, error=str(exc)[:300], confidence=0.0,
            summary=f"ZAP scan failed: {type(exc).__name__}",
        )

    by_risk: dict[str, int] = {}
    normalized = []
    for alert in alerts:
        risk = alert.get("risk", "Informational")
        by_risk[risk] = by_risk.get(risk, 0) + 1
        normalized.append({
            "name": alert.get("alert", ""),
            "risk": risk,
            "confidence": alert.get("confidence", ""),
            "url": alert.get("url", ""),
            "param": alert.get("param", ""),
            "cweid": alert.get("cweid", ""),
            "wascid": alert.get("wascid", ""),
            "solution": (alert.get("solution", "") or "")[:400],
        })

    high = by_risk.get("High", 0)
    medium = by_risk.get("Medium", 0)
    if high:
        verdict, severity, confidence = Verdict.MALICIOUS, Severity.HIGH, 0.85
    elif medium:
        verdict, severity, confidence = Verdict.SUSPICIOUS, Severity.MEDIUM, 0.75
    else:
        verdict, severity, confidence = Verdict.BENIGN, Severity.INFO, 0.7

    return Evidence(
        source="zap", tool="scan", indicator=indicator,
        status=ToolStatus.OK, verdict=verdict, severity_hint=severity,
        confidence=confidence,
        summary=(f"OWASP ZAP: {len(alerts)} alert(s), "
                 + ", ".join(f"{k}: {v}" for k, v in sorted(by_risk.items()))),
        signals={"alert_count": len(alerts), "by_risk": by_risk,
                 "alerts": normalized[:50]},
    )


def _zap_findings(ev: Evidence) -> list[Finding]:
    findings: list[Finding] = []
    # Group by alert name so one reflected-XSS class isn't 40 separate findings.
    grouped: dict[str, list[dict]] = {}
    for alert in ev.signals.get("alerts", []):
        if alert.get("risk") in ("High", "Medium"):
            grouped.setdefault(alert["name"], []).append(alert)

    for name, alerts in grouped.items():
        first = alerts[0]
        cwe = f"CWE-{first['cweid']}" if str(first.get("cweid", "")).isdigit() else ""
        findings.append(Finding(
            title=f"{name}",
            description=(
                f"OWASP ZAP reported this on {len(alerts)} URL(s). "
                f"Example: {first.get('url', '')}"
                + (f" (parameter '{first['param']}')" if first.get("param") else "")
                + (f"\n\nRecommended fix: {first['solution']}"
                   if first.get("solution") else "")
            ),
            category="web_vulnerability",
            severity=_ZAP_RISK.get(first.get("risk", ""), Severity.MEDIUM),
            confidence=0.8 if first.get("confidence") in ("High", "Medium") else 0.55,
            indicators=[ev.indicator], evidence_ids=[ev.id],
            cwe=[cwe] if cwe else [], agent="websec",
        ))
    return findings


def _header_findings(ev: Evidence) -> list[Finding]:
    missing = ev.signals.get("missing_security_headers") or []
    if not missing:
        return []
    explanations = [f"- `{h}`, mitigates {SECURITY_HEADERS[h]}"
                    for h in missing if h in SECURITY_HEADERS]
    return [Finding(
        title="Missing HTTP security headers",
        description=(
            f"The endpoint omits {len(missing)} recommended response header(s):\n"
            + "\n".join(explanations)
        ),
        category="misconfiguration",
        severity=Severity.MEDIUM if len(missing) >= 4 else Severity.LOW,
        confidence=0.9,
        indicators=[ev.indicator], evidence_ids=[ev.id], agent="websec",
    )]


async def run(state: InvestigationState) -> InvestigationState:
    with timed_action("websec", "scan") as record:
        ctx = state["tool_ctx"]
        settings = ctx.settings

        targets = [
            i.value for i in state.get("indicators", [])
            if i.type in (IndicatorType.URL, IndicatorType.DOMAIN)
        ][:3]
        if not targets:
            record.detail = "no web target supplied"
            return {"actions": [record]}

        evidence: list[Evidence] = []
        findings: list[Finding] = []
        scanned, refused = 0, 0

        for target in targets:
            url = target if "://" in target else f"https://{target}"

            # --- passive review always runs; it is one ordinary GET ---
            probe = await ctx.cached(f"http_probe|{url.lower()}",
                                     lambda u=url: http_probe(ctx, u))
            evidence.append(probe)
            if probe.status == ToolStatus.OK:
                findings.extend(_header_findings(probe))

            # --- active scan: all three gates must pass ---
            if not state.get("allow_active_scan"):
                continue
            if not is_authorized(url, settings.authorized_targets):
                refused += 1
                evidence.append(Evidence(
                    source="zap", tool="scan", indicator=f"url:{url.lower()}",
                    status=ToolStatus.REFUSED, confidence=0.0,
                    summary=(
                        f"Active scan refused: {urlparse(url).hostname} is not in "
                        f"AUTHORIZED_SCAN_TARGETS. Add it to the server "
                        f"configuration to authorise scanning of a system you own."
                    ),
                    signals={"authorization_required": True},
                ))
                continue
            if not settings.zap_base_url:
                evidence.append(Evidence(
                    source="zap", tool="scan", indicator=f"url:{url.lower()}",
                    status=ToolStatus.SKIPPED, confidence=0.0,
                    summary="ZAP_BASE_URL not configured; active scanning disabled",
                ))
                continue

            zap_ev = await _zap_scan(ctx, url)
            evidence.append(zap_ev)
            if zap_ev.status == ToolStatus.OK:
                scanned += 1
                findings.extend(_zap_findings(zap_ev))

        record.detail = (f"{len(targets)} target(s); {scanned} active scan(s), "
                         f"{refused} refused for lack of authorisation, "
                         f"{len(findings)} finding(s)")

    return {"evidence": evidence, "findings": findings, "actions": [record]}
