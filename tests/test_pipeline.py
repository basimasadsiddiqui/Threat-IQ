"""End-to-end pipeline tests with every network tool stubbed.

The point is to prove the orchestration wiring, routing, parallel fan-out,
reducers, and the ordering of correlation -> risk -> compliance -> remediation
-> report, without depending on any external service.
"""
import pytest

from threatiq.schemas import (
    Evidence, InputKind, InvestigationRequest, Severity, ToolStatus, Verdict,
)


@pytest.mark.asyncio
async def test_phishing_email_end_to_end(stub_network):
    from threatiq.service import investigate

    report = await investigate(InvestigationRequest(
        input=("From: \"Microsoft\" <a@micros0ft-alerts.tk>\n"
               "Reply-To: b@other-domain.top\n"
               "Subject: Urgent: account suspended\n"
               "Authentication-Results: mx.corp.com; spf=fail dmarc=fail\n\n"
               "Verify immediately: https://micros0ft-login.tk/verify\n"),
        asset_criticality="high",
    ))

    assert report.status == "completed"
    assert report.kind is InputKind.EMAIL_MESSAGE
    assert report.risk.score >= 65, f"under-scored at {report.risk.score}"
    assert report.risk.severity.rank >= Severity.HIGH.rank
    assert report.findings
    assert report.remediation
    assert report.summary

    # Every agent in the pipeline must have recorded an action.
    agents = {a.agent for a in report.actions}
    assert {"orchestrator", "phishing", "threat_intel", "correlation", "risk",
            "compliance", "remediation", "report"} <= agents

    # Findings must carry a framework mapping.
    assert any(f.mitre_attack for f in report.findings)

    # The victim's own mail relay must not be investigated.
    assert not any("corp.com" in i.value for i in report.indicators)


@pytest.mark.asyncio
async def test_cve_routes_to_vulnerability_agent(stub_network):
    from threatiq.service import investigate

    report = await investigate(InvestigationRequest(
        input="CVE-2024-3400", asset_criticality="critical"))

    assert report.kind is InputKind.CVE
    assert report.risk.severity is Severity.CRITICAL
    assert report.risk.score >= 85
    assert any(a.agent == "vulnerability" for a in report.actions)
    assert any("KEV" in f.description or "exploited" in f.title.lower()
               for f in report.findings)
    # A single CVE is not an infrastructure "campaign".
    assert not any(f.category == "campaign" for f in report.findings)


@pytest.mark.asyncio
async def test_benign_domain_scores_low(stub_network, monkeypatch):
    from threatiq.tools.base import registry
    from threatiq.service import investigate

    async def clean_rdap(ctx, domain):
        return Evidence(source="rdap", tool="domain", indicator=f"domain:{domain}",
                        status=ToolStatus.OK, verdict=Verdict.BENIGN,
                        confidence=0.85, summary="registered 4000 days ago",
                        signals={"age_days": 4000})

    async def clean_abuse(ctx, ip):
        return Evidence(source="abuseipdb", tool="check", indicator=f"ipv4:{ip}",
                        status=ToolStatus.OK, verdict=Verdict.BENIGN,
                        confidence=0.6, summary=f"{ip}: no abuse reports",
                        signals={"abuse_confidence_score": 0, "total_reports": 0})

    monkeypatch.setitem(registry._tools, "rdap_domain", clean_rdap)
    # The shared fixture flags every IP as malicious; a benign case must not
    # inherit that, or the pivot to the hosting IP poisons the result.
    monkeypatch.setitem(registry._tools, "abuseipdb_check", clean_abuse)
    report = await investigate(InvestigationRequest(
        input="wikipedia.org", asset_criticality="critical"))

    assert report.risk.score <= 25, f"benign domain over-scored at {report.risk.score}"
    assert not [f for f in report.findings
                if f.severity.rank >= Severity.HIGH.rank]


@pytest.mark.asyncio
async def test_pivot_creates_new_indicators(stub_network):
    from threatiq.service import investigate

    report = await investigate(InvestigationRequest(input="suspicious-site.test"))
    # The DNS stub resolves to 45.33.32.156, which must become its own indicator
    # and receive its own reputation lookup.
    assert any(i.value == "45.33.32.156" for i in report.indicators)
    assert any(e.indicator == "ipv4:45.33.32.156" for e in report.evidence)


@pytest.mark.asyncio
async def test_active_scan_refused_without_authorization(stub_network):
    from threatiq.service import investigate

    report = await investigate(InvestigationRequest(
        input="https://not-authorized.test/api", allow_active_scan=True))

    refused = [e for e in report.evidence if e.status is ToolStatus.REFUSED]
    assert refused, "active scan should have been refused"
    assert any("AUTHORIZED_SCAN_TARGETS" in e.summary for e in refused)


@pytest.mark.asyncio
async def test_investigation_is_serializable(stub_network):
    from threatiq.service import investigate

    report = await investigate(InvestigationRequest(input="CVE-2024-3400"))
    payload = report.model_dump(mode="json")
    import json
    assert json.loads(json.dumps(payload))["risk"]["score"] == report.risk.score
