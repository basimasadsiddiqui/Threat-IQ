import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Imported after the path insert, not before: relying on pytest's rootdir
# insertion to make this work is an ordering accident, not a guarantee.
from threatiq.schemas import Evidence, Severity, ToolStatus, Verdict  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_settings(monkeypatch):
    """Every test runs with no API keys and no LLM, so nothing hits the network
    by accident and results are reproducible.

    Clearing the environment variables is not enough on its own. `Settings`
    also reads a `.env` file, so on any machine where someone has actually
    configured ThreatIQ, real credentials were being loaded into the suite:
    tests asserting the unconfigured path failed, and tests that reach a tool
    could have spent that person's live quota. The file has to be detached, not
    just the variables unset, and it is done here rather than in the tests that
    happened to notice, because every test inherits the same exposure.
    """
    from threatiq.config import Settings, get_settings

    monkeypatch.setitem(Settings.model_config, "env_file", None)

    get_settings.cache_clear()
    for var in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "URLSCAN_API_KEY",
                "GROQ_API_KEY", "GOOGLE_API_KEY", "NVD_API_KEY",
                "DATABASE_URL", "ZAP_BASE_URL", "AUTHORIZED_SCAN_TARGETS",
                "API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "none")
    yield
    get_settings.cache_clear()


# Shared by the pipeline and LangGraph suites: both need every outbound
# tool stubbed so a test run touches no network and is deterministic.
@pytest.fixture
def stub_network(monkeypatch):
    """Replace every outbound tool with a deterministic stub."""
    async def fake_dns(ctx, domain):
        return Evidence(source="dns", tool="resolve", indicator=f"domain:{domain}",
                        status=ToolStatus.OK, confidence=0.9,
                        summary=f"{domain} resolves",
                        signals={"resolves": True, "ips": ["45.33.32.156"]})

    async def fake_rdap(ctx, domain):
        return Evidence(source="rdap", tool="domain", indicator=f"domain:{domain}",
                        status=ToolStatus.OK, verdict=Verdict.SUSPICIOUS,
                        severity_hint=Severity.HIGH, confidence=0.85,
                        summary=f"{domain} registered 3 days ago",
                        signals={"age_days": 3, "registrar": "Test Registrar"})

    async def fake_rdap_ip(ctx, ip):
        return Evidence(source="rdap", tool="ip", indicator=f"ipv4:{ip}",
                        status=ToolStatus.OK, confidence=0.85,
                        summary=f"{ip} belongs to TestNet",
                        signals={"organization": "TestNet", "country": "XX"})

    async def fake_urlscan(ctx, value):
        return Evidence(source="urlscan", tool="search",
                        indicator=f"domain:{value}", status=ToolStatus.NOT_FOUND,
                        confidence=0.3, summary="no prior scans",
                        signals={"scan_count": 0})

    async def fake_http(ctx, url):
        return Evidence(source="http", tool="probe", indicator=f"url:{url.lower()}",
                        status=ToolStatus.OK, confidence=0.8,
                        summary="1 hop, 200",
                        signals={"redirect_chain": [], "final_url": url,
                                 "missing_security_headers": [
                                     "content-security-policy",
                                     "strict-transport-security",
                                     "x-frame-options",
                                     "x-content-type-options"]})

    async def fake_abuse(ctx, ip):
        return Evidence(source="abuseipdb", tool="check", indicator=f"ipv4:{ip}",
                        status=ToolStatus.OK, verdict=Verdict.MALICIOUS,
                        severity_hint=Severity.CRITICAL, confidence=0.9,
                        summary=f"{ip}: 42 reports, confidence 92%",
                        signals={"abuse_confidence_score": 92,
                                 "total_reports": 42, "distinct_reporters": 12})

    async def fake_kev(ctx, cve):
        in_kev = cve.upper() == "CVE-2024-3400"
        return Evidence(source="cisa_kev", tool="lookup", indicator=f"cve:{cve}",
                        status=ToolStatus.OK,
                        verdict=Verdict.MALICIOUS if in_kev else Verdict.UNKNOWN,
                        severity_hint=Severity.CRITICAL if in_kev else Severity.INFO,
                        confidence=0.98,
                        summary=f"{cve} {'is' if in_kev else 'is not'} in KEV",
                        signals={"in_kev": in_kev, "due_date": "2024-04-30",
                                 "known_ransomware_use": in_kev})

    async def fake_nvd(ctx, cve):
        return Evidence(source="nvd", tool="cve", indicator=f"cve:{cve}",
                        status=ToolStatus.OK, verdict=Verdict.MALICIOUS,
                        severity_hint=Severity.CRITICAL, confidence=0.95,
                        summary=f"{cve}: CVSS 10.0",
                        signals={"cvss_score": 10.0, "cvss_vector": "AV:N/PR:N/UI:N",
                                 "network_exploitable": True,
                                 "no_privileges_required": True,
                                 "description": "Command injection.",
                                 "cwe": ["CWE-78"]})

    import threatiq.tools.vuln_feeds as vf
    from threatiq.tools.base import registry

    for name, fn in [
        ("dns_lookup", fake_dns), ("rdap_domain", fake_rdap),
        ("rdap_ip", fake_rdap_ip), ("urlscan_search", fake_urlscan),
        ("http_probe", fake_http), ("abuseipdb_check", fake_abuse),
        ("cisa_kev", fake_kev), ("nvd_cve", fake_nvd),
    ]:
        monkeypatch.setitem(registry._tools, name, fn)
    monkeypatch.setattr(vf, "cisa_kev", fake_kev)
    monkeypatch.setattr(vf, "nvd_cve", fake_nvd)
    # Neutralise the VirusTotal family (unconfigured -> skipped anyway).
    for name in ("virustotal_url", "virustotal_domain", "virustotal_ip",
                 "virustotal_file"):
        async def skipped(ctx, value, _n=name):
            return Evidence(source="virustotal", tool=_n, indicator=str(value),
                            status=ToolStatus.SKIPPED, confidence=0.0,
                            summary="no key")
        monkeypatch.setitem(registry._tools, name, skipped)


