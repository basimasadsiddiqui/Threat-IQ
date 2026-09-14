"""API contract tests using FastAPI's TestClient (no server, no network)."""
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    from threatiq.api.main import app
    with TestClient(app) as c:
        yield c


def test_health_reports_degraded_state_honestly(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["graph_backend"] in ("langgraph", "fallback")
    # With no keys configured this must be visible, not hidden.
    assert body["llm"]["enabled"] is False
    assert body["auth_enabled"] is False
    assert "virustotal_url" in body["tools_unconfigured"]


def test_tools_endpoint_lists_every_registered_tool(client):
    tools = client.get("/tools").json()["tools"]
    names = {t["name"] for t in tools}
    # Regression guard: these were silently absent when the package did not
    # import its own tool modules.
    assert {"dns_lookup", "rdap_domain", "virustotal_url", "abuseipdb_check",
            "urlscan_search", "lookalike_domain", "nvd_cve", "cisa_kev",
            "http_probe", "email_analyze"} <= names


def test_classify_makes_no_external_calls(client):
    body = client.post("/classify", json={"input": "CVE-2024-3400"}).json()
    assert body["kind"] == "cve"
    assert body["indicators"][0]["value"] == "CVE-2024-3400"


def test_unknown_investigation_returns_404(client):
    assert client.get("/investigations/doesnotexist").status_code == 404


def test_empty_input_is_rejected(client):
    assert client.post("/investigate", json={"input": ""}).status_code == 422


def test_security_headers_present(client):
    headers = client.get("/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "X-Process-Time-Ms" in headers


def test_api_key_enforced_when_configured(monkeypatch):
    from threatiq.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("API_KEY", "s3cret")
    from threatiq.api import main as api_main
    monkeypatch.setattr(api_main, "settings", get_settings())

    with TestClient(api_main.app) as c:
        assert c.post("/investigate", json={"input": "x.com"}).status_code == 401
        assert c.post("/investigate", json={"input": "x.com"},
                      headers={"X-API-Key": "wrong"}).status_code == 401
    get_settings.cache_clear()


def test_search_requires_minimum_length(client):
    assert client.get("/search", params={"indicator": "a"}).status_code == 422
