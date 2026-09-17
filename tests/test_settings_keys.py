"""Caller-supplied API keys: what they may reach, and what they must not.

A request carrying credentials is the one place in ThreatIQ where a caller
writes into configuration, so most of what is asserted here is the shape of the
blast radius rather than the happy path. The override mechanism exists so an
analyst can bring their own keys to a deployment that holds none; it must not
become a way to reconfigure the deployment itself.
"""
from __future__ import annotations

import httpx
import pytest

from threatiq.config import OVERRIDABLE_SETTINGS, get_settings
from threatiq.keycheck import PROBES, PROBES_BY_SETTING, Probe, check_one
from threatiq.schemas import InvestigationRequest

# --------------------------------------------------------------- the allowlist

def test_overrides_apply_the_keys_they_are_for():
    applied = get_settings().with_overrides(
        {"virustotal_api_key": "vt-supplied", "abuseipdb_api_key": "abuse-supplied"}
    )
    assert applied.virustotal_api_key == "vt-supplied"
    assert applied.abuseipdb_api_key == "abuse-supplied"


def test_overrides_cannot_authorise_an_active_scan(monkeypatch):
    """The one privilege a caller must never be able to grant itself.

    Active scanning is gated on a server-side allowlist precisely so that
    reaching /investigate is not enough to point a scanner at a host. An
    override that could write `authorized_scan_targets` would hand that
    decision to whoever sends the request.
    """
    monkeypatch.setenv("AUTHORIZED_SCAN_TARGETS", "mine.example.com")
    get_settings.cache_clear()

    applied = get_settings().with_overrides(
        {"authorized_scan_targets": "victim.example.com,mine.example.com"}
    )
    assert applied.authorized_targets == {"mine.example.com"}
    assert "victim.example.com" not in applied.authorized_scan_targets


def test_overrides_cannot_rewrite_the_shared_secret(monkeypatch):
    """Rewriting `api_key` would let a caller set the secret it is checked
    against, which is an authentication bypass rather than a configuration
    change."""
    monkeypatch.setenv("API_KEY", "the-real-secret")
    get_settings.cache_clear()

    applied = get_settings().with_overrides({"api_key": "attacker-chosen"})
    assert applied.api_key == "the-real-secret"


@pytest.mark.parametrize("field", [
    "api_key",
    "authorized_scan_targets",
    "zap_base_url",
    "max_response_bytes",
    "rate_limit_overrides",
    "rate_limit_max_wait_s",
    "database_url",
    "cors_origins",
])
def test_privileged_settings_are_not_overridable(field):
    """An allowlist, so a field added to Settings later is closed by default.

    Each of these is a control rather than a credential: the response ceiling
    stops a hostile host exhausting the container, the rate limits keep the
    deployment inside a provider's free tier, and the rest guard the deployment
    itself.
    """
    assert field not in OVERRIDABLE_SETTINGS


def test_only_credentials_and_the_provider_are_overridable():
    """Pin the allowlist. Widening it is a security decision and should have to
    be made deliberately, in a diff that also changes this test."""
    assert OVERRIDABLE_SETTINGS == {
        "virustotal_api_key", "abuseipdb_api_key", "urlscan_api_key",
        "nvd_api_key", "groq_api_key", "google_api_key", "llm_provider",
    }


def test_an_unknown_llm_provider_is_ignored():
    """`model_copy` skips validation by design, so the value has to be checked
    by hand. Without that, `llm_provider` could hold a string no branch in the
    system handles."""
    applied = get_settings().with_overrides({"llm_provider": "definitely-not-a-provider"})
    assert applied.llm_provider in ("groq", "gemini", "none")


def test_blank_and_non_string_overrides_are_ignored():
    """An empty box on the settings page must not blank out a key the
    deployment has configured."""
    base = get_settings().with_overrides({"virustotal_api_key": "configured"})
    applied = base.with_overrides({"virustotal_api_key": "   ",
                                   "abuseipdb_api_key": None})  # type: ignore[dict-item]
    assert applied.virustotal_api_key == "configured"


def test_overrides_never_mutate_the_shared_settings():
    """Two investigations run concurrently in one process. If an override wrote
    through to the cached settings object, one caller's key would leak into
    another caller's investigation."""
    shared = get_settings()
    shared.with_overrides({"virustotal_api_key": "caller-one"})
    assert shared.virustotal_api_key == ""
    assert get_settings().virustotal_api_key == ""


def test_no_overrides_returns_the_shared_object():
    """Identity, not just equality: `llm_for` relies on it to keep reusing one
    constructed provider client on the ordinary path."""
    shared = get_settings()
    assert shared.with_overrides({}) is shared
    assert shared.with_overrides(None) is shared


# ----------------------------------------------- .env and session, side by side

# Both ways of supplying a key have to keep working, because they answer
# different deployments: one shared set for a machine only you use, and
# per-session keys for a console more than one person opens. The session path is
# the newer one, so these pin the older path against being quietly broken by it.

def test_the_suite_is_detached_from_a_real_dot_env():
    """The suite must not read whatever .env exists on this machine.

    Clearing the environment variables was not enough: `Settings` also reads a
    file, so on a machine where ThreatIQ is actually configured, real
    credentials were loaded into every test. Tests asserting the unconfigured
    path failed, and a test that reaches a tool could have spent live quota
    belonging to whoever was running it. This pins the fix in conftest.
    """
    from threatiq.config import Settings

    assert Settings.model_config["env_file"] is None, (
        "the suite is reading a .env file; a developer's real credentials "
        "would leak into tests and could spend live API quota"
    )
    assert get_settings().virustotal_api_key == ""
    assert not get_settings().llm_enabled


def test_a_dot_env_file_supplies_keys(tmp_path, monkeypatch):
    """Pasting a key into .env still configures the deployment.

    Settings reads `.env` relative to the working directory, so this builds a
    real file and reads it rather than setting an environment variable, which
    would pass even if .env parsing were broken entirely.
    """
    from threatiq.config import Settings

    (tmp_path / ".env").write_text(
        "VIRUSTOTAL_API_KEY=vt-from-dot-env\n"
        "ABUSEIPDB_API_KEY=abuse-from-dot-env\n"
        "LLM_PROVIDER=groq\n"
        "GROQ_API_KEY=groq-from-dot-env\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    # The suite detaches the .env file from Settings so that a developer's real
    # credentials never leak into a test run. This is the one test that wants
    # the file read, so it opts back in, pointed at the throwaway one it just
    # wrote rather than at whatever exists on this machine.
    monkeypatch.setitem(Settings.model_config, "env_file", str(tmp_path / ".env"))
    for var in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "GROQ_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)

    settings = Settings()
    assert settings.virustotal_api_key == "vt-from-dot-env"
    assert settings.abuseipdb_api_key == "abuse-from-dot-env"
    assert settings.llm_enabled, "an LLM key in .env should enable the model"


def test_server_keys_are_used_when_the_caller_supplies_none(monkeypatch):
    """The deployment's own keys are the default, not a fallback that only
    applies when someone remembers to ask for them."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-from-dot-env")
    get_settings.cache_clear()

    applied = get_settings().with_overrides({})
    assert applied.virustotal_api_key == "vt-from-dot-env"


def test_a_supplied_key_takes_precedence_over_the_server_key(monkeypatch):
    """What the settings page promises when it says "yours would take
    precedence"."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-from-dot-env")
    get_settings.cache_clear()

    applied = get_settings().with_overrides({"virustotal_api_key": "vt-from-session"})
    assert applied.virustotal_api_key == "vt-from-session"


def test_a_partial_override_leaves_the_other_server_keys_intact(monkeypatch):
    """The realistic mixed case: a deployment holds several keys and an analyst
    brings one of their own. Replacing the whole credential set rather than the
    named field would silently drop every source they did not mention.
    """
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-from-dot-env")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuse-from-dot-env")
    monkeypatch.setenv("NVD_API_KEY", "nvd-from-dot-env")
    get_settings.cache_clear()

    applied = get_settings().with_overrides({"virustotal_api_key": "vt-from-session"})
    assert applied.virustotal_api_key == "vt-from-session"
    assert applied.abuseipdb_api_key == "abuse-from-dot-env"
    assert applied.nvd_api_key == "nvd-from-dot-env"


def test_a_server_llm_survives_a_session_that_supplied_no_model_key(monkeypatch):
    """A caller who brings a VirusTotal key but no model key must not end up
    turning off a language model the deployment has configured."""
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "groq-from-dot-env")
    get_settings.cache_clear()

    applied = get_settings().with_overrides({"virustotal_api_key": "vt-from-session"})
    assert applied.llm_enabled
    assert applied.groq_api_key == "groq-from-dot-env"


# ------------------------------------------------------------ no key leakage

def test_supplied_keys_are_masked_in_a_repr():
    """Requests get logged eventually, somewhere, by someone. That is exactly
    when a plain `str` would burn a credential."""
    request = InvestigationRequest(
        input="example.com",
        key_overrides={"virustotal_api_key": "super-secret-value"},
    )
    assert "super-secret-value" not in repr(request)
    assert "super-secret-value" not in str(request.key_overrides)


def test_supplied_keys_are_excluded_from_serialization():
    """`exclude=True` keeps them out of anything derived from the request, so
    they cannot ride along into a stored report or an audit record."""
    request = InvestigationRequest(
        input="example.com",
        key_overrides={"virustotal_api_key": "super-secret-value"},
    )
    assert "key_overrides" not in request.model_dump()
    assert "super-secret-value" not in request.model_dump_json()


def test_resolved_overrides_returns_usable_values():
    """The masking must not defeat the actual purpose."""
    request = InvestigationRequest(
        input="example.com",
        key_overrides={"virustotal_api_key": "super-secret-value"},
    )
    assert request.resolved_overrides() == {
        "virustotal_api_key": "super-secret-value"}


@pytest.mark.asyncio
async def test_supplied_keys_do_not_reach_the_stored_report(stub_network):
    """End to end: a key goes in with the request and appears nowhere in the
    report that gets persisted and served back."""
    from threatiq.service import investigate

    secret = "vt-key-that-must-not-appear"
    report = await investigate(InvestigationRequest(
        input="paypa1-login.tk",
        key_overrides={"virustotal_api_key": secret},
    ))
    assert secret not in report.model_dump_json()


@pytest.mark.asyncio
async def test_supplied_keys_reach_the_tools(monkeypatch, stub_network):
    """The mechanism has to actually work, or every assertion above is about
    a feature nobody can use."""
    from threatiq.service import investigate

    seen: list[str] = []

    async def spy(ctx, value):
        seen.append(ctx.settings.virustotal_api_key)
        from threatiq.schemas import Evidence, ToolStatus
        return Evidence(source="virustotal", tool="domain",
                        indicator=f"domain:{value}", status=ToolStatus.SKIPPED,
                        confidence=0.0, summary="spy")

    from threatiq.tools.base import registry
    monkeypatch.setitem(registry._tools, "virustotal_domain", spy)

    await investigate(InvestigationRequest(
        input="paypa1-login.tk",
        key_overrides={"virustotal_api_key": "vt-supplied"},
    ))
    assert seen and all(k == "vt-supplied" for k in seen)


# ---------------------------------------------------------------- key probing

def test_every_probe_targets_a_real_settings_field():
    """A probe naming a field that does not exist would report every key of
    that provider as absent, for ever, with no error."""
    settings = get_settings()
    for probe in PROBES:
        assert hasattr(settings, probe.setting), probe.setting


def test_every_probe_url_is_a_fixed_https_constant():
    """The endpoint accepting these keys reaches out to the internet. The
    destinations must not be derivable from caller input, or it becomes a
    request-forgery primitive."""
    for probe in PROBES:
        assert probe.url.startswith("https://"), probe.name
        assert "{" not in probe.url, f"{probe.name} url is templated"


def test_probes_cover_the_overridable_credentials():
    """Every key the system accepts should be testable from the settings page,
    otherwise someone pastes a key with no way to find out it is wrong."""
    credentials = OVERRIDABLE_SETTINGS - {"llm_provider"}
    assert credentials == set(PROBES_BY_SETTING)


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [
    (200, "ok"),
    (201, "ok"),
    # A valid key with a spent quota. Reporting this as broken would send
    # someone hunting for a typo in a key that is perfectly fine.
    (429, "ok"),
    (401, "rejected"),
    (403, "rejected"),
    (500, "unclear"),
])
async def test_probe_verdicts(monkeypatch, status, expected):
    probe = PROBES[0]

    async def fake_get(self, url, headers=None, timeout=None):
        return httpx.Response(status_code=status, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    async with httpx.AsyncClient() as client:
        result = await check_one(client, probe, "some-key")
    assert result.state == expected


@pytest.mark.asyncio
async def test_an_unreachable_service_is_not_a_rejected_key(monkeypatch):
    """Two different failures that send you to fix two different things."""
    probe = PROBES[0]

    async def boom(self, url, headers=None, timeout=None):
        raise httpx.ConnectError("no route to host")

    monkeypatch.setattr(httpx.AsyncClient, "get", boom)
    async with httpx.AsyncClient() as client:
        result = await check_one(client, probe, "some-key")
    assert result.state == "unreachable"
    assert not result.usable


@pytest.mark.asyncio
async def test_an_absent_key_is_never_sent_anywhere(monkeypatch):
    """Nothing is transmitted for a key that was not supplied."""
    called = False

    async def fake_get(self, url, headers=None, timeout=None):
        nonlocal called
        called = True
        return httpx.Response(status_code=200, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    async with httpx.AsyncClient() as client:
        result = await check_one(client, PROBES[0], "   ")
    assert result.state == "absent"
    assert not called


@pytest.mark.asyncio
async def test_a_check_result_never_carries_the_key(monkeypatch):
    """A key must not be able to come back out of the endpoint that took it in,
    including through an error string: a transport exception can quote the
    request, and the request carries the key in a header.
    """
    secret = "a-very-distinctive-key-value"

    async def boom(self, url, headers=None, timeout=None):
        raise httpx.ConnectError(f"failed sending headers {headers}")

    monkeypatch.setattr(httpx.AsyncClient, "get", boom)
    async with httpx.AsyncClient() as client:
        result = await check_one(client, PROBES[0], secret)
    assert secret not in repr(result)


def test_probe_builds_its_auth_header():
    probe = Probe(name="T", setting="groq_api_key", signup="", unlocks="",
                  url="https://example.invalid", auth_header="Authorization",
                  auth_template="Bearer {key}")
    assert probe.headers("abc") == {"Authorization": "Bearer abc"}


def test_no_probe_puts_a_key_in_a_query_string():
    """A key in a URL lands in proxy logs, browser history and referrer
    headers. Google accepts `?key=`; this uses the header form instead."""
    for probe in PROBES:
        assert "key=" not in probe.url.lower(), probe.name
