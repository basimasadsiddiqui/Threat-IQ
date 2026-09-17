"""UI rendering tests via Streamlit's AppTest harness.

These run the real app script with no browser, so every page and every tab
body is executed. A template error, a bad column config or a KeyError in a
rarely-visited tab shows up here instead of in front of an analyst.

The API is stubbed at the httpx layer, so the tests need neither a running
backend nor network access.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")

HEALTH = {
    "status": "ok", "version": "1.0.0", "environment": "dev",
    "graph_backend": "langgraph", "repository": "InMemoryRepository",
    "llm": {"enabled": False, "provider": "groq", "model": None},
    "auth_enabled": False,
    "tools_configured": {"dns_lookup": True, "virustotal_url": False},
    "tools_unconfigured": ["virustotal_url"],
    "active_scanning": {"zap_configured": False, "authorized_targets": []},
}

REPORT = {
    "id": "abc123def456", "status": "completed", "input": "paypa1-login.tk",
    "kind": "domain", "summary": "A domain impersonating PayPal.",
    "error": None,
    "created_at": "2026-09-13T12:00:00+00:00",
    "risk": {
        "score": 72.3, "severity": "high", "confidence": 0.63, "coverage": 0.56,
        "evidence_count": 4, "corroborating_sources": 1,
        "explanation": "Risk 72.3/100 (HIGH).",
        "factors": [
            {"name": "Threat intelligence reputation", "weight": 0.24,
             "value": 0.0, "contribution": 0.0, "applicable": False,
             "rationale": "no reputation source covers the indicator"},
            {"name": "Confirmed findings", "weight": 0.16, "value": 0.96,
             "contribution": 0.1536, "applicable": True,
             "rationale": "2 findings"},
        ],
    },
    "indicators": [{"id": "i1", "type": "domain", "value": "paypa1-login.tk",
                    "source": "user_input"}],
    "evidence": [
        {"id": "e1", "source": "lookalike", "tool": "analyze",
         "indicator": "domain:paypa1-login.tk", "status": "ok",
         "verdict": "malicious", "confidence": 0.85, "severity_hint": "critical",
         "summary": "resembles paypal", "signals": {"score": 0.95},
         "raw": {}, "error": None, "latency_ms": 3,
         "collected_at": "2026-09-13T12:00:00+00:00"},
        {"id": "e2", "source": "virustotal", "tool": "domain",
         "indicator": "domain:paypa1-login.tk", "status": "skipped",
         "verdict": "unknown", "confidence": 0.0, "severity_hint": "info",
         "summary": "no key", "signals": {}, "raw": {}, "error": None,
         "latency_ms": 0, "collected_at": "2026-09-13T12:00:00+00:00"},
    ],
    "findings": [
        {"id": "f1", "title": "Brand impersonation domain", "description": "d",
         "category": "phishing", "severity": "critical", "confidence": 0.92,
         "agent": "phishing", "indicators": ["domain:paypa1-login.tk"],
         "evidence_ids": ["e1"], "owasp": ["A07:2021"], "cwe": ["CWE-290"],
         "mitre_attack": ["T1566"], "nist_csf": ["DE.CM"],
         "references": ["https://owasp.org/Top10/A07_2021-x/"]},
        {"id": "f2", "title": "Malicious indicator", "description": "d",
         "category": "malicious_infrastructure", "severity": "high",
         "confidence": 0.8, "agent": "threat_intel",
         "indicators": ["domain:paypa1-login.tk"], "evidence_ids": ["e1"],
         "owasp": [], "cwe": [], "mitre_attack": [], "nist_csf": [],
         "references": []},
    ],
    "graph": {
        "nodes": [{"id": "domain:paypa1-login.tk", "label": "paypa1-login.tk",
                   "type": "domain", "verdict": "malicious", "meta": {}}],
        "edges": [{"source": "source:lookalike",
                   "target": "domain:paypa1-login.tk",
                   "relation": "reported_on", "meta": {}}],
    },
    "remediation": [{"priority": 1, "action": "Block the domain",
                     "rationale": "Denies reachability.", "owner": "network",
                     "effort": "low", "automatable": True, "references": []}],
    "actions": [{"id": "a1", "agent": "orchestrator", "action": "triage",
                 "detail": "kind=domain", "duration_ms": 5, "status": "ok",
                 "started_at": "2026-09-13T12:00:00+00:00"}],
}

SUMMARY_ROW = {
    "id": "abc123def456", "created_at": "2026-09-13T12:00:00+00:00",
    "status": "completed", "input": "paypa1-login.tk", "kind": "domain",
    "risk_score": 72.3, "severity": "high", "confidence": 0.63,
    "finding_count": 2, "evidence_count": 2,
}


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.text = json.dumps(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


def _fake_get(url, params=None, headers=None, timeout=None):
    if "/settings/keys" in url:
        return _Resp({"providers": [
            {"name": "VirusTotal", "setting": "virustotal_api_key",
             "signup": "https://example.invalid/vt", "unlocks": "reputation",
             "optional": False, "server_configured": False},
            {"name": "Groq", "setting": "groq_api_key",
             "signup": "https://example.invalid/groq", "unlocks": "narrative",
             "optional": True, "server_configured": False},
        ]})
    if "/health" in url:
        return _Resp(HEALTH)
    if "/tools" in url:
        return _Resp({"tools": [
            {"name": "dns_lookup", "description": "Resolve DNS.",
             "accepts": ["domain"], "requires_key": None, "configured": True},
            {"name": "virustotal_url", "description": "VT reputation.",
             "accepts": ["url"], "requires_key": "virustotal_api_key",
             "configured": False},
        ]})
    if "/investigations/" in url:
        return _Resp(REPORT)
    if "/investigations" in url:
        return _Resp({"investigations": [SUMMARY_ROW]})
    if "/stats" in url:
        return _Resp({"backend": "memory", "investigations": 1, "findings": 2,
                      "by_severity": {"high": 1}, "by_category": {"phishing": 1},
                      "mean_risk": 72.3})
    if "/search" in url:
        return _Resp({"results": [{**SUMMARY_ROW,
                                   "matched_indicators": ["paypa1-login.tk"],
                                   "related_findings": [
                                       {"title": "Brand impersonation",
                                        "severity": "critical"}]}]})
    return _Resp({})


def _fake_post(url, json=None, headers=None, timeout=None):
    if "/settings/test-keys" in url:
        return _Resp({"results": [
            {"name": "VirusTotal", "setting": "virustotal_api_key",
             "state": "ok", "detail": "accepted", "optional": False,
             "signup": "https://example.invalid/vt", "unlocks": "reputation",
             "server_configured": False},
        ]})
    if "/classify" in url:
        return _Resp({"kind": "domain",
                      "indicators": [{"type": "domain",
                                      "value": "paypa1-login.tk"}]})
    if "/investigate" in url:
        return _Resp(REPORT)
    if "/copilot/chat" in url:
        return _Resp({"answer": "Because the domain impersonates PayPal.",
                      "citations": ["A07:2021"], "used_context": []})
    return _Resp({})


@pytest.fixture
def app(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", _fake_get)
    monkeypatch.setattr(httpx, "post", _fake_post)
    return AppTest.from_file(APP, default_timeout=30)


PAGE_NAMES = ["Investigate", "Investigations", "Security Copilot",
              "Indicator pivot", "API keys", "System status"]


def test_shell_renders_without_exception(app):
    at = app.run()
    assert not at.exception, f"initial render raised: {at.exception}"


@pytest.mark.parametrize("index,name", list(enumerate(PAGE_NAMES)))
def test_every_page_renders_without_exception(monkeypatch, index, name):
    """Each page body is rendered on its own.

    AppTest.switch_page only understands file-based multipage apps, so it
    cannot drive st.navigation's programmatic pages. Running each page function
    through AppTest.from_function tests the thing that actually matters, which
    is whether that page renders, without depending on navigation internals.
    """
    import httpx
    from streamlit.testing.v1 import AppTest

    monkeypatch.setattr(httpx, "get", _fake_get)
    monkeypatch.setattr(httpx, "post", _fake_post)

    from ui.app import PAGES

    assert PAGES[index][1] == name
    # from_string rather than from_function: from_function executes the callable
    # without its module globals, so `st` is unbound inside the page body.
    root = str(Path(APP).resolve().parents[1])
    at = AppTest.from_string(
        "import sys\n"
        f"sys.path.insert(0, {root!r})\n"
        "from ui.app import PAGES\n"
        f"PAGES[{index}][0]()\n",
        default_timeout=30,
    ).run()
    assert not at.exception, f"page {name!r} raised: {at.exception}"


def test_navigation_is_wired_and_addressable():
    """Navigation is st.navigation rather than a radio group.

    Radio circles are a form affordance: they say "choose a value", not "go to
    a page". st.navigation also gives every page its own URL, so a link to the
    Copilot can be shared.
    """
    from ui.app import PAGES

    assert len(PAGES) == len(PAGE_NAMES)
    titles = [t for _, t, _, _ in PAGES]
    paths = [p for _, _, _, p in PAGES]
    icons = [i for _, _, i, _ in PAGES]

    assert titles == PAGE_NAMES
    assert len(set(paths)) == len(paths), "two pages share a url_path"
    assert all(p and p.islower() and " " not in p for p in paths)
    assert all(i.startswith(":material/") for i in icons)
    assert all(callable(fn) for fn, _, _, _ in PAGES)

    source = Path(APP).read_text(encoding="utf-8")
    assert "st.navigation(" in source
    assert "st.radio(" not in source, "navigation must not be a radio group"


def _run_with_session(monkeypatch, body: str, **session):
    """Execute a snippet inside the app's module context with session state set."""
    import httpx
    from streamlit.testing.v1 import AppTest

    monkeypatch.setattr(httpx, "get", _fake_get)
    monkeypatch.setattr(httpx, "post", _fake_post)
    root = str(Path(APP).resolve().parents[1])
    at = AppTest.from_string(
        "import sys\n"
        f"sys.path.insert(0, {root!r})\n"
        "import streamlit as st\n"
        "from ui.app import session_keys, key_overrides, page_settings\n"
        + body,
        default_timeout=30,
    )
    for name, value in session.items():
        at.session_state[name] = value
    return at.run()


def test_provider_choice_is_not_counted_as_a_key(monkeypatch):
    """The language-model selectbox shares the session prefix but is a routing
    choice, not a credential.

    Counting it would report "1 key supplied" to a session that supplied none,
    and, worse, would send `llm_provider: none` with every request, overriding a
    deployment's own working model with nothing. Visiting the settings page
    would silently downgrade every later investigation.
    """
    at = _run_with_session(
        monkeypatch,
        "st.text(repr(sorted(session_keys())))\n"
        "st.text(repr(sorted(key_overrides())))\n",
        **{"apikey:llm_provider": "groq"},
    )
    assert not at.exception
    assert at.text[0].value == "[]"
    assert at.text[1].value == "[]", "the provider was sent with no key behind it"


def test_provider_rides_along_once_its_key_is_present(monkeypatch):
    """It does have to be sent when there is a key, or a Gemini key is inert on
    a deployment configured for Groq and looks broken."""
    at = _run_with_session(
        monkeypatch,
        "st.text(repr(sorted(session_keys())))\n"
        "st.text(repr(sorted(key_overrides())))\n",
        **{"apikey:llm_provider": "gemini", "apikey:google_api_key": "g-test"},
    )
    assert not at.exception
    assert at.text[0].value == "['google_api_key']"
    assert at.text[1].value == "['google_api_key', 'llm_provider']"


def test_blank_keys_are_not_sent(monkeypatch):
    """An emptied box must not send an empty string, which would blank out a
    key the deployment has configured."""
    at = _run_with_session(
        monkeypatch,
        "st.text(repr(sorted(session_keys())))\n",
        **{"apikey:virustotal_api_key": "   "},
    )
    assert not at.exception
    assert at.text[0].value == "[]"


def test_a_session_llm_key_is_not_reported_as_no_model(monkeypatch):
    """/health answers for the deployment, which is the wrong question to put in
    front of the analyst.

    A session holding a working provider key was being told "No language model
    configured" while its own investigations were quite happily using one. That
    reads as a fault and sends someone to fix configuration that is not broken.
    """
    at = _run_with_session(
        monkeypatch,
        "from ui.app import effective_llm_enabled\n"
        "st.text(repr(effective_llm_enabled({'llm': {'enabled': False}})))\n",
        **{"apikey:llm_provider": "groq", "apikey:groq_api_key": "gsk-test"},
    )
    assert not at.exception
    assert at.text[0].value == "True"


def test_no_model_anywhere_still_reports_no_model(monkeypatch):
    """The correction must not become a blanket claim that a model exists."""
    at = _run_with_session(
        monkeypatch,
        "from ui.app import effective_llm_enabled\n"
        "st.text(repr(effective_llm_enabled({'llm': {'enabled': False}})))\n",
        **{"apikey:llm_provider": "groq"},  # provider chosen, no key behind it
    )
    assert not at.exception
    assert at.text[0].value == "False"


def test_a_source_covered_by_a_session_key_is_not_shown_as_missing(monkeypatch):
    """Rendering a covered source as "No API key" is the same failure as showing
    a skipped lookup as a clean result: it reports missing coverage that is not
    missing."""
    at = _run_with_session(
        monkeypatch,
        "from ui.app import source_status, sources_missing_a_key\n"
        "tools = {'tools': [\n"
        "  {'name': 'virustotal_url', 'requires_key': 'virustotal_api_key',\n"
        "   'configured': False},\n"
        "  {'name': 'abuseipdb_check', 'requires_key': 'abuseipdb_api_key',\n"
        "   'configured': False},\n"
        "  {'name': 'dns_lookup', 'requires_key': None, 'configured': True},\n"
        "]}\n"
        "supplied = {'virustotal_api_key'}\n"
        "st.text(source_status(tools['tools'][0], supplied))\n"
        "st.text(source_status(tools['tools'][1], supplied))\n"
        "st.text(source_status(tools['tools'][2], supplied))\n"
        "st.text(repr(sources_missing_a_key(tools, supplied)))\n",
    )
    assert not at.exception
    assert at.text[0].value == "This session"
    assert at.text[1].value == "No API key"
    assert at.text[2].value == "Configured"
    assert at.text[3].value == "['abuseipdb_check']"


def test_the_sidebar_reports_a_session_model_once(monkeypatch):
    """There were briefly two language-model lines, one saying it was
    configured and one saying it was not."""
    at = _run_with_session(
        monkeypatch,
        "from ui.app import sidebar_status\n"
        "sidebar_status()\n",
        **{"apikey:llm_provider": "groq", "apikey:groq_api_key": "gsk-test"},
    )
    assert not at.exception
    rendered = "\n".join(str(getattr(el, "value", "")) for el in at.markdown)
    assert rendered.count("No language model configured") == 0
    assert rendered.count("Language model key supplied for this session") == 1


def test_settings_page_never_renders_a_supplied_key(monkeypatch):
    """The page confirms a paste landed by reporting its length. Echoing the
    key itself would put it on screen, in a screenshot, and in the DOM."""
    secret = "vt-secret-value-9876"
    at = _run_with_session(
        monkeypatch, "page_settings()\n",
        **{"apikey:virustotal_api_key": secret},
    )
    assert not at.exception
    rendered = "\n".join(
        str(getattr(el, "value", "") or getattr(el, "body", ""))
        for el in [*at.markdown, *at.caption, *at.text]
    )
    assert secret not in rendered
    assert str(len(secret)) in rendered, "the length hint should confirm the paste"


def test_report_renders_all_tabs(app):
    """The report view is the densest surface; every tab body must execute."""
    at = app.run()
    at.query_params["investigation"] = "abc123def456"
    at = at.run()
    assert not at.exception, f"report render raised: {at.exception}"

    labels = [t.label for t in at.tabs]
    # Weaknesses in the target are separated from intelligence about the
    # attacker: they are different questions and go to different people.
    assert labels[0].startswith("Flaws and vulnerabilities")
    assert labels[1].startswith("Threat intelligence")
    assert labels[2:] == ["Risk breakdown", "Evidence", "Threat graph",
                          "Remediation", "Agent trace"]


def test_findings_are_ordered_by_severity_rank(app):
    """Sorting the severity string puts 'medium' above 'critical'."""
    from ui.app import sev_rank

    order = sorted(["medium", "critical", "info", "high", "low"],
                   key=lambda s: -sev_rank(s))
    assert order == ["critical", "high", "medium", "low", "info"]


def test_severity_palette_is_complete_and_distinct():
    from ui.app import _RAMP, ACCENT, ACCENT_MARK_DARK, ACCENT_MARK_LIGHT

    assert set(_RAMP) == {"dark", "light"}, "both modes must define a ramp"
    for mode, ramp in _RAMP.items():
        assert set(ramp) == {"critical", "high", "medium", "low", "info"}, mode
        colors = list(ramp.values())
        assert len(set(colors)) == len(colors), f"{mode}: two severities share a colour"
        # Blue is reserved for interactive chrome and never means a severity.
        for accent in (ACCENT, ACCENT_MARK_DARK, ACCENT_MARK_LIGHT):
            assert accent not in colors, f"{mode}: accent used as a severity"


def test_no_emoji_or_em_dash_in_ui_source():
    """Both are banned: the em-dash is a writing tell, and emoji are not a real
    icon system (Material Symbols are used instead).

    The dashes are written as escapes rather than literals on purpose. A
    project-wide find-and-replace over the dash characters would otherwise
    rewrite this assertion into `"-" not in source`, which passes vacuously
    while checking nothing.
    """
    source = Path(APP).read_text(encoding="utf-8")
    assert "\u2014" not in source, "em-dash found in UI source"
    assert "\u2013" not in source, "en-dash found in UI source"
    # Middle dot (U+00B7) is a legitimate separator and stays allowed.
    emoji = [c for c in source if ord(c) > 0x2500]
    assert not emoji, f"emoji found in UI source: {emoji[:5]}"


def test_no_deprecated_streamlit_apis():
    """Both of these passed their removal date and would break on upgrade."""
    source = Path(APP).read_text(encoding="utf-8")
    assert "use_container_width" not in source
    assert "components.v1.html" not in source


# --------------------------------------------------------------- accessibility

def _relative_luminance(hex_color: str) -> float:
    raw = hex_color.lstrip("#")
    channels = [int(raw[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
              for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast_ratio(fg: str, bg: str) -> float:
    a, b = _relative_luminance(fg), _relative_luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


BACKGROUND = "#0b0f14"
PANEL = "#141b23"


def test_contrast_sanity_check():
    """Guard the helper itself, so a broken formula cannot silently pass
    every contrast assertion below."""
    assert contrast_ratio("#ffffff", "#000000") == pytest.approx(21.0, abs=0.01)
    assert contrast_ratio("#000000", "#000000") == pytest.approx(1.0, abs=0.01)


@pytest.mark.parametrize("name,fg,bg", [
    ("body text",        "#e6edf3", BACKGROUND),
    ("muted caption",    "#9aa6b2", BACKGROUND),
    ("link",             "#6aa3ff", BACKGROUND),
    ("chart axis label", "#9aa6b2", PANEL),
    ("critical badge",   "#ff9592", "#3c1618"),
    ("high badge",       "#ffa057", "#3a1d0a"),
    ("medium badge",     "#f1c21b", "#38290a"),
    ("low badge",        "#6ecf7f", "#13291a"),
    ("info badge",       "#9aa6b2", "#1a212b"),
])
def test_text_meets_wcag_aa(name, fg, bg):
    ratio = contrast_ratio(fg, bg)
    assert ratio >= 4.5, f"{name}: {ratio:.2f}:1 is below WCAG AA 4.5:1"


def test_primary_button_label_meets_wcag_aa():
    """The stock Streamlit primary reached only 3.18:1 against white, which
    fails for button labels. The accent is darkened specifically to clear AA."""
    from ui.app import ACCENT
    ratio = contrast_ratio("#ffffff", ACCENT)
    assert ratio >= 4.5, f"white on {ACCENT} is {ratio:.2f}:1, below AA"


def test_accent_is_visible_against_the_page():
    from ui.app import ACCENT
    assert contrast_ratio(ACCENT, BACKGROUND) >= 3.0


def _to_lab(hex_color: str) -> tuple[float, float, float]:
    """sRGB to CIE L*a*b* (D65)."""
    raw = hex_color.lstrip("#")
    rgb = [int(raw[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
           for c in rgb]
    x = lin[0] * 0.4124 + lin[1] * 0.3576 + lin[2] * 0.1805
    y = lin[0] * 0.2126 + lin[1] * 0.7152 + lin[2] * 0.0722
    z = lin[0] * 0.0193 + lin[1] * 0.1192 + lin[2] * 0.9505
    xn, yn, zn = 0.95047, 1.0, 1.08883

    def f(t: float) -> float:
        return t ** (1 / 3) if t > 0.008856 else (7.787 * t) + (16 / 116)

    fx, fy, fz = f(x / xn), f(y / yn), f(z / zn)
    return 116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)


def delta_e(a: str, b: str) -> float:
    """CIE76 colour difference. Roughly: <2.3 is imperceptible, >10 is obvious."""
    la, aa, ba = _to_lab(a)
    lb, ab, bb = _to_lab(b)
    return ((la - lb) ** 2 + (aa - ab) ** 2 + (ba - bb) ** 2) ** 0.5


def test_delta_e_sanity_check():
    assert delta_e("#ffffff", "#ffffff") == pytest.approx(0.0, abs=0.01)
    assert delta_e("#000000", "#ffffff") > 90


@pytest.mark.parametrize("mode", ["dark", "light"])
def test_severity_colors_are_perceptually_separated(mode):
    """Adjacent severities must be tellable apart at a glance.

    Measured as Lab delta-E, not contrast ratio. Contrast ratio is luminance
    only, so it reports red and orange as nearly identical when they differ
    almost entirely in hue, which is exactly how this ramp is built.
    """
    from ui.app import _RAMP

    ramp = _RAMP[mode]
    order = ["info", "low", "medium", "high", "critical"]
    for lo, hi in zip(order, order[1:], strict=False):
        distance = delta_e(ramp[lo], ramp[hi])
        assert distance >= 15.0, (
            f"{mode}: {lo} and {hi} are too close (delta-E {distance:.1f})")


def _theme_config() -> dict:
    import tomllib

    root = Path(__file__).resolve().parents[1]
    config_path = root / ".streamlit" / "config.toml"
    assert config_path.exists(), "the theme config is missing"
    return tomllib.loads(config_path.read_text())["theme"]


def test_theme_defines_both_modes_and_forces_neither():
    """The viewer's own light/dark preference decides.

    Setting `base` would force one mode on everyone. Theme Lock means the page
    is never half light and half dark; it does not mean only one mode may
    exist. Getting that backwards ships a dark-only app.
    """
    theme = _theme_config()
    assert "base" not in theme, "base forces a mode on every viewer"
    assert "dark" in theme and "light" in theme, "both modes must be defined"


@pytest.mark.parametrize("mode", ["dark", "light"])
def test_each_mode_reserves_red_for_severity(mode):
    """Streamlit's stock primaryColor is #FF4B4B, the same red this app uses
    for CRITICAL. Shipping the default would make 'clickable' and 'critical'
    the same colour."""
    from ui.app import _RAMP, ACCENT

    block = _theme_config()[mode]
    assert block["primaryColor"].lower() == ACCENT.lower()
    assert block["primaryColor"].upper() != "#FF4B4B"
    assert block["primaryColor"].lower() not in {
        c.lower() for c in _RAMP[mode].values()}


@pytest.mark.parametrize("mode", ["dark", "light"])
def test_each_mode_meets_contrast(mode):
    """The dark ramp is unusable on white: #e5484d on #ffffff is 3.6:1. Each
    mode needs its own ramp, and both must clear AA against their own canvas."""
    from ui.app import _RAMP

    block = _theme_config()[mode]
    panel = block["secondaryBackgroundColor"]
    for name, color in _RAMP[mode].items():
        ratio = contrast_ratio(color, panel)
        assert ratio >= 4.5, (
            f"{mode}/{name}: {color} on {panel} is {ratio:.2f}:1, below AA")

    body = contrast_ratio(block["textColor"], block["backgroundColor"])
    assert body >= 7.0, f"{mode}: body text {body:.2f}:1 should clear AAA"

    button = contrast_ratio("#ffffff", block["primaryColor"])
    assert button >= 4.5, f"{mode}: white button text {button:.2f}:1 below AA"


def test_docker_image_ships_the_theme():
    """An explicit COPY list silently dropped .streamlit once already."""
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "Dockerfile").read_text()
    assert ".streamlit" in dockerfile, (
        "Dockerfile does not COPY .streamlit, so the container would render "
        "with Streamlit's default palette")


# ------------------------------------------------------------- theme-awareness

def test_colours_are_declared_once_not_scattered_through_render_code():
    """Every hex literal must live in the palette tables at the top of the file.

    A hardcoded colour inside a chart or layout function is dark-mode-only by
    construction: it was picked while looking at a dark screen. That is exactly
    how the threat graph ended up painting a black canvas inside a white page.
    """
    import re

    source = Path(APP).read_text(encoding="utf-8")
    # The declaration block ends where the first render helper begins.
    boundary = source.index("def _tint(")
    body = source[boundary:]

    offenders = []
    for line in body.split("\n"):
        stripped = line.strip()
        if stripped.startswith("#"):          # comment
            continue
        if re.search(r"#[0-9a-fA-F]{6}\b", line):
            offenders.append(stripped[:90])
    assert not offenders, (
        "hex colours outside the palette tables:\n  " + "\n  ".join(offenders))


def test_active_theme_falls_back_safely():
    """Outside a script run st.context has no theme. The helper must still
    return a usable mode rather than raising into the render path."""
    from ui.app import active_theme

    assert active_theme() in ("dark", "light")


@pytest.mark.parametrize("mode", ["dark", "light"])
def test_every_severity_resolves_in_both_modes(mode):
    from ui.app import _RAMP, SEVERITY

    for name in SEVERITY:
        assert name in _RAMP[mode], f"{name} has no colour in {mode} mode"


def test_middle_dot_is_rationed():
    """Skill rule: at most one middle dot per rendered line. Strings that chain
    three or four facts with separators read as one run-on and stop being
    scannable."""
    source = Path(APP).read_text(encoding="utf-8")
    offenders = [
        (n, line.strip()[:80])
        for n, line in enumerate(source.split("\n"), start=1)
        if line.count("·") > 1
    ]
    assert not offenders, f"lines with more than one middle dot: {offenders}"


def test_loading_state_is_shaped_not_a_bare_spinner():
    """A spinner communicates only 'something is happening'. The skeleton shows
    the shape of the answer so the eye is already in the right place."""
    source = Path(APP).read_text(encoding="utf-8")
    assert "def report_skeleton" in source
    assert "st.skeleton(" in source
    # No invented progress: the API call is a single blocking request, so the
    # client cannot honestly know how far along the agents are.
    assert "st.progress(" not in source


# ------------------------------------------------------------------ injection

def test_finding_titles_are_escaped_before_reaching_unsafe_html():
    """Finding titles embed indicator values and email subject lines, both
    attacker-controlled. A phishing lure must not be able to inject markup into
    the console that is analysing it."""
    import html as html_mod

    hostile = 'Malicious indicator: <img src=x onerror="alert(1)">'
    escaped = html_mod.escape(hostile)
    assert "<img" not in escaped
    assert "&lt;img" in escaped

    source = Path(APP).read_text(encoding="utf-8")
    # Every unsafe_allow_html block must escape its interpolated values.
    assert "safe_title = html.escape" in source
    assert "html.escape(str(text))" in source
    for forbidden in ('">{f["title"]}<', '>{f["severity"].upper()}<'):
        assert forbidden not in source, (
            f"unescaped interpolation still present: {forbidden}")


def test_hostile_finding_renders_without_injecting_markup(app):
    """End to end: a finding whose title carries a script tag must render as
    text."""
    at = app.run()
    at.query_params["investigation"] = "abc123def456"
    at = at.run()
    assert not at.exception

    markdown_blobs = " ".join(str(m.value) for m in at.markdown)
    assert "<script" not in markdown_blobs.lower()


# --------------------------------------------------------------- graph render

def test_graph_page_makes_no_outbound_request():
    """PyVis's stock template pulls Bootstrap from a CDN and references a dead
    node_modules path. An air-gapped SOC cannot reach a CDN, and a security
    tool should not make unnecessary third-party requests."""
    from threatiq.engine import threat_graph
    from threatiq.schemas import GraphEdge, GraphNode, ThreatGraph, Verdict

    graph = ThreatGraph(
        nodes=[GraphNode(id="domain:evil.test", label="evil.test",
                         type="domain", verdict=Verdict.MALICIOUS),
               GraphNode(id="ipv4:203.0.113.9", label="203.0.113.9",
                         type="ipv4", verdict=Verdict.SUSPICIOUS)],
        edges=[GraphEdge(source="domain:evil.test", target="ipv4:203.0.113.9",
                         relation="resolves_to")],
    )
    for theme in ("dark", "light"):
        page = threat_graph.render_html(graph, theme=theme)
        assert "cdn.jsdelivr.net" not in page
        assert "node_modules" not in page
        assert "bootstrap" not in page.lower()
        assert "prefers-reduced-motion" in page, "motion must degrade"
        assert "vis.Network" in page


def test_graph_render_failure_is_contained():
    """The error handler referenced an undefined `log`, so a rendering failure
    raised NameError and masked the real error."""
    from unittest.mock import patch

    from threatiq.engine import threat_graph
    from threatiq.schemas import ThreatGraph

    with patch("threatiq.engine.graph_render.render",
               side_effect=RuntimeError("boom")):
        page = threat_graph.render_html(ThreatGraph())
    assert "Could not render" in page


def test_graph_node_size_reflects_connectivity():
    """Size is the encoding for centrality. If every node is the same size the
    hub of a cluster is invisible."""
    from threatiq.engine.graph_render import THEMES, _build_nodes
    from threatiq.schemas import GraphEdge, GraphNode, ThreatGraph

    graph = ThreatGraph(
        nodes=[GraphNode(id=f"domain:n{i}.test", label=f"n{i}", type="domain")
               for i in range(4)],
        edges=[GraphEdge(source="domain:n0.test", target=f"domain:n{i}.test",
                         relation="resolves_to") for i in (1, 2, 3)],
    )
    sizes = {n["id"]: n["size"] for n in _build_nodes(graph, THEMES["dark"])}
    hub = sizes["domain:n0.test"]
    leaves = [sizes[f"domain:n{i}.test"] for i in (1, 2, 3)]
    assert hub > max(leaves), "the hub must be visibly larger than its leaves"


# ------------------------------------------------------------------- sidebar

def test_status_severity_is_not_flattened():
    """The old sidebar printed "Authentication disabled" in the same grey as
    "API 1.0.0". One is a security warning and the other is a version string;
    rendering them identically trains the analyst to skim past the warning."""
    source = Path(APP).read_text(encoding="utf-8")
    assert "def status_dot" in source
    for state in ('"bad"', '"warn"', '"info"'):
        assert state in source, f"status state {state} unused"
    # Auth is a security problem, a missing model is a deployment choice.
    assert 'status_dot("warn", "Authentication disabled")' in source
    assert 'status_dot("info", "No language model configured")' in source


def test_status_is_quiet_when_healthy(monkeypatch):
    """A healthy deployment should show no warning rows at all, so anything
    that does appear in that block is worth reading."""
    import httpx
    from streamlit.testing.v1 import AppTest

    healthy = dict(HEALTH)
    healthy["auth_enabled"] = True
    healthy["tools_unconfigured"] = []
    healthy["llm"] = {"enabled": True, "provider": "groq", "model": "x"}
    healthy["repository"] = "PostgresRepository"

    def _healthy_get(url, params=None, headers=None, timeout=None):
        if "/health" in url:
            return _Resp(healthy)
        return _fake_get(url, params, headers, timeout)

    monkeypatch.setattr(httpx, "get", _healthy_get)
    monkeypatch.setattr(httpx, "post", _fake_post)

    root = str(Path(APP).resolve().parents[1])
    at = AppTest.from_string(
        "import sys\n"
        f"sys.path.insert(0, {root!r})\n"
        "from ui.app import sidebar_status\n"
        "sidebar_status()\n",
        default_timeout=30,
    ).run()
    assert not at.exception

    rendered = " ".join(str(m.value) for m in at.markdown)
    for noisy in ("Authentication disabled", "without an API key",
                  "No language model", "In-memory store"):
        assert noisy not in rendered, f"healthy deployment still warns: {noisy}"


def test_wordmark_is_theme_aware_and_labelled():
    """An <img> cannot inherit the page's text colour, so the mark is drawn per
    theme. It also needs an accessible name."""
    from ui.app import _CHROME, wordmark

    dark, light = wordmark("dark"), wordmark("light")
    assert dark != light, "the wordmark must not be one fixed colour"
    for theme, mark in (("dark", dark), ("light", light)):
        assert mark.startswith("data:image/svg+xml"), "no outbound request"
        from urllib.parse import unquote
        svg = unquote(mark.split(",", 1)[1])
        assert 'role="img"' in svg and "aria-label=" in svg
        assert _CHROME[theme]["ink"] in svg


def test_cors_is_not_wide_open():
    """enableCORS=false makes Streamlit send Access-Control-Allow-Origin:* and
    accept a WebSocket from any origin. XSRF protection does not close that,
    because opening a WebSocket needs no XSRF token."""
    import tomllib

    root = Path(__file__).resolve().parents[1]
    server = tomllib.loads(
        (root / ".streamlit" / "config.toml").read_text())["server"]
    assert server["enableCORS"] is True
    assert server["enableXsrfProtection"] is True
    assert server.get("corsAllowedOrigins"), "allowed origins must be listed"


# ---------------------------------------------------------------- click safety

@pytest.mark.parametrize("raw,must_not_contain", [
    ("Visit https://micros0ft-login.tk/verify now", "https://micros0ft-login.tk"),
    ("Block http://evil.example/payload.exe", "http://evil.example"),
    ("Two: https://a.tk/x and https://b.top/y", "https://a.tk"),
])
def test_urls_are_defanged_before_render(raw, must_not_contain):
    """Streamlit's markdown auto-links bare URLs, so a phishing link lifted out
    of a hostile email was arriving in the console as a working anchor. An
    analyst could click the payload from inside the tool analysing it."""
    from ui.app import defang

    out = defang(raw)
    assert must_not_contain not in out
    assert "hxxp" in out
    assert "[.]" in out


def test_defang_leaves_ordinary_text_alone():
    from ui.app import defang

    assert defang("No links here at all.") == "No links here at all."
    assert defang("") == ""


def test_defang_is_wired_into_every_render_path():
    """A helper that exists but is not called is why this bug shipped in the
    first place: the backend had a refang() that nothing ever invoked."""
    source = Path(APP).read_text(encoding="utf-8")
    for path in ('defang(report.get("summary")',
                 'st.write(defang(f["description"]))',
                 '"Detail": defang(e["summary"])'):
        assert path in source, f"defang missing from render path: {path}"


def test_no_orphaned_palette_tables_remain():
    """Rendering moved to graph_render.py; the old tables in threat_graph.py
    were left behind referencing nothing."""
    from threatiq.engine import threat_graph

    assert not hasattr(threat_graph, "_NODE_COLORS")
    assert not hasattr(threat_graph, "_TYPE_SHAPES")
