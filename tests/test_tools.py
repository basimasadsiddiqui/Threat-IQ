import pytest

from threatiq.agents.websec import is_authorized
from threatiq.llm import parse_json_object
from threatiq.schemas import Verdict
from threatiq.tools.base import verdict_from_ratio
from threatiq.tools.email_analysis import analyze_email
from threatiq.tools.lookalike import analyze_domain


# ----------------------------------------------------- brand impersonation

@pytest.mark.parametrize("domain,brand", [
    ("paypa1.com", "paypal"),
    ("gmai1.com", "gmail"),
    ("micros0ft-login.com", "microsoft"),
    ("secure-login-microsoft-verify.tk", "microsoft"),
])
def test_detects_impersonation(domain, brand):
    result = analyze_domain(domain)
    assert result["matched_brand"] == brand
    assert result["score"] >= 0.5


@pytest.mark.parametrize("domain", [
    "microsoft.com", "google.com", "example.org", "wikipedia.org",
    "github.com", "python.org",
])
def test_no_false_positives_on_legitimate_domains(domain):
    assert analyze_domain(domain)["score"] == 0.0


def test_real_brand_is_not_a_typosquat_of_a_neighbouring_brand():
    """github.com and gitlab.com are 2 edits apart; neither impersonates the
    other, and edit distance alone cannot tell them apart."""
    for domain in ("github.com", "gitlab.com"):
        assert analyze_domain(domain)["score"] == 0.0


@pytest.mark.parametrize("domain", [
    "bbc.co.uk", "paypal.co.uk", "hsbc.com.au", "google.co.jp", "amazon.co.uk",
])
def test_regional_brand_domains_are_not_flagged(domain):
    """Multi-part ccTLDs must resolve through the public suffix list, a naive
    split reads paypal.co.uk as the brand on the suspicious TLD 'co'."""
    assert analyze_domain(domain)["score"] == 0.0


def test_subdomain_brand_lure_is_detected():
    """login.microsoft.evil.com is registered to evil.com, not Microsoft."""
    result = analyze_domain("login.microsoft.evil.com")
    assert result["matched_brand"] == "microsoft"
    assert result["score"] >= 0.5


def test_registrable_label_handles_multi_part_suffixes():
    from threatiq.tools.lookalike import _registrable_label
    assert _registrable_label("bbc.co.uk") == ("bbc", "co.uk")
    assert _registrable_label("foo.bar.com") == ("bar", "com")
    assert _registrable_label("example.org") == ("example", "org")


def test_real_brand_on_throwaway_tld_is_flagged_as_abuse():
    result = analyze_domain("paypal.zip")
    assert result["technique"] == "brand_tld_abuse"
    assert result["score"] >= 0.5


def test_homoglyph_domain_is_flagged():
    result = analyze_domain("аpple.com")   # Cyrillic 'а'
    assert result["non_ascii"] is True
    assert result["score"] >= 0.5


def test_lure_tokens_detected():
    result = analyze_domain("account-verify-secure.tk")
    assert set(result["lure_tokens"]) >= {"verify", "secure", "account"}


# ----------------------------------------------------------- email analysis

PHISH = """From: "Microsoft Account Team" <security@micros0ft-alerts.tk>
Reply-To: recovery@mailbox-secure.top
Return-Path: <bounce@spam-relay.ru>
Subject: Urgent: Your account will be suspended
Authentication-Results: mx.corp.com; spf=fail dkim=none dmarc=fail

Unusual sign-in activity. Your account will be suspended within 24 hours.
Verify your identity immediately: https://micros0ft-login.tk/verify
"""

BENIGN = """From: notifications@github.com
To: dev@corp.com
Subject: Your weekly digest
Authentication-Results: mx.corp.com; spf=pass dkim=pass dmarc=pass

Here is a summary of activity in repositories you watch this week.
"""


def test_phishing_email_signals():
    a = analyze_email(PHISH)
    assert a["reply_to_mismatch"] is True
    assert a["return_path_mismatch"] is True
    assert set(a["auth_failures"]) == {"spf", "dkim", "dmarc"}
    assert a["pressure_score"] >= 0.5
    assert "micros0ft-login.tk" in a["link_domains"]


def test_benign_email_scores_low():
    a = analyze_email(BENIGN)
    assert a["reply_to_mismatch"] is False
    assert a["auth_failures"] == []
    assert a["pressure_score"] <= 0.2


def test_bec_patterns_detected():
    bec = ("From: ceo@gmail.com\nSubject: Quick favour\n\n"
           "Are you at your desk? Process an urgent wire transfer and update "
           "the payment bank details. Keep this confidential.")
    a = analyze_email(bec)
    labels = a["social_engineering_patterns"]
    assert any("BEC" in label for label in labels)


# --------------------------------------------------------- scan authorization

@pytest.mark.parametrize("target,expected", [
    ("https://example.com/path", True),
    ("https://api.example.com", True),
    ("example.com", True),
    ("https://evil-example.com", False),      # substring must not match
    ("https://notexample.com", False),
    ("example.com.attacker.net", False),      # suffix must not match
    ("https://other.org", False),
])
def test_scan_authorization_has_no_bypass(target, expected):
    assert is_authorized(target, {"example.com"}) is expected


def test_empty_authorization_list_refuses_everything():
    assert is_authorized("https://example.com", set()) is False


# ------------------------------------------------------------- shared scoring

@pytest.mark.parametrize("malicious,total,expected", [
    (0, 90, Verdict.BENIGN),
    (1, 90, Verdict.SUSPICIOUS),
    (3, 90, Verdict.SUSPICIOUS),
    (12, 90, Verdict.MALICIOUS),
    (0, 0, Verdict.UNKNOWN),
])
def test_verdict_from_ratio(malicious, total, expected):
    verdict, _, _ = verdict_from_ratio(malicious, total)
    assert verdict is expected


# ------------------------------------------------------------- llm json parse

@pytest.mark.parametrize("text,expected", [
    ('{"a": 1}', {"a": 1}),
    ('```json\n{"b": [1,2]}\n```', {"b": [1, 2]}),
    ('Sure! {"c": "x"} hope that helps', {"c": "x"}),
    ('{"d": 1,}', {"d": 1}),                       # trailing comma
    ('{"e": "a } brace in a string"}', {"e": "a } brace in a string"}),
    ("not json at all", None),
    ('[1,2,3]', None),                             # arrays are not objects
])
def test_parse_json_object(text, expected):
    assert parse_json_object(text) == expected
