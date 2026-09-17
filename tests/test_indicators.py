import pytest

from threatiq.engine.indicators import (
    classify_input,
    defang,
    extract_indicators,
    is_private_ip,
    strip_infrastructure_headers,
)
from threatiq.schemas import IndicatorType, InputKind


@pytest.mark.parametrize("text,expected", [
    ("https://micros0ft-login.com/verify", InputKind.URL),
    ("hxxps://evil[.]com/a", InputKind.URL),
    ("185.220.101.5", InputKind.IP),
    ("CVE-2024-3400", InputKind.CVE),
    ("paypa1.com", InputKind.DOMAIN),
    ("d41d8cd98f00b204e9800998ecf8427e", InputKind.FILE_HASH),
])
def test_classify_single_token(text, expected):
    assert classify_input(text) is expected


def test_classify_email_needs_two_headers():
    assert classify_input("From: a@b.com\nSubject: x\nReceived: y\n\nbody") \
        is InputKind.EMAIL_MESSAGE
    # A lone From: line in a sentence is not a message.
    assert classify_input("From: the docs") is not InputKind.EMAIL_MESSAGE


def test_defang_roundtrip():
    assert defang("hxxps://evil[.]com") == "https://evil.com"
    assert defang("a[at]b[dot]com") == "a@b.com"


def test_extract_deduplicates_and_pivots_email_domain():
    iocs = extract_indicators("mail bad@evil.tk and bad@evil.tk")
    values = {(i.type, i.value) for i in iocs}
    assert (IndicatorType.EMAIL, "bad@evil.tk") in values
    # The sending domain is promoted to its own indicator.
    assert (IndicatorType.DOMAIN, "evil.tk") in values
    assert len([i for i in iocs if i.type is IndicatorType.EMAIL]) == 1


def test_cve_keeps_uppercase():
    iocs = extract_indicators("see cve-2024-1086 for details")
    assert [i.value for i in iocs if i.type is IndicatorType.CVE] == ["CVE-2024-1086"]


def test_private_ips_are_never_extracted():
    iocs = extract_indicators("internal 192.168.1.5 and 127.0.0.1 and 8.8.8.8")
    ips = {i.value for i in iocs if i.type is IndicatorType.IPV4}
    assert ips == {"8.8.8.8"}


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.1", "127.0.0.1",
                                "169.254.169.254", "172.16.0.1", "::1"])
def test_private_ip_detection(ip):
    assert is_private_ip(ip)


def test_file_extensions_are_not_domains():
    iocs = extract_indicators("open report.pdf and image.png")
    assert not [i for i in iocs if i.type is IndicatorType.DOMAIN]


def test_strip_infrastructure_headers_drops_folded_continuations():
    raw = (
        "From: a@sender.tk\n"
        "Authentication-Results: mx.victim.com; spf=fail\n"
        "\tdmarc=fail header.from=leaked.com\n"
        "Subject: hi\n"
        "\n"
        "body https://payload.tk/x\n"
    )
    cleaned = strip_infrastructure_headers(raw)
    assert "mx.victim.com" not in cleaned
    assert "leaked.com" not in cleaned      # folded line must go too
    assert "payload.tk" in cleaned
    assert "sender.tk" in cleaned
