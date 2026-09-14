"""IOC extraction, normalization and input classification.

Deliberately regex + stdlib based: classification must be deterministic and
free, because it runs before any LLM or paid API call.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from threatiq.schemas import Indicator, IndicatorType, InputKind

# Defanged IOCs are the norm in threat reports and phishing tickets.
_DEFANG = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}", re.I), "."),
    (re.compile(r"\[:\]|\(:\)", re.I), ":"),
    (re.compile(r"\bhxxp(s?)\b", re.I), r"http\1"),
    (re.compile(r"\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\[dot\]|\(dot\)", re.I), "."),
]

URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\]\)]+", re.I)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.I)
EMAIL_RE = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.I)

# Email headers we trust enough to route on.
_HEADER_MARKERS = ("from:", "to:", "subject:", "received:", "return-path:",
                   "message-id:", "dkim-signature:", "authentication-results:")

# Extensions that look like a TLD in text but never are.
_FILE_EXT_FALSE_POSITIVES = {
    "png", "jpg", "jpeg", "gif", "pdf", "doc", "docx", "xls", "xlsx", "zip",
    "exe", "dll", "js", "css", "html", "htm", "php", "py", "json", "xml", "txt",
}


def defang(text: str) -> str:
    """Turn `hxxp://evil[.]com` back into something parseable."""
    for pattern, repl in _DEFANG:
        text = pattern.sub(repl, text)
    return text


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def ip_type(value: str) -> IndicatorType:
    return (
        IndicatorType.IPV6
        if ipaddress.ip_address(value).version == 6
        else IndicatorType.IPV4
    )


def is_private_ip(value: str) -> bool:
    """Private/loopback/link-local addresses must never be sent to public
    reputation APIs, and are also the SSRF vector for any active scanning."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("www."):
        value = value[4:]
    try:
        # IDN/punycode homograph domains must be compared in ASCII form.
        value = value.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass
    return value


def domain_of(url_or_host: str) -> str | None:
    candidate = url_or_host.strip()
    if "://" in candidate:
        candidate = urlparse(candidate).hostname or ""
    candidate = candidate.split("/")[0].split(":")[0]
    if not candidate or is_ip(candidate):
        return None
    return normalize_domain(candidate)


def _plausible_domain(value: str) -> bool:
    tld = value.rsplit(".", 1)[-1].lower()
    return tld not in _FILE_EXT_FALSE_POSITIVES and not tld.isdigit()


def classify_input(text: str) -> InputKind:
    """Decide which investigation branch the orchestrator should take."""
    raw = text.strip()
    lowered = raw.lower()

    header_hits = sum(1 for marker in _HEADER_MARKERS if marker in lowered)
    if header_hits >= 2 or (header_hits >= 1 and "\n" in raw and len(raw) > 120):
        return InputKind.EMAIL_MESSAGE

    cleaned = defang(raw)
    single_token = len(cleaned.split()) == 1

    if single_token:
        if CVE_RE.fullmatch(cleaned):
            return InputKind.CVE
        if HASH_RE.fullmatch(cleaned):
            return InputKind.FILE_HASH
        if is_ip(cleaned):
            return InputKind.IP
        if URL_RE.fullmatch(cleaned):
            return InputKind.URL
        if DOMAIN_RE.fullmatch(cleaned) and _plausible_domain(cleaned):
            return InputKind.DOMAIN

    # Multi-token text: fall back to whatever dominates.
    if CVE_RE.search(cleaned):
        return InputKind.CVE
    if EMAIL_RE.search(cleaned) and len(raw) > 200:
        return InputKind.EMAIL_MESSAGE
    if URL_RE.search(cleaned):
        return InputKind.URL
    return InputKind.FREE_TEXT


def extract_indicators(text: str, source: str = "user_input") -> list[Indicator]:
    """Pull every distinct IOC out of arbitrary text, de-duplicated."""
    cleaned = defang(text)
    found: dict[str, Indicator] = {}

    def add(itype: IndicatorType, value: str) -> None:
        value = value.strip().rstrip(".,;:)]}\"'")
        if not value:
            return
        if itype in (IndicatorType.DOMAIN,):
            value = normalize_domain(value)
            if not _plausible_domain(value):
                return
        elif itype in (IndicatorType.IPV4, IndicatorType.IPV6):
            if not is_ip(value) or is_private_ip(value):
                return
        elif itype == IndicatorType.CVE:
            value = value.upper()
        elif itype != IndicatorType.URL:
            value = value.lower()
        key = f"{itype.value}:{value.lower()}"
        if key not in found:
            found[key] = Indicator(type=itype, value=value, source=source)

    for match in CVE_RE.findall(cleaned):
        add(IndicatorType.CVE, match.upper())
    for match in HASH_RE.findall(cleaned):
        add(IndicatorType.FILE_HASH, match)
    for match in EMAIL_RE.findall(cleaned):
        add(IndicatorType.EMAIL, match)
        # The sending domain is independently investigable and is usually the
        # thing you actually block, so promote it to its own indicator.
        if "@" in match:
            add(IndicatorType.DOMAIN, match.split("@", 1)[1])

    urls = URL_RE.findall(cleaned)
    for url in urls:
        add(IndicatorType.URL, url)
        host = urlparse(url).hostname
        if host and is_ip(host):
            add(ip_type(host), host)
        elif host:
            add(IndicatorType.DOMAIN, host)

    # Strip what we already consumed so bare-IOC regexes don't re-match inside
    # URLs and email addresses.
    residue = cleaned
    for url in urls:
        residue = residue.replace(url, " ")
    for addr in EMAIL_RE.findall(cleaned):
        residue = residue.replace(addr, " ")

    for match in IPV4_RE.findall(residue):
        add(IndicatorType.IPV4, match)
    for match in IPV6_RE.findall(residue):
        if match.count(":") >= 2 and is_ip(match):
            add(IndicatorType.IPV6, match)
    for match in DOMAIN_RE.findall(residue):
        add(IndicatorType.DOMAIN, match)

    return list(found.values())


# Headers that describe the receiving/relaying infrastructure rather than the
# sender. Domains here belong to the victim's own mail path, so extracting them
# wastes lookups and pollutes the evidence set with unrelated verdicts.
_INFRASTRUCTURE_HEADERS = (
    "received:", "authentication-results:", "arc-authentication-results:",
    "arc-seal:", "arc-message-signature:", "received-spf:", "x-received:",
    "dkim-signature:", "x-ms-exchange-", "x-microsoft-antispam",
    "x-forefront-antispam-report:", "x-google-dkim-signature:",
    "x-originating-ip:", "x-spam-", "message-id:", "references:", "in-reply-to:",
)


def strip_infrastructure_headers(raw: str) -> str:
    """Drop mail-path headers before IOC extraction.

    Header folding means a header's continuation lines start with whitespace;
    those must be dropped with their parent or the domains inside them survive.
    """
    kept: list[str] = []
    dropping = False
    for line in raw.splitlines():
        lowered = line.lower()
        if line[:1].isspace():
            if dropping:
                continue          # folded continuation of a dropped header
            kept.append(line)
            continue
        if not line.strip():
            # Blank line ends the header block; everything after is the body.
            dropping = False
            kept.append(line)
            continue
        dropping = lowered.startswith(_INFRASTRUCTURE_HEADERS)
        if not dropping:
            kept.append(line)
    return "\n".join(kept)


def primary_indicator(indicators: list[Indicator], kind: InputKind) -> Indicator | None:
    """The IOC the investigation is *about*, as opposed to pivots."""
    preference = {
        InputKind.URL: [IndicatorType.URL, IndicatorType.DOMAIN],
        InputKind.DOMAIN: [IndicatorType.DOMAIN],
        InputKind.IP: [IndicatorType.IPV4, IndicatorType.IPV6],
        InputKind.EMAIL_MESSAGE: [IndicatorType.URL, IndicatorType.EMAIL,
                                  IndicatorType.DOMAIN],
        InputKind.FILE_HASH: [IndicatorType.FILE_HASH],
        InputKind.CVE: [IndicatorType.CVE],
        InputKind.WEB_TARGET: [IndicatorType.URL, IndicatorType.DOMAIN],
        InputKind.FREE_TEXT: [IndicatorType.URL, IndicatorType.DOMAIN,
                              IndicatorType.IPV4, IndicatorType.CVE],
    }[kind]
    for itype in preference:
        for ind in indicators:
            if ind.type == itype and ind.source == "user_input":
                return ind
    for itype in preference:
        for ind in indicators:
            if ind.type == itype:
                return ind
    return indicators[0] if indicators else None
