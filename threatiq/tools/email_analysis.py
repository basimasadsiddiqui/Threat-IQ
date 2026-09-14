"""Phishing / BEC analysis of a raw email message.

Everything here is header and text analysis with the stdlib `email` parser -
no API, no LLM. The LLM later *explains* these signals but never produces them.
"""
from __future__ import annotations

import re
from email import message_from_string, policy
from email.utils import parseaddr
from typing import Any

from threatiq.engine.indicators import extract_indicators, normalize_domain
from threatiq.schemas import Evidence, Severity, ToolStatus, Verdict
from threatiq.tools.base import ToolContext, registry, timed

# Weighted social-engineering patterns. Weights are additive into a 0..1 score.
_PRESSURE_PATTERNS: list[tuple[str, str, float]] = [
    (r"\b(?:verify|confirm|validate)\s+(?:your\s+)?(?:account|identity|password|email)", "credential verification request", 0.25),
    (r"\b(?:account|password|access|mailbox)\s+(?:will\s+be\s+)?(?:suspend|disabl|lock|clos|terminat|expir|delet)", "account termination threat", 0.25),
    (r"\b(?:within|in)\s+\d+\s*(?:hour|minute|day)s?\b", "artificial deadline", 0.15),
    (r"\b(?:urgent|immediate(?:ly)?|action\s+required|final\s+(?:notice|warning)|last\s+chance)\b", "urgency language", 0.15),
    (r"\b(?:click|tap)\s+(?:here|below|the\s+link)\b", "generic call to action", 0.10),
    (r"\b(?:unusual|suspicious)\s+(?:activity|sign[- ]?in|login)", "fake security alert", 0.20),
    (r"\bwire\s+transfer|\bbank\s+details|\bchange\s+(?:of\s+)?bank|\bupdate\s+(?:the\s+)?payment", "payment redirection (BEC)", 0.30),
    (r"\b(?:invoice|payment)\s+(?:is\s+)?(?:overdue|attached|pending)", "invoice lure", 0.15),
    (r"\b(?:gift\s+card|itunes\s+card|bitcoin|crypto(?:currency)?\s+payment)", "gift-card / crypto fraud", 0.30),
    (r"\bare\s+you\s+(?:available|at\s+your\s+desk)\b|\bquick\s+(?:favou?r|task)\b", "BEC pretext opener", 0.25),
    (r"\bdo\s+not\s+(?:tell|inform|discuss)\b|\bkeep\s+this\s+confidential\b", "secrecy request (BEC)", 0.25),
    (r"\b(?:reset|change)\s+your\s+password\s+(?:now|immediately)", "password reset lure", 0.20),
    (r"\bsent\s+from\s+my\s+(?:iphone|mobile)\b.{0,40}\bplease\s+reply\b", "mobile-pretext reply bait", 0.10),
]

_AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.I)


def _extract_display_name_spoof(from_header: str, envelope_domain: str) -> dict[str, Any] | None:
    """Detect `"IT Support" <attacker@gmail.com>`, display name claims one
    organisation while the actual address belongs to another."""
    display, address = parseaddr(from_header)
    if not display or not address or "@" not in address:
        return None
    actual_domain = normalize_domain(address.split("@", 1)[1])
    # Does the display name itself contain a domain-looking token or brand word?
    claimed = re.findall(r"[A-Za-z0-9-]+\.[A-Za-z]{2,}", display)
    for candidate in claimed:
        candidate_domain = normalize_domain(candidate)
        if candidate_domain and candidate_domain != actual_domain:
            return {"display_claims": candidate_domain, "actual_domain": actual_domain}
    if envelope_domain and envelope_domain != actual_domain:
        return {"envelope_domain": envelope_domain, "actual_domain": actual_domain}
    return None


def analyze_email(raw: str) -> dict[str, Any]:
    """Parse an RFC822 message (or best-effort plain text) into signals."""
    try:
        msg = message_from_string(raw, policy=policy.default)
    except Exception:
        msg = None

    headers: dict[str, str] = {}
    body = raw
    if msg is not None:
        headers = {k.lower(): str(v) for k, v in msg.items()}
        try:
            part = msg.get_body(preferencelist=("plain", "html"))
            if part is not None:
                body = part.get_content()
        except Exception:
            body = raw

    from_header = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    return_path = headers.get("return-path", "")
    subject = headers.get("subject", "")

    _, from_addr = parseaddr(from_header)
    _, reply_addr = parseaddr(reply_to)
    _, return_addr = parseaddr(return_path)

    from_domain = normalize_domain(from_addr.split("@", 1)[1]) if "@" in from_addr else ""
    reply_domain = normalize_domain(reply_addr.split("@", 1)[1]) if "@" in reply_addr else ""
    return_domain = normalize_domain(return_addr.split("@", 1)[1]) if "@" in return_addr else ""

    # Reply-To pointing somewhere other than From is the classic BEC tell.
    reply_to_mismatch = bool(reply_domain and from_domain and reply_domain != from_domain)
    return_path_mismatch = bool(return_domain and from_domain and return_domain != from_domain)

    auth: dict[str, str] = {}
    for header_name in ("authentication-results", "received-spf", "arc-authentication-results"):
        for mech, result in _AUTH_RESULT_RE.findall(headers.get(header_name, "")):
            auth.setdefault(mech.lower(), result.lower())

    auth_failures = [m for m, r in auth.items() if r in ("fail", "softfail", "none", "permerror")]

    haystack = f"{subject}\n{body}".lower()
    matched: list[str] = []
    pressure_score = 0.0
    for pattern, label, weight in _PRESSURE_PATTERNS:
        if re.search(pattern, haystack, re.I):
            matched.append(label)
            pressure_score += weight
    pressure_score = min(1.0, pressure_score)

    indicators = extract_indicators(body, source="email_body")
    urls = [i.value for i in indicators if i.type.value == "url"]
    link_domains = sorted({
        normalize_domain(re.sub(r"^https?://", "", u).split("/")[0].split(":")[0])
        for u in urls
    } - {""})

    # A link whose visible text is one domain but whose href is another.
    mismatched_links: list[dict[str, str]] = []
    for text, href in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                                 body, re.I | re.S):
        href_domain = normalize_domain(
            re.sub(r"^https?://", "", text).split("/")[0].split(":")[0]
        )
        shown = re.sub(r"<[^>]+>", "", href).strip()
        shown_domains = re.findall(r"[A-Za-z0-9-]+\.[A-Za-z]{2,}", shown)
        for shown_domain in shown_domains:
            if normalize_domain(shown_domain) != href_domain and href_domain:
                mismatched_links.append({"displayed": shown_domain, "actual": href_domain})

    attachments: list[str] = []
    if msg is not None:
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
    risky_attachments = [
        a for a in attachments
        if a.lower().endswith((".exe", ".scr", ".js", ".vbs", ".jar", ".iso",
                               ".img", ".lnk", ".hta", ".ps1", ".docm", ".xlsm",
                               ".zip", ".rar", ".7z", ".html", ".htm"))
    ]

    return {
        "from": from_addr,
        "from_domain": from_domain,
        "reply_to": reply_addr,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_domain,
        "subject": subject,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "auth_results": auth,
        "auth_failures": auth_failures,
        "pressure_score": round(pressure_score, 2),
        "social_engineering_patterns": matched,
        "urls": urls[:25],
        "link_domains": link_domains[:25],
        "mismatched_links": mismatched_links[:10],
        "attachments": attachments[:20],
        "risky_attachments": risky_attachments,
        "display_name_spoof": _extract_display_name_spoof(from_header, return_domain),
        "has_headers": bool(headers),
        "indicator_count": len(indicators),
    }


@registry.register(
    "email_analyze",
    description="Analyze raw email headers and body for phishing/BEC indicators.",
    accepts=["email_message"],
)
@timed("email", "analyze")
async def email_analyze(ctx: ToolContext, raw: str) -> Evidence:
    a = analyze_email(raw)

    # Weighted composite. Header-level spoofing is worth more than wording,
    # because wording alone produces false positives on legitimate IT notices.
    score = 0.0
    reasons: list[str] = []
    if a["reply_to_mismatch"]:
        score += 0.3
        reasons.append(
            f"Reply-To domain ({a['reply_to_domain']}) differs from "
            f"From domain ({a['from_domain']})"
        )
    if a["return_path_mismatch"]:
        score += 0.2
        reasons.append(
            f"Return-Path domain ({a['return_path_domain']}) differs from From domain"
        )
    if a["auth_failures"]:
        score += 0.25
        reasons.append(f"email authentication failed: {', '.join(a['auth_failures'])}")
    if a["display_name_spoof"]:
        score += 0.25
        reasons.append("display name impersonates a different organisation")
    if a["mismatched_links"]:
        score += 0.25
        reasons.append(f"{len(a['mismatched_links'])} link(s) display one domain but point to another")
    if a["risky_attachments"]:
        score += 0.2
        reasons.append(f"high-risk attachment(s): {', '.join(a['risky_attachments'][:3])}")
    score += a["pressure_score"] * 0.4
    if a["social_engineering_patterns"]:
        reasons.append("social-engineering patterns: " + ", ".join(a["social_engineering_patterns"]))
    score = min(1.0, score)

    if score >= 0.7:
        verdict, severity, confidence = Verdict.MALICIOUS, Severity.CRITICAL, 0.85
    elif score >= 0.45:
        verdict, severity, confidence = Verdict.SUSPICIOUS, Severity.HIGH, 0.7
    elif score >= 0.2:
        verdict, severity, confidence = Verdict.SUSPICIOUS, Severity.MEDIUM, 0.55
    else:
        verdict, severity, confidence = Verdict.BENIGN, Severity.INFO, 0.5

    a["phishing_score"] = round(score, 2)
    summary = (
        f"Email phishing score {score:.2f}: " + "; ".join(reasons)
        if reasons else "Email shows no strong phishing indicators"
    )

    return Evidence(
        source="email", tool="analyze", indicator="email_message:submitted",
        status=ToolStatus.OK, verdict=verdict, severity_hint=severity,
        confidence=confidence, summary=summary, signals=a,
    )
