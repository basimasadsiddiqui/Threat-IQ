"""Passive HTTP inspection: redirect chain and security headers.

SSRF is the real hazard here, the target URL is attacker-controlled by
definition. Every hop is re-validated against private address space before the
request is made, and redirects are followed manually so no hop escapes the check.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

from threatiq.engine.indicators import is_private_ip
from threatiq.schemas import Evidence, Severity, ToolStatus, Verdict
from threatiq.tools.base import ToolContext, failed, registry, timed

MAX_REDIRECTS = 8

# Headers whose absence is a real finding, with the risk each one mitigates.
SECURITY_HEADERS = {
    "strict-transport-security": "downgrade / SSL-stripping attacks",
    "content-security-policy": "cross-site scripting (XSS)",
    "x-content-type-options": "MIME-type confusion",
    "x-frame-options": "clickjacking",
    "referrer-policy": "referrer leakage",
    "permissions-policy": "unwanted browser feature access",
}

# Shorteners hide the real destination; a chain through one is worth flagging.
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in",
}


async def _resolves_to_public_ip(host: str) -> tuple[bool, list[str]]:
    """Reject the request unless every resolved address is publicly routable."""
    try:
        ipaddress.ip_address(host)
        return (not is_private_ip(host)), [host]
    except ValueError:
        pass
    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM
        )
    except (socket.gaierror, UnicodeError):
        return False, []
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        return False, []
    return all(not is_private_ip(addr) for addr in addresses), addresses


@registry.register(
    "http_probe",
    description="Follow a URL's redirect chain and inspect its security headers.",
    accepts=["url"],
)
@timed("http", "probe")
async def http_probe(ctx: ToolContext, url: str) -> Evidence:
    indicator = f"url:{url.lower()}"
    assert ctx.client is not None

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return Evidence(
            source="http", tool="probe", indicator=indicator,
            status=ToolStatus.REFUSED, confidence=0.0,
            summary=f"Refusing to fetch non-HTTP scheme '{parsed.scheme}'",
        )

    chain: list[dict[str, object]] = []
    shortener_used = False
    current = url
    final_response = None

    for hop in range(MAX_REDIRECTS + 1):
        host = (urlparse(current).hostname or "").lower()
        if not host:
            break
        if host in _SHORTENERS:
            shortener_used = True

        public, addresses = await _resolves_to_public_ip(host)
        if not public:
            return Evidence(
                source="http", tool="probe", indicator=indicator,
                status=ToolStatus.REFUSED, confidence=0.0,
                summary=(f"Refusing to fetch {host}: it resolves to a private or "
                         f"non-routable address ({', '.join(addresses) or 'unresolvable'})"),
                signals={"ssrf_guard_triggered": True, "host": host,
                         "addresses": addresses, "redirect_chain": chain},
            )

        try:
            resp = await ctx.get(current, follow_redirects=False)
        except Exception as exc:
            return Evidence(
                source="http", tool="probe", indicator=indicator,
                status=ToolStatus.ERROR, confidence=0.3,
                summary=f"Could not reach {current}: {type(exc).__name__}",
                error=str(exc)[:300],
                signals={"redirect_chain": chain, "reachable": False},
            )

        chain.append({
            "url": current, "status": resp.status_code,
            "host": host, "addresses": addresses,
        })
        final_response = resp

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if not location or hop == MAX_REDIRECTS:
                break
            current = urljoin(current, location)
            continue
        break

    if final_response is None:
        return failed("http", "probe", indicator, "no response received")

    headers = {k.lower(): v for k, v in final_response.headers.items()}
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    present = [h for h in SECURITY_HEADERS if h in headers]

    final_url = str(chain[-1]["url"]) if chain else url
    final_host = (urlparse(final_url).hostname or "").lower()
    start_host = (urlparse(url).hostname or "").lower()
    cross_domain_redirect = bool(chain) and final_host != start_host

    # Redirects that cross domains, hide behind shorteners, or downgrade to
    # plaintext are the patterns phishing kits rely on.
    downgraded = url.startswith("https://") and final_url.startswith("http://")

    severity, verdict = Severity.INFO, Verdict.UNKNOWN
    notes = [f"{len(chain)} hop(s), final status {final_response.status_code}"]
    if cross_domain_redirect:
        notes.append(f"redirects across domains ({start_host} -> {final_host})")
        severity, verdict = Severity.MEDIUM, Verdict.SUSPICIOUS
    if shortener_used:
        notes.append("chain passes through a URL shortener")
        severity, verdict = Severity.MEDIUM, Verdict.SUSPICIOUS
    if downgraded:
        notes.append("downgrades from HTTPS to HTTP")
        severity, verdict = Severity.HIGH, Verdict.SUSPICIOUS
    if len(chain) > 3:
        notes.append("unusually long redirect chain")
        severity = max(severity, Severity.MEDIUM, key=lambda s: s.rank)
    if missing:
        notes.append(f"{len(missing)} security header(s) missing")

    return Evidence(
        source="http", tool="probe", indicator=indicator,
        status=ToolStatus.OK, verdict=verdict, severity_hint=severity,
        confidence=0.8, summary=f"{url}: " + "; ".join(notes),
        signals={
            "redirect_chain": chain,
            "redirect_count": max(0, len(chain) - 1),
            "final_url": final_url,
            "final_status": final_response.status_code,
            "cross_domain_redirect": cross_domain_redirect,
            "shortener_used": shortener_used,
            "https_downgrade": downgraded,
            "missing_security_headers": missing,
            "present_security_headers": present,
            "server": headers.get("server", ""),
            "content_type": headers.get("content-type", ""),
        },
        raw={"headers": dict(list(headers.items())[:40])},
    )
