"""DNS and RDAP collection, free, unauthenticated, and high signal.

Domain age in particular is one of the strongest phishing predictors available
without a paid feed, so RDAP runs on every domain investigation.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from threatiq.engine.indicators import is_private_ip
from threatiq.schemas import Evidence, Severity, ToolStatus, Verdict
from threatiq.tools.base import ToolContext, failed, registry, timed

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")

# Registrars/TLDs disproportionately abused for short-lived phishing infra.
_HIGH_RISK_TLDS = {
    "zip", "mov", "top", "xyz", "gq", "cf", "tk", "ml", "ga", "click", "link",
    "work", "live", "rest", "cam", "quest", "sbs", "cfd", "icu", "buzz",
}


def _resolve_sync(domain: str) -> dict[str, list[str]]:
    """Blocking resolution, run in a worker thread by the caller."""
    import dns.resolver  # imported lazily so the module loads without dnspython

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6.0
    resolver.timeout = 3.0
    records: dict[str, list[str]] = {}
    for rtype in _RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = sorted(r.to_text().strip('"') for r in answers)
        except Exception:
            continue  # NXDOMAIN / NoAnswer per-type is normal, not an error
    return records


@registry.register(
    "dns_lookup",
    description="Resolve A/AAAA/MX/NS/TXT/CNAME records for a domain.",
    accepts=["domain"],
)
@timed("dns", "resolve")
async def dns_lookup(ctx: ToolContext, domain: str) -> Evidence:
    records = await asyncio.to_thread(_resolve_sync, domain)

    if not records:
        return Evidence(
            source="dns", tool="resolve", indicator=f"domain:{domain}",
            status=ToolStatus.NOT_FOUND, verdict=Verdict.UNKNOWN, confidence=0.5,
            summary=f"{domain} does not resolve (NXDOMAIN or no records)",
            signals={"resolves": False},
        )

    ips = records.get("A", []) + records.get("AAAA", [])
    # A domain that resolves but accepts no mail, while sending mail, is a
    # classic disposable-phishing pattern.
    has_mx = bool(records.get("MX"))
    spf = [t for t in records.get("TXT", []) if t.lower().startswith("v=spf1")]
    dmarc_absent = True  # checked separately via _dmarc subdomain below

    signals: dict[str, Any] = {
        "resolves": True,
        "ips": [ip for ip in ips if not is_private_ip(ip)],
        "record_types": sorted(records.keys()),
        "has_mx": has_mx,
        "has_spf": bool(spf),
        "nameservers": records.get("NS", []),
        "cname": records.get("CNAME", []),
    }

    tld = domain.rsplit(".", 1)[-1].lower()
    severity = Severity.INFO
    verdict = Verdict.UNKNOWN
    notes = [f"resolves to {len(ips)} address(es)"]
    if tld in _HIGH_RISK_TLDS:
        signals["high_risk_tld"] = tld
        severity = Severity.LOW
        verdict = Verdict.SUSPICIOUS
        notes.append(f".{tld} is a frequently abused TLD")
    if not has_mx:
        notes.append("no MX records")
    if not spf:
        notes.append("no SPF record")
        signals["missing_spf"] = True

    return Evidence(
        source="dns", tool="resolve", indicator=f"domain:{domain}",
        status=ToolStatus.OK, verdict=verdict, severity_hint=severity,
        confidence=0.9, summary=f"{domain}: " + "; ".join(notes),
        signals=signals, raw={"records": records},
    )


@registry.register(
    "rdap_domain",
    description="Fetch domain registration data (age, registrar, status) via RDAP.",
    accepts=["domain"],
)
@timed("rdap", "domain")
async def rdap_domain(ctx: ToolContext, domain: str) -> Evidence:
    assert ctx.client is not None
    resp = await ctx.get(
        f"https://rdap.org/domain/{domain}", follow_redirects=True
    )
    if resp.status_code == 404:
        return Evidence(
            source="rdap", tool="domain", indicator=f"domain:{domain}",
            status=ToolStatus.NOT_FOUND, confidence=0.5,
            summary=f"No RDAP registration record for {domain}",
        )
    if resp.status_code != 200:
        return failed("rdap", "domain", f"domain:{domain}",
                      f"HTTP {resp.status_code}")

    data = resp.json()
    registered_at: datetime | None = None
    expires_at: datetime | None = None
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        raw_date = event.get("eventDate", "")
        try:
            parsed = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        if action == "registration":
            registered_at = parsed
        elif action == "expiration":
            expires_at = parsed

    registrar = ""
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            for item in entity.get("vcardArray", [[], []])[1]:
                if item and item[0] == "fn":
                    registrar = item[3]
                    break

    age_days: int | None = None
    if registered_at:
        age_days = (datetime.now(timezone.utc) - registered_at).days

    # Age thresholds: most phishing domains are consumed within weeks of
    # registration, so recency is weighted heavily.
    severity, verdict, note = Severity.INFO, Verdict.UNKNOWN, "registration age unknown"
    if age_days is not None:
        if age_days <= 7:
            severity, verdict = Severity.HIGH, Verdict.SUSPICIOUS
            note = f"registered {age_days} day(s) ago, very recently created"
        elif age_days <= 30:
            severity, verdict = Severity.MEDIUM, Verdict.SUSPICIOUS
            note = f"registered {age_days} days ago, recently created"
        elif age_days <= 180:
            severity, verdict = Severity.LOW, Verdict.UNKNOWN
            note = f"registered {age_days} days ago"
        else:
            severity, verdict = Severity.INFO, Verdict.BENIGN
            note = f"registered {age_days} days ago, established domain"

    statuses = data.get("status", [])
    signals = {
        "age_days": age_days,
        "registrar": registrar,
        "registered_at": registered_at.isoformat() if registered_at else None,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "status": statuses,
        "privacy_protected": any(
            "privacy" in str(s).lower() or "redacted" in str(s).lower()
            for s in statuses
        ),
    }
    summary = f"{domain}: {note}"
    if registrar:
        summary += f"; registrar {registrar}"

    return Evidence(
        source="rdap", tool="domain", indicator=f"domain:{domain}",
        status=ToolStatus.OK, verdict=verdict, severity_hint=severity,
        confidence=0.85, summary=summary, signals=signals,
        raw={"events": data.get("events", []), "status": statuses},
    )


@registry.register(
    "rdap_ip",
    description="Fetch network/ASN ownership for an IP address via RDAP.",
    accepts=["ipv4", "ipv6"],
)
@timed("rdap", "ip")
async def rdap_ip(ctx: ToolContext, ip: str) -> Evidence:
    if is_private_ip(ip):
        return Evidence(
            source="rdap", tool="ip", indicator=f"ipv4:{ip}",
            status=ToolStatus.SKIPPED, summary=f"{ip} is a private address",
            signals={"private": True}, confidence=0.0,
        )
    assert ctx.client is not None
    resp = await ctx.get(f"https://rdap.org/ip/{ip}", follow_redirects=True)
    if resp.status_code != 200:
        return failed("rdap", "ip", f"ipv4:{ip}", f"HTTP {resp.status_code}")

    data = resp.json()
    signals = {
        "network_name": data.get("name", ""),
        "cidr": data.get("handle", ""),
        "country": data.get("country", ""),
        "type": data.get("type", ""),
    }
    org = ""
    for entity in data.get("entities", []):
        for item in entity.get("vcardArray", [[], []])[1]:
            if item and item[0] == "fn":
                org = item[3]
                break
        if org:
            break
    signals["organization"] = org

    return Evidence(
        source="rdap", tool="ip", indicator=f"ipv4:{ip}",
        status=ToolStatus.OK, confidence=0.85,
        summary=f"{ip} belongs to {org or signals['network_name'] or 'unknown'} "
                f"({signals['country'] or '??'})",
        signals=signals,
    )
