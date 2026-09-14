#!/usr/bin/env python3
"""Verify each configured API key against its live service.

    python scripts/check_keys.py

Makes one cheap, well-known request per configured key and reports whether the
service accepted it. A key that is present but rejected is worse than no key at
all: the tool reports `error` rather than `skipped`, which is easy to skim past
in a long evidence table.

Nothing is sent for a key you have not set. Unset keys are reported as absent,
with the signup link, and are not an error: ThreatIQ runs without them.
"""
from __future__ import annotations

import asyncio
import os
import sys

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threatiq.config import get_settings  # noqa: E402

# A probe is deliberately boring: a well-known indicator, one request, no
# writes. google.com and 8.8.8.8 are safe to look up anywhere.
PROBES = [
    {
        "name": "VirusTotal",
        "setting": "virustotal_api_key",
        "signup": "https://www.virustotal.com/gui/my-apikey",
        "unlocks": "URL, domain, IP and file-hash reputation, plus 24% of the risk model",
        "url": "https://www.virustotal.com/api/v3/domains/google.com",
        "headers": lambda key: {"x-apikey": key},
    },
    {
        "name": "AbuseIPDB",
        "setting": "abuseipdb_api_key",
        "signup": "https://www.abuseipdb.com/account/api",
        "unlocks": "IP abuse reports, the only IP reputation source",
        "url": "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90",
        "headers": lambda key: {"Key": key, "Accept": "application/json"},
    },
    {
        "name": "NVD",
        "setting": "nvd_api_key",
        "signup": "https://nvd.nist.gov/developers/request-an-api-key",
        "unlocks": "a higher CVE lookup rate; CVE lookups already work without it",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
        "headers": lambda key: {"apiKey": key},
        "optional": True,
    },
    {
        "name": "urlscan.io",
        "setting": "urlscan_api_key",
        "signup": "https://urlscan.io/user/apikey",
        "unlocks": "a higher search quota; search already works without it",
        "url": "https://urlscan.io/api/v1/search/?q=domain%3Agoogle.com&size=1",
        "headers": lambda key: {"API-Key": key},
        "optional": True,
    },
    {
        "name": "Groq",
        "setting": "groq_api_key",
        "signup": "https://console.groq.com/keys",
        "unlocks": "narrative explanations; every score is computed without it",
        "url": "https://api.groq.com/openai/v1/models",
        "headers": lambda key: {"Authorization": f"Bearer {key}"},
        "optional": True,
    },
]

GREEN, RED, YELLOW, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m")


async def probe(client: httpx.AsyncClient, spec: dict, key: str) -> tuple[str, str]:
    try:
        response = await client.get(
            spec["url"], headers=spec["headers"](key), timeout=20.0)
    except httpx.HTTPError as exc:
        return "error", f"could not reach the service: {type(exc).__name__}"

    if response.status_code in (200, 201):
        return "ok", "accepted"
    if response.status_code in (401, 403):
        return "bad", f"rejected the key (HTTP {response.status_code})"
    if response.status_code == 429:
        # The key is valid; the quota for this minute is spent.
        return "ok", "accepted, but currently rate limited (HTTP 429)"
    return "warn", f"unexpected HTTP {response.status_code}"


async def main() -> int:
    settings = get_settings()
    print("Checking configured API keys\n")

    failures = 0
    async with httpx.AsyncClient(follow_redirects=True) as client:
        for spec in PROBES:
            key = getattr(settings, spec["setting"], "")
            label = spec["name"]

            if not key:
                tag = "optional" if spec.get("optional") else "recommended"
                print(f"  {DIM}[ absent  ]{RESET} {label:12s} not set ({tag})")
                print(f"               {DIM}{spec['signup']}{RESET}")
                print(f"               {DIM}unlocks: {spec['unlocks']}{RESET}")
                continue

            state, detail = await probe(client, spec, key)
            if state == "ok":
                print(f"  {GREEN}[ working ]{RESET} {label:12s} {detail}")
            elif state == "bad":
                failures += 1
                print(f"  {RED}[ REJECTED]{RESET} {label:12s} {detail}")
                print(f"               {DIM}check for a stray space or a "
                      f"truncated paste in .env{RESET}")
            else:
                print(f"  {YELLOW}[ unclear ]{RESET} {label:12s} {detail}")

    print()
    if failures:
        print(f"{RED}{failures} key(s) were rejected.{RESET} A present-but-invalid "
              f"key makes its tool report `error` rather than `skipped`, which is "
              f"easy to miss in a long evidence table. Fix or clear them.")
        return 1

    print("No rejected keys. Restart the API to pick up any changes:")
    print("  make run-api")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
