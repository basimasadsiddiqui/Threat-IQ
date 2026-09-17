#!/usr/bin/env python3
"""Verify each configured API key against its live service.

    python scripts/check_keys.py

Makes one cheap, well-known request per configured key and reports whether the
service accepted it. A key that is present but rejected is worse than no key at
all: the tool reports `error` rather than `skipped`, which is easy to skim past
in a long evidence table.

Nothing is sent for a key you have not set. Unset keys are reported as absent,
with the signup link, and are not an error: ThreatIQ runs without them.

The probes themselves live in `threatiq/keycheck.py`, shared with the console's
settings page, so the two cannot drift apart and disagree about what a working
key looks like.
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threatiq.config import get_settings  # noqa: E402
from threatiq.keycheck import PROBES, check_keys  # noqa: E402

GREEN, RED, YELLOW, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m")

_LABEL = {
    "ok": f"{GREEN}[ working ]{RESET}",
    "rejected": f"{RED}[ REJECTED]{RESET}",
    "unreachable": f"{YELLOW}[ unclear ]{RESET}",
    "unclear": f"{YELLOW}[ unclear ]{RESET}",
    "absent": f"{DIM}[ absent  ]{RESET}",
}


async def main() -> int:
    settings = get_settings()
    print("Checking configured API keys\n")

    keys = {p.setting: getattr(settings, p.setting, "") for p in PROBES}
    results = await check_keys(keys, models={
        "groq_model": settings.groq_model,
        "gemini_model": settings.gemini_model,
    })

    failures = 0
    for result in results:
        label = _LABEL[result.state]
        if result.state == "absent":
            tag = "optional" if result.optional else "recommended"
            print(f"  {label} {result.name:12s} not set ({tag})")
            print(f"               {DIM}{result.signup}{RESET}")
            print(f"               {DIM}unlocks: {result.unlocks}{RESET}")
            continue

        print(f"  {label} {result.name:12s} {result.detail}")
        if result.state == "rejected":
            failures += 1
            print(f"               {DIM}check for a stray space or a "
                  f"truncated paste in .env{RESET}")

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
