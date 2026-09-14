#!/usr/bin/env python3
"""Seed the security knowledge base into pgvector.

    python scripts_seed.py

Safe to re-run: documents are upserted by id. Without DATABASE_URL this is a
no-op, because the in-process retriever already has the same corpus.
"""
from __future__ import annotations

import asyncio
import sys

from threatiq.config import get_settings
from threatiq.knowledge.corpus import KNOWLEDGE_BASE
from threatiq.rag.store import PgVectorStore
from threatiq.telemetry import setup_logging


async def main() -> int:
    settings = get_settings()
    setup_logging(settings)

    store = PgVectorStore(settings)
    if not store.enabled:
        print("DATABASE_URL is not set, nothing to seed. The in-process "
              f"retriever already serves all {len(KNOWLEDGE_BASE)} documents.")
        return 0

    try:
        seeded = await store.seed()
    except Exception as exc:
        print(f"Seeding failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        await store.close()

    print(f"Seeded {seeded} documents into pgvector.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
