"""pgvector-backed knowledge store.

The retriever works entirely in-process, which is what makes ThreatIQ runnable
with no database. This module is what makes the corpus *shared and queryable*
once PostgreSQL is present: embeddings are computed once at seed time instead
of on every process start, and the corpus becomes available to anything else
that can reach the database.

Falls back silently to the in-process path whenever pgvector is unavailable -
retrieval must never be the reason an investigation fails.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from threatiq.config import Settings, get_settings
from threatiq.knowledge.corpus import KNOWLEDGE_BASE, BY_ID, KnowledgeDoc
from threatiq.rag.embeddings import Embedder, get_embedder

log = logging.getLogger(__name__)


@dataclass
class StoredHit:
    doc: KnowledgeDoc
    distance: float

    @property
    def similarity(self) -> float:
        return 1.0 - self.distance


class PgVectorStore:
    def __init__(self, settings: Settings | None = None,
                 embedder: Embedder | None = None) -> None:
        self.settings = settings or get_settings()
        self.embedder = embedder or get_embedder(self.settings)
        self._engine = None

    @property
    def enabled(self) -> bool:
        return bool(self.settings.database_url)

    def _get_engine(self):
        if self._engine is None:
            from sqlalchemy.ext.asyncio import create_async_engine

            url = self.settings.database_url
            if url.startswith("postgresql://"):
                url = url.replace("postgresql://", "postgresql+psycopg://", 1)
            self._engine = create_async_engine(url, pool_pre_ping=True)
        return self._engine

    async def seed(self, docs: list[KnowledgeDoc] | None = None) -> int:
        """Embed the corpus and upsert it. Idempotent, safe to re-run."""
        from sqlalchemy import text

        docs = docs if docs is not None else list(KNOWLEDGE_BASE)
        if not docs:
            return 0

        vectors = await self.embedder.embed([d.to_document() for d in docs])
        dim = len(vectors[0])
        engine = self._get_engine()

        async with engine.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            # The column dimension depends on which embedder is configured, so
            # the table is created to match rather than assumed.
            await conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS knowledge_docs (
                    id         TEXT PRIMARY KEY,
                    framework  TEXT NOT NULL,
                    code       TEXT NOT NULL,
                    title      TEXT NOT NULL,
                    body       TEXT NOT NULL,
                    keywords   TEXT[] DEFAULT '{{}}',
                    url        TEXT DEFAULT '',
                    embedding  vector({dim}),
                    created_at TIMESTAMPTZ DEFAULT now()
                )
            """))
            # A dimension change means a different embedder; the old vectors are
            # not comparable, so replace rather than mix them.
            current_dim = (await conn.execute(text("""
                SELECT atttypmod FROM pg_attribute
                WHERE attrelid = 'knowledge_docs'::regclass AND attname = 'embedding'
            """))).scalar()
            if current_dim not in (None, -1, dim):
                log.warning("embedding dimension changed %s -> %s; rebuilding table",
                            current_dim, dim)
                await conn.execute(text("DROP TABLE knowledge_docs"))
                await conn.execute(text(f"""
                    CREATE TABLE knowledge_docs (
                        id TEXT PRIMARY KEY, framework TEXT NOT NULL,
                        code TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
                        keywords TEXT[] DEFAULT '{{}}', url TEXT DEFAULT '',
                        embedding vector({dim}),
                        created_at TIMESTAMPTZ DEFAULT now()
                    )
                """))

            for doc, vector in zip(docs, vectors):
                await conn.execute(
                    text("""
                        INSERT INTO knowledge_docs
                            (id, framework, code, title, body, keywords, url, embedding)
                        VALUES
                            (:id, :framework, :code, :title, :body, :keywords, :url,
                             CAST(:embedding AS vector))
                        ON CONFLICT (id) DO UPDATE SET
                            framework = EXCLUDED.framework,
                            code      = EXCLUDED.code,
                            title     = EXCLUDED.title,
                            body      = EXCLUDED.body,
                            keywords  = EXCLUDED.keywords,
                            url       = EXCLUDED.url,
                            embedding = EXCLUDED.embedding
                    """),
                    {
                        "id": doc.id, "framework": doc.framework, "code": doc.code,
                        "title": doc.title, "body": doc.text,
                        "keywords": doc.keywords, "url": doc.url,
                        "embedding": "[" + ",".join(f"{v:.6f}" for v in vector) + "]",
                    },
                )

            # IVFFlat only helps once there are rows to cluster, which is why
            # this is here rather than in init.sql.
            try:
                await conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS ix_knowledge_embedding
                    ON knowledge_docs USING ivfflat (embedding vector_cosine_ops)
                    WITH (lists = 10)
                """))
            except Exception as exc:
                log.warning("ivfflat index not created (%s); scans will be exact", exc)

        log.info("seeded %d knowledge documents into pgvector", len(docs))
        return len(docs)

    async def search(self, query: str, top_k: int = 5) -> list[StoredHit]:
        from sqlalchemy import text

        try:
            vector = (await self.embedder.embed([query]))[0]
            engine = self._get_engine()
            async with engine.connect() as conn:
                rows = (await conn.execute(
                    text("""
                        SELECT id, embedding <=> CAST(:q AS vector) AS distance
                        FROM knowledge_docs
                        ORDER BY distance ASC
                        LIMIT :k
                    """),
                    {"q": "[" + ",".join(f"{v:.6f}" for v in vector) + "]",
                     "k": top_k},
                )).all()
        except Exception as exc:
            log.warning("pgvector search unavailable (%s); using in-process index",
                        exc)
            return []

        hits: list[StoredHit] = []
        for doc_id, distance in rows:
            doc = BY_ID.get(doc_id)
            if doc is not None:
                hits.append(StoredHit(doc=doc, distance=float(distance)))
        return hits

    async def count(self) -> int:
        from sqlalchemy import text

        try:
            async with self._get_engine().connect() as conn:
                return int((await conn.execute(
                    text("SELECT count(*) FROM knowledge_docs"))).scalar() or 0)
        except Exception:
            return 0

    async def close(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
