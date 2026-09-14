-- Runs once on first container start of the postgres service.
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Knowledge base for RAG. The application creates its own tables via
-- SQLAlchemy; this one is managed here because it needs the vector type.
CREATE TABLE IF NOT EXISTS knowledge_docs (
    id           TEXT PRIMARY KEY,
    framework    TEXT NOT NULL,
    code         TEXT NOT NULL,
    title        TEXT NOT NULL,
    body         TEXT NOT NULL,
    keywords     TEXT[] DEFAULT '{}',
    url          TEXT DEFAULT '',
    embedding    vector(384),
    created_at   TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_knowledge_framework ON knowledge_docs (framework);
CREATE INDEX IF NOT EXISTS ix_knowledge_code      ON knowledge_docs (code);

-- IVFFlat needs rows before it can be built usefully; created by the seeding
-- script after the corpus is loaded. Left here as documentation of intent:
--   CREATE INDEX ix_knowledge_embedding ON knowledge_docs
--     USING ivfflat (embedding vector_cosine_ops) WITH (lists = 20);

-- NOTE: the application's own tables (investigations, indicators, evidence,
-- findings, audit_logs) are created by SQLAlchemy at startup, so indexes on
-- them cannot live here, this script runs before the app has ever connected.
-- PostgresRepository.create_all() adds them once the tables exist.
