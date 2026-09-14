"""Hybrid retrieval over the security knowledge base.

Two channels are combined with reciprocal rank fusion:
  * BM25, exact terminology ("SQL injection", "HSTS") which dominates in a
    standards corpus.
  * Vector cosine, paraphrase tolerance ("the site can be framed" -> clickjacking).

Neither channel alone is reliable for compliance mapping; fused, they are.
"""
from __future__ import annotations

import asyncio
import logging
import math
from dataclasses import dataclass

from threatiq.config import Settings, get_settings
from threatiq.knowledge.corpus import KNOWLEDGE_BASE, KnowledgeDoc
from threatiq.rag.embeddings import Embedder, cosine, get_embedder, tokenize

log = logging.getLogger(__name__)

# BM25 parameters, standard defaults, corpus is small and homogeneous.
_K1 = 1.5
_B = 0.75
# Rank-fusion constant; 60 is the value from the original RRF paper.
_RRF_K = 60
# Channel weights. On a small standards corpus exact terminology is far more
# discriminative than the offline hashing embedder, so BM25 leads and the
# vector channel acts as a tiebreaker rather than an equal vote.
_W_BM25 = 1.0
_W_VECTOR = 0.4


@dataclass
class RetrievedDoc:
    doc: KnowledgeDoc
    score: float
    channel: str

    def as_context(self) -> str:
        return self.doc.to_document()


class KnowledgeRetriever:
    """In-process index. Built once, reused across investigations."""

    def __init__(self, docs: list[KnowledgeDoc] | None = None,
                 settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.docs = docs if docs is not None else list(KNOWLEDGE_BASE)
        self.embedder: Embedder = get_embedder(self.settings)
        self._vectors: list[list[float]] = []
        self._ready = False
        self._lock = asyncio.Lock()
        # When PostgreSQL is configured, the vector channel is served by
        # pgvector so embeddings are computed once at seed time rather than on
        # every process start. Falls back to the in-process index otherwise.
        self._store = None
        if self.settings.database_url:
            try:
                from threatiq.rag.store import PgVectorStore

                self._store = PgVectorStore(self.settings, self.embedder)
            except Exception as exc:
                log.warning("pgvector store unavailable: %s", exc)

        # --- BM25 index (built eagerly; it is pure CPU and instant) ---
        self._doc_tokens: list[list[str]] = [
            # Keywords repeated so exact framework terminology outweighs prose.
            tokenize(d.to_document() + " " + " ".join(d.keywords) * 3)
            for d in self.docs
        ]
        self._doc_len = [len(t) for t in self._doc_tokens]
        self._avg_len = (sum(self._doc_len) / len(self._doc_len)) if self._doc_len else 0.0
        self._df: dict[str, int] = {}
        for tokens in self._doc_tokens:
            for term in set(tokens):
                self._df[term] = self._df.get(term, 0) + 1
        self._tf: list[dict[str, int]] = []
        for tokens in self._doc_tokens:
            counts: dict[str, int] = {}
            for token in tokens:
                counts[token] = counts.get(token, 0) + 1
            self._tf.append(counts)

    async def ensure_ready(self) -> None:
        """Embed the corpus once, lazily, avoids a network call at import."""
        if self._ready:
            return
        async with self._lock:
            if self._ready:
                return
            try:
                self._vectors = await self.embedder.embed(
                    [d.to_document() for d in self.docs]
                )
            except Exception as exc:
                log.warning("corpus embedding failed (%s); BM25 only", exc)
                self._vectors = []
            self._ready = True

    def _bm25(self, query: str) -> list[tuple[int, float]]:
        terms = tokenize(query)
        if not terms or not self.docs:
            return []
        n = len(self.docs)
        scores: list[float] = [0.0] * n
        for term in terms:
            df = self._df.get(term, 0)
            if df == 0:
                continue
            idf = math.log(1 + (n - df + 0.5) / (df + 0.5))
            for i in range(n):
                tf = self._tf[i].get(term, 0)
                if tf == 0:
                    continue
                denom = tf + _K1 * (1 - _B + _B * self._doc_len[i] / (self._avg_len or 1))
                scores[i] += idf * (tf * (_K1 + 1)) / denom
        ranked = sorted(enumerate(scores), key=lambda kv: -kv[1])
        return [(i, s) for i, s in ranked if s > 0]

    async def _vector_search(self, query: str) -> list[tuple[int, float]]:
        if self._store is not None:
            hits = await self._store.search(query, top_k=25)
            if hits:
                index_of = {d.id: i for i, d in enumerate(self.docs)}
                return [(index_of[h.doc.id], h.similarity)
                        for h in hits if h.doc.id in index_of]
            # Empty result means the store is unseeded or unreachable; the
            # in-process index below still answers.
        await self.ensure_ready()
        if not self._vectors:
            return []
        try:
            query_vec = (await self.embedder.embed([query]))[0]
        except Exception as exc:
            log.warning("query embedding failed: %s", exc)
            return []
        scored = [(i, cosine(query_vec, v)) for i, v in enumerate(self._vectors)]
        scored.sort(key=lambda kv: -kv[1])
        return [(i, s) for i, s in scored if s > 0.02]

    async def search(self, query: str, top_k: int | None = None,
                     frameworks: list[str] | None = None) -> list[RetrievedDoc]:
        top_k = top_k or self.settings.rag_top_k
        lexical, semantic = await asyncio.gather(
            asyncio.to_thread(self._bm25, query),
            self._vector_search(query),
        )

        fused: dict[int, float] = {}
        channels: dict[int, set[str]] = {}
        for rank, (idx, _) in enumerate(lexical[:25]):
            fused[idx] = fused.get(idx, 0.0) + _W_BM25 / (_RRF_K + rank + 1)
            channels.setdefault(idx, set()).add("bm25")
        # Only the strongest vector hits vote; the tail is noise on a corpus
        # this small and would otherwise outrank exact lexical matches.
        for rank, (idx, _) in enumerate(semantic[:8]):
            fused[idx] = fused.get(idx, 0.0) + _W_VECTOR / (_RRF_K + rank + 1)
            channels.setdefault(idx, set()).add("vector")

        results: list[RetrievedDoc] = []
        for idx, score in sorted(fused.items(), key=lambda kv: -kv[1]):
            doc = self.docs[idx]
            if frameworks and doc.framework not in frameworks:
                continue
            results.append(RetrievedDoc(
                doc=doc, score=round(score, 5),
                channel="+".join(sorted(channels.get(idx, {"bm25"}))),
            ))
            if len(results) >= top_k:
                break
        return results

    async def context_block(self, query: str, top_k: int | None = None,
                            frameworks: list[str] | None = None) -> tuple[str, list[str]]:
        """Retrieved text formatted for a prompt, plus the citation codes."""
        hits = await self.search(query, top_k, frameworks)
        if not hits:
            return "", []
        blocks = [f"--- Reference {i} ---\n{h.as_context()}"
                  for i, h in enumerate(hits, start=1)]
        return "\n\n".join(blocks), [h.doc.code for h in hits]


_retriever: KnowledgeRetriever | None = None


def get_retriever() -> KnowledgeRetriever:
    global _retriever
    if _retriever is None:
        _retriever = KnowledgeRetriever()
    return _retriever
