"""Embeddings with an offline default.

A hosted embedding model is used when one is configured. Otherwise ThreatIQ
falls back to a deterministic hashing embedder so retrieval keeps working with
no network and no key, important because the compliance mapper must never
silently stop mapping just because an API is down.
"""
from __future__ import annotations

import hashlib
import logging
import math
import re
from typing import Protocol

import httpx

from threatiq.config import Settings, get_settings

log = logging.getLogger(__name__)

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "is", "are", "be", "that",
    "this", "it", "for", "on", "with", "as", "by", "from", "at", "not", "can",
    "may", "which", "such", "their", "its", "has", "have", "been", "was", "were",
}


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower())
            if len(t) > 1 and t not in _STOPWORDS]


class Embedder(Protocol):
    dim: int

    async def embed(self, texts: list[str]) -> list[list[float]]: ...


class HashingEmbedder:
    """Deterministic feature-hashing embedder (no model, no network).

    Words and character 4-grams are hashed into a fixed-width vector with
    sublinear term weighting. It is not semantic, but combined with the BM25
    channel in the retriever it is more than adequate for a 46-document,
    jargon-heavy corpus where exact terminology carries the meaning.
    """

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim

    def _vector(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        tokens = tokenize(text)
        counts: dict[str, int] = {}
        for token in tokens:
            counts[token] = counts.get(token, 0) + 1
        # Character n-grams capture morphology ("injection"/"injections").
        joined = " ".join(tokens)
        for i in range(len(joined) - 3):
            gram = joined[i:i + 4]
            counts[f"#{gram}"] = counts.get(f"#{gram}", 0) + 1

        for term, count in counts.items():
            digest = hashlib.blake2b(term.encode(), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "big") % self.dim
            sign = 1.0 if digest[4] & 1 else -1.0
            weight = 1.0 + math.log(count)
            # Character grams carry less signal than whole words.
            if term.startswith("#"):
                weight *= 0.35
            vec[index] += sign * weight

        norm = math.sqrt(sum(v * v for v in vec))
        return [v / norm for v in vec] if norm else vec

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._vector(t) for t in texts]


class GeminiEmbedder:
    """Google's text-embedding model, used when GOOGLE_API_KEY is present."""

    def __init__(self, api_key: str, dim: int = 768) -> None:
        self.api_key = api_key
        self.dim = dim
        self.model = "models/text-embedding-004"

    async def embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            # The batch endpoint caps at 100 inputs per request.
            for start in range(0, len(texts), 100):
                batch = texts[start:start + 100]
                resp = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/"
                    f"{self.model}:batchEmbedContents",
                    headers={"x-goog-api-key": self.api_key},
                    json={"requests": [
                        {"model": self.model,
                         "content": {"parts": [{"text": t[:8000]}]}}
                        for t in batch
                    ]},
                )
                resp.raise_for_status()
                for item in resp.json().get("embeddings", []):
                    out.append(item.get("values", []))
        return out


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def get_embedder(settings: Settings | None = None) -> Embedder:
    settings = settings or get_settings()
    if settings.google_api_key:
        try:
            return GeminiEmbedder(settings.google_api_key)
        except Exception as exc:
            log.warning("falling back to hashing embedder: %s", exc)
    return HashingEmbedder(settings.embedding_dim)
