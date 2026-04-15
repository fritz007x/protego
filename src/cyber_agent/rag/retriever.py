"""In-process threat signature retriever.

Production: persist embeddings to watsonx.data's vector column. For MVP we keep
an in-memory list seeded on first use; swap the store out without touching
callers.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from .embeddings import get_embeddings

_SEED = [
    ("bec-gift-card", "bec", "Urgent gift card request from CEO, keep confidential"),
    ("bec-wire", "bec", "Please wire funds immediately to this new account"),
    ("phish-login", "phishing", "Verify your account by clicking the secure login link"),
    ("phish-invoice", "phishing", "Your invoice is attached, open the document to view"),
]


@dataclass
class Signature:
    id: str
    type: str
    pattern: str
    embedding: list[float]


_store: list[Signature] | None = None


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(x * x for x in b)) or 1.0
    return dot / (na * nb)


def _ensure_store() -> list[Signature]:
    global _store
    if _store is not None:
        return _store
    emb = get_embeddings()
    vecs = emb.embed_documents([p for _, _, p in _SEED])
    _store = [Signature(id=i, type=t, pattern=p, embedding=v) for (i, t, p), v in zip(_SEED, vecs)]
    return _store


def retrieve_similar(text: str, k: int = 3) -> list[dict]:
    store = _ensure_store()
    q = get_embeddings().embed_query(text)
    scored = [(s, _cosine(q, s.embedding)) for s in store]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [
        {"id": s.id, "type": s.type, "pattern": s.pattern, "score": round(score, 4)}
        for s, score in scored[:k]
    ]
