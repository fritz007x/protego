from __future__ import annotations

from ..llm import make_embeddings

_embeddings = None


def get_embeddings():
    global _embeddings
    if _embeddings is None:
        _embeddings = make_embeddings()
    return _embeddings
