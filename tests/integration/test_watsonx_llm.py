"""Integration: real WatsonxLLM + WatsonxEmbeddings calls."""
import pytest

from tests.integration.conftest import watsonx
from cyber_agent.llm import make_embeddings, make_llm


@watsonx
def test_llm_invoke_returns_text():
    llm = make_llm("test")
    result = llm.invoke("Reply with the single word: pong")
    assert isinstance(result, str)
    assert len(result) > 0


@watsonx
def test_llm_orchestrator_temp_zero():
    """Orchestrator uses temperature=0 — repeated calls should return same output."""
    llm = make_llm("orchestrator")
    r1 = llm.invoke("Say: hello")
    r2 = llm.invoke("Say: hello")
    assert r1 == r2


@watsonx
def test_embeddings_produce_vectors():
    emb = make_embeddings()
    vecs = emb.embed_documents(["invoice fraud", "phishing link"])
    assert len(vecs) == 2
    assert all(isinstance(v, list) and len(v) > 0 for v in vecs)


@watsonx
def test_embeddings_query_similar_to_doc():
    """Query embedding for 'wire transfer fraud' should be closer to a BEC doc than a receipt."""
    import math

    emb = make_embeddings()
    bec = emb.embed_documents(["urgent wire transfer request from CEO"])[0]
    unrelated = emb.embed_documents(["restaurant receipt for lunch"])[0]
    query = emb.embed_query("wire transfer fraud")

    def cos(a, b):
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(x * x for x in b))
        return dot / (na * nb)

    assert cos(query, bec) > cos(query, unrelated)
