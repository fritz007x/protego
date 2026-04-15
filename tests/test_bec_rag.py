from __future__ import annotations

import uuid

from langgraph.checkpoint.memory import MemorySaver

from cyber_agent.graph import build_graph
from cyber_agent.rag.retriever import retrieve_similar


def test_retriever_returns_signatures():
    hits = retrieve_similar("please wire funds immediately", k=3)
    assert len(hits) == 3
    assert all("score" in h for h in hits)


def test_bec_graph_flow_includes_rag():
    g = build_graph(checkpointer=MemorySaver())
    tid = str(uuid.uuid4())
    cfg = {"configurable": {"thread_id": tid}}
    out = g.invoke(
        {
            "raw_input": {
                "type": "bec",
                "sender": "ceo@example.com",
                "content": "URGENT: please wire funds immediately, confidential",
            },
            "trace_id": tid,
        },
        config=cfg,
    )
    assert out["threat_type"] == "bec"
    assert "rag" in (out.get("parsed") or {})
