from __future__ import annotations

import uuid

from langgraph.checkpoint.memory import MemorySaver

from cyber_agent.graph import build_graph


def _run(graph, text: str, declared: str = ""):
    tid = str(uuid.uuid4())
    cfg = {"configurable": {"thread_id": tid}}
    return graph.invoke(
        {"raw_input": {"type": declared, "content": text}, "trace_id": tid},
        config=cfg,
    )


def test_orchestrator_routes_invoice():
    out = _run(
        build_graph(checkpointer=MemorySaver()),
        "Vendor: X\nInvoice No: 1\nAmount Due: $10\nAccount Number: A-1\n",
    )
    assert out["threat_type"] == "invoice"


def test_orchestrator_routes_phishing_on_url():
    out = _run(
        build_graph(checkpointer=MemorySaver()),
        "Hello, click http://evil.example.zip to update your account.",
    )
    assert out["threat_type"] == "phishing"
    assert any(s.get("reason") == "suspicious_tld" for s in out["signals"])


def test_orchestrator_routes_bec():
    out = _run(
        build_graph(checkpointer=MemorySaver()),
        "URGENT wire transfer required, confidential — please send gift card details.",
    )
    assert out["threat_type"] == "bec"
    assert any(s.get("reason") == "urgency_language" for s in out["signals"])
