from __future__ import annotations

import time

from cyber_agent.hitl_mailer import build_link, verify_token


def test_link_signing_roundtrip():
    link = build_link("abc-123")
    assert "abc-123" in link
    # parse exp and sig back out
    q = link.split("?", 1)[1]
    parts = dict(p.split("=") for p in q.split("&"))
    assert verify_token("abc-123", int(parts["exp"]), parts["sig"])


def test_expired_token_rejected():
    past = int(time.time()) - 10
    from cyber_agent.hitl_mailer import _sign

    assert not verify_token("x", past, _sign("x", past))


def test_graph_compiles_with_retry_policies():
    from langgraph.checkpoint.memory import MemorySaver

    from cyber_agent.graph import build_graph

    g = build_graph(checkpointer=MemorySaver())
    assert g is not None
