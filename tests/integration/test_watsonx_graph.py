"""Integration: full graph runs with real watsonx.ai LLM calls."""
import uuid

import pytest
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from tests.integration.conftest import watsonx
from cyber_agent.graph import build_graph


INVOICE_KNOWN = """
Vendor: Acme Supplies
Invoice No: 2001
Date: 2026-04-01
Amount Due: $500.00
Account Number: ACME-111-222
"""

INVOICE_BANK_CHANGE = """
Vendor: Acme Supplies
Invoice No: 2002
Date: 2026-04-10
Amount Due: $500.00
Account Number: NEW-999-888
"""

PHISHING_EMAIL = """\
From: support <support@amaz0n-security.zip>
Subject: Your account has been suspended

Dear customer, click http://amaz0n-verify.zip/login to restore access.
"""

BEC_EMAIL = """\
From: ceo@example.com
Subject: Urgent request

Hi, I need you to urgently wire $5,000 to a new account immediately. Keep this confidential.
"""


@pytest.fixture
def graph():
    return build_graph(checkpointer=MemorySaver())


@watsonx
def test_invoice_known_good_completes(graph, tmp_path, monkeypatch):
    from cyber_agent.data.watsonx_data import init_db, upsert_vendor
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.sqlite"))
    from cyber_agent import config as cfg
    object.__setattr__(cfg.settings, "audit_db_path", str(tmp_path / "audit.sqlite"))
    init_db()
    upsert_vendor("Acme Supplies", bank_account="ACME-111-222", avg_amount=500.0)

    tid = str(uuid.uuid4())
    out = graph.invoke(
        {"raw_input": {"type": "invoice", "content": INVOICE_KNOWN}, "trace_id": tid},
        config={"configurable": {"thread_id": tid}},
    )
    assert out["decision"] in ("pass", "alert")
    assert isinstance(out["reasoning"], str) and len(out["reasoning"]) > 0


@watsonx
def test_invoice_bank_change_triggers_hitl_and_resumes(graph, tmp_path, monkeypatch):
    from cyber_agent.data.watsonx_data import init_db, upsert_vendor
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.sqlite"))
    from cyber_agent import config as cfg
    object.__setattr__(cfg.settings, "audit_db_path", str(tmp_path / "audit.sqlite"))
    init_db()
    upsert_vendor("Acme Supplies", bank_account="ACME-111-222", avg_amount=500.0)

    tid = str(uuid.uuid4())
    cfg_run = {"configurable": {"thread_id": tid}}
    graph.invoke(
        {"raw_input": {"type": "invoice", "content": INVOICE_BANK_CHANGE}, "trace_id": tid},
        config=cfg_run,
    )
    snap = graph.get_state(cfg_run)
    assert snap.next, "graph must pause on bank-account-change"

    out = graph.invoke(Command(resume={"approved": False, "notes": "rejected"}), config=cfg_run)
    assert out["decision"] == "block"


@watsonx
def test_phishing_email_routes_and_scores(graph):
    tid = str(uuid.uuid4())
    out = graph.invoke(
        {"raw_input": {"type": "phishing", "content": PHISHING_EMAIL}, "trace_id": tid},
        config={"configurable": {"thread_id": tid}},
    )
    assert out["threat_type"] == "phishing"
    assert out["risk_score"] > 0
    assert out["decision"] in ("alert", "block", "verify", "pass")


@watsonx
def test_bec_email_routes_and_scores(graph):
    tid = str(uuid.uuid4())
    out = graph.invoke(
        {
            "raw_input": {
                "type": "bec",
                "sender": "ceo@example.com",
                "content": BEC_EMAIL,
            },
            "trace_id": tid,
        },
        config={"configurable": {"thread_id": tid}},
    )
    assert out["threat_type"] == "bec"
    assert any(s.get("reason") == "urgency_language" for s in out["signals"])
