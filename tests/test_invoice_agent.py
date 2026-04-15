from __future__ import annotations

import uuid

import pytest
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from cyber_agent.data.watsonx_data import init_db, upsert_vendor
from cyber_agent.graph import build_graph


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.sqlite"))
    # reimport settings module attribute
    from cyber_agent import config as cfg

    object.__setattr__(cfg.settings, "audit_db_path", str(tmp_path / "audit.sqlite"))
    init_db()
    yield


def _run(graph, text: str, thread_id: str | None = None):
    tid = thread_id or str(uuid.uuid4())
    cfg = {"configurable": {"thread_id": tid}}
    out = graph.invoke(
        {"raw_input": {"type": "invoice", "content": text}, "trace_id": tid},
        config=cfg,
    )
    return tid, cfg, out


INVOICE_KNOWN = """
Vendor: Acme Supplies
Invoice No: 1001
Date: 2026-01-10
Amount Due: $500.00
Account Number: ACME-111-222
"""

INVOICE_BANK_CHANGE = """
Vendor: Acme Supplies
Invoice No: 1002
Date: 2026-02-01
Amount Due: $510.00
Account Number: NEW-999-888
"""

INVOICE_NEW_VENDOR = """
Vendor: Unknown Traders LLC
Invoice No: 77
Date: 2026-02-02
Amount Due: $120.00
Account Number: UT-000-111
"""

INVOICE_AMOUNT_ANOMALY = """
Vendor: Acme Supplies
Invoice No: 1003
Date: 2026-02-03
Amount Due: $9,999.00
Account Number: ACME-111-222
"""


def _seed_acme():
    upsert_vendor("Acme Supplies", bank_account="ACME-111-222", avg_amount=500.0)


def test_known_good_invoice_passes():
    _seed_acme()
    g = build_graph(checkpointer=MemorySaver())
    _, _, out = _run(g, INVOICE_KNOWN)
    assert out["decision"] in ("pass", "alert")


def test_bank_account_change_triggers_hitl():
    _seed_acme()
    g = build_graph(checkpointer=MemorySaver())
    tid, cfg, out = _run(g, INVOICE_BANK_CHANGE)
    # Interrupt surfaces as no final decision yet; state is paused.
    snap = g.get_state(cfg)
    assert snap.next, "graph should be paused on interrupt"
    # Resume with rejection → blocked
    out2 = g.invoke(Command(resume={"approved": False, "notes": "nope"}), config=cfg)
    assert out2["decision"] == "block"
    assert any(s.get("reason") == "bank_account_changed" for s in out2["signals"])


def test_new_vendor_alerts():
    g = build_graph(checkpointer=MemorySaver())
    _, _, out = _run(g, INVOICE_NEW_VENDOR)
    assert out["decision"] in ("alert", "pass")
    assert any(s.get("reason") == "new_vendor" for s in out["signals"])


def test_amount_anomaly_alerts():
    _seed_acme()
    g = build_graph(checkpointer=MemorySaver())
    _, _, out = _run(g, INVOICE_AMOUNT_ANOMALY)
    assert any(s.get("reason") == "amount_anomaly" for s in out["signals"])
    assert out["decision"] in ("alert", "block")
