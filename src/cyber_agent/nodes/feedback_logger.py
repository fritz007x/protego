from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from ..data.watsonx_data import upsert_vendor, write_audit
from ..state import ThreatState


def feedback_logger(state: ThreatState) -> dict:
    parsed = state.get("parsed") or {}
    raw = json.dumps(state.get("raw_input") or {}, sort_keys=True, default=str)
    input_hash = hashlib.sha256(raw.encode()).hexdigest()

    write_audit(
        {
            "trace_id": state.get("trace_id"),
            "input_hash": input_hash,
            "decision": state.get("decision"),
            "risk_score": state.get("risk_score"),
            "signals": state.get("signals"),
            "human_feedback": state.get("human_feedback"),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
    )

    feedback = state.get("human_feedback") or {}
    if feedback.get("approved") and parsed.get("vendor"):
        upsert_vendor(
            parsed["vendor"],
            bank_account=parsed.get("bank_account"),
            avg_amount=parsed.get("amount"),
            last_seen=datetime.now(timezone.utc).isoformat(),
        )
    return {}
