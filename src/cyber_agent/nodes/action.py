from __future__ import annotations

from langgraph.types import interrupt

from ..state import ThreatState


def action(state: ThreatState) -> dict:
    decision = state.get("decision", "")
    if decision == "verify":
        human = interrupt(
            {
                "trace_id": state.get("trace_id"),
                "summary": state.get("reasoning"),
                "evidence": state.get("signals"),
                "parsed": state.get("parsed"),
            }
        )
        approved = bool(human.get("approved")) if isinstance(human, dict) else False
        final = "pass" if approved else "block"
        return {"human_feedback": human if isinstance(human, dict) else {"raw": human}, "decision": final}
    return {}
