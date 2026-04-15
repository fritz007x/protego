from __future__ import annotations

import operator
from typing import Annotated, Literal, TypedDict


ThreatType = Literal["phishing", "bec", "invoice", "unknown"]
Decision = Literal["alert", "block", "verify", "pass", ""]


class ThreatState(TypedDict, total=False):
    raw_input: dict
    parsed: dict
    threat_type: ThreatType
    signals: Annotated[list[dict], operator.add]
    risk_score: float
    decision: Decision
    reasoning: str
    human_feedback: dict | None
    trace_id: str
