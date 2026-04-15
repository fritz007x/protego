from __future__ import annotations

from ..state import ThreatState

_WEIGHTS = {"low": 0.15, "medium": 0.4, "high": 0.75, "critical": 1.0}


def risk_scoring(state: ThreatState) -> dict:
    signals = state.get("signals") or []
    score = 0.0
    force_verify = False
    for s in signals:
        score = max(score, _WEIGHTS.get(s.get("severity", "low"), 0.1))
        if s.get("force") == "verify":
            force_verify = True

    if force_verify:
        decision = "verify"
    elif score >= 0.75:
        decision = "block"
    elif score >= 0.35:
        decision = "alert"
    else:
        decision = "pass"

    return {"risk_score": score, "decision": decision}
