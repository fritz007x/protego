from __future__ import annotations

from ..llm import make_llm
from ..rag.retriever import retrieve_similar
from ..state import ThreatState
from ..tools.email_baseline import get_sender_baseline

_URGENCY_WORDS = ("urgent", "asap", "immediately", "wire", "gift card", "confidential")


def bec_agent(state: ThreatState) -> dict:
    parsed = state.get("parsed") or {}
    text = (parsed.get("text") or "").lower()

    signals: list[dict] = []
    hits = [w for w in _URGENCY_WORDS if w in text]
    if hits:
        signals.append(
            {
                "source": "bec",
                "severity": "medium" if len(hits) < 3 else "high",
                "reason": "urgency_language",
                "detail": hits,
            }
        )

    # RAG: pull similar known BEC/phishing patterns
    similar = retrieve_similar(text, k=3)
    top_bec = [s for s in similar if s["type"] == "bec" and s["score"] > 0.6]
    if top_bec:
        signals.append(
            {
                "source": "bec",
                "severity": "high",
                "reason": "similar_known_bec",
                "detail": top_bec,
            }
        )

    # Sender baseline (stubbed)
    raw = state.get("raw_input") or {}
    sender = (raw.get("sender") or "").strip()
    if sender:
        baseline = get_sender_baseline.invoke({"email": sender})
        state_out_baseline = baseline
    else:
        state_out_baseline = None

    llm = make_llm("bec")
    try:
        reasoning = str(
            llm.invoke(
                "Assess this message for Business Email Compromise indicators in one sentence.\n"
                + text[:1500]
            )
        )
    except Exception as e:
        reasoning = f"[llm-error] {e}"
    out = {"signals": signals, "reasoning": reasoning, "threat_type": "bec"}
    if state_out_baseline is not None:
        out["parsed"] = {**parsed, "sender_baseline": state_out_baseline, "rag": similar}
    else:
        out["parsed"] = {**parsed, "rag": similar}
    return out
