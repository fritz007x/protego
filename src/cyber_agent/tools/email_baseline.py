from __future__ import annotations

from langchain_core.tools import tool


@tool
def get_sender_baseline(email: str) -> dict:
    """Return a (stubbed) behavioral baseline for a sender.

    Real implementation would query email_baselines in watsonx.data.
    """
    return {
        "sender": email,
        "avg_hour": 10,
        "typical_recipients": ["finance@example.com"],
        "tone": "formal",
    }
