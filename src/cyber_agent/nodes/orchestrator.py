from __future__ import annotations

import re
from typing import Literal

from langgraph.types import Command

from ..state import ThreatState

_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_INVOICE_HINTS = ("invoice", "amount due", "account number", "bill to")
_BEC_HINTS = ("wire transfer", "gift card", "urgent", "confidential")


def orchestrator(
    state: ThreatState,
) -> Command[Literal["invoice_agent", "phishing_agent", "bec_agent"]]:
    raw = state.get("raw_input") or {}
    declared = (raw.get("type") or "").lower()
    parsed = state.get("parsed") or {}
    text = (parsed.get("text") or "").lower()

    if declared in {"invoice", "phishing", "bec"}:
        route = declared
    elif any(h in text for h in _INVOICE_HINTS):
        route = "invoice"
    elif _URL_RE.search(text):
        route = "phishing"
    elif any(h in text for h in _BEC_HINTS):
        route = "bec"
    else:
        route = "phishing"

    goto = {"invoice": "invoice_agent", "phishing": "phishing_agent", "bec": "bec_agent"}[route]
    return Command(update={"threat_type": route}, goto=goto)
