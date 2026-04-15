from __future__ import annotations

from ..preprocessing.ocr import extract_invoice_fields
from ..state import ThreatState


def preprocess(state: ThreatState) -> dict:
    raw = state.get("raw_input") or {}
    content = raw.get("content")
    parsed = extract_invoice_fields(content) if content is not None else {}
    return {"parsed": parsed}
