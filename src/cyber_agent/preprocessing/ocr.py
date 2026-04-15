"""Invoice field extraction. Supports raw PDF bytes or already-extracted text dicts."""
from __future__ import annotations

import re
from typing import Any


_VENDOR_RE = re.compile(r"(?:vendor|from|bill\s*from)\s*[:\-]\s*(.+)", re.IGNORECASE)
_BANK_RE = re.compile(r"(?:account|acct|iban)\s*(?:no\.?|number)?\s*[:\-]?\s*([A-Z0-9\- ]{6,34})", re.IGNORECASE)
_AMOUNT_RE = re.compile(r"(?:total|amount\s*due|balance)\s*[:\-]?\s*\$?\s*([\d,]+(?:\.\d{2})?)", re.IGNORECASE)
_INV_RE = re.compile(r"invoice\s*(?:no\.?|number|#)\s*[:\-]?\s*([A-Za-z0-9\-]+)", re.IGNORECASE)
_DATE_RE = re.compile(r"(?:date|issued)\s*[:\-]?\s*(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})", re.IGNORECASE)


def extract_invoice_fields(source: Any) -> dict:
    """Accepts bytes (PDF), str (raw text), or dict with 'text'."""
    text = _to_text(source)
    return {
        "text": text,
        "vendor": _first(_VENDOR_RE, text),
        "bank_account": _normalize_acct(_first(_BANK_RE, text)),
        "amount": _to_float(_first(_AMOUNT_RE, text)),
        "invoice_no": _first(_INV_RE, text),
        "date": _first(_DATE_RE, text),
    }


def _to_text(source: Any) -> str:
    if isinstance(source, dict) and "text" in source:
        return source["text"]
    if isinstance(source, str):
        return source
    if isinstance(source, bytes):
        try:
            import pdfplumber  # type: ignore
            import io

            with pdfplumber.open(io.BytesIO(source)) as pdf:
                return "\n".join((p.extract_text() or "") for p in pdf.pages)
        except Exception:
            try:
                return source.decode("utf-8", errors="ignore")
            except Exception:
                return ""
    return ""


def _first(pat: re.Pattern, text: str) -> str | None:
    m = pat.search(text)
    return m.group(1).strip() if m else None


def _normalize_acct(val: str | None) -> str | None:
    if not val:
        return None
    return re.sub(r"\s+", "", val).upper()


def _to_float(val: str | None) -> float | None:
    if not val:
        return None
    try:
        return float(val.replace(",", ""))
    except ValueError:
        return None
