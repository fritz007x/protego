from __future__ import annotations

from langchain_core.tools import tool

from ..data.watsonx_data import get_vendor, upsert_vendor


@tool
def lookup_vendor(vendor_name: str) -> dict:
    """Return the stored record for a vendor or an empty dict if unknown."""
    return get_vendor(vendor_name) or {}


@tool
def remember_vendor(vendor_name: str, bank_account: str, avg_amount: float) -> str:
    """Create or update a vendor record after human verification."""
    upsert_vendor(vendor_name, bank_account=bank_account, avg_amount=avg_amount)
    return "ok"
