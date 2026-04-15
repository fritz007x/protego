from __future__ import annotations

from ..data.watsonx_data import get_vendor
from ..llm import make_llm
from ..state import ThreatState


def invoice_agent(state: ThreatState) -> dict:
    parsed = state.get("parsed") or {}
    vendor = parsed.get("vendor")
    bank = parsed.get("bank_account")
    amount = parsed.get("amount")

    signals: list[dict] = []
    record = get_vendor(vendor) if vendor else None

    if record is None:
        signals.append(
            {
                "source": "invoice",
                "severity": "medium",
                "reason": "new_vendor",
                "detail": f"No prior record for vendor={vendor!r}",
            }
        )
    else:
        stored_bank = (record.get("bank_account") or "").upper()
        if bank and stored_bank and bank != stored_bank:
            signals.append(
                {
                    "source": "invoice",
                    "severity": "high",
                    "reason": "bank_account_changed",
                    "force": "verify",
                    "detail": f"stored={stored_bank!r} new={bank!r}",
                }
            )
        avg = record.get("avg_amount")
        if amount and avg and avg > 0 and amount > 2 * avg:
            signals.append(
                {
                    "source": "invoice",
                    "severity": "medium",
                    "reason": "amount_anomaly",
                    "detail": f"avg={avg} new={amount}",
                }
            )

    llm = make_llm("invoice")
    prompt = (
        "You are an invoice fraud analyst. Given the extracted fields, "
        "state in one sentence whether anything looks suspicious.\n"
        f"Fields: vendor={vendor} amount={amount} bank_account={bank}\n"
        f"Known vendor record: {record}\n"
    )
    try:
        reasoning = str(llm.invoke(prompt))
    except Exception as e:  # pragma: no cover - defensive for remote API
        reasoning = f"[llm-error] {e}"

    return {"signals": signals, "reasoning": reasoning, "threat_type": "invoice"}
