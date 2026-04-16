from __future__ import annotations

from ..data.watsonx_data import get_vendor
from ..llm import make_llm
from ..state import ThreatState

_PROMPT_TEMPLATE = """\
You are an expert financial fraud analyst specializing in invoice fraud detection. \
Your task is to analyze an invoice and determine if it is legitimate or fraudulent \
using a systematic Chain of Thought approach. You will be provided with:
1. Extracted invoice fields (vendor, amount, bank account, invoice number, date)
2. Known vendor record from historical data
3. Pre-detected anomaly signals from rule-based checks

Please analyze the invoice step-by-step using the following Chain of Thought process:

STEP 1: VENDOR ANALYSIS
- Is this a known vendor or a first-time supplier?
- Does the vendor name match any known legitimate suppliers?
- Are there signs of vendor impersonation (slight name variations, typos)?
- Assess the risk level of dealing with an unknown vendor

STEP 2: PAYMENT DETAILS ANALYSIS
- Does the bank account match the stored record for this vendor?
- Is the payment amount consistent with historical invoices?
- Are there any unusual payment instructions (urgent wire, gift card, crypto)?
- Flag any discrepancies between current and historical payment details

STEP 3: DOCUMENT ANALYSIS
- Is the invoice number format consistent with prior invoices?
- Is the invoice date reasonable (not backdated, not far future)?
- Are there signs of document manipulation or template fraud?
- Assess the overall legitimacy of the document structure

STEP 4: HISTORICAL COMPARISON
- How does this invoice compare to the vendor's historical average amount?
- Is there a pattern of escalating amounts or frequency changes?
- Does the timing align with expected billing cycles?
- Consider any metadata anomalies relative to the vendor record

STEP 5: FINAL ASSESSMENT
- Weigh all evidence from previous steps
- Consider the overall fraud risk profile
- Make a final classification with confidence level

Format your response as:
STEP 1: [Your vendor analysis]
STEP 2: [Your payment details analysis]
STEP 3: [Your document analysis]
STEP 4: [Your historical comparison]
STEP 5: [Your final assessment]
CLASSIFICATION: [FRAUDULENT or LEGITIMATE]
CONFIDENCE: [High/Medium/Low]
REASONING: [Brief summary of key factors that led to your decision]

---
EXTRACTED INVOICE FIELDS:
  Vendor:         {vendor}
  Amount:         {amount}
  Bank Account:   {bank_account}
  Invoice No:     {invoice_no}
  Date:           {date}

KNOWN VENDOR RECORD:
{vendor_record}

PRE-DETECTED SIGNALS:
{signals_summary}
"""


def _build_prompt(
    vendor: str | None,
    amount: float | None,
    bank: str | None,
    invoice_no: str | None,
    date: str | None,
    record: dict | None,
    signals: list[dict],
) -> str:
    vendor_record = (
        f"  Stored bank account: {record.get('bank_account')}\n"
        f"  Average amount:      {record.get('avg_amount')}\n"
        f"  Last seen:           {record.get('last_seen')}"
        if record else "  No prior record found (new vendor)"
    )
    if signals:
        signals_summary = "\n".join(
            f"  [{s['severity'].upper()}] {s['reason']}: {s.get('detail', '')}"
            for s in signals
        )
    else:
        signals_summary = "  None"

    return _PROMPT_TEMPLATE.format(
        vendor=vendor or "(unknown)",
        amount=amount if amount is not None else "(unknown)",
        bank_account=bank or "(unknown)",
        invoice_no=invoice_no or "(unknown)",
        date=date or "(unknown)",
        vendor_record=vendor_record,
        signals_summary=signals_summary,
    )


def _parse_classification(response: str) -> tuple[str, str]:
    classification = "UNKNOWN"
    confidence = "Low"
    for line in response.splitlines():
        line = line.strip()
        if line.upper().startswith("CLASSIFICATION:"):
            val = line.split(":", 1)[1].strip().upper()
            if "FRAUDULENT" in val:
                classification = "FRAUDULENT"
            elif "LEGITIMATE" in val:
                classification = "LEGITIMATE"
        elif line.upper().startswith("CONFIDENCE:"):
            val = line.split(":", 1)[1].strip().capitalize()
            if val in ("High", "Medium", "Low"):
                confidence = val
    return classification, confidence


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
    prompt = _build_prompt(
        vendor, amount, bank,
        parsed.get("invoice_no"), parsed.get("date"),
        record, signals,
    )
    try:
        llm_response = str(llm.invoke(prompt))
        reasoning = llm_response
        classification, confidence = _parse_classification(llm_response)
        if classification == "FRAUDULENT":
            severity = "high" if confidence == "High" else "medium"
            signals.append({
                "source": "invoice",
                "severity": severity,
                "reason": "llm_classified_fraudulent",
                "detail": f"confidence={confidence}",
            })
    except Exception as e:  # pragma: no cover - defensive for remote API
        reasoning = f"[llm-error] {e}"

    return {"signals": signals, "reasoning": reasoning, "threat_type": "invoice"}
