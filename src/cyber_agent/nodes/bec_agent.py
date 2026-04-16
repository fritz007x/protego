from __future__ import annotations

from ..llm import make_llm
from ..rag.retriever import retrieve_similar
from ..state import ThreatState
from ..tools.email_baseline import get_sender_baseline
from ._parse_utils import confidence_to_severity, extract_sender_domain, parse_bec_response

_URGENCY_WORDS: frozenset[str] = frozenset(
    ("urgent", "asap", "immediately", "wire", "gift card", "confidential")
)

_RISK_TO_SEVERITY = {"High": "high", "Medium": "medium", "Low": "low"}

_PROMPT_TEMPLATE = """\
You are a cybersecurity expert specializing in phishing and Business Email Compromise (BEC) detection.

Analyze the provided URL and visible text content to determine whether the content shows signs of phishing or impersonation.

Perform the following analyses:

1. Content Semantics Analysis:
   Evaluate whether the language indicates phishing intent. Look for:
   - Urgency or pressure tactics
   - Requests for sensitive information (credentials, payments, invoices)
   - Financial instructions or changes (e.g., bank details, wire transfers)
   - Emotional manipulation or authority pressure
   - Suspicious login or verification requests

2. Brand / Identity Impersonation Analysis:
   Determine whether the content attempts to impersonate a known organization or trusted entity. Look for:
   - Company or brand names (e.g., Microsoft, PayPal, internal executives)
   - Mismatches between the URL and claimed identity
   - Email-style impersonation (CEO, vendor, finance department)
   - Subtle misspellings or domain spoofing

Input:
- Sender domain: {sender_domain}
- Visible Text:
{visible_text}

Known BEC Patterns (from threat intelligence):
{rag_patterns}

Provide your response in the following structured format:

- Phishing_Claim: [Yes / No]
- Impersonation_Claim: [Yes / No]
- Overall_BEC_Risk: [Low / Medium / High]

- Confidence: [0 to 1]

- Evidence:
  - Content Signals: [Specific phrases, tone, or patterns]
  - Impersonation Signals: [Brand names, identity clues, mismatches]
  - URL Signals: [Suspicious structure, domain issues]

- Reasoning:
  [Brief explanation combining both analyses into a final judgment]
"""


def _build_prompt(text: str, sender: str, similar: list[dict]) -> str:
    rag_lines = (
        "\n".join(
            f"  [{s['type'].upper()}] (score={s['score']:.2f}) {s['pattern']}"
            for s in similar
        )
        if similar else "  (none)"
    )
    return _PROMPT_TEMPLATE.format(
        sender_domain=extract_sender_domain(sender),
        visible_text=text[:2000],
        rag_patterns=rag_lines,
    )


def bec_agent(state: ThreatState) -> dict:
    parsed = state.get("parsed") or {}
    raw_text = parsed.get("text") or ""
    text_lower = raw_text.lower()

    signals: list[dict] = []
    hits = [w for w in _URGENCY_WORDS if w in text_lower]
    if hits:
        signals.append({
            "source": "bec",
            "severity": "medium" if len(hits) < 3 else "high",
            "reason": "urgency_language",
            "detail": hits,
        })

    similar = retrieve_similar(text_lower, k=3)
    top_bec = [s for s in similar if s["type"] == "bec" and s["score"] > 0.6]
    if top_bec:
        signals.append({
            "source": "bec",
            "severity": "high",
            "reason": "similar_known_bec",
            "detail": top_bec,
        })

    raw = state.get("raw_input") or {}
    sender = (raw.get("sender") or "").strip()
    sender_baseline = get_sender_baseline.invoke({"email": sender}) if sender else None

    llm = make_llm("bec")
    prompt = _build_prompt(raw_text, sender, similar)
    reasoning = ""
    try:
        llm_response = str(llm.invoke(prompt))
        reasoning = llm_response
        risk, phishing_claim, confidence = parse_bec_response(llm_response)
        severity = _RISK_TO_SEVERITY.get(risk, "low")
        if phishing_claim == "Yes" and severity == "low":
            severity = "medium"
        if risk in ("Medium", "High") or phishing_claim == "Yes":
            signals.append({
                "source": "bec",
                "severity": severity,
                "reason": "llm_bec_risk",
                "detail": f"risk={risk} phishing={phishing_claim} confidence={confidence:.2f}",
            })
    except Exception as e:
        reasoning = f"[llm-error] {e}"

    extra = {"sender_baseline": sender_baseline} if sender_baseline is not None else {}
    return {
        "signals": signals,
        "reasoning": reasoning,
        "threat_type": "bec",
        "parsed": {**parsed, **extra, "rag": similar},
    }
