"""Shared LLM response parsing utilities for agent nodes."""
from __future__ import annotations


def confidence_to_severity(confidence: str) -> str:
    """Map High/Medium/Low confidence string to high/medium/low severity."""
    return {"High": "high", "Medium": "medium", "Low": "low"}.get(confidence, "low")


def extract_sender_domain(sender: str) -> str:
    """Extract domain from an email address, or return the sender itself if no @."""
    if sender and "@" in sender:
        return sender.split("@", 1)[1]
    return sender or "(unknown)"


def truncate_at_word(text: str, limit: int) -> str:
    """Truncate text at a word boundary at or before limit characters."""
    if len(text) <= limit:
        return text
    boundary = text.rfind(" ", 0, limit)
    return text[:boundary] if boundary > 0 else text[:limit]


def parse_classification(response: str, positive_label: str) -> tuple[str, str]:
    """Extract CLASSIFICATION and CONFIDENCE from a structured LLM response.

    Args:
        response: Raw LLM output text.
        positive_label: The label to match as the positive case (e.g. "PHISHING", "FRAUDULENT").

    Returns:
        (classification, confidence) where classification is positive_label, its opposite, or
        "UNKNOWN"; and confidence is "High", "Medium", or "Low".
    """
    classification = "UNKNOWN"
    confidence = "Low"
    for line in response.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("CLASSIFICATION:"):
            val = stripped.split(":", 1)[1].strip().upper()
            if positive_label.upper() in val:
                classification = positive_label.upper()
            elif val:
                classification = "LEGITIMATE"
        elif stripped.upper().startswith("CONFIDENCE:"):
            val = stripped.split(":", 1)[1].strip().capitalize()
            if val in ("High", "Medium", "Low"):
                confidence = val
    return classification, confidence


def parse_bec_response(response: str) -> tuple[str, str, float]:
    """Extract Overall_BEC_Risk, Phishing_Claim, and Confidence from a BEC LLM response.

    Returns:
        (risk, phishing_claim, confidence) where risk is "High"/"Medium"/"Low",
        phishing_claim is "Yes"/"No", and confidence is clamped to [0.0, 1.0].
    """
    risk = "Low"
    phishing_claim = "No"
    confidence = 0.0
    for line in response.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if low.startswith("- overall_bec_risk:"):
            val = stripped.split(":", 1)[1].strip().capitalize()
            if val in ("Low", "Medium", "High"):
                risk = val
        elif low.startswith("- phishing_claim:"):
            val = stripped.split(":", 1)[1].strip().lower()
            phishing_claim = "Yes" if "yes" in val else "No"
        elif low.startswith("- confidence:"):
            try:
                raw = float(stripped.split(":", 1)[1].strip())
                confidence = max(0.0, min(1.0, raw))
            except ValueError:
                pass
    return risk, phishing_claim, confidence
