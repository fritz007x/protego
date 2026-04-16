from __future__ import annotations

import pytest

from cyber_agent.nodes._parse_utils import (
    parse_bec_response,
    parse_classification,
    truncate_at_word,
)
from cyber_agent.nodes.bec_agent import _build_prompt as bec_build_prompt
from cyber_agent.nodes.invoice_agent import _build_prompt as invoice_build_prompt
from cyber_agent.nodes.phishing_agent import _build_prompt as phishing_build_prompt


# ── parse_classification ───────────────────────────────────────────────────────

def test_parse_classification_phishing():
    resp = "STEP 5: looks bad\nCLASSIFICATION: PHISHING\nCONFIDENCE: High\n"
    c, conf = parse_classification(resp, "PHISHING")
    assert c == "PHISHING"
    assert conf == "High"


def test_parse_classification_legitimate():
    resp = "CLASSIFICATION: LEGITIMATE\nCONFIDENCE: Medium"
    c, conf = parse_classification(resp, "PHISHING")
    assert c == "LEGITIMATE"
    assert conf == "Medium"


def test_parse_classification_fraudulent():
    resp = "CLASSIFICATION: FRAUDULENT\nCONFIDENCE: Low"
    c, conf = parse_classification(resp, "FRAUDULENT")
    assert c == "FRAUDULENT"
    assert conf == "Low"


def test_parse_classification_empty_response():
    c, conf = parse_classification("", "PHISHING")
    assert c == "UNKNOWN"
    assert conf == "Low"


def test_parse_classification_missing_confidence():
    resp = "CLASSIFICATION: PHISHING\n"
    c, conf = parse_classification(resp, "PHISHING")
    assert c == "PHISHING"
    assert conf == "Low"  # default


def test_parse_classification_unrecognised_confidence():
    resp = "CLASSIFICATION: PHISHING\nCONFIDENCE: Very High"
    _, conf = parse_classification(resp, "PHISHING")
    assert conf == "Low"  # unrecognised → default


# ── parse_bec_response ─────────────────────────────────────────────────────────

def test_parse_bec_response_high_risk():
    resp = (
        "- Phishing_Claim: Yes\n"
        "- Impersonation_Claim: Yes\n"
        "- Overall_BEC_Risk: High\n"
        "- Confidence: 0.92\n"
    )
    risk, phishing, conf = parse_bec_response(resp)
    assert risk == "High"
    assert phishing == "Yes"
    assert conf == 0.92


def test_parse_bec_response_confidence_clamped():
    resp = "- Overall_BEC_Risk: Low\n- Confidence: 5.0\n"
    _, _, conf = parse_bec_response(resp)
    assert conf == 1.0  # clamped to max


def test_parse_bec_response_confidence_negative_clamped():
    resp = "- Overall_BEC_Risk: Low\n- Confidence: -0.5\n"
    _, _, conf = parse_bec_response(resp)
    assert conf == 0.0


def test_parse_bec_response_empty():
    risk, phishing, conf = parse_bec_response("")
    assert risk == "Low"
    assert phishing == "No"
    assert conf == 0.0


def test_parse_bec_response_invalid_confidence():
    resp = "- Confidence: not-a-number\n"
    _, _, conf = parse_bec_response(resp)
    assert conf == 0.0  # default on ValueError


# ── _build_prompt smoke tests ──────────────────────────────────────────────────

def test_invoice_build_prompt_no_crash():
    out = invoice_build_prompt(
        vendor="Acme", amount=500.0, bank="ACME-111",
        invoice_no="INV-1", date="2026-01-01", record=None, signals=[],
    )
    assert "Acme" in out
    assert "ACME-111" in out
    assert "No prior record" in out


def test_invoice_build_prompt_with_signals():
    signals = [{"severity": "high", "reason": "bank_account_changed", "detail": "x"}]
    out = invoice_build_prompt(
        vendor="Acme", amount=500.0, bank="NEW-999",
        invoice_no="INV-2", date="2026-01-02",
        record={"bank_account": "ACME-111", "avg_amount": 500.0, "last_seen": None},
        signals=signals,
    )
    assert "bank_account_changed" in out
    assert "HIGH" in out


def test_phishing_build_prompt_no_urls():
    out = phishing_build_prompt("Click here now!", [], [])
    assert "none found" in out
    assert "no URLs fetched" in out


def test_phishing_build_prompt_with_url_results():
    url_results = [{
        "url": "http://evil.zip",
        "html_analysis": {
            "analyzed": True,
            "fetch": {"ssl_valid": True, "redirect_chain": [], "final_url": "http://evil.zip", "ssl_error": None},
            "indicators": {"login_form_offsite": {"found": True}},
        },
        "urlscan": {"submitted": False, "reason": "no_api_key"},
    }]
    out = phishing_build_prompt("Visit us!", ["http://evil.zip"], url_results)
    assert "evil.zip" in out
    assert "login_form_offsite" in out
    assert "no_api_key" in out


def test_bec_build_prompt_extracts_sender_domain():
    out = bec_build_prompt("Please wire money", "ceo@example.com", [])
    assert "example.com" in out
    assert "ceo@example.com" not in out  # full address should not appear as domain


def test_bec_build_prompt_includes_rag():
    similar = [{"type": "bec", "score": 0.9, "pattern": "urgent wire transfer from CEO"}]
    out = bec_build_prompt("Wire money now", "boss@evil.com", similar)
    assert "urgent wire transfer from CEO" in out
    assert "0.90" in out


def test_bec_build_prompt_no_sender():
    out = bec_build_prompt("No sender here", "", [])
    assert "unknown" in out


# ── truncate_at_word ──────────────────────────────────────────────────────────

def test_truncate_short_text_unchanged():
    assert truncate_at_word("hello world", 2000) == "hello world"


def testtruncate_at_word_boundary():
    text = "one two three four five"
    result = truncate_at_word(text, 11)  # "one two thr" → boundary at 7 ("one two")
    assert result == "one two"
    assert not result.endswith(" ")


def test_truncate_no_space_falls_back_to_hard_cut():
    text = "a" * 100
    result = truncate_at_word(text, 10)
    assert len(result) == 10
