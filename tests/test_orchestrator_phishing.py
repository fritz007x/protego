from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

from langgraph.checkpoint.memory import MemorySaver

from cyber_agent.graph import build_graph


def _run(graph, text: str, declared: str = ""):
    tid = str(uuid.uuid4())
    cfg = {"configurable": {"thread_id": tid}}
    return graph.invoke(
        {"raw_input": {"type": declared, "content": text}, "trace_id": tid},
        config=cfg,
    )


def test_orchestrator_routes_invoice():
    out = _run(
        build_graph(checkpointer=MemorySaver()),
        "Vendor: X\nInvoice No: 1\nAmount Due: $10\nAccount Number: A-1\n",
    )
    assert out["threat_type"] == "invoice"


def test_orchestrator_routes_phishing_on_url():
    out = _run(
        build_graph(checkpointer=MemorySaver()),
        "Hello, click http://evil.example.zip to update your account.",
    )
    assert out["threat_type"] == "phishing"
    assert any(s.get("reason") == "suspicious_tld" for s in out["signals"])


def _html_result(indicators: dict) -> dict:
    """Build a canned analyze_html return value with the given indicators found."""
    found_severities = [v["severity"] for v in indicators.values() if v.get("found")]
    severity_order = {"high": 3, "medium": 2, "low": 1}
    summary = max(found_severities, key=lambda s: severity_order.get(s, 0), default="none")
    return {
        "url": "http://evil.example.zip",
        "analyzed": True,
        "fetch": {"status_code": 200, "final_url": "http://evil.example.zip",
                  "redirect_chain": [], "content_type": "text/html",
                  "ssl_valid": True, "ssl_error": None},
        "indicators": indicators,
        "summary_severity": summary,
    }


def test_html_credential_harvest_signal_emitted():
    """analyze_html returning login_form_offsite=True must produce html_credential_harvest signal."""
    canned = _html_result({
        "login_form_offsite":  {"found": True,  "severity": "high",   "details": ["form action=steal.com"]},
        "brand_impersonation": {"found": False, "severity": None,     "details": []},
        "obfuscated_js":       {"found": False, "severity": None,     "details": []},
        "low_quality_page":    {"found": False, "severity": None,     "details": []},
        "data_exfiltration":   {"found": False, "severity": None,     "details": []},
        "suspicious_metadata": {"found": False, "severity": None,     "details": []},
    })
    with patch("cyber_agent.nodes.phishing_agent.analyze_html") as mock_html:
        mock_html.invoke = MagicMock(return_value=canned)
        out = _run(
            build_graph(checkpointer=MemorySaver()),
            "Click http://evil.example.zip to verify your account.",
        )
    assert out["threat_type"] == "phishing"
    assert any(s.get("reason") == "html_credential_harvest" for s in out["signals"])
    assert any(s.get("severity") == "high" for s in out["signals"]
               if s.get("reason") == "html_credential_harvest")


def test_html_brand_impersonation_signal_emitted():
    canned = _html_result({
        "login_form_offsite":  {"found": False, "severity": None,   "details": []},
        "brand_impersonation": {"found": True,  "severity": "high", "details": ["brand=microsoft on evil.zip"]},
        "obfuscated_js":       {"found": False, "severity": None,   "details": []},
        "low_quality_page":    {"found": False, "severity": None,   "details": []},
        "data_exfiltration":   {"found": False, "severity": None,   "details": []},
        "suspicious_metadata": {"found": False, "severity": None,   "details": []},
    })
    with patch("cyber_agent.nodes.phishing_agent.analyze_html") as mock_html:
        mock_html.invoke = MagicMock(return_value=canned)
        out = _run(
            build_graph(checkpointer=MemorySaver()),
            "Sign in to Microsoft at http://evil.example.zip",
        )
    assert any(s.get("reason") == "html_brand_impersonation" for s in out["signals"])


def test_html_ssl_invalid_signal_emitted():
    canned = {
        "url": "http://evil.example.zip",
        "analyzed": True,
        "fetch": {"status_code": 200, "final_url": "http://evil.example.zip",
                  "redirect_chain": [], "content_type": "text/html",
                  "ssl_valid": False, "ssl_error": "cert verify failed"},
        "indicators": {k: {"found": False, "severity": None, "details": []}
                       for k in ("login_form_offsite", "brand_impersonation", "obfuscated_js",
                                 "low_quality_page", "data_exfiltration", "suspicious_metadata")},
        "summary_severity": "none",
    }
    with patch("cyber_agent.nodes.phishing_agent.analyze_html") as mock_html:
        mock_html.invoke = MagicMock(return_value=canned)
        out = _run(
            build_graph(checkpointer=MemorySaver()),
            "Click http://evil.example.zip now.",
        )
    assert any(s.get("reason") == "html_ssl_invalid" for s in out["signals"])


def test_html_excessive_redirects_signal_emitted():
    canned = {
        "url": "http://evil.example.zip",
        "analyzed": True,
        "fetch": {"status_code": 200, "final_url": "http://final.evil.com",
                  "redirect_chain": ["h1", "h2", "h3", "h4"],
                  "content_type": "text/html", "ssl_valid": True, "ssl_error": None},
        "indicators": {k: {"found": False, "severity": None, "details": []}
                       for k in ("login_form_offsite", "brand_impersonation", "obfuscated_js",
                                 "low_quality_page", "data_exfiltration", "suspicious_metadata")},
        "summary_severity": "none",
    }
    with patch("cyber_agent.nodes.phishing_agent.analyze_html") as mock_html:
        mock_html.invoke = MagicMock(return_value=canned)
        out = _run(
            build_graph(checkpointer=MemorySaver()),
            "Visit http://evil.example.zip for your prize.",
        )
    assert any(s.get("reason") == "html_excessive_redirects" for s in out["signals"])


def test_clean_html_emits_no_html_signals():
    """When analyze_html returns analyzed=False (e.g. blocked), no html_* signals appear."""
    canned = {"url": "http://evil.example.zip", "analyzed": False, "reason": "blocked"}
    with patch("cyber_agent.nodes.phishing_agent.analyze_html") as mock_html:
        mock_html.invoke = MagicMock(return_value=canned)
        out = _run(
            build_graph(checkpointer=MemorySaver()),
            "Click http://evil.example.zip",
        )
    html_signals = [s for s in out["signals"] if s.get("reason", "").startswith("html_")]
    assert html_signals == []


def test_orchestrator_routes_bec():
    out = _run(
        build_graph(checkpointer=MemorySaver()),
        "URGENT wire transfer required, confidential — please send gift card details.",
    )
    assert out["threat_type"] == "bec"
    assert any(s.get("reason") == "urgency_language" for s in out["signals"])
