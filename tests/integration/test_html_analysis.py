"""Integration: real HTTP fetch + HTML analysis. Needs network access.

Run with:
    SKIP_NETWORK_TESTS=0 pytest tests/integration/test_html_analysis.py -v
"""
import os

import pytest

from cyber_agent.tools.html_analysis import analyze_html

html_integration = pytest.mark.skipif(
    os.getenv("SKIP_NETWORK_TESTS", "1") == "1",
    reason="Network tests skipped (set SKIP_NETWORK_TESTS=0 to run)",
)


@html_integration
def test_example_com_is_clean():
    result = analyze_html.invoke({"url": "https://www.example.com"})
    assert result["analyzed"] is True
    assert result["summary_severity"] == "none"
    assert result["fetch"]["ssl_valid"] is True


@html_integration
def test_redirect_chain_captured():
    # http → https redirect
    result = analyze_html.invoke({"url": "http://www.example.com"})
    assert result["analyzed"] is True
    assert len(result["fetch"]["redirect_chain"]) >= 1


@html_integration
def test_ssl_valid_on_known_good_site():
    result = analyze_html.invoke({"url": "https://www.google.com"})
    assert result["fetch"]["ssl_valid"] is True
    assert result["analyzed"] is True
