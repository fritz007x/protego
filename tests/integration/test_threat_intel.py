"""Integration: real Google Safe Browsing and urlscan.io calls."""
import pytest

from tests.integration.conftest import threat_intel_sb, threat_intel_us
from cyber_agent.tools.safe_browsing import check_url_safe_browsing
from cyber_agent.tools.urlscan import urlscan_submit

# EICAR-equivalent test URL from Safe Browsing test suite
_SAFE_TEST_URL = "https://testsafebrowsing.appspot.com/s/phishing.html"
_BENIGN_URL = "https://www.example.com"


@threat_intel_sb
def test_safe_browsing_flags_known_phishing():
    result = check_url_safe_browsing.invoke({"url": _SAFE_TEST_URL})
    assert result["checked"] is True
    assert len(result.get("matches", [])) > 0


@threat_intel_sb
def test_safe_browsing_passes_benign_url():
    result = check_url_safe_browsing.invoke({"url": _BENIGN_URL})
    assert result["checked"] is True
    assert result.get("matches", []) == []


@threat_intel_us
def test_urlscan_submits_url():
    result = urlscan_submit.invoke({"url": _BENIGN_URL})
    assert result["submitted"] is True
    assert "response" in result
