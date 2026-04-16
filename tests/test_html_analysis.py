from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cyber_agent.tools.html_analysis import analyze_html


def _make_response(
    html: str,
    status: int = 200,
    url: str = "https://evil-phish.xyz/login",
    content_type: str = "text/html; charset=utf-8",
    history: list[str] | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.url = url
    resp.headers = {"content-type": content_type}
    resp.content = html.encode("utf-8")
    resp.history = [MagicMock(url=u) for u in (history or [])]
    return resp


def _patch(html: str, **kw):
    """Context manager: patch httpx.Client so analyze_html runs offline."""
    resp = _make_response(html, **kw)
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)
    cm.get = MagicMock(return_value=resp)
    return patch("cyber_agent.tools.html_analysis.httpx.Client", return_value=cm)


# ── Login forms ────────────────────────────────────────────────────────────────

def test_login_form_offsite_detected():
    html = '<form action="https://evil.example.com/steal"><input type="password"></form>'
    with _patch(html, url="https://legitimate-bank.com/page"):
        out = analyze_html.invoke({"url": "https://legitimate-bank.com/page"})
    assert out["analyzed"] is True
    ind = out["indicators"]["login_form_offsite"]
    assert ind["found"] is True
    assert ind["severity"] == "high"


def test_login_form_same_domain_not_flagged():
    html = '<form action="https://legitimate-bank.com/submit"><input type="password"></form>'
    with _patch(html, url="https://legitimate-bank.com/page"):
        out = analyze_html.invoke({"url": "https://legitimate-bank.com/page"})
    assert out["indicators"]["login_form_offsite"]["found"] is False


# ── Brand impersonation ────────────────────────────────────────────────────────

def test_brand_impersonation_detected():
    html = (
        "<title>Microsoft Login</title>"
        '<img src="microsoft-logo.png" alt="microsoft">'
        '<input type="password">'
    )
    with _patch(html, url="https://m1cr0soft-login.xyz/"):
        out = analyze_html.invoke({"url": "https://m1cr0soft-login.xyz/"})
    assert out["indicators"]["brand_impersonation"]["found"] is True
    assert out["indicators"]["brand_impersonation"]["severity"] == "high"


def test_brand_on_legitimate_domain_not_flagged():
    html = (
        "<title>Microsoft Login</title>"
        '<img src="logo.png" alt="microsoft">'
        '<input type="password">'
    )
    with _patch(html, url="https://microsoft.com/login"):
        out = analyze_html.invoke({"url": "https://microsoft.com/login"})
    assert out["indicators"]["brand_impersonation"]["found"] is False


# ── Obfuscated JS ──────────────────────────────────────────────────────────────

def test_obfuscated_js_eval_detected():
    html = '<script>eval(atob("SGVsbG8gV29ybGQ="))</script>'
    with _patch(html):
        out = analyze_html.invoke({"url": "https://evil.xyz/"})
    ind = out["indicators"]["obfuscated_js"]
    assert ind["found"] is True
    assert ind["severity"] == "medium"


def test_clean_js_not_flagged():
    html = "<script>document.getElementById('x').style.display='block';</script>"
    with _patch(html):
        out = analyze_html.invoke({"url": "https://clean.com/"})
    assert out["indicators"]["obfuscated_js"]["found"] is False


# ── Page quality ───────────────────────────────────────────────────────────────

def test_low_quality_page_detected():
    html = (
        '<form action="/submit"><input type="password"></form>'
        '<div style="display:none">h</div>'
        '<div style="display:none">h</div>'
        '<div style="display:none">h</div>'
        "Hi"
    )
    with _patch(html):
        out = analyze_html.invoke({"url": "https://evil.xyz/"})
    assert out["indicators"]["low_quality_page"]["found"] is True


# ── Data exfiltration ──────────────────────────────────────────────────────────

def test_external_iframe_detected():
    html = '<iframe src="https://evil.com/collect"></iframe>'
    with _patch(html, url="https://victim.com/"):
        out = analyze_html.invoke({"url": "https://victim.com/"})
    assert out["indicators"]["data_exfiltration"]["found"] is True
    assert out["indicators"]["data_exfiltration"]["severity"] == "high"


# ── Metadata ───────────────────────────────────────────────────────────────────

def test_missing_title_flagged():
    html = "<html><body><p>No title here</p></body></html>"
    with _patch(html):
        out = analyze_html.invoke({"url": "https://suspicious.xyz/"})
    assert out["indicators"]["suspicious_metadata"]["found"] is True


def test_meta_refresh_redirect_flagged():
    html = (
        '<html><head><title>Wait</title>'
        '<meta http-equiv="refresh" content="0;url=https://evil.com">'
        "</head></html>"
    )
    with _patch(html):
        out = analyze_html.invoke({"url": "https://suspicious.xyz/"})
    assert out["indicators"]["suspicious_metadata"]["found"] is True


# ── Fetch error states ─────────────────────────────────────────────────────────

def test_ssl_error_records_ssl_invalid():
    import httpx

    real_resp = _make_response("<html><title>X</title></html>")
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)
    # First call raises SSLError, second returns normally
    cm.get = MagicMock(side_effect=[httpx.ConnectError("ssl cert verify failed"), real_resp])

    with patch("cyber_agent.tools.html_analysis.httpx.Client", return_value=cm):
        out = analyze_html.invoke({"url": "https://bad-cert.example.com/"})
    assert out["analyzed"] is True
    assert out["fetch"]["ssl_valid"] is False


def test_timeout_returns_not_analyzed():
    import httpx

    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)
    cm.get = MagicMock(side_effect=httpx.TimeoutException("timeout"))

    with patch("cyber_agent.tools.html_analysis.httpx.Client", return_value=cm):
        out = analyze_html.invoke({"url": "https://slow.example.com/"})
    assert out["analyzed"] is False
    assert out["reason"] == "timeout"


def test_non_html_returns_not_analyzed():
    resp = _make_response(b"binary".decode(), content_type="application/pdf")
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)
    cm.get = MagicMock(return_value=resp)

    with patch("cyber_agent.tools.html_analysis.httpx.Client", return_value=cm):
        out = analyze_html.invoke({"url": "https://example.com/doc.pdf"})
    assert out["analyzed"] is False
    assert out["reason"] == "not_html"


def test_blocked_returns_not_analyzed():
    resp = _make_response("", status=403)
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)
    cm.get = MagicMock(return_value=resp)

    with patch("cyber_agent.tools.html_analysis.httpx.Client", return_value=cm):
        out = analyze_html.invoke({"url": "https://example.com/"})
    assert out["analyzed"] is False
    assert out["reason"] == "blocked"


def test_redirect_chain_recorded():
    hops = [
        "https://bit.ly/xyz",
        "https://redirect1.com/",
        "https://redirect2.com/",
        "https://redirect3.com/",
    ]
    resp = _make_response("<html><title>Final</title></html>", history=hops)
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)
    cm.get = MagicMock(return_value=resp)

    with patch("cyber_agent.tools.html_analysis.httpx.Client", return_value=cm):
        out = analyze_html.invoke({"url": "https://bit.ly/xyz"})
    assert out["analyzed"] is True
    assert len(out["fetch"]["redirect_chain"]) == 4
