from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx
from langchain_core.tools import tool

_MAX_BODY_BYTES = 500_000
_TIMEOUT = 8.0
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

_BRANDS: frozenset[tuple[str, str]] = frozenset(
    [
        ("microsoft", "microsoft.com"),
        ("office365", "microsoft.com"),
        ("onedrive", "microsoft.com"),
        ("outlook", "microsoft.com"),
        ("google", "google.com"),
        ("gmail", "google.com"),
        ("paypal", "paypal.com"),
        ("apple", "apple.com"),
        ("icloud", "apple.com"),
        ("amazon", "amazon.com"),
        ("netflix", "netflix.com"),
        ("dhl", "dhl.com"),
        ("bank of america", "bankofamerica.com"),
        ("chase", "chase.com"),
        ("wells fargo", "wellsfargo.com"),
        ("docusign", "docusign.com"),
        ("dropbox", "dropbox.com"),
        ("linkedin", "linkedin.com"),
        ("facebook", "facebook.com"),
        ("instagram", "instagram.com"),
    ]
)

_SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "none": 0}


def _max_severity(*severities: str | None) -> str:
    best = "none"
    for s in severities:
        if s and _SEVERITY_ORDER.get(s, 0) > _SEVERITY_ORDER[best]:
            best = s
    return best


def _extract_domain(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _fetch_page(url: str) -> tuple[dict, str | None]:
    """Returns (fetch_meta_dict, html_body_or_None)."""
    meta: dict = {
        "status_code": None,
        "final_url": url,
        "redirect_chain": [],
        "content_type": "",
        "ssl_valid": True,
        "ssl_error": None,
    }
    headers = {"User-Agent": _USER_AGENT}

    def _do_get(verify: bool):
        with httpx.Client(follow_redirects=True, max_redirects=5, verify=verify) as client:
            resp = client.get(url, headers=headers, timeout=_TIMEOUT)
            return resp

    try:
        resp = _do_get(verify=True)
    except httpx.ConnectError as e:
        if "ssl" in str(e).lower() or "cert" in str(e).lower() or "certificate" in str(e).lower():
            meta["ssl_valid"] = False
            meta["ssl_error"] = str(e)
            try:
                resp = _do_get(verify=False)
            except Exception:
                return meta, None
        else:
            return {**meta, "error": str(e)}, None
    except httpx.TimeoutException:
        return {**meta, "error": "timeout"}, None
    except Exception as e:
        return {**meta, "error": str(e)}, None

    meta["status_code"] = resp.status_code
    meta["final_url"] = str(resp.url)
    meta["redirect_chain"] = [str(r.url) for r in resp.history]
    meta["content_type"] = resp.headers.get("content-type", "")

    if resp.status_code in (403, 429):
        return {**meta, "error": "blocked"}, None
    if "text/html" not in meta["content_type"].lower():
        return {**meta, "error": "not_html"}, None

    body = resp.content[:_MAX_BODY_BYTES].decode("utf-8", errors="ignore")
    return meta, body


def _check_login_forms(html: str, page_domain: str) -> dict:
    details: list[str] = []
    for m in re.finditer(r"<form\b[^>]*>", html, re.IGNORECASE | re.DOTALL):
        form_tag = m.group(0)
        action_m = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
        if not action_m:
            continue
        action = action_m.group(1)
        action_domain = _extract_domain(action)
        if action_domain and action_domain != page_domain and not action.startswith("/"):
            details.append(f"form action={action!r} (page domain: {page_domain!r})")
    return {"found": bool(details), "severity": "high" if details else None, "details": details}


def _check_brand_impersonation(html: str, page_domain: str) -> dict:
    details: list[str] = []
    # Look in title and img alt/src only (reduce false positives from body text)
    title_m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    title_text = (title_m.group(1) if title_m else "").lower()
    img_tags = " ".join(re.findall(r"<img\b[^>]*/?>", html, re.IGNORECASE | re.DOTALL)).lower()
    searchable = title_text + " " + img_tags

    # Also check if any login/password form is present (needed for high-confidence flag)
    has_password_input = bool(re.search(r'type\s*=\s*["\']?password', html, re.IGNORECASE))

    for brand, legit_domain in _BRANDS:
        if brand in searchable:
            if legit_domain not in (page_domain or ""):
                if has_password_input:
                    details.append(f"brand={brand!r} on domain={page_domain!r}")
    return {"found": bool(details), "severity": "high" if details else None, "details": details}


def _check_obfuscated_js(html: str) -> dict:
    details: list[str] = []
    scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.IGNORECASE | re.DOTALL)
    for script in scripts:
        if re.search(r"\beval\s*\(", script):
            details.append("eval() call detected")
        if re.search(r"\batob\s*\(", script):
            details.append("atob() (base64 decode) detected")
        if re.search(r"\bdocument\.write\s*\(", script):
            details.append("document.write() detected")
        if re.search(r"\bString\.fromCharCode\s*\(", script):
            details.append("String.fromCharCode() detected")
        hex_count = len(re.findall(r"\\x[0-9a-fA-F]{2}", script))
        if hex_count > 10:
            details.append(f"bulk hex escapes: {hex_count} occurrences")
        if re.search(r"\bunescape\s*\(", script):
            details.append("unescape() detected")
    return {"found": bool(details), "severity": "medium" if details else None, "details": details}


def _check_page_quality(html: str) -> dict:
    details: list[str] = []
    # Visible text: strip tags, collapse whitespace
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()
    has_form = bool(re.search(r"<form\b", html, re.IGNORECASE))
    hidden_count = len(re.findall(
        r'(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)', html, re.IGNORECASE
    ))
    if has_form and len(text) < 100:
        details.append(f"form present but only {len(text)} chars of visible text")
    if hidden_count >= 3:
        details.append(f"{hidden_count} hidden elements detected")
    return {"found": bool(details), "severity": "medium" if details else None, "details": details}


def _check_data_exfiltration(html: str, page_domain: str) -> dict:
    details: list[str] = []
    # External POST forms
    for m in re.finditer(
        r'<form\b[^>]*method\s*=\s*["\']?post["\']?[^>]*>', html, re.IGNORECASE | re.DOTALL
    ):
        form_tag = m.group(0)
        action_m = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_tag, re.IGNORECASE)
        if action_m:
            action = action_m.group(1)
            action_domain = _extract_domain(action)
            if action_domain and action_domain != page_domain:
                details.append(f"POST form to external domain: {action_domain!r}")
    # External iframes
    for m in re.finditer(r"<iframe\b[^>]*>", html, re.IGNORECASE | re.DOTALL):
        src_m = re.search(r'src\s*=\s*["\']([^"\']+)["\']', m.group(0), re.IGNORECASE)
        if src_m:
            src_domain = _extract_domain(src_m.group(1))
            if src_domain and src_domain != page_domain:
                details.append(f"external iframe: {src_domain!r}")
    return {"found": bool(details), "severity": "high" if details else None, "details": details}


def _check_metadata(html: str) -> dict:
    details: list[str] = []
    if not re.search(r"<title\b[^>]*>\s*\S", html, re.IGNORECASE):
        details.append("missing or empty <title>")
    if re.search(r'<meta\b[^>]*http-equiv\s*=\s*["\']?refresh["\']?', html, re.IGNORECASE):
        details.append("meta refresh redirect detected")
    return {"found": bool(details), "severity": "low" if details else None, "details": details}


@tool
def analyze_html(url: str) -> dict:
    """Fetch a URL and analyze its HTML structure for phishing indicators.

    Returns a comprehensive dict with fetch metadata and per-indicator findings.
    No API key required. Falls back gracefully on network errors.
    """
    fetch_meta, html = _fetch_page(url)

    if html is None:
        reason = fetch_meta.get("error", "fetch_failed")
        return {"url": url, "analyzed": False, "reason": reason, "fetch": fetch_meta}

    page_domain = _extract_domain(fetch_meta["final_url"]) or _extract_domain(url)

    indicators = {
        "login_form_offsite": _check_login_forms(html, page_domain),
        "brand_impersonation": _check_brand_impersonation(html, page_domain),
        "obfuscated_js": _check_obfuscated_js(html),
        "low_quality_page": _check_page_quality(html),
        "data_exfiltration": _check_data_exfiltration(html, page_domain),
        "suspicious_metadata": _check_metadata(html),
    }

    found_severities = [
        ind["severity"]
        for ind in indicators.values()
        if ind.get("found") and ind.get("severity")
    ]
    summary = _max_severity(*found_severities) if found_severities else "none"

    return {
        "url": url,
        "analyzed": True,
        "fetch": fetch_meta,
        "indicators": indicators,
        "summary_severity": summary,
    }
