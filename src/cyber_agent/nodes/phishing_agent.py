from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..llm import make_llm
from ..state import ThreatState
from ..tools.html_analysis import analyze_html
from ..tools.safe_browsing import check_url_safe_browsing
from ..tools.urlscan import urlscan_submit
from ._parse_utils import confidence_to_severity, parse_classification, truncate_at_word

_HTML_INDICATOR_SIGNALS: dict[str, tuple[str, str]] = {
    "login_form_offsite":  ("high",   "html_credential_harvest"),
    "brand_impersonation": ("high",   "html_brand_impersonation"),
    "obfuscated_js":       ("medium", "html_obfuscated_js"),
    "low_quality_page":    ("medium", "html_low_quality"),
    "data_exfiltration":   ("high",   "html_data_exfiltration"),
    "suspicious_metadata": ("low",    "html_suspicious_metadata"),
}

_URL_RE = re.compile(r"https?://[^\s>\]\)]+", re.IGNORECASE)
_DISPLAY_DOMAIN_RE = re.compile(r"<([^>]+)>")
_SUSPICIOUS_TLDS = {".zip", ".mov", ".country", ".click"}

_PROMPT_TEMPLATE = """\
You are an expert cybersecurity analyst specializing in phishing detection. \
Your task is to analyze websites and determine if they are phishing or legitimate \
using a systematic Chain of Thought approach. You will be provided with:
1. URL of the website
2. HTML content of the website
3. Visible text content extracted from the website

Please analyze the website step-by-step using the following Chain of Thought process:

STEP 1: URL ANALYSIS
- Examine the domain name for suspicious patterns
- Check for typosquatting (misspellings of legitimate brands)
- Look for suspicious TLDs or subdomains
- Identify any URL shortening or redirection indicators

STEP 2: CONTENT ANALYSIS
- Analyze the HTML structure and quality
- Look for suspicious scripts or hidden elements
- Check for legitimate branding vs. impersonation attempts
- Examine form elements and data collection practices

STEP 3: TEXT ANALYSIS
- Review the visible text for urgency tactics
- Check for grammar/spelling errors typical of phishing
- Look for legitimate contact information
- Analyze the overall messaging and tone

STEP 4: TECHNICAL INDICATORS
- Check for HTTPS usage and security indicators
- Look for suspicious redirects or external links
- Examine metadata and technical elements
- Consider overall website quality and professionalism

STEP 5: FINAL ASSESSMENT
- Weigh all evidence from previous steps
- Consider the overall risk profile
- Make a final classification with confidence level

Format your response as:
STEP 1: [Your URL analysis]
STEP 2: [Your content analysis]
STEP 3: [Your text analysis]
STEP 4: [Your technical analysis]
STEP 5: [Your final assessment]
CLASSIFICATION: [PHISHING or LEGITIMATE]
CONFIDENCE: [High/Medium/Low]
REASONING: [Brief summary of key factors that led to your decision]

---
URL(s): {urls}

HTML INDICATORS:
{html_summary}

URLSCAN RESULTS:
{urlscan_summary}

VISIBLE TEXT:
{visible_text}
"""


def _build_prompt(text: str, urls: list[str], url_results: list[dict]) -> str:
    urls_str = "\n".join(urls) if urls else "(none found)"

    html_parts: list[str] = []
    urlscan_parts: list[str] = []
    for entry in url_results:
        u = entry["url"]
        hr = entry.get("html_analysis") or {}
        if not hr.get("analyzed"):
            html_parts.append(f"  {u}: fetch failed ({hr.get('reason', 'unknown')})")
        else:
            fetch = hr.get("fetch", {})
            inds = hr.get("indicators", {})
            found = [k for k, v in inds.items() if v.get("found")]
            ssl_status = "valid" if fetch.get("ssl_valid") else f"INVALID ({fetch.get('ssl_error','')})"
            redirects = len(fetch.get("redirect_chain", []))
            html_parts.append(
                f"  {u}:\n"
                f"    SSL: {ssl_status} | redirects: {redirects} | "
                f"final_url: {fetch.get('final_url', u)}\n"
                f"    Indicators found: {found if found else 'none'}"
            )
        us = entry.get("urlscan") or {}
        if us.get("submitted"):
            resp = us.get("response") or {}
            scan_url = resp.get("result") or resp.get("api") or "(pending)"
            urlscan_parts.append(f"  {u}: submitted — result at {scan_url}")
        else:
            urlscan_parts.append(f"  {u}: not submitted ({us.get('reason', us.get('error', 'unknown'))})")

    html_summary = "\n".join(html_parts) if html_parts else "  (no URLs fetched)"
    urlscan_summary = "\n".join(urlscan_parts) if urlscan_parts else "  (no URLs scanned)"

    return _PROMPT_TEMPLATE.format(
        urls=urls_str,
        html_summary=html_summary,
        urlscan_summary=urlscan_summary,
        visible_text=truncate_at_word(text, 2000),
    )


def phishing_agent(state: ThreatState) -> dict:
    parsed = state.get("parsed") or {}
    text = parsed.get("text") or ""
    urls = list(dict.fromkeys(_URL_RE.findall(text)))[:5]

    def _scan_url(u: str) -> dict:
        with ThreadPoolExecutor(max_workers=3) as ex:
            f_sb = ex.submit(check_url_safe_browsing.invoke, {"url": u})
            f_us = ex.submit(urlscan_submit.invoke, {"url": u})
            f_html = ex.submit(analyze_html.invoke, {"url": u})
        return {
            "url": u,
            "safe_browsing": f_sb.result(),
            "urlscan": f_us.result(),
            "html_analysis": f_html.result(),
        }

    signals: list[dict] = []
    url_results = [_scan_url(u) for u in urls]
    for entry in url_results:
        u = entry["url"]
        sb = entry["safe_browsing"]
        html_result = entry["html_analysis"]
        if sb.get("matches"):
            signals.append(
                {
                    "source": "phishing",
                    "severity": "high",
                    "reason": "safe_browsing_match",
                    "detail": sb["matches"],
                }
            )

        if html_result.get("analyzed"):
            indicators = html_result.get("indicators", {})
            for key, (severity, reason) in _HTML_INDICATOR_SIGNALS.items():
                ind = indicators.get(key, {})
                if ind.get("found"):
                    signals.append({
                        "source": "phishing",
                        "severity": severity,
                        "reason": reason,
                        "detail": ind.get("details", []),
                    })
            fetch_info = html_result.get("fetch", {})
            if fetch_info.get("ssl_valid") is False:
                signals.append({
                    "source": "phishing",
                    "severity": "medium",
                    "reason": "html_ssl_invalid",
                    "detail": fetch_info.get("ssl_error", ""),
                })
            if len(fetch_info.get("redirect_chain", [])) > 3:
                signals.append({
                    "source": "phishing",
                    "severity": "medium",
                    "reason": "html_excessive_redirects",
                    "detail": fetch_info["redirect_chain"],
                })
        for tld in _SUSPICIOUS_TLDS:
            if u.lower().split("?")[0].endswith(tld):
                signals.append(
                    {
                        "source": "phishing",
                        "severity": "medium",
                        "reason": "suspicious_tld",
                        "detail": u,
                    }
                )
                break

    # Display-name vs. actual domain mismatch (very light heuristic)
    header_match = _DISPLAY_DOMAIN_RE.search(text)
    if header_match:
        actual = header_match.group(1)
        if "support" in text.lower() and "support" not in actual.lower():
            signals.append(
                {
                    "source": "phishing",
                    "severity": "medium",
                    "reason": "display_name_mismatch",
                    "detail": actual,
                }
            )

    llm = make_llm("phishing")
    prompt = _build_prompt(text, urls, url_results)
    try:
        llm_response = str(llm.invoke(prompt))
        reasoning = llm_response
        classification, confidence = parse_classification(llm_response, "PHISHING")
        if classification == "PHISHING":
            severity = confidence_to_severity(confidence)
            signals.append({
                "source": "phishing",
                "severity": severity,
                "reason": "llm_classified_phishing",
                "detail": f"confidence={confidence}",
            })
    except Exception as e:
        reasoning = f"[llm-error] {e}"

    return {
        "signals": signals,
        "reasoning": reasoning,
        "threat_type": "phishing",
        "parsed": {**parsed, "urls": urls, "url_results": url_results},
    }
