from __future__ import annotations

import re

from ..llm import make_llm
from ..state import ThreatState
from ..tools.safe_browsing import check_url_safe_browsing
from ..tools.urlscan import urlscan_submit

_URL_RE = re.compile(r"https?://[^\s>\]\)]+", re.IGNORECASE)
_DISPLAY_DOMAIN_RE = re.compile(r"<([^>]+)>")
_SUSPICIOUS_TLDS = {".zip", ".mov", ".country", ".click"}


def phishing_agent(state: ThreatState) -> dict:
    parsed = state.get("parsed") or {}
    text = parsed.get("text") or ""
    urls = list(dict.fromkeys(_URL_RE.findall(text)))[:5]

    signals: list[dict] = []
    url_results = []
    for u in urls:
        sb = check_url_safe_browsing.invoke({"url": u})
        if sb.get("matches"):
            signals.append(
                {
                    "source": "phishing",
                    "severity": "high",
                    "reason": "safe_browsing_match",
                    "detail": sb["matches"],
                }
            )
        us = urlscan_submit.invoke({"url": u})
        url_results.append({"url": u, "safe_browsing": sb, "urlscan": us})
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
    try:
        reasoning = str(
            llm.invoke(
                "Assess the following message for phishing in one sentence.\n" + text[:1500]
            )
        )
    except Exception as e:
        reasoning = f"[llm-error] {e}"

    return {
        "signals": signals,
        "reasoning": reasoning,
        "threat_type": "phishing",
        "parsed": {**parsed, "urls": urls, "url_results": url_results},
    }
