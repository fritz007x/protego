from __future__ import annotations

from langchain_core.tools import tool

from ..config import settings


@tool
def check_url_safe_browsing(url: str) -> dict:
    """Check a URL against Google Safe Browsing. Offline-safe fallback if no key."""
    if not settings.safe_browsing_key:
        return {"url": url, "checked": False, "reason": "no_api_key"}
    try:
        import httpx

        resp = httpx.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": settings.safe_browsing_key},
            json={
                "client": {"clientId": "protego", "clientVersion": "0.1"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=5,
        )
        data = resp.json()
        return {"url": url, "checked": True, "matches": data.get("matches", [])}
    except Exception as e:
        return {"url": url, "checked": False, "error": str(e)}
