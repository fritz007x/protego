from __future__ import annotations

from langchain_core.tools import tool

from ..config import settings


@tool
def urlscan_submit(url: str) -> dict:
    """Submit URL to urlscan.io. Returns stub when no key."""
    if not settings.urlscan_key:
        return {"url": url, "submitted": False, "reason": "no_api_key"}
    try:
        import httpx

        resp = httpx.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": settings.urlscan_key, "Content-Type": "application/json"},
            json={"url": url, "visibility": "private"},
            timeout=10,
        )
        return {"url": url, "submitted": True, "response": resp.json()}
    except Exception as e:
        return {"url": url, "submitted": False, "error": str(e)}
