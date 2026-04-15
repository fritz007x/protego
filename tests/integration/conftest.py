"""Shared fixtures and skip guards for integration tests.

Every test that calls a real external service is guarded by a pytest.mark
that skips unless the relevant env var is present. Run the full suite with:

    pytest tests/integration/ -m watsonx
    pytest tests/integration/ -m threat_intel
    pytest tests/integration/ -m smtp
    pytest tests/integration/          # all integration tests

Set env vars (or populate .env) before running.
"""
import os

import pytest


def _require(*vars_: str, reason: str):
    missing = [v for v in vars_ if not os.getenv(v)]
    return pytest.mark.skipif(bool(missing), reason=f"{reason} — missing: {', '.join(missing)}")


watsonx = _require(
    "WATSONX_URL", "WATSONX_APIKEY", "WATSONX_PROJECT_ID",
    reason="watsonx.ai credentials required",
)
threat_intel_sb = _require("SAFE_BROWSING_KEY", reason="Google Safe Browsing key required")
threat_intel_us = _require("URLSCAN_KEY", reason="urlscan.io key required")
smtp = _require(
    "SMTP_HOST", "SMTP_FROM", "HITL_APPROVER_EMAIL",
    reason="SMTP config required",
)
