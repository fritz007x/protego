"""Integration: SMTP HITL email delivery.

Sends a real approval email to HITL_APPROVER_EMAIL. Verify receipt manually.
Skipped unless SMTP_HOST, SMTP_FROM, and HITL_APPROVER_EMAIL are set.
"""
import pytest

from tests.integration.conftest import smtp
from cyber_agent.hitl_mailer import build_link, send_approval_email


@smtp
def test_hitl_email_sends_without_error():
    thread_id = "integ-test-001"
    link = send_approval_email(
        thread_id=thread_id,
        summary="Integration test — please ignore this email.",
    )
    assert thread_id in link
    assert link.startswith("http")


@smtp
def test_hitl_link_is_verifiable():
    from cyber_agent.hitl_mailer import verify_token

    link = build_link("integ-test-002")
    q = dict(p.split("=", 1) for p in link.split("?", 1)[1].split("&"))
    assert verify_token("integ-test-002", int(q["exp"]), q["sig"])
