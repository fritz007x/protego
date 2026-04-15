"""HITL email approval link helper.

Emits a signed URL pointing at GET /hitl/{thread_id}?token=... which renders
Approve/Reject buttons that POST to /resume/{thread_id}. Falls back to logging
when SMTP is not configured.
"""
from __future__ import annotations

import hmac
import logging
import smtplib
import time
from email.message import EmailMessage
from hashlib import sha256

from .config import settings

log = logging.getLogger("protego.hitl")


def _sign(thread_id: str, exp: int) -> str:
    msg = f"{thread_id}.{exp}".encode()
    return hmac.new(settings.hitl_signing_key.encode(), msg, sha256).hexdigest()


def build_link(thread_id: str) -> str:
    exp = int(time.time()) + settings.hitl_link_ttl_minutes * 60
    sig = _sign(thread_id, exp)
    return f"{settings.hitl_public_base_url}/hitl/{thread_id}?exp={exp}&sig={sig}"


def verify_token(thread_id: str, exp: int, sig: str) -> bool:
    if exp < int(time.time()):
        return False
    return hmac.compare_digest(sig, _sign(thread_id, exp))


def send_approval_email(thread_id: str, summary: str) -> str:
    link = build_link(thread_id)
    body = f"A suspicious event needs your review:\n\n{summary}\n\nApprove/Reject: {link}\n"
    if not (settings.smtp_host and settings.hitl_approver_email and settings.smtp_from):
        log.warning("HITL email not configured; link=%s", link)
        return link
    msg = EmailMessage()
    msg["Subject"] = f"[Protego] Action required — {thread_id}"
    msg["From"] = settings.smtp_from
    msg["To"] = settings.hitl_approver_email
    msg.set_content(body)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as s:
            s.starttls()
            if settings.smtp_user:
                s.login(settings.smtp_user, settings.smtp_password)
            s.send_message(msg)
    except Exception as e:  # pragma: no cover - best-effort notification
        log.error("HITL email send failed: %s", e)
    return link
