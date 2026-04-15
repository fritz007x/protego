from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from langgraph.types import Command

from ..graph import build_graph
from ..hitl_mailer import send_approval_email, verify_token

app = FastAPI(title="Protego Cyber Agent")
_graph = build_graph()


@app.post("/analyze")
async def analyze(
    file: UploadFile | None = File(default=None),
    text: str | None = Form(default=None),
) -> dict[str, Any]:
    if file is None and not text:
        raise HTTPException(400, "Provide either a file or text")
    content: Any = await file.read() if file is not None else text
    trace_id = str(uuid.uuid4())
    config = {"configurable": {"thread_id": trace_id}}
    result = _graph.invoke(
        {"raw_input": {"type": "invoice", "content": content}, "trace_id": trace_id},
        config=config,
    )
    snapshot = _graph.get_state(config)
    paused = bool(snapshot.next)
    link = None
    if paused:
        link = send_approval_email(trace_id, str(result.get("reasoning") or "pending review"))
    return {"trace_id": trace_id, "paused": paused, "hitl_link": link, "state": _safe(result)}


@app.get("/hitl/{thread_id}", response_class=HTMLResponse)
async def hitl_page(thread_id: str, exp: int, sig: str) -> str:
    if not verify_token(thread_id, exp, sig):
        raise HTTPException(403, "invalid or expired token")
    return f"""
    <html><body>
      <h2>Protego review — {thread_id}</h2>
      <form method="post" action="/resume/{thread_id}">
        <input type="hidden" name="token_exp" value="{exp}" />
        <input type="hidden" name="token_sig" value="{sig}" />
        <button name="approved" value="true">Approve</button>
        <button name="approved" value="false">Reject</button>
      </form>
    </body></html>
    """


@app.post("/resume/{thread_id}")
async def resume(
    thread_id: str,
    approved: bool = Form(...),
    notes: str = Form(""),
    token_exp: int | None = Form(default=None),
    token_sig: str | None = Form(default=None),
) -> dict[str, Any]:
    if token_exp is not None and token_sig is not None:
        if not verify_token(thread_id, token_exp, token_sig):
            raise HTTPException(403, "invalid or expired token")
    config = {"configurable": {"thread_id": thread_id}}
    result = _graph.invoke(Command(resume={"approved": approved, "notes": notes}), config=config)
    return {"trace_id": thread_id, "state": _safe(result)}


def _safe(state: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in state.items() if k != "raw_input"}
