from __future__ import annotations

from pathlib import Path

from langgraph.graph import END, START, StateGraph

try:
    from langgraph.pregel import RetryPolicy  # type: ignore
except Exception:  # pragma: no cover
    RetryPolicy = None  # type: ignore

from .config import settings
from .nodes.action import action
from .nodes.bec_agent import bec_agent
from .nodes.feedback_logger import feedback_logger
from .nodes.invoice_agent import invoice_agent
from .nodes.orchestrator import orchestrator
from .nodes.phishing_agent import phishing_agent
from .nodes.preprocess import preprocess
from .nodes.risk_scoring import risk_scoring
from .state import ThreatState


def _checkpointer():
    try:
        from langgraph.checkpoint.sqlite import SqliteSaver  # type: ignore

        path = Path(settings.sqlite_checkpoint_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return SqliteSaver.from_conn_string(str(path))
    except Exception:
        from langgraph.checkpoint.memory import MemorySaver  # type: ignore

        return MemorySaver()


def build_graph(checkpointer=None):
    g = StateGraph(ThreatState)
    retry = {"retry": RetryPolicy(max_attempts=3)} if RetryPolicy is not None else {}
    g.add_node("preprocess", preprocess)
    g.add_node("orchestrator", orchestrator)
    g.add_node("invoice_agent", invoice_agent, **retry)
    g.add_node("phishing_agent", phishing_agent, **retry)
    g.add_node("bec_agent", bec_agent, **retry)
    g.add_node("risk_scoring", risk_scoring)
    g.add_node("action", action)
    g.add_node("feedback_logger", feedback_logger)

    g.add_edge(START, "preprocess")
    g.add_edge("preprocess", "orchestrator")
    # orchestrator uses Command(goto=...) for dynamic routing
    g.add_edge("invoice_agent", "risk_scoring")
    g.add_edge("phishing_agent", "risk_scoring")
    g.add_edge("bec_agent", "risk_scoring")
    g.add_edge("risk_scoring", "action")
    g.add_edge("action", "feedback_logger")
    g.add_edge("feedback_logger", END)

    return g.compile(checkpointer=checkpointer or _checkpointer())
