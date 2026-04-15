from __future__ import annotations

from typing import Any

from .config import settings, watsonx_credentials_present


def _params(agent: str) -> dict[str, Any]:
    return {
        "decoding_method": "greedy",
        "max_new_tokens": 512,
        "temperature": 0.0 if agent == "orchestrator" else 0.2,
    }


def make_llm(agent: str = "default", model_id: str | None = None):
    """Build a WatsonxLLM. Falls back to a deterministic stub when credentials are absent.

    The stub lets us run unit tests and local smoke flows without hitting watsonx.
    """
    if not watsonx_credentials_present():
        return _StubLLM(agent=agent)

    from langchain_ibm import WatsonxLLM  # lazy import

    return WatsonxLLM(
        model_id=model_id or settings.watsonx_model_id,
        url=settings.watsonx_url,
        project_id=settings.watsonx_project_id,
        apikey=settings.watsonx_apikey,
        params=_params(agent),
    )


def make_embeddings():
    if not watsonx_credentials_present():
        return _StubEmbeddings()
    from langchain_ibm import WatsonxEmbeddings

    return WatsonxEmbeddings(
        model_id=settings.watsonx_embedding_model_id,
        url=settings.watsonx_url,
        project_id=settings.watsonx_project_id,
        apikey=settings.watsonx_apikey,
    )


class _StubLLM:
    def __init__(self, agent: str):
        self.agent = agent

    def invoke(self, prompt: str, **_: Any) -> str:
        return f"[stub-{self.agent}] {prompt[:120]}"

    def __call__(self, prompt: str, **kw: Any) -> str:
        return self.invoke(prompt, **kw)


class _StubEmbeddings:
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [[float(len(t) % 7)] * 8 for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return [float(len(text) % 7)] * 8
