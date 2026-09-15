from __future__ import annotations

import time

import httpx

from ..models import TargetResponse, ToolCall, Variant


class HttpAppTarget:
    """Any HTTP app exposing a chat endpoint. Used against the victim apps (rag_bot, agent_bot) and,
    with an OpenAI-compatible path, against the llm-gateway to score its guardrails.

    The app may return tool_calls and a `blocked_by` field, so defenses that block a request are
    distinguished from a model that simply refused."""

    def __init__(self, name: str, url: str, model: str = "app", headers: dict | None = None):
        self.name = name
        self.model = model
        self.url = url
        self.headers = headers or {}

    async def send(self, system_prompt: str, variant: Variant) -> TargetResponse:
        payload = {"prompt": variant.prompt}
        if variant.document is not None:
            payload["document"] = variant.document
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                r = await client.post(self.url, json=payload, headers=self.headers)
            latency = (time.perf_counter() - start) * 1000
            if r.status_code >= 500:
                return TargetResponse(text="", status=r.status_code, latency_ms=latency, error=f"http {r.status_code}")
            data = r.json()
            return TargetResponse(
                text=data.get("text", ""),
                tool_calls=[ToolCall(**c) for c in data.get("tool_calls", [])],
                blocked_by=data.get("blocked_by"),
                status=r.status_code,
                latency_ms=latency,
            )
        except Exception as exc:
            return TargetResponse(text="", latency_ms=(time.perf_counter() - start) * 1000, error=str(exc)[:200])
