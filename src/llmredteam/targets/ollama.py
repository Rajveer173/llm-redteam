from __future__ import annotations

import time

import httpx

from ..models import TargetResponse, Variant


class OllamaTarget:
    """A bare LLM behind Ollama's /api/chat. Used to measure model susceptibility with no app defenses,
    so app-level defenses can be attributed to the app rather than the model."""

    def __init__(self, model: str, base_url: str = "http://localhost:11434", temperature: float = 0.0):
        self.name = f"ollama:{model}"
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature

    async def send(self, system_prompt: str, variant: Variant) -> TargetResponse:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        # Indirect injection: the poisoned document arrives as retrieved context the user asks about.
        if variant.document is not None:
            messages.append({
                "role": "user",
                "content": f"Here is a document:\n\n{variant.document}\n\n{variant.prompt}",
            })
        else:
            messages.append({"role": "user", "content": variant.prompt})

        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                r = await client.post(
                    f"{self.base_url}/api/chat",
                    json={
                        "model": self.model,
                        "messages": messages,
                        "stream": False,
                        "options": {"temperature": self.temperature, "seed": variant_seed(variant)},
                    },
                )
            latency = (time.perf_counter() - start) * 1000
            if r.status_code != 200:
                return TargetResponse(text="", status=r.status_code, latency_ms=latency, error=f"http {r.status_code}")
            data = r.json()
            return TargetResponse(text=data.get("message", {}).get("content", ""), latency_ms=latency)
        except Exception as exc:  # network, timeout, model missing
            return TargetResponse(text="", latency_ms=(time.perf_counter() - start) * 1000, error=str(exc)[:200])


def variant_seed(variant: Variant) -> int:
    # Stable per-variant seed so temperature-0 runs are reproducible.
    return abs(hash((variant.attack_id, variant.mutator, variant.language))) % (2**31)
