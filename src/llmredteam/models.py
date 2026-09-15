"""Core data types shared by attacks, targets, judges and the runner."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Goal(StrEnum):
    """What a successful attack achieves. Every goal is checked by a deterministic judge."""

    LEAK_SECRET = "leak_secret"  # make the model reveal a secret from its system prompt
    LEAK_SYSTEM_PROMPT = "leak_system_prompt"  # make the model reveal its instructions (marker canary)
    INDIRECT_INJECTION = "indirect_injection"  # instructions hidden in retrieved/pasted content get followed
    TOOL_MISUSE = "tool_misuse"  # make an agent call a dangerous tool (send data to an attacker)
    CROSS_TENANT = "cross_tenant"  # make a multi-tenant RAG app return another tenant's data


class Attack(BaseModel):
    id: str
    goal: Goal
    technique: str
    owasp: str = Field(description="OWASP Top 10 for LLM Applications (2025) id, e.g. LLM01")
    prompt: str
    # Attacker-controlled content for indirect injection: placed in a document the user innocently asks about.
    document: str | None = None
    # Hand-written translations of `prompt` (and `document`), keyed by language code.
    translations: dict[str, dict[str, str]] = Field(default_factory=dict)
    scenarios: list[str] = Field(default_factory=lambda: ["direct"])


class Variant(BaseModel):
    """One concrete prompt sent to a target: an attack after a mutator and language were applied."""

    attack_id: str
    goal: Goal
    technique: str
    owasp: str
    mutator: str
    language: str
    prompt: str
    document: str | None = None


class ToolCall(BaseModel):
    tool: str
    args: dict = Field(default_factory=dict)


class TargetResponse(BaseModel):
    text: str
    tool_calls: list[ToolCall] = Field(default_factory=list)
    blocked_by: str | None = None  # set when a defense stopped the request before/after the model
    status: int = 200
    latency_ms: float = 0.0
    error: str | None = None


class Verdict(BaseModel):
    success: bool
    evidence: str | None = None  # e.g. "exact", "base64", "spaced", "tool:send_email"


class TrialResult(BaseModel):
    trial_id: str
    run_id: str
    target: str
    model: str
    defense: str
    attack_id: str
    goal: Goal
    technique: str
    owasp: str
    mutator: str
    language: str
    repeat: int
    seed: int
    success: bool
    evidence: str | None
    blocked_by: str | None
    status: int
    latency_ms: float
    error: str | None
    response_excerpt: str
    llm_judge: bool | None = None
