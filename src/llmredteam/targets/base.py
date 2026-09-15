"""A Target is anything we can send a chat request to and get a response from."""

from __future__ import annotations

from typing import Protocol

from ..models import TargetResponse, Variant


class Target(Protocol):
    name: str
    model: str

    async def send(self, system_prompt: str, variant: Variant) -> TargetResponse: ...
