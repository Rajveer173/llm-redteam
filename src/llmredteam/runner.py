"""Expands attacks into variants, runs them against targets under defenses, judges each, writes results."""

from __future__ import annotations

import asyncio
import json
import platform
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .defenses import Defense
from .judges import judge
from .models import Attack, TargetResponse, TrialResult, Variant
from .mutators import MUTATORS
from .prompts import VAULT_ASSISTANT
from .targets.base import Target


def expand(attack: Attack, mutators: list[str], languages: list[str]) -> Iterable[Variant]:
    for lang in languages:
        base_prompt = attack.prompt
        base_doc = attack.document
        if lang != "en":
            tr = attack.translations.get(lang)
            if not tr:
                continue  # only run languages we have hand-written translations for
            base_prompt = tr.get("prompt", base_prompt)
            base_doc = tr.get("document", base_doc)
        for mname in mutators:
            # Don't scramble non-English text or documents with the char-level mutators; keep them meaningful.
            if mname != "identity" and (lang != "en" or base_doc is not None):
                continue
            mutate = MUTATORS[mname]
            yield Variant(
                attack_id=attack.id,
                goal=attack.goal,
                technique=attack.technique,
                owasp=attack.owasp,
                mutator=mname,
                language=lang,
                prompt=mutate(base_prompt),
                document=base_doc,
            )


async def _run_one(
    target: Target,
    defense: Defense,
    system_prompt: str,
    variant: Variant,
    repeat: int,
    run_id: str,
    sem: asyncio.Semaphore,
) -> TrialResult:
    async with sem:
        user_text = f"{variant.document}\n{variant.prompt}" if variant.document else variant.prompt
        decision = defense.guard_input(system_prompt, user_text)
        if decision.reject:
            resp = TargetResponse(text="", blocked_by=decision.reason, status=0)
        else:
            resp = await target.send(decision.system_prompt, variant)
            filtered, blocked = defense.filter_output(resp.text)
            if blocked:
                resp = resp.model_copy(update={"text": filtered, "blocked_by": blocked})

    verdict = judge(variant.goal, resp)
    seed = abs(hash((variant.attack_id, variant.mutator, variant.language, repeat))) % (2**31)
    return TrialResult(
        trial_id=f"{run_id}:{target.name}:{defense.name}:{variant.attack_id}:{variant.mutator}:{variant.language}:{repeat}",
        run_id=run_id,
        target=target.name,
        model=target.model,
        defense=defense.name,
        attack_id=variant.attack_id,
        goal=variant.goal,
        technique=variant.technique,
        owasp=variant.owasp,
        mutator=variant.mutator,
        language=variant.language,
        repeat=repeat,
        seed=seed,
        success=verdict.success,
        evidence=verdict.evidence,
        blocked_by=resp.blocked_by,
        status=resp.status,
        latency_ms=round(resp.latency_ms, 1),
        error=resp.error,
        response_excerpt=resp.text[:280],
    )


async def run_matrix(
    targets: list[Target],
    defenses: list[Defense],
    attacks: list[Attack],
    *,
    mutators: list[str],
    languages: list[str],
    repeats: int,
    system_prompt: str = VAULT_ASSISTANT,
    concurrency: int = 4,
    run_id: str | None = None,
) -> list[TrialResult]:
    run_id = run_id or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    sem = asyncio.Semaphore(concurrency)
    variants = [v for a in attacks for v in expand(a, mutators, languages)]
    tasks = [
        _run_one(t, d, system_prompt, v, r, run_id, sem)
        for t in targets
        for d in defenses
        for v in variants
        for r in range(repeats)
    ]
    return await asyncio.gather(*tasks)


def write_run(results: list[TrialResult], config: dict, out_dir: Path) -> Path:
    run_id = results[0].run_id if results else datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_path = out_dir / run_id
    run_path.mkdir(parents=True, exist_ok=True)
    (run_path / "results.jsonl").write_text(
        "\n".join(r.model_dump_json() for r in results), encoding="utf-8"
    )
    manifest = {
        "run_id": run_id,
        "created": datetime.now(UTC).isoformat(),
        "tool_version": __version__,
        "python": platform.python_version(),
        "config": config,
        "trials": len(results),
    }
    (run_path / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return run_path
