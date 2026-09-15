from __future__ import annotations

from importlib import resources

import yaml

from ..canary import SECRET_CANARY, SYSTEM_PROMPT_MARKER
from ..models import Attack

_PACKS = ("direct.yaml", "indirect.yaml", "rag_agent.yaml")


def _fill(text: str | None) -> str | None:
    if text is None:
        return None
    return text.replace("{{SECRET}}", SECRET_CANARY).replace("{{MARKER}}", SYSTEM_PROMPT_MARKER)


def load_attacks(packs: list[str] | None = None) -> list[Attack]:
    """Load and validate every attack pack. Placeholders are substituted so canaries live in one place."""
    chosen = packs or list(_PACKS)
    attacks: list[Attack] = []
    for pack in chosen:
        raw = resources.files(__package__).joinpath(pack).read_text(encoding="utf-8")
        for item in yaml.safe_load(raw):
            item["prompt"] = _fill(item["prompt"])
            if "document" in item:
                item["document"] = _fill(item["document"])
            for lang in item.get("translations", {}).values():
                for k in list(lang):
                    lang[k] = _fill(lang[k])
            attacks.append(Attack(**item))
    return attacks
