from __future__ import annotations

import asyncio
from pathlib import Path

import typer
import yaml

from .attacks import load_attacks
from .defenses import DEFENSES
from .report import load_results, print_summary, summarize, write_report
from .runner import run_matrix, write_run
from .targets import HttpAppTarget, OllamaTarget

app = typer.Typer(add_completion=False, help="Red-team harness for LLM apps.")

DEFAULT_OUT = Path("runs")


def _build_targets(spec: list[dict]) -> list:
    targets = []
    for t in spec:
        kind = t["type"]
        if kind == "ollama":
            targets.append(OllamaTarget(t["model"], t.get("base_url", "http://localhost:11434")))
        elif kind == "http":
            targets.append(HttpAppTarget(t["name"], t["url"], t.get("model", "app"), t.get("headers")))
        else:
            raise typer.BadParameter(f"unknown target type: {kind}")
    return targets


@app.command()
def run(
    config: Path = typer.Argument(..., help="YAML run config"),
    out: Path = typer.Option(DEFAULT_OUT, help="output directory"),
    concurrency: int = typer.Option(4),
):
    """Run the attack matrix defined by CONFIG and write results + an HTML report."""
    cfg = yaml.safe_load(config.read_text(encoding="utf-8"))
    targets = _build_targets(cfg["targets"])
    defenses = [DEFENSES[d]() for d in cfg.get("defenses", ["none"])]
    attacks = load_attacks(cfg.get("packs"))
    if cfg.get("attack_ids"):
        wanted = set(cfg["attack_ids"])
        attacks = [a for a in attacks if a.id in wanted]

    typer.echo(
        f"{len(targets)} targets × {len(defenses)} defenses × {len(attacks)} attacks "
        f"× {len(cfg.get('mutators', ['identity']))} mutators × {len(cfg.get('languages', ['en']))} langs "
        f"× {cfg.get('repeats', 1)} repeats"
    )
    results = asyncio.run(
        run_matrix(
            targets,
            defenses,
            attacks,
            mutators=cfg.get("mutators", ["identity"]),
            languages=cfg.get("languages", ["en"]),
            repeats=cfg.get("repeats", 1),
            concurrency=concurrency,
        )
    )
    run_path = write_run(results, cfg, out)
    html = write_report(run_path)
    print_summary(summarize(results))
    typer.echo(f"results: {run_path}\nreport:  {html}")


@app.command()
def report(run_path: Path = typer.Argument(..., help="a runs/<id> directory")):
    """Re-summarise an existing run and rewrite its HTML report."""
    html = write_report(run_path)
    print_summary(summarize(load_results(run_path)))
    typer.echo(f"report: {html}")


@app.command()
def attacks(packs: list[str] = typer.Option(None, "--pack")):  # noqa: B008
    """List the loaded attacks."""
    for a in load_attacks(packs or None):
        typer.echo(f"{a.id:<22} {a.owasp:<6} {a.goal:<20} {a.technique}")


if __name__ == "__main__":
    app()
