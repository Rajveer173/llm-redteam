"""Turn a results.jsonl into aggregate tables (ASR with bootstrap CIs) and an HTML report."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from jinja2 import Template

from .models import TrialResult
from .stats import asr_ci, pct


def load_results(run_path: Path) -> list[TrialResult]:
    lines = (run_path / "results.jsonl").read_text(encoding="utf-8").splitlines()
    return [TrialResult.model_validate_json(line) for line in lines if line.strip()]


def _group(results: list[TrialResult], key) -> dict:
    buckets: dict = defaultdict(list)
    for r in results:
        buckets[key(r)].append(r.success)
    return buckets


def summarize(results: list[TrialResult]) -> dict:
    overall_mean, overall_lo, overall_hi = asr_ci([r.success for r in results])

    def table(key) -> list[dict]:
        rows = []
        for k, succ in sorted(_group(results, key).items()):
            m, lo, hi = asr_ci(succ)
            rows.append({"key": k, "n": len(succ), "asr": m, "lo": lo, "hi": hi, "hits": sum(succ)})
        return sorted(rows, key=lambda r: r["asr"], reverse=True)

    by_model_defense: dict[str, dict[str, float]] = defaultdict(dict)
    for (model, defense), succ in _group(results, lambda r: (r.model, r.defense)).items():
        by_model_defense[model][defense] = asr_ci(succ)[0]

    return {
        "trials": len(results),
        "overall": {"asr": overall_mean, "lo": overall_lo, "hi": overall_hi},
        "by_model": table(lambda r: r.model),
        "by_defense": table(lambda r: r.defense),
        "by_goal": table(lambda r: r.goal),
        "by_owasp": table(lambda r: r.owasp),
        "by_mutator": table(lambda r: r.mutator),
        "by_language": table(lambda r: r.language),
        "matrix": dict(by_model_defense),
    }


def print_summary(s: dict) -> None:
    o = s["overall"]
    print(f"\ntrials: {s['trials']}   overall ASR: {pct(o['asr'])}  (95% CI {pct(o['lo'])}–{pct(o['hi'])})\n")
    for title, rows in (("by model", s["by_model"]), ("by defense", s["by_defense"]), ("by attack goal", s["by_goal"]), ("by mutator", s["by_mutator"]), ("by language", s["by_language"])):
        print(title)
        for r in rows:
            print(f"  {str(r['key']):<20} ASR {pct(r['asr']):>6}  [{pct(r['lo'])}–{pct(r['hi'])}]  ({r['hits']}/{r['n']})")
        print()


_HTML = Template(
    """<!doctype html><html><head><meta charset=utf-8><title>llm-redteam report {{ run_id }}</title>
<style>
 body{font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1a1f2b}
 h1{margin-bottom:0}.sub{color:#667}
 table{border-collapse:collapse;width:100%;margin:1rem 0}
 th,td{border:1px solid #dde;padding:6px 10px;text-align:left}th{background:#f4f6fb}
 td.n{text-align:right;font-variant-numeric:tabular-nums}
 .bar{height:10px;background:#e6534b;border-radius:3px;display:inline-block;vertical-align:middle}
 .ci{color:#889;font-size:12px}
 .good{color:#1a8f5a}.bad{color:#c0392b}
 caption{text-align:left;font-weight:600;margin:.5rem 0}
</style></head><body>
<h1>llm-redteam</h1>
<p class=sub>run {{ run_id }} · {{ s.trials }} trials · overall ASR
 <b class="{{ 'bad' if s.overall.asr>0.2 else 'good' }}">{{ p(s.overall.asr) }}</b>
 <span class=ci>(95% CI {{ p(s.overall.lo) }}–{{ p(s.overall.hi) }})</span></p>

<h2>Model × defense (attack success rate)</h2>
<table><tr><th>model</th>{% for d in defenses %}<th>{{ d }}</th>{% endfor %}</tr>
{% for model, row in s.matrix.items() %}<tr><td>{{ model }}</td>
{% for d in defenses %}<td class=n>{{ p(row.get(d, 0)) }}</td>{% endfor %}</tr>{% endfor %}
</table>

{% for title, rows in sections %}
<table><caption>{{ title }}</caption>
<tr><th>{{ title.split(' ')[-1] }}</th><th>ASR</th><th></th><th class=n>hits/n</th></tr>
{% for r in rows %}<tr><td>{{ r.key }}</td><td class=n>{{ p(r.asr) }}</td>
<td><span class=bar style="width:{{ (r.asr*200)|round(0) }}px"></span> <span class=ci>{{ p(r.lo) }}–{{ p(r.hi) }}</span></td>
<td class=n>{{ r.hits }}/{{ r.n }}</td></tr>{% endfor %}
</table>{% endfor %}
<p class=sub>ASR = attack success rate, judged deterministically by canary/marker match or tool-call inspection.
CIs are 95% bootstrap over trials.</p>
</body></html>"""
)


def render_html(s: dict, run_id: str) -> str:
    defenses = sorted({d for row in s["matrix"].values() for d in row})
    sections = [
        ("by attack goal", s["by_goal"]),
        ("by OWASP category", s["by_owasp"]),
        ("by mutator", s["by_mutator"]),
        ("by language", s["by_language"]),
    ]
    return _HTML.render(s=s, run_id=run_id, defenses=defenses, sections=sections, p=pct)


def write_report(run_path: Path) -> Path:
    results = load_results(run_path)
    s = summarize(results)
    (run_path / "summary.json").write_text(json.dumps(s, indent=2), encoding="utf-8")
    html_path = run_path / "report.html"
    html_path.write_text(render_html(s, run_path.name), encoding="utf-8")
    return html_path
