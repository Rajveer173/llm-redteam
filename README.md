# llm-redteam

[![ci](https://github.com/Rajveer173/llm-redteam/actions/workflows/ci.yml/badge.svg)](https://github.com/Rajveer173/llm-redteam/actions/workflows/ci.yml)

An automated red-team harness for LLM applications. It fires prompt-injection, jailbreak, system-prompt-leak,
data-exfiltration, indirect-injection, cross-tenant RAG and tool-misuse attacks at a target, judges each one
**deterministically**, and reports attack success rate (ASR) per model × defense × attack family with bootstrap
confidence intervals. Attacks are mapped to the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

It targets bare models (via Ollama), two deliberately vulnerable demo apps, or any HTTP chat endpoint — including
the [llm-gateway](https://github.com/Rajveer173/llm-gateway), to measure what its guardrails actually block.

## Why deterministic judging

Most "LLM security" demos eyeball whether an answer looks bad. That can't be compared across models or repeated.
Here every attack has a **canary**: a unique secret planted where the model can see it but must not repeat
(`CANARY-VAULT-7Q3F-9XZ2`). Success is that string appearing in the output — exact, spaced, reversed, base64 or
hex encoded (the report says which). Tool misuse is judged by inspecting the actual tool call and its
destination. No second model decides what counts, so a "34% ASR" means the same thing every run.

An optional LLM-as-judge can be layered on for fuzzy cases, and the harness reports how often it agrees with the
canary judge — so its bias is measured, not trusted.

## What it measures

- **Model susceptibility** — the same attacks against several models with no defenses.
- **Defense effectiveness** — `none`, `hardened_prompt`, `input_filter`, `output_filter`, `input_output`, so you
  can see, for example, that a hardened system prompt barely helps while an output canary filter drives leakage to zero.
- **Evasion** — mutators (`base64`, `leetspeak`, `payload_split`, `polite`) wrap each attack to test whether a
  wrapping defeats a defense.
- **Language** — attacks translated to Hindi and Marathi, to test whether English-only guardrails miss non-English
  attacks (they usually do). This connects to my earlier tokenization work, [tokfair](https://github.com/Rajveer173/Tokfair).

## Install & run

```bash
python -m venv .venv && . .venv/Scripts/activate   # or source .venv/bin/activate
pip install -e ".[dev]"
ollama serve && ollama pull qwen2.5:0.5b

llmrt attacks                    # list the attack packs
llmrt run configs/smoke.yaml     # fast pipeline check (1 model, 2 defenses)
llmrt run configs/models.yaml    # the full matrix (3 models × 5 defenses × mutators × 3 languages × 3 repeats)
```

Each run writes `runs/<id>/` with `results.jsonl` (one row per trial), `manifest.json` (config, versions, seeds
for reproducibility) and `report.html` (ASR tables with CIs and a model×defense heatmap). `llmrt report runs/<id>`
re-summarises without re-running.

### Attack the vulnerable demo apps

```bash
uvicorn victims.rag_bot:app --port 8200      # multi-tenant RAG with a cross-tenant leak
uvicorn victims.agent_bot:app --port 8201    # tool-using agent with no destination allow-list
# point a config's `http` target at these and run
```

### Score the llm-gateway's guardrails

`configs/gateway.yaml` runs the same attacks against two gateway endpoints — one tenant with guardrails off, one
on — so the harness produces a before/after ASR for the gateway's defenses.

## Layout

| Path | What |
|---|---|
| `src/llmredteam/attacks/*.yaml` | Attack packs (direct, indirect, RAG/agent), OWASP-tagged, with Hindi/Marathi translations |
| `src/llmredteam/canary.py` | Canary secrets and encoded-leak detection |
| `src/llmredteam/judges.py` | Deterministic per-goal judging |
| `src/llmredteam/mutators.py` | Evasion transforms |
| `src/llmredteam/defenses.py` | Baseline defenses to compare |
| `src/llmredteam/targets/` | Ollama and HTTP-app adapters |
| `src/llmredteam/runner.py` | Variant expansion, async matrix, seeded run manifests |
| `src/llmredteam/stats.py` | Bootstrap confidence intervals |
| `src/llmredteam/report.py` | Aggregation + HTML report |
| `victims/` | Deliberately vulnerable demo apps |

## Results

Populated by `llmrt run configs/models.yaml` on the local model set; the headline table and `runs/<id>/report.html`
go here once the full sweep has run. Numbers are committed under `runs/` so every figure traces to raw trial data.

## Ethics

Everything here runs against models and apps **you** control, for defensive testing. The vulnerable apps are toys
with planted canaries and no real data. Don't point it at systems you're not authorised to test.
