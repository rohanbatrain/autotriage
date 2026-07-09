# Configuration reference

AutoTriage is configured through **environment variables** (for deployment and
secrets) and **CLI flags** (for per-invocation overrides). CLI flags always take
precedence over environment variables, which take precedence over the built-in
defaults:

```
CLI flag  >  environment variable  >  built-in default
```

> **Implementation status.** The environment variables below are the canonical
> configuration contract for AutoTriage. They are centralized in
> `src/autotriage/config.py`. A few are already read directly by the runtime
> today (`ANTHROPIC_API_KEY`, `AUTOTRIAGE_MODEL`); the remainder are being
> migrated behind the config module and their built-in defaults already match
> the values listed here. The **Status** column records what is wired today so
> operators are not surprised. Roadmap items are called out explicitly.

---

## Environment variables

| Name | Default | Description | Example | Status |
|---|---|---|---|---|
| `ANTHROPIC_API_KEY` | *(none — required for live triage)* | API key used by both the `api` and `sdk` backends. Without it, live triage fails fast with a clear error; `--dry-run` and the eval stub do not need it. | `sk-ant-...` | Read directly by the agent today |
| `AUTOTRIAGE_MODEL` | `claude-sonnet-5` | Model id used for triage. Overridable per-run with `--model`. | `claude-sonnet-5` | Read directly by the agent today |
| `AUTOTRIAGE_BACKEND` | `api` | Default triage backend: `api` (Anthropic Messages API, forced tool call — most reliable) or `sdk` (Claude Agent SDK structured output). Overridable with `--backend`. | `sdk` | CLI flag today; env via `config.py` |
| `AUTOTRIAGE_CONFIDENCE_THRESHOLD` | `0.6` | Any `TriageDecision` below this confidence is coerced to `needs_human` / `escalate`. This is the core auto-action guardrail. | `0.75` | Constant today (`GUARDRAIL_CONFIDENCE_THRESHOLD`); env via `config.py` |
| `AUTOTRIAGE_TICKETS_DIR` | `tickets` | Directory that ticket Markdown files are written into. Overridable with `--tickets-dir`. | `out/tickets` | CLI flag today; env via `config.py` |
| `AUTOTRIAGE_TRACKER_PATH` | `TRACKER.md` | Path to the append-only action ledger. Overridable with `--tracker`. | `out/TRACKER.md` | CLI flag today; env via `config.py` |
| `AUTOTRIAGE_PR_DIR` | `pull_requests` | Directory that remediation PR drafts are written into. Overridable with `--pr-dir`. | `out/prs` | CLI flag today; env via `config.py` |
| `AUTOTRIAGE_CODEOWNERS` | `target/CODEOWNERS` | Path to the CODEOWNERS file used to assign owners to findings. Overridable with `--codeowners`. | `.github/CODEOWNERS` | CLI flag today; env via `config.py` |
| `AUTOTRIAGE_MAX_TOKENS` | `4096` | Output-token ceiling for a single triage decision. | `4096` | Constant today (`_MAX_TOKENS`); env via `config.py` |
| `AUTOTRIAGE_LOG_LEVEL` | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`. | `DEBUG` | Roadmap (see [operations.md](operations.md#observability)) |
| `AUTOTRIAGE_LOG_FORMAT` | `json` | Log emitter format: `json` (structured, for aggregation) or `text` (human-readable). | `text` | Roadmap (see [operations.md](operations.md#observability)) |

### Notes

- **`ANTHROPIC_API_KEY` is a secret.** Never commit it. Use environment
  variables locally, GitHub Actions secrets in CI, and a secrets manager in
  production. See [deployment.md](deployment.md#secrets-management).
- The default `AUTOTRIAGE_CODEOWNERS` path (`target/CODEOWNERS`) points at the
  bundled vulnerable demo app. For a real repo, point it at your repo-root
  `.github/CODEOWNERS` or `CODEOWNERS`.
- Directory-valued settings (`AUTOTRIAGE_TICKETS_DIR`, `AUTOTRIAGE_PR_DIR`) and
  the tracker parent directory are created automatically on first write.

---

## CLI flags

All flags are implemented today on `python -m autotriage`.

| Flag | Default | Description | Example |
|---|---|---|---|
| `--findings PATH` | `fixtures/findings.sample.json` | Path to a JSON array of normalized `Finding` records to triage. | `--findings findings.json` |
| `--backend {api,sdk}` | `api` | Triage backend to use. `api` is the most reliable (forced tool call); `sdk` uses the Claude Agent SDK. | `--backend sdk` |
| `--model ID` | *(unset → `AUTOTRIAGE_MODEL` → `claude-sonnet-5`)* | Override the triage model id for this run. | `--model claude-sonnet-5` |
| `--dry-run` | *(off)* | Triage and print the summary, but write **no** tickets, PRs, or tracker rows and dispatch **no** actions. This is the operational kill switch. | `--dry-run` |
| `--tickets-dir PATH` | `tickets` | Directory for ticket files. | `--tickets-dir out/tickets` |
| `--codeowners PATH` | `target/CODEOWNERS` | CODEOWNERS file used to assign owners. | `--codeowners .github/CODEOWNERS` |
| `--tracker PATH` | `TRACKER.md` | Path to the `TRACKER.md` ledger to append to. | `--tracker out/TRACKER.md` |
| `--pr-dir PATH` | `pull_requests` | Directory for remediation PR drafts. | `--pr-dir out/prs` |

### Scanner CLI

The scanner layer has its own small CLI (`python -m autotriage.scanners`):

| Flag / arg | Default | Description |
|---|---|---|
| `target` (positional) | *(required)* | File or directory to scan. |
| `-o`, `--output PATH` | *(stdout)* | Write the normalized findings JSON here instead of stdout. |

### Eval CLI

The eval scorer (`python evals/run_eval.py`) accepts:

| Flag | Default | Description |
|---|---|---|
| `--stub` | *(off)* | Use the deterministic offline stub triage — **no API key required**. |
| `--backend {api,sdk}` | `api` | Backend used when not running `--stub`. |
| `--findings PATH` | `fixtures/findings.sample.json` | Normalized findings to score. |
| `--labels PATH` | `evals/labeled_findings.json` | Ground-truth labels. |
| `--report PATH` | `evals/report.md` | Where to write the Markdown report. |

---

## Precedence example

```bash
export AUTOTRIAGE_MODEL=claude-sonnet-5      # env default for the shell
python -m autotriage --findings f.json                 # uses claude-sonnet-5
python -m autotriage --findings f.json --model claude-sonnet-5  # flag wins
```

See also: [operations.md](operations.md) for SLOs and observability,
[deployment.md](deployment.md) for how these are set per environment.
