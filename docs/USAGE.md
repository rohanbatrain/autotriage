# AutoTriage — Usage (every command, every flow)

An exhaustive operator's reference for AutoTriage: every command, every flag,
every environment variable, and every end-to-end flow. Flags and defaults here
are read directly from the source (`src/autotriage/__main__.py`,
`src/autotriage/scanners.py`, `evals/run_eval.py`, `src/autotriage/config.py`,
`Makefile`, `Dockerfile`, `pyproject.toml`, and the two GitHub workflows).

![help](media/help.gif)

For the conceptual "how it fits together" tour, see
[CODE_TOUR.md](CODE_TOUR.md) and [architecture.md](architecture.md). For the
config contract in prose, see [configuration.md](configuration.md).

---

## 1. Setup

### 1.1 Virtual environment + install

```bash
# From the repository root.
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

# Editable install with the agent runtime + dev tooling extras.
pip install -e ".[agent,dev]"
```

Extras (from `pyproject.toml`):

- **core** (always) — `pydantic>=2.6`, `pydantic-settings>=2.2`. Enough for the
  schema, scanners, and the offline eval stub.
- **`agent`** — `claude-agent-sdk>=0.1.0`, `anthropic>=0.40.0`. Required for
  live triage (the `api` / `sdk` backends).
- **`dev`** — `ruff`, `mypy`, `pytest`, `pytest-cov`, `hypothesis`, `bandit`,
  `pip-audit`. Required to run the quality gate locally.

Install just what you need, e.g. `pip install -e ".[agent]"` for a runtime-only
container, or `pip install -e ".[dev]"` to run tests without the LLM backends.

### 1.2 Install the scanners

The scanner binaries are **not** bundled (see the note in `Dockerfile`); they
must be on `PATH`. A missing binary is skipped with a warning, never fatal.

```bash
# Semgrep (SAST) — pip is the simplest path.
pip install semgrep

# Trivy (SCA / IaC / secrets) — macOS/Homebrew shown.
brew install trivy                   # Linux: see aquasecurity/trivy install docs

# Gitleaks (secret detection).
brew install gitleaks                # Linux: see gitleaks releases / install.sh
```

Commands each adapter runs (from `scanners.py`):

- Semgrep: `semgrep --config auto --json <target>`
- Trivy: `trivy fs --format json --scanners vuln,misconfig,secret <target>`
- Gitleaks: `gitleaks detect --source <target> --no-git --report-format json --report-path <tmp>`

### 1.3 Set the API key (live triage only)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Live triage (`python -m autotriage` without `--dry-run`, and
`run_eval.py` without `--stub`) fails fast with a clear error if this is unset.
`--dry-run` still runs triage and therefore still needs the key; only the
**write** actions are suppressed. The eval **stub** (`run_eval.py --stub`)
needs no key at all.

---

## 2. Command reference

### 2.1 `python -m autotriage.scanners` — run scanners, emit findings

Runs Semgrep + Trivy + Gitleaks over a target and prints a normalized
`Finding[]` JSON array (deduplicated by finding id).

```bash
python -m autotriage.scanners <target> [-o OUTPUT]
```

| Flag / arg | Default | Description |
|---|---|---|
| `target` (positional, required) | — | File or directory to scan. |
| `-o`, `--output PATH` | *(stdout)* | Write the findings JSON here instead of stdout. |

```bash
python -m autotriage.scanners target/ -o findings.json
python -m autotriage.scanners target/app.py            # print to stdout
```

### 2.2 `python -m autotriage` — triage findings and act

Loads a `Finding[]` JSON file, triages each finding into a `TriageDecision`,
assigns an owner from CODEOWNERS when the model gave none, dispatches the
resulting action (unless `--dry-run`), and prints a summary. Also runnable as
the `autotriage` console script.

```bash
python -m autotriage [--findings PATH] [--backend {api,sdk}] [--model ID] \
                     [--dry-run] [--tickets-dir PATH] [--codeowners PATH] \
                     [--tracker PATH] [--pr-dir PATH]
```

| Flag | Default | Description |
|---|---|---|
| `--findings PATH` | `fixtures/findings.sample.json` | JSON array of `Finding` records to triage. (Hard-coded default; not env-configurable.) |
| `--backend {api,sdk}` | `api` (or `$AUTOTRIAGE_BACKEND`) | Triage backend: `api` = Anthropic Messages API forced tool call (most reliable); `sdk` = Claude Agent SDK structured output. |
| `--model ID` | `$AUTOTRIAGE_MODEL` → `claude-sonnet-5` | Model id override for this run. |
| `--dry-run` | *(off)* | Triage and print the summary but write **no** tickets/PRs/tracker rows and dispatch **no** actions. Operational kill switch. |
| `--tickets-dir PATH` | `tickets` (or `$AUTOTRIAGE_TICKETS_DIR`) | Directory for ticket Markdown files. |
| `--codeowners PATH` | `target/CODEOWNERS` (or `$AUTOTRIAGE_CODEOWNERS`) | CODEOWNERS file used for owner assignment. |
| `--tracker PATH` | `TRACKER.md` (or `$AUTOTRIAGE_TRACKER_PATH`) | Path to the append-only `TRACKER.md` ledger. |
| `--pr-dir PATH` | `pull_requests` (or `$AUTOTRIAGE_PR_DIR`) | Directory for remediation PR drafts. |

```bash
python -m autotriage --findings findings.json --backend api
python -m autotriage --findings findings.json --dry-run
python -m autotriage --findings findings.json \
    --tickets-dir out/tickets --tracker out/TRACKER.md --pr-dir out/prs
```

### 2.3 `python evals/run_eval.py` — score triage quality

Scores triage decisions against the labeled ground-truth set, writes a Markdown
report, and prints one metrics line. With `--stub` it uses a deterministic
offline heuristic (no API key); otherwise it replays the real agent.

```bash
python evals/run_eval.py [--stub] [--backend {api,sdk}] [--findings PATH] \
                         [--labels PATH] [--report PATH]
```

| Flag | Default | Description |
|---|---|---|
| `--stub` | *(off)* | Use the built-in offline stub triage — **no API key required**. |
| `--backend {api,sdk}` | `api` | Agent backend used when **not** running `--stub`. |
| `--findings PATH` | `fixtures/findings.sample.json` | Normalized findings to score. |
| `--labels PATH` | `evals/labeled_findings.json` | Ground-truth labels. |
| `--report PATH` | `evals/report.md` | Where to write the Markdown report. |

```bash
python evals/run_eval.py --stub                        # offline, CI-safe
python evals/run_eval.py --backend sdk                 # live, needs API key
python evals/run_eval.py --report examples/report.md   # custom report path
```

### 2.4 `make` targets

Wrappers around the commands above (from `Makefile`). Override the interpreter
with `PYTHON=...` and the scan target with `TARGET=...`.

| Target | What it runs |
|---|---|
| `make install` | `pip install -e ".[agent,dev]"` (editable, agent + dev extras). |
| `make lint` | `ruff check src tests`. |
| `make format` | `ruff format src tests` (auto-format in place). |
| `make typecheck` | `mypy src` (strict). |
| `make test` | `pytest`. |
| `make cov` | `pytest --cov=autotriage --cov-fail-under=80`. |
| `make security` | `bandit -c pyproject.toml -r src` then `pip-audit`. |
| `make scan` | `python -m autotriage.scanners target -o findings.json`. |
| `make triage` | `python -m autotriage --findings findings.json`. |
| `make eval` | `python evals/run_eval.py --stub`. |
| `make docker-build` | `docker build -t autotriage:latest .`. |
| `make demos` | Render all demo GIFs from the tapes in `docs/tapes/` (requires `vhs`). |
| `make all` | `lint typecheck test` (the default gate: lint, type-check, test). |

> Demo GIFs are rendered with `vhs` via `make demos` (or each tape directly) —
> see [Flow H](#flow-h--regenerate-the-demo-gifs).

### 2.5 Docker

The image ships only the Python triage/action pipeline (scanners are expected
on `PATH` / mounted in). `ENTRYPOINT` is `python -m autotriage`; default `CMD`
is `--help`.

```bash
# Build (or: make docker-build)
docker build -t autotriage:latest .

# Show help (default CMD)
docker run --rm autotriage:latest

# Triage a mounted findings file (append CLI flags after the image name;
# they are passed through to `python -m autotriage`).
docker run --rm \
    -e ANTHROPIC_API_KEY \
    -v "$PWD:/workspace" \
    autotriage:latest \
    --findings findings.json --dry-run
```

The container runs as the unprivileged `autotriage` user with `/workspace` as
its working directory.

### 2.6 Direct quality tools

Run the underlying tools without `make`:

```bash
ruff check src tests                       # or: ruff check .
ruff format src tests                      # add --check for a non-mutating gate
mypy src                                   # strict typing (pyproject config)
pytest                                     # test suite
pytest --cov=autotriage --cov-report=term-missing --cov-fail-under=80
bandit -c pyproject.toml -r src            # SAST on our own source
pip-audit                                  # dependency CVE audit
pre-commit run --all-files                 # pre-commit hooks (.pre-commit-config.yaml)
```

---

## 3. Environment variables

All tunables are centralized in `src/autotriage/config.py` (a Pydantic
`Settings` model). `ANTHROPIC_API_KEY` is unprefixed (provider convention);
every other tunable uses the `AUTOTRIAGE_` prefix.

**Precedence:** `CLI flag  >  environment variable  >  built-in default`.
The CLI builds its flag defaults from the resolved settings, so an explicit
flag always wins over the environment, which wins over the coded default.

| Name | Default | Meaning |
|---|---|---|
| `ANTHROPIC_API_KEY` | *(none — required for live triage)* | Credential used by both the `api` and `sdk` backends. Live triage fails fast without it; `--dry-run` still needs it, the eval `--stub` does not. |
| `AUTOTRIAGE_MODEL` | `claude-sonnet-5` | Model id passed to the triage backend. Overridable with `--model`. |
| `AUTOTRIAGE_BACKEND` | `api` | Default backend: `api` (Messages API) or `sdk` (Agent SDK). Overridable with `--backend`. |
| `AUTOTRIAGE_CONFIDENCE_THRESHOLD` | `0.6` | Confidence floor below which a decision is coerced to `needs_human` / `escalate`. *(Enforced today as the `GUARDRAIL_CONFIDENCE_THRESHOLD` constant in `schema.py`; env override is in `config.py`.)* |
| `AUTOTRIAGE_TICKETS_DIR` | `tickets` | Directory for ticket files. Overridable with `--tickets-dir`. |
| `AUTOTRIAGE_TRACKER_PATH` | `TRACKER.md` | Path to the append-only ledger. Overridable with `--tracker`. |
| `AUTOTRIAGE_PR_DIR` | `pull_requests` | Directory for remediation PR drafts. Overridable with `--pr-dir`. |
| `AUTOTRIAGE_CODEOWNERS` | `target/CODEOWNERS` | CODEOWNERS file for owner assignment. Overridable with `--codeowners`. |
| `AUTOTRIAGE_MAX_TOKENS` | `4096` | Output-token ceiling per triage decision. *(Enforced today as the `_MAX_TOKENS` constant in `agent.py`; env override is in `config.py`.)* |
| `AUTOTRIAGE_LOG_LEVEL` | `INFO` | Logging level name (`DEBUG`/`INFO`/`WARNING`/`ERROR`). |
| `AUTOTRIAGE_LOG_FORMAT` | `json` | Log rendering: `json` (structured) or `text` (human-readable). |

An optional `.env` file at the repo root is loaded automatically; unknown
environment variables are ignored. Full prose reference:
[configuration.md](configuration.md).

---

## 4. Flows

Every end-to-end flow, as copy-pasteable steps.

### Flow A — full local run (scan → triage → act)

Produces tickets, PR drafts, and a tracker ledger.

```bash
source .venv/bin/activate
export ANTHROPIC_API_KEY="sk-ant-..."

# 1. Scan the bundled vulnerable target into normalized findings.
python -m autotriage.scanners target/ -o findings.json

# 2. Triage every finding and dispatch actions.
python -m autotriage --findings findings.json --backend api \
    --tickets-dir out/tickets --tracker out/TRACKER.md --pr-dir out/prs
```

Artifacts produced:

- `findings.json` — normalized `Finding[]` (from step 1).
- `out/tickets/<finding-id>.md` — one ticket per `open_ticket` / `draft_pr`.
- `out/prs/<finding-id>.pr.md` — a remediation draft per `draft_pr`.
- `out/TRACKER.md` — one appended row per finding acted on.
- stdout — the `=== AutoTriage summary ===` block (verdict/severity counts,
  tickets to write, escalations).

Owner assignment: if the model does not set `suggested_owner`, the CLI resolves
one from `--codeowners` (default `target/CODEOWNERS`).

### Flow B — dry-run preview (no writes)

Same triage, zero side effects. Use it as a kill switch or a plan preview.

```bash
export ANTHROPIC_API_KEY="sk-ant-..."     # triage still runs, so the key is needed
python -m autotriage --findings findings.json --dry-run
```

Artifacts: **none written** — only the stdout summary, ending with
`mode : dry-run (no actions taken)`. No `tickets/`, `pull_requests/`, or
`TRACKER.md` are touched.

### Flow C — evaluation (offline stub vs live)

![eval](media/eval.gif)

```bash
# Offline — deterministic stub, no API key. CI-safe.
python evals/run_eval.py --stub

# Live — replay the real agent (needs ANTHROPIC_API_KEY).
export ANTHROPIC_API_KEY="sk-ant-..."
python evals/run_eval.py --backend sdk
```

Both write `evals/report.md` (override with `--report`) and print one metrics
line, e.g.:

```
precision=1.000 recall=1.000 f1=1.000 accuracy=1.000 severity_agreement=1.000
report written to evals/report.md
```

Artifacts: `evals/report.md` (verdict precision/recall/F1, accuracy, severity
agreement, a confusion matrix, and per-finding pass/fail). Methodology:
[eval-methodology.md](eval-methodology.md).

### Flow D — choosing a backend (api vs sdk) and model

Both backends consume a `Finding` and emit a `TriageDecision`, so they are
interchangeable.

```bash
# api (default): Messages API, single forced submit_triage tool call. Most reliable.
python -m autotriage --findings findings.json --backend api

# sdk: Claude Agent SDK query with json_schema output.
python -m autotriage --findings findings.json --backend sdk

# Pin a model for one run (else $AUTOTRIAGE_MODEL, else claude-sonnet-5).
python -m autotriage --findings findings.json --model claude-sonnet-5

# Set a shell-wide default via env; a flag still overrides it.
export AUTOTRIAGE_BACKEND=sdk
export AUTOTRIAGE_MODEL=claude-sonnet-5
```

### Flow E — CI quality gate (`.github/workflows/ci.yml`)

Runs on **every push and pull request**, on a Python **3.11 / 3.12** matrix.

![tests](media/tests.gif)

Steps, in order:

1. `pip install -e ".[agent,dev]"`
2. `ruff check .` — lint.
3. `ruff format --check .` — format gate.
4. `mypy src` — strict typing.
5. `pytest --cov=autotriage --cov-report=term-missing --cov-report=xml --cov-fail-under=80`.
6. `bandit -c pyproject.toml -r src` — SAST on our own source.
7. `pip-audit` — dependency audit (informational; `continue-on-error`).
8. Upload `coverage.xml` as an artifact.

Reproduce locally:

```bash
make all && make cov && make security
```

### Flow F — PR-triage workflow (`.github/workflows/triage.yml`)

Runs on **pull requests**. Installs the scanners, scans the checkout, and
triages in dry-run mode.

Steps, in order:

1. Checkout + set up Python 3.12.
2. `pip install -e ".[agent]"`.
3. Install Semgrep (`pip install semgrep`), Trivy (`aquasecurity/setup-trivy`),
   Gitleaks (install script onto `PATH`).
4. `python -m autotriage.scanners . -o findings.json`.
5. `python -m autotriage --findings findings.json --dry-run`
   (with `ANTHROPIC_API_KEY` from repo secrets).
6. Upload `findings.json`, `TRACKER.md`, and `tickets/` as the
   `triage-summary` artifact (`if: always()`, skipped if absent).

Because step 5 is `--dry-run`, the workflow reports triage without committing
tickets or PRs back to the repo.

### Flow G — containerized run (Docker)

```bash
docker build -t autotriage:latest .        # or make docker-build

# Default CMD prints --help.
docker run --rm autotriage:latest

# Real run against a mounted workspace.
docker run --rm \
    -e ANTHROPIC_API_KEY \
    -v "$PWD:/workspace" \
    autotriage:latest \
    --findings findings.json \
    --tickets-dir out/tickets --tracker out/TRACKER.md --pr-dir out/prs
```

Notes: scanners are not in the image — scan on the host (or a scanner-equipped
runner) and mount `findings.json` in. Artifacts land under the mounted
`/workspace`. See [deployment.md](deployment.md) for production guidance.

### Flow H — regenerate the demo GIFs

The GIFs embedded in the docs are rendered from the [VHS](https://github.com/charmbracelet/vhs)
tapes in `docs/tapes/`. Regenerate them all with `make demos`, or render each
tape directly:

```bash
# Requires the `vhs` binary (brew install vhs) and an activated venv.
make demos                      # renders every docs/tapes/*.tape

# ...or one at a time:
vhs docs/tapes/help.tape        # -> docs/media/help.gif
vhs docs/tapes/eval.tape        # -> docs/media/eval.gif
vhs docs/tapes/tests.tape       # -> docs/media/tests.gif
```

Each tape declares its own `Output` path (all under `docs/media/`). Edit the
tape to change the recorded command, then re-run `vhs` to regenerate.

---

## 5. Outputs reference

Real, committed samples live in [`../examples/`](../examples/) (see its
[README](../examples/README.md)).

### `findings.json` — normalized `Finding[]`

Array of `Finding` objects (schema in `src/autotriage/schema.py`). Example
element (from `fixtures/findings.sample.json`):

```json
{
  "id": "sast-sqli-001",
  "tool": "semgrep",
  "type": "SAST",
  "rule_id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
  "title": "SQL injection via f-string in query",
  "severity_raw": "ERROR",
  "cwe": ["CWE-89"],
  "owasp": ["A03:2021"],
  "file": "target/app.py",
  "line": 44,
  "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE name = '{username}'\")",
  "description": "User-controlled input is interpolated directly into a SQL query, allowing injection.",
  "raw": {}
}
```

A live 44-finding scan is committed at
[`../examples/real-scan.findings.json`](../examples/real-scan.findings.json).

### `tickets/<finding-id>.md`

One Markdown ticket per `open_ticket` (and per `draft_pr`, which also files a
tracking ticket). Header line, metadata block, and Business impact / Reasoning /
Remediation / Offending code sections. Sample:
[`../examples/tickets/sast-sqli-001.md`](../examples/tickets/sast-sqli-001.md).

```markdown
# [CRITICAL] SQL injection via f-string in query

- **Finding ID:** sast-sqli-001
- **Scanner:** semgrep (SAST)
- **Verdict:** true_positive
- **Severity:** critical
- **Confidence:** 0.93
- **Recommended action:** open_ticket
- **Owner:** backend-app-team
...
```

### `pull_requests/<finding-id>.pr.md`

A remediation draft per `draft_pr`: Why / Proposed change / Original code.
Sample:
[`../examples/prs/sast-cmdinj-003.pr.md`](../examples/prs/sast-cmdinj-003.pr.md).

```markdown
# Fix: OS command injection via os.system

_Automated remediation draft generated by AutoTriage._

- **Finding ID:** sast-cmdinj-003
- **Location:** `target/app.py:57`
- **Severity:** critical
- **Suggested reviewer:** app-security / backend-team
...
```

### `TRACKER.md`

Append-only Markdown ledger; one row per acted-on finding. Sample:
[`../examples/TRACKER.md`](../examples/TRACKER.md).

```markdown
| Timestamp (UTC) | Finding | Verdict | Severity | Confidence | Action | Owner | Location |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-07-09T11:57:30+00:00 | sast-sqli-001 | true_positive | critical | 0.93 | open_ticket | backend-app-team | target/app.py:44 |
```

### `evals/report.md`

The evaluation scorecard: metrics table, verdict confusion matrix, and a
per-finding pass/fail table. Sample:
[`../examples/report.md`](../examples/report.md) (the default output path is
`evals/report.md`).

```markdown
# AutoTriage Evaluation Report

Scored **15** findings — **15/15** fully correct.

| Metric | Value |
| --- | --- |
| Verdict accuracy (all findings) | 100.0% |
| Severity agreement (true positives) | 100.0% |
```

---

## 6. Troubleshooting

Symptom-to-fix guide (missing API key, missing scanner binaries, empty
findings, backend errors, and more):
[runbooks/troubleshooting.md](runbooks/troubleshooting.md).
