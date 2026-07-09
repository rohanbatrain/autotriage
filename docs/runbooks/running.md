# Runbook: running a scan → triage

**Audience:** engineers and on-call operators running AutoTriage locally or in
CI.
**Goal:** produce normalized findings, triage them into structured decisions,
and (optionally) act on them.

This runbook documents the real, implemented pipeline. For flag/env details see
[configuration.md](../configuration.md).

---

## The pipeline in one line

```
scanners (Semgrep/Trivy/Gitleaks)  →  findings.json  →  agent (Claude)  →  TriageDecision  →  actions (tickets / PRs / escalations)
```

Stage 1 (scan) and stage 2 (triage) are decoupled by the `findings.json`
contract, so you can run them independently.

---

## Prerequisites

- Python **3.11+** (CI runs 3.12).
- For **live triage:** an `ANTHROPIC_API_KEY`. Not needed for `--dry-run` or the
  eval stub.
- For a **real scan:** the three scanner binaries on `PATH`. Each is optional —
  a missing scanner logs a warning and is skipped, it does not abort the run.

---

## 1. Set up a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[agent,dev]"        # agent = live backends; dev = tooling
```

If you only need scanning + the offline eval (no live LLM), `pip install -e .`
is enough — the `anthropic` / `claude-agent-sdk` deps live in the `agent` extra
and are imported lazily.

## 2. Install the scanners

macOS / Homebrew:

```bash
pip install semgrep            # SAST
brew install trivy gitleaks    # SCA/IaC + secrets
```

Linux (CI-style):

```bash
pip install semgrep
# Trivy: use the aquasecurity/setup-trivy action or the official install script
# Gitleaks: curl the official install.sh (see .github/workflows/triage.yml)
```

Confirm they resolve:

```bash
command -v semgrep trivy gitleaks
```

## 3. Provide the API key (live triage only)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Never commit this. See [deployment.md](../deployment.md#secrets-management).

---

## Running locally

### Scan a target into normalized findings

```bash
python -m autotriage.scanners target/ -o findings.json
```

- Runs Semgrep, Trivy, and Gitleaks over `target/`, normalizes each tool's JSON
  onto the shared `Finding` schema, de-duplicates by finding id, and writes a
  JSON array.
- **Expected output:** a `findings.json` file containing a JSON array. Warnings
  like `semgrep binary not found on PATH; skipping SAST scan` are normal when a
  scanner is absent — the other scanners still run.
- **Empty array?** That is a valid result (nothing found, or all scanners
  skipped). See [troubleshooting.md](troubleshooting.md#empty-findings).

### Triage the findings

Live (writes tickets, PRs, tracker rows, assigns owners):

```bash
python -m autotriage --findings findings.json --backend api
```

Preview only — **no side effects** (the kill switch):

```bash
python -m autotriage --findings findings.json --dry-run
```

**Expected output** — a summary printed to stdout, e.g.:

```
=== AutoTriage summary ===
findings triaged : 15
verdicts         : true_positive=12, false_positive=2, needs_human=1
severities       : critical=3, high=5, medium=4, low=2, info=1
tickets to write : 11
escalations      : 1
mode             : dry-run (no actions taken)      # only in --dry-run
```

On a **live** run, `mode` is replaced by `actions taken : N` followed by one
line per finding (e.g. `sast-sqli-001: drafted PR ... and opened tracking
ticket`).

### What a live run writes

| Artifact | Location (default) | Written when |
|---|---|---|
| Ticket Markdown | `tickets/<finding-id>.md` | verdict → `open_ticket` or `draft_pr` |
| Remediation PR draft | `pull_requests/<finding-id>.pr.md` | verdict → `draft_pr` |
| Action ledger row | `TRACKER.md` | every dispatched action (incl. suppress/escalate) |

`TRACKER.md` is an **append-only** Markdown table with one row per action
(timestamp, finding, verdict, severity, confidence, action, owner, location).

### Choosing a backend

- `--backend api` (default) — Anthropic Messages API with a single **forced tool
  call**. Structured output is guaranteed by the tool contract. Most reliable;
  use this in CI.
- `--backend sdk` — Claude Agent SDK `query()` with a `json_schema` output
  format. Use when you want the Agent SDK runtime.

Both fail **closed**: if a finding cannot be triaged, it is escalated to a human
rather than dropped.

---

## Scoring triage quality (eval harness)

Offline, deterministic, **no API key**:

```bash
python evals/run_eval.py --stub
```

Against the live agent:

```bash
python evals/run_eval.py --backend api
```

**Expected output** — a one-line metric summary plus `evals/report.md`:

```
precision=1.000 recall=0.933 f1=0.966 accuracy=0.933 severity_agreement=0.917
report written to evals/report.md
```

A `needs_human` verdict is treated as an **abstention**: it never hurts
precision, but if the ground truth was `true_positive` it counts as a recall
miss. See [operations.md](../operations.md#slos--slis) for how these map to SLIs.

---

## Running in CI

Two workflows ship in `.github/workflows/`:

- **`ci.yml`** — the quality gate (ruff, ruff format check, `mypy --strict`,
  pytest) on every push and PR.
- **`triage.yml`** — on every PR: installs the scanners, runs
  `python -m autotriage.scanners . -o findings.json`, then
  `python -m autotriage --findings findings.json --dry-run`, and uploads
  `findings.json`, `TRACKER.md`, and `tickets/` as the `triage-summary`
  artifact.

The triage workflow runs in **`--dry-run`** today — it reports, it does not
auto-act. `ANTHROPIC_API_KEY` is supplied from repository secrets. To promote
to a live gate, see [deployment.md](../deployment.md#deployment-models).

---

## Quick verification

A green end-to-end smoke test that needs **no** scanners and **no** API key:

```bash
python -m autotriage --findings fixtures/findings.sample.json --dry-run
python evals/run_eval.py --stub
```

Both should exit `0` and print a summary. If they do, the install is sound.

## Related runbooks

- Something went wrong at runtime → [troubleshooting.md](troubleshooting.md)
- The agent misbehaved (mass FPs, runaway cost, bad auto-action) →
  [incident-response.md](incident-response.md)
- Bad release or model change → [rollback.md](rollback.md)
