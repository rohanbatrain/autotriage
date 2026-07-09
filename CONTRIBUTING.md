# Contributing to AutoTriage

Thanks for helping improve AutoTriage — an autonomous vulnerability-triage agent.
This guide covers dev setup, the quality gate, commit/PR conventions, and how to
extend the system (new scanner adapter or new action tool).

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Development setup

Python **3.11+** (CI runs 3.12).

```bash
# 1. Fork & clone, then:
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

# 2. Editable install with the agent + dev extras
pip install -e ".[agent,dev]"

# 3. Wire the pre-commit hooks (same checks CI runs)
pre-commit install
```

`agent` pulls in the live backends (`anthropic`, `claude-agent-sdk`); `dev` pulls
in the full tooling (ruff, mypy, pytest, coverage, hypothesis, bandit,
pip-audit). The heavy agent deps are imported lazily, so the schema/scanner/eval
code runs even without them.

Smoke test (no API key needed):

```bash
python -m autotriage --findings fixtures/findings.sample.json --dry-run
python evals/run_eval.py --stub
```

---

## Quality gate

Every change must pass the same gate CI enforces. Run it locally before pushing:

| Check | Command | Standard |
|---|---|---|
| Lint | `ruff check .` | PEP 8 + pydocstyle (`D`), import order, bugbear, etc. |
| Format | `ruff format --check .` | Single source of formatting truth |
| Types | `mypy src` | PEP 484, `--strict` |
| Tests | `pytest` | Unit + integration + property tests |
| Coverage | `pytest --cov=autotriage --cov-report=term-missing` | **≥ 80%** (`fail_under = 80`) |
| Security (our code) | `bandit -r src` | SAST on our own source |
| Deps | `pip-audit` | Known-vuln dependencies |

One-liner:

```bash
ruff check . && ruff format --check . && mypy src && pytest --cov=autotriage
```

Notes:
- The intentionally-vulnerable `target/` app is **excluded** from lint, types,
  and bandit — do not "fix" it.
- Public interfaces need PEP 257 Google-style docstrings and full type hints;
  `tests/*` relax a few docstring/annotation rules.
- `pre-commit` runs ruff (with `--fix`), ruff-format, mypy, and hygiene hooks
  (end-of-file, trailing-whitespace, check-yaml, detect-private-key) on commit.

---

## Commit messages — Conventional Commits

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]
[optional footer(s)]
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`,
`chore`. Breaking changes: add `!` (e.g. `feat!:`) or a `BREAKING CHANGE:`
footer.

Examples:

```
feat(scanners): add Bandit adapter for Python SAST
fix(agent): escalate on empty tool-call response instead of raising
docs(ops): document error-budget policy
```

---

## Branch & PR flow

1. Branch from `main`: `git checkout -b feat/<short-name>`.
2. Make focused commits (Conventional Commits).
3. Run the full quality gate locally.
4. Update [CHANGELOG.md](CHANGELOG.md) under **Unreleased** and add/adjust tests.
5. Open a PR and fill in the
   [pull request template](.github/PULL_REQUEST_TEMPLATE.md) checklist.
6. CI (`ci.yml`) must be green; address review feedback.

Keep PRs small and single-purpose. If you change triage behavior (prompt, model,
threshold), include the eval impact (`python evals/run_eval.py`) in the PR.

---

## How to add a scanner adapter

Scanner adapters live in `src/autotriage/scanners.py`. Each one normalizes a
tool's native output onto the shared `Finding` schema. To add one (e.g. Bandit):

1. Add the tool to the `ScannerTool` enum in `src/autotriage/schema.py` (and, if
   it is a new weakness class, `FindingType`).
2. Write `run_<tool>(target: Path) -> list[Finding]`, following the existing
   adapters:
   - Resolve the binary with `shutil.which`; if absent, **log a warning and
     return `[]`** (never raise — one broken tool must not abort the scan).
   - Run it with a **fixed argv list** (never `shell=True`) via the defensive
     `_run_json` helper (or read a report file, like the Gitleaks adapter).
   - Map each record to a `Finding`, using `Finding.make_id(tool, rule_id, file,
     line)` for a stable id and the `_extract_cwe` / `_extract_owasp` helpers.
3. Register it in the `_ADAPTERS` map so `run_scans` picks it up.
4. Add tests under `tests/` with a captured sample of the tool's JSON, asserting
   the normalization (and the missing-binary / bad-JSON degradation paths).

Keep the adapter pure and defensive — that is why the scanner layer is robust.

## How to add an action tool

The deterministic action layer lives in `src/autotriage/tools.py`
(`file_ticket`, `draft_pr`, `escalate`, routed by `dispatch`). To add an action:

1. Implement a pure function that takes `(finding, decision, *, <paths>)` and
   writes its artifact — no network calls; keep it unit-testable and offline.
2. If it is a new agent-recommended action, add it to the `Action` enum in
   `schema.py` and route it in `dispatch`.
3. If it should be available to the **autonomous** (Agent SDK) mode, register it
   in `build_action_mcp_server` alongside the existing `file_ticket` /
   `draft_pr` / `escalate` SDK tools.
4. Add tests covering the artifact contents and the `dispatch` routing.

Respect the guardrails: side effects must stay bounded and auditable (write to
`TRACKER.md`), and anything the agent is unsure about must be able to fail closed
to human escalation.

---

## Reporting security issues

Do **not** open a public issue for a vulnerability in AutoTriage itself. See
[SUPPORT.md](SUPPORT.md) for how to reach a maintainer privately.
