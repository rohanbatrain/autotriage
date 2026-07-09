# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Enterprise operations & governance docs: operations (SLOs/SLIs, error budgets,
  observability, on-call, cost), deployment, configuration reference, and
  runbooks (running, incident-response, rollback, troubleshooting).
- Community health files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`,
  issue/PR templates, `dependabot.yml`, and repo-level `CODEOWNERS`.
- Centralized configuration contract via `AUTOTRIAGE_*` environment variables
  (see [docs/configuration.md](docs/configuration.md)); implemented in
  `src/autotriage/config.py`.

### Changed
- _Nothing yet._

### Deprecated
- _Nothing yet._

### Removed
- _Nothing yet._

### Fixed
- _Nothing yet._

### Security
- _Nothing yet._

## [0.1.0] - 2026-07-09

Initial release of AutoTriage — an autonomous vulnerability-triage agent built on
the Claude Agent SDK.

### Added
- **Shared contracts** (`autotriage.schema`): Pydantic v2 `Finding` and
  `TriageDecision` models as the single source of truth, with a confidence
  guardrail that coerces low-confidence decisions to `needs_human` / `escalate`.
- **Scanner layer** (`autotriage.scanners`): defensive subprocess adapters that
  normalize **Semgrep** (SAST), **Trivy** (SCA/IaC/secrets), and **Gitleaks**
  (secrets) output onto `Finding`, deduplicated by a stable content-hash id. A
  missing binary or malformed output degrades to an empty result rather than
  aborting the scan.
- **Triage agent** (`autotriage.agent`): two interchangeable backends — the
  Anthropic Messages API with a forced `submit_triage` tool call (`api`,
  default, most reliable) and the Claude Agent SDK with `json_schema` structured
  output (`sdk`). Batch triage fails **closed**: an un-triageable finding is
  escalated to a human, never dropped. Free-text fields are scrubbed of leaked
  prompt/tool markup.
- **Action layer** (`autotriage.tools`): deterministic, offline `file_ticket`,
  `draft_pr`, `escalate`, and CODEOWNERS-based `assign_owner`, routed by
  `dispatch`; an append-only `TRACKER.md` ledger; and an optional Agent SDK MCP
  server exposing the write actions for fully-autonomous mode.
- **CLI** (`python -m autotriage`): `--findings`, `--backend`, `--model`,
  `--dry-run`, `--tickets-dir`, `--codeowners`, `--tracker`, `--pr-dir`.
- **Eval harness** (`autotriage.eval_harness` + `evals/run_eval.py`): scores
  triage quality against a labeled set — precision, recall, F1, accuracy, and
  severity-agreement — with an offline `--stub` that needs no API key.
- **CI**: `ci.yml` quality gate (ruff, ruff format, `mypy --strict`, pytest) and
  `triage.yml` running a scan → triage (`--dry-run`) on every PR and uploading
  the summary as an artifact.
- **Tooling**: PEP 8 / 257 / 484 enforced via ruff + mypy strict, ≥80% coverage,
  bandit and pip-audit, and pre-commit hooks.

[Unreleased]: https://github.com/rohanbatrain/autotriage/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rohanbatrain/autotriage/releases/tag/v0.1.0
