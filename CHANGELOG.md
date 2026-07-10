# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Composite GitHub Action** ([`action.yml`](action.yml)): any repository adopts
  the full scan → triage → act → comment pipeline in one workflow block
  (`uses: rohanbatrain/autotriage@main`). Installs the scanners + tool, runs the
  pipeline, writes the verdict table to the job summary, and **upserts a single
  pull-request comment**. Reference: [docs/live-demo.md](docs/live-demo.md).
- **Live end-to-end demo**: companion repo
  [`nimbuspay-web`](https://github.com/rohanbatrain/nimbuspay-web) — a fictional
  payments app that consumes the action; opening a PR runs real scanners → live
  Claude triage → inline verdict comment
  ([PR #1](https://github.com/rohanbatrain/nimbuspay-web/pull/1)).
- **Offline `stub` triage backend** (`autotriage.stub`): a deterministic,
  no-API-key heuristic. The CI action falls back to it when no key is available
  (e.g. untrusted fork PRs, where GitHub withholds secrets) so the pipeline
  degrades gracefully instead of failing the build. Also de-duplicates the eval
  harness's former private copy.
- **Markdown triage report** (`autotriage.report`): severity-sorted verdict
  table rendered for the PR comment and `$GITHUB_STEP_SUMMARY`. New CLI flag
  `--summary-md PATH`.
- **Cost guardrail** `--max-findings N`: triage only the N most-severe findings
  and note the remainder in the report.
- **`make demo`**: one-command local pipeline (scan → triage → tickets/PRs +
  summary) on the bundled target; offline by default, `BACKEND=api` for live.
- **Fix-validation loop** (`autotriage.revalidate`): closes the remediation loop
  by applying a proposed fix to an isolated copy of the target and re-running the
  scanner, accepting the fix only when the finding's signature is gone **and** no
  new finding was introduced. Fails closed (`UNRESOLVED` / `REGRESSED` / `ERROR`)
  on anything else, including a baseline that can't reproduce the finding or an
  ambiguous patch. New contracts `FixPatch`, `FileEdit`, `FixValidation`,
  `ValidationStatus` in `autotriage.schema`; live patch generation via
  `autotriage.agent.propose_fix` (forced `submit_fix` tool call); CLI
  `python -m autotriage.revalidate`; design notes in
  [docs/fix-validation.md](docs/fix-validation.md); a real Trivy-verified example
  under [examples/fix-validation/](examples/fix-validation/); and 19 offline
  tests covering the full status matrix plus the ambiguous-match and
  path-traversal guards.
- Enterprise operations & governance docs: operations (SLOs/SLIs, error budgets,
  observability, on-call, cost), deployment, configuration reference, and
  runbooks (running, incident-response, rollback, troubleshooting).
- Community health files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`,
  issue/PR templates, `dependabot.yml`, and repo-level `CODEOWNERS`.
- Centralized configuration contract via `AUTOTRIAGE_*` environment variables
  (see [docs/configuration.md](docs/configuration.md)); implemented in
  `src/autotriage/config.py`.

### Changed
- **Calibrated the triage confidence rubric** in `autotriage.prompts`: unambiguous,
  textbook findings (injection on request data, hardcoded credentials, world-open
  buckets/ports, a dependency with a published CVE and a fix) now get high
  confidence and are auto-actioned, while only genuinely ambiguous findings fall
  below the guardrail and escalate. Previously the rubric framed under-confidence
  as always-safe, which over-escalated clear-cut issues. Live eval verdict
  accuracy remains 1.0.
- The self-scan CI workflow now **dogfoods the composite action** against the
  bundled target instead of duplicating the install/scan/triage steps.

### Deprecated
- _Nothing yet._

### Removed
- _Nothing yet._

### Fixed
- CI scanner installation: Trivy is installed via the official `install.sh`
  (the `aquasecurity/setup-trivy@v0.2.0` tag no longer exists) and Gitleaks from
  a pinned release tarball (its `install.sh` was removed upstream).

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
