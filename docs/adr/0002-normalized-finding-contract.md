# 2. A single normalized `Finding` contract across scanners

- Status: Accepted
- Date: 2026-07-09
- Deciders: AutoTriage maintainers

## Context

AutoTriage integrates three heterogeneous scanners, each with its own native
JSON shape and severity vocabulary:

- **Semgrep** (SAST) — `results[].check_id`, `extra.metadata.cwe`, `start.line`.
- **Trivy** (SCA / IaC / secrets) — `Results[].Vulnerabilities|Misconfigurations|Secrets`, `Severity`, `PkgName`.
- **Gitleaks** (secrets) — `RuleID`, `File`, `StartLine`, `Match`.

If the triage agent, the action layer, and the evaluation harness each consumed
raw scanner JSON, every downstream component would need per-tool branching, the
prompt would carry tool-specific formatting, and adding a fourth scanner would
ripple through the whole system. Deduplication across tools (e.g. Trivy and
Gitleaks both flagging one secret) would also be ad hoc.

## Decision

Define **one** Pydantic v2 model, `Finding` (in `src/autotriage/schema.py`), as
the sole contract between the scan layer and everything downstream. Each scanner
gets a thin adapter in `src/autotriage/scanners.py` that maps its native records
onto `Finding`; no other module ever sees raw scanner JSON.

Key design points:

- Normalized enums (`ScannerTool`, `FindingType`, `Severity`) replace each tool's
  private vocabulary.
- A deterministic content-hash id, `Finding.make_id(tool, rule_id, file, line)`,
  yields a stable 12-char identifier that lets the tracker and eval harness
  deduplicate reliably across runs.
- The untouched scanner record is preserved in `raw` for auditability.
- Adapters are defensive: a missing binary, non-zero exit, or malformed JSON
  degrades to an empty list with a warning rather than raising.

## Consequences

- Positive: the agent, action layer, and eval harness are backend- and
  scanner-agnostic; they depend only on `Finding`.
- Positive: adding a scanner is a localized change — write one adapter that
  emits `Finding` objects.
- Positive: stable ids make dedupe, tracking, and ground-truth labeling reliable.
- Negative: normalization is lossy at the top level (tool-specific nuance is
  flattened); mitigated by retaining `raw`.
- Negative: the contract is a coordination point — a breaking change to `Finding`
  affects every layer, so it is versioned deliberately (see ADR-0001).
