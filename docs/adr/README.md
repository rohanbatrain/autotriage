# Architecture Decision Records

This directory records the significant, hard-to-reverse architectural decisions
behind AutoTriage, using the [Michael Nygard ADR format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions).
Each record is immutable once accepted; a changed decision is captured as a new
ADR that supersedes the old one (see [ADR-0001](0001-record-architecture-decisions.md)).

## Index

| ADR | Title | Status | Date |
| --- | --- | --- | --- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted | 2026-07-09 |
| [0002](0002-normalized-finding-contract.md) | A single normalized `Finding` contract across scanners | Accepted | 2026-07-09 |
| [0003](0003-forced-tool-call-for-structured-output.md) | Forced tool-call / JSON-schema for structured triage output | Accepted | 2026-07-09 |
| [0004](0004-confidence-guardrail-and-fail-closed.md) | Confidence guardrail enforced in the type layer, fail closed to human | Accepted | 2026-07-09 |
| [0005](0005-dual-backend-sdk-and-messages-api.md) | Support both the Claude Agent SDK and the Anthropic Messages API | Accepted | 2026-07-09 |
| [0006](0006-treat-scanner-output-as-untrusted.md) | Treat scanner output as untrusted (prompt-injection defense) | Accepted | 2026-07-09 |

## Status legend

- **Proposed** — under discussion, not yet in force.
- **Accepted** — in force; reflected in the code.
- **Superseded by ADR-XXXX** — replaced by a later decision.
- **Deprecated** — no longer relevant, not replaced.

## Related documents

- [Architecture](../architecture.md) — C4-style system, container, and component views.
- [Threat model](../threat-model.md) — STRIDE analysis of the agent.
- [Escalation policy](../escalation-policy.md) — the autonomous-vs-escalate decision table.
- [Data contracts](../data-contracts.md) — `Finding` and `TriageDecision` field reference.
