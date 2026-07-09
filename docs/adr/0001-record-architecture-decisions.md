# 1. Record architecture decisions

- Status: Accepted
- Date: 2026-07-09
- Deciders: AutoTriage maintainers

## Context

AutoTriage is an autonomous agent that ingests attacker-influenceable scanner
output and takes actions (files tickets, drafts remediation PRs, escalates to
humans). Decisions about how the system reasons, where it fails closed, and what
it is allowed to trust are security-relevant and long-lived. We need a durable,
reviewable record of *why* the architecture is the way it is, so that future
contributors do not silently unwind a guardrail without understanding its intent.

Tribal knowledge and commit messages are insufficient: they are hard to discover,
rarely explain rejected alternatives, and do not capture the consequences of a
choice.

## Decision

We will use Architecture Decision Records (ADRs) as described by Michael Nygard.

- Each significant, hard-to-reverse decision gets one Markdown file in
  `docs/adr/`, numbered sequentially: `NNNN-short-title.md`.
- Every ADR follows the same skeleton: **Status**, **Context**, **Decision**,
  **Consequences**.
- Status is one of `Proposed`, `Accepted`, `Superseded by ADR-XXXX`, or
  `Deprecated`. ADRs are immutable once accepted; a changed decision is a new
  ADR that supersedes the old one, never an in-place rewrite.
- `docs/adr/README.md` is the index of record.

## Consequences

- Positive: the reasoning behind guardrails (confidence threshold, fail-closed,
  untrusted-input posture) is discoverable and reviewable in code review.
- Positive: rejected alternatives are captured, so debates are not re-litigated.
- Negative: a small, ongoing documentation cost per significant decision.
- Neutral: ADRs describe intent and trade-offs; the executable source of truth
  remains the code in `src/autotriage/`.
