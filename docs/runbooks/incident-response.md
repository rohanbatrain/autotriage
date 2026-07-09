# Runbook: incident response

**Audience:** on-call operator when AutoTriage misbehaves.
**Kill switch:** run with `--dry-run`, or disable the `triage.yml` workflow.
Neither destroys state; both stop new side effects immediately.

This runbook is written SRE-style: **Detect → Contain → Eradicate → Recover →
Review**. Reach for the incident that matches your symptom.

---

## Severity & first move

| Situation | Sev | First move |
|---|---|---|
| Wrong auto-action already merged/shipped | SEV1 | Contain, then [rollback.md](rollback.md) |
| Mass false-positives / mass mis-verdicts | SEV2 | Flip to `--dry-run`, stop the batch |
| Provider (Anthropic API) outage | SEV2/3 | Fail closed (escalate), pause scheduled runs |
| Runaway cost / token spend | SEV2 | Kill the run, cap `AUTOTRIAGE_MAX_TOKENS` / batch size |

**Golden rule:** AutoTriage is designed to *fail closed* — a finding it cannot
triage is escalated to a human, not dropped. When in doubt, force that behavior
by disabling actions (`--dry-run`) and letting humans take over.

---

## The kill switch (memorize this)

There is no single daemon to kill; AutoTriage runs as discrete invocations. To
stop it taking action:

1. **Local / manual runs** — add `--dry-run` (or just stop invoking it). No
   tickets, PRs, tracker rows, or dispatches are written.
2. **CI / scheduled runs** — disable the workflow:
   - GitHub UI: *Actions → Security triage → ⋯ → Disable workflow*, **or**
   - `gh workflow disable triage.yml`.
3. **In-flight run** — interrupt the process (`Ctrl-C` / cancel the Actions
   run). Because `TRACKER.md` and tickets are written incrementally per finding,
   already-written artifacts remain; no partial-write corruption of the schema
   occurs (each file is written whole).

Nothing above deletes existing tickets/PRs — those are reviewed and reverted
during **Recover**.

---

## Incident 1 — Mass false-positives / mass mis-verdicts

The agent is filing tickets for benign findings, or systematically assigning the
wrong verdict/severity.

**Detect**
- Eval regression: `python evals/run_eval.py --stub` (baseline) vs
  `--backend api` shows precision or severity-agreement dropping below the SLO
  (see [operations.md](../operations.md#slos--slis)).
- A spike in ticket volume vs the historical per-run average in `TRACKER.md`.
- Owners reporting a flood of low-quality tickets.

**Contain**
- Flip runs to `--dry-run` and/or disable `triage.yml` (kill switch above).

**Eradicate (find the cause)**
- Did the **model** change? Check `AUTOTRIAGE_MODEL` / `--model` against the
  last known-good pin.
- Did the **prompt** change? Diff `src/autotriage/prompts.py`.
- Did the **threshold** change? Confirm `AUTOTRIAGE_CONFIDENCE_THRESHOLD` (or the
  `GUARDRAIL_CONFIDENCE_THRESHOLD` constant) is still `0.6` (or your intended
  value). A too-low threshold lets shaky verdicts through.
- Reproduce on the labeled set: `python evals/run_eval.py --backend api` and
  read `evals/report.md` for the confusion matrix and per-finding misses.

**Recover**
- Revert the offending change per [rollback.md](rollback.md) (pin model + prompt
  + package versions).
- Delete or close the bad tickets/PRs (they live under `tickets/` and
  `pull_requests/`; the ledger row stays in `TRACKER.md` as an audit trail —
  annotate rather than rewrite history).
- Raise the confidence threshold temporarily to bias toward escalation while you
  investigate.

---

## Incident 2 — Anthropic API outage / auth failure

Live triage fails: `401`, `429`, connection errors, or timeouts.

**Detect**
- `RuntimeError: ANTHROPIC_API_KEY is not set` → missing/rotated key.
- HTTP `401` → invalid key. `429` → rate limit. `5xx` / timeouts → provider
  degradation.
- `triage_all` prints `[triage] <id>: <ExceptionType>: ...; escalating` to
  stderr for each affected finding.

**Contain**
- The system already fails closed: each un-triageable finding becomes a
  `needs_human` / `escalate` decision at `confidence = 0.0`. No wrong
  auto-actions occur during an outage.
- Pause **scheduled/batch** runs so you are not burning retries; PR-gate runs
  can keep escalating harmlessly, but consider disabling to reduce noise.

**Eradicate**
- Auth: rotate/re-set `ANTHROPIC_API_KEY` (env locally; repo secret in CI).
- Rate limit: reduce batch size / concurrency, back off, retry later.
- Provider outage: check provider status; wait it out. Triage is safe to defer —
  findings remain in `findings.json`.

**Recover**
- Re-run triage over the same `findings.json` once the provider is healthy. The
  finding ids are deterministic content hashes, so re-runs are idempotent for
  dedup and the eval harness.

---

## Incident 3 — Runaway cost / token spend

Spend is climbing unexpectedly.

**Detect**
- Anthropic usage dashboard shows a spike.
- An unusually large `findings.json` (e.g. a scanner matched a vendored/`node_modules`
  tree) → one LLM call per finding multiplies fast.

**Contain**
- Kill the in-flight run. Disable scheduled runs.

**Eradicate**
- Cap the blast radius: lower `AUTOTRIAGE_MAX_TOKENS`, and scan a **scoped**
  target path rather than the whole repo.
- Trim `findings.json` (scan narrower directories; exclude vendored code) before
  re-triaging. Cost scales with the number of findings — one Messages API call
  per finding.
- Confirm you are not accidentally on a more expensive model via `--model` /
  `AUTOTRIAGE_MODEL`.

**Recover**
- Re-run on the scoped input. Track cost/finding as an SLI
  ([operations.md](../operations.md#cost-management)).

---

## Incident 4 — A wrong auto-action (bad ticket, PR, or owner)

The agent took a side effect that should not have happened.

**Detect**
- A merged/opened remediation PR that is wrong, or a ticket routed to the wrong
  owner. Note: today AutoTriage **drafts** PRs as Markdown files under
  `pull_requests/`; it does not open real GitHub PRs, and `CRITICAL` findings
  require human sign-off before any remediation is merged
  (see [escalation-policy.md](../escalation-policy.md)).

**Contain**
- Stop further runs (kill switch).

**Eradicate**
- Trace the decision: find the row in `TRACKER.md` (timestamp, finding id,
  verdict, confidence, action, owner) and the matching `tickets/<id>.md`, which
  records the model's `reasoning` and `business_impact`.
- Determine whether it was a bad **verdict** (agent error), a bad **owner**
  (CODEOWNERS mismatch — check `--codeowners` path and patterns), or a config
  drift (wrong threshold/model).

**Recover**
- Close/delete the bad ticket and PR draft; reassign the owner.
- If owner routing is systematically wrong, fix `.github/CODEOWNERS` (or whatever
  `AUTOTRIAGE_CODEOWNERS` points at) and re-run — owner assignment is
  deterministic.
- If the verdict was the problem, follow Incident 1's eradication steps.

---

## Communications

For SEV1/SEV2:

1. Open an incident channel; post a one-line summary + current impact + kill
   status ("triage is in `--dry-run`, no new side effects since HH:MM").
2. Notify affected code owners if bad tickets/PRs reached them.
3. Post updates on containment, cause, and ETA to recovery.
4. On resolution, post the all-clear and link the post-incident review.

Keep the language honest and blameless. The `TRACKER.md` ledger + per-ticket
reasoning is your source of truth for the timeline.

---

## Post-incident review

Within a few working days, write a blameless PIR covering:

- **Timeline** — detection → containment → recovery (pull timestamps from
  `TRACKER.md`).
- **Impact** — how many wrong tickets/PRs/verdicts; which owners; any cost blow.
- **Root cause** — model/prompt/threshold/config/provider.
- **What worked** — did we fail closed as designed? did the guardrail hold?
- **Action items** — e.g. add an eval case that would have caught it, pin the
  model, add a cost/volume alert (see
  [operations.md](../operations.md#alerting-thresholds)).
- **Changelog** — record any fix in [CHANGELOG.md](../../CHANGELOG.md).

Feeding the failing case back into `evals/labeled_findings.json` so the eval
harness catches a regression next time is the single highest-value follow-up.
