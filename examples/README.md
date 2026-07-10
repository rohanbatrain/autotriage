# Example output

These are **real artifacts** produced by AutoTriage, committed so reviewers can
see the output without running the pipeline.

| Path | What it is |
| --- | --- |
| `tickets/` | Triage tickets auto-filed for true-positive findings (severity, business impact, reasoning, owner, remediation). |
| `prs/` | Auto-drafted remediation PRs for mechanically-fixable findings. |
| `TRACKER.md` | The rolling tracker the agent appends to as it triages. |
| `report.md` | Evaluation report scoring the agent's triage against the labeled ground-truth set. |
| `real-scan.findings.json` | Raw output of a **live** Semgrep + Trivy + Gitleaks scan of `target/` (44 findings), normalized into the `Finding` contract. |
| `fix-validation/` | A **live** run of the fix-validation loop: proposed fixes applied to an isolated copy of `target/` and re-scanned with Trivy to prove each finding is actually gone. |

## How they were generated

```bash
# Clean demo tickets + PRs from the curated fixture (aligns with the eval set)
python -m autotriage --findings fixtures/findings.sample.json \
    --tickets-dir examples/tickets --tracker examples/TRACKER.md --pr-dir examples/prs

# Genuine accuracy metrics from a live API run
python evals/run_eval.py --report examples/report.md

# The real end-to-end scan of the bundled vulnerable target
python -m autotriage.scanners target -o examples/real-scan.findings.json

# The fix-validation loop: apply each patch to an isolated copy and re-scan
python -m autotriage.revalidate --target target \
    --findings examples/fix-validation/findings.json \
    --patches examples/fix-validation/patches.json \
    --report examples/fix-validation/report.md
```

On the labeled 15-finding set the agent scored **100% verdict accuracy** (both
planted false positives correctly suppressed). On a live scan of `target/` it
triaged **44 raw findings into 24 tickets and 20 human-escalations**.

### The `fix-validation/` example

`report.md` there is a real Trivy re-scan of three proposed fixes:

- the world-open SSH security group and the public-read S3 ACL are **confirmed
  resolved** — after the patch, the finding no longer fires and no new finding
  was introduced;
- the third row is **intentionally `unresolved`**: a "fix" that only adds a
  comment (instead of a real `description` argument) is correctly rejected by
  the re-scan. That negative case is the point — the loop trusts a fix only when
  the scanner agrees the vulnerability is gone, so it fails closed on anything
  else (the run exits non-zero when not every fix is resolved).
