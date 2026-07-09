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

## How they were generated

```bash
# Clean demo tickets + PRs from the curated fixture (aligns with the eval set)
python -m autotriage --findings fixtures/findings.sample.json \
    --tickets-dir examples/tickets --tracker examples/TRACKER.md --pr-dir examples/prs

# Genuine accuracy metrics from a live API run
python evals/run_eval.py --report examples/report.md

# The real end-to-end scan of the bundled vulnerable target
python -m autotriage.scanners target -o examples/real-scan.findings.json
```

On the labeled 15-finding set the agent scored **100% verdict accuracy** (both
planted false positives correctly suppressed). On a live scan of `target/` it
triaged **44 raw findings into 24 tickets and 20 human-escalations**.
