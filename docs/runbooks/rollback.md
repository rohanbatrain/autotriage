# Runbook: rollback

**Audience:** on-call operator reverting a bad AutoTriage release, model change,
or prompt change.
**Principle:** roll back to a **known-good, pinned** combination of *package
version + model id + prompt*. Any one of the three can regress triage quality.

Use this after containment (see
[incident-response.md](incident-response.md#the-kill-switch-memorize-this)).

---

## What can regress, and how to pin it

AutoTriage's behavior is a function of three things. Pin all three for a
reproducible rollback:

| Layer | Where it lives | How to pin |
|---|---|---|
| **Package version** | `pyproject.toml` `version`, installed wheel | Install a specific tag/commit (below) |
| **Model id** | `AUTOTRIAGE_MODEL` env / `--model` flag / `DEFAULT_MODEL` | Set the env/flag to the last known-good id |
| **Prompt** | `src/autotriage/prompts.py` (`SYSTEM_PROMPT`) | Revert to the last known-good commit |

The confidence threshold (`AUTOTRIAGE_CONFIDENCE_THRESHOLD` / the
`GUARDRAIL_CONFIDENCE_THRESHOLD` constant, default `0.6`) is a fourth lever —
raising it biases toward escalation and is a safe *mitigation* while you roll
back.

---

## 1. Roll back a model change

A model swap is the cheapest thing to revert and needs **no** redeploy:

```bash
# Pin explicitly for one run:
python -m autotriage --findings findings.json --model claude-sonnet-5

# Or pin for the environment / CI:
export AUTOTRIAGE_MODEL=claude-sonnet-5
```

In CI, set `AUTOTRIAGE_MODEL` as a repository/environment variable so every run
uses the pinned id until you deliberately bump it.

**Always pin an explicit model id in production.** Relying on an alias that
floats to a newer model is how a "silent" model change regresses triage.

**Verify the rollback** against the labeled set before trusting it:

```bash
python evals/run_eval.py --backend api
# check evals/report.md: precision / recall / severity_agreement back to baseline?
```

---

## 2. Roll back a package / prompt release

AutoTriage is a Python package installed from source. To return to a known-good
release:

```bash
# By tag (recommended — tags follow the CHANGELOG):
pip install "autotriage @ git+https://github.com/rohanbatrain/autotriage@v0.1.0"

# By commit SHA (when you need an exact point):
pip install "autotriage @ git+https://github.com/rohanbatrain/autotriage@<good-sha>"
```

For a local checkout, revert the working tree to the good tag/commit and
reinstall editable:

```bash
git checkout v0.1.0
pip install -e ".[agent,dev]"
```

If only the **prompt** regressed, you can revert just that file to the good
revision rather than the whole package, then re-run the eval to confirm.

---

## 3. Pin package + scanner versions for reproducibility

Two classes of dependency affect output:

- **Python deps** — pin in `pyproject.toml` (owned by another workstream; do not
  edit here) or, for a deployment, freeze a lockfile:

  ```bash
  pip freeze > constraints.txt
  pip install -e ".[agent]" -c constraints.txt
  ```

- **Scanner binaries** — Semgrep/Trivy/Gitleaks versions change *findings*, which
  changes what the agent triages. Pin them in the environment/container:
  - Semgrep: `pip install semgrep==<version>`.
  - Trivy: pin the `aquasecurity/setup-trivy` action version / the installed
    binary.
  - Gitleaks: pin the release downloaded by the install script.

Record the pinned quartet — **package + model + prompt commit + scanner
versions** — in the incident's post-mortem so the recovery is reproducible.

---

## 4. Clean up artifacts written by the bad release

Rolling back code does **not** retract artifacts already written:

- `tickets/` and `pull_requests/` — close/delete the bad drafts.
- `TRACKER.md` — append-only audit log. **Do not rewrite history**; annotate the
  affected rows (e.g. add a note row) so the timeline stays intact for the PIR.

Because finding ids are deterministic content hashes, **re-running the good
version over the same `findings.json` is idempotent** for dedup — it will not
double-file the same finding id in the tracker's dedup logic, and the eval
harness matches on id.

---

## 5. Post-rollback checklist

- [ ] Model pinned to a known-good explicit id (`AUTOTRIAGE_MODEL` / `--model`).
- [ ] Package/prompt at a known-good tag or SHA.
- [ ] Scanner versions pinned.
- [ ] Eval re-run: precision / recall / severity-agreement at or above SLO
      ([operations.md](../operations.md#slos--slis)).
- [ ] Smoke test green:
      `python -m autotriage --findings fixtures/findings.sample.json --dry-run`.
- [ ] Kill switch lifted (`--dry-run` removed / `triage.yml` re-enabled) only
      after the two checks above pass.
- [ ] Rollback recorded in [CHANGELOG.md](../../CHANGELOG.md) and the PIR.

---

## Rollout note (forward direction)

When rolling **forward** again (new model, prompt, or release), de-risk it the
same way you verified the rollback:

1. Run the eval on the candidate (`--backend api`) and compare `evals/report.md`
   to the baseline. Gate on no regression in precision / severity-agreement.
2. Roll out to `--dry-run` first (report-only), inspect the summary and a few
   tickets, then enable actions.
3. Keep the previous pin handy so this runbook is a one-command revert.
