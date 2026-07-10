# Fix-validation loop

> Module: [`autotriage.revalidate`](../src/autotriage/revalidate.py) ·
> Contracts: `FixPatch`, `FileEdit`, `FixValidation`, `ValidationStatus` in
> [`autotriage.schema`](../src/autotriage/schema.py) ·
> Live example: [`examples/fix-validation/`](../examples/fix-validation/)

## Why this exists

Triage tells you *what* to fix. A remediation agent can also propose *how*. But a
proposed fix is a **claim**, not a fact — the model can hallucinate a change that
doesn't compile, doesn't remove the vulnerability, or quietly introduces a new
one. Trusting that claim is exactly the failure mode a security tool cannot
afford.

The fix-validation loop closes the gap: it **applies the fix and re-runs the
scanner**, so AutoTriage only ever reports a remediation as done when the tool
that found the bug agrees the bug is gone. It is the same posture as the triage
confidence guardrail — *fail closed* — applied to remediation.

## The loop

```
propose fix ──▶ copy target to an isolated workdir ──▶ baseline re-scan
                                                             │
                          ┌── finding not in baseline ──▶ ERROR (can't verify)
                          │
                     apply patch ──▶ (ambiguous / missing / escapes) ──▶ ERROR
                          │
                     re-scan workdir
                          │
        ┌─────────────────┼───────────────────────────┐
   finding still      finding gone +               finding gone +
     present         new finding(s)                nothing new
        │                 │                              │
   UNRESOLVED         REGRESSED                       RESOLVED  ✅
```

Only `RESOLVED` is trusted. Every other outcome escalates to a human.

## Design decisions

**Signature, not line number.** A finding is matched across the before/after
scans by its *signature* — `(tool, rule_id, file-basename)` — deliberately
**excluding the line number**. A real fix shifts surrounding lines; keying on the
exact line would make a genuinely-fixed finding look like it merely *moved*. The
file is reduced to its basename so the signature is stable no matter which
directory the scanner was invoked from.

**Isolated copy, never the original.** The patch is applied to a throwaway copy
(`shutil.copytree` into a temp dir). The real target is never mutated, so
validation has no side effects and a batch of fixes can't interfere with each
other.

**Exact, unambiguous edits.** A `FixPatch` is a list of `FileEdit`s with
`str_replace` semantics: each `search` string must occur **exactly once** in its
file. Zero matches or more than one both fail the patch closed rather than
guessing where to apply it — the same discipline a careful human editor uses.
Edits are confined to the target tree; a path that escapes it is rejected.

**Baseline reproduction is required.** Before applying anything, the loop
confirms the finding actually fires on the pristine copy. If it doesn't — most
commonly because the relevant scanner isn't installed — the result is `ERROR`,
never a false `RESOLVED`. AutoTriage refuses to claim it fixed something it could
not first observe.

**Regressions are caught.** A fix that removes the target finding but introduces
a *new* signature (present after but not before) is flagged `REGRESSED`, not
`RESOLVED`. A remediation that trades one vulnerability for another is not a fix.

## Where generation vs. verification live

The two halves are deliberately separate:

| Half | Location | Nature |
| --- | --- | --- |
| **Generate** the patch | `autotriage.agent.propose_fix` | LLM call (forced `submit_fix` tool, `FixPatch` schema) |
| **Verify** the patch | `autotriage.revalidate.validate_fix` | Pure, deterministic, offline; re-scan is injected |

Because verification takes the scanner as an injected `RescanFn`, the whole
engine is unit-testable with a deterministic fake scanner — no network, no
binaries — while `make_rescan()` wires in the real scanner layer for live runs.
See [`tests/test_revalidate.py`](../tests/test_revalidate.py) for the full status
matrix (`RESOLVED` / `UNRESOLVED` / `REGRESSED` / `ERROR` / `SKIPPED`, plus the
ambiguous-match and path-traversal guards).

## Running it

```bash
python -m autotriage.revalidate \
    --target target \
    --findings examples/fix-validation/findings.json \
    --patches  examples/fix-validation/patches.json \
    --report   examples/fix-validation/report.md
```

Exit code is `0` only when **every** proposed fix is `RESOLVED`, so the command
doubles as a CI gate on auto-generated remediations. The committed
[example report](../examples/fix-validation/report.md) is a real Trivy run: two
IaC fixes (a world-open SSH security group and a public-read S3 ACL) confirmed
resolved, and one deliberately cosmetic "fix" correctly rejected as
`unresolved`.

## Limits & next steps

- Validation re-runs only the scanner(s) you point it at; narrow to the finding's
  own tool for speed (`make_rescan([ScannerTool.TRIVY])`).
- Patch *generation* is single-file and single-hunk today; multi-file fixes at
  repo scale are future work.
- The natural next step is to **auto-apply** a `RESOLVED` fix as a real pull
  request (rather than a Markdown draft), gated on this loop passing in CI.
