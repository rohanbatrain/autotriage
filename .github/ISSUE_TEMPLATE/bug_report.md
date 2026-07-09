---
name: Bug report
about: Report something that isn't working as expected
title: "bug: <short description>"
labels: ["bug", "triage"]
assignees: []
---

<!-- Before filing, please check docs/runbooks/troubleshooting.md — many issues
     (missing scanner binary, no API key, empty findings) are covered there. -->

## What happened

<!-- A clear description of the bug and what you expected instead. -->

## Steps to reproduce

1.
2.
3.

**Exact command:**

```bash
python -m autotriage --findings ... --backend ...
```

## Expected behavior

<!-- What you expected to happen. -->

## Output / logs

<!-- Paste the run summary, any warnings, and the error/traceback. Redact secrets. -->

```
```

## Environment

- AutoTriage version / commit:
- Python version (`python --version`):
- OS:
- Backend: `api` / `sdk` / n/a (`--dry-run`)
- Model (`AUTOTRIAGE_MODEL` / `--model`):
- Scanner versions (`semgrep --version`, `trivy --version`, `gitleaks version`), if relevant:

## Additional context

<!-- Anything else that helps. A minimal findings.json that reproduces it is ideal. -->
