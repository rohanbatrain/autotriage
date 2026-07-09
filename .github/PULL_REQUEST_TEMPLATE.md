<!-- Thanks for contributing to AutoTriage! Please fill this out. -->

## Summary

<!-- What does this PR change and why? Link any related issue: Closes #123 -->

## Type of change

<!-- Match your Conventional Commit type. Check all that apply. -->

- [ ] `feat` — new feature
- [ ] `fix` — bug fix
- [ ] `docs` — documentation only
- [ ] `refactor` / `perf` — no behavior change / performance
- [ ] `test` — tests only
- [ ] `build` / `ci` / `chore` — tooling, deps, pipelines
- [ ] Breaking change (`!` / `BREAKING CHANGE:`)

## Triage-behavior impact

<!-- Required if you touched the prompt, model default, threshold, scanners, or
     schema. Otherwise write "none". -->

- [ ] This PR changes triage behavior. Eval impact (paste `python evals/run_eval.py` output):

```
precision=... recall=... f1=... accuracy=... severity_agreement=...
```

## Quality gate

<!-- Run the same checks CI runs. See CONTRIBUTING.md. -->

- [ ] `ruff check .` passes
- [ ] `ruff format --check .` passes
- [ ] `mypy src` passes (`--strict`)
- [ ] `pytest` passes and coverage is **≥ 80%**
- [ ] `bandit -r src` clean (or justified)
- [ ] `pip-audit` clean (or justified)

## Docs & changelog

- [ ] Docs updated (README / `docs/**`) if behavior or config changed
- [ ] [CHANGELOG.md](../CHANGELOG.md) updated under **Unreleased**
- [ ] Conventional Commit messages used

## Reviewer notes

<!-- Anything reviewers should focus on, risks, or follow-ups. -->
