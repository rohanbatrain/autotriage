# Security Posture

This document describes how **AutoTriage itself** is kept secure — as opposed to
the [threat model](threat-model.md), which covers the security of the agent's
*runtime behavior*. It reflects the repository's actual configuration; planned
hardening is marked **Roadmap**.

## 1. Secrets management

- **`ANTHROPIC_API_KEY` is read only from the environment** (`autotriage.agent`
  calls `os.environ.get`), never hardcoded, never committed, and never logged by
  AutoTriage.
- The core package (schema / scanners / eval) imports and runs **without** any
  API key; the key is required only for live triage.
- In CI, the key is injected via `secrets.ANTHROPIC_API_KEY` (see
  `.github/workflows/triage.yml`) and is never echoed.
- The **`detect-private-key`** pre-commit hook (`.pre-commit-config.yaml`) blocks
  accidental commits of private keys.
- If a key is ever exposed, rotate it in the Anthropic console and update the
  environment / CI secret; see [SECURITY.md](../SECURITY.md).

## 2. Least privilege

- **The action layer (`autotriage.tools`) is pure, offline, and file-based.** It
  writes tickets, a `TRACKER.md` ledger, and PR *drafts* — it does not execute
  code, open network connections, or merge anything.
- **Scanner subprocesses use fixed argument vectors, never `shell=True`**, so
  finding content or paths cannot be interpreted as shell commands. Every
  invocation carries a 600-second timeout.
- **No auto-merge.** Even for critical findings the agent drafts a fix; a human
  reviews and merges (see [escalation-policy.md](escalation-policy.md)).
- The network surface is limited to the Claude backend and the scanner binaries;
  the core install pulls only `pydantic` / `pydantic-settings`, and the LLM
  runtimes live in the optional `agent` extra.

## 3. Self security-scanning

The project scans its own source and dependencies:

- **Bandit** is configured in `pyproject.toml` (`[tool.bandit]`): it excludes the
  intentionally-vulnerable `target/` fixture and the tests, and documents the
  three subprocess-related skips (`B404`, `B603`, `B607`) with the justification
  that the scanner adapters use fixed argv lists and never `shell=True`. `bandit`
  is a declared dev dependency.
- **pip-audit** is a declared dev dependency (`[project.optional-dependencies].dev`)
  for auditing the dependency tree against known CVEs.
- **Static & security quality gates run in CI** (`.github/workflows/ci.yml`) on a
  Python 3.11/3.12 matrix: `ruff check` (lint incl. security-relevant Bugbear/`B`
  rules), `ruff format --check`, `mypy --strict` on `src`, `pytest` with branch
  coverage enforced at `--cov-fail-under=80`, `bandit -r src` (self security
  scan), and `pip-audit` (dependency CVE audit, informational). Strict typing and
  the Pydantic contracts eliminate whole classes of data-handling bugs.

> **Roadmap:** scanner-binary version pinning in CI and signed-provenance checks
> on the scanner supply chain are planned hardening.

## 4. Dependency management

- Dependencies are declared in `pyproject.toml` with **minimum-version floors**
  (`pydantic>=2.6`, `anthropic>=0.40.0`, `claude-agent-sdk>=0.1.0`, etc.).
- The runtime footprint is deliberately small; heavy LLM runtimes are optional
  extras and are **imported lazily**, so a minimal install has a minimal
  dependency and attack surface.
- Pre-commit pins hook versions (`.pre-commit-config.yaml`) so local and CI checks
  match.
- **Roadmap:** pinned/locked dependency versions and automated dependency-update
  review; scanner-binary checksum/signature verification in CI.

## 5. The intentionally-vulnerable fixture — disclaimer

The `target/` directory is a **deliberately insecure Flask app and Terraform
config used as a test fixture** so that real scanners produce real findings. Its
module docstring states plainly: *"Every weakness below is planted on purpose …
This is NOT production code — DO NOT DEPLOY."*

Consequently:

- **All credentials in `target/` and in the fixtures are fake.** The AWS access
  key `AKIA4TQ7NREALKEY1234` in `target/app.py` is a bait string, not a live
  credential; the false-positive fixture deliberately uses AWS's public
  documentation placeholder `AKIAIOSFODNN7EXAMPLE`. Neither grants access to
  anything.
- `target/` is **excluded from linting, type-checking, Bandit, and coverage** so
  its intentional vulnerabilities do not pollute the project's own quality gates.
- The fixture exists solely to demonstrate and evaluate the pipeline; it must
  never be deployed or copied into real infrastructure.

## 6. Reporting a vulnerability

Coordinated disclosure, supported versions, and response SLAs are documented in
the repository-root [SECURITY.md](../SECURITY.md).
