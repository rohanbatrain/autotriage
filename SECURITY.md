# Security Policy

AutoTriage is an autonomous vulnerability-triage and remediation agent. Because it
ingests attacker-influenceable scanner output and takes actions, we take the
security of the tool itself seriously and welcome coordinated disclosure.

This file is the **coordinated vulnerability disclosure (CVD)** policy for the
project. For how the tool is engineered to be secure, see
[docs/security-posture.md](docs/security-posture.md); for its runtime threat model,
see [docs/threat-model.md](docs/threat-model.md).

## Supported versions

AutoTriage is pre-1.0 (`0.1.0`). Security fixes are applied to the latest release
and the `main` branch only.

| Version | Supported |
| --- | --- |
| `0.1.x` (latest) | ✅ |
| `main` (unreleased) | ✅ |
| Older / forks | ❌ |

We recommend always running the latest release.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through either channel:

1. **GitHub private vulnerability reporting** (preferred) — open a report via the
   **Security → Report a vulnerability** tab of
   <https://github.com/rohanbatrain/autotriage>. This creates a private advisory
   visible only to maintainers.
2. **Email** — <tdsworks@gmail.com> with the subject line
   `AutoTriage security report`.

Please include, where possible:

- affected version / commit and environment (OS, Python version, backend used);
- a description of the issue and its impact;
- reproduction steps or a proof of concept;
- any suggested remediation.

If you need to send sensitive material, ask in your first message and we will
arrange an encrypted channel. Do not include real third-party credentials in a
report.

## Response SLAs

| Stage | Target |
| --- | --- |
| Acknowledge receipt | within **3 business days** |
| Initial assessment & severity triage | within **7 business days** |
| Fix or mitigation plan for confirmed reports | within **30 days** (sooner for critical) |
| Public disclosure / advisory | coordinated with the reporter, typically after a fix ships |

We will keep you informed of progress and credit you in the advisory unless you
prefer to remain anonymous.

## Disclosure policy

- We follow **coordinated disclosure**: please give us a reasonable window to ship
  a fix before any public disclosure.
- Once a fix is available, we publish a GitHub Security Advisory describing the
  issue, affected versions, and remediation.
- We support **safe-harbor** for good-faith research: testing that respects this
  policy, avoids privacy violations and service disruption, and uses only accounts
  and data you own will not be pursued as a policy violation.

## Scope

**In scope** — the AutoTriage codebase (`src/autotriage/`), its CLI, the scanner
adapters, the two Claude backends, the action/artifact layer, the evaluation
harness, and the CI/pre-commit configuration.

**Out of scope:**

- The intentionally-vulnerable test fixture under `target/` and the sample
  `fixtures/` — every weakness and credential there is **planted on purpose** and
  fake by design (see [docs/security-posture.md](docs/security-posture.md)).
  Findings against `target/` are expected, not vulnerabilities in AutoTriage.
- Vulnerabilities in third-party dependencies or the scanner binaries themselves
  (Semgrep, Trivy, Gitleaks) — please report those upstream; we will still act on
  reports that show AutoTriage using a dependency unsafely.
- Vulnerabilities in the Anthropic Claude service.
- Findings that require a compromised host, physical access, or social
  engineering of maintainers.

## A note on model behavior

Reports that AutoTriage can be induced — via crafted scanner output or prompt
injection — to produce an unsafe verdict or take an unsafe action are **in scope**
and of particular interest. When reporting, please include the finding content
used and the observed behavior. Note that the confidence guardrail and the
human-in-the-loop for escalations and PR merges are the intended backstops; a
report is strongest if it demonstrates a bypass of those controls.

---

_Thank you for helping keep AutoTriage and its users safe._
