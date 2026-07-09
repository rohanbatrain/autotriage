# AutoTriage Vulnerable Target (Test Fixture)

**This is an INTENTIONALLY VULNERABLE sample application. DO NOT DEPLOY.**

Every file in `target/` contains deliberately planted security weaknesses so
that real scanners (Semgrep, Trivy, Gitleaks) produce findings that the
AutoTriage triage agent can be exercised and evaluated against. Nothing here
is production code, none of the credentials are real, and the infrastructure
must never be applied.

## What is planted

`app.py` (Flask):

| Vulnerability | CWE | Approx. line |
| --- | --- | --- |
| SQL injection via f-string | CWE-89 | 44 |
| Hardcoded AWS access key id | CWE-798 | 18 |
| OS command injection via `os.system` | CWE-78 | 57 |
| `eval()` on request data | CWE-95 | 63 |
| MD5 used for password hashing | CWE-327 | 71 |
| `pickle.loads` on request body | CWE-502 | 78 |
| Flask `app.run(debug=True)` | CWE-489 | 92 |

It also includes two **benign** lines that scanners tend to false-positive on:
a static `EXAMPLE_QUERY` constant (~line 103) and a reference to AWS's public
documentation placeholder key `AKIAIOSFODNN7EXAMPLE` in a comment (~line 110).

`requirements.txt`: pinned to known-vulnerable versions (`requests==2.19.1`,
`PyYAML==5.1`, `Flask==0.12.2`).

`infra/main.tf`: a public-read S3 bucket with no server-side encryption and a
security group exposing SSH (port 22) to `0.0.0.0/0`.

## Why it exists

The AutoTriage agent ingests scanner output for this target and produces
structured triage decisions. The fixture lets the pipeline and its evaluation
harness run end-to-end against a known, stable set of findings.

**Reminder: DO NOT DEPLOY. For AutoTriage testing only.**
