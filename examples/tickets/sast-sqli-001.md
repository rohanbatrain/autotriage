# [CRITICAL] SQL injection via f-string in query

- **Finding ID:** sast-sqli-001
- **Scanner:** semgrep (SAST)
- **Rule:** python.lang.security.audit.formatted-sql-query.formatted-sql-query
- **Location:** `target/app.py:44`
- **CWE:** CWE-89
- **Verdict:** true_positive
- **Severity:** critical
- **Confidence:** 0.93
- **Recommended action:** open_ticket
- **Owner:** backend-app-team

## Business impact
Attackers could read, modify, or exfiltrate user/customer account data (including potentially PII tied to payments) via unauthenticated or authenticated SQL injection, risking data breach and PCI-DSS/compliance violations.

## Reasoning
The code directly interpolates a variable (username) into a SQL query string via an f-string and executes it with cursor.execute(), with no parameterization or sanitization visible. This is a textbook classic SQL injection pattern (CWE-89) that Semgrep correctly flags as an error-level finding. If `username` originates from any user-controlled input (login, search, profile lookup, etc.), an attacker can manipulate the query to bypass authentication, exfiltrate arbitrary rows, or enumerate the users table. Given this is a payments company codebase where the `users` table likely ties to account/financial data, exploitability is trivial (no special preconditions) and impact is severe, warranting critical severity. The fix is deterministic and mechanical (switch to parameterized queries), so this is a clear draft_pr candidate rather than requiring a design discussion.

## Remediation
Replace the f-string interpolation with a parameterized query, e.g. cursor.execute("SELECT * FROM users WHERE name = %s", (username,)) (or using the appropriate DB-API placeholder syntax). Audit surrounding code for the same anti-pattern in other queries and add a Semgrep CI gate to block merges on this rule going forward.

## Offending code
```
cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
```
