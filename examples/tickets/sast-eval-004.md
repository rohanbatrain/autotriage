# [CRITICAL] Use of eval() on request data

- **Finding ID:** sast-eval-004
- **Scanner:** semgrep (SAST)
- **Rule:** python.lang.security.audit.eval-detected.eval-detected
- **Location:** `target/app.py:63`
- **CWE:** CWE-95
- **Verdict:** true_positive
- **Severity:** critical
- **Confidence:** 0.98
- **Recommended action:** draft_pr
- **Owner:** app-security-eng

## Business impact
Remote attackers can execute arbitrary Python code on the server via a simple HTTP request, potentially compromising payment systems and customer data.

## Reasoning
The code directly passes unsanitized, attacker-controlled query parameter data ('expr') into Python's eval(), which executes arbitrary code with the privileges of the application process. This is a textbook remote code execution vulnerability (CWE-95) reachable from an internet-facing endpoint with no authentication or sanitization shown. In a payments environment, RCE could lead to full system compromise, lateral movement into cardholder data environments, and violation of PCI-DSS requirements. There is no indication this is test/example code isolated from production; the pattern (request.args.get) strongly suggests a live Flask route. This is unambiguously exploitable and high impact, warranting critical severity and immediate remediation.

## Remediation
Remove eval() entirely. Replace with a safe expression evaluator such as Python's ast.literal_eval() if only literals are needed, or a restricted math expression parser (e.g., asteval, numexpr) if arithmetic evaluation is the intended use case. Add strict input validation/allowlisting and ensure no direct execution of user-supplied strings. Add a regression test confirming that malicious payloads (e.g., '__import__("os").system(...)') are rejected.

## Offending code
```
result = eval(request.args.get('expr'))
```
