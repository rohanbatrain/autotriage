# [MEDIUM] Flask 0.12.2 denial of service via crafted JSON

- **Finding ID:** sca-flask-010
- **Scanner:** trivy (SCA)
- **Rule:** CVE-2018-1000656
- **Location:** `target/requirements.txt:3`
- **CWE:** CWE-400
- **Verdict:** true_positive
- **Severity:** medium
- **Confidence:** 0.85
- **Recommended action:** open_ticket
- **Owner:** platform-backend-team

## Business impact
A vulnerable Flask version could allow an attacker to crash the application via a crafted request, causing service disruption to payment-related APIs.

## Reasoning
CVE-2018-1000656 is a confirmed DoS vulnerability in Flask <=0.12.2 triggered by malformed JSON or large request headers causing unbounded memory/CPU consumption. The finding is deterministic: installed_version 0.12.2 matches the vulnerable range and fixed_version 0.12.3 remediates it. This is DoS-only (no RCE, no data exposure), so impact is limited to availability rather than confidentiality/integrity of cardholder or payment data, keeping severity at medium rather than high/critical. However, since this affects an internet-facing web framework potentially used in payment services, it should still be remediated promptly. No indication this is a test/dev-only dependency path (target/requirements.txt suggests a build artifact, but the package is still shipped/installed).

## Remediation
Upgrade Flask to >=0.12.3 (or later supported LTS version) in requirements.txt and regenerate lockfiles/build artifacts; run regression tests to confirm compatibility.

## Offending code
```
Flask==0.12.2
```
