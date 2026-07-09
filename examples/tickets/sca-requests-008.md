# [HIGH] requests 2.19.1 leaks Authorization header on redirect

- **Finding ID:** sca-requests-008
- **Scanner:** trivy (SCA)
- **Rule:** CVE-2018-18074
- **Location:** `target/requirements.txt:1`
- **CWE:** CWE-200
- **Verdict:** true_positive
- **Severity:** high
- **Confidence:** 0.85
- **Recommended action:** draft_pr
- **Owner:** platform-security / backend-dependencies-team

## Business impact
A vulnerable HTTP library could leak Authorization headers (e.g., API keys/tokens) to third-party hosts during cross-domain redirects, risking exposure of credentials used to access payment/partner APIs.

## Reasoning
CVE-2018-18074 affects requests <2.20.0 where the library fails to strip the Authorization header when following a redirect to a different host, leading to credential/token leakage (CWE-200). This is a well-known, easily triggerable issue whenever the app makes outbound HTTP requests with auth headers and follows redirects (default behavior). Given this is a payments company likely making authenticated calls to internal/external APIs (banking, KYC, card processors), leakage of bearer tokens or API keys to an unintended host is a meaningful confidentiality risk. Exploitability requires an attacker-controlled or malicious redirect target, which is a modest precondition, and impact is sensitive-data exposure rather than direct RCE, so I rate this high rather than critical. Fix is a straightforward version bump with no expected breaking changes for typical usage.

## Remediation
Upgrade requests to >=2.20.0 (latest stable recommended) in requirements.txt/lockfile and re-run dependency resolution; verify no code relies on old redirect-header-forwarding behavior.

## Offending code
```
requests==2.19.1
```
