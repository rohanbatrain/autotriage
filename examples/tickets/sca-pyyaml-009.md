# [HIGH] PyYAML 5.1 arbitrary code execution via full_load

- **Finding ID:** sca-pyyaml-009
- **Scanner:** trivy (SCA)
- **Rule:** CVE-2020-1747
- **Location:** `target/requirements.txt:2`
- **CWE:** CWE-502
- **Verdict:** true_positive
- **Severity:** high
- **Confidence:** 0.75
- **Recommended action:** draft_pr
- **Owner:** platform-security / backend-dependencies-team

## Business impact
A vulnerable YAML parsing library could allow attacker-controlled YAML input to execute arbitrary code on servers handling payment/application logic, risking full host compromise.

## Reasoning
CVE-2020-1747 is a known, well-documented deserialization vulnerability in PyYAML versions before 5.3.1, where FullLoader (and even some other loader paths due to a flaw) can be tricked into instantiating arbitrary Python objects, leading to code execution. Installed version 5.1 is confirmed vulnerable, and a fixed version 5.3.1 is available, making this a deterministic dependency bump. I rate this high rather than critical because exploitability depends on whether the application actually parses untrusted/attacker-supplied YAML using yaml.load/FullLoad without safe_load — this is common but not verified from the finding alone (no code path shown ingesting external YAML). Given this is a payments company where any RCE-capable library is a serious concern, and the fix is trivial, this should be remediated promptly. Confidence is moderate-high because the CVE and version match are unambiguous, but exact reachability/exploitability in this codebase isn't confirmed here.

## Remediation
Upgrade PyYAML to >=5.3.1 (or latest maintained release) in requirements.txt; ensure code uses yaml.safe_load or SafeLoader for any untrusted input regardless of library version as defense-in-depth.

## Offending code
```
PyYAML==5.1
```
