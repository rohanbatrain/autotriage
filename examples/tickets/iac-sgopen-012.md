# [HIGH] Security group allows SSH from 0.0.0.0/0

- **Finding ID:** iac-sgopen-012
- **Scanner:** trivy (IAC)
- **Rule:** AVD-AWS-0107
- **Location:** `target/infra/main.tf:21`
- **CWE:** CWE-284
- **Verdict:** true_positive
- **Severity:** high
- **Confidence:** 0.85
- **Recommended action:** draft_pr
- **Owner:** cloud-infra-security

## Business impact
An open SSH port to the entire internet materially increases the risk of unauthorized access to production infrastructure hosting payments systems.

## Reasoning
The Terraform security group rule explicitly allows inbound TCP/22 from 0.0.0.0/0, which is a well-known high-risk misconfiguration (AVD-AWS-0107) enabling brute-force or credential-stuffing attacks against SSH from any internet host. Exploitability requires only network reachability plus valid or weak credentials/key exposure, and successful access could lead to full host compromise, which is severe given this is infrastructure for a payments company (potential pivot to cardholder data environment). This is not high enough to be 'critical' by itself since it requires additional compromise (valid creds/key) to achieve RCE-level impact, but it is a serious, directly exploitable network exposure that should be fixed. No evidence of compensating controls (e.g., bastion-only access, VPN restriction) is present in the snippet, and no indication this is test/example code — path is under infra/main.tf suggesting real deployment config.

## Remediation
Restrict the security group ingress rule for port 22 to specific known IP ranges (corporate VPN/bastion CIDR) instead of 0.0.0.0/0. Consider replacing direct SSH access with AWS Systems Manager Session Manager or a bastion host with MFA, and enforce this via a policy-as-code check (e.g., tfsec/Trivy in CI) to prevent regression.

## Offending code
```
cidr_blocks = ["0.0.0.0/0"]
```
