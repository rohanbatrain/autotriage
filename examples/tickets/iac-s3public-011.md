# [HIGH] S3 bucket allows public read ACL

- **Finding ID:** iac-s3public-011
- **Scanner:** trivy (IAC)
- **Rule:** AVD-AWS-0086
- **Location:** `target/infra/main.tf:6`
- **CWE:** CWE-732
- **Verdict:** true_positive
- **Severity:** high
- **Confidence:** 0.85
- **Recommended action:** open_ticket
- **Owner:** cloud-infra-security

## Business impact
A misconfigured S3 bucket could expose stored files (potentially including customer, transaction, or KYC documents) to anyone on the internet, risking data breach and PCI/regulatory violations.

## Reasoning
The Terraform code explicitly sets acl = "public-read" on an S3 bucket, which is a well-known, high-confidence IaC misconfiguration (AVD-AWS-0086) that grants anonymous read access to all objects in the bucket. Unless this bucket is verified to hold only intentionally public, non-sensitive static assets (e.g., public website assets), this is a clear violation of least-privilege and data protection best practices, especially concerning for a payments company handling cardholder data, PII, and KYC documents. There is no evidence in the snippet of scoping/exception (e.g., a public static-assets bucket) so I treat it as a real, actionable finding, though I'd want confirmation of the bucket's actual content/purpose before ruling out that it's a legitimate public-assets bucket. The fix is deterministic (remove public ACL, enable Block Public Access, use private ACL + CloudFront/OAI if public access to specific assets is truly needed), so this is a good draft_pr candidate rather than requiring extensive human design discussion — though I'll flag it as open_ticket since infra changes to S3 ACL/bucket policy typically need review/rollout coordination (e.g., verifying no legitimate consumers rely on public access) before merging.

## Remediation
Remove acl = "public-read"; set to "private". Enable S3 Block Public Access (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets = true) at the bucket and account level. If public access to specific assets is required, serve via CloudFront with Origin Access Control/Identity instead of a public bucket ACL. Audit current bucket contents for any sensitive data before remediation and add automated policy checks (e.g., tfsec/Trivy in CI) to prevent regressions.

## Offending code
```
acl = "public-read"
```
