# [CRITICAL] Insecure deserialization via pickle.loads

- **Finding ID:** sast-pickle-006
- **Scanner:** semgrep (SAST)
- **Rule:** python.lang.security.deserialization.pickle.avoid-pickle
- **Location:** `target/app.py:78`
- **CWE:** CWE-502
- **Verdict:** true_positive
- **Severity:** critical
- **Confidence:** 0.95
- **Recommended action:** draft_pr
- **Owner:** backend-platform-security

## Business impact
An attacker could send a crafted HTTP request to achieve remote code execution on the server, potentially compromising payment and customer data.

## Reasoning
The code directly deserializes raw request body bytes via pickle.loads(request.get_data()) with no validation, signing, or allow-listing. Pickle deserialization of untrusted input is a well-known RCE vector (CWE-502) since pickle can invoke arbitrary object constructors/__reduce__ methods during unpickling. Since this reads directly from an HTTP request, it is remotely reachable and trivially exploitable by any client able to reach this endpoint, making it critical in a payments environment where the app likely handles sensitive financial/PII data. There is no indication of a compensating control (e.g., HMAC signature verification prior to unpickling) in the snippet.

## Remediation
Replace pickle.loads with a safe serialization format such as JSON (json.loads) or a schema-validated format (protobuf, msgpack with strict schemas). If pickle must be retained for internal use, ensure it is never fed attacker-controlled data — restrict to trusted, signed payloads only, verified via HMAC before deserialization, and never expose this endpoint to untrusted/external input.

## Offending code
```
data = pickle.loads(request.get_data())
```
