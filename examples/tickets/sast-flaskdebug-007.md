# [CRITICAL] Flask app run with debug=True

- **Finding ID:** sast-flaskdebug-007
- **Scanner:** semgrep (SAST)
- **Rule:** python.flask.security.audit.debug-enabled.debug-enabled
- **Location:** `target/app.py:92`
- **CWE:** CWE-489
- **Verdict:** true_positive
- **Severity:** critical
- **Confidence:** 0.85
- **Recommended action:** draft_pr
- **Owner:** backend-platform-team

## Business impact
If this configuration reaches production, an attacker could gain remote code execution via the Werkzeug debugger, potentially compromising cardholder/payment systems.

## Reasoning
Flask's debug=True with host='0.0.0.0' binds to all interfaces and enables the interactive Werkzeug debugger, which allows arbitrary Python code execution if the debugger PIN is exposed or brute-forced. This is a well-known critical misconfiguration (CWE-489, OWASP A05:2021) especially dangerous when combined with binding to all network interfaces, indicating it may be internet- or network-reachable. Severity is elevated above the scanner's default WARNING because this is a payments environment where any RCE vector is unacceptable, and host='0.0.0.0' suggests this isn't just local dev usage. However, I flag moderate rather than full confidence since the file path 'target/app.py' could indicate a build/test artifact directory rather than the actual production entrypoint, which would lower real-world risk substantially — this needs confirmation of deployment context.

## Remediation
Set debug=False (or remove the flag, defaulting to False) for any production/deployed configuration. Use environment-variable-driven config (e.g., FLASK_DEBUG) so debug mode is only enabled in local development, and ensure app.run() with debug=True is never invoked when serving real traffic. Consider using a proper WSGI server (gunicorn/uwsgi) instead of the Flask dev server in production.

## Offending code
```
app.run(host='0.0.0.0', debug=True)
```
