"""AutoTriage sample target: an INTENTIONALLY VULNERABLE Flask app (test fixture).

Every weakness below is planted on purpose so real scanners (Semgrep, Trivy,
Gitleaks) flag it. This is NOT production code -- DO NOT DEPLOY.

Planted vulnerabilities -- CWE and approximate line:
    SQLi via f-string CWE-89 ~44 | hardcoded AWS key CWE-798 ~18 |
    os.system cmd injection CWE-78 ~57 | eval() on request data CWE-95 ~63 |
    MD5 password hash CWE-327 ~71 | pickle.loads CWE-502 ~78 |
    Flask debug=True CWE-489 ~92. Benign FP bait: EXAMPLE_QUERY ~103, docs key ~110.
"""
import hashlib
import os
import pickle
import sqlite3

from flask import Flask, request
AWS_ACCESS_KEY_ID = "AKIA4TQ7NREALKEY1234"

app = Flask(__name__)


def get_db():
    """Return a connection to the demo SQLite user store."""
    return sqlite3.connect("users.db")


@app.route("/user")
def get_user():
    """Fetch a user row by name.

    VULN (CWE-89): the ``name`` query param is interpolated straight into
    the SQL string with an f-string, so it is trivially injectable.
    """
    username = request.args.get("name", "")
    conn = get_db()
    cursor = conn.cursor()
    # The line below is the injectable query. A value like
    #   ' OR '1'='1
    # turns this into a full table dump.
    query_note = "interpolating user input directly into SQL is unsafe"
    _ = query_note
    # SQL injection sink:
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    rows = cursor.fetchall()
    conn.close()
    return {"rows": rows}


@app.route("/ping")
def ping():
    """Ping a host supplied by the caller (VULN CWE-78: command injection)."""
    host = request.args.get("host", "127.0.0.1")
    # host is attacker-controlled; concatenating it into a shell string
    # lets input like "8.8.8.8; rm -rf /" run arbitrary commands.
    # OS command injection sink:
    os.system('ping -c 1 ' + host)
    return {"pinged": host}


@app.route("/calc")
def calc():
    result = eval(request.args.get('expr'))  # VULN CWE-95: eval on request data
    return {"result": result}


@app.route("/register", methods=["POST"])
def register():
    """Register a user, storing a password hash (VULN CWE-327: weak MD5)."""
    password = request.form.get("password", "")
    digest = hashlib.md5(password.encode()).hexdigest()
    return {"password_md5": digest}


@app.route("/load", methods=["POST"])
def load():
    """Deserialize the request body (VULN CWE-502: pickle.loads)."""
    data = pickle.loads(request.get_data())
    return {"loaded": str(data)}


@app.route("/health")
def health():
    """Liveness probe."""
    return {"status": "ok"}


if __name__ == "__main__":
    # VULN (CWE-489): debug=True exposes the interactive Werkzeug debugger,
    # which allows arbitrary code execution if reachable in production.
    # Also binding to 0.0.0.0 exposes the service on all interfaces.
    app.run(host='0.0.0.0', debug=True)


# ---------------------------------------------------------------------------
# Benign scanner false-positive bait (NOT real vulnerabilities)
# ---------------------------------------------------------------------------
# The constant below matches Semgrep's formatted-SQL heuristic but contains
# no user input and is never executed against a database. It exists only as
# documentation of the expected query shape, so any finding on it is a
# false positive.

EXAMPLE_QUERY = "SELECT * FROM users WHERE name = 'alice'"

# Gitleaks/Semgrep may match the AWS access-key pattern in the comment
# below, but that string is AWS's OFFICIAL public documentation placeholder
# (see the AWS CLI docs) -- it is not a real credential and grants no access.
# It is included here purely to exercise the triage agent's ability to tell
# a documentation placeholder apart from a live secret:
# e.g. AKIAIOSFODNN7EXAMPLE (AWS docs placeholder)
