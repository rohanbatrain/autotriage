"""Scanner adapters that normalize third-party tool output into ``Finding``.

This module wraps three security scanners as subprocess adapters and maps each
tool's native JSON onto the shared :class:`~autotriage.schema.Finding` contract:

* **Semgrep** — static analysis (SAST).
* **Trivy** — dependency CVEs (SCA), IaC misconfiguration (IAC), and secrets.
* **Gitleaks** — hard-coded secret detection (SECRET).

Every adapter is defensive: a missing binary, a non-zero exit code, or malformed
JSON degrades to an empty result with a warning rather than raising, so one
broken tool never aborts the whole scan. Only PEP 8 / PEP 257 / PEP 484 clean
code lives here, matching the style of :mod:`autotriage.schema`.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from autotriage.schema import Finding, FindingType, ScannerTool

logger = logging.getLogger("autotriage.scanners")

#: Extracts the canonical ``CWE-<n>`` token from a decorated label such as
#: ``"CWE-89: Improper Neutralization of ... ('SQL Injection')"``.
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
#: Extracts the canonical ``A<nn>:<year>`` OWASP token from a label such as
#: ``"A03:2021 - Injection"``.
_OWASP_RE = re.compile(r"A\d{2}:\d{4}")

#: Subprocess timeout (seconds) applied to every scanner invocation.
_SCAN_TIMEOUT = 600


def _as_str_list(value: Any) -> list[str]:  # noqa: ANN401 - heterogeneous JSON
    """Coerce a scalar-or-list JSON value into a list of strings.

    Args:
        value: A string, a list, ``None``, or any other JSON scalar.

    Returns:
        A list of strings; an empty list when ``value`` is falsy.
    """
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _extract_cwe(values: Any) -> list[str]:  # noqa: ANN401 - heterogeneous JSON
    """Return normalized ``CWE-<n>`` tokens found in a raw metadata value.

    Args:
        values: A string or list of possibly-decorated CWE labels.

    Returns:
        Upper-cased, de-duplicated CWE identifiers in first-seen order.
    """
    out: list[str] = []
    for item in _as_str_list(values):
        match = _CWE_RE.search(item)
        if match:
            token = match.group(0).upper()
            if token not in out:
                out.append(token)
    return out


def _extract_owasp(values: Any) -> list[str]:  # noqa: ANN401 - heterogeneous JSON
    """Return normalized ``A<nn>:<year>`` OWASP tokens from a raw value.

    Args:
        values: A string or list of possibly-decorated OWASP labels.

    Returns:
        De-duplicated OWASP identifiers in first-seen order.
    """
    out: list[str] = []
    for item in _as_str_list(values):
        match = _OWASP_RE.search(item)
        if match:
            token = match.group(0)
            if token not in out:
                out.append(token)
    return out


def _first_line(text: str) -> str:
    """Return the first non-empty line of ``text``, stripped.

    Args:
        text: Arbitrary, possibly multi-line text.

    Returns:
        The first non-empty line, or an empty string.
    """
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


#: Placeholder Semgrep emits for matched code when it is not authenticated to
#: the Semgrep registry; useless to the triage agent, so we read the real source.
_SEMGREP_REDACTED = "requires login"


def _read_source_lines(path: str, start: int, end: int, *, context: int = 2) -> str:
    """Read source lines ``[start, end]`` (1-based, inclusive) from ``path``.

    Semgrep redacts the matched code to ``"requires login"`` unless the CLI is
    authenticated, which would leave the triage agent reasoning about a finding
    without ever seeing the offending code. Reading the lines straight from disk
    (plus a little surrounding ``context``) restores that evidence so the agent
    can actually confirm exploitability.

    Args:
        path: Source file path, relative to the current working directory.
        start: 1-based first line of the match.
        end: 1-based last line of the match (may equal or precede ``start``).
        context: Extra lines to include on each side for readability.

    Returns:
        The joined source lines, or an empty string if the file cannot be read.
    """
    if start <= 0:
        return ""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    last = max(start, end)
    lo = max(0, start - 1 - context)
    hi = min(len(lines), last + context)
    return "\n".join(lines[lo:hi]).strip()


def _run_json(cmd: list[str], tool: str) -> Any:  # noqa: ANN401 - JSON payload
    """Run ``cmd`` and parse its stdout as JSON, defensively.

    Non-zero exit codes are tolerated because several scanners signal
    "findings present" that way (e.g. Gitleaks exits ``1``); only genuinely
    unparseable output is treated as failure.

    Args:
        cmd: The full argument vector to execute.
        tool: Human-readable tool name, used only in log messages.

    Returns:
        The parsed JSON object, or ``None`` if the tool could not be run or
        produced no valid JSON.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - args are built from trusted input
            cmd,
            capture_output=True,
            text=True,
            timeout=_SCAN_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("%s failed to execute: %s", tool, exc)
        return None
    if not proc.stdout.strip():
        logger.warning("%s produced no output (stderr: %s)", tool, proc.stderr.strip())
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        logger.warning("%s emitted invalid JSON: %s", tool, exc)
        return None


def run_semgrep(target: Path) -> list[Finding]:
    """Run Semgrep over ``target`` and normalize its results.

    Command: ``semgrep --config auto --json <target>``.

    Args:
        target: File or directory to scan.

    Returns:
        SAST findings, or an empty list if Semgrep is unavailable or fails.
    """
    binary = shutil.which("semgrep")
    if binary is None:
        logger.warning("semgrep binary not found on PATH; skipping SAST scan")
        return []

    cmd = [binary, "--config", "auto", "--json", str(target)]
    payload = _run_json(cmd, "semgrep")
    if not isinstance(payload, dict):
        return []

    findings: list[Finding] = []
    for result in payload.get("results", []):
        if not isinstance(result, dict):
            continue
        extra = result.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        rule_id = str(result.get("check_id", "unknown"))
        file = str(result.get("path", ""))
        line = int((result.get("start", {}) or {}).get("line", 0) or 0)
        end_line = int((result.get("end", {}) or {}).get("line", line) or line)
        message = str(extra.get("message", ""))
        snippet = str(extra.get("lines", "")).strip()
        if not snippet or snippet.lower() == _SEMGREP_REDACTED:
            # Semgrep redacted the code (unauthenticated); read it from disk so
            # the triage agent can see the actual offending lines.
            snippet = _read_source_lines(file, line, end_line)
        findings.append(
            Finding(
                id=Finding.make_id("semgrep", rule_id, file, line),
                tool=ScannerTool.SEMGREP,
                type=FindingType.SAST,
                rule_id=rule_id,
                title=_first_line(message) or rule_id,
                severity_raw=str(extra.get("severity", "")),
                cwe=_extract_cwe(metadata.get("cwe")),
                owasp=_extract_owasp(metadata.get("owasp")),
                file=file,
                line=line,
                code_snippet=snippet,
                description=message,
                raw=result,
            )
        )
    return findings


def _trivy_code_snippet(cause: dict[str, Any]) -> str:
    """Return the source snippet from a Trivy ``CauseMetadata``/``Code`` block.

    Args:
        cause: A Trivy ``CauseMetadata`` object (or empty dict).

    Returns:
        The joined non-empty source lines, or an empty string.
    """
    lines = ((cause.get("Code", {}) or {}).get("Lines", []) or []) if cause else []
    contents = [str(item.get("Content", "")).strip() for item in lines if item]
    return "\n".join(c for c in contents if c)


def run_trivy(target: Path) -> list[Finding]:
    """Run Trivy over ``target`` and normalize vuln/misconfig/secret results.

    Command:
    ``trivy fs --format json --scanners vuln,misconfig,secret <target>``.

    Vulnerabilities become SCA findings, misconfigurations become IAC findings,
    and detected secrets become SECRET findings.

    Args:
        target: File or directory to scan.

    Returns:
        Normalized findings, or an empty list if Trivy is unavailable or fails.
    """
    binary = shutil.which("trivy")
    if binary is None:
        logger.warning("trivy binary not found on PATH; skipping SCA/IaC scan")
        return []

    cmd = [
        binary,
        "fs",
        "--format",
        "json",
        "--scanners",
        "vuln,misconfig,secret",
        str(target),
    ]
    payload = _run_json(cmd, "trivy")
    if not isinstance(payload, dict):
        return []

    findings: list[Finding] = []
    for result in payload.get("Results", []):
        if not isinstance(result, dict):
            continue
        file = str(result.get("Target", ""))
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(_trivy_vuln(vuln, file))
        for misconfig in result.get("Misconfigurations", []) or []:
            findings.append(_trivy_misconfig(misconfig, file))
        for secret in result.get("Secrets", []) or []:
            findings.append(_trivy_secret(secret, file))
    return findings


def _trivy_vuln(vuln: dict[str, Any], file: str) -> Finding:
    """Map a single Trivy vulnerability record to an SCA ``Finding``.

    Args:
        vuln: A Trivy ``Vulnerabilities`` entry.
        file: The lockfile/manifest the vulnerability was found in.

    Returns:
        The normalized SCA finding.
    """
    rule_id = str(vuln.get("VulnerabilityID", "unknown"))
    package = vuln.get("PkgName")
    installed = vuln.get("InstalledVersion")
    title = str(vuln.get("Title", "")) or f"{package} {rule_id}"
    return Finding(
        id=Finding.make_id("trivy", rule_id, file, 0),
        tool=ScannerTool.TRIVY,
        type=FindingType.SCA,
        rule_id=rule_id,
        title=title,
        severity_raw=str(vuln.get("Severity", "")),
        cwe=_extract_cwe(vuln.get("CweIDs")),
        file=file,
        line=0,
        code_snippet=f"{package}=={installed}" if package and installed else "",
        description=str(vuln.get("Description", "")),
        package=str(package) if package is not None else None,
        installed_version=str(installed) if installed is not None else None,
        fixed_version=(str(vuln["FixedVersion"]) if vuln.get("FixedVersion") else None),
        raw=vuln,
    )


def _trivy_misconfig(misconfig: dict[str, Any], file: str) -> Finding:
    """Map a single Trivy misconfiguration record to an IAC ``Finding``.

    Args:
        misconfig: A Trivy ``Misconfigurations`` entry.
        file: The IaC file the misconfiguration was found in.

    Returns:
        The normalized IAC finding.
    """
    rule_id = str(misconfig.get("ID") or misconfig.get("AVDID") or "unknown")
    cause = misconfig.get("CauseMetadata", {}) or {}
    line = int(cause.get("StartLine", 0) or 0)
    return Finding(
        id=Finding.make_id("trivy", rule_id, file, line),
        tool=ScannerTool.TRIVY,
        type=FindingType.IAC,
        rule_id=rule_id,
        title=str(misconfig.get("Title", "")) or rule_id,
        severity_raw=str(misconfig.get("Severity", "")),
        file=file,
        line=line,
        code_snippet=_trivy_code_snippet(cause),
        description=str(misconfig.get("Description") or misconfig.get("Message") or ""),
        raw=misconfig,
    )


def _trivy_secret(secret: dict[str, Any], file: str) -> Finding:
    """Map a single Trivy secret record to a SECRET ``Finding``.

    Args:
        secret: A Trivy ``Secrets`` entry.
        file: The file the secret was found in.

    Returns:
        The normalized SECRET finding.
    """
    rule_id = str(secret.get("RuleID", "unknown"))
    line = int(secret.get("StartLine", 0) or 0)
    snippet = _trivy_code_snippet(secret) or str(secret.get("Match", ""))
    return Finding(
        id=Finding.make_id("trivy", rule_id, file, line),
        tool=ScannerTool.TRIVY,
        type=FindingType.SECRET,
        rule_id=rule_id,
        title=str(secret.get("Title", "")) or rule_id,
        severity_raw=str(secret.get("Severity", "")),
        cwe=["CWE-798"],
        file=file,
        line=line,
        code_snippet=snippet.strip(),
        description=str(secret.get("Title", "")),
        raw=secret,
    )


def _read_gitleaks_report(report_path: Path) -> list[Any]:
    """Read and parse a Gitleaks JSON report, defensively.

    Args:
        report_path: Path the Gitleaks report was written to.

    Returns:
        The parsed list of records, or an empty list on any read/parse error.
    """
    try:
        raw = report_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        logger.warning("gitleaks report unreadable: %s", exc)
        return []
    finally:
        report_path.unlink(missing_ok=True)
    if not raw:
        return []
    try:
        records = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("gitleaks emitted invalid JSON: %s", exc)
        return []
    return records if isinstance(records, list) else []


def run_gitleaks(target: Path) -> list[Finding]:
    """Run Gitleaks over ``target`` and normalize its secret findings.

    Command: ``gitleaks detect --source <target> --no-git
    --report-format json --report-path <tmpfile>``. Gitleaks exits non-zero
    when leaks are present, so the report file is read regardless of exit code.

    Args:
        target: File or directory to scan.

    Returns:
        SECRET findings, or an empty list if Gitleaks is unavailable or fails.
    """
    binary = shutil.which("gitleaks")
    if binary is None:
        logger.warning("gitleaks binary not found on PATH; skipping secret scan")
        return []

    with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as handle:
        report_path = Path(handle.name)
    cmd = [
        binary,
        "detect",
        "--source",
        str(target),
        "--no-git",
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
    ]
    try:
        subprocess.run(  # noqa: S603 - args are built from trusted input
            cmd,
            capture_output=True,
            text=True,
            timeout=_SCAN_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("gitleaks failed to execute: %s", exc)
        report_path.unlink(missing_ok=True)
        return []

    records = _read_gitleaks_report(report_path)
    findings: list[Finding] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        rule_id = str(record.get("RuleID", "unknown"))
        file = str(record.get("File", ""))
        line = int(record.get("StartLine", 0) or 0)
        description = str(record.get("Description", ""))
        findings.append(
            Finding(
                id=Finding.make_id("gitleaks", rule_id, file, line),
                tool=ScannerTool.GITLEAKS,
                type=FindingType.SECRET,
                rule_id=rule_id,
                title=description or rule_id,
                severity_raw="HIGH",
                cwe=["CWE-798"],
                file=file,
                line=line,
                code_snippet=str(record.get("Match", "")).strip(),
                description=description,
                raw=record,
            )
        )
    return findings


#: Maps each scanner to its adapter entry point.
_ADAPTERS: dict[ScannerTool, Any] = {
    ScannerTool.SEMGREP: run_semgrep,
    ScannerTool.TRIVY: run_trivy,
    ScannerTool.GITLEAKS: run_gitleaks,
}


def run_scans(target: Path, tools: list[ScannerTool] | None = None) -> list[Finding]:
    """Run the selected scanners over ``target`` and return deduped findings.

    Each adapter is isolated: a failure in one tool is logged and skipped so the
    remaining tools still run. Findings are de-duplicated by
    :attr:`Finding.id`, keeping the first occurrence.

    Args:
        target: File or directory to scan.
        tools: Scanners to run; defaults to all supported scanners.

    Returns:
        The combined, de-duplicated list of findings.
    """
    selected = tools if tools is not None else list(ScannerTool)
    deduped: dict[str, Finding] = {}
    for tool in selected:
        adapter = _ADAPTERS[tool]
        for finding in adapter(target):
            deduped.setdefault(finding.id, finding)
    return list(deduped.values())


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point for the scanner layer.

    Usage: ``python -m autotriage.scanners <target> [-o findings.json]``.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        A process exit code (``0`` on success).
    """
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        prog="autotriage.scanners",
        description="Run security scanners and emit normalized findings as JSON.",
    )
    parser.add_argument("target", type=Path, help="File or directory to scan.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write findings JSON here instead of stdout.",
    )
    args = parser.parse_args(argv)

    findings = run_scans(args.target)
    payload = json.dumps([f.model_dump(mode="json") for f in findings], indent=2)
    if args.output is not None:
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        sys.stdout.write(payload + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
