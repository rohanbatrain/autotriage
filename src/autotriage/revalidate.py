"""Fix-validation loop: prove a proposed remediation actually closes a finding.

A triage decision can *recommend* a fix, but a recommendation is not a fix. This
module closes the loop: it applies a :class:`~autotriage.schema.FixPatch` to an
**isolated copy** of the target, re-runs the scanner, and only reports the fix as
``resolved`` when the finding's signature is gone *and* no new finding was
introduced. Everything else fails closed to a human — the same posture as the
triage confidence guardrail.

The re-scan is injected (:data:`RescanFn`) so the engine is pure and fully
unit-testable offline; :func:`make_rescan` wires in the real scanner layer for
live use. No LLM calls happen here — patch *generation* lives in
:mod:`autotriage.agent`; this module only *verifies*.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import shutil
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from autotriage import observability
from autotriage.schema import (
    Finding,
    FixPatch,
    FixValidation,
    ScannerTool,
    ValidationStatus,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

#: A callable that scans a directory and returns normalized findings. Injected so
#: the validation engine never hard-depends on the (subprocess-backed) scanners.
RescanFn = Callable[[Path], list[Finding]]

_LOGGER = observability.get_logger(__name__)


class FixApplyError(RuntimeError):
    """Raised when a :class:`FixPatch` cannot be applied deterministically.

    An edit whose ``search`` text is missing, ambiguous (appears more than once),
    or points outside the target tree fails the whole patch rather than guessing.
    """


def finding_signature(finding: Finding) -> tuple[str, str, str]:
    """Return a location-stable identity for a finding: ``(tool, rule, file)``.

    Deliberately **excludes the line number**: a real fix shifts the lines
    around it, so matching on the exact line would make a genuinely-fixed finding
    look like it moved rather than disappeared. The file component is reduced to
    its basename so the signature is stable regardless of the directory the
    scanner was invoked from (repo root vs. the target subtree).

    Args:
        finding: The finding to identify.

    Returns:
        A ``(tool, rule_id, basename)`` tuple usable as a set/dict key.
    """
    return (finding.tool.value, finding.rule_id, PurePosixPath(finding.file).name)


def _signature_str(signature: tuple[str, str, str]) -> str:
    """Render a signature tuple as a compact ``tool:rule:file`` string."""
    return ":".join(signature)


def _resolve_within(root: Path, relative: str) -> Path:
    """Resolve ``relative`` under ``root``, rejecting path traversal.

    Args:
        root: The directory the edit is confined to.
        relative: A path from a :class:`~autotriage.schema.FileEdit`.

    Returns:
        The resolved, in-tree path.

    Raises:
        FixApplyError: If the path escapes ``root`` or the file is absent.
    """
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise FixApplyError(f"edit path {relative!r} escapes the target tree")
    if not candidate.is_file():
        raise FixApplyError(f"edit target {relative!r} does not exist in the tree")
    return candidate


def apply_fix_patch(patch: FixPatch, workdir: Path) -> None:
    """Apply every edit in ``patch`` to files under ``workdir``, in order.

    Each edit's ``search`` text must occur **exactly once** in its file; anything
    else raises :class:`FixApplyError` so a fix is never applied ambiguously.

    Args:
        patch: The machine-applicable remediation to apply.
        workdir: The (already-isolated) copy of the target tree to mutate.

    Raises:
        FixApplyError: If any edit cannot be applied deterministically.
    """
    for edit in patch.edits:
        path = _resolve_within(workdir, edit.file)
        text = path.read_text(encoding="utf-8")
        occurrences = text.count(edit.search)
        if occurrences == 0:
            raise FixApplyError(
                f"search text not found in {edit.file!r}; fix does not apply"
            )
        if occurrences > 1:
            raise FixApplyError(
                f"search text is ambiguous in {edit.file!r} "
                f"({occurrences} matches); refusing to guess"
            )
        path.write_text(text.replace(edit.search, edit.replace, 1), encoding="utf-8")


def _isolated_copy(target: Path) -> tuple[Path, Path]:
    """Copy ``target`` into a fresh temp directory and return ``(root, workdir)``.

    Args:
        target: The directory (or file) to copy.

    Returns:
        A ``(root, workdir)`` pair: ``root`` is the temp directory to remove
        when done; ``workdir`` is the copied target within it.
    """
    root = Path(tempfile.mkdtemp(prefix="autotriage-revalidate-"))
    workdir = root / target.name
    if target.is_dir():
        shutil.copytree(target, workdir)
    else:
        workdir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, workdir / target.name)
    return root, workdir


def validate_fix(
    target: Path,
    finding: Finding,
    patch: FixPatch,
    *,
    rescan: RescanFn,
) -> FixValidation:
    """Apply ``patch`` to an isolated copy of ``target`` and re-scan to verify.

    The contract is intentionally strict and fails closed:

    * **No edits** -> ``SKIPPED`` (there was nothing to validate).
    * **Baseline does not reproduce the finding** -> ``ERROR`` (we refuse to
      claim a fix works when we could not even observe the vulnerability first;
      usually the relevant scanner is not installed).
    * **Patch will not apply** -> ``ERROR``.
    * **Finding still fires after the fix** -> ``UNRESOLVED``.
    * **Finding gone but a new finding appeared** -> ``REGRESSED``.
    * **Finding gone and nothing new** -> ``RESOLVED`` (the only trusted state).

    Args:
        target: The target tree to copy and fix in isolation (never mutated).
        finding: The finding the patch claims to remediate.
        patch: The machine-applicable remediation.
        rescan: A scan callable applied to the isolated copy.

    Returns:
        A :class:`FixValidation` describing the outcome.
    """
    target_sig = finding_signature(finding)
    if not patch.edits:
        return FixValidation(
            finding_id=finding.id,
            status=ValidationStatus.SKIPPED,
            resolved=False,
            detail="no patch edits were proposed for this finding",
        )

    root, workdir = _isolated_copy(target)
    try:
        before = {finding_signature(f) for f in rescan(workdir)}
        if target_sig not in before:
            return FixValidation(
                finding_id=finding.id,
                status=ValidationStatus.ERROR,
                resolved=False,
                signatures_before=len(before),
                detail=(
                    f"baseline scan did not reproduce {_signature_str(target_sig)!r}; "
                    "cannot validate the fix (is the scanner installed?)"
                ),
            )

        try:
            apply_fix_patch(patch, workdir)
        except FixApplyError as exc:
            return FixValidation(
                finding_id=finding.id,
                status=ValidationStatus.ERROR,
                resolved=False,
                signatures_before=len(before),
                detail=f"patch did not apply: {exc}",
            )

        after = {finding_signature(f) for f in rescan(workdir)}
    finally:
        shutil.rmtree(root, ignore_errors=True)

    new_signatures = sorted(_signature_str(s) for s in (after - before))
    if target_sig in after:
        status = ValidationStatus.UNRESOLVED
        detail = "the finding still fires after applying the fix"
    elif new_signatures:
        status = ValidationStatus.REGRESSED
        detail = f"finding resolved but {len(new_signatures)} new finding(s) appeared"
    else:
        status = ValidationStatus.RESOLVED
        detail = "finding no longer fires and no new findings were introduced"

    result = FixValidation(
        finding_id=finding.id,
        status=status,
        resolved=status is ValidationStatus.RESOLVED,
        signatures_before=len(before),
        signatures_after=len(after),
        new_signatures=new_signatures,
        detail=detail,
    )
    with contextlib.suppress(Exception):
        _LOGGER.info(
            "fix validated",
            extra={
                "event": "fix.validated",
                "finding_id": finding.id,
                "status": status.value,
                "resolved": result.resolved,
            },
        )
    return result


def validate_fixes(
    target: Path,
    pairs: Iterable[tuple[Finding, FixPatch]],
    *,
    rescan: RescanFn,
) -> list[FixValidation]:
    """Validate a batch of ``(finding, patch)`` pairs against ``target``.

    Each pair is validated independently against its own isolated copy, so one
    failing fix never affects another.

    Args:
        target: The target tree to validate fixes against.
        pairs: The finding/patch pairs to validate.
        rescan: The scan callable applied to each isolated copy.

    Returns:
        One :class:`FixValidation` per input pair, in order.
    """
    return [
        validate_fix(target, finding, patch, rescan=rescan) for finding, patch in pairs
    ]


def make_rescan(tools: Sequence[ScannerTool] | None = None) -> RescanFn:
    """Return a :data:`RescanFn` backed by the real scanner layer.

    Args:
        tools: Scanners to run on each re-scan; defaults to all supported tools.
            Narrowing to the single tool that produced a finding makes validation
            dramatically faster.

    Returns:
        A callable suitable to pass as ``rescan`` to :func:`validate_fix`.
    """
    from autotriage import scanners  # noqa: PLC0415 - keep import light for tests

    selected = list(tools) if tools is not None else None

    def _rescan(path: Path) -> list[Finding]:
        return scanners.run_scans(path, selected)

    return _rescan


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _load_findings(path: Path) -> dict[str, Finding]:
    """Load findings from a JSON array, keyed by id."""
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = [Finding.model_validate(item) for item in data]
    return {f.id: f for f in findings}


def _load_patches(path: Path) -> list[FixPatch]:
    """Load a JSON array of fix patches."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return [FixPatch.model_validate(item) for item in data]


def render_report(results: list[FixValidation]) -> str:
    """Render a Markdown fix-validation report for ``results``.

    Args:
        results: The validation outcomes to summarize.

    Returns:
        A Markdown document with headline counts and a per-finding table.
    """
    resolved = sum(1 for r in results if r.status is ValidationStatus.RESOLVED)
    total = len(results)
    lines = [
        "# AutoTriage Fix-Validation Report",
        "",
        f"Validated **{total}** proposed fixes — "
        f"**{resolved}/{total}** confirmed resolved by re-scan.",
        "",
        "Each fix is applied to an isolated copy of the target and the scanner "
        "re-run; a fix is trusted only when the finding is gone and no new "
        "finding is introduced.",
        "",
        "| Finding | Status | Resolved | Before | After | New findings | Detail |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in results:
        new = ", ".join(r.new_signatures) or "—"
        lines.append(
            f"| {r.finding_id} | {r.status.value} | {'✅' if r.resolved else '❌'} "
            f"| {r.signatures_before} | {r.signatures_after} | {new} | {r.detail} |"
        )
    lines.append("")
    return "\n".join(lines)


def _print_summary(results: list[FixValidation]) -> None:
    """Print a terminal summary of validation outcomes."""
    from collections import Counter  # noqa: PLC0415

    counts = Counter(r.status.value for r in results)
    resolved = counts.get(ValidationStatus.RESOLVED.value, 0)
    print("\n=== AutoTriage fix-validation summary ===")
    print(f"fixes validated  : {len(results)}")
    print(f"resolved         : {resolved}")
    print("by status        : " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    for r in results:
        mark = "✅" if r.resolved else "❌"
        print(f"  {mark} {r.finding_id}: {r.status.value} — {r.detail}")


def main(argv: list[str] | None = None) -> int:
    r"""Command-line entry point for the fix-validation loop.

    Usage::

        python -m autotriage.revalidate --target target \\
            --findings fixtures/findings.sample.json \\
            --patches fixtures/fix_patches.sample.json [--report report.md]

    Args:
        argv: Optional argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        ``0`` if every proposed fix was confirmed resolved, else ``1``.
    """
    parser = argparse.ArgumentParser(
        prog="autotriage.revalidate",
        description=(
            "Apply proposed fixes to an isolated copy of the target and re-scan "
            "to confirm each finding is actually resolved."
        ),
    )
    parser.add_argument("--target", type=Path, required=True, help="Target tree.")
    parser.add_argument(
        "--findings",
        type=Path,
        required=True,
        help="JSON array of findings (matched to patches by finding_id).",
    )
    parser.add_argument(
        "--patches",
        type=Path,
        required=True,
        help="JSON array of FixPatch objects to validate.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional path to write a Markdown report to.",
    )
    args = parser.parse_args(argv)

    findings = _load_findings(args.findings)
    patches = _load_patches(args.patches)
    rescan = make_rescan()

    pairs: list[tuple[Finding, FixPatch]] = []
    for patch in patches:
        finding = findings.get(patch.finding_id)
        if finding is None:
            print(
                f"warning: no finding matches patch {patch.finding_id!r}; skipping",
                file=sys.stderr,
            )
            continue
        pairs.append((finding, patch))

    results = validate_fixes(args.target, pairs, rescan=rescan)
    _print_summary(results)
    if args.report is not None:
        args.report.write_text(render_report(results), encoding="utf-8")
        print(f"\nreport written to {args.report}")

    all_resolved = bool(results) and all(r.resolved for r in results)
    return 0 if all_resolved else 1


__all__ = [
    "FixApplyError",
    "RescanFn",
    "apply_fix_patch",
    "finding_signature",
    "make_rescan",
    "render_report",
    "validate_fix",
    "validate_fixes",
]


if __name__ == "__main__":
    raise SystemExit(main())
