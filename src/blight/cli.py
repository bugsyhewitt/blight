"""blight command-line interface.

Usage:
    blight --binary path/to/elf  --checks all --format json
    blight --binary path/to/dir/ --checks all --format json --workers 4

``--binary`` accepts either a single ELF file or a directory. When given a
directory, every regular file inside it (recursively) is treated as a binary to
scan, and ``--workers N`` fans the scan out across a thread pool.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import blight
from blight.confidence_filter import CONFIDENCE_CHOICES, filter_findings
from blight.detectors import DETECTORS
from blight.exit_gate import (
    FAIL_ON_CHOICES,
    GATE_TRIPPED_EXIT_CODE,
    gate_trips,
)
from blight.formatters.sarif import dump_sarif
from blight.formatters.text import dump_text_directory, dump_text_single
from blight.scan import ScanResult, scan_targets
from blight.suppressions import (
    SuppressionError,
    SuppressionSet,
    load_suppressions,
)

_ALL_CHECKS = sorted(DETECTORS)
# Accepted --checks tokens: each cwe id as a string, plus "all".
_CHECK_CHOICES = [str(c) for c in _ALL_CHECKS] + ["all"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blight",
        description=(
            "Python-native CWE pattern detector for ELF binaries, driving "
            "radare2 via r2pipe. Detects CWE-22, CWE-78, CWE-89, CWE-119, "
            "CWE-120, CWE-122, CWE-134, CWE-191, CWE-197, CWE-242, CWE-252, "
            "CWE-295, CWE-327, CWE-330, CWE-362, CWE-369, CWE-377, CWE-401, "
            "CWE-415, CWE-416, CWE-426, CWE-476, CWE-676, CWE-732, and CWE-798."
        ),
    )
    parser.add_argument(
        "--binary",
        required=True,
        metavar="PATH",
        help="path to an ELF binary, or a directory of binaries, to analyze",
    )
    parser.add_argument(
        "--checks",
        default="all",
        choices=_CHECK_CHOICES,
        help="which CWE check to run (default: all)",
    )
    parser.add_argument(
        "--format",
        default="json",
        choices=["json", "sarif", "text"],
        help=(
            "output format: 'json' (default, machine-readable), 'sarif' "
            "(GitHub Code Scanning), or 'text' (human-readable console "
            "report). 'text' carries no stability contract — use 'json' or "
            "'sarif' for tooling."
        ),
    )
    parser.add_argument(
        "--output-file",
        "-o",
        metavar="FILE",
        default=None,
        help=(
            "write the report to FILE instead of stdout. The file is created "
            "(or truncated) and the rendered report — in whichever --format is "
            "selected — is written to it; nothing is printed to stdout. The "
            "--fail-on exit code is unaffected. Use '-' to force stdout "
            "explicitly (the default)."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help=(
            "number of parallel worker threads for scanning a directory of "
            "binaries (default: 1, sequential). Ignored when --binary is a "
            "single file."
        ),
    )
    parser.add_argument(
        "--suppress",
        metavar="FILE",
        default=None,
        help=(
            "path to a JSON suppression file listing known false positives to "
            "drop from the output. Each rule keys on 'cwe' plus any of "
            "'function', 'address', 'symbol'."
        ),
    )
    parser.add_argument(
        "--min-confidence",
        default="low",
        choices=list(CONFIDENCE_CHOICES),
        help=(
            "drop findings below this triage confidence before output. "
            "'high' keeps only high-confidence findings; 'medium' keeps "
            "medium and high; 'low' (default) keeps everything."
        ),
    )
    parser.add_argument(
        "--fail-on",
        default="none",
        choices=list(FAIL_ON_CHOICES),
        help=(
            "exit non-zero when any emitted finding is at or above this "
            "triage confidence, turning blight into a CI build gate. "
            "'high' fails only on a high-confidence finding; 'medium' fails "
            "on medium or high; 'low' fails on any finding; 'none' (default) "
            "never fails. The gate runs over findings that survive "
            "--suppress and --min-confidence, so it matches the report."
        ),
    )
    return parser


def _resolve_checks(token: str) -> list[int]:
    if token == "all":
        return list(_ALL_CHECKS)
    return [int(token)]


def discover_binaries(directory: Path) -> list[Path]:
    """Return the binaries to scan inside ``directory``.

    Every regular file under ``directory`` (recursively) is a candidate, sorted
    by path so output ordering is stable across runs and filesystems. blight
    does not sniff file types here — radare2 will simply report no findings for
    a non-ELF input — but symlinks and special files are skipped.
    """
    return sorted(p for p in directory.rglob("*") if p.is_file())


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.workers < 1:
        parser.error("--workers must be >= 1")

    suppressions = SuppressionSet(rules=())
    if args.suppress is not None:
        try:
            suppressions = load_suppressions(args.suppress)
        except SuppressionError as exc:
            parser.error(f"--suppress: {exc}")

    target = Path(args.binary)
    checks = _resolve_checks(args.checks)

    if target.is_dir():
        binaries = discover_binaries(target)
        if not binaries:
            parser.error(f"no files found under directory: {target}")
        results = scan_targets(
            [str(p) for p in binaries], checks, workers=args.workers
        )
        results = [_apply_suppressions(r, suppressions) for r in results]
        results = [
            _apply_min_confidence(r, args.min_confidence) for r in results
        ]
        report = _render_directory(target, checks, results, args.format)
        _write_report(report, args.output_file, parser)
        emitted = [f for r in results for f in r.findings]
        return _gate_exit_code(emitted, args.fail_on)

    if not target.is_file():
        parser.error(f"binary not found: {target}")

    # Single-file scan. Honour the historical output shape exactly so existing
    # consumers (and tests) are unaffected.
    [result] = scan_targets([str(target)], checks, workers=1)
    result = _apply_suppressions(result, suppressions)
    result = _apply_min_confidence(result, args.min_confidence)
    report = _render_single(str(target), checks, result, args.format)
    _write_report(report, args.output_file, parser)
    return _gate_exit_code(result.findings, args.fail_on)


def _gate_exit_code(emitted_findings, fail_on: str) -> int:
    """Return the process exit code for the ``--fail-on`` gate.

    The gate is evaluated over the findings that were actually emitted (after
    suppression and the min-confidence threshold), so it is always consistent
    with the report the user just saw. ``--fail-on none`` (the default) keeps
    the historical ``0`` return for full backward compatibility.
    """
    if gate_trips(emitted_findings, fail_on):
        return GATE_TRIPPED_EXIT_CODE
    return 0


def _apply_suppressions(
    result: ScanResult, suppressions: SuppressionSet
) -> ScanResult:
    """Return ``result`` with suppressed findings removed.

    A result that errored carries no findings, so suppression is a no-op there;
    the ``error`` field is preserved untouched.
    """
    if not suppressions:
        return result
    return ScanResult(
        binary=result.binary,
        findings=suppressions.apply(result.findings),
        error=result.error,
    )


def _apply_min_confidence(result: ScanResult, minimum: str) -> ScanResult:
    """Return ``result`` with findings below ``minimum`` confidence dropped.

    ``minimum == "low"`` is the default and keeps everything (identity), so an
    errored result (no findings) is returned untouched and the common case adds
    no allocation churn. The ``error`` field is always preserved.
    """
    if minimum == "low":
        return result
    return ScanResult(
        binary=result.binary,
        findings=filter_findings(result.findings, minimum),
        error=result.error,
    )


def _render_single(
    binary: str, checks: list[int], result: ScanResult, fmt: str
) -> str:
    """Render a single-file scan to its report string (no trailing newline)."""
    if fmt == "sarif":
        return dump_sarif(binary, result.findings, version=blight.__version__)
    if fmt == "text":
        return dump_text_single(binary, checks, result.findings)
    output = {
        "binary": binary,
        "checks": checks,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(output, indent=2)


def _render_directory(
    directory: Path, checks: list[int], results: list[ScanResult], fmt: str
) -> str:
    """Render a directory scan to its report string (no trailing newline)."""
    if fmt == "sarif":
        # One SARIF run per binary keeps each result's artifactLocation correct.
        all_findings = [f for r in results for f in r.findings]
        return dump_sarif(
            str(directory), all_findings, version=blight.__version__
        )
    if fmt == "text":
        return dump_text_directory(str(directory), checks, results)
    output = {
        "directory": str(directory),
        "checks": checks,
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(output, indent=2)


def _write_report(
    report: str, output_file: str | None, parser: argparse.ArgumentParser
) -> None:
    """Write the rendered ``report`` to ``output_file`` or stdout.

    The report is emitted with a single trailing newline, matching the
    historical stdout behaviour exactly. ``output_file`` of ``None`` or ``"-"``
    means stdout (the default and the explicit stdout token); any other value
    is a filesystem path that is created or truncated. An OS error writing the
    file is surfaced as an ``argparse`` error so the run aborts cleanly with the
    usage exit code rather than an unhandled traceback.
    """
    if output_file is None or output_file == "-":
        sys.stdout.write(report)
        sys.stdout.write("\n")
        return
    try:
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(report)
            fh.write("\n")
    except OSError as exc:
        parser.error(f"--output-file: cannot write {output_file!r}: {exc}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
