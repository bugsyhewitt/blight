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
from blight.detectors import DETECTORS
from blight.formatters.sarif import dump_sarif
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
            "radare2 via r2pipe. Detects CWE-78, CWE-120, and CWE-242."
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
        choices=["json", "sarif"],
        help="output format (default: json)",
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
        _emit_directory(target, checks, results, args.format)
        return 0

    if not target.is_file():
        parser.error(f"binary not found: {target}")

    # Single-file scan. Honour the historical output shape exactly so existing
    # consumers (and tests) are unaffected.
    [result] = scan_targets([str(target)], checks, workers=1)
    result = _apply_suppressions(result, suppressions)
    _emit_single(str(target), checks, result, args.format)
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


def _emit_single(
    binary: str, checks: list[int], result: ScanResult, fmt: str
) -> None:
    if fmt == "sarif":
        sys.stdout.write(
            dump_sarif(binary, result.findings, version=blight.__version__)
        )
        sys.stdout.write("\n")
    else:
        output = {
            "binary": binary,
            "checks": checks,
            "findings": [f.to_dict() for f in result.findings],
        }
        json.dump(output, sys.stdout, indent=2)
        sys.stdout.write("\n")


def _emit_directory(
    directory: Path, checks: list[int], results: list[ScanResult], fmt: str
) -> None:
    if fmt == "sarif":
        # One SARIF run per binary keeps each result's artifactLocation correct.
        all_findings = [f for r in results for f in r.findings]
        sys.stdout.write(
            dump_sarif(str(directory), all_findings, version=blight.__version__)
        )
        sys.stdout.write("\n")
    else:
        output = {
            "directory": str(directory),
            "checks": checks,
            "results": [r.to_dict() for r in results],
        }
        json.dump(output, sys.stdout, indent=2)
        sys.stdout.write("\n")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
