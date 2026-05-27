"""blight command-line interface.

Usage:
    blight --binary path/to/elf --checks all --format json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import blight
from blight.detectors import DETECTORS
from blight.engine import run_checks
from blight.formatters.sarif import dump_sarif

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
        help="path to the ELF binary to analyze",
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
    return parser


def _resolve_checks(token: str) -> list[int]:
    if token == "all":
        return list(_ALL_CHECKS)
    return [int(token)]


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    binary_path = Path(args.binary)
    if not binary_path.is_file():
        parser.error(f"binary not found: {binary_path}")

    checks = _resolve_checks(args.checks)

    # Imported here so the module imports without radare2/r2pipe present;
    # the unit suite never reaches this line.
    from blight.r2 import Radare2Session

    with Radare2Session(str(binary_path)) as session:
        findings = run_checks(session, checks)

    if args.format == "sarif":
        sys.stdout.write(dump_sarif(str(binary_path), findings, version=blight.__version__))
        sys.stdout.write("\n")
    else:
        output = {
            "binary": str(binary_path),
            "checks": checks,
            "findings": [f.to_dict() for f in findings],
        }
        json.dump(output, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
