"""Pipeline adapter: expose blight as a BinaryAnalyzer for binary-pipeline.

Wraps blight's :func:`~blight.engine.run_checks` + radare2 session into the
:class:`~binary_pipeline.BinaryAnalyzer` protocol so embalmer (or any other
orchestrator using ``binary-pipeline``) can call blight as a Python-API
analyzer rather than through a subprocess.

Usage::

    from pathlib import Path
    from blight.pipeline_adapter import analyze_binary

    findings = analyze_binary(Path("/path/to/target"))
    # returns list[BinaryFinding] from binary-finding-schema

This module is r2pipe-free at import time: the radare2 session is only opened
when :func:`analyze_binary` is actually called.
"""

from __future__ import annotations

from pathlib import Path

from binary_finding_schema import BinaryFinding

from blight.detectors import DETECTORS
from blight.findings import Finding


def analyze_binary(binary: Path) -> list[BinaryFinding]:
    """Analyze ``binary`` using blight/radare2 and return canonical BinaryFindings.

    Implements the :class:`~binary_pipeline.BinaryAnalyzer` protocol:
    ``(Path) -> list[BinaryFinding]``.

    Runs all supported CWE detectors (78, 120, 242). If radare2 or r2pipe is
    not available, a :class:`ImportError` or :class:`RuntimeError` will
    propagate to the caller.

    Args:
        binary: Path to the target ELF binary.

    Returns:
        List of :class:`~binary_finding_schema.BinaryFinding` objects, sorted
        by (address, cwe). Empty list if no findings.
    """
    # Lazy import keeps module top level r2pipe-free.
    from blight.r2 import Radare2Session
    from blight.engine import run_checks

    checks = list(DETECTORS)
    with Radare2Session(str(binary)) as session:
        findings = run_checks(session, checks)

    return [_to_binary_finding(f) for f in findings]


def _to_binary_finding(finding: Finding) -> BinaryFinding:
    """Convert a blight :class:`~blight.findings.Finding` to a BinaryFinding."""
    return BinaryFinding(
        cwe_id=f"CWE-{finding.cwe}",
        function=finding.function,
        address=finding.address,
        evidence=finding.evidence,
        symbol=finding.symbol,
        confidence=finding.confidence,
    )
