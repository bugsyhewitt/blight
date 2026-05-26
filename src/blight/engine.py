"""Analysis engine: run selected detectors over an R2Session."""

from __future__ import annotations

from collections.abc import Iterable

from blight.detectors import DETECTORS
from blight.findings import Finding
from blight.r2 import R2Session


def run_checks(session: R2Session, checks: Iterable[int]) -> list[Finding]:
    """Run the requested CWE checks against ``session``.

    Args:
        session: An open R2Session over the target binary.
        checks: Iterable of CWE ids to run (must be keys of DETECTORS).

    Returns:
        All findings, sorted by (address, cwe) for stable output.
    """
    findings: list[Finding] = []
    for cwe in checks:
        detector = DETECTORS[cwe]
        findings.extend(detector(session))

    findings.sort(key=lambda f: (int(f.address, 16), f.cwe))
    return findings
