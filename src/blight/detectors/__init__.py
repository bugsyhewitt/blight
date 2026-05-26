"""CWE detectors for blight.

Each detector is a small, auditable function that takes an
:class:`~blight.r2.R2Session` and returns a list of
:class:`~blight.findings.Finding`. One CWE class per module.

To add a CWE class: write a ``detect(session) -> list[Finding]`` function in a
new module and register it in :data:`DETECTORS` below.
"""

from __future__ import annotations

from collections.abc import Callable

from blight.findings import Finding
from blight.r2 import R2Session

from . import cwe78, cwe120, cwe134, cwe242

Detector = Callable[[R2Session], list[Finding]]

# Keyed by the integer CWE id the CLI accepts via --checks.
DETECTORS: dict[int, Detector] = {
    78: cwe78.detect,
    120: cwe120.detect,
    134: cwe134.detect,
    242: cwe242.detect,
}

__all__ = ["DETECTORS", "Detector"]
