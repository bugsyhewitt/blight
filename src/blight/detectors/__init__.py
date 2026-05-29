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

from . import (
    cwe22,
    cwe78,
    cwe89,
    cwe119,
    cwe120,
    cwe134,
    cwe242,
    cwe252,
    cwe295,
    cwe327,
    cwe426,
    cwe476,
    cwe676,
    cwe798,
)

Detector = Callable[[R2Session], list[Finding]]

# Keyed by the integer CWE id the CLI accepts via --checks.
DETECTORS: dict[int, Detector] = {
    22: cwe22.detect,
    78: cwe78.detect,
    89: cwe89.detect,
    119: cwe119.detect,
    120: cwe120.detect,
    134: cwe134.detect,
    242: cwe242.detect,
    252: cwe252.detect,
    295: cwe295.detect,
    327: cwe327.detect,
    426: cwe426.detect,
    476: cwe476.detect,
    676: cwe676.detect,
    798: cwe798.detect,
}

__all__ = ["DETECTORS", "Detector"]
