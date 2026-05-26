"""Finding data model for blight.

A Finding is a single detected CWE pattern in a binary. The JSON shape is the
public contract (see README and v0.1 criteria): every finding carries
``cwe``, ``function``, ``address``, and ``evidence``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    """One detected CWE pattern.

    Attributes:
        cwe: CWE identifier as an integer (e.g. 120).
        function: Name of the function containing the call site.
        address: Hex string of the call-site address (e.g. "0x40114f").
        evidence: Human-readable explanation of why this was flagged.
        symbol: The dangerous library symbol involved (e.g. "strcpy").
    """

    cwe: int
    function: str
    address: str
    evidence: str
    symbol: str

    def to_dict(self) -> dict:
        return asdict(self)
