"""Finding data model for blight.

A Finding is a single detected CWE pattern in a binary. The JSON shape is the
public contract (see README and v0.1 criteria): every finding carries
``cwe``, ``function``, ``address``, and ``evidence``.

The internal representation delegates to
:class:`binary_finding_schema.BinaryFinding` for validation and canonical
serialization. The :class:`Finding` wrapper preserves the original attribute
names and dict shape that the v0.1 tests and CLI depend on.
"""

from __future__ import annotations

from binary_finding_schema import BinaryFinding


class Finding:
    """One detected CWE pattern.

    Wraps :class:`~binary_finding_schema.BinaryFinding` and exposes the
    blight-native attribute names used throughout the codebase and test suite.

    Attributes:
        cwe: CWE identifier as an integer (e.g. 120).
        function: Name of the function containing the call site.
        address: Hex string of the call-site address (e.g. "0x40114f").
        evidence: Human-readable explanation of why this was flagged.
        symbol: The dangerous library symbol involved (e.g. "strcpy").
    """

    __slots__ = ("_inner",)

    def __init__(
        self,
        *,
        cwe: int,
        function: str,
        address: str,
        evidence: str,
        symbol: str,
    ) -> None:
        self._inner = BinaryFinding(
            cwe_id=f"CWE-{cwe}",
            function=function,
            address=address,
            evidence=evidence,
            symbol=symbol,
        )

    # --- blight-native attribute access ----------------------------------

    @property
    def cwe(self) -> int:
        return int(self._inner.cwe_id[4:])

    @property
    def function(self) -> str:
        return self._inner.function

    @property
    def address(self) -> str:
        return self._inner.address

    @property
    def evidence(self) -> str:
        return self._inner.evidence

    @property
    def symbol(self) -> str:
        return self._inner.symbol  # type: ignore[return-value]

    # --- serialization ---------------------------------------------------

    def to_dict(self) -> dict:
        """Return the blight finding shape: {cwe, function, address, evidence, symbol}."""
        return {
            "cwe": self.cwe,
            "function": self.function,
            "address": self.address,
            "evidence": self.evidence,
            "symbol": self.symbol,
        }

    # --- equality / repr (used by engine sort and test assertions) -------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return (
            self.cwe == other.cwe
            and self.function == other.function
            and self.address == other.address
            and self.evidence == other.evidence
            and self.symbol == other.symbol
        )

    def __hash__(self) -> int:
        return hash((self.cwe, self.function, self.address, self.evidence, self.symbol))

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"Finding(cwe={self.cwe!r}, function={self.function!r}, "
            f"address={self.address!r}, evidence={self.evidence!r}, "
            f"symbol={self.symbol!r})"
        )
