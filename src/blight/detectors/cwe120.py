"""CWE-120: Buffer Copy without Checking Size of Input.

Flags calls to the classic unchecked-copy primitives: ``strcpy``, ``sprintf``,
and ``gets``. Each call site is a finding — these functions copy without a
size bound, so their mere presence is the pattern.
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 120

# Unchecked-copy primitives. ``strcat`` is intentionally omitted from v0.1 to
# keep the detector tight and false-positive-free on the documented classes.
DANGEROUS = ("strcpy", "sprintf", "gets")

_DESCRIPTIONS = {
    "strcpy": "strcpy copies without a destination size bound",
    "sprintf": "sprintf writes a formatted string without a size bound",
    "gets": "gets reads input without any size bound",
}


def detect(session) -> list[Finding]:
    findings: list[Finding] = []
    for symbol, xref in call_sites(session, DANGEROUS):
        findings.append(
            Finding(
                cwe=CWE,
                function=xref.function,
                address=hex(xref.from_addr),
                evidence=f"call to {symbol}: {_DESCRIPTIONS[symbol]}",
                symbol=symbol,
            )
        )
    return findings
