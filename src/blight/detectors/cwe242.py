"""CWE-242: Use of Inherently Dangerous Function.

Flags calls to functions that cannot be used safely under any circumstances.
The canonical member is ``gets``; we also flag ``getpass`` (deprecated, no
bound on the returned buffer in historical implementations).
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 242

# Inherently dangerous: no safe usage exists.
DANGEROUS = ("gets", "getpass")

_DESCRIPTIONS = {
    "gets": "gets cannot be used safely and was removed from C11",
    "getpass": "getpass is obsolete and returns an unbounded static buffer",
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
