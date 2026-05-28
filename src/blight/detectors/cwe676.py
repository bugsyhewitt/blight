"""CWE-676: Use of Potentially Dangerous Function.

Flags calls to libc functions that have no safe call site. Unlike CWE-242
(``gets``/``getpass``, which are categorically unusable), these functions are
"potentially dangerous": the call itself is the finding because each has a
direct, safer replacement and the unsafe variant should not appear in new code.

This is a pure PLT-lookup detector — any call to one of these symbols is
flagged. No data-flow context is needed; the symbol is the evidence.

Covered functions:

* ``tmpnam`` / ``mktemp`` — TOCTOU race condition; use ``mkstemp``.
* ``strtok`` — non-reentrant (static state); use ``strtok_r``.
* ``asctime`` / ``ctime`` — non-reentrant (static buffer); use ``*_r`` forms.
* ``rand`` — predictable PRNG; use ``getrandom`` for security-sensitive values.
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 676

# Each entry: symbol -> (severity, human-readable finding text).
# Severity is surfaced in the evidence string since the Finding model carries
# no dedicated severity field.
_DANGEROUS = {
    "tmpnam": ("HIGH", "Use of tmpnam() has race condition; use mkstemp()"),
    "mktemp": ("HIGH", "Use of mktemp() has race condition; use mkstemp()"),
    "strtok": ("MEDIUM", "Use of non-reentrant strtok(); use strtok_r()"),
    "asctime": ("LOW", "Use of non-reentrant asctime(); use asctime_r()"),
    "ctime": ("LOW", "Use of non-reentrant ctime(); use ctime_r()"),
    "rand": ("MEDIUM", "Use of predictable PRNG rand(); use getrandom() for security"),
}

DANGEROUS = tuple(_DANGEROUS)

# Map the per-symbol severity to a triage confidence label. The PLT match is
# always certain (the symbol is the finding), so confidence here reflects how
# strongly the call warrants action, mirroring the documented severity.
_CONFIDENCE_FOR_SEVERITY = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def detect(session) -> list[Finding]:
    findings: list[Finding] = []
    for symbol, xref in call_sites(session, DANGEROUS):
        severity, message = _DANGEROUS[symbol]
        findings.append(
            Finding(
                cwe=CWE,
                function=xref.function,
                address=hex(xref.from_addr),
                evidence=f"[{severity}] call to {symbol}: {message}",
                symbol=symbol,
                confidence=_CONFIDENCE_FOR_SEVERITY[severity],
            )
        )
    return findings
