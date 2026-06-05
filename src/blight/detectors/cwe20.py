"""CWE-20: Improper Input Validation — unsafe ASCII-to-numeric conversion.

Flags call sites to ``atoi``, ``atol``, ``atoll``, ``atof``, and ``atoq``
(the BSD/glibc alias for ``atoll``). These functions offer **no error
detection**: when the string is out of range they silently return a clamped or
undefined value without setting ``errno`` and without providing any signal to
the caller that parsing failed. They are the textbook example of "you must
validate your input before this call, and there is no feedback if you forgot."

This is a *pure PLT-lookup* detector — any call site to one of these symbols
is a finding. No data-flow context is needed; the symbol is the evidence.

The safe alternatives are ``strtol`` / ``strtoul`` / ``strtoll`` / ``strtoull``
/ ``strtod`` / ``strtof`` / ``strtold`` (all set ``errno`` and expose the end
pointer), or ``sscanf`` with explicit range validation. Use one of those
instead.

CWE-20 is ranked #5 in the MITRE CWE Top 25 Most Dangerous Software Weaknesses
(2025 edition), making this one of the highest-value unimplemented checks
available to a PLT-only static analysis tool.
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 20

# Each entry: symbol -> (severity, human-readable finding text).
# All ato* functions carry MEDIUM severity: the call site is the indicator,
# but not all callers handle security-sensitive input, so the confidence is
# medium rather than high (matching the CWE-676 / CWE-242 policy for
# "potentially dangerous" as opposed to "categorically unusable").
_UNSAFE_PARSERS: dict[str, tuple[str, str]] = {
    "atoi": (
        "MEDIUM",
        "atoi() silently overflows on out-of-range input; use strtol() with errno",
    ),
    "atol": (
        "MEDIUM",
        "atol() silently overflows on out-of-range input; use strtol() with errno",
    ),
    "atoll": (
        "MEDIUM",
        "atoll() silently overflows on out-of-range input; use strtoll() with errno",
    ),
    "atof": (
        "MEDIUM",
        "atof() silently returns ±HUGE_VAL on overflow; use strtod() with errno",
    ),
    "atoq": (
        "MEDIUM",
        "atoq() (BSD atoll alias) silently overflows; use strtoll() with errno",
    ),
}

UNSAFE_PARSERS = tuple(_UNSAFE_PARSERS)

# Map the per-symbol severity to a triage confidence label. The PLT match is
# always certain (the symbol is the finding), so confidence here reflects how
# strongly the call warrants immediate action — matching CWE-676 policy.
_CONFIDENCE_FOR_SEVERITY = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def detect(session) -> list[Finding]:
    findings: list[Finding] = []
    for symbol, xref in call_sites(session, UNSAFE_PARSERS):
        severity, message = _UNSAFE_PARSERS[symbol]
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
