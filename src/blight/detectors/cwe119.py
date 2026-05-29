"""CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer.

Flags calls to the memory-copy / concatenation primitives whose safe use depends
entirely on the caller having already computed a correct size bound. Unlike the
CWE-120 set (``strcpy`` / ``sprintf`` / ``gets``), which have no size argument at
all and so are *always* unbounded, the CWE-119 set is more nuanced:

* ``memcpy`` / ``memmove`` / ``bcopy`` take an explicit length, but the length is
  routinely an attacker-influenced value or a miscomputed ``sizeof`` — the
  canonical "the size argument was wrong" overflow. The call site is where an
  out-of-bounds write lands when the length exceeds the destination capacity.
* ``strcat`` / ``wcscat`` append onto a destination with no awareness of its
  remaining capacity — a classic unbounded concatenation overflow. CWE-120
  deliberately omits ``strcat`` to stay tight on the copy primitives; it belongs
  to this broader memory-bounds class.
* ``strncat`` / ``wcsncat`` take a count, but it is the number of bytes read from
  the *source*, NOT the space left in the destination — an off-by-one
  (the implicit NUL terminator) and a routinely-misunderstood bound, so it is
  flagged at MEDIUM as a "confirm the bound is destination-relative" prompt.
* ``stpcpy`` / ``wcscpy`` are unbounded copies (no size argument) — HIGH, same
  shape as ``strcpy``.
* ``alloca`` allocates on the stack with a caller-supplied size; an unconstrained
  or attacker-influenced size is a stack-clash / stack-exhaustion primitive, so a
  call is surfaced at MEDIUM for review.

This is a pure PLT-lookup detector — the same shape as CWE-89, CWE-327, CWE-295
and CWE-676. It deliberately does **not** read the length argument out of the
disassembly to prove it is non-constant. The size argument arrives in different
registers across the functions, is frequently computed across basic blocks, and
the high-value signal — "this binary performs raw bounded/unbounded memory copies,
so a reviewer must confirm every length is destination-clamped" — is already
carried by the presence of the call. Reading the argument would require
per-function, per-architecture data flow for marginal precision gain, so the call
to a memory-bounds-sensitive routine is itself the finding, surfaced at the
per-symbol confidence for triage.

The bounded counterparts (``strlcpy`` / ``strlcat`` / ``snprintf``) are the safe
pattern and are NOT flagged — flagging them would invert the signal.

The severity is surfaced in the evidence string (as for CWE-89 / CWE-327 /
CWE-676 / CWE-295), since the Finding model carries no dedicated severity field.
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 119

# Each entry: symbol -> (severity, human-readable finding text).
# Severity is surfaced in the evidence string since the Finding model carries
# no dedicated severity field.
_RISKY = {
    # --- explicit-length copies (length is routinely wrong) ----------------
    "memcpy": (
        "HIGH",
        "memcpy copies a caller-supplied length — confirm the length cannot "
        "exceed the destination size; a wrong length is an out-of-bounds write",
    ),
    "memmove": (
        "HIGH",
        "memmove copies a caller-supplied length — confirm the length cannot "
        "exceed the destination size; a wrong length is an out-of-bounds write",
    ),
    "bcopy": (
        "HIGH",
        "bcopy copies a caller-supplied length (legacy) — confirm the length is "
        "destination-bounded; prefer memmove with a validated size",
    ),
    # --- unbounded copies (no size argument at all) -----------------------
    "stpcpy": (
        "HIGH",
        "stpcpy copies without a destination size bound — use a bounded copy "
        "(strlcpy) with the destination capacity",
    ),
    "wcscpy": (
        "HIGH",
        "wcscpy copies a wide string without a destination size bound — use a "
        "bounded copy (wcslcpy / wcsncpy with an explicit cap)",
    ),
    # --- unbounded concatenation ------------------------------------------
    "strcat": (
        "HIGH",
        "strcat appends with no awareness of the destination's remaining "
        "capacity — use strlcat with the destination size",
    ),
    "wcscat": (
        "HIGH",
        "wcscat appends a wide string with no destination-capacity check — use "
        "a bounded concatenation with the destination size",
    ),
    # --- count-bounded but routinely-misused ------------------------------
    "strncat": (
        "MEDIUM",
        "strncat's count is the bytes read from the source, NOT the destination "
        "space remaining (plus an implicit NUL) — confirm the bound is "
        "destination-relative; prefer strlcat",
    ),
    "wcsncat": (
        "MEDIUM",
        "wcsncat's count is source-relative, NOT destination space remaining — "
        "confirm the bound accounts for the destination capacity and terminator",
    ),
    "alloca": (
        "MEDIUM",
        "alloca allocates a caller-supplied size on the stack — an unconstrained "
        "or attacker-influenced size is a stack-clash primitive; use a bounded "
        "heap allocation or a fixed stack buffer",
    ),
}

RISKY = tuple(_RISKY)

# Map the per-symbol severity to a triage confidence label. The PLT match is
# always certain (the symbol is the finding); confidence reflects how strongly
# the call warrants action — unbounded or wrong-length copies are HIGH, the
# count-bounded-but-misused routines (which CAN be used correctly) are MEDIUM.
# Same policy as CWE-89 / CWE-327 / CWE-295 / CWE-676.
_CONFIDENCE_FOR_SEVERITY = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def detect(session) -> list[Finding]:
    findings: list[Finding] = []
    for symbol, xref in call_sites(session, RISKY):
        severity, message = _RISKY[symbol]
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
