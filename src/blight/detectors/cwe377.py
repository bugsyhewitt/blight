"""CWE-377: Insecure Temporary File.

Flags call sites to libc routines that create temporary *files* (or reserve
temporary *filenames* in a file-creating idiom) through historically insecure
mechanisms. These are distinct from the ``tmpnam`` / ``mktemp`` pair already
flagged by CWE-676 (which is "use of inherently dangerous function" more
broadly): CWE-377 is the *insecure-temp-file* class — the weakness is the
combination of a predictable name and a non-atomic creation step, which an
attacker who can write the temp directory can race or pre-create with a
symlink, redirecting the privileged program's write into an attacker-chosen
target.

This is a *pure PLT-lookup* detector — the same shape as CWE-22 / CWE-89 /
CWE-119 / CWE-295 / CWE-327 / CWE-362 / CWE-426 / CWE-676 / CWE-732. The call
to one of the insecure temp-file primitives is itself the finding; the detector
does not (and need not) read any argument out of the disassembly, because:

* the temp-file weakness is intrinsic to the function — ``tempnam`` returns a
  predictable name regardless of any argument it is handed, ``tmpfile`` /
  ``tmpfile64`` open a temporary file through a libc-internal name-generation
  scheme the caller cannot make safe from the outside, and ``tmpnam_r`` is the
  reentrant sibling of ``tmpnam`` with the same TOCTOU race window; and
* the high-value triage signal — "this binary creates temporary files through
  a primitive that is unsafe by construction; replace with ``mkstemp`` /
  ``mkostemp`` (an atomic ``open`` with ``O_CREAT|O_EXCL``) or use
  ``O_TMPFILE`` explicitly relative to a trusted dirfd" — is already carried by
  the presence of the call.

Two severity tiers:

* **HIGH** — ``tempnam`` and ``tmpnam_r`` return a unique *name* but do not
  open the file. The caller must then ``open(name, O_CREAT, ...)``, opening a
  TOCTOU window in which an attacker who can write the parent directory swaps
  the name for a symlink before the ``open`` runs. The Linux ``tempnam(3)``
  manual page literally says "Never use this function. Use ``mkstemp(3)`` or
  ``tmpfile(3)`` instead.". ``tmpnam_r`` is the reentrant form of ``tmpnam``
  and carries the same race window — flagging both here keeps CWE-377 the
  single home for the temp-file-creation race class while CWE-676 keeps the
  legacy (and identically unsafe) ``tmpnam`` / ``mktemp`` flagged as
  inherently-dangerous-function for the broader audit story.
* **MEDIUM** — ``tmpfile`` and ``tmpfile64`` *do* atomically open a temp file
  and so on modern glibc with kernel ``O_TMPFILE`` support are essentially
  safe, but on legacy glibc fallback paths and on a number of embedded /
  alternative libcs (uClibc-ng, older musl pre-1.2, BSD) ``tmpfile`` is
  implemented in terms of ``mkstemp`` against the ``P_tmpdir`` template, which
  inherits ``mkstemp``'s long-standing template-permission concerns and races
  if ``TMPDIR`` is attacker-controlled. The MEDIUM tier is the "audit-and-
  confirm" signal: confirm the target libc takes the ``O_TMPFILE`` fast path,
  or migrate to an explicit ``open(dir, O_TMPFILE|O_RDWR, 0600)`` against a
  trusted dirfd.

The *safe* replacements ``mkstemp`` / ``mkostemp`` / ``mkstemps`` /
``mkostemps`` / ``mkdtemp`` and the explicit ``open`` + ``O_TMPFILE`` /
``O_EXCL`` idiom are deliberately **not** flagged — they are the recommended
mitigation and flagging them would invert the signal. Confidence mirrors the
per-symbol severity (HIGH → ``high``, MEDIUM → ``medium``) since the PLT match
is certain: the symbol is the finding and the severity reflects how strongly
the call warrants action.

This detector is architecture-agnostic (works on every arch radare2 can
disassemble) and requires no new infrastructure on top of the shared
``_common.call_sites`` helper. Deliberately distinct from CWE-676 (which is
``tmpnam`` / ``mktemp`` plus the broader inherently-dangerous-function family
``strtok`` / ``asctime`` / ``ctime`` / ``rand``): the two detectors are
complementary — CWE-676 is "this function should not appear in new code at
all", CWE-377 is "this is the *insecure temp file* class specifically". A
``tmpnam`` call site is therefore not double-flagged here — CWE-676 already
owns it.
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 377

# Each entry: symbol -> (severity, human-readable finding text).
# Severity is surfaced in the evidence string since the Finding model carries
# no dedicated severity field.
_INSECURE_TEMP = {
    "tempnam": (
        "HIGH",
        "tempnam() returns a predictable name; the caller's open(O_CREAT) is a "
        "TOCTOU window — use mkstemp()",
    ),
    "tmpnam_r": (
        "HIGH",
        "tmpnam_r() returns a predictable name; the caller's open(O_CREAT) is a "
        "TOCTOU window — use mkstemp()",
    ),
    "tmpfile": (
        "MEDIUM",
        "tmpfile() relies on libc-internal name generation; on legacy/embedded "
        "libcs this falls back to mkstemp against P_tmpdir — confirm O_TMPFILE "
        "fast path or use open(dir, O_TMPFILE, 0600)",
    ),
    "tmpfile64": (
        "MEDIUM",
        "tmpfile64() shares tmpfile()'s name-generation fallback on legacy "
        "libcs — confirm O_TMPFILE fast path or use open(dir, O_TMPFILE, 0600)",
    ),
}

INSECURE_TEMP = tuple(_INSECURE_TEMP)

# Map the per-symbol severity to a triage confidence label. The PLT match is
# always certain (the symbol is the finding), so confidence here reflects how
# strongly the call warrants action, mirroring the documented severity.
_CONFIDENCE_FOR_SEVERITY = {
    "HIGH": "high",
    "MEDIUM": "medium",
}


def detect(session) -> list[Finding]:
    findings: list[Finding] = []
    for symbol, xref in call_sites(session, INSECURE_TEMP):
        severity, message = _INSECURE_TEMP[symbol]
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
