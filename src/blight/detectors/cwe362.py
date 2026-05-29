"""CWE-362: Concurrent Execution using Shared Resource with Improper
Synchronization ('Race Condition') — the filesystem TOCTOU check-then-use class.

Flags call sites to the classic *check* primitives whose result is used to make
a security decision about a filesystem path — ``access`` / ``faccessat``, the
``euidaccess`` / ``eaccess`` variants, and the ``stat`` family
(``stat`` / ``lstat`` / ``fstatat`` / ``stat64`` / ``lstat64``). The textbook
TOCTOU (time-of-check-to-time-of-use) bug is:

    if (access("/tmp/x", W_OK) == 0)   /* CHECK — by path */
        fd = open("/tmp/x", O_WRONLY); /* USE   — by the same path */

Between the check and the use an attacker who can influence the namespace
(a writable parent directory, a predictable temp name) swaps the path for a
symlink to a file they could not otherwise reach. The privileged program then
operates on the attacker's target. The race window is the weakness, and it is
present *regardless of the path argument's provenance* — even a perfectly
constant path is exploitable when the containing directory is attacker-writable.

This is a *pure PLT-lookup* detector — the same shape as CWE-22 / CWE-426 /
CWE-676. The call to a check-by-path primitive is itself the finding; the
detector does not (and need not) prove that a matching use-by-path call follows,
because:

* the check and the use are frequently in different functions / basic blocks,
  so a same-block pairing heuristic would miss the common case and add false
  negatives without removing real ones, and
* the high-value triage signal — "this binary makes access/permission decisions
  by *path*; confirm every one is converted to an fd-based check
  (``open`` then ``fstat`` / ``faccessat(AT_EMPTY_PATH)``) or made atomic
  (``O_NOFOLLOW`` / ``openat`` relative to a trusted dirfd)" — is already
  carried by the presence of the check call.

This is the complement of CWE-22 (path traversal): CWE-22 also lists ``access``
/ ``stat`` as MEDIUM path-consuming sinks, but for a *different* reason — there
the concern is the path *content* (``../`` escaping a base directory), here it
is the *race window* of using a name twice. A single ``access`` call site can
therefore legitimately carry both findings; they are surfaced under distinct
CWE ids so a reviewer sees both axes of risk.

Covered routines (all MEDIUM — a check-by-path is a *triage* signal, not a
confirmed race; it is benign when the result is not subsequently used as a
security gate or when the directory is not attacker-writable):

* ``access`` / ``faccessat`` — test a path's accessibility with the *real* uid;
  the canonical setuid TOCTOU primitive.
* ``euidaccess`` / ``eaccess`` — the effective-uid variants of the same check.
* ``stat`` / ``lstat`` / ``fstatat`` / ``stat64`` / ``lstat64`` — read a path's
  metadata to decide what to do next, then act on the same path.

The fd-relative / atomic forms (``fstat`` and ``fstatat`` *with*
``AT_EMPTY_PATH`` on an open fd) are not the path-racing shape; ``fstat`` takes
an fd, never a path, so it is deliberately **not** flagged. ``faccessat`` and
``fstatat`` *are* flagged because their common two-argument-path use still
resolves a pathname and races unless an explicit trusted dirfd + ``AT_*`` flag
combination is used — which blight cannot confirm statically, so the call is a
triage signal.

The per-symbol severity is surfaced in the evidence string and mapped to the
triage confidence label, mirroring the CWE-676 / CWE-327 / CWE-426 policy.
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 362

# Each entry: symbol -> (severity, human-readable finding text).
# Every check-by-path primitive is MEDIUM: the call is a triage signal for a
# possible time-of-check-to-time-of-use race, not a confirmed bug, because the
# race only lands when the result gates a later use-by-path on an
# attacker-influenceable name.
_TOCTOU_CHECKS = {
    # --- access(2) family: permission check by path (the classic setuid race)
    "access": (
        "MEDIUM",
        "access() checks a path's accessibility by name; if the result gates a "
        "later open/exec on the same path it is a TOCTOU race — use an fd-based "
        "check (open then fstat / faccessat with a trusted dirfd)",
    ),
    "faccessat": (
        "MEDIUM",
        "faccessat() checks a path by name; unless it uses a trusted dirfd plus "
        "AT_* flags it still races a later use of the same path — confirm the "
        "check and use are atomic",
    ),
    "euidaccess": (
        "MEDIUM",
        "euidaccess() checks a path's accessibility by name; if the result "
        "gates a later use of the same path it is a TOCTOU race — switch to an "
        "fd-based check",
    ),
    "eaccess": (
        "MEDIUM",
        "eaccess() checks a path's accessibility by name; if the result gates a "
        "later use of the same path it is a TOCTOU race — switch to an fd-based "
        "check",
    ),
    # --- stat(2) family: metadata check by path ---------------------------
    "stat": (
        "MEDIUM",
        "stat() reads a path's metadata by name; acting on the same path "
        "afterwards is a TOCTOU race — open the file first, then fstat the fd",
    ),
    "lstat": (
        "MEDIUM",
        "lstat() reads a path's metadata by name; acting on the same path "
        "afterwards is a TOCTOU race — open with O_NOFOLLOW, then fstat the fd",
    ),
    "fstatat": (
        "MEDIUM",
        "fstatat() reads metadata by name; unless it uses a trusted dirfd plus "
        "AT_* flags it still races a later use of the same path — confirm the "
        "check and use are atomic",
    ),
    "stat64": (
        "MEDIUM",
        "stat64() reads a path's metadata by name; acting on the same path "
        "afterwards is a TOCTOU race — open the file first, then fstat the fd",
    ),
    "lstat64": (
        "MEDIUM",
        "lstat64() reads a path's metadata by name; acting on the same path "
        "afterwards is a TOCTOU race — open with O_NOFOLLOW, then fstat the fd",
    ),
}

TOCTOU_CHECKS = tuple(_TOCTOU_CHECKS)

# Map the per-symbol severity to a triage confidence label. The PLT match is
# always certain (the symbol is the finding); confidence reflects how strongly
# the call warrants action, mirroring CWE-676 / CWE-327 / CWE-426.
_CONFIDENCE_FOR_SEVERITY = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def detect(session) -> list[Finding]:
    findings: list[Finding] = []
    for symbol, xref in call_sites(session, TOCTOU_CHECKS):
        severity, message = _TOCTOU_CHECKS[symbol]
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
