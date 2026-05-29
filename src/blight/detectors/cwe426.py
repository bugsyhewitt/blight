"""CWE-426: Untrusted Search Path.

Flags call sites to routines that resolve a *program* or a *shared object* by
consulting an externally controllable search path — ``$PATH`` for process
launchers, the dynamic-loader search path (``LD_LIBRARY_PATH``, ``rpath``,
``$ORIGIN``, the current working directory, …) for library loaders. When the
search path is attacker-influenceable, even a call with a perfectly *constant*
program/library name can be hijacked: a malicious ``ls`` earlier in ``$PATH``,
a planted ``libfoo.so`` in the CWD, or an ``LD_LIBRARY_PATH`` entry the attacker
controls all redirect the call to attacker code.

This is a *pure PLT-lookup* detector — the call to a search-path-resolving
routine is itself the finding. Unlike CWE-78 (OS command injection), which
inspects the command *argument* to decide whether it is non-constant, CWE-426 is
about the *resolution mechanism*: the weakness is present even with a constant
name, because the attack vector is the search path, not the argument. The two
detectors are complementary — a single ``execvp("ls", …)`` call site can carry a
CWE-426 finding (PATH search) without a CWE-78 finding (constant command), and a
``system(buf)`` call site can carry both.

Covered routines (grouped by mechanism, with the safe alternative):

* Dynamic-loader search path — ``dlopen`` / ``dlmopen`` (HIGH). When the name
  argument is a bare filename (no ``/``) the loader walks ``LD_LIBRARY_PATH``,
  the ``DT_RUNPATH``/``DT_RPATH`` entries (which may contain ``$ORIGIN`` or a
  writable directory) and the default cache. Load shared objects by absolute
  path, or with ``RTLD_DEEPBIND`` / a hardened, non-writable ``rpath`` — never a
  bare name.
* ``$PATH``-searching process launchers — ``execlp`` / ``execvp`` / ``execvpe``
  (HIGH; the trailing ``p`` is the search-path resolution) and ``popen`` /
  ``system`` (HIGH; both invoke ``/bin/sh -c``, which resolves the program via
  ``$PATH``). Use the explicit-path forms (``execv`` / ``execve`` /
  ``posix_spawn`` with an absolute path) and a sanitised environment.

The non-``p`` exec forms (``execl`` / ``execv`` / ``execle`` / ``execve``) take
an explicit pathname and do **not** consult ``$PATH``, so they are deliberately
**not** flagged here (a path-traversal concern on their argument is CWE-22's
remit, and a non-constant command is CWE-78's). Flagging them would invert the
signal — they are the recommended replacement for the ``p`` forms.

The per-symbol severity is surfaced in the evidence string and mapped to the
triage confidence label, mirroring the CWE-676 / CWE-327 policy.
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 426

# Each entry: symbol -> (severity, human-readable finding text).
# Severity is surfaced in the evidence string since the Finding model carries
# no dedicated severity field.
_SEARCH_PATH = {
    # --- Dynamic-loader search path (library hijack / preload) -------------
    "dlopen": (
        "HIGH",
        "dlopen() resolves a bare name via LD_LIBRARY_PATH/rpath/$ORIGIN; "
        "load shared objects by absolute path",
    ),
    "dlmopen": (
        "HIGH",
        "dlmopen() resolves a bare name via LD_LIBRARY_PATH/rpath/$ORIGIN; "
        "load shared objects by absolute path",
    ),
    # --- $PATH-searching process launchers --------------------------------
    "execlp": (
        "HIGH",
        "execlp() resolves the program via $PATH; use execv/execve with an "
        "absolute path",
    ),
    "execvp": (
        "HIGH",
        "execvp() resolves the program via $PATH; use execv/execve with an "
        "absolute path",
    ),
    "execvpe": (
        "HIGH",
        "execvpe() resolves the program via $PATH; use execve with an "
        "absolute path",
    ),
    "popen": (
        "HIGH",
        "popen() runs /bin/sh -c, resolving the program via $PATH; use an "
        "absolute path and a sanitised environment",
    ),
    "system": (
        "HIGH",
        "system() runs /bin/sh -c, resolving the program via $PATH; use "
        "execv/execve with an absolute path",
    ),
}

SEARCH_PATH = tuple(_SEARCH_PATH)

# Map the per-symbol severity to a triage confidence label. The PLT match is
# always certain (the symbol is the finding), so confidence here reflects how
# strongly the call warrants action, mirroring the documented severity — the
# same policy as CWE-676 / CWE-327.
_CONFIDENCE_FOR_SEVERITY = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def detect(session) -> list[Finding]:
    findings: list[Finding] = []
    for symbol, xref in call_sites(session, SEARCH_PATH):
        severity, message = _SEARCH_PATH[symbol]
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
