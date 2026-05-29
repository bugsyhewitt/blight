"""CWE-22: Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal").

Flags call sites to filesystem routines that consume a *pathname* — the sinks
where a path-traversal vulnerability lands. If the path is assembled from
untrusted input (a request parameter, an archive entry name, an environment
variable) and is not first canonicalised and confined to an intended base
directory, an attacker can reach files outside it with ``../`` sequences (or
absolute paths). The call to the path-consuming routine is the exact spot a
reviewer must inspect to confirm the path is validated.

This is a pure PLT-lookup detector — the same shape as CWE-78, CWE-89, CWE-119,
CWE-327, CWE-295 and CWE-676. It deliberately does **not** read the path
argument out of the disassembly to prove it is non-constant or attacker-derived:
the pathname arrives in different argument positions across these routines
(``open``'s path is the first argument, ``openat``'s is the second, ``rename``
takes two paths), is frequently built across basic blocks via ``snprintf`` /
``strcat`` / ``realpath``, and the high-value signal — "this binary opens /
deletes / links files by name, so a reviewer must confirm every such path is
canonicalised and confined" — is already carried by the presence of the call.
Reading the argument would require per-routine, per-architecture data flow for
marginal precision gain, so the call to a path-consuming routine is itself the
finding, surfaced at the per-symbol confidence for triage.

Two severity tiers, mirroring the policy of the other PLT detectors:

* **HIGH** — routines that *destroy*, *replace* or *escalate* via a pathname:
  ``unlink`` / ``remove`` / ``rmdir`` (delete), ``rename`` (move/overwrite),
  ``symlink`` / ``link`` (create a link, the classic ``../`` + symlink combo),
  ``chmod`` / ``chown`` (change permissions/ownership of an attacker-chosen
  path), ``mkdir`` (create a directory at an attacker-chosen path), and the
  exec-by-path family ``execv`` / ``execve`` / ``execvp`` (run a binary chosen
  by a traversable path). A wrong path here is an immediate, irreversible
  effect.

* **MEDIUM** — routines that *open* / *read metadata for* a pathname:
  ``open`` / ``openat`` / ``fopen`` / ``freopen`` / ``creat`` (open a file by
  name — the canonical traversal read/write sink), ``opendir`` (list a
  directory), ``access`` / ``stat`` / ``lstat`` (test a path — also a TOCTOU
  hint), and ``readlink`` (resolve a link target). These are flagged MEDIUM
  because the very same routines appear in benign, fully-validated code; the
  call is a *triage* signal, not a confirmed bug.

The *canonicalisation* primitive ``realpath`` is deliberately **not** flagged —
it is part of the recommended mitigation (resolve, then verify the result is
under the intended base directory), and flagging it would invert the signal.
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 22

# Each entry: symbol -> (severity, human-readable finding text).
# Severity is surfaced in the evidence string since the Finding model carries
# no dedicated severity field.
_PATH_SINKS = {
    # --- HIGH: destructive / privilege / exec by pathname -----------------
    "unlink": (
        "HIGH",
        "unlink deletes a file by path — confirm the path is canonicalised "
        "(realpath) and confined to an intended base directory",
    ),
    "unlinkat": (
        "HIGH",
        "unlinkat deletes a path relative to a directory fd — confirm the "
        "pathname is canonicalised and confined to an intended base directory",
    ),
    "remove": (
        "HIGH",
        "remove deletes a file/directory by path — confirm the path is "
        "canonicalised (realpath) and confined to an intended base directory",
    ),
    "rmdir": (
        "HIGH",
        "rmdir deletes a directory by path — confirm the path is canonicalised "
        "and confined to an intended base directory",
    ),
    "rename": (
        "HIGH",
        "rename moves/overwrites by path — confirm both paths are canonicalised "
        "and confined to an intended base directory",
    ),
    "symlink": (
        "HIGH",
        "symlink creates a link by path (classic ../-plus-symlink escape) — "
        "confirm the target/link paths are canonicalised and confined",
    ),
    "link": (
        "HIGH",
        "link creates a hard link by path — confirm both paths are "
        "canonicalised and confined to an intended base directory",
    ),
    "chmod": (
        "HIGH",
        "chmod changes permissions of a path — confirm the path is "
        "canonicalised and confined to an intended base directory",
    ),
    "chown": (
        "HIGH",
        "chown changes ownership of a path — confirm the path is canonicalised "
        "and confined to an intended base directory",
    ),
    "lchown": (
        "HIGH",
        "lchown changes ownership of a link path — confirm the path is "
        "canonicalised and confined to an intended base directory",
    ),
    "mkdir": (
        "HIGH",
        "mkdir creates a directory at a path — confirm the path is "
        "canonicalised and confined to an intended base directory",
    ),
    "execv": (
        "HIGH",
        "execv runs a binary chosen by path — confirm the path is canonicalised "
        "and confined; a traversable path selects an attacker-chosen binary",
    ),
    "execve": (
        "HIGH",
        "execve runs a binary chosen by path — confirm the path is canonicalised "
        "and confined; a traversable path selects an attacker-chosen binary",
    ),
    "execvp": (
        "HIGH",
        "execvp runs a binary chosen by path/PATH — confirm the path is "
        "canonicalised and confined to an intended location",
    ),
    # --- MEDIUM: open / read-metadata by pathname -------------------------
    "open": (
        "MEDIUM",
        "open opens a file by path — confirm the path is canonicalised "
        "(realpath) and confined to an intended base directory before opening",
    ),
    "open64": (
        "MEDIUM",
        "open64 opens a file by path — confirm the path is canonicalised and "
        "confined to an intended base directory before opening",
    ),
    "openat": (
        "MEDIUM",
        "openat opens a path relative to a directory fd — confirm the pathname "
        "cannot escape the intended base directory with ../",
    ),
    "fopen": (
        "MEDIUM",
        "fopen opens a file by path — confirm the path is canonicalised "
        "(realpath) and confined to an intended base directory before opening",
    ),
    "fopen64": (
        "MEDIUM",
        "fopen64 opens a file by path — confirm the path is canonicalised and "
        "confined to an intended base directory before opening",
    ),
    "freopen": (
        "MEDIUM",
        "freopen reopens a stream on a path — confirm the path is canonicalised "
        "and confined to an intended base directory",
    ),
    "creat": (
        "MEDIUM",
        "creat creates/truncates a file by path — confirm the path is "
        "canonicalised and confined to an intended base directory",
    ),
    "opendir": (
        "MEDIUM",
        "opendir lists a directory by path — confirm the path is canonicalised "
        "and confined to an intended base directory",
    ),
    "access": (
        "MEDIUM",
        "access tests a path (also a TOCTOU hint) — confirm the path is "
        "canonicalised and confined to an intended base directory",
    ),
    "stat": (
        "MEDIUM",
        "stat reads metadata for a path — confirm the path is canonicalised "
        "and confined to an intended base directory",
    ),
    "lstat": (
        "MEDIUM",
        "lstat reads metadata for a link path — confirm the path is "
        "canonicalised and confined to an intended base directory",
    ),
    "readlink": (
        "MEDIUM",
        "readlink resolves a link target by path — confirm the path is "
        "canonicalised and confined to an intended base directory",
    ),
}

PATH_SINKS = tuple(_PATH_SINKS)

# Map the per-symbol severity to a triage confidence label. The PLT match is
# always certain (the symbol is the finding); confidence reflects how strongly
# the call warrants action — destructive/exec-by-path sinks are HIGH, the
# open/read-metadata sinks (which appear routinely in fully-validated code) are
# MEDIUM. Same policy as CWE-89 / CWE-327 / CWE-295 / CWE-676.
_CONFIDENCE_FOR_SEVERITY = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def detect(session) -> list[Finding]:
    findings: list[Finding] = []
    for symbol, xref in call_sites(session, PATH_SINKS):
        severity, message = _PATH_SINKS[symbol]
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
