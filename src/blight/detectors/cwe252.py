"""CWE-252: Unchecked Return Value.

Flags call sites to security-sensitive functions whose return value is never
inspected before it is discarded. The classic bug class: a program calls
``setuid(0)`` to drop privileges, the call fails (e.g. EAGAIN under an rlimit),
the program ignores the non-zero return, and continues running with elevated
privileges. The same shape causes silent data loss for ``write``/``fwrite``
short writes and ``fclose`` flush failures.

This is the inverse of the CWE-476 (NULL deref) pattern: instead of a *use*
without a *check*, CWE-252 is a *discard* without a *check*. The detector is a
deliberately conservative single-function forward linear scan (no CFG
reconstruction, no inter-procedural analysis — those remain out of scope, per
POST_V01 item 7). It answers one question per call site:

  After the call, is the return register *read* (tested, compared, moved, stored,
  or passed onward) before it is *clobbered* (overwritten by an unrelated value)
  or the function returns?

  * If the return register is read first → the value was used → NOT flagged.
  * If the return register is clobbered first, or the function ends without the
    value ever being read → the return was discarded → flagged.

The return value of a C function arrives in ``rax`` (with ``eax``/``ax``
sub-register views) on x86_64 and ``x0`` (with ``w0``) on AArch64. A *read* is
any instruction that names the return register as a source operand — a
``test rax, rax`` / ``cmp eax, 0`` guard, a ``mov rbx, rax`` save, a
``mov [rbp-8], rax`` store, or its use as an outgoing argument. A *clobber* is
an instruction that writes the return register from a source that does not
reference it (a fresh ``mov eax, 0``, a ``xor eax, eax``, a following ``call``
that returns into ``rax``, or ``lea``/``movzx`` into it).

Because proving the call can actually fail on the reached path needs
inter-procedural reasoning, every finding is ``low`` confidence — matching the
POST_V01 ranking for this CWE.

[Worker decision: scoped to an in-function, post-call linear scan tracking only
the return register and its sub-register aliases. The function set is restricted
to calls whose result is *security- or integrity-relevant* (privilege changes,
sandbox entry, durable writes) so the false-positive rate stays bounded — a
program legitimately ignores plenty of return values, but ignoring these
specific ones is the documented bug class. A subsequent ``call`` before any read
clobbers the return register (the new callee's return overwrites it) and counts
as a discard. Architecture-aware on x86_64 and AArch64, consistent with
POST_V01 item 5.]
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._argregs import DEFAULT_ARCH
from ._common import call_sites

CWE = 252

# Functions whose return value carries security or data-integrity meaning, so
# discarding it is a recognized bug class (privilege-drop bypass, sandbox-entry
# bypass, silent data loss). Keyed to the cwe_checker CWE-252 function set plus
# the canonical CERT ERR33-C / POS54-C examples.
DANGEROUS = (
    # Privilege / identity changes — ignoring failure = privilege not dropped.
    "setuid",
    "setgid",
    "seteuid",
    "setegid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
    "setgroups",
    # Sandbox / environment entry — ignoring failure = sandbox not entered.
    "chroot",
    "chdir",
    # Durable writes / flushes — ignoring failure = silent data loss/corruption.
    "write",
    "pwrite",
    "fwrite",
    "fclose",
    "fflush",
    "fsync",
    "fdatasync",
)

# Return register (and its sub-register aliases) by normalized architecture.
_RETURN_REGISTERS: dict[str, tuple[str, ...]] = {
    "x86_64": ("rax", "eax", "ax", "al"),
    "arm64": ("x0", "w0"),
}

# Sub-register aliases collapse to a canonical 64-bit name so a value tracked as
# ``rax`` is still recognized when an instruction names ``eax``.
_SUBREG_TO_64: dict[str, str] = {
    "eax": "rax", "ax": "rax", "al": "rax",
    "w0": "x0",
}

# Match "<mnemonic> <dst>, <rest>"  (two-operand form) and "<mnemonic> <op>".
_TWO_OP = re.compile(r"^\s*(\w+)\s+([\w.]+)\s*,\s*(.+)$")
_ONE_OP = re.compile(r"^\s*(\w+)\s+(.+)$")

# Mnemonics that read their first operand as a source rather than purely writing
# it. ``test``/``cmp`` are the canonical x86_64 return-value guards; ``push``
# reads; ``cbz``/``cbnz``/``tbz``/``tbnz`` are the AArch64 compare-and-branch
# guards that read the register they test.
_READ_FIRST_OPERAND = {"test", "cmp", "push", "cbz", "cbnz", "tbz", "tbnz"}


def _return_aliases(arch: str) -> tuple[str, ...]:
    return _RETURN_REGISTERS.get(arch, _RETURN_REGISTERS[DEFAULT_ARCH])


def _canon(reg: str) -> str:
    return _SUBREG_TO_64.get(reg, reg)


def _tokens(text: str) -> set[str]:
    """Canonicalized register-name tokens appearing anywhere in ``text``."""
    return {_canon(t) for t in re.findall(r"[a-z]\w*", text)}


def _return_is_checked(instructions, call_addr: int, arch: str) -> bool:
    """Return True if the return value produced at ``call_addr`` is read before
    it is clobbered or the function ends — i.e. the return WAS checked/used."""
    aliases = _return_aliases(arch)
    ret64 = _canon(aliases[0])
    alias_set = {_canon(a) for a in aliases}

    seen_call = False
    for ins in instructions:
        if ins.addr == call_addr:
            seen_call = True
            continue
        if not seen_call or ins.addr < call_addr:
            continue

        disasm = ins.disasm.strip()
        two = _TWO_OP.match(disasm)
        one = _ONE_OP.match(disasm)
        if not one:
            continue

        mnem = one.group(1)

        if two:
            dst, src = two.group(2), two.group(3)
        else:
            dst, src = one.group(2), ""

        cdst = _canon(dst)

        # --- A following call clobbers the return register (callee returns into
        # it) before we read it → the value was discarded. ---
        if mnem in ("call", "bl", "blr"):
            return False

        # --- Self-xor is a zeroing CLOBBER, not a read. ---
        # `xor eax, eax` names eax as a source but produces a constant 0; treat
        # it as overwriting the return register before any genuine read.
        if mnem in ("xor", "eor") and two and cdst == ret64 and _canon(src.strip()) == ret64:
            return False

        # --- READ of the return value? ---
        # test/cmp/push read their first operand. For any other instruction the
        # return register is read if it appears as a *source* (the src side, or
        # inside a memory operand).
        if mnem in _READ_FIRST_OPERAND and cdst in alias_set:
            return True
        if two and (alias_set & _tokens(src)):
            return True

        # --- CLOBBER of the return register? ---
        # A two-operand write to the return register whose source does NOT
        # reference it overwrites the value before any read → discarded.
        if two and cdst == ret64 and not (alias_set & _tokens(src)):
            return False

    # Reached function end without ever reading the return register → discarded.
    return False


def detect(session: R2Session) -> list[Finding]:
    findings: list[Finding] = []

    arch = session.arch()
    func_cache: dict[str, list] = {}

    for symbol, xref in call_sites(session, DANGEROUS):
        func = xref.function
        if func not in func_cache:
            func_cache[func] = session.function_instructions(xref.from_addr)
        instructions = func_cache[func]

        # No disassembly available for the function → can't reason about the
        # return; stay conservative and do NOT flag (avoid false positives when
        # the function body is opaque).
        if not instructions:
            continue

        if _return_is_checked(instructions, xref.from_addr, arch):
            continue

        findings.append(
            Finding(
                cwe=CWE,
                function=func,
                address=hex(xref.from_addr),
                evidence=(
                    f"return value of {symbol} is ignored "
                    "(unchecked return value — failure goes undetected)"
                ),
                symbol=symbol,
                # Path-reachability of the failure is not proven statically, so
                # per POST_V01 this is a low-confidence finding.
                confidence="low",
            )
        )
    return findings
