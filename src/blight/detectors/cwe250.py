"""CWE-250: Execution with Unnecessary Privileges.

Flags call sites where a process explicitly *sets* its real, effective, or saved
user/group id to **root** (uid/gid ``0``) via the libc privilege-change family.
The canonical CWE-250 pattern in shipped binaries is a constant-zero argument to
``setuid`` / ``seteuid`` / ``setgid`` / ``setegid`` / ``setreuid`` / ``setregid``
/ ``setresuid`` / ``setresgid``: a program that was launched setuid-root (or
running as root and trying to *drop* to an unprivileged uid) instead re-escalates
to uid 0 every time it runs, removing the safety boundary that the surrounding
code may have been written to assume.

This is deliberately distinct from CWE-252 (which already flags the same family
when the *return value* is discarded — failure to drop privileges goes
undetected). CWE-252 asks "was the call's success checked?"; CWE-250 asks "was
the privilege level being asked for the *root* privilege level?". A call site
can legitimately carry both findings — they are complementary signals, not
overlapping detections.

Hybrid detector — PLT lookup locates the call sites, then the same
per-architecture argument-register inspection used by CWE-78 / CWE-134 / CWE-732
parses the immediate operand that last writes the uid/gid argument register(s).
Only call sites where **every** id argument is parsed as a literal ``0`` are
flagged. A non-constant id (register/memory operand reaching the id position) is
**not** flagged here to keep precision high — CWE-250 wants to catch the
embedded ``setuid(0)`` mistake, not every dynamic privilege change. A non-zero
literal id (the canonical drop-to-nobody ``setuid(65534)`` pattern) is also not
flagged — that is exactly the safe usage.

Argument-position table — the id arguments live at different positions across
the family:

  * ``setuid(uid)``                                 — uid at arg0
  * ``seteuid(uid)``                                — uid at arg0
  * ``setgid(gid)``                                 — gid at arg0
  * ``setegid(gid)``                                — gid at arg0
  * ``setreuid(ruid, euid)``                        — both args
  * ``setregid(rgid, egid)``                        — both args
  * ``setresuid(ruid, euid, suid)``                 — all three args
  * ``setresgid(rgid, egid, sgid)``                 — all three args

For the multi-argument forms (``setreuid``/``setregid``/``setresuid``/
``setresgid``) **every** id argument must parse as literal ``0`` for the call to
flag, because the documented "leave this id unchanged" sentinel ``-1`` is a
common pattern (``setreuid(-1, 0)`` is "set only the effective uid to root,
leave the real uid alone") and flagging the call regardless would double-fire
with CWE-252 noise. Requiring *all* args to be zero pins the finding to the
unambiguous full re-escalation to root.

Severity is uniformly HIGH — an embedded literal zero is the bug pattern, no
context needed. Confidence is HIGH — the immediate is read literally out of the
instruction.
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._argregs import arg_register_aliases
from ._common import call_sites

CWE = 250

# PLT symbols we anchor on, keyed to the ordered argument positions that carry
# the (real, effective, saved) user/group ids that we require to be zero for the
# call to flag. A single-arg member of the family lists just ``(0,)``.
_ID_ARG_POSITIONS: dict[str, tuple[int, ...]] = {
    "setuid":    (0,),
    "seteuid":   (0,),
    "setgid":    (0,),
    "setegid":   (0,),
    "setreuid":  (0, 1),
    "setregid":  (0, 1),
    "setresuid": (0, 1, 2),
    "setresgid": (0, 1, 2),
}

DANGEROUS = tuple(_ID_ARG_POSITIONS)

# Match a two-operand instruction's destination + source: "<mnem> <dst>, <src>".
_DEST_OP_RE = re.compile(r"\s*\w+\s+(\w+)\s*,\s*(.+?)\s*$")

# Match a bare integer immediate. Hex (``0x0``) and decimal (``0``) accepted;
# C-style leading-zero octal is not — radare2 disassembly never uses it.
_IMM_RE = re.compile(r"^(?:0x([0-9a-f]+)|([0-9]+))$", re.IGNORECASE)


def _parse_immediate(operand: str) -> int | None:
    """Return the integer value of a bare immediate operand, or ``None``.

    Tolerates a leading AArch64 ``#`` prefix and trailing comma fragments.
    Returns ``None`` for any operand that references a register, memory, or a
    symbol — those are non-constant and out of scope for this precision-first
    detector.
    """
    s = operand.strip().rstrip(",").lstrip("#").strip()
    m = _IMM_RE.match(s)
    if not m:
        return None
    if m.group(1) is not None:
        return int(m.group(1), 16)
    return int(m.group(2))


def _last_write_to_reg(
    instructions, call_addr: int, aliases: tuple[str, ...]
) -> str | None:
    """Return the disassembly of the last instruction before ``call_addr`` that
    writes any register named in ``aliases``. ``None`` if no such write is
    visible inside the same function (i.e. the value entered the function from
    a caller — opaque to this single-function scan).

    Special-case the ``xor reg, reg`` (x86_64) / ``eor reg, reg, reg``
    (AArch64) zeroing idiom: the compiler routinely emits it instead of an
    explicit ``mov reg, 0``, so we synthesise an equivalent ``mov`` form to feed
    the immediate parser.
    """
    last: str | None = None
    for ins in instructions:
        if ins.addr >= call_addr:
            break
        disasm = ins.disasm
        m = _DEST_OP_RE.match(disasm)
        if not m:
            continue
        dest = m.group(1)
        if dest not in aliases:
            continue

        # Normalise the self-xor / self-eor zeroing idiom into a synthetic
        # ``mov <dest>, 0`` so the immediate parser below sees the literal 0.
        tokens = re.split(r"[\s,]+", disasm.strip())
        if tokens and tokens[0] in ("xor", "eor"):
            # x86_64 ``xor eax, eax`` — 3 tokens. AArch64 ``eor w0, w0, w0`` —
            # 4 tokens. In both cases every operand after the mnemonic is the
            # destination register or one of its aliases.
            operands = [t.rstrip(",") for t in tokens[1:]]
            if all(op == dest for op in operands):
                last = f"mov {dest}, 0"
                continue

        last = disasm
    return last


def _immediate_from_disasm(disasm: str) -> int | None:
    """Extract the source-side immediate from a ``mov <reg>, <imm>`` style
    instruction. Returns ``None`` when the source is not a bare immediate (a
    register-to-register move ``mov edi, eax`` or a memory load).
    """
    m = _DEST_OP_RE.match(disasm)
    if not m:
        return None
    return _parse_immediate(m.group(2))


def detect(session: R2Session) -> list[Finding]:
    findings: list[Finding] = []

    arch = session.arch()
    func_cache: dict[str, list] = {}

    for symbol, xref in call_sites(session, DANGEROUS):
        func = xref.function
        if func not in func_cache:
            func_cache[func] = session.function_instructions(xref.from_addr)
        instructions = func_cache[func]

        positions = _ID_ARG_POSITIONS[symbol]

        all_zero = True
        for arg_index in positions:
            aliases = arg_register_aliases(arch, arg_index)
            last_write = _last_write_to_reg(
                instructions, xref.from_addr, aliases
            )
            if last_write is None:
                # The argument was set outside this function's view — opaque,
                # not provably zero. Precision-first: do not flag.
                all_zero = False
                break
            value = _immediate_from_disasm(last_write)
            if value is None:
                # Non-constant id (register or memory operand). Out of scope.
                all_zero = False
                break
            if value != 0:
                # A non-zero literal id is the *safe* drop-to-unprivileged
                # pattern (e.g. ``setuid(65534)``). Not flagged.
                all_zero = False
                break

        if not all_zero:
            continue

        if len(positions) == 1:
            description = "uid/gid argument is literal 0 (root)"
        else:
            description = (
                f"all {len(positions)} uid/gid arguments are literal 0 (root)"
            )

        findings.append(
            Finding(
                cwe=CWE,
                function=func,
                address=hex(xref.from_addr),
                evidence=(
                    f"[HIGH] call to {symbol} with {description} "
                    "(execution with unnecessary root privileges)"
                ),
                symbol=symbol,
                confidence="high",
            )
        )
    return findings
