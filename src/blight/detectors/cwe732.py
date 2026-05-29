"""CWE-732: Incorrect Permission Assignment for Critical Resource.

Flags call-sites where ``chmod``/``fchmod`` / ``fchmodat`` / ``mkdir`` /
``mkdirat`` / ``creat`` is called with a *constant* mode argument that grants
world-writable (or, at HIGH severity, world-writable AND setuid/setgid)
permissions on a filesystem resource. A constant ``0o644`` is fine and is NOT
flagged; a constant ``0o777`` / ``0o666`` / ``0o2777`` is a misconfiguration
the binary will ship with every time it runs and is the canonical CWE-732
pattern in audited firmware.

This is a hybrid detector — it combines PLT lookup (find the call sites) with
the same per-architecture argument-register inspection used by CWE-78 and
CWE-134, then parses the immediate operand of the instruction that last writes
the mode register. Only *constant* permissive modes flag; a non-constant mode
(register/memory operand reaching the mode position) is **not** flagged here
to keep precision high — CWE-732 wants to catch the embedded ``0o777`` mistake,
not every dynamic chmod.

Argument-position table:

  * ``chmod(path, mode)``                 — mode at arg1
  * ``fchmod(fd, mode)``                  — mode at arg1
  * ``mkdir(path, mode)``                 — mode at arg1
  * ``creat(path, mode)``                 — mode at arg1
  * ``fchmodat(dirfd, path, mode, flags)``— mode at arg2
  * ``mkdirat(dirfd, path, mode)``        — mode at arg2

Severity ladder, applied to the parsed permission bits:

  * HIGH   — setuid/setgid bit (``0o4000`` / ``0o2000``) AND world-writable.
  * MEDIUM — world-writable (``mode & 0o002``) without setuid/setgid bits.
  * LOW    — world-writable cleared but world-readable on a mkdir/chmod over
             everything (``0o777`` with the write bit deliberately stripped
             never happens in practice — this rung exists only to give the
             ``0o775`` "group-writable" mistake a label and is currently
             unused; future heuristics can plug in here without changing the
             public API).

Confidence reflects how much we *know*: a parsed constant immediate is HIGH
confidence (we read the literal bits out of the instruction), no guesswork.
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._argregs import arg_register_aliases
from ._common import call_sites

CWE = 732

# PLT symbols we anchor on, keyed to the argument position carrying the mode.
_MODE_ARG_INDEX: dict[str, int] = {
    "chmod": 1,
    "fchmod": 1,
    "mkdir": 1,
    "creat": 1,
    "fchmodat": 2,
    "mkdirat": 2,
}

DANGEROUS = tuple(_MODE_ARG_INDEX)

# A confidence label for each severity tier.
_CONFIDENCE_FOR_SEVERITY = {
    "HIGH": "high",
    "MEDIUM": "high",  # the immediate is a parsed literal — we know its value
    "LOW": "medium",
}

# Match the destination operand of an instruction: "<mnemonic> <reg>, <src>".
_DEST_OP_RE = re.compile(r"\s*\w+\s+(\w+)\s*,\s*(.+?)\s*$")

# Parse a radare2 immediate operand. radare2 typically emits hex (``0x1ff``) or
# decimal; both are accepted. We deliberately do NOT accept C-style octal
# (``0777`` with a leading zero) because radare2 disassembly never uses that
# form for x86_64 or AArch64 immediates.
_HEX_IMM_RE = re.compile(r"^(?:0x([0-9a-f]+)|([0-9]+))$", re.IGNORECASE)


def _parse_immediate(operand: str) -> int | None:
    """Parse an instruction source operand as an integer immediate.

    Returns the integer value, or ``None`` if ``operand`` is not a bare
    immediate (e.g. it references a register, memory, or a symbol). Tolerates
    leading ``#`` (AArch64) and trailing comma fragments left by a regex match.
    """
    s = operand.strip().rstrip(",").lstrip("#").strip()
    # Strip an AArch64 immediate prefix ('#0x1ff' or '#511'); radare2 sometimes
    # omits the '#' so both forms above are handled.
    m = _HEX_IMM_RE.match(s)
    if not m:
        return None
    if m.group(1) is not None:
        return int(m.group(1), 16)
    return int(m.group(2))


def _classify_mode(value: int) -> tuple[str, str] | None:
    """Classify a parsed constant mode into ``(severity, description)``.

    Returns ``None`` when the mode is benign (no world-writable bit set and
    no setuid/setgid bits).
    """
    # POSIX permission bits — strip anything above the 12-bit suid/sgid/sticky
    # range so a stray sign-extension doesn't perturb the classification.
    perms = value & 0o7777
    world_write = bool(perms & 0o0002)
    setuid_or_setgid = bool(perms & 0o6000)  # 0o4000 | 0o2000

    if world_write and setuid_or_setgid:
        return (
            "HIGH",
            f"world-writable setuid/setgid permission mode {oct(perms)}",
        )
    if world_write:
        return ("MEDIUM", f"world-writable permission mode {oct(perms)}")
    return None


def _last_write_to_mode_reg(
    instructions, call_addr: int, aliases: tuple[str, ...]
) -> str | None:
    """Return the disassembly of the last instruction that writes any register
    in ``aliases`` before ``call_addr``. ``None`` if there is no such write
    visible inside the same function.
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
        if dest in aliases:
            last = disasm
    return last


def _mode_immediate_from_disasm(disasm: str) -> int | None:
    """Extract the source-side immediate from a ``mov <reg>, <imm>`` style
    instruction. Returns ``None`` if the instruction's source operand is not a
    bare immediate (e.g. a register move ``mov edi, eax`` or a memory load).
    """
    m = _DEST_OP_RE.match(disasm)
    if not m:
        return None
    src = m.group(2)
    return _parse_immediate(src)


def detect(session: R2Session) -> list[Finding]:
    findings: list[Finding] = []

    arch = session.arch()
    func_cache: dict[str, list] = {}

    for symbol, xref in call_sites(session, DANGEROUS):
        aliases = arg_register_aliases(arch, _MODE_ARG_INDEX[symbol])
        func = xref.function
        if func not in func_cache:
            func_cache[func] = session.function_instructions(xref.from_addr)
        instructions = func_cache[func]

        last_write = _last_write_to_mode_reg(
            instructions, xref.from_addr, aliases
        )
        if last_write is None:
            # We can't see how mode was set — stay quiet (precision first).
            continue

        mode_value = _mode_immediate_from_disasm(last_write)
        if mode_value is None:
            # Non-constant mode (register/memory). Out of scope for CWE-732.
            continue

        classification = _classify_mode(mode_value)
        if classification is None:
            continue  # benign mode (e.g. 0o644, 0o755)

        severity, description = classification
        findings.append(
            Finding(
                cwe=CWE,
                function=func,
                address=hex(xref.from_addr),
                evidence=(
                    f"[{severity}] call to {symbol} with {description} "
                    "(insecure permission assignment)"
                ),
                symbol=symbol,
                confidence=_CONFIDENCE_FOR_SEVERITY[severity],
            )
        )
    return findings
