"""CWE-134: Use of Externally-Controlled Format String.

Flags call-sites where printf-family functions receive a format argument that
is NOT a constant string literal. A constant format string (e.g.
``printf("hello %s\\n", name)``) is not a vulnerability; a format string
built from a buffer or supplied by the caller is.

Heuristic (x86_64, v0.1 scope): inspect the instructions in the containing
function up to the call site. The format argument lives in a register that
depends on the calling convention and the function signature:

  - arg0 (rdi): printf, vprintf
  - arg1 (rsi): fprintf, vfprintf, syslog, vsyslog, vsprintf
  - arg2 (rdx): snprintf, vsnprintf

If the instruction that last loads that register references a string literal
(radare2 names these ``str.*``), the format is constant and we do NOT flag.
Otherwise the format is non-constant and we flag.

Same conservative static heuristic as CWE-78. Cross-architecture register
conventions are deferred to a later version (same as CWE-78).
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._common import call_sites

CWE = 134

# All printf-family functions we care about.
DANGEROUS = (
    "printf",
    "fprintf",
    "syslog",
    "snprintf",
    "vprintf",
    "vsprintf",
    "vfprintf",
    "vsyslog",
    "vsnprintf",
)

# Which register carries the format-string argument for each function.
# SysV AMD64 ABI argument registers: rdi(0), rsi(1), rdx(2).
_FORMAT_REG: dict[str, str] = {
    "printf": "rdi",       # printf(fmt, ...)
    "vprintf": "rdi",      # vprintf(fmt, va)
    "fprintf": "rsi",      # fprintf(fp, fmt, ...)
    "vfprintf": "rsi",     # vfprintf(fp, fmt, va)
    "syslog": "rsi",       # syslog(priority, fmt, ...)
    "vsyslog": "rsi",      # vsyslog(priority, fmt, va)
    "vsprintf": "rsi",     # vsprintf(buf, fmt, va)
    "snprintf": "rdx",     # snprintf(buf, size, fmt, ...)
    "vsnprintf": "rdx",    # vsnprintf(buf, size, fmt, va)
}

# Sub-registers that alias each argument register.
_ALIASES: dict[str, tuple[str, ...]] = {
    "rdi": ("rdi", "edi", "di"),
    "rsi": ("rsi", "esi", "si"),
    "rdx": ("rdx", "edx", "dx"),
}

_STR_REF = re.compile(r"\bstr\.")


def _format_arg_is_constant(instructions, call_addr: int, fmt_reg: str) -> bool:
    """Return True if the last write to ``fmt_reg`` before ``call_addr``
    loads a string literal (``str.*``)."""
    aliases = _ALIASES.get(fmt_reg, (fmt_reg,))
    last_fmt_load: str | None = None
    for ins in instructions:
        if ins.addr >= call_addr:
            break
        disasm = ins.disasm
        # Match the destination operand: "<mnemonic> <reg>, ..."
        m = re.match(r"\s*\w+\s+(\w+)", disasm)
        if not m:
            continue
        dest = m.group(1)
        if dest in aliases:
            last_fmt_load = disasm
    if last_fmt_load is None:
        # Cannot determine how the format register was set; flag conservatively.
        return False
    return bool(_STR_REF.search(last_fmt_load))


def detect(session: R2Session) -> list[Finding]:
    findings: list[Finding] = []

    func_cache: dict[str, list] = {}

    for symbol, xref in call_sites(session, DANGEROUS):
        fmt_reg = _FORMAT_REG[symbol]
        func = xref.function
        if func not in func_cache:
            func_cache[func] = session.function_instructions(xref.from_addr)
        instructions = func_cache[func]

        if _format_arg_is_constant(instructions, xref.from_addr, fmt_reg):
            continue  # constant format string — not flagged

        findings.append(
            Finding(
                cwe=CWE,
                function=func,
                address=hex(xref.from_addr),
                evidence=(
                    f"call to {symbol} with a non-constant format string "
                    "(possible format string injection)"
                ),
                symbol=symbol,
            )
        )
    return findings
