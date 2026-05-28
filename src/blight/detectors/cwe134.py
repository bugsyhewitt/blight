"""CWE-134: Use of Externally-Controlled Format String.

Flags call-sites where printf-family functions receive a format argument that
is NOT a constant string literal. A constant format string (e.g.
``printf("hello %s\\n", name)``) is not a vulnerability; a format string
built from a buffer or supplied by the caller is.

Heuristic: inspect the instructions in the containing function up to the call
site. The format argument lives at a function-specific argument *position*:

  - arg0: printf, vprintf
  - arg1: fprintf, vfprintf, syslog, vsyslog, vsprintf
  - arg2: snprintf, vsnprintf

The physical register for that position depends on the architecture's calling
convention (resolved via :mod:`blight.detectors._argregs`): on x86_64 args 0-2
are ``rdi/rsi/rdx``; on AArch64 they are ``x0/x1/x2`` (with ``w0/w1/w2``
aliases). If the instruction that last loads that register references a string
literal (radare2 names these ``str.*``), the format is constant and we do NOT
flag. Otherwise the format is non-constant and we flag.

Same conservative static heuristic as CWE-78, and architecture-aware in the
same way (POST_V01 item 5).
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._argregs import arg_register_aliases
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

# Which ARGUMENT POSITION carries the format-string for each function. The
# physical register for that position is resolved per-architecture at runtime.
_FORMAT_ARG_INDEX: dict[str, int] = {
    "printf": 0,       # printf(fmt, ...)
    "vprintf": 0,      # vprintf(fmt, va)
    "fprintf": 1,      # fprintf(fp, fmt, ...)
    "vfprintf": 1,     # vfprintf(fp, fmt, va)
    "syslog": 1,       # syslog(priority, fmt, ...)
    "vsyslog": 1,      # vsyslog(priority, fmt, va)
    "vsprintf": 1,     # vsprintf(buf, fmt, va)
    "snprintf": 2,     # snprintf(buf, size, fmt, ...)
    "vsnprintf": 2,    # vsnprintf(buf, size, fmt, va)
}

_STR_REF = re.compile(r"\bstr\.")


def _format_arg_is_constant(
    instructions, call_addr: int, aliases: tuple[str, ...]
) -> bool:
    """Return True if the last write to the format register before ``call_addr``
    loads a string literal (``str.*``)."""
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

    arch = session.arch()
    func_cache: dict[str, list] = {}

    for symbol, xref in call_sites(session, DANGEROUS):
        aliases = arg_register_aliases(arch, _FORMAT_ARG_INDEX[symbol])
        func = xref.function
        if func not in func_cache:
            func_cache[func] = session.function_instructions(xref.from_addr)
        instructions = func_cache[func]

        if _format_arg_is_constant(instructions, xref.from_addr, aliases):
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
                # Same non-constant heuristic as CWE-78: it can miss aliased
                # registers, so this is a medium-confidence finding.
                confidence="medium",
            )
        )
    return findings
