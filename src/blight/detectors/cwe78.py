"""CWE-78: OS Command Injection.

Flags calls to ``system`` and the ``exec*`` family where the command argument
is NOT a constant string literal. A constant command (e.g. ``system("ls")``)
is uninteresting; a command built from a buffer or variable is the injection
risk.

Heuristic: inspect the instructions in the containing function up to the call
site. The first argument is passed in an architecture-specific register
(``rdi`` on x86_64, ``x0``/``w0`` on AArch64). If the instruction that last
loads that register references a string literal (radare2 names these
``str.*``), the argument is constant and we do NOT flag. Otherwise the argument
is non-constant and we flag.

[Worker decision: this is a deliberately conservative static heuristic, not
taint analysis (taint/symbolic execution is explicitly post-v0.1). It correctly
separates the shipped vulnerable fixture (argument built via snprintf into a
stack buffer) from a constant-string call. The register convention is resolved
per-architecture via :mod:`blight.detectors._argregs` (POST_V01 item 5); x86_64
and AArch64 are supported, with x86_64 as the conservative fallback.]
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._argregs import arg_register_aliases
from ._common import call_sites

CWE = 78

# system + the exec* family.
DANGEROUS = ("system", "execl", "execlp", "execle", "execv", "execvp", "execvpe")

# All these functions take the command/program as their FIRST argument.
_ARG_INDEX = 0

_STR_REF = re.compile(r"\bstr\.")


def _arg_is_constant(instructions, call_addr: int, arg0_aliases: tuple[str, ...]) -> bool:
    """Return True if the last write to the arg0 register before ``call_addr``
    loads a string literal (``str.*``)."""
    last_arg0_load: str | None = None
    for ins in instructions:
        if ins.addr >= call_addr:
            break
        disasm = ins.disasm
        # Does this instruction write the first-argument register?
        # Match the destination operand: "<mnemonic> <reg>, ..."
        m = re.match(r"\s*\w+\s+(\w+)", disasm)
        if not m:
            continue
        dest = m.group(1)
        if dest in arg0_aliases:
            last_arg0_load = disasm
    if last_arg0_load is None:
        # Couldn't see how arg0 was set; treat as non-constant (flag it).
        return False
    return bool(_STR_REF.search(last_arg0_load))


def detect(session: R2Session) -> list[Finding]:
    findings: list[Finding] = []

    arg0_aliases = arg_register_aliases(session.arch(), _ARG_INDEX)

    # Cache disassembly per function to avoid re-querying.
    func_cache: dict[str, list] = {}

    for symbol, xref in call_sites(session, DANGEROUS):
        func = xref.function
        if func not in func_cache:
            # Resolve the function start from its first instruction by walking
            # back is unnecessary: radare2 lets us disassemble by function via
            # the call site's function. We approximate by disassembling the
            # function containing the call using the symbol's own address space
            # — the xref already tells us the function name; we disassemble from
            # the call site's function start address, which radare2 resolves
            # when we pass the call address through pdfj.
            func_cache[func] = session.function_instructions(xref.from_addr)
        instructions = func_cache[func]

        if _arg_is_constant(instructions, xref.from_addr, arg0_aliases):
            continue  # constant command string — not flagged

        findings.append(
            Finding(
                cwe=CWE,
                function=func,
                address=hex(xref.from_addr),
                evidence=(
                    f"call to {symbol} with a non-constant command argument "
                    "(possible OS command injection)"
                ),
                symbol=symbol,
                # The non-constant heuristic can miss aliased registers and
                # cannot prove the argument is attacker-controlled, so this is
                # a medium-confidence finding.
                confidence="medium",
            )
        )
    return findings
