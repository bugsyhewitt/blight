"""CWE-369: Divide By Zero.

Flags integer division and remainder instructions whose divisor is *not* a
proven-nonzero constant — i.e. the divisor comes from a register or a memory
operand whose value the code did not zero-check beforehand. If that divisor can
be zero at runtime (attacker-controlled length, parsed field, untrusted count),
the division traps (SIGFPE on x86_64) or yields undefined behaviour.

Unlike most blight detectors this is *not* anchored to a library call site —
there is no import to cross-reference. The divide is a raw instruction, so the
detector walks every function radare2 discovered (``R2Session.function_addrs``)
and scans each body for a division opcode:

  * x86_64: ``div``/``idiv`` take a single operand — the divisor. ``div rcx``,
    ``idiv dword [rbp - 0xc]``. A *constant* operand (``div 0x10`` — rare, but
    some encodings via a loaded immediate) is safe; a register or memory divisor
    is the risk.
  * AArch64: ``sdiv``/``udiv`` are three-operand — ``sdiv x0, x1, x2`` divides
    ``x1`` by ``x2``; the *third* operand is the divisor. A register divisor is
    the risk (AArch64 has no immediate-divisor form).

Guard awareness (conservative, in-function, backward + forward linear scan):

  Before flagging a division by register ``D``, the detector looks *backwards*
  within the function for a zero-check on ``D`` that dominates the divide on a
  linear path:

    * x86_64: ``test D, D`` / ``cmp D, 0`` / ``cmp D, 0x0`` followed (anywhere
      before the divide) marks ``D`` as checked.
    * AArch64: ``cbz D`` / ``cbnz D`` / ``cmp D, #0`` marks ``D`` as checked.

  If the divisor register was zero-checked earlier in the function, the divide is
  treated as guarded and is NOT flagged. A divisor that is itself loaded from an
  immediately-preceding ``mov D, <nonzero-immediate>`` is also safe (a literal
  constant divisor cannot be zero unless the literal is zero).

Confidence: ``low``. Proving the divisor is actually reachable as zero needs
value/range analysis we explicitly keep out of scope; the finding marks an
*unchecked* divisor, which is the statically-visible signal. This matches the
POST_V01 confidence guidance for data-flow-adjacent heuristics (CWE-476/252).

[Worker decision: scoped to a single-function linear scan. No CFG dominance
proof, no inter-procedural value tracking — a backward search for a zero-check
on the divisor register within the same function is the sanitizer test, exactly
mirroring the guard idioms CWE-476 already recognizes. Architecture-aware on
x86_64 (div/idiv, one operand) and AArch64 (sdiv/udiv, third operand),
consistent with POST_V01 item 5.]
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import Instruction, R2Session

CWE = 369

# Division mnemonics by family. x86_64 forms take a single divisor operand;
# AArch64 forms take three operands (dst, dividend, divisor).
_X86_DIV = ("div", "idiv")
_ARM_DIV = ("sdiv", "udiv")

# x86_64 zero-guard idioms and AArch64 compare-and-branch-on-zero idioms.
_ARM_GUARD_CBZ = ("cbz", "cbnz")

# Canonicalize sub-register names to their 64-bit form so a divisor tracked as
# ``ecx`` is recognized when guarded as ``rcx`` (and vice versa).
_SUBREG_TO_64: dict[str, str] = {
    "eax": "rax", "ax": "rax", "al": "rax",
    "ebx": "rbx", "bx": "rbx", "bl": "rbx",
    "ecx": "rcx", "cx": "rcx", "cl": "rcx",
    "edx": "rdx", "dx": "rdx", "dl": "rdx",
    "esi": "rsi", "si": "rsi",
    "edi": "rdi", "di": "rdi",
    "ebp": "rbp", "esp": "rsp",
    **{f"w{i}": f"x{i}" for i in range(0, 31)},
    **{f"r{i}d": f"r{i}" for i in range(8, 16)},
    **{f"r{i}w": f"r{i}" for i in range(8, 16)},
}

# A bare register token (used to decide register-vs-memory-vs-immediate divisor).
_REG_RE = re.compile(r"^[a-z]\w*$")
# An immediate operand: decimal or 0x-hex, optionally AArch64 ``#``-prefixed.
_IMM_RE = re.compile(r"^#?(?:0x[0-9a-fA-F]+|\d+)$")


def _canon(reg: str) -> str:
    return _SUBREG_TO_64.get(reg, reg)


def _norm_operand(operand: str) -> str:
    """Whitespace-normalize an operand for textual comparison.

    radare2 names stack slots symbolically (``dword [var_8h]``), so two
    references to the same slot compare equal after collapsing internal
    whitespace.
    """
    return re.sub(r"\s+", " ", operand.strip())


def _split(disasm: str) -> tuple[str, list[str]]:
    """Return ``(mnemonic, [operands])`` for a disassembly line."""
    parts = disasm.strip().split(None, 1)
    if not parts:
        return "", []
    mnem = parts[0]
    if len(parts) == 1:
        return mnem, []
    operands = [o.strip() for o in parts[1].split(",")]
    return mnem, operands


def _divisor_operand(mnem: str, operands: list[str]) -> str | None:
    """Return the divisor operand text for a division instruction, else None."""
    if mnem in _X86_DIV and len(operands) >= 1:
        return operands[0]
    if mnem in _ARM_DIV and len(operands) >= 3:
        return operands[2]
    return None


def _divisor_register(operand: str) -> str | None:
    """If ``operand`` is a bare register, return its canonical name, else None.

    A memory operand (``[rbp - 0xc]``) is *controllable* too, but we cannot name
    a single register to look for a zero-guard on, so memory divisors are treated
    as unguarded register-class risks via :func:`_is_register_divisor`.
    """
    op = operand.strip()
    if _REG_RE.match(op):
        return _canon(op)
    return None


def _is_immediate_divisor(operand: str) -> bool:
    return bool(_IMM_RE.match(operand.strip()))


def _is_memory_divisor(operand: str) -> bool:
    return "[" in operand


def _is_zero_literal(text: str) -> bool:
    return bool(re.fullmatch(r"#?0(?:x0+)?", text.strip()))


def _zero_checked_before(
    instructions: list[Instruction], div_index: int, divisor: str, arch: str
) -> bool:
    """Return True if ``divisor`` is zero-checked anywhere earlier in the same
    function body, or set from a nonzero immediate.

    ``divisor`` is either a canonical register name (e.g. ``rcx``) or a memory
    operand's normalized text (e.g. ``dword [var_8h]``). For a register divisor a
    ``test``/``cmp`` against the register (or ``cbz``/``cbnz`` on AArch64) is the
    guard. For a memory divisor a ``cmp`` against the *same* memory operand is the
    guard — real radare2 emits ``idiv dword [var_8h]`` for stack divisors, so the
    matching guard is ``cmp dword [var_8h], 0``.
    """
    is_mem = _is_memory_divisor(divisor)
    div_norm = _norm_operand(divisor) if is_mem else divisor

    for ins in instructions[:div_index]:
        mnem, operands = _split(ins.disasm)
        if not operands:
            continue
        first = operands[0]
        cfirst = _canon(first)

        if is_mem:
            # cmp <same memory operand>, 0  (test mem, mem is unusual; cmp is the
            # idiom GCC/clang emit for `if (mem == 0)`).
            if mnem in ("cmp", "test") and len(operands) >= 2 \
                    and _is_memory_divisor(first) \
                    and _norm_operand(first) == div_norm \
                    and (_is_zero_literal(operands[1]) or _norm_operand(operands[1]) == div_norm):
                return True
            continue

        # --- register divisor ---
        if arch == "arm64":
            # cbz/cbnz D    |    cmp D, #0
            if mnem in _ARM_GUARD_CBZ and cfirst == divisor:
                return True
            if mnem == "cmp" and cfirst == divisor and len(operands) >= 2 \
                    and _is_zero_literal(operands[1]):
                return True
        else:
            # test D, D    |    cmp D, 0 / 0x0
            if mnem == "test" and cfirst == divisor and len(operands) >= 2 \
                    and _canon(operands[1]) == divisor:
                return True
            if mnem == "cmp" and cfirst == divisor and len(operands) >= 2 \
                    and _is_zero_literal(operands[1]):
                return True

        # mov D, <nonzero immediate>  → the divisor is a literal constant.
        if mnem == "mov" and cfirst == divisor and len(operands) >= 2:
            src = operands[1].strip()
            if _is_immediate_divisor(src):
                # A literal 0 divisor is itself the bug; nonzero literal is safe.
                normalized = src.lstrip("#")
                try:
                    if int(normalized, 0) != 0:
                        return True
                except ValueError:  # pragma: no cover - defensive
                    pass
    return False


def _scan_function(
    instructions: list[Instruction], arch: str
) -> list[tuple[Instruction, str]]:
    """Return ``(instruction, divisor_text)`` for each unguarded division."""
    hits: list[tuple[Instruction, str]] = []
    for i, ins in enumerate(instructions):
        mnem, operands = _split(ins.disasm)
        divisor = _divisor_operand(mnem, operands)
        if divisor is None:
            continue

        # A literal-immediate divisor is constant; only a literal 0 is a bug, but
        # `idiv 0` essentially never appears, so skip immediate divisors.
        if _is_immediate_divisor(divisor):
            continue

        reg = _divisor_register(divisor)
        if reg is not None:
            if _zero_checked_before(instructions, i, reg, arch):
                continue
            hits.append((ins, divisor))
        elif _is_memory_divisor(divisor):
            # Memory divisor: controllable. Guarded only if an earlier cmp/test
            # against the *same* memory operand zero-checks it.
            if _zero_checked_before(instructions, i, divisor, arch):
                continue
            hits.append((ins, divisor))
        # Anything else (unparseable operand) is skipped conservatively.
    return hits


def detect(session: R2Session) -> list[Finding]:
    findings: list[Finding] = []
    arch = session.arch()

    for func_addr in session.function_addrs():
        instructions = session.function_instructions(func_addr)
        if not instructions:
            continue

        func_name = ""  # radare2 names are resolved per-xref elsewhere; aflj
        # gives only the offset here, so we report the function by address.
        for ins, divisor in _scan_function(instructions, arch):
            findings.append(
                Finding(
                    cwe=CWE,
                    function=func_name or hex(func_addr),
                    address=hex(ins.addr),
                    evidence=(
                        f"division with non-constant divisor {divisor!r} and no "
                        "preceding zero-check (possible divide-by-zero / SIGFPE)"
                    ),
                    symbol=_split(ins.disasm)[0],
                    confidence="low",
                )
            )
    return findings
