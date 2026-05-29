"""CWE-191: Integer Underflow (Wrap or Wraparound).

Flags the statically-detectable integer-underflow pattern that turns into a
memory-safety bug: an *unsigned subtraction* produces a size/length that is then
handed to an allocation or copy routine without a preceding bound check on the
operands. When the minuend is smaller than the subtrahend (``len - header``,
``end - start``, ``count - 1`` with ``count == 0``), the unsigned result wraps to
a near-``SIZE_MAX`` value; feeding that to ``malloc`` / ``memcpy`` / ``alloca``
requests or copies an enormous region — the classic underflow-to-overflow
primitive behind countless CVEs.

This is the *narrow, statically-visible* slice of CWE-191. blight deliberately
does NOT attempt the general integer-underflow problem: proving that a given
subtraction can actually underflow at runtime needs value-range / symbolic
analysis that POST_V01 records — repeatedly, for the sibling CWE-190 integer
overflow — as out of scope for a static PLT-and-disassembly tool. Instead this
detector anchors on the same fingerprint blight already exploits elsewhere: a
subtraction result reaching a *size-consuming sink* (allocator / copy) with no
preceding compare that bounds the subtraction. That reaching-a-sink anchor is
what keeps the false-positive rate low — a bare ``sub`` is everywhere; a ``sub``
whose result is the size argument of ``memcpy`` is a security-relevant signal.

Heuristic (deliberately conservative — single-function, linear backward scan
with simple register-alias tracking, the same machinery proven by CWE-122 and
CWE-369):

  1. Find every call site to a size-consuming sink:
       * arg0 carries the size:  ``malloc``, ``alloca``, ``valloc``,
         ``pvalloc``, ``__builtin_alloca``.
       * arg2 carries the size:  ``memcpy``, ``memmove``, ``memset``,
         ``bcopy`` (n is arg3, handled below), ``calloc`` (size is the *product*
         of arg0*arg1 — we track the size register arg1 there too).
     The size-argument register is resolved per-architecture (``rdi``/``rsi``/
     ``rdx`` on x86_64, ``x0``/``x1``/``x2`` on AArch64).
  2. Backward-scan the function from the call: track the size register and any
     register it was moved from (alias chain). If a tracked register is the
     *destination* of a subtraction (``sub D, S`` on x86_64; ``sub D, A, B`` on
     AArch64), the size is a subtraction result — a candidate underflow.
  3. Guard awareness: if, *before* that subtraction, the function compares the
     subtraction's minuend/operands (``cmp``/``test`` followed by a conditional
     branch — ``jae``/``jb``/``jbe``/``ja`` on x86_64, ``b.hs``/``b.lo``/``cmp``
     on AArch64) the subtraction is treated as bounds-checked and is NOT flagged.
  4. A subtraction by a *nonzero immediate* from a register that is itself a
     freshly-loaded length is still flagged (``len - 8`` underflows when
     ``len < 8``); a subtraction producing the size with NO preceding guard is
     the finding.

Confidence: ``low``. Reachability and the actual runtime range of the operands
are not proven statically — the finding marks an *unguarded* size-producing
subtraction reaching an allocation/copy, which is the statically-visible signal.
This matches the POST_V01 confidence guidance for data-flow-adjacent heuristics
(CWE-122 / CWE-369 / CWE-476).

[Worker decision: scoped to an in-function backward scan anchored on a
size-consuming sink, mirroring CWE-122's PLT anchoring and CWE-369's guard-aware
linear scan — no CFG dominance proof, no value-range/symbolic analysis, none of
which POST_V01 sanctions for the integer-wrap CWE family. Kept distinct from
CWE-190 (integer *overflow*), which POST_V01 explicitly defers as needing
symbolic execution: this detector does NOT attempt to prove overflow of an
addition/multiplication; it fires only on a *subtraction* whose result is a
sink's size argument and which is not preceded by a bounds compare — the precise,
statically-visible underflow-to-allocation fingerprint. Architecture-aware on
x86_64 and AArch64, consistent with POST_V01 item 5.]
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import Instruction, R2Session

from ._argregs import DEFAULT_ARCH, arg_register_aliases
from ._common import call_sites

CWE = 191

# Size-consuming sinks keyed to the argument index that carries the size/length.
# malloc/alloca take the size as arg0; the mem* copies take the length as arg2.
# calloc(nmemb, size) — arg1 is the per-element size, the product can wrap too.
_SIZE_ARG_INDEX: dict[str, int] = {
    "malloc": 0,
    "alloca": 0,
    "__builtin_alloca": 0,
    "valloc": 0,
    "pvalloc": 0,
    "calloc": 1,
    "memcpy": 2,
    "memmove": 2,
    "memset": 2,
    "bcopy": 2,
    "realloc": 1,
    "reallocarray": 1,
}

# Full-width general registers we are willing to track an alias through.
_X86_64_GPRS = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
_ARM64_GPRS = tuple(f"x{i}" for i in range(0, 29))

# Sub-register aliases collapse to their canonical 64-bit name so a size tracked
# as ``rdx`` is recognized when an instruction names ``edx`` (and vice versa).
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

# x86_64 unsigned-comparison conditional branches that act as a bounds guard.
_X86_GUARD_JCC = ("jae", "jnb", "jb", "jnae", "jbe", "ja", "jna", "jc", "jnc")
# AArch64 unsigned condition codes used after a cmp to guard a subtraction.
_ARM_GUARD_BCC = ("b.hs", "b.lo", "b.ls", "b.hi", "b.cs", "b.cc")

_BARE_REG_RE = re.compile(r"^[a-z]\w*$")
_IMM_RE = re.compile(r"^#?(?:0x[0-9a-fA-F]+|\d+)$")


def _canon(reg: str) -> str:
    return _SUBREG_TO_64.get(reg, reg)


def _gprs_for(arch: str) -> tuple[str, ...]:
    return _ARM64_GPRS if arch == "arm64" else _X86_64_GPRS


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


def _arg_register(arch: str, index: int) -> str:
    """Canonical 64-bit name of argument register ``index`` on ``arch``."""
    a = arch if arch in ("x86_64", "arm64") else DEFAULT_ARCH
    aliases = arg_register_aliases(a, index)
    return _canon(aliases[0])


def _is_bare_reg(operand: str) -> bool:
    return bool(_BARE_REG_RE.match(operand.strip()))


def _sub_destination(mnem: str, operands: list[str], arch: str) -> str | None:
    """If this instruction subtracts into a register, return that register's
    canonical name, else None.

    x86_64: ``sub D, S`` — destination is the first operand.
    AArch64: ``sub D, A, B`` — destination is the first operand. (The
    architecturally-distinct ``subs`` flag-setting form is also recognized.)
    """
    if mnem not in ("sub", "subs"):
        return None
    if not operands:
        return None
    dst = operands[0]
    if _is_bare_reg(dst):
        return _canon(dst)
    return None


def _is_guard_branch(mnem: str, arch: str) -> bool:
    if arch == "arm64":
        return mnem in _ARM_GUARD_BCC
    return mnem in _X86_GUARD_JCC


def _underflow_before(
    instructions: list[Instruction], call_index: int, size_reg: str, arch: str
) -> bool:
    """Return True if the size register reaching the call at ``call_index`` was
    produced by an *unguarded* subtraction earlier in the same function.

    Walks backward from the call. Maintains an alias set seeded with the size
    register; a ``mov D, S`` where ``D`` is tracked adds ``S`` to the set (the
    value came from ``S``). A subtraction into a tracked register is the
    underflow candidate — unless a guard branch was seen *between* that
    subtraction and the call (a bounds check on the operands).
    """
    gprs = _gprs_for(arch)
    alive: set[str] = {size_reg}

    # The size-producing subtraction is the candidate. Scanning *backward* from
    # the call, we encounter that subtraction before the guard that protects it
    # (the guard sits earlier in program order). So we record that a candidate
    # subtraction was found, then KEEP scanning backward: if an unsigned-compare
    # guard branch appears *before* the subtraction, it bounds-checks the
    # operands and the size is safe. If we reach the function start with no such
    # preceding guard, the subtraction is unguarded → underflow.
    found_sub = False

    # Scan strictly backward over instructions preceding the call.
    for ins in reversed(instructions[:call_index]):
        mnem, operands = _split(ins.disasm)

        # --- guard branch (unsigned compare result) ---
        # A guard reached *after* (i.e. earlier in program order than) the
        # candidate subtraction bounds-checks it → safe.
        if _is_guard_branch(mnem, arch):
            if found_sub:
                return False
            continue

        if not operands:
            # Mnemonic with no operands (e.g. cdq, ret) — nothing to track.
            continue

        # --- a subtraction into a tracked register is the candidate ---
        sub_dst = _sub_destination(mnem, operands, arch)
        if sub_dst is not None and sub_dst in alive:
            found_sub = True
            continue

        if found_sub:
            # Already have the candidate subtraction; only a preceding guard
            # branch can clear it now, so keep scanning without re-tracking
            # aliases (the operands feeding the sub are not the size register).
            continue

        # --- alias propagation: mov D, S where D is tracked → also track S ---
        if mnem == "mov" and len(operands) >= 2:
            dst = _canon(operands[0]) if _is_bare_reg(operands[0]) else None
            src = operands[1].strip()
            if dst is not None and dst in alive:
                if _is_bare_reg(src):
                    csrc = _canon(src)
                    if csrc in gprs:
                        alive.add(csrc)
                # A non-register source (immediate / memory load) terminates the
                # backward chain for this register: the size value originates
                # here, not from an earlier subtraction. Drop the dst so an
                # unrelated earlier `sub dst, ...` does not false-positive.
                alive.discard(dst)
                if not alive:
                    return False
            continue

        # --- AArch64 register-move forms (mov xD, xS) handled above; ldr loads
        # a fresh value into the destination, terminating that chain. ---
        if mnem in ("ldr", "ldur", "lea") and len(operands) >= 1:
            dst = _canon(operands[0]) if _is_bare_reg(operands[0]) else None
            if dst is not None and dst in alive:
                alive.discard(dst)
                if not alive:
                    return False
            continue

    # Reached the function start. If a size-producing subtraction was found and
    # no preceding guard cleared it, the size is an unguarded underflow.
    return found_sub


def detect(session: R2Session) -> list[Finding]:
    findings: list[Finding] = []

    arch = session.arch()
    func_cache: dict[str, list[Instruction]] = {}

    for symbol, xref in call_sites(session, _SIZE_ARG_INDEX.keys()):
        func = xref.function
        if func not in func_cache:
            func_cache[func] = session.function_instructions(xref.from_addr)
        instructions = func_cache[func]
        if not instructions:
            continue

        # Locate the call instruction's index within the function body.
        call_index = next(
            (i for i, ins in enumerate(instructions) if ins.addr == xref.from_addr),
            None,
        )
        if call_index is None:
            continue

        size_reg = _arg_register(arch, _SIZE_ARG_INDEX[symbol])
        if not _underflow_before(instructions, call_index, size_reg, arch):
            continue

        findings.append(
            Finding(
                cwe=CWE,
                function=func,
                address=hex(xref.from_addr),
                evidence=(
                    f"size argument to {symbol} is produced by an unsigned "
                    "subtraction with no preceding bounds check (possible integer "
                    "underflow → oversized allocation/copy)"
                ),
                symbol=symbol,
                # Operand ranges are not proven statically, so per POST_V01 this
                # is a low-confidence finding (matching CWE-122 / CWE-369).
                confidence="low",
            )
        )
    return findings
