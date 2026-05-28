"""CWE-476: NULL Pointer Dereference.

Flags the most common statically-detectable NULL-deref pattern: a pointer
returned by a *nullable allocator* (``malloc``/``calloc``/``realloc``/
``strdup``/``fopen``/...) is dereferenced later in the same function with no
intervening NULL guard. On failure these functions return ``NULL``; using the
result without checking it dereferences a null pointer.

This is a taint-propagation problem analogous to CWE-415: the *source* is the
allocator's return value (which lands in the architecture's return register),
the *sink* is a memory access through that pointer, and the *sanitizer* is any
NULL check between source and sink.

Heuristic (deliberately conservative — taint/symbolic execution is out of
scope, so this stays a single-function, linear-scan pattern):

  1. Find every call site to a nullable allocator.
  2. The return value arrives in the return register (``rax``/``eax`` on
     x86_64, ``x0``/``w0`` on AArch64). Track the set of registers that alias
     the pointer: a ``mov <reg>, rax`` (x86_64) or ``mov <reg>, x0`` (AArch64)
     propagates the pointer into ``<reg>``.
  3. Walk the instructions *after* the call, in order:
       * If a NULL guard for any aliasing register appears first — a
         ``test reg, reg`` / ``cmp reg, 0`` (x86_64) or ``cbz``/``cbnz``/
         ``cmp reg, #0`` (AArch64) — the pointer is checked. Stop; do NOT flag.
       * If a *dereference* of an aliasing register appears first — a memory
         operand ``[reg ...]`` that reads/writes through the pointer — flag it.
       * If the register is overwritten by an unrelated value, the alias is
         dropped (the pointer is no longer live in it).
  4. If neither a guard nor a deref is seen before the function ends (or the
     pointer escapes, e.g. is passed to another call / stored to memory), do
     NOT flag — we can only reason about a deref we can actually see.

Because the heuristic cannot prove the allocation can fail on the reached path
(it almost always can, but proving it needs inter-procedural analysis), every
finding is ``low`` confidence — matching the POST_V01 guidance for this CWE.

[Worker decision: scoped to in-function, post-call linear scan with simple
register-alias tracking. No CFG reconstruction, no inter-procedural analysis —
those remain explicitly out of scope. The allocator return register and the
NULL-guard idioms are resolved per-architecture so this works on x86_64 and
AArch64, consistent with POST_V01 item 5.]
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._argregs import DEFAULT_ARCH
from ._common import call_sites

CWE = 476

# Library functions that return a pointer which is NULL on failure. Using the
# result without a NULL check is the classic CWE-476 pattern.
DANGEROUS = (
    "malloc",
    "calloc",
    "realloc",
    "strdup",
    "strndup",
    "fopen",
    "fdopen",
    "freopen",
    "opendir",
    "getenv",
)

# The register a C function's return value arrives in, plus its sub-register
# aliases, keyed by normalized architecture.
_RETURN_REGISTERS: dict[str, tuple[str, ...]] = {
    "x86_64": ("rax", "eax", "ax"),
    "arm64": ("x0", "w0"),
}

# Full-width general registers we are willing to track a pointer alias through.
# A pointer lives in a 64-bit register; we track the canonical 64-bit name.
_X86_64_GPRS = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
_ARM64_GPRS = tuple(f"x{i}" for i in range(0, 29))

# Match "<mnemonic> <dst>, <src>" capturing dst and the rest.
_TWO_OP = re.compile(r"^\s*(\w+)\s+([\w.]+)\s*,\s*(.+)$")
# Match "<mnemonic> <op>" (single operand, e.g. cbz x0, ... is two-op; je is one).
_ONE_OP = re.compile(r"^\s*(\w+)\s+([\w.]+)")


def _return_aliases(arch: str) -> tuple[str, ...]:
    return _RETURN_REGISTERS.get(arch, _RETURN_REGISTERS[DEFAULT_ARCH])


def _gprs_for(arch: str) -> tuple[str, ...]:
    return _ARM64_GPRS if arch == "arm64" else _X86_64_GPRS


# Sub-register aliases collapse to their canonical 64-bit name so a pointer
# tracked as ``rax`` is still recognized when an instruction names ``eax``.
_SUBREG_TO_64: dict[str, str] = {
    "eax": "rax", "ax": "rax",
    "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp",
    **{f"w{i}": f"x{i}" for i in range(0, 31)},
    **{f"r{i}d": f"r{i}" for i in range(8, 16)},
}


def _canon(reg: str) -> str:
    """Collapse a register token to its canonical 64-bit name."""
    return _SUBREG_TO_64.get(reg, reg)


def _mem_regs(operand: str) -> set[str]:
    """Return the register names appearing inside a ``[ ... ]`` memory operand."""
    regs: set[str] = set()
    for m in re.finditer(r"\[([^\]]*)\]", operand):
        for tok in re.findall(r"[a-z]\w+", m.group(1)):
            regs.add(_canon(tok))
    return regs


# On x86_64 the NULL guard is a `test reg, reg` or `cmp reg, 0` of the pointer
# register — we do not require the exact following je/jne, since the compare of
# the pointer register is itself the guard signal. On AArch64 the compare-and-
# branch-on-zero idioms (`cbz`/`cbnz`) guard a pointer register directly.
_ARM64_GUARD_CBZ = ("cbz", "cbnz")


def _is_null_guard(arch: str, mnem: str, dst: str, src: str, alive: set[str]) -> bool:
    """Return True if this instruction NULL-checks a currently-live pointer."""
    cdst = _canon(dst)
    if arch == "arm64":
        if mnem in _ARM64_GUARD_CBZ and cdst in alive:
            return True
        # cmp xN, #0  /  cmp xN, 0
        if mnem == "cmp" and cdst in alive and re.fullmatch(r"#?0", src.strip()):
            return True
        return False
    # x86_64: test reg, reg  (same reg) or cmp reg, 0
    if mnem == "test" and cdst in alive and _canon(src.strip()) == cdst:
        return True
    if mnem == "cmp" and cdst in alive and src.strip() in ("0", "0x0"):
        return True
    return False


def _detect_in_function(
    instructions, call_addr: int, arch: str
) -> bool:
    """Return True if the allocator return at ``call_addr`` is dereferenced
    with no intervening NULL guard, scanning forward within the function."""
    ret_aliases = _return_aliases(arch)
    gprs = _gprs_for(arch)
    ret64 = ret_aliases[0]  # canonical 64-bit return register

    # Registers currently holding the (possibly-null) allocator pointer.
    alive: set[str] = {ret64}

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

        # --- NULL guard? Pointer is checked → safe, stop. ---
        if _is_null_guard(arch, mnem, dst, src, alive):
            return False

        # --- Dereference of a live pointer? That's the sink → flag. ---
        # Any memory operand `[ ... reg ... ]` that names an aliasing register
        # reads/writes through the pointer. (x86_64 `mov rax, [reg]` /
        # `mov dword [reg], 0`; AArch64 `ldr x1, [reg]` / `str wzr, [reg]`.)
        if alive & _mem_regs(disasm):
            return True

        # --- Alias propagation / kill, for register-to-register moves. ---
        # x86_64 uses `mov`; AArch64 register moves are `mov`/`mov` too (radare2
        # disassembles `mov x1, x0`). A move whose source is a *bare* register
        # (no memory operand) either propagates or kills the pointer alias.
        if mnem == "mov" and two:
            src_reg = _canon(src.strip())
            cdst = _canon(dst)
            if cdst in gprs:
                if src_reg in alive and "[" not in src:
                    # mov dst, <live ptr>  → dst now aliases the pointer.
                    alive.add(cdst)
                elif "[" not in src:
                    # dst overwritten by an unrelated bare value → drop alias.
                    alive.discard(cdst)
        # Pointer escapes if it's pushed/stored or passed onward; we simply stop
        # tracking once it leaves a register we can see. If the return register
        # itself is reused as an argument before any deref we can't prove a
        # null-deref, so we keep scanning until function end (no flag).

        if not alive:
            return False

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

        if not _detect_in_function(instructions, xref.from_addr, arch):
            continue

        findings.append(
            Finding(
                cwe=CWE,
                function=func,
                address=hex(xref.from_addr),
                evidence=(
                    f"return value of {symbol} dereferenced without a NULL check "
                    "(possible NULL pointer dereference on allocation failure)"
                ),
                symbol=symbol,
                # The path-reachability of the failure is not proven statically,
                # so per POST_V01 this is a low-confidence finding.
                confidence="low",
            )
        )
    return findings
