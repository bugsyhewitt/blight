"""CWE-131: Incorrect Calculation of Buffer Size.

Flags the statically-detectable buffer-sizing mistake that turns into a
memory-safety bug: an allocation whose size argument is the return of
``strlen``/``wcslen`` with **no ``+ 1`` adjustment for the NUL terminator**.
The canonical C source is ``buf = malloc(strlen(src)); strcpy(buf, src);`` —
the buffer is one byte short of holding the string plus terminator, so the
``strcpy`` writes the NUL past the end of the heap allocation. This off-by-one
heap overflow is one of the most-cited examples of CWE-131 (compare the entry
on cwe.mitre.org) and is endemic in legacy C that still misuses ``strlen``
return values as full-string buffer sizes.

This is the *narrow, statically-visible* slice of CWE-131. blight deliberately
does NOT attempt the general buffer-size-calculation problem: proving that an
arbitrary arithmetic expression sizes a buffer correctly needs value-range /
symbolic analysis that POST_V01 records — repeatedly, for the sibling CWE-190
integer overflow — as out of scope for a static PLT-and-disassembly tool.
Instead this detector anchors on the same fingerprint blight already exploits
elsewhere (compare CWE-191's size-from-subtraction shape): a sized allocation
whose size register traces back, through register-alias propagation, to the
return of ``strlen`` with no intervening adjustment by one. That
reaching-a-sink anchor is what keeps the false-positive rate low — a bare
``strlen`` call is everywhere, but a ``strlen`` whose return is the size
argument of ``malloc`` with no ``+ 1`` is the textbook NUL-terminator
off-by-one.

Heuristic (deliberately conservative — single-function, linear backward scan
with simple register-alias tracking, the same machinery proven by CWE-122,
CWE-191, and CWE-369):

  1. Find every call site to an allocator:
       * arg0 carries the size:  ``malloc``, ``alloca``, ``valloc``,
         ``pvalloc``, ``__builtin_alloca``.
       * arg1 carries the size:  ``realloc``, ``reallocarray``, ``calloc``
         (per-element size, the product can hold the same mistake).
     The size-argument register is resolved per-architecture (``rdi``/``rsi``
     on x86_64, ``x0``/``x1`` on AArch64).
  2. Backward-scan the function from the call: track the size register and any
     register it was moved from (alias chain).
  3. If we encounter ``add D, 1`` / ``inc D`` (x86_64) or ``add D, S, #1`` /
     ``add D, S, 1`` (AArch64) where ``D`` is a tracked register, the program
     accounted for the NUL terminator — the candidate is cleared, not flagged.
  4. If, with the size's return-register alias (``rax``/``x0``) still live, we
     reach a ``call sym.imp.strlen`` (or ``wcslen``), the size was produced by
     ``strlen`` with no surviving ``+ 1``: this is the off-by-one. Flagged.
  5. A non-register source (immediate / unrelated memory load) terminates the
     alias chain for that register so an unrelated earlier ``strlen`` cannot
     false-positive.

Confidence: ``low``. Reachability is not proven statically — the finding marks
an *unadjusted* ``strlen``-sized allocation, which is the statically-visible
signal. This matches the POST_V01 confidence guidance for data-flow-adjacent
heuristics (CWE-122 / CWE-191 / CWE-369 / CWE-476).

[Worker decision: scoped to an in-function backward scan anchored on an
allocator's size register, mirroring CWE-191's size-from-subtraction shape — no
CFG dominance proof, no value-range/symbolic analysis, none of which POST_V01
sanctions for the buffer-sizing CWE family. Kept distinct from CWE-122 (heap
overflow via unbounded copy of a heap buffer): CWE-122 anchors on the
*destination* of the copy; CWE-131 anchors on the *size* of the allocation
itself, the upstream off-by-one source. A call site can legitimately carry
both findings — the two detectors are complementary, not redundant.
Architecture-aware on x86_64 and AArch64, consistent with POST_V01 item 5.]
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import Instruction, R2Session

from ._argregs import DEFAULT_ARCH, arg_register_aliases
from ._common import call_sites

CWE = 131

# Allocators keyed to the argument index that carries the size/length. malloc/
# alloca take the size as arg0; realloc/reallocarray/calloc carry it as arg1.
_SIZE_ARG_INDEX: dict[str, int] = {
    "malloc": 0,
    "alloca": 0,
    "__builtin_alloca": 0,
    "valloc": 0,
    "pvalloc": 0,
    "realloc": 1,
    "reallocarray": 1,
    "calloc": 1,
}

# strlen-family return sources whose result is the off-by-one fingerprint when
# fed directly to an allocator without a ``+ 1`` adjustment.
_STRLEN_FAMILY = ("strlen", "wcslen")

_X86_64_GPRS = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
_ARM64_GPRS = tuple(f"x{i}" for i in range(0, 29))

# Sub-register aliases collapse to their canonical 64-bit name so a size tracked
# as ``rdi`` is recognized when an instruction names ``edi`` (and vice versa).
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

_BARE_REG_RE = re.compile(r"^[a-z]\w*$")
_IMM_RE = re.compile(r"^#?(?:0x0*1|1)$")


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


def _is_immediate_one(operand: str) -> bool:
    """True if the operand is the literal value 1 (with or without ``#``/``0x``)."""
    return bool(_IMM_RE.match(operand.strip()))


def _is_strlen_call(disasm: str) -> str | None:
    """If this disassembly line is a CALL/BL to a strlen-family import,
    return the symbol short name, else None.

    radare2 renders the target as ``sym.imp.strlen`` (or ``sym.strlen``); we
    match the suffix to remain layout-tolerant.
    """
    mnem, operands = _split(disasm)
    if mnem not in ("call", "bl"):
        return None
    if not operands:
        return None
    target = operands[0]
    for name in _STRLEN_FAMILY:
        if target.endswith(f".{name}") or target == name or target.endswith(f".imp.{name}"):
            return name
    return None


def _adjustment_destination(
    mnem: str, operands: list[str], arch: str
) -> str | None:
    """If this instruction increments a register by one (the NUL-terminator
    adjustment), return that register's canonical name, else None.

    Recognized forms:
      x86_64: ``inc D`` (any width), ``add D, 1``
      AArch64: ``add D, S, #1`` / ``add D, S, 1`` (S is irrelevant — the
      result lives in D, which is what we track).
    """
    if not operands:
        return None
    dst_raw = operands[0]
    if not _is_bare_reg(dst_raw):
        return None
    dst = _canon(dst_raw)

    if mnem == "inc":
        return dst
    if mnem in ("add", "adds"):
        # x86_64 form: ``add D, 1``  (2 operands, second is the immediate).
        # AArch64 form: ``add D, S, #1``  (3 operands, third is the immediate).
        if len(operands) == 2 and _is_immediate_one(operands[1]):
            return dst
        if len(operands) >= 3 and _is_immediate_one(operands[-1]):
            return dst
    return None


def _strlen_sized_before(
    instructions: list[Instruction],
    call_index: int,
    size_reg: str,
    arch: str,
) -> str | None:
    """Return the strlen-family symbol if the size register reaching the
    allocator at ``call_index`` was produced by a strlen-family call with no
    intervening ``+ 1`` adjustment, else None.

    Walks backward from the call. Maintains an alias set seeded with the size
    register; a ``mov D, S`` where ``D`` is tracked adds ``S`` to the set (the
    value came from ``S``). If a ``+ 1`` adjustment lands in a tracked
    register the candidate is cleared (the NUL was accounted for). If the
    return register (``rax``/``x0``) is alive when we hit a strlen-family
    call, the size came from strlen unadjusted — the off-by-one fingerprint.
    """
    gprs = _gprs_for(arch)
    return_reg = "rax" if arch != "arm64" else "x0"
    alive: set[str] = {size_reg}

    for ins in reversed(instructions[:call_index]):
        mnem, operands = _split(ins.disasm)

        # --- a strlen-family call upstream of the allocator size ----------
        # If the return register is still in the alive set when we hit a
        # strlen call, the size was produced by strlen and never adjusted
        # by +1 along the way — the off-by-one fingerprint.
        strlen_name = _is_strlen_call(ins.disasm)
        if strlen_name is not None:
            if return_reg in alive:
                return strlen_name
            # A strlen call that does NOT feed the size register clobbers the
            # return register, so any earlier strlen cannot reach the size
            # through rax/x0 — drop the return register from the alive set so
            # we do not chain past this clobber.
            alive.discard(return_reg)
            # Any *other* call between the size-producing strlen and the
            # allocator also clobbers the return register and breaks the link;
            # treating that as a clean break keeps the heuristic conservative.
            continue

        # A non-strlen call also clobbers the return register, breaking the
        # chain — the size cannot have come from a strlen earlier than this.
        if mnem in ("call", "bl"):
            alive.discard(return_reg)
            continue

        # --- +1 adjustment that accounts for the NUL terminator -----------
        adj_dst = _adjustment_destination(mnem, operands, arch)
        if adj_dst is not None and adj_dst in alive:
            # The size was incremented by 1 along the path — NUL accounted
            # for. The size register's value at the allocator is *after* this
            # adjustment, so the strlen result (if any) is safely bounded.
            return None

        if not operands:
            continue

        # --- alias propagation: mov D, S where D is tracked → also track S
        if mnem == "mov" and len(operands) >= 2:
            dst_raw = operands[0]
            dst = _canon(dst_raw) if _is_bare_reg(dst_raw) else None
            src = operands[1].strip()
            if dst is not None and dst in alive:
                if _is_bare_reg(src):
                    csrc = _canon(src)
                    if csrc in gprs:
                        alive.add(csrc)
                # A non-register source (immediate / memory load) terminates
                # the backward chain for this register: the size value
                # originates here, not from an earlier strlen return. Drop
                # the dst so an unrelated earlier strlen cannot false-positive.
                alive.discard(dst)
                if not alive:
                    return None
            continue

        # AArch64 register-move forms (mov xD, xS handled above as `mov`);
        # ldr loads a fresh value into the destination, terminating that chain.
        if mnem in ("ldr", "ldur", "lea") and len(operands) >= 1:
            dst_raw = operands[0]
            dst = _canon(dst_raw) if _is_bare_reg(dst_raw) else None
            if dst is not None and dst in alive:
                alive.discard(dst)
                if not alive:
                    return None
            continue

    # Reached the function start with no strlen reaching the size register.
    return None


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

        call_index = next(
            (i for i, ins in enumerate(instructions) if ins.addr == xref.from_addr),
            None,
        )
        if call_index is None:
            continue

        size_reg = _arg_register(arch, _SIZE_ARG_INDEX[symbol])
        strlen_src = _strlen_sized_before(instructions, call_index, size_reg, arch)
        if strlen_src is None:
            continue

        findings.append(
            Finding(
                cwe=CWE,
                function=func,
                address=hex(xref.from_addr),
                evidence=(
                    f"size argument to {symbol} is the return of {strlen_src} with "
                    "no +1 adjustment for the NUL terminator (off-by-one buffer "
                    "size — heap overflow on subsequent string copy)"
                ),
                symbol=symbol,
                # The +1 adjustment may live outside the in-function view;
                # per POST_V01 confidence guidance for data-flow-adjacent
                # heuristics this is a low-confidence finding (matching
                # CWE-122 / CWE-191 / CWE-369 / CWE-476).
                confidence="low",
            )
        )
    return findings
