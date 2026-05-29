"""CWE-122: Heap-Based Buffer Overflow.

Flags the statically-detectable heap-overflow pattern: a *heap* buffer is
obtained from an allocator (``malloc`` / ``calloc`` / ``realloc`` / ``strdup`` /
``aligned_alloc`` / ``valloc`` / ``memalign`` / ``reallocarray``), and that same
pointer is then handed — in the *destination* argument register — to an
*unbounded* copy routine (``strcpy`` / ``strcat`` / ``sprintf`` / ``vsprintf`` /
``gets``) in the same function without first being reassigned. The allocation
fixes the destination's size; an unbounded copy writes as many bytes as the
source contains, so the moment a fixed-size heap buffer is the destination of a
length-unaware copy it can be overflowed on the heap. The freshly-allocated
pointer reaching the copy's destination register is the fingerprint.

This is the same single-function, forward-scan, register-alias shape already
proven by CWE-416 (use-after-free) and CWE-476 (NULL-pointer-dereference): the
*source* is the allocator's return value (which lives in the return register —
``rax`` on x86_64, ``x0`` on AArch64 — at the allocation call site), the *sink*
is an unbounded-copy call reached while that pointer still aliases the
destination (first-argument) register, and the *sanitizer* is a reassignment of
the destination register before the copy — a reload with an unrelated value
that severs the heap alias.

Deliberately distinct from CWE-120 (Buffer Copy without Checking Size of Input).
CWE-120 flags *every* call to a dangerous copy routine regardless of where it
writes — the presence of the function IS the finding. CWE-122 is narrower and
more specific: it fires only when the copy's destination is provably a *heap*
allocation visible in the same function, which is the precise signal that the
overflow lands on the heap (as opposed to a stack buffer, a global, or an
already-correctly-sized region). A call site can legitimately carry both: the
generic CWE-120 signal and the heap-specific CWE-122 signal.

Heuristic (deliberately conservative — full heap modeling / symbolic execution
is out of scope per POST_V01, so this stays a single-function, linear forward
scan with simple register-alias tracking, mirroring CWE-416):

  1. Find every call site to a heap allocator.
  2. The allocated pointer is returned in the return register (``rax`` on
     x86_64, ``x0`` on AArch64). Seed the alias set with the canonical 64-bit
     name of that register.
  3. Walk the instructions *after* the allocation call, in order:
       * A register-to-register move of a live alias propagates the alias into
         the destination (``mov rbx, rax`` makes ``rbx`` hold the heap pointer
         too), so a later ``strcpy(rbx, …)`` is still a heap overflow.
       * Storing the heap pointer to memory (``mov [rbp-8], rax``) or
         overwriting a live alias with a bare/unrelated value kills that alias —
         the heap pointer escapes our view (it may be copied into bounded later,
         or its size tracked elsewhere) so we stop tracking it. If no aliases
         remain, do NOT flag.
       * If an *unbounded* copy call is reached while the destination
         (first-argument) register still holds a live alias of the heap pointer
         — i.e. the heap buffer is the copy destination — flag a heap overflow.
       * A *bounded* copy (``strncpy`` / ``snprintf`` / ``strlcpy`` / ``memcpy``
         with an explicit length) is intentionally NOT flagged here: the length
         argument is what prevents (or, when wrong, causes) the overflow, and
         judging it requires value-range analysis that is out of scope. Those
         remain CWE-120's broader territory.
  4. If no unbounded copy targets the heap pointer before the function ends, do
     NOT flag.

Because reachability of the copy along the allocated path is not proven
statically (an intervening branch may resize or reallocate on a path we cannot
see), every finding is ``low`` confidence — matching the POST_V01 guidance for
the heap-class CWEs and mirroring CWE-416 / CWE-415 / CWE-476.

[Worker decision: scoped to an in-function, post-allocation linear scan with
simple register-alias tracking, exactly like CWE-416/CWE-476 — no CFG
reconstruction, no inter-procedural analysis, no heap-state/size modeling. The
allocator return register and the destination (first-argument) register are
resolved per-architecture so this works on x86_64 and AArch64, consistent with
POST_V01 item 5. Only *unbounded* copies are sinks; *bounded* copies are
intentionally excluded because vetting their length argument needs value-range
analysis that POST_V01 repeatedly records as out of scope. Kept crisply distinct
from CWE-120, which flags the dangerous copy unconditionally — CWE-122 requires
the destination to be a same-function heap allocation, the precise heap-overflow
signal.]
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._argregs import DEFAULT_ARCH, arg_register_aliases
from ._common import call_sites

CWE = 122

# Heap allocators whose return value is a freshly-allocated buffer of a fixed
# size. ``realloc`` / ``reallocarray`` are included: their *return* value is the
# (possibly moved) live heap buffer, which is exactly what we seed from.
ALLOCATORS = (
    "malloc",
    "calloc",
    "realloc",
    "reallocarray",
    "strdup",
    "strndup",
    "aligned_alloc",
    "valloc",
    "pvalloc",
    "memalign",
)

# Unbounded copy/format routines: they write the full length of the *source*
# into the destination with no awareness of the destination's capacity, so a
# fixed-size heap destination can be overflowed. The destination is the
# first-argument register. (``gets`` reads an unbounded line into arg0.)
UNBOUNDED_COPIES = (
    "strcpy",
    "stpcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "gets",
)

# Full-width general registers we are willing to track a heap alias through.
_X86_64_GPRS = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
_ARM64_GPRS = tuple(f"x{i}" for i in range(0, 29))

# Sub-register aliases collapse to their canonical 64-bit name so a pointer
# tracked as ``rax`` is still recognized when an instruction names ``eax``.
_SUBREG_TO_64: dict[str, str] = {
    "eax": "rax", "ax": "rax",
    "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp",
    "di": "rdi", "si": "rsi", "dx": "rdx", "cx": "rcx",
    **{f"w{i}": f"x{i}" for i in range(0, 31)},
    **{f"r{i}d": f"r{i}" for i in range(8, 16)},
}

# Match "<mnemonic> <dst>, <src>" capturing dst and the rest.
_TWO_OP = re.compile(r"^\s*(\w+)\s+([\w.]+)\s*,\s*(.+)$")
# Match "<mnemonic> <op>" (single operand, e.g. `call sym.imp.foo`).
_ONE_OP = re.compile(r"^\s*(\w+)\s+([\w.]+)")

# A call target naming one of the unbounded copies — used to recognize the sink
# from the disassembly of the call instruction.
_COPY_TARGET = re.compile(
    r"\b(?:" + "|".join(re.escape(c) for c in UNBOUNDED_COPIES) + r")\b"
)


def _gprs_for(arch: str) -> tuple[str, ...]:
    return _ARM64_GPRS if arch == "arm64" else _X86_64_GPRS


def _canon(reg: str) -> str:
    """Collapse a register token to its canonical 64-bit name."""
    return _SUBREG_TO_64.get(reg, reg)


def _arg_register(arch: str, index: int) -> str:
    """Canonical 64-bit name of argument register ``index`` on ``arch``."""
    aliases = arg_register_aliases(
        arch if arch in ("x86_64", "arm64") else DEFAULT_ARCH, index
    )
    return _canon(aliases[0])


def _return_register(arch: str) -> str:
    """Canonical 64-bit name of the integer/pointer return register on ``arch``."""
    return "x0" if arch == "arm64" else "rax"


def _calls_unbounded_copy(disasm: str) -> bool:
    """True if this call instruction targets an unbounded copy routine."""
    return bool(_COPY_TARGET.search(disasm))


def _detect_in_function(instructions, call_addr: int, arch: str) -> bool:
    """Return True if the heap pointer allocated at ``call_addr`` becomes the
    destination of an unbounded copy with no intervening reassignment, scanning
    forward within the function."""
    ret = _return_register(arch)
    dst_arg = _arg_register(arch, 0)
    gprs = _gprs_for(arch)

    # Registers currently holding the freshly-allocated heap pointer.
    alive: set[str] = {ret}

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

        # --- An unbounded copy whose destination is the live heap pointer. ---
        # Checked before the reassignment logic: if the destination (first-arg)
        # register still aliases the heap allocation and we reach an unbounded
        # copy, the fixed-size heap buffer is the copy destination → overflow.
        if (
            mnem in ("call", "bl", "blr")
            and _calls_unbounded_copy(disasm)
            and dst_arg in alive
        ):
            return True

        # --- mov handling: alias propagation, escape, or reassignment. ---
        if mnem == "mov" and two:
            src_reg = _canon(src.strip())
            if cdst in gprs and "[" not in src and src_reg in alive:
                # mov dst, <live alias>  → dst now aliases the heap pointer too.
                alive.add(cdst)
            elif cdst in alive:
                # mov <live alias>, <fresh value / reload>  → alias killed.
                alive.discard(cdst)
                if not alive:
                    return False
            # A store of a live alias to memory (`mov [rbp-8], rax`) lets the
            # heap pointer escape our in-function view; we keep tracking the
            # register copy if any remains but no longer follow the stack slot.
            continue

        # --- lea into a live alias reassigns it with a fresh address. ---
        if mnem == "lea" and two and cdst in alive:
            alive.discard(cdst)
            if not alive:
                return False
            continue

        # --- xor reg, reg zeroes a live alias → killed. ---
        if mnem == "xor" and two and cdst in alive and _canon(src.strip()) == cdst:
            alive.discard(cdst)
            if not alive:
                return False
            continue

    return False


def detect(session: R2Session) -> list[Finding]:
    findings: list[Finding] = []

    arch = session.arch()
    func_cache: dict[str, list] = {}

    for symbol, xref in call_sites(session, ALLOCATORS):
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
                    f"heap buffer from {symbol} is the destination of an "
                    "unbounded copy in the same function without an intervening "
                    "size-aware reassignment (possible heap buffer overflow)"
                ),
                symbol=symbol,
                # Reachability of the copy along the allocated path is not proven
                # statically, so per POST_V01 this is a low-confidence finding
                # (matching CWE-416 / CWE-415 / CWE-476).
                confidence="low",
            )
        )
    return findings
