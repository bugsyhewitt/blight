"""CWE-401: Missing Release of Memory after Effective Lifetime (memory leak).

Flags the statically-detectable memory-leak pattern: a *heap* buffer is obtained
from an allocator (``malloc`` / ``calloc`` / ``realloc`` / ``reallocarray`` /
``strdup`` / ``strndup`` / ``aligned_alloc`` / ``valloc`` / ``pvalloc`` /
``memalign``), and the *only* register holding that pointer is then **overwritten
with an unrelated value** — before the pointer is ever freed, stored to memory,
returned, or otherwise handed off — so the sole handle to the allocation is lost
inside the same function. Once the last live alias of a freshly-allocated buffer
is clobbered with no surviving copy, the program can never call ``free`` on it:
the memory is leaked. The freshly-allocated pointer being discarded (its register
reloaded) with no intervening free/escape is the fingerprint.

This is the *inverse-sink* sibling of the heap-lifetime detectors already proven
in the suite (CWE-416 use-after-free, CWE-415 double-free, CWE-122 heap
overflow): the *source* is identical — the allocator's return value, which lives
in the return register (``rax`` on x86_64, ``x0`` on AArch64) at the allocation
call site — and the alias-tracking machinery (register-to-register moves
propagate the alias; a store to memory or a reassignment kills it) is the same
single-function forward scan. What differs is the *sink*: where CWE-416's sink is
a *use* of a freed pointer and CWE-415's is a *second free*, CWE-401's sink is the
**loss** of the last live alias with no preceding free — the absence of release
where release was required.

Heuristic (deliberately conservative — full heap-lifetime / escape analysis is
out of scope per POST_V01, so this stays a single-function, linear forward scan
with simple register-alias tracking, mirroring CWE-415 / CWE-416 / CWE-122):

  1. Find every call site to a heap allocator.
  2. The allocated pointer is returned in the return register (``rax`` on
     x86_64, ``x0`` on AArch64). Seed the alias set with the canonical 64-bit
     name of that register.
  3. Walk the instructions *after* the allocation call, in order:
       * A register-to-register move of a live alias propagates the alias into
         the destination (``mov rbx, rax`` makes ``rbx`` hold the heap pointer
         too), so the handle survives in the copy.
       * A *store of a live alias to memory* (``mov [rbp-8], rax`` /
         ``mov [rbx], rax`` — any memory destination) lets the heap pointer
         escape our in-function view (it may be a struct field, a global, an
         out-parameter, or a slot freed elsewhere). We can no longer prove it
         leaks → stop tracking and do NOT flag. This is the conservative,
         false-positive-avoiding choice: an escaped pointer is presumed managed.
       * A *free* (``free`` / ``cfree``) reached while a live alias sits in the
         first-argument register releases the buffer → do NOT flag. (We also
         clear all aliases on any free that consumes a live alias.)
       * The freed/escaped/handed-off pointer reaching the *return register* at
         (or just before) a ``ret`` is ownership transfer to the caller → the
         caller is responsible for freeing it, so do NOT flag.
       * Passing a live alias to *any other* call leaves ownership ambiguous
         (the callee may take ownership or free it) — conservatively stop
         tracking that path and do NOT flag.
       * Overwriting the LAST live alias with an unrelated value — a reload from
         memory, a fresh ``lea`` address, an immediate, an ``xor reg,reg`` zero,
         or a register that is not itself a live alias — with no surviving copy
         and no preceding free/escape/return/handoff is the leak: the only
         handle to the allocation is gone → flag.
  4. If the scan ends without the last alias being clobbered (e.g. the function
     simply ``ret``s while the pointer is still live in a register, which on the
     common path means it is being returned), do NOT flag — that is a caller
     handoff, not a proven leak.

Because reachability of the clobber along the allocated path is not proven
statically (an intervening branch may free or store the pointer on a path we
cannot see), every finding is ``low`` confidence — matching the POST_V01 guidance
for the heap-lifetime CWE classes and mirroring CWE-415 / CWE-416 / CWE-122.

[Worker decision: chosen over CWE-457 (uninitialized variable use), which
POST_V01 records as needing def-use dataflow over stack slots across basic blocks
— the CFG/value-flow modeling repeatedly recorded as out of scope. CWE-401
reduces to the *same* in-function forward-scan-with-register-alias-tracking shape
already shipped for CWE-416/CWE-415/CWE-122, so it lands as a small,
infrastructure-free PR. Scoped deliberately narrow: the *only* sink is the
clobber of the LAST live register alias with no preceding free/escape/return/
handoff — a register reload that severs the sole handle (the canonical
``p = malloc(); p = q;`` overwrite). A store to memory, a free, a return-register
handoff, and a pass to any other call are all treated as "we can no longer prove
a leak" and suppress the finding, which keeps false positives low (the dominant
risk for a leak detector) at the cost of missing leaks that escape our register
view. ``realloc`` / ``reallocarray`` are included as allocators because their
*return* value is the live (possibly moved) heap buffer that must be freed,
exactly as in CWE-122. The allocator return register and the first-argument /
return registers are resolved per-architecture so this works on x86_64 and
AArch64, consistent with POST_V01 item 5. Kept crisply distinct from CWE-415/416
(whose sinks are a second free / a use of a *freed* pointer) — here nothing is
freed at all, which is the whole point.]
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._argregs import DEFAULT_ARCH, arg_register_aliases
from ._common import call_sites

CWE = 401

# Heap allocators whose return value is a freshly-allocated buffer the caller
# must eventually free. ``realloc`` / ``reallocarray`` are included: their
# *return* value is the (possibly moved) live heap buffer, which is what we seed
# from — matching CWE-122.
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

# Deallocators: a live alias reaching one of these (in the first-argument
# register) releases the buffer, so there is no leak.
DEALLOCATORS = ("free", "cfree")

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
# A call target naming a deallocator — recognizes a free from the call disasm.
_FREE_TARGET = re.compile(
    r"\b(?:" + "|".join(re.escape(d) for d in DEALLOCATORS) + r")\b"
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


def _calls_free(disasm: str) -> bool:
    """True if this call instruction targets a deallocator routine."""
    return bool(_FREE_TARGET.search(disasm))


def _detect_in_function(instructions, call_addr: int, arch: str) -> bool:
    """Return True if the heap pointer allocated at ``call_addr`` has its last
    live register alias overwritten with no intervening free / store-to-memory /
    return-handoff / pass-to-call, scanning forward within the function."""
    ret_reg = _return_register(arch)
    arg0 = _arg_register(arch, 0)
    gprs = _gprs_for(arch)

    # Registers currently holding the freshly-allocated heap pointer.
    alive: set[str] = {ret_reg}

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

        # --- A return while a live alias still holds the pointer is a caller
        # handoff (the pointer is being returned / left in the return register),
        # not a proven leak. Also reached when no operand-bearing instruction
        # matched (e.g. a bare `ret`). ---
        mnem0 = disasm.split(None, 1)[0] if disasm else ""
        if mnem0 in ("ret", "retn"):
            return False

        # --- A store of a live alias to memory lets the pointer escape our
        # in-function view (struct field, global, out-parameter, slot freed
        # elsewhere). Handled here, before the `_TWO_OP` split, because a
        # size-prefixed store (`mov qword [rbp-8], rax`) does not match the
        # register-to-register two-operand shape. The pointer being stored is
        # the token after the final comma; if it is a live alias, stop tracking
        # and do NOT flag — an escaped pointer is conservatively presumed
        # managed. (A memory *read* into a register is handled in the mov
        # branch below as a clobber.) ---
        if mnem0 in ("mov", "str", "stp", "stur") and "[" in disasm:
            src_tail = _canon(disasm.rsplit(",", 1)[-1].strip().rstrip("]!"))
            # On AArch64 a store names the source register FIRST (`str x0,
            # [sp, 8]`); on x86_64 the source is last. Check both ends.
            head_reg = _canon(disasm.split(None, 2)[1].rstrip(",")) if len(
                disasm.split()
            ) > 1 else ""
            if src_tail in alive or (mnem0 in ("str", "stp", "stur") and head_reg in alive):
                return False

        if not one:
            continue

        mnem = one.group(1)
        if two:
            dst, src = two.group(2), two.group(3)
        else:
            dst, src = one.group(2), ""

        cdst = _canon(dst)

        # --- A free of a live alias releases the buffer → no leak. ---
        if mnem in ("call", "bl", "blr"):
            if _calls_free(disasm) and arg0 in alive:
                return False
            # Any other call may take ownership of the pointer if a live alias
            # sits in the first-argument register — conservatively stop here.
            if arg0 in alive:
                return False
            continue

        # --- mov handling: alias propagation, memory-read clobber, or reload. ---
        if mnem == "mov" and two:
            # A memory *read* into a live alias (`mov rax, [rbp-8]`) overwrites
            # that alias with an unrelated value. (Stores to memory were already
            # handled above and returned.)
            if "[" in src:
                if cdst in alive:
                    alive.discard(cdst)
                    if not alive:
                        return True
                continue

            src_reg = _canon(src.strip())
            if cdst in gprs and src_reg in alive:
                # mov dst, <live alias>  → dst now aliases the heap pointer too.
                alive.add(cdst)
            elif cdst in alive:
                # mov <live alias>, <fresh value / reload>  → this alias clobbered.
                alive.discard(cdst)
                if not alive:
                    # The last handle to the allocation is gone, unfreed → leak.
                    return True
            continue

        # --- lea into a live alias overwrites it with a fresh address. ---
        if mnem == "lea" and two and cdst in alive:
            alive.discard(cdst)
            if not alive:
                return True
            continue

        # --- xor reg, reg zeroes a live alias → handle lost. ---
        if mnem == "xor" and two and cdst in alive and _canon(src.strip()) == cdst:
            alive.discard(cdst)
            if not alive:
                return True
            continue

    # Scan ended without the last alias being clobbered (e.g. fell off the end
    # of the disassembly while the pointer was still live) — not a proven leak.
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
                    f"heap buffer from {symbol} has its only register alias "
                    "overwritten in the same function without being freed, "
                    "stored, or returned (possible memory leak)"
                ),
                symbol=symbol,
                # Reachability of the clobber along the allocated path is not
                # proven statically, so per POST_V01 this is a low-confidence
                # finding (matching CWE-415 / CWE-416 / CWE-122).
                confidence="low",
            )
        )
    return findings
