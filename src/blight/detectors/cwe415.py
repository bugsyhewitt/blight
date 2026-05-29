"""CWE-415: Double Free.

Flags the statically-detectable double-free pattern: a pointer is passed to
``free`` (the deallocation that makes it dangling), and the *same pointer
register* is handed to ``free`` *again* later in the same function without first
being reassigned (set to ``NULL`` / reloaded with a fresh value) and without an
intervening reallocation that gives it a live address again. Releasing the same
storage twice corrupts the allocator's bookkeeping; the freed register still
carrying the stale address and reaching a second ``free`` is the fingerprint.

This is the same taint-propagation shape as its sibling CWE-416
(use-after-free): the *source* is the freed pointer (which lives in the
first-argument register at the ``free`` call site), the *sink* is a *second*
``free`` reached while that register still aliases the freed pointer, and the
*sanitizer* is a reassignment of the register — the canonical ``ptr = NULL;``
after ``free(ptr)``, or any reload of the register with an unrelated value —
which severs the dangling alias before it can be freed again. Where CWE-416's
sink is *any* read of the dangling pointer, CWE-415's sink is specifically a
second deallocation of it, so the two detectors are deliberately kept distinct:
a double-free is a narrower, higher-confidence signal than a generic use.

Heuristic (deliberately conservative — full heap modeling / symbolic execution
is out of scope per POST_V01, so this stays a single-function, linear forward
scan with simple register-alias tracking, mirroring CWE-416):

  1. Find every call site to a freeing routine (``free`` / ``cfree``).
  2. The pointer to be freed arrives in the first-argument register
     (``rdi`` on x86_64, ``x0`` on AArch64). Seed the alias set with the
     canonical 64-bit name of that register.
  3. Walk the instructions *after* the call, in order:
       * If the freed pointer is *reassigned* first — written with a fresh
         value (``mov rdi, 0`` / ``xor rdi, rdi`` on x86_64, ``mov x0, 0`` on
         AArch64, ``lea`` of a fresh address, or a reload from memory /
         another register that is not itself a live alias) — the dangling alias
         is killed. Stop tracking that register; if no aliases remain, the
         pointer can no longer reach a second free safely → do NOT flag.
       * A register-to-register move of a live alias propagates the alias into
         the destination (``mov rbx, rdi`` makes ``rbx`` dangling too), so a
         later ``free(rbx)`` is still a double-free.
       * If a *second* ``free`` is reached while the first-argument register
         still holds a live alias of the freed pointer — i.e. the dangling
         pointer is passed to ``free`` again — flag a double-free.
       * Any *other* call (to a non-deallocator) that consumes the live alias
         in the first-argument register does NOT, by itself, prove a double
         free — that is a generic use, which is CWE-416's territory, not this
         detector's. We only flag a second *deallocation*.
  4. If no second free is seen before the function ends, do NOT flag.

Because reachability of the second free along the freed path is not proven
statically (an intervening branch may reassign the pointer on a path we cannot
see), every finding is ``low`` confidence — matching the POST_V01 guidance for
the heap-lifetime CWE classes and mirroring CWE-416 / CWE-476 / CWE-252.

[Worker decision: scoped to an in-function, post-call linear scan with simple
register-alias tracking, exactly like CWE-416 — no CFG reconstruction, no
inter-procedural analysis, no heap-state modeling. The first second-``free`` of
a live alias is the sink; a non-deallocator call of the alias is intentionally
NOT flagged here because that generic use is already CWE-416's signal, keeping
the two detectors crisply separated. ``realloc`` is intentionally NOT treated as
a deallocator (its return value, not its argument, is the live pointer, and the
old pointer is only freed on success), consistent with CWE-416 — so the detector
keeps to the unambiguous ``free``/``cfree`` deallocators. The freed-pointer
argument register and the kill idioms are resolved per-architecture so this
works on x86_64 and AArch64, consistent with POST_V01 item 5.]
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._argregs import DEFAULT_ARCH, arg_register_aliases
from ._common import call_sites

CWE = 415

# Deallocators after which the argument pointer is dangling. ``realloc`` is
# deliberately excluded (see the module docstring), matching CWE-416.
DANGEROUS = ("free", "cfree")

# Full-width general registers we are willing to track a dangling alias through.
_X86_64_GPRS = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
_ARM64_GPRS = tuple(f"x{i}" for i in range(0, 29))

# Sub-register aliases collapse to their canonical 64-bit name so a pointer
# tracked as ``rdi`` is still recognized when an instruction names ``edi``.
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

# A call target naming one of the deallocators — used to recognize the second
# ``free`` from the disassembly of the call instruction.
_FREE_TARGET = re.compile(r"\b(?:" + "|".join(re.escape(d) for d in DANGEROUS) + r")\b")


def _gprs_for(arch: str) -> tuple[str, ...]:
    return _ARM64_GPRS if arch == "arm64" else _X86_64_GPRS


def _canon(reg: str) -> str:
    """Collapse a register token to its canonical 64-bit name."""
    return _SUBREG_TO_64.get(reg, reg)


def _first_arg_register(arch: str) -> str:
    """Canonical 64-bit name of the first-argument register on ``arch``."""
    aliases = arg_register_aliases(arch if arch in ("x86_64", "arm64") else DEFAULT_ARCH, 0)
    return _canon(aliases[0])


def _calls_free(disasm: str) -> bool:
    """True if this call instruction targets a deallocator routine."""
    return bool(_FREE_TARGET.search(disasm))


def _detect_in_function(instructions, call_addr: int, arch: str) -> bool:
    """Return True if the pointer freed at ``call_addr`` is freed *again* with no
    intervening reassignment, scanning forward within the function."""
    arg0 = _first_arg_register(arch)
    gprs = _gprs_for(arch)

    # Registers currently holding the (now-dangling) freed pointer.
    alive: set[str] = {arg0}

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

        # --- A second free of a live (dangling) alias → double-free. ---
        # Checked before the reassignment logic: if the first-argument register
        # still aliases the freed pointer and we reach another `free` call, the
        # same storage is released twice.
        if mnem in ("call", "bl", "blr") and _calls_free(disasm) and arg0 in alive:
            return True

        # --- xor reg, reg zeroes the register → alias killed (safe). ---
        if mnem == "xor" and two and cdst in alive and _canon(src.strip()) == cdst:
            alive.discard(cdst)
            if not alive:
                return False
            continue

        # --- mov handling: alias propagation or reassignment. ---
        if mnem == "mov" and two and cdst in gprs:
            src_reg = _canon(src.strip())
            if "[" not in src and src_reg in alive:
                # mov dst, <live alias>  → dst now aliases the freed pointer too.
                alive.add(cdst)
            elif cdst in alive:
                # mov <live alias>, <fresh value / reload>  → alias killed.
                alive.discard(cdst)
                if not alive:
                    return False
            continue

        # --- lea into a live alias reassigns it with a fresh address. ---
        if mnem == "lea" and two and cdst in alive:
            alive.discard(cdst)
            if not alive:
                return False
            continue

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
                    f"pointer freed by {symbol} is passed to a second free in the "
                    "same function without being reassigned (possible double-free)"
                ),
                symbol=symbol,
                # The reachability of the second free along the freed path is not
                # proven statically, so per POST_V01 this is a low-confidence
                # finding (matching CWE-416).
                confidence="low",
            )
        )
    return findings
