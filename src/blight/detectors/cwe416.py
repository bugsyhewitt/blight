"""CWE-416: Use After Free.

Flags the most common statically-detectable use-after-free pattern: a pointer
is passed to ``free`` (the dangling-pointer *source*), and the *same pointer
register* is then read — dereferenced through a memory operand, or passed onward
as an argument — later in the same function without first being reassigned (set
to ``NULL`` / overwritten with a fresh value). Using a pointer after the storage
it names has been released is the weakness; the freed register still carrying the
stale address and being touched again is the fingerprint.

This is a taint-propagation problem of the same shape as CWE-476
(NULL-pointer-dereference) and CWE-252 (unchecked return value): the *source* is
the freed pointer (which lives in the first-argument register at the ``free``
call site), the *sink* is any subsequent read of that register, and the
*sanitizer* is a reassignment of the register — the canonical ``ptr = NULL;``
after ``free(ptr)``, or any reload of the register with an unrelated value —
which severs the dangling alias.

Heuristic (deliberately conservative — full heap modeling / symbolic execution
is out of scope per POST_V01, so this stays a single-function, linear forward
scan with simple register-alias tracking):

  1. Find every call site to a freeing routine (``free`` / ``cfree``).
  2. The pointer to be freed arrives in the first-argument register
     (``rdi`` on x86_64, ``x0`` on AArch64). Seed the alias set with the
     canonical 64-bit name of that register.
  3. Walk the instructions *after* the call, in order:
       * If the freed pointer is *reassigned* first — written with a fresh
         value (``mov rdi, 0`` / ``xor rdi, rdi`` on x86_64, ``mov x0, 0`` on
         AArch64, or a reload from memory / another register that is not itself
         a live alias) — the dangling alias is killed. Stop tracking that
         register; if no aliases remain, the pointer is safe. Do NOT flag.
       * If the freed pointer is *dereferenced* first — a memory operand
         ``[reg ...]`` that names a live alias reads/writes through the stale
         pointer — flag a use-after-free.
       * If the freed pointer is *passed onward* first — moved into an
         argument register (``mov rdi, <alias>`` ahead of a ``call``) or itself
         consumed by a following ``call`` while still live — the freed pointer
         is used again; flag it.
       * A register-to-register move of a live alias propagates the alias into
         the destination (``mov rbx, rdi`` makes ``rbx`` dangling too).
  4. If neither a reassignment nor a use is seen before the function ends, do
     NOT flag — we can only reason about a use we can actually see.

Because reachability of the use along the freed path is not proven statically
(an intervening branch may reassign the pointer on the path we cannot see), and
because aggressive compilers reuse the argument register for unrelated values,
every finding is ``low`` confidence — matching the POST_V01 guidance for the
heap-lifetime CWE classes and mirroring CWE-476 / CWE-252.

[Worker decision: scoped to an in-function, post-call linear scan with simple
register-alias tracking, exactly like CWE-476/CWE-252 — no CFG reconstruction,
no inter-procedural analysis, no heap-state modeling. The freed-pointer argument
register and the kill/use idioms are resolved per-architecture so this works on
x86_64 and AArch64, consistent with POST_V01 item 5. ``realloc`` is intentionally
NOT treated as a free here: its return value (not its argument) is the live
pointer and the old pointer is only dangling on the failure path, which this
single-pass heuristic cannot disambiguate without raising false positives — so
the detector keeps to the unambiguous ``free``/``cfree`` deallocators.]
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._argregs import DEFAULT_ARCH, arg_register_aliases
from ._common import call_sites

CWE = 416

# Deallocators after which the argument pointer is dangling. ``realpath`` /
# ``realloc`` are deliberately excluded (see the module docstring): realloc's
# old pointer is only freed on success and the live pointer is its *return*
# value, which this argument-tracking pass cannot model without false positives.
DANGEROUS = ("free", "cfree")

# Full-width general registers we are willing to track a dangling alias through.
# A pointer lives in a 64-bit register; we track the canonical 64-bit name.
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


def _gprs_for(arch: str) -> tuple[str, ...]:
    return _ARM64_GPRS if arch == "arm64" else _X86_64_GPRS


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


def _first_arg_register(arch: str) -> str:
    """Canonical 64-bit name of the first-argument register on ``arch``."""
    aliases = arg_register_aliases(arch if arch in ("x86_64", "arm64") else DEFAULT_ARCH, 0)
    return _canon(aliases[0])


def _detect_in_function(instructions, call_addr: int, arch: str) -> bool:
    """Return True if the pointer freed at ``call_addr`` is *used* again with no
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

        # --- Dereference of a live (dangling) pointer → use-after-free. ---
        # Any memory operand `[ ... reg ... ]` that names a live alias reads or
        # writes through the freed pointer. Checked before the reassignment
        # logic so that `mov rax, [rdi]` (a *read through* the freed register,
        # which also writes rax) is correctly classified as a USE, not a kill.
        if alive & _mem_regs(disasm):
            return True

        # --- Reassignment of a dangling register → alias killed (safe). ---
        # A write to a live alias with a *bare* value (no memory operand, and
        # the source is not itself another live alias) severs the dangling
        # pointer: the canonical `ptr = NULL;` (`mov rdi, 0` / `xor rdi, rdi` /
        # AArch64 `mov x0, 0`) or a reload with an unrelated register/immediate.
        if mnem == "xor" and two and cdst in alive and _canon(src.strip()) == cdst:
            # xor reg, reg  → zeroes the register, killing the alias.
            alive.discard(cdst)
            if not alive:
                return False
            continue

        if mnem == "mov" and two and cdst in gprs:
            src_reg = _canon(src.strip())
            if "[" not in src and src_reg in alive:
                # mov dst, <live alias>  → dst now aliases the freed pointer too.
                alive.add(cdst)
            elif cdst in alive and "[" not in src:
                # mov <live alias>, <fresh bare value>  → alias killed.
                alive.discard(cdst)
                if not alive:
                    return False
            # (A reload `mov <live alias>, [mem]` is handled by the deref check
            # above when the memory operand names a live alias; an unrelated
            # `mov <live alias>, [mem]` reassigns it — also a kill.)
            elif cdst in alive:
                alive.discard(cdst)
                if not alive:
                    return False
            continue

        # --- `lea` into a live alias reassigns it with a fresh address. ---
        # `lea rdi, str.done` / `lea rdi, [rbp - 0x8]` computes an address that
        # is not the freed pointer (the deref check above already flagged the
        # case where the lea's memory operand names a live alias), so it severs
        # the dangling alias.
        if mnem == "lea" and two and cdst in alive:
            alive.discard(cdst)
            if not alive:
                return False
            continue

        # --- The freed pointer passed onward to / consumed by a call. ---
        # If a call is reached while the freed pointer is still live in the
        # first-argument register, it is being passed to another routine — a
        # use of the dangling pointer.
        if mnem in ("call", "bl", "blr") and arg0 in alive:
            return True

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
                    f"pointer freed by {symbol} is used again without being "
                    "reassigned (possible use-after-free of a dangling pointer)"
                ),
                symbol=symbol,
                # The reachability of the use along the freed path is not proven
                # statically, so per POST_V01 this is a low-confidence finding.
                confidence="low",
            )
        )
    return findings
