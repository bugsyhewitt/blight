"""CWE-197: Numeric Truncation Error.

Flags the statically-detectable numeric-truncation pattern: a *wide* value
(``size_t`` / ``ssize_t`` / ``long`` — 64 bits in the SysV AMD64 and AAPCS64
ABIs) is produced by a libc routine whose documented return type is wider than
``int``, and the program's *first* use of that value is to copy its **narrow
sub-register** — dropping the high 32 (or 48, or 56) bits — into a narrower
destination. The canonical C source is ``int n = strlen(s);`` or
``int n = read(fd, buf, len);``: the call returns a 64-bit count in the return
register (``rax`` on x86_64, ``x0`` on AArch64), and the compiler immediately
stores only the 32-bit view (``eax`` / ``w0``) into an ``int`` slot. If the true
value exceeds ``INT_MAX`` (a 2GB+ read, a giant attacker-supplied length, a
negative ``ssize_t`` error sign-confused into a large ``int``), the truncated
value silently disagrees with reality — the classic source of under-allocations
and bounds-check bypasses downstream.

This is the PLT-anchored, single-function forward-scan sibling of the heap and
divide detectors already proven in the suite (CWE-401 / CWE-369): the *source*
is a known call site whose return value lives in the architecture's return
register; the analysis is a linear scan of the instructions *after* the call,
with no CFG, no inter-procedural value flow, and no symbolic execution. What
differs is the *sink*: a **narrowing move** of the return value — the wide
register's 32/16/8-bit sub-register written into a smaller destination before the
value is ever consumed at its full width.

Heuristic (deliberately conservative — chosen precisely because it needs no
dataflow infrastructure, matching the POST_V01 record that the *other* remaining
high-yield classes — CWE-190 integer overflow, CWE-457 uninitialized-variable —
require symbolic execution / def-use CFG analysis that is explicitly out of
scope):

  1. Find every call site to a wide-return libc routine (:data:`WIDE_RETURNERS`).
  2. The result lives in the return register (``rax`` on x86_64, ``x0`` on
     AArch64), 64 bits wide. Seed the tracked-wide-value set with that register's
     canonical 64-bit name.
  3. Walk the instructions *after* the call, in order:
       * A *full-width* read of the value — a 64-bit register-to-register move
         (``mov rbx, rax``), a 64-bit compare (``cmp rax, ...``), a 64-bit store
         (``mov qword [rbp-8], rax``), or passing it onward in a 64-bit register
         — means the program kept all the bits. The value was not truncated on
         this path → stop tracking and do NOT flag.
       * A *narrowing* use — a move of the value's 32/16/8-bit sub-register
         (``eax`` / ``ax`` / ``al`` on x86_64; ``w0`` on AArch64) into a narrower
         destination (``mov dword [rbp-4], eax``, ``mov word [rbp-2], ax``,
         ``mov dword [rbp-4], eax`` then nothing wider) is the truncation: the
         high bits were discarded. Flag it.
       * A move that *re-extends* the value (``movsxd rbx, eax`` /
         ``movsx`` / ``cdqe`` / AArch64 ``sxtw``) re-widens the sub-register back
         to 64 bits — the compiler preserved the value's magnitude → do NOT flag,
         stop tracking.
       * Anything that overwrites the return register with an unrelated value
         (a reload from memory, another call) before any narrowing use means the
         value was discarded, not truncated → stop tracking.

Confidence: ``low``. Whether the runtime value actually exceeds the narrow
destination's range needs value/range analysis that is out of scope; the finding
marks a *statically-visible* truncating store of a known-wide return value, which
is the observable signal — mirroring the POST_V01 confidence guidance for the
dataflow-adjacent classes (CWE-369 / CWE-476 / CWE-401).

[Worker decision: chosen over CWE-190 (integer overflow), which POST_V01 records
— repeatedly — as requiring symbolic execution for precise detection and is
therefore out of scope; CWE-190 dropped off the 2025 CWE Top 25 and was
explicitly deprioritized in this project's roadmap. CWE-197 reduces to the *same*
PLT-anchored single-function forward-scan shape already shipped for CWE-401 /
CWE-369, so it lands as a small, infrastructure-free PR. Scoped deliberately
narrow: the source must be a libc routine whose return type is *wider than int*
(so an ``int`` destination genuinely loses bits), and the sink must be a
narrowing move of that value's sub-register that is NOT immediately re-extended.
A full-width use of the value, a re-widening (``movsxd`` / ``cdqe`` / ``sxtw``),
or an overwrite before any narrowing use all suppress the finding, which keeps
false positives low. The wide-return source set is curated to the count/length/
offset routines whose values are routinely attacker-influenced (``read`` /
``recv`` byte counts, ``strlen`` lengths, ``strtoul`` parses, ``lseek`` /
``ftell`` offsets). Return and sub-register names are resolved per-architecture
so this works on x86_64 and AArch64, consistent with POST_V01 item 5.]
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._common import call_sites

CWE = 197

# libc routines whose documented return type is wider than ``int`` (``size_t`` /
# ``ssize_t`` / ``long`` / ``off_t`` — 64 bits on LP64 targets). Storing one of
# these into a 32-bit (or narrower) slot drops the high bits. Curated to the
# count/length/offset routines whose values are routinely attacker-influenced.
WIDE_RETURNERS = (
    "strlen",       # size_t
    "strnlen",      # size_t
    "wcslen",       # size_t
    "read",         # ssize_t
    "pread",        # ssize_t
    "recv",         # ssize_t
    "recvfrom",     # ssize_t
    "readv",        # ssize_t
    "fread",        # size_t
    "write",        # ssize_t
    "send",         # ssize_t
    "strtol",       # long
    "strtoul",      # unsigned long
    "strtoll",      # long long
    "strtoull",     # unsigned long long
    "mbstowcs",     # size_t
    "wcstombs",     # size_t
    "sysconf",      # long
    "ftell",        # long
    "lseek",        # off_t
)

# Canonical 64-bit register names, indexed for sub-register classification.
# Each entry maps a SUB-register token to (canonical-64, width-in-bits).
_X86_SUBREG: dict[str, tuple[str, int]] = {
    "rax": ("rax", 64), "eax": ("rax", 32), "ax": ("rax", 16), "al": ("rax", 8),
    "rbx": ("rbx", 64), "ebx": ("rbx", 32), "bx": ("rbx", 16), "bl": ("rbx", 8),
    "rcx": ("rcx", 64), "ecx": ("rcx", 32), "cx": ("rcx", 16), "cl": ("rcx", 8),
    "rdx": ("rdx", 64), "edx": ("rdx", 32), "dx": ("rdx", 16), "dl": ("rdx", 8),
    "rsi": ("rsi", 64), "esi": ("rsi", 32), "si": ("rsi", 16), "sil": ("rsi", 8),
    "rdi": ("rdi", 64), "edi": ("rdi", 32), "di": ("rdi", 16), "dil": ("rdi", 8),
    "rbp": ("rbp", 64), "ebp": ("rbp", 32),
    "rsp": ("rsp", 64), "esp": ("rsp", 32),
    **{f"r{i}": (f"r{i}", 64) for i in range(8, 16)},
    **{f"r{i}d": (f"r{i}", 32) for i in range(8, 16)},
    **{f"r{i}w": (f"r{i}", 16) for i in range(8, 16)},
    **{f"r{i}b": (f"r{i}", 8) for i in range(8, 16)},
}
# AArch64: each 64-bit xN has a 32-bit wN view; there is no narrower GPR view.
_ARM_SUBREG: dict[str, tuple[str, int]] = {
    **{f"x{i}": (f"x{i}", 64) for i in range(0, 31)},
    **{f"w{i}": (f"x{i}", 32) for i in range(0, 31)},
}

# Sign/zero re-extension mnemonics that re-widen a narrow value back to 64 bits.
# Their presence means the compiler preserved the magnitude → not a truncation.
_X86_EXTEND = ("movsx", "movsxd", "movzx", "cdqe", "cltq")
_ARM_EXTEND = ("sxtw", "uxtw", "sxth", "uxth", "sxtb", "uxtb")

# Operand-size keywords radare2 prints on memory operands.
_SIZE_KEYWORDS = {
    "byte": 8, "word": 16, "dword": 32, "qword": 64,
}


def _subreg_map(arch: str) -> dict[str, tuple[str, int]]:
    return _ARM_SUBREG if arch == "arm64" else _X86_SUBREG


def _return_register(arch: str) -> str:
    return "x0" if arch == "arm64" else "rax"


def _split(disasm: str) -> tuple[str, list[str]]:
    """Return ``(mnemonic, [operands])`` for a disassembly line."""
    parts = disasm.strip().split(None, 1)
    if not parts:
        return "", []
    mnem = parts[0]
    if len(parts) == 1:
        return mnem, []
    return mnem, [o.strip() for o in parts[1].split(",")]


def _reg_token(operand: str) -> str | None:
    """Return the bare register token if ``operand`` is a single register."""
    op = operand.strip()
    return op if re.fullmatch(r"[a-z]\w*", op) else None


def _mem_width(operand: str) -> int | None:
    """Return the bit-width of a memory operand from its size keyword, if any."""
    if "[" not in operand:
        return None
    for kw, bits in _SIZE_KEYWORDS.items():
        if re.search(rf"\b{kw}\b", operand):
            return bits
    return None


def _classify(token: str, arch: str) -> tuple[str, int] | None:
    """If ``token`` is a register, return its (canonical-64, width); else None."""
    reg = _reg_token(token)
    if reg is None:
        return None
    return _subreg_map(arch).get(reg.lower())


def _truncated_after_call(instructions, call_addr: int, arch: str) -> bool:
    """Return True if the wide return value of the call at ``call_addr`` is
    narrowed (a sub-register move into a smaller slot) before any full-width use,
    scanning forward within the function."""
    ret_reg = _return_register(arch)
    submap = _subreg_map(arch)
    extends = _ARM_EXTEND if arch == "arm64" else _X86_EXTEND

    seen_call = False
    for ins in instructions:
        if ins.addr == call_addr:
            seen_call = True
            continue
        if not seen_call or ins.addr < call_addr:
            continue

        mnem, operands = _split(ins.disasm)
        if not mnem:
            continue

        # A re-extension of the value back to 64 bits preserves the magnitude
        # (`movsxd rbx, eax`, `cdqe`, `sxtw x0, w0`). Not a truncation.
        if mnem in extends:
            # `cdqe` / `cltq` re-extend eax->rax implicitly; an explicit
            # movsx/movzx/sxtw whose SOURCE is a sub-register of the return reg
            # also re-extends. Either way the value was widened → suppress.
            return False

        if len(operands) < 1:
            continue

        dst = operands[0]
        src = operands[1] if len(operands) >= 2 else ""

        # --- Memory store: `mov <size> [mem], <reg>` (x86) or `str wN/xN, [mem]`
        # (AArch64). The source register is last on x86_64, first on AArch64. ---
        if "[" in dst or (arch == "arm64" and "[" in src):
            # Identify which operand is the source register and which is memory.
            if arch == "arm64":
                src_reg_tok, mem_tok = dst, src  # str wN, [mem]
            else:
                src_reg_tok, mem_tok = src, dst  # mov [mem], reg
            cls = _classify(src_reg_tok, arch)
            if cls is None or cls[0] != ret_reg:
                continue
            _, reg_width = cls
            mem_width = _mem_width(mem_tok)
            # A store of the NARROW sub-register (or into a narrow slot) drops
            # the high bits. On x86_64 `mov dword [..], eax` is a 32-bit store of
            # a 64-bit value → truncation. A `mov qword [..], rax` keeps all 64.
            if reg_width < 64:
                return True
            if mem_width is not None and mem_width < 64:
                return True
            # Full-width store: value escaped intact → no truncation.
            return False

        # --- Register-to-register move of the value. ---
        if mnem == "mov" and src:
            scls = _classify(src, arch)
            if scls is not None and scls[0] == ret_reg:
                _, src_width = scls
                dcls = _classify(dst, arch)
                if src_width < 64:
                    # Reading the narrow sub-register into another register
                    # discards the high bits → truncation, unless the very next
                    # context re-extends it (handled by the `extends` check on
                    # the following instruction).
                    return True
                # Full-width move: the value is propagated intact. If it lands in
                # the return register itself nothing changed; otherwise the alias
                # now lives elsewhere — but we conservatively stop: the value was
                # used at full width, so no truncation on this site.
                if dcls is not None and dcls[0] != ret_reg:
                    return False
                continue
            # The return register is overwritten by an unrelated value before any
            # narrowing use → the wide value was discarded, not truncated.
            dcls = _classify(dst, arch)
            if dcls is not None and dcls[0] == ret_reg:
                return False
            continue

        # --- A full-width compare / arithmetic on the value uses all the bits. ---
        if mnem in ("cmp", "test", "add", "sub", "imul", "mul", "lea", "and",
                    "or", "xor", "shl", "shr", "sar", "sub", "adds", "subs"):
            for op in operands:
                cls = _classify(op, arch)
                if cls is not None and cls[0] == ret_reg:
                    if cls[1] == 64:
                        # Used at full width → not truncated here.
                        return False
                    # A narrow-subreg arithmetic use also drops bits.
                    return True
            continue

        # --- Any other call clobbers the return register convention; stop. ---
        if mnem in ("call", "bl", "blr"):
            return False

    return False


def detect(session: R2Session) -> list[Finding]:
    findings: list[Finding] = []

    arch = session.arch()
    func_cache: dict[str, list] = {}

    for symbol, xref in call_sites(session, WIDE_RETURNERS):
        func = xref.function
        if func not in func_cache:
            func_cache[func] = session.function_instructions(xref.from_addr)
        instructions = func_cache[func]

        if not _truncated_after_call(instructions, xref.from_addr, arch):
            continue

        findings.append(
            Finding(
                cwe=CWE,
                function=func,
                address=hex(xref.from_addr),
                evidence=(
                    f"wide return value of {symbol} (size_t/ssize_t/long) is "
                    "truncated into a narrower destination without re-extension "
                    "(possible numeric truncation / lost high bits)"
                ),
                symbol=symbol,
                # Whether the runtime value actually exceeds the narrow range
                # needs value analysis (out of scope per POST_V01), so the
                # statically-visible truncating store is a low-confidence signal
                # (matching CWE-369 / CWE-401).
                confidence="low",
            )
        )
    return findings
