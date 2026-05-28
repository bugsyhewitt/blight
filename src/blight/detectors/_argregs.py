"""Architecture-aware argument-register conventions for blight detectors.

The CWE-78 and CWE-134 heuristics inspect the register that carries a specific
argument (the command string, the format string) at a call site. Which physical
register that is depends on the target architecture's calling convention. This
module isolates that knowledge so detectors stay architecture-agnostic.

Supported architectures:

  * ``x86_64`` (SysV AMD64 ABI): integer/pointer args 0-5 in
    ``rdi, rsi, rdx, rcx, r8, r9``. Each has 32/16-bit sub-register aliases.
  * ``arm64`` (AArch64 AAPCS64): integer/pointer args 0-7 in ``x0``-``x7``.
    Each 64-bit ``xN`` has a 32-bit ``wN`` alias.

[Worker decision: CWE-120 and CWE-242 do not consult this table — they flag any
call site regardless of register convention, so they already work on every
architecture. Only the argument-is-constant heuristics (CWE-78, CWE-134) need
it. This is why item 5 of POST_V01 is scoped to those two detectors.]
"""

from __future__ import annotations

# Map a normalized architecture name to the ordered argument-passing registers.
# The outer tuple is indexed by argument position (0 = first arg). Each inner
# tuple is every register name that aliases that argument register (a write to
# any of them sets the argument).
_ARG_REGISTERS: dict[str, tuple[tuple[str, ...], ...]] = {
    "x86_64": (
        ("rdi", "edi", "di"),   # arg0
        ("rsi", "esi", "si"),   # arg1
        ("rdx", "edx", "dx"),   # arg2
        ("rcx", "ecx", "cx"),   # arg3
        ("r8", "r8d", "r8w"),   # arg4
        ("r9", "r9d", "r9w"),   # arg5
    ),
    "arm64": (
        ("x0", "w0"),   # arg0
        ("x1", "w1"),   # arg1
        ("x2", "w2"),   # arg2
        ("x3", "w3"),   # arg3
        ("x4", "w4"),   # arg4
        ("x5", "w5"),   # arg5
        ("x6", "w6"),   # arg6
        ("x7", "w7"),   # arg7
    ),
}

# Architecture names blight knows how to apply register heuristics to. Anything
# else falls back to x86_64 so existing behaviour is unchanged for callers that
# cannot report an architecture.
DEFAULT_ARCH = "x86_64"


def normalize_arch(arch: str | None, bits: int | None = None) -> str:
    """Map radare2's reported architecture to a blight architecture key.

    radare2's ``iAj`` reports ``arch`` (e.g. ``"x86"``, ``"arm"``) and ``bits``
    (e.g. 64). We collapse those to the keys used in :data:`_ARG_REGISTERS`.
    Unknown or 32-bit-only architectures fall back to :data:`DEFAULT_ARCH` so the
    detectors keep their conservative behaviour.
    """
    if not arch:
        return DEFAULT_ARCH
    a = arch.strip().lower()
    # AArch64 (64-bit ARM) — explicit aarch64/arm64 names always map; a bare
    # "arm" only maps when bits==64 (32-bit ARM uses r0-r3 and is out of scope).
    if a in ("aarch64", "arm64"):
        return "arm64"
    if a == "arm" and bits == 64:
        return "arm64"
    if a in ("x86", "x86_64", "amd64") and bits in (64, None):
        return "x86_64"
    return DEFAULT_ARCH


def arg_register_aliases(arch: str, index: int) -> tuple[str, ...]:
    """Return every register name that aliases argument ``index`` on ``arch``.

    ``arch`` must be a normalized key (see :func:`normalize_arch`). Falls back to
    :data:`DEFAULT_ARCH` for unknown architectures. Raises ``IndexError`` only if
    the argument index exceeds what the convention passes in registers.
    """
    table = _ARG_REGISTERS.get(arch, _ARG_REGISTERS[DEFAULT_ARCH])
    return table[index]
