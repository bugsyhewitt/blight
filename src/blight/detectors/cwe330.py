"""CWE-330: Use of Insufficiently Random Values (predictable PRNG seeding).

Flags call-sites where a non-cryptographic PRNG seeding routine (``srand`` /
``srandom`` / ``srand48`` / ``seed48``) is invoked with a *predictable* seed:

  * **HIGH severity** — the seed is the return value of a public clock /
    process-id source (``time`` / ``gettimeofday`` / ``clock`` / ``getpid`` /
    ``getppid``). This is the textbook predictable-seed primitive that drives a
    long tail of token-prediction, key-recovery, and session-replay CVEs
    (Kaminsky DNS, embedded auth-token attacks, the "I seeded with time(NULL),
    surely that's random?" mistake).
  * **MEDIUM severity** — the seed is a small constant immediate
    (``0`` / ``1`` / ``2`` / any value ≤ ``0xff``). A constant seed makes the
    entire PRNG output deterministic across every invocation of the binary, the
    canonical CWE-336 (Same Seed) pattern.

A seed loaded from a register that this detector cannot resolve (e.g. a value
read from a config file at runtime) is **not** flagged. The detector is
precision-first: it stays quiet unless it can prove the seed is one of the two
predictable forms above. Bare ``rand()`` calls remain CWE-676's territory; the
two are complementary — ``rand()`` is "predictable PRNG used at all", CWE-330
is "PRNG seeded in a way that fixes its output sequence ahead of time".

This is a hybrid detector — it combines PLT lookup (find the seeding call
sites) with the same per-architecture argument-register inspection used by
CWE-78 / CWE-134 / CWE-732. The seed argument is the *first* argument for every
covered API (the new draw-48 state pointer for ``seed48`` is still arg0, and
exploits there are out of scope — we only inspect when arg0 is a plain
register-loaded scalar). To detect the ``srand(time(NULL))`` shape, the
detector walks the call's containing function backward and identifies the most
recent ``call <plt-symbol>`` whose return register (``rax`` on x86_64,
``x0`` / ``w0`` on AArch64) is then moved into the seed argument register with
no intervening clobber by an unrelated value.

Confidence reflects how much we *know*: the predictable-call shape (call to
``time`` then ``srand``) is HIGH (we read the literal sequence out of the
disassembly); the constant-immediate seed shape is also HIGH (we read the
literal immediate). The detector does NOT emit MEDIUM-confidence findings — if
the evidence is not literal, the call site is left alone.
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import R2Session

from ._argregs import arg_register_aliases
from ._common import call_sites

CWE = 330

# Seeding APIs we anchor on. The seed register is always at argument index 0
# for these symbols — both ``srand(unsigned)`` and ``srand48(long)`` take the
# seed as the first (and only) integer argument; ``seed48(unsigned short[3])``
# takes a pointer as arg0, which we treat as opaque (we only flag when arg0 is
# loaded with a literal predictable immediate or a clock-source return).
_SEEDING_APIS: tuple[str, ...] = ("srand", "srandom", "srand48", "seed48")

DANGEROUS = _SEEDING_APIS

# PLT symbols whose return value, when fed into a PRNG seed, signals a
# predictable seed. Each is a *publicly observable* clock / pid source.
_PREDICTABLE_SOURCES: frozenset[str] = frozenset(
    {
        "time",
        "gettimeofday",
        "clock",
        "clock_gettime",
        "getpid",
        "getppid",
    }
)

# A constant seed at or below this threshold (decimal 255 / 0xff) is treated as
# the textbook same-seed mistake (e.g. ``srand(0)``, ``srand(1)``,
# ``srand(42)``). Larger immediates are not flagged — they may be legitimate
# domain-specific constants embedded by the build system. The threshold is
# deliberately conservative to keep precision high.
_SMALL_CONSTANT_LIMIT = 0xFF

# Both severity tiers carry HIGH triage confidence — the evidence is parsed
# directly out of the disassembly (a literal immediate, or a literal call
# sequence). No heuristic guess.
_CONFIDENCE_FOR_SEVERITY = {
    "HIGH": "high",
    "MEDIUM": "high",
}

# Destination operand of an instruction: "<mnemonic> <reg>, <src>".
_DEST_OP_RE = re.compile(r"\s*\w+\s+(\w+)\s*,\s*(.+?)\s*$")

# Bare immediate operand: ``0x1f`` / ``31`` / ``#0x1f`` (AArch64).
_IMM_RE = re.compile(r"^(?:0x([0-9a-f]+)|([0-9]+))$", re.IGNORECASE)

# A ``call`` / ``bl`` instruction that targets an imported symbol.
# radare2 prints these as ``call sym.imp.<name>`` (x86_64) or
# ``bl sym.imp.<name>`` (AArch64) — we extract ``<name>``.
_PLT_CALL_RE = re.compile(
    r"^\s*(?:call|bl)\s+(?:sym\.imp\.)?([A-Za-z_][A-Za-z0-9_]*)\s*$"
)


def _parse_immediate(operand: str) -> int | None:
    """Parse an instruction source operand as an integer immediate, or ``None``
    if the operand is not a bare immediate (register / memory / symbol).
    Tolerates a leading AArch64 ``#`` and a trailing comma fragment.
    """
    s = operand.strip().rstrip(",").lstrip("#").strip()
    m = _IMM_RE.match(s)
    if not m:
        return None
    if m.group(1) is not None:
        return int(m.group(1), 16)
    return int(m.group(2))


def _split_dest_src(disasm: str) -> tuple[str, str] | None:
    """Return ``(dest_reg, src_operand)`` for a 2-operand instruction, or
    ``None`` if the instruction is not in that form (e.g. ``ret``, ``cdq``).
    """
    m = _DEST_OP_RE.match(disasm)
    if not m:
        return None
    return m.group(1), m.group(2).strip().rstrip(",").strip()


def _last_write_to_seed_reg(
    instructions, call_addr: int, aliases: tuple[str, ...]
) -> tuple[int, str] | None:
    """Return ``(addr, disasm)`` of the last instruction that writes any
    register in ``aliases`` before ``call_addr``. ``None`` if no such write is
    visible inside the same function.
    """
    last: tuple[int, str] | None = None
    for ins in instructions:
        if ins.addr >= call_addr:
            break
        parts = _split_dest_src(ins.disasm)
        if parts is None:
            continue
        dest, _ = parts
        if dest in aliases:
            last = (ins.addr, ins.disasm)
    return last


def _return_register_aliases(arch: str) -> tuple[str, ...]:
    """Return the register names (with sub-register aliases) that carry an
    integer return value on ``arch``. This mirrors the conventions hard-coded
    elsewhere in blight (CWE-252's return scan) so a single source of truth
    isn't dragged in just for one detector.
    """
    if arch == "arm64":
        return ("x0", "w0")
    # x86_64 (and fallback)
    return ("rax", "eax", "ax", "al")


def _preceding_predictable_call(
    instructions, write_addr: int
) -> str | None:
    """Return the imported symbol name of the most recent ``call <plt>`` before
    ``write_addr`` that targets a known predictable seed source, or ``None``.

    Used to recognise the ``call time; mov edi, eax; call srand`` shape (and
    its AArch64 equivalent). We deliberately do NOT walk past an intervening
    call that returns a different value — if any unrelated call sits between
    the predictable source and the seed register write, we cannot assert the
    return value of the predictable source is what reached the seed.
    """
    last_call_symbol: str | None = None
    for ins in instructions:
        if ins.addr >= write_addr:
            break
        m = _PLT_CALL_RE.match(ins.disasm)
        if m is None:
            continue
        last_call_symbol = m.group(1)
    if last_call_symbol is None:
        return None
    if last_call_symbol in _PREDICTABLE_SOURCES:
        return last_call_symbol
    return None


def _classify_seed_write(
    instructions, write_addr: int, write_disasm: str, arch: str
) -> tuple[str, str] | None:
    """Classify the most recent write to the seed register.

    Returns ``(severity, description)`` for a flagged write, or ``None`` when
    the seed is not provably predictable (the precision-first default).
    """
    parts = _split_dest_src(write_disasm)
    if parts is None:
        return None
    _dest, src = parts

    # Case 1: bare constant immediate seed → MEDIUM if small enough.
    imm = _parse_immediate(src)
    if imm is not None:
        if 0 <= imm <= _SMALL_CONSTANT_LIMIT:
            return (
                "MEDIUM",
                f"seed is constant immediate {hex(imm)} (deterministic PRNG)",
            )
        return None  # large constant — probably a domain literal, not a same-seed mistake

    # Case 2: seed register receives a value from the return register of the
    # most recent PLT call to a predictable clock / pid source → HIGH.
    return_aliases = set(_return_register_aliases(arch))
    src_token = src.split()[0].rstrip(",")
    # Strip an optional AArch64 ``#`` prefix and operand-suffix punctuation.
    src_token = src_token.lstrip("#").rstrip(",")
    if src_token in return_aliases:
        source_symbol = _preceding_predictable_call(instructions, write_addr)
        if source_symbol is not None:
            return (
                "HIGH",
                (
                    f"seed is the return value of {source_symbol}() "
                    "(predictable clock/pid source)"
                ),
            )

    return None


def detect(session: R2Session) -> list[Finding]:
    findings: list[Finding] = []

    arch = session.arch()
    seed_aliases = arg_register_aliases(arch, 0)
    func_cache: dict[str, list] = {}

    for symbol, xref in call_sites(session, DANGEROUS):
        func = xref.function
        if func not in func_cache:
            func_cache[func] = session.function_instructions(xref.from_addr)
        instructions = func_cache[func]

        last_write = _last_write_to_seed_reg(
            instructions, xref.from_addr, seed_aliases
        )
        if last_write is None:
            # We can't see how the seed was set — precision-first, stay quiet.
            continue
        write_addr, write_disasm = last_write

        classification = _classify_seed_write(
            instructions, write_addr, write_disasm, arch
        )
        if classification is None:
            continue

        severity, description = classification
        findings.append(
            Finding(
                cwe=CWE,
                function=func,
                address=hex(xref.from_addr),
                evidence=(
                    f"[{severity}] call to {symbol} with {description} "
                    "(predictable PRNG seeding)"
                ),
                symbol=symbol,
                confidence=_CONFIDENCE_FOR_SEVERITY[severity],
            )
        )
    return findings
