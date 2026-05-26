"""A fake R2Session for blight unit tests.

This stands in for :class:`blight.r2.Radare2Session` so the unit suite runs
without radare2 or r2pipe installed. It is built from small, hand-authored
data structures that mirror the real radare2 JSON we observed for the fixtures.
"""

from __future__ import annotations

from blight.r2 import Import, Instruction, Xref


class FakeR2Session:
    """Implements the R2Session protocol from in-memory data.

    Args:
        imports: list of Import.
        xrefs: dict mapping a PLT address -> list of Xref.
        functions: dict mapping a function-containing address -> list of
            Instruction (the disassembly returned for any address inside it).
    """

    def __init__(
        self,
        imports: list[Import],
        xrefs: dict[int, list[Xref]] | None = None,
        functions: dict[int, list[Instruction]] | None = None,
    ) -> None:
        self._imports = imports
        self._xrefs = xrefs or {}
        self._functions = functions or {}

    def imports(self) -> list[Import]:
        return list(self._imports)

    def xrefs_to(self, addr: int) -> list[Xref]:
        return list(self._xrefs.get(addr, []))

    def function_instructions(self, func_addr: int) -> list[Instruction]:
        # Mirror radare2's pdfj-by-address: return the block whose key matches,
        # else the block that contains the address.
        if func_addr in self._functions:
            return list(self._functions[func_addr])
        for start, ops in self._functions.items():
            if ops and start <= func_addr <= ops[-1].addr:
                return list(ops)
        return []


# --- Convenience builders mirroring the shipped fixtures -------------------

def strcpy_vuln_session() -> FakeR2Session:
    """strcpy-vuln: strcpy + sprintf + gets across two functions."""
    imports = [
        Import(name="strcpy", plt=0x401050),
        Import(name="sprintf", plt=0x401060),
        Import(name="gets", plt=0x401070),
        Import(name="printf", plt=0x401080),
    ]
    xrefs = {
        0x401050: [Xref(0x40114a, "CALL", "copy_it", "call sym.imp.strcpy")],
        0x401060: [Xref(0x40119c, "CALL", "format_it", "call sym.imp.sprintf")],
        0x401070: [Xref(0x4011f0, "CALL", "main", "call sym.imp.gets")],
    }
    return FakeR2Session(imports, xrefs)


def system_vuln_session() -> FakeR2Session:
    """system-vuln: system() with a non-constant (stack buffer) argument."""
    imports = [
        Import(name="system", plt=0x401030),
        Import(name="execl", plt=0x401040),
        Import(name="snprintf", plt=0x401050),
    ]
    xrefs = {
        0x401030: [Xref(0x40118f, "CALL", "run_cmd", "call sym.imp.system")],
        0x401040: [Xref(0x4011d0, "CALL", "run_exec", "call sym.imp.execl")],
    }
    # run_cmd: builds the command in a stack buffer, then loads it into rdi.
    run_cmd_ops = [
        Instruction(0x401166, "push rbp"),
        Instruction(0x401170, "mov rdx, qword [rbp - 0x108]"),
        Instruction(0x401178, "lea rsi, str.ls__s"),
        Instruction(0x401180, "mov esi, 0x100"),
        Instruction(0x401185, "lea rax, [rbp - 0x100]"),
        Instruction(0x40118a, "mov rdi, rax"),
        Instruction(0x40118f, "call sym.imp.system"),
        Instruction(0x401194, "leave"),
    ]
    # run_exec: execl("/bin/sh", "sh", "-c", user) — rdi is the constant
    # "/bin/sh" string. (We still flag because arg passed to the program is
    # user-controlled; but for our arg0 heuristic this loads str., so this
    # builder is used to exercise the non-system exec path separately.)
    run_exec_ops = [
        Instruction(0x4011a0, "push rbp"),
        Instruction(0x4011c0, "mov rdx, qword [rbp - 0x18]"),
        Instruction(0x4011c8, "lea rdi, [rbp - 0x10]"),
        Instruction(0x4011d0, "call sym.imp.execl"),
    ]
    functions = {0x401166: run_cmd_ops, 0x4011a0: run_exec_ops}
    return FakeR2Session(imports, xrefs, functions)


def system_constant_session() -> FakeR2Session:
    """system("ls") — constant argument, must NOT be flagged."""
    imports = [Import(name="system", plt=0x401030)]
    xrefs = {0x401030: [Xref(0x40113f, "CALL", "main", "call sym.imp.system")]}
    main_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x40113a, "lea rdi, str.ls"),
        Instruction(0x40113f, "call sym.imp.system"),
        Instruction(0x401144, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: main_ops})


def gets_vuln_session() -> FakeR2Session:
    """gets-vuln: a single gets() call in main."""
    imports = [
        Import(name="gets", plt=0x401040),
        Import(name="printf", plt=0x401050),
    ]
    xrefs = {0x401040: [Xref(0x401158, "CALL", "main", "call sym.imp.gets")]}
    return FakeR2Session(imports, xrefs)


def clean_baseline_session() -> FakeR2Session:
    """clean-baseline: only fgets + snprintf, nothing flagged."""
    imports = [
        Import(name="fgets", plt=0x401040),
        Import(name="snprintf", plt=0x401050),
        Import(name="printf", plt=0x401060),
        Import(name="strcspn", plt=0x401070),
    ]
    return FakeR2Session(imports, xrefs={})


# --- CWE-134 format-string fixtures ----------------------------------------

def printf_fmtstr_vuln_session() -> FakeR2Session:
    """printf with a non-constant format string (rdi loaded from a stack buffer).

    Scenario: a function reads a line from the user into a buffer and passes it
    directly to printf — classic format string vulnerability.
    """
    imports = [
        Import(name="printf", plt=0x401030),
        Import(name="fgets", plt=0x401040),
    ]
    xrefs = {
        0x401030: [Xref(0x401185, "CALL", "log_msg", "call sym.imp.printf")],
    }
    # log_msg builds a message in a stack buffer and passes it to printf.
    # rdi is loaded via `lea rdi, [rbp - 0x80]` (stack address, not a str.*)
    log_msg_ops = [
        Instruction(0x401166, "push rbp"),
        Instruction(0x401170, "lea rax, [rbp - 0x80]"),
        Instruction(0x401178, "mov rdi, rax"),       # loads stack addr into rdi
        Instruction(0x401185, "call sym.imp.printf"),
        Instruction(0x40118a, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401166: log_msg_ops})


def printf_constant_session() -> FakeR2Session:
    """printf("Hello %s\\n", name) — constant format string, must NOT be flagged."""
    imports = [Import(name="printf", plt=0x401030)]
    xrefs = {0x401030: [Xref(0x401150, "CALL", "main", "call sym.imp.printf")]}
    main_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "lea rsi, [rbp - 0x10]"),    # second arg: name
        Instruction(0x401148, "lea rdi, str.Hello__s_n"),   # format literal
        Instruction(0x401150, "call sym.imp.printf"),
        Instruction(0x401155, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: main_ops})


def fprintf_fmtstr_vuln_session() -> FakeR2Session:
    """fprintf with a non-constant format string (rsi loaded from stack)."""
    imports = [
        Import(name="fprintf", plt=0x401030),
    ]
    xrefs = {
        0x401030: [Xref(0x4011a0, "CALL", "write_log", "call sym.imp.fprintf")],
    }
    # rsi (format arg for fprintf) is loaded from a stack buffer.
    write_log_ops = [
        Instruction(0x401180, "push rbp"),
        Instruction(0x401190, "lea rax, [rbp - 0x100]"),
        Instruction(0x401198, "mov rsi, rax"),          # non-constant into rsi
        Instruction(0x4011a0, "call sym.imp.fprintf"),
        Instruction(0x4011a5, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401180: write_log_ops})


def snprintf_fmtstr_vuln_session() -> FakeR2Session:
    """snprintf with a non-constant format string (rdx loaded from stack)."""
    imports = [
        Import(name="snprintf", plt=0x401030),
    ]
    xrefs = {
        0x401030: [Xref(0x4011c0, "CALL", "build_msg", "call sym.imp.snprintf")],
    }
    # rdx (format arg for snprintf) is loaded from a stack buffer.
    build_msg_ops = [
        Instruction(0x401190, "push rbp"),
        Instruction(0x4011a0, "lea rax, [rbp - 0x80]"),
        Instruction(0x4011b0, "mov rdx, rax"),          # non-constant into rdx
        Instruction(0x4011c0, "call sym.imp.snprintf"),
        Instruction(0x4011c5, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401190: build_msg_ops})


def syslog_fmtstr_vuln_session() -> FakeR2Session:
    """syslog with a non-constant format string (rsi loaded from stack)."""
    imports = [
        Import(name="syslog", plt=0x401030),
    ]
    xrefs = {
        0x401030: [Xref(0x4011b0, "CALL", "audit_event", "call sym.imp.syslog")],
    }
    # rsi (format arg for syslog) is a stack buffer.
    audit_ops = [
        Instruction(0x401190, "push rbp"),
        Instruction(0x4011a0, "lea rax, [rbp - 0x200]"),
        Instruction(0x4011a8, "mov rsi, rax"),          # non-constant into rsi
        Instruction(0x4011b0, "call sym.imp.syslog"),
        Instruction(0x4011b5, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401190: audit_ops})


def printf_no_dangerous_imports_session() -> FakeR2Session:
    """A session with no printf-family imports — nothing should be flagged."""
    imports = [
        Import(name="puts", plt=0x401030),
        Import(name="fgets", plt=0x401040),
    ]
    return FakeR2Session(imports, xrefs={})
