"""A fake R2Session for blight unit tests.

This stands in for :class:`blight.r2.Radare2Session` so the unit suite runs
without radare2 or r2pipe installed. It is built from small, hand-authored
data structures that mirror the real radare2 JSON we observed for the fixtures.
"""

from __future__ import annotations

from blight.r2 import Import, Instruction, Str, Xref


class FakeR2Session:
    """Implements the R2Session protocol from in-memory data.

    Args:
        imports: list of Import.
        xrefs: dict mapping a PLT address -> list of Xref.
        functions: dict mapping a function-containing address -> list of
            Instruction (the disassembly returned for any address inside it).
        strings: list of Str literals extracted from the binary (izzj).
    """

    def __init__(
        self,
        imports: list[Import],
        xrefs: dict[int, list[Xref]] | None = None,
        functions: dict[int, list[Instruction]] | None = None,
        arch: str = "x86_64",
        strings: list[Str] | None = None,
    ) -> None:
        self._imports = imports
        self._xrefs = xrefs or {}
        self._functions = functions or {}
        self._arch = arch
        self._strings = strings or []

    def imports(self) -> list[Import]:
        return list(self._imports)

    def arch(self) -> str:
        return self._arch

    def strings(self) -> list[Str]:
        return list(self._strings)

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

    def function_addrs(self) -> list[int]:
        # Mirror radare2's aflj: the entry address of every known function.
        return list(self._functions.keys())


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


# --- CWE-676 potentially-dangerous-function fixtures -----------------------

def tmpnam_vuln_session() -> FakeR2Session:
    """A single tmpnam() call (TOCTOU race)."""
    imports = [Import(name="tmpnam", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "make_path", "call sym.imp.tmpnam")]}
    return FakeR2Session(imports, xrefs)


def mktemp_vuln_session() -> FakeR2Session:
    """A single mktemp() call (TOCTOU race)."""
    imports = [Import(name="mktemp", plt=0x401050)]
    xrefs = {0x401050: [Xref(0x401172, "CALL", "make_temp", "call sym.imp.mktemp")]}
    return FakeR2Session(imports, xrefs)


def strtok_vuln_session() -> FakeR2Session:
    """A single strtok() call (non-reentrant)."""
    imports = [Import(name="strtok", plt=0x401060)]
    xrefs = {0x401060: [Xref(0x401184, "CALL", "parse_line", "call sym.imp.strtok")]}
    return FakeR2Session(imports, xrefs)


def asctime_vuln_session() -> FakeR2Session:
    """A single asctime() call (non-reentrant static buffer)."""
    imports = [Import(name="asctime", plt=0x401070)]
    xrefs = {0x401070: [Xref(0x401196, "CALL", "fmt_time", "call sym.imp.asctime")]}
    return FakeR2Session(imports, xrefs)


def ctime_vuln_session() -> FakeR2Session:
    """A single ctime() call (non-reentrant static buffer)."""
    imports = [Import(name="ctime", plt=0x401080)]
    xrefs = {0x401080: [Xref(0x4011a8, "CALL", "stamp", "call sym.imp.ctime")]}
    return FakeR2Session(imports, xrefs)


def rand_vuln_session() -> FakeR2Session:
    """A single rand() call (predictable PRNG)."""
    imports = [Import(name="rand", plt=0x401090)]
    xrefs = {0x401090: [Xref(0x4011ba, "CALL", "gen_token", "call sym.imp.rand")]}
    return FakeR2Session(imports, xrefs)


def cwe676_all_session() -> FakeR2Session:
    """All six CWE-676 functions, each called once in a distinct function."""
    imports = [
        Import(name="tmpnam", plt=0x401040),
        Import(name="mktemp", plt=0x401050),
        Import(name="strtok", plt=0x401060),
        Import(name="asctime", plt=0x401070),
        Import(name="ctime", plt=0x401080),
        Import(name="rand", plt=0x401090),
        Import(name="snprintf", plt=0x4010a0),  # safe neighbour, must not fire
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "make_path", "call sym.imp.tmpnam")],
        0x401050: [Xref(0x401172, "CALL", "make_temp", "call sym.imp.mktemp")],
        0x401060: [Xref(0x401184, "CALL", "parse_line", "call sym.imp.strtok")],
        0x401070: [Xref(0x401196, "CALL", "fmt_time", "call sym.imp.asctime")],
        0x401080: [Xref(0x4011a8, "CALL", "stamp", "call sym.imp.ctime")],
        0x401090: [Xref(0x4011ba, "CALL", "gen_token", "call sym.imp.rand")],
    }
    return FakeR2Session(imports, xrefs)


def cwe676_clean_session() -> FakeR2Session:
    """Only safe replacements imported — no CWE-676 function present."""
    imports = [
        Import(name="mkstemp", plt=0x401040),
        Import(name="strtok_r", plt=0x401050),
        Import(name="asctime_r", plt=0x401060),
        Import(name="getrandom", plt=0x401070),
    ]
    return FakeR2Session(imports, xrefs={})


# --- CWE-327 broken/risky-cryptography fixtures ----------------------------
#
# Pure PLT-lookup detector (same shape as CWE-676): the presence of a call to a
# broken hash / cipher / weak-randomness routine is the finding. No data flow.

def md5_vuln_session() -> FakeR2Session:
    """A single MD5() call (collision-broken hash)."""
    imports = [Import(name="MD5", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "hash_pw", "call sym.imp.MD5")]}
    return FakeR2Session(imports, xrefs)


def sha1_vuln_session() -> FakeR2Session:
    """A single SHA1() call (collision-broken hash)."""
    imports = [Import(name="SHA1", plt=0x401050)]
    xrefs = {0x401050: [Xref(0x401172, "CALL", "sign_blob", "call sym.imp.SHA1")]}
    return FakeR2Session(imports, xrefs)


def des_vuln_session() -> FakeR2Session:
    """A single DES_ecb_encrypt() call (single-DES, 56-bit key)."""
    imports = [Import(name="DES_ecb_encrypt", plt=0x401060)]
    xrefs = {
        0x401060: [Xref(0x401184, "CALL", "encrypt_block", "call sym.imp.DES_ecb_encrypt")]
    }
    return FakeR2Session(imports, xrefs)


def rc4_vuln_session() -> FakeR2Session:
    """A single RC4() call (biased keystream)."""
    imports = [Import(name="RC4", plt=0x401070)]
    xrefs = {0x401070: [Xref(0x401196, "CALL", "stream_cipher", "call sym.imp.RC4")]}
    return FakeR2Session(imports, xrefs)


def blowfish_vuln_session() -> FakeR2Session:
    """A single BF_cbc_encrypt() call (64-bit block cipher)."""
    imports = [Import(name="BF_cbc_encrypt", plt=0x401080)]
    xrefs = {
        0x401080: [Xref(0x4011a8, "CALL", "encrypt_cbc", "call sym.imp.BF_cbc_encrypt")]
    }
    return FakeR2Session(imports, xrefs)


def srand_vuln_session() -> FakeR2Session:
    """A single srand() call (seeding a predictable PRNG)."""
    imports = [Import(name="srand", plt=0x401090)]
    xrefs = {0x401090: [Xref(0x4011ba, "CALL", "gen_key", "call sym.imp.srand")]}
    return FakeR2Session(imports, xrefs)


def cwe327_all_session() -> FakeR2Session:
    """One call to each of six representative CWE-327 routines."""
    imports = [
        Import(name="MD5", plt=0x401040),
        Import(name="SHA1", plt=0x401050),
        Import(name="DES_ecb_encrypt", plt=0x401060),
        Import(name="RC4", plt=0x401070),
        Import(name="BF_cbc_encrypt", plt=0x401080),
        Import(name="srand", plt=0x401090),
        Import(name="snprintf", plt=0x4010a0),  # safe neighbour, must not fire
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "hash_pw", "call sym.imp.MD5")],
        0x401050: [Xref(0x401172, "CALL", "sign_blob", "call sym.imp.SHA1")],
        0x401060: [Xref(0x401184, "CALL", "encrypt_block", "call sym.imp.DES_ecb_encrypt")],
        0x401070: [Xref(0x401196, "CALL", "stream_cipher", "call sym.imp.RC4")],
        0x401080: [Xref(0x4011a8, "CALL", "encrypt_cbc", "call sym.imp.BF_cbc_encrypt")],
        0x401090: [Xref(0x4011ba, "CALL", "gen_key", "call sym.imp.srand")],
    }
    return FakeR2Session(imports, xrefs)


def cwe327_clean_session() -> FakeR2Session:
    """Only strong primitives imported — no CWE-327 routine present."""
    imports = [
        Import(name="SHA256", plt=0x401040),
        Import(name="EVP_aes_256_gcm", plt=0x401050),
        Import(name="getrandom", plt=0x401060),
        Import(name="crypto_secretbox", plt=0x401070),
    ]
    return FakeR2Session(imports, xrefs={})


# --- CWE-295 improper-certificate-validation fixtures ----------------------
#
# Pure PLT-lookup detector (same shape as CWE-327 / CWE-676): the presence of a
# call to a TLS verification-policy routine is the finding. No data flow.

def ssl_set_verify_vuln_session() -> FakeR2Session:
    """A single SSL_CTX_set_verify() call (the verify-mode toggle)."""
    imports = [Import(name="SSL_CTX_set_verify", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "init_tls", "call sym.imp.SSL_CTX_set_verify")]
    }
    return FakeR2Session(imports, xrefs)


def ssl_get_peer_cert_vuln_session() -> FakeR2Session:
    """A single SSL_get_peer_certificate() call (presence is not trust)."""
    imports = [Import(name="SSL_get_peer_certificate", plt=0x401050)]
    xrefs = {
        0x401050: [
            Xref(0x401172, "CALL", "check_cert", "call sym.imp.SSL_get_peer_certificate")
        ]
    }
    return FakeR2Session(imports, xrefs)


def curl_setopt_vuln_session() -> FakeR2Session:
    """A single curl_easy_setopt() call (CURLOPT_SSL_VERIFY* sink)."""
    imports = [Import(name="curl_easy_setopt", plt=0x401060)]
    xrefs = {
        0x401060: [Xref(0x401184, "CALL", "setup", "call sym.imp.curl_easy_setopt")]
    }
    return FakeR2Session(imports, xrefs)


def gnutls_verify_peers2_vuln_session() -> FakeR2Session:
    """A single gnutls_certificate_verify_peers2() call (no hostname check)."""
    imports = [Import(name="gnutls_certificate_verify_peers2", plt=0x401070)]
    xrefs = {
        0x401070: [
            Xref(
                0x401196,
                "CALL",
                "verify",
                "call sym.imp.gnutls_certificate_verify_peers2",
            )
        ]
    }
    return FakeR2Session(imports, xrefs)


def mbedtls_authmode_vuln_session() -> FakeR2Session:
    """A single mbedtls_ssl_conf_authmode() call (verify-mode toggle)."""
    imports = [Import(name="mbedtls_ssl_conf_authmode", plt=0x401080)]
    xrefs = {
        0x401080: [
            Xref(0x4011a8, "CALL", "conf", "call sym.imp.mbedtls_ssl_conf_authmode")
        ]
    }
    return FakeR2Session(imports, xrefs)


def cwe295_all_session() -> FakeR2Session:
    """One call to each of five representative CWE-295 routines."""
    imports = [
        Import(name="SSL_CTX_set_verify", plt=0x401040),
        Import(name="SSL_get_peer_certificate", plt=0x401050),
        Import(name="curl_easy_setopt", plt=0x401060),
        Import(name="gnutls_certificate_verify_peers2", plt=0x401070),
        Import(name="mbedtls_ssl_conf_authmode", plt=0x401080),
        Import(name="SSL_get_verify_result", plt=0x4010a0),  # correct API, must NOT fire
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "init_tls", "call sym.imp.SSL_CTX_set_verify")],
        0x401050: [
            Xref(0x401172, "CALL", "check_cert", "call sym.imp.SSL_get_peer_certificate")
        ],
        0x401060: [Xref(0x401184, "CALL", "setup", "call sym.imp.curl_easy_setopt")],
        0x401070: [
            Xref(
                0x401196,
                "CALL",
                "verify",
                "call sym.imp.gnutls_certificate_verify_peers2",
            )
        ],
        0x401080: [
            Xref(0x4011a8, "CALL", "conf", "call sym.imp.mbedtls_ssl_conf_authmode")
        ],
    }
    return FakeR2Session(imports, xrefs)


def cwe295_clean_session() -> FakeR2Session:
    """Only correct verification APIs imported — no CWE-295 routine present."""
    imports = [
        Import(name="SSL_get_verify_result", plt=0x401040),
        Import(name="X509_check_host", plt=0x401050),
        Import(name="gnutls_certificate_verify_peers3", plt=0x401060),
        Import(name="gnutls_session_set_verify_cert", plt=0x401070),
    ]
    return FakeR2Session(imports, xrefs={})


# --- CWE-89 SQL-injection fixtures -----------------------------------------
#
# Pure PLT-lookup detector (same shape as CWE-327 / CWE-295 / CWE-676): the
# presence of a call to a raw-SQL-execution routine is the finding. No data
# flow — the call site is where injection lands when the query string is built
# from untrusted input.

def sqlite3_exec_vuln_session() -> FakeR2Session:
    """A single sqlite3_exec() call (raw SQL string execution)."""
    imports = [Import(name="sqlite3_exec", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "run_query", "call sym.imp.sqlite3_exec")]
    }
    return FakeR2Session(imports, xrefs)


def mysql_query_vuln_session() -> FakeR2Session:
    """A single mysql_query() call (raw query string execution)."""
    imports = [Import(name="mysql_query", plt=0x401050)]
    xrefs = {
        0x401050: [Xref(0x401172, "CALL", "lookup_user", "call sym.imp.mysql_query")]
    }
    return FakeR2Session(imports, xrefs)


def pqexec_vuln_session() -> FakeR2Session:
    """A single PQexec() call (raw libpq command string)."""
    imports = [Import(name="PQexec", plt=0x401060)]
    xrefs = {0x401060: [Xref(0x401184, "CALL", "fetch_rows", "call sym.imp.PQexec")]}
    return FakeR2Session(imports, xrefs)


def sqlexecdirect_vuln_session() -> FakeR2Session:
    """A single SQLExecDirect() call (raw ODBC statement string)."""
    imports = [Import(name="SQLExecDirect", plt=0x401070)]
    xrefs = {
        0x401070: [Xref(0x401196, "CALL", "exec_stmt", "call sym.imp.SQLExecDirect")]
    }
    return FakeR2Session(imports, xrefs)


def sqlite3_prepare_v2_session() -> FakeR2Session:
    """A single sqlite3_prepare_v2() call (MEDIUM — gateway to bound params)."""
    imports = [Import(name="sqlite3_prepare_v2", plt=0x401080)]
    xrefs = {
        0x401080: [Xref(0x4011a8, "CALL", "compile_q", "call sym.imp.sqlite3_prepare_v2")]
    }
    return FakeR2Session(imports, xrefs)


def cwe89_all_session() -> FakeR2Session:
    """One call to each of five representative CWE-89 routines.

    Includes a safe neighbour (sqlite3_bind_text) that must NOT fire.
    """
    imports = [
        Import(name="sqlite3_exec", plt=0x401040),
        Import(name="mysql_query", plt=0x401050),
        Import(name="PQexec", plt=0x401060),
        Import(name="SQLExecDirect", plt=0x401070),
        Import(name="sqlite3_prepare_v2", plt=0x401080),
        Import(name="sqlite3_bind_text", plt=0x4010a0),  # safe API, must not fire
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "run_query", "call sym.imp.sqlite3_exec")],
        0x401050: [Xref(0x401172, "CALL", "lookup_user", "call sym.imp.mysql_query")],
        0x401060: [Xref(0x401184, "CALL", "fetch_rows", "call sym.imp.PQexec")],
        0x401070: [Xref(0x401196, "CALL", "exec_stmt", "call sym.imp.SQLExecDirect")],
        0x401080: [
            Xref(0x4011a8, "CALL", "compile_q", "call sym.imp.sqlite3_prepare_v2")
        ],
    }
    return FakeR2Session(imports, xrefs)


def cwe89_clean_session() -> FakeR2Session:
    """Only safe parameterised APIs imported — no CWE-89 routine present."""
    imports = [
        Import(name="sqlite3_bind_text", plt=0x401040),
        Import(name="sqlite3_step", plt=0x401050),
        Import(name="mysql_stmt_bind_param", plt=0x401060),
        Import(name="PQexecParams", plt=0x401070),
        Import(name="SQLBindParameter", plt=0x401080),
    ]
    return FakeR2Session(imports, xrefs={})


# --- CWE-119 memory-bounds fixtures ----------------------------------------
#
# Pure PLT-lookup detector (same shape as CWE-89 / CWE-327 / CWE-676): the
# presence of a call to a bounded/unbounded memory-copy or concatenation routine
# is the finding. No data flow — the call site is where an out-of-bounds write
# lands when the length is wrong or the destination capacity is exceeded.

def memcpy_vuln_session() -> FakeR2Session:
    """A single memcpy() call (caller-supplied length, possible OOB write)."""
    imports = [Import(name="memcpy", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "copy_buf", "call sym.imp.memcpy")]}
    return FakeR2Session(imports, xrefs)


def memmove_vuln_session() -> FakeR2Session:
    """A single memmove() call (caller-supplied length, possible OOB write)."""
    imports = [Import(name="memmove", plt=0x401050)]
    xrefs = {0x401050: [Xref(0x401172, "CALL", "shift_buf", "call sym.imp.memmove")]}
    return FakeR2Session(imports, xrefs)


def strcat_vuln_session() -> FakeR2Session:
    """A single strcat() call (unbounded concatenation)."""
    imports = [Import(name="strcat", plt=0x401060)]
    xrefs = {0x401060: [Xref(0x401184, "CALL", "build_path", "call sym.imp.strcat")]}
    return FakeR2Session(imports, xrefs)


def strncat_vuln_session() -> FakeR2Session:
    """A single strncat() call (source-relative count — MEDIUM)."""
    imports = [Import(name="strncat", plt=0x401070)]
    xrefs = {0x401070: [Xref(0x401196, "CALL", "append_seg", "call sym.imp.strncat")]}
    return FakeR2Session(imports, xrefs)


def alloca_vuln_session() -> FakeR2Session:
    """A single alloca() call (caller-supplied stack size — MEDIUM)."""
    imports = [Import(name="alloca", plt=0x401080)]
    xrefs = {0x401080: [Xref(0x4011a8, "CALL", "scratch", "call sym.imp.alloca")]}
    return FakeR2Session(imports, xrefs)


def cwe119_all_session() -> FakeR2Session:
    """One call to each of five representative CWE-119 routines.

    Includes a safe neighbour (strlcpy) that must NOT fire.
    """
    imports = [
        Import(name="memcpy", plt=0x401040),
        Import(name="memmove", plt=0x401050),
        Import(name="strcat", plt=0x401060),
        Import(name="strncat", plt=0x401070),
        Import(name="alloca", plt=0x401080),
        Import(name="strlcpy", plt=0x4010a0),  # safe API, must not fire
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "copy_buf", "call sym.imp.memcpy")],
        0x401050: [Xref(0x401172, "CALL", "shift_buf", "call sym.imp.memmove")],
        0x401060: [Xref(0x401184, "CALL", "build_path", "call sym.imp.strcat")],
        0x401070: [Xref(0x401196, "CALL", "append_seg", "call sym.imp.strncat")],
        0x401080: [Xref(0x4011a8, "CALL", "scratch", "call sym.imp.alloca")],
    }
    return FakeR2Session(imports, xrefs)


def cwe119_clean_session() -> FakeR2Session:
    """Only bounded/safe routines imported — no CWE-119 routine present."""
    imports = [
        Import(name="strlcpy", plt=0x401040),
        Import(name="strlcat", plt=0x401050),
        Import(name="snprintf", plt=0x401060),
        Import(name="memset", plt=0x401070),
    ]
    return FakeR2Session(imports, xrefs={})


# --- CWE-22 path-traversal fixtures ----------------------------------------
#
# Pure PLT-lookup detector (same shape as CWE-89 / CWE-119 / CWE-327 / CWE-676):
# the presence of a call to a path-consuming filesystem routine is the finding.
# No data flow — the call site is where traversal lands when the path is built
# from untrusted input and not canonicalised/confined.

def unlink_vuln_session() -> FakeR2Session:
    """A single unlink() call (HIGH — destructive delete by path)."""
    imports = [Import(name="unlink", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "del_file", "call sym.imp.unlink")]}
    return FakeR2Session(imports, xrefs)


def rename_vuln_session() -> FakeR2Session:
    """A single rename() call (HIGH — move/overwrite by path)."""
    imports = [Import(name="rename", plt=0x401050)]
    xrefs = {0x401050: [Xref(0x401172, "CALL", "move_file", "call sym.imp.rename")]}
    return FakeR2Session(imports, xrefs)


def symlink_vuln_session() -> FakeR2Session:
    """A single symlink() call (HIGH — classic ../-plus-symlink escape)."""
    imports = [Import(name="symlink", plt=0x401060)]
    xrefs = {0x401060: [Xref(0x401184, "CALL", "make_link", "call sym.imp.symlink")]}
    return FakeR2Session(imports, xrefs)


def execve_vuln_session() -> FakeR2Session:
    """A single execve() call (HIGH — run a binary chosen by path)."""
    imports = [Import(name="execve", plt=0x401070)]
    xrefs = {0x401070: [Xref(0x401196, "CALL", "spawn", "call sym.imp.execve")]}
    return FakeR2Session(imports, xrefs)


def open_vuln_session() -> FakeR2Session:
    """A single open() call (MEDIUM — open a file by path)."""
    imports = [Import(name="open", plt=0x401080)]
    xrefs = {0x401080: [Xref(0x4011a8, "CALL", "load_cfg", "call sym.imp.open")]}
    return FakeR2Session(imports, xrefs)


def fopen_path_vuln_session() -> FakeR2Session:
    """A single fopen() call (MEDIUM — open a file by path)."""
    imports = [Import(name="fopen", plt=0x401090)]
    xrefs = {0x401090: [Xref(0x4011ba, "CALL", "read_doc", "call sym.imp.fopen")]}
    return FakeR2Session(imports, xrefs)


def access_vuln_session() -> FakeR2Session:
    """A single access() call (MEDIUM — test a path; also a TOCTOU hint)."""
    imports = [Import(name="access", plt=0x4010a0)]
    xrefs = {0x4010a0: [Xref(0x4011cc, "CALL", "check_path", "call sym.imp.access")]}
    return FakeR2Session(imports, xrefs)


def cwe22_all_session() -> FakeR2Session:
    """One call to each of seven representative CWE-22 routines.

    Includes a safe neighbour (realpath, the canonicalisation primitive) that
    must NOT fire.
    """
    imports = [
        Import(name="unlink", plt=0x401040),
        Import(name="rename", plt=0x401050),
        Import(name="symlink", plt=0x401060),
        Import(name="execve", plt=0x401070),
        Import(name="open", plt=0x401080),
        Import(name="fopen", plt=0x401090),
        Import(name="access", plt=0x4010a0),
        Import(name="realpath", plt=0x4010b0),  # safe API, must not fire
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "del_file", "call sym.imp.unlink")],
        0x401050: [Xref(0x401172, "CALL", "move_file", "call sym.imp.rename")],
        0x401060: [Xref(0x401184, "CALL", "make_link", "call sym.imp.symlink")],
        0x401070: [Xref(0x401196, "CALL", "spawn", "call sym.imp.execve")],
        0x401080: [Xref(0x4011a8, "CALL", "load_cfg", "call sym.imp.open")],
        0x401090: [Xref(0x4011ba, "CALL", "read_doc", "call sym.imp.fopen")],
        0x4010a0: [Xref(0x4011cc, "CALL", "check_path", "call sym.imp.access")],
    }
    return FakeR2Session(imports, xrefs)


def cwe22_clean_session() -> FakeR2Session:
    """Only the canonicalisation primitive imported — no CWE-22 sink present."""
    imports = [
        Import(name="realpath", plt=0x401040),
        Import(name="printf", plt=0x401050),
    ]
    return FakeR2Session(imports, xrefs={})


# --- CWE-476 NULL-pointer-dereference fixtures -----------------------------
#
# Pattern: an allocator (malloc/calloc/fopen/...) returns a pointer in rax.
# Vulnerable cases dereference it (memory operand through the pointer register)
# with no intervening NULL guard. Safe cases test/cmp the pointer first.

def malloc_deref_vuln_session() -> FakeR2Session:
    """malloc() result dereferenced immediately, no NULL check (vulnerable)."""
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "build", "call sym.imp.malloc")]}
    # rax = malloc(...); *(int*)rax = 0  -> deref through rax, no test/cmp.
    build_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov edi, 0x10"),
        Instruction(0x401150, "call sym.imp.malloc"),
        Instruction(0x401155, "mov dword [rax], 0"),   # deref, no guard
        Instruction(0x40115c, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: build_ops})


def malloc_checked_session() -> FakeR2Session:
    """malloc() result NULL-checked before use (safe — must NOT flag)."""
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "build", "call sym.imp.malloc")]}
    # rax = malloc(...); test rax, rax; je fail; *(int*)rax = 0
    build_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov edi, 0x10"),
        Instruction(0x401150, "call sym.imp.malloc"),
        Instruction(0x401155, "test rax, rax"),         # NULL guard
        Instruction(0x401158, "je 0x401170"),
        Instruction(0x40115e, "mov dword [rax], 0"),     # deref AFTER guard
        Instruction(0x401165, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: build_ops})


def malloc_aliased_checked_session() -> FakeR2Session:
    """malloc() result moved to rbx, then rbx is NULL-checked (safe).

    Exercises the register-alias tracking: the guard is on rbx, not rax."""
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "build", "call sym.imp.malloc")]}
    build_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.malloc"),
        Instruction(0x401155, "mov rbx, rax"),          # alias: rbx = ptr
        Instruction(0x401158, "test rbx, rbx"),          # guard on the alias
        Instruction(0x40115b, "je 0x401180"),
        Instruction(0x401161, "mov dword [rbx], 1"),     # deref after guard
        Instruction(0x401168, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: build_ops})


def malloc_aliased_deref_vuln_session() -> FakeR2Session:
    """malloc() result moved to rbx, dereferenced via rbx, no guard (vulnerable)."""
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "build", "call sym.imp.malloc")]}
    build_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.malloc"),
        Instruction(0x401155, "mov rbx, rax"),          # alias: rbx = ptr
        Instruction(0x401158, "mov rcx, [rbx]"),         # deref via alias, no guard
        Instruction(0x40115f, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: build_ops})


def fopen_deref_vuln_session() -> FakeR2Session:
    """fopen() result passed-through then dereferenced without a NULL check."""
    imports = [Import(name="fopen", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x4011a0, "CALL", "read_cfg", "call sym.imp.fopen")]}
    read_cfg_ops = [
        Instruction(0x401180, "push rbp"),
        Instruction(0x4011a0, "call sym.imp.fopen"),
        Instruction(0x4011a5, "mov rsi, [rax]"),         # deref FILE*, no guard
        Instruction(0x4011ac, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401180: read_cfg_ops})


def calloc_stored_escapes_session() -> FakeR2Session:
    """calloc() result stored to the stack and never dereferenced in-function.

    The pointer escapes (we can't see the deref) — conservatively NOT flagged."""
    imports = [Import(name="calloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "alloc_it", "call sym.imp.calloc")]}
    alloc_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.calloc"),
        Instruction(0x401155, "mov qword [rbp - 0x8], rax"),  # store to stack (escape)
        Instruction(0x40115d, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: alloc_ops})


def cwe476_no_allocators_session() -> FakeR2Session:
    """A session with no nullable-allocator imports — nothing to flag."""
    imports = [
        Import(name="puts", plt=0x401030),
        Import(name="strlen", plt=0x401040),
    ]
    return FakeR2Session(imports, xrefs={})


def arm64_malloc_deref_vuln_session() -> FakeR2Session:
    """AArch64: malloc() result (x0) dereferenced with no cbz/cmp guard."""
    imports = [Import(name="malloc", plt=0x710)]
    xrefs = {0x710: [Xref(0x83c, "CALL", "build", "bl sym.imp.malloc")]}
    build_ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x838, "mov w0, 0x10"),
        Instruction(0x83c, "bl sym.imp.malloc"),
        Instruction(0x840, "str wzr, [x0]"),             # deref x0, no guard
        Instruction(0x844, "ldp x29, x30, [sp], 0x20"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: build_ops}, arch="arm64")


def arm64_malloc_checked_session() -> FakeR2Session:
    """AArch64: malloc() result (x0) guarded with cbz before deref (safe)."""
    imports = [Import(name="malloc", plt=0x710)]
    xrefs = {0x710: [Xref(0x83c, "CALL", "build", "bl sym.imp.malloc")]}
    build_ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x838, "mov w0, 0x10"),
        Instruction(0x83c, "bl sym.imp.malloc"),
        Instruction(0x840, "cbz x0, 0x860"),             # NULL guard
        Instruction(0x844, "str wzr, [x0]"),             # deref after guard
        Instruction(0x848, "ldp x29, x30, [sp], 0x20"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: build_ops}, arch="arm64")


# --- CWE-252 unchecked-return-value fixtures -------------------------------
#
# Pattern: a security-sensitive call (setuid/chroot/write/fclose/...) returns a
# status in rax. Vulnerable cases discard it — the return register is clobbered
# (overwritten / consumed by another call) or the function ends before the value
# is ever read. Safe cases test/cmp/save the return value before discarding it.

def setuid_unchecked_vuln_session() -> FakeR2Session:
    """setuid() return value ignored: clobbered by `mov eax, 0` before any read."""
    imports = [Import(name="setuid", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "drop_privs", "call sym.imp.setuid")]}
    drop_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov edi, 0"),
        Instruction(0x401150, "call sym.imp.setuid"),
        Instruction(0x401155, "mov eax, 0"),       # clobber rax, return discarded
        Instruction(0x40115a, "leave"),
        Instruction(0x40115b, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: drop_ops})


def setuid_checked_session() -> FakeR2Session:
    """setuid() return value tested before use (safe — must NOT flag)."""
    imports = [Import(name="setuid", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "drop_privs", "call sym.imp.setuid")]}
    drop_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov edi, 0"),
        Instruction(0x401150, "call sym.imp.setuid"),
        Instruction(0x401155, "test eax, eax"),     # NULL/zero guard on return
        Instruction(0x401158, "jne 0x401180"),
        Instruction(0x40115e, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: drop_ops})


def write_return_saved_session() -> FakeR2Session:
    """write() return value moved into another register (used — must NOT flag)."""
    imports = [Import(name="write", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x4011a0, "CALL", "dump", "call sym.imp.write")]}
    dump_ops = [
        Instruction(0x401180, "push rbp"),
        Instruction(0x4011a0, "call sym.imp.write"),
        Instruction(0x4011a5, "mov rbx, rax"),       # save return value → read
        Instruction(0x4011a8, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401180: dump_ops})


def fclose_unchecked_call_clobber_session() -> FakeR2Session:
    """fclose() return discarded by an immediately following call (clobber)."""
    imports = [
        Import(name="fclose", plt=0x401040),
        Import(name="puts", plt=0x401050),
    ]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "finish", "call sym.imp.fclose")]}
    finish_ops = [
        Instruction(0x401150, "push rbp"),
        Instruction(0x401160, "call sym.imp.fclose"),
        Instruction(0x401165, "lea rdi, str.done"),  # next call clobbers rax
        Instruction(0x40116c, "call sym.imp.puts"),
        Instruction(0x401171, "leave"),
    ]
    return FakeR2Session(imports, xrefs, {0x401150: finish_ops})


def chroot_unchecked_fallthrough_session() -> FakeR2Session:
    """chroot() return ignored: function ends without reading rax (discarded)."""
    imports = [Import(name="chroot", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "enter_jail", "call sym.imp.chroot")]}
    jail_ops = [
        Instruction(0x401150, "push rbp"),
        Instruction(0x401160, "call sym.imp.chroot"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),                # return never inspected
    ]
    return FakeR2Session(imports, xrefs, {0x401150: jail_ops})


def cwe252_clean_session() -> FakeR2Session:
    """Only non-sensitive imports — nothing CWE-252 should flag."""
    imports = [
        Import(name="printf", plt=0x401040),
        Import(name="malloc", plt=0x401050),
    ]
    return FakeR2Session(imports, xrefs={})


def arm64_setuid_unchecked_vuln_session() -> FakeR2Session:
    """AArch64: setuid() return (w0) clobbered by `mov w0, 0` before any read."""
    imports = [Import(name="setuid", plt=0x710)]
    xrefs = {0x710: [Xref(0x83c, "CALL", "drop_privs", "bl sym.imp.setuid")]}
    drop_ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x10]!"),
        Instruction(0x838, "mov w0, 0"),
        Instruction(0x83c, "bl sym.imp.setuid"),
        Instruction(0x840, "mov w0, 0"),             # clobber, return discarded
        Instruction(0x844, "ldp x29, x30, [sp], 0x10"),
        Instruction(0x848, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: drop_ops}, arch="arm64")


def arm64_setuid_checked_session() -> FakeR2Session:
    """AArch64: setuid() return (w0) guarded with cbz before discard (safe)."""
    imports = [Import(name="setuid", plt=0x710)]
    xrefs = {0x710: [Xref(0x83c, "CALL", "drop_privs", "bl sym.imp.setuid")]}
    drop_ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x10]!"),
        Instruction(0x838, "mov w0, 0"),
        Instruction(0x83c, "bl sym.imp.setuid"),
        Instruction(0x840, "cbz w0, 0x860"),         # guard on the return
        Instruction(0x844, "ldp x29, x30, [sp], 0x10"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: drop_ops}, arch="arm64")


# --- CWE-369 divide-by-zero fixtures ---------------------------------------
#
# Instruction-pattern detector (NOT a PLT-lookup): it walks every function body
# (function_addrs + function_instructions) looking for a div/idiv (x86_64) or
# sdiv/udiv (AArch64) whose divisor is a register or memory operand with no
# preceding zero-check. These fixtures carry only `functions=` disassembly.


def idiv_register_vuln_session() -> FakeR2Session:
    """x86_64: `idiv ecx` with no zero-check on ecx (vulnerable)."""
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov eax, dword [rbp - 0x4]"),  # dividend
        Instruction(0x401144, "cdq"),
        Instruction(0x401146, "idiv ecx"),                    # divisor ecx, unchecked
        Instruction(0x401148, "leave"),
        Instruction(0x401149, "ret"),
    ]
    return FakeR2Session(imports=[], functions={0x401136: ops})


def div_memory_vuln_session() -> FakeR2Session:
    """x86_64: `div dword [rbp - 0xc]` — memory divisor (vulnerable)."""
    ops = [
        Instruction(0x401200, "push rbp"),
        Instruction(0x401208, "mov eax, dword [rbp - 0x8]"),
        Instruction(0x40120c, "xor edx, edx"),
        Instruction(0x40120e, "div dword [rbp - 0xc]"),       # memory divisor
        Instruction(0x401211, "leave"),
        Instruction(0x401212, "ret"),
    ]
    return FakeR2Session(imports=[], functions={0x401200: ops})


def idiv_checked_session() -> FakeR2Session:
    """x86_64: divisor `ecx` zero-checked before the idiv (safe — must NOT fire)."""
    ops = [
        Instruction(0x401300, "push rbp"),
        Instruction(0x401308, "mov ecx, dword [rbp - 0x4]"),  # load divisor
        Instruction(0x40130c, "test ecx, ecx"),               # zero-check
        Instruction(0x40130e, "je 0x401320"),
        Instruction(0x401314, "mov eax, dword [rbp - 0x8]"),
        Instruction(0x401318, "cdq"),
        Instruction(0x40131a, "idiv ecx"),                    # guarded divisor
        Instruction(0x40131e, "leave"),
        Instruction(0x40131f, "ret"),
    ]
    return FakeR2Session(imports=[], functions={0x401300: ops})


def idiv_cmp_checked_session() -> FakeR2Session:
    """x86_64: divisor `esi` checked via `cmp esi, 0` before idiv (safe)."""
    ops = [
        Instruction(0x401400, "push rbp"),
        Instruction(0x401408, "cmp esi, 0"),                  # zero-check
        Instruction(0x40140b, "je 0x401420"),
        Instruction(0x401411, "mov eax, edi"),
        Instruction(0x401413, "cdq"),
        Instruction(0x401415, "idiv esi"),                    # guarded
        Instruction(0x401419, "leave"),
        Instruction(0x40141a, "ret"),
    ]
    return FakeR2Session(imports=[], functions={0x401400: ops})


def idiv_constant_divisor_session() -> FakeR2Session:
    """x86_64: divisor set from a nonzero immediate before idiv (safe)."""
    ops = [
        Instruction(0x401500, "push rbp"),
        Instruction(0x401508, "mov ecx, 0xa"),                # constant divisor 10
        Instruction(0x40150d, "mov eax, edi"),
        Instruction(0x40150f, "cdq"),
        Instruction(0x401511, "idiv ecx"),                    # divisor proven nonzero
        Instruction(0x401515, "leave"),
        Instruction(0x401516, "ret"),
    ]
    return FakeR2Session(imports=[], functions={0x401500: ops})


def no_division_session() -> FakeR2Session:
    """x86_64: a function with arithmetic but no division (must NOT fire)."""
    ops = [
        Instruction(0x401600, "push rbp"),
        Instruction(0x401608, "mov eax, edi"),
        Instruction(0x40160a, "imul eax, esi"),               # multiply, not divide
        Instruction(0x40160d, "add eax, 1"),
        Instruction(0x401610, "leave"),
        Instruction(0x401611, "ret"),
    ]
    return FakeR2Session(imports=[], functions={0x401600: ops})


def arm64_sdiv_register_vuln_session() -> FakeR2Session:
    """AArch64: `sdiv x0, x1, x2` with no zero-check on x2 (vulnerable)."""
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x10]!"),
        Instruction(0x838, "ldr w1, [x29, 0x8]"),             # dividend
        Instruction(0x83c, "ldr w2, [x29, 0xc]"),             # divisor (unchecked)
        Instruction(0x840, "sdiv w0, w1, w2"),                # divisor w2/x2
        Instruction(0x844, "ldp x29, x30, [sp], 0x10"),
        Instruction(0x848, "ret"),
    ]
    return FakeR2Session(imports=[], functions={0x830: ops}, arch="arm64")


def arm64_udiv_checked_session() -> FakeR2Session:
    """AArch64: divisor w2 guarded with `cbz` before udiv (safe)."""
    ops = [
        Instruction(0x900, "stp x29, x30, [sp, -0x10]!"),
        Instruction(0x908, "ldr w2, [x29, 0xc]"),             # load divisor
        Instruction(0x90c, "cbz w2, 0x930"),                  # zero-check
        Instruction(0x910, "ldr w1, [x29, 0x8]"),
        Instruction(0x914, "udiv w0, w1, w2"),                # guarded
        Instruction(0x918, "ldp x29, x30, [sp], 0x10"),
        Instruction(0x91c, "ret"),
    ]
    return FakeR2Session(imports=[], functions={0x900: ops}, arch="arm64")


def cwe369_multi_function_session() -> FakeR2Session:
    """Two functions: one unguarded idiv (flag), one guarded idiv (skip)."""
    vuln_ops = [
        Instruction(0x401136, "mov eax, edi"),
        Instruction(0x401138, "cdq"),
        Instruction(0x40113a, "idiv esi"),                    # unguarded → flag
        Instruction(0x40113e, "ret"),
    ]
    safe_ops = [
        Instruction(0x401200, "test ecx, ecx"),               # guard
        Instruction(0x401202, "je 0x401210"),
        Instruction(0x401208, "mov eax, edi"),
        Instruction(0x40120a, "cdq"),
        Instruction(0x40120c, "idiv ecx"),                    # guarded → skip
        Instruction(0x401210, "ret"),
    ]
    return FakeR2Session(
        imports=[], functions={0x401136: vuln_ops, 0x401200: safe_ops}
    )


def cwe369_clean_session() -> FakeR2Session:
    """No functions / no division anywhere — nothing to flag."""
    return FakeR2Session(imports=[], functions={})


# --- CWE-191 integer-underflow fixtures ------------------------------------
#
# PLT-anchored, single-function BACKWARD scan: a size argument to an
# allocator/copy (malloc arg0 = rdi/x0; memcpy length arg2 = rdx/x2) that is
# produced by an unguarded unsigned subtraction is the underflow signal. These
# carry both imports/xrefs (to find the sink) and the function disassembly.

def cwe191_malloc_sub_vuln_session() -> FakeR2Session:
    """x86_64: malloc(len - header) with no bounds check (vulnerable).

    eax = len; eax = eax - esi (header); edi = eax; call malloc — the size in
    edi/rdi is an unguarded subtraction result that wraps when len < header.
    """
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "alloc_body", "call sym.imp.malloc")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov eax, dword [rbp - 0x4]"),   # eax = len
        Instruction(0x401148, "mov esi, dword [rbp - 0x8]"),   # esi = header
        Instruction(0x40114c, "sub eax, esi"),                 # eax = len - header
        Instruction(0x40114f, "mov edi, eax"),                 # size arg (rdi)
        Instruction(0x401160, "call sym.imp.malloc"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe191_memcpy_sub_len_vuln_session() -> FakeR2Session:
    """x86_64: memcpy(dst, src, end - start) — length (rdx) is an unguarded sub."""
    imports = [Import(name="memcpy", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401210, "CALL", "copy_range", "call sym.imp.memcpy")]}
    ops = [
        Instruction(0x401200, "push rbp"),
        Instruction(0x401204, "mov rdx, qword [rbp - 0x10]"),  # rdx = end
        Instruction(0x401208, "sub rdx, rsi"),                 # rdx = end - start
        Instruction(0x40120c, "lea rdi, [rbp - 0x80]"),        # dst
        Instruction(0x401210, "call sym.imp.memcpy"),
        Instruction(0x401215, "leave"),
        Instruction(0x401216, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401200: ops})


def cwe191_sub_guarded_session() -> FakeR2Session:
    """x86_64: the operands are compared (cmp + jb) before the sub → safe."""
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "alloc_body", "call sym.imp.malloc")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov eax, dword [rbp - 0x4]"),   # eax = len
        Instruction(0x401144, "mov esi, dword [rbp - 0x8]"),   # esi = header
        Instruction(0x401148, "cmp eax, esi"),                 # bounds check
        Instruction(0x40114a, "jb 0x401180"),                  # if len < header skip
        Instruction(0x40114c, "sub eax, esi"),                 # guarded subtraction
        Instruction(0x40114f, "mov edi, eax"),
        Instruction(0x401160, "call sym.imp.malloc"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe191_malloc_constant_size_session() -> FakeR2Session:
    """x86_64: malloc(0x40) — constant size, no subtraction (safe)."""
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "alloc_fixed", "call sym.imp.malloc")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "mov edi, 0x40"),                # constant size
        Instruction(0x401160, "call sym.imp.malloc"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe191_aliased_sub_vuln_session() -> FakeR2Session:
    """x86_64: size reaches malloc through a register alias of a subtraction.

    rbx = rax - rcx; rdi = rbx; call malloc — the size in rdi traces back
    through rbx to an unguarded subtraction.
    """
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "alloc_alias", "call sym.imp.malloc")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rax, qword [rbp - 0x8]"),   # rax = total
        Instruction(0x401144, "mov rcx, qword [rbp - 0x10]"),  # rcx = used
        Instruction(0x401148, "sub rax, rcx"),                 # rax = total - used
        Instruction(0x40114b, "mov rbx, rax"),                 # alias the result
        Instruction(0x40114e, "mov rdi, rbx"),                 # size arg
        Instruction(0x401160, "call sym.imp.malloc"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe191_size_reloaded_safe_session() -> FakeR2Session:
    """x86_64: a sub exists, but the size is reloaded from memory afterward.

    The value reaching malloc is the fresh reload, NOT the subtraction → safe.
    """
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "alloc_reload", "call sym.imp.malloc")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov eax, dword [rbp - 0x4]"),
        Instruction(0x401144, "sub eax, esi"),                 # unrelated earlier sub
        Instruction(0x401148, "mov edi, dword [rbp - 0x20]"),  # size := fresh reload
        Instruction(0x401160, "call sym.imp.malloc"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe191_no_size_sinks_session() -> FakeR2Session:
    """No size-consuming sink imported — nothing for CWE-191 to anchor on."""
    imports = [
        Import(name="puts", plt=0x401030),
        Import(name="strlen", plt=0x401040),
    ]
    return FakeR2Session(imports, xrefs={})


def cwe191_arm64_malloc_sub_vuln_session() -> FakeR2Session:
    """AArch64: malloc(len - header) — size in x0 from an unguarded sub."""
    imports = [Import(name="malloc", plt=0x710)]
    xrefs = {0x710: [Xref(0x840, "CALL", "alloc_body", "bl sym.imp.malloc")]}
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x834, "ldr w1, [x29, 0x8]"),              # w1 = len
        Instruction(0x838, "ldr w2, [x29, 0xc]"),              # w2 = header
        Instruction(0x83c, "sub w0, w1, w2"),                  # w0 = len - header
        Instruction(0x840, "bl sym.imp.malloc"),
        Instruction(0x844, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x848, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def cwe191_arm64_sub_guarded_session() -> FakeR2Session:
    """AArch64: `cmp w1, w2; b.lo ...` guards the sub before malloc (safe)."""
    imports = [Import(name="malloc", plt=0x710)]
    xrefs = {0x710: [Xref(0x848, "CALL", "alloc_body", "bl sym.imp.malloc")]}
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x834, "ldr w1, [x29, 0x8]"),
        Instruction(0x838, "ldr w2, [x29, 0xc]"),
        Instruction(0x83c, "cmp w1, w2"),                      # bounds check
        Instruction(0x840, "b.lo 0x880"),                      # if len < header skip
        Instruction(0x844, "sub w0, w1, w2"),                  # guarded subtraction
        Instruction(0x848, "bl sym.imp.malloc"),
        Instruction(0x84c, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x850, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def cwe191_multi_call_session() -> FakeR2Session:
    """Two malloc sites in two functions: one sub-sized (flag), one constant."""
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {
        0x401040: [
            Xref(0x40113A, "CALL", "vuln_alloc", "call sym.imp.malloc"),
            Xref(0x401234, "CALL", "fixed_alloc", "call sym.imp.malloc"),
        ]
    }
    vuln_ops = [
        Instruction(0x401130, "mov eax, dword [rbp - 0x4]"),
        Instruction(0x401134, "sub eax, esi"),                 # unguarded sub
        Instruction(0x401137, "mov edi, eax"),
        Instruction(0x40113A, "call sym.imp.malloc"),          # → flag
        Instruction(0x40113F, "ret"),
    ]
    fixed_ops = [
        Instruction(0x401230, "mov edi, 0x20"),                # constant size
        Instruction(0x401234, "call sym.imp.malloc"),          # → skip
        Instruction(0x401239, "ret"),
    ]
    return FakeR2Session(
        imports, xrefs, {0x401130: vuln_ops, 0x401230: fixed_ops}
    )


# --- AArch64 (arm64) fixtures (POST_V01 item 5) ----------------------------
#
# On AArch64 the first integer/pointer argument lives in x0 (w0 for the 32-bit
# view), the second in x1, the third in x2 — not rdi/rsi/rdx. These fixtures
# exercise the architecture-aware register heuristic in cwe78/cwe134.

def arm64_system_vuln_session() -> FakeR2Session:
    """AArch64: system() with a non-constant command in x0 (stack-built)."""
    imports = [Import(name="system", plt=0x710)]
    xrefs = {0x710: [Xref(0x84c, "CALL", "run_cmd", "bl sym.imp.system")]}
    # x0 is set from a stack address (not a str.*) => non-constant => flagged.
    run_cmd_ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x120]!"),
        Instruction(0x838, "add x1, sp, 0x10"),
        Instruction(0x83c, "adrp x0, str.ls__s"),
        Instruction(0x840, "add x0, x0, str.ls__s"),   # x0 = format literal for sprintf
        Instruction(0x844, "bl sym.imp.sprintf"),
        Instruction(0x848, "add x0, sp, 0x10"),         # x0 = stack buffer (non-const)
        Instruction(0x84c, "bl sym.imp.system"),
        Instruction(0x850, "ldp x29, x30, [sp], 0x120"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: run_cmd_ops}, arch="arm64")


def arm64_system_constant_session() -> FakeR2Session:
    """AArch64: system("ls") — constant x0, must NOT be flagged."""
    imports = [Import(name="system", plt=0x710)]
    xrefs = {0x710: [Xref(0x80c, "CALL", "main", "bl sym.imp.system")]}
    main_ops = [
        Instruction(0x800, "stp x29, x30, [sp, -0x10]!"),
        Instruction(0x804, "adrp x0, str.ls"),
        Instruction(0x808, "add x0, x0, str.ls"),   # x0 = "ls" literal
        Instruction(0x80c, "bl sym.imp.system"),
        Instruction(0x810, "ldp x29, x30, [sp], 0x10"),
    ]
    return FakeR2Session(imports, xrefs, {0x800: main_ops}, arch="arm64")


def arm64_printf_fmtstr_vuln_session() -> FakeR2Session:
    """AArch64: printf() with a non-constant format string in x0 (stack-built)."""
    imports = [Import(name="printf", plt=0x710)]
    xrefs = {0x710: [Xref(0x848, "CALL", "log_msg", "bl sym.imp.printf")]}
    log_msg_ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x90]!"),
        Instruction(0x83c, "add x0, sp, 0x10"),     # x0 = stack buffer (non-const)
        Instruction(0x848, "bl sym.imp.printf"),
        Instruction(0x84c, "ldp x29, x30, [sp], 0x90"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: log_msg_ops}, arch="arm64")


def arm64_printf_constant_session() -> FakeR2Session:
    """AArch64: printf("Hello %s\\n", name) — constant x0, must NOT be flagged."""
    imports = [Import(name="printf", plt=0x710)]
    xrefs = {0x710: [Xref(0x814, "CALL", "main", "bl sym.imp.printf")]}
    main_ops = [
        Instruction(0x800, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x804, "add x1, sp, 0x10"),               # arg1: name
        Instruction(0x808, "adrp x0, str.Hello__s_n"),
        Instruction(0x80c, "add x0, x0, str.Hello__s_n"),     # x0 = format literal
        Instruction(0x814, "bl sym.imp.printf"),
        Instruction(0x818, "ldp x29, x30, [sp], 0x20"),
    ]
    return FakeR2Session(imports, xrefs, {0x800: main_ops}, arch="arm64")


def arm64_fprintf_fmtstr_vuln_session() -> FakeR2Session:
    """AArch64: fprintf() with non-constant format in x1 (second arg)."""
    imports = [Import(name="fprintf", plt=0x710)]
    xrefs = {0x710: [Xref(0x84c, "CALL", "write_log", "bl sym.imp.fprintf")]}
    # x0 = FILE*, x1 = format. x1 is loaded from the stack => non-constant.
    write_log_ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x110]!"),
        Instruction(0x83c, "ldr x0, [x29, 0x18]"),   # x0 = FILE* (not the format)
        Instruction(0x844, "add x1, sp, 0x10"),       # x1 = stack buffer (non-const)
        Instruction(0x84c, "bl sym.imp.fprintf"),
        Instruction(0x850, "ldp x29, x30, [sp], 0x110"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: write_log_ops}, arch="arm64")


def arm64_gets_vuln_session() -> FakeR2Session:
    """AArch64: a single gets() call — CWE-242 is register-agnostic, so it must
    flag on ARM exactly as on x86_64."""
    imports = [Import(name="gets", plt=0x710)]
    xrefs = {0x710: [Xref(0x820, "CALL", "main", "bl sym.imp.gets")]}
    return FakeR2Session(imports, xrefs, arch="arm64")


def arm64_strcpy_vuln_session() -> FakeR2Session:
    """AArch64: a single strcpy() call — CWE-120 is register-agnostic and must
    flag on ARM exactly as on x86_64."""
    imports = [Import(name="strcpy", plt=0x710)]
    xrefs = {0x710: [Xref(0x830, "CALL", "copy_it", "bl sym.imp.strcpy")]}
    return FakeR2Session(imports, xrefs, arch="arm64")


# --- CWE-426 untrusted-search-path fixtures --------------------------------
#
# Pure PLT-lookup detector (same shape as CWE-327 / CWE-89 / CWE-676): the
# presence of a call to a search-path-resolving routine is the finding. No data
# flow — the weakness is the resolution mechanism ($PATH / LD_LIBRARY_PATH /
# rpath / CWD), not the argument, so even a constant name is hijackable.

def dlopen_vuln_session() -> FakeR2Session:
    """A single dlopen() call (HIGH — library resolved via loader search path)."""
    imports = [Import(name="dlopen", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "load_plugin", "call sym.imp.dlopen")]}
    return FakeR2Session(imports, xrefs)


def dlmopen_vuln_session() -> FakeR2Session:
    """A single dlmopen() call (HIGH — library resolved via loader search path)."""
    imports = [Import(name="dlmopen", plt=0x401050)]
    xrefs = {
        0x401050: [Xref(0x401172, "CALL", "load_ns", "call sym.imp.dlmopen")]
    }
    return FakeR2Session(imports, xrefs)


def execvp_searchpath_vuln_session() -> FakeR2Session:
    """A single execvp() call (HIGH — program resolved via $PATH)."""
    imports = [Import(name="execvp", plt=0x401060)]
    xrefs = {0x401060: [Xref(0x401184, "CALL", "spawn_tool", "call sym.imp.execvp")]}
    return FakeR2Session(imports, xrefs)


def execlp_searchpath_vuln_session() -> FakeR2Session:
    """A single execlp() call (HIGH — program resolved via $PATH)."""
    imports = [Import(name="execlp", plt=0x401070)]
    xrefs = {0x401070: [Xref(0x401196, "CALL", "run_helper", "call sym.imp.execlp")]}
    return FakeR2Session(imports, xrefs)


def popen_searchpath_vuln_session() -> FakeR2Session:
    """A single popen() call (HIGH — runs /bin/sh -c, $PATH resolution)."""
    imports = [Import(name="popen", plt=0x401080)]
    xrefs = {0x401080: [Xref(0x4011a8, "CALL", "read_proc", "call sym.imp.popen")]}
    return FakeR2Session(imports, xrefs)


def system_searchpath_vuln_session() -> FakeR2Session:
    """A single system() call (HIGH — runs /bin/sh -c, $PATH resolution).

    Note: this is the *same symbol* CWE-78 inspects for command injection, but
    CWE-426 flags it for a different reason (the $PATH resolution mechanism), so
    a call site can legitimately carry both findings.
    """
    imports = [Import(name="system", plt=0x401090)]
    xrefs = {0x401090: [Xref(0x4011ba, "CALL", "run_cmd", "call sym.imp.system")]}
    return FakeR2Session(imports, xrefs)


def cwe426_all_session() -> FakeR2Session:
    """One call to each of the seven CWE-426 routines.

    Includes safe neighbours (execve — explicit path, no $PATH search; and
    snprintf) that must NOT fire.
    """
    imports = [
        Import(name="dlopen", plt=0x401040),
        Import(name="dlmopen", plt=0x401050),
        Import(name="execlp", plt=0x401060),
        Import(name="execvp", plt=0x401070),
        Import(name="execvpe", plt=0x401080),
        Import(name="popen", plt=0x401090),
        Import(name="system", plt=0x4010a0),
        Import(name="execve", plt=0x4010b0),   # explicit path — must NOT fire
        Import(name="snprintf", plt=0x4010c0),  # safe neighbour — must NOT fire
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "load_plugin", "call sym.imp.dlopen")],
        0x401050: [Xref(0x401172, "CALL", "load_ns", "call sym.imp.dlmopen")],
        0x401060: [Xref(0x401184, "CALL", "run_helper", "call sym.imp.execlp")],
        0x401070: [Xref(0x401196, "CALL", "spawn_tool", "call sym.imp.execvp")],
        0x401080: [Xref(0x4011a8, "CALL", "spawn_env", "call sym.imp.execvpe")],
        0x401090: [Xref(0x4011ba, "CALL", "read_proc", "call sym.imp.popen")],
        0x4010a0: [Xref(0x4011cc, "CALL", "run_cmd", "call sym.imp.system")],
    }
    return FakeR2Session(imports, xrefs)


def cwe426_clean_session() -> FakeR2Session:
    """Only explicit-path / safe launchers imported — no CWE-426 sink present."""
    imports = [
        Import(name="execv", plt=0x401040),
        Import(name="execve", plt=0x401050),
        Import(name="posix_spawn", plt=0x401060),
        Import(name="printf", plt=0x401070),
    ]
    return FakeR2Session(imports, xrefs={})


# --- CWE-362 TOCTOU check-then-use fixtures --------------------------------
#
# Pure PLT-lookup detector (same shape as CWE-426 / CWE-22 / CWE-676): the
# presence of a call to a check-by-path primitive (access/stat family) is the
# finding. No data flow — the call site is where a time-of-check-to-time-of-use
# race lands when the result gates a later use of the same path.

def access_toctou_vuln_session() -> FakeR2Session:
    """A single access() call (MEDIUM — permission check by path, classic TOCTOU)."""
    imports = [Import(name="access", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "guarded_open", "call sym.imp.access")]}
    return FakeR2Session(imports, xrefs)


def faccessat_toctou_vuln_session() -> FakeR2Session:
    """A single faccessat() call (MEDIUM — by-name check still races without AT_*)."""
    imports = [Import(name="faccessat", plt=0x401050)]
    xrefs = {0x401050: [Xref(0x401172, "CALL", "check_at", "call sym.imp.faccessat")]}
    return FakeR2Session(imports, xrefs)


def stat_toctou_vuln_session() -> FakeR2Session:
    """A single stat() call (MEDIUM — metadata check by path, then act on it)."""
    imports = [Import(name="stat", plt=0x401060)]
    xrefs = {0x401060: [Xref(0x401184, "CALL", "inspect", "call sym.imp.stat")]}
    return FakeR2Session(imports, xrefs)


def lstat_toctou_vuln_session() -> FakeR2Session:
    """A single lstat() call (MEDIUM — symlink-aware metadata check by path)."""
    imports = [Import(name="lstat", plt=0x401070)]
    xrefs = {0x401070: [Xref(0x401196, "CALL", "probe_link", "call sym.imp.lstat")]}
    return FakeR2Session(imports, xrefs)


def cwe362_all_session() -> FakeR2Session:
    """One call to each of the nine CWE-362 check primitives.

    Includes safe neighbours (fstat — fd-based, never a path; and open) that
    must NOT fire: fstat takes an fd and so cannot race on a name, and open is a
    *use* sink (CWE-22's remit), not a check primitive.
    """
    imports = [
        Import(name="access", plt=0x401040),
        Import(name="faccessat", plt=0x401050),
        Import(name="euidaccess", plt=0x401060),
        Import(name="eaccess", plt=0x401070),
        Import(name="stat", plt=0x401080),
        Import(name="lstat", plt=0x401090),
        Import(name="fstatat", plt=0x4010a0),
        Import(name="stat64", plt=0x4010b0),
        Import(name="lstat64", plt=0x4010c0),
        Import(name="fstat", plt=0x4010d0),  # fd-based — must NOT fire
        Import(name="open", plt=0x4010e0),   # a use sink, not a check — must NOT fire
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "guarded_open", "call sym.imp.access")],
        0x401050: [Xref(0x401172, "CALL", "check_at", "call sym.imp.faccessat")],
        0x401060: [Xref(0x401184, "CALL", "euid_check", "call sym.imp.euidaccess")],
        0x401070: [Xref(0x401196, "CALL", "eacc_check", "call sym.imp.eaccess")],
        0x401080: [Xref(0x4011a8, "CALL", "inspect", "call sym.imp.stat")],
        0x401090: [Xref(0x4011ba, "CALL", "probe_link", "call sym.imp.lstat")],
        0x4010a0: [Xref(0x4011cc, "CALL", "stat_at", "call sym.imp.fstatat")],
        0x4010b0: [Xref(0x4011de, "CALL", "big_stat", "call sym.imp.stat64")],
        0x4010c0: [Xref(0x4011f0, "CALL", "big_lstat", "call sym.imp.lstat64")],
    }
    return FakeR2Session(imports, xrefs)


def cwe362_clean_session() -> FakeR2Session:
    """Only fd-based / atomic primitives imported — no CWE-362 check present."""
    imports = [
        Import(name="fstat", plt=0x401040),     # fd-based, never a path
        Import(name="openat", plt=0x401050),    # atomic dirfd-relative open
        Import(name="open", plt=0x401060),      # a use sink (CWE-22), not a check
        Import(name="printf", plt=0x401070),
    ]
    return FakeR2Session(imports, xrefs={})


# --- CWE-798 hard-coded-credential fixtures --------------------------------
#
# Data-driven detector (NOT a PLT-lookup): it scans the binary's extracted
# string literals (R2Session.strings() / radare2 izzj) for the textual shape of
# an embedded secret. Each fixture supplies a `strings=[Str(...)]` list.

def _strings_session(strings: list[Str]) -> FakeR2Session:
    """A session carrying only string literals (no imports/xrefs)."""
    return FakeR2Session(imports=[], strings=strings)


def password_assignment_vuln_session() -> FakeR2Session:
    """A `password=...` assignment with a concrete value (HIGH)."""
    return _strings_session(
        [Str(vaddr=0x402010, string="password=SuperSecret123", section=".rodata")]
    )


def passwd_colon_assignment_vuln_session() -> FakeR2Session:
    """A `passwd: ...` colon-style assignment with a concrete value (HIGH)."""
    return _strings_session(
        [Str(vaddr=0x402020, string="db_passwd: hunter2value", section=".rodata")]
    )


def api_key_secret_shaped_vuln_session() -> FakeR2Session:
    """An `api_key=` with a long, secret-shaped value (token-class → HIGH)."""
    return _strings_session(
        [
            Str(
                vaddr=0x402030,
                string="api_key=AKIAIOSFODNN7EXAMPLE0KEY",
                section=".rodata",
            )
        ]
    )


def token_short_value_session() -> FakeR2Session:
    """A `token=` with a short, non-secret-shaped value (token-class → MEDIUM)."""
    return _strings_session(
        [Str(vaddr=0x402040, string="token=abc123", section=".rodata")]
    )


def private_key_blob_vuln_session() -> FakeR2Session:
    """An embedded PEM private-key header (HIGH)."""
    return _strings_session(
        [
            Str(
                vaddr=0x403000,
                string=(
                    "-----BEGIN RSA PRIVATE KEY-----\n"
                    "MIIEpAIBAAKCAQEA...redacted...\n"
                    "-----END RSA PRIVATE KEY-----"
                ),
                section=".rodata",
            )
        ]
    )


def openssh_key_blob_vuln_session() -> FakeR2Session:
    """An embedded OpenSSH private-key banner (HIGH)."""
    return _strings_session(
        [
            Str(
                vaddr=0x403100,
                string="-----BEGIN OPENSSH PRIVATE KEY-----",
                section=".data",
            )
        ]
    )


def uri_credential_vuln_session() -> FakeR2Session:
    """A connection URI carrying an inline user:password@host (HIGH)."""
    return _strings_session(
        [
            Str(
                vaddr=0x402050,
                string="mysql://root:hunter2pass@db.internal:3306/app",
                section=".rodata",
            )
        ]
    )


def cwe798_placeholder_clean_session() -> FakeR2Session:
    """Placeholders / templates / empty values — must NOT fire."""
    return _strings_session(
        [
            Str(vaddr=0x402060, string="password=%s", section=".rodata"),
            Str(vaddr=0x402068, string="password=", section=".rodata"),
            Str(vaddr=0x402070, string="api_key=${API_KEY}", section=".rodata"),
            Str(vaddr=0x402078, string="secret=changeme", section=".rodata"),
            Str(vaddr=0x402080, string="token={0}", section=".rodata"),
            Str(vaddr=0x402088, string="password=YOUR_PASSWORD_HERE", section=".rodata"),
            Str(vaddr=0x402090, string="http://user:%s@host/path", section=".rodata"),
            Str(vaddr=0x402098, string="username=admin", section=".rodata"),  # not a secret key
        ]
    )


def cwe798_no_strings_session() -> FakeR2Session:
    """A binary with no string literals at all — nothing to flag."""
    return _strings_session([])


# --- CWE-416 use-after-free fixtures ---------------------------------------
#
# Pattern: a pointer is passed to free() in the first-argument register (rdi on
# x86_64, x0 on AArch64). Vulnerable cases read that register again — deref a
# memory operand through it, or pass it to another call — with no intervening
# reassignment. Safe cases reassign the freed register (mov rdi, 0 / xor / a
# fresh reload) before any use, or never touch it again.

def free_then_deref_vuln_session() -> FakeR2Session:
    """free(rdi) then `mov rax, [rdi]` — deref the freed pointer (vulnerable)."""
    imports = [Import(name="free", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "use_after", "call sym.imp.free")]}
    use_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),  # rdi = ptr
        Instruction(0x401150, "call sym.imp.free"),
        Instruction(0x401155, "mov rax, qword [rdi]"),         # deref freed ptr
        Instruction(0x40115c, "leave"),
        Instruction(0x40115d, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: use_ops})


def free_then_null_assign_session() -> FakeR2Session:
    """free(rdi); rdi = 0 before any use — the canonical ptr=NULL (safe)."""
    imports = [Import(name="free", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "tidy", "call sym.imp.free")]}
    tidy_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.free"),
        Instruction(0x401155, "mov rdi, 0"),                   # reassign → kill alias
        Instruction(0x40115c, "mov rax, rdi"),                 # later read is of NULL
        Instruction(0x40115f, "leave"),
        Instruction(0x401160, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: tidy_ops})


def free_then_xor_zero_session() -> FakeR2Session:
    """free(rdi); xor rdi, rdi before any use — zeroed alias (safe)."""
    imports = [Import(name="free", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "tidy", "call sym.imp.free")]}
    tidy_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.free"),
        Instruction(0x401155, "xor rdi, rdi"),                 # zero → kill alias
        Instruction(0x401158, "mov qword [rbp - 0x8], rdi"),   # store NULL back
        Instruction(0x40115f, "leave"),
        Instruction(0x401160, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: tidy_ops})


def free_then_aliased_deref_vuln_session() -> FakeR2Session:
    """free(rdi); rbx = rdi; deref via rbx — alias propagation (vulnerable)."""
    imports = [Import(name="free", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "use_alias", "call sym.imp.free")]}
    use_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.free"),
        Instruction(0x401155, "mov rbx, rdi"),                 # alias: rbx = freed ptr
        Instruction(0x401158, "mov rcx, qword [rbx]"),          # deref via alias
        Instruction(0x40115f, "leave"),
        Instruction(0x401160, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: use_ops})


def free_then_pass_to_call_vuln_session() -> FakeR2Session:
    """free(rdi); then call puts while rdi still holds the freed ptr (vulnerable)."""
    imports = [
        Import(name="free", plt=0x401040),
        Import(name="puts", plt=0x401050),
    ]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "dbl_use", "call sym.imp.free")]}
    use_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.free"),
        Instruction(0x401155, "call sym.imp.puts"),            # rdi still freed ptr
        Instruction(0x40115a, "leave"),
        Instruction(0x40115b, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: use_ops})


def free_then_reassigned_before_call_session() -> FakeR2Session:
    """free(rdi); rdi reloaded with a fresh value before the next call (safe)."""
    imports = [
        Import(name="free", plt=0x401040),
        Import(name="puts", plt=0x401050),
    ]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "reload", "call sym.imp.free")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.free"),
        Instruction(0x401155, "lea rdi, str.done"),            # fresh value → kill alias
        Instruction(0x40115c, "call sym.imp.puts"),            # passes the fresh ptr
        Instruction(0x401161, "leave"),
        Instruction(0x401162, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def free_then_unused_session() -> FakeR2Session:
    """free(rdi); the freed register is never read again (safe — nothing to flag)."""
    imports = [Import(name="free", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "release", "call sym.imp.free")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.free"),
        Instruction(0x401155, "mov eax, 0"),                   # unrelated work
        Instruction(0x40115a, "leave"),
        Instruction(0x40115b, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe416_no_free_imports_session() -> FakeR2Session:
    """A session with no deallocator imports — nothing to flag."""
    imports = [
        Import(name="malloc", plt=0x401030),
        Import(name="puts", plt=0x401040),
    ]
    return FakeR2Session(imports, xrefs={})


def arm64_free_then_deref_vuln_session() -> FakeR2Session:
    """AArch64: free(x0) then `ldr x1, [x0]` — deref freed ptr (vulnerable)."""
    imports = [Import(name="free", plt=0x710)]
    xrefs = {0x710: [Xref(0x83c, "CALL", "use_after", "bl sym.imp.free")]}
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x838, "ldr x0, [x29, 0x18]"),             # x0 = ptr
        Instruction(0x83c, "bl sym.imp.free"),
        Instruction(0x840, "ldr x1, [x0]"),                     # deref freed ptr
        Instruction(0x844, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x848, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def arm64_free_then_null_assign_session() -> FakeR2Session:
    """AArch64: free(x0); x0 = 0 before any use — ptr=NULL (safe)."""
    imports = [Import(name="free", plt=0x710)]
    xrefs = {0x710: [Xref(0x83c, "CALL", "tidy", "bl sym.imp.free")]}
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x838, "ldr x0, [x29, 0x18]"),
        Instruction(0x83c, "bl sym.imp.free"),
        Instruction(0x840, "mov x0, 0"),                        # reassign → kill alias
        Instruction(0x844, "str x0, [x29, 0x18]"),              # store NULL back
        Instruction(0x848, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x84c, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


# --- CWE-415 double-free fixtures ------------------------------------------
#
# Pattern: a pointer is passed to free() in the first-argument register (rdi on
# x86_64, x0 on AArch64) and is then passed to free() *again* in the same
# function. Vulnerable cases reach the second free with the register still
# aliasing the freed pointer (directly, or through a register-to-register move).
# Safe cases reassign the freed register (mov rdi, 0 / xor / a fresh reload)
# before the second free, only ever free once, or use the dangling pointer for
# something other than a second free (that is CWE-416's signal, not CWE-415's).

def double_free_vuln_session() -> FakeR2Session:
    """free(rdi); ... ; free(rdi) again — classic double-free (vulnerable)."""
    imports = [Import(name="free", plt=0x401040)]
    xrefs = {
        0x401040: [
            Xref(0x401150, "CALL", "dbl_free", "call sym.imp.free"),
            Xref(0x401160, "CALL", "dbl_free", "call sym.imp.free"),
        ]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),  # rdi = ptr
        Instruction(0x401150, "call sym.imp.free"),            # first free
        Instruction(0x401155, "mov eax, 0"),                   # unrelated work
        Instruction(0x401160, "call sym.imp.free"),            # SECOND free → bug
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def double_free_via_alias_vuln_session() -> FakeR2Session:
    """free(rdi); rbx = rdi; rdi = rbx; free(rdi) — alias-propagated double-free."""
    imports = [Import(name="free", plt=0x401040)]
    xrefs = {
        0x401040: [
            Xref(0x401150, "CALL", "alias_dbl", "call sym.imp.free"),
            Xref(0x401168, "CALL", "alias_dbl", "call sym.imp.free"),
        ]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.free"),            # first free
        Instruction(0x401155, "mov rbx, rdi"),                 # rbx aliases freed ptr
        Instruction(0x401160, "mov rdi, rbx"),                 # rdi re-aliases it
        Instruction(0x401168, "call sym.imp.free"),            # SECOND free → bug
        Instruction(0x40116d, "leave"),
        Instruction(0x40116e, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def double_free_nulled_between_session() -> FakeR2Session:
    """free(rdi); rdi = 0; ...; free(rdi) — alias killed before 2nd free (safe)."""
    imports = [Import(name="free", plt=0x401040)]
    xrefs = {
        0x401040: [
            Xref(0x401150, "CALL", "tidy_twice", "call sym.imp.free"),
            Xref(0x401168, "CALL", "tidy_twice", "call sym.imp.free"),
        ]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.free"),            # first free
        Instruction(0x401155, "mov rdi, 0"),                   # ptr = NULL → safe
        Instruction(0x40115c, "mov rdi, qword [rbp - 0x10]"),  # load a *different* ptr
        Instruction(0x401168, "call sym.imp.free"),            # frees the other ptr
        Instruction(0x40116d, "leave"),
        Instruction(0x40116e, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def double_free_xor_between_session() -> FakeR2Session:
    """free(rdi); xor rdi, rdi; free(rdi) — zeroed before 2nd free (safe)."""
    imports = [Import(name="free", plt=0x401040)]
    xrefs = {
        0x401040: [
            Xref(0x401150, "CALL", "zero_twice", "call sym.imp.free"),
            Xref(0x401165, "CALL", "zero_twice", "call sym.imp.free"),
        ]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.free"),            # first free
        Instruction(0x401155, "xor rdi, rdi"),                 # zero → kill alias
        Instruction(0x40115d, "mov rdi, qword [rbp - 0x10]"),  # load a different ptr
        Instruction(0x401165, "call sym.imp.free"),            # frees the other ptr
        Instruction(0x40116a, "leave"),
        Instruction(0x40116b, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def single_free_session() -> FakeR2Session:
    """free(rdi) exactly once — nothing to flag for double-free."""
    imports = [Import(name="free", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "release_one", "call sym.imp.free")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.free"),            # only free
        Instruction(0x401155, "mov eax, 0"),
        Instruction(0x40115a, "leave"),
        Instruction(0x40115b, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def free_then_nonfree_use_session() -> FakeR2Session:
    """free(rdi); call puts (a *use*, not a free) — CWE-416's signal, not 415's."""
    imports = [
        Import(name="free", plt=0x401040),
        Import(name="puts", plt=0x401050),
    ]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "use_not_free", "call sym.imp.free")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.free"),            # first free
        Instruction(0x401155, "call sym.imp.puts"),            # generic use, not free
        Instruction(0x40115a, "leave"),
        Instruction(0x40115b, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe415_no_free_imports_session() -> FakeR2Session:
    """A session with no deallocator imports — nothing to flag."""
    imports = [
        Import(name="malloc", plt=0x401030),
        Import(name="puts", plt=0x401040),
    ]
    return FakeR2Session(imports, xrefs={})


def arm64_double_free_vuln_session() -> FakeR2Session:
    """AArch64: free(x0); ...; free(x0) again — double-free (vulnerable)."""
    imports = [Import(name="free", plt=0x710)]
    xrefs = {
        0x710: [
            Xref(0x83c, "CALL", "dbl_free", "bl sym.imp.free"),
            Xref(0x848, "CALL", "dbl_free", "bl sym.imp.free"),
        ]
    }
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x838, "ldr x0, [x29, 0x18]"),             # x0 = ptr
        Instruction(0x83c, "bl sym.imp.free"),                 # first free
        Instruction(0x840, "nop"),
        Instruction(0x848, "bl sym.imp.free"),                 # SECOND free → bug
        Instruction(0x84c, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x850, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def arm64_double_free_nulled_session() -> FakeR2Session:
    """AArch64: free(x0); x0 = 0; free(x0) — alias killed before 2nd free (safe)."""
    imports = [Import(name="free", plt=0x710)]
    xrefs = {
        0x710: [
            Xref(0x83c, "CALL", "tidy_twice", "bl sym.imp.free"),
            Xref(0x84c, "CALL", "tidy_twice", "bl sym.imp.free"),
        ]
    }
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x838, "ldr x0, [x29, 0x18]"),
        Instruction(0x83c, "bl sym.imp.free"),                 # first free
        Instruction(0x840, "mov x0, 0"),                        # x0 = NULL → safe
        Instruction(0x844, "ldr x0, [x29, 0x10]"),              # load a different ptr
        Instruction(0x84c, "bl sym.imp.free"),                  # frees the other ptr
        Instruction(0x850, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x854, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


# --- CWE-122 heap-based-buffer-overflow fixtures ---------------------------
#
# Pattern: an allocator (malloc/calloc/strdup/...) returns a heap buffer in rax
# (x0 on AArch64). A vulnerable case routes that pointer into the destination
# (first-argument) register of an UNBOUNDED copy (strcpy/strcat/sprintf/gets) in
# the same function — the fixed-size heap buffer is the copy destination, so it
# can overflow. Safe cases reassign the destination before the copy, use a
# bounded copy, or never feed the heap pointer to a copy at all.


def malloc_strcpy_heap_overflow_vuln_session() -> FakeR2Session:
    """malloc() result handed to strcpy as destination, no resize (vulnerable)."""
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="strcpy", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401150, "CALL", "build", "call sym.imp.malloc")],
        0x401050: [Xref(0x401160, "CALL", "build", "call sym.imp.strcpy")],
    }
    # rax = malloc(16); rdi = rax; strcpy(rdi, src) -> heap dest, unbounded copy.
    build_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov edi, 0x10"),
        Instruction(0x401150, "call sym.imp.malloc"),       # rax = heap buffer
        Instruction(0x401155, "mov rdi, rax"),              # dest = heap buffer
        Instruction(0x40115a, "lea rsi, str.user_input"),   # source string
        Instruction(0x401160, "call sym.imp.strcpy"),       # unbounded copy → bug
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: build_ops})


def calloc_sprintf_heap_overflow_vuln_session() -> FakeR2Session:
    """calloc() result routed (via rbx alias) into sprintf destination (vulnerable)."""
    imports = [
        Import(name="calloc", plt=0x401040),
        Import(name="sprintf", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401150, "CALL", "fmt", "call sym.imp.calloc")],
        0x401050: [Xref(0x401170, "CALL", "fmt", "call sym.imp.sprintf")],
    }
    # rax = calloc(...); rbx = rax (alias); rdi = rbx; sprintf(rdi, ...) -> bug.
    fmt_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.calloc"),       # rax = heap buffer
        Instruction(0x401155, "mov rbx, rax"),              # alias propagation
        Instruction(0x401160, "mov rdi, rbx"),              # dest = heap buffer
        Instruction(0x401168, "lea rsi, str.fmt"),
        Instruction(0x401170, "call sym.imp.sprintf"),      # unbounded format → bug
        Instruction(0x401175, "leave"),
        Instruction(0x401176, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: fmt_ops})


def malloc_strncpy_bounded_session() -> FakeR2Session:
    """malloc() result handed to strncpy (bounded) — must NOT flag (CWE-120 land)."""
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="strncpy", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401150, "CALL", "build", "call sym.imp.malloc")],
        0x401050: [Xref(0x401160, "CALL", "build", "call sym.imp.strncpy")],
    }
    build_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.malloc"),
        Instruction(0x401155, "mov rdi, rax"),              # dest = heap buffer
        Instruction(0x40115a, "mov edx, 0x10"),             # explicit length
        Instruction(0x401160, "call sym.imp.strncpy"),      # bounded → not flagged
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: build_ops})


def malloc_reassigned_before_copy_session() -> FakeR2Session:
    """malloc() result clobbered in rdi before strcpy — dest is a different buffer."""
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="strcpy", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401150, "CALL", "build", "call sym.imp.malloc")],
        0x401050: [Xref(0x401168, "CALL", "build", "call sym.imp.strcpy")],
    }
    # rax = malloc(...); ... ; rdi = [rbp-0x20] (a *different*, stack dest);
    # strcpy(rdi, src). The heap alias never reaches the copy destination.
    build_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.malloc"),       # rax = heap buffer
        Instruction(0x401155, "mov qword [rbp - 0x8], rax"),  # heap ptr stored away
        Instruction(0x40115d, "lea rdi, [rbp - 0x20]"),     # dest = stack buffer
        Instruction(0x401162, "lea rsi, str.user_input"),
        Instruction(0x401168, "call sym.imp.strcpy"),       # dest is NOT the heap ptr
        Instruction(0x40116d, "leave"),
        Instruction(0x40116e, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: build_ops})


def malloc_no_copy_session() -> FakeR2Session:
    """malloc() result used but never fed to a copy — nothing to flag."""
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "alloc_only", "call sym.imp.malloc")]}
    alloc_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.malloc"),
        Instruction(0x401155, "mov qword [rbp - 0x8], rax"),  # just stored
        Instruction(0x40115d, "leave"),
        Instruction(0x40115e, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: alloc_ops})


def cwe122_no_allocator_imports_session() -> FakeR2Session:
    """A session with no heap-allocator imports — nothing to flag."""
    imports = [
        Import(name="strcpy", plt=0x401030),
        Import(name="puts", plt=0x401040),
    ]
    return FakeR2Session(imports, xrefs={})


def arm64_malloc_strcpy_heap_overflow_vuln_session() -> FakeR2Session:
    """AArch64: malloc() result (x0) handed to strcpy destination (x0) — vulnerable."""
    imports = [
        Import(name="malloc", plt=0x710),
        Import(name="strcpy", plt=0x720),
    ]
    xrefs = {
        0x710: [Xref(0x83c, "CALL", "build", "bl sym.imp.malloc")],
        0x720: [Xref(0x84c, "CALL", "build", "bl sym.imp.strcpy")],
    }
    # x0 = malloc(16); x0 stays the destination of strcpy (arg0) -> heap overflow.
    build_ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x838, "mov w0, 0x10"),
        Instruction(0x83c, "bl sym.imp.malloc"),            # x0 = heap buffer
        Instruction(0x840, "adrp x1, str.user_input"),
        Instruction(0x844, "add x1, x1, str.user_input"),   # x1 = source
        Instruction(0x84c, "bl sym.imp.strcpy"),            # dest x0 = heap → bug
        Instruction(0x850, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x854, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: build_ops}, arch="arm64")


def arm64_malloc_strncpy_bounded_session() -> FakeR2Session:
    """AArch64: malloc() result handed to strncpy (bounded) — must NOT flag."""
    imports = [
        Import(name="malloc", plt=0x710),
        Import(name="strncpy", plt=0x720),
    ]
    xrefs = {
        0x710: [Xref(0x83c, "CALL", "build", "bl sym.imp.malloc")],
        0x720: [Xref(0x848, "CALL", "build", "bl sym.imp.strncpy")],
    }
    build_ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x838, "mov w0, 0x10"),
        Instruction(0x83c, "bl sym.imp.malloc"),            # x0 = heap buffer
        Instruction(0x840, "mov w2, 0x10"),                 # explicit length
        Instruction(0x848, "bl sym.imp.strncpy"),           # bounded → not flagged
        Instruction(0x84c, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x850, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: build_ops}, arch="arm64")


# --- CWE-401 memory-leak fixtures ------------------------------------------
#
# Pattern: an allocator (malloc/calloc/strdup/...) returns a heap buffer in rax
# (x0 on AArch64). A vulnerable case overwrites the ONLY register alias of that
# pointer with an unrelated value before it is ever freed, stored to memory, or
# returned — the sole handle is lost, so the buffer can never be freed (leak).
# Safe cases free the pointer, store it away (escape), return it (caller owns
# it), or pass it to another call (ownership ambiguous).


def malloc_clobbered_leak_vuln_session() -> FakeR2Session:
    """malloc() result clobbered in rax by a fresh value, unfreed (vulnerable)."""
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "leaky", "call sym.imp.malloc")]}
    # rax = malloc(16); ...; rax = 0  -> the only handle is overwritten, no free.
    leaky_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov edi, 0x10"),
        Instruction(0x401150, "call sym.imp.malloc"),       # rax = heap buffer
        Instruction(0x401155, "mov eax, 0"),                # clobber sole handle
        Instruction(0x40115a, "leave"),
        Instruction(0x40115b, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: leaky_ops})


def strdup_clobbered_leak_vuln_session() -> FakeR2Session:
    """strdup() result aliased to rbx, then rbx reloaded from memory (leak).

    Exercises alias propagation: rbx = rax, then rax reloaded (still aliased via
    rbx), then rbx clobbered too → last handle lost, unfreed."""
    imports = [Import(name="strdup", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "dup_it", "call sym.imp.strdup")]}
    dup_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.strdup"),       # rax = heap buffer
        Instruction(0x401155, "mov rbx, rax"),              # alias: rbx = ptr
        Instruction(0x401158, "mov rax, qword [rbp - 0x8]"),  # rax clobbered (rbx alive)
        Instruction(0x40115c, "mov rbx, qword [rbp - 0x10]"),  # last handle lost
        Instruction(0x401160, "leave"),
        Instruction(0x401161, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: dup_ops})


def malloc_freed_session() -> FakeR2Session:
    """malloc() result freed before being lost — must NOT flag."""
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="free", plt=0x401050),
    ]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "ok", "call sym.imp.malloc")]}
    ok_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.malloc"),       # rax = heap buffer
        Instruction(0x401155, "mov rdi, rax"),              # arg0 = ptr
        Instruction(0x401158, "call sym.imp.free"),         # released → no leak
        Instruction(0x40115d, "mov eax, 0"),
        Instruction(0x401162, "leave"),
        Instruction(0x401163, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ok_ops})


def malloc_stored_escapes_leak_session() -> FakeR2Session:
    """malloc() result stored to the stack (escapes) — conservatively NOT flagged."""
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "store_it", "call sym.imp.malloc")]}
    store_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.malloc"),       # rax = heap buffer
        Instruction(0x401155, "mov qword [rbp - 0x8], rax"),  # escapes our view
        Instruction(0x40115d, "mov eax, 0"),
        Instruction(0x401162, "leave"),
        Instruction(0x401163, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: store_ops})


def malloc_returned_session() -> FakeR2Session:
    """malloc() result left in rax at ret (returned to caller) — must NOT flag."""
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "make", "call sym.imp.malloc")]}
    make_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.malloc"),       # rax = heap buffer
        Instruction(0x401155, "leave"),
        Instruction(0x401156, "ret"),                       # ptr returned in rax
    ]
    return FakeR2Session(imports, xrefs, {0x401136: make_ops})


def malloc_passed_to_call_session() -> FakeR2Session:
    """malloc() result passed to another call (ownership ambiguous) — NOT flagged."""
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="init_obj", plt=0x401050),
    ]
    xrefs = {0x401040: [Xref(0x401150, "CALL", "build", "call sym.imp.malloc")]}
    build_ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.malloc"),       # rax = heap buffer
        Instruction(0x401155, "mov rdi, rax"),              # arg0 = ptr
        Instruction(0x401158, "call sym.imp.init_obj"),     # callee may take ownership
        Instruction(0x40115d, "mov eax, 0"),
        Instruction(0x401162, "leave"),
        Instruction(0x401163, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: build_ops})


def cwe401_no_allocator_imports_session() -> FakeR2Session:
    """A session with no heap-allocator imports — nothing to flag."""
    imports = [
        Import(name="free", plt=0x401030),
        Import(name="puts", plt=0x401040),
    ]
    return FakeR2Session(imports, xrefs={})


def arm64_malloc_clobbered_leak_vuln_session() -> FakeR2Session:
    """AArch64: malloc() result (x0) clobbered by `mov w0, 0`, unfreed (leak)."""
    imports = [Import(name="malloc", plt=0x710)]
    xrefs = {0x710: [Xref(0x83c, "CALL", "leaky", "bl sym.imp.malloc")]}
    leaky_ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x10]!"),
        Instruction(0x838, "mov w0, 0x10"),
        Instruction(0x83c, "bl sym.imp.malloc"),            # x0 = heap buffer
        Instruction(0x840, "mov w0, 0"),                    # clobber sole handle
        Instruction(0x844, "ldp x29, x30, [sp], 0x10"),
        Instruction(0x848, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: leaky_ops}, arch="arm64")


def arm64_malloc_freed_session() -> FakeR2Session:
    """AArch64: malloc() result (x0) freed before being lost — must NOT flag."""
    imports = [
        Import(name="malloc", plt=0x710),
        Import(name="free", plt=0x720),
    ]
    xrefs = {0x710: [Xref(0x83c, "CALL", "ok", "bl sym.imp.malloc")]}
    ok_ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x10]!"),
        Instruction(0x838, "mov w0, 0x10"),
        Instruction(0x83c, "bl sym.imp.malloc"),            # x0 = heap buffer
        Instruction(0x840, "bl sym.imp.free"),              # x0 still ptr → released
        Instruction(0x844, "mov w0, 0"),
        Instruction(0x848, "ldp x29, x30, [sp], 0x10"),
        Instruction(0x84c, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ok_ops}, arch="arm64")


def cwe798_all_session() -> FakeR2Session:
    """A mix of every CWE-798 signal in one binary, plus benign neighbours."""
    return _strings_session(
        [
            Str(vaddr=0x402010, string="password=SuperSecret123", section=".rodata"),
            Str(
                vaddr=0x402030,
                string="api_key=AKIAIOSFODNN7EXAMPLE0KEY",
                section=".rodata",
            ),
            Str(
                vaddr=0x403000,
                string="-----BEGIN EC PRIVATE KEY-----",
                section=".rodata",
            ),
            Str(
                vaddr=0x402050,
                string="postgres://admin:s3cr3tDBpass@10.0.0.5/prod",
                section=".rodata",
            ),
            # benign neighbours — must not fire
            Str(vaddr=0x402100, string="Usage: %s [options]", section=".rodata"),
            Str(vaddr=0x402108, string="password=%s\n", section=".rodata"),
            Str(vaddr=0x402110, string="username=guest", section=".rodata"),
        ]
    )


# --- CWE-197 (Numeric Truncation Error) fixtures ---------------------------
#
# These exercise the PLT-anchored, single-function forward scan: a libc routine
# whose return type is wider than ``int`` (size_t/ssize_t/long) returns a 64-bit
# value in the return register (rax on x86_64, x0 on AArch64), and the program's
# first use of that value either truncates it (stores/moves the narrow
# sub-register) or keeps it whole (full-width use / re-extension).

def cwe197_strlen_truncated_session() -> FakeR2Session:
    """x86_64: `int n = strlen(s);` — strlen's size_t result (rax) stored as the
    32-bit eax into a dword stack slot (truncation)."""
    imports = [Import(name="strlen", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401152, "CALL", "process", "call sym.imp.strlen")]}
    ops = [
        Instruction(0x401140, "push rbp"),
        Instruction(0x401148, "mov rdi, qword [rbp - 0x18]"),  # the string
        Instruction(0x401152, "call sym.imp.strlen"),          # rax = size_t len
        Instruction(0x401157, "mov dword [rbp - 0x4], eax"),   # int n = (truncate)
        Instruction(0x40115a, "leave"),
        Instruction(0x40115b, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401140: ops})


def cwe197_read_truncated_session() -> FakeR2Session:
    """x86_64: `int n = read(fd, buf, len);` — read's ssize_t result truncated
    into a dword slot."""
    imports = [Import(name="read", plt=0x401050)]
    xrefs = {0x401050: [Xref(0x401210, "CALL", "recv_loop", "call sym.imp.read")]}
    ops = [
        Instruction(0x401200, "push rbp"),
        Instruction(0x401208, "mov edx, dword [rbp - 0x8]"),
        Instruction(0x401210, "call sym.imp.read"),            # rax = ssize_t
        Instruction(0x401215, "mov dword [rbp - 0xc], eax"),   # int n = (truncate)
        Instruction(0x401218, "leave"),
        Instruction(0x401219, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401200: ops})


def cwe197_word_store_truncated_session() -> FakeR2Session:
    """x86_64: strtoul's unsigned long result stored as a 16-bit word (severe
    truncation into a `short`/`uint16_t`)."""
    imports = [Import(name="strtoul", plt=0x401060)]
    xrefs = {0x401060: [Xref(0x401320, "CALL", "parse", "call sym.imp.strtoul")]}
    ops = [
        Instruction(0x401300, "push rbp"),
        Instruction(0x401318, "mov rdi, qword [rbp - 0x18]"),
        Instruction(0x401320, "call sym.imp.strtoul"),         # rax = unsigned long
        Instruction(0x401326, "mov word [rbp - 0x2], ax"),     # uint16_t = (truncate)
        Instruction(0x40132a, "leave"),
        Instruction(0x40132b, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401300: ops})


def cwe197_fullwidth_safe_session() -> FakeR2Session:
    """x86_64: strlen's result kept at full width (`mov qword [..], rax`, then a
    64-bit compare) — no truncation, must NOT fire."""
    imports = [Import(name="strlen", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401152, "CALL", "process", "call sym.imp.strlen")]}
    ops = [
        Instruction(0x401140, "push rbp"),
        Instruction(0x401152, "call sym.imp.strlen"),
        Instruction(0x401157, "mov qword [rbp - 0x8], rax"),   # size_t kept (64-bit)
        Instruction(0x40115b, "cmp rax, 0x10"),                # full-width compare
        Instruction(0x40115f, "leave"),
        Instruction(0x401160, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401140: ops})


def cwe197_reextended_safe_session() -> FakeR2Session:
    """x86_64: read's result narrowed to eax but immediately sign-extended back
    (`cdqe` / `movsxd`) — the magnitude is preserved, must NOT fire."""
    imports = [Import(name="read", plt=0x401050)]
    xrefs = {0x401050: [Xref(0x401210, "CALL", "recv_loop", "call sym.imp.read")]}
    ops = [
        Instruction(0x401200, "push rbp"),
        Instruction(0x401210, "call sym.imp.read"),
        Instruction(0x401215, "cdqe"),                          # re-extend eax->rax
        Instruction(0x401217, "mov qword [rbp - 0x8], rax"),
        Instruction(0x40121b, "leave"),
        Instruction(0x40121c, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401200: ops})


def cwe197_movsxd_reextended_safe_session() -> FakeR2Session:
    """x86_64: strtol's result re-extended via `movsxd rbx, eax` — preserved."""
    imports = [Import(name="strtol", plt=0x401070)]
    xrefs = {0x401070: [Xref(0x401410, "CALL", "parse", "call sym.imp.strtol")]}
    ops = [
        Instruction(0x401400, "push rbp"),
        Instruction(0x401410, "call sym.imp.strtol"),
        Instruction(0x401415, "movsxd rbx, eax"),               # re-extend
        Instruction(0x401418, "mov qword [rbp - 0x8], rbx"),
        Instruction(0x40141c, "leave"),
        Instruction(0x40141d, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401400: ops})


def cwe197_no_wide_returner_session() -> FakeR2Session:
    """x86_64: a narrowing store, but the source call is `atoi` (returns int) —
    not a wide-return routine, so there is nothing to truncate. Must NOT fire."""
    imports = [Import(name="atoi", plt=0x401080)]
    xrefs = {0x401080: [Xref(0x401510, "CALL", "parse", "call sym.imp.atoi")]}
    ops = [
        Instruction(0x401500, "push rbp"),
        Instruction(0x401510, "call sym.imp.atoi"),             # int, not wide
        Instruction(0x401515, "mov dword [rbp - 0x4], eax"),    # storing an int as int
        Instruction(0x401519, "leave"),
        Instruction(0x40151a, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401500: ops})


def cwe197_arm64_truncated_session() -> FakeR2Session:
    """AArch64: `int n = strlen(s);` — strlen's x0 result stored as the 32-bit w0
    into a stack slot (truncation)."""
    imports = [Import(name="strlen", plt=0x710)]
    xrefs = {0x710: [Xref(0x848, "CALL", "process", "bl sym.imp.strlen")]}
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x840, "ldr x0, [x29, 0x18]"),
        Instruction(0x848, "bl sym.imp.strlen"),               # x0 = size_t len
        Instruction(0x84c, "str w0, [x29, 0x4]"),              # int n = (truncate w0)
        Instruction(0x850, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x854, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def cwe197_arm64_fullwidth_safe_session() -> FakeR2Session:
    """AArch64: strlen's x0 result stored at full width (`str x0, [..]`) — no
    truncation, must NOT fire."""
    imports = [Import(name="strlen", plt=0x710)]
    xrefs = {0x710: [Xref(0x848, "CALL", "process", "bl sym.imp.strlen")]}
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x848, "bl sym.imp.strlen"),
        Instruction(0x84c, "str x0, [x29, 0x8]"),              # 64-bit store
        Instruction(0x850, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x854, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def cwe197_multi_call_session() -> FakeR2Session:
    """Two wide-return call sites in two functions: one truncates (flag), one
    keeps full width (skip)."""
    vuln_imports = Import(name="strlen", plt=0x401040)
    safe_imports = Import(name="read", plt=0x401050)
    xrefs = {
        0x401040: [Xref(0x401152, "CALL", "trunc_fn", "call sym.imp.strlen")],
        0x401050: [Xref(0x401252, "CALL", "safe_fn", "call sym.imp.read")],
    }
    trunc_ops = [
        Instruction(0x401152, "call sym.imp.strlen"),
        Instruction(0x401157, "mov dword [rbp - 0x4], eax"),   # truncate → flag
        Instruction(0x40115b, "ret"),
    ]
    safe_ops = [
        Instruction(0x401252, "call sym.imp.read"),
        Instruction(0x401257, "mov qword [rbp - 0x8], rax"),   # full width → skip
        Instruction(0x40125b, "ret"),
    ]
    return FakeR2Session(
        imports=[vuln_imports, safe_imports],
        xrefs=xrefs,
        functions={0x401152: trunc_ops, 0x401252: safe_ops},
    )


# --- CWE-732 incorrect-permission-assignment fixtures ----------------------
#
# Pattern: a chmod/fchmod/mkdir/creat/fchmodat/mkdirat call where the *constant*
# mode operand grants world-writable permissions. The detector inspects the
# instruction that last writes the mode-arg register before the call and parses
# its immediate. Per-architecture register naming is resolved via
# :mod:`blight.detectors._argregs`.

def cwe732_chmod_world_writable_vuln_session() -> FakeR2Session:
    """x86_64: chmod(path, 0o777) — 0o777 = 0x1ff, world-writable (vulnerable)."""
    imports = [Import(name="chmod", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "open_world", "call sym.imp.chmod")]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "lea rdi, str.tmp_file"),     # path = arg0
        Instruction(0x401148, "mov esi, 0x1ff"),            # mode = 0o777
        Instruction(0x401160, "call sym.imp.chmod"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe732_fchmod_world_writable_vuln_session() -> FakeR2Session:
    """x86_64: fchmod(fd, 0o666) — 0o666 = 0x1b6, world-writable (vulnerable)."""
    imports = [Import(name="fchmod", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "open_fd", "call sym.imp.fchmod")]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov edi, 0x3"),              # fd = 3
        Instruction(0x401148, "mov esi, 0x1b6"),            # mode = 0o666
        Instruction(0x401160, "call sym.imp.fchmod"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe732_chmod_setuid_vuln_session() -> FakeR2Session:
    """x86_64: chmod(path, 0o4777) — setuid + world-writable (HIGH severity)."""
    imports = [Import(name="chmod", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "ship_helper", "call sym.imp.chmod")]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "lea rdi, str.helper"),
        Instruction(0x401148, "mov esi, 0x9ff"),            # 0o4777 = 0x9ff
        Instruction(0x401160, "call sym.imp.chmod"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe732_chmod_safe_mode_session() -> FakeR2Session:
    """x86_64: chmod(path, 0o644) — typical safe mode (must NOT fire)."""
    imports = [Import(name="chmod", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "ship_doc", "call sym.imp.chmod")]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "lea rdi, str.config"),
        Instruction(0x401148, "mov esi, 0x1a4"),            # 0o644 = 0x1a4
        Instruction(0x401160, "call sym.imp.chmod"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe732_mkdir_world_writable_vuln_session() -> FakeR2Session:
    """x86_64: mkdir(path, 0o777) — world-writable directory (vulnerable)."""
    imports = [Import(name="mkdir", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "make_tmp", "call sym.imp.mkdir")]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "lea rdi, str.tmpdir"),
        Instruction(0x401148, "mov esi, 0x1ff"),            # 0o777
        Instruction(0x401160, "call sym.imp.mkdir"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe732_creat_world_writable_vuln_session() -> FakeR2Session:
    """x86_64: creat(path, 0o666) — newly created file is world-writable."""
    imports = [Import(name="creat", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "spool", "call sym.imp.creat")]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "lea rdi, str.spoolfile"),
        Instruction(0x401148, "mov esi, 0x1b6"),            # 0o666
        Instruction(0x401160, "call sym.imp.creat"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe732_fchmodat_world_writable_vuln_session() -> FakeR2Session:
    """x86_64: fchmodat(dirfd, path, 0o777, 0) — mode at arg2 (rdx)."""
    imports = [Import(name="fchmodat", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "loosen", "call sym.imp.fchmodat")]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov edi, 0xffffff9c"),        # AT_FDCWD
        Instruction(0x401145, "lea rsi, str.target"),
        Instruction(0x40114c, "mov edx, 0x1ff"),             # mode arg2 = 0o777
        Instruction(0x401152, "xor ecx, ecx"),               # flags = 0
        Instruction(0x401160, "call sym.imp.fchmodat"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe732_mkdirat_world_writable_vuln_session() -> FakeR2Session:
    """x86_64: mkdirat(dirfd, path, 0o777) — mode at arg2 (rdx)."""
    imports = [Import(name="mkdirat", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "build_tree", "call sym.imp.mkdirat")]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "mov edi, 0xffffff9c"),
        Instruction(0x401145, "lea rsi, str.subdir"),
        Instruction(0x40114c, "mov edx, 0x1ff"),
        Instruction(0x401160, "call sym.imp.mkdirat"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe732_chmod_nonconstant_session() -> FakeR2Session:
    """x86_64: chmod(path, mode_from_var) — mode is a register move, not a
    bare immediate. The detector is precision-first and must NOT flag.
    """
    imports = [Import(name="chmod", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "apply_mode", "call sym.imp.chmod")]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "lea rdi, str.target"),
        Instruction(0x401148, "mov esi, eax"),               # mode from a var
        Instruction(0x401160, "call sym.imp.chmod"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe732_mkdir_safe_mode_session() -> FakeR2Session:
    """x86_64: mkdir(path, 0o755) — typical safe directory mode (must NOT fire)."""
    imports = [Import(name="mkdir", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "make_cfgdir", "call sym.imp.mkdir")]
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "lea rdi, str.cfg_dir"),
        Instruction(0x401148, "mov esi, 0x1ed"),            # 0o755 = 0x1ed
        Instruction(0x401160, "call sym.imp.mkdir"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe732_clean_session() -> FakeR2Session:
    """No permission-setting imports — nothing for CWE-732 to anchor on."""
    imports = [
        Import(name="puts", plt=0x401030),
        Import(name="strlen", plt=0x401040),
    ]
    return FakeR2Session(imports, xrefs={})


def cwe732_arm64_chmod_world_writable_vuln_session() -> FakeR2Session:
    """AArch64: chmod(path, 0o777) — mode in w1, immediate via `mov w1, 0x1ff`."""
    imports = [Import(name="chmod", plt=0x710)]
    xrefs = {0x710: [Xref(0x840, "CALL", "open_world", "bl sym.imp.chmod")]}
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x834, "adrp x0, 0x1000"),               # path arg0
        Instruction(0x838, "add x0, x0, 0x10"),
        Instruction(0x83c, "mov w1, 0x1ff"),                 # mode = 0o777
        Instruction(0x840, "bl sym.imp.chmod"),
        Instruction(0x844, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x848, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def cwe732_arm64_chmod_safe_mode_session() -> FakeR2Session:
    """AArch64: chmod(path, 0o644) — safe mode (must NOT fire)."""
    imports = [Import(name="chmod", plt=0x710)]
    xrefs = {0x710: [Xref(0x840, "CALL", "ship_doc", "bl sym.imp.chmod")]}
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x834, "adrp x0, 0x1000"),
        Instruction(0x838, "add x0, x0, 0x20"),
        Instruction(0x83c, "mov w1, 0x1a4"),                 # 0o644
        Instruction(0x840, "bl sym.imp.chmod"),
        Instruction(0x844, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x848, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def cwe732_multi_call_session() -> FakeR2Session:
    """Two chmod sites: one world-writable (flag), one 0o644 (skip)."""
    imports = [Import(name="chmod", plt=0x401040)]
    xrefs = {
        0x401040: [
            Xref(0x401160, "CALL", "vuln_chmod", "call sym.imp.chmod"),
            Xref(0x401260, "CALL", "safe_chmod", "call sym.imp.chmod"),
        ]
    }
    vuln_ops = [
        Instruction(0x401140, "lea rdi, str.world_file"),
        Instruction(0x401148, "mov esi, 0x1ff"),             # 0o777 → flag
        Instruction(0x401160, "call sym.imp.chmod"),
        Instruction(0x401165, "ret"),
    ]
    safe_ops = [
        Instruction(0x401240, "lea rdi, str.safe_file"),
        Instruction(0x401248, "mov esi, 0x1a4"),             # 0o644 → skip
        Instruction(0x401260, "call sym.imp.chmod"),
        Instruction(0x401265, "ret"),
    ]
    return FakeR2Session(
        imports, xrefs, {0x401140: vuln_ops, 0x401240: safe_ops}
    )


# --- CWE-330 predictable-PRNG-seeding fixtures -----------------------------
#
# Pattern: a seeding routine (srand / srandom / srand48 / seed48) is called with
# a seed that is either (a) the return value of a publicly observable clock /
# pid source (HIGH — predictable seed) or (b) a small constant immediate
# (MEDIUM — same-seed mistake). Both forms are precision-first: the evidence
# is read literally out of the disassembly.

def cwe330_srand_time_vuln_session() -> FakeR2Session:
    """x86_64: srand(time(NULL)) — return of time() flows into edi (HIGH)."""
    imports = [
        Import(name="srand", plt=0x401040),
        Import(name="time", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401168, "CALL", "seed_prng", "call sym.imp.srand")],
        0x401050: [Xref(0x401150, "CALL", "seed_prng", "call sym.imp.time")],
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401140, "xor edi, edi"),              # time(NULL)
        Instruction(0x401150, "call sym.imp.time"),
        Instruction(0x401155, "mov edi, eax"),              # seed reg ← return
        Instruction(0x401168, "call sym.imp.srand"),
        Instruction(0x40116d, "leave"),
        Instruction(0x40116e, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe330_srand_getpid_vuln_session() -> FakeR2Session:
    """x86_64: srand(getpid()) — pid is a predictable seed (HIGH)."""
    imports = [
        Import(name="srand", plt=0x401040),
        Import(name="getpid", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401168, "CALL", "seed_prng", "call sym.imp.srand")],
        0x401050: [Xref(0x401150, "CALL", "seed_prng", "call sym.imp.getpid")],
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.getpid"),
        Instruction(0x401155, "mov edi, eax"),              # seed ← return
        Instruction(0x401168, "call sym.imp.srand"),
        Instruction(0x40116d, "leave"),
        Instruction(0x40116e, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe330_srand_constant_zero_session() -> FakeR2Session:
    """x86_64: srand(0) — constant immediate seed (MEDIUM, same-seed mistake)."""
    imports = [Import(name="srand", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "seed_zero", "call sym.imp.srand")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401148, "mov edi, 0"),                # constant seed = 0
        Instruction(0x401160, "call sym.imp.srand"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe330_srand_constant_small_session() -> FakeR2Session:
    """x86_64: srand(42) — small constant immediate seed (MEDIUM)."""
    imports = [Import(name="srand", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "seed_42", "call sym.imp.srand")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401148, "mov edi, 0x2a"),             # seed = 42
        Instruction(0x401160, "call sym.imp.srand"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe330_srand_large_constant_safe_session() -> FakeR2Session:
    """x86_64: srand(0xdeadbeef) — large constant, deliberately NOT flagged.

    A 32-bit literal embedded by the build system is probably a domain knob,
    not a same-seed mistake. The detector is precision-first: only seeds at or
    below 0xff get the MEDIUM tier.
    """
    imports = [Import(name="srand", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "seed_big", "call sym.imp.srand")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401148, "mov edi, 0xdeadbeef"),       # large literal
        Instruction(0x401160, "call sym.imp.srand"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe330_srand_nonconstant_safe_session() -> FakeR2Session:
    """x86_64: srand(seed_from_var) — seed is a register-to-register move from
    a value the detector cannot resolve. Precision-first: do NOT flag.
    """
    imports = [Import(name="srand", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "seed_var", "call sym.imp.srand")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401148, "mov edi, ecx"),              # seed from a var
        Instruction(0x401160, "call sym.imp.srand"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe330_srand_intervening_call_safe_session() -> FakeR2Session:
    """x86_64: time() is called, but an UNRELATED call sits between time() and
    the seed-register write — the seed reg ← eax sequence no longer proves
    time()'s return reached srand. Precision-first: do NOT flag.
    """
    imports = [
        Import(name="srand", plt=0x401040),
        Import(name="time", plt=0x401050),
        Import(name="puts", plt=0x401060),
    ]
    xrefs = {
        0x401040: [Xref(0x401180, "CALL", "noisy_seed", "call sym.imp.srand")],
        0x401050: [Xref(0x401150, "CALL", "noisy_seed", "call sym.imp.time")],
        0x401060: [Xref(0x401168, "CALL", "noisy_seed", "call sym.imp.puts")],
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.time"),
        Instruction(0x401168, "call sym.imp.puts"),         # clobbers eax
        Instruction(0x40116d, "mov edi, eax"),              # eax is now puts()'s return
        Instruction(0x401180, "call sym.imp.srand"),
        Instruction(0x401185, "leave"),
        Instruction(0x401186, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe330_srandom_gettimeofday_vuln_session() -> FakeR2Session:
    """x86_64: srandom(gettimeofday-derived) — covers the srandom alias and the
    gettimeofday predictable source (HIGH).
    """
    imports = [
        Import(name="srandom", plt=0x401040),
        Import(name="gettimeofday", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401168, "CALL", "seed_prng", "call sym.imp.srandom")],
        0x401050: [
            Xref(0x401150, "CALL", "seed_prng", "call sym.imp.gettimeofday")
        ],
    }
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401150, "call sym.imp.gettimeofday"),
        Instruction(0x401155, "mov edi, eax"),
        Instruction(0x401168, "call sym.imp.srandom"),
        Instruction(0x40116d, "leave"),
        Instruction(0x40116e, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe330_srand48_constant_session() -> FakeR2Session:
    """x86_64: srand48(1) — covers the srand48 alias with a constant (MEDIUM)."""
    imports = [Import(name="srand48", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "seed_drand", "call sym.imp.srand48")]}
    ops = [
        Instruction(0x401136, "push rbp"),
        Instruction(0x401148, "mov edi, 1"),                # constant = 1
        Instruction(0x401160, "call sym.imp.srand48"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401136: ops})


def cwe330_clean_session() -> FakeR2Session:
    """No seeding imports — nothing for CWE-330 to anchor on."""
    imports = [
        Import(name="getrandom", plt=0x401030),             # the safe API
        Import(name="puts", plt=0x401040),
    ]
    return FakeR2Session(imports, xrefs={})


def cwe330_arm64_srand_time_vuln_session() -> FakeR2Session:
    """AArch64: srand(time(NULL)) — return of time() flows into w0 (HIGH)."""
    imports = [
        Import(name="srand", plt=0x710),
        Import(name="time", plt=0x720),
    ]
    xrefs = {
        0x710: [Xref(0x850, "CALL", "seed_prng", "bl sym.imp.srand")],
        0x720: [Xref(0x83c, "CALL", "seed_prng", "bl sym.imp.time")],
    }
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x10]!"),
        Instruction(0x838, "mov x0, 0"),                    # time(NULL)
        Instruction(0x83c, "bl sym.imp.time"),
        Instruction(0x840, "mov w0, w0"),                   # seed reg ← return
        Instruction(0x850, "bl sym.imp.srand"),
        Instruction(0x854, "ldp x29, x30, [sp], 0x10"),
        Instruction(0x858, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def cwe330_arm64_srand_constant_session() -> FakeR2Session:
    """AArch64: srand(0) — constant seed in w0 (MEDIUM)."""
    imports = [Import(name="srand", plt=0x710)]
    xrefs = {0x710: [Xref(0x840, "CALL", "seed_zero", "bl sym.imp.srand")]}
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x10]!"),
        Instruction(0x838, "mov w0, 0"),                    # constant seed = 0
        Instruction(0x840, "bl sym.imp.srand"),
        Instruction(0x844, "ldp x29, x30, [sp], 0x10"),
        Instruction(0x848, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def cwe330_arm64_srand_nonconstant_safe_session() -> FakeR2Session:
    """AArch64: srand(reg_from_var) — non-constant, non-return-flow seed.

    Precision-first: do NOT flag.
    """
    imports = [Import(name="srand", plt=0x710)]
    xrefs = {0x710: [Xref(0x840, "CALL", "seed_var", "bl sym.imp.srand")]}
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x10]!"),
        Instruction(0x838, "mov w0, w3"),                   # seed from a var
        Instruction(0x840, "bl sym.imp.srand"),
        Instruction(0x844, "ldp x29, x30, [sp], 0x10"),
        Instruction(0x848, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def cwe330_multi_call_session() -> FakeR2Session:
    """Two srand sites: one predictable (flag), one non-constant (skip)."""
    imports = [
        Import(name="srand", plt=0x401040),
        Import(name="time", plt=0x401050),
    ]
    xrefs = {
        0x401040: [
            Xref(0x401168, "CALL", "predictable_seed", "call sym.imp.srand"),
            Xref(0x401260, "CALL", "runtime_seed", "call sym.imp.srand"),
        ],
        0x401050: [Xref(0x401150, "CALL", "predictable_seed", "call sym.imp.time")],
    }
    vuln_ops = [
        Instruction(0x401140, "xor edi, edi"),
        Instruction(0x401150, "call sym.imp.time"),
        Instruction(0x401155, "mov edi, eax"),
        Instruction(0x401168, "call sym.imp.srand"),
        Instruction(0x40116d, "ret"),
    ]
    safe_ops = [
        Instruction(0x401240, "mov edi, ecx"),              # non-constant → skip
        Instruction(0x401260, "call sym.imp.srand"),
        Instruction(0x401265, "ret"),
    ]
    return FakeR2Session(
        imports, xrefs, {0x401140: vuln_ops, 0x401240: safe_ops}
    )


# --- CWE-131 fixtures (incorrect buffer-size calculation) ------------------
#
# Pattern: ``malloc(strlen(s))`` — forgetting the ``+ 1`` for the NUL
# terminator. The size argument to an allocator traces back via register-alias
# propagation to a strlen-family return, with no intervening ``inc`` / ``add
# ...,1`` adjustment. See ``src/blight/detectors/cwe131.py``.


def cwe131_malloc_strlen_no_plus_one_vuln_session() -> FakeR2Session:
    """x86_64: ``buf = malloc(strlen(src));`` — off-by-one, NUL not allocated."""
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="strlen", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "build_buf", "call sym.imp.malloc")],
        0x401050: [Xref(0x401150, "CALL", "build_buf", "call sym.imp.strlen")],
    }
    ops = [
        Instruction(0x401130, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),    # rdi = src
        Instruction(0x401150, "call sym.imp.strlen"),           # rax = strlen(src)
        Instruction(0x401158, "mov edi, eax"),                  # size arg → rdi
        Instruction(0x401160, "call sym.imp.malloc"),           # ← off-by-one
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401130: ops})


def cwe131_malloc_strlen_plus_one_safe_session() -> FakeR2Session:
    """x86_64: ``buf = malloc(strlen(src) + 1);`` — NUL accounted for, safe."""
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="strlen", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "build_buf", "call sym.imp.malloc")],
        0x401050: [Xref(0x401150, "CALL", "build_buf", "call sym.imp.strlen")],
    }
    ops = [
        Instruction(0x401130, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.strlen"),
        Instruction(0x401155, "add rax, 1"),                    # +1 for NUL
        Instruction(0x401158, "mov edi, eax"),
        Instruction(0x401160, "call sym.imp.malloc"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401130: ops})


def cwe131_malloc_strlen_inc_safe_session() -> FakeR2Session:
    """x86_64: ``inc rax`` after strlen also counts as the +1 adjustment."""
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="strlen", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "build_buf", "call sym.imp.malloc")],
        0x401050: [Xref(0x401150, "CALL", "build_buf", "call sym.imp.strlen")],
    }
    ops = [
        Instruction(0x401130, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.strlen"),
        Instruction(0x401155, "inc rax"),                       # +1 via inc
        Instruction(0x401158, "mov edi, eax"),
        Instruction(0x401160, "call sym.imp.malloc"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401130: ops})


def cwe131_realloc_strlen_no_plus_one_vuln_session() -> FakeR2Session:
    """x86_64: ``realloc(buf, strlen(s));`` — realloc carries size in arg1 (rsi)."""
    imports = [
        Import(name="realloc", plt=0x401040),
        Import(name="strlen", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401210, "CALL", "grow_buf", "call sym.imp.realloc")],
        0x401050: [Xref(0x401200, "CALL", "grow_buf", "call sym.imp.strlen")],
    }
    ops = [
        Instruction(0x4011f0, "push rbp"),
        Instruction(0x4011f8, "mov rdi, qword [rbp - 0x10]"),   # rdi = s
        Instruction(0x401200, "call sym.imp.strlen"),
        Instruction(0x401204, "mov esi, eax"),                  # size arg (arg1)
        Instruction(0x401208, "mov rdi, qword [rbp - 0x8]"),    # buf
        Instruction(0x401210, "call sym.imp.realloc"),
        Instruction(0x401215, "leave"),
        Instruction(0x401216, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x4011f0: ops})


def cwe131_calloc_strlen_no_plus_one_vuln_session() -> FakeR2Session:
    """x86_64: ``calloc(1, strlen(s));`` — calloc's per-element size in arg1."""
    imports = [
        Import(name="calloc", plt=0x401040),
        Import(name="strlen", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401210, "CALL", "zero_buf", "call sym.imp.calloc")],
        0x401050: [Xref(0x401200, "CALL", "zero_buf", "call sym.imp.strlen")],
    }
    ops = [
        Instruction(0x4011f0, "push rbp"),
        Instruction(0x4011f8, "mov rdi, qword [rbp - 0x10]"),
        Instruction(0x401200, "call sym.imp.strlen"),
        Instruction(0x401204, "mov esi, eax"),                  # per-elt size
        Instruction(0x401208, "mov edi, 1"),                    # nmemb = 1
        Instruction(0x401210, "call sym.imp.calloc"),
        Instruction(0x401215, "leave"),
        Instruction(0x401216, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x4011f0: ops})


def cwe131_aliased_strlen_vuln_session() -> FakeR2Session:
    """x86_64: ``size = strlen(s); ptr = malloc(size);`` via register aliases.

    strlen → rax; rbx = rax (alias); rdi = rbx (size arg) → off-by-one.
    """
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="strlen", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "alias_alloc", "call sym.imp.malloc")],
        0x401050: [Xref(0x401150, "CALL", "alias_alloc", "call sym.imp.strlen")],
    }
    ops = [
        Instruction(0x401130, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.strlen"),
        Instruction(0x401154, "mov rbx, rax"),                  # alias
        Instruction(0x401158, "mov rdi, rbx"),                  # size arg
        Instruction(0x401160, "call sym.imp.malloc"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401130: ops})


def cwe131_malloc_constant_size_session() -> FakeR2Session:
    """x86_64: ``malloc(0x40);`` — constant size, no strlen → safe."""
    imports = [Import(name="malloc", plt=0x401040)]
    xrefs = {0x401040: [Xref(0x401160, "CALL", "fixed_alloc", "call sym.imp.malloc")]}
    ops = [
        Instruction(0x401130, "push rbp"),
        Instruction(0x401150, "mov edi, 0x40"),
        Instruction(0x401160, "call sym.imp.malloc"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401130: ops})


def cwe131_size_reloaded_safe_session() -> FakeR2Session:
    """x86_64: strlen was called, but the size is reloaded from memory after.

    The value reaching malloc is the fresh memory reload — not the strlen
    return — so the size cannot be off-by-one from strlen → safe.
    """
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="strlen", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "reload_alloc", "call sym.imp.malloc")],
        0x401050: [Xref(0x401150, "CALL", "reload_alloc", "call sym.imp.strlen")],
    }
    ops = [
        Instruction(0x401130, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.strlen"),
        Instruction(0x401155, "mov edi, dword [rbp - 0x20]"),   # fresh reload
        Instruction(0x401160, "call sym.imp.malloc"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401130: ops})


def cwe131_intervening_call_safe_session() -> FakeR2Session:
    """x86_64: a non-strlen call clobbers rax between strlen and the size
    register's final write — the value reaching malloc came from the clobbered
    rax, so it cannot be proven to be strlen's result → safe (conservative).
    """
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="strlen", plt=0x401050),
        Import(name="puts", plt=0x401060),
    ]
    xrefs = {
        0x401040: [Xref(0x401170, "CALL", "noisy_alloc", "call sym.imp.malloc")],
        0x401050: [Xref(0x401150, "CALL", "noisy_alloc", "call sym.imp.strlen")],
        0x401060: [Xref(0x401158, "CALL", "noisy_alloc", "call sym.imp.puts")],
    }
    ops = [
        Instruction(0x401130, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.strlen"),           # rax = len
        Instruction(0x401158, "call sym.imp.puts"),             # clobbers rax!
        Instruction(0x401165, "mov edi, eax"),                  # size from clobbered rax
        Instruction(0x401170, "call sym.imp.malloc"),
        Instruction(0x401175, "leave"),
        Instruction(0x401176, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401130: ops})


def cwe131_no_strlen_import_session() -> FakeR2Session:
    """No strlen-family import — nothing for CWE-131 to anchor on."""
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="puts", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "alloc_fixed", "call sym.imp.malloc")],
    }
    ops = [
        Instruction(0x401130, "push rbp"),
        Instruction(0x401150, "mov edi, 0x80"),
        Instruction(0x401160, "call sym.imp.malloc"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401130: ops})


def cwe131_arm64_malloc_strlen_no_plus_one_vuln_session() -> FakeR2Session:
    """AArch64: ``malloc(strlen(s));`` — size in x0 traces back to strlen's x0."""
    imports = [
        Import(name="malloc", plt=0x710),
        Import(name="strlen", plt=0x720),
    ]
    xrefs = {
        0x710: [Xref(0x848, "CALL", "build_buf", "bl sym.imp.malloc")],
        0x720: [Xref(0x83c, "CALL", "build_buf", "bl sym.imp.strlen")],
    }
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x834, "ldr x0, [x29, 0x8]"),               # x0 = src
        Instruction(0x83c, "bl sym.imp.strlen"),                # x0 = strlen(src)
        Instruction(0x848, "bl sym.imp.malloc"),                # ← off-by-one
        Instruction(0x84c, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x850, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def cwe131_arm64_malloc_strlen_plus_one_safe_session() -> FakeR2Session:
    """AArch64: ``malloc(strlen(s) + 1);`` — +1 via ``add x0, x0, #1`` → safe."""
    imports = [
        Import(name="malloc", plt=0x710),
        Import(name="strlen", plt=0x720),
    ]
    xrefs = {
        0x710: [Xref(0x848, "CALL", "build_buf", "bl sym.imp.malloc")],
        0x720: [Xref(0x83c, "CALL", "build_buf", "bl sym.imp.strlen")],
    }
    ops = [
        Instruction(0x830, "stp x29, x30, [sp, -0x20]!"),
        Instruction(0x834, "ldr x0, [x29, 0x8]"),
        Instruction(0x83c, "bl sym.imp.strlen"),
        Instruction(0x840, "add x0, x0, 1"),                    # +1 for NUL
        Instruction(0x848, "bl sym.imp.malloc"),
        Instruction(0x84c, "ldp x29, x30, [sp], 0x20"),
        Instruction(0x850, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x830: ops}, arch="arm64")


def cwe131_multi_call_session() -> FakeR2Session:
    """Two malloc sites: one sized by an unadjusted strlen (flag), one constant."""
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="strlen", plt=0x401050),
    ]
    xrefs = {
        0x401040: [
            Xref(0x40113A, "CALL", "vuln_alloc", "call sym.imp.malloc"),
            Xref(0x401234, "CALL", "fixed_alloc", "call sym.imp.malloc"),
        ],
        0x401050: [
            Xref(0x401130, "CALL", "vuln_alloc", "call sym.imp.strlen"),
        ],
    }
    vuln_ops = [
        Instruction(0x401120, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401130, "call sym.imp.strlen"),
        Instruction(0x401135, "mov edi, eax"),
        Instruction(0x40113A, "call sym.imp.malloc"),           # → flag
        Instruction(0x40113F, "ret"),
    ]
    fixed_ops = [
        Instruction(0x401230, "mov edi, 0x20"),                 # constant size
        Instruction(0x401234, "call sym.imp.malloc"),           # → skip
        Instruction(0x401239, "ret"),
    ]
    return FakeR2Session(
        imports, xrefs, {0x401120: vuln_ops, 0x401230: fixed_ops}
    )


def cwe131_wcslen_no_plus_one_vuln_session() -> FakeR2Session:
    """x86_64: ``malloc(wcslen(ws));`` — wide-char variant; same off-by-one."""
    imports = [
        Import(name="malloc", plt=0x401040),
        Import(name="wcslen", plt=0x401050),
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "build_wbuf", "call sym.imp.malloc")],
        0x401050: [Xref(0x401150, "CALL", "build_wbuf", "call sym.imp.wcslen")],
    }
    ops = [
        Instruction(0x401130, "push rbp"),
        Instruction(0x401140, "mov rdi, qword [rbp - 0x8]"),
        Instruction(0x401150, "call sym.imp.wcslen"),
        Instruction(0x401155, "mov edi, eax"),
        Instruction(0x401160, "call sym.imp.malloc"),
        Instruction(0x401165, "leave"),
        Instruction(0x401166, "ret"),
    ]
    return FakeR2Session(imports, xrefs, {0x401130: ops})
# --- CWE-377 insecure-temporary-file fixtures ------------------------------

# Pure PLT-lookup detector (same shape as CWE-22 / CWE-89 / CWE-119 / CWE-295 /
# CWE-327 / CWE-362 / CWE-426 / CWE-676 / CWE-732): the presence of a call to a
# temp-file primitive that is unsafe by construction is itself the finding —
# no argument inspection is needed because the weakness is intrinsic to the
# routine (predictable name + non-atomic creation step).

def tempnam_vuln_session() -> FakeR2Session:
    """A single tempnam() call — HIGH (predictable name → TOCTOU on open)."""
    imports = [Import(name="tempnam", plt=0x401040)]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "build_path", "call sym.imp.tempnam")]
    }
    return FakeR2Session(imports, xrefs)


def tmpnam_r_vuln_session() -> FakeR2Session:
    """A single tmpnam_r() call — HIGH (reentrant sibling of tmpnam, same race)."""
    imports = [Import(name="tmpnam_r", plt=0x401050)]
    xrefs = {
        0x401050: [Xref(0x401172, "CALL", "name_temp", "call sym.imp.tmpnam_r")]
    }
    return FakeR2Session(imports, xrefs)


def tmpfile_vuln_session() -> FakeR2Session:
    """A single tmpfile() call — MEDIUM (libc-internal name fallback)."""
    imports = [Import(name="tmpfile", plt=0x401060)]
    xrefs = {
        0x401060: [Xref(0x401184, "CALL", "open_scratch", "call sym.imp.tmpfile")]
    }
    return FakeR2Session(imports, xrefs)


def tmpfile64_vuln_session() -> FakeR2Session:
    """A single tmpfile64() call — MEDIUM (64-bit sibling of tmpfile)."""
    imports = [Import(name="tmpfile64", plt=0x401070)]
    xrefs = {
        0x401070: [Xref(0x401196, "CALL", "large_scratch", "call sym.imp.tmpfile64")]
    }
    return FakeR2Session(imports, xrefs)


def cwe377_all_session() -> FakeR2Session:
    """All four CWE-377 functions, each called once in a distinct function."""
    imports = [
        Import(name="tempnam", plt=0x401040),
        Import(name="tmpnam_r", plt=0x401050),
        Import(name="tmpfile", plt=0x401060),
        Import(name="tmpfile64", plt=0x401070),
        # Benign neighbours that must NOT be flagged.
        Import(name="mkstemp", plt=0x401080),
        Import(name="mkostemp", plt=0x401090),
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "build_path", "call sym.imp.tempnam")],
        0x401050: [Xref(0x401172, "CALL", "name_temp", "call sym.imp.tmpnam_r")],
        0x401060: [Xref(0x401184, "CALL", "open_scratch", "call sym.imp.tmpfile")],
        0x401070: [Xref(0x401196, "CALL", "large_scratch", "call sym.imp.tmpfile64")],
        0x401080: [Xref(0x4011a8, "CALL", "open_safe", "call sym.imp.mkstemp")],
        0x401090: [Xref(0x4011ba, "CALL", "open_safe2", "call sym.imp.mkostemp")],
    }
    return FakeR2Session(imports, xrefs)


def cwe377_clean_session() -> FakeR2Session:
    """Only the safe replacements imported — nothing for CWE-377 to anchor on."""
    imports = [
        Import(name="mkstemp", plt=0x401040),
        Import(name="mkostemp", plt=0x401050),
        Import(name="mkstemps", plt=0x401060),
        Import(name="mkostemps", plt=0x401070),
        Import(name="mkdtemp", plt=0x401080),
        Import(name="open", plt=0x401090),
    ]
    return FakeR2Session(imports, xrefs={})


def cwe377_does_not_overlap_cwe676_session() -> FakeR2Session:
    """A binary with both tmpnam (CWE-676) and tempnam (CWE-377).

    Confirms the two detectors are complementary and do not double-flag the
    same call site — CWE-377 owns tempnam, CWE-676 owns tmpnam.
    """
    imports = [
        Import(name="tmpnam", plt=0x401040),    # CWE-676 territory
        Import(name="tempnam", plt=0x401050),   # CWE-377 territory
    ]
    xrefs = {
        0x401040: [Xref(0x401160, "CALL", "legacy_name", "call sym.imp.tmpnam")],
        0x401050: [Xref(0x401172, "CALL", "modern_name", "call sym.imp.tempnam")],
    }
    return FakeR2Session(imports, xrefs)
