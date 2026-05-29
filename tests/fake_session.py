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
        arch: str = "x86_64",
    ) -> None:
        self._imports = imports
        self._xrefs = xrefs or {}
        self._functions = functions or {}
        self._arch = arch

    def imports(self) -> list[Import]:
        return list(self._imports)

    def arch(self) -> str:
        return self._arch

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
