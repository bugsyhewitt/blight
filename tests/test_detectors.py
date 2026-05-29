"""Unit tests for blight detectors — fully mocked, no radare2 required."""

from __future__ import annotations

from blight.detectors import (
    cwe78,
    cwe89,
    cwe120,
    cwe134,
    cwe242,
    cwe252,
    cwe295,
    cwe327,
    cwe476,
    cwe676,
)
from tests.fake_session import (
    arm64_malloc_checked_session,
    arm64_malloc_deref_vuln_session,
    arm64_setuid_checked_session,
    arm64_setuid_unchecked_vuln_session,
    asctime_vuln_session,
    blowfish_vuln_session,
    calloc_stored_escapes_session,
    chroot_unchecked_fallthrough_session,
    clean_baseline_session,
    ctime_vuln_session,
    curl_setopt_vuln_session,
    cwe89_all_session,
    cwe89_clean_session,
    cwe252_clean_session,
    cwe295_all_session,
    cwe295_clean_session,
    cwe327_all_session,
    cwe327_clean_session,
    cwe476_no_allocators_session,
    gnutls_verify_peers2_vuln_session,
    mbedtls_authmode_vuln_session,
    ssl_get_peer_cert_vuln_session,
    ssl_set_verify_vuln_session,
    cwe676_all_session,
    cwe676_clean_session,
    des_vuln_session,
    fopen_deref_vuln_session,
    fprintf_fmtstr_vuln_session,
    gets_vuln_session,
    malloc_aliased_checked_session,
    malloc_aliased_deref_vuln_session,
    malloc_checked_session,
    malloc_deref_vuln_session,
    md5_vuln_session,
    mktemp_vuln_session,
    mysql_query_vuln_session,
    pqexec_vuln_session,
    sqlexecdirect_vuln_session,
    sqlite3_exec_vuln_session,
    sqlite3_prepare_v2_session,
    printf_constant_session,
    printf_fmtstr_vuln_session,
    printf_no_dangerous_imports_session,
    rand_vuln_session,
    rc4_vuln_session,
    fclose_unchecked_call_clobber_session,
    setuid_checked_session,
    setuid_unchecked_vuln_session,
    sha1_vuln_session,
    snprintf_fmtstr_vuln_session,
    srand_vuln_session,
    strcpy_vuln_session,
    strtok_vuln_session,
    syslog_fmtstr_vuln_session,
    system_constant_session,
    system_vuln_session,
    tmpnam_vuln_session,
    write_return_saved_session,
)


class TestCwe120:
    def test_flags_strcpy_sprintf_gets(self) -> None:
        findings = cwe120.detect(strcpy_vuln_session())
        symbols = {f.symbol for f in findings}
        assert symbols == {"strcpy", "sprintf", "gets"}
        for f in findings:
            assert f.cwe == 120
            assert f.function
            assert f.address.startswith("0x")
            assert f.evidence

    def test_clean_baseline_no_findings(self) -> None:
        assert cwe120.detect(clean_baseline_session()) == []

    def test_strcpy_finding_has_expected_fields(self) -> None:
        findings = cwe120.detect(strcpy_vuln_session())
        strcpy_finding = next(f for f in findings if f.symbol == "strcpy")
        assert strcpy_finding.cwe == 120
        assert strcpy_finding.function == "copy_it"
        assert strcpy_finding.address == hex(0x40114A)
        assert "strcpy" in strcpy_finding.evidence


class TestCwe242:
    def test_flags_gets(self) -> None:
        findings = cwe242.detect(gets_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 242
        assert f.symbol == "gets"
        assert f.function == "main"
        assert f.address.startswith("0x")
        assert "gets" in f.evidence

    def test_clean_baseline_no_findings(self) -> None:
        assert cwe242.detect(clean_baseline_session()) == []

    def test_does_not_flag_when_no_dangerous_imports(self) -> None:
        # strcpy-vuln does have gets, so it should appear for 242 too.
        findings = cwe242.detect(strcpy_vuln_session())
        assert [f.symbol for f in findings] == ["gets"]


class TestCwe134:
    def test_flags_printf_with_nonconstant_format(self) -> None:
        findings = cwe134.detect(printf_fmtstr_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 134
        assert f.symbol == "printf"
        assert f.function == "log_msg"
        assert f.address == hex(0x401185)
        assert "non-constant" in f.evidence

    def test_does_not_flag_printf_with_constant_format(self) -> None:
        assert cwe134.detect(printf_constant_session()) == []

    def test_flags_fprintf_with_nonconstant_format(self) -> None:
        findings = cwe134.detect(fprintf_fmtstr_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 134
        assert f.symbol == "fprintf"
        assert f.function == "write_log"
        assert f.address == hex(0x4011A0)
        assert "non-constant" in f.evidence

    def test_flags_snprintf_with_nonconstant_format(self) -> None:
        findings = cwe134.detect(snprintf_fmtstr_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 134
        assert f.symbol == "snprintf"
        assert f.function == "build_msg"
        assert "non-constant" in f.evidence

    def test_flags_syslog_with_nonconstant_format(self) -> None:
        findings = cwe134.detect(syslog_fmtstr_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 134
        assert f.symbol == "syslog"
        assert f.function == "audit_event"
        assert "non-constant" in f.evidence

    def test_clean_baseline_no_findings(self) -> None:
        # clean-baseline has snprintf but no xrefs to it — no findings.
        assert cwe134.detect(clean_baseline_session()) == []

    def test_no_dangerous_imports_no_findings(self) -> None:
        assert cwe134.detect(printf_no_dangerous_imports_session()) == []

    def test_finding_has_correct_cwe_id(self) -> None:
        findings = cwe134.detect(printf_fmtstr_vuln_session())
        assert all(f.cwe == 134 for f in findings)

    def test_evidence_mentions_symbol(self) -> None:
        findings = cwe134.detect(printf_fmtstr_vuln_session())
        assert all("printf" in f.evidence for f in findings)


class TestCwe676:
    def test_flags_tmpnam(self) -> None:
        findings = cwe676.detect(tmpnam_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 676
        assert f.symbol == "tmpnam"
        assert f.function == "make_path"
        assert f.address == hex(0x401160)
        assert "HIGH" in f.evidence
        assert "mkstemp" in f.evidence

    def test_flags_mktemp(self) -> None:
        findings = cwe676.detect(mktemp_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 676
        assert f.symbol == "mktemp"
        assert f.function == "make_temp"
        assert "HIGH" in f.evidence
        assert "mkstemp" in f.evidence

    def test_flags_strtok(self) -> None:
        findings = cwe676.detect(strtok_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 676
        assert f.symbol == "strtok"
        assert f.function == "parse_line"
        assert "MEDIUM" in f.evidence
        assert "strtok_r" in f.evidence

    def test_flags_asctime(self) -> None:
        findings = cwe676.detect(asctime_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 676
        assert f.symbol == "asctime"
        assert f.function == "fmt_time"
        assert "LOW" in f.evidence
        assert "asctime_r" in f.evidence

    def test_flags_ctime(self) -> None:
        findings = cwe676.detect(ctime_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 676
        assert f.symbol == "ctime"
        assert f.function == "stamp"
        assert "LOW" in f.evidence
        assert "ctime_r" in f.evidence

    def test_flags_rand(self) -> None:
        findings = cwe676.detect(rand_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 676
        assert f.symbol == "rand"
        assert f.function == "gen_token"
        assert "MEDIUM" in f.evidence
        assert "getrandom" in f.evidence

    def test_flags_all_six_functions(self) -> None:
        findings = cwe676.detect(cwe676_all_session())
        symbols = {f.symbol for f in findings}
        assert symbols == {"tmpnam", "mktemp", "strtok", "asctime", "ctime", "rand"}
        for f in findings:
            assert f.cwe == 676
            assert f.function
            assert f.address.startswith("0x")
            assert f.evidence

    def test_clean_session_no_findings(self) -> None:
        # Only the safe *_r / mkstemp / getrandom replacements are imported.
        assert cwe676.detect(cwe676_clean_session()) == []

    def test_does_not_flag_absent_function(self) -> None:
        # clean-baseline has none of the CWE-676 functions.
        assert cwe676.detect(clean_baseline_session()) == []


class TestCwe327:
    def test_flags_md5(self) -> None:
        findings = cwe327.detect(md5_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 327
        assert f.symbol == "MD5"
        assert f.function == "hash_pw"
        assert f.address == hex(0x401160)
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "SHA-256" in f.evidence

    def test_flags_sha1(self) -> None:
        findings = cwe327.detect(sha1_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 327
        assert f.symbol == "SHA1"
        assert f.function == "sign_blob"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"

    def test_flags_des(self) -> None:
        findings = cwe327.detect(des_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 327
        assert f.symbol == "DES_ecb_encrypt"
        assert f.function == "encrypt_block"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "AES-GCM" in f.evidence

    def test_flags_rc4(self) -> None:
        findings = cwe327.detect(rc4_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 327
        assert f.symbol == "RC4"
        assert f.function == "stream_cipher"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"

    def test_flags_blowfish_medium(self) -> None:
        findings = cwe327.detect(blowfish_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 327
        assert f.symbol == "BF_cbc_encrypt"
        assert f.function == "encrypt_cbc"
        assert "MEDIUM" in f.evidence
        assert f.confidence == "medium"

    def test_flags_srand_medium(self) -> None:
        findings = cwe327.detect(srand_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 327
        assert f.symbol == "srand"
        assert f.function == "gen_key"
        assert "MEDIUM" in f.evidence
        assert f.confidence == "medium"
        assert "getrandom" in f.evidence

    def test_flags_all_representative_routines(self) -> None:
        findings = cwe327.detect(cwe327_all_session())
        symbols = {f.symbol for f in findings}
        assert symbols == {"MD5", "SHA1", "DES_ecb_encrypt", "RC4", "BF_cbc_encrypt", "srand"}
        for f in findings:
            assert f.cwe == 327
            assert f.function
            assert f.address.startswith("0x")
            assert f.evidence
            assert f.confidence in ("high", "medium", "low")

    def test_clean_session_no_findings(self) -> None:
        # Only strong primitives (SHA256/AES-GCM/getrandom) are imported.
        assert cwe327.detect(cwe327_clean_session()) == []

    def test_does_not_flag_absent_routine(self) -> None:
        # clean-baseline has none of the CWE-327 routines.
        assert cwe327.detect(clean_baseline_session()) == []


class TestCwe89:
    def test_flags_sqlite3_exec(self) -> None:
        findings = cwe89.detect(sqlite3_exec_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 89
        assert f.symbol == "sqlite3_exec"
        assert f.function == "run_query"
        assert f.address == hex(0x401160)
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "sqlite3_bind" in f.evidence

    def test_flags_mysql_query(self) -> None:
        findings = cwe89.detect(mysql_query_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 89
        assert f.symbol == "mysql_query"
        assert f.function == "lookup_user"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "prepared-statement" in f.evidence

    def test_flags_pqexec(self) -> None:
        findings = cwe89.detect(pqexec_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 89
        assert f.symbol == "PQexec"
        assert f.function == "fetch_rows"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "PQexecParams" in f.evidence

    def test_flags_sqlexecdirect(self) -> None:
        findings = cwe89.detect(sqlexecdirect_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 89
        assert f.symbol == "SQLExecDirect"
        assert f.function == "exec_stmt"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "SQLBindParameter" in f.evidence

    def test_flags_prepare_v2_medium(self) -> None:
        # The prepare/compile gateway CAN be used safely with bound parameters,
        # so it is MEDIUM, not HIGH.
        findings = cwe89.detect(sqlite3_prepare_v2_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 89
        assert f.symbol == "sqlite3_prepare_v2"
        assert f.function == "compile_q"
        assert "MEDIUM" in f.evidence
        assert f.confidence == "medium"
        assert "sqlite3_bind" in f.evidence

    def test_flags_all_representative_routines(self) -> None:
        findings = cwe89.detect(cwe89_all_session())
        symbols = {f.symbol for f in findings}
        assert symbols == {
            "sqlite3_exec",
            "mysql_query",
            "PQexec",
            "SQLExecDirect",
            "sqlite3_prepare_v2",
        }
        for f in findings:
            assert f.cwe == 89
            assert f.function
            assert f.address.startswith("0x")
            assert f.evidence
            assert f.confidence in ("high", "medium", "low")

    def test_does_not_flag_safe_bind_api(self) -> None:
        # cwe89_all imports sqlite3_bind_text but never xrefs it as a call —
        # and even a call to it must never be flagged: it is the safe pattern.
        findings = cwe89.detect(cwe89_all_session())
        assert all(f.symbol != "sqlite3_bind_text" for f in findings)

    def test_clean_session_no_findings(self) -> None:
        # Only parameterised APIs (bind/step/exec-params) are imported.
        assert cwe89.detect(cwe89_clean_session()) == []

    def test_does_not_flag_absent_routine(self) -> None:
        # clean-baseline has none of the CWE-89 routines.
        assert cwe89.detect(clean_baseline_session()) == []


class TestCwe295:
    def test_flags_ssl_set_verify(self) -> None:
        findings = cwe295.detect(ssl_set_verify_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 295
        assert f.symbol == "SSL_CTX_set_verify"
        assert f.function == "init_tls"
        assert f.address == hex(0x401160)
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "SSL_VERIFY_NONE" in f.evidence

    def test_flags_ssl_get_peer_certificate_medium(self) -> None:
        findings = cwe295.detect(ssl_get_peer_cert_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 295
        assert f.symbol == "SSL_get_peer_certificate"
        assert f.function == "check_cert"
        assert "MEDIUM" in f.evidence
        assert f.confidence == "medium"
        assert "SSL_get_verify_result" in f.evidence

    def test_flags_curl_easy_setopt_medium(self) -> None:
        findings = cwe295.detect(curl_setopt_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 295
        assert f.symbol == "curl_easy_setopt"
        assert f.function == "setup"
        assert "MEDIUM" in f.evidence
        assert f.confidence == "medium"
        assert "CURLOPT_SSL_VERIFYPEER" in f.evidence

    def test_flags_gnutls_verify_peers2(self) -> None:
        findings = cwe295.detect(gnutls_verify_peers2_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 295
        assert f.symbol == "gnutls_certificate_verify_peers2"
        assert f.function == "verify"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "hostname" in f.evidence

    def test_flags_mbedtls_authmode(self) -> None:
        findings = cwe295.detect(mbedtls_authmode_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 295
        assert f.symbol == "mbedtls_ssl_conf_authmode"
        assert f.function == "conf"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "MBEDTLS_SSL_VERIFY_NONE" in f.evidence

    def test_flags_all_representative_routines(self) -> None:
        findings = cwe295.detect(cwe295_all_session())
        symbols = {f.symbol for f in findings}
        assert symbols == {
            "SSL_CTX_set_verify",
            "SSL_get_peer_certificate",
            "curl_easy_setopt",
            "gnutls_certificate_verify_peers2",
            "mbedtls_ssl_conf_authmode",
        }
        # SSL_get_verify_result is the correct API and must NOT be flagged.
        assert "SSL_get_verify_result" not in symbols
        for f in findings:
            assert f.cwe == 295
            assert f.function
            assert f.address.startswith("0x")
            assert f.evidence
            assert f.confidence in ("high", "medium", "low")

    def test_clean_session_no_findings(self) -> None:
        # Only correct verification APIs are imported.
        assert cwe295.detect(cwe295_clean_session()) == []

    def test_does_not_flag_absent_routine(self) -> None:
        # clean-baseline has none of the CWE-295 routines.
        assert cwe295.detect(clean_baseline_session()) == []


class TestCwe476:
    def test_flags_malloc_deref_without_check(self) -> None:
        findings = cwe476.detect(malloc_deref_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 476
        assert f.symbol == "malloc"
        assert f.function == "build"
        assert f.address == hex(0x401150)
        assert "NULL" in f.evidence
        assert f.confidence == "low"

    def test_does_not_flag_when_null_checked(self) -> None:
        # test rax, rax before the deref → safe.
        assert cwe476.detect(malloc_checked_session()) == []

    def test_does_not_flag_when_alias_checked(self) -> None:
        # Pointer moved to rbx, rbx is tested before deref → safe.
        assert cwe476.detect(malloc_aliased_checked_session()) == []

    def test_flags_deref_through_alias(self) -> None:
        # Pointer moved to rbx, dereferenced via rbx, no guard → flagged.
        findings = cwe476.detect(malloc_aliased_deref_vuln_session())
        assert len(findings) == 1
        assert findings[0].symbol == "malloc"
        assert findings[0].function == "build"

    def test_flags_fopen_deref(self) -> None:
        findings = cwe476.detect(fopen_deref_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 476
        assert f.symbol == "fopen"
        assert f.function == "read_cfg"
        assert f.confidence == "low"

    def test_does_not_flag_when_pointer_escapes_to_stack(self) -> None:
        # calloc result stored to the stack; no in-function deref we can see.
        assert cwe476.detect(calloc_stored_escapes_session()) == []

    def test_no_allocator_imports_no_findings(self) -> None:
        assert cwe476.detect(cwe476_no_allocators_session()) == []

    def test_clean_baseline_no_findings(self) -> None:
        assert cwe476.detect(clean_baseline_session()) == []

    def test_arm64_flags_malloc_deref(self) -> None:
        findings = cwe476.detect(arm64_malloc_deref_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 476
        assert f.symbol == "malloc"
        assert f.function == "build"

    def test_arm64_does_not_flag_when_cbz_guarded(self) -> None:
        assert cwe476.detect(arm64_malloc_checked_session()) == []


class TestCwe252:
    def test_flags_setuid_return_clobbered(self) -> None:
        findings = cwe252.detect(setuid_unchecked_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 252
        assert f.symbol == "setuid"
        assert f.function == "drop_privs"
        assert f.address == hex(0x401150)
        assert "unchecked return value" in f.evidence
        assert f.confidence == "low"

    def test_does_not_flag_when_return_tested(self) -> None:
        # test eax, eax before discard → the return was checked.
        assert cwe252.detect(setuid_checked_session()) == []

    def test_does_not_flag_when_return_saved(self) -> None:
        # mov rbx, rax reads the return value → used, not discarded.
        assert cwe252.detect(write_return_saved_session()) == []

    def test_flags_fclose_clobbered_by_following_call(self) -> None:
        findings = cwe252.detect(fclose_unchecked_call_clobber_session())
        assert len(findings) == 1
        assert findings[0].symbol == "fclose"
        assert findings[0].function == "finish"

    def test_flags_chroot_return_discarded_at_function_end(self) -> None:
        findings = cwe252.detect(chroot_unchecked_fallthrough_session())
        assert len(findings) == 1
        assert findings[0].symbol == "chroot"
        assert findings[0].function == "enter_jail"

    def test_clean_session_no_findings(self) -> None:
        assert cwe252.detect(cwe252_clean_session()) == []

    def test_clean_baseline_no_findings(self) -> None:
        assert cwe252.detect(clean_baseline_session()) == []

    def test_arm64_flags_setuid_clobber(self) -> None:
        findings = cwe252.detect(arm64_setuid_unchecked_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 252
        assert f.symbol == "setuid"
        assert f.function == "drop_privs"

    def test_arm64_does_not_flag_when_cbz_guarded(self) -> None:
        assert cwe252.detect(arm64_setuid_checked_session()) == []


class TestCwe78:
    def test_flags_nonconstant_system(self) -> None:
        findings = cwe78.detect(system_vuln_session())
        system_findings = [f for f in findings if f.symbol == "system"]
        assert len(system_findings) == 1
        f = system_findings[0]
        assert f.cwe == 78
        assert f.function == "run_cmd"
        assert f.address == hex(0x40118F)
        assert "non-constant" in f.evidence

    def test_does_not_flag_constant_system(self) -> None:
        # system("ls") loads rdi from a str. literal — must NOT be flagged.
        assert cwe78.detect(system_constant_session()) == []

    def test_clean_baseline_no_findings(self) -> None:
        assert cwe78.detect(clean_baseline_session()) == []
