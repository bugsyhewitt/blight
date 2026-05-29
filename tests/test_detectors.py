"""Unit tests for blight detectors — fully mocked, no radare2 required."""

from __future__ import annotations

from blight.detectors import (
    cwe22,
    cwe78,
    cwe89,
    cwe119,
    cwe120,
    cwe122,
    cwe134,
    cwe197,
    cwe242,
    cwe252,
    cwe295,
    cwe327,
    cwe362,
    cwe369,
    cwe401,
    cwe415,
    cwe416,
    cwe426,
    cwe476,
    cwe676,
    cwe798,
)
from tests.fake_session import (
    api_key_secret_shaped_vuln_session,
    cwe798_all_session,
    cwe798_no_strings_session,
    cwe798_placeholder_clean_session,
    openssh_key_blob_vuln_session,
    passwd_colon_assignment_vuln_session,
    password_assignment_vuln_session,
    private_key_blob_vuln_session,
    token_short_value_session,
    uri_credential_vuln_session,
    arm64_malloc_checked_session,
    arm64_malloc_deref_vuln_session,
    arm64_setuid_checked_session,
    arm64_setuid_unchecked_vuln_session,
    access_vuln_session,
    asctime_vuln_session,
    blowfish_vuln_session,
    cwe22_all_session,
    cwe22_clean_session,
    execve_vuln_session,
    fopen_path_vuln_session,
    open_vuln_session,
    rename_vuln_session,
    symlink_vuln_session,
    unlink_vuln_session,
    calloc_stored_escapes_session,
    chroot_unchecked_fallthrough_session,
    clean_baseline_session,
    cwe119_all_session,
    cwe119_clean_session,
    memcpy_vuln_session,
    memmove_vuln_session,
    strcat_vuln_session,
    strncat_vuln_session,
    alloca_vuln_session,
    ctime_vuln_session,
    curl_setopt_vuln_session,
    cwe89_all_session,
    cwe89_clean_session,
    cwe252_clean_session,
    cwe295_all_session,
    cwe295_clean_session,
    cwe327_all_session,
    cwe327_clean_session,
    idiv_register_vuln_session,
    div_memory_vuln_session,
    idiv_checked_session,
    idiv_cmp_checked_session,
    idiv_constant_divisor_session,
    no_division_session,
    arm64_sdiv_register_vuln_session,
    arm64_udiv_checked_session,
    cwe369_multi_function_session,
    cwe369_clean_session,
    cwe197_strlen_truncated_session,
    cwe197_read_truncated_session,
    cwe197_word_store_truncated_session,
    cwe197_fullwidth_safe_session,
    cwe197_reextended_safe_session,
    cwe197_movsxd_reextended_safe_session,
    cwe197_no_wide_returner_session,
    cwe197_arm64_truncated_session,
    cwe197_arm64_fullwidth_safe_session,
    cwe197_multi_call_session,
    free_then_deref_vuln_session,
    free_then_null_assign_session,
    free_then_xor_zero_session,
    free_then_aliased_deref_vuln_session,
    free_then_pass_to_call_vuln_session,
    free_then_reassigned_before_call_session,
    free_then_unused_session,
    cwe416_no_free_imports_session,
    arm64_free_then_deref_vuln_session,
    arm64_free_then_null_assign_session,
    double_free_vuln_session,
    double_free_via_alias_vuln_session,
    double_free_nulled_between_session,
    double_free_xor_between_session,
    single_free_session,
    free_then_nonfree_use_session,
    cwe415_no_free_imports_session,
    arm64_double_free_vuln_session,
    arm64_double_free_nulled_session,
    malloc_strcpy_heap_overflow_vuln_session,
    calloc_sprintf_heap_overflow_vuln_session,
    malloc_strncpy_bounded_session,
    malloc_reassigned_before_copy_session,
    malloc_no_copy_session,
    cwe122_no_allocator_imports_session,
    arm64_malloc_strcpy_heap_overflow_vuln_session,
    arm64_malloc_strncpy_bounded_session,
    malloc_clobbered_leak_vuln_session,
    strdup_clobbered_leak_vuln_session,
    malloc_freed_session,
    malloc_stored_escapes_leak_session,
    malloc_returned_session,
    malloc_passed_to_call_session,
    cwe401_no_allocator_imports_session,
    arm64_malloc_clobbered_leak_vuln_session,
    arm64_malloc_freed_session,
    access_toctou_vuln_session,
    faccessat_toctou_vuln_session,
    stat_toctou_vuln_session,
    lstat_toctou_vuln_session,
    cwe362_all_session,
    cwe362_clean_session,
    cwe426_all_session,
    cwe426_clean_session,
    dlopen_vuln_session,
    dlmopen_vuln_session,
    execvp_searchpath_vuln_session,
    execlp_searchpath_vuln_session,
    popen_searchpath_vuln_session,
    system_searchpath_vuln_session,
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


class TestCwe22:
    def test_flags_unlink_high(self) -> None:
        findings = cwe22.detect(unlink_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 22
        assert f.symbol == "unlink"
        assert f.function == "del_file"
        assert f.address == hex(0x401160)
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "canonicalised" in f.evidence

    def test_flags_rename_high(self) -> None:
        findings = cwe22.detect(rename_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 22
        assert f.symbol == "rename"
        assert f.function == "move_file"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"

    def test_flags_symlink_high(self) -> None:
        findings = cwe22.detect(symlink_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 22
        assert f.symbol == "symlink"
        assert f.function == "make_link"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"

    def test_flags_execve_high(self) -> None:
        findings = cwe22.detect(execve_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 22
        assert f.symbol == "execve"
        assert f.function == "spawn"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"

    def test_flags_open_medium(self) -> None:
        # The open/read-metadata sinks appear routinely in validated code, so
        # they are MEDIUM, not HIGH.
        findings = cwe22.detect(open_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 22
        assert f.symbol == "open"
        assert f.function == "load_cfg"
        assert "MEDIUM" in f.evidence
        assert f.confidence == "medium"

    def test_flags_fopen_medium(self) -> None:
        findings = cwe22.detect(fopen_path_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 22
        assert f.symbol == "fopen"
        assert f.function == "read_doc"
        assert "MEDIUM" in f.evidence
        assert f.confidence == "medium"

    def test_flags_access_medium(self) -> None:
        findings = cwe22.detect(access_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 22
        assert f.symbol == "access"
        assert f.function == "check_path"
        assert "MEDIUM" in f.evidence
        assert f.confidence == "medium"

    def test_flags_all_representative_routines(self) -> None:
        findings = cwe22.detect(cwe22_all_session())
        symbols = {f.symbol for f in findings}
        assert symbols == {
            "unlink",
            "rename",
            "symlink",
            "execve",
            "open",
            "fopen",
            "access",
        }
        for f in findings:
            assert f.cwe == 22
            assert f.function
            assert f.address.startswith("0x")
            assert f.evidence
            assert f.confidence in ("high", "medium", "low")

    def test_does_not_flag_realpath(self) -> None:
        # cwe22_all imports realpath (the canonicalisation primitive); it is the
        # safe mitigation and must never be flagged — flagging it inverts signal.
        findings = cwe22.detect(cwe22_all_session())
        assert all(f.symbol != "realpath" for f in findings)

    def test_clean_session_no_findings(self) -> None:
        # Only realpath + printf imported — no CWE-22 sink.
        assert cwe22.detect(cwe22_clean_session()) == []

    def test_does_not_flag_absent_routine(self) -> None:
        # clean-baseline has none of the CWE-22 routines.
        assert cwe22.detect(clean_baseline_session()) == []


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


class TestCwe119:
    def test_flags_memcpy_high(self) -> None:
        findings = cwe119.detect(memcpy_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 119
        assert f.symbol == "memcpy"
        assert f.function == "copy_buf"
        assert f.address == hex(0x401160)
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "length" in f.evidence

    def test_flags_memmove_high(self) -> None:
        findings = cwe119.detect(memmove_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 119
        assert f.symbol == "memmove"
        assert f.function == "shift_buf"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"

    def test_flags_strcat_high(self) -> None:
        findings = cwe119.detect(strcat_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 119
        assert f.symbol == "strcat"
        assert f.function == "build_path"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "strlcat" in f.evidence

    def test_flags_strncat_medium(self) -> None:
        # strncat's count is source-relative, not destination-relative, so it
        # CAN be used correctly — MEDIUM, not HIGH.
        findings = cwe119.detect(strncat_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 119
        assert f.symbol == "strncat"
        assert f.function == "append_seg"
        assert "MEDIUM" in f.evidence
        assert f.confidence == "medium"

    def test_flags_alloca_medium(self) -> None:
        findings = cwe119.detect(alloca_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 119
        assert f.symbol == "alloca"
        assert f.function == "scratch"
        assert "MEDIUM" in f.evidence
        assert f.confidence == "medium"
        assert "stack" in f.evidence

    def test_flags_all_representative_routines(self) -> None:
        findings = cwe119.detect(cwe119_all_session())
        symbols = {f.symbol for f in findings}
        assert symbols == {"memcpy", "memmove", "strcat", "strncat", "alloca"}
        for f in findings:
            assert f.cwe == 119
            assert f.function
            assert f.address.startswith("0x")
            assert f.evidence
            assert f.confidence in ("high", "medium", "low")

    def test_does_not_flag_safe_bounded_api(self) -> None:
        # strlcpy is imported but is the safe pattern — must never be flagged.
        findings = cwe119.detect(cwe119_all_session())
        assert all(f.symbol != "strlcpy" for f in findings)

    def test_clean_session_no_findings(self) -> None:
        # Only bounded/safe routines (strlcpy/strlcat/snprintf/memset).
        assert cwe119.detect(cwe119_clean_session()) == []

    def test_does_not_flag_absent_routine(self) -> None:
        # clean-baseline has none of the CWE-119 routines.
        assert cwe119.detect(clean_baseline_session()) == []

    def test_does_not_flag_strcpy_owned_by_cwe120(self) -> None:
        # strcpy/sprintf/gets belong to CWE-120; CWE-119 must not claim them.
        findings = cwe119.detect(strcpy_vuln_session())
        assert findings == []


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


class TestCwe426:
    def test_flags_dlopen(self) -> None:
        findings = cwe426.detect(dlopen_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 426
        assert f.symbol == "dlopen"
        assert f.function == "load_plugin"
        assert f.address == hex(0x401160)
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "LD_LIBRARY_PATH" in f.evidence

    def test_flags_dlmopen(self) -> None:
        findings = cwe426.detect(dlmopen_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 426
        assert f.symbol == "dlmopen"
        assert f.function == "load_ns"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"

    def test_flags_execvp(self) -> None:
        findings = cwe426.detect(execvp_searchpath_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 426
        assert f.symbol == "execvp"
        assert f.function == "spawn_tool"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "$PATH" in f.evidence

    def test_flags_execlp(self) -> None:
        findings = cwe426.detect(execlp_searchpath_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 426
        assert f.symbol == "execlp"
        assert f.function == "run_helper"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"

    def test_flags_popen(self) -> None:
        findings = cwe426.detect(popen_searchpath_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 426
        assert f.symbol == "popen"
        assert f.function == "read_proc"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        assert "/bin/sh" in f.evidence

    def test_flags_system(self) -> None:
        # system() is also inspected by CWE-78, but CWE-426 flags it for the
        # $PATH-resolution mechanism regardless of argument constness.
        findings = cwe426.detect(system_searchpath_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 426
        assert f.symbol == "system"
        assert f.function == "run_cmd"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"

    def test_flags_all_representative_routines(self) -> None:
        findings = cwe426.detect(cwe426_all_session())
        symbols = {f.symbol for f in findings}
        assert symbols == {
            "dlopen",
            "dlmopen",
            "execlp",
            "execvp",
            "execvpe",
            "popen",
            "system",
        }
        # execve (explicit path) and snprintf must NOT fire.
        assert "execve" not in symbols
        assert "snprintf" not in symbols
        for f in findings:
            assert f.cwe == 426
            assert f.function
            assert f.address.startswith("0x")
            assert f.evidence
            assert f.confidence in ("high", "medium", "low")

    def test_clean_session_no_findings(self) -> None:
        # Only explicit-path launchers (execv/execve/posix_spawn) are imported.
        assert cwe426.detect(cwe426_clean_session()) == []

    def test_does_not_flag_absent_routine(self) -> None:
        # clean-baseline has none of the CWE-426 routines.
        assert cwe426.detect(clean_baseline_session()) == []


class TestCwe798:
    def test_flags_password_assignment_high(self) -> None:
        findings = cwe798.detect(password_assignment_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 798
        assert f.symbol == "password"
        assert f.address == hex(0x402010)
        assert f.function == ".rodata"
        assert "HIGH" in f.evidence
        assert f.confidence == "high"
        # The raw secret value must be redacted out of the report.
        assert "SuperSecret123" not in f.evidence
        assert "len=" in f.evidence

    def test_flags_colon_style_assignment(self) -> None:
        findings = cwe798.detect(passwd_colon_assignment_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 798
        assert f.symbol == "db_passwd"
        assert f.confidence == "high"
        assert "hunter2value" not in f.evidence

    def test_api_key_long_value_is_high(self) -> None:
        findings = cwe798.detect(api_key_secret_shaped_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 798
        assert f.symbol == "api_key"
        # A long, secret-shaped token value upgrades token-class to HIGH.
        assert "HIGH" in f.evidence
        assert f.confidence == "high"

    def test_token_short_value_is_medium(self) -> None:
        findings = cwe798.detect(token_short_value_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 798
        assert f.symbol == "token"
        # A short token-class value stays MEDIUM (could be a config knob).
        assert "MEDIUM" in f.evidence
        assert f.confidence == "medium"

    def test_flags_pem_private_key(self) -> None:
        findings = cwe798.detect(private_key_blob_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 798
        assert f.confidence == "high"
        assert "private key" in f.evidence.lower()
        assert f.address == hex(0x403000)

    def test_flags_openssh_private_key(self) -> None:
        findings = cwe798.detect(openssh_key_blob_vuln_session())
        assert len(findings) == 1
        assert findings[0].confidence == "high"
        assert "private key" in findings[0].evidence.lower()

    def test_flags_uri_credential(self) -> None:
        findings = cwe798.detect(uri_credential_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 798
        assert f.symbol == "connection-uri"
        assert f.confidence == "high"
        # The inline password must be redacted, not echoed.
        assert "hunter2pass" not in f.evidence
        assert "URI" in f.evidence

    def test_placeholders_and_empty_do_not_fire(self) -> None:
        # %s templates, empty values, ${VAR}, sentinels, and non-secret keys
        # (username=) must all be rejected.
        assert cwe798.detect(cwe798_placeholder_clean_session()) == []

    def test_no_strings_no_findings(self) -> None:
        assert cwe798.detect(cwe798_no_strings_session()) == []

    def test_flags_all_signals_together(self) -> None:
        findings = cwe798.detect(cwe798_all_session())
        symbols = {f.symbol for f in findings}
        # password assignment, api_key assignment, PEM key, and URI credential.
        assert "password" in symbols
        assert "api_key" in symbols
        assert "connection-uri" in symbols
        assert any("private key" in f.evidence.lower() for f in findings)
        # Benign neighbours (format templates, username=) must NOT appear.
        assert "username" not in symbols
        assert len(findings) == 4
        for f in findings:
            assert f.cwe == 798
            assert f.address.startswith("0x")
            assert f.evidence
            assert f.confidence in ("high", "medium", "low")

    def test_clean_baseline_no_findings(self) -> None:
        # clean-baseline session carries no strings → nothing to flag.
        assert cwe798.detect(clean_baseline_session()) == []


class TestCwe369:
    """CWE-369 Divide By Zero — instruction-pattern detector over every body."""

    def test_flags_idiv_register_divisor(self) -> None:
        findings = cwe369.detect(idiv_register_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 369
        assert f.symbol == "idiv"
        assert f.confidence == "low"
        assert f.address == hex(0x401146)
        assert "ecx" in f.evidence

    def test_flags_div_memory_divisor(self) -> None:
        findings = cwe369.detect(div_memory_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 369
        assert f.symbol == "div"
        assert f.address == hex(0x40120E)

    def test_test_guard_suppresses(self) -> None:
        # `test ecx, ecx` before the idiv proves the divisor was zero-checked.
        assert cwe369.detect(idiv_checked_session()) == []

    def test_cmp_zero_guard_suppresses(self) -> None:
        # `cmp esi, 0` before the idiv is also a valid zero-check.
        assert cwe369.detect(idiv_cmp_checked_session()) == []

    def test_constant_divisor_not_flagged(self) -> None:
        # divisor set from a nonzero immediate cannot be zero → safe.
        assert cwe369.detect(idiv_constant_divisor_session()) == []

    def test_no_division_no_findings(self) -> None:
        # a body with imul/add but no div/idiv must not fire.
        assert cwe369.detect(no_division_session()) == []

    def test_flags_arm64_sdiv_register_divisor(self) -> None:
        findings = cwe369.detect(arm64_sdiv_register_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 369
        assert f.symbol == "sdiv"
        assert f.address == hex(0x840)
        # The AArch64 divisor is the THIRD operand (w2), not the dividend.
        assert "w2" in f.evidence

    def test_arm64_cbz_guard_suppresses(self) -> None:
        # `cbz w2, ...` before the udiv proves the divisor was zero-checked.
        assert cwe369.detect(arm64_udiv_checked_session()) == []

    def test_scans_every_function_body(self) -> None:
        # Two functions: the unguarded idiv fires, the guarded one does not.
        findings = cwe369.detect(cwe369_multi_function_session())
        assert len(findings) == 1
        assert findings[0].address == hex(0x40113A)

    def test_clean_session_no_findings(self) -> None:
        assert cwe369.detect(cwe369_clean_session()) == []


class TestCwe197:
    """CWE-197 Numeric Truncation — PLT-anchored, single-function forward scan
    over wide-return libc routines whose result is narrowed."""

    def test_flags_strlen_truncated_to_int(self) -> None:
        findings = cwe197.detect(cwe197_strlen_truncated_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 197
        assert f.symbol == "strlen"
        assert f.confidence == "low"
        assert f.address == hex(0x401152)
        assert "strlen" in f.evidence

    def test_flags_read_truncated_to_int(self) -> None:
        findings = cwe197.detect(cwe197_read_truncated_session())
        assert len(findings) == 1
        assert findings[0].symbol == "read"
        assert findings[0].address == hex(0x401210)

    def test_flags_word_store_truncation(self) -> None:
        # A 16-bit store of a 64-bit strtoul result is an even more severe drop.
        findings = cwe197.detect(cwe197_word_store_truncated_session())
        assert len(findings) == 1
        assert findings[0].symbol == "strtoul"

    def test_fullwidth_store_not_flagged(self) -> None:
        # `mov qword [..], rax` keeps all 64 bits → no truncation.
        assert cwe197.detect(cwe197_fullwidth_safe_session()) == []

    def test_cdqe_reextension_not_flagged(self) -> None:
        # `cdqe` re-extends eax->rax → the magnitude is preserved.
        assert cwe197.detect(cwe197_reextended_safe_session()) == []

    def test_movsxd_reextension_not_flagged(self) -> None:
        # `movsxd rbx, eax` re-extends the narrowed value back to 64 bits.
        assert cwe197.detect(cwe197_movsxd_reextended_safe_session()) == []

    def test_int_returning_source_not_flagged(self) -> None:
        # atoi returns int, not a wide type → storing it as int loses no bits.
        assert cwe197.detect(cwe197_no_wide_returner_session()) == []

    def test_flags_arm64_truncation(self) -> None:
        findings = cwe197.detect(cwe197_arm64_truncated_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.symbol == "strlen"
        assert f.address == hex(0x848)

    def test_arm64_fullwidth_store_not_flagged(self) -> None:
        # `str x0, [..]` is a 64-bit store → no truncation on AArch64.
        assert cwe197.detect(cwe197_arm64_fullwidth_safe_session()) == []

    def test_scans_every_call_site(self) -> None:
        # Two wide-return call sites: one truncates (flag), one keeps width.
        findings = cwe197.detect(cwe197_multi_call_session())
        assert len(findings) == 1
        assert findings[0].address == hex(0x401152)


class TestCwe362:
    """CWE-362 TOCTOU check-then-use — pure PLT-lookup over check-by-path sinks."""

    def test_flags_access(self) -> None:
        findings = cwe362.detect(access_toctou_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 362
        assert f.symbol == "access"
        assert f.confidence == "medium"
        assert "MEDIUM" in f.evidence
        assert "TOCTOU" in f.evidence
        assert f.address == hex(0x401160)

    def test_flags_faccessat(self) -> None:
        findings = cwe362.detect(faccessat_toctou_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 362
        assert f.symbol == "faccessat"
        assert f.confidence == "medium"

    def test_flags_stat(self) -> None:
        findings = cwe362.detect(stat_toctou_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.symbol == "stat"
        assert f.confidence == "medium"
        assert "metadata" in f.evidence

    def test_flags_lstat(self) -> None:
        findings = cwe362.detect(lstat_toctou_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.symbol == "lstat"
        assert "O_NOFOLLOW" in f.evidence

    def test_flags_all_check_primitives(self) -> None:
        findings = cwe362.detect(cwe362_all_session())
        symbols = {f.symbol for f in findings}
        # All nine check-by-path primitives fire.
        assert symbols == {
            "access",
            "faccessat",
            "euidaccess",
            "eaccess",
            "stat",
            "lstat",
            "fstatat",
            "stat64",
            "lstat64",
        }
        # fstat (fd-based) and open (a use sink, not a check) must NOT fire.
        assert "fstat" not in symbols
        assert "open" not in symbols
        assert len(findings) == 9
        for f in findings:
            assert f.cwe == 362
            assert f.confidence == "medium"
            assert f.address.startswith("0x")
            assert f.evidence

    def test_clean_session_no_findings(self) -> None:
        # Only fd-based/atomic primitives (fstat, openat) and a use sink (open)
        # are imported — no check-by-path primitive is present.
        assert cwe362.detect(cwe362_clean_session()) == []


class TestCwe415:
    """CWE-415 double-free — in-function forward scan with alias tracking."""

    def test_flags_double_free(self) -> None:
        findings = cwe415.detect(double_free_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 415
        assert f.symbol == "free"
        assert f.function == "dbl_free"
        assert f.address == hex(0x401150)
        assert "double-free" in f.evidence
        assert f.confidence == "low"

    def test_flags_double_free_through_alias(self) -> None:
        # rbx = rdi; rdi = rbx; free(rdi) — alias propagation still a double-free.
        findings = cwe415.detect(double_free_via_alias_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.symbol == "free"
        assert f.function == "alias_dbl"

    def test_does_not_flag_when_nulled_between(self) -> None:
        # mov rdi, 0 between the two frees severs the alias → safe.
        assert cwe415.detect(double_free_nulled_between_session()) == []

    def test_does_not_flag_when_xored_between(self) -> None:
        # xor rdi, rdi between the two frees zeroes the register → safe.
        assert cwe415.detect(double_free_xor_between_session()) == []

    def test_does_not_flag_single_free(self) -> None:
        # A pointer freed exactly once is not a double-free.
        assert cwe415.detect(single_free_session()) == []

    def test_does_not_flag_nonfree_use(self) -> None:
        # free then a generic use (puts) is CWE-416's signal, not a double-free.
        assert cwe415.detect(free_then_nonfree_use_session()) == []

    def test_no_free_imports_no_findings(self) -> None:
        assert cwe415.detect(cwe415_no_free_imports_session()) == []

    def test_clean_baseline_no_findings(self) -> None:
        assert cwe415.detect(clean_baseline_session()) == []

    def test_arm64_flags_double_free(self) -> None:
        findings = cwe415.detect(arm64_double_free_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 415
        assert f.symbol == "free"
        assert f.function == "dbl_free"

    def test_arm64_does_not_flag_when_nulled_between(self) -> None:
        assert cwe415.detect(arm64_double_free_nulled_session()) == []


class TestCwe416:
    """CWE-416 use-after-free — in-function forward scan with alias tracking."""

    def test_flags_deref_of_freed_pointer(self) -> None:
        findings = cwe416.detect(free_then_deref_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 416
        assert f.symbol == "free"
        assert f.function == "use_after"
        assert f.address == hex(0x401150)
        assert "use-after-free" in f.evidence
        assert f.confidence == "low"

    def test_does_not_flag_when_pointer_nulled(self) -> None:
        # mov rdi, 0 after free severs the dangling alias → safe.
        assert cwe416.detect(free_then_null_assign_session()) == []

    def test_does_not_flag_when_pointer_xored_zero(self) -> None:
        # xor rdi, rdi zeroes the register → alias killed → safe.
        assert cwe416.detect(free_then_xor_zero_session()) == []

    def test_flags_deref_through_alias(self) -> None:
        # rbx = rdi propagates the dangling alias; deref via rbx is still UAF.
        findings = cwe416.detect(free_then_aliased_deref_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.symbol == "free"
        assert f.function == "use_alias"

    def test_flags_freed_pointer_passed_to_call(self) -> None:
        # A following call while rdi still holds the freed pointer is a use.
        findings = cwe416.detect(free_then_pass_to_call_vuln_session())
        assert len(findings) == 1
        assert findings[0].symbol == "free"
        assert findings[0].function == "dbl_use"

    def test_does_not_flag_when_reassigned_before_call(self) -> None:
        # rdi reloaded with a fresh value before the next call → safe.
        assert cwe416.detect(free_then_reassigned_before_call_session()) == []

    def test_does_not_flag_when_pointer_unused(self) -> None:
        # The freed register is never read again → nothing to flag.
        assert cwe416.detect(free_then_unused_session()) == []

    def test_no_free_imports_no_findings(self) -> None:
        assert cwe416.detect(cwe416_no_free_imports_session()) == []

    def test_clean_baseline_no_findings(self) -> None:
        assert cwe416.detect(clean_baseline_session()) == []

    def test_arm64_flags_deref_of_freed_pointer(self) -> None:
        findings = cwe416.detect(arm64_free_then_deref_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 416
        assert f.symbol == "free"
        assert f.function == "use_after"

    def test_arm64_does_not_flag_when_pointer_nulled(self) -> None:
        assert cwe416.detect(arm64_free_then_null_assign_session()) == []


class TestCwe122:
    """CWE-122 heap-based buffer overflow — in-function alias tracking from an
    allocator return register into an unbounded-copy destination."""

    def test_flags_malloc_into_strcpy(self) -> None:
        findings = cwe122.detect(malloc_strcpy_heap_overflow_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 122
        assert f.symbol == "malloc"
        assert f.function == "build"
        assert f.address == hex(0x401150)
        assert "heap buffer overflow" in f.evidence
        assert f.confidence == "low"

    def test_flags_calloc_into_sprintf_through_alias(self) -> None:
        # rbx = rax alias propagation; rdi = rbx; sprintf(rdi, ...) is the sink.
        findings = cwe122.detect(calloc_sprintf_heap_overflow_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.symbol == "calloc"
        assert f.function == "fmt"

    def test_does_not_flag_bounded_copy(self) -> None:
        # strncpy is bounded (explicit length) — that is CWE-120's territory.
        assert cwe122.detect(malloc_strncpy_bounded_session()) == []

    def test_does_not_flag_when_dest_reassigned(self) -> None:
        # The heap pointer is stored away and a different (stack) dest is copied.
        assert cwe122.detect(malloc_reassigned_before_copy_session()) == []

    def test_does_not_flag_when_no_copy(self) -> None:
        # The heap pointer is never fed to a copy routine.
        assert cwe122.detect(malloc_no_copy_session()) == []

    def test_no_allocator_imports_no_findings(self) -> None:
        assert cwe122.detect(cwe122_no_allocator_imports_session()) == []

    def test_clean_baseline_no_findings(self) -> None:
        assert cwe122.detect(clean_baseline_session()) == []

    def test_arm64_flags_malloc_into_strcpy(self) -> None:
        findings = cwe122.detect(arm64_malloc_strcpy_heap_overflow_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 122
        assert f.symbol == "malloc"
        assert f.function == "build"

    def test_arm64_does_not_flag_bounded_copy(self) -> None:
        assert cwe122.detect(arm64_malloc_strncpy_bounded_session()) == []


class TestCwe401:
    """CWE-401 memory leak — in-function alias tracking from an allocator return
    register; the sink is the clobber of the last live alias with no preceding
    free / store / return / handoff."""

    def test_flags_clobbered_unfreed_allocation(self) -> None:
        findings = cwe401.detect(malloc_clobbered_leak_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 401
        assert f.symbol == "malloc"
        assert f.function == "leaky"
        assert f.address == hex(0x401150)
        assert "memory leak" in f.evidence
        assert f.confidence == "low"

    def test_flags_leak_through_alias(self) -> None:
        # rbx = rax; rax reloaded (rbx still alive); rbx reloaded → last handle lost.
        findings = cwe401.detect(strdup_clobbered_leak_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.symbol == "strdup"
        assert f.function == "dup_it"

    def test_does_not_flag_when_freed(self) -> None:
        # free(ptr) before the handle is lost → released, no leak.
        assert cwe401.detect(malloc_freed_session()) == []

    def test_does_not_flag_when_stored_to_memory(self) -> None:
        # The pointer escapes to a stack slot — conservatively not a proven leak.
        assert cwe401.detect(malloc_stored_escapes_leak_session()) == []

    def test_does_not_flag_when_returned(self) -> None:
        # The pointer is left in the return register at ret → caller owns it.
        assert cwe401.detect(malloc_returned_session()) == []

    def test_does_not_flag_when_passed_to_call(self) -> None:
        # Passed to another call → ownership ambiguous, not flagged.
        assert cwe401.detect(malloc_passed_to_call_session()) == []

    def test_no_allocator_imports_no_findings(self) -> None:
        assert cwe401.detect(cwe401_no_allocator_imports_session()) == []

    def test_clean_baseline_no_findings(self) -> None:
        assert cwe401.detect(clean_baseline_session()) == []

    def test_arm64_flags_clobbered_unfreed_allocation(self) -> None:
        findings = cwe401.detect(arm64_malloc_clobbered_leak_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 401
        assert f.symbol == "malloc"
        assert f.function == "leaky"

    def test_arm64_does_not_flag_when_freed(self) -> None:
        assert cwe401.detect(arm64_malloc_freed_session()) == []
