"""Unit tests for blight detectors — fully mocked, no radare2 required."""

from __future__ import annotations

from blight.detectors import cwe78, cwe120, cwe134, cwe242, cwe252, cwe476, cwe676
from tests.fake_session import (
    arm64_malloc_checked_session,
    arm64_malloc_deref_vuln_session,
    arm64_setuid_checked_session,
    arm64_setuid_unchecked_vuln_session,
    asctime_vuln_session,
    calloc_stored_escapes_session,
    chroot_unchecked_fallthrough_session,
    clean_baseline_session,
    ctime_vuln_session,
    cwe252_clean_session,
    cwe476_no_allocators_session,
    cwe676_all_session,
    cwe676_clean_session,
    fopen_deref_vuln_session,
    fprintf_fmtstr_vuln_session,
    gets_vuln_session,
    malloc_aliased_checked_session,
    malloc_aliased_deref_vuln_session,
    malloc_checked_session,
    malloc_deref_vuln_session,
    mktemp_vuln_session,
    printf_constant_session,
    printf_fmtstr_vuln_session,
    printf_no_dangerous_imports_session,
    rand_vuln_session,
    fclose_unchecked_call_clobber_session,
    setuid_checked_session,
    setuid_unchecked_vuln_session,
    snprintf_fmtstr_vuln_session,
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
