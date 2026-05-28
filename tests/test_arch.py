"""Architecture-aware detection tests (POST_V01 item 5 — ARM/aarch64 support).

These exercise the architecture-aware argument-register heuristic in cwe78 and
cwe134, plus the architecture-agnostic detectors (cwe120/cwe242) which must work
on ARM unchanged. Fully mocked — no radare2 required.
"""

from __future__ import annotations

import pytest

from blight.detectors import cwe78, cwe120, cwe134, cwe242
from blight.detectors._argregs import (
    DEFAULT_ARCH,
    arg_register_aliases,
    normalize_arch,
)
from tests.fake_session import (
    arm64_fprintf_fmtstr_vuln_session,
    arm64_gets_vuln_session,
    arm64_printf_constant_session,
    arm64_printf_fmtstr_vuln_session,
    arm64_strcpy_vuln_session,
    arm64_system_constant_session,
    arm64_system_vuln_session,
    system_vuln_session,
)


class TestNormalizeArch:
    @pytest.mark.parametrize(
        "arch,bits,expected",
        [
            ("x86", 64, "x86_64"),
            ("x86_64", 64, "x86_64"),
            ("amd64", 64, "x86_64"),
            ("x86", None, "x86_64"),
            ("arm", 64, "arm64"),
            ("aarch64", 64, "arm64"),
            ("arm64", 64, "arm64"),
            ("AArch64", None, "arm64"),
            # 32-bit ARM is out of scope -> conservative fallback.
            ("arm", 32, DEFAULT_ARCH),
            # Unknown / missing -> fallback.
            ("mips", 32, DEFAULT_ARCH),
            (None, None, DEFAULT_ARCH),
            ("", 64, DEFAULT_ARCH),
        ],
    )
    def test_mapping(self, arch, bits, expected) -> None:
        assert normalize_arch(arch, bits) == expected


class TestArgRegisterAliases:
    def test_x86_64_arg0_is_rdi_family(self) -> None:
        assert arg_register_aliases("x86_64", 0) == ("rdi", "edi", "di")

    def test_arm64_arg0_is_x0_w0(self) -> None:
        assert arg_register_aliases("arm64", 0) == ("x0", "w0")

    def test_arm64_arg2_is_x2_w2(self) -> None:
        assert arg_register_aliases("arm64", 2) == ("x2", "w2")

    def test_unknown_arch_falls_back_to_x86_64(self) -> None:
        assert arg_register_aliases("sparc", 0) == arg_register_aliases("x86_64", 0)


class TestCwe78OnArm:
    def test_flags_nonconstant_x0(self) -> None:
        findings = cwe78.detect(arm64_system_vuln_session())
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == 78
        assert f.symbol == "system"
        assert f.function == "run_cmd"
        assert f.confidence == "medium"

    def test_constant_x0_not_flagged(self) -> None:
        assert cwe78.detect(arm64_system_constant_session()) == []

    def test_x86_64_still_works(self) -> None:
        # Regression: the default (x86_64) path is unchanged.
        findings = cwe78.detect(system_vuln_session())
        symbols = {f.symbol for f in findings}
        assert "system" in symbols


class TestCwe134OnArm:
    def test_flags_nonconstant_x0_printf(self) -> None:
        findings = cwe134.detect(arm64_printf_fmtstr_vuln_session())
        assert len(findings) == 1
        assert findings[0].symbol == "printf"
        assert findings[0].cwe == 134

    def test_constant_x0_printf_not_flagged(self) -> None:
        assert cwe134.detect(arm64_printf_constant_session()) == []

    def test_flags_nonconstant_x1_fprintf(self) -> None:
        # fprintf's format is the SECOND arg => x1 on ARM. The FILE* in x0 must
        # not be mistaken for the format argument.
        findings = cwe134.detect(arm64_fprintf_fmtstr_vuln_session())
        assert len(findings) == 1
        assert findings[0].symbol == "fprintf"


class TestRegisterAgnosticDetectorsOnArm:
    """CWE-120 and CWE-242 flag any call site, so they must work on ARM with no
    changes — these tests pin that behaviour."""

    def test_cwe120_flags_strcpy_on_arm(self) -> None:
        findings = cwe120.detect(arm64_strcpy_vuln_session())
        assert {f.symbol for f in findings} == {"strcpy"}

    def test_cwe242_flags_gets_on_arm(self) -> None:
        findings = cwe242.detect(arm64_gets_vuln_session())
        assert len(findings) == 1
        assert findings[0].symbol == "gets"
