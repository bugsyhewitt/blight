"""Unit tests for blight detectors — fully mocked, no radare2 required."""

from __future__ import annotations

from blight.detectors import cwe78, cwe120, cwe242
from tests.fake_session import (
    clean_baseline_session,
    gets_vuln_session,
    strcpy_vuln_session,
    system_constant_session,
    system_vuln_session,
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
