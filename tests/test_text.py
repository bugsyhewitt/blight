"""Tests for the human-readable text output formatter and --format text CLI flag."""

from __future__ import annotations

import blight.cli as cli
from blight.findings import Finding
from blight.formatters.text import (
    _confidence_breakdown,
    _cwe_summary,
    dump_text_directory,
    dump_text_single,
)
from blight.scan import ScanResult
from tests.fake_session import (
    clean_baseline_session,
    strcpy_vuln_session,
    system_vuln_session,
)


def _finding(
    cwe: int,
    symbol: str = "strcpy",
    function: str = "fn",
    address: str = "0x401000",
    confidence: str = "high",
) -> Finding:
    return Finding(
        cwe=cwe,
        function=function,
        address=address,
        evidence=f"call to {symbol}",
        symbol=symbol,
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Unit tests for the helper functions
# ---------------------------------------------------------------------------


class TestConfidenceBreakdown:
    def test_counts_in_high_medium_low_order(self):
        findings = [
            _finding(120, confidence="high"),
            _finding(78, confidence="medium"),
            _finding(476, confidence="low"),
            _finding(252, confidence="low"),
        ]
        assert _confidence_breakdown(findings) == "high: 1, medium: 1, low: 2"

    def test_empty_is_all_zero(self):
        assert _confidence_breakdown([]) == "high: 0, medium: 0, low: 0"


class TestCweSummary:
    def test_orders_by_count_desc_then_cwe_asc(self):
        findings = [
            _finding(78, "system"),
            _finding(120, "strcpy"),
            _finding(120, "sprintf"),
            _finding(120, "gets"),
        ]
        # CWE-120 has 3, CWE-78 has 1 → 120 first
        assert _cwe_summary(findings) == "CWE-120 x3, CWE-78 x1"

    def test_ties_break_on_cwe_id(self):
        findings = [_finding(120), _finding(78, "system")]
        assert _cwe_summary(findings) == "CWE-78 x1, CWE-120 x1"


# ---------------------------------------------------------------------------
# dump_text_single()
# ---------------------------------------------------------------------------


class TestDumpTextSingle:
    def test_header_includes_binary_and_checks(self):
        out = dump_text_single("path/to/elf", [78, 120], [])
        lines = out.splitlines()
        assert lines[0] == "binary: path/to/elf"
        assert lines[1] == "checks: 78, 120"

    def test_clean_binary_says_no_findings(self):
        out = dump_text_single("clean", [120], [])
        assert "no findings" in out
        # No summary line for a clean binary.
        assert "summary:" not in out

    def test_finding_count_and_breakdown_line(self):
        findings = [_finding(120, confidence="high")]
        out = dump_text_single("b", [120], findings)
        assert "1 finding (high: 1, medium: 0, low: 0)" in out

    def test_plural_findings(self):
        findings = [_finding(120), _finding(120, "sprintf")]
        out = dump_text_single("b", [120], findings)
        assert "2 findings" in out

    def test_finding_body_groups_by_function(self):
        findings = [
            _finding(120, "strcpy", function="copy_it", address="0x401170"),
            _finding(120, "sprintf", function="copy_it", address="0x401180"),
        ]
        out = dump_text_single("b", [120], findings)
        # One function header for two findings under the same function.
        assert out.count("function copy_it") == 1
        assert "[high] CWE-120 strcpy @ 0x401170" in out
        assert "[high] CWE-120 sprintf @ 0x401180" in out

    def test_distinct_functions_get_distinct_headers(self):
        findings = [
            _finding(120, "strcpy", function="a"),
            _finding(78, "system", function="b", confidence="medium"),
        ]
        out = dump_text_single("b", [78, 120], findings)
        assert "function a" in out
        assert "function b" in out

    def test_evidence_is_rendered(self):
        findings = [_finding(120, "strcpy")]
        out = dump_text_single("b", [120], findings)
        assert "call to strcpy" in out

    def test_summary_line_present(self):
        findings = [_finding(120), _finding(120, "sprintf")]
        out = dump_text_single("b", [120], findings)
        assert "summary: CWE-120 x2" in out


# ---------------------------------------------------------------------------
# dump_text_directory()
# ---------------------------------------------------------------------------


class TestDumpTextDirectory:
    def test_directory_header_and_total(self):
        results = [
            ScanResult(binary="dir/a", findings=[_finding(120)]),
            ScanResult(binary="dir/b", findings=[]),
        ]
        out = dump_text_directory("dir", [120], results)
        lines = out.splitlines()
        assert lines[0] == "directory: dir"
        assert lines[1] == "checks: 120"
        assert "total: 1 finding across 2 binaries" in out

    def test_each_binary_block_present(self):
        results = [
            ScanResult(binary="dir/a", findings=[_finding(120)]),
            ScanResult(binary="dir/b", findings=[]),
        ]
        out = dump_text_directory("dir", [120], results)
        assert "binary: dir/a" in out
        assert "binary: dir/b" in out
        assert "no findings" in out

    def test_errored_binary_shows_error_not_findings(self):
        results = [
            ScanResult(binary="dir/bad", findings=[], error="OSError: nope"),
        ]
        out = dump_text_directory("dir", [120], results)
        assert "error: OSError: nope" in out
        assert "no findings" not in out

    def test_total_singular_binary(self):
        results = [ScanResult(binary="dir/a", findings=[])]
        out = dump_text_directory("dir", [120], results)
        assert "across 1 binary" in out


# ---------------------------------------------------------------------------
# CLI integration tests for --format text
# ---------------------------------------------------------------------------


def _fake_ctx(session_fn):
    class _FakeCtx:
        def __enter__(self):
            return session_fn()

        def __exit__(self, *exc):
            return False

    return _FakeCtx()


class TestCLIText:
    def test_text_is_valid_choice(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--binary", "x", "--format", "text"])
        assert args.format == "text"

    def test_single_binary_text_output(self, monkeypatch, capsys, tmp_path):
        fake_binary = tmp_path / "fake_elf"
        fake_binary.write_bytes(b"\x7fELF")
        monkeypatch.setattr(
            "blight.r2.Radare2Session",
            lambda path: _fake_ctx(strcpy_vuln_session),
            raising=True,
        )

        rc = cli.main(
            ["--binary", str(fake_binary), "--checks", "120", "--format", "text"]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert out.startswith(f"binary: {fake_binary}")
        # strcpy_vuln_session yields 3 CWE-120 findings.
        assert "3 findings" in out
        assert "summary: CWE-120 x3" in out

    def test_clean_binary_text_output(self, monkeypatch, capsys, tmp_path):
        fake_binary = tmp_path / "clean_elf"
        fake_binary.write_bytes(b"\x7fELF")
        monkeypatch.setattr(
            "blight.r2.Radare2Session",
            lambda path: _fake_ctx(clean_baseline_session),
            raising=True,
        )

        rc = cli.main(
            ["--binary", str(fake_binary), "--checks", "all", "--format", "text"]
        )
        assert rc == 0
        assert "no findings" in capsys.readouterr().out

    def test_directory_text_output(self, monkeypatch, capsys, tmp_path):
        d = tmp_path / "bins"
        d.mkdir()
        (d / "a").write_bytes(b"\x7fELF")
        (d / "b").write_bytes(b"\x7fELF")
        monkeypatch.setattr(
            "blight.r2.Radare2Session",
            lambda path: _fake_ctx(system_vuln_session),
            raising=True,
        )

        rc = cli.main(
            ["--binary", str(d), "--checks", "78", "--format", "text"]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert out.startswith(f"directory: {d}")
        assert "across 2 binaries" in out

    def test_min_confidence_composes_with_text(self, monkeypatch, capsys, tmp_path):
        """The text gate sees the same filtered findings as json/sarif."""
        fake_binary = tmp_path / "fake_elf"
        fake_binary.write_bytes(b"\x7fELF")
        # system_vuln yields a medium-confidence CWE-78 finding; filtering to
        # high should drop it, leaving a clean text report.
        monkeypatch.setattr(
            "blight.r2.Radare2Session",
            lambda path: _fake_ctx(system_vuln_session),
            raising=True,
        )

        cli.main(
            [
                "--binary",
                str(fake_binary),
                "--checks",
                "78",
                "--format",
                "text",
                "--min-confidence",
                "high",
            ]
        )
        assert "no findings" in capsys.readouterr().out

    def test_json_format_still_works(self, monkeypatch, capsys, tmp_path):
        """Regression: --format json must be unaffected by the text addition."""
        import json

        fake_binary = tmp_path / "fake_elf"
        fake_binary.write_bytes(b"\x7fELF")
        monkeypatch.setattr(
            "blight.r2.Radare2Session",
            lambda path: _fake_ctx(strcpy_vuln_session),
            raising=True,
        )

        rc = cli.main(
            ["--binary", str(fake_binary), "--checks", "120", "--format", "json"]
        )
        assert rc == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc["checks"] == [120]
        assert len(doc["findings"]) == 3
