"""Tests for the SARIF 2.1.0 output formatter and --format sarif CLI flag."""

from __future__ import annotations

import json

import pytest

import blight.cli as cli
from blight.findings import Finding
from blight.formatters.sarif import build_sarif, dump_sarif, _level_for_cwe
from tests.fake_session import strcpy_vuln_session


# ---------------------------------------------------------------------------
# Unit tests for build_sarif()
# ---------------------------------------------------------------------------

def _make_finding(cwe: int, symbol: str = "strcpy", function: str = "fn") -> Finding:
    return Finding(
        cwe=cwe,
        function=function,
        address="0x401000",
        evidence=f"call to {symbol}",
        symbol=symbol,
    )


class TestSarifStructure:
    """Verify the top-level SARIF 2.1.0 structure."""

    def test_schema_field(self):
        doc = build_sarif("mybinary", [])
        assert doc["$schema"].startswith("https://docs.oasis-open.org/sarif/")

    def test_version_field(self):
        doc = build_sarif("mybinary", [])
        assert doc["version"] == "2.1.0"

    def test_runs_is_list(self):
        doc = build_sarif("mybinary", [])
        assert isinstance(doc["runs"], list)
        assert len(doc["runs"]) == 1

    def test_tool_driver_name(self):
        run = build_sarif("mybinary", [])["runs"][0]
        assert run["tool"]["driver"]["name"] == "blight"

    def test_tool_driver_version(self):
        run = build_sarif("mybinary", [], version="1.2.3")["runs"][0]
        assert run["tool"]["driver"]["version"] == "1.2.3"

    def test_tool_driver_information_uri(self):
        run = build_sarif("mybinary", [])["runs"][0]
        assert "github.com/bugsyhewitt/blight" in run["tool"]["driver"]["informationUri"]

    def test_empty_findings_empty_results(self):
        run = build_sarif("mybinary", [])["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []


class TestSarifRules:
    """Verify rule deduplication and fields."""

    def test_single_cwe_produces_one_rule(self):
        findings = [_make_finding(120), _make_finding(120, "sprintf", "other")]
        rules = build_sarif("b", findings)["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "CWE-120"

    def test_multiple_cwes_produce_multiple_rules(self):
        findings = [_make_finding(120), _make_finding(78, "system", "cmd")]
        rules = build_sarif("b", findings)["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert rule_ids == {"CWE-120", "CWE-78"}

    def test_rule_has_short_description(self):
        findings = [_make_finding(120)]
        rules = build_sarif("b", findings)["runs"][0]["tool"]["driver"]["rules"]
        assert "text" in rules[0]["shortDescription"]
        assert rules[0]["shortDescription"]["text"] != ""

    def test_rule_has_help_uri(self):
        findings = [_make_finding(120)]
        rules = build_sarif("b", findings)["runs"][0]["tool"]["driver"]["rules"]
        assert "cwe.mitre.org" in rules[0]["helpUri"]


class TestSarifResults:
    """Verify individual result shape and field mapping."""

    def test_result_rule_id(self):
        findings = [_make_finding(120)]
        result = build_sarif("b", findings)["runs"][0]["results"][0]
        assert result["ruleId"] == "CWE-120"

    def test_result_message_text(self):
        findings = [_make_finding(120)]
        result = build_sarif("b", findings)["runs"][0]["results"][0]
        assert result["message"]["text"] == "call to strcpy"

    def test_result_locations_artifact_uri(self):
        findings = [_make_finding(120)]
        result = build_sarif("b", findings)["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]["artifactLocation"]
        assert loc["uri"] == "b"

    def test_result_logical_location_function(self):
        findings = [_make_finding(120, function="my_func")]
        result = build_sarif("b", findings)["runs"][0]["results"][0]
        logical = result["locations"][0]["physicalLocation"]["logicalLocations"]
        assert any(ll["name"] == "my_func" for ll in logical)

    def test_result_properties_address_and_symbol(self):
        findings = [_make_finding(120)]
        result = build_sarif("b", findings)["runs"][0]["results"][0]
        assert result["properties"]["address"] == "0x401000"
        assert result["properties"]["symbol"] == "strcpy"


class TestSarifLevelMapping:
    """Verify severity-to-SARIF-level mapping."""

    @pytest.mark.parametrize("cwe,expected", [
        (78,  "error"),
        (120, "error"),
        (134, "error"),
        (242, "warning"),
        (676, "warning"),
        (999, "note"),    # unknown CWE defaults to note
    ])
    def test_level_mapping(self, cwe, expected):
        assert _level_for_cwe(cwe) == expected

    def test_error_level_in_result(self):
        findings = [_make_finding(120)]
        result = build_sarif("b", findings)["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_warning_level_in_result(self):
        findings = [_make_finding(676, "tmpnam", "make_path")]
        result = build_sarif("b", findings)["runs"][0]["results"][0]
        assert result["level"] == "warning"


class TestDumpSarif:
    """Verify dump_sarif() returns valid JSON."""

    def test_returns_valid_json_string(self):
        findings = [_make_finding(120)]
        text = dump_sarif("mybinary", findings)
        doc = json.loads(text)
        assert doc["version"] == "2.1.0"

    def test_round_trip(self):
        findings = [_make_finding(120), _make_finding(78, "system", "cmd")]
        doc = json.loads(dump_sarif("path/to/bin", findings))
        results = doc["runs"][0]["results"]
        assert len(results) == 2


# ---------------------------------------------------------------------------
# CLI integration tests for --format sarif
# ---------------------------------------------------------------------------

class TestCLISarif:
    """Verify --format sarif wires through the CLI correctly."""

    def _make_fake_ctx(self):
        class _FakeCtx:
            def __enter__(self):
                return strcpy_vuln_session()

            def __exit__(self, *exc):
                return False

        return _FakeCtx()

    def test_sarif_is_valid_choice(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--binary", "x", "--format", "sarif"])
        assert args.format == "sarif"

    def test_sarif_output_is_valid_json(self, monkeypatch, capsys, tmp_path):
        fake_binary = tmp_path / "fake_elf"
        fake_binary.write_bytes(b"\x7fELF")

        monkeypatch.setattr(
            "blight.r2.Radare2Session",
            lambda path: self._make_fake_ctx(),
            raising=True,
        )

        rc = cli.main(["--binary", str(fake_binary), "--checks", "120", "--format", "sarif"])
        assert rc == 0
        out = capsys.readouterr().out
        doc = json.loads(out)
        assert doc["version"] == "2.1.0"

    def test_sarif_output_has_correct_structure(self, monkeypatch, capsys, tmp_path):
        fake_binary = tmp_path / "fake_elf"
        fake_binary.write_bytes(b"\x7fELF")

        monkeypatch.setattr(
            "blight.r2.Radare2Session",
            lambda path: self._make_fake_ctx(),
            raising=True,
        )

        cli.main(["--binary", str(fake_binary), "--checks", "120", "--format", "sarif"])
        doc = json.loads(capsys.readouterr().out)

        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "blight"
        assert len(run["results"]) == 3   # strcpy_vuln_session has 3 CWE-120 findings
        assert len(run["tool"]["driver"]["rules"]) == 1   # all same CWE → 1 rule

    def test_sarif_results_all_have_error_level(self, monkeypatch, capsys, tmp_path):
        fake_binary = tmp_path / "fake_elf"
        fake_binary.write_bytes(b"\x7fELF")

        monkeypatch.setattr(
            "blight.r2.Radare2Session",
            lambda path: self._make_fake_ctx(),
            raising=True,
        )

        cli.main(["--binary", str(fake_binary), "--checks", "120", "--format", "sarif"])
        doc = json.loads(capsys.readouterr().out)

        for result in doc["runs"][0]["results"]:
            assert result["level"] == "error"

    def test_json_format_still_works(self, monkeypatch, capsys, tmp_path):
        """Regression: existing --format json must not be broken."""
        fake_binary = tmp_path / "fake_elf"
        fake_binary.write_bytes(b"\x7fELF")

        monkeypatch.setattr(
            "blight.r2.Radare2Session",
            lambda path: self._make_fake_ctx(),
            raising=True,
        )

        rc = cli.main(["--binary", str(fake_binary), "--checks", "120", "--format", "json"])
        assert rc == 0
        doc = json.loads(capsys.readouterr().out)
        assert "findings" in doc
        assert doc["checks"] == [120]
