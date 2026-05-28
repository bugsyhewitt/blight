"""Tests for confidence scoring on findings (POST_V01 item 4).

Confidence policy:
  - CWE-120 / CWE-242: ``high``  — the dangerous symbol IS the finding; no
    data-flow inference is involved.
  - CWE-78 / CWE-134:  ``medium`` — the non-constant heuristic can miss aliased
    registers, so the finding is plausible but not certain.
  - CWE-676:           mirrors the per-symbol severity (HIGH→high, MEDIUM→
    medium, LOW→low).

These tests are fully mocked — no radare2 required.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from binary_finding_schema import CONFIDENCE_LEVELS, BinaryFinding

import blight.cli as cli
from blight.detectors import cwe78, cwe120, cwe134, cwe242, cwe676
from blight.findings import Finding
from blight.formatters.sarif import build_sarif
from blight.pipeline_adapter import _to_binary_finding
from tests.fake_session import (
    asctime_vuln_session,
    cwe676_all_session,
    fprintf_fmtstr_vuln_session,
    gets_vuln_session,
    printf_fmtstr_vuln_session,
    rand_vuln_session,
    snprintf_fmtstr_vuln_session,
    strcpy_vuln_session,
    strtok_vuln_session,
    system_vuln_session,
    tmpnam_vuln_session,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Finding model carries confidence
# ---------------------------------------------------------------------------


class TestFindingModel:
    def test_default_confidence_is_medium(self) -> None:
        f = Finding(cwe=120, function="fn", address="0x401000",
                    evidence="e", symbol="strcpy")
        assert f.confidence == "medium"

    def test_explicit_confidence_round_trips(self) -> None:
        for level in CONFIDENCE_LEVELS:
            f = Finding(cwe=120, function="fn", address="0x401000",
                        evidence="e", symbol="strcpy", confidence=level)
            assert f.confidence == level

    def test_invalid_confidence_rejected(self) -> None:
        with pytest.raises(ValueError):
            Finding(cwe=120, function="fn", address="0x401000",
                    evidence="e", symbol="strcpy", confidence="critical")

    def test_to_dict_includes_confidence(self) -> None:
        f = Finding(cwe=120, function="fn", address="0x401000",
                    evidence="e", symbol="strcpy", confidence="high")
        d = f.to_dict()
        assert d["confidence"] == "high"
        assert set(d) == {"cwe", "function", "address", "evidence", "symbol", "confidence"}

    def test_confidence_participates_in_equality(self) -> None:
        a = Finding(cwe=120, function="fn", address="0x401000",
                    evidence="e", symbol="strcpy", confidence="high")
        b = Finding(cwe=120, function="fn", address="0x401000",
                    evidence="e", symbol="strcpy", confidence="low")
        assert a != b
        assert hash(a) != hash(b)


# ---------------------------------------------------------------------------
# Detector confidence assignment
# ---------------------------------------------------------------------------


class TestDetectorConfidence:
    def test_cwe120_is_high(self) -> None:
        findings = cwe120.detect(strcpy_vuln_session())
        assert findings
        assert all(f.confidence == "high" for f in findings)

    def test_cwe242_is_high(self) -> None:
        findings = cwe242.detect(gets_vuln_session())
        assert findings
        assert all(f.confidence == "high" for f in findings)

    def test_cwe78_is_medium(self) -> None:
        findings = [f for f in cwe78.detect(system_vuln_session()) if f.symbol == "system"]
        assert findings
        assert all(f.confidence == "medium" for f in findings)

    def test_cwe134_is_medium(self) -> None:
        for session in (
            printf_fmtstr_vuln_session(),
            fprintf_fmtstr_vuln_session(),
            snprintf_fmtstr_vuln_session(),
        ):
            findings = cwe134.detect(session)
            assert findings
            assert all(f.confidence == "medium" for f in findings)

    def test_cwe676_high_severity_is_high(self) -> None:
        findings = cwe676.detect(tmpnam_vuln_session())  # HIGH severity
        assert findings
        assert all(f.confidence == "high" for f in findings)

    def test_cwe676_medium_severity_is_medium(self) -> None:
        for session in (strtok_vuln_session(), rand_vuln_session()):  # MEDIUM
            findings = cwe676.detect(session)
            assert findings
            assert all(f.confidence == "medium" for f in findings)

    def test_cwe676_low_severity_is_low(self) -> None:
        findings = cwe676.detect(asctime_vuln_session())  # LOW severity
        assert findings
        assert all(f.confidence == "low" for f in findings)

    def test_cwe676_mixed_session_maps_each_severity(self) -> None:
        findings = cwe676.detect(cwe676_all_session())
        by_symbol = {f.symbol: f.confidence for f in findings}
        assert by_symbol["tmpnam"] == "high"
        assert by_symbol["mktemp"] == "high"
        assert by_symbol["strtok"] == "medium"
        assert by_symbol["rand"] == "medium"
        assert by_symbol["asctime"] == "low"
        assert by_symbol["ctime"] == "low"


# ---------------------------------------------------------------------------
# Confidence propagates through the output layers
# ---------------------------------------------------------------------------


class TestConfidencePropagation:
    def test_pipeline_adapter_preserves_confidence(self) -> None:
        f = Finding(cwe=78, function="run_cmd", address="0x40118f",
                    evidence="e", symbol="system", confidence="medium")
        bf = _to_binary_finding(f)
        assert isinstance(bf, BinaryFinding)
        assert bf.confidence == "medium"

    def test_sarif_result_carries_confidence(self) -> None:
        f = Finding(cwe=120, function="fn", address="0x401000",
                    evidence="e", symbol="strcpy", confidence="high")
        result = build_sarif("b", [f])["runs"][0]["results"][0]
        assert result["properties"]["confidence"] == "high"

    def test_cli_json_includes_confidence(self, monkeypatch, capsys) -> None:
        class _FakeCtx:
            def __enter__(self):
                return strcpy_vuln_session()

            def __exit__(self, *exc):
                return False

        monkeypatch.setattr(
            "blight.r2.Radare2Session", lambda path: _FakeCtx(), raising=True
        )
        fixture = FIXTURES / "strcpy-vuln"
        cli.main(["--binary", str(fixture), "--checks", "120", "--format", "json"])
        out = json.loads(capsys.readouterr().out)
        assert all(f["confidence"] == "high" for f in out["findings"])
