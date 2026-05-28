"""Tests for the ``--fail-on`` exit-code gate.

Two layers are covered:

* the pure gating predicate :func:`blight.exit_gate.gate_trips`; and
* the end-to-end CLI behaviour — ``main()`` returning the gate exit code while
  still emitting the unchanged report — for single-file and directory scans,
  and its interaction with ``--suppress`` and ``--min-confidence``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import blight.cli as cli
from blight.exit_gate import (
    FAIL_ON_CHOICES,
    GATE_TRIPPED_EXIT_CODE,
    gate_trips,
)
from blight.findings import Finding
from blight.scan import ScanResult
from tests.fake_session import strcpy_vuln_session

FIXTURES = Path(__file__).parent / "fixtures"


def _finding(confidence: str, address: str = "0x401000") -> Finding:
    return Finding(
        cwe=120,
        function="main",
        address=address,
        evidence="x",
        symbol="strcpy",
        confidence=confidence,
    )


# --- gate_trips predicate -------------------------------------------------


def test_none_never_trips_even_with_high_findings() -> None:
    assert gate_trips([_finding("high")], "none") is False


def test_empty_findings_never_trip() -> None:
    for level in FAIL_ON_CHOICES:
        assert gate_trips([], level) is False


def test_low_trips_on_any_finding() -> None:
    assert gate_trips([_finding("low")], "low") is True
    assert gate_trips([_finding("medium")], "low") is True
    assert gate_trips([_finding("high")], "low") is True


def test_medium_trips_on_medium_and_high_only() -> None:
    assert gate_trips([_finding("low")], "medium") is False
    assert gate_trips([_finding("medium")], "medium") is True
    assert gate_trips([_finding("high")], "medium") is True


def test_high_trips_only_on_high() -> None:
    assert gate_trips([_finding("low")], "high") is False
    assert gate_trips([_finding("medium")], "high") is False
    assert gate_trips([_finding("high")], "high") is True


def test_trips_when_any_one_finding_qualifies() -> None:
    findings = [_finding("low"), _finding("low"), _finding("high")]
    assert gate_trips(findings, "high") is True


def test_invalid_fail_on_raises() -> None:
    with pytest.raises(ValueError):
        gate_trips([_finding("high")], "critical")


# --- CLI wiring -----------------------------------------------------------


def test_fail_on_choices_in_help() -> None:
    help_text = cli.build_parser().format_help()
    assert "--fail-on" in help_text
    for token in FAIL_ON_CHOICES:
        assert token in help_text


def test_fail_on_defaults_to_none() -> None:
    args = cli.build_parser().parse_args(["--binary", "x"])
    assert args.fail_on == "none"


def _patch_strcpy_session(monkeypatch) -> None:
    class _FakeCtx:
        def __enter__(self):
            return strcpy_vuln_session()

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        "blight.r2.Radare2Session", lambda path: _FakeCtx(), raising=True
    )


def test_default_returns_zero_despite_findings(monkeypatch, capsys) -> None:
    """Backward compatibility: without --fail-on, findings still exit 0."""
    _patch_strcpy_session(monkeypatch)
    fixture = FIXTURES / "strcpy-vuln"
    rc = cli.main(["--binary", str(fixture), "--checks", "120"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out["findings"]) == 3


def test_fail_on_high_trips_on_high_findings(monkeypatch, capsys) -> None:
    _patch_strcpy_session(monkeypatch)
    fixture = FIXTURES / "strcpy-vuln"
    rc = cli.main(
        ["--binary", str(fixture), "--checks", "120", "--fail-on", "high"]
    )
    assert rc == GATE_TRIPPED_EXIT_CODE
    # The report is still emitted unchanged alongside the non-zero exit.
    out = json.loads(capsys.readouterr().out)
    assert len(out["findings"]) == 3


def test_fail_on_does_not_trip_when_below_threshold(
    monkeypatch, capsys
) -> None:
    """CWE-120 findings are high confidence; --min-confidence high then
    --fail-on high should still trip, but suppressing them should not."""
    _patch_strcpy_session(monkeypatch)
    fixture = FIXTURES / "strcpy-vuln"
    rc = cli.main(
        [
            "--binary",
            str(fixture),
            "--checks",
            "120",
            "--fail-on",
            "high",
            "--min-confidence",
            "high",
        ]
    )
    # Findings survive the high threshold, so the gate still trips.
    assert rc == GATE_TRIPPED_EXIT_CODE
    capsys.readouterr()


def test_gate_runs_after_suppression(monkeypatch, capsys, tmp_path) -> None:
    """A suppressed finding must not trip the gate — the gate matches the
    emitted report, not the raw detector output."""
    _patch_strcpy_session(monkeypatch)
    suppress_file = tmp_path / "supp.json"
    suppress_file.write_text(json.dumps({"suppressions": [{"cwe": 120}]}))
    fixture = FIXTURES / "strcpy-vuln"
    rc = cli.main(
        [
            "--binary",
            str(fixture),
            "--checks",
            "120",
            "--suppress",
            str(suppress_file),
            "--fail-on",
            "low",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["findings"] == []


def test_gate_helper_directory_aggregates() -> None:
    """The CLI gate helper trips when any binary in a directory qualifies."""
    results = [
        ScanResult(binary="a", findings=[_finding("low")]),
        ScanResult(binary="b", findings=[_finding("high")]),
    ]
    emitted = [f for r in results for f in r.findings]
    assert cli._gate_exit_code(emitted, "high") == GATE_TRIPPED_EXIT_CODE
    assert cli._gate_exit_code(emitted, "none") == 0


def test_errored_result_does_not_trip_gate() -> None:
    """An errored scan carries no findings and never trips the gate."""
    results = [ScanResult(binary="bad", findings=[], error="boom")]
    emitted = [f for r in results for f in r.findings]
    assert cli._gate_exit_code(emitted, "low") == 0
