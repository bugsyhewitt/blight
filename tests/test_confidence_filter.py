"""Tests for the ``--min-confidence`` triage threshold filter.

Covers the ordering/threshold logic (`confidence_filter`), and the CLI wiring
for single-file and directory scans (including that it composes with
``--suppress`` and is a no-op at the default ``low`` threshold).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import blight.cli as cli
from blight.confidence_filter import (
    CONFIDENCE_CHOICES,
    filter_findings,
    meets_threshold,
)
from blight.findings import Finding

FIXTURES = Path(__file__).parent / "fixtures"


def _finding(confidence="high", cwe=120, symbol="strcpy", address="0x10"):
    return Finding(
        cwe=cwe,
        function="f",
        address=address,
        evidence="x",
        symbol=symbol,
        confidence=confidence,
    )


# --- ordering / threshold logic ------------------------------------------


def test_choices_are_ordered_weakest_to_strongest() -> None:
    assert CONFIDENCE_CHOICES == ("low", "medium", "high")


@pytest.mark.parametrize(
    "confidence,minimum,expected",
    [
        ("high", "high", True),
        ("medium", "high", False),
        ("low", "high", False),
        ("high", "medium", True),
        ("medium", "medium", True),
        ("low", "medium", False),
        ("high", "low", True),
        ("medium", "low", True),
        ("low", "low", True),
    ],
)
def test_meets_threshold(confidence, minimum, expected) -> None:
    assert meets_threshold(confidence, minimum) is expected


def test_meets_threshold_rejects_unknown_label() -> None:
    with pytest.raises(ValueError, match="confidence must be one of"):
        meets_threshold("bogus", "low")


def test_filter_low_is_identity_and_preserves_order() -> None:
    findings = [
        _finding("low", address="0x1"),
        _finding("high", address="0x2"),
        _finding("medium", address="0x3"),
    ]
    kept = filter_findings(findings, "low")
    assert kept == findings


def test_filter_medium_drops_low_only() -> None:
    findings = [_finding("low"), _finding("medium"), _finding("high")]
    kept = filter_findings(findings, "medium")
    assert [f.confidence for f in kept] == ["medium", "high"]


def test_filter_high_keeps_only_high() -> None:
    findings = [_finding("low"), _finding("medium"), _finding("high")]
    kept = filter_findings(findings, "high")
    assert [f.confidence for f in kept] == ["high"]


def test_filter_empty_input() -> None:
    assert filter_findings([], "high") == []


# --- CLI wiring ----------------------------------------------------------


def _mixed_findings():
    # Three findings, one per confidence level, stable addresses for ordering.
    return [
        _finding("low", cwe=476, symbol="malloc", address="0x10"),
        _finding("medium", cwe=78, symbol="system", address="0x20"),
        _finding("high", cwe=120, symbol="strcpy", address="0x30"),
    ]


def _patch_single_scan(monkeypatch, findings) -> None:
    from blight.scan import ScanResult

    def fake_scan_targets(paths, checks, *, workers=1, session_factory=None):
        return [ScanResult(binary=p, findings=list(findings)) for p in paths]

    monkeypatch.setattr(cli, "scan_targets", fake_scan_targets)


def test_cli_default_keeps_all_confidences(monkeypatch, capsys, tmp_path) -> None:
    _patch_single_scan(monkeypatch, _mixed_findings())
    fixture = tmp_path / "bin"
    fixture.write_bytes(b"\x7fELF")
    rc = cli.main(["--binary", str(fixture), "--checks", "all"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert sorted(f["confidence"] for f in out["findings"]) == [
        "high",
        "low",
        "medium",
    ]


def test_cli_min_confidence_high_single_file(monkeypatch, capsys, tmp_path) -> None:
    _patch_single_scan(monkeypatch, _mixed_findings())
    fixture = tmp_path / "bin"
    fixture.write_bytes(b"\x7fELF")
    rc = cli.main(
        ["--binary", str(fixture), "--checks", "all", "--min-confidence", "high"]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert [f["confidence"] for f in out["findings"]] == ["high"]
    assert [f["symbol"] for f in out["findings"]] == ["strcpy"]


def test_cli_min_confidence_medium_single_file(
    monkeypatch, capsys, tmp_path
) -> None:
    _patch_single_scan(monkeypatch, _mixed_findings())
    fixture = tmp_path / "bin"
    fixture.write_bytes(b"\x7fELF")
    rc = cli.main(
        ["--binary", str(fixture), "--checks", "all", "--min-confidence", "medium"]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert sorted(f["confidence"] for f in out["findings"]) == ["high", "medium"]


def test_cli_min_confidence_directory(monkeypatch, capsys, tmp_path) -> None:
    from blight.scan import ScanResult

    bin_dir = tmp_path / "bins"
    bin_dir.mkdir()
    (bin_dir / "a").write_bytes(b"\x7fELF")
    (bin_dir / "b").write_bytes(b"\x7fELF")

    def fake_scan_targets(paths, checks, *, workers=1, session_factory=None):
        return [
            ScanResult(binary=p, findings=_mixed_findings()) for p in paths
        ]

    monkeypatch.setattr(cli, "scan_targets", fake_scan_targets)

    rc = cli.main(
        ["--binary", str(bin_dir), "--checks", "all", "--min-confidence", "high"]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out["results"]) == 2
    for result in out["results"]:
        assert [f["confidence"] for f in result["findings"]] == ["high"]


def test_cli_min_confidence_composes_with_suppress(
    monkeypatch, capsys, tmp_path
) -> None:
    # strcpy is the only HIGH finding; suppress it, then ask for high-only:
    # nothing should remain.
    _patch_single_scan(monkeypatch, _mixed_findings())
    supp = tmp_path / "supp.json"
    supp.write_text(
        json.dumps({"suppressions": [{"cwe": 120, "symbol": "strcpy"}]})
    )
    fixture = tmp_path / "bin"
    fixture.write_bytes(b"\x7fELF")
    rc = cli.main(
        [
            "--binary",
            str(fixture),
            "--checks",
            "all",
            "--suppress",
            str(supp),
            "--min-confidence",
            "high",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["findings"] == []


def test_cli_rejects_invalid_min_confidence(monkeypatch, tmp_path) -> None:
    fixture = tmp_path / "bin"
    fixture.write_bytes(b"\x7fELF")
    with pytest.raises(SystemExit):
        cli.main(
            ["--binary", str(fixture), "--checks", "all", "--min-confidence", "huge"]
        )


def test_cli_min_confidence_preserves_error_results(
    monkeypatch, capsys, tmp_path
) -> None:
    # A result that errored carries no findings; the filter must leave the
    # error field intact.
    from blight.scan import ScanResult

    bin_dir = tmp_path / "bins"
    bin_dir.mkdir()
    (bin_dir / "a").write_bytes(b"\x7fELF")

    def fake_scan_targets(paths, checks, *, workers=1, session_factory=None):
        return [
            ScanResult(binary=p, findings=[], error="OSError: boom")
            for p in paths
        ]

    monkeypatch.setattr(cli, "scan_targets", fake_scan_targets)

    rc = cli.main(
        ["--binary", str(bin_dir), "--checks", "all", "--min-confidence", "high"]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["results"][0]["error"] == "OSError: boom"
    assert out["results"][0]["findings"] == []
