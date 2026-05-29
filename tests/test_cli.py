"""Unit tests for the blight CLI — argument parsing and output shape.

The radare2-backed path is patched out so these run without radare2.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import blight.cli as cli
from tests.fake_session import strcpy_vuln_session

FIXTURES = Path(__file__).parent / "fixtures"


def test_help_lists_required_options(capsys) -> None:
    parser = cli.build_parser()
    help_text = parser.format_help()
    assert "--binary" in help_text
    assert "--checks" in help_text
    assert "--format" in help_text
    # --checks must offer 78, 120, 242, all
    for token in ("78", "120", "242", "all"):
        assert token in help_text


def test_checks_choices() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["--binary", "x", "--checks", "120", "--format", "json"])
    assert args.checks == "120"
    assert args.format == "json"


def test_resolve_all() -> None:
    assert cli._resolve_checks("all") == [
        22,
        78,
        89,
        119,
        120,
        134,
        242,
        252,
        295,
        327,
        426,
        476,
        676,
        798,
    ]


def test_resolve_single() -> None:
    assert cli._resolve_checks("242") == [242]


def test_missing_binary_errors() -> None:
    with pytest.raises(SystemExit):
        cli.main(["--binary", "/nonexistent/path/xyz", "--checks", "120"])


def test_main_emits_json(monkeypatch, capsys) -> None:
    # Patch the radare2 session out: main() opens Radare2Session; we replace it
    # with a context manager yielding our fake.
    class _FakeCtx:
        def __enter__(self):
            return strcpy_vuln_session()

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        "blight.r2.Radare2Session", lambda path: _FakeCtx(), raising=True
    )

    fixture = FIXTURES / "strcpy-vuln"
    rc = cli.main(["--binary", str(fixture), "--checks", "120", "--format", "json"])
    assert rc == 0

    out = json.loads(capsys.readouterr().out)
    assert out["checks"] == [120]
    assert len(out["findings"]) == 3
    f = out["findings"][0]
    assert set(f) == {"cwe", "function", "address", "evidence", "symbol", "confidence"}
    assert f["cwe"] == 120
    # CWE-120 findings are high confidence (the symbol IS the finding).
    assert f["confidence"] == "high"


def _patch_strcpy_session(monkeypatch) -> None:
    """Patch Radare2Session to yield the strcpy fake (no radare2 needed)."""

    class _FakeCtx:
        def __enter__(self):
            return strcpy_vuln_session()

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        "blight.r2.Radare2Session", lambda path: _FakeCtx(), raising=True
    )


def test_output_file_flag_in_help() -> None:
    parser = cli.build_parser()
    help_text = parser.format_help()
    assert "--output-file" in help_text


def test_output_file_default_is_none() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["--binary", "x", "--checks", "120"])
    assert args.output_file is None


def test_output_file_short_flag() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["--binary", "x", "-o", "report.json"])
    assert args.output_file == "report.json"


def test_output_file_writes_json_and_silences_stdout(
    monkeypatch, capsys, tmp_path
) -> None:
    _patch_strcpy_session(monkeypatch)
    out_path = tmp_path / "report.json"
    fixture = FIXTURES / "strcpy-vuln"

    rc = cli.main(
        [
            "--binary",
            str(fixture),
            "--checks",
            "120",
            "--format",
            "json",
            "--output-file",
            str(out_path),
        ]
    )
    assert rc == 0

    # Nothing leaked to stdout when writing to a file.
    assert capsys.readouterr().out == ""

    # The file holds exactly the JSON report, terminated by one newline.
    text = out_path.read_text(encoding="utf-8")
    assert text.endswith("\n")
    out = json.loads(text)
    assert out["checks"] == [120]
    assert len(out["findings"]) == 3


def test_output_file_matches_stdout_byte_for_byte(
    monkeypatch, capsys, tmp_path
) -> None:
    _patch_strcpy_session(monkeypatch)
    fixture = FIXTURES / "strcpy-vuln"
    argv = ["--binary", str(fixture), "--checks", "120", "--format", "json"]

    cli.main(argv)
    stdout_text = capsys.readouterr().out

    _patch_strcpy_session(monkeypatch)
    out_path = tmp_path / "report.json"
    cli.main(argv + ["--output-file", str(out_path)])
    file_text = out_path.read_text(encoding="utf-8")

    assert file_text == stdout_text


def test_output_file_writes_sarif(monkeypatch, capsys, tmp_path) -> None:
    _patch_strcpy_session(monkeypatch)
    out_path = tmp_path / "report.sarif"
    fixture = FIXTURES / "strcpy-vuln"

    rc = cli.main(
        [
            "--binary",
            str(fixture),
            "--checks",
            "120",
            "--format",
            "sarif",
            "-o",
            str(out_path),
        ]
    )
    assert rc == 0
    assert capsys.readouterr().out == ""

    doc = json.loads(out_path.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"


def test_output_file_dash_forces_stdout(monkeypatch, capsys) -> None:
    _patch_strcpy_session(monkeypatch)
    fixture = FIXTURES / "strcpy-vuln"

    rc = cli.main(
        ["--binary", str(fixture), "--checks", "120", "-o", "-"]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["checks"] == [120]


def test_output_file_does_not_affect_fail_on_exit(
    monkeypatch, capsys, tmp_path
) -> None:
    _patch_strcpy_session(monkeypatch)
    out_path = tmp_path / "report.json"
    fixture = FIXTURES / "strcpy-vuln"

    rc = cli.main(
        [
            "--binary",
            str(fixture),
            "--checks",
            "120",
            "--fail-on",
            "high",
            "--output-file",
            str(out_path),
        ]
    )
    # The gate still trips on the high-confidence CWE-120 findings even though
    # the report went to a file rather than stdout.
    assert rc == cli.GATE_TRIPPED_EXIT_CODE
    assert capsys.readouterr().out == ""
    assert out_path.exists()


def test_output_file_unwritable_path_errors(monkeypatch) -> None:
    _patch_strcpy_session(monkeypatch)
    fixture = FIXTURES / "strcpy-vuln"
    # A path whose parent directory does not exist cannot be created.
    bad_path = FIXTURES / "no_such_dir" / "report.json"

    with pytest.raises(SystemExit):
        cli.main(
            [
                "--binary",
                str(fixture),
                "--checks",
                "120",
                "--output-file",
                str(bad_path),
            ]
        )


def test_directory_scan_writes_to_file(monkeypatch, capsys, tmp_path) -> None:
    _patch_strcpy_session(monkeypatch)
    # A directory containing one binary fixture copy.
    scan_dir = tmp_path / "bins"
    scan_dir.mkdir()
    (scan_dir / "a.bin").write_bytes((FIXTURES / "strcpy-vuln").read_bytes())

    out_path = tmp_path / "dir-report.json"
    rc = cli.main(
        [
            "--binary",
            str(scan_dir),
            "--checks",
            "120",
            "--output-file",
            str(out_path),
        ]
    )
    assert rc == 0
    assert capsys.readouterr().out == ""
    out = json.loads(out_path.read_text(encoding="utf-8"))
    assert out["directory"] == str(scan_dir)
    assert "results" in out
