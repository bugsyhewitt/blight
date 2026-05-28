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
    assert cli._resolve_checks("all") == [78, 120, 134, 242, 676]


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
