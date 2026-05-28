"""Tests for the ``--suppress`` known-false-positive filter.

Covers the parser (schema validation, ergonomic input forms), the matching
semantics (AND of present constraints, omitted = wildcard, address
normalization), and the CLI wiring (single-file and directory scans, error
surfacing for a malformed file).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import blight.cli as cli
from blight.findings import Finding
from blight.suppressions import (
    Suppression,
    SuppressionError,
    SuppressionSet,
    load_suppressions,
    parse_suppressions,
)
from tests.fake_session import strcpy_vuln_session

FIXTURES = Path(__file__).parent / "fixtures"


def _finding(cwe=120, function="copy_it", address="0x40114a", symbol="strcpy"):
    return Finding(
        cwe=cwe,
        function=function,
        address=address,
        evidence="x",
        symbol=symbol,
        confidence="high",
    )


# --- parser --------------------------------------------------------------


def test_empty_document_yields_no_rules() -> None:
    s = parse_suppressions("{}")
    assert not s
    assert s.rules == ()


def test_empty_suppressions_list() -> None:
    s = parse_suppressions(json.dumps({"suppressions": []}))
    assert not s


def test_parse_single_rule() -> None:
    s = parse_suppressions(
        json.dumps({"suppressions": [{"cwe": 120, "symbol": "strcpy"}]})
    )
    assert s.rules == (Suppression(cwe=120, symbol="strcpy"),)


def test_cwe_accepts_string_and_cwe_prefix() -> None:
    s = parse_suppressions(
        json.dumps({"suppressions": [{"cwe": "120"}, {"cwe": "CWE-78"}]})
    )
    assert [r.cwe for r in s.rules] == [120, 78]


def test_reason_and_comment_keys_are_ignored() -> None:
    s = parse_suppressions(
        json.dumps(
            {
                "//": "top comment",
                "suppressions": [
                    {"cwe": 120, "reason": "audited", "//": "see ticket 99"}
                ],
            }
        )
    )
    assert s.rules == (Suppression(cwe=120),)


def test_missing_cwe_is_error() -> None:
    with pytest.raises(SuppressionError, match="missing required key 'cwe'"):
        parse_suppressions(json.dumps({"suppressions": [{"symbol": "strcpy"}]}))


def test_unknown_key_is_error() -> None:
    with pytest.raises(SuppressionError, match="unknown key"):
        parse_suppressions(json.dumps({"suppressions": [{"cwe": 120, "fnuction": "x"}]}))


def test_non_numeric_cwe_is_error() -> None:
    with pytest.raises(SuppressionError, match="non-numeric cwe"):
        parse_suppressions(json.dumps({"suppressions": [{"cwe": "abc"}]}))


def test_bool_cwe_is_error() -> None:
    with pytest.raises(SuppressionError, match="must be an integer"):
        parse_suppressions(json.dumps({"suppressions": [{"cwe": True}]}))


def test_non_string_constraint_is_error() -> None:
    with pytest.raises(SuppressionError, match="must be a string"):
        parse_suppressions(json.dumps({"suppressions": [{"cwe": 120, "symbol": 5}]}))


def test_rule_not_object_is_error() -> None:
    with pytest.raises(SuppressionError, match="must be an object"):
        parse_suppressions(json.dumps({"suppressions": [42]}))


def test_suppressions_not_list_is_error() -> None:
    with pytest.raises(SuppressionError, match="must be a list"):
        parse_suppressions(json.dumps({"suppressions": {}}))


def test_top_level_not_object_is_error() -> None:
    with pytest.raises(SuppressionError, match="top level must be an object"):
        parse_suppressions(json.dumps([1, 2, 3]))


def test_invalid_json_is_error() -> None:
    with pytest.raises(SuppressionError, match="invalid JSON"):
        parse_suppressions("{not json")


# --- matching ------------------------------------------------------------


def test_cwe_only_matches_any_finding_of_that_cwe() -> None:
    rule = Suppression(cwe=120)
    assert rule.matches(_finding(symbol="strcpy"))
    assert rule.matches(_finding(symbol="gets", function="main"))
    assert not rule.matches(_finding(cwe=78))


def test_constraints_are_anded() -> None:
    rule = Suppression(cwe=120, symbol="strcpy", function="copy_it")
    assert rule.matches(_finding())
    # Same cwe+symbol but different function: not suppressed.
    assert not rule.matches(_finding(function="other"))
    # Same cwe+function but different symbol: not suppressed.
    assert not rule.matches(_finding(symbol="sprintf"))


def test_address_match_is_case_and_prefix_insensitive() -> None:
    f = _finding(address="0x40114A")
    assert Suppression(cwe=120, address="0x40114a").matches(f)
    assert Suppression(cwe=120, address="40114A").matches(f)
    assert not Suppression(cwe=120, address="0xdeadbeef").matches(f)


def test_apply_drops_only_matching_findings_and_preserves_order() -> None:
    findings = [
        _finding(symbol="strcpy", address="0x10", function="a"),
        _finding(symbol="gets", address="0x20", function="b"),
        _finding(cwe=78, symbol="system", address="0x30", function="c"),
    ]
    s = SuppressionSet(rules=(Suppression(cwe=120, symbol="gets"),))
    kept = s.apply(findings)
    assert [f.symbol for f in kept] == ["strcpy", "system"]


def test_empty_set_apply_is_identity() -> None:
    findings = [_finding(), _finding(cwe=78, symbol="system")]
    assert SuppressionSet(rules=()).apply(findings) == findings


# --- file loading --------------------------------------------------------


def test_load_missing_file_is_error(tmp_path: Path) -> None:
    with pytest.raises(SuppressionError, match="cannot read suppression file"):
        load_suppressions(tmp_path / "nope.json")


def test_load_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "supp.json"
    p.write_text(json.dumps({"suppressions": [{"cwe": 120, "symbol": "gets"}]}))
    s = load_suppressions(p)
    assert s.rules == (Suppression(cwe=120, symbol="gets"),)


# --- CLI wiring ----------------------------------------------------------


def _patch_fake_session(monkeypatch) -> None:
    class _FakeCtx:
        def __enter__(self):
            return strcpy_vuln_session()

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        "blight.r2.Radare2Session", lambda path: _FakeCtx(), raising=True
    )


def test_cli_suppresses_single_file(monkeypatch, capsys, tmp_path) -> None:
    _patch_fake_session(monkeypatch)
    supp = tmp_path / "supp.json"
    # Suppress the gets call site (cwe 120 at main / 0x4011f0).
    supp.write_text(
        json.dumps({"suppressions": [{"cwe": 120, "symbol": "gets"}]})
    )

    fixture = FIXTURES / "strcpy-vuln"
    rc = cli.main(
        [
            "--binary",
            str(fixture),
            "--checks",
            "120",
            "--format",
            "json",
            "--suppress",
            str(supp),
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    symbols = sorted(f["symbol"] for f in out["findings"])
    # gets dropped; strcpy + sprintf remain.
    assert symbols == ["sprintf", "strcpy"]


def test_cli_without_suppress_keeps_everything(monkeypatch, capsys) -> None:
    _patch_fake_session(monkeypatch)
    fixture = FIXTURES / "strcpy-vuln"
    rc = cli.main(
        ["--binary", str(fixture), "--checks", "120", "--format", "json"]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out["findings"]) == 3


def test_cli_malformed_suppress_file_errors(monkeypatch, tmp_path) -> None:
    _patch_fake_session(monkeypatch)
    supp = tmp_path / "bad.json"
    supp.write_text("{not json")
    fixture = FIXTURES / "strcpy-vuln"
    with pytest.raises(SystemExit):
        cli.main(
            [
                "--binary",
                str(fixture),
                "--checks",
                "120",
                "--suppress",
                str(supp),
            ]
        )


def test_cli_suppresses_across_directory(monkeypatch, capsys, tmp_path) -> None:
    # Two binaries, each with a strcpy and a gets CWE-120 finding. A single
    # cwe+symbol rule must drop the gets finding in *every* result.
    from blight.scan import ScanResult

    bin_dir = tmp_path / "bins"
    bin_dir.mkdir()
    (bin_dir / "a").write_bytes(b"\x7fELF")
    (bin_dir / "b").write_bytes(b"\x7fELF")

    def fake_scan_targets(paths, checks, *, workers=1, session_factory=None):
        results = []
        for p in paths:
            results.append(
                ScanResult(
                    binary=p,
                    findings=[
                        _finding(symbol="strcpy", address="0x10", function="a"),
                        _finding(symbol="gets", address="0x20", function="main"),
                    ],
                )
            )
        return results

    monkeypatch.setattr(cli, "scan_targets", fake_scan_targets)

    supp = tmp_path / "supp.json"
    supp.write_text(json.dumps({"suppressions": [{"cwe": 120, "symbol": "gets"}]}))

    rc = cli.main(
        ["--binary", str(bin_dir), "--checks", "120", "--suppress", str(supp)]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out["results"]) == 2
    for result in out["results"]:
        symbols = [f["symbol"] for f in result["findings"]]
        assert symbols == ["strcpy"]


def test_cli_suppress_address_targets_single_callsite(
    monkeypatch, capsys, tmp_path
) -> None:
    _patch_fake_session(monkeypatch)
    supp = tmp_path / "supp.json"
    supp.write_text(
        json.dumps(
            {
                "suppressions": [
                    {"cwe": 120, "symbol": "strcpy", "address": "0x40114a"}
                ]
            }
        )
    )
    fixture = FIXTURES / "strcpy-vuln"
    rc = cli.main(
        [
            "--binary",
            str(fixture),
            "--checks",
            "120",
            "--suppress",
            str(supp),
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    symbols = sorted(f["symbol"] for f in out["findings"])
    assert symbols == ["gets", "sprintf"]
