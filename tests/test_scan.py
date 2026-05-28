"""Tests for blight's multi-binary / parallel scanning (POST_V01 item 6).

The core guarantee under test: scanning a set of binaries with ``--workers N``
produces output that is byte-for-byte identical to the sequential (``workers=1``)
scan — same result ordering, same per-binary finding ordering — and that running
many workers concurrently introduces no race conditions or dropped/duplicated
results.

All radare2 access is replaced by in-memory fake sessions, so these run without
radare2 installed.
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

import blight.cli as cli
from blight.scan import ScanResult, scan_one, scan_targets
from tests.fake_session import (
    clean_baseline_session,
    cwe676_all_session,
    gets_vuln_session,
    strcpy_vuln_session,
    system_vuln_session,
)

ALL_CHECKS = [78, 120, 134, 242, 252, 476, 676]

# Map a synthetic binary "path" to the fake session it should produce. This lets
# us build a deterministic, varied corpus without touching disk or radare2.
_SESSION_BUILDERS = {
    "/corpus/strcpy": strcpy_vuln_session,
    "/corpus/system": system_vuln_session,
    "/corpus/gets": gets_vuln_session,
    "/corpus/cwe676": cwe676_all_session,
    "/corpus/clean": clean_baseline_session,
}


def _factory(delay: float = 0.0):
    """Build a session_factory that yields the fake mapped to each path.

    Args:
        delay: optional sleep inside the context manager to widen the window for
            races to manifest under the thread pool.
    """

    @contextmanager
    def _open(path: str):
        builder = _SESSION_BUILDERS[path]
        session = builder()
        if delay:
            time.sleep(delay)
        yield session

    return _open


def _results_to_comparable(results: list[ScanResult]):
    return [(r.binary, [f.to_dict() for f in r.findings], r.error) for r in results]


# --- determinism: parallel == sequential ----------------------------------

def test_empty_corpus_returns_empty() -> None:
    assert scan_targets([], ALL_CHECKS, workers=4) == []


def test_single_binary_matches_scan_one() -> None:
    paths = ["/corpus/strcpy"]
    [seq] = scan_targets(paths, ALL_CHECKS, workers=1, session_factory=_factory())
    direct = scan_one("/corpus/strcpy", ALL_CHECKS, session_factory=_factory())
    assert _results_to_comparable([seq]) == _results_to_comparable([direct])


def test_parallel_equals_sequential() -> None:
    paths = list(_SESSION_BUILDERS)
    seq = scan_targets(paths, ALL_CHECKS, workers=1, session_factory=_factory())
    par = scan_targets(paths, ALL_CHECKS, workers=4, session_factory=_factory())
    assert _results_to_comparable(par) == _results_to_comparable(seq)


def test_parallel_preserves_input_order() -> None:
    # Reverse the corpus order; results must come back in THAT order, even
    # though completion order under the pool is nondeterministic.
    paths = list(reversed(list(_SESSION_BUILDERS)))
    par = scan_targets(paths, ALL_CHECKS, workers=4, session_factory=_factory())
    assert [r.binary for r in par] == paths


def test_workers_greater_than_targets_is_safe() -> None:
    paths = ["/corpus/strcpy", "/corpus/gets"]
    par = scan_targets(paths, ALL_CHECKS, workers=64, session_factory=_factory())
    seq = scan_targets(paths, ALL_CHECKS, workers=1, session_factory=_factory())
    assert _results_to_comparable(par) == _results_to_comparable(seq)


def test_findings_are_nonempty_where_expected() -> None:
    # Sanity: the parallel path actually ran detectors, not just returned shells.
    results = scan_targets(
        list(_SESSION_BUILDERS), ALL_CHECKS, workers=4, session_factory=_factory()
    )
    by_binary = {r.binary: r for r in results}
    assert by_binary["/corpus/strcpy"].findings  # has strcpy/sprintf/gets
    assert by_binary["/corpus/cwe676"].findings   # six dangerous functions
    assert by_binary["/corpus/clean"].findings == []  # nothing flagged


# --- race / concurrency stress --------------------------------------------

def test_no_dropped_or_duplicated_results_under_load() -> None:
    # Repeat the same path many times so the pool genuinely overlaps work, and
    # add a small delay so threads are in-flight simultaneously. Every result
    # must be present exactly once and correct.
    paths = ["/corpus/strcpy"] * 50
    par = scan_targets(
        paths, ALL_CHECKS, workers=8, session_factory=_factory(delay=0.002)
    )
    assert len(par) == 50
    expected = _results_to_comparable(
        [scan_one("/corpus/strcpy", ALL_CHECKS, session_factory=_factory())]
    )[0]
    for r in par:
        assert _results_to_comparable([r])[0] == expected


def test_concurrent_factory_invocations_observed() -> None:
    # Prove the pool truly runs work in parallel: track peak concurrency.
    peak = 0
    current = 0
    lock = threading.Lock()

    @contextmanager
    def _open(path: str):
        nonlocal peak, current
        with lock:
            current += 1
            peak = max(peak, current)
        try:
            time.sleep(0.01)
            yield strcpy_vuln_session()
        finally:
            with lock:
                current -= 1

    scan_targets(
        ["/corpus/strcpy"] * 8, ALL_CHECKS, workers=4, session_factory=_open
    )
    assert peak >= 2  # at least two threads ran concurrently


# --- per-binary failure isolation -----------------------------------------

def test_failure_in_one_binary_does_not_abort_others() -> None:
    @contextmanager
    def _open(path: str):
        if path == "/corpus/bad":
            raise RuntimeError("radare2 exploded")
        yield strcpy_vuln_session()

    paths = ["/corpus/strcpy", "/corpus/bad", "/corpus/strcpy"]
    results = scan_targets(paths, ALL_CHECKS, workers=4, session_factory=_open)
    assert len(results) == 3
    assert results[1].error is not None
    assert "radare2 exploded" in results[1].error
    assert results[1].findings == []
    # Neighbours still produced findings.
    assert results[0].findings
    assert results[2].findings


def test_scanresult_to_dict_omits_error_when_clean() -> None:
    r = ScanResult(binary="/x", findings=[])
    assert "error" not in r.to_dict()
    r2 = ScanResult(binary="/x", findings=[], error="boom")
    assert r2.to_dict()["error"] == "boom"


# --- CLI integration: directory scanning -----------------------------------

def _write_dummy_files(tmp_path: Path, names: list[str]) -> None:
    for n in names:
        (tmp_path / n).write_bytes(b"\x7fELF dummy")


def test_discover_binaries_recursive_and_sorted(tmp_path: Path) -> None:
    _write_dummy_files(tmp_path, ["b.bin", "a.bin"])
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.bin").write_bytes(b"\x7fELF")
    found = cli.discover_binaries(tmp_path)
    assert [p.name for p in found] == ["a.bin", "b.bin", "c.bin"]


def test_cli_directory_emits_results_array(monkeypatch, tmp_path, capsys) -> None:
    _write_dummy_files(tmp_path, ["one", "two"])

    # Patch scan_targets so the CLI doesn't reach radare2; return deterministic
    # results keyed off the discovered paths.
    def fake_scan_targets(paths, checks, *, workers=1, session_factory=None):
        return [ScanResult(binary=p, findings=[]) for p in paths]

    monkeypatch.setattr(cli, "scan_targets", fake_scan_targets)

    rc = cli.main(["--binary", str(tmp_path), "--checks", "120", "--workers", "3"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["directory"] == str(tmp_path)
    assert out["checks"] == [120]
    assert [r["binary"] for r in out["results"]] == sorted(
        str(tmp_path / n) for n in ("one", "two")
    )


def test_cli_workers_propagated(monkeypatch, tmp_path) -> None:
    _write_dummy_files(tmp_path, ["one"])
    captured = {}

    def fake_scan_targets(paths, checks, *, workers=1, session_factory=None):
        captured["workers"] = workers
        return [ScanResult(binary=p, findings=[]) for p in paths]

    monkeypatch.setattr(cli, "scan_targets", fake_scan_targets)
    cli.main(["--binary", str(tmp_path), "--workers", "7"])
    assert captured["workers"] == 7


def test_cli_rejects_zero_workers(tmp_path) -> None:
    _write_dummy_files(tmp_path, ["one"])
    with pytest.raises(SystemExit):
        cli.main(["--binary", str(tmp_path), "--workers", "0"])


def test_cli_empty_directory_errors(tmp_path) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--binary", str(tmp_path)])


def test_cli_single_file_keeps_legacy_shape(monkeypatch, tmp_path, capsys) -> None:
    # A single-file --binary must still emit {binary, checks, findings}.
    f = tmp_path / "elf"
    f.write_bytes(b"\x7fELF")

    def fake_scan_targets(paths, checks, *, workers=1, session_factory=None):
        return [ScanResult(binary=paths[0], findings=[])]

    monkeypatch.setattr(cli, "scan_targets", fake_scan_targets)
    rc = cli.main(["--binary", str(f), "--checks", "120"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out) == {"binary", "checks", "findings"}
    assert out["binary"] == str(f)
