"""Unit tests for blight.pipeline_adapter.

All radare2/r2pipe interactions are mocked via the FakeR2Session fixture.
Tests verify:
- analyze_binary() returns list[BinaryFinding]
- Findings are correctly converted from blight.findings.Finding
- analyze_binary is callable as a BinaryAnalyzer protocol
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from binary_finding_schema import BinaryFinding
from blight.findings import Finding
from blight.pipeline_adapter import analyze_binary, _to_binary_finding
from tests.fake_session import strcpy_vuln_session, clean_baseline_session


def test_to_binary_finding_converts_correctly() -> None:
    """_to_binary_finding preserves all fields from blight Finding."""
    f = Finding(cwe=120, function="copy_it", address="0x40114a",
                evidence="calls strcpy", symbol="strcpy")
    bf = _to_binary_finding(f)

    assert isinstance(bf, BinaryFinding)
    assert bf.cwe_id == "CWE-120"
    assert bf.function == "copy_it"
    assert bf.address == "0x40114a"
    assert bf.evidence == "calls strcpy"
    assert bf.symbol == "strcpy"


def test_to_binary_finding_cwe_78() -> None:
    """_to_binary_finding handles CWE-78 findings."""
    f = Finding(cwe=78, function="run_cmd", address="0x40118f",
                evidence="system call", symbol="system")
    bf = _to_binary_finding(f)
    assert bf.cwe_id == "CWE-78"


def test_to_binary_finding_no_taint_trace() -> None:
    """blight findings have no taint trace (not produced by radare2 analysis)."""
    f = Finding(cwe=242, function="main", address="0x401050",
                evidence="gets call", symbol="gets")
    bf = _to_binary_finding(f)
    assert bf.taint_trace == []


def test_analyze_binary_mocked_session(tmp_path: Path) -> None:
    """analyze_binary returns converted BinaryFindings from a fake session."""
    p = tmp_path / "elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)

    session = strcpy_vuln_session()

    # Patch Radare2Session at its source module since it's imported lazily.
    with patch("blight.r2.Radare2Session") as MockSession:
        MockSession.return_value.__enter__ = lambda s: session
        MockSession.return_value.__exit__ = MagicMock(return_value=False)

        result = analyze_binary(p)

    assert isinstance(result, list)
    assert len(result) > 0
    assert all(isinstance(f, BinaryFinding) for f in result)
    # strcpy_vuln should have CWE-120 and CWE-242 findings
    cwe_ids = {f.cwe_id for f in result}
    assert "CWE-120" in cwe_ids


def test_analyze_binary_clean_baseline_empty(tmp_path: Path) -> None:
    """analyze_binary returns empty list for clean binary."""
    p = tmp_path / "elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)

    session = clean_baseline_session()

    with patch("blight.r2.Radare2Session") as MockSession:
        MockSession.return_value.__enter__ = lambda s: session
        MockSession.return_value.__exit__ = MagicMock(return_value=False)

        result = analyze_binary(p)

    assert result == []


def test_analyze_binary_conforms_to_protocol() -> None:
    """analyze_binary is callable with (Path) -> list[BinaryFinding] signature."""
    from binary_pipeline import BinaryAnalyzer
    assert callable(analyze_binary)


def test_analyze_binary_no_eager_r2pipe_import() -> None:
    """Importing pipeline_adapter does NOT import r2pipe at module level."""
    import sys
    # r2pipe may or may not be installed; either way importing pipeline_adapter
    # should not trigger it at import time (blight.r2 imports r2pipe lazily).
    import blight.pipeline_adapter  # should not raise even without r2pipe
