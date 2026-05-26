"""Unit tests for the blight engine and check selection — mocked."""

from __future__ import annotations

from blight.engine import run_checks
from tests.fake_session import (
    clean_baseline_session,
    strcpy_vuln_session,
)


def test_run_single_check() -> None:
    findings = run_checks(strcpy_vuln_session(), [120])
    assert all(f.cwe == 120 for f in findings)
    assert len(findings) == 3


def test_run_all_checks_on_strcpy_vuln() -> None:
    # strcpy-vuln has strcpy+sprintf+gets. 120 flags all three; 242 flags gets.
    findings = run_checks(strcpy_vuln_session(), [78, 120, 242])
    cwes = sorted({f.cwe for f in findings})
    assert cwes == [120, 242]


def test_findings_sorted_by_address() -> None:
    findings = run_checks(strcpy_vuln_session(), [120, 242])
    addrs = [int(f.address, 16) for f in findings]
    assert addrs == sorted(addrs)


def test_clean_baseline_zero_findings_all_checks() -> None:
    findings = run_checks(clean_baseline_session(), [78, 120, 242])
    assert findings == []
