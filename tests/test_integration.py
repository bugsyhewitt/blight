"""Integration test: run blight against the real radare2 on shipped fixtures.

Marked @pytest.mark.integration so the default unit run can deselect it with
``-m 'not integration'``. Skips gracefully if radare2 or r2pipe is absent.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from blight.engine import run_checks

FIXTURES = Path(__file__).parent / "fixtures"

_HAVE_R2 = shutil.which("radare2") is not None
try:  # pragma: no cover - environment dependent
    import r2pipe  # noqa: F401

    _HAVE_R2PIPE = True
except Exception:  # pragma: no cover
    _HAVE_R2PIPE = False

pytestmark = pytest.mark.integration

_SKIP_REASON = "requires radare2 and r2pipe installed"


@pytest.fixture()
def session_for():
    from blight.r2 import Radare2Session

    sessions = []

    def _open(name: str):
        s = Radare2Session(str(FIXTURES / name))
        sessions.append(s)
        return s

    yield _open
    for s in sessions:
        s.close()


@pytest.mark.skipif(not (_HAVE_R2 and _HAVE_R2PIPE), reason=_SKIP_REASON)
def test_cwe120_on_strcpy_vuln(session_for) -> None:
    findings = run_checks(session_for("strcpy-vuln"), [120])
    symbols = {f.symbol for f in findings}
    assert {"strcpy", "sprintf"} <= symbols
    for f in findings:
        assert f.cwe == 120
        assert f.address.startswith("0x")
        assert f.function
        assert f.evidence


@pytest.mark.skipif(not (_HAVE_R2 and _HAVE_R2PIPE), reason=_SKIP_REASON)
def test_cwe78_on_system_vuln(session_for) -> None:
    findings = run_checks(session_for("system-vuln"), [78])
    system_findings = [f for f in findings if f.symbol == "system"]
    assert len(system_findings) >= 1
    assert system_findings[0].cwe == 78
    assert "non-constant" in system_findings[0].evidence


@pytest.mark.skipif(not (_HAVE_R2 and _HAVE_R2PIPE), reason=_SKIP_REASON)
def test_cwe242_on_gets_vuln(session_for) -> None:
    findings = run_checks(session_for("gets-vuln"), [242])
    assert any(f.symbol == "gets" and f.cwe == 242 for f in findings)


@pytest.mark.skipif(not (_HAVE_R2 and _HAVE_R2PIPE), reason=_SKIP_REASON)
def test_clean_baseline_zero_findings(session_for) -> None:
    findings = run_checks(session_for("clean-baseline"), [78, 120, 242])
    assert findings == []


@pytest.mark.skipif(not (_HAVE_R2 and _HAVE_R2PIPE), reason=_SKIP_REASON)
def test_cwe798_on_creds_vuln(session_for) -> None:
    # The creds-vuln fixture embeds a hard-coded admin password, an api_key, and
    # a credential-bearing connection URI as .rodata string literals. The
    # CWE-798 detector reads them out of the real binary via izzj.
    findings = run_checks(session_for("creds-vuln"), [798])
    symbols = {f.symbol for f in findings}
    assert "password" in symbols
    assert "api_key" in symbols
    assert "connection-uri" in symbols
    for f in findings:
        assert f.cwe == 798
        assert f.confidence in ("high", "medium", "low")
        assert f.address.startswith("0x")
        # The secret value itself must never appear verbatim in the report.
        assert "Sup3rSecretAdminPW" not in f.evidence
        assert "hunter2dbpass" not in f.evidence


@pytest.mark.skipif(not (_HAVE_R2 and _HAVE_R2PIPE), reason=_SKIP_REASON)
def test_cwe369_on_divzero_vuln(session_for) -> None:
    # divzero-vuln has two divisions: compute_ratio() divides by a caller value
    # with NO zero-check (must flag) and safe_ratio() guards the divisor with
    # `if (d == 0)` first (must NOT flag). The detector walks every function body
    # via aflj/pdfj and recognizes the cmp-against-the-same-operand guard.
    findings = run_checks(session_for("divzero-vuln"), [369])
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 369
    assert f.symbol in ("idiv", "div")
    assert f.confidence == "low"
    assert f.address.startswith("0x")
    assert "zero-check" in f.evidence


@pytest.mark.skipif(not (_HAVE_R2 and _HAVE_R2PIPE), reason=_SKIP_REASON)
def test_function_addrs_lists_functions(session_for) -> None:
    # The real Radare2Session.function_addrs() (aflj) must surface the user
    # functions so the instruction-pattern detectors (CWE-369) have bodies to
    # walk. The two divzero helpers are among the discovered functions.
    addrs = session_for("divzero-vuln").function_addrs()
    assert len(addrs) >= 2
    assert all(isinstance(a, int) for a in addrs)


@pytest.mark.skipif(not (_HAVE_R2 and _HAVE_R2PIPE), reason=_SKIP_REASON)
def test_strings_surfaces_rodata_literals(session_for) -> None:
    # The real Radare2Session.strings() (izzj) must surface the embedded
    # credential literals so CWE-798 has data to scan.
    strings = session_for("creds-vuln").strings()
    blob = "\n".join(s.string for s in strings)
    assert "password=" in blob
    assert "mysql://" in blob


@pytest.mark.skipif(not (_HAVE_R2 and _HAVE_R2PIPE), reason=_SKIP_REASON)
def test_arch_detected_for_x86_64_fixtures(session_for) -> None:
    # The shipped fixtures are x86_64 ELFs; arch() must resolve them via iAj to
    # the normalized "x86_64" key so the register heuristics pick rdi/rsi/rdx.
    assert session_for("system-vuln").arch() == "x86_64"
