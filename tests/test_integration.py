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
def test_arch_detected_for_x86_64_fixtures(session_for) -> None:
    # The shipped fixtures are x86_64 ELFs; arch() must resolve them via iAj to
    # the normalized "x86_64" key so the register heuristics pick rdi/rsi/rdx.
    assert session_for("system-vuln").arch() == "x86_64"
