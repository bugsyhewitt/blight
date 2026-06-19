"""blight v1.0 wheel ship-gate tests.

Six tests that pin the release-artifact contract:
  1. python -m build produces a wheel + sdist.
  2. A fresh venv can install the wheel plus runtime deps.
  3. blight --version from the fresh venv prints "blight 1.0.0".
  4. import blight; assert blight.__version__ == "1.0.0" succeeds.
  5. All 9 public top-level modules import cleanly.
  6. CHANGELOG.md exists with a [1.0.0] entry.

Run the full suite for the v1.0 release gate.
Skip these in the fast inner-loop: pytest -q -m "not ship_gate"
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Module-level shared state: built once per pytest session.
# ---------------------------------------------------------------------------

_DIST_DIR: Path | None = None
_WHEEL_PATH: Path | None = None
_VENV_DIR: Path | None = None
_TMPROOT: Path | None = None


def _project_root() -> Path:
    return Path(__file__).parent.parent


def _setup_fresh_venv() -> tuple[Path, Path, Path]:
    """Build wheel + sdist then install into a fresh venv. Returns (dist_dir, wheel, venv)."""
    global _DIST_DIR, _WHEEL_PATH, _VENV_DIR, _TMPROOT

    if _WHEEL_PATH is not None:
        assert _DIST_DIR is not None
        assert _VENV_DIR is not None
        return _DIST_DIR, _WHEEL_PATH, _VENV_DIR

    tmproot = Path(tempfile.mkdtemp(prefix="blight_ship_gate_"))
    _TMPROOT = tmproot
    dist_dir = tmproot / "dist"
    dist_dir.mkdir()
    venv_dir = tmproot / "fresh-venv"

    root = _project_root()
    python = sys.executable

    # Ensure build package is available in the running interpreter's env.
    subprocess.run(
        [python, "-m", "pip", "install", "build", "--quiet"],
        check=True,
    )

    # Build wheel + sdist into dist_dir.
    subprocess.run(
        [python, "-m", "build", "--wheel", "--sdist", "--outdir", str(dist_dir), str(root)],
        check=True,
    )

    wheels = list(dist_dir.glob("blight-*.whl"))
    assert wheels, f"No wheel produced in {dist_dir}"
    wheel = wheels[0]

    # Create a fully isolated fresh venv.
    subprocess.run([python, "-m", "venv", str(venv_dir)], check=True)
    pip = venv_dir / "bin" / "pip"

    # Install the wheel (pulls in declared runtime deps from PyPI/git).
    subprocess.run(
        [str(pip), "install", str(wheel), "--quiet"],
        check=True,
    )

    _DIST_DIR = dist_dir
    _WHEEL_PATH = wheel
    _VENV_DIR = venv_dir
    return dist_dir, wheel, venv_dir


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.ship_gate
def test_build_wheel_and_sdist() -> None:
    """python -m build produces both blight-1.0.0-py3-none-any.whl and blight-1.0.0.tar.gz."""
    dist_dir, wheel, _venv = _setup_fresh_venv()

    wheels = list(dist_dir.glob("blight-*.whl"))
    sdists = list(dist_dir.glob("blight-*.tar.gz"))

    assert wheels, f"Wheel not found in {dist_dir}"
    assert sdists, f"Sdist not found in {dist_dir}"
    assert "blight-1.0.0" in wheels[0].name, f"Unexpected wheel name: {wheels[0].name}"
    assert "blight-1.0.0" in sdists[0].name, f"Unexpected sdist name: {sdists[0].name}"


@pytest.mark.ship_gate
def test_fresh_venv_installs_wheel() -> None:
    """The wheel installs cleanly into a fresh venv (pip exits 0)."""
    _dist_dir, wheel, venv_dir = _setup_fresh_venv()
    # If _setup_fresh_venv() completed without raising, the install succeeded.
    assert wheel.exists(), f"Wheel disappeared: {wheel}"
    assert (venv_dir / "bin" / "blight").exists(), "blight console script missing from fresh venv"


@pytest.mark.ship_gate
def test_cli_version_from_fresh_venv() -> None:
    """blight --version from the fresh venv prints exactly 'blight 1.0.0'."""
    _dist_dir, _wheel, venv_dir = _setup_fresh_venv()
    blight_bin = venv_dir / "bin" / "blight"

    result = subprocess.run(
        [str(blight_bin), "--version"],
        capture_output=True,
        text=True,
    )
    output = (result.stdout + result.stderr).strip()
    assert result.returncode == 0, f"blight --version exited {result.returncode}: {output}"
    assert output == "blight 1.0.0", f"Unexpected --version output: {output!r}"


@pytest.mark.ship_gate
def test_import_and_version_from_fresh_venv() -> None:
    """import blight; assert blight.__version__ == '1.0.0' succeeds in the fresh venv."""
    _dist_dir, _wheel, venv_dir = _setup_fresh_venv()
    python_bin = venv_dir / "bin" / "python"

    result = subprocess.run(
        [
            str(python_bin),
            "-c",
            "import blight; assert blight.__version__ == '1.0.0', blight.__version__",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Version assertion failed (exit {result.returncode}): "
        f"{result.stdout}{result.stderr}"
    )


@pytest.mark.ship_gate
def test_all_public_modules_import_from_fresh_venv() -> None:
    """All 9 non-__init__ public top-level modules import cleanly from the fresh venv."""
    _dist_dir, _wheel, venv_dir = _setup_fresh_venv()
    python_bin = venv_dir / "bin" / "python"

    import_stmt = (
        "import blight.cli, blight.confidence_filter, blight.engine, "
        "blight.exit_gate, blight.findings, blight.pipeline_adapter, "
        "blight.r2, blight.scan, blight.suppressions; print('ok')"
    )
    result = subprocess.run(
        [str(python_bin), "-c", import_stmt],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Public module import failed (exit {result.returncode}): "
        f"{result.stdout}{result.stderr}"
    )
    assert result.stdout.strip() == "ok", f"Unexpected stdout: {result.stdout!r}"


@pytest.mark.ship_gate
def test_changelog_exists_with_v1_0_0_entry() -> None:
    """CHANGELOG.md exists at repo root and has a [1.0.0] entry."""
    changelog = _project_root() / "CHANGELOG.md"
    assert changelog.is_file(), f"CHANGELOG.md missing at {changelog}"
    text = changelog.read_text(encoding="utf-8")
    assert "## [1.0.0]" in text, (
        f"CHANGELOG.md does not contain a [1.0.0] entry; first 200 chars: {text[:200]!r}"
    )
