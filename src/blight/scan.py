"""Multi-binary scanning for blight, with optional parallelism.

The single-binary path (:func:`scan_one`) opens an :class:`R2Session` over one
binary and runs the requested detectors. :func:`scan_targets` applies that to a
list of binaries and, when ``workers > 1``, fans the work out across a thread
pool.

Why a thread pool (not a process pool): each binary's analysis spends almost all
of its wall time inside the radare2 child process — i.e. blocked on I/O to that
subprocess — so threads release the GIL and run truly concurrently. A thread
pool also avoids pickling sessions/findings across process boundaries and keeps
the fake-session-injection path the unit tests rely on working unchanged.

Determinism guarantee: regardless of ``workers``, :func:`scan_targets` returns
results in the *same order* as the input ``paths`` and each binary's findings
are sorted identically to the sequential path. Parallel output therefore equals
sequential output exactly — see ``tests/test_scan.py``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from blight.engine import run_checks
from blight.findings import Finding
from blight.r2 import R2Session


@dataclass(frozen=True)
class ScanResult:
    """The outcome of scanning a single binary.

    Attributes:
        binary: Path to the binary that was scanned.
        findings: Findings for that binary (empty if none / on error).
        error: ``None`` on success, otherwise a short human-readable string.
            A failure on one binary never aborts the rest of the scan.
    """

    binary: str
    findings: list[Finding]
    error: str | None = None

    def to_dict(self) -> dict:
        out: dict = {
            "binary": self.binary,
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.error is not None:
            out["error"] = self.error
        return out


# A session factory takes a binary path and returns a context manager yielding
# an R2Session. Production uses Radare2Session; tests inject a fake.
SessionFactory = Callable[[str], "object"]


def _default_session_factory(binary_path: str) -> "object":
    # Imported lazily so the package imports without r2pipe/radare2 present.
    from blight.r2 import Radare2Session

    return Radare2Session(binary_path)


def scan_one(
    binary_path: str,
    checks: Sequence[int],
    *,
    session_factory: SessionFactory | None = None,
) -> ScanResult:
    """Scan one binary and return its :class:`ScanResult`.

    Any exception from opening the session or running the detectors is captured
    into ``ScanResult.error`` rather than propagated, so a single bad binary in
    a directory scan cannot abort the whole run.
    """
    factory = session_factory or _default_session_factory
    try:
        with factory(binary_path) as session:  # type: ignore[union-attr]
            findings = run_checks(session, checks)
        return ScanResult(binary=binary_path, findings=findings)
    except Exception as exc:  # noqa: BLE001 - isolate per-binary failures
        return ScanResult(
            binary=binary_path,
            findings=[],
            error=f"{type(exc).__name__}: {exc}",
        )


def scan_targets(
    paths: Iterable[str],
    checks: Sequence[int],
    *,
    workers: int = 1,
    session_factory: SessionFactory | None = None,
) -> list[ScanResult]:
    """Scan many binaries, optionally in parallel.

    Args:
        paths: Binary paths to scan, in the order results should be returned.
        checks: CWE ids to run against each binary.
        workers: Parallelism degree. ``<= 1`` runs sequentially; ``> 1`` uses a
            thread pool of that many workers. The thread count is capped at the
            number of binaries so we never spin up idle threads.
        session_factory: Optional override for the R2Session source (tests).

    Returns:
        One :class:`ScanResult` per input path, in input order. The ordering and
        per-binary finding order are identical whether or not parallelism is
        used.
    """
    targets = list(paths)
    if not targets:
        return []

    if workers <= 1 or len(targets) == 1:
        return [
            scan_one(p, checks, session_factory=session_factory) for p in targets
        ]

    pool_size = min(workers, len(targets))
    with ThreadPoolExecutor(max_workers=pool_size) as pool:
        # executor.map preserves input order in its output, giving us
        # deterministic results regardless of completion order.
        results = pool.map(
            lambda p: scan_one(p, checks, session_factory=session_factory),
            targets,
        )
        return list(results)
