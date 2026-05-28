"""Confidence-threshold filtering for blight findings.

Every :class:`~blight.findings.Finding` carries a triage ``confidence`` label
(``high`` / ``medium`` / ``low``) describing how certain the detection is. The
``--min-confidence`` CLI flag lets a consumer drop everything below a chosen
threshold *before* output, so a CI gate can ask for only ``high``-confidence
findings without post-processing the JSON.

This is a pure output-layer filter — it never touches the detectors or the
analyzed binary, and it composes with ``--suppress`` (suppression and threshold
filtering are independent passes over the same finding list). The ordering is
the natural one:

    low  <  medium  <  high

so ``--min-confidence high`` keeps only ``high`` findings, ``--min-confidence
medium`` keeps ``medium`` and ``high``, and ``--min-confidence low`` (the
default behaviour when the flag is omitted) keeps everything.
"""

from __future__ import annotations

from collections.abc import Iterable

from blight.findings import Finding

# Ordered weakest -> strongest. A finding passes a threshold when its rank is
# >= the threshold's rank.
_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}

# The accepted CLI tokens, ordered weakest -> strongest for help text.
CONFIDENCE_CHOICES: tuple[str, ...] = ("low", "medium", "high")


def meets_threshold(confidence: str, minimum: str) -> bool:
    """Return whether ``confidence`` is at or above ``minimum``.

    Raises:
        ValueError: if either label is not one of ``low`` / ``medium`` / ``high``.
    """
    try:
        return _RANK[confidence] >= _RANK[minimum]
    except KeyError as exc:  # pragma: no cover - guarded by CLI choices
        raise ValueError(
            f"confidence must be one of {CONFIDENCE_CHOICES!r}, got: {exc.args[0]!r}"
        ) from exc


def filter_findings(
    findings: Iterable[Finding], minimum: str
) -> list[Finding]:
    """Return ``findings`` with everything below ``minimum`` confidence dropped.

    Order is preserved. ``minimum == "low"`` is the identity filter (keeps
    everything), matching the default when ``--min-confidence`` is not given.
    """
    return [f for f in findings if meets_threshold(f.confidence, minimum)]
