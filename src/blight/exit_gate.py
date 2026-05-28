"""Exit-code gating for blight — fail a CI build on findings.

blight's output is advisory by default: ``main()`` returns ``0`` whether or not
anything was flagged, so a consumer must post-process the JSON to decide whether
to fail a pipeline. ``--fail-on`` closes that gap. It turns blight into a build
gate: if any *emitted* finding is at or above the chosen triage confidence, the
process exits non-zero, so a CI job fails without parsing the report.

The threshold reuses the same ``low < medium < high`` ordering as
``--min-confidence`` (see :mod:`blight.confidence_filter`):

    --fail-on high     fail only when a high-confidence finding survives
    --fail-on medium   fail on a medium- or high-confidence finding
    --fail-on low      fail on any finding at all
    --fail-on none     never fail (the default — fully backward compatible)

The gate runs over the findings that are actually *emitted*, i.e. after
``--suppress`` and ``--min-confidence`` have already removed findings. A
suppressed or below-threshold finding therefore cannot trip the gate — the gate
is consistent with what the user sees in the report. For a directory scan the
gate considers every binary's surviving findings; one tripping finding anywhere
fails the whole run.

A scan that errored (e.g. an unreadable binary) carries no findings, so it never
trips the gate on its own. Surfacing scan errors as a failure is a separate
concern from gating on findings and is intentionally out of scope here.
"""

from __future__ import annotations

from collections.abc import Iterable

from blight.confidence_filter import meets_threshold
from blight.findings import Finding

# ``none`` is gate-specific (disable gating) and sits *above* every real
# confidence, so no finding can ever meet it. The real labels keep the same
# weakest -> strongest ordering used everywhere else in blight.
FAIL_ON_CHOICES: tuple[str, ...] = ("none", "low", "medium", "high")

# The exit code returned when the gate trips. Distinct from argparse's usage
# error code (2) so callers can tell "found vulnerabilities" apart from "bad
# invocation".
GATE_TRIPPED_EXIT_CODE = 1


def gate_trips(findings: Iterable[Finding], fail_on: str) -> bool:
    """Return whether ``fail_on`` should fail the run given ``findings``.

    Args:
        findings: The findings that are actually emitted (post-suppression,
            post-``--min-confidence``).
        fail_on: One of :data:`FAIL_ON_CHOICES`. ``"none"`` disables the gate
            and always returns ``False``.

    Returns:
        ``True`` if at least one finding is at or above the ``fail_on``
        confidence threshold (and ``fail_on`` is not ``"none"``).

    Raises:
        ValueError: if ``fail_on`` is not one of :data:`FAIL_ON_CHOICES`.
    """
    if fail_on == "none":
        return False
    if fail_on not in FAIL_ON_CHOICES:
        raise ValueError(
            f"fail_on must be one of {FAIL_ON_CHOICES!r}, got: {fail_on!r}"
        )
    return any(meets_threshold(f.confidence, fail_on) for f in findings)
