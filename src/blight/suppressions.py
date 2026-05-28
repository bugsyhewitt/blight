"""Suppression of known false-positive findings.

Every static-analysis tool accumulates known false positives over time. blight
lets a team codify accepted risk in a small JSON *suppression file* and pass it
with ``--suppress FILE``; matching findings are dropped from the output before
it is emitted. The binary is never modified and the detectors are untouched —
suppression is a pure output-layer filter applied after :func:`run_checks`.

Why JSON and not YAML: blight's dependency stance is "pure Python, no extra
toolchain" (no Ghidra/JVM/Docker/Rust). Adding a YAML parser would pull in a
third-party dependency for a feature whose schema is trivially expressible in
the standard library's :mod:`json`. Comments are supported by ignoring any
top-level/per-rule ``"//"`` keys, which covers the common "why is this
suppressed" annotation need without a new parser.

Suppression file shape::

    {
      "version": "1",
      "suppressions": [
        { "cwe": 120, "symbol": "strcpy", "function": "copy_it",
          "reason": "audited: bounded by caller" },
        { "cwe": 78,  "address": "0x40119c" }
      ]
    }

A rule **must** specify ``cwe``. Any of ``function``, ``address``, and
``symbol`` may additionally be given; those that are present must *all* match a
finding for it to be suppressed (logical AND). Fields that are omitted act as
wildcards, so ``{"cwe": 120}`` suppresses every CWE-120 finding while
``{"cwe": 120, "symbol": "strcpy", "address": "0x40114a"}`` suppresses exactly
one call site. ``address`` matching is case-insensitive and tolerant of a
missing ``0x`` prefix, since hex casing varies between tools. The optional
``reason`` key is documentation only and is never used for matching.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from blight.findings import Finding

# Keys a rule may carry. ``cwe`` is required; the three below are optional
# match constraints. ``reason`` and any ``//`` comment key are ignored.
_MATCH_FIELDS = ("function", "address", "symbol")
_KNOWN_KEYS = {"cwe", "reason", "//", *_MATCH_FIELDS}


class SuppressionError(ValueError):
    """Raised when a suppression file is malformed.

    The message is suitable for surfacing directly to the user via
    ``argparse``'s ``parser.error`` (a short, single-line explanation).
    """


def _normalize_address(value: str) -> str:
    """Canonicalize a hex address for comparison.

    Lowercases and strips a leading ``0x`` so ``"0x40114A"``, ``"0x40114a"``,
    and ``"40114a"`` all compare equal.
    """
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    return text


@dataclass(frozen=True)
class Suppression:
    """One parsed suppression rule.

    ``cwe`` is required; ``function``, ``address`` and ``symbol`` are optional
    constraints (``None`` means "match any"). A finding is suppressed when its
    ``cwe`` equals this rule's ``cwe`` and every non-``None`` constraint matches.
    """

    cwe: int
    function: str | None = None
    address: str | None = None
    symbol: str | None = None

    def matches(self, finding: Finding) -> bool:
        if finding.cwe != self.cwe:
            return False
        if self.function is not None and finding.function != self.function:
            return False
        if self.symbol is not None and finding.symbol != self.symbol:
            return False
        if self.address is not None:
            if _normalize_address(finding.address) != _normalize_address(self.address):
                return False
        return True


@dataclass(frozen=True)
class SuppressionSet:
    """A collection of suppression rules with the filtering operation."""

    rules: tuple[Suppression, ...]

    def __bool__(self) -> bool:
        return bool(self.rules)

    def is_suppressed(self, finding: Finding) -> bool:
        return any(rule.matches(finding) for rule in self.rules)

    def apply(self, findings: list[Finding]) -> list[Finding]:
        """Return ``findings`` with every suppressed finding removed.

        Order is preserved; only matching findings are dropped.
        """
        if not self.rules:
            return list(findings)
        return [f for f in findings if not self.is_suppressed(f)]


def _parse_rule(raw: object, index: int) -> Suppression:
    if not isinstance(raw, dict):
        raise SuppressionError(
            f"suppression #{index} must be an object, got {type(raw).__name__}"
        )

    unknown = set(raw) - _KNOWN_KEYS
    if unknown:
        keys = ", ".join(sorted(unknown))
        raise SuppressionError(f"suppression #{index} has unknown key(s): {keys}")

    if "cwe" not in raw:
        raise SuppressionError(f"suppression #{index} is missing required key 'cwe'")

    cwe = raw["cwe"]
    # Accept an int (120) or a numeric/"CWE-120" string for ergonomics.
    if isinstance(cwe, str):
        text = cwe.strip()
        if text.upper().startswith("CWE-"):
            text = text[4:]
        try:
            cwe = int(text)
        except ValueError as exc:
            raise SuppressionError(
                f"suppression #{index} has non-numeric cwe: {raw['cwe']!r}"
            ) from exc
    elif not isinstance(cwe, int) or isinstance(cwe, bool):
        raise SuppressionError(
            f"suppression #{index} cwe must be an integer, got {raw['cwe']!r}"
        )

    constraints: dict[str, str] = {}
    for field in _MATCH_FIELDS:
        if field in raw:
            value = raw[field]
            if not isinstance(value, str):
                raise SuppressionError(
                    f"suppression #{index} field {field!r} must be a string, "
                    f"got {type(value).__name__}"
                )
            constraints[field] = value

    return Suppression(cwe=cwe, **constraints)


def parse_suppressions(text: str) -> SuppressionSet:
    """Parse a suppression document from its JSON ``text``.

    Raises:
        SuppressionError: if the JSON is invalid or the schema is violated.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SuppressionError(f"invalid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise SuppressionError("top level must be an object")

    raw_rules = doc.get("suppressions", [])
    if not isinstance(raw_rules, list):
        raise SuppressionError("'suppressions' must be a list")

    rules = tuple(_parse_rule(r, i) for i, r in enumerate(raw_rules))
    return SuppressionSet(rules=rules)


def load_suppressions(path: str | Path) -> SuppressionSet:
    """Load and parse a suppression file from ``path``.

    Raises:
        SuppressionError: if the file is missing, unreadable, or malformed.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise SuppressionError(f"cannot read suppression file {path!s}: {exc}") from exc
    return parse_suppressions(text)
