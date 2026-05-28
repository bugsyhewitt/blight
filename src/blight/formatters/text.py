"""Human-readable text output formatter for blight.

blight's machine-readable formats (``json``, ``sarif``) are the right contract
for CI pipelines and security dashboards, but at an interactive terminal a
developer who just wants to know "what is wrong with this binary" has to pipe
the JSON through ``jq``. This formatter renders the same findings — the ones
that survive ``--suppress`` and ``--min-confidence`` — as a compact,
grouped-by-function report with a one-line per-CWE summary, so the common
console case needs no post-processing.

The output is a *report for humans*: it is intentionally not machine-parseable
and carries no stability contract. Consumers that need structured data should
keep using ``--format json`` or ``--format sarif``. This is purely an
output-layer addition — no detector, finding model, or architecture change.

Layout (single binary)::

    binary: path/to/elf
    checks: 78, 120
    3 findings (high: 1, medium: 0, low: 0; plus...)

    function copy_it
      [high] CWE-120 strcpy @ 0x401170
        call to strcpy: strcpy copies without a destination size bound

    summary: CWE-120 x3

A clean binary prints ``no findings`` after the header. A directory scan
prints one such block per binary (errored binaries show their ``error``
string), preceded by a ``directory:`` header.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from blight.findings import Finding
    from blight.scan import ScanResult

# Confidence labels in descending triage order, for stable summary counts.
_CONFIDENCE_ORDER = ("high", "medium", "low")


def _format_checks(checks: "list[int]") -> str:
    return ", ".join(str(c) for c in checks)


def _confidence_breakdown(findings: "list[Finding]") -> str:
    """Return ``high: 1, medium: 0, low: 2`` for the given findings."""
    counts = {level: 0 for level in _CONFIDENCE_ORDER}
    for f in findings:
        # confidence is always one of the three levels (validated on Finding),
        # but guard against an unexpected value rather than KeyError.
        if f.confidence in counts:
            counts[f.confidence] += 1
    return ", ".join(f"{level}: {counts[level]}" for level in _CONFIDENCE_ORDER)


def _cwe_summary(findings: "list[Finding]") -> str:
    """Return ``CWE-120 x3, CWE-78 x1`` in descending-count, then cwe order."""
    counts: dict[int, int] = {}
    for f in findings:
        counts[f.cwe] = counts.get(f.cwe, 0) + 1
    # Sort by count desc, then by cwe id asc, so output is deterministic.
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return ", ".join(f"CWE-{cwe} x{n}" for cwe, n in ordered)


def _render_findings_block(findings: "list[Finding]", indent: str) -> list[str]:
    """Render the grouped-by-function body for one binary's findings.

    Findings arrive already sorted by the engine; this preserves that order
    while grouping consecutive findings under their function header. (A
    function whose findings are not contiguous would get more than one header,
    which is acceptable and still readable — but the engine's sort keeps a
    function's findings together in practice.)
    """
    lines: list[str] = []
    current_function: str | None = None
    for f in findings:
        if f.function != current_function:
            current_function = f.function
            lines.append(f"{indent}function {f.function}")
        lines.append(
            f"{indent}  [{f.confidence}] CWE-{f.cwe} {f.symbol} @ {f.address}"
        )
        lines.append(f"{indent}    {f.evidence}")
    return lines


def _render_one(
    label: str,
    name: str,
    findings: "list[Finding]",
    checks: "list[int] | None",
    error: str | None,
    indent: str,
) -> list[str]:
    """Render a single binary's report block (header + body)."""
    lines = [f"{indent}{label}: {name}"]
    if checks is not None:
        lines.append(f"{indent}checks: {_format_checks(checks)}")

    if error is not None:
        lines.append(f"{indent}error: {error}")
        return lines

    n = len(findings)
    if n == 0:
        lines.append(f"{indent}no findings")
        return lines

    noun = "finding" if n == 1 else "findings"
    lines.append(f"{indent}{n} {noun} ({_confidence_breakdown(findings)})")
    lines.append("")
    lines.extend(_render_findings_block(findings, indent))
    lines.append("")
    lines.append(f"{indent}summary: {_cwe_summary(findings)}")
    return lines


def dump_text_single(
    binary: str, checks: "list[int]", findings: "list[Finding]"
) -> str:
    """Return the human-readable report for a single-binary scan."""
    return "\n".join(
        _render_one("binary", binary, findings, checks, error=None, indent="")
    )


def dump_text_directory(
    directory: str,
    checks: "list[int]",
    results: "list[ScanResult]",
) -> str:
    """Return the human-readable report for a directory scan.

    One block per binary, each indented under a ``directory:`` header. A
    trailing aggregate line totals findings across the whole corpus.
    """
    lines = [f"directory: {directory}", f"checks: {_format_checks(checks)}"]
    total = 0
    for r in results:
        lines.append("")
        lines.extend(
            _render_one(
                "binary",
                r.binary,
                r.findings,
                checks=None,
                error=r.error,
                indent="  ",
            )
        )
        total += len(r.findings)

    lines.append("")
    noun = "finding" if total == 1 else "findings"
    lines.append(
        f"total: {total} {noun} across {len(results)} "
        f"{'binary' if len(results) == 1 else 'binaries'}"
    )
    return "\n".join(lines)
