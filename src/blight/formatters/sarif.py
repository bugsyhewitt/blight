"""SARIF 2.1.0 output formatter for blight.

Produces a SARIF document suitable for GitHub Code Scanning and VS Code
security extensions. Each unique CWE becomes a rule; each Finding becomes
a result referencing that rule.

Severity mapping (no severity field on Finding — derived from CWE class):
  CWE-22  (Path Traversal)               → HIGH  → "error"
  CWE-78  (OS Command Injection)         → HIGH  → "error"
  CWE-89  (SQL Injection)                → HIGH  → "error"
  CWE-119 (Memory-Bounds Restriction)    → HIGH  → "error"
  CWE-120 (Buffer Copy w/o Size Check)   → HIGH  → "error"
  CWE-122 (Heap-Based Buffer Overflow)   → HIGH  → "error"
  CWE-131 (Incorrect Buffer-Size Calc.)  → HIGH  → "error"
  CWE-134 (Uncontrolled Format String)   → HIGH  → "error"
  CWE-197 (Numeric Truncation Error)     → MEDIUM → "warning"
  CWE-242 (Use of Inherently Dangerous)  → MEDIUM → "warning"
  CWE-295 (Improper Certificate Valid.)  → HIGH  → "error"
  CWE-327 (Broken/Risky Cryptography)    → HIGH  → "error"
  CWE-330 (Insufficiently Random Values) → HIGH  → "error"
  CWE-377 (Insecure Temporary File)      → HIGH  → "error"
  CWE-401 (Missing Memory Release / Leak)→ HIGH  → "error"
  CWE-415 (Double Free)                  → HIGH  → "error"
  CWE-416 (Use After Free)               → HIGH  → "error"
  CWE-426 (Untrusted Search Path)        → HIGH  → "error"
  CWE-676 (Use of Potentially Dangerous) → MEDIUM → "warning"
  CWE-798 (Use of Hard-coded Credentials)→ HIGH  → "error"
  unknown                                → "note"
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from blight.findings import Finding

_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)
_INFORMATION_URI = "https://github.com/bugsyhewitt/blight"

# CWE id → (short description, SARIF level)
_CWE_META: dict[int, tuple[str, str]] = {
    22:  ("Improper Limitation of a Pathname to a Restricted Directory", "error"),
    78:  ("OS Command Injection", "error"),
    89:  ("SQL Injection", "error"),
    119: ("Improper Restriction of Operations within the Bounds of a Memory Buffer", "error"),
    120: ("Buffer Copy without Checking Size of Input", "error"),
    122: ("Heap-Based Buffer Overflow", "error"),
    131: ("Incorrect Calculation of Buffer Size", "error"),
    134: ("Uncontrolled Format String", "error"),
    197: ("Numeric Truncation Error", "warning"),
    242: ("Use of Inherently Dangerous Function", "warning"),
    250: ("Execution with Unnecessary Privileges", "error"),
    295: ("Improper Certificate Validation", "error"),
    327: ("Use of a Broken or Risky Cryptographic Algorithm", "error"),
    330: ("Use of Insufficiently Random Values", "error"),
    377: ("Insecure Temporary File", "error"),
    401: ("Missing Release of Memory after Effective Lifetime", "error"),
    415: ("Double Free", "error"),
    416: ("Use After Free", "error"),
    426: ("Untrusted Search Path", "error"),
    676: ("Use of Potentially Dangerous Function", "warning"),
    732: ("Incorrect Permission Assignment for Critical Resource", "error"),
    798: ("Use of Hard-coded Credentials", "error"),
}


def _level_for_cwe(cwe: int) -> str:
    """Return the SARIF level for a CWE id."""
    return _CWE_META.get(cwe, ("Unknown", "note"))[1]


def _short_description(cwe: int) -> str:
    return _CWE_META.get(cwe, ("Unknown CWE", "note"))[0]


def build_sarif(
    binary: str,
    findings: "list[Finding]",
    version: str = "0.1.0",
) -> dict:
    """Build a SARIF 2.1.0 document from a list of blight findings.

    Args:
        binary: Path to the analysed binary (used as the artifact URI).
        findings: List of :class:`~blight.findings.Finding` instances.
        version: Tool version string to embed in the driver block.

    Returns:
        A dict ready to be serialised with :func:`json.dumps`.
    """
    # Collect unique CWE ids (in insertion order) for the rules array.
    seen_cwes: dict[int, None] = {}
    for f in findings:
        seen_cwes.setdefault(f.cwe, None)

    rules = [
        {
            "id": f"CWE-{cwe}",
            "name": _short_description(cwe).replace(" ", ""),
            "shortDescription": {"text": _short_description(cwe)},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe}.html",
        }
        for cwe in seen_cwes
    ]

    results = [
        {
            "ruleId": f"CWE-{f.cwe}",
            "level": _level_for_cwe(f.cwe),
            "message": {"text": f.evidence},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": binary},
                        "logicalLocations": [
                            {"name": f.function, "kind": "function"}
                        ],
                    }
                }
            ],
            "properties": {
                "address": f.address,
                "symbol": f.symbol,
                "confidence": f.confidence,
            },
        }
        for f in findings
    ]

    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "blight",
                        "version": version,
                        "informationUri": _INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def dump_sarif(
    binary: str,
    findings: "list[Finding]",
    version: str = "0.1.0",
) -> str:
    """Return a formatted SARIF JSON string."""
    return json.dumps(build_sarif(binary, findings, version=version), indent=2)
