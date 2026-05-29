"""CWE-89: SQL Injection.

Flags calls to library routines that execute a SQL statement supplied as a
string. These are the *sinks* of every SQL-injection vulnerability: if the
query string is assembled from untrusted input with string concatenation or
``sprintf`` rather than a parameterised/prepared statement, the call is the
exact point where the injection lands.

This is a pure PLT-lookup detector — the same shape as CWE-78, CWE-327, CWE-295
and CWE-676. It deliberately does **not** read the query argument out of the
disassembly to prove it is non-constant: unlike the OS-command case (a single
``rdi`` argument), the query string arrives in different argument positions
across the many database client libraries, is frequently built across basic
blocks, and the high-value signal — "this binary executes raw SQL strings at
all, so a reviewer must confirm every call site uses bound parameters" — is
already carried by the presence of the call. Reading the argument would require
per-library, per-architecture data flow for marginal precision gain, so the call
to a raw-SQL-execution routine is itself the finding, surfaced at the per-symbol
confidence for triage.

The *parameterised* counterparts (prepare/bind/step) are NOT flagged — they are
the safe pattern and flagging them would invert the signal:

* SQLite — ``sqlite3_exec`` and the printf-formatting helpers
  ``sqlite3_mprintf`` / ``sqlite3_vmprintf`` build a statement from a format
  string (HIGH). ``sqlite3_prepare`` / ``sqlite3_prepare_v2`` /
  ``sqlite3_prepare_v3`` take a raw SQL string but are the gateway to bound
  parameters, so they are MEDIUM (confirm ``sqlite3_bind_*`` is used, not
  concatenation). ``sqlite3_bind_*`` / ``sqlite3_step`` are NOT flagged.
* MySQL / MariaDB — ``mysql_query`` / ``mysql_real_query`` execute a raw query
  string (HIGH); the prepared-statement API
  (``mysql_stmt_prepare``/``mysql_stmt_bind_param``/``mysql_stmt_execute``) is
  the safe path and is NOT flagged.
* PostgreSQL (libpq) — ``PQexec`` runs a raw command string (HIGH);
  ``PQexecParams`` / ``PQprepare`` / ``PQexecPrepared`` are the parameterised
  forms and are NOT flagged.
* ODBC — ``SQLExecDirect`` / ``SQLExecDirectW`` execute a statement string
  directly (HIGH); ``SQLPrepare`` is MEDIUM.

The severity is surfaced in the evidence string (as for CWE-327 / CWE-676 /
CWE-295), since the Finding model carries no dedicated severity field.
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 89

# Each entry: symbol -> (severity, human-readable finding text).
# Severity is surfaced in the evidence string since the Finding model carries
# no dedicated severity field.
_RISKY = {
    # --- SQLite -----------------------------------------------------------
    "sqlite3_exec": (
        "HIGH",
        "sqlite3_exec runs a raw SQL string — confirm it is not built from "
        "untrusted input; use sqlite3_prepare_v2 + sqlite3_bind_*",
    ),
    "sqlite3_mprintf": (
        "HIGH",
        "sqlite3_mprintf formats a SQL string from arguments — use bound "
        "parameters (sqlite3_prepare_v2 + sqlite3_bind_*) instead of formatting",
    ),
    "sqlite3_vmprintf": (
        "HIGH",
        "sqlite3_vmprintf formats a SQL string from arguments — use bound "
        "parameters (sqlite3_prepare_v2 + sqlite3_bind_*) instead of formatting",
    ),
    "sqlite3_prepare": (
        "MEDIUM",
        "sqlite3_prepare compiles a SQL string — confirm bound parameters "
        "(sqlite3_bind_*) are used and the SQL is not concatenated input",
    ),
    "sqlite3_prepare_v2": (
        "MEDIUM",
        "sqlite3_prepare_v2 compiles a SQL string — confirm bound parameters "
        "(sqlite3_bind_*) are used and the SQL is not concatenated input",
    ),
    "sqlite3_prepare_v3": (
        "MEDIUM",
        "sqlite3_prepare_v3 compiles a SQL string — confirm bound parameters "
        "(sqlite3_bind_*) are used and the SQL is not concatenated input",
    ),
    # --- MySQL / MariaDB --------------------------------------------------
    "mysql_query": (
        "HIGH",
        "mysql_query executes a raw query string — use the prepared-statement "
        "API (mysql_stmt_prepare + mysql_stmt_bind_param)",
    ),
    "mysql_real_query": (
        "HIGH",
        "mysql_real_query executes a raw query string — use the "
        "prepared-statement API (mysql_stmt_prepare + mysql_stmt_bind_param)",
    ),
    # --- PostgreSQL (libpq) ----------------------------------------------
    "PQexec": (
        "HIGH",
        "PQexec runs a raw command string — use PQexecParams / PQprepare + "
        "PQexecPrepared with bound parameters",
    ),
    # --- ODBC -------------------------------------------------------------
    "SQLExecDirect": (
        "HIGH",
        "SQLExecDirect executes a statement string directly — use SQLPrepare + "
        "SQLBindParameter + SQLExecute with bound parameters",
    ),
    "SQLExecDirectW": (
        "HIGH",
        "SQLExecDirectW executes a statement string directly — use SQLPrepare + "
        "SQLBindParameter + SQLExecute with bound parameters",
    ),
    "SQLPrepare": (
        "MEDIUM",
        "SQLPrepare compiles a statement string — confirm SQLBindParameter is "
        "used and the SQL is not concatenated input",
    ),
}

RISKY = tuple(_RISKY)

# Map the per-symbol severity to a triage confidence label. The PLT match is
# always certain (the symbol is the finding); confidence reflects how strongly
# the call warrants action — raw-string execution sinks are HIGH, the
# prepare/compile gateways (which CAN be used safely with bound parameters) are
# MEDIUM. Same policy as CWE-327 / CWE-295 / CWE-676.
_CONFIDENCE_FOR_SEVERITY = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def detect(session) -> list[Finding]:
    findings: list[Finding] = []
    for symbol, xref in call_sites(session, RISKY):
        severity, message = _RISKY[symbol]
        findings.append(
            Finding(
                cwe=CWE,
                function=xref.function,
                address=hex(xref.from_addr),
                evidence=f"[{severity}] call to {symbol}: {message}",
                symbol=symbol,
                confidence=_CONFIDENCE_FOR_SEVERITY[severity],
            )
        )
    return findings
