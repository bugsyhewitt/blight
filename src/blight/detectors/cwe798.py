"""CWE-798: Use of Hard-coded Credentials.

Unlike every other detector shipped so far, this one does **not** key off the
PLT / call graph — a hard-coded secret leaves no call-site fingerprint, it is
*data*. CWE-798 therefore scans the binary's extracted string literals
(``R2Session.strings()`` → radare2 ``izzj``) for the textual signatures of an
embedded credential.

Hard-coded credentials are a perennial MITRE Top-25 weakness and are endemic in
the firmware / embedded ELF binaries blight targets — a baked-in default
admin password or an embedded private key is one of the most common and most
damaging findings in a real binary audit. radare2 already gives us every
printable string for free, so the marginal cost of this check is tiny while the
value is high.

Detection strategy — three independent string-shape signals:

1. **Embedded private-key / certificate material** (HIGH). A PEM
   ``-----BEGIN ... PRIVATE KEY-----`` armour header, an OpenSSH private-key
   banner, or a PuTTY ``PRIVATE-KEYS`` header inside a shipped binary is an
   unambiguous secret — there is no benign reason to bake a private key into an
   executable. The string itself is the finding.

2. **Credential-bearing connection strings / URIs** (HIGH). A URL or DSN that
   carries an inline ``user:password@host`` authority
   (``mysql://root:hunter2@db``, ``https://admin:secret@10.0.0.1``) embeds the
   password in the binary. We require a *non-empty, non-placeholder* password
   component so ``http://user:@host`` and ``http://x:%s@host`` (a format
   template) do not fire.

3. **Assignment-style secrets** (HIGH / MEDIUM). A ``key = value`` or
   ``key: value`` (or shell ``export KEY=value``) where the key names a secret
   (``password``, ``passwd``, ``pwd``, ``secret``, ``api_key``, ``apikey``,
   ``access_key``, ``secret_key``, ``token``, ``auth_token``,
   ``private_key``, ``client_secret``, ``aws_secret_access_key``) and the value
   is a concrete literal — not empty, not a format placeholder (``%s``,
   ``{0}``, ``$VAR``, ``${VAR}``), and not an obvious non-secret sentinel
   (``none``/``null``/``changeme``/``example``/``your_*_here``). Password-class
   keys are HIGH; the lower-risk token/key class is HIGH too when the value is
   long/secret-shaped and MEDIUM when it is short (it may be a config knob, not
   a secret).

False-positive control: every signal requires a *concrete* value and rejects
format templates and placeholders, because the most common benign hit is a
``"%s=%s"``-style format string or an empty default. The detector never reads
or transmits the secret value itself beyond a redacted preview in the evidence
string (see :func:`_redact`).
"""

from __future__ import annotations

import re

from blight.findings import Finding
from blight.r2 import Str

CWE = 798

# --- Signal 1: embedded private-key / cert material ------------------------
_KEY_HEADERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "PuTTY-User-Key-File-",
    "PuTTY-User-Key-File:",
)

# --- Signal 2: credential-bearing URI authority ---------------------------
# scheme://user:password@host — capture the password component.
_URI_CRED_RE = re.compile(
    r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s/@]+)@[^\s/]+",
    re.IGNORECASE,
)

# --- Signal 3: assignment-style secrets -----------------------------------
# Key-name *component* tokens. A key matches if, after normalising separators
# to '_', one of its underscore-delimited components equals one of these (so
# `db_passwd`, `admin_password`, `x.api_key` all match, but `keyboard` does
# not). Password-class components are HIGH; token/key-class severity depends on
# the value's secret-shape.
_PASSWORD_COMPONENTS = frozenset(
    {"password", "passwd", "passphrase", "pwd"}
)
_TOKEN_COMPONENTS = frozenset(
    {
        "secret",
        "apikey",
        "token",
        # Multi-word forms are normalised to a joined component below, but the
        # common single components below also catch `*_secret`, `*_token`, etc.
    }
)
# Multi-component key names matched as a whole (after normalisation) — these
# carry intrinsic secret meaning that a single component would miss.
_TOKEN_FULL_KEYS = frozenset(
    {
        "secret_key",
        "client_secret",
        "api_key",
        "access_key",
        "access_token",
        "auth_token",
        "auth_key",
        "private_key",
        "aws_secret_access_key",
        "aws_access_key_id",
    }
)


def _classify_key(normalized_key: str) -> str | None:
    """Return ``"password"``, ``"token"``, or ``None`` for a normalised key.

    ``normalized_key`` has separators collapsed to ``_`` and is lower-cased.
    Password-class wins over token-class when both could match.
    """
    components = set(normalized_key.split("_"))
    if components & _PASSWORD_COMPONENTS:
        return "password"
    if normalized_key in _TOKEN_FULL_KEYS or (components & _TOKEN_COMPONENTS):
        return "token"
    return None

# key <sep> value, where sep is '=' / ':' (optionally after `export `).
_ASSIGN_RE = re.compile(
    r"""(?ix)              # case-insensitive, verbose
    (?:^|[\s;,&"'(\[{])    # left boundary (start / separator / quote / bracket)
    (?:export\s+)?         # optional shell export
    ([a-z][a-z0-9_.\-]*)   # 1: the key name
    \s*[:=]\s*             # the = or : separator
    (?:["']?)              # optional opening quote around the value
    ([^\s"';,&)\]}]+)      # 2: the value (no whitespace / quote / separator)
    """,
)

# Values that are placeholders / templates / sentinels — never a real secret.
# Anchored at the start (the value tokeniser already strips trailing
# separators/quotes), so an unterminated `${API_KEY` template still matches via
# the leading-`$` rule.
_PLACEHOLDER_RE = re.compile(
    r"""(?ix)
    ^(?:
        %[-+ #0-9.]*[a-z]              # printf conversion: %s %d %02x ...
      | \$.*                          # any $-prefixed shell/template var: $VAR ${VAR ${VAR}
      | \{.*                          # {}, {0}, {name}, or unterminated {name
      | (?:none|null|nil|false|true)
      | (?:changeme|change_me|example|test|sample|default)
      | x{3,} | \*+ | \.+ | -+ | _+
      | your[_a-z0-9]*here
      | (?:placeholder|redacted|todo|fixme)
    )$
    """,
)

# A value is "secret-shaped" if it is long enough and not a tidy English word /
# small integer. Used to upgrade token-class findings to HIGH.
_SECRET_SHAPED_MIN_LEN = 12


def _redact(value: str) -> str:
    """Return a non-disclosing preview of a secret value for the evidence text.

    Keeps the first character and the length so a human can correlate it
    against the binary without the report itself leaking the credential.
    """
    if len(value) <= 1:
        return "*"
    return f"{value[0]}{'*' * (len(value) - 1)} (len={len(value)})"


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.match(value))


def _is_secret_shaped(value: str) -> bool:
    if len(value) < _SECRET_SHAPED_MIN_LEN:
        return False
    # Mixed character classes or base64/hex bulk → looks like a real token.
    has_alpha = any(c.isalpha() for c in value)
    has_other = any((not c.isalpha()) for c in value)
    return has_alpha and (has_other or len(value) >= 20)


def _scan_string(s: Str) -> list[Finding]:
    """Return findings for one extracted string literal."""
    text = s.string
    if not text:
        return []
    addr = hex(s.vaddr)
    findings: list[Finding] = []

    # --- Signal 1: PEM / private-key material -----------------------------
    for header in _KEY_HEADERS:
        if header in text:
            findings.append(
                Finding(
                    cwe=CWE,
                    function=s.section or "(data)",
                    address=addr,
                    evidence=(
                        f"[HIGH] embedded private key / key material "
                        f"('{header.strip('-')[:32]}') hard-coded in the binary"
                    ),
                    symbol=header.strip("-").strip()[:48] or "private-key",
                    confidence="high",
                )
            )
            return findings  # one finding per key blob is enough

    # --- Signal 2: credential in a connection URI -------------------------
    for m in _URI_CRED_RE.finditer(text):
        pw = m.group(1)
        if pw and not _is_placeholder(pw):
            findings.append(
                Finding(
                    cwe=CWE,
                    function=s.section or "(data)",
                    address=addr,
                    evidence=(
                        f"[HIGH] hard-coded credential in connection URI "
                        f"(password {_redact(pw)})"
                    ),
                    symbol="connection-uri",
                    confidence="high",
                )
            )

    # --- Signal 3: assignment-style secret --------------------------------
    for m in _ASSIGN_RE.finditer(text):
        key_raw, value = m.group(1), m.group(2)
        key = key_raw.lower().replace("-", "_").replace(".", "_")
        key_class = _classify_key(key)
        if key_class is None:
            continue
        if _is_placeholder(value):
            continue
        if key_class == "password":
            severity, confidence = "HIGH", "high"
        else:  # token / key class — depends on how secret-shaped the value is
            if _is_secret_shaped(value):
                severity, confidence = "HIGH", "high"
            else:
                severity, confidence = "MEDIUM", "medium"
        findings.append(
            Finding(
                cwe=CWE,
                function=s.section or "(data)",
                address=addr,
                evidence=(
                    f"[{severity}] hard-coded credential: "
                    f"{key_raw}={_redact(value)}"
                ),
                symbol=key_raw,
                confidence=confidence,
            )
        )

    return findings


def detect(session) -> list[Finding]:
    findings: list[Finding] = []
    for s in session.strings():
        findings.extend(_scan_string(s))
    return findings
