"""CWE-295: Improper Certificate Validation.

Flags calls to library routines whose *presence* indicates that TLS/SSL
certificate or hostname verification is being configured by hand — the call
site is exactly where verification is most commonly disabled or weakened
(``SSL_VERIFY_NONE``, a verify callback that always returns "OK", a peer-verify
toggle set to 0, hostname checks turned off). On the embedded/firmware targets
blight serves, broken cert validation is one of the most frequently shipped TLS
flaws.

This is a pure PLT-lookup detector — the same shape as CWE-327 and CWE-676. It
does **not** attempt to read the verify-mode argument out of the disassembly
(that would require per-architecture data-flow, and the constant is frequently
loaded indirectly); instead the call to a verification-policy routine is itself
the finding, surfaced at ``medium`` confidence so triage can confirm the mode
argument. The deprecated-by-design hostname helpers are flagged ``high``.

Covered routines (grouped by family, with what to do instead):

* OpenSSL verify-policy toggles — ``SSL_CTX_set_verify`` / ``SSL_set_verify``
  (the mode is frequently ``SSL_VERIFY_NONE``), the manual result inspector
  ``SSL_get_verify_result`` is *correct* and NOT flagged. ``SSL_CTX_set_cert_verify_callback``
  installs a wholesale replacement for the built-in chain check.
* OpenSSL deprecated hostname matching — ``X509_check_host`` is the right call;
  the legacy ``X509_check_issued`` alone is not hostname validation. The
  deprecated, unsafe ``SSL_get_peer_certificate`` used without a following
  ``SSL_get_verify_result`` is the classic "I have *a* cert, therefore trusted"
  bug.
* GnuTLS — ``gnutls_certificate_set_verify_function`` and the deprecated
  ``gnutls_certificate_verify_peers2`` (no hostname check; use
  ``gnutls_certificate_verify_peers3`` / ``gnutls_session_set_verify_cert``).
* libcurl — ``curl_easy_setopt`` is the sink for ``CURLOPT_SSL_VERIFYPEER`` /
  ``CURLOPT_SSL_VERIFYHOST`` being set to 0; the call is flagged for review.
* mbedTLS — ``mbedtls_ssl_conf_authmode`` (the mode is frequently
  ``MBEDTLS_SSL_VERIFY_NONE``).

The per-symbol severity is surfaced in the evidence string and mapped to the
triage confidence label, mirroring the CWE-327 / CWE-676 policy.
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 295

# Each entry: symbol -> (severity, human-readable finding text).
# Severity is surfaced in the evidence string since the Finding model carries
# no dedicated severity field.
_RISKY = {
    # --- OpenSSL verify-policy toggles ------------------------------------
    "SSL_CTX_set_verify": (
        "HIGH",
        "SSL_CTX_set_verify configures the verify mode — confirm it is not "
        "SSL_VERIFY_NONE and that a verify callback does not force success",
    ),
    "SSL_set_verify": (
        "HIGH",
        "SSL_set_verify configures the verify mode — confirm it is not "
        "SSL_VERIFY_NONE and that a verify callback does not force success",
    ),
    "SSL_CTX_set_cert_verify_callback": (
        "HIGH",
        "SSL_CTX_set_cert_verify_callback replaces the built-in chain "
        "verification wholesale — confirm the callback actually validates",
    ),
    "SSL_get_peer_certificate": (
        "MEDIUM",
        "SSL_get_peer_certificate returns a cert even when verification "
        "failed — pair it with SSL_get_verify_result, presence alone is not trust",
    ),
    # --- GnuTLS -----------------------------------------------------------
    "gnutls_certificate_set_verify_function": (
        "HIGH",
        "gnutls_certificate_set_verify_function installs a custom verify "
        "callback — confirm it fails closed on an invalid chain",
    ),
    "gnutls_certificate_verify_peers2": (
        "HIGH",
        "gnutls_certificate_verify_peers2 does not check the hostname; use "
        "gnutls_certificate_verify_peers3 or gnutls_session_set_verify_cert",
    ),
    # --- libcurl ----------------------------------------------------------
    "curl_easy_setopt": (
        "MEDIUM",
        "curl_easy_setopt is the sink for CURLOPT_SSL_VERIFYPEER / "
        "CURLOPT_SSL_VERIFYHOST — confirm neither is disabled (set to 0)",
    ),
    # --- mbedTLS ----------------------------------------------------------
    "mbedtls_ssl_conf_authmode": (
        "HIGH",
        "mbedtls_ssl_conf_authmode configures the verify mode — confirm it "
        "is not MBEDTLS_SSL_VERIFY_NONE",
    ),
}

RISKY = tuple(_RISKY)

# Map the per-symbol severity to a triage confidence label. The PLT match is
# always certain (the symbol is the finding), so confidence here reflects how
# strongly the call warrants action, mirroring the CWE-327 / CWE-676 policy.
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
