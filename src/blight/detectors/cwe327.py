"""CWE-327: Use of a Broken or Risky Cryptographic Algorithm.

Flags calls to library routines that implement cryptographic primitives now
considered broken or risky for security use. Unlike a data-flow check, the
*presence of the call itself* is the finding: linking against a known-broken
hash (MD5/MD4/SHA-1), a broken cipher (DES/RC4/Blowfish), or a weak/predictable
random source used where cryptographic strength is required is the signal.

This is a pure PLT-lookup detector — any call to one of these symbols is
flagged. No data-flow context is needed; the symbol is the evidence. It follows
the same shape as the CWE-676 detector.

Covered routines (grouped by family, with the modern replacement):

* Broken hashes — ``MD5``/``MD4``/``MD2`` and their incremental forms
  (``MD5_Init``/``MD5_Update``/``MD5_Final``, likewise MD4/MD2), plus
  ``SHA1``/``SHA``/``SHA1_Init``/``SHA1_Update``/``SHA1_Final``. MD5 and SHA-1
  are collision-broken; use SHA-256 / SHA-3.
* Broken/legacy ciphers — the single-DES routines
  (``DES_ecb_encrypt``/``DES_ncbc_encrypt``/``DES_cbc_encrypt``/
  ``DES_set_key``/``DES_crypt``), RC4 (``RC4``/``RC4_set_key``), and Blowfish
  (``BF_ecb_encrypt``/``BF_cbc_encrypt``/``BF_set_key``). Single-DES has a
  56-bit key, RC4 has biased keystreams, Blowfish has a 64-bit block; use
  AES-GCM / ChaCha20-Poly1305.
* Weak randomness for crypto — ``srand``/``random``/``srandom`` seed or draw a
  predictable PRNG; ``MD5_crypt``-style password obfuscation belongs above.
  Use ``getrandom`` / a CSPRNG.

The severity is surfaced in the evidence string (as for CWE-676), since the
Finding model carries no dedicated severity field.
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 327

# Each entry: symbol -> (severity, human-readable finding text).
# Severity is surfaced in the evidence string since the Finding model carries
# no dedicated severity field.
_RISKY = {
    # --- Broken hash functions (collision-broken) -------------------------
    "MD5": ("HIGH", "Use of collision-broken MD5 hash; use SHA-256 or SHA-3"),
    "MD5_Init": ("HIGH", "Use of collision-broken MD5 hash; use SHA-256 or SHA-3"),
    "MD5_Update": ("HIGH", "Use of collision-broken MD5 hash; use SHA-256 or SHA-3"),
    "MD5_Final": ("HIGH", "Use of collision-broken MD5 hash; use SHA-256 or SHA-3"),
    "MD4": ("HIGH", "Use of broken MD4 hash; use SHA-256 or SHA-3"),
    "MD4_Init": ("HIGH", "Use of broken MD4 hash; use SHA-256 or SHA-3"),
    "MD4_Update": ("HIGH", "Use of broken MD4 hash; use SHA-256 or SHA-3"),
    "MD4_Final": ("HIGH", "Use of broken MD4 hash; use SHA-256 or SHA-3"),
    "MD2": ("HIGH", "Use of broken MD2 hash; use SHA-256 or SHA-3"),
    "MD2_Init": ("HIGH", "Use of broken MD2 hash; use SHA-256 or SHA-3"),
    "MD2_Update": ("HIGH", "Use of broken MD2 hash; use SHA-256 or SHA-3"),
    "MD2_Final": ("HIGH", "Use of broken MD2 hash; use SHA-256 or SHA-3"),
    "SHA1": ("HIGH", "Use of collision-broken SHA-1 hash; use SHA-256 or SHA-3"),
    "SHA": ("HIGH", "Use of collision-broken SHA-0/SHA-1 hash; use SHA-256 or SHA-3"),
    "SHA1_Init": ("HIGH", "Use of collision-broken SHA-1 hash; use SHA-256 or SHA-3"),
    "SHA1_Update": ("HIGH", "Use of collision-broken SHA-1 hash; use SHA-256 or SHA-3"),
    "SHA1_Final": ("HIGH", "Use of collision-broken SHA-1 hash; use SHA-256 or SHA-3"),
    # --- Broken / legacy block & stream ciphers ---------------------------
    "DES_ecb_encrypt": ("HIGH", "Use of single-DES (56-bit key); use AES-GCM"),
    "DES_ncbc_encrypt": ("HIGH", "Use of single-DES (56-bit key); use AES-GCM"),
    "DES_cbc_encrypt": ("HIGH", "Use of single-DES (56-bit key); use AES-GCM"),
    "DES_set_key": ("HIGH", "Use of single-DES (56-bit key); use AES-GCM"),
    "DES_crypt": ("HIGH", "Use of single-DES (56-bit key); use AES-GCM"),
    "RC4": ("HIGH", "Use of RC4 (biased keystream); use AES-GCM or ChaCha20-Poly1305"),
    "RC4_set_key": (
        "HIGH",
        "Use of RC4 (biased keystream); use AES-GCM or ChaCha20-Poly1305",
    ),
    "BF_ecb_encrypt": ("MEDIUM", "Use of Blowfish (64-bit block); use AES-GCM"),
    "BF_cbc_encrypt": ("MEDIUM", "Use of Blowfish (64-bit block); use AES-GCM"),
    "BF_set_key": ("MEDIUM", "Use of Blowfish (64-bit block); use AES-GCM"),
    # --- Weak / predictable randomness for crypto use ---------------------
    "srand": (
        "MEDIUM",
        "Seeding predictable PRNG srand(); use getrandom() for cryptographic randomness",
    ),
    "random": (
        "MEDIUM",
        "Use of predictable PRNG random(); use getrandom() for cryptographic randomness",
    ),
    "srandom": (
        "MEDIUM",
        "Seeding predictable PRNG srandom(); use getrandom() for cryptographic randomness",
    ),
}

RISKY = tuple(_RISKY)

# Map the per-symbol severity to a triage confidence label. The PLT match is
# always certain (the symbol is the finding), so confidence here reflects how
# strongly the call warrants action, mirroring the documented severity — the
# same policy as CWE-676.
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
