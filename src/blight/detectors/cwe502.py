"""CWE-502: Deserialization of Untrusted Data.

Flags calls to library routines that materialise an in-memory object graph from
a serialised byte stream where the byte stream is the attack surface. Calling
any of these routines on attacker-influenced bytes is the bug pattern: the
deserialiser will happily build whatever the bytes describe — type-confused
objects, oversized allocations, gadget chains for libraries that resolve type
tags into class instantiations, or, in the Python and PHP cases, executable
code paths whose mere reconstruction runs attacker logic.

This is a pure PLT-lookup detector — any call to one of these symbols is
flagged. No data-flow context is needed; the symbol is the evidence. It follows
the same shape as CWE-327 / CWE-676 / CWE-89.

Covered routines (grouped by family, with the safer alternative):

* Python embedded interpreter — ``PyMarshal_ReadObjectFromString`` /
  ``PyMarshal_ReadObjectFromFile`` / ``PyMarshal_ReadLastObjectFromFile``.
  The marshal format reconstructs arbitrary Python objects including code
  objects whose execution is implicit on import; never use on bytes that
  crossed a trust boundary. Use a parsed wire format (JSON via
  ``PyJSON_LoadFromString``) and reconstruct objects yourself.
* PHP unserialize sinks — ``php_unserialize`` / ``php_var_unserialize`` /
  ``unserialize``. Type-tag-driven object instantiation is the classic
  POP-chain entry point. Use ``json_decode`` and rebuild objects from the
  primitive tree.
* libyaml document loaders — ``yaml_parser_load`` / ``yaml_load`` /
  ``yaml_load_file``. With default tag resolution any ``!!python/object`` or
  custom-type tag triggers attacker-chosen constructors. Use the explicit
  *safe* loader (``yaml_safe_load``) or restrict the tag set.
* CBOR / MessagePack / BSON tree decoders — ``cbor_load`` /
  ``msgpack_unpack`` / ``msgpack_unpack_next`` / ``bson_init_from_json``.
  These build an in-memory tree from attacker bytes without a schema; the
  attacker controls allocation sizing, nesting depth, and tag dispatch. Use
  the streaming/iterator forms with an explicit per-field schema and bound
  the input size before the call.
* Protobuf-C / XDR generic decoders — ``protobuf_c_message_unpack`` (when
  invoked without a length cap or with a descriptor chosen from attacker
  bytes) and the generic ``xdr_pointer`` / ``xdr_reference`` family (which
  follow XDR-encoded pointer chains during decode and are reachable from any
  ``xdrmem_create``-backed stream).

The severity is surfaced in the evidence string (as for CWE-676 / CWE-327),
since the Finding model carries no dedicated severity field. The Python and
PHP families are HIGH because the deserialisation is itself a code-execution
sink; the tree-decoder families are MEDIUM because exploitation typically
requires a follow-on gadget that operates on the resulting tree.
"""

from __future__ import annotations

from blight.findings import Finding

from ._common import call_sites

CWE = 502

_RISKY = {
    # --- Python embedded interpreter ---------------------------------------
    "PyMarshal_ReadObjectFromString": (
        "HIGH",
        "Use of Python marshal deserialiser; reconstructs arbitrary objects "
        "including code objects — use a parsed wire format (JSON) instead",
    ),
    "PyMarshal_ReadObjectFromFile": (
        "HIGH",
        "Use of Python marshal deserialiser; reconstructs arbitrary objects "
        "including code objects — use a parsed wire format (JSON) instead",
    ),
    "PyMarshal_ReadLastObjectFromFile": (
        "HIGH",
        "Use of Python marshal deserialiser; reconstructs arbitrary objects "
        "including code objects — use a parsed wire format (JSON) instead",
    ),
    # --- PHP unserialize sinks ---------------------------------------------
    "php_unserialize": (
        "HIGH",
        "Use of PHP unserialize; type-tag-driven object instantiation is the "
        "classic POP-chain sink — use json_decode and rebuild objects yourself",
    ),
    "php_var_unserialize": (
        "HIGH",
        "Use of PHP unserialize; type-tag-driven object instantiation is the "
        "classic POP-chain sink — use json_decode and rebuild objects yourself",
    ),
    "unserialize": (
        "HIGH",
        "Use of unserialize on a byte stream; type-tag-driven object "
        "instantiation — use a parsed wire format (JSON) and rebuild objects",
    ),
    # --- libyaml document loaders ------------------------------------------
    "yaml_parser_load": (
        "HIGH",
        "Use of libyaml document loader with default tag resolution; custom "
        "type tags trigger attacker-chosen constructors — use a safe loader",
    ),
    "yaml_load": (
        "HIGH",
        "Use of yaml_load with default tag resolution; custom type tags "
        "trigger attacker-chosen constructors — use yaml_safe_load instead",
    ),
    "yaml_load_file": (
        "HIGH",
        "Use of yaml_load_file with default tag resolution; custom type tags "
        "trigger attacker-chosen constructors — use yaml_safe_load instead",
    ),
    # --- CBOR / MessagePack / BSON schema-less tree decoders ---------------
    "cbor_load": (
        "MEDIUM",
        "Use of cbor_load schema-less tree decoder; attacker controls "
        "allocation sizing and nesting — use the streaming decoder with a schema",
    ),
    "msgpack_unpack": (
        "MEDIUM",
        "Use of msgpack_unpack schema-less tree decoder; attacker controls "
        "allocation sizing and nesting — use the streaming decoder with a schema",
    ),
    "msgpack_unpack_next": (
        "MEDIUM",
        "Use of msgpack_unpack_next schema-less tree decoder; attacker controls "
        "allocation sizing and nesting — use the streaming decoder with a schema",
    ),
    "bson_init_from_json": (
        "MEDIUM",
        "Use of bson_init_from_json tree decoder; attacker controls document "
        "shape and sizing — validate against an explicit schema before decoding",
    ),
    # --- protobuf-c / XDR generic decoders ---------------------------------
    "protobuf_c_message_unpack": (
        "MEDIUM",
        "Use of protobuf_c_message_unpack; bound the input length and pin the "
        "descriptor before the call to avoid attacker-chosen type dispatch",
    ),
    "xdr_pointer": (
        "MEDIUM",
        "Use of xdr_pointer in DECODE mode follows attacker-encoded pointer "
        "chains — validate the XDR stream length and depth before the call",
    ),
    "xdr_reference": (
        "MEDIUM",
        "Use of xdr_reference in DECODE mode follows attacker-encoded pointer "
        "chains — validate the XDR stream length and depth before the call",
    ),
}

RISKY = tuple(_RISKY)

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
