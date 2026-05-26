"""Shared helpers for blight detectors."""

from __future__ import annotations

from collections.abc import Iterable

from blight.r2 import R2Session, Xref


def call_sites(session: R2Session, symbol_names: Iterable[str]) -> list[tuple[str, Xref]]:
    """Return ``(symbol, xref)`` pairs for every CALL to any of ``symbol_names``.

    Resolves each requested symbol to its PLT entry via the import table, then
    asks radare2 for cross-references to that address. Only CALL-type xrefs are
    returned — data references to a PLT slot are not invocations.
    """
    wanted = set(symbol_names)
    plt_by_symbol = {
        imp.name: imp.plt
        for imp in session.imports()
        if imp.name in wanted and imp.plt is not None
    }

    results: list[tuple[str, Xref]] = []
    for symbol, plt in plt_by_symbol.items():
        for xref in session.xrefs_to(plt):
            if xref.type.upper() == "CALL":
                results.append((symbol, xref))
    return results
