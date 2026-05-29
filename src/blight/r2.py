"""radare2 driver for blight.

This module is the single boundary between blight and the radare2 process. It
wraps ``r2pipe`` and exposes a small, structured API that detectors consume:
imports, cross-references to a symbol's PLT entry, and the disassembly of a
function.

Architectural decision — the mock boundary lives HERE, not at r2pipe.
[Worker decision: detectors operate on the R2Session interface, so unit tests
inject a fake R2Session and never touch r2pipe or a real radare2 process. The
one integration test constructs a real R2Session. This keeps the test suite
runnable without radare2 installed, per v0.1 criterion 7.]
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class Import:
    """An imported (external) symbol as reported by radare2's ``iij``."""

    name: str
    plt: int | None


@dataclass(frozen=True)
class Xref:
    """A cross-reference to a symbol, from radare2's ``axtj``."""

    from_addr: int
    type: str
    function: str
    opcode: str


@dataclass(frozen=True)
class Instruction:
    """A single disassembled instruction from radare2's ``pdfj``."""

    addr: int
    disasm: str


@dataclass(frozen=True)
class Str:
    """A literal string extracted from the binary, from radare2's ``izzj``.

    ``izzj`` lists every printable string in the file's sections (not just the
    declared .rodata literals ``izj`` reports), which is what a credential hunt
    wants — hard-coded secrets are frequently squirrelled away in odd sections.
    """

    vaddr: int
    string: str
    section: str


class R2Session(Protocol):
    """Interface detectors depend on. Implemented by :class:`Radare2Session`
    for real analysis and by a fake in the unit tests."""

    def imports(self) -> list[Import]: ...

    def xrefs_to(self, addr: int) -> list[Xref]: ...

    def function_instructions(self, func_addr: int) -> list[Instruction]: ...

    def function_addrs(self) -> list[int]: ...

    def arch(self) -> str: ...

    def strings(self) -> list[Str]: ...


class Radare2Session:
    """Concrete :class:`R2Session` backed by a real radare2 process.

    Opens the binary, runs full analysis (``aaa``) once, and answers detector
    queries against the live process. Use as a context manager so the radare2
    process is always closed.
    """

    def __init__(self, binary_path: str) -> None:
        # Imported lazily so the package imports cleanly (and unit tests run)
        # on machines without r2pipe / radare2 installed.
        import r2pipe  # noqa: PLC0415

        self._r2 = r2pipe.open(binary_path, flags=["-2"])
        self._r2.cmd("aaa")

    def __enter__(self) -> "Radare2Session":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._r2.quit()
        except Exception:  # pragma: no cover - best-effort cleanup
            pass

    def _cmdj(self, cmd: str) -> Any:
        raw = self._r2.cmd(cmd)
        if not raw or not raw.strip():
            return []
        try:
            return json.loads(raw)
        except json.JSONDecodeError:  # pragma: no cover - defensive
            return []

    def imports(self) -> list[Import]:
        data = self._cmdj("iij")
        return [Import(name=i.get("name", ""), plt=i.get("plt")) for i in data]

    def xrefs_to(self, addr: int) -> list[Xref]:
        data = self._cmdj(f"axtj @ {addr}")
        out: list[Xref] = []
        for x in data:
            out.append(
                Xref(
                    from_addr=x.get("from", 0),
                    type=x.get("type", ""),
                    function=x.get("realname") or x.get("fcn_name") or "",
                    opcode=x.get("opcode", ""),
                )
            )
        return out

    def function_instructions(self, func_addr: int) -> list[Instruction]:
        data = self._cmdj(f"pdfj @ {func_addr}")
        ops = data.get("ops", []) if isinstance(data, dict) else []
        out: list[Instruction] = []
        for o in ops:
            out.append(
                Instruction(
                    addr=o.get("addr", 0),
                    disasm=o.get("disasm") or o.get("opcode", ""),
                )
            )
        return out

    def function_addrs(self) -> list[int]:
        """Return the entry address of every function radare2 discovered.

        Backed by ``aflj`` (the analysis function list). Detectors that reason
        about instruction patterns which are not anchored to a library call site
        — e.g. a divide-by-zero where the divisor is a register — need to walk
        every function body, not just PLT cross-references.
        """
        data = self._cmdj("aflj")
        if not isinstance(data, list):
            return []
        out: list[int] = []
        for fn in data:
            # radare2 reports the function entry under "offset" on some builds
            # and "addr" on others; accept whichever is an integer.
            addr = fn.get("offset")
            if not isinstance(addr, int):
                addr = fn.get("addr")
            if isinstance(addr, int):
                out.append(addr)
        return out

    def strings(self) -> list[Str]:
        """Return every printable string in the binary, via ``izzj``.

        ``izzj`` scans the whole file (all sections), not just the strings
        radare2 has attributed to data symbols, so embedded credentials that
        live outside .rodata are still surfaced. The base64-or-raw ``string``
        field is decoded by radare2 already; we take it verbatim.
        """
        import base64  # noqa: PLC0415

        data = self._cmdj("izzj")
        # izzj shape: a list of {"vaddr", "string", "section", ...} objects, or
        # (older r2) {"strings": [...]}.
        entries = data.get("strings", []) if isinstance(data, dict) else data
        out: list[Str] = []
        for s in entries:
            raw = s.get("string", "")
            # Some r2 builds base64-encode the string under a "type":"base64"
            # marker; decode defensively, falling back to the raw text.
            if s.get("type") == "base64" and raw:
                try:
                    raw = base64.b64decode(raw).decode("utf-8", "replace")
                except Exception:  # pragma: no cover - defensive
                    pass
            out.append(
                Str(
                    vaddr=s.get("vaddr", 0),
                    string=raw,
                    section=s.get("section", ""),
                )
            )
        return out

    def arch(self) -> str:
        """Return the binary's architecture as a normalized blight key.

        Uses radare2's ``iAj`` (binary arch info) and collapses the reported
        ``arch``/``bits`` to one of the keys blight's register tables use
        (``x86_64``, ``arm64``). Unknown architectures fall back to the default
        so detectors keep their conservative x86_64 behaviour.
        """
        from blight.detectors._argregs import DEFAULT_ARCH, normalize_arch

        data = self._cmdj("iAj")
        # iAj shape: {"bins": [{"arch": "...", "bits": N, ...}]}
        bins = data.get("bins", []) if isinstance(data, dict) else []
        if not bins:
            return DEFAULT_ARCH
        info = bins[0]
        return normalize_arch(info.get("arch"), info.get("bits"))
