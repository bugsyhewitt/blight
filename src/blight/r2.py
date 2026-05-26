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


class R2Session(Protocol):
    """Interface detectors depend on. Implemented by :class:`Radare2Session`
    for real analysis and by a fake in the unit tests."""

    def imports(self) -> list[Import]: ...

    def xrefs_to(self, addr: int) -> list[Xref]: ...

    def function_instructions(self, func_addr: int) -> list[Instruction]: ...


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
