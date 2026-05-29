"""blight — Python-native CWE pattern detector for ELF binaries.

Drives radare2 via r2pipe to detect a small, well-defined set of statically
detectable CWE classes: CWE-78, CWE-89, CWE-119, CWE-120, CWE-134, CWE-242,
CWE-252, CWE-295, CWE-327, CWE-476, CWE-676. No Ghidra, no Java, no Docker, no
Rust toolchain.
"""

from __future__ import annotations

__version__ = "0.1.0"

from blight.findings import Finding

# pipeline_adapter is kept separate to avoid importing r2pipe at the top level.
# Explicit import: from blight.pipeline_adapter import analyze_binary

__all__ = ["Finding", "__version__"]
