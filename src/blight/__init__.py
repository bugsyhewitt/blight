"""blight — Python-native CWE pattern detector for ELF binaries.

Drives radare2 via r2pipe to detect a small, well-defined set of statically
detectable CWE classes: CWE-78, CWE-120, CWE-242. No Ghidra, no Java, no
Docker, no Rust toolchain.
"""

from __future__ import annotations

__version__ = "0.1.0"

from blight.findings import Finding

__all__ = ["Finding", "__version__"]
