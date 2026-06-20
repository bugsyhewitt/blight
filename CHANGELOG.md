# Changelog

All notable changes to blight are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-19

### Added
- **28 CWE pattern detectors** (registered in `src/blight/detectors/__init__.py`):
  - CWE-22 (path traversal), CWE-78 (OS command injection), CWE-89 (SQL injection), CWE-119 (buffer overflow, memcpy-family), CWE-120 (buffer overflow, classic strcpy/sprintf), CWE-122 (heap-based buffer overflow), CWE-131 (incorrect length calculation), CWE-134 (use of externally-controlled format string), CWE-191 (integer underflow), CWE-197 (numeric truncation), CWE-242 (use of inherently dangerous function), CWE-250 (execution with unnecessary privileges), CWE-252 (unchecked return value), CWE-295 (improper cert validation), CWE-327 (use of broken/risky crypto), CWE-330 (use of insufficiently random values), CWE-362 (race condition / TOCTOU), CWE-369 (divide by zero), CWE-377 (insecure temporary file), CWE-401 (memory leak), CWE-415 (double free), CWE-416 (use after free), CWE-426 (untrusted search path), CWE-476 (NULL pointer dereference), CWE-502 (deserialization of untrusted data), CWE-676 (use of potentially-dangerous function), CWE-732 (incorrect permission assignment), CWE-798 (use of hard-coded credentials)
- **3 output formats** (`--format` choice):
  - `json` (default) — full nested finding tree (cwe/function/location/snippet/confidence)
  - `sarif` — SARIF v2.1.0 for GitHub code scanning / DefectDojo import
  - `text` — compact grouped-by-function console output for human review
- **CLI surface**:
  - `--binary PATH` — single ELF binary scan (positional, required)
  - `--checks {22,78,...,798,all}` — which CWE detectors to run
  - `--format {json,sarif,text}` — output format (default json)
  - `--workers N` — parallel binary scanning for directory mode
  - `--min-confidence {low,medium,high}` — filter findings below confidence floor
  - `--fail-on {none,low,medium,high}` — non-zero exit when finding meets threshold
  - `--suppress FILE` — path to suppression YAML/JSON (false-positive whitelist)
  - `--output-file FILE` — write report to file instead of stdout
  - `--version` — print `blight 1.0.0` and exit
- **Backend**: Python 3.13+ stdlib + `r2pipe>=1.8.0` driving radare2 5.x/6.x. No Ghidra, no Java, no Docker, no Rust toolchain.
- **Shared deps**: `binary-finding-schema` + `binary-pipeline` (git-pinned, shared with the necromancer suite).
- **Wheel-install ship-gate contract**: 6 `pytest.mark.ship_gate` tests in `tests/test_wheel_ship_gate.py` pin the wheel-build + fresh-venv-install + `--version` + `__version__` + all-9-public-modules-import + CHANGELOG-entry contract.
- **Dist**: `blight-1.0.0-py3-none-any.whl` and `blight-1.0.0.tar.gz`.

### Changed
- Version bump: `0.1.0` → `1.0.0` (release-cut only; no source-code changes outside the 1-line `__version__` edit in `src/blight/__init__.py`).
- Updated 9 hardcoded `0.1.0` references in `tests/test_wheel_ship_gate.py` to `1.0.0` so the ship-gate contract pins the v1.0 release.

### Security
- blight is a **static pattern detector only** — every finding is a "may apply" advisory, not an active-exploitation claim. A high-confidence `CWE-120 strcpy` finding should be triaged by a reverse-engineer before being treated as exploitable.
- No outbound network calls in the analysis path (radare2 + r2pipe are local subprocess; `--suppress` reads local file).
- The detector does NOT execute the binary — analysis is performed against the disassembled instruction stream, not against runtime behavior.
- False-positive rate is bound by the CWE-pattern regex quality; `--min-confidence` + `--suppress` let operators tune the FP/FN tradeoff per engagement.

### Notes
- This is the first v1.0 release of blight. The 0.x → 1.0 transition reflects: (1) the 28-detector surface is complete and pinned, (2) the wheel-install contract is pinned and green at 498/498 tests, (3) `--version` is wired and matches the wheel glob, (4) the radare2 backend has been exercised across CWE-120/122/415/416/502/etc. via the integration test suite on hosts with radare2 installed.
- 3 declared runtime dependencies: `r2pipe>=1.8.0`, `binary-finding-schema @ git+https://github.com/bugsyhewitt/binary-finding-schema`, `binary-pipeline @ git+https://github.com/bugsyhewitt/binary-pipeline` (no others).
- Requires Python 3.13+; radare2 5.x or 6.x on PATH; `--workers N` parallel mode requires no extra deps (stdlib `concurrent.futures.ThreadPoolExecutor`).
