# blight

A Python-native CWE pattern detector for ELF binaries. `blight` drives
[radare2](https://github.com/radareorg/radare2) via
[r2pipe](https://github.com/radareorg/radare2-r2pipe) for disassembly,
control-flow, and cross-reference analysis — **no Ghidra, no Java, no Docker,
no Rust toolchain.**

It detects a small, deliberately tight set of statically detectable CWE
classes. Each detector is a single, auditable Python file.

## System dependency: radare2

`blight` shells out to `radare2` through `r2pipe`. **You must install radare2
separately** — it is not a pip dependency and is not bundled.

```bash
# Most distributions:
#   Arch:    sudo pacman -S radare2
#   Debian:  sudo apt install radare2
#   macOS:   brew install radare2
# Or from source (recommended for latest):
git clone https://github.com/radareorg/radare2
radare2/sys/install.sh
```

Verify it's on your PATH:

```bash
radare2 -version
```

## Install

```bash
git clone https://github.com/bugsyhewitt/blight
cd blight
pip install -e .          # Python 3.13+
```

This installs the `blight` console command and the `r2pipe` Python binding.

## Usage

```
blight --binary PATH [--checks {78,120,134,242,676,all}] [--format json]
```

- `--binary` — path to the ELF binary to analyze (required)
- `--checks` — which CWE check to run; one of `78`, `120`, `134`, `242`, `676`,
  or `all` (default: `all`)
- `--format` — output format; `json` (default)

Output is a JSON object with the analyzed `binary`, the `checks` run, and a
list of `findings`. Each finding carries `cwe`, `function`, `address`,
`evidence`, the dangerous `symbol`, and a triage `confidence` label.

### Confidence scoring

Every finding carries a `confidence` label — one of `high`, `medium`, or
`low` — so consumers can triage and filter without understanding each
detector's heuristic internals. The label reflects how certain the detection
is, not how severe the bug would be if exploited:

| Confidence | Meaning | Applies to |
|---|---|---|
| `high` | The dangerous symbol *is* the finding; no data-flow inference. | CWE-120, CWE-242, CWE-676 (HIGH-severity symbols) |
| `medium` | A heuristic fired (e.g. non-constant argument) that can miss aliased registers. | CWE-78, CWE-134, CWE-676 (MEDIUM-severity symbols) |
| `low` | The pattern is weakly indicative. | CWE-676 (LOW-severity symbols) |

For CWE-676 the confidence mirrors the per-symbol severity surfaced in the
evidence string (HIGH→`high`, MEDIUM→`medium`, LOW→`low`). The field is also
emitted in `--format sarif` output under each result's `properties.confidence`.

## Detected CWE classes

`blight` detects well-defined classes that are reliably catchable via static
disassembly + cross-reference analysis. The three CWE-78/120/242 classes shipped
in v0.1; CWE-134 and CWE-676 were added post-v0.1 (see
[POST_V01.md](POST_V01.md)).

### CWE-78 — OS Command Injection

Calls to `system()` and the `exec*()` family **where the command argument is
not a constant string literal**. A constant command such as `system("ls")` is
not flagged; a command built from a buffer or variable is. The argument-register
convention is resolved per architecture (see
[Architecture support](#architecture-support)), so this works on x86_64 and
AArch64.

```bash
$ blight --binary tests/fixtures/system-vuln --checks 78 --format json
{
  "binary": "tests/fixtures/system-vuln",
  "checks": [78],
  "findings": [
    {
      "cwe": 78,
      "function": "run_cmd",
      "address": "0x40118f",
      "evidence": "call to system with a non-constant command argument (possible OS command injection)",
      "symbol": "system",
      "confidence": "medium"
    }
  ]
}
```

### CWE-120 — Buffer Copy without Checking Size of Input

Calls to the classic unchecked-copy primitives: `strcpy`, `sprintf`, `gets`.

```bash
$ blight --binary tests/fixtures/strcpy-vuln --checks 120 --format json
{
  "binary": "tests/fixtures/strcpy-vuln",
  "checks": [120],
  "findings": [
    {
      "cwe": 120,
      "function": "copy_it",
      "address": "0x401170",
      "evidence": "call to strcpy: strcpy copies without a destination size bound",
      "symbol": "strcpy",
      "confidence": "high"
    }
  ]
}
```

### CWE-134 — Use of Externally-Controlled Format String

Calls to the `printf` family (`printf`, `fprintf`, `syslog`, `snprintf`,
`vprintf`, `vsprintf`, `vfprintf`, `vsyslog`) **where the format-string argument
is not a constant string literal**. A literal format such as
`printf("Hello %s\n", name)` is not flagged; a format built from a buffer or
variable is. Like CWE-78, the format-argument register is resolved per
architecture, so this works on x86_64 and AArch64.

### CWE-242 — Use of Inherently Dangerous Function

Calls to functions that cannot be used safely under any circumstances:
`gets`, `getpass`.

```bash
$ blight --binary tests/fixtures/gets-vuln --checks 242 --format json
{
  "binary": "tests/fixtures/gets-vuln",
  "checks": [242],
  "findings": [
    {
      "cwe": 242,
      "function": "main",
      "address": "0x401159",
      "evidence": "call to gets: gets cannot be used safely and was removed from C11",
      "symbol": "gets",
      "confidence": "high"
    }
  ]
}
```

### CWE-676 — Use of Potentially Dangerous Function

Calls to libc functions that have a direct, safer replacement and no good
reason to appear in new code. This is a pure PLT-lookup check — any call site is
flagged; the severity is surfaced in the evidence string.

| Symbol | Severity | Why it's flagged | Use instead |
|---|---|---|---|
| `tmpnam` | HIGH | TOCTOU race condition | `mkstemp()` |
| `mktemp` | HIGH | TOCTOU race condition | `mkstemp()` |
| `strtok` | MEDIUM | Non-reentrant (static state) | `strtok_r()` |
| `rand` | MEDIUM | Predictable PRNG | `getrandom()` |
| `asctime` | LOW | Non-reentrant (static buffer) | `asctime_r()` |
| `ctime` | LOW | Non-reentrant (static buffer) | `ctime_r()` |

```bash
$ blight --binary path/to/elf --checks 676 --format json
{
  "binary": "path/to/elf",
  "checks": [676],
  "findings": [
    {
      "cwe": 676,
      "function": "make_path",
      "address": "0x401160",
      "evidence": "[HIGH] call to tmpnam: Use of tmpnam() has race condition; use mkstemp()",
      "symbol": "tmpnam",
      "confidence": "high"
    }
  ]
}
```

## Architecture support

`blight` supports **x86_64** and **AArch64 (arm64)** ELF binaries.

The CWE-120, CWE-242, and CWE-676 detectors flag any call site to a dangerous
symbol and are therefore architecture-agnostic — they work on every
architecture radare2 can disassemble. The CWE-78 and CWE-134 detectors inspect
the register that carries a specific argument (the command string, the format
string), which depends on the calling convention:

| Argument | x86_64 (SysV) | AArch64 (AAPCS64) |
|---|---|---|
| arg0 | `rdi` (`edi`/`di`) | `x0` (`w0`) |
| arg1 | `rsi` (`esi`/`si`) | `x1` (`w1`) |
| arg2 | `rdx` (`edx`/`dx`) | `x2` (`w2`) |

The architecture is detected automatically from the binary via radare2's `iAj`
and resolved through `blight.detectors._argregs`. Unknown or 32-bit-only
architectures fall back to the conservative x86_64 convention. 32-bit ARM, MIPS,
and PPC remain out of scope (see [POST_V01.md](POST_V01.md)).

## Tests

The unit suite mocks the radare2 boundary and runs **without radare2
installed**:

```bash
pip install -e . pytest
pytest -m 'not integration'
```

A single integration test runs against a real radare2 if one is available:

```bash
pip install r2pipe
pytest -m integration
```

The deliberately-vulnerable test fixtures are committed as pre-built ELF blobs
so the suite runs without a C toolchain. See [REGENERATE.md](REGENERATE.md) to
rebuild them.

## Scope (v0.1)

In scope: ELF (x86_64 and AArch64), the CWE classes above, JSON and SARIF
output, pattern matching on disassembly.

Not in scope (deferred): Ghidra integration, PE binaries, 32-bit ARM / MIPS /
PPC architectures, symbolic execution / taint analysis, firmware analysis.
Additional CWE classes are tracked in [POST_V01.md](POST_V01.md).

See [POST_V01.md](POST_V01.md) for the ranked backlog of post-v0.1 directions.

## Ethical use

`blight` is a defensive static-analysis tool for auditing software you own or
are authorized to assess. Use it to find and fix dangerous patterns in your own
binaries, in code you are responsible for, or under an explicit authorization
(e.g. a penetration-test engagement or bug-bounty scope). **Do not** use it to
analyze, attack, or weaponize software you do not have permission to test. You
are responsible for complying with all applicable laws and agreements.

## License

MIT — see [LICENSE](LICENSE). See [NOTICE](NOTICE) for attribution to
`cwe_checker` (design inspiration), radare2, and r2pipe.
