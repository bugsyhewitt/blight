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
blight --binary PATH [--checks {78,120,242,all}] [--format json]
```

- `--binary` — path to the ELF binary to analyze (required)
- `--checks` — which CWE check to run; one of `78`, `120`, `242`, or `all`
  (default: `all`)
- `--format` — output format; `json` (default)

Output is a JSON object with the analyzed `binary`, the `checks` run, and a
list of `findings`. Each finding carries `cwe`, `function`, `address`,
`evidence`, and the dangerous `symbol`.

## Detected CWE classes (v0.1)

`blight` v0.1 detects three well-defined classes that are reliably catchable
via static disassembly + cross-reference analysis.

### CWE-78 — OS Command Injection

Calls to `system()` and the `exec*()` family **where the command argument is
not a constant string literal**. A constant command such as `system("ls")` is
not flagged; a command built from a buffer or variable is.

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
      "symbol": "system"
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
      "symbol": "strcpy"
    }
  ]
}
```

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
      "symbol": "gets"
    }
  ]
}
```

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

In scope: ELF (x86_64), the three CWE classes above, JSON output, pattern
matching on disassembly.

Not in scope for v0.1 (deferred): Ghidra integration, PE binaries, non-x86_64
architectures (ARM/MIPS/PPC), additional CWE classes, symbolic execution /
taint analysis, firmware analysis.

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
