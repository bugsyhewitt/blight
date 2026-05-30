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
blight --binary PATH [--checks {22,78,89,119,120,122,131,134,197,242,252,295,327,362,369,401,415,416,426,476,676,732,798,all}] [--format {json,sarif,text}] [--output-file FILE] [--workers N] [--min-confidence {low,medium,high}] [--fail-on {none,low,medium,high}]
```

- `--binary` — path to the ELF binary **or a directory of binaries** to analyze
  (required)
- `--checks` — which CWE check to run; one of `22`, `78`, `89`, `119`, `120`,
  `122`, `131`, `134`, `191`, `197`, `242`, `252`, `295`, `327`, `330`, `362`,
  `369`, `401`, `415`, `416`, `426`, `476`, `676`, `732`, `798`, or `all`
  (default: `all`)
- `--format` — output format; `json` (default), `sarif`, or `text` (a
  human-readable console report, see **Human-readable text output** below)
- `--output-file FILE` (`-o FILE`) — write the report to `FILE` instead of
  stdout (see **Writing the report to a file** below)
- `--workers` — number of parallel worker threads for a directory scan
  (default: `1`, sequential). Ignored when `--binary` is a single file.
- `--suppress FILE` — path to a JSON suppression file listing known false
  positives to drop from the output (see **Suppressing known false positives**
  below)
- `--min-confidence` — drop findings below this triage confidence before
  output; one of `low` (default, keeps everything), `medium`, or `high` (see
  **Filtering by confidence** below)
- `--fail-on` — exit non-zero when any emitted finding is at or above this
  triage confidence, turning blight into a CI build gate; one of `none`
  (default, never fails), `low`, `medium`, or `high` (see **Failing a build on
  findings** below)

For a single binary, the output is a JSON object with the analyzed `binary`, the
`checks` run, and a list of `findings`. Each finding carries `cwe`, `function`,
`address`, `evidence`, the dangerous `symbol`, and a triage `confidence` label.

### Scanning a directory in parallel

Point `--binary` at a directory and `blight` scans every regular file inside it
(recursively). Add `--workers N` to fan the scan out across a thread pool —
since each binary's analysis spends almost all its time blocked on the radare2
subprocess, threads run truly concurrently and large-corpus scans get
significantly faster.

```bash
blight --binary ./firmware/bin --checks all --workers 8
```

The directory output is a JSON object with the `directory`, the `checks` run,
and a `results` array — one entry per binary, each with its own `binary` path
and `findings` list:

```json
{
  "directory": "./firmware/bin",
  "checks": [78, 89, 120, 134, 242, 252, 295, 327, 476, 676],
  "results": [
    { "binary": "./firmware/bin/httpd",  "findings": [ /* ... */ ] },
    { "binary": "./firmware/bin/telnetd", "findings": [ /* ... */ ] }
  ]
}
```

Results are returned in sorted path order, and each binary's findings are sorted
identically, **regardless of `--workers`** — a parallel scan produces output
identical to a sequential one. A failure on a single binary (e.g. an unreadable
file) is isolated: that entry carries an `"error"` string and the remaining
binaries are still scanned. With `--format sarif`, a directory scan emits one
SARIF document covering all findings across the corpus.

### Writing the report to a file

By default the report is printed to stdout. `--output-file FILE` (short form
`-o FILE`) writes it to `FILE` instead — the file is created or truncated and
nothing is printed to stdout, so a wrapper script can pipeline the report
without scraping it out of the terminal:

```bash
blight --binary ./firmware/bin --checks all --format sarif -o blight.sarif
```

The flag is format-agnostic: it writes whichever `--format` is selected
(`json`, `sarif`, or `text`), byte-for-byte identical to what would have gone
to stdout (with a single trailing newline). Pass `-o -` to force stdout
explicitly (the default). `--output-file` does not change the `--fail-on` exit code — the CI
gate still trips on the same findings whether the report lands in a file or on
stdout. If the file cannot be written (e.g. the parent directory does not
exist), `blight` aborts with a usage error before exiting.

### Confidence scoring

Every finding carries a `confidence` label — one of `high`, `medium`, or
`low` — so consumers can triage and filter without understanding each
detector's heuristic internals. The label reflects how certain the detection
is, not how severe the bug would be if exploited:

| Confidence | Meaning | Applies to |
|---|---|---|
| `high` | The dangerous symbol *is* the finding; no data-flow inference. | CWE-22 (HIGH-severity symbols), CWE-89 (HIGH-severity symbols), CWE-119 (HIGH-severity symbols), CWE-120, CWE-242, CWE-295 (HIGH-severity symbols), CWE-327 (HIGH-severity symbols), CWE-330 (parsed predictable seed — clock/pid return or small constant immediate), CWE-426, CWE-676 (HIGH-severity symbols), CWE-732 (parsed constant world-writable mode), CWE-798 (password / key-material / URI-credential / secret-shaped values) |
| `medium` | A heuristic fired (e.g. non-constant argument) that can miss aliased registers. | CWE-22 (MEDIUM-severity symbols), CWE-78, CWE-89 (MEDIUM-severity symbols), CWE-119 (MEDIUM-severity symbols), CWE-134, CWE-295 (MEDIUM-severity symbols), CWE-327 (MEDIUM-severity symbols), CWE-362, CWE-676 (MEDIUM-severity symbols), CWE-798 (short token/key-class values that may be config knobs) |
| `low` | The pattern is weakly indicative. | CWE-122 (a heap buffer reaches the destination of an unbounded copy but the reachability of that copy along the allocated path is not proven), CWE-131 (an allocator's size argument traces back to a strlen-family return with no +1 adjustment in the in-function view but reachability of the allocation along that strlen path is not proven), CWE-401 (the last register alias of a heap allocation is overwritten unfreed but the reachability of that clobber along the allocated path is not proven), CWE-415 (the freed pointer reaches a second free but the reachability of that second free along the freed path is not proven), CWE-416 (the freed pointer is reused but the reachability of the use along the freed path is not proven), CWE-476 (path-reachability of the allocation failure is not proven), CWE-252 (path-reachability of the call failure is not proven), CWE-369 (the divisor is unchecked but its zero-reachability is not proven), CWE-191 (a size argument is produced by an unguarded subtraction but whether the operands actually underflow at runtime is not proven), CWE-197 (a known-wide return value is truncated into a narrower slot but whether the runtime value actually exceeds the narrow range is not proven), CWE-676 (LOW-severity symbols) |

For CWE-676 the confidence mirrors the per-symbol severity surfaced in the
evidence string (HIGH→`high`, MEDIUM→`medium`, LOW→`low`). The field is also
emitted in `--format sarif` output under each result's `properties.confidence`.

### Filtering by confidence

`--min-confidence` drops every finding below a chosen triage confidence before
output, so a CI gate can ask for only the highest-certainty findings without
post-processing the JSON. The threshold is inclusive and ordered
`low < medium < high`:

| `--min-confidence` | Keeps |
|---|---|
| `low` (default) | everything |
| `medium` | `medium` and `high` |
| `high` | `high` only |

```bash
# Fail a pipeline only on high-confidence findings:
blight --binary ./firmware/bin --checks all --min-confidence high
```

Like `--suppress`, this is a pure output-layer filter — the detectors and the
analyzed binary are untouched — and it is applied uniformly to single-file and
directory scans and to both `json` and `sarif` output. The two flags compose:
`--suppress` removes named false positives and `--min-confidence` then drops
whatever remains below the threshold.

### Failing a build on findings

By default `blight` is advisory: it always exits `0`, so a pipeline must
post-process the JSON to decide whether to fail. `--fail-on` turns blight into a
build gate — if any **emitted** finding is at or above the chosen triage
confidence, the process exits non-zero and the CI job fails without parsing the
report. The threshold reuses the same `low < medium < high` ordering, with an
extra `none` token that disables the gate:

| `--fail-on` | Exits non-zero when |
|---|---|
| `none` (default) | never — fully backward compatible |
| `low` | any finding at all is emitted |
| `medium` | a `medium`- or `high`-confidence finding is emitted |
| `high` | a `high`-confidence finding is emitted |

```bash
# Fail the CI job if any high-confidence finding survives:
blight --binary ./firmware/bin --checks all --fail-on high
echo "exit code: $?"   # 1 if a high-confidence finding was emitted, else 0
```

The gate runs **over the findings that are actually emitted** — i.e. after
`--suppress` and `--min-confidence` have removed findings — so it is always
consistent with the report you see. A suppressed or below-threshold finding
cannot trip the gate. For a directory scan the gate considers every binary's
surviving findings; one qualifying finding anywhere fails the whole run. The
report is still written to stdout exactly as before; only the exit code changes.

A scan that errored (e.g. an unreadable binary) carries no findings and never
trips the gate on its own. The gate exit code is `1`; argparse usage errors stay
`2`, so a CI job can tell "found vulnerabilities" apart from "bad invocation".

### Human-readable text output

`--format text` renders the findings as a compact, grouped-by-function console
report instead of JSON or SARIF. It's for the interactive case — "I just
scanned this binary, what's wrong with it?" — where piping the JSON through
`jq` is friction. Findings are grouped under their containing function, each
line shows the triage confidence, CWE, symbol, and address, and a per-CWE
summary closes the report:

```bash
$ blight --binary tests/fixtures/strcpy-vuln --checks 120 --format text
binary: tests/fixtures/strcpy-vuln
checks: 120
3 findings (high: 3, medium: 0, low: 0)

function copy_it
  [high] CWE-120 strcpy @ 0x401170
    call to strcpy: strcpy copies without a destination size bound
function format_it
  [high] CWE-120 sprintf @ 0x4011aa
    call to sprintf: sprintf writes a formatted string without a size bound
function main
  [high] CWE-120 gets @ 0x401202
    call to gets: gets reads input without any size bound

summary: CWE-120 x3
```

A clean binary prints `no findings` after the header. A directory scan prints
one indented block per binary under a `directory:` header (errored binaries
show their `error` string instead of findings), followed by a corpus total:

```bash
$ blight --binary ./firmware/bin --checks all --format text
directory: ./firmware/bin
checks: 78, 89, 120, 134, 242, 252, 295, 327, 476, 676

  binary: ./firmware/bin/httpd
  1 finding (high: 1, medium: 0, low: 0)

  function handle_request
    [high] CWE-120 strcpy @ 0x401abc
      call to strcpy: strcpy copies without a destination size bound

  summary: CWE-120 x1

  binary: ./firmware/bin/telnetd
  no findings

total: 1 finding across 2 binaries
```

Like `json` and `sarif`, the text report covers exactly the findings that
survive `--suppress` and `--min-confidence`, and `--fail-on` evaluates the same
set — so the exit code always matches the report you see. **The text format is
a report for humans and carries no stability contract**: its layout may change
between releases. For tooling, scripting, or CI parsing, keep using
`--format json` or `--format sarif`.

### Suppressing known false positives

Every static-analysis tool accumulates known false positives over time.
`--suppress FILE` lets a team codify accepted risk in a small JSON file; any
matching finding is dropped from the output before it is emitted. The binary is
never modified and the detectors are untouched — suppression is a pure
output-layer filter applied to both single-file and directory scans (and to
both `json` and `sarif` output).

```bash
blight --binary ./firmware/bin --checks all --suppress blight-suppress.json
```

The file is JSON (no extra toolchain — blight stays pure-Python). Each rule
**must** carry a `cwe`; it may add any of `function`, `address`, and `symbol`
as extra constraints. All present constraints must match for a finding to be
suppressed (logical **AND**); omitted fields act as wildcards. An optional
`reason` key (and any `"//"` comment key) is documentation only and is ignored
when matching.

```json
{
  "//": "Accepted risks, reviewed 2025-05. Owner: appsec.",
  "suppressions": [
    { "cwe": 120, "symbol": "strcpy", "function": "copy_it",
      "reason": "bounded by caller; audited in TICKET-481" },
    { "cwe": 78, "address": "0x40119c", "reason": "constant argv, not attacker-controlled" },
    { "cwe": 676 }
  ]
}
```

- `{ "cwe": 120 }` suppresses **every** CWE-120 finding.
- Adding `symbol`/`function`/`address` narrows the rule — e.g. the first rule
  above suppresses only the `strcpy` call site inside `copy_it`.
- `address` matching is case-insensitive and tolerant of a missing `0x` prefix.
- `cwe` may be written as an integer (`120`), a numeric string (`"120"`), or a
  prefixed string (`"CWE-120"`).

A malformed suppression file (bad JSON, missing `cwe`, unknown key, wrong type)
is reported as a clear CLI error and aborts the run before any scanning happens.

## Detected CWE classes

`blight` detects well-defined classes that are reliably catchable via static
disassembly + cross-reference analysis. The three CWE-78/120/242 classes shipped
in v0.1; CWE-22, CWE-89, CWE-119, CWE-122, CWE-131, CWE-134, CWE-191, CWE-197,
CWE-252, CWE-295, CWE-327, CWE-330, CWE-362, CWE-369, CWE-401, CWE-415, CWE-416,
CWE-426, CWE-476, CWE-676, CWE-732, and CWE-798 were added post-v0.1 (see
[POST_V01.md](POST_V01.md)).

### CWE-22 — Path Traversal

Calls to filesystem routines that **consume a pathname** — the sinks where a
path-traversal vulnerability lands. If the path is assembled from untrusted
input (a request parameter, an archive entry name, an environment variable) and
is not first canonicalised (`realpath`) and confined to an intended base
directory, an attacker can reach files outside it with `../` sequences or
absolute paths. The call to the path-consuming routine is the exact spot a
reviewer must inspect.

This is a pure PLT-lookup check (the same shape as CWE-89, CWE-119, CWE-327,
CWE-295 and CWE-676): it does **not** read the path argument out of the
disassembly — the pathname arrives in different argument positions across these
routines and is frequently built across basic blocks, so the call to a
path-consuming routine is itself the finding, surfaced at the per-symbol
confidence for triage. Two severity tiers:

- **HIGH** — routines that destroy, replace or escalate via a pathname:
  `unlink` / `unlinkat` / `remove` / `rmdir` (delete), `rename` (move/overwrite),
  `symlink` / `link` (the classic `../`-plus-symlink escape), `chmod` / `chown` /
  `lchown`, `mkdir`, and the exec-by-path family `execv` / `execve` / `execvp`.
- **MEDIUM** — routines that open or read metadata for a pathname:
  `open` / `open64` / `openat` / `fopen` / `fopen64` / `freopen` / `creat`,
  `opendir`, `access` / `stat` / `lstat` (also a TOCTOU hint), and `readlink`.
  These appear routinely in fully-validated code, so the call is a *triage*
  signal, not a confirmed bug.

The canonicalisation primitive `realpath` is deliberately **not** flagged — it
is part of the recommended mitigation (resolve, then verify the result is under
the intended base directory), and flagging it would invert the signal. Because
it is a pure PLT lookup the check is architecture-agnostic — it works on every
architecture radare2 can disassemble.

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

### CWE-89 — SQL Injection

Calls to database-client routines that **execute a SQL statement supplied as a
string** — the sink of every SQL-injection vulnerability. If the query is built
from untrusted input by concatenation or `sprintf` rather than a
parameterised/prepared statement, the call is exactly where the injection lands.

This is a pure PLT-lookup check (the same shape as CWE-78, CWE-327, CWE-295 and
CWE-676): it does **not** read the query argument out of the disassembly — the
query string arrives in different argument positions across the many database
libraries and is frequently assembled across basic blocks, so the high-value
signal "this binary executes raw SQL strings, confirm every call site uses bound
parameters" is already carried by the presence of the call. Raw-string execution
sinks (`sqlite3_exec`, `sqlite3_mprintf`/`sqlite3_vmprintf`, `mysql_query`,
`mysql_real_query`, `PQexec`, `SQLExecDirect`/`SQLExecDirectW`) are `high`
confidence; the prepare/compile gateways that *can* be used safely with bound
parameters (`sqlite3_prepare`/`_v2`/`_v3`, `SQLPrepare`) are `medium`. The safe
parameterised APIs (`sqlite3_bind_*`, `sqlite3_step`, `mysql_stmt_bind_param`,
`PQexecParams`/`PQprepare`/`PQexecPrepared`, `SQLBindParameter`) are **not**
flagged. Because it is a pure PLT lookup it is architecture-agnostic.

```bash
$ blight --binary path/to/elf --checks 89 --format json
{
  "binary": "path/to/elf",
  "checks": [89],
  "findings": [
    {
      "cwe": 89,
      "function": "lookup_user",
      "address": "0x401172",
      "evidence": "[HIGH] call to mysql_query: mysql_query executes a raw query string — use the prepared-statement API (mysql_stmt_prepare + mysql_stmt_bind_param)",
      "symbol": "mysql_query",
      "confidence": "high"
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

### CWE-119 — Improper Restriction of Operations within the Bounds of a Memory Buffer

Calls to the memory-copy / concatenation primitives whose safe use depends
entirely on the caller having computed a correct size bound — the broader
memory-bounds class that complements CWE-120's unchecked-copy set. This is a
pure PLT-lookup check (the same shape as CWE-89, CWE-327, CWE-295 and CWE-676):
it does **not** read the length argument out of the disassembly — the call site
is itself the finding, because the high-value signal "this binary performs raw
bounded/unbounded memory copies, confirm every length is destination-clamped" is
already carried by the call's presence.

The unbounded copies and concatenations (`memcpy`, `memmove`, `bcopy`,
`stpcpy`, `wcscpy`, `strcat`, `wcscat`) are `high` confidence. The
count-bounded-but-routinely-misused routines (`strncat`/`wcsncat`, whose count
is source-relative rather than destination-relative, and `alloca`, a
caller-sized stack allocation) are `medium`. The safe bounded forms (`strlcpy`,
`strlcat`, `snprintf`) are **not** flagged — they are the recommended pattern.
The severity is surfaced in the evidence string. `strcpy`/`sprintf`/`gets`
belong to CWE-120, not CWE-119; the two detectors are complementary, not
redundant.

```bash
$ blight --binary ./service --checks 119 --format json
{
  "binary": "./service",
  "checks": [119],
  "findings": [
    {
      "cwe": 119,
      "function": "copy_buf",
      "address": "0x401160",
      "evidence": "[HIGH] call to memcpy: memcpy copies a caller-supplied length — confirm the length cannot exceed the destination size; a wrong length is an out-of-bounds write",
      "symbol": "memcpy",
      "confidence": "high"
    }
  ]
}
```

### CWE-122 — Heap-Based Buffer Overflow

Flags the statically-detectable heap-overflow shape: a **heap buffer** is
obtained from an allocator (`malloc`, `calloc`, `realloc`, `reallocarray`,
`strdup`, `strndup`, `aligned_alloc`, `valloc`, `pvalloc`, `memalign`), and that
same pointer is then handed — in the **destination** (first-argument) register —
to an **unbounded** copy routine (`strcpy`, `stpcpy`, `strcat`, `sprintf`,
`vsprintf`, `gets`) in the same function with no intervening size-aware
reassignment. The allocation fixes the destination's size; an unbounded copy
writes the full length of the source, so a fixed-size heap buffer used as the
destination of a length-unaware copy can be overflowed on the heap.

This is the same in-function, forward-scan, register-alias machinery proven by
[CWE-416](#cwe-416--use-after-free) and CWE-476, except the tracked pointer is
seeded from the **allocator return register** (`rax` on x86_64, `x0` on AArch64)
and the sink is an unbounded copy whose destination register still aliases the
heap buffer. A register-to-register move propagates the alias (`mov rbx, rax`
then `strcpy(rbx, …)` is still caught); storing the pointer away or overwriting
the destination register with a different buffer kills the alias (safe).

Deliberately distinct from [CWE-120](#cwe-120--buffer-copy-without-checking-size-of-input):
CWE-120 flags *every* call to a dangerous copy regardless of where it writes,
because the function's presence is the finding. CWE-122 is the narrower,
heap-specific signal — it fires only when the copy's destination is provably a
same-function heap allocation, which is precisely what makes the overflow land
on the heap. A single call site can legitimately carry both findings. **Bounded**
copies (`strncpy`/`snprintf`/`memcpy` with an explicit length) are intentionally
**not** flagged here: judging whether the length is correct needs value-range
analysis that is out of scope; those remain CWE-120's broader territory.

Because reachability of the copy along the allocated path is not proven
statically (an intervening branch may resize on a path we cannot see), every
CWE-122 finding is `low` confidence — matching CWE-415 / CWE-416 / CWE-476. The
detector is architecture-aware on x86_64 and AArch64.

```bash
$ blight --binary path/to/elf --checks 122 --format json
{
  "binary": "path/to/elf",
  "checks": [122],
  "findings": [
    {
      "cwe": 122,
      "function": "build",
      "address": "0x401150",
      "evidence": "heap buffer from malloc is the destination of an unbounded copy in the same function without an intervening size-aware reassignment (possible heap buffer overflow)",
      "symbol": "malloc",
      "confidence": "low"
    }
  ]
}
```

### CWE-131 — Incorrect Calculation of Buffer Size

An allocation whose **size argument is the return of `strlen` / `wcslen` with
no `+ 1` adjustment for the NUL terminator**. The canonical C source is
`buf = malloc(strlen(src)); strcpy(buf, src);` — the buffer is one byte short
of holding the string plus its terminator, so the `strcpy` writes the NUL byte
past the end of the heap allocation. This off-by-one heap overflow is one of
the most-cited examples of CWE-131 (see the entry on cwe.mitre.org) and is
endemic in legacy C that still treats `strlen` returns as full-string buffer
sizes.

This is the *narrow, statically-visible* slice of CWE-131. blight does **not**
attempt the general buffer-size-calculation problem (proving an arbitrary
arithmetic expression sizes a buffer correctly needs value-range / symbolic
analysis that blight keeps out of scope — the same reason CWE-190 integer
overflow is deferred). Instead it anchors on the fingerprint it can see: a
sized allocation whose size register traces back, through register-alias
propagation, to the return of `strlen` with no intervening adjustment by one.

This is a PLT-anchored, single-function **backward** scan (the same machinery
as CWE-122, CWE-191 and CWE-369). The detector finds every call site to an
allocator — `malloc` / `alloca` / `valloc` / `pvalloc` (size in arg0),
`realloc` / `reallocarray` / `calloc` (size in arg1) — resolves that
argument's register per architecture (`rdi`/`rsi` on x86_64, `x0`/`x1` on
AArch64), then walks backward:

- if the size register (or a register it was moved from) is the **destination
  of an `inc` / `add ..., 1`** (x86_64) or `add D, S, #1` (AArch64), the
  program accounted for the NUL terminator → not flagged;
- if a non-`strlen` **call** is reached while the return register (`rax`/`x0`)
  is alive, that call clobbers the return register and breaks the chain →
  not flagged (conservative);
- if the return register is alive when we reach a **`call strlen` /
  `call wcslen`**, the size was produced by `strlen` and never adjusted by
  one → flagged.

```bash
$ blight --binary path/to/elf --checks 131 --format json
{
  "binary": "path/to/elf",
  "checks": [131],
  "findings": [
    {
      "cwe": 131,
      "function": "build_buf",
      "address": "0x401160",
      "evidence": "size argument to malloc is the return of strlen with no +1 adjustment for the NUL terminator (off-by-one buffer size — heap overflow on subsequent string copy)",
      "symbol": "malloc",
      "confidence": "low"
    }
  ]
}
```

Reachability of the allocation along the strlen path is not proven
statically, so every CWE-131 finding is `low` confidence — it marks a
*statically-visible* unadjusted `strlen`-sized allocation. The detector is
architecture-aware on x86_64 and AArch64. It is kept distinct from CWE-122
(heap overflow via unbounded copy of a heap buffer): CWE-122 anchors on the
*destination* of the copy; CWE-131 anchors on the *size* of the allocation
itself — the upstream off-by-one source. A call site can legitimately carry
both findings.

### CWE-134 — Use of Externally-Controlled Format String

Calls to the `printf` family (`printf`, `fprintf`, `syslog`, `snprintf`,
`vprintf`, `vsprintf`, `vfprintf`, `vsyslog`) **where the format-string argument
is not a constant string literal**. A literal format such as
`printf("Hello %s\n", name)` is not flagged; a format built from a buffer or
variable is. Like CWE-78, the format-argument register is resolved per
architecture, so this works on x86_64 and AArch64.

### CWE-191 — Integer Underflow (Wrap or Wraparound)

An **unsigned subtraction** whose result is handed to an allocator or copy
routine as a **size/length** without a preceding bounds check on its operands.
The canonical C source is `malloc(len - header)` or `memcpy(dst, src, end - start)`:
when the minuend is smaller than the subtrahend (`len < header`, `end < start`,
`count - 1` with `count == 0`), the unsigned result wraps to a near-`SIZE_MAX`
value, so the allocation requests — or the copy moves — an enormous region. This
underflow-to-overflow primitive is behind a long tail of memory-corruption CVEs.

This is the *narrow, statically-visible* slice of CWE-191. blight does **not**
attempt the general integer-underflow problem (proving a given subtraction can
underflow at runtime needs value-range / symbolic analysis that blight keeps out
of scope — the same reason CWE-190 integer overflow is deferred; see
[POST_V01.md](POST_V01.md)). Instead it anchors on the fingerprint it can see:
a subtraction result reaching a *size-consuming sink*. That anchor keeps the
false-positive rate low — a bare `sub` is everywhere, but a `sub` whose result is
the size argument of `memcpy` is a security-relevant signal.

This is a PLT-anchored, single-function **backward** scan (the same machinery as
CWE-122 and CWE-369). The detector finds every call site to a size-consuming
sink — `malloc` / `alloca` / `valloc` / `pvalloc` (size in arg0), `calloc` /
`realloc` / `reallocarray` (size in arg1), `memcpy` / `memmove` / `memset` /
`bcopy` (length in arg2) — resolves that argument's register per architecture
(`rdi`/`rsi`/`rdx` on x86_64, `x0`/`x1`/`x2` on AArch64), then walks backward:

- if the size register (or a register it was moved from) is the **destination of
  a subtraction** (`sub eax, esi` on x86_64; `sub w0, w1, w2` on AArch64), the
  size is a subtraction result → candidate underflow;
- if an **unsigned-compare guard branch** (`jae`/`jb`/`jbe`/`ja` on x86_64,
  `b.hs`/`b.lo`/`b.ls`/`b.hi` on AArch64) precedes that subtraction, the operands
  were bounds-checked → not flagged;
- if the size register is **reloaded from memory** after the subtraction, the
  value reaching the sink is the fresh reload, not the subtraction → not flagged.

```bash
$ blight --binary path/to/elf --checks 191 --format json
{
  "binary": "path/to/elf",
  "checks": [191],
  "findings": [
    {
      "cwe": 191,
      "function": "alloc_body",
      "address": "0x401160",
      "evidence": "size argument to malloc is produced by an unsigned subtraction with no preceding bounds check (possible integer underflow → oversized allocation/copy)",
      "symbol": "malloc",
      "confidence": "low"
    }
  ]
}
```

Reachability and the actual runtime range of the operands are not proven
statically, so every CWE-191 finding is `low` confidence — it marks a
*statically-visible* unguarded size-producing subtraction reaching an
allocation/copy. The detector is architecture-aware on x86_64 and AArch64. It is
kept distinct from CWE-190 (integer *overflow*): CWE-191 fires only on a
*subtraction*, never attempting to prove overflow of an addition/multiplication.

### CWE-197 — Numeric Truncation Error

A **wide value** — a `size_t` / `ssize_t` / `long` (64 bits on LP64 targets) —
returned by a libc routine whose result the program **truncates into a narrower
destination** before ever using it at full width. The canonical C source is
`int n = strlen(s);` or `int n = read(fd, buf, len);`: the call returns a 64-bit
count in the return register (`rax` on x86_64, `x0` on AArch64), and the compiler
stores only the 32-bit view (`eax` / `w0`) into the `int` slot. If the true value
exceeds `INT_MAX` (a 2GB+ `read`, a giant attacker-supplied length, a negative
`ssize_t` error code sign-confused into a large `int`), the truncated value
silently disagrees with reality — a classic source of under-allocations and
bounds-check bypasses.

This is a PLT-anchored, single-function forward scan (the same shape as CWE-401
and CWE-369). The detector finds every call site to a wide-return routine —
`strlen`, `strnlen`, `wcslen`, `read`, `pread`, `recv`, `recvfrom`, `readv`,
`fread`, `write`, `send`, `strtol`/`strtoul`/`strtoll`/`strtoull`, `mbstowcs`,
`wcstombs`, `sysconf`, `ftell`, `lseek` — seeds the 64-bit return register, then
walks the instructions after the call:

- a **narrowing use** — a move or store of the value's 32/16/8-bit sub-register
  into a narrower slot (`mov dword [rbp - 4], eax`, `mov word [rbp - 2], ax`,
  AArch64 `str w0, [..]`) drops the high bits → **flagged**;
- a **full-width use** — a 64-bit store (`mov qword [..], rax`), a 64-bit compare
  (`cmp rax, ...`), or a 64-bit register move keeps all the bits → not flagged;
- a **re-extension** — `cdqe` / `cltq` / `movsx` / `movsxd` (x86_64) or `sxtw` /
  `uxtw` (AArch64) re-widens the value back to 64 bits, preserving its magnitude
  → not flagged.

`int`-returning sources (`atoi`, etc.) are not in the source set — storing an
`int` into an `int` loses no bits, so they are never flagged.

```bash
$ blight --binary path/to/elf --checks 197 --format json
{
  "binary": "path/to/elf",
  "checks": [197],
  "findings": [
    {
      "cwe": 197,
      "function": "process",
      "address": "0x401152",
      "evidence": "wide return value of strlen (size_t/ssize_t/long) is truncated into a narrower destination without re-extension (possible numeric truncation / lost high bits)",
      "symbol": "strlen",
      "confidence": "low"
    }
  ]
}
```

Whether the runtime value actually exceeds the narrow destination's range needs
value/range analysis that blight keeps out of scope, so every CWE-197 finding is
`low` confidence — it marks a *statically-visible* truncating store of a
known-wide return value. The detector is architecture-aware on x86_64 and
AArch64. (CWE-190 integer overflow was evaluated alongside it and deferred: it
requires symbolic execution for precise detection — see [POST_V01.md](POST_V01.md).)

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

### CWE-295 — Improper Certificate Validation

Calls to library routines whose **presence** marks the spot where TLS/SSL
certificate or hostname verification is configured by hand — exactly where
verification is most often disabled or weakened (`SSL_VERIFY_NONE`, a verify
callback that always returns success, `CURLOPT_SSL_VERIFYPEER` set to `0`, or a
hostname check skipped). Broken certificate validation is one of the most
frequently shipped TLS flaws on the embedded/firmware targets blight serves.

Like CWE-327 and CWE-676 this is a pure PLT-lookup check — it does **not** read
the verify-mode argument out of the disassembly (the constant is frequently
loaded indirectly), so the call to a verification-policy routine is itself the
finding and the result is surfaced for triage. The severity is in the evidence
string; the routine, not the mode, is the signal.

| Symbol | Severity | Why it's flagged | Confirm / use instead |
|---|---|---|---|
| `SSL_CTX_set_verify` / `SSL_set_verify` | HIGH | Sets the verify mode (often `SSL_VERIFY_NONE`) | Mode must include `SSL_VERIFY_PEER`; callback must fail closed |
| `SSL_CTX_set_cert_verify_callback` | HIGH | Replaces the built-in chain check wholesale | Confirm the callback actually validates |
| `gnutls_certificate_set_verify_function` | HIGH | Installs a custom GnuTLS verify callback | Confirm it fails closed |
| `gnutls_certificate_verify_peers2` | HIGH | Does not check the hostname | `gnutls_certificate_verify_peers3` / `gnutls_session_set_verify_cert` |
| `mbedtls_ssl_conf_authmode` | HIGH | Sets the verify mode (often `MBEDTLS_SSL_VERIFY_NONE`) | Use `MBEDTLS_SSL_VERIFY_REQUIRED` |
| `SSL_get_peer_certificate` | MEDIUM | Returns a cert even when verification failed | Pair with `SSL_get_verify_result` |
| `curl_easy_setopt` | MEDIUM | Sink for `CURLOPT_SSL_VERIFYPEER` / `CURLOPT_SSL_VERIFYHOST` being `0` | Leave both at their secure defaults |

The correct verification APIs — `SSL_get_verify_result`, `X509_check_host`,
`gnutls_certificate_verify_peers3`, `gnutls_session_set_verify_cert` — are
**not** flagged.

```bash
$ blight --binary path/to/elf --checks 295 --format json
{
  "binary": "path/to/elf",
  "checks": [295],
  "findings": [
    {
      "cwe": 295,
      "function": "init_tls",
      "address": "0x401160",
      "evidence": "[HIGH] call to SSL_CTX_set_verify: SSL_CTX_set_verify configures the verify mode — confirm it is not SSL_VERIFY_NONE and that a verify callback does not force success",
      "symbol": "SSL_CTX_set_verify",
      "confidence": "high"
    }
  ]
}
```

The confidence mirrors the per-symbol severity (HIGH→`high`, MEDIUM→`medium`),
the same policy as CWE-327 and CWE-676. Because it is a pure PLT lookup it is
architecture-agnostic and works on every architecture radare2 can disassemble.

### CWE-327 — Use of a Broken or Risky Cryptographic Algorithm

Calls to library routines that implement cryptographic primitives now
considered **broken or risky** for security use. Unlike a data-flow check, the
*presence of the call itself* is the finding — linking against a known-broken
hash, a legacy cipher, or a predictable random source is the signal. This is a
pure PLT-lookup check (same shape as CWE-676); any matching call site is
flagged and the severity is surfaced in the evidence string.

| Family | Symbols | Severity | Why it's flagged | Use instead |
|---|---|---|---|---|
| Broken hashes | `MD5`/`MD4`/`MD2` (+ `_Init`/`_Update`/`_Final`), `SHA`/`SHA1` (+ `_Init`/`_Update`/`_Final`) | HIGH | Collision-broken | `SHA-256` / `SHA-3` |
| Single-DES | `DES_ecb_encrypt`, `DES_ncbc_encrypt`, `DES_cbc_encrypt`, `DES_set_key`, `DES_crypt` | HIGH | 56-bit key, brute-forceable | `AES-GCM` |
| RC4 | `RC4`, `RC4_set_key` | HIGH | Biased keystream | `AES-GCM` / `ChaCha20-Poly1305` |
| Blowfish | `BF_ecb_encrypt`, `BF_cbc_encrypt`, `BF_set_key` | MEDIUM | 64-bit block (birthday bound) | `AES-GCM` |
| Weak randomness | `srand`, `random`, `srandom` | MEDIUM | Predictable PRNG used for crypto | `getrandom()` / a CSPRNG |

```bash
$ blight --binary path/to/elf --checks 327 --format json
{
  "binary": "path/to/elf",
  "checks": [327],
  "findings": [
    {
      "cwe": 327,
      "function": "hash_pw",
      "address": "0x401160",
      "evidence": "[HIGH] call to MD5: Use of collision-broken MD5 hash; use SHA-256 or SHA-3",
      "symbol": "MD5",
      "confidence": "high"
    }
  ]
}
```

The confidence mirrors the per-symbol severity (HIGH→`high`, MEDIUM→`medium`),
the same policy as CWE-676. Because it is a pure PLT lookup it is
architecture-agnostic and works on every architecture radare2 can disassemble.

### CWE-330 — Use of Insufficiently Random Values (predictable PRNG seeding)

Calls to a non-cryptographic PRNG seeding routine (`srand` / `srandom` /
`srand48` / `seed48`) where the seed is *predictable*. Two textbook insecure
patterns are flagged:

| Seed pattern | Severity | Why it's flagged |
|---|---|---|
| Seed is the return value of a public clock / pid source — `time`, `gettimeofday`, `clock`, `clock_gettime`, `getpid`, `getppid` (e.g. `srand(time(NULL))`) | HIGH | The PRNG stream is fully determined by a value anyone watching the wall clock or `/proc` can recover — the canonical predictable-seed primitive behind a long tail of token-prediction, key-recovery, and session-replay CVEs |
| Seed is a small constant immediate (`0`, `1`, any value ≤ `0xff`) | MEDIUM | The PRNG output is identical across every invocation of the binary — the same-seed (CWE-336) mistake |

A seed loaded from a value the detector cannot resolve (a config-read at
runtime, a register chain reaching outside the function, a large literal that
is probably a domain-specific constant) is **not** flagged. Bare `rand()`
calls remain CWE-676's territory; the two are complementary — CWE-676 catches
"predictable PRNG used at all", CWE-330 catches "PRNG seeded in a way that
fixes its output sequence ahead of time".

The detector is a hybrid: PLT lookup locates the seeding call sites, then
per-architecture argument-register inspection (the same machinery as CWE-78
and CWE-732) walks the containing function backward to find the last
instruction that writes the seed register. The HIGH case additionally checks
that the most recent `call` before that write targets a known predictable
source; an intervening unrelated call between the predictable source and the
seed write breaks the link and the call site is left alone. x86_64 and AArch64
are supported. Both severity tiers are emitted at HIGH `confidence` — the
evidence is read literally out of the disassembly, not heuristically inferred.

```bash
$ blight --binary path/to/elf --checks 330 --format json
{
  "binary": "path/to/elf",
  "checks": [330],
  "findings": [
    {
      "cwe": 330,
      "function": "seed_prng",
      "address": "0x401168",
      "evidence": "[HIGH] call to srand with seed is the return value of time() (predictable clock/pid source) (predictable PRNG seeding)",
      "symbol": "srand",
      "confidence": "high"
    }
  ]
}
```

### CWE-362 — Race Condition (filesystem TOCTOU check-then-use)

Calls to the classic *check* primitives that test a filesystem path **by name** —
the `access` family (`access`, `faccessat`, `euidaccess`, `eaccess`) and the
`stat` family (`stat`, `lstat`, `fstatat`, `stat64`, `lstat64`). The textbook
time-of-check-to-time-of-use bug is:

```c
if (access("/tmp/x", W_OK) == 0)   /* CHECK — by path  */
    fd = open("/tmp/x", O_WRONLY); /* USE   — same path */
```

Between the check and the use, an attacker who can influence the namespace (a
writable parent directory, a predictable temp name) swaps the path for a symlink
to a file they could not otherwise reach, and the privileged program operates on
the attacker's target. The *race window* is the weakness, and it is present
**regardless of the path argument's provenance** — even a perfectly constant
path is exploitable when the containing directory is attacker-writable.

Like CWE-22, CWE-426, and CWE-676 this is a pure PLT-lookup check — the call to
a check-by-path primitive is itself the finding. It does **not** try to prove a
matching use-by-path call follows, because the check and the use are frequently
in different functions/blocks, and the high-value triage signal — "this binary
makes access/permission decisions *by path*; confirm every one is converted to
an fd-based check (`open` then `fstat`) or made atomic (`O_NOFOLLOW`, `openat`
relative to a trusted dirfd)" — is already carried by the call's presence.

This is the complement of [CWE-22](#cwe-22--path-traversal), which also lists
`access`/`stat` as MEDIUM sinks but for a *different* reason: there the concern
is the path *content* (`../` escaping a base directory), here it is the *race
window* of using a name twice. A single `access` call site can therefore
legitimately carry **both** findings, surfaced under distinct CWE ids.

The fd-based / atomic forms are deliberately **not** flagged: `fstat` takes an
open fd and so cannot race on a name, and `openat` is the recommended
dirfd-relative replacement. All flagged primitives are MEDIUM — a check-by-path
is a *triage* signal, not a confirmed race; it is benign when the result does
not gate a later use of the same path.

```bash
$ blight --binary path/to/elf --checks 362 --format json
{
  "binary": "path/to/elf",
  "checks": [362],
  "findings": [
    {
      "cwe": 362,
      "function": "guarded_open",
      "address": "0x401160",
      "evidence": "[MEDIUM] call to access: access() checks a path's accessibility by name; if the result gates a later open/exec on the same path it is a TOCTOU race — use an fd-based check (open then fstat / faccessat with a trusted dirfd)",
      "symbol": "access",
      "confidence": "medium"
    }
  ]
}
```

Because it is a pure PLT lookup it is architecture-agnostic and works on every
architecture radare2 can disassemble.

### CWE-369 — Divide By Zero

An integer division or remainder instruction whose **divisor is not a
proven-nonzero constant** — it comes from a register or a stack/memory operand
that the code did not zero-check first. If that divisor can be zero at runtime
(an attacker-controlled length, a parsed field, an untrusted count), the
division **traps** (SIGFPE on x86_64) or yields undefined behaviour.

Unlike every other blight check this is **not** a PLT-lookup — there is no
library call to cross-reference. The divide is a raw instruction, so the
detector walks **every function body** radare2 discovered (`aflj` →
`function_addrs`, then `pdfj` per function) and inspects each division opcode:

| Architecture | Opcodes | Divisor operand |
|---|---|---|
| x86_64 | `div`, `idiv` | the single operand (`idiv ecx`, `idiv dword [rbp - 8]`) |
| AArch64 | `sdiv`, `udiv` | the **third** operand (`sdiv w0, w1, w2` → `w2`) |

A division is flagged only when the divisor is **unguarded**. The detector does
a conservative in-function backward scan for a zero-check that dominates the
divide on a linear path:

- **register divisor** — a `test D, D` / `cmp D, 0` (x86_64) or `cbz`/`cbnz` /
  `cmp D, #0` (AArch64) earlier in the function marks `D` as checked; a
  `mov D, <nonzero immediate>` proves the divisor is a literal constant.
- **memory divisor** — a `cmp` against the **same** memory operand
  (`cmp dword [rbp - 8], 0` before `idiv dword [rbp - 8]`) is the guard, which
  is the exact idiom GCC/clang emit for `if (d == 0)`.

A literal-immediate divisor is treated as constant (and skipped — a non-zero
literal cannot divide by zero).

```bash
$ blight --binary path/to/elf --checks 369 --format json
{
  "binary": "path/to/elf",
  "checks": [369],
  "findings": [
    {
      "cwe": 369,
      "function": "0x401126",
      "address": "0x401134",
      "evidence": "division with non-constant divisor 'dword [rbp - 8]' and no preceding zero-check (possible divide-by-zero / SIGFPE)",
      "symbol": "idiv",
      "confidence": "low"
    }
  ]
}
```

Because proving the divisor is actually reachable as zero needs value/range
analysis that blight keeps out of scope, every CWE-369 finding is `low`
confidence — it marks an *unchecked* divisor, the statically-visible signal. The
function is reported by its entry address (radare2's `aflj` carries the offset,
not a resolved name, for this anchorless check). The detector is architecture-
aware on x86_64 and AArch64.

### CWE-401 — Missing Release of Memory after Effective Lifetime

A **heap buffer** is obtained from an allocator (`malloc`, `calloc`, `realloc`,
`reallocarray`, `strdup`, `strndup`, `aligned_alloc`, `valloc`, `pvalloc`,
`memalign`), and the **only register holding that pointer is then overwritten
with an unrelated value** — before it is ever freed, stored to memory, returned,
or passed to another call. Once the sole handle to a freshly-allocated buffer is
clobbered with no surviving copy, the program can never call `free` on it: the
memory is leaked.

This is the *inverse-sink* sibling of the heap-lifetime detectors: the source is
identical to [CWE-122](#cwe-122--heap-based-buffer-overflow) — the **allocator
return register** (`rax` on x86_64, `x0` on AArch64) — and the alias-tracking
machinery is the same single-function forward scan shared by
[CWE-415](#cwe-415--double-free) and [CWE-416](#cwe-416--use-after-free). What
differs is the sink: where CWE-415's sink is a *second free* and CWE-416's is a
*use of a freed pointer*, CWE-401's sink is the **loss of the last live alias
with no preceding free** — the absence of release where release was required
(the canonical `p = malloc(); … ; p = something_else;` that drops the handle).

The detector is deliberately conservative to keep false positives low (the
dominant risk for a leak detector):

- A register-to-register move **propagates** the alias (`mov rbx, rax` keeps the
  handle alive in `rbx`).
- A **store to memory** (`mov [rbp-8], rax`) lets the pointer escape our
  in-function view — it may be a struct field, a global, or a slot freed
  elsewhere — so it is conservatively presumed managed and **not** flagged.
- A **free** of a live alias releases the buffer — **not** flagged.
- The pointer left in (or moved to) the **return register** at `ret` is a
  handoff to the caller — **not** flagged.
- Passing a live alias to **any other call** leaves ownership ambiguous — **not**
  flagged.
- Overwriting the **last** live alias with an unrelated value (a memory reload, a
  fresh `lea` address, an immediate, an `xor reg,reg`, or an unrelated register)
  with no surviving copy and no preceding free/escape/return/handoff is the leak.

`realloc` / `reallocarray` are included because their *return* value is the live
(possibly moved) heap buffer that must be freed, exactly as in CWE-122.

Because reachability of the clobber along the allocated path is not proven
statically (an intervening branch may free or store the pointer on a path we
cannot see), every CWE-401 finding is `low` confidence — matching CWE-415 /
CWE-416 / CWE-122. The detector is architecture-aware on x86_64 and AArch64.

```bash
$ blight --binary path/to/elf --checks 401 --format json
{
  "binary": "path/to/elf",
  "checks": [401],
  "findings": [
    {
      "cwe": 401,
      "function": "leaky",
      "address": "0x401150",
      "evidence": "heap buffer from malloc has its only register alias overwritten in the same function without being freed, stored, or returned (possible memory leak)",
      "symbol": "malloc",
      "confidence": "low"
    }
  ]
}
```

### CWE-415 — Double Free

A pointer is passed to `free` (the deallocation that makes it dangling) and the
**same pointer is then passed to `free` a second time in the same function
without first being reassigned** (set to `NULL`, zeroed, or reloaded with a fresh
value). Releasing the same storage twice corrupts the allocator's free-list
bookkeeping and is a well-known path to heap exploitation.

This is the narrower sibling of [CWE-416](#cwe-416--use-after-free): both seed an
alias set with the first-argument register (`rdi` on x86_64, `x0` on AArch64)
that carries the freed pointer at the `free` call site, then scan forward through
the function. Where CWE-416's sink is *any* later read of the dangling pointer,
CWE-415's sink is specifically a **second deallocation** of it:

- a **reassignment** of a live alias — `mov rdi, 0` / `xor rdi, rdi` (x86_64),
  `mov x0, 0` (AArch64), a `lea` of a fresh address, or a reload from an
  unrelated source — kills the dangling alias (the canonical `ptr = NULL;` after
  `free(ptr)`) and **suppresses** the finding;
- a register-to-register move (`mov rbx, rdi`; later `mov rdi, rbx`)
  **propagates** the dangling alias, so a `free` of the propagated register is
  still caught;
- a **second `free`/`cfree`** reached while the first-argument register still
  holds a live alias is flagged as a double-free;
- a generic *non-deallocator* use of the freed pointer (e.g. `puts(ptr)`) is
  **not** flagged here — that is CWE-416's signal, keeping the two detectors
  crisply separated.

Only the unambiguous deallocators `free`/`cfree` are tracked; `realloc` is
excluded for the same reason as in CWE-416.

```bash
$ blight --binary path/to/elf --checks 415 --format json
{
  "binary": "path/to/elf",
  "checks": [415],
  "findings": [
    {
      "cwe": 415,
      "function": "dbl_free",
      "address": "0x401150",
      "evidence": "pointer freed by free is passed to a second free in the same function without being reassigned (possible double-free)",
      "symbol": "free",
      "confidence": "low"
    }
  ]
}
```

Because the reachability of the second free along the freed path is not proven
statically (an intervening branch this linear scan cannot see may reassign the
pointer), every CWE-415 finding is `low` confidence. The detector is
architecture-aware on x86_64 and AArch64.

### CWE-416 — Use After Free

A pointer is passed to `free` (the dangling-pointer source) and the **same
pointer is then used again — dereferenced or passed onward — without first being
reassigned** (set to `NULL`, zeroed, or reloaded with a fresh value). Touching
storage after it has been released is the classic use-after-free: the freed chunk
may have been recycled into a different allocation, so the stale pointer now reads
or writes another object's memory.

Like [CWE-476](#cwe-476--null-pointer-dereference) and
[CWE-252](#cwe-252--unchecked-return-value) this is a single-function
taint-propagation check. The *source* is the freed pointer, which lives in the
first-argument register (`rdi` on x86_64, `x0` on AArch64) at the `free` call
site; the *sink* is any later read of that register; the *sanitizer* is a
reassignment that severs the dangling alias. The detector seeds the alias set
with the first-argument register, then scans forward from the call:

- a **reassignment** of a live alias — `mov rdi, 0` / `xor rdi, rdi` (x86_64),
  `mov x0, 0` (AArch64), a `lea` of a fresh address, or a reload from an
  unrelated source — kills the dangling alias (the canonical `ptr = NULL;` after
  `free(ptr)`) and **suppresses** the finding;
- a **dereference** of a live alias (a `[reg …]` memory operand naming the freed
  register) reached before any reassignment is flagged;
- the freed pointer **passed onward** — moved into an argument register or still
  live in the first-argument register at a following `call`/`bl` — is flagged;
- a register-to-register move (`mov rbx, rdi`) **propagates** the dangling alias
  so a deref via `rbx` is still caught.

Only the unambiguous deallocators `free`/`cfree` are tracked. `realloc` is
deliberately excluded: its *return value* (not its argument) is the live pointer
and the old pointer is only dangling on the failure path, which this single-pass
heuristic cannot disambiguate without raising false positives.

```bash
$ blight --binary path/to/elf --checks 416 --format json
{
  "binary": "path/to/elf",
  "checks": [416],
  "findings": [
    {
      "cwe": 416,
      "function": "use_after",
      "address": "0x401150",
      "evidence": "pointer freed by free is used again without being reassigned (possible use-after-free of a dangling pointer)",
      "symbol": "free",
      "confidence": "low"
    }
  ]
}
```

Because the reachability of the use along the freed path is not proven
statically (an intervening branch this linear scan cannot see may reassign the
pointer), and because compilers reuse the argument register freely, every
CWE-416 finding is `low` confidence. The detector is architecture-aware on
x86_64 and AArch64.

### CWE-426 — Untrusted Search Path

Calls to routines that resolve a **program** or a **shared object** by walking
an externally controllable search path — `$PATH` for process launchers, the
dynamic-loader search path (`LD_LIBRARY_PATH`, `DT_RUNPATH`/`DT_RPATH`,
`$ORIGIN`, the current working directory) for library loaders. The weakness is
the *resolution mechanism*, not the argument: even a perfectly constant name
(`dlopen("libfoo.so")`, `execvp("ls", …)`) can be hijacked by an attacker who
controls the search path — a planted `libfoo.so` in the CWD, a malicious `ls`
earlier in `$PATH`, or a writable `rpath` directory all redirect the call to
attacker code.

This is the complement of [CWE-78](#cwe-78--os-command-injection): CWE-78
inspects the command *argument* to decide whether it is non-constant
(injection), whereas CWE-426 flags the *search-path resolution itself*
regardless of constness. A single `system(buf)` call site can therefore carry
**both** findings, and an `execvp("ls", …)` call site can carry a CWE-426
finding without a CWE-78 one. Like CWE-327 and CWE-676 it is a pure PLT-lookup
check — any matching call site is flagged and the severity is surfaced in the
evidence string.

| Mechanism | Symbols | Severity | Why it's flagged | Use instead |
|---|---|---|---|---|
| Dynamic-loader search path | `dlopen`, `dlmopen` | HIGH | A bare-name load walks `LD_LIBRARY_PATH`/`rpath`/`$ORIGIN` | Load by absolute path |
| `$PATH`-searching exec | `execlp`, `execvp`, `execvpe` | HIGH | The trailing `p` resolves the program via `$PATH` | `execv`/`execve` with an absolute path |
| Shell launchers | `popen`, `system` | HIGH | Both run `/bin/sh -c`, resolving the program via `$PATH` | Absolute path + sanitised environment |

The explicit-path exec forms (`execl`, `execv`, `execle`, `execve`) take a full
pathname and do **not** consult `$PATH`, so they are deliberately **not**
flagged — they are the recommended replacement.

```bash
$ blight --binary path/to/elf --checks 426 --format json
{
  "binary": "path/to/elf",
  "checks": [426],
  "findings": [
    {
      "cwe": 426,
      "function": "load_plugin",
      "address": "0x401160",
      "evidence": "[HIGH] call to dlopen: dlopen() resolves a bare name via LD_LIBRARY_PATH/rpath/$ORIGIN; load shared objects by absolute path",
      "symbol": "dlopen",
      "confidence": "high"
    }
  ]
}
```

The confidence mirrors the per-symbol severity (HIGH→`high`), the same policy as
CWE-327 and CWE-676. Because it is a pure PLT lookup it is architecture-agnostic
and works on every architecture radare2 can disassemble.

### CWE-476 — NULL Pointer Dereference

Pointers returned by a *nullable allocator* — `malloc`, `calloc`, `realloc`,
`strdup`, `strndup`, `fopen`, `fdopen`, `freopen`, `opendir`, `getenv` — that
are **dereferenced later in the same function with no intervening NULL check**.
On failure these functions return `NULL`; using the result unchecked
dereferences a null pointer.

This is a taint-propagation check (the source is the allocator return, the sink
is a memory access through the returned pointer, the sanitizer is any NULL
guard between them). The detector tracks the return register (`rax` on x86_64,
`x0` on AArch64) and any register the pointer is moved into, then scans forward
from the call site: a `test`/`cmp`-against-zero (x86_64) or `cbz`/`cbnz`/`cmp
#0` (AArch64) on the pointer is treated as a guard and **suppresses** the
finding; a dereference (`[reg]` memory operand) reached *before* any guard is
flagged. A pointer that escapes (stored to memory, passed onward) before any
visible dereference is **not** flagged. The heuristic is intentionally
conservative — no CFG reconstruction, no inter-procedural analysis — and every
CWE-476 finding is therefore `low` confidence.

```bash
$ blight --binary path/to/elf --checks 476 --format json
{
  "binary": "path/to/elf",
  "checks": [476],
  "findings": [
    {
      "cwe": 476,
      "function": "build",
      "address": "0x401150",
      "evidence": "return value of malloc dereferenced without a NULL check (possible NULL pointer dereference on allocation failure)",
      "symbol": "malloc",
      "confidence": "low"
    }
  ]
}
```

### CWE-252 — Unchecked Return Value

Calls to security- or integrity-sensitive functions whose **return value is
discarded without being checked**. The canonical bug: a program calls
`setuid(0)` to drop privileges, the call fails, the non-zero return is ignored,
and execution continues with elevated privileges. The same shape causes silent
data loss for short `write`/`fwrite` and for `fclose`/`fflush`/`fsync` flush
failures. The flagged set covers privilege/identity changes (`setuid`, `setgid`,
`seteuid`, `setegid`, `setreuid`, `setregid`, `setresuid`, `setresgid`,
`setgroups`), sandbox entry (`chroot`, `chdir`), and durable writes (`write`,
`pwrite`, `fwrite`, `fclose`, `fflush`, `fsync`, `fdatasync`).

This is the inverse of the CWE-476 check (a *discard* without a *check*, rather
than a *use* without a *check*). The detector tracks the return register (`rax`
on x86_64, `x0`/`w0` on AArch64) and scans forward from the call site: a
`test`/`cmp` guard (x86_64) or `cbz`/`cbnz` (AArch64) on the return, or any read
of it (saved to another register, stored, passed onward), means the value was
checked and **suppresses** the finding. If the return register is overwritten by
an unrelated value, clobbered by a following `call`, or the function ends before
the value is ever read, the return was discarded and is flagged. The heuristic
is intentionally conservative — no CFG reconstruction, no inter-procedural
analysis — and every CWE-252 finding is therefore `low` confidence.

```bash
$ blight --binary path/to/elf --checks 252 --format json
{
  "binary": "path/to/elf",
  "checks": [252],
  "findings": [
    {
      "cwe": 252,
      "function": "drop_privs",
      "address": "0x401150",
      "evidence": "return value of setuid is ignored (unchecked return value — failure goes undetected)",
      "symbol": "setuid",
      "confidence": "low"
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

### CWE-732 — Incorrect Permission Assignment for Critical Resource

Calls to `chmod` / `fchmod` / `fchmodat` / `mkdir` / `mkdirat` / `creat` with
a **constant** mode operand that grants world-writable permissions. The
embedded `0o777` / `0o666` mistake is the canonical CWE-732 pattern in audited
firmware — the binary ships with the over-permissive mode every time it runs.
A safe mode such as `0o644` or `0o755` is **not** flagged; a non-constant
mode (a register or memory operand reaching the mode position) is also
**not** flagged here — the detector is precision-first and exists to catch
the literal-immediate misconfiguration, not every dynamic chmod.

The detector is a hybrid: PLT lookup locates the call sites, then per-
architecture argument-register inspection (the same machinery as CWE-78 and
CWE-134) parses the immediate that last writes the mode register. The mode
register varies by symbol — `chmod`/`fchmod`/`mkdir`/`creat` carry mode at
arg1; `fchmodat`/`mkdirat` carry mode at arg2 — so the detector consults a
per-symbol arg-index table before reading the register convention. x86_64
and AArch64 are supported.

| Mode pattern | Severity | Why it's flagged |
|---|---|---|
| `mode & 0o6000` set AND world-writable (e.g. `0o4777`) | HIGH | Setuid/setgid binary world-writable — full privilege-escalation primitive |
| World-writable (`mode & 0o002`), no suid/sgid (e.g. `0o777`, `0o666`) | MEDIUM | Any user on the system can write to the resource |

Both tiers are emitted at HIGH `confidence` — the mode is a parsed literal,
not a heuristic guess. Use `--min-confidence high` to keep CWE-732 alongside
other parsed-evidence findings, or filter on `CWE-732` in your suppression
file as usual.

```bash
$ blight --binary path/to/elf --checks 732 --format json
{
  "binary": "path/to/elf",
  "checks": [732],
  "findings": [
    {
      "cwe": 732,
      "function": "open_world",
      "address": "0x401160",
      "evidence": "[MEDIUM] call to chmod with world-writable permission mode 0o777 (insecure permission assignment)",
      "symbol": "chmod",
      "confidence": "high"
    }
  ]
}
```

### CWE-798 — Use of Hard-coded Credentials

A secret baked into the binary — a default admin password, an API key, an
embedded private key, or a connection string with an inline `user:password@host`
— is one of the most common and most damaging findings in a real firmware /
embedded audit. Unlike every other detector, CWE-798 is **data-driven, not
PLT-driven**: a hard-coded secret leaves no call-site fingerprint, so this check
scans the binary's extracted string literals (radare2 `izzj`, surfaced via
`R2Session.strings()`) for the textual shape of a credential. It is the first
blight detector that reads string *data* rather than the call graph.

Three independent signals fire:

| Signal | Severity | What it matches |
|---|---|---|
| Embedded key material | HIGH | A PEM `-----BEGIN … PRIVATE KEY-----` armour header, an OpenSSH private-key banner, or a PuTTY key header |
| Credential URI | HIGH | A `scheme://user:password@host` authority with a concrete (non-placeholder) password |
| Assignment-style secret | HIGH / MEDIUM | `key=value` / `key: value` / `export KEY=value` where the key names a secret (`password`, `passwd`, `secret`, `api_key`, `token`, `private_key`, …) and the value is concrete; password-class keys are HIGH, token/key-class are HIGH when the value is long/secret-shaped and MEDIUM otherwise |

False positives are controlled by rejecting **format templates and
placeholders**: `%s` conversions, `{0}` / `${VAR}` / `$VAR` templates, empty
values, and sentinels (`changeme`, `example`, `your_password_here`, …) never
fire, and only secret-class key names are considered (so `username=admin` is not
flagged). The detector **never echoes the secret value** — evidence strings carry
only a redacted preview (first character + length), so the report itself does not
leak the credential. Like the PLT-lookup detectors it is architecture-agnostic;
strings are the same on every target radare2 can parse.

```bash
$ blight --binary path/to/elf --checks 798 --format json
{
  "binary": "path/to/elf",
  "checks": [798],
  "findings": [
    {
      "cwe": 798,
      "function": ".rodata",
      "address": "0x402010",
      "evidence": "[HIGH] hard-coded credential: password=S************** (len=15)",
      "symbol": "password",
      "confidence": "high"
    }
  ]
}
```

## Architecture support

`blight` supports **x86_64** and **AArch64 (arm64)** ELF binaries.

The CWE-22, CWE-89, CWE-119, CWE-120, CWE-242, CWE-295, CWE-327, CWE-362,
CWE-426, and CWE-676 detectors flag any call site to a dangerous symbol and are therefore architecture-agnostic
— they work on every architecture radare2 can disassemble. CWE-798 is likewise
architecture-agnostic (it scans string data, not the call graph). The CWE-78 and CWE-134 detectors inspect
the register that carries a specific argument (the command string, the format
string), CWE-476 and CWE-252 inspect the *return* register (`rax`/`x0`) plus
the architecture's guard idioms (NULL-checks for CWE-476, return-value checks for
CWE-252), and CWE-416 tracks the *first-argument* register (`rdi`/`x0`) carrying
the freed pointer plus the per-architecture reassignment idioms (`mov rdi, 0` /
`xor` / `mov x0, 0`); all resolve the register convention per-architecture, so
they work on x86_64 and AArch64:

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

In scope: ELF (x86_64 and AArch64), the CWE classes above, JSON, SARIF, and
human-readable text output, pattern matching on disassembly.

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
