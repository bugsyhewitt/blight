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
blight --binary PATH [--checks {22,78,89,119,120,134,242,252,295,327,362,369,426,476,676,798,all}] [--format {json,sarif,text}] [--output-file FILE] [--workers N] [--min-confidence {low,medium,high}] [--fail-on {none,low,medium,high}]
```

- `--binary` — path to the ELF binary **or a directory of binaries** to analyze
  (required)
- `--checks` — which CWE check to run; one of `22`, `78`, `89`, `119`, `120`,
  `134`, `242`, `252`, `295`, `327`, `362`, `369`, `426`, `476`, `676`, `798`,
  or `all` (default: `all`)
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
| `high` | The dangerous symbol *is* the finding; no data-flow inference. | CWE-22 (HIGH-severity symbols), CWE-89 (HIGH-severity symbols), CWE-119 (HIGH-severity symbols), CWE-120, CWE-242, CWE-295 (HIGH-severity symbols), CWE-327 (HIGH-severity symbols), CWE-426, CWE-676 (HIGH-severity symbols), CWE-798 (password / key-material / URI-credential / secret-shaped values) |
| `medium` | A heuristic fired (e.g. non-constant argument) that can miss aliased registers. | CWE-22 (MEDIUM-severity symbols), CWE-78, CWE-89 (MEDIUM-severity symbols), CWE-119 (MEDIUM-severity symbols), CWE-134, CWE-295 (MEDIUM-severity symbols), CWE-327 (MEDIUM-severity symbols), CWE-362, CWE-676 (MEDIUM-severity symbols), CWE-798 (short token/key-class values that may be config knobs) |
| `low` | The pattern is weakly indicative. | CWE-476 (path-reachability of the allocation failure is not proven), CWE-252 (path-reachability of the call failure is not proven), CWE-369 (the divisor is unchecked but its zero-reachability is not proven), CWE-676 (LOW-severity symbols) |

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
in v0.1; CWE-22, CWE-89, CWE-119, CWE-134, CWE-252, CWE-295, CWE-327, CWE-362,
CWE-369, CWE-426, CWE-476, CWE-676, and CWE-798 were added post-v0.1 (see
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
string), and CWE-476 and CWE-252 inspect the *return* register (`rax`/`x0`) plus
the architecture's guard idioms (NULL-checks for CWE-476, return-value checks for
CWE-252); all resolve the register convention per-architecture, so they work on
x86_64 and AArch64:

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
