# blight — Post-v0.1 Directions

This file records the ranked backlog of improvements for blight after v0.1 ships.
Items are ranked by **value/effort ratio**: highest return for the smallest change first.
Each item notes whether it requires only a new detector file (`detector-only`) or deeper
architectural changes (`arch-change`).

**How to pick the next item:** Take the top-ranked item that fits your current risk appetite
for scope. Detector-only items can be done in one small PR with no impact on existing tests.
Arch-change items need a design pass first; scope them carefully before starting. When an
item is complete, move it to `## Shipped` at the bottom and update `README.md`.

---

## Ranked Backlog

### 1. CWE-134 — Format String Detection  ★★★★★  ✅ SHIPPED
**Complexity:** Low (`detector-only`)  
**Requires:** New `src/blight/detectors/cwe134.py` + fake session fixtures + tests.  
**Architecture change:** None. Follows the identical PLT-lookup + xref pattern as CWE-120.

**Rationale:**  
Format string vulnerabilities are among the most actively disclosed CWEs in 2025. The
[CVE-2025-48826](https://radar.offseq.com/threat/cve-2025-48826-cwe-134-use-of-externally-controlle-fd583422)
(Planet WGR-500 router, CVSS 8.8), Ruby JSON gem format string injection, Notepad++
format string in the Find Results panel, and SonicOS post-auth crash all landed in a
single six-month window. Embedded devices and network appliances — exactly the class of
ELF binaries blight targets — are disproportionately affected.

Detection pattern: flag any call-site where `printf`, `fprintf`, `syslog`, `snprintf`,
`vprintf`, `vsprintf`, `vfprintf`, `vsyslog` receive a format argument that is NOT a
constant string literal. This is the same heuristic blight already ships for CWE-78:
inspect the instruction that last sets the format-string register (`rdi` for single-arg
forms, `rsi` for `fprintf`-style two-arg forms) and check whether it references a
`str.*` symbol. `cwe_checker` lists CWE-134 as RED (critical severity), confirming
community consensus on its importance.

**Implementation note:** `snprintf` is in the DANGEROUS list for CWE-120 too; for CWE-134
the question is different (is the format string a literal?). The two detectors are
complementary, not redundant.

---

### 2. Additional Inherently Dangerous Functions (CWE-676 / CWE-242 extension)  ★★★★☆  ✅ SHIPPED
**Complexity:** Low (`detector-only`)  
**Requires:** Extend `src/blight/detectors/cwe242.py` (or add `cwe676.py`) + test cases.  
**Architecture change:** None.

**Rationale:**  
`cwe_checker` flags CWE-676 (Use of Potentially Dangerous Function) as RED. Beyond the
`gets`/`getpass` blight already detects, a short list of functions have no safe call
sites: `tmpnam` (race condition, replaced by `mkstemp`), `mktemp` (same),
`strtok` (non-reentrant, replaced by `strtok_r`), `asctime`/`ctime` (non-reentrant),
`rand` (predictable PRNG when used for security). These are PLT-lookup detections — zero
new infrastructure needed, one line of evidence string per symbol. False-positive rate
approaches zero because the functions themselves are the finding, with no context needed.

---

### 3. SARIF Output Format  ★★★★☆  ✅ SHIPPED
**Complexity:** Low (`arch-change` in output layer only)  
**Requires:** Add `--format sarif` to CLI; add `src/blight/formatters/sarif.py`; tests.  
**Architecture change:** CLI output layer only. No detector changes.

**Rationale:**  
SARIF (Static Analysis Results Interchange Format) is the native format for GitHub Code
Scanning, VS Code security extensions, and most modern CI/CD pipelines. Adding `--format
sarif` lets blight emit findings that appear as inline annotations in GitHub PRs and that
feed into security dashboards without post-processing. This is a pure integration win —
no analysis logic changes, minimal implementation risk, and it unblocks blight's use in
automated supply-chain pipelines alongside tools like CodeQL. SARIF output also sets the
stage for future embalmer integration as a first-class pipeline source.

---

### 4. Confidence Scoring on Findings  ★★★☆☆  ✅ SHIPPED
**Complexity:** Low (`arch-change` in Finding model)  
**Requires:** Add `confidence: str` field (`high`/`medium`/`low`) to `Finding`; update
all detectors to emit a confidence value; update JSON output schema.  
**Architecture change:** `findings.py`, `pipeline_adapter.py`, all detectors, CLI output.

**Rationale:**  
Static analysis tools live or die by false-positive rate. Attaching a confidence label to
each finding gives consumers a first-pass filter without requiring them to understand the
heuristic internals. Proposed defaults: CWE-120/242 findings are `high` confidence
(presence of the dangerous function IS the finding); CWE-78 findings where the
non-constant heuristic fired are `medium` (the heuristic can miss aliased registers);
CWE-134 (when added) is `medium`. The `BinaryFinding` schema from `binary-finding-schema`
likely needs a version bump to carry this field, so this item should be coordinated with
that project.

---

### 5. ARM/aarch64 Architecture Support  ★★★☆☆  ✅ SHIPPED
**Complexity:** Medium (`arch-change` in CWE-78 heuristic)  
**Requires:** Abstract the register-convention logic in `cwe78.py` behind an
architecture-aware helper; add AArch64 register names (`x0`, `w0`); integration test
against an ARM ELF.  
**Architecture change:** `cwe78.py`, `r2.py` (needs to surface the binary's arch).

**Rationale:**  
The README defers ARM/MIPS/PPC explicitly. ARM (AArch64) is the highest-value first
target: the first function argument lives in `x0`/`w0`, not `rdi`. CWE-120 and CWE-242
detectors do not depend on register conventions (they flag any call site), so they work on
ARM already. Only the CWE-78 argument-is-constant heuristic needs updating. AArch64
embedded Linux is now dominant in IoT and mobile, making this a meaningful coverage
expansion. `radare2` fully supports AArch64 (`aaa` works cleanly); the change is confined
to blight's register-alias table and the `r2.py` session (add an `arch()` method using
`iAj`).

---

### 6. CWE-476 — NULL Pointer Dereference  ★★★☆☆  ✅ SHIPPED
**Complexity:** Medium (`detector-only`, but heuristic is harder)  
**Requires:** New `src/blight/detectors/cwe476.py` + fixtures; must define a conservative
heuristic for statically detectable patterns.  
**Architecture change:** None in the dispatch layer; heuristic complexity is the risk.

**Rationale:**  
`cwe_checker` lists CWE-476 as ORANGE (moderate) and it appears in its top-detected
categories. A conservative static heuristic: flag call sites where a function's return
value is used as a pointer (dereferenced or passed to a pointer-taking argument) without
an intervening null check. This is detectable via `pdfj` disassembly without
inter-procedural analysis. Common pattern in C: `malloc()` return used without null check,
`fopen()` return dereferenced directly. False-positive rate will be higher than CWE-120 —
the confidence should be `low` by default. Scope carefully: start with `malloc`/`calloc`
returns used without a `test`/`cmp` null guard in the same basic block.

---

### 7. CWE-252 — Unchecked Return Value  ★★☆☆☆  ✅ SHIPPED
**Complexity:** High (`detector-only` but needs control-flow analysis)  
**Requires:** Function-level CFG from radare2 (`agj`); check whether return value register
is tested after calls to security-sensitive functions.  
**Architecture change:** New CFG query in `r2.py`.

**Rationale:**  
`cwe_checker` v0.9 shipped CWE-252 as a new check, including Linux Kernel Module support,
signaling maturation of the pattern. Unchecked return values from `setuid`, `setgid`,
`chroot`, `fclose`, `write` are a class of privilege escalation / data-loss bugs. The
detection requires confirming that the instruction after a call does NOT test/move the
return register (`rax`/`eax`). This is feasible with `pdfj` data but requires tracking
CFG edges when the call is not the last instruction in a basic block. Rank is lower than
items 1-6 because the heuristic complexity is high relative to yield; implement after
confidence scoring is in place (item 4) so the `low`-confidence label can be applied.

---

### 8. `--suppress` File for Known False Positives  ★★☆☆☆  ✅ SHIPPED
**Complexity:** Medium (`arch-change` in CLI + engine)  
**Requires:** Define a YAML/JSON suppression format; CLI `--suppress FILE` flag; engine
filters findings against suppressions before output.  
**Architecture change:** `cli.py`, `engine.py`, new `suppressions.py`.

**Rationale:**  
Every static analysis tool accumulates known FPs over time. A suppression file (keyed on
`cwe + function + address` or `cwe + function + symbol`) lets teams codify accepted risk
without modifying the binary or the tool. This is table-stakes functionality for adoption
in organizations with existing risk registers. Lower ranked because blight's current FP
rate is already low (PLT-based detection) and the benefit grows with user base.

---

## How to Pick the Next Item

1. **If you have two hours:** Pick item 1 (CWE-134) or item 2 (CWE-676 extension). Both
   are a single new Python file plus tests. No design needed.

2. **If you want integration wins:** Pick item 3 (SARIF). Purely additive to the output
   layer; no analysis logic touched.

3. **If the tool is being used in production:** Pick item 4 (confidence scoring) to
   reduce alert fatigue before adding more detectors.

4. **If expanding to IoT/embedded targets:** Pick item 5 (ARM) before adding more
   CWE classes — coverage breadth matters more than CWE depth for that audience.

5. **Do not pick items 7 or 8 first.** They have higher effort, lower precision,
   or depend on earlier items (CFG for 7). Item 6 (CWE-476) has shipped.

---

## Research Notes

**Competitor landscape (as of 2025-05):**
- `cwe_checker` (fkie-cad): Ghidra + BAP-based, requires Rust toolchain + Docker.
  Detects 18+ CWEs. blight's niche (pure Python, no JVM/Docker) is validated.
- `flawfinder` / `semgrep`: Source-code only. Not competitors for binary analysis.
- `Joern`: JVM-based binary analysis. The other Python-free binary option is blight.
- `r2inspect`: Emerging radare2-based static malware analysis framework (r2con 2025).
  Watch for overlap with blight's detection approach.

**MITRE 2025 CWE Top 25 signal:**
- CWE-78 is #9 with 18 CISA KEV additions in 2025 — blight's coverage is well-placed.
- CWE-120 NEW ENTRY at #11 — validates blight's v0.1 detector selection.
- CWE-134 dropped off Top 25 but has very active CVE flow in embedded firmware (2025).
- CWE-190 (integer overflow) dropped off Top 25 and requires symbolic execution for
  precise detection — deprioritized accordingly.
- CWE-416 (use-after-free) requires heap modeling — out of scope for static PLT analysis.

**radare2 / r2pipe status (2025):**
- r2pipe 1.9.6 (June 2025), radare2 6.1.2 active development.
- No breaking API changes; `iij`, `axtj`, `pdfj`, `agj` commands stable.
- `iAj` (binary arch info) available for architecture detection (item 5 above).
- r2inspect emerging as a complementary framework; worth tracking for future integration.

---

## Shipped

- **`--fail-on` CI Exit-Code Gate** (post-backlog; completes the CI story
  begun by Rank 4 confidence scoring and the `--min-confidence` filter).
  `src/blight/exit_gate.py` adds a `--fail-on {none,low,medium,high}` CLI flag
  that makes `blight` exit non-zero when any *emitted* finding is at or above
  the chosen triage confidence, turning the tool into a build gate that fails
  a pipeline without any post-processing of the JSON. The threshold reuses the
  `low < medium < high` ordering (via `confidence_filter.meets_threshold`),
  with an extra `none` token (the default) that disables the gate for full
  backward compatibility — the historical "always exit 0" behaviour is
  unchanged when the flag is omitted. Crucially the gate runs over the findings
  that survive `--suppress` and `--min-confidence`, so it is always consistent
  with the report the user sees: a suppressed or below-threshold finding cannot
  trip the gate. For a directory scan it aggregates across every binary's
  surviving findings (one qualifying finding anywhere fails the run); an
  errored scan carries no findings and never trips on its own. The gate exit
  code is `1`, distinct from argparse's usage-error code `2`, so CI can tell
  "found vulnerabilities" apart from "bad invocation". This was chosen as the
  next improvement because all eight ranked backlog items plus the
  `--min-confidence` filter had shipped, the confidence labels were being
  emitted but were not yet *actionable* as a build gate (a real adoption
  blocker for CI pipelines), and it is a pure CLI/output-layer change requiring
  no new detector heuristics or blocked external tooling — the remaining
  high-yield CWE classes (CWE-190, CWE-416) still need symbolic execution /
  heap modeling that is out of scope for blight's static approach. See
  `tests/test_exit_gate.py`.

- **`--min-confidence` Triage Threshold Filter** (post-backlog; pairs with
  Rank 4 confidence scoring). `src/blight/confidence_filter.py` adds a
  `--min-confidence {low,medium,high}` CLI flag that drops every finding below
  the chosen triage confidence before output. The threshold is inclusive and
  ordered `low < medium < high`, so `high` keeps only high-confidence findings,
  `medium` keeps medium and high, and `low` (the default) is the identity
  filter that keeps everything — making the flag fully backward compatible.
  Like `--suppress` it is a pure output-layer filter (detectors and the
  analyzed binary are untouched), applied uniformly to single-file and
  directory scans and to both `json` and `sarif` output via
  `_apply_min_confidence` in `cli.py`, and it composes with `--suppress`
  (suppression runs first, then the confidence threshold). Errored results are
  passed through untouched (no findings to filter, `error` preserved). This
  turns the Rank-4 confidence labels into an actionable CI gate without any
  post-processing of the JSON. Chosen as the next improvement because all eight
  ranked backlog items had already shipped and the remaining high-yield
  CWE classes (CWE-190 integer overflow, CWE-416 use-after-free) require
  symbolic execution / heap modeling that is out of scope for blight's
  PLT-and-disassembly static approach (see Research Notes). See
  `tests/test_confidence_filter.py`.

- **`--suppress` File for Known False Positives** (Rank 8).
  `src/blight/suppressions.py` adds a `--suppress FILE` CLI flag that loads a
  JSON suppression file and drops matching findings from the output before it
  is emitted. It is a pure output-layer filter — detectors and the analyzed
  binary are untouched — applied uniformly to single-file and directory scans
  and to both `json` and `sarif` output (the CLI filters each `ScanResult`'s
  findings in `_apply_suppressions` before `_emit_single`/`_emit_directory`).
  A rule must carry `cwe` and may add any of `function`/`address`/`symbol` as
  extra constraints; all present constraints must match (logical AND) and
  omitted fields are wildcards, so `{"cwe": 120}` suppresses every CWE-120
  finding while `{"cwe": 120, "symbol": "strcpy", "address": "0x40114a"}`
  suppresses exactly one call site. `address` comparison is case-insensitive
  and `0x`-prefix-tolerant; `cwe` accepts an int, a numeric string, or a
  `"CWE-120"` string; `reason` and `"//"` keys are documentation-only and
  ignored. JSON was chosen over YAML deliberately to avoid adding a
  third-party parser — blight's pure-Python, no-extra-toolchain stance is part
  of its niche. Malformed files raise `SuppressionError`, surfaced as an
  `argparse` error that aborts the run before any scanning. See
  `tests/test_suppressions.py`.

- **CWE-252 — Unchecked Return Value** (Rank 7).
  `src/blight/detectors/cwe252.py` flags call sites to security- and
  integrity-sensitive functions whose return value is discarded without being
  checked: privilege/identity changes (`setuid`/`setgid`/`seteuid`/`setegid`/
  `setreuid`/`setregid`/`setresuid`/`setresgid`/`setgroups`), sandbox entry
  (`chroot`/`chdir`), and durable writes (`write`/`pwrite`/`fwrite`/`fclose`/
  `fflush`/`fsync`/`fdatasync`). It is the inverse of CWE-476: a single-function
  forward linear scan tracks the return register (`rax`/`eax` on x86_64,
  `x0`/`w0` on AArch64) from the call site. A read of the return — a `test`/`cmp`
  guard, a `cbz`/`cbnz` (AArch64), a save into another register, a store, or use
  as an outgoing argument — counts as "checked" and suppresses the finding. A
  clobber (overwrite by an unrelated value, or a following `call` returning into
  the same register) or reaching function end before any read means the return
  was discarded and is flagged. No CFG reconstruction and no inter-procedural
  analysis (the higher-effort CFG path noted in the original rank-7 design was
  deliberately not taken — the conservative linear scan is sufficient for the
  discard-vs-check distinction), so every finding is `low` confidence per the
  rank-7 guidance. Architecture-aware on x86_64 and AArch64. Registered as check
  `252`. See the `TestCwe252` block in `tests/test_detectors.py` and the CWE-252
  fixtures in `tests/fake_session.py`.

- **CWE-476 — NULL Pointer Dereference** (Rank 6).
  `src/blight/detectors/cwe476.py` flags the common pattern where a pointer
  returned by a nullable allocator (`malloc`/`calloc`/`realloc`/`strdup`/
  `strndup`/`fopen`/`fdopen`/`freopen`/`opendir`/`getenv`) is dereferenced
  later in the same function with no intervening NULL guard. It is a
  taint-propagation detector: the source is the allocator return register
  (`rax`/`x0`), tracked through register-to-register `mov` aliases; the sink is
  a memory operand `[reg]` through a live pointer register; the sanitizer is a
  `test`/`cmp #0` (x86_64) or `cbz`/`cbnz`/`cmp #0` (AArch64) on the pointer.
  Reaching a guard first suppresses the finding; a pointer that escapes (stored
  to memory / passed onward) before any visible deref is not flagged. No CFG or
  inter-procedural analysis — a single-function forward linear scan — so every
  finding is `low` confidence per the rank-6 guidance. Architecture-aware on
  x86_64 and AArch64. Registered as check `476`. See the `TestCwe476` block in
  `tests/test_detectors.py` and the CWE-476 fixtures in `tests/fake_session.py`.

- **Parallel directory scanning (`--workers N`)**. `--binary` now accepts a
  directory; `blight` discovers every regular file under it (recursively, sorted
  by path) and scans them via `src/blight/scan.py`. `--workers N` fans the scan
  out across a `ThreadPoolExecutor` — threads were chosen over processes because
  each binary's analysis is dominated by I/O to the radare2 subprocess (the GIL
  is released), avoiding pickling and keeping the fake-session test injection
  path intact. `scan_targets` returns results in input order with each binary's
  findings sorted identically regardless of `--workers`, so parallel output
  equals sequential output exactly; a failure on one binary is isolated to that
  result's `error` field and never aborts the rest. Directory JSON output is a
  `{directory, checks, results[]}` object; single-file output keeps the legacy
  `{binary, checks, findings}` shape. See `tests/test_scan.py`.

- **CWE-134 — Format String Detection** (Rank 1). `src/blight/detectors/cwe134.py`
  flags `printf`/`fprintf`/`syslog`/`snprintf`/`vprintf`/`vsprintf`/`vfprintf`/
  `vsyslog` call sites where the format-string register is loaded from a
  non-constant source. Registered as check `134`.

- **CWE-676 — Use of Potentially Dangerous Function** (Rank 2).
  `src/blight/detectors/cwe676.py` flags any call site to `tmpnam`, `mktemp`
  (HIGH — TOCTOU race, use `mkstemp`), `strtok` (MEDIUM — non-reentrant, use
  `strtok_r`), `asctime`/`ctime` (LOW — non-reentrant, use `*_r`), and `rand`
  (MEDIUM — predictable PRNG, use `getrandom`). Pure PLT-lookup detection; the
  symbol is the finding. Registered as check `676`. Severity is surfaced in the
  evidence string.

- **Confidence Scoring on Findings** (Rank 4). Every `Finding` now carries a
  `confidence` label (`high`/`medium`/`low`), threaded through `to_dict()`,
  the CLI JSON output, the SARIF `properties.confidence` field, and the
  `pipeline_adapter` → `BinaryFinding` conversion (the `binary-finding-schema`
  `BinaryFinding` already supports the field, defaulting to `medium`, so no
  schema bump was needed). Policy: CWE-120/242 are `high` (the symbol is the
  finding); CWE-78/134 are `medium` (the non-constant heuristic can miss
  aliased registers); CWE-676 mirrors its per-symbol severity (HIGH→`high`,
  MEDIUM→`medium`, LOW→`low`). See `tests/test_confidence.py`.

- **SARIF Output Format** (Rank 3). `--format sarif` emits SARIF 2.1.0 via
  `src/blight/formatters/sarif.py`, with each finding's `confidence` surfaced
  under `properties.confidence`. See `tests/test_sarif.py`.

- **ARM/aarch64 Architecture Support** (Rank 5). The argument-register
  convention used by the CWE-78 and CWE-134 heuristics is now resolved
  per-architecture via `src/blight/detectors/_argregs.py`. `R2Session` gained an
  `arch()` method (`Radare2Session` reads radare2's `iAj`; the fake takes an
  `arch=` argument) that normalizes the binary's arch to `x86_64` or `arm64`,
  falling back to x86_64 for unknown/32-bit-only targets. On AArch64 the first
  three arguments are read from `x0`/`x1`/`x2` (with `w0`-`w2` aliases) instead
  of `rdi`/`rsi`/`rdx`. CWE-120/242/676 were already register-agnostic and work
  on ARM unchanged. 32-bit ARM/MIPS/PPC remain out of scope. See
  `tests/test_arch.py` and the new `arch()` integration assertion in
  `tests/test_integration.py`.
