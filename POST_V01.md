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
- CWE-89 (SQL injection) is a perennial Top-25 weakness — now covered via the
  raw-SQL-execution PLT sinks (see Shipped: CWE-89).
- CWE-120 NEW ENTRY at #11 — validates blight's v0.1 detector selection.
- CWE-134 dropped off Top 25 but has very active CVE flow in embedded firmware (2025).
- CWE-190 (integer overflow) dropped off Top 25 and requires symbolic execution for
  precise detection — deprioritized accordingly.
- CWE-416 (use-after-free): full heap-lifetime modeling is out of scope for
  static analysis, but a conservative *triage* detector now ships — it flags a
  pointer that is freed and then reused (dereferenced or passed onward) in the
  same function with no intervening reassignment, the same single-function
  alias-tracking shape as CWE-476 / CWE-252 (see Shipped: CWE-416).

**radare2 / r2pipe status (2025):**
- r2pipe 1.9.6 (June 2025), radare2 6.1.2 active development.
- No breaking API changes; `iij`, `axtj`, `pdfj`, `agj` commands stable.
- `iAj` (binary arch info) available for architecture detection (item 5 above).
- r2inspect emerging as a complementary framework; worth tracking for future integration.

---

## Shipped

- **CWE-131 — Incorrect Calculation of Buffer Size** (post-backlog; the
  upstream off-by-one sibling of CWE-122). `src/blight/detectors/cwe131.py`
  flags the textbook NUL-terminator off-by-one: an allocation
  (`malloc` / `calloc` / `realloc` / `reallocarray` / `alloca` / `valloc` /
  `pvalloc` / `__builtin_alloca`) whose **size argument is the return of
  `strlen` / `wcslen` with no `+ 1` adjustment** for the trailing NUL byte.
  The canonical C source is `buf = malloc(strlen(src)); strcpy(buf, src);` —
  the buffer is one byte short of holding the string plus its terminator, so
  the `strcpy` writes the NUL past the end of the heap allocation. **Chosen
  over CWE-252** (the original next-detector candidate) after auditing the
  source tree: CWE-252 already shipped in R8 (`src/blight/detectors/cwe252.py`)
  via the conservative linear-scan check-vs-clobber heuristic, so the
  task's first suggestion was a no-op; CWE-131 was the next named candidate
  and is the highest-value unshipped MITRE-listed memory-corruption gap that
  fits blight's existing precision-first PLT-anchored backward-scan machinery
  (the same shape as the shipped CWE-191 size-from-subtraction detector and
  the shipped CWE-122 alias-tracking heap-overflow detector). Implementation
  mirrors CWE-191: a PLT lookup over the allocator family locates the call
  sites, the size-argument register is resolved per-architecture via the
  shared `_argregs.arg_register_aliases` table (arg0 for `malloc` /
  `alloca` / `valloc` / `pvalloc`; arg1 for `realloc` / `reallocarray` /
  `calloc`), then a single-function linear backward scan walks from the
  allocator with an alias set seeded by the size register. A `mov D, S`
  where `D` is tracked propagates the alias by adding `S` and dropping `D`
  (a non-register source — immediate or memory load — terminates the chain
  for `D` so an unrelated earlier `strlen` cannot false-positive); an
  `inc D` or `add D, 1` (x86_64) / `add D, S, #1` (AArch64) into a tracked
  register clears the candidate — the NUL was accounted for; a non-`strlen`
  call clobbers the return register (`rax` on x86_64, `x0` on AArch64) and
  breaks the alias chain (conservative — suppress over false-flag); a
  `strlen` / `wcslen` call reached while the return register is still alive
  is the off-by-one fingerprint. Deliberately distinct from CWE-122 (whose
  sink is an unbounded *copy* of a heap buffer): CWE-122 anchors on the
  destination of the copy; CWE-131 anchors on the size of the allocation
  itself — the upstream off-by-one source. A call site can legitimately
  carry both findings. Architecture-aware on x86_64 and AArch64 (POST_V01
  item 5). Because the reachability of the allocation along the strlen path
  is not proven statically, every CWE-131 finding is `low` confidence,
  matching CWE-122 / CWE-191 / CWE-369 / CWE-476 policy. Registered as check
  `131`, so the `--checks {…,131,…,all}` token and the `all` set wire in
  automatically through the `DETECTORS` dispatch dict; SARIF maps CWE-131
  to level `error`. 14 new unit tests
  (`tests/test_detectors.py::TestCwe131`) cover the direct
  `malloc(strlen)` off-by-one, the `realloc` (arg1) and `calloc`
  variants, the `wcslen` wide-char sibling, the alias-propagated
  `strlen` → `mov rbx, rax` → `mov rdi, rbx` chain, the `+1` safe cases
  (`add rax, 1`, `inc rax`, AArch64 `add x0, x0, 1`), the size-reloaded
  safe case, the intervening-call clobber safe case, the constant-size /
  no-strlen-import baseline negatives, the AArch64 vuln + safe pair, and
  the multi-call-site mixed case; the `--checks all` (`test_cli`) and
  SARIF level-mapping (`test_sarif`) assertions were updated to include
  `131`. Unit test count 439 → 453.
- **CWE-377 — Insecure Temporary File** (post-backlog; new pure-PLT detector).
  `src/blight/detectors/cwe377.py` flags call sites to libc routines that
  create temporary files (or reserve temporary filenames in a file-creating
  idiom) through historically insecure mechanisms — distinct from the
  `tmpnam`/`mktemp` pair already flagged by CWE-676 (which is "use of
  inherently dangerous function" more broadly). Two severity tiers: HIGH for
  `tempnam` and `tmpnam_r` (they return a unique *name* but do not open the
  file, opening a TOCTOU window in which an attacker who can write the parent
  directory swaps the name for a symlink before the caller's
  `open(name, O_CREAT, ...)` runs — the Linux `tempnam(3)` manual page
  literally says "Never use this function. Use `mkstemp(3)` or `tmpfile(3)`
  instead."), and MEDIUM for `tmpfile` and `tmpfile64` (which *do* atomically
  open a temp file and are safe on modern glibc with kernel `O_TMPFILE`
  support, but fall back to `mkstemp` against `P_tmpdir` on legacy glibc and
  embedded/alternative libcs — uClibc-ng, older musl pre-1.2, BSD — where the
  template-permission and `TMPDIR`-attacker concerns reappear; the MEDIUM tier
  is the "audit-and-confirm" signal). The safe replacements `mkstemp` /
  `mkostemp` / `mkstemps` / `mkostemps` / `mkdtemp` and the explicit
  `open` + `O_TMPFILE` / `O_EXCL` idiom are deliberately not flagged — they
  are the recommended mitigation and flagging them would invert the signal.
  **Chosen as the next improvement after verifying both originally-named
  candidates (CWE-416 use-after-free, CWE-362 race condition) were already
  shipped**: per the worker pivot protocol, when both target CWEs are already
  detectors in the codebase the next-best gap from the post-v0.1 directions
  should be selected. The remaining named high-yield classes (CWE-190 integer
  overflow, CWE-457 uninitialized variable) still require symbolic execution
  or CFG/value-flow modeling that POST_V01 records as out of scope, whereas
  insecure-temp-file fits the existing precision-first PLT-and-arg-symbol
  machinery exactly (the same shape as CWE-22 / CWE-89 / CWE-119 / CWE-295 /
  CWE-327 / CWE-362 / CWE-426 / CWE-676 / CWE-732). Like CWE-676 it is a
  *pure PLT-lookup* detector built on the existing `_common.call_sites`
  helper — the symbol is the finding, no data-flow context is needed — so it
  required zero new infrastructure and is architecture-agnostic. Deliberately
  complementary, not overlapping, with CWE-676: CWE-676 owns `tmpnam` and
  `mktemp` (and the broader inherently-dangerous-function family `strtok` /
  `asctime` / `ctime` / `rand`), CWE-377 owns `tempnam`, `tmpnam_r`,
  `tmpfile`, `tmpfile64`. A `tmpnam` call site is therefore not double-flagged
  here. Confidence mirrors the per-symbol severity (HIGH → `high`,
  MEDIUM → `medium`), mirroring the CWE-676 / CWE-732 policy; SARIF maps
  CWE-377 to level `error`. Registered as check `377`, so the
  `--checks {…,377,…,all}` token and the `all` set wire in automatically
  through the `DETECTORS` dispatch dict. 11 new unit tests
  (`tests/test_detectors.py::TestCwe377`) covering each of the four flagged
  symbols, the all-four mixed session with confidence/severity assertions,
  the safe-replacement-not-flagged assertion, the clean-session and
  clean-baseline negatives, and a complementary-with-CWE-676 non-overlap
  assertion (verifying that a binary importing both `tmpnam` and `tempnam`
  produces exactly one CWE-377 finding for `tempnam`, and that CWE-676 still
  picks up `tmpnam` from the same session); the `--checks all` (`test_cli`)
  and SARIF level-mapping (`test_sarif`) assertions were updated to include
  `377`. Unit test count 378 → 389.

- **CWE-330 — Use of Insufficiently Random Values** (predictable PRNG
  seeding; the *seeding* sibling of CWE-676's bare-`rand` detector). Built on
  the same PLT-anchored argument-register inspection used by CWE-78 / CWE-134
  / CWE-732. `src/blight/detectors/cwe330.py` flags call sites to `srand` /
  `srandom` / `srand48` / `seed48` where the seed is provably predictable:
  either (HIGH) the return value of a publicly observable clock / pid source
  (`time`, `gettimeofday`, `clock`, `clock_gettime`, `getpid`, `getppid`) —
  the textbook predictable-seed primitive behind a long tail of token-
  prediction, key-recovery and session-replay CVEs — or (MEDIUM) a small
  constant immediate (≤ `0xff`), the canonical same-seed (CWE-336) mistake.
  Bare `rand()` calls remain CWE-676's territory; the two detectors are
  complementary — CWE-676 flags "predictable PRNG used at all", CWE-330 flags
  "PRNG seeded in a way that fixes its output sequence ahead of time".
  **Chosen over CWE-190 (integer overflow)** because precise CWE-190
  detection requires symbolic execution and was deliberately deprioritised
  in the Research Notes above, whereas CWE-330 fits the existing precision-
  first PLT-plus-arg-register machinery exactly. The detector is a hybrid:
  PLT lookup locates the seeding call sites; the same `_argregs` machinery
  resolves the per-architecture seed-argument register; a backward walk of
  the containing function finds the last write to that register, then
  classifies it as a literal predictable-source-return move (HIGH), a literal
  small-immediate move (MEDIUM), or unresolvable (skip — precision-first).
  An *intervening unrelated call* between the predictable source and the
  seed-register write breaks the link and silences the finding, because
  the intervening call clobbers the return register the heuristic relies
  on. Large constant immediates (`> 0xff`) are not flagged — they are likely
  domain-specific literals embedded by the build system, not same-seed
  mistakes. Both severity tiers carry HIGH triage confidence: the evidence
  is read literally out of the disassembly (a literal immediate, or a literal
  call sequence), so no heuristic guess is needed. Architecture-aware on
  x86_64 and AArch64. Registered as check `330`, so the `--checks {…,330,…}`
  CLI accepts it and the `DETECTORS` registry routes to its dispatch entry;
  SARIF maps CWE-330 to level `error`. 15 new unit tests in the
  `TestCwe330` block of `tests/test_detectors.py` and 13 new fixtures in
  `tests/fake_session.py` cover both severity tiers, both architectures, the
  intervening-call safe case, and a multi-call session with one predictable
  and one non-constant seed.

- **CWE-732 — Incorrect Permission Assignment for Critical Resource**
  (post-backlog; the *permissions* sibling of the existing PLT-anchored
  argument-constant detectors). `src/blight/detectors/cwe732.py` flags
  call-sites where `chmod` / `fchmod` / `fchmodat` / `mkdir` / `mkdirat` /
  `creat` is invoked with a **constant** mode argument that grants
  world-writable permissions. The embedded `0o777` / `0o666` mistake is the
  canonical CWE-732 pattern in audited firmware: the binary ships with the
  over-permissive mode every time it runs, no triage data flow needed —
  the constant immediate is the evidence. **Chosen over CWE-415 / CWE-672**
  (the original next-detector candidates) after re-reading the roster: both
  were already shipped earlier in the wave (see CWE-415 below; CWE-672 is
  closely covered by CWE-362's filesystem-TOCTOU detector). CWE-732 is the
  highest-value unshipped MITRE Top-25-adjacent permission weakness that
  fits the existing precision-first PLT-plus-arg-constant shape used by
  CWE-78 and CWE-134, so it lands as a small, infrastructure-free PR. The
  detector is a hybrid: PLT lookup locates the call sites, then per-
  architecture argument-register inspection (the same `_argregs` machinery
  shared with CWE-78 / CWE-134) parses the immediate that last writes the
  mode register. The mode register varies by symbol — `chmod` / `fchmod` /
  `mkdir` / `creat` carry mode at arg1; `fchmodat` / `mkdirat` carry mode
  at arg2 — so the detector consults a per-symbol arg-index table before
  reading the register convention. The parsed immediate is classified
  against two precision-first tiers: **HIGH** when both world-writable
  (`mode & 0o002`) and setuid/setgid (`mode & 0o6000`) bits are set (a
  full privilege-escalation primitive — `0o4777` is the textbook case);
  **MEDIUM** when world-writable without setuid/setgid (`0o777`, `0o666`).
  Safe modes (`0o644`, `0o755`) are not flagged; a non-constant mode (a
  register or memory operand reaching the mode position) is also not
  flagged, by design — the detector exists to catch the literal-immediate
  misconfiguration, not every dynamic chmod. Both severity tiers emit at
  HIGH triage confidence, because the immediate is a parsed literal (no
  heuristic guess). Architecture-aware on x86_64 and AArch64.

- **CWE-401 — Missing Release of Memory after Effective Lifetime** (memory
  leak; the *inverse-sink* sibling of the heap-lifetime detectors, built on the
  single-function alias-tracking machinery shared by CWE-122 / CWE-415 /
  CWE-416). `src/blight/detectors/cwe401.py` flags the statically-detectable
  leak: a heap buffer obtained from an allocator (`malloc` / `calloc` /
  `realloc` / `reallocarray` / `strdup` / `strndup` / `aligned_alloc` / `valloc`
  / `pvalloc` / `memalign`) whose **only register alias is then overwritten with
  an unrelated value** before it is ever freed, stored to memory, returned, or
  passed to another call. Once the sole handle to a freshly-allocated buffer is
  clobbered with no surviving copy, the program can never `free` it — the memory
  leaks. **Chosen over CWE-457** (uninitialized variable use): POST_V01 records
  (see the CWE-122 entry below) that a precise CWE-457 detector needs def-use
  dataflow over stack slots across basic blocks — the CFG/value-flow modeling
  repeatedly recorded as out of scope — whereas a leak reduces to the *same*
  in-function forward-scan-with-register-alias-tracking shape already proven by
  CWE-122/CWE-415/CWE-416, so it lands as a small, infrastructure-free PR. The
  detector seeds the alias set with the allocator **return** register (`rax` on
  x86_64, `x0` on AArch64) and scans forward: a register-to-register move
  propagates the alias (so the handle surviving in a copy is not a leak); a
  **store to memory** (`mov [rbp-8], rax`) lets the pointer escape our
  in-function view and is conservatively presumed managed (not flagged); a
  **free** of a live alias releases the buffer (not flagged); the pointer left
  in / moved to the **return register** at `ret` is a caller handoff (not
  flagged); a pass to **any other call** leaves ownership ambiguous (not
  flagged); and overwriting the **last** live alias with an unrelated value — a
  memory reload, a fresh `lea` address, an immediate, an `xor reg,reg`, or an
  unrelated register — with no surviving copy and no preceding
  free/escape/return/handoff is the leak. This conservative bias (suppress on
  escape/free/return/handoff) keeps false positives low, which is the dominant
  risk for a leak detector — at the cost of missing leaks that escape our
  register view. Deliberately distinct from CWE-415/CWE-416 (whose sinks are a
  *second free* / a *use of a freed pointer*) — here nothing is freed at all,
  which is the whole point. `realloc` / `reallocarray` are included as
  allocators because their *return* value is the live (possibly moved) heap
  buffer that must be freed, exactly as in CWE-122. Architecture-aware on x86_64
  and AArch64 (POST_V01 item 5), resolved through the shared
  `_argregs.arg_register_aliases` table. Because reachability of the clobber
  along the allocated path is not proven statically, every CWE-401 finding is
  `low` confidence, matching CWE-122 / CWE-415 / CWE-416 / CWE-476 policy.
  Registered as check `401`, so the `--checks {…,401,all}` token and the `all`
  set wire in automatically through the `DETECTORS` dispatch dict; SARIF maps
  CWE-401 to level `error`. 10 new unit tests
  (`tests/test_detectors.py::TestCwe401`) covering the direct clobbered-unfreed
  leak, the alias-propagated leak, the freed / stored-escape / returned /
  passed-to-call safe cases, the no-allocator-import / clean-baseline negatives,
  and the AArch64 leak + freed-safe pair; the `--checks all` (`test_cli`) and
  SARIF level-mapping (`test_sarif`) assertions were updated to include `401`.
  Unit test count 367 → 378.

- **CWE-122 — Heap-Based Buffer Overflow** (post-backlog; the heap-specific
  refinement of CWE-120, built on the single-function alias-tracking machinery
  shared by CWE-416 / CWE-415 / CWE-476).
  `src/blight/detectors/cwe122.py` flags the statically-detectable heap
  overflow: a heap buffer obtained from an allocator (`malloc` / `calloc` /
  `realloc` / `reallocarray` / `strdup` / `strndup` / `aligned_alloc` / `valloc`
  / `pvalloc` / `memalign`) that is then handed — in the **destination**
  (first-argument) register — to an **unbounded** copy (`strcpy` / `stpcpy` /
  `strcat` / `sprintf` / `vsprintf` / `gets`) in the same function with no
  intervening size-aware reassignment. The allocation fixes the destination
  size; an unbounded copy writes the full source length, so a fixed-size heap
  buffer used as a length-unaware copy destination can overflow on the heap.
  Chosen over CWE-457 (uninitialized variable use): a precise CWE-457 detector
  needs def-use dataflow over stack slots across basic blocks (which path
  initialised which slot before which read) — that is the CFG/value-flow
  modeling POST_V01 repeatedly records as out of scope — whereas heap overflow
  reduces to the *same* in-function forward-scan-with-register-alias-tracking
  shape already proven by CWE-416/CWE-415, so it lands as a small,
  infrastructure-free PR. The detector seeds the alias set with the allocator
  **return** register (`rax` on x86_64, `x0` on AArch64) and scans forward: a
  register-to-register move propagates the heap alias (`mov rbx, rax` then
  `strcpy(rbx, …)` is still caught); storing the pointer away or overwriting a
  live alias with a different/bare value kills it; an unbounded copy reached
  while the **destination** (first-argument) register still aliases the heap
  buffer is flagged. Deliberately distinct from CWE-120, which flags the
  dangerous copy *unconditionally* (its presence is the finding) — CWE-122
  requires the destination to be a provable same-function heap allocation, the
  precise heap-overflow signal, so a call site can legitimately carry both.
  **Bounded** copies (`strncpy`/`snprintf`/`memcpy` with an explicit length) are
  intentionally NOT sinks here: vetting the length needs value-range analysis
  that is out of scope, and they remain CWE-120's broader territory. `realloc` /
  `reallocarray` are included as allocators because their *return* value is the
  live (possibly moved) heap buffer, which is exactly what is seeded — unlike in
  CWE-416/CWE-415 where `realloc` is excluded because there it is the *argument*
  that is the dangling/old pointer. Architecture-aware on x86_64 and AArch64
  (POST_V01 item 5), resolved through the shared `_argregs.arg_register_aliases`
  table. Because reachability of the copy along the allocated path is not proven
  statically, every CWE-122 finding is `low` confidence, matching CWE-415 /
  CWE-416 / CWE-476 policy. Registered as check `122`, so the `--checks {…,122,
  all}` token and the `all` set wire in automatically through the `DETECTORS`
  dispatch dict; SARIF maps CWE-122 to level `error`. 8 new unit tests
  (`tests/test_detectors.py::TestCwe122`) covering the direct
  malloc→strcpy overflow, the alias-propagated calloc→sprintf overflow, the
  bounded-copy safe case, the destination-reassigned safe case, the
  never-copied safe case, the no-allocator-import / clean-baseline negatives,
  and the AArch64 vuln + bounded-safe pair; the `--checks all` (`test_cli`) and
  SARIF level-mapping (`test_sarif`) assertions were updated to include `122`.
  Unit test count 357 → 367 (8 detector tests + the added `122` rows in the
  `test_resolve_all` list and the SARIF level-mapping parametrization).

- **CWE-415 — Double Free** (post-backlog; the narrower sibling of CWE-416,
  sharing its single-function alias-tracking machinery).
  `src/blight/detectors/cwe415.py` flags the statically-detectable double-free:
  a pointer passed to `free`/`cfree` (the dangling-pointer source, carried in
  the first-argument register — `rdi` on x86_64, `x0` on AArch64) that is then
  passed to `free` **a second time without being reassigned** in between.
  Releasing the same storage twice corrupts the allocator's free-list and is a
  classic heap-exploitation primitive. Chosen over CWE-190 (integer overflow):
  POST_V01 records — repeatedly — that CWE-190 requires symbolic execution /
  value-range analysis that is out of scope for blight's static
  PLT-and-disassembly approach, whereas double-free is the *same* in-function
  forward-scan-with-register-alias-tracking shape already proven by the shipped
  CWE-416 detector, so it lands as a small, infrastructure-free PR. The detector
  seeds the alias set with the first-argument register at the `free` call site
  and scans forward in the same function: a reassignment of a live alias
  (`mov rdi, 0` / `xor rdi, rdi` / `mov x0, 0`, a `lea` of a fresh address, or a
  reload from an unrelated source) kills the dangling alias — the canonical
  `ptr = NULL;` after `free(ptr)` — and suppresses the finding; a
  register-to-register move propagates the alias so a `free` of the copy is
  still caught; a *second* `free`/`cfree` reached while the first-argument
  register still holds a live alias is flagged. Deliberately distinct from
  CWE-416: a generic *non-deallocator* use of the freed pointer is NOT flagged
  here (that is CWE-416's signal), keeping the two detectors crisply separated.
  `realloc` is excluded for the same reason as in CWE-416. Architecture-aware on
  x86_64 and AArch64 (POST_V01 item 5), resolved through the shared
  `_argregs.arg_register_aliases` table. Because the reachability of the second
  free along the freed path is not proven statically, every CWE-415 finding is
  `low` confidence, matching CWE-416 / CWE-476 / CWE-252 policy. Registered as
  check `415`, so the `--checks {…,415,all}` token and the `all` set wire in
  automatically through the `DETECTORS` dispatch dict; SARIF maps CWE-415 to
  level `error`. 10 new unit tests (`tests/test_detectors.py::TestCwe415`)
  covering the direct double-free, the alias-propagated double-free, the
  `ptr=NULL`/`xor`-between safe cases, the single-free and non-deallocator-use
  safe cases, the no-`free`-import / clean-baseline negatives, and the AArch64
  vuln + safe pair; the `--checks all` (`test_cli`) and SARIF level-mapping
  (`test_sarif`) assertions were updated to include `415`. Unit test count
  345 → 357.

- **CWE-416 — Use After Free** (post-backlog; the third single-function
  taint-propagation detector, after CWE-476 and CWE-252).
  `src/blight/detectors/cwe416.py` flags the most common statically-detectable
  use-after-free: a pointer passed to `free`/`cfree` (the dangling-pointer
  source, carried in the first-argument register — `rdi` on x86_64, `x0` on
  AArch64) that is then **reused before being reassigned**. The detector seeds
  the alias set with the first-argument register at the `free` call site and
  scans forward in the same function: a reassignment of a live alias
  (`mov rdi, 0` / `xor rdi, rdi` / `mov x0, 0`, a `lea` of a fresh address, or a
  reload from an unrelated source) kills the dangling alias — the canonical
  `ptr = NULL;` after `free(ptr)` — and suppresses the finding; a dereference
  (`[reg …]` memory operand naming a live alias) or the freed pointer passed
  onward to a following `call`/`bl` is flagged; a register-to-register move
  propagates the alias so a deref via the copy is still caught. This reuses the
  existing register-alias machinery (mirroring CWE-476): no CFG reconstruction,
  no inter-procedural analysis, no heap-state modeling. `realloc` is
  deliberately **not** tracked — its old pointer is only dangling on the failure
  path and the live pointer is its *return* value, which this argument-tracking
  pass cannot disambiguate without false positives. Architecture-aware on
  x86_64 and AArch64 (POST_V01 item 5), resolved through the shared
  `_argregs.arg_register_aliases` table. Because the reachability of the use
  along the freed path is not proven statically, every CWE-416 finding is `low`
  confidence, matching CWE-476 / CWE-252 policy. Registered as check `416`, so
  the `--checks {…,416,all}` token and the `all` set wire in automatically
  through the `DETECTORS` dispatch dict; SARIF maps CWE-416 to level `error`.
  10 new unit tests (`tests/test_detectors.py::TestCwe416`) covering deref,
  alias-propagated deref, pass-to-call, the `ptr=NULL`/`xor`/`lea`-reload safe
  cases, the never-reused safe case, the no-`free`-import / clean-baseline
  negatives, and the AArch64 vuln + safe pair. Unit test count 335 → 345.

- **CWE-798 — Use of Hard-coded Credentials** (post-backlog; the first
  *data-driven* detector — it scans string literals, not the call graph).
  `src/blight/detectors/cwe798.py` flags hard-coded secrets embedded in the
  binary by scanning the extracted string table (a new `R2Session.strings()`
  primitive backed by radare2's `izzj`, which lists every printable string in
  the file's sections, added to `r2.py` and the fake session). This is the
  first blight detector that does **not** key off the PLT / xref graph: a baked
  secret leaves no call-site fingerprint, it is *data*, so the right primitive
  is a string scan. Three independent signals fire: (1) embedded private-key /
  cert material (a PEM `-----BEGIN … PRIVATE KEY-----` header, an OpenSSH
  private-key banner, or a PuTTY key header — HIGH, the blob itself is the
  secret); (2) credential-bearing connection URIs (`scheme://user:password@host`
  with a concrete, non-placeholder password — HIGH); and (3) assignment-style
  secrets (`key=value` / `key: value` / `export KEY=value` where the key names a
  secret — `password`/`passwd`/`secret`/`api_key`/`token`/`private_key`/… — and
  the value is concrete), where password-class keys are HIGH and token/key-class
  keys are HIGH when the value is long/secret-shaped and MEDIUM otherwise. False
  positives are controlled by rejecting format templates and placeholders
  (`%s`, `{0}`, `${VAR}`, `$VAR`, empty values, and sentinels like `changeme` /
  `example` / `your_password_here`) and by only matching secret-class key names
  (so `username=admin` does not fire). Crucially the detector **never echoes the
  secret value** — evidence strings carry only a redacted preview (first char +
  length), so the report itself cannot leak the credential (asserted in the
  tests). Architecture-agnostic (strings are the same on every target radare2
  can parse). Registered as check `798`, so the `--checks {…,798,all}` token and
  the `all` set wire in automatically through the `DETECTORS` dispatch dict;
  SARIF maps CWE-798 to level `error`. A new committed fixture `creds-vuln`
  (`tests/fixtures/creds-vuln.c` + blob, wired into the `Makefile` and
  `REGENERATE.md`) embeds a hard-coded password, an api_key, and a credential
  URI in `.rodata` for the integration test. Chosen as the next improvement
  because the entire ranked backlog (items 1-8) plus every CLI/output-layer item
  and the CWE-22/78/89/119/120/134/242/252/295/327/426/476/676 detector families
  had already shipped — hard-coded credentials are a perennial MITRE Top-25
  weakness and are endemic in the firmware / embedded ELF binaries blight
  targets, and the *string-scanning* detection mechanism it introduces is a
  genuinely new capability blight lacked (every prior detector was PLT/xref or
  disassembly based), opening the door to a whole class of data-driven checks.
  The remaining high-yield classes (CWE-190 integer overflow, CWE-416
  use-after-free) still require symbolic execution / heap modeling that is out
  of scope for blight's static approach. 13 new unit tests
  (`tests/test_detectors.py::TestCwe798`) plus 2 integration tests
  (`test_cwe798_on_creds_vuln`, `test_strings_surfaces_rodata_literals`); the
  `--checks all`, scan-fixture, and SARIF-mapping assertions were updated to
  include `798`. Test count 306 → 318 (unit) + 2 integration.

- **CWE-22 — Improper Limitation of a Pathname to a Restricted Directory
  ("Path Traversal")** (post-backlog; new static-analysis detector).
  `src/blight/detectors/cwe22.py` flags call sites to filesystem routines that
  consume a *pathname* — the sinks where a path-traversal vulnerability lands
  when the path is built from untrusted input and is not first canonicalised
  (`realpath`) and confined to an intended base directory. Two severity tiers:
  HIGH for routines that destroy / replace / escalate via a pathname
  (`unlink`/`unlinkat`/`remove`/`rmdir` delete, `rename` move-or-overwrite,
  `symlink`/`link` the classic `../`-plus-symlink escape, `chmod`/`chown`/
  `lchown`, `mkdir`, and the exec-by-path family `execv`/`execve`/`execvp`), and
  MEDIUM for routines that open or read metadata for a pathname (`open`/`open64`/
  `openat`/`fopen`/`fopen64`/`freopen`/`creat`, `opendir`, `access`/`stat`/
  `lstat` — also a TOCTOU hint — and `readlink`), which appear routinely in
  fully-validated code and are therefore a triage signal rather than a confirmed
  bug. The canonicalisation primitive `realpath` is deliberately **not** flagged
  — it is part of the recommended mitigation, and flagging it would invert the
  signal. Like CWE-89, CWE-119, CWE-327, CWE-295 and CWE-676 it is a *pure
  PLT-lookup* detector built on the existing `_common.call_sites` helper: it
  deliberately does **not** read the path argument out of the disassembly to
  prove it is non-constant or attacker-derived (the pathname arrives in different
  argument positions across these routines — `open`'s is the first argument,
  `openat`'s is the second, `rename` takes two paths — and is frequently built
  across basic blocks via `snprintf`/`strcat`/`realpath`, so per-routine,
  per-architecture data flow would buy marginal precision), so the call to a
  path-consuming routine is itself the finding, surfaced at the per-symbol
  confidence (HIGH→`high`, MEDIUM→`medium`) in the evidence string for triage.
  Zero new infrastructure, architecture-agnostic (works on every arch radare2
  can disassemble). Registered as check `22`, so the `--checks {22,…,all}` token
  and the `all` set wire in automatically through the `DETECTORS` dispatch dict;
  SARIF maps CWE-22 to level `error`. Chosen as the next improvement because the
  entire ranked backlog (items 1-8) plus every CLI/output-layer item and the
  CWE-78/89/119/120/295/327 families had already shipped, and of the two named
  remaining candidates (CWE-22 path traversal, CWE-362 TOCTOU) path traversal is
  the better fit for blight's PLT-level approach: its sinks are well-defined
  single-symbol call sites, whereas a precise TOCTOU detector needs the *pair*
  (check-then-use) and call-sequence/argument-aliasing data flow that is fragile
  at the PLT level (the highest-value TOCTOU primitives `tmpnam`/`mktemp` are
  already covered by CWE-676). The remaining high-yield classes (CWE-190 integer
  overflow, CWE-416 use-after-free) still require symbolic execution / heap
  modeling that is out of scope for blight's static PLT-and-disassembly approach.
  12 new unit tests (`tests/test_detectors.py::TestCwe22`); the `--checks all`,
  scan-fixture, and SARIF-mapping assertions were updated to include `22`. Test
  count 284 → 296.

- **CWE-119 — Improper Restriction of Operations within the Bounds of a Memory
  Buffer** (post-backlog; new static-analysis detector). `src/blight/detectors/cwe119.py`
  flags call sites to the memory-copy / concatenation primitives whose safe use
  depends entirely on the caller having computed a correct size bound — the
  broader memory-bounds class that complements CWE-120's unchecked-copy set
  (`strcpy`/`sprintf`/`gets`). Covered: the explicit-length copies
  `memcpy`/`memmove`/`bcopy` (HIGH — a wrong/attacker-influenced length is the
  canonical out-of-bounds write), the unbounded copies `stpcpy`/`wcscpy` and
  unbounded concatenations `strcat`/`wcscat` (HIGH — no size argument at all;
  CWE-120 deliberately omits `strcat`, which belongs to this class), and the
  count-bounded-but-routinely-misused routines `strncat`/`wcsncat` (MEDIUM — the
  count is source-relative, NOT destination-space-remaining, plus the implicit
  NUL terminator) and `alloca` (MEDIUM — a caller-sized stack allocation is a
  stack-clash primitive). The *safe* bounded forms (`strlcpy`, `strlcat`,
  `snprintf`, `memset`) are deliberately **not** flagged — they are the
  recommended pattern and flagging them would invert the signal. Like CWE-89,
  CWE-327, CWE-295 and CWE-676 it is a *pure PLT-lookup* detector built on the
  existing `_common.call_sites` helper: it deliberately does **not** read the
  length argument out of the disassembly to prove it is non-constant (the size
  arrives in different registers across the functions and is frequently computed
  across basic blocks, so per-function/per-architecture data flow would buy
  marginal precision), so the call to a memory-bounds-sensitive routine is itself
  the finding, surfaced at the per-symbol confidence (HIGH→`high`,
  MEDIUM→`medium`) in the evidence string for triage. Zero new infrastructure,
  architecture-agnostic (works on every arch radare2 can disassemble). Registered
  as check `119`, so the `--checks {…,119,…,all}` token and the `all` set wire in
  automatically through the `DETECTORS` dispatch dict; SARIF maps CWE-119 to level
  `error`. Chosen as the next improvement because the entire ranked backlog
  (items 1-8) plus every CLI/output-layer item and the CWE-78/89/327/295 families
  had already shipped — the memory-corruption class (overflows via raw/bounded
  copies) is the highest-value remaining gap and the most tractable for blight's
  PLT-level approach (path-traversal/TOCTOU candidates need fragile argument or
  call-sequence data flow), making it the natural extension of the existing
  CWE-120 unchecked-copy detector. 10 new unit tests
  (`tests/test_detectors.py::TestCwe119`); the `--checks all` and scan-fixture
  assertions were updated to include `119`. Test count 274 → 284.

- **CWE-89 — SQL Injection** (post-backlog; new static-analysis heuristic).
  `src/blight/detectors/cwe89.py` flags call sites to database-client routines
  that execute a SQL statement supplied as a string — the *sink* of every
  SQL-injection vulnerability. Covered: SQLite (`sqlite3_exec` and the
  printf-formatting helpers `sqlite3_mprintf`/`sqlite3_vmprintf` — HIGH; the
  prepare gateways `sqlite3_prepare`/`_v2`/`_v3` — MEDIUM, they *can* be used
  safely with bound parameters), MySQL/MariaDB (`mysql_query`/`mysql_real_query`
  — HIGH), PostgreSQL/libpq (`PQexec` — HIGH), and ODBC
  (`SQLExecDirect`/`SQLExecDirectW` — HIGH; `SQLPrepare` — MEDIUM). The *safe*
  parameterised APIs (`sqlite3_bind_*`, `sqlite3_step`, `mysql_stmt_bind_param`,
  `PQexecParams`/`PQprepare`/`PQexecPrepared`, `SQLBindParameter`) are
  deliberately **not** flagged — flagging them would invert the signal. Like
  CWE-78, CWE-327, CWE-295 and CWE-676 it is a *pure PLT-lookup* detector built
  on the existing `_common.call_sites` helper: it deliberately does **not** read
  the query argument out of the disassembly to prove it is non-constant (unlike
  the single-`rdi` OS-command case, the query string arrives in different
  argument positions across the many DB libraries and is frequently built across
  basic blocks, so per-library/per-architecture data flow would buy marginal
  precision), so the call to a raw-SQL-execution routine is itself the finding,
  surfaced at the per-symbol confidence (HIGH→`high`, MEDIUM→`medium`) for
  triage. Zero new infrastructure, architecture-agnostic (works on every arch
  radare2 can disassemble). Registered as check `89`, so the
  `--checks {…,89,…,all}` token and the `all` set wire in automatically through
  the `DETECTORS` dispatch dict; SARIF maps CWE-89 to level `error`. Chosen as
  the next improvement because the entire ranked backlog (items 1-8) plus every
  CLI/output-layer item had shipped and the previous gap-fills built out the
  injection/crypto/TLS families (CWE-78 command injection, CWE-327 broken crypto,
  CWE-295 improper cert validation) — SQL injection is the natural companion to
  CWE-78 (both are "untrusted data reaches an interpreter" sinks), is a perennial
  MITRE Top-25 weakness, and is the highest-value PLT-only class still missing,
  while the remaining high-yield classes (CWE-190 integer overflow, CWE-416
  use-after-free) still require symbolic execution / heap modeling that is out of
  scope for blight's static PLT-and-disassembly approach. See the `TestCwe89`
  block in `tests/test_detectors.py` and the CWE-89 fixtures in
  `tests/fake_session.py`.

- **CWE-295 — Improper Certificate Validation** (post-backlog; new
  static-analysis heuristic). `src/blight/detectors/cwe295.py` flags call sites
  to library routines whose *presence* marks where TLS/SSL certificate or
  hostname verification is configured by hand — exactly the spot where
  verification is most often disabled or weakened. Covered: OpenSSL verify-mode
  toggles (`SSL_CTX_set_verify`/`SSL_set_verify` — HIGH, the mode is frequently
  `SSL_VERIFY_NONE`), the wholesale chain-check replacement
  `SSL_CTX_set_cert_verify_callback` (HIGH), the "I have *a* cert therefore
  trusted" bug `SSL_get_peer_certificate` (MEDIUM — must be paired with
  `SSL_get_verify_result`); GnuTLS `gnutls_certificate_set_verify_function`
  (HIGH) and the no-hostname-check `gnutls_certificate_verify_peers2` (HIGH);
  the libcurl `CURLOPT_SSL_VERIFYPEER`/`CURLOPT_SSL_VERIFYHOST` sink
  `curl_easy_setopt` (MEDIUM); and mbedTLS `mbedtls_ssl_conf_authmode` (HIGH).
  The *correct* APIs (`SSL_get_verify_result`, `X509_check_host`,
  `gnutls_certificate_verify_peers3`, `gnutls_session_set_verify_cert`) are not
  flagged. Like CWE-327 and CWE-676 it is a *pure PLT-lookup* detector built on
  the existing `_common.call_sites` helper — it deliberately does **not** read
  the verify-mode argument out of the disassembly (the constant is frequently
  loaded indirectly and reading it would require per-architecture data flow), so
  the call to a verification-policy routine is itself the finding, surfaced at
  the per-symbol confidence (HIGH→`high`, MEDIUM→`medium`) for triage. Zero new
  infrastructure, architecture-agnostic (works on every arch radare2 can
  disassemble). Registered as check `295`, so the `--checks {…,295,…,all}` token
  and the `all` set wire in automatically through the `DETECTORS` dispatch dict;
  SARIF maps CWE-295 to level `error`. Chosen as the next improvement because the
  entire ranked backlog (items 1-8) plus every CLI/output-layer item had
  shipped, and the previous gap-fill (CWE-327, R15) established broken-crypto
  detection — improper certificate validation is the natural companion gap and
  the highest-value PLT-only TLS class still missing (CWE-295 is a perennial
  top-cited weakness in shipped binaries, especially the embedded/firmware
  targets blight serves), while the remaining high-yield classes (CWE-190
  integer overflow, CWE-416 use-after-free) still require symbolic execution /
  heap modeling that is out of scope for blight's static PLT-and-disassembly
  approach. See the `TestCwe295` block in `tests/test_detectors.py` and the
  CWE-295 fixtures in `tests/fake_session.py`.

- **CWE-327 — Use of a Broken or Risky Cryptographic Algorithm** (post-backlog;
  new static-analysis heuristic). `src/blight/detectors/cwe327.py` flags call
  sites to library routines that implement cryptographic primitives now
  considered broken or risky: collision-broken hashes (`MD5`/`MD4`/`MD2` and
  their incremental `_Init`/`_Update`/`_Final` forms, `SHA`/`SHA1` likewise —
  all HIGH), legacy/broken ciphers (single-DES `DES_ecb_encrypt`/
  `DES_ncbc_encrypt`/`DES_cbc_encrypt`/`DES_set_key`/`DES_crypt` and `RC4`/
  `RC4_set_key` — HIGH; Blowfish `BF_ecb_encrypt`/`BF_cbc_encrypt`/`BF_set_key`
  — MEDIUM), and predictable randomness used for crypto (`srand`/`random`/
  `srandom` — MEDIUM). Like CWE-676 it is a *pure PLT-lookup* detector built on
  the existing `_common.call_sites` helper — the symbol is the finding, no
  data-flow context is needed — so it required zero new infrastructure and is
  architecture-agnostic (works on every arch radare2 can disassemble). The
  per-symbol severity is surfaced in the evidence string and mapped to the
  triage confidence label (HIGH→`high`, MEDIUM→`medium`), mirroring the CWE-676
  policy; SARIF maps CWE-327 to level `error`. Registered as check `327`, so the
  `--checks {…,327,…,all}` token and the `all` set wire in automatically through
  the `DETECTORS` dispatch dict. Chosen as the next improvement because the
  entire ranked backlog (items 1-8) plus every post-backlog CLI/output-layer
  item (`--min-confidence`, `--fail-on`, `--format text`, `--output-file`) had
  shipped, leaving "add a new statically-detectable CWE class" as the natural
  next gap — and broken-cryptography detection is the highest-value PLT-only
  class still missing (CWE-327 is a perennial top-cited weakness in shipped
  binaries, especially the embedded/firmware targets blight serves), while the
  remaining high-yield classes (CWE-190 integer overflow, CWE-416
  use-after-free) still require symbolic execution / heap modeling that is out
  of scope for blight's static PLT-and-disassembly approach. See the
  `TestCwe327` block in `tests/test_detectors.py` and the CWE-327 fixtures in
  `tests/fake_session.py`.

- **`--output-file` / `-o` Report Destination** (post-backlog; CLI ergonomics
  gap fill). Adds an `--output-file FILE` (short `-o FILE`) flag that writes the
  rendered report to a file instead of stdout; when set, nothing is printed to
  stdout. The change refactored the CLI emit path so each scan is *rendered* to
  a report string (`_render_single` / `_render_directory`) and then *written* by
  a single `_write_report` helper, so the new destination logic lives in exactly
  one place and is format-agnostic — it works for `--format json`, `--format
  sarif`, and `--format text` identically, with the same single trailing newline
  as the historical stdout output (verified byte-for-byte in
  `tests/test_cli.py`). `-o -` forces stdout explicitly (the default when the
  flag is omitted), preserving full backward compatibility. The `--fail-on` gate
  is evaluated over the same emitted findings regardless of destination, so the
  CI exit code is unchanged whether the report goes to a file or stdout. An
  unwritable path (e.g. a missing parent directory) is surfaced as an `argparse`
  usage error that aborts before any partial output. Chosen as the next
  improvement because all eight ranked backlog items plus the `--min-confidence`
  filter, the `--fail-on` gate, and `--format text` had shipped, and routing the
  report to a file is the natural companion to the CI-gate story (a pipeline
  that fails the build on findings typically also wants to archive the report as
  an artifact) while remaining a pure output-layer change with no new detector
  heuristics or blocked external tooling. The remaining high-yield CWE classes
  (CWE-190 integer overflow, CWE-416 use-after-free) still require symbolic
  execution / heap modeling that is out of scope for blight's static
  PLT-and-disassembly approach. See the `--output-file` tests in
  `tests/test_cli.py`.

- **`--format text` Human-Readable Console Output** (post-backlog;
  CLI/output-layer direction). `src/blight/formatters/text.py` adds a third
  `--format` choice alongside `json` and `sarif` that renders the findings as a
  compact, grouped-by-function console report: a `binary`/`checks` header, a
  finding count with a `high/medium/low` confidence breakdown, one block per
  function (each finding line showing `[confidence] CWE-N symbol @ address`
  plus the evidence string), and a closing per-CWE `summary` line ordered by
  count. A clean binary prints `no findings`; a directory scan prints one
  indented block per binary under a `directory:` header (errored binaries show
  their `error` string), closed by a corpus `total:` line. Like the existing
  output-layer filters it is purely additive — no detector, `Finding` model, or
  architecture change — and it consumes exactly the findings that survive
  `--suppress` and `--min-confidence`, with `--fail-on` evaluating the same
  set, so the exit code always matches the rendered report. The format is
  explicitly documented as a *report for humans* with no stability contract
  (layout may change between releases); JSON and SARIF remain the machine
  contracts. Chosen as the next improvement because all eight ranked backlog
  items plus the three post-backlog CLI gates had shipped, leaving the
  interactive-console case (where reading JSON through `jq` is friction) as the
  natural next CLI/output-layer win, while the remaining high-yield CWE classes
  (CWE-190 integer overflow, CWE-416 use-after-free) still require symbolic
  execution / heap modeling that is out of scope for blight's static approach.
  See `tests/test_text.py`.

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
