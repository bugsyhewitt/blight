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

### 3. SARIF Output Format  ★★★★☆
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

### 5. ARM/aarch64 Architecture Support  ★★★☆☆
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

### 6. CWE-476 — NULL Pointer Dereference  ★★★☆☆
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

### 7. CWE-252 — Unchecked Return Value  ★★☆☆☆
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

### 8. `--suppress` File for Known False Positives  ★★☆☆☆
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

5. **Do not pick items 6, 7, or 8 first.** They have higher effort, lower precision,
   or depend on earlier items (4 for confidence labels, CFG for 7).

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
