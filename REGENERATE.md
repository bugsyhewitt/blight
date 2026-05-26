# Regenerating the test fixtures

The test suite and the integration test run against deliberately-vulnerable
ELF binaries. **These compiled blobs are committed to git** so the suite runs
without a C toolchain. This file documents how to rebuild them from source.

## Fixtures

| Binary | Source | Exercises |
|---|---|---|
| `strcpy-vuln` | `strcpy-vuln.c` | CWE-120 (`strcpy`, `sprintf`, `gets`) |
| `system-vuln` | `system-vuln.c` | CWE-78 (`system` with non-constant arg, `execl`) |
| `gets-vuln` | `gets-vuln.c` | CWE-242 (`gets`) |
| `clean-baseline` | `clean-baseline.c` | nothing (zero-finding baseline) |

All sources live in `tests/fixtures/`.

## Rebuild

Requires `gcc` (or set `CC`).

```bash
cd tests/fixtures
make clean
make all
```

## Build flags and why

The `Makefile` compiles with:

```
-O0 -g -no-pie -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -w
```

- `-fno-stack-protector` and `-D_FORTIFY_SOURCE=0` keep the dangerous libc
  calls (`strcpy`/`sprintf`/`gets`/`system`) emitted verbatim as PLT calls.
  With FORTIFY on, the compiler rewrites some of them to `*_chk` variants,
  which would change the imported symbol names the detectors key on.
- `-no-pie` gives stable, low load addresses so the example addresses in the
  README and tests stay readable.
- `-w` silences the (expected and intentional) "dangerous function" warnings.

## Note on `gets`

`gets()` was removed from C11 headers, so `strcpy-vuln.c` and `gets-vuln.c`
declare `extern char *gets(char *);` themselves. The symbol still resolves
against glibc at link time.

## After regenerating

Re-run the integration tests to confirm the new blobs still match the
detectors (addresses may shift slightly with toolchain changes, but the
symbols and finding counts must hold):

```bash
pip install r2pipe
pytest -m integration
```

If addresses changed, update the example output in `README.md`.
