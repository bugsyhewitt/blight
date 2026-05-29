# Makefile for blight test fixtures.
#
# Builds the deliberately-vulnerable ELF binaries used by the test suite and
# the integration test. The COMPILED BLOBS ARE COMMITTED TO GIT so the test
# suite (and the Team Lead) can run without a C toolchain. This Makefile
# exists for regeneration only. See REGENERATE.md.
#
# Flags: we disable the stack protector and FORTIFY so the dangerous libc
# calls (strcpy/sprintf/gets/system) are emitted as plain PLT calls rather
# than being rewritten to *_chk variants — that keeps the fixtures honest
# representations of the CWE patterns we detect.

CC      ?= gcc
CFLAGS  := -O0 -g -no-pie -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -w

BINARIES := strcpy-vuln system-vuln gets-vuln clean-baseline creds-vuln divzero-vuln

.PHONY: all clean

all: $(BINARIES)

strcpy-vuln: strcpy-vuln.c
	$(CC) $(CFLAGS) -o $@ $<

system-vuln: system-vuln.c
	$(CC) $(CFLAGS) -o $@ $<

gets-vuln: gets-vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean-baseline: clean-baseline.c
	$(CC) $(CFLAGS) -o $@ $<

creds-vuln: creds-vuln.c
	$(CC) $(CFLAGS) -o $@ $<

divzero-vuln: divzero-vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BINARIES)
