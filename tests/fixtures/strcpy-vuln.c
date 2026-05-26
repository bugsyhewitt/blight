/*
 * strcpy-vuln.c — CWE-120 fixture (Buffer Copy without Checking Size).
 *
 * Calls strcpy(), sprintf(), and gets() — classic unchecked-copy primitives.
 * Compiled with no stack protector / no fortify so the dangerous calls are
 * emitted verbatim into the PLT and detectable via radare2 import xrefs.
 *
 * Build: see Makefile / REGENERATE.md.
 */
#include <stdio.h>
#include <string.h>

/* gets() was removed from C11 headers; declare it so the fixture still
 * exercises the dangerous symbol. The symbol resolves against glibc. */
extern char *gets(char *);

void copy_it(const char *src) {
    char buf[16];
    strcpy(buf, src);        /* CWE-120: no size check */
    printf("%s\n", buf);
}

void format_it(const char *src) {
    char buf[16];
    sprintf(buf, "value=%s", src);  /* CWE-120: sprintf into fixed buffer */
    printf("%s\n", buf);
}

int main(int argc, char **argv) {
    char line[16];
    if (argc > 1) {
        copy_it(argv[1]);
        format_it(argv[1]);
    } else {
        gets(line);          /* also CWE-120 / CWE-242 */
        copy_it(line);
    }
    return 0;
}
