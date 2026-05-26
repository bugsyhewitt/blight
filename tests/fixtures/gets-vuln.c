/*
 * gets-vuln.c — CWE-242 fixture (Use of Inherently Dangerous Function).
 *
 * Calls gets(), which cannot be used safely under any circumstances.
 * This is the canonical CWE-242 case.
 *
 * Build: see Makefile / REGENERATE.md.
 */
#include <stdio.h>

/* gets() was removed from C11 headers; declare it so the fixture still
 * exercises the dangerous symbol. The symbol resolves against glibc. */
extern char *gets(char *);

int main(void) {
    char line[64];
    printf("name? ");
    gets(line);          /* CWE-242: inherently dangerous, no bounds possible */
    printf("hello %s\n", line);
    return 0;
}
