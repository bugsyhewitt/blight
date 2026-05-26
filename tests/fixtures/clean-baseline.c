/*
 * clean-baseline.c — clean fixture, must produce ZERO findings.
 *
 * Uses only safe primitives: fgets() with a bounded size, snprintf() with
 * an explicit size, and no system()/exec*()/gets()/strcpy()/sprintf().
 *
 * Build: see Makefile / REGENERATE.md.
 */
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[64];
    char out[128];

    printf("name? ");
    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        return 1;
    }
    buf[strcspn(buf, "\n")] = '\0';

    snprintf(out, sizeof(out), "hello %s", buf);  /* bounded */
    printf("%s\n", out);
    return 0;
}
