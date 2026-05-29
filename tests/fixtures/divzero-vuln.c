/* divzero-vuln.c — a deliberately-vulnerable CWE-369 (Divide By Zero) fixture.
 *
 * `compute_ratio` divides a fixed numerator by a caller-supplied divisor with
 * NO zero-check. When the divisor is 0 the `idiv` traps (SIGFPE). The divisor
 * is derived from argc so the compiler cannot fold the division to a constant,
 * and `-O0` keeps the raw `idiv <reg|mem>` in the emitted code.
 *
 * `safe_ratio` performs the same division but guards the divisor with an
 * explicit `if (d == 0)` first, so blight's CWE-369 detector must NOT flag it.
 *
 * Built with the fixtures Makefile (-O0 -g -no-pie). The compiled blob is
 * committed to git so the suite runs without a C toolchain. See REGENERATE.md.
 */

#include <stdio.h>
#include <stdlib.h>

/* VULNERABLE: divisor `d` is used directly in a division with no zero-check. */
int compute_ratio(int total, int d) {
    return total / d;            /* idiv with a register/stack divisor, unchecked */
}

/* SAFE: divisor is zero-checked before the division. */
int safe_ratio(int total, int d) {
    if (d == 0) {
        return 0;
    }
    return total / d;            /* guarded — must not be flagged */
}

int main(int argc, char **argv) {
    int d = argc - 1;            /* attacker-influenced, not a constant */
    printf("%d\n", compute_ratio(100, d));
    printf("%d\n", safe_ratio(100, d));
    return 0;
}
