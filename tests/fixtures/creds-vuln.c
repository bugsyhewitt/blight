/* creds-vuln.c — a deliberately-vulnerable fixture for CWE-798.
 *
 * Embeds hard-coded credentials as string literals so blight's CWE-798
 * detector (which scans the binary's extracted strings) has a real ELF to
 * find them in. The strings land in .rodata; radare2's izzj surfaces them.
 *
 * The compiled blob is committed to git (see REGENERATE.md) so the test suite
 * runs without a C toolchain.
 */
#include <stdio.h>

/* Assignment-style secret (HIGH): a literal admin password. */
static const char *ADMIN_PASSWORD = "password=Sup3rSecretAdminPW";

/* Token-class secret with a long, secret-shaped value (HIGH). */
static const char *API_KEY = "api_key=AKIAIOSFODNN7EXAMPLEKEY";

/* Credential-bearing connection URI (HIGH): inline user:password@host. */
static const char *DB_URI = "mysql://root:hunter2dbpass@db.internal:3306/app";

/* A benign format template that must NOT be flagged. */
static const char *USAGE = "usage: %s [--password=PW]";

int main(int argc, char **argv) {
    (void)argc;
    printf("%s\n", ADMIN_PASSWORD);
    printf("%s\n", API_KEY);
    printf("%s\n", DB_URI);
    printf(USAGE, argv[0]);
    return 0;
}
