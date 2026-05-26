/*
 * system-vuln.c — CWE-78 fixture (OS Command Injection).
 *
 * Calls system() and execl() with a non-constant argument derived from
 * untrusted input (argv). The non-constant argument is the signal: a
 * constant string literal passed to system() is far less interesting.
 *
 * Build: see Makefile / REGENERATE.md.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void run_cmd(const char *user) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ls %s", user);  /* user-controlled command */
    system(cmd);                                /* CWE-78: tainted system() */
}

void run_exec(const char *user) {
    execl("/bin/sh", "sh", "-c", user, (char *)NULL);  /* CWE-78: exec* with input */
}

int main(int argc, char **argv) {
    if (argc > 1) {
        run_cmd(argv[1]);
        run_exec(argv[1]);
    }
    return 0;
}
