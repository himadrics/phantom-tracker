/*
 * find_do_wait.c — standalone test driver for find_do_wait.h.
 *
 * Scans the given libgomp (or auto-detects via ldconfig) for every inlined
 * do_wait body using the disassembly heuristic in find_do_wait.h, and
 * prints all found offsets.  Exits 0 if at least one offset is found.
 *
 * Build:
 *   gcc -O2 -o find_do_wait find_do_wait.c && ./find_do_wait [libgomp-path]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "find_do_wait.h"

#define MAX_DO_WAIT 64   /* upper bound on how many copies libgomp can have */

/* -----------------------------------------------------------------------
 * find_libgomp — locate the x86-64 libgomp via ldconfig
 * ----------------------------------------------------------------------- */
static int find_libgomp(char *buf, size_t bufsz)
{
    FILE *f = popen(
        "ldconfig -p | grep 'libgomp\\.so' | grep 'x86-64'"
        " | awk '{print $NF}' | head -1", "r");
    if (!f) { perror("popen ldconfig"); return -1; }

    if (!fgets(buf, bufsz, f)) {
        fprintf(stderr, "error: libgomp (x86-64) not found via ldconfig\n");
        pclose(f);
        return -1;
    }
    pclose(f);
    buf[strcspn(buf, "\n")] = '\0';

    if (buf[0] == '\0') {
        fprintf(stderr, "error: ldconfig returned empty path\n");
        return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    char libgomp_path[512] = {0};

    if (argc >= 2) {
        strncpy(libgomp_path, argv[1], sizeof(libgomp_path) - 1);
    } else {
        if (find_libgomp(libgomp_path, sizeof(libgomp_path)) < 0)
            return 1;
    }

    printf("Target library : %s\n\n", libgomp_path);

    uint64_t offsets[MAX_DO_WAIT];
    int n = find_do_wait_offsets(libgomp_path, offsets, MAX_DO_WAIT);

    if (n < 0) {
        fprintf(stderr, "error: find_do_wait_offsets failed\n");
        return 1;
    }

    if (n == 0) {
        fprintf(stderr, "No do_wait bodies found in %s\n", libgomp_path);
        return 1;
    }

    printf("\nFound %d do_wait body/bodies:\n", n);
    for (int i = 0; i < n; i++)
        printf("  [%d] offset = 0x%lx\n", i, offsets[i]);

    printf("\nAll %d offset(s) will be used as uprobe attach points.\n", n);
    return 0;
}
