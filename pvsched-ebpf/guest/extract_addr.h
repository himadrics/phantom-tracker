#ifndef __EXTRACT_ADDR_H__
#define __EXTRACT_ADDR_H__

/*
 * extract_addr.h — header-only helper: finds the file offset of the
 * stripped gomp_thread_start function inside a libgomp shared library
 * by disassembling it and locating the RIP-relative LEA into %rdx that
 * immediately precedes the pthread_create@plt call.
 *
 * Include this header in any translation unit that needs the function;
 * the 'static' qualifier gives each TU its own copy (no ODR issues).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define _EXTRACT_LOOKAHEAD 25
#define _EXTRACT_LINE_CAP  512

/*
 * find_gomp_thread_start_offset
 *
 * pthread_create(tid, attr, start_fn, arg) passes start_fn in %rdx
 * (3rd arg, x86-64 SysV ABI).  libgomp loads it via a RIP-relative
 * LEA immediately before the pthread_create@plt call:
 *
 *   lea    -0x75f(%rip), %rdx     ← &gomp_thread_start → rdx
 *   ...                           ← other setup (≤ LOOKAHEAD lines)
 *   call   pthread_create@plt
 *
 * fn_addr = next_instruction_addr + signed_RIP_offset
 *
 * Returns the offset on success, 0 on failure.
 */
static uint64_t find_gomp_thread_start_offset(const char *libgomp)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "objdump -d %s", libgomp);

    FILE *fp = popen(cmd, "r");
    if (!fp) { perror("popen objdump"); return 0; }

    /* Read all disassembly lines into a dynamic array */
    int capacity = 8192, nlines = 0;
    char **lines = malloc(capacity * sizeof(char *));
    if (!lines) { pclose(fp); return 0; }

    char buf[_EXTRACT_LINE_CAP];
    while (fgets(buf, sizeof(buf), fp)) {
        if (nlines == capacity) {
            capacity *= 2;
            char **tmp = realloc(lines, capacity * sizeof(char *));
            if (!tmp) break;
            lines = tmp;
        }
        lines[nlines++] = strdup(buf);
    }
    pclose(fp);

    uint64_t result = 0;

    for (int i = 0; i < nlines - 1 && !result; i++) {
        char *l = lines[i];

        if (!strstr(l, "lea"))               continue;  /* no lea */
        if (strstr(l, "pthread_create@plt")) continue;  /* skip the call itself */
        if (!strstr(l, "(%rip),%rdx"))       continue;  /* not RIP→rdx */

        /* Parse the signed hex offset: skip past "lea" and whitespace */
        char *p = strstr(l, "lea") + 3;
        while (*p == ' ' || *p == '\t') p++;

        char *endptr;
        long long signed_offset = strtoll(p, &endptr, 16);
        if (endptr == p || *endptr != '(') continue;    /* no valid number */

        /* Next instruction address from lines[i+1] */
        uint64_t next_addr = 0;
        if (sscanf(lines[i + 1], " %lx:", &next_addr) != 1 || !next_addr)
            continue;

        /* Scan ahead for pthread_create@plt within LOOKAHEAD lines.
         * Abort if another lea into %rdx clobbers the register first. */
        int found = 0;
        for (int j = i + 1; j < i + 1 + _EXTRACT_LOOKAHEAD && j < nlines; j++) {
            if (strstr(lines[j], "lea") && strstr(lines[j], "%rdx"))
                break;
            if (strstr(lines[j], "pthread_create@plt")) { found = 1; break; }
        }
        if (!found) continue;

        result = (uint64_t)((int64_t)next_addr + signed_offset);
    }

    for (int i = 0; i < nlines; i++) free(lines[i]);
    free(lines);
    return result;
}

#endif /* __EXTRACT_ADDR_H__ */