#ifndef __FIND_DO_WAIT_H__
#define __FIND_DO_WAIT_H__

/*
 * find_do_wait.h — header-only helper: finds every file offset of inlined
 * do_wait bodies inside a libgomp shared library by disassembling it and
 * matching the signature:
 *
 *   pause                           ← cpu_relax() inside do_spin
 *   ... (≤ LOOKAHEAD_FUTEX lines, without crossing function boundary ret)
 *   mov eax,0xca  OR               ← __NR_futex = 202 loaded into eax, OR
 *   mov rNd,0xca                   ← loaded via staging register
 *   ... (≤ LOOKAHEAD_SYSCALL lines)
 *   syscall                         ← actual futex syscall
 *
 * Resolves the function entry address by scanning backward from pause past the
 * preceding ret and padding nops.
 *
 * Usage:
 *   uint64_t offsets[32];
 *   int n = find_do_wait_offsets(libgomp_path, offsets, 32);
 *   for (int i = 0; i < n; i++) { ... attach uprobe at offsets[i] ... }
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define _DW_LOOKAHEAD_FUTEX 100   /* pause → 0xca load */
#define _DW_LOOKAHEAD_SYSCALL 150 /* 0xca load → syscall */
#define _DW_MAX_LINES 600000
#define _DW_LINE_CAP 512

/*
 * _dw_parse_addr — extract the hex address at the start of an objdump line.
 *   "   20930:  f3 0f 1e fa   endbr64"  →  0x20930
 * Returns 0 if the line doesn't begin with a valid hex address.
 */
static uint64_t _dw_parse_addr(const char *line)
{
	const char *p = line;
	while (*p == ' ' || *p == '\t')
		p++;
	if ((*p < '0' || *p > '9') && (*p < 'a' || *p > 'f'))
		return 0;
	char *end;
	uint64_t addr = (uint64_t)strtoull(p, &end, 16);
	if (*end != ':')
		return 0;
	return addr;
}

/*
 * _dw_find_fn_entry — scan backward from pause to find the start of the function body.
 */
static uint64_t _dw_find_fn_entry(char **lines, int pause_idx)
{
	int entry_idx = 0;
	for (int k = pause_idx - 1; k >= 0; k--) {
		if (strstr(lines[k], "\tret") || strstr(lines[k], " ret") ||
		    strstr(lines[k], "\tretq") || strstr(lines[k], " retq")) {
			entry_idx = k + 1;
			break;
		}
	}
	/* Skip alignment nops if any */
	while (entry_idx < pause_idx &&
	       (strstr(lines[entry_idx], "nop") || strstr(lines[entry_idx], "cs nop"))) {
		entry_idx++;
	}

	return _dw_parse_addr(lines[entry_idx]);
}

/*
 * find_do_wait_offsets — scan libgomp for all do_wait body offsets.
 *
 * Parameters:
 *   libgomp   — path to the libgomp shared library.
 *   out       — caller-allocated array to receive the found offsets.
 *   out_max   — capacity of out[].
 *
 * Returns the number of offsets written to out[], or -1 on error.
 */
static int find_do_wait_offsets(const char *libgomp, uint64_t *out, int out_max)
{
	char cmd[700];
	snprintf(cmd, sizeof(cmd), "objdump -d -M intel %s 2>/dev/null", libgomp);

	FILE *fp = popen(cmd, "r");
	if (!fp) {
		perror("popen objdump");
		return -1;
	}

	/* Read all disassembly lines into memory */
	int capacity = _DW_MAX_LINES, nlines = 0;
	char **lines = malloc(capacity * sizeof(char *));
	if (!lines) {
		pclose(fp);
		return -1;
	}

	char buf[_DW_LINE_CAP];
	while (fgets(buf, sizeof(buf), fp)) {
		if (nlines >= capacity) {
			fprintf(stderr,
				"find_do_wait: objdump output truncated at %d lines\n",
				capacity);
			break;
		}
		lines[nlines++] = strdup(buf);
	}
	pclose(fp);

	int found = 0;

	for (int i = 0; i < nlines && found < out_max; i++) {
		/* Step 1: look for pause instruction (cpu_relax inside do_spin) */
		if (!strstr(lines[i], "\tpause") && !strstr(lines[i], " pause"))
			continue;

		/* Step 2: look forward for NR_futex (0xca) load */
		int futex_idx = -1;
		int end_futex = i + _DW_LOOKAHEAD_FUTEX;
		if (end_futex > nlines)
			end_futex = nlines;

		for (int j = i + 1; j < end_futex; j++) {
			/* Stop if we cross a function boundary (ret) */
			if (strstr(lines[j], "\tret") || strstr(lines[j], " ret") ||
			    strstr(lines[j], "\tretq") || strstr(lines[j], " retq"))
				break;

			if (!strstr(lines[j], "0xca"))
				continue;

			if (strstr(lines[j], "mov    eax,0xca")) {
				futex_idx = j;
				break;
			}

			char *p = lines[j];
			while ((p = strstr(p, "mov    r")) != NULL) {
				char after_r = p[8];
				if (after_r >= '0' && after_r <= '9') {
					if (strstr(p, ",0xca")) {
						futex_idx = j;
						break;
					}
				}
				p++;
			}
			if (futex_idx >= 0)
				break;
		}

		if (futex_idx < 0)
			continue;

		/* Step 3: look forward for syscall instruction */
		int sc_end = futex_idx + _DW_LOOKAHEAD_SYSCALL;
		if (sc_end > nlines)
			sc_end = nlines;

		int matched = 0;
		for (int j = futex_idx + 1; j < sc_end; j++) {
			if (strstr(lines[j], "\tret") || strstr(lines[j], " ret") ||
			    strstr(lines[j], "\tretq") || strstr(lines[j], " retq"))
				break;
			if (strstr(lines[j], "\tsyscall") || strstr(lines[j], " syscall")) {
				matched = 1;
				break;
			}
		}

		if (!matched)
			continue;

		/* Step 4: resolve function entry offset */
		uint64_t fn_addr = _dw_find_fn_entry(lines, i);
		if (!fn_addr)
			fn_addr = _dw_parse_addr(lines[i]); /* fallback to pause instruction address */

		/* Deduplicate function offsets */
		int duplicate = 0;
		for (int k = 0; k < found; k++) {
			if (out[k] == fn_addr) {
				duplicate = 1;
				break;
			}
		}

		if (!duplicate && fn_addr != 0) {
			out[found++] = fn_addr;
		}
	}

	for (int i = 0; i < nlines; i++)
		free(lines[i]);
	free(lines);
	return found;
}

#undef _DW_LOOKAHEAD_FUTEX
#undef _DW_LOOKAHEAD_SYSCALL
#undef _DW_MAX_LINES
#undef _DW_LINE_CAP

#endif /* __FIND_DO_WAIT_H__ */
