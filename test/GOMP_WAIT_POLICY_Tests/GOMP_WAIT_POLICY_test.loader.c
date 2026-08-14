// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Loader for GOMP_WAIT_POLICY_test.bpf.c — skeleton-based approach.
 *
 * Attaches five programs to the OpenMP / kernel stack:
 *   1. gomp_switch_handler  → tp/sched/sched_switch
 *      Attached via bpf_program__attach().
 *
 *   2. gomp_futex_enter     → tp/syscalls/sys_enter_futex
 *      Attached via bpf_program__attach().
 *
 *   3. gomp_do_wait_handler → uprobe on every do_wait body in libgomp.
 *      Discovered via find_do_wait.h disassembly heuristic.
 *
 *   4. guest_read_entry     → kprobe/guest_ivshmem_read
 *      Attached via bpf_program__attach().
 *
 *   5. guest_read_return    → kretprobe/guest_ivshmem_read
 *      Attached via bpf_program__attach().
 *
 * All programs remain attached until SIGINT or SIGTERM (Ctrl+C) is received.
 *
 * Prerequisites:
 *   - omp_thread_reg loader must be running (omp_threads_map pinned at
 *     /sys/fs/bpf/omp_threads_map).
 *   - guest_ivshmem.ko loaded.
 *   - Run as root.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "GOMP_WAIT_POLICY_test.skel.h"
#include "find_do_wait.h"

/* Reuse the omp_threads_map already pinned by omp_thread_reg */
#define PIN_OMP_THREADS_MAP "/sys/fs/bpf/omp_threads_map"

/* Maximum number of do_wait uprobe links we will manage */
#define MAX_DO_WAIT 64

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

/* -----------------------------------------------------------------------
 * find_libgomp — locate the x86-64 libgomp via ldconfig
 * ----------------------------------------------------------------------- */
static int find_libgomp(char *buf, size_t bufsz)
{
	FILE *f = popen("ldconfig -p | grep 'libgomp\\.so' | grep 'x86-64' "
			"| awk '{print $NF}' | head -1",
			"r");
	if (!f) {
		perror("popen ldconfig");
		return -1;
	}

	if (!fgets(buf, bufsz, f)) {
		fprintf(stderr,
			"error: libgomp (x86-64) not found via ldconfig\n");
		pclose(f);
		return -1;
	}
	pclose(f);
	buf[strcspn(buf, "\n")] = '\0';

	if (buf[0] == '\0') {
		fprintf(stderr,
			"error: ldconfig returned empty path for libgomp\n");
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */
int main(void)
{
	struct GOMP_WAIT_POLICY_test_bpf *skel = NULL;
	struct bpf_link *switch_link = NULL;
	struct bpf_link *futex_link = NULL;
	struct bpf_link *kprobe_entry_link = NULL;
	struct bpf_link *kretprobe_ret_link = NULL;

	/* Array of per-instance do_wait links */
	struct bpf_link *do_wait_links[MAX_DO_WAIT] = { 0 };
	int n_do_wait = 0;

	char libgomp_path[512] = { 0 };
	int err = 0;
	uint64_t dw_offsets[MAX_DO_WAIT];

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	/* 1 — find libgomp path */
	if (find_libgomp(libgomp_path, sizeof(libgomp_path)) < 0)
		return 1;
	printf("libgomp : %s\n", libgomp_path);

	/* 2 — find ALL do_wait bodies via disassembly heuristic */
	n_do_wait = find_do_wait_offsets(libgomp_path, dw_offsets, MAX_DO_WAIT);
	if (n_do_wait < 0) {
		fprintf(stderr, "error: find_do_wait_offsets failed\n");
		return 1;
	}
	if (n_do_wait == 0) {
		fprintf(stderr,
			"warning: no do_wait bodies found in %s\n"
			"         tracepoints & kprobes will still be attached.\n",
			libgomp_path);
	} else {
		printf("Found %d do_wait body/bodies:\n", n_do_wait);
		for (int i = 0; i < n_do_wait; i++)
			printf("  [%d] offset = 0x%lx\n", i, dw_offsets[i]);
	}

	/* 3 — open BPF skeleton */
	skel = GOMP_WAIT_POLICY_test_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	/*
	 * 4 — reuse the omp_threads_map pinned by omp_thread_reg BEFORE load()
	 *     so BPF programs query the active pinned map.
	 */
	int pinned_map_fd = bpf_obj_get(PIN_OMP_THREADS_MAP);
	if (pinned_map_fd < 0) {
		fprintf(stderr,
			"error: cannot open pinned omp_threads_map at %s: %s\n"
			"       Is the omp_thread_reg loader running?\n",
			PIN_OMP_THREADS_MAP, strerror(errno));
		err = -1;
		goto cleanup;
	}
	if (bpf_map__reuse_fd(skel->maps.omp_threads_map, pinned_map_fd) < 0) {
		perror("bpf_map__reuse_fd omp_threads_map");
		close(pinned_map_fd);
		err = -1;
		goto cleanup;
	}
	close(pinned_map_fd);
	printf("Reusing pinned omp_threads_map from omp_thread_reg loader\n");

	err = GOMP_WAIT_POLICY_test_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skeleton\n");
		goto cleanup;
	}

	/* 5a — attach sched_switch tracepoint */
	switch_link = bpf_program__attach(skel->progs.gomp_switch_handler);
	err = libbpf_get_error(switch_link);
	if (err) {
		switch_link = NULL;
		fprintf(stderr, "failed to attach tp/sched/sched_switch: %s\n",
			strerror(-err));
		goto cleanup;
	}
	printf("Attached → tp/sched/sched_switch          (gomp_switch_handler)\n");

	/* 5b — attach sys_enter_futex tracepoint */
	futex_link = bpf_program__attach(skel->progs.gomp_futex_enter);
	err = libbpf_get_error(futex_link);
	if (err) {
		futex_link = NULL;
		fprintf(stderr,
			"failed to attach tp/syscalls/sys_enter_futex: %s\n",
			strerror(-err));
		goto cleanup;
	}
	printf("Attached → tp/syscalls/sys_enter_futex    (gomp_futex_enter)\n");

	/* 5c — attach kprobe/guest_ivshmem_read */
	kprobe_entry_link = bpf_program__attach(skel->progs.guest_read_entry);
	err = libbpf_get_error(kprobe_entry_link);
	if (err) {
		kprobe_entry_link = NULL;
		fprintf(stderr,
			"failed to attach kprobe/guest_ivshmem_read: %s\n",
			strerror(-err));
		goto cleanup;
	}
	printf("Attached → kprobe/guest_ivshmem_read      (guest_read_entry)\n");

	/* 5d — attach kretprobe/guest_ivshmem_read */
	kretprobe_ret_link = bpf_program__attach(skel->progs.guest_read_return);
	err = libbpf_get_error(kretprobe_ret_link);
	if (err) {
		kretprobe_ret_link = NULL;
		fprintf(stderr,
			"failed to attach kretprobe/guest_ivshmem_read: %s\n",
			strerror(-err));
		goto cleanup;
	}
	printf("Attached → kretprobe/guest_ivshmem_read   (guest_read_return)\n");

	/* 5e — attach one uprobe per do_wait body found */
	for (int i = 0; i < n_do_wait; i++) {
		do_wait_links[i] = bpf_program__attach_uprobe_opts(
			skel->progs.gomp_do_wait_handler,
			-1, /* all processes */
			libgomp_path, dw_offsets[i], NULL);

		err = libbpf_get_error(do_wait_links[i]);
		if (err) {
			fprintf(stderr,
				"failed to attach uprobe [%d] → %s+0x%lx: %s\n",
				i, libgomp_path, dw_offsets[i], strerror(-err));
			do_wait_links[i] = NULL;
			goto cleanup;
		}

		printf("Attached → %s+0x%lx  [do_wait body %d]\n", libgomp_path,
		       dw_offsets[i], i);
	}

	if (n_do_wait == 0)
		printf("Skipped do_wait uprobe (no bodies found)\n");

	printf("\nAll programs attached. Running... Press Ctrl+C to exit.\n");

	while (!exiting)
		sleep(1);

	printf("\nExiting and detaching programs...\n");

cleanup:
	for (int i = n_do_wait - 1; i >= 0; i--)
		bpf_link__destroy(do_wait_links[i]);
	bpf_link__destroy(kretprobe_ret_link);
	bpf_link__destroy(kprobe_entry_link);
	bpf_link__destroy(futex_link);
	bpf_link__destroy(switch_link);
	GOMP_WAIT_POLICY_test_bpf__destroy(skel);
	return err ? 1 : 0;
}
