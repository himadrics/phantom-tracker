// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Loader for omp_thread_reg.bpf.c — skeleton-based approach.
 *
 * Attaches two uprobes to libgomp (x86-64), both system-wide (-1):
 *   1. capture_omp_master_thread → GOMP_parallel   (by exported symbol name)
 *   2. capture_omp_worker_threads → gomp_thread_start (by raw file offset,
 *      discovered at runtime via disassembly since the symbol is stripped)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "omp_thread_reg.skel.h"
#include "extract_addr.h"

#define PIN_WORKER_LINK "/sys/fs/bpf/links/worker"
#define PIN_OMP_THREADS_MAP "/sys/fs/bpf/omp_threads_map"
#define PIN_MASTER_LINK "/sys/fs/bpf/links/master"
#define PIN_SWITCH_LINK "/sys/fs/bpf/links/sched_switch"
#define PIN_EXIT_LINK "/sys/fs/bpf/links/sched_process_exit"
#define PIN_EXEC_LINK "/sys/fs/bpf/links/sched_process_exec"
/*
 * find_libgomp - locate the x86-64 libgomp shared library via ldconfig.
 * Filters for x86-64 so it doesn't return the x32 or i386 variant.
 */
static int find_libgomp(char *buf, size_t bufsz)
{
    FILE *f = popen(
        "ldconfig -p | grep 'libgomp\\.so' | grep 'x86-64' "
        "| awk '{print $NF}' | head -1", "r");
    if (!f) { perror("popen ldconfig"); return -1; }

    if (!fgets(buf, bufsz, f)) {
        fprintf(stderr, "error: libgomp (x86-64) not found via ldconfig\n");
        pclose(f); return -1;
    }
    pclose(f);
    buf[strcspn(buf, "\n")] = '\0';

    if (buf[0] == '\0') {
        fprintf(stderr, "error: ldconfig returned empty path for libgomp\n");
        return -1;
    }
    return 0;
}

int main(void)
{
    struct omp_thread_reg_bpf *skel  = NULL;
    struct bpf_link            *link = NULL, *worker_link = NULL, *switch_link = NULL;
    struct bpf_link            *exit_link = NULL, *exec_link = NULL;
    char    libgomp_path[512] = {0};
    int     err = 0;
    uint64_t worker_offset = 0;

    /* 1 — find libgomp path */
    if (find_libgomp(libgomp_path, sizeof(libgomp_path)) < 0)
        return 1;
    printf("libgomp : %s\n", libgomp_path);

    /* 2 — find gomp_thread_start offset via disassembly */
    worker_offset = find_gomp_thread_start_offset(libgomp_path);
    if (!worker_offset) {
        fprintf(stderr, "error: could not find gomp_thread_start offset in %s\n",
                libgomp_path);
        return 1;
    }
    printf("gomp_thread_start offset : 0x%lx\n", worker_offset);

    /* 3 — load BPF skeleton */
    skel = omp_thread_reg_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load BPF skeleton\n");
        return 1;
    }

    /* 4a — attach master probe: GOMP_parallel (exported symbol) */
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_master_opts,
        .func_name = "GOMP_parallel",
    );
    link = bpf_program__attach_uprobe_opts(
        skel->progs.capture_omp_master_thread,
        -1, libgomp_path, 0, &uprobe_master_opts);

    err = libbpf_get_error(link);
    if (err) {
        link = NULL;
        fprintf(stderr, "failed to attach uprobe → %s:GOMP_parallel: %s\n",
                libgomp_path, strerror(-err));
        goto cleanup;
    }
    printf("Attached → %s : GOMP_parallel          (master)\n", libgomp_path);

    //pin links

    /* 4b — attach worker probe: gomp_thread_start (raw offset, symbol stripped) */
    worker_link = bpf_program__attach_uprobe_opts(
        skel->progs.capture_omp_worker_threads,
        -1, libgomp_path, worker_offset, NULL);

    err = libbpf_get_error(worker_link);
    if (err) {
        worker_link = NULL;
        fprintf(stderr, "failed to attach uprobe → %s+0x%lx: %s\n",
                libgomp_path, worker_offset, strerror(-err));
        goto cleanup;
    }

    //pin links
    if (bpf_link__pin(link, PIN_MASTER_LINK) < 0) {
        perror("pin master link");
        goto cleanup;
    }
    if (bpf_link__pin(worker_link, PIN_WORKER_LINK) < 0) {
        perror("pin worker link");
        goto cleanup;
    }
    if (bpf_map__pin(skel->maps.omp_threads_map, PIN_OMP_THREADS_MAP) < 0) {
        perror("pin omp_threads_map");
        goto cleanup;
    }
    printf("Attached → %s+0x%lx : gomp_thread_start (workers)\n",
           libgomp_path, worker_offset);

    /* 4c — attach sched_switch tracepoint */
    switch_link = bpf_program__attach(skel->progs.handle_switch);
    err = libbpf_get_error(switch_link);
    if (err) {
        switch_link = NULL;
        fprintf(stderr, "failed to attach tp/sched/sched_switch: %s\n",
                strerror(-err));
        goto cleanup;
    }
    if (bpf_link__pin(switch_link, PIN_SWITCH_LINK) < 0) {
        perror("pin sched_switch link");
        goto cleanup;
    }
    printf("Attached → tp/sched/sched_switch          (handle_switch)\n");

    /* 4d — attach sched_process_exit/exec tracepoints (stale TID cleanup) */
    exit_link = bpf_program__attach(skel->progs.remove_exited_omp_thread);
    err = libbpf_get_error(exit_link);
    if (err) {
        exit_link = NULL;
        fprintf(stderr, "failed to attach tp/sched/sched_process_exit: %s\n",
                strerror(-err));
        goto cleanup;
    }
    if (bpf_link__pin(exit_link, PIN_EXIT_LINK) < 0) {
        perror("pin sched_process_exit link");
        goto cleanup;
    }
    printf("Attached → tp/sched/sched_process_exit    (remove_exited_omp_thread)\n");

    exec_link = bpf_program__attach(skel->progs.remove_execed_omp_thread);
    err = libbpf_get_error(exec_link);
    if (err) {
        exec_link = NULL;
        fprintf(stderr, "failed to attach tp/sched/sched_process_exec: %s\n",
                strerror(-err));
        goto cleanup;
    }
    if (bpf_link__pin(exec_link, PIN_EXEC_LINK) < 0) {
        perror("pin sched_process_exec link");
        goto cleanup;
    }
    printf("Attached → tp/sched/sched_process_exec    (remove_execed_omp_thread)\n");

cleanup:
    bpf_link__destroy(exec_link);
    bpf_link__destroy(exit_link);
    bpf_link__destroy(switch_link);
    bpf_link__destroy(worker_link);
    bpf_link__destroy(link);
    omp_thread_reg_bpf__destroy(skel);
    return err ? 1 : 0;
}