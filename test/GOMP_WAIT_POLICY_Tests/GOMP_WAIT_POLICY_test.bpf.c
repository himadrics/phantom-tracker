// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * GOMP_WAIT_POLICY BPF test program.
 *
 * Attaches to three points in the OpenMP / kernel stack to verify that
 * pvsched causes OMP threads to block early (via futex) when the host
 * reports a positive phantom average.
 *
 * Programs:
 *   1. gomp_switch_handler    – tp/sched/sched_switch
 *      Detects when a registered OMP thread is preempted.
 *
 *   2. gomp_futex_enter       – tp/syscalls/sys_enter_futex
 *      Detects a registered OMP thread issuing FUTEX_WAIT 
 *
 *   3. gomp_do_wait_handler   – uprobe on callers of do_wait (libgomp)
 *      Fires at the entry of functions that call do_wait, so we can
 *      correlate wait entry with subsequent futex_wait and preemption events.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "pvsched.h"

#define FUTEX_WAIT 0


/*
 * Map: tid (u32) → cpu index (u32)
 * Populated by the omp_thread_reg loader; keyed on thread-id (lower 32 bits
 * of bpf_get_current_pid_tgid()), not on PID/TGID.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000000);
	__type(key, __u32); /* thread id */
	__type(value, __u32); /* cpu index */
} omp_threads_map SEC(".maps");



struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} buf_map SEC(".maps");


/* -----------------------------------------------------------------------
 * Program 1: sched_switch
 *
 * On every context switch, check whether the outgoing thread (prev_pid)
 * is a registered OMP thread and log it if so.
 * ----------------------------------------------------------------------- */
SEC("tp/sched/sched_switch")
int gomp_switch_handler(struct trace_event_raw_sched_switch *ctx)
{
	__u32 core = bpf_get_smp_processor_id();
	__u32 omp_tid = ctx->prev_pid;

	/* bpf_map_lookup_elem returns a *pointer* to the value, or NULL */
	__u32 *res = bpf_map_lookup_elem(&omp_threads_map, &omp_tid);
	if (res != NULL)
		bpf_printk("CPU %u: OMP thread %u preempted\n", core, omp_tid);

	return 0;
}

/* -----------------------------------------------------------------------
 * Program 2: sys_enter_futex
 *
 * When a registered OMP thread issues FUTEX_WAIT, read the host phantom
 * average and log both the average and the thread id.
 * ----------------------------------------------------------------------- */
SEC("tp/syscalls/sys_enter_futex")
int gomp_futex_enter(str
uct trace_event_raw_sys_enter *ctx)
{
    __u32 core = bpf_get_smp_processor_id();
    __u32 omp_tid = (__u32)bpf_get_current_pid_tgid();

    __u32 *res = bpf_map_lookup_elem(&omp_threads_map, &omp_tid);

    if (res != NULL && ctx->args[1] == FUTEX_WAIT) {
        bpf_printk("CPU %u: OMP thread %u executed futex wait\n",
                   core, omp_tid);
    }

    return 0;
}
/*
 * Params:
         struct pt_regs *ctx: register state at the uprobe site
 * Objective:
         Fires at the entry of functions that call do_wait, verifying
         if the calling thread is a registered OMP thread.
         If yes, prints the thread id and CPU.
 */
SEC("uprobe")
int gomp_do_wait_handler(struct pt_regs *ctx)
{
	__u32 core = bpf_get_smp_processor_id();

	/* tid = lower 32 bits of pid_tgid */
	__u32 omp_tid = (__u32)bpf_get_current_pid_tgid();

	__u32 *res = bpf_map_lookup_elem(&omp_threads_map, &omp_tid);
	if (res != NULL)
		bpf_printk("CPU %u: OMP thread %u calling do_wait\n", core,
			   omp_tid);

	return 0;
}

char _license[] SEC("license") = "GPL";



SEC("kretprobe/guest_ivshmem_read")
int BPF_KRETPROBE(guest_read_return)
{
    __u32 tid;
    __u64 *buf_addr;
    __u64 phantom_avg = 0;

    tid = (__u32)bpf_get_current_pid_tgid();

    buf_addr = bpf_map_lookup_elem(&buf_map, &tid);

    if (!buf_addr)
        return 0;

    if (PT_REGS_RC(ctx) != 64)
        goto cleanup;


    if (bpf_probe_read_user(&phantom_avg,
                            sizeof(phantom_avg),
                            (void *)*buf_addr) == 0)
    {
        bpf_printk("Phantom Average: %llu read by thread %d\n",
                   phantom_avg,tid);
    }

cleanup:
    bpf_map_delete_elem(&buf_map, &tid);

    return 0;
}


SEC("kprobe/guest_ivshmem_read")
int BPF_KPROBE(guest_read_entry,
               struct file *file,
               char *buf,
               size_t size,
               loff_t *offset)
{
    __u32 tid;
    __u64 buf_addr;

    tid = (__u32)bpf_get_current_pid_tgid();

    buf_addr = (__u64)buf;

    bpf_map_update_elem(&buf_map, &tid, &buf_addr, BPF_ANY);

    return 0;
}