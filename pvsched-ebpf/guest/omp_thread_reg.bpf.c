// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Guest-side eBPF uprobe: captures OpenMP threads hooking into GOMP_parallel.
 * Loader attaches this to libgomp at runtime using the symbol name,
 * so it works regardless of the libgomp install path.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "pvsched.h"

char LICENSE[] SEC("license") = "GPL";

/* Kfunc exported by guest_ivshmem.ko */
extern int bpf_guest_ivshmem_g2h_write(__u32 index,
					const struct gh_message *gh_msg) __ksym;

/*
 * Map: tid (u32) → cpu index (u32)
 * Records which physical CPU each OpenMP thread was running on
 * when it entered a parallel region.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000000);
	__type(key, __u32); /* thread id */
	__type(value, __u32); /* cpu index */
} omp_threads_map SEC(".maps");

/*
 * Uprobe on GOMP_parallel (libgomp).
 * Fires when an OpenMP parallel region starts on this thread.
 * Loader attaches this to the correct libgomp path at runtime.
 */
SEC("uprobe")
int capture_omp_master_thread(struct pt_regs *ctx)
{
	/* tid = lower 32 bits of pid_tgid */
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u32 cpu = bpf_get_smp_processor_id();

	bpf_printk("omp master tid=%u cpu=%u\n", tid, cpu);

	bpf_map_update_elem(&omp_threads_map, &tid, &cpu, BPF_ANY);

	return 0;
}

/*
 * Uprobe on gomp_thread_start (libgomp).
 * Fires when an OpenMP  worker thread starts.
 */
SEC("uprobe")
int capture_omp_worker_threads(struct pt_regs *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u32 cpu = bpf_get_smp_processor_id();

	bpf_printk("omp worker tid=%u cpu=%u\n", tid, cpu);

	bpf_map_update_elem(&omp_threads_map, &tid, &cpu, BPF_ANY);

	return 0;
}
/*
 * Removes the calling thread's entry from omp_threads_map, if present.
 * Used to keep the map from misclassifying a TID after it stops being
 * an OpenMP thread (process exit, TID reuse) or changes identity (exec).
 *
 * sched_process_exit/exec fire while the calling thread is still "current",
 * before its final sched_switch off this cpu. If we only deleted the map
 * entry here, handle_switch's prev_tid lookup on that final switch-out
 * would already miss, so the vCPU's run state would stay stuck at 1.
 * Write the 0 here instead, while we still know the right cpu and that
 * this tid was actually tracked.
 */
static __always_inline void remove_current_tid(void)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();

	if (bpf_map_lookup_elem(&omp_threads_map, &tid)) {
		struct gh_message gh_msg = {};
		__u32 cpu = bpf_get_smp_processor_id();

		gh_msg.msg = 0;
		bpf_guest_ivshmem_g2h_write(cpu, &gh_msg);
	}

	bpf_map_delete_elem(&omp_threads_map, &tid);
}

/*
 * A thread exiting frees its TID for reuse by an unrelated future task.
 * Without this, that future task would inherit the stale OpenMP tag.
 */
/*
 * remove_current_tid() calls bpf_guest_ivshmem_g2h_write(), which is only
 * registered for BPF_PROG_TYPE_TRACING (see guest_ivshmem.c) — so this must
 * be tp_btf, not the classic tp/sched/sched_process_exit, same reasoning as
 * handle_switch below.
 */
SEC("tp_btf/sched_process_exit")
int remove_exited_omp_thread(__u64 *ctx)
{
	remove_current_tid();
	return 0;
}

/*
 * execve() keeps the same TID but replaces the task's code entirely,
 * so a former OpenMP thread's tag is no longer meaningful afterward.
 */
SEC("tp_btf/sched_process_exec")
int remove_execed_omp_thread(__u64 *ctx)
{
	remove_current_tid();
	return 0;
}


SEC("tp_btf/sched_switch")
int handle_switch(__u64 *ctx)
{
	struct task_struct *prev = (struct task_struct *)ctx[1];
	struct task_struct *next = (struct task_struct *)ctx[2];
	__u32 prev_tid = prev->pid;
	__u32 next_tid = next->pid;
	__u32 current_cpu = bpf_get_smp_processor_id();
	struct gh_message gh_msg = {};

	if (bpf_map_lookup_elem(&omp_threads_map, &prev_tid)) {
		/* OpenMP thread switched out: cpu is no longer running one */
		gh_msg.msg = 0;
		bpf_guest_ivshmem_g2h_write(current_cpu, &gh_msg);
		bpf_printk("updating ivshmem entry for cpu %d to 0\n",
			   current_cpu);
	}

	if (bpf_map_lookup_elem(&omp_threads_map, &next_tid)) {
		/* OpenMP thread switched in: cpu is now running one */
		gh_msg.msg = 1;
		bpf_guest_ivshmem_g2h_write(current_cpu, &gh_msg);
		bpf_printk("updating ivshmem entry for cpu %d to 1\n",
			   current_cpu);
	}

	return 0;
}