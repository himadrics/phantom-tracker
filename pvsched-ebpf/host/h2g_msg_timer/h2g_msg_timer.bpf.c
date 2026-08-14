/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Contributors:
 *   Human: Himadri Chhaya-Shailesh
 *   AI: ChatGPT-5.5
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "pvsched.h"

char LICENSE[] SEC("license") = "GPL";

/* Kfunc exported by host_ivshmem.ko */
extern int bpf_host_ivshmem_h2g_write(__u32 index,
              const struct hg_message *hg_msg) __ksym;

#define MSG_INDEX 0
#define MSG_TIMER_PERIOD_NS 4000000ULL /* 4 ms */
#define PVSCHED_CLOCK 1 /* CLOCK_MONOTONIC */

struct h2g_msg_timer {
  struct bpf_timer timer;
  struct hg_message hg_msg;
  __u32 started;
  __u32 index;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct h2g_msg_timer);
} h2g_msg_timer_map SEC(".maps");

static int h2g_msg_timer_callback(void *map, __u32 *key,
            struct h2g_msg_timer *hg_timer)
{
  if (!hg_timer)
    return 0;

  hg_timer->index++;

  if (hg_timer->index >= NR_HOST_IVSHMEM_MSGS)
	  hg_timer->index = H2G_FIRST_HISTORY_SLOT;

  if (hg_timer->index < H2G_FIRST_HISTORY_SLOT)
	  hg_timer->index = H2G_FIRST_HISTORY_SLOT;

  hg_timer->hg_msg.msg = bpf_ktime_get_ns() / 1000;

  bpf_host_ivshmem_h2g_write(hg_timer->index, &hg_timer->hg_msg);
  bpf_timer_start(&hg_timer->timer, MSG_TIMER_PERIOD_NS, 0);

  return 0;
}

/* Initialize the timer upon the first context-switch after loading */
SEC("tp_btf/sched_switch")
int h2g_msg_timer_init(__u64 *ctx)
{
  int ret;
  __u32 key = 0;
  struct h2g_msg_timer *hg_timer;

  hg_timer = bpf_map_lookup_elem(&h2g_msg_timer_map, &key);

  if (!hg_timer)
    return 0;

  /* Exactly one pCPU starts the timer */
  if (__sync_val_compare_and_swap(&hg_timer->started, 0, 1) != 0)
    return 0;

  /* Initialize the timer here */
  __builtin_memset(&hg_timer->hg_msg, 0, sizeof(hg_timer->hg_msg));
  __builtin_memset(&hg_timer->index, 0, sizeof(hg_timer->index));

  ret = bpf_timer_init(&hg_timer->timer, &h2g_msg_timer_map, PVSCHED_CLOCK);

  if (ret)
    return 0;

  ret = bpf_timer_set_callback(&hg_timer->timer, h2g_msg_timer_callback);

  if (ret)
    return 0;

  bpf_host_ivshmem_h2g_write(hg_timer->index, &hg_timer->hg_msg);
  bpf_timer_start(&hg_timer->timer, MSG_TIMER_PERIOD_NS, 0);

  return 0;
}