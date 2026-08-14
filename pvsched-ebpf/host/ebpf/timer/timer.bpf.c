// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "phantom_tracker.h"
#include "register_vm_bpf.h"
#include <bpf/bpf_helpers.h>
#include "pvsched.h"

char LICENSE[] SEC("license") = "GPL";

#define CLOCK_BOOTTIME 7

#define MSG_INDEX H2G_FIRST_HISTORY_SLOT
#define MSG_TIMER_PERIOD_NS 4000000ULL /* 4 ms */
// timer map and struct


/* Kfunc exported by host_ivshmem.ko */
extern int bpf_host_ivshmem_h2g_write(__u32 index,
              const struct hg_message *hg_msg) __ksym;

struct elem {
	struct bpf_timer timer;
	__u64 counter;
	__u64 started;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct elem);
} timer_map SEC(".maps");

// bpf maps

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000000);
	__type(key, char[VM_NAME_LEN]); // vm name
	__type(value, struct vm_t);
} vms SEC(".maps");

// map containing all vcpus
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000000);
	__type(key, __u32); // thread id
	__type(value, struct vcpu_t);
} vcpus SEC(".maps");

// map containing collection and processing maps

struct phantom_avg_ctx {
	__s64 sum;
	__u64 total_time;
	int nb_samples;
	__s64 avg;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, 1024);
	__type(key, char[VM_NAME_LEN]);
	__type(value, __u32); // index into inner map array
} map_registry SEC(".maps");

static long callback_fn(struct bpf_map *map, const void *key, void *value,
			void *ctx);

/*
 * Inputs: map - pointer to the BPF map
 *         key - pointer to the map key
 *         value - pointer to the map value
 *         ctx - pointer to custom context passed to callback
 * Outputs: Returns 0 to continue iteration
 * Description: Callback function to calculate the weighted sum and total time for phantom average
 */
static long phantom_avg_cb(struct bpf_map *map, const void *key, void *value,
			   void *ctx)
{
	struct phantom_avg_ctx *data = (struct phantom_avg_ctx *)ctx;
	__u32 k = *(__u32 *)key;

	// Only process valid intermediate samples
	if (k >= data->nb_samples) {
		return 0;
	}

	struct phantom_count *current_sample = (struct phantom_count *)value;
	__u32 next_k = k + 1;
	struct phantom_count *next_sample = bpf_map_lookup_elem(map, &next_k);
	if (!next_sample) {
		return 0;
	}

	/* Drop out-of-order: cross-CPU races can assign a later index
	 * an earlier timestamp, causing unsigned wrap on subtraction.
	 */
	if (next_sample->timestamp < current_sample->timestamp) {
		return 0;
	}

	__s64 count = current_sample->count;
	if (count < 0) {
		count = 0;
	}

	__u64 duration = next_sample->timestamp - current_sample->timestamp;

	data->sum += ((__s64)count * (__s64)duration);
	data->total_time += duration;

	return 0;
}

/*
 * Inputs: map_ptr - pointer to the BPF map to iterate
 *         nb_samples - number of samples in the map
 * Outputs: Returns the calculated phantom average
 * Description: Iterates over the map samples to calculate and return the weighted average
 */
static __s64 phantom_average(void *map_ptr, int nb_samples)
{
	struct phantom_avg_ctx ctx;
	ctx.nb_samples = nb_samples;
	ctx.avg = 0;
	ctx.sum = 0;
	ctx.total_time = 0;
	bpf_for_each_map_elem(map_ptr, phantom_avg_cb, &ctx, 0);

	if (ctx.total_time > 0) {
		ctx.avg = ctx.sum / ctx.total_time;
	} else {
		ctx.avg = 0;
	}
	return ctx.avg;
}

/*
 * Inputs: map - pointer to the BPF timer map
 *         key - pointer to the map key
 *         val - pointer to the element containing the timer
 * Outputs: Returns 0
 * Description: Timer callback that iterates over all VMs and triggers processing, then restarts timer
 */
static int timer_cb(void *map, __u32 *key, struct elem *val)
{
	val->counter++;
	//bpf_printk("tick: counter=%llu\n", val->counter);

	// swap collection and processing maps for each vm
	// iterate through each vm
	bpf_for_each_map_elem(&vms, callback_fn, NULL, 0);

	bpf_timer_start(&val->timer, 4000000ULL, 0);
	return 0;
}

/*
 * Inputs: map - pointer to the BPF map
 *         key - pointer to the map key (vm_name)
 *         value - pointer to the map value (vm_t struct)
 *         ctx - pointer to custom context
 * Outputs: Returns 0 to continue iteration
 * Description: Callback for each VM to process phantom count samples and swap collection/processing maps
 */
static long callback_fn(struct bpf_map *map, const void *key, void *value,
			void *ctx)
{
	struct vm_t *vm;
	const char *vm_name;
	char collection_buff_1[VM_NAME_LEN] = {};
	char collection_buff_2[VM_NAME_LEN] = {};
	int i;
	struct phantom_count count_end = {};
	struct phantom_count count_start = {};
	void *collection_map_ptr, *processing_map_ptr;
	int nb_samples;
	void *map_to_use;
	struct hg_message msg = {};

	vm_name = (const char *)key;
	vm = (struct vm_t *)value;

#pragma GCC \
	unroll 64 /* bpf-gcc equivalent of clang loop unroll(full); VM_NAME_LEN=64 */
	for (i = 0; i < VM_NAME_LEN - 3; i++) {
		char c = vm_name[i];
		collection_buff_1[i] = c;
		collection_buff_2[i] = c;
		if (c == '\0')
			break;
	}

	collection_buff_1[i] = '_';
	collection_buff_1[i + 1] = '1';
	collection_buff_1[i + 2] = '\0';

	collection_buff_2[i] = '_';
	collection_buff_2[i + 1] = '2';
	collection_buff_2[i + 2] = '\0';

	collection_map_ptr =
		bpf_map_lookup_elem(&map_registry, collection_buff_1);
	processing_map_ptr =
		bpf_map_lookup_elem(&map_registry, collection_buff_2);

	if (!collection_map_ptr || !processing_map_ptr)
		return 0;

	count_end.timestamp = bpf_ktime_get_ns();
	count_end.count = vm->phantom_count;

	count_start.timestamp = bpf_ktime_get_ns();
	count_start.count = vm->phantom_count;

	if (vm->is_collectx_in_buff_1 == 1) {
		// Currently storing in collection_buff_1 map (1), switch to collection_buff_2 map (0)
		// Write time_start to new buffer (collection_buff_2 map) at index 0
		__u32 zero = 0;
		bpf_map_update_elem(processing_map_ptr, &zero, &count_start,
				    BPF_ANY);

		vm->collection_buff_2_index = 1; // start next samples at 1

		// Swap is_collectx_in_buff_1 to 0 atomically so switch handlers start writing to collection_buff_2 map
		__sync_val_compare_and_swap(&vm->is_collectx_in_buff_1, 1, 0);

		// Reserve index for count_end atomically in the old collection_buff_1 map
		__u32 end_idx =
			__sync_fetch_and_add(&vm->collection_buff_1_index, 1);
		bpf_map_update_elem(collection_map_ptr, &end_idx, &count_end,
				    BPF_ANY);

		nb_samples = end_idx;
		map_to_use = collection_map_ptr;
	} else {
		// Currently storing in collection_buff_2 map (0), switch to collection_buff_1 map (1)
		// Write time_start to new buffer (collection_buff_1 map) at index 0
		__u32 zero = 0;
		bpf_map_update_elem(collection_map_ptr, &zero, &count_start,
				    BPF_ANY);

		vm->collection_buff_1_index = 1; // start next samples at 1

		// Swap is_collectx_in_buff_1 to 1 atomically so switch handlers start writing to collection_buff_1 map
		__sync_val_compare_and_swap(&vm->is_collectx_in_buff_1, 0, 1);

		// Reserve index for count_end atomically in the old collection_buff_2 map
		__u32 end_idx =
			__sync_fetch_and_add(&vm->collection_buff_2_index, 1);
		bpf_map_update_elem(processing_map_ptr, &end_idx, &count_end,
				    BPF_ANY);

		nb_samples = end_idx;
		map_to_use = processing_map_ptr;
	}
	__s64 avg = phantom_average(map_to_use, nb_samples);

	bpf_printk("Phantom average is %lld\n", avg);
	msg.msg=avg;
	bpf_host_ivshmem_h2g_write(MSG_INDEX, &msg);
	return 0;
}

/*
 * Inputs: ctx - raw tracepoint context (unused)
 * Outputs: Returns 0
 * Description: Initializes and starts the phantom average processing timer
 *              on the first sched_switch event after loading.
 */
SEC("tp_btf/sched_switch")
int phantom_timer_handler(__u64 *ctx)
{
	__u32 key = 0;
	struct elem *e = bpf_map_lookup_elem(&timer_map, &key);
	if (!e)
		return 0;

	if (__sync_lock_test_and_set(&e->started, 1) != 0)
		return 0;

	int ret = bpf_timer_init(&e->timer, &timer_map, CLOCK_BOOTTIME);
	if (ret) {
		bpf_printk("timer_init failed: %d\n", ret);
		__sync_val_compare_and_swap(&e->started, 1, 0);
		return 0;
	}
	bpf_timer_set_callback(&e->timer, timer_cb);
	bpf_timer_start(&e->timer, MSG_TIMER_PERIOD_NS, 0);

	return 0;
}
