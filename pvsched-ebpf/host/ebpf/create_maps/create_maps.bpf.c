#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "phantom_tracker.h"
#include "bpf/bpf_core_read.h"
#include "register_vm_bpf.h"
#include "pvsched.h"

char LICENSE[] SEC("license") = "GPL";

#define TASK_RUNNING 0x00000000
#define TASK_WAKING 0x00000200
extern int bpf_host_ivshmem_g2h_read(__u32 index,
				     struct gh_message *msg) __ksym;
// map containing all vms
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
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, 1024);
	__type(key, char[VM_NAME_LEN]);
	__type(value, __u32); // index into inner map array
} map_registry SEC(".maps");

/*
 * Inputs: p - pointer to s64 value
 * Outputs: Returns the decremented value on success, or the value at p if <= 0 or if all retries failed
 * Description: Atomically decrements the value pointed to by p if it is positive.
 *              Uses BPF 64-bit atomic compare-and-swap to ensure correct field-level atomicity.
 */
static inline s64 atomic_dec_if_pos(s64 *p)
{
	for (int attempt = 0; attempt < 24; attempt++) {
		s64 old = *(volatile s64 *)p;
		if (old <= 0) {
			return old;
		}
		s64 new = old - 1;
		if (__sync_val_compare_and_swap(p, old, new) == old) {
			return new;
		}
	}
	return *(volatile s64 *)p;
}

/*
 * Inputs: p - pointer to s64 value (vm->phantom_count)
		   vCPUs - pointer to u32 value (vm->vcpu_count)
 * Outputs: Returns the decremented value on success, or the value at p if <= 0 or if all retries failed
 * Description: Atomically decrements the value pointed to by p if it is positive.
 *              Uses BPF 64-bit atomic compare-and-swap to ensure correct field-level atomicity.
 */
static inline s64 atomic_inc_if_lt_ceil(s64 *p, u32 *ceil_val)
{
	for (int attempt = 0; attempt < 24; attempt++) {
		s64 old = *(volatile s64 *)p;

		if (old >= *ceil_val) {
			return old;
		}
		s64 new = old + 1;
		if (__sync_val_compare_and_swap(p, old, new) == old) {
			return new;
		}
	}
	return *(volatile s64 *)p;
}

/*
 * Inputs: ctx - context containing sched_switch tracepoint data including prev and next pids
 * Outputs: Returns 0
 * Description: Tracepoint handler for sched_switch. Increments phantom count on outgoing vCPUs and decrements on incoming vCPUs, records timestamps and updates collection/processing buffers
 */
SEC("tp/sched/sched_switch")
int phantom_switch_handler(struct trace_event_raw_sched_switch *ctx)
{
	__u32 incoming_process = 0, outgoing_process = 0;
	struct vcpu_t *vcpu = NULL;
	struct vm_t *vm = NULL;
	int i = 0;
	__u32 idx = 0;
	void *collection_map_ptr = NULL, *processing_map_ptr = NULL;
	s64 new_count = 0;
	u64 prev_state = 0;

	incoming_process = ctx->next_pid;
	outgoing_process = ctx->prev_pid;

	vcpu = bpf_map_lookup_elem(&vcpus, &incoming_process);
	if (vcpu != NULL){

	
		

	struct gh_message msg = {};
	// log if current cpu is running a vcpu running an OpenMP thread
	(void)bpf_host_ivshmem_g2h_read(vcpu->vcpu_index, &msg);
	if (msg.msg == 1)
		bpf_printk("VCPU #%d OpenMP run state(switch): %llu\n",
			   vcpu->vcpu_index, msg.msg);

	prev_state = ctx->prev_state;

	if (msg.msg == 1 &&
	    __sync_bool_compare_and_swap(&vcpu->is_phantom, 1, 0)) {
		vm = bpf_map_lookup_elem(&vms, vcpu->vm_name);
		if (vm!=NULL){

			
		/* Decrement, but clamp at 0.
		 * If phantom_count is 0 the vCPU was already running when
		 * register_vm populated the map, so we missed the initial
		 * outgoing event. Skip the decrement to avoid going negative.
		 */
		new_count = atomic_dec_if_pos(&vm->phantom_count);

		char collection_buff_1[VM_NAME_LEN] = {};
		char collection_buff_2[VM_NAME_LEN] = {};
		struct phantom_count count = {};

#pragma GCC unroll 64
		for (i = 0; i < VM_NAME_LEN - 3; i++) {
			char c = vcpu->vm_name[i];
			collection_buff_1[i] = c;
			collection_buff_2[i] = c;
			if (c == '\0')
				break;
		}

		// append "_1" for collection buff 1
		collection_buff_1[i] = '_';
		collection_buff_1[i + 1] = '1';
		collection_buff_1[i + 2] = '\0';

		// append "_2" for collection buff 2
		collection_buff_2[i] = '_';
		collection_buff_2[i + 1] = '2';
		collection_buff_2[i + 2] = '\0';
		
		// get the map pointers for the collection and processing buffers
		collection_map_ptr =
			bpf_map_lookup_elem(&map_registry, collection_buff_1);
		if (!collection_map_ptr) {
			bpf_printk("Error Opening collection buffer\n");
		}

		processing_map_ptr =
			bpf_map_lookup_elem(&map_registry, collection_buff_2);
		if (!processing_map_ptr) {
			bpf_printk("Error Opening processing buffer\n");
		}

		// Plain field read — vm is map_value (non-null) here
		__u64 collecting = vm->is_collectx_in_buff_1;
		if (collecting == 1) {
			// use collection map (is_collectx_in_buff_1 == 1)
			collection_map_ptr = bpf_map_lookup_elem(
				&map_registry, collection_buff_1);
			if (collection_map_ptr != NULL) {
				idx = __sync_fetch_and_add(
					&vm->collection_buff_1_index, 1);

				count.timestamp = bpf_ktime_get_ns();
				count.count = new_count;

				bpf_map_update_elem(collection_map_ptr, &idx,
						    &count, BPF_ANY);
			}
		} else {
			// use processing map (is_collectx_in_buff_1 == 0)
			processing_map_ptr = bpf_map_lookup_elem(
				&map_registry, collection_buff_2);
			if (processing_map_ptr != NULL) {
				idx = __sync_fetch_and_add(
					&vm->collection_buff_2_index, 1);

				count.timestamp = bpf_ktime_get_ns();
				count.count = new_count;

				bpf_map_update_elem(processing_map_ptr, &idx,
						    &count, BPF_ANY);
			}
		}
		}
			

	}

	}





	// logic if vcpu is outgoing
	vcpu = bpf_map_lookup_elem(&vcpus, &outgoing_process);
	if (vcpu !=NULL){

	struct gh_message msg = {};
	// log if current cpu is running a vcpu running an OpenMP thread
	(void)bpf_host_ivshmem_g2h_read(vcpu->vcpu_index, &msg);
	if (msg.msg == 1)
		bpf_printk("VCPU #%d OpenMP run state (switch): %llu\n",
			   vcpu->vcpu_index, msg.msg);

	// set vCPU as phantom if it is running an OpenMP thread and was preempted (RUNNING or WAKING)
	if (msg.msg == 1 &&
	    (prev_state == TASK_RUNNING || prev_state == TASK_WAKING) &&
	    __sync_bool_compare_and_swap(&vcpu->is_phantom, 0, 1)) {
		vm = bpf_map_lookup_elem(&vms, vcpu->vm_name);
		if (vm!=NULL)
		{
			new_count = atomic_inc_if_lt_ceil(&vm->phantom_count,
							  &vm->nb_vcpus);

		char collection_buff_1[VM_NAME_LEN] = {};
		char collection_buff_2[VM_NAME_LEN] = {};
		struct phantom_count count = {};

#pragma GCC unroll 64
		for (i = 0; i < VM_NAME_LEN - 3; i++) {
			char c = vcpu->vm_name[i];
			collection_buff_1[i] = c;
			collection_buff_2[i] = c;
			if (c == '\0')
				break;
		}

		// append "_1" for collection buff 1
		collection_buff_1[i] = '_';
		collection_buff_1[i + 1] = '1';
		collection_buff_1[i + 2] = '\0';

		// append "_2" for collection buff 2
		collection_buff_2[i] = '_';
		collection_buff_2[i + 1] = '2';
		collection_buff_2[i + 2] = '\0';
		
		// get the map pointers for the collection and processing buffers
		collection_map_ptr =
			bpf_map_lookup_elem(&map_registry, collection_buff_1);
		if (!collection_map_ptr) {
			bpf_printk("Error Opening collection buffer\n");
		}

		processing_map_ptr =
			bpf_map_lookup_elem(&map_registry, collection_buff_2);
		if (!processing_map_ptr) {
			bpf_printk("Error Opening processing buffer\n");
		}

		// Plain field read — vm is map_value (non-null) here
		__u64 collecting = vm->is_collectx_in_buff_1;
		if (collecting == 1) {
			// use collection map (is_collectx_in_buff_1 == 1)
			collection_map_ptr = bpf_map_lookup_elem(
				&map_registry, collection_buff_1);
			if (collection_map_ptr != NULL) {
				idx = __sync_fetch_and_add(
					&vm->collection_buff_1_index, 1);

				count.timestamp = bpf_ktime_get_ns();
				count.count = new_count;

				bpf_map_update_elem(collection_map_ptr, &idx,
							    &count, BPF_ANY);

				/*
				bpf_printk(
						"Updating collection map inc with count %lld at index %u\n",
						count.count,
						idx);
						*/
			}
		} else {
			// use processing map (is_collectx_in_buff_1 == 0)
			processing_map_ptr = bpf_map_lookup_elem(
				&map_registry, collection_buff_2);
			if (processing_map_ptr != NULL) {
				idx = __sync_fetch_and_add(
					&vm->collection_buff_2_index, 1);

				count.timestamp = bpf_ktime_get_ns();
				count.count = new_count;

				bpf_map_update_elem(processing_map_ptr, &idx,
							    &count, BPF_ANY);

				/*
				*/
			}
		}
		}

	}

	}
		
	return 0;
}

/*
SEC("tp/sched/sched_wakeup")
int phantom_wakeup_handler(struct trace_event_raw_sched_wakeup *ctx)
{
	struct vm_t *vm = NULL;
	struct vcpu_t *vcpu = NULL;
	void *collection_map_ptr = NULL, *processing_map_ptr = NULL;
	s64 new_count = 0;
	__u32 idx = 0;
	int i = 0;

	__u32 pid = ctx->pid;

	vcpu = bpf_map_lookup_elem(&vcpus, &pid);
	if (!vcpu)
		return 0;

	struct gh_message msg = {};
	char collection_buff_1[VM_NAME_LEN] = {};
	char collection_buff_2[VM_NAME_LEN] = {};
	struct phantom_count count = {};

	// log if current vcpu is running an OpenMP thread
	int g2h_ret = bpf_host_ivshmem_g2h_read(vcpu->vcpu_index, &msg);
	if (g2h_ret == 0)
		bpf_printk("VCPU #%d OpenMP run state (wakeup): %llu\n",
			   vcpu->vcpu_index, msg.msg);

	// mark as phantom if it's running an OpenMP thread and is not yet running
	if (msg.msg == 1 &&
	    __sync_bool_compare_and_swap(&vcpu->is_phantom, 0, 1)) {
		vm = bpf_map_lookup_elem(&vms, vcpu->vm_name);
		if (!vm)
			return 0;

		new_count = atomic_inc_if_lt_ceil(&vm->phantom_count,
						  &vm->nb_vcpus);

#pragma GCC unroll 64
		for (i = 0; i < VM_NAME_LEN - 3; i++) {
			char c = vcpu->vm_name[i];
			collection_buff_1[i] = c;
			collection_buff_2[i] = c;
			if (c == '\0')
				break;
		}

		// append "_1" for collection buff 1
		collection_buff_1[i] = '_';
		collection_buff_1[i + 1] = '1';
		collection_buff_1[i + 2] = '\0';

		// append "_2" for collection buff 2
		collection_buff_2[i] = '_';
		collection_buff_2[i + 1] = '2';
		collection_buff_2[i + 2] = '\0';

		// get the map pointers for the collection and processing buffers
		collection_map_ptr =
			bpf_map_lookup_elem(&map_registry, collection_buff_1);
		if (!collection_map_ptr)
			bpf_printk("Error Opening collection buffer\n");

		processing_map_ptr =
			bpf_map_lookup_elem(&map_registry, collection_buff_2);
		if (!processing_map_ptr)
			bpf_printk("Error Opening processing buffer\n");

		// Plain field read — vm is map_value (non-null) here
		__u64 collecting = vm->is_collectx_in_buff_1;
		if (collecting == 1) {
			// use collection map (is_collectx_in_buff_1 == 1)
			collection_map_ptr = bpf_map_lookup_elem(
				&map_registry, collection_buff_1);
			if (collection_map_ptr != NULL) {
				idx = __sync_fetch_and_add(
					&vm->collection_buff_1_index, 1);

				count.timestamp = bpf_ktime_get_ns();
				count.count = new_count;

				bpf_map_update_elem(collection_map_ptr, &idx,
						    &count, BPF_ANY);
			}
		} else {
			// use processing map (is_collectx_in_buff_1 == 0)
			processing_map_ptr = bpf_map_lookup_elem(
				&map_registry, collection_buff_2);
			if (processing_map_ptr != NULL) {
				idx = __sync_fetch_and_add(
					&vm->collection_buff_2_index, 1);

				count.timestamp = bpf_ktime_get_ns();
				count.count = new_count;

				bpf_map_update_elem(processing_map_ptr, &idx,
						    &count, BPF_ANY);
			}
		}
	}
	return 0;
}
*/
