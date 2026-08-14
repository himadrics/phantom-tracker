// include/register_vm_shared.h
#ifndef REGISTER_VM_BPF_H
#define REGISTER_VM_BPF_H

#define VM_NAME_LEN 64

struct vm_t {
	char qmp_socket[128];
	__s64 phantom_count;
	__u32 collection_buff_1_index;
	__u32 collection_buff_2_index;
	__u64 is_collectx_in_buff_1;
	__u32 nb_vcpus;
};

struct vcpu_t {
	__u32 vcpu_index;
	char vm_name[VM_NAME_LEN];
	__u64 is_phantom;
};

struct qmp_vpcu {
	int cpuIndex;
	int threadId;
};

#endif