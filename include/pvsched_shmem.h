#ifndef PVSCHED_SHMEM_H
#define PVSCHED_SHMEM_H

#include <linux/types.h>

#define PVSCHED_MAGIC        0x4856534D
#define PVSCHED_VERSION      1
#define MAX_NB_DEVICES            256
#define HOST_NB_METADATA_PAGES    1


struct ivshmem_header {
	__u32 magic;
	__u32 version;
	__u32 latest_slot;
	__u64 h2g_page_offset;
	__u64 h2g_page_size;
	__u64 g2h_page_offset;
	__u64 g2h_page_size;
};


struct vm_reg_req{
    __u32 nb_cpu;
	__u64 backend_name;
	__s32 vm_id;
	__u64 size;
};




#define PHANT_REG _IOW('a', 'b', struct vm_reg_req)
#endif