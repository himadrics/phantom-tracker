/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Contributors:
 *   Human: Himadri Chhaya-Shailesh
 *   Human: Nchang Roy Fru
 *   AI: Claude Sonnet 4.6, ChatGPT-5.5
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/limits.h>
#include <linux/bpf.h>
#include <linux/string.h>
#include <linux/debugfs.h>

#define PVSCHED_IVSHMEM_PAGE_SIZE PAGE_SIZE
#include "pvsched.h"
#include "ebpf_compatibility.h"

/* grep for the following string in dmesg for debugging */
#define HOST_IVSHMEM_NAME "host_ivshmem"

/* Maximum number of backends supported at the same time */
#define HOST_IVSHMEM_MAX_DEVS 1024U

/*
 * For now, each backend owns exactly two pages:
 *   page 0: host-to-guest communication
 *		slot-0 is reserved for the latest msg
 *		slot-1 to NR_HOST_IVSHMEM_MSGS-1 are used for the history of msgs
 *		see pvsched.h for the definitions of these slots
 *   page 1: guest-to-host communication
 */
#define HOST_IVSHMEM_SIZE (2 * PVSCHED_IVSHMEM_PAGE_SIZE)
#define HOST_IVSHMEM_H2G_OFFSET 0UL
#define HOST_IVSHMEM_G2H_OFFSET PVSCHED_IVSHMEM_PAGE_SIZE

/*
 * When we create a character device, userspace accesses it via a /dev node.
 * 
 * Internally, the kernel identifies that node by a device number.
 * - The major number selects the driver (this module).
 * - The minor number selects one device instance managed by that driver.
 *   (The per-VM ivshmem-plain backends are the device instances in this case.)
 * 
 *  We fill the following structure with a dynamically allocated major number
 *  and a minor number assigned to each device instance. This information is
 *  kept globally because the module initialization, device creation, and
 *  module exit functions all need to access it.
 */
static dev_t host_ivshmem_devt;

/*
 * sysfs is a virtual filesystem mounted at /sys, which exposes kernel objects
 * to userspace as files and directories. This is useful for us to manage the
 * per-vm ivshemem backends from our userspace scripts.
 * 
 * Creating the following class provides a common directory for all devices
 * managed by this driver at /sys/class/host_ivshmem and a common prefix for
 * all device nodes at /dev/host_ivshmem*.
 */
static struct class *host_ivshmem_class;

/*
 * Debugfs is a virtual filesystem mounted at /sys/kernel/debug, which exposes
 * kernel objects to userspace as files and directories. This is useful for us
 * to debug the contents written to the host_ivshmem device by the eBPF program.
 *
 * The following provides a common directory for this debugging at:
 * /sys/kernel/debug/host_ivshmem/
 *
 * The driver should continue to work even if debugfs is unavailable, so failure
 * to create this debugfs directory is not fatal.
 */
static struct dentry *host_ivshmem_debugfs_root;

/*
 * One static ivshmem backend instance for initial testing.
 *
 * cdev  - Connects this backend to file_operations.
 * dev   - Represents this backend in sysfs and enables /dev node creation
 * mem   - Kernel memory backing the shared-memory region
 * size  - Size of the shared-memory region
 * minor - Minor number assigned to this backend
 */
struct host_ivshmem_backend {
	struct cdev cdev;
	struct device *dev;
	struct dentry *debugfs_dentry;
	struct debugfs_blob_wrapper debugfs_blob;
	void *mem;
	size_t size;
	int minor;
};

static struct host_ivshmem_backend backend = {
	.size = HOST_IVSHMEM_SIZE,
	.minor = 0,
};

static int host_ivshmem_h2g_write_msg(struct host_ivshmem_backend *backend,
				      u32 index,
				      const struct hg_message *hg_msg)
{
	struct hg_message *history, *latest;
	char *h2g_page;

	if (!backend || !backend->mem)
		return -ENODEV;

	if (!hg_msg)
		return -EINVAL;

	if (index == H2G_LATEST_SLOT || index >= NR_HOST_IVSHMEM_MSGS)
		return -EINVAL;

	h2g_page = (char *)backend->mem + HOST_IVSHMEM_H2G_OFFSET;
	history =
		(struct hg_message *)(h2g_page + index * HOST_IVSHMEM_MSG_SIZE);
	latest = (struct hg_message *)(h2g_page +
				       H2G_LATEST_SLOT * HOST_IVSHMEM_MSG_SIZE);

	WRITE_ONCE(history->msg, hg_msg->msg);
	smp_store_release(&latest->msg, hg_msg->msg);

	return 0;
}

/*Params::
	@Param1:ivshmem backend structure pointer
	@Param2:u32 index corresponding to cpu index (cpu slot) we wish to read from the guest-to-host page
	@Param3:caller-owned buffer that receives the message

*/
static int host_ivshmem_g2h_read(struct host_ivshmem_backend *backend,
				 u32 index, struct gh_message *msg)
{
	struct gh_message *src;
	char *g2h_page;

	if (!backend || !backend->mem)
		return -ENODEV;

	if (index >= NR_GUEST_IVSHMEM_MSGS)
		return -EINVAL;

	if (!msg)
		return -EINVAL;

	g2h_page = (char *)backend->mem + HOST_IVSHMEM_G2H_OFFSET;
	src = (struct gh_message *)(g2h_page + index * GUEST_IVSHMEM_MSG_SIZE);
	msg->msg = READ_ONCE(src->msg);
	return 0;
}

//bpf kfuncs registration
PVSCHED_KFUNC_DEFS_START();

PVSCHED_KFUNC int bpf_host_ivshmem_h2g_write(u32 index,
					     const struct hg_message *hg_msg)
{
	return host_ivshmem_h2g_write_msg(&backend, index, hg_msg);
}

PVSCHED_KFUNC int bpf_host_ivshmem_g2h_read(u32 index,
					      struct gh_message *msg)
{
	return host_ivshmem_g2h_read(&backend, index, msg);
}

PVSCHED_KFUNC_DEFS_END();

PVSCHED_KFUNCS_START(bpf_host_ivshmem_kfuncs)
BTF_ID_FLAGS(func, bpf_host_ivshmem_h2g_write)
BTF_ID_FLAGS(func, bpf_host_ivshmem_g2h_read)
PVSCHED_KFUNCS_END(bpf_host_ivshmem_kfuncs)

static const struct btf_kfunc_id_set bpf_host_ivshmem_kfunc_id_set = {
	.owner = THIS_MODULE,
	.set = &bpf_host_ivshmem_kfuncs,
};

static int host_ivshmem_register_kfuncs(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
					 &bpf_host_ivshmem_kfunc_id_set);
}

static int host_ivshmem_open(struct inode *inode, struct file *file)
{
	if (iminor(inode) != backend.minor)
		return -ENODEV;

	/* Save the backend pointer to be later used by the fops */
	file->private_data = &backend;
	return 0;
}

static int host_ivshmem_release(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

static int host_ivshmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct host_ivshmem_backend *backend = file->private_data;
	unsigned long len = vma->vm_end - vma->vm_start;

	if (!backend)
		return -ENODEV;

	/*
	 * Mapping must start at the beginning of the backend memory.
	 * All users are expected to mmap the entire shared-memory region.
	 */
	if (vma->vm_pgoff != 0 || len != backend->size)
		return -EINVAL;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	return remap_vmalloc_range(vma, backend->mem, 0);
}

/* Minimal file operations for testing the static backend */
static const struct file_operations host_ivshmem_fops = {
	.owner = THIS_MODULE,
	.open = host_ivshmem_open,
	.release = host_ivshmem_release,
	.llseek = noop_llseek,
	.mmap = host_ivshmem_mmap,
};

static int host_ivshmem_create_static_backend(void)
{
	dev_t devt = MKDEV(MAJOR(host_ivshmem_devt), backend.minor);
	int ret;

	/* Allocate zero-filled, page-backed memory */
	backend.mem = vmalloc_user(backend.size);
	if (!backend.mem)
		return -ENOMEM;

	/* Bind this backend's device number to our fops. */
	cdev_init(&backend.cdev, &host_ivshmem_fops);
	backend.cdev.owner = THIS_MODULE;

	ret = cdev_add(&backend.cdev, devt, 1);
	if (ret)
		goto err_free_mem;

	backend.dev = device_create(host_ivshmem_class, NULL, devt, &backend,
				    "host_ivshmem%d", backend.minor);

	if (IS_ERR(backend.dev)) {
		ret = PTR_ERR(backend.dev);
		backend.dev = NULL;
		goto err_del_cdev;
	}

	backend.debugfs_blob.data = backend.mem;
	backend.debugfs_blob.size = backend.size;

	if (host_ivshmem_debugfs_root) {
		backend.debugfs_dentry = debugfs_create_blob(
			"host_ivshmem_blob_vm0", 0400,
			host_ivshmem_debugfs_root, &backend.debugfs_blob);

		/* Even if debugfs blob creation fails, the device should still function */
		if (IS_ERR_OR_NULL(backend.debugfs_dentry)) {
			pr_warn("host_ivshmem: failed to create debugfs blob for vm0\n");
			backend.debugfs_dentry = NULL;
		}
	}

	pr_info("host_ivshmem: created /dev/host_ivshmem%d size=%zu\n",
		backend.minor, backend.size);
	return 0;

err_del_cdev:
	cdev_del(&backend.cdev);
err_free_mem:
	vfree(backend.mem);
	backend.mem = NULL;
	return ret;
}

static void host_ivshmem_destroy_static_backend(void)
{
	dev_t devt = MKDEV(MAJOR(host_ivshmem_devt), backend.minor);

	debugfs_remove(backend.debugfs_dentry);
	backend.debugfs_dentry = NULL;
	backend.debugfs_blob.data = NULL;
	backend.debugfs_blob.size = 0;

	if (backend.dev) {
		device_destroy(host_ivshmem_class, devt);
		backend.dev = NULL;
	}

	cdev_del(&backend.cdev);

	vfree(backend.mem);
	backend.mem = NULL;
}

static int __init host_ivshmem_init(void)
{
	int ret;

	/* Sanity check in case the user alters MSG_SIZE! */
	if (PAGE_SIZE % HOST_IVSHMEM_MSG_SIZE) {
		pr_err("host_ivshmem: PAGE_SIZE (%lu) is not a multiple of HOST_IVSHMEM_MSG_SIZE (%zu)\n",
		       PAGE_SIZE, HOST_IVSHMEM_MSG_SIZE);
		return -EINVAL;
	}

	/* 
		* Reserve a range of character-device numbers for this module.
		* The kernel chooses a free major number for us and reserves
		* HOST_IVSHMEM_MAX_DEVS minor numbers starting at 0.
		* 
		* Later, the per-VM ivshmem backends will use the minor numbers in this
		* range, and userspace will access them via the corresponding
		* /dev/host_ivshmem* nodes and manage them via /sys/class/host_ivshmem.
		*/
	ret = alloc_chrdev_region(&host_ivshmem_devt, 0, HOST_IVSHMEM_MAX_DEVS,
				  HOST_IVSHMEM_NAME);

	if (ret)
		return ret;

	host_ivshmem_class = class_create(HOST_IVSHMEM_NAME);

	host_ivshmem_debugfs_root = debugfs_create_dir(HOST_IVSHMEM_NAME, NULL);

	if (IS_ERR_OR_NULL(host_ivshmem_debugfs_root)) {
		pr_warn("host_ivshmem: failed to create debugfs directory\n");
		host_ivshmem_debugfs_root = NULL;
	}

	if (IS_ERR(host_ivshmem_class)) {
		ret = PTR_ERR(host_ivshmem_class);
		unregister_chrdev_region(host_ivshmem_devt,
					 HOST_IVSHMEM_MAX_DEVS);
		goto err_unregister_chrdev;
	}

	ret = host_ivshmem_create_static_backend();

	if (ret) {
		pr_err("host_ivshmem: failed to create static backend: %d\n",
		       ret);
		goto err_destroy_class;
	}

	ret = host_ivshmem_register_kfuncs();

	if (ret) {
		pr_err("host_ivshmem: failed to register kfuncs: %d\n", ret);
		goto err_destroy_backend;
	}

	pr_info("host_ivshmem: loaded major=%u\n", MAJOR(host_ivshmem_devt));

	return 0;

err_destroy_backend:
	host_ivshmem_destroy_static_backend();
err_destroy_class:
	debugfs_remove_recursive(host_ivshmem_debugfs_root);
	host_ivshmem_debugfs_root = NULL;
	class_destroy(host_ivshmem_class);
	host_ivshmem_class = NULL;
err_unregister_chrdev:
	unregister_chrdev_region(host_ivshmem_devt, HOST_IVSHMEM_MAX_DEVS);
	return ret;
}

static void __exit host_ivshmem_exit(void)
{
	host_ivshmem_destroy_static_backend();
	debugfs_remove_recursive(host_ivshmem_debugfs_root);
	host_ivshmem_debugfs_root = NULL;
	class_destroy(host_ivshmem_class);
	unregister_chrdev_region(host_ivshmem_devt, HOST_IVSHMEM_MAX_DEVS);
	pr_info("host_ivshmem: unloaded\n");
}

module_init(host_ivshmem_init);
module_exit(host_ivshmem_exit);

MODULE_AUTHOR("Himadri Chhaya-Shailesh");
MODULE_DESCRIPTION("Host-pvsched-shmem using QEMU ivshmem-plain devices");
MODULE_LICENSE("GPL");