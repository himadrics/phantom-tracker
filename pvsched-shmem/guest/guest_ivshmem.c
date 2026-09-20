/* SPDX-License-Identifier: GPL-3.0 with GCC-exception-3.1
 *
 * Contributors:
 *   Human: Himadri Chhaya-Shailesh
 *   Human: Nchang Roy Fru
 *   AI: ChatGPT-5.6
 */
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/mm_types.h>

/*
 * pvsched.h is the common header shared by kernel modules, eBPF programs,
 * and userspace. Kernel modules must define the page size which lets the
 * common header derive the number of messages that fit in each
 * direction-specific (host-to-guest or guest-to-host) page.
 */
#define PVSCHED_IVSHMEM_PAGE_SIZE PAGE_SIZE
#include "pvsched.h"
#include "pvsched_shmem.h"
#include "ebpf_compatibility.h"

/* grep for the following string in dmesg for debugging */
#define GUEST_IVSHMEM_NAME "guest_ivshmem"

/*
 * See https://www.qemu.org/docs/master/specs/ivshmem-spec.html
 * for detailed device specifications. 
 * The following values are taken from that spec.
 */
#define GUEST_IVSHMEM_VENDOR_ID 0x1af4
#define GUEST_IVSHMEM_DEVICE_ID 0x1110
#define GUEST_IVSHMEM_BAR 2

/*
 * The host (host_ivshmem.c) lays out each per-VM backend as:
 *   page 0: metadata (struct ivshmem_header), describing where the
 *           H2G and G2H regions actually live and how big they are.
 *   page 1: host-to-guest messages (struct hg_message)
 *           - exclusively written by the host and read by the guest userspace
 *           - NOT mapped by this driver to prevent accidental modification
 *             by the guest
 *   page 2..N: guest-to-host messages (struct gh_message)
 *           - exclusively written by the guest and read by the host
 *           - mapped by this driver to write the guest messages using a kfunc
 *
 * The H2G/G2H offsets and sizes are NOT hardcoded here: they are read at
 * probe() time from the metadata page, so this driver stays correct even
 * if the host's layout changes, and doesn't need to be kept in sync with
 * host_ivshmem.c by hand.
 */
#define GUEST_IVSHMEM_METADATA_OFFSET 0UL
#define GUEST_IVSHMEM_METADATA_SIZE PVSCHED_IVSHMEM_PAGE_SIZE

/*
 * QEMU exposes an ivshmem-plain device to the guest as a PCI device. Hence,
 * this module is implemented as a Linux PCI driver and the following struct
 * represents the private state associated with such ivshmem-plain device.
 * 
 * struct guest_ivshmem_device - State for one guest ivshmem-plain PCI device.
 *
 * @pdev: PCI device to which this driver is bound.
 * During probe(), the PCI subsystem passes the driver a struct pci_dev, which
 * represents the discovered ivshmem device. The driver allocates one instance
 * of this structure, pointed by pdev for each device to which it successfully
 * binds. The pointer is stored using pci_set_drvdata() and retrieved later in
 * callbacks such as remove() using pci_get_drvdata().
 *
 * @g2h_page: Kernel virtual address of the guest-to-host page in BAR2.
 * BARs, or Base Address Registers, describe memory or I/O regions
 * exposed by a PCI device. For our ivshmem-plain, BAR2 exposes the shared
 * memory allocated by the pvsched-shmem host module and supplied through QEMU.
 * __iomem marks this pointer as referring to device-mapped I/O memory,
 * and sets it apart from ordinary RAM. This memory must therefore be accessed
 * through the appropriate kernel I/O accessors rather than ordinary pointer
 * dereferences or memcpy().
 *
 * @h2g_page: Kernel virtual address of the host-to-guest page in BAR2.
 *
 * @cdev: Character device to which this driver is bound.
 *
 * @size: Total size of BAR2, in bytes, as reported by the PCI subsystem.
 * PCI resource addresses and lengths may be wider than int or unsigned
 * long on some architectures, such as ARM. Hence, we use resource_size_t
 * to ensure that the size is represented correctly on all architectures.
 *
 * @metadata_phy_page: Physical address of the metadata page in BAR2.
 * Userspace mmaps this together with the H2G page (metadata followed by
 * H2G, in series) so it can read both the header and the latest message
 * with a single mapping.
 */
struct guest_ivshmem_device {
	struct pci_dev *pdev;
	u8 __iomem *g2h_page;
	struct cdev cdev;
	resource_size_t size;
	resource_size_t h2g_phy_page;
	resource_size_t h2g_page_size;
	resource_size_t metadata_phy_page;
};

/*
 * We assume that the VM contains exactly one ivshmem-plain device. probe()
 * should publish its initialized state here before the module registers
 * the kfunc. We also assume that the device remains bound as long as the VM is
 * running and hence also during the lifetime of guest pvsched-ebpf component
 * that calls the kfunc.
 */
static struct guest_ivshmem_device *guest_ivshmem;

/*
	Holds device number for the char device
*/
static dev_t guest_ivshmem_devt;

/*
	sysfs class for the char device
*/
static struct class *guest_ivshmem_class;


static int guest_ivshmem_open(struct inode *inode, struct file *file)
{
	file->private_data = guest_ivshmem;
	return 0;
}

static int guest_ivshmem_release(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

/*
 * params:
	file: struct file:
	vm_area: struct vm_area_struct
	objective: a file operation to permit userspace programs to directly map
			  the metadata page and the host_to_guest page, in series, into
			  userspace memory and read the phantom average with lower
			  overhead. The metadata page lands at offset 0 of the mapping
			  and the H2G page immediately follows it.
 */
int  guest_ivshmem_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct guest_ivshmem_device *guest = file->private_data;
	resource_size_t total_size = GUEST_IVSHMEM_METADATA_SIZE + guest->h2g_page_size;
	int status;

	if (vma->vm_pgoff != 0 || vma_pages(vma) * PAGE_SIZE != total_size)
		return -EINVAL;

	status  = remap_pfn_range(vma,
							  vma->vm_start,
							  guest->metadata_phy_page >> PAGE_SHIFT,
							  total_size,
							  vma->vm_page_prot);
	return status;
}





/*
	file operations for the char device
	
*/

static struct file_operations guest_ivshmem_fops ={
	.owner = THIS_MODULE,
	.open = guest_ivshmem_open,
	.release = guest_ivshmem_release,
	.mmap = guest_ivshmem_mmap
};


/*
 * Must be called after guest_ivshmem is populated by probe() -- cdev_init()
 * cdev_add() below bind to &guest_ivshmem->cdev, which doesn't exist yet
 * before that.
 */
static int guest_ivshmem_register_chardev(void)
{
	struct device *dev;
	int ret;

	ret = alloc_chrdev_region(&guest_ivshmem_devt, 0, 1, GUEST_IVSHMEM_NAME);
	if (ret < 0) {
		pr_err(GUEST_IVSHMEM_NAME ": failed to allocate chrdev region: %d\n", ret);
		return ret;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	guest_ivshmem_class = class_create(THIS_MODULE, GUEST_IVSHMEM_NAME);
#else
	guest_ivshmem_class = class_create(GUEST_IVSHMEM_NAME);
#endif
	if (IS_ERR(guest_ivshmem_class)) {
		ret = PTR_ERR(guest_ivshmem_class);
		guest_ivshmem_class = NULL;
		pr_err(GUEST_IVSHMEM_NAME ": failed to create class: %d\n", ret);
		goto err_unregister_chrdev;
	}

	cdev_init(&guest_ivshmem->cdev, &guest_ivshmem_fops);
	guest_ivshmem->cdev.owner = THIS_MODULE;

	ret = cdev_add(&guest_ivshmem->cdev, guest_ivshmem_devt, 1);
	if (ret < 0) {
		pr_err(GUEST_IVSHMEM_NAME ": failed to add chrdev: %d\n", ret);
		goto err_destroy_class;
	}

	dev = device_create(guest_ivshmem_class, NULL, guest_ivshmem_devt, NULL,
			    GUEST_IVSHMEM_NAME);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		pr_err(GUEST_IVSHMEM_NAME ": failed to create device: %d\n", ret);
		goto err_del_cdev;
	}

	pr_info(GUEST_IVSHMEM_NAME ": created /dev/%s\n", GUEST_IVSHMEM_NAME);
	return 0;

err_del_cdev:
	cdev_del(&guest_ivshmem->cdev);
err_destroy_class:
	class_destroy(guest_ivshmem_class);
	guest_ivshmem_class = NULL;
err_unregister_chrdev:
	unregister_chrdev_region(guest_ivshmem_devt, 1);
	return ret;
}

static void guest_ivshmem_unregister_chardev(void)
{
	if (!guest_ivshmem_class)
		return;

	device_destroy(guest_ivshmem_class, guest_ivshmem_devt);
	cdev_del(&guest_ivshmem->cdev);
	class_destroy(guest_ivshmem_class);
	guest_ivshmem_class = NULL;
	unregister_chrdev_region(guest_ivshmem_devt, 1);
}

static int guest_ivshmem_g2h_write_msg(
	u32 index, const struct gh_message *gh_msg)
{
	struct guest_ivshmem_device *guest;
	struct gh_message __iomem *slot;

	guest = READ_ONCE(guest_ivshmem);

	if (!guest || !guest->g2h_page)
		return -ENODEV;

	if (!gh_msg)
		return -EINVAL;

	if (index >= NR_GUEST_IVSHMEM_MSGS)
		return -EINVAL;

	slot = (struct gh_message __iomem *)
		(guest->g2h_page + index * GUEST_IVSHMEM_MSG_SIZE);

	/*
	 * vCPU-i writes its 1-word msg in its own cache-line-sized slot, i.e.
	 * g2h_page[i]->gh_msg->msg.
	 * The remaining words of its gh_msg are used for padding and are
   * intentionally left untouched.
	 */
  writeq(gh_msg->msg, &slot->msg);

	return 0;
}

PVSCHED_KFUNC_DEFS_START();

PVSCHED_KFUNC int bpf_guest_ivshmem_g2h_write(
	u32 index, const struct gh_message *gh_msg)
{
	return guest_ivshmem_g2h_write_msg(index, gh_msg);
}

PVSCHED_KFUNC_DEFS_END();

PVSCHED_KFUNCS_START(bpf_guest_ivshmem_kfuncs)
BTF_ID_FLAGS(func, bpf_guest_ivshmem_g2h_write)
PVSCHED_KFUNCS_END(bpf_guest_ivshmem_kfuncs)

static const struct btf_kfunc_id_set bpf_guest_ivshmem_kfunc_id_set = {
	.owner = THIS_MODULE,
	.set = &bpf_guest_ivshmem_kfuncs,
};

static int guest_ivshmem_register_kfuncs(void)
{
	return register_btf_kfunc_id_set(
		BPF_PROG_TYPE_TRACING,
		&bpf_guest_ivshmem_kfunc_id_set);
}

/*
 * PCI devices identify themselves using numeric vendor and device IDs.
 *
 * QEMU's ivshmem-plain device appears inside the guest as a PCI device with
 * vendor ID GUEST_IVSHMEM_VENDOR_ID and device ID
 * GUEST_IVSHMEM_DEVICE_ID.
 *
 * The Linux PCI core compares every detected PCI device against this table.
 * When both IDs match an entry, this driver is eligible to bind to that
 * device and its probe() callback can be called.
 */
static const struct pci_device_id guest_ivshmem_ids[] = {
	{ PCI_DEVICE(GUEST_IVSHMEM_VENDOR_ID, GUEST_IVSHMEM_DEVICE_ID) },
	{ }
};

/*
 * Export the PCI ID table as module metadata.
 *
 * This allows userspace device-management tools, such as modprobe, to
 * determine that this module supports the matching PCI device and to load the
 * module automatically when that device is discovered.
 */
MODULE_DEVICE_TABLE(pci, guest_ivshmem_ids);

static int guest_ivshmem_probe(struct pci_dev *pdev,
			       const struct pci_device_id *id)
{
	struct guest_ivshmem_device *guest;
	struct ivshmem_header hdr;
	void __iomem *metadata_page;
	resource_size_t size;
	unsigned long flags;
	int ret;

	guest = kzalloc(sizeof(*guest), GFP_KERNEL);

	if (!guest) {
		pr_err(GUEST_IVSHMEM_NAME ": memory allocation failed for guest_ivshmem_device\n");
		return -ENOMEM;
	}

	/* Enabling the device turns on PCI memory decoding. */
	ret = pci_enable_device(pdev);

	if (ret) {
		dev_err(&pdev->dev, GUEST_IVSHMEM_NAME ": failed to enable PCI device: %d\n", ret);
		goto err_free_guest;
	}

  /*
   * GUEST_IVSHMEM_BAR must describe a memory-mapped PCI space through an
   * __iomem mapping and not through an I/O port mapping. This is a sanity check
   * to ensure that later our pci_iomap_range() will correcly resolve to ioremap().
   */
	flags = pci_resource_flags(pdev, GUEST_IVSHMEM_BAR);

	if (!(flags & IORESOURCE_MEM)) {
		dev_err(&pdev->dev, GUEST_IVSHMEM_NAME ": BAR%d is not an expected memory resource\n",
			GUEST_IVSHMEM_BAR);
		ret = -ENODEV;
		goto err_disable_device;
	}

  /*
   * BAR2 must be at least large enough to hold the metadata page before
   * it can be mapped and read to find out where the H2G/G2H regions
   * actually are.
   */
  size = pci_resource_len(pdev, GUEST_IVSHMEM_BAR);

	if (size < GUEST_IVSHMEM_METADATA_SIZE) {
		dev_err(&pdev->dev, GUEST_IVSHMEM_NAME ": BAR%d is too small (%llu bytes) to hold the metadata page\n",
			GUEST_IVSHMEM_BAR, (unsigned long long)size);
		ret = -EINVAL;
		goto err_disable_device;
	}

	/*
	 * Reserve GUEST_IVSHMEM_BAR so another guest driver cannot claim and map
	 * the same shared-memory resource at the same time.
	 */
	ret = pci_request_region(pdev, GUEST_IVSHMEM_BAR,
			GUEST_IVSHMEM_NAME);

	if (ret) {
		dev_err(&pdev->dev, GUEST_IVSHMEM_NAME ": failed to request BAR%d: %d\n",
			GUEST_IVSHMEM_BAR, ret);
		goto err_disable_device;
	}

	/*
	 * Read the metadata page to find out where the host actually placed
	 * the H2G and G2H regions, instead of hardcoding the host's layout
	 * here. Unmapped again immediately after reading it.
	 */
	metadata_page = pci_iomap_range(pdev, GUEST_IVSHMEM_BAR,
					 GUEST_IVSHMEM_METADATA_OFFSET,
					 GUEST_IVSHMEM_METADATA_SIZE);
	if (!metadata_page) {
		dev_err(&pdev->dev, GUEST_IVSHMEM_NAME ": failed to map the metadata page in BAR%d\n",
			GUEST_IVSHMEM_BAR);
		ret = -ENOMEM;
		goto err_release_region;
	}

	memcpy_fromio(&hdr, metadata_page, sizeof(hdr));
	pci_iounmap(pdev, metadata_page);

	if (hdr.magic != PVSCHED_MAGIC || hdr.version != PVSCHED_VERSION) {
		dev_err(&pdev->dev, GUEST_IVSHMEM_NAME ": unexpected metadata header (magic=0x%x version=%u)\n",
			hdr.magic, hdr.version);
		ret = -EINVAL;
		goto err_release_region;
	}

	/*
	 * guest_ivshmem_mmap() maps the metadata page and the H2G page in a
	 * single, contiguous mapping (metadata first, H2G immediately after)
	 * so userspace can reach both with one mmap(). That's only valid if
	 * the host actually laid them out back-to-back.
	 */
	if (hdr.h2g_page_offset != GUEST_IVSHMEM_METADATA_OFFSET + GUEST_IVSHMEM_METADATA_SIZE) {
		dev_err(&pdev->dev, GUEST_IVSHMEM_NAME ": H2G page (offset=%llu) is not immediately after the metadata page (offset=%llu size=%llu)\n",
			hdr.h2g_page_offset, (unsigned long long)GUEST_IVSHMEM_METADATA_OFFSET,
			(unsigned long long)GUEST_IVSHMEM_METADATA_SIZE);
		ret = -EINVAL;
		goto err_release_region;
	}

	if (size < hdr.g2h_page_offset + hdr.g2h_page_size) {
		dev_err(&pdev->dev, GUEST_IVSHMEM_NAME ": BAR%d (%llu bytes) is smaller than the G2H region described by the metadata header (offset=%llu size=%llu)\n",
			GUEST_IVSHMEM_BAR, (unsigned long long)size,
			hdr.g2h_page_offset, hdr.g2h_page_size);
		ret = -EINVAL;
		goto err_release_region;
	}

  /*
   * Map the G2H region described by the metadata header. The H2G page
   * is intentionally left unmapped by this driver; only its physical
   * address is recorded below, for userspace to mmap directly.
	 */
	guest->g2h_page = pci_iomap_range(pdev, GUEST_IVSHMEM_BAR, hdr.g2h_page_offset,
      hdr.g2h_page_size);

	if (!guest->g2h_page) {
		dev_err(&pdev->dev, GUEST_IVSHMEM_NAME ": failed to map the G2H page in BAR%d\n",
			GUEST_IVSHMEM_BAR);
		ret = -ENOMEM;
		goto err_release_region;
	}

	guest->pdev = pdev;
	guest->size = size;

	/*
	 * Get physical addresses of the metadata and h2g pages.
	 */
	guest->metadata_phy_page = pci_resource_start(pdev, GUEST_IVSHMEM_BAR) + GUEST_IVSHMEM_METADATA_OFFSET;
	guest->h2g_phy_page = pci_resource_start(pdev, GUEST_IVSHMEM_BAR) + hdr.h2g_page_offset;
	guest->h2g_page_size = hdr.h2g_page_size;

	/*
	 * Remember! That we assume the VM contains exactly one ivshmem-plain device.
   * So reject an unexpected second device.
	 */
	if (READ_ONCE(guest_ivshmem)) {
		dev_err(&pdev->dev,
			GUEST_IVSHMEM_NAME
			": only one ivshmem device is supported\n");
		ret = -EBUSY;
		
	}

	/* Make the per-device state available for the remove callback. */
	pci_set_drvdata(pdev, guest);

  WRITE_ONCE(guest_ivshmem, guest);

	dev_info(&pdev->dev, GUEST_IVSHMEM_NAME ": successfully mapped BAR%d G2H page: offset %llu, size %llu, %zu messages\n",
		 GUEST_IVSHMEM_BAR, hdr.g2h_page_offset,
		 hdr.g2h_page_size,
 		 (size_t)NR_GUEST_IVSHMEM_MSGS);

	return 0;


err_unmap_g2h:
	pci_iounmap(pdev, guest->g2h_page);
err_release_region:
	pci_release_region(pdev, GUEST_IVSHMEM_BAR);
err_disable_device:
	pci_disable_device(pdev);
err_free_guest:
	kfree(guest);
	return ret;
}

static void guest_ivshmem_remove(struct pci_dev *pdev)
{
	struct guest_ivshmem_device *guest = pci_get_drvdata(pdev);

	if (!guest) {
    pr_err(GUEST_IVSHMEM_NAME ": remove() called with no guest_ivshmem_device state!\n");
		return;
  }

	pci_set_drvdata(pdev, NULL);
	WARN_ON_ONCE(READ_ONCE(guest_ivshmem) != guest);
  	WRITE_ONCE(guest_ivshmem, NULL);
	pci_release_region(pdev, GUEST_IVSHMEM_BAR);
	pci_disable_device(pdev);
	kfree(guest);

	dev_info(&pdev->dev, GUEST_IVSHMEM_NAME ": unmapped BAR%d G2H/H2G pages\n", GUEST_IVSHMEM_BAR);
}

/*
 * Describe this guest ivshmem PCI driver to the Linux PCI core.
 *
 * When this structure is registered with pci_register_driver(), the PCI
 * core compares detected devices against @id_table. For each matching
 * device, it calls @probe to initialize the device. It calls @remove when
 * the device is unbound, removed, or the driver is unregistered. @name
 * identifies the driver in places such as sysfs and kernel messages.
 */

static struct pci_driver guest_ivshmem_driver = {
  .driver = {
    .suppress_bind_attrs = true,
  },
	.name = GUEST_IVSHMEM_NAME,
	.id_table = guest_ivshmem_ids,
	.probe = guest_ivshmem_probe,
	.remove = guest_ivshmem_remove,
};

static int __init guest_ivshmem_init(void)
{
	int ret;

	/*
	 * The G2H page must contain an integer number of messages. Otherwise,
	 * the final message would extend beyond the guest-owned page.
	 */
	if (PAGE_SIZE % GUEST_IVSHMEM_MSG_SIZE) {
		pr_err(GUEST_IVSHMEM_NAME ": PAGE_SIZE (%lu) is not a multiple of GUEST_IVSHMEM_MSG_SIZE (%zu)\n",
		       PAGE_SIZE, GUEST_IVSHMEM_MSG_SIZE);
		return -EINVAL;
	}

  /*
   * Register the driver with the PCI core. This triggers matching against
   * already discovered PCI devices and allows probe() to be called.
   */
	ret = pci_register_driver(&guest_ivshmem_driver);

	if (!READ_ONCE(guest_ivshmem)) {
		pr_err(GUEST_IVSHMEM_NAME
		       ": no compatible ivshmem device was found\n");
		ret = -ENODEV;
		goto err_unregister_pci_driver;
	}

	ret = guest_ivshmem_register_kfuncs();

	if (ret) {
		pr_err(GUEST_IVSHMEM_NAME
		       ": failed to register BPF kfuncs: %d\n", ret);
		goto err_unregister_pci_driver;
	}

	ret = guest_ivshmem_register_chardev();

	if (ret) {
		pr_err(GUEST_IVSHMEM_NAME
		       ": failed to register chardev: %d\n", ret);
		goto err_unregister_pci_driver;
	}

	if (ret) {
		pr_err(GUEST_IVSHMEM_NAME ": failed to register PCI driver: %d\n", ret);
    goto err_unregister_pci_driver;
  }
	else
		pr_info(GUEST_IVSHMEM_NAME ": loaded the PCI driver\n");

  return 0;

err_unregister_pci_driver:
  pci_unregister_driver(&guest_ivshmem_driver);
	return ret;
}

static void __exit guest_ivshmem_exit(void)
{
	/*
	 * Tear down the chardev first: it points at &guest_ivshmem->cdev,
	 * and pci_unregister_driver() below is what frees that struct via
	 * remove().
	 */
	guest_ivshmem_unregister_chardev();
	/* pci_unregister_driver() invokes remove() for every bound device. */
	pci_unregister_driver(&guest_ivshmem_driver);
	pr_info(GUEST_IVSHMEM_NAME ": unloaded the PCI driver\n");
}

module_init(guest_ivshmem_init);
module_exit(guest_ivshmem_exit);

MODULE_AUTHOR("Himadri Chhaya-Shailesh");
MODULE_DESCRIPTION("Guest-pvsched-shmem using QEMU ivshmem-plain device");
MODULE_LICENSE("GPL");