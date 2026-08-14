ifneq ($(KERNELRELEASE),)

obj-m := guest_ivshmem.o

ccflags-y += -I$(src)/../../include

else

KERNEL_RELEASE := $(shell uname -r)
KERNELDIR ?= /lib/modules/$(KERNEL_RELEASE)/build

BTF_BASE ?= /sys/kernel/btf/vmlinux
KERNEL_VMLINUX := $(KERNELDIR)/vmlinux

# TODO: Remove this check after scripts/lib/cloudinit.sh installs the required kernel headers.
ifeq ($(wildcard $(KERNELDIR)/Makefile),)
$(error Kernel build tree not found at $(KERNELDIR). Install headers for $(KERNEL_RELEASE) (for Debian/Ubuntu: apt install linux-headers-$(KERNEL_RELEASE)) or override KERNELDIR=/path/to/kernel/build)
endif

.PHONY: default clean modules_install

default: check_btf
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR) modules

check_btf:
	@test -e "$(KERNEL_VMLINUX)" || { \
	  echo "error: $(KERNEL_VMLINUX) is missing"; \
	  echo "run: sudo make prepare_btf"; \
	  exit 1; \
	}

prepare_btf:
	@test -r "$(BTF_BASE)" || { \
	  echo "error: base BTF not found at $(BTF_BASE)"; \
	  exit 1; \
	}
	ln -sfn "$(BTF_BASE)" "$(KERNEL_VMLINUX)"
	@echo "Linked $(KERNEL_VMLINUX) -> $(BTF_BASE)"

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR) clean
endif