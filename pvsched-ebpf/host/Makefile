# ============================================================
# Compiler configuration
# ============================================================
CC ?= gcc
BPF_CC ?= bpf-gcc
CLANG = clang
CFLAGS ?= -Wall -Wextra -O2 -g
INCLUDES = -Iuser -Iinclude

BPF_PROG_CFLAGS ?= -O2 -g -gbtf -Wall -Wextra -Wno-unused-parameter
BPF_PROG_CFLAGS += -DPVSCHED_IVSHMEM_PAGE_SIZE=$(shell getconf PAGE_SIZE)
BPF_PROG_CFLAGS += -D__TARGET_ARCH_x86

# Final userspace target (VM registration binary)
TARGET = bin/register_vm
CLEANUP_TARGET = bin/cleanup

# Source files for userspace application
SRCS = user/register_vm.c user/linkedlist.c
CLEANUP_SRCS = user/cleanup.c user/linkedlist.c

# ============================================================
# Default target
# ============================================================
all: bpf userspace

# ============================================================
# Create output directory
# ============================================================
bin:
	mkdir -p bin

# ============================================================
# ============================================================
# eBPF BUILD PIPELINE (RUNS FIRST)
# ============================================================
# Step order:
#   1. compile .bpf.c -> .bpf.o
#   2. generate skeleton header (.skel.h)
#   3. build loader (userspace program that loads BPF)
# ============================================================

BPF_INCLUDE = -Iinclude -I../../include -I/usr/include
PROJECT_INCLUDE := ../../include
PVSCHED_HDR := $(PROJECT_INCLUDE)/pvsched.h
# Build eBPF loader (userspace program that loads BPF into kernel)
BPF_CFLAGS := $(shell pkg-config --cflags libbpf)
BPF_LDLIBS := $(shell pkg-config --libs libbpf)

# Compile eBPF program into BPF object file
include/vmlinux.h: | include
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

include:
	mkdir -p include



bin/create_maps.bpf.o: ebpf/create_maps/create_maps.bpf.c | bin include/vmlinux.h
	$(BPF_CC) $(BPF_PROG_CFLAGS) $(BPF_INCLUDE) -c $< -o $@

# Generate skeleton header from BPF object
include/create_maps.skel.h: bin/create_maps.bpf.o
	bpftool gen skeleton $< > $@


bin/create_maps.loader: include/create_maps.skel.h ebpf/create_maps/create_maps.loader.c
	gcc ebpf/create_maps/create_maps.loader.c -o $@ $(BPF_CFLAGS) $(BPF_LDLIBS) $(BPF_INCLUDE)

bin/timer.bpf.o: ebpf/timer/timer.bpf.c $(PVSCHED_HDR) | bin include/vmlinux.h
	$(BPF_CC) $(BPF_PROG_CFLAGS) $(BPF_INCLUDE) -c $< -o $@

include/timer.skel.h: bin/timer.bpf.o
	bpftool gen skeleton $< > $@

bin/timer.loader: include/timer.skel.h ebpf/timer/timer.loader.c
	gcc ebpf/timer/timer.loader.c -o $@ $(BPF_CFLAGS) $(BPF_LDLIBS) $(BPF_INCLUDE)

timer: bin/timer.loader

# eBPF meta target
bpf: bin/create_maps.loader timer

# ============================================================
# ============================================================
# USERSPACE VM REGISTRATION PROGRAM
# ============================================================
# Depends on:
#   - compiled C sources
#   - eBPF system already built (maps + loader ready)
# ============================================================

userspace: bin $(SRCS) user/cleanup.c
	$(CC) $(CFLAGS) $(BPF_CFLAGS) $(INCLUDES) $(SRCS) -o $(TARGET) $(BPF_LDLIBS)
	$(CC) $(CFLAGS) $(BPF_CFLAGS) $(INCLUDES) user/cleanup.c -o $(CLEANUP_TARGET) $(BPF_LDLIBS)

# ============================================================
# RUN TARGETS
# ============================================================

run_bpf: bpf
	sudo ./bin/create_maps.loader


# ============================================================
# CLEAN BUILD ARTIFACTS
# ============================================================

clean:
	rm -rf bin include/create_maps.skel.h include/timer.skel.h
