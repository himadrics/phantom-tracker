BPF_CC ?= bpf-gcc
CC ?= gcc

BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
BPF_CFLAGS += -DPVSCHED_IVSHMEM_PAGE_SIZE=$(shell getconf PAGE_SIZE)

CFLAGS ?= -O2 -g -Wall -Wextra

PROJECT_INCLUDE := ../../include
PVSCHED_HDR := $(PROJECT_INCLUDE)/pvsched.h

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)

.PHONY: all clean check

all: h2g_msg_timer.bpf.o h2g_msg_timer_loader

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

h2g_msg_timer.bpf.o: h2g_msg_timer.bpf.c $(PVSCHED_HDR) vmlinux.h
	$(BPF_CC) $(BPF_CFLAGS) -I. -I/usr/include -I$(PROJECT_INCLUDE) -c $< -o $@

h2g_msg_timer_loader: h2g_msg_timer_loader.c
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

check:
	@command -v $(BPF_CC) >/dev/null || { echo "missing BPF compiler: $(BPF_CC)"; exit 1; }
	@command -v bpftool >/dev/null || { echo "missing bpftool"; exit 1; }
	@pkg-config --exists libbpf || echo "warning: pkg-config cannot find libbpf; falling back to -lbpf -lelf -lz"
	@test -f $(PVSCHED_HDR) || { echo "missing shared header: $(PVSCHED_HDR)"; exit 1; }

clean:
	rm -f h2g_msg_timer.bpf.o h2g_msg_timer_loader vmlinux.h
