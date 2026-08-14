BPF_CC ?= clang
CC ?= gcc

BPF_CFLAGS ?= -target bpf -O2 -g -Wall -Wextra -Wno-unused-parameter
BPF_CFLAGS += -DPVSCHED_IVSHMEM_PAGE_SIZE=$(shell getconf PAGE_SIZE)

CFLAGS ?= -O2 -g -Wall -Wextra

PROJECT_INCLUDE := ../../include
PVSCHED_HDR := $(PROJECT_INCLUDE)/pvsched.h

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)

BPF_INCLUDE := -I. -I/usr/include -I$(PROJECT_INCLUDE)

.PHONY: all clean check

all: omp_thread_reg.loader

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

omp_thread_reg.bpf.o: omp_thread_reg.bpf.c vmlinux.h
	$(BPF_CC) $(BPF_CFLAGS) $(BPF_INCLUDE) -c $< -o $@

omp_thread_reg.skel.h: omp_thread_reg.bpf.o
	bpftool gen skeleton $< > $@

omp_thread_reg.loader: omp_thread_reg.loader.c omp_thread_reg.skel.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -I. $< -o $@ $(LIBBPF_LIBS)

check:
	@command -v $(BPF_CC) >/dev/null || { echo "missing BPF compiler: $(BPF_CC)"; exit 1; }
	@command -v bpftool >/dev/null || { echo "missing bpftool"; exit 1; }
	@pkg-config --exists libbpf || echo "warning: pkg-config cannot find libbpf"
	@test -f $(PVSCHED_HDR) || { echo "missing shared header: $(PVSCHED_HDR)"; exit 1; }

clean:
	rm -f omp_thread_reg.bpf.o omp_thread_reg.skel.h omp_thread_reg.loader
