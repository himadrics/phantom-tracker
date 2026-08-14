CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra
CFLAGS += -I../include
CFLAGS += -DPVSCHED_IVSHMEM_PAGE_SIZE=$(shell getconf PAGE_SIZE)

all: h2g_read_test omp_test

h2g_read_test: h2g_read_test.c
	$(CC) $(CFLAGS) $< -o $@

omp_test: omp_test.c
	$(CC) $(CFLAGS) -fopenmp $< -o $@

clean:
	rm -f h2g_read_test omp_test
