/* SPDX-License-Identifier: GPL-3.0 with GCC-exception-3.1
 *
 * h2g_read_test.c -- reads a single slot from the host-to-guest ivshmem
 * page exposed by /dev/guest_ivshmem and prints its msg value.
 *
 * The device's read() ignores the file position and treats the offset
 * given to pread() as a slot index (0..NR_HOST_IVSHMEM_MSGS-1), not a
 * byte offset -- see guest_ivshmem.c. Slot H2G_LATEST_SLOT (0) always
 * holds the most recently published message.
 *
 * Usage: h2g_read_test [slot]   (default: slot 0, the latest message)
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* PVSCHED_IVSHMEM_PAGE_SIZE is supplied by the Makefile via -D. */
#include "pvsched.h"

#define GUEST_IVSHMEM_DEV "/dev/guest_ivshmem"

int main(int argc, char *argv[])
{
	struct hg_message msg;
	long slot = H2G_LATEST_SLOT;
	int fd;
	ssize_t n;

	if (argc > 2) {
		fprintf(stderr, "usage: %s [slot]\n", argv[0]);
		return 1;
	}

	if (argc == 2) {
		char *end;

		slot = strtol(argv[1], &end, 10);
		if (*end != '\0' || slot < 0 || (size_t)slot >= NR_HOST_IVSHMEM_MSGS) {
			fprintf(stderr, "error: slot must be an integer in [0, %zu)\n",
				(size_t)NR_HOST_IVSHMEM_MSGS);
			return 1;
		}
	}

	fd = open(GUEST_IVSHMEM_DEV, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "error: open(%s) failed: %s\n",
			GUEST_IVSHMEM_DEV, strerror(errno));
		fprintf(stderr, "       (needs root, and guest_ivshmem.ko loaded)\n");
		return 1;
	}

	n = pread(fd, &msg, sizeof(msg), (off_t)slot);
	if (n != sizeof(msg)) {
		if (n < 0)
			fprintf(stderr, "error: pread failed: %s\n", strerror(errno));
		else
			fprintf(stderr, "error: short read: got %zd of %zu bytes\n",
				n, sizeof(msg));
		close(fd);
		return 1;
	}

	printf("slot %ld: msg = %llu\n", slot, (unsigned long long)msg.msg);

	close(fd);
	return 0;
}
