#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "pvsched_shmem.h"

#define HOST_REGISTRY_DEVICE "/dev/host_registry"

int main(int argc, char *argv[])
{
	struct vm_reg_req req = {0};
	char *endptr;
	long nb_cpu;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <nb_cpu>\n", argv[0]);
		return 1;
	}

	errno = 0;
	nb_cpu = strtol(argv[1], &endptr, 10);
	if (errno != 0 || *endptr != '\0' || nb_cpu <= 0) {
		fprintf(stderr, "error: invalid nb_cpu: %s\n", argv[1]);
		return 1;
	}
	req.nb_cpu = (__u32)nb_cpu;

	fd = open(HOST_REGISTRY_DEVICE, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "error: failed to open %s: %s\n",
			HOST_REGISTRY_DEVICE, strerror(errno));
		return 1;
	}

	if (ioctl(fd, PHANT_REG, &req) < 0) {
		fprintf(stderr, "error: PHANT_REG ioctl failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	close(fd);

	/*
	 * Print "<vm_id> <size>" so a caller can capture both, e.g.:
	 *   read -r VM_ID BACKEND_SIZE <<< "$(register_vm_backend 4)"
	 */
	printf("%d %llu\n", req.vm_id, (unsigned long long)req.size);
	return 0;
}
