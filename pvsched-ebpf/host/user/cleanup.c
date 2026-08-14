// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "register_vm.h"

/*
 * Unlink every pinned entry inside the per-VM bpffs directory, whatever it
 * is named. Hardcoding the map names here has drifted out of sync with what
 * setup_vm_maps() actually pins before (leaving stray files that block the
 * final rmdir), so just walk the directory instead.
 */
static int unlink_dir_contents(const char *dir_path)
{
	DIR *dir;
	struct dirent *entry;
	char entry_path[320];
	int ret = 0;

	dir = opendir(dir_path);
	if (!dir) {
		if (errno == ENOENT)
			return 0;
		perror("opendir VM directory");
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(entry_path, sizeof(entry_path), "%s/%s", dir_path,
			 entry->d_name);
		if (unlink(entry_path) < 0) {
			perror("unlink VM directory entry");
			ret = -1;
		} else {
			printf("Unpinned: %s\n", entry_path);
		}
	}

	closedir(dir);
	return ret;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <vm_name>\n", argv[0]);
		return 1;
	}

	const char *vm_name = argv[1];
	char path[256];
	int ret = 0;

	printf("Cleaning up resources for VM: %s\n", vm_name);

	// 1. Unlink everything pinned under the per-VM bpffs directory
	snprintf(path, sizeof(path), "%s/%s", PIN_BASE, vm_name);
	if (unlink_dir_contents(path) < 0)
		ret = 1;

	// 2. Remove per-VM BPF directory
	if (rmdir(path) < 0) {
		if (errno != ENOENT) {
			perror("rmdir VM directory");
			ret = 1;
		}
	} else {
		printf("Removed directory: %s\n", path);
	}

	// 3. Delete entries from registry map
	int registry_fd = bpf_obj_get(PIN_REGISTRY);
	if (registry_fd >= 0) {
		char key[VM_NAME_LEN]; /* must be zero-padded: BPF compares all key_size bytes */

		memset(key, 0, sizeof(key));
		snprintf(key, sizeof(key), "%s" VM_KEY_SUFFIX_1, vm_name);
		if (bpf_map_delete_elem(registry_fd, key) < 0) {
			if (errno != ENOENT) {
				perror("bpf_map_delete_elem registry suffix 1");
				ret = 1;
			}
		} else {
			printf("Deleted registry key: %s\n", key);
		}

		memset(key, 0, sizeof(key));
		snprintf(key, sizeof(key), "%s" VM_KEY_SUFFIX_2, vm_name);
		if (bpf_map_delete_elem(registry_fd, key) < 0) {
			if (errno != ENOENT) {
				perror("bpf_map_delete_elem registry suffix 2");
				ret = 1;
			}
		} else {
			printf("Deleted registry key: %s\n", key);
		}

		close(registry_fd);
	} else {
		if (errno != ENOENT) {
			perror("bpf_obj_get map_registry");
			ret = 1;
		}
	}

	// 4. Delete entry from VMs map
	int vm_fd = bpf_obj_get(PIN_VMS);
	if (vm_fd >= 0) {
		char vm_key[VM_NAME_LEN]; /* must be zero-padded: BPF compares all key_size bytes */
		memset(vm_key, 0, sizeof(vm_key));
		strncpy(vm_key, vm_name, sizeof(vm_key) - 1);
		if (bpf_map_delete_elem(vm_fd, vm_key) < 0) {
			if (errno != ENOENT) {
				perror("bpf_map_delete_elem vms");
				ret = 1;
			}
		} else {
			printf("Deleted VM key from vms map: %s\n", vm_name);
		}
		close(vm_fd);
	} else {
		if (errno != ENOENT) {
			perror("bpf_obj_get vms");
			ret = 1;
		}
	}

	// 5. Delete all associated vCPUs from vCPUs map
	int vcpus_fd = bpf_obj_get(PIN_VCPUS);
	if (vcpus_fd >= 0) {
		cleanup_stale_vcpus(vcpus_fd, vm_name);
		printf("Cleaned up vCPUs for VM: %s\n", vm_name);
		close(vcpus_fd);
	} else {
		if (errno != ENOENT) {
			perror("bpf_obj_get vcpus");
			ret = 1;
		}
	}

	return ret;
}
