// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "create_maps.skel.h"
#include "phantom_tracker.h"

#define PIN_PATH_LINK        "/sys/fs/bpf/links/sched_switch_link"
#define PIN_PATH_WAKEUP_LINK "/sys/fs/bpf/links/try_to_wake_up_link"

#define MAP_REGISTRY_MAX_ENTRIES 1000000

/*
 * Inputs: None
 * Outputs: Returns 0 on success, 1 on failure
 * Description: Main entry point that sets up the BPF maps (inner map for registry, reuses pinned maps), loads the programs, and pins them for persistence across execution
 */
int main(void)
{
	struct create_maps_bpf *skel;
	struct bpf_link *link;
	/* struct bpf_link *wakeup_link; */
	int vms_fd, vcpus_fd, registry_fd;

	int inner_fd;
	int ret = 1;

	skel = create_maps_bpf__open();
	if (!skel) {
		perror("open skeleton");
		return 1;
	}

	/*
	 * Create inner map template for map_registry.
	 * The fd is only used as a template; ownership transfers to the
	 * skeleton after set_inner_map_fd().
	 */
	inner_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, sizeof(__u32),
				  sizeof(struct phantom_count),
				  MAP_REGISTRY_MAX_ENTRIES, NULL);
	if (inner_fd < 0) {
		perror("create inner map template");
		goto cleanup_skel;
	}

	if (bpf_map__set_inner_map_fd(skel->maps.map_registry, inner_fd) < 0) {
		perror("set map_registry inner fd");
		goto cleanup_inner;
	}

	/*
	 * Try to reuse already-pinned maps so that state survives
	 * across reloads.
	 */
	vms_fd = bpf_obj_get(PIN_PATH_VMS);
	if (vms_fd >= 0) {
		printf("reusing pinned vms map\n");
		if (bpf_map__reuse_fd(skel->maps.vms, vms_fd) < 0) {
			perror("reuse vms map");
			goto cleanup_inner;
		}
	}

	vcpus_fd = bpf_obj_get(PIN_PATH_VCPUS);
	if (vcpus_fd >= 0) {
		printf("reusing pinned vcpus map\n");
		if (bpf_map__reuse_fd(skel->maps.vcpus, vcpus_fd) < 0) {
			perror("reuse vcpus map");
			goto cleanup_inner;
		}
	}

	registry_fd = bpf_obj_get(PIN_PATH_REGISTRY);
	if (registry_fd >= 0) {
		printf("reusing pinned map_registry map\n");
		if (bpf_map__reuse_fd(skel->maps.map_registry, registry_fd) <
		    0) {
			perror("reuse map_registry map");
			goto cleanup_inner;
		}
	}

	if (create_maps_bpf__load(skel) < 0) {
		perror("load skeleton");
		goto cleanup_inner;
	}

	link = bpf_program__attach_tracepoint(skel->progs.phantom_switch_handler,
					      "sched", "sched_switch");
	if (!link) {
		perror("attach tracepoint");
		goto cleanup_inner;
	}

	if (bpf_link__pin(link, PIN_PATH_LINK) < 0) {
		perror("pin sched_switch link");
		goto cleanup_link;
	}

	/*
	wakeup_link = bpf_program__attach_kprobe(
		skel->progs.phantom_wakeup_handler,
		false, "try_to_wake_up");
	if (!wakeup_link) {
		perror("attach kprobe try_to_wake_up");
		goto cleanup_link;
	}

	if (bpf_link__pin(wakeup_link, PIN_PATH_WAKEUP_LINK) < 0) {
		perror("pin try_to_wake_up link");
		goto cleanup_wakeup_link;
	}
	*/

	/*
	 * Pin maps only when they were not already pinned.
	 */
	if (vms_fd < 0) {
		if (bpf_obj_pin(bpf_map__fd(skel->maps.vms), PIN_PATH_VMS) <
		    0) {
			perror("pin vms");
			goto cleanup_link;
		}
		printf("pinned vms map\n");
	}

	if (vcpus_fd < 0) {
		if (bpf_obj_pin(bpf_map__fd(skel->maps.vcpus), PIN_PATH_VCPUS) <
		    0) {
			perror("pin vcpus");
			goto cleanup_link;
		}
		printf("pinned vcpus map\n");
	}

	if (registry_fd < 0) {
		if (bpf_obj_pin(bpf_map__fd(skel->maps.map_registry),
				PIN_PATH_REGISTRY) < 0) {
			perror("pin map_registry");
			goto cleanup_link;
		}
		printf("pinned map_registry map\n");
	}

	printf("everything loaded successfully\n");
	ret = 0;

/* cleanup_wakeup_link:
	bpf_link__destroy(wakeup_link); */
cleanup_link:
	bpf_link__destroy(link);
cleanup_inner:
	close(inner_fd);
cleanup_skel:
	create_maps_bpf__destroy(skel);
	return ret;
}