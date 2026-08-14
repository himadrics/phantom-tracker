#include "timer.skel.h"
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "phantom_tracker.h"

static struct timer_bpf *skel;
static struct bpf_link *prog_link;

/*
 * Inputs: sig - the signal number received
 * Outputs: None
 * Description: Signal handler that detaches the program and cleans up the BPF skeleton before exiting
 */
static void cleanup(int sig)
{
	bpf_link__destroy(prog_link);
	timer_bpf__destroy(skel);
	printf("cleaned up\n");
	_exit(0);
}

/*
 * Inputs: None
 * Outputs: Returns 0 on success, 1 on failure
 * Description: Main function that opens the BPF skeleton, reuses pinned maps, loads the BPF program, and attaches it to sched_switch
 */
int main()
{
	int vcpus_fd, vms_fd, map_registry_fd;

	skel = timer_bpf__open();
	if (!skel) {
		fprintf(stderr, "open failed\n");
		return 1;
	}

	//load preexisting vpcu and vm maps
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

	map_registry_fd = bpf_obj_get(PIN_PATH_REGISTRY);
	if (map_registry_fd >= 0) {
		printf("reusing pinned map_registry map\n");
		if (bpf_map__reuse_fd(skel->maps.map_registry,
				      map_registry_fd) < 0) {
			perror("reuse map_registry map");
			goto cleanup_inner;
		}
	}

	if (timer_bpf__load(skel)) {
		fprintf(stderr, "load failed\n");
		goto cleanup_inner;
	}

	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);

	prog_link = bpf_program__attach(skel->progs.phantom_timer_handler);
	if (libbpf_get_error(prog_link)) {
		fprintf(stderr, "attach failed\n");
		prog_link = NULL;
		goto cleanup_inner;
	}

	printf("attached — timer starts on the next sched_switch event\n");

	printf("watch: cat /sys/kernel/debug/tracing/trace_pipe\n");
	pause();
	return 0;

cleanup_inner:
	timer_bpf__destroy(skel);
	return 1;
}
