#ifndef PHANTOM_TRACKER_H
#define PHANTOM_TRACKER_H

#define PIN_PATH_VMS "/sys/fs/bpf/vms"
#define PIN_PATH_VCPUS "/sys/fs/bpf/vcpus"
#define PIN_PATH_REGISTRY "/sys/fs/bpf/map_registry"

struct phantom_count {
	int64_t count;
	uint64_t timestamp;
};

#endif //PHANTOM_TRACKER_H