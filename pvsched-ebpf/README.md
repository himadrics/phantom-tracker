# pvsched-ebpf

eBPF programs and userspace loaders that implement **phantom vCPU
detection**: figuring out when a virtual CPU is runnable inside the host
scheduler but the workload running on top of it (e.g. an OpenMP program)
is not actually making progress. A "phantom vCPU" is one that QEMU/KVM
has scheduled out even though the guest still considers it busy.

This directory contains two related, but currently separate, detection
paths:

1. **`host/` phantom-count tracking** — a self-contained, working
   mechanism entirely on the host: it watches the host scheduler for the
   VM's vCPU threads and maintains a live "how many vCPUs are phantom
   right now" counter per VM.
2. **`guest/` + `host/h2g_msg_timer` ivshmem path** — a newer, in-progress
   mechanism where the guest tracks its own OpenMP threads and the host
   publishes its clock into shared memory (ivshmem), so the guest can one
   day correlate "my thread is runnable" with "my vCPU actually ran
   recently". As of this writing, the guest side records the necessary
   state but does not yet write it to shared memory (see
   [Status / TODO](#status--todo)).

```
pvsched-ebpf/
├── host/                    # runs on the host (hypervisor) kernel
│   ├── include/             # shared headers (map layouts, pin paths)
│   ├── user/                # userspace: register/unregister a VM
│   ├── ebpf/create_maps/    # attaches phantom-count tracking to sched_switch
│   ├── ebpf/timer/          # periodic aggregation of phantom-count samples
│   └── h2g_msg_timer/       # periodic host->guest ivshmem timestamp writer
└── guest/                   # runs inside the guest VM kernel
    ├── omp_thread_reg.bpf.c # tracks which TIDs are OpenMP threads
    └── omp_test.c           # sample OpenMP workload to exercise the above
```

## host/ — phantom-count tracking

This is the part of the system that actually computes and aggregates a
phantom-vCPU metric today.

### `host/include/`

Headers shared across the host's eBPF programs and userspace code:

- `register_vm_bpf.h` — the map value types: `struct vm_t` (per-VM state:
  QMP socket path, `phantom_count`, double-buffer bookkeeping,
  `nb_vcpus`) and `struct vcpu_t` (per-vCPU-thread state: which VM it
  belongs to, and whether it is currently considered "phantom").
- `phantom_tracker.h` — the pin paths for the three core maps
  (`/sys/fs/bpf/vms`, `/sys/fs/bpf/vcpus`, `/sys/fs/bpf/map_registry`)
  and `struct phantom_count` (a timestamped sample of the phantom
  counter).
- `register_vm.h` — declarations shared by the userspace VM-registration
  tools.

### `host/user/` — VM registration and cleanup

- `register_vm.c` — connects to a running QEMU VM's QMP UNIX socket,
  issues `query-cpus-fast` to learn the Linux thread ID backing each
  vCPU, then populates the `vms` and `vcpus` BPF maps (via
  `create_maps.h`'s `register_vm()`/`setup_vm_maps()` helpers) and
  allocates that VM's pair of sample-collection maps.
  Usage: `register_vm <qmp_socket_path> <vm_name> <nb_vcpus>`.
- `cleanup.c` — the inverse: unpins a VM's collection maps, removes its
  `/sys/fs/bpf/<vm_name>` directory, and deletes its entries from the
  `vms`, `vcpus`, and `map_registry` maps. Usage: `cleanup <vm_name>`.
- `linkedlist.c` — a small generic linked-list used to shuttle the
  QMP-parsed vCPU list from `register_vm.c` into the registration
  helpers.

### `host/ebpf/create_maps/` — phantom counting

`create_maps.bpf.c` owns the three core BPF maps (`vms`, `vcpus`,
`map_registry`, the last being a `HASH_OF_MAPS` used as a lookup table
for per-VM sample buffers) and attaches `phantom_switch_handler` to the
`sched_switch` tracepoint. On every context switch on the host, it
checks whether the outgoing or incoming task is a registered vCPU
thread:

- vCPU thread switched **out** while it was `TASK_RUNNING`/`TASK_WAKING`
  (i.e. preempted, not voluntarily sleeping) → mark it phantom and
  increment `vm->phantom_count` (clamped at `nb_vcpus`).
- vCPU thread switched **in** while marked phantom → clear the flag and
  decrement `vm->phantom_count` (clamped at 0).

Each transition also appends a `{timestamp, count}` sample into the
VM's currently-active collection buffer (see below).

The loader (`create_maps.loader.c`) creates/loads these maps, tries to
reuse already-pinned maps so counters survive a reload, attaches the
tracepoint, and pins everything under `/sys/fs/bpf/`.

### `host/ebpf/timer/` — periodic aggregation

`timer.bpf.c` starts a `BPF_TIMER` (4 ms period, `CLOCK_BOOTTIME`) on
the first `sched_switch` after load. Each tick, for every registered VM,
it double-buffers the VM's sample array: it swaps which of the two
per-VM collection maps (named `collection_buff_1` / `collection_buff_2`, allocated by
`register_vm.c` and looked up via `map_registry`) is currently being
written to by `phantom_switch_handler`, and computes a time-weighted
average phantom count (`phantom_average()`) over the buffer that just
stopped collecting, via `bpf_for_each_map_elem`.

### `host/h2g_msg_timer/` — ivshmem host clock publisher

Independent of the phantom-count maps above, `h2g_msg_timer.bpf.c` is
the host half of the ivshmem-based design (see `guest/` below and
`pvsched-shmem/`). It starts its own `BPF_TIMER` (4 ms,
`CLOCK_MONOTONIC`) on the first `sched_switch` and, on each tick, writes
the current monotonic time (in microseconds) into a circular history of
shared-memory slots via the `bpf_host_ivshmem_h2g_write()` kfunc
(exported by the `host_ivshmem.ko` kernel module — see
`pvsched-shmem/host`). This gives the guest a way to observe recent host
timestamps through the ivshmem "host-to-guest" page. It has its own
loader (`h2g_msg_timer_loader.c`) that loads the object file directly
(no skeleton) and keeps the program attached until `SIGINT`/`SIGTERM`.

## guest/ — OpenMP thread tracking

Runs inside the guest VM and is the guest half of the ivshmem design.

- `omp_thread_reg.bpf.c` — two uprobes into `libgomp` record, in
  `omp_threads_map` (PID → CPU), every thread that is part of an OpenMP
  parallel region: `capture_omp_master_thread` on `GOMP_parallel` (the
  thread that enters the region) and `capture_omp_worker_threads` on the
  internal `gomp_thread_start` (worker threads libgomp spawns). It also
  attaches a `sched_switch` tracepoint (`handle_switch`) that checks
  whether the outgoing/incoming TID is a tracked OpenMP thread.
- `omp_thread_reg.loader.c` — locates the guest's x86-64 `libgomp.so`
  via `ldconfig`, resolves the uprobe attach points, and loads/attaches
  the skeleton, pinning the links and the map under `/sys/fs/bpf/`.
- `extract_addr.h` — `gomp_thread_start` is not an exported symbol, so
  its address isn't available by name. This header disassembles
  `libgomp.so` (via `objdump`) and locates the file offset by pattern
  matching the RIP-relative `lea ...,%rdx` that loads the thread entry
  point immediately before the call to `pthread_create@plt`.
  **This is a fragile heuristic**: it assumes x86-64 codegen and the
  exact `lea %rdx` / `pthread_create@plt` calling sequence GCC currently
  emits, so it can silently break on another architecture, a different
  compiler, or a future libgomp build that orders things differently.
  See [Status / TODO](#status--todo).
- `omp_test.c` — a standalone OpenMP program (parallel regions, a
  parallel for, nested regions, and a rapid-fire loop) used to exercise
  the uprobes end to end; build with `gcc -O2 -fopenmp omp_test.c -o
  omp_test` and run with `OMP_NUM_THREADS=<n>`.

## Status / TODO

The two paths are not yet wired together. `host/ebpf/create_maps` +
`host/ebpf/timer` already compute a live, host-only phantom-count metric
per VM. The ivshmem path (`guest/` + `host/h2g_msg_timer`) is a
work-in-progress toward a guest-aware detector: `handle_switch` in
`omp_thread_reg.bpf.c` currently only `bpf_printk`s when an OpenMP
thread's vCPU switches in or out — it does not yet write to the ivshmem
guest-to-host page (see `pvsched-shmem/guest/guest_ivshmem.c` for the
driver that exposes that page and its guest-to-host write kfunc). The
intended next step is for `handle_switch` to publish per-vCPU
runnable/running state through that kfunc so the host can cross-reference
it against the phantom-count / host timestamp data above.

TODO:
- Define and document the ivshmem ABI: the layout/meaning of the
  guest-to-host page (`struct gh_message`) is not written down anywhere,
  unlike the host-to-guest side which at least has the slot 0 = latest /
  slots 1..N = history convention in `pvsched.h`.
- Implement the guest ivshmem driver or BPF kfunc needed to write
  guest-to-host state (the guest-to-host equivalent of
  `bpf_host_ivshmem_h2g_write()`), so `omp_thread_reg.bpf.c` has
  something to call.
- Guest scheduling state is not written to ivshmem yet — `handle_switch`
  only calls `bpf_printk()` on the phantom/non-phantom transition instead
  of publishing it.
- Connect guest vCPU state to the corresponding QEMU vCPU TID in the host
  tracker: nothing today maps an OpenMP thread's guest-side CPU index to
  the host's `vcpus` map entry (keyed by host TID from
  `register_vm.c`/QMP), so the two phantom-count computations can't be
  cross-referenced yet.
- Add counters for map failures, timer failures, heartbeat gaps, and
  shared-memory write failures — current failure paths only `bpf_printk`/
  `perror` and otherwise are silently dropped (e.g. failed
  `bpf_map_update_elem` calls in `phantom_switch_handler`,
  `bpf_timer_start` return values, missed `h2g_msg_timer` ticks).
- Demonstrate end-to-end phantom-vCPU detection in a VM: no run so far
  ties `omp_test.c`, `register_vm`, and the host phantom-count/timer
  pipeline together into one observed detection.
- Add an automated VM integration test that oversubscribes host CPUs and
  verifies a known phantom-vCPU interval.
- Replace the `objdump`-based offset scan in `guest/extract_addr.h`
  (`find_gomp_thread_start_offset()`) with something that doesn't depend
  on x86-64 disassembly and a specific `lea %rdx` / `pthread_create@plt`
  code shape — it will silently break on other architectures, compilers,
  or libgomp versions that emit the thread-start sequence differently.
  Longer term this really wants upstream support: libgomp exposing a
  stable, documented hook/API for "a team thread started/stopped" (or an
  official USDT probe point) instead of us reverse-engineering an
  internal, unexported symbol's address.
