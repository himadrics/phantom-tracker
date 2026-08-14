#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Contributors:
#   Human: Himadri Chhaya-Shailesh
#   AI: Claude Sonet 4.6, ChatGPT-5.5
#
# Usage: create_vm.sh --name=<vm-name> --ssh-pubkey=<path-to-ssh-pubkey> [options]
#

set -euo pipefail # exit on error, unset variable, or failed pipeline

arch="$(uname -m)"
if [[ "$arch" != "x86_64" ]]; then
    echo "error: unsupported host architecture: $arch (x86_64 required)" >&2
    exit 1
fi

# source helper scripts from lib/
. "$(dirname "$0")/lib/args.sh"
. "$(dirname "$0")/lib/numa.sh"
. "$(dirname "$0")/lib/cloudinit.sh"
. "$(dirname "$0")/lib/ssh.sh"

# --- Dependency check ---
_DEPS_OK=1
check_cmd qemu-system-x86_64 qemu-system-x86 fedora=qemu-kvm rhel=qemu-kvm centos=qemu-kvm almalinux=qemu-kvm rocky=qemu-kvm || _DEPS_OK=0

[[ "$_DEPS_OK" -eq 1 ]] || exit 1

declare_arg name           required "Name of the VM"
declare_arg type           required "VM type (target or noise)"
declare_arg ssh-pubkey     required "Path to SSH public key file to inject into the VM"
declare_arg password       optional "Password for the debian user (for console login)" debian
declare_arg sockets        optional "Number of CPU sockets" 1
declare_arg cores          optional "Number of cores per socket" 2
declare_arg threads        optional "Number of threads per core" 1
declare_arg mem            optional "RAM size (e.g. 4G)" 4G
declare_arg disk-size      optional "Disk image size (e.g. 20G)" 20G
declare_arg base-image     optional "Path to base cloud image (downloaded if absent)" "debian-12-generic-amd64.qcow2"
declare_arg ssh-port       optional "Host port forwarded to guest SSH (port 22, auto-selects from 2222 if omitted)" ""
declare_arg add-vsock      optional "Add a vhost-vsock device to the VM" false
declare_arg vsock-cid      optional "Guest CID for vhost-vsock (required when --add-vsock=true)" ""
declare_arg per-vm-cgroups    optional "Use cgroups for the VM" true
declare_arg pin-to-socket     optional "Pin VM to a specific NUMA node" false
declare_arg socket-nr         optional "NUMA node number (required when --pin-to-socket=true)"

parse_args "$@" # parse all space-separated args

if [[ -z "${ARG_SSH_PORT:-}" ]]; then
    ARG_SSH_PORT="$(find_free_tcp_port 2222)"
    if [[ -z "$ARG_SSH_PORT" ]]; then
        echo "error: could not find a free host TCP port for SSH forwarding (searched 2222-65535)" >&2
        exit 1
    fi
    echo "ssh-port: auto-selected host port $ARG_SSH_PORT"
fi

if [[ ! "$ARG_SSH_PORT" =~ ^[0-9]+$ || "$ARG_SSH_PORT" -lt 1 || "$ARG_SSH_PORT" -gt 65535 ]]; then
    echo "error: --ssh-port must be an integer between 1 and 65535" >&2
    exit 1
fi

if tcp_port_is_in_use "$ARG_SSH_PORT"; then
    echo "error: --ssh-port=$ARG_SSH_PORT is already in use on the host" >&2
    echo "  choose another port, or omit --ssh-port to auto-select a free one" >&2
    exit 1
fi

if [[ "$ARG_PIN_TO_SOCKET" == "true" ]]; then
    check_cmd numactl numactl || exit 1
fi

if [[ "$ARG_TYPE" != "target" && "$ARG_TYPE" != "noise" ]]; then
    echo "error: --type must be either 'target' or 'noise'" >&2
    exit 1
fi

# We use the same name for pvsched-shmem backends and VM names, so validate the name here before we do any work.
if [[ ! "$ARG_NAME" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    echo "error: --name must contain only letters, digits, '.', '_', or '-'" >&2
    exit 1
fi

# We use vsocks for generating host-guest traces
if [[ "$ARG_ADD_VSOCK" == "true" && -z "${ARG_VSOCK_CID:-}" ]]; then
    echo "error: --vsock-cid is required when --add-vsock is true" >&2
    exit 1
fi

# We use ivshmem for host-guest shared memory and pass host-guest messages using eBPF for target VMs
if [[ "$ARG_TYPE" == "target" ]]; then
    TARGET_DEPS_OK=1

    check_pkg_config libbpf libbpf-dev fedora=libbpf-devel rhel=libbpf-devel centos=libbpf-devel almalinux=libbpf-devel rocky=libbpf-devel opensuse=libbpf-devel sles=libbpf-devel arch=libbpf alpine=libbpf-dev gentoo=libbpf nixos=libbpf || TARGET_DEPS_OK=0
    check_cmd bpftool   bpftool || TARGET_DEPS_OK=0
    if ! command -v bpf-gcc &>/dev/null && ! command -v bpf-unknown-none-gcc &>/dev/null; then
        echo "error: required BPF compiler not found: bpf-gcc (or bpf-unknown-none-gcc)" >&2
        echo "  install it with:" >&2
        distro_install_hint gcc-bpf fedora=gcc-bpf rhel=gcc centos=gcc almalinux=gcc rocky=gcc opensuse=gcc13 sles=gcc13 arch=gcc alpine=gcc gentoo=sys-devel/gcc nixos=gcc >&2
        TARGET_DEPS_OK=0
    fi

    . "$(dirname "$0")/create_pvsched_shmem.sh"
    create_pvsched_shmem_check_deps || TARGET_DEPS_OK=0

    [[ "$TARGET_DEPS_OK" -eq 1 ]] || exit 1

    create_pvsched_shmem_setup

    cleanup_target_pvsched_shmem() {
        if ! create_pvsched_shmem_cleanup; then
            echo "warning: failed to fully clean up host_ivshmem resources" >&2
        fi
    }

    cleanup_target_pvsched_ebpf() {
        echo "Cleaning up BPF maps and registry for VM: $ARG_NAME"
        local pvsched_ebpf_host
        pvsched_ebpf_host="$(cd "$(dirname "${BASH_SOURCE[0]}")/../pvsched-ebpf/host" && pwd)"
        if [[ -x "$pvsched_ebpf_host/bin/cleanup" ]]; then
            sudo "$pvsched_ebpf_host/bin/cleanup" "$ARG_NAME" || true
        fi

        echo "Stopping background VM monitoring loaders..."
        sudo pkill -f timer.loader || true
        sudo pkill -f h2g_msg_timer_loader || true
    }

    cleanup_all() {
        cleanup_target_pvsched_shmem
        cleanup_target_pvsched_ebpf
    }

    trap cleanup_all EXIT
fi

IVSHMEM_QEMU_ARGS=()
HOSTBACKEND_DEVICE=""
if [[ "$ARG_TYPE" == "target" ]]; then
    HOSTBACKEND_DEVICE="/dev/host_ivshmem0"
    if grep -qE '^host_ivshmem[[:space:]]' /proc/modules && [[ -e "$HOSTBACKEND_DEVICE" ]]; then
        IVSHMEM_QEMU_ARGS=(
            -object "memory-backend-file,id=hostmem0,size=8192,share=on,mem-path=$HOSTBACKEND_DEVICE"
            -device "ivshmem-plain,memdev=hostmem0"
        )
        echo "ivshmem: enabled host-backed shared memory via $HOSTBACKEND_DEVICE"
    else
        HOSTBACKEND_DEVICE=""
        echo "warning: host_ivshmem is not ready (host backend device missing or module not loaded), skipping ivshmem device" >&2
    fi
fi

# On multi-numa hosts, pinning a VM to a single numa-node is the standard practice, and we support this
if [[ "$ARG_PIN_TO_SOCKET" == "true" && -z "${ARG_SOCKET_NR:-}" ]]; then
    echo "error: --socket-nr is required when --pin-to-socket is true" >&2
    exit 1
fi

# We don't use one-to-one vCPU to pCPU mapping, but rather allow the host scheduler to distribute vCPUs across the host pCPUs of the specified numa node.
PCPU_LIST=""
if [[ "$ARG_PIN_TO_SOCKET" == "true" ]]; then
    numa_check
    node_count="$(numa_node_count)"
    if [[ "$ARG_SOCKET_NR" -ge "$node_count" ]]; then
        echo "error: --socket-nr=$ARG_SOCKET_NR is out of range (host has $node_count NUMA node(s): 0-$((node_count - 1)))" >&2
        exit 1
    fi
    PCPU_LIST="$(numa_cpulist "$ARG_SOCKET_NR")"
    echo "socket $ARG_SOCKET_NR pCPUs: $PCPU_LIST"
fi

# Print the effective configuration before launching the VM.
echo "name: $ARG_NAME"
echo "type: $ARG_TYPE"
echo "ssh-port: $ARG_SSH_PORT"
echo "pin-to-socket: $ARG_PIN_TO_SOCKET"
echo "socket-nr: ${ARG_SOCKET_NR:-}"
if [[ "$ARG_TYPE" == "target" ]]; then
    echo "hostbackend-device: ${HOSTBACKEND_DEVICE:-unavailable}"
fi

# --- Disk image ---
DISK_IMG="${ARG_NAME}.qcow2"
SEED_ISO="${ARG_NAME}-seed.iso"

if [[ -f "$DISK_IMG" ]]; then
    echo "disk image $DISK_IMG already exists, booting from it"
    SEED_ISO_ARG=()
else
    cloudinit_check_deps
    if [[ ! -f "$ARG_SSH_PUBKEY" ]]; then
        echo "error: SSH public key file not found: $ARG_SSH_PUBKEY" >&2
        exit 1
    fi
    SSH_PUBKEY_STR="$(cat "$ARG_SSH_PUBKEY")"
    cloudinit_fetch_base_image "$ARG_BASE_IMAGE"
    cloudinit_create_overlay   "$ARG_BASE_IMAGE" "$DISK_IMG" "$ARG_DISK_SIZE"
    cloudinit_make_iso         "$SEED_ISO" "$ARG_NAME" "$SSH_PUBKEY_STR" "$ARG_PASSWORD" "$ARG_TYPE"
    SEED_ISO_ARG=(-drive "file=$SEED_ISO,format=raw,if=virtio,readonly=on")
fi

# --- CPU topology ---
TOTAL_VCPUS=$(( ARG_SOCKETS * ARG_CORES * ARG_THREADS ))
CPU_TOPOLOGY="$TOTAL_VCPUS,sockets=$ARG_SOCKETS,cores=$ARG_CORES,threads=$ARG_THREADS"

# --- QEMU command ---


#--vm qmp socket definition ----
QMP_SOCKET="/tmp/${ARG_NAME}-qmp.sock"
rm -f "$QMP_SOCKET"

QEMU_CMD=(
    qemu-system-x86_64
    -enable-kvm
    -cpu host
    -name "guest=$ARG_NAME,debug-threads=on"
    -m "$ARG_MEM"
    -smp "$CPU_TOPOLOGY"
    -drive "file=$DISK_IMG,format=qcow2,if=virtio"
    "${IVSHMEM_QEMU_ARGS[@]}"
    "${SEED_ISO_ARG[@]}"
    -net nic,model=virtio
    -net "user,hostfwd=tcp::${ARG_SSH_PORT}-:22"
    -nographic
    -qmp "unix:${QMP_SOCKET},server,nowait"
)

if [[ "$ARG_ADD_VSOCK" == "true" ]]; then
    QEMU_CMD+=(-device "vhost-vsock-pci,guest-cid=${ARG_VSOCK_CID}")
fi

if [[ "$ARG_PIN_TO_SOCKET" == "true" ]]; then
    QEMU_CMD=(numactl --physcpubind="$PCPU_LIST" --membind="$ARG_SOCKET_NR" "${QEMU_CMD[@]}")
fi

# --- per-VM cgroup (systemd transient scope, machine.slice — same layout as libvirt) ---
if [[ "$ARG_PER_VM_CGROUPS" == "true" ]]; then
    if ! command -v systemd-run &>/dev/null; then
        echo "warning: systemd-run not found, skipping per-vm cgroup" >&2
    else
        QEMU_CMD=(
            systemd-run
            --scope
            --collect
            --quiet
            --slice=machine.slice
            --unit="qemu-$ARG_NAME"
            --
            "${QEMU_CMD[@]}"
        )
        echo "cgroup: machine.slice/qemu-$ARG_NAME.scope"
    fi
fi

echo "launching VM:"
printf '  %q' "${QEMU_CMD[@]}" # Print the full qemu command
printf '\n'
echo "once booted, SSH in with: ssh -p $ARG_SSH_PORT debian@localhost"
if [[ -n "${SEED_ISO_ARG[*]}" ]]; then
    echo "note: first boot runs cloud-init, SSH may take 1-2 minutes to become available"
fi
echo "starting in 10 seconds..." # Sleep before starting to give the user a chance to read the output and cancel if something looks wrong
sleep 10
set +e
"${QEMU_CMD[@]}" &
qemu_pid=$!

# Wait for QEMU to create the QMP socket before registering the VM
echo "waiting for QMP socket at $QMP_SOCKET..."
for i in $(seq 1 30); do
    if [[ -S "$QMP_SOCKET" ]]; then
        echo "QMP socket ready"
        break
    fi
    sleep 1
done

if [[ -S "$QMP_SOCKET" && "$ARG_TYPE" == "target" ]]; then
    bash "$(dirname "$0")/lib/register_vm.sh" --socket="$QMP_SOCKET" --name="$ARG_NAME" --nb-vcpus="$TOTAL_VCPUS"
else
    echo "warning: QMP socket never appeared, skipping VM registration" >&2
fi

wait "$qemu_pid"
qemu_rc=$?
rm -f "$QMP_SOCKET"
set -e
exit "$qemu_rc"
