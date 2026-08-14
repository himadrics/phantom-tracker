#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Contributors:
#   Human: Nchang Roy Fru
#   AI: Chatgpt GPT-5.3-mini
#
# VM registration helper script.
#
# This script:
#   - Parses VM socket and VM name from CLI arguments
#   - Starts the eBPF loader in the background
#   - Waits briefly for initialization
#   - Prepares VM registration flow (QMP + vCPU tracking expected)
#
# Expected usage:
#   ./script.sh --socket=<vm_socket> --name=<vm_name>

# Anchor all paths to the repo root (this script lives at scripts/lib/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PVSCHED_HOST_H2G_TIMER="$REPO_DIR/pvsched-ebpf/host/h2g_msg_timer"
PVSCHED_EBPF_HOST="$REPO_DIR/pvsched-ebpf/host"

# Parse VM socket argument
# Expected format: --socket=<vm_socket>
if [[ "$1" == --socket=* ]]; then
    VM_SOCKET="${1#--socket=}"
    echo "socket:  $VM_SOCKET"
else
    echo "Invalid argument: $1"
    echo "Expected: --socket=<vm_socket>"
    exit 1
fi
# Parse VM name argument
# Expected format: --name=<vm_name>
if [[ "$2" == --name=* ]]; then
    VM_NAME="${2#--name=}"
    echo "vm_name: $VM_NAME"
else
    echo "Invalid argument: $2"
    echo "Expected: --name=<vm_name>"
    exit 1
fi
# Parse nb-vcpus argument
# Expected format: --nb-vcpus=<nb_vcpus>
if [[ "$3" == --nb-vcpus=* ]]; then
    NB_VCPUS="${3#--nb-vcpus=}"
    echo "nb_vcpus: $NB_VCPUS"
else
    echo "Invalid argument: $3"
    echo "Expected: --nb-vcpus=<nb_vcpus>"
    exit 1
fi
# ------------------------------------------------------------
# Build phase
# ------------------------------------------------------------
echo "Building pvsched-host h2g timer   binaries..."
make -C "$PVSCHED_HOST_H2G_TIMER"
echo "Building pvsched-ebpf/host binaries..."
make -C "$PVSCHED_EBPF_HOST"
# ------------------------------------------------------------
# Initialization phase
# ------------------------------------------------------------
echo "Creating maps..."
echo "Connecting to vm socket $VM_SOCKET"
# Start the eBPF loader in the background
# This is expected to:
#   - load BPF program into kernel
#   - create/register required maps
#   - initialize tracking structures
sudo "$PVSCHED_EBPF_HOST/bin/create_maps.loader"
# Optional: give loader time to initialize maps and attach probes
sleep 1
# Start the ebpf timer in the background
# This is expected to:
#   - load a timer program for periodically calculating the phantom average
# Kill any previously running timer to avoid two timers racing on the same maps
sudo pkill -f timer.loader || true
sleep 0.5
TIMER_BIN="$PVSCHED_EBPF_HOST/bin/timer.loader"
sudo "$TIMER_BIN" &
timer_pid=$!
sleep 1
if ! sudo kill -0 "$timer_pid" 2>/dev/null; then
    echo "error: timer.loader failed to stay running" >&2
    exit 1
fi
#ping lo interface to start timer
ping -c 2 localhost
# ------------------------------------------------------------
# VM registration phase
# ------------------------------------------------------------
echo -e "\nRegistering VM $VM_NAME..."
# Run VM registration program:
#   - communicates with QEMU via QMP socket
#   - queries VM configuration
#   - registers vCPUs into eBPF maps
sudo "$PVSCHED_EBPF_HOST/bin/register_vm" "$VM_SOCKET" "$VM_NAME" "$NB_VCPUS" &

# Start the h2g_msg_timer: writes host timestamps into ivshmem every 4ms
# This is what the guest reads to detect phantom vCPU stalls
echo "Starting h2g_msg_timer (writes to ivshmem)..."
sudo pkill -f h2g_msg_timer_loader || true
sudo "$PVSCHED_HOST_H2G_TIMER/h2g_msg_timer_loader" &
echo "h2g_msg_timer_loader started (pid $!)"