#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Contributors:
#   Human: Himadri Chhaya-Shailesh
#   AI: Claude Sonet 4.6, ChatGPT-5.5
#
# cloud-init seed ISO helpers.
#
# Provides:
#   cloudinit_check_deps            — verify required tools are installed
#   cloudinit_make_iso <out.iso> \  — write a cloud-init seed ISO
#       <hostname> <ssh-pubkey>

# shellcheck source=distro.sh
. "$(dirname "${BASH_SOURCE[0]}")/distro.sh"

# Default Debian 12 (Bookworm) stable cloud image URL
CLOUD_IMAGE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"

cloudinit_check_deps() {
    local missing=0
    check_cmd qemu-img qemu-utils arch=qemu-img || missing=1
    check_cmd wget     wget                      || missing=1
    check_cmd xorriso  xorriso arch=libisoburn gentoo=libisoburn || missing=1
    return "$missing"
}

# Download the base cloud image if not already present.
# Usage: cloudinit_fetch_base_image <dest-path>
cloudinit_fetch_base_image() {
    local dest="$1"
    if [[ -f "$dest" ]]; then
        echo "base image already present: $dest"
        return 0
    fi
    echo "downloading base cloud image from $CLOUD_IMAGE_URL ..."
    wget --progress=bar:force -O "$dest" "$CLOUD_IMAGE_URL"
    echo "download complete: $dest"
}

# Create a qcow2 overlay backed by the base image and resize it.
# Usage: cloudinit_create_overlay <base-img> <overlay-img> <size>
cloudinit_create_overlay() {
    local base="$1"
    local overlay="$2"
    local size="$3"
    if [[ -f "$overlay" ]]; then
        echo "overlay disk already present: $overlay"
        return 0
    fi
    echo "creating overlay disk: $overlay (backing: $base, size: $size)"
    qemu-img create -f qcow2 -b "$(realpath "$base")" -F qcow2 "$overlay"
    qemu-img resize "$overlay" "$size"
}

# Generate a cloud-init seed ISO with user-data and meta-data.
# Usage: cloudinit_make_iso <out.iso> <hostname> <ssh-pubkey-string> <password> <type>
#   <type> is "target" or "noise" -- only "target" VMs get the guest_ivshmem
#   kernel module and omp_thread_reg BPF program built and started, since
#   only target VMs have the ivshmem-plain PCI device attached by
#   create_vm.sh in the first place. Building/loading that stack on a noise
#   VM is wasted work, and modprobe guest_ivshmem fails outright there since
#   no matching PCI device exists for it to bind to.
cloudinit_make_iso() {
    local iso="$1"
    local hostname="$2"
    local ssh_pubkey="$3"
    local password="$4"
    local type="$5"
    if [[ -f "$iso" ]]; then
        echo "seed ISO already present: $iso"
        return 0
    fi
    local tmpdir
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' RETURN

    if [[ "$type" == "target" ]]; then
        cat > "$tmpdir/user-data" <<EOF
#cloud-config
hostname: ${hostname}
manage_etc_hosts: true
users:
  - name: debian
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: ${password}
    ssh_authorized_keys:
      - ${ssh_pubkey}
package_update: true
package_upgrade: false
packages:
  - qemu-guest-agent
  - openssh-server
write_files:
  - path: /etc/udev/rules.d/99-guest-ivshmem.rules
    permissions: '0644'
    content: |
      KERNEL=="guest_ivshmem", MODE="0644"
  - path: /root/guest_ivshmem_driver_setup.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail
      export HOME=/root
      mkdir -p /tmp/phantom-tracker/logs
      exec > >(tee -a /tmp/phantom-tracker/logs/guest_ivshmem_driver_setup.log > /dev/console) 2>&1
      echo "******** Installing dependencies ********"
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q git  gfortran linux-headers-\$(uname -r) linux-source-6.1 dwarves libelf-dev zlib1g-dev libbpf-dev clang bpftool

      echo "******** Cloning/Updating phantom-tracker repo ********"
      if [ -d "\$HOME/phantom-tracker" ]; then
        cd \$HOME/phantom-tracker
        git fetch origin
        git checkout Nchang
        git pull origin Nchang
      else
        git clone https://github.com/himadrics/phantom-tracker \$HOME/phantom-tracker
        cd \$HOME/phantom-tracker
        git checkout Nchang
      fi
      cd \$HOME

      echo "******** Building resolve_btfids ********"
      mkdir -p \$HOME/src
      tar -C \$HOME/src -xf /usr/src/linux-source-6.1.tar.xz
      make -C \$HOME/src/linux-source-6.1/tools/bpf/resolve_btfids

      echo "******** Preparing BTF for guest_ivshmem ********"
      cd \$HOME/phantom-tracker/pvsched-shmem/guest
      make prepare_btf


      RESOLVE_BTFIDS_BIN=\$HOME/src/linux-source-6.1/tools/bpf/resolve_btfids/resolve_btfids
      KVER=\$(uname -r)
      KCOMMON="/usr/src/linux-headers-\${KVER%-*}-common"
      KARCH="/usr/src/linux-headers-\${KVER}"

      mkdir -p "\${KCOMMON}/tools/bpf/resolve_btfids" "\${KARCH}/tools/bpf/resolve_btfids"
      cp "\${RESOLVE_BTFIDS_BIN}" "\${KCOMMON}/tools/bpf/resolve_btfids/resolve_btfids" 2>/dev/null || true
      cp "\${RESOLVE_BTFIDS_BIN}" "\${KARCH}/tools/bpf/resolve_btfids/resolve_btfids" 2>/dev/null || true

      echo "******** Building guest_ivshmem kernel module and resolving BTF ********"
      make V=1 RESOLVE_BTFIDS="\${RESOLVE_BTFIDS_BIN}"

      echo "******** Installing guest_ivshmem kernel module ********"
      make modules_install
      depmod -a "\$(uname -r)"
      udevadm control --reload-rules
      modprobe guest_ivshmem

      echo "******** Building omp_thread_reg BPF program ********"
      cd \$HOME/phantom-tracker/pvsched-ebpf/guest
      make

      echo "******** Starting omp_thread_reg BPF program ********"
      ./omp_thread_reg.loader

      echo "******** guest_ivshmem_driver_setup.sh complete ********"
  - path: /etc/systemd/system/phantom-tracker.service

    content: |
        [Unit]
        Description = Pulls latest phantom tracker repository, builds and installs guest_ivshmem driver.
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/bin/bash /root/guest_ivshmem_driver_setup.sh
        
        [Install]
        WantedBy=multi-user.target



runcmd:
  - systemctl enable --now ssh
  - systemctl enable --now qemu-guest-agent
  - systemctl daemon-reload
  - systemctl enable --now phantom-tracker
EOF
    else
        cat > "$tmpdir/user-data" <<EOF
#cloud-config
hostname: ${hostname}
manage_etc_hosts: true
users:
  - name: debian
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: ${password}
    ssh_authorized_keys:
      - ${ssh_pubkey}
package_update: true
package_upgrade: false
packages:
  - qemu-guest-agent
  - openssh-server
runcmd:
  - systemctl enable --now ssh
  - systemctl enable --now qemu-guest-agent
EOF
    fi

    cat > "$tmpdir/meta-data" <<EOF
instance-id: ${hostname}
local-hostname: ${hostname}
EOF

    echo "generating cloud-init seed ISO: $iso"
    xorriso -as mkisofs -output "$iso" -volid cidata -joliet -rock \
        "$tmpdir/user-data" "$tmpdir/meta-data"
}
