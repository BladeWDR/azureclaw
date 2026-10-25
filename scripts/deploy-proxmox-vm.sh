#!/usr/bin/env bash
# scripts/deploy-proxmox-vm.sh - Helper script to provision Azureclaw VM on Proxmox VE
set -euo pipefail

VMID="${1:-}"
STORAGE="${2:-local-lvm}"
DISK_PATH="${3:-}"

if [ -z "${VMID}" ] || [ -z "${DISK_PATH}" ]; then
    echo "Usage: $0 <VMID> [STORAGE_POOL] <PATH_TO_QCOW2_DISK>"
    echo "Example: $0 900 local-lvm ./disk.qcow2"
    echo ""
    echo "Parameters:"
    echo "  VMID:          Unique Proxmox VM ID (e.g., 900)"
    echo "  STORAGE_POOL:  Proxmox storage pool name (default: local-lvm, or local-zfs / ceph)"
    echo "  PATH_TO_DISK:  Local path on the Proxmox host to the generated disk.qcow2"
    exit 1
fi

if [ ! -f "${DISK_PATH}" ]; then
    echo "Error: Disk image file '${DISK_PATH}' does not exist." >&2
    exit 1
fi

WAN_BRIDGE="${WAN_BRIDGE:-vmbr0}"
LAN_BRIDGE="${LAN_BRIDGE:-vmbr1}"
VM_NAME="azureclaw-router"
VM_MEM="2048"
VM_CORES="2"

echo "=========================================================="
echo " Deploying Azureclaw Router to Proxmox VE"
echo " VMID:        ${VMID}"
echo " VM Name:     ${VM_NAME}"
echo " Storage:     ${STORAGE}"
echo " WAN Bridge:  ${WAN_BRIDGE} (net0 -> ens18 / eth0)"
echo " LAN Bridge:  ${LAN_BRIDGE} (net1 -> ens19 / eth1)"
echo " Disk Source: ${DISK_PATH}"
echo "=========================================================="

echo "==> 1. Creating VM container shell..."
qm create "${VMID}" \
    --name "${VM_NAME}" \
    --memory "${VM_MEM}" \
    --cores "${VM_CORES}" \
    --cpu host \
    --machine q35 \
    --bios ovmf \
    --scsihw virtio-scsi-single \
    --agent enabled=1 \
    --net0 virtio,bridge="${WAN_BRIDGE}",firewall=0 \
    --net1 virtio,bridge="${LAN_BRIDGE}",firewall=0 \
    --onboot 1 \
    --tablet 0

echo "==> 2. Creating EFI System Disk..."
qm set "${VMID}" --efidisk0 "${STORAGE}:0,efitype=4m,pre-enrolled-keys=0"

echo "==> 3. Importing router root filesystem disk..."
qm disk import "${VMID}" "${DISK_PATH}" "${STORAGE}"

# Find the newly imported disk identifier
IMPORTED_DISK=$(qm config "${VMID}" | grep -E "unused[0-9]:" | awk '{print $2}' | tail -n1)

if [ -z "${IMPORTED_DISK}" ]; then
    echo "Error: Failed to identify imported disk in VM config." >&2
    exit 1
fi

echo "==> 4. Attaching imported disk as primary SCSI boot disk..."
qm set "${VMID}" \
    --scsi0 "${IMPORTED_DISK},discard=on,ssd=1" \
    --boot order=scsi0

echo "=========================================================="
echo " Deployment Complete!"
echo " Start the VM with:"
echo "   qm start ${VMID}"
echo ""
echo " To monitor via console:"
echo "   qm terminal ${VMID}   (or use Proxmox Web GUI NoVNC console)"
echo "=========================================================="
