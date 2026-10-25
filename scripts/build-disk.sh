#!/usr/bin/env bash
# scripts/build-disk.sh - Generate Proxmox QCOW2 disk image via bootc-image-builder
set -euo pipefail

IMAGE_REF="${1:-azureclaw:latest}"
OUTPUT_DIR="${2:-$(pwd)/output}"
DISK_TYPE="${DISK_TYPE:-qcow2}"

echo "=========================================================="
echo " Azureclaw Disk Image Builder"
echo " Target Image: ${IMAGE_REF}"
echo " Output Type:  ${DISK_TYPE}"
echo " Output Dir:   ${OUTPUT_DIR}"
echo "=========================================================="

mkdir -p "${OUTPUT_DIR}"

ENGINE=""
if command -v podman >/dev/null 2>&1; then
    ENGINE="podman"
elif command -v docker >/dev/null 2>&1; then
    ENGINE="docker"
else
    echo "Error: Neither podman nor docker was found." >&2
    exit 1
fi

# Warn if free disk space is under 8GB
FREE_KB=$(df -k . | tail -1 | awk '{print $4}')
FREE_GB=$(( FREE_KB / 1024 / 1024 ))
if [ "${FREE_GB}" -lt 6 ]; then
    echo "WARNING: Only ~${FREE_GB}GB of free disk space detected."
    echo "bootc-image-builder may require up to 6-8GB of temporary workspace."
    echo "If disk fills up, consider running this step on your Proxmox host or GitHub Actions CI."
    echo ""
    read -r -p "Do you want to proceed anyway? [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]) ;;
        *) echo "Aborted by user."; exit 1 ;;
    esac
fi

BUILDER_IMAGE="quay.io/centos-bootc/bootc-image-builder:latest"

echo "==> Running bootc-image-builder container..."
if [ "${ENGINE}" = "podman" ]; then
    sudo podman run \
        --rm \
        --privileged \
        --security-opt label=type:unconfined_t \
        -v /var/lib/containers/storage:/var/lib/containers/storage \
        -v "${OUTPUT_DIR}":/output \
        "${BUILDER_IMAGE}" \
        --type "${DISK_TYPE}" \
        "${IMAGE_REF}"
else
    # Docker mode
    # Note: When using Docker, bootc-image-builder pulls the image directly from the registry
    # or container storage. If image is local, push to registry first or use Podman.
    docker run \
        --rm \
        --privileged \
        -v "${OUTPUT_DIR}":/output \
        "${BUILDER_IMAGE}" \
        --type "${DISK_TYPE}" \
        "${IMAGE_REF}"
fi

echo "==> Disk generation completed!"
echo "Disk image is located at: ${OUTPUT_DIR}/qcow2/disk.qcow2"
echo ""
echo "To import into Proxmox VE:"
echo "1. Transfer disk.qcow2 to your Proxmox host (e.g. /var/lib/vz/template/iso/ or /tmp)"
echo "2. Run: ./scripts/deploy-proxmox-vm.sh <VMID> <STORAGE_POOL> /path/to/disk.qcow2"
