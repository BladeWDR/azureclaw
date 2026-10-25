#!/usr/bin/env bash
# scripts/build-container.sh - Build the Azureclaw bootc container image
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-azureclaw}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"

ENGINE=""
if command -v podman >/dev/null 2>&1; then
    ENGINE="podman"
elif command -v docker >/dev/null 2>&1; then
    ENGINE="docker"
else
    echo "Error: Neither podman nor docker was found on this system." >&2
    exit 1
fi

echo "==> Building container image '${FULL_IMAGE}' using ${ENGINE}..."
${ENGINE} build -t "${FULL_IMAGE}" -f Containerfile .

echo "==> Build complete!"
echo "Image available locally as: ${FULL_IMAGE}"
echo ""
echo "Next steps:"
echo "1. To test locally or tag for registry:"
echo "   ${ENGINE} tag ${FULL_IMAGE} ghcr.io/<your-username>/${IMAGE_NAME}:${IMAGE_TAG}"
echo "   ${ENGINE} push ghcr.io/<your-username>/${IMAGE_NAME}:${IMAGE_TAG}"
echo "2. To build a Proxmox VM disk image (qcow2):"
echo "   ./scripts/build-disk.sh ${FULL_IMAGE}"
