#!/bin/bash
set -euo pipefail

echo "=== Tier 1.3: Component Version Verification ==="
echo ""

IMAGE="${IMAGE:-flyio/rchab:test}"

echo "Checking component versions in ${IMAGE}..."
echo ""

# Override entrypoint to skip docker-entrypoint.d scripts (they require --privileged)
echo "Docker version:"
DOCKER_VERSION=$(docker run --rm --entrypoint docker "${IMAGE}" --version)
echo "${DOCKER_VERSION}"

if [[ "${DOCKER_VERSION}" == *"25.0.5"* ]]; then
    echo "✓ Docker 25.0.5 confirmed"
else
    echo "✗ ERROR: Expected Docker 25.0.5, got: ${DOCKER_VERSION}"
    exit 1
fi

echo ""
echo "Docker daemon version:"
DOCKERD_VERSION=$(docker run --rm --entrypoint dockerd "${IMAGE}" --version)
echo "${DOCKERD_VERSION}"

echo ""
echo "Buildx version:"
BUILDX_VERSION=$(docker run --rm --entrypoint docker "${IMAGE}" buildx version)
echo "${BUILDX_VERSION}"

if [[ "${BUILDX_VERSION}" == *"v0.13."* ]]; then
    echo "✓ Buildx v0.13.x confirmed"
else
    echo "✗ ERROR: Expected Buildx v0.13.x, got: ${BUILDX_VERSION}"
    exit 1
fi

echo ""
echo "Alpine version:"
ALPINE_VERSION=$(docker run --rm --entrypoint cat "${IMAGE}" /etc/alpine-release)
echo "${ALPINE_VERSION}"

if [[ "${ALPINE_VERSION}" == 3.20.* ]]; then
    echo "✓ Alpine 3.20.x confirmed"
else
    echo "✗ ERROR: Expected Alpine 3.20.x, got: ${ALPINE_VERSION}"
    exit 1
fi

echo ""
echo "Checking dockerproxy binary exists:"
docker run --rm --entrypoint ls "${IMAGE}" -lh /dockerproxy
echo "✓ dockerproxy binary present"

echo ""
echo "✓ All component versions verified"
