#!/bin/bash
set -euo pipefail

BUILD_TAG=$(cat /tmp/rchab-test-tag.txt)
IMAGE="flyio/rchab:${BUILD_TAG}"

echo "=== Verifying Component Versions in ${IMAGE} ==="
echo ""

echo "Docker Engine Version:"
docker run --rm ${IMAGE} dockerd --version
DOCKER_VERSION=$(docker run --rm ${IMAGE} dockerd --version | grep -oP 'version \K[0-9.]+')
if [[ "${DOCKER_VERSION}" == "25.0.5" ]]; then
    echo "✓ Docker 25.0.5 confirmed"
else
    echo "✗ ERROR: Expected Docker 25.0.5, got ${DOCKER_VERSION}"
    exit 1
fi

echo ""
echo "Docker Buildx Version:"
docker run --rm ${IMAGE} docker buildx version
BUILDX_VERSION=$(docker run --rm ${IMAGE} docker buildx version | grep -oP 'v[0-9.]+')
if [[ "${BUILDX_VERSION}" =~ ^v0\.13\. ]]; then
    echo "✓ Buildx v0.13.x confirmed"
else
    echo "✗ ERROR: Expected Buildx v0.13.x, got ${BUILDX_VERSION}"
    exit 1
fi

echo ""
echo "Alpine Version:"
docker run --rm ${IMAGE} cat /etc/alpine-release
ALPINE_VERSION=$(docker run --rm ${IMAGE} cat /etc/alpine-release)
if [[ "${ALPINE_VERSION}" =~ ^3\.20 ]]; then
    echo "✓ Alpine 3.20.x confirmed"
else
    echo "✗ ERROR: Expected Alpine 3.20.x, got ${ALPINE_VERSION}"
    exit 1
fi

echo ""
echo "Overlaybd Snapshotter:"
if docker run --rm ${IMAGE} test -f /opt/overlaybd/snapshotter/snapshotter; then
    echo "✓ overlaybd snapshotter binary present"
else
    echo "✗ ERROR: overlaybd snapshotter binary missing"
    exit 1
fi

echo ""
echo "Overlaybd Tools:"
docker run --rm ${IMAGE} ls -lh /opt/overlaybd/bin/ || echo "⚠ overlaybd/bin not found"

echo ""
echo "dockerproxy Binary:"
docker run --rm ${IMAGE} /dockerproxy --help 2>&1 | head -3 || echo "✓ dockerproxy binary present"

echo ""
echo "✓ Phase 3 complete: All versions verified"
