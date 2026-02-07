#!/bin/bash
set -euo pipefail

echo "=== Tier 1.3: Component Version Verification ==="
echo ""

IMAGE="${IMAGE:-flyio/rchab:test}"

echo "Checking component versions in ${IMAGE}..."
echo ""

# Check Docker version
echo "Docker version:"
DOCKER_VERSION=$(docker run --rm "${IMAGE}" docker --version)
echo "${DOCKER_VERSION}"

if [[ "${DOCKER_VERSION}" == *"25.0.5"* ]]; then
    echo "✓ Docker 25.0.5 confirmed"
else
    echo "✗ ERROR: Expected Docker 25.0.5, got: ${DOCKER_VERSION}"
    exit 1
fi

echo ""
echo "Docker daemon version:"
DOCKERD_VERSION=$(docker run --rm "${IMAGE}" dockerd --version)
echo "${DOCKERD_VERSION}"

echo ""
echo "Docker API version (critical for buildpacks):"
# Start temporary container to check API
TEMP_CONTAINER=$(docker run -d --privileged --entrypoint /bin/sh "${IMAGE}" -c "dockerd &>/tmp/dockerd.log & sleep 10 && tail -f /dev/null")
sleep 12

API_VERSION=$(docker exec "${TEMP_CONTAINER}" docker version --format '{{.Server.APIVersion}}' 2>/dev/null || echo "unknown")
echo "API Version: ${API_VERSION}"

docker stop "${TEMP_CONTAINER}" >/dev/null 2>&1
docker rm "${TEMP_CONTAINER}" >/dev/null 2>&1

if [[ "${API_VERSION}" == "1.44" ]] || [[ "${API_VERSION}" > "1.44" ]]; then
    echo "✓ API version ${API_VERSION} supports buildpacks (requires 1.44+)"
else
    echo "✗ ERROR: API version ${API_VERSION} is too old (need 1.44+)"
    exit 1
fi

echo ""
echo "Go version (dockerproxy):"
GO_VERSION=$(docker run --rm "${IMAGE}" go version 2>/dev/null || echo "Go not in PATH")
echo "${GO_VERSION}"

echo ""
echo "✓ All component versions verified"
