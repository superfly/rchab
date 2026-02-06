#!/bin/bash
set -euo pipefail

cd /home/sprite/flyctl/rchab

echo "=== Building rchab Docker Image ==="
echo "This will take 15-30 minutes (compiling overlaybd from source)"
echo ""

# Build with timestamp tag
BUILD_TAG="test-docker25-$(date +%Y%m%d-%H%M%S)"
echo "Building image: flyio/rchab:${BUILD_TAG}"

# Build the image
time docker build \
    --platform linux/amd64 \
    --build-arg BUILD_SHA=$(git rev-parse HEAD) \
    -t flyio/rchab:${BUILD_TAG} \
    -t flyio/rchab:latest-test \
    .

echo ""
echo "✓ Docker image built successfully"
echo "  Image: flyio/rchab:${BUILD_TAG}"
echo "  Image: flyio/rchab:latest-test"

# Save the tag for later scripts
echo "${BUILD_TAG}" > /tmp/rchab-test-tag.txt

echo ""
echo "=== Inspecting Image ==="
docker images flyio/rchab:${BUILD_TAG}
docker inspect flyio/rchab:${BUILD_TAG} | jq '.[0].Size' | \
    numfmt --to=iec-i --suffix=B

echo ""
echo "✓ Phase 2 complete: Docker image built"
