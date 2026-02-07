#!/bin/bash
set -euo pipefail

echo "=== Tier 1.2: Docker Build Verification ==="
echo ""

cd /home/sprite/flyctl/rchab

# Check if image already exists (from CI build)
if docker images flyio/rchab:test --format "{{.Repository}}:{{.Tag}}" | grep -q "flyio/rchab:test"; then
    echo "✓ Docker image flyio/rchab:test exists"
    docker images flyio/rchab:test --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
else
    echo "Building Docker image (this may take 5-10 minutes)..."
    docker build --platform linux/amd64 \
        --build-arg BUILD_SHA=$(git rev-parse HEAD 2>/dev/null || echo "test") \
        -t flyio/rchab:test \
        .
    echo "✓ Docker image built successfully"
fi

echo ""
echo "Inspecting image..."
docker inspect flyio/rchab:test | jq -r '.[0] | {
  "Created": .Created,
  "Size": (.Size / 1024 / 1024 | tostring + "MB"),
  "Architecture": .Architecture
}'

echo ""
echo "✓ Docker build verification complete"
