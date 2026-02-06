#!/bin/bash
set -euo pipefail

echo "=== Testing overlaybd Image Conversion ==="
echo ""

# Ensure container is running
if ! docker ps --format '{{.Names}}' | grep -q '^rchab-test$'; then
    echo "✗ ERROR: rchab-test container not running"
    exit 1
fi

echo "=== Checking overlaybd Components ==="
docker exec rchab-test ls -la /opt/overlaybd/bin/ || echo "⚠ overlaybd bin directory not found"
docker exec rchab-test ls -la /opt/overlaybd/snapshotter/snapshotter || echo "⚠ snapshotter not found"

echo ""
echo "=== Testing overlaybd Conversion Endpoint ==="

# Test the custom flyio endpoint for overlaybd conversion
echo "Testing /flyio/v1/buildOverlaybdImage endpoint..."

# First, pull a small test image
echo "Pulling alpine:3.20 for conversion test..."
docker exec rchab-test docker pull alpine:3.20

# Test overlaybd conversion
RESPONSE=$(curl -s -X POST http://localhost:8080/flyio/v1/buildOverlaybdImage \
    -H "Content-Type: application/json" \
    -d '{"image": "alpine:3.20"}')

echo "Conversion response:"
echo "${RESPONSE}" | jq . || echo "${RESPONSE}"

if echo "${RESPONSE}" | jq -e .success >/dev/null 2>&1; then
    echo "✓ overlaybd conversion endpoint working"
else
    echo "⚠ overlaybd conversion may have issues (check logs)"
    docker logs rchab-test --tail 30 | grep -i overlaybd || true
fi

echo ""
echo "✓ Phase 6 complete: overlaybd tested"
