#!/bin/bash
set -euo pipefail

echo "=== Testing Storage Management and Pruning ==="
echo ""

# Ensure container is running
if ! docker ps --format '{{.Names}}' | grep -q '^rchab-test$'; then
    echo "✗ ERROR: rchab-test container not running"
    exit 1
fi

echo "=== Initial Storage Status ==="
docker exec rchab-test df -h /data || true

echo ""
echo "=== Creating Test Images for Pruning ==="
# Pull multiple images to have something to prune
docker exec rchab-test docker pull alpine:3.19
docker exec rchab-test docker pull alpine:3.18
docker exec rchab-test docker pull busybox:latest

echo ""
echo "Images before pruning:"
docker exec rchab-test docker images

echo ""
echo "=== Testing Manual Prune Endpoint ==="
echo "Calling /flyio/v1/prune?since=1h..."
PRUNE_RESPONSE=$(curl -s "http://localhost:8080/flyio/v1/prune?since=1h")
echo "${PRUNE_RESPONSE}" | jq . || echo "${PRUNE_RESPONSE}"

echo ""
echo "Images after pruning:"
docker exec rchab-test docker images

echo ""
echo "=== Testing Disk Space Monitoring ==="
docker logs rchab-test 2>&1 | grep -i "disk space" || echo "No disk space logs yet"

echo ""
echo "=== Storage Statistics ==="
docker exec rchab-test sh -c 'docker system df' || true

echo ""
echo "✓ Phase 7 complete: Storage and pruning tested"
