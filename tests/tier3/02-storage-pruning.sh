#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

echo "=== Tier 3.2: Storage Management and Pruning ==="
echo ""

IMAGE="${IMAGE:-flyio/rchab:test}"

# Start container if not running
if ! is_container_running; then
  start_rchab_container "${IMAGE}"
  trap stop_rchab_container EXIT
fi

echo "Initial storage status:"
docker exec rchab-test df -h /data 2>/dev/null || docker exec rchab-test df -h /

echo ""
echo "Creating test images for pruning..."
docker exec rchab-test docker pull alpine:3.19 >/dev/null 2>&1
docker exec rchab-test docker pull alpine:3.18 >/dev/null 2>&1
docker exec rchab-test docker pull busybox:latest >/dev/null 2>&1

echo ""
echo "Images before pruning:"
docker exec rchab-test docker images

echo ""
echo "Testing manual prune endpoint..."
PRUNE_RESPONSE=$(curl -s "http://localhost:8080/flyio/v1/prune?since=1h")
echo "${PRUNE_RESPONSE}" | jq . || echo "${PRUNE_RESPONSE}"

echo ""
echo "Images after pruning:"
docker exec rchab-test docker images

echo ""
echo "Storage statistics:"
docker exec rchab-test docker system df 2>/dev/null || true

echo ""
echo "✓ Tier 3.2: Storage and pruning test complete"
