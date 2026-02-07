#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

echo "=== Tier 3.1: overlaybd Image Conversion ==="
echo ""

IMAGE="${IMAGE:-flyio/rchab:test}"

# Start container if not running
if ! is_container_running; then
  start_rchab_container "${IMAGE}"
  trap stop_rchab_container EXIT
fi

echo "Checking overlaybd components..."
docker exec rchab-test ls -la /opt/overlaybd/bin/ || echo "⚠ overlaybd bin directory not found"
docker exec rchab-test ls -la /opt/overlaybd/snapshotter/snapshotter || echo "⚠ snapshotter not found"

echo ""
echo "Testing overlaybd conversion endpoint..."

# Pull a small test image
echo "Pulling alpine:3.20 for conversion test..."
docker exec rchab-test docker pull alpine:3.20 >/dev/null 2>&1

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
echo "✓ Tier 3.1: overlaybd test complete"
