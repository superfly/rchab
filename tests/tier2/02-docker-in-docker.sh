#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

echo "=== Tier 2.2: Docker-in-Docker Smoke Test ==="
echo ""

IMAGE="${IMAGE:-flyio/rchab:test}"

# Start container if not running
if ! is_container_running; then
  start_rchab_container "${IMAGE}"
  trap stop_rchab_container EXIT
fi

echo "Test 1: Verify dockerd is running..."
docker exec rchab-test pgrep dockerd >/dev/null
echo "✓ dockerd process is running"

echo ""
echo "Test 2: Docker info..."
docker exec rchab-test docker info | head -10
echo "✓ Docker daemon responding"

echo ""
echo "Test 3: Pull and run a simple container..."
docker exec rchab-test docker pull alpine:3.20 >/dev/null 2>&1
docker exec rchab-test docker run --rm alpine:3.20 echo "Hello from nested Docker" | grep "Hello from nested Docker"
echo "✓ Nested container execution works"

echo ""
echo "Test 4: Build a simple image..."
docker exec rchab-test sh -c 'cat > /tmp/Dockerfile <<EOF
FROM alpine:3.20
RUN echo "test build" > /test.txt
CMD ["cat", "/test.txt"]
EOF'

docker exec rchab-test docker build -t test-build /tmp >/dev/null 2>&1
docker exec rchab-test docker run --rm test-build | grep "test build"
echo "✓ Image build and run works"

echo ""
echo "✓ Tier 2.2: Docker-in-Docker test complete"
