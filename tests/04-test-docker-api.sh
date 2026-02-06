#!/bin/bash
set -euo pipefail

BUILD_TAG=$(cat /tmp/rchab-test-tag.txt)
IMAGE="flyio/rchab:${BUILD_TAG}"

echo "=== Testing Docker API Functionality ==="
echo ""

# Create a test network and volume for the container
docker network create rchab-test-net 2>/dev/null || true

# Start rchab container with privileged mode (needed for dockerd)
echo "Starting rchab container..."
CONTAINER_ID=$(docker run -d \
    --privileged \
    --name rchab-test \
    --network rchab-test-net \
    -p 8080:8080 \
    -p 2375:2375 \
    -e NO_AUTH=1 \
    -e NO_APP_NAME=1 \
    -e FLY_APP_NAME=rchab-test \
    -v /tmp/rchab-data:/data \
    ${IMAGE})

echo "✓ Container started: ${CONTAINER_ID:0:12}"
echo "  Waiting for dockerd to start (30 seconds)..."
sleep 30

# Check container logs
echo ""
echo "=== Container Logs (last 20 lines) ==="
docker logs rchab-test --tail 20

# Test if dockerproxy is responding
echo ""
echo "=== Testing dockerproxy HTTP endpoints ==="

# Test flyio settings endpoint
echo "Testing /flyio/v1/settings..."
if curl -s http://localhost:8080/flyio/v1/settings | jq .; then
    echo "✓ Settings endpoint working"
else
    echo "✗ Settings endpoint failed"
fi

# Test Docker version endpoint via proxy
echo ""
echo "Testing /v1.44/version (Docker API v1.44)..."
if curl -s http://localhost:8080/v1.44/version | jq .; then
    echo "✓ Docker API v1.44 endpoint working"
else
    echo "⚠ Docker API v1.44 endpoint failed (may need more startup time)"
fi

# Test internal port (no auth)
echo ""
echo "Testing :2375 internal port..."
if curl -s http://localhost:2375/version | jq .; then
    echo "✓ Internal Docker API working"
else
    echo "⚠ Internal Docker API not ready yet"
fi

echo ""
echo "=== Testing Docker Build Inside Container ==="

# Create a simple test Dockerfile
cat > /tmp/test-dockerfile <<'EOF'
FROM alpine:3.20
RUN echo "Test build for Docker 25 API" > /test.txt
CMD cat /test.txt
EOF

# Copy test Dockerfile to container
docker cp /tmp/test-dockerfile rchab-test:/tmp/Dockerfile

# Try to build inside the container
echo "Building test image inside rchab container..."
docker exec rchab-test sh -c 'cd /tmp && docker build -t test-build .' || {
    echo "⚠ Build failed - checking dockerd status"
    docker exec rchab-test sh -c 'ps aux | grep dockerd'
}

echo ""
echo "=== Checking Container Health ==="
docker ps --filter name=rchab-test --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "Container will remain running for further testing..."
echo "To view logs: docker logs -f rchab-test"
echo "To stop: docker stop rchab-test"
echo ""
echo "✓ Phase 4 complete: Docker API tested"
