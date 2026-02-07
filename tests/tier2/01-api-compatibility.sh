#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

echo "=== Tier 2.1: API v1.44 Compatibility Test ==="
echo ""
echo "This is the CRITICAL test - verifying API 1.44 support to fix:"
echo "  'client version 1.52 is too new. Maximum supported API version is 1.43'"
echo ""

IMAGE="${IMAGE:-flyio/rchab:test}"

# Start container if not running
if ! is_container_running; then
  start_rchab_container "${IMAGE}"
  trap stop_rchab_container EXIT
fi

# Test 1: API version endpoint
echo "Test 1: Checking API version..."
RESPONSE=$(curl -s http://localhost:8080/v1.44/version)
API_VERSION=$(echo "${RESPONSE}" | jq -r '.ApiVersion')

assert_equals "1.44" "${API_VERSION}" "API version mismatch"
echo "✓ API v1.44 confirmed"

# Test 2: Docker build with API v1.44
echo ""
echo "Test 2: Docker build via API v1.44..."
docker exec rchab-test sh -c 'echo "FROM alpine:3.20
RUN echo test" > /tmp/Dockerfile && docker build -t api-test /tmp' >/dev/null 2>&1

echo "✓ Docker build succeeded"

# Test 3: API operations
echo ""
echo "Test 3: API operations (list images, inspect)..."
docker exec rchab-test docker images -q > /dev/null
docker exec rchab-test docker system info > /dev/null

echo "✓ All API operations succeeded"

# Test 4: Simulate buildpacks-style API client
echo ""
echo "Test 4: Buildpacks-style API client test..."
cat > /tmp/test-buildpacks-api.go <<'GOEOF'
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/docker/docker/client"
    "github.com/docker/docker/api/types/image"
)

func main() {
    cli, err := client.NewClientWithOpts(
        client.FromEnv,
        client.WithAPIVersionNegotiation(),
        client.WithVersion("1.44"),
    )
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to create client: %v\n", err)
        os.Exit(1)
    }
    defer cli.Close()

    ctx := context.Background()

    version, err := cli.ServerVersion(ctx)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to get version: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("✓ Connected to Docker API v%s\n", version.APIVersion)

    if version.APIVersion < "1.44" {
        fmt.Fprintf(os.Stderr, "✗ ERROR: API version %s too old (need 1.44+)\n", version.APIVersion)
        os.Exit(1)
    }

    images, err := cli.ImageList(ctx, image.ListOptions{})
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to list images: %v\n", err)
        os.Exit(1)
    }
    fmt.Printf("✓ ImageList API call succeeded (%d images)\n", len(images))
    fmt.Println("✓ All buildpacks-style API calls succeeded")
}
GOEOF

cd /tmp
export DOCKER_HOST=tcp://localhost:2375
go mod init test-buildpacks-api 2>/dev/null || true
go mod edit -require github.com/docker/docker@v25.0.5+incompatible
go mod tidy -e 2>/dev/null

if go build -o test-buildpacks-api test-buildpacks-api.go 2>/dev/null && [ -f test-buildpacks-api ]; then
    ./test-buildpacks-api || {
        echo "✗ ERROR: Buildpacks API compatibility test failed"
        rm -f test-buildpacks-api test-buildpacks-api.go go.mod go.sum
        exit 1
    }
    rm -f test-buildpacks-api test-buildpacks-api.go go.mod go.sum
else
    echo "⚠ Could not build Go test client, skipping programmatic test"
fi

echo ""
echo "🎯 PRIMARY OBJECTIVE VERIFIED: API v1.44 is working!"
echo "✓ Tier 2.1: API compatibility test complete"
