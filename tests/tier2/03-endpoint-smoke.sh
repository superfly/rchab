#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

echo "=== Tier 2.3: Endpoint Smoke Tests ==="
echo ""

IMAGE="${IMAGE:-flyio/rchab:test}"

# Start container if not running
if ! is_container_running; then
  start_rchab_container "${IMAGE}"
  trap stop_rchab_container EXIT
fi

echo "Testing rchab custom endpoints..."
echo ""

echo "Test 1: /flyio/v1/settings endpoint..."
RESPONSE=$(curl -s http://localhost:8080/flyio/v1/settings)
echo "${RESPONSE}" | jq .
echo "✓ Settings endpoint works"

echo ""
echo "Test 2: Docker proxy endpoint (/_ping)..."
RESPONSE=$(curl -s http://localhost:8080/_ping)
assert_equals "OK" "${RESPONSE}" "Docker ping failed"
echo "✓ Docker proxy works"

echo ""
echo "Test 3: Version endpoint..."
RESPONSE=$(curl -s http://localhost:8080/version)
API_VERSION=$(echo "${RESPONSE}" | jq -r '.ApiVersion')
echo "API Version: ${API_VERSION}"
echo "✓ Version endpoint works"

echo ""
echo "Test 4: /flyio/v1/extendDeadline endpoint..."
RESPONSE=$(curl -s -X POST http://localhost:8080/flyio/v1/extendDeadline)
echo "${RESPONSE}" | jq .
echo "✓ Extend deadline endpoint works"

echo ""
echo "✓ Tier 2.3: Endpoint smoke tests complete"
