#!/bin/bash
set -euo pipefail

TIER="${1:-tier1}"  # Default to tier1 if no argument
IMAGE="${2:-flyio/rchab:test}"  # Default to test tag

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

echo "=========================================="
echo "  rchab Test Suite - ${TIER}"
echo "=========================================="
echo ""
echo "Image: ${IMAGE}"
echo ""

# Export IMAGE for sub-scripts
export IMAGE

# Always tear down a running rchab-test container, even if a test fails and
# run_test calls `exit 1` below. Without this trap, `set -e` skips the cleanup
# block and leaves an orphaned container on the host between local runs.
cleanup_on_exit() {
  if is_container_running; then
    echo ""
    echo "Cleaning up test container..."
    stop_rchab_container
  fi
}
trap cleanup_on_exit EXIT

run_tier1_tests() {
  run_test "tier1/01-go-unit-tests.sh"
  run_test "tier1/02-docker-build-verify.sh"
}

run_tier2_tests() {
  run_test "tier2/01-api-compatibility.sh"  # THE CRITICAL TEST
  run_test "tier2/02-docker-in-docker.sh"
  run_test "tier2/03-endpoint-smoke.sh"
}

run_tier3_tests() {
  run_test "tier3/01-overlaybd.sh"
  run_test "tier3/02-storage-pruning.sh"
  run_test "tier3/03-integration.sh"
}

case "${TIER}" in
  tier1)
    echo "Running Tier 1: Fast Checks (2-5 minutes)"
    echo "Tests: Go unit tests, Docker build verification"
    echo ""
    run_tier1_tests
    ;;

  tier2)
    echo "Running Tier 2: Critical Integration (10-15 minutes)"
    echo "Tests: Tier 1 + API v1.44 compatibility, Docker-in-Docker, endpoints"
    echo ""
    run_tier1_tests
    run_tier2_tests
    ;;

  tier3)
    echo "Running Tier 3: Full Suite (30-45 minutes)"
    echo "Tests: All tiers including overlaybd, storage, full integration"
    echo ""
    run_tier1_tests
    run_tier2_tests
    run_tier3_tests
    ;;

  *)
    echo "Error: Unknown tier '${TIER}'"
    echo "Usage: $0 [tier1|tier2|tier3] [image]"
    exit 1
    ;;
esac

echo ""
echo "=========================================="
echo "✅ All ${TIER} tests passed!"
echo "=========================================="
echo ""
echo "Tests run: ${TESTS_RUN}"
echo "Tests passed: ${TESTS_PASSED}"
echo "Tests failed: ${TESTS_FAILED}"
echo ""

if [ "${TIER}" == "tier1" ]; then
  echo "💡 Tip: Run 'make test-integration' for critical tests (tier2)"
  echo "💡 Tip: Run 'make test-all' for the full test suite (tier3)"
fi
