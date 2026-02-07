#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test result tracking
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test script
run_test() {
  local test_script="$1"
  local test_name=$(basename "${test_script}" .sh)

  echo ""
  echo "=========================================="
  echo "Running: ${test_name}"
  echo "=========================================="

  TESTS_RUN=$((TESTS_RUN + 1))

  if bash "${SCRIPT_DIR}/${test_script}"; then
    echo -e "${GREEN}✓ ${test_name} passed${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    echo -e "${RED}✗ ${test_name} failed${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1  # Fail fast
  fi
}

# Function to start rchab container for testing
start_rchab_container() {
  local image="${1:-flyio/rchab:test}"

  echo "Starting rchab container: ${image}"

  docker run -d \
    --privileged \
    --name rchab-test \
    -p 8080:8080 \
    -p 2375:2375 \
    -e NO_AUTH=1 \
    -e NO_APP_NAME=1 \
    -e FLY_APP_NAME=rchab-test \
    -v /tmp/rchab-data:/data \
    --entrypoint /bin/sh \
    "${image}" -c "dockerd &>/var/log/dockerd.log & sleep 5 && /dockerproxy"

  echo "Waiting for services to start (45 seconds)..."
  sleep 45
}

# Function to stop rchab container
stop_rchab_container() {
  docker stop rchab-test 2>/dev/null || true
  docker rm rchab-test 2>/dev/null || true
}

# Function to check if container is running
is_container_running() {
  docker ps --format '{{.Names}}' | grep -q '^rchab-test$'
}

# Assert functions
assert_equals() {
  local expected="$1"
  local actual="$2"
  local message="${3:-Assertion failed}"

  if [ "${expected}" != "${actual}" ]; then
    echo -e "${RED}${message}${NC}"
    echo "  Expected: ${expected}"
    echo "  Actual:   ${actual}"
    return 1
  fi
  return 0
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local message="${3:-String not found}"

  if [[ "${haystack}" != *"${needle}"* ]]; then
    echo -e "${RED}${message}${NC}"
    echo "  Haystack: ${haystack}"
    echo "  Needle:   ${needle}"
    return 1
  fi
  return 0
}
