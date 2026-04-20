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
#
# Bypasses the normal entrypoint (which would require --privileged setup of
# docker-entrypoint.d scripts) and runs dockerd + dockerproxy directly. Then
# polls the Docker API on :2375 until it responds, rather than blind-sleeping.
start_rchab_container() {
  local image="${1:-flyio/rchab:test}"
  local timeout="${RCHAB_READY_TIMEOUT:-60}"

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

  echo "Waiting for rchab to become ready (timeout: ${timeout}s)..."
  local elapsed=0
  until curl -sf --max-time 2 http://127.0.0.1:2375/_ping >/dev/null 2>&1; do
    if ! is_container_running; then
      echo "rchab-test container exited before becoming ready. Logs:" >&2
      docker logs rchab-test 2>&1 | tail -50 >&2 || true
      return 1
    fi
    if (( elapsed >= timeout )); then
      echo "rchab did not respond on :2375 within ${timeout}s. Logs:" >&2
      docker logs rchab-test 2>&1 | tail -50 >&2 || true
      return 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  echo "rchab ready after ${elapsed}s"
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
