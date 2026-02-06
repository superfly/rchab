#!/bin/bash
set -euo pipefail

echo "=========================================="
echo "  rchab Docker 25 Upgrade Test Suite"
echo "=========================================="
echo ""
echo "This will run all test phases sequentially."
echo "Estimated time: 45-60 minutes"
echo ""
read -p "Press Enter to continue..."

TEST_DIR="/home/sprite/flyctl/rchab/tests"
RESULTS_FILE="/tmp/rchab-test-results.txt"

# Create tests directory
mkdir -p "${TEST_DIR}"
cd "${TEST_DIR}"

# Initialize results
echo "rchab Docker 25 Test Results - $(date)" > "${RESULTS_FILE}"
echo "========================================" >> "${RESULTS_FILE}"
echo "" >> "${RESULTS_FILE}"

# Array of test scripts
declare -a TESTS=(
    "00-setup-environment"
    "01-test-go-build"
    "02-build-docker-image"
    "03-verify-versions"
    "04-test-docker-api"
    "05-test-buildpacks-api"
    "06-test-overlaybd"
    "07-test-storage-pruning"
    "08-test-integration"
)

PASSED=0
FAILED=0
SKIPPED=0

# Run each test
for test in "${TESTS[@]}"; do
    echo ""
    echo "=========================================="
    echo "Running: ${test}.sh"
    echo "=========================================="
    echo ""

    if [ -f "${test}.sh" ]; then
        START_TIME=$(date +%s)

        if bash "${test}.sh" 2>&1 | tee "/tmp/${test}.log"; then
            END_TIME=$(date +%s)
            DURATION=$((END_TIME - START_TIME))
            echo "✓ ${test} - PASSED (${DURATION}s)" >> "${RESULTS_FILE}"
            ((PASSED++))
            echo ""
            echo "✓ ${test} completed successfully"
        else
            END_TIME=$(date +%s)
            DURATION=$((END_TIME - START_TIME))
            echo "✗ ${test} - FAILED (${DURATION}s)" >> "${RESULTS_FILE}"
            ((FAILED++))
            echo ""
            echo "✗ ${test} FAILED"
            read -p "Continue with remaining tests? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                break
            fi
        fi
    else
        echo "⚠ ${test} - SKIPPED (script not found)" >> "${RESULTS_FILE}"
        ((SKIPPED++))
        echo "⚠ Script not found: ${test}.sh"
    fi

    sleep 2
done

# Final cleanup
echo ""
echo "=========================================="
echo "  Cleaning Up"
echo "=========================================="
docker stop rchab-test 2>/dev/null || true
docker rm rchab-test 2>/dev/null || true
docker network rm rchab-test-net 2>/dev/null || true

# Print summary
echo "" >> "${RESULTS_FILE}"
echo "========================================" >> "${RESULTS_FILE}"
echo "Summary:" >> "${RESULTS_FILE}"
echo "  Passed: ${PASSED}" >> "${RESULTS_FILE}"
echo "  Failed: ${FAILED}" >> "${RESULTS_FILE}"
echo "  Skipped: ${SKIPPED}" >> "${RESULTS_FILE}"
echo "========================================" >> "${RESULTS_FILE}"

echo ""
echo "=========================================="
echo "  Test Summary"
echo "=========================================="
cat "${RESULTS_FILE}"
echo ""
echo "Full results saved to: ${RESULTS_FILE}"
echo "Individual test logs in: /tmp/*.log"
echo ""

if [ ${FAILED} -eq 0 ]; then
    echo "✓ ALL TESTS PASSED!"
    echo ""
    echo "Next steps:"
    echo "  1. Review test results"
    echo "  2. Commit changes to git"
    echo "  3. Push to GitHub (CI will build and push image)"
    echo "  4. Deploy to staging: fly orgs builder update <org> <image>"
    exit 0
else
    echo "✗ SOME TESTS FAILED"
    echo "Review logs and fix issues before proceeding"
    exit 1
fi
