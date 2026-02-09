# rchab Test Suite

Comprehensive test suite for the rchab (Remote Controlled Hot Air Balloon) Docker proxy.

## Overview

The test suite is organized into **3 tiers** for different testing scenarios:

- **Tier 1 (Fast)**: Quick validation for PR checks (2-5 minutes)
- **Tier 2 (Critical)**: Essential integration tests for main branch (10-15 minutes)
- **Tier 3 (Full)**: Complete test suite for releases (30-45 minutes)

## Quick Start

### Run Tests Locally

```bash
# Fast tests (Tier 1)
make test                    # Go unit tests only
cd tests && ./run-tests.sh tier1

# Critical integration tests (Tier 2) - includes API v1.44 compatibility
make test-integration
cd tests && ./run-tests.sh tier2

# Full test suite (Tier 3)
make test-all
cd tests && ./run-tests.sh tier3

# Linting only
make lint
```

### Run Tests in CI

Tests run automatically on GitHub Actions:

- **Pull Requests**: Tier 1 by default (fast feedback)
- **Main branch**: Tier 2 (critical tests including API compatibility)
- **Release tags** (`v*.*.*`): Tier 3 (full validation)

#### Override Test Tier on PRs

To run higher tiers on a PR, add a label:

- **`test:tier2`** - Run critical tests (~15-20 min)
- **`test:tier3`** - Run full suite (~50 min)

Or use **workflow dispatch**:
1. Go to Actions → ci workflow
2. Click "Run workflow"
3. Select your branch and desired tier

## Test Structure

```
tests/
├── lib/
│   └── common.sh              # Shared test functions
├── tier1/                     # Fast checks (2-5 min)
│   ├── 01-go-unit-tests.sh
│   ├── 02-docker-build-verify.sh
│   └── 03-version-check.sh
├── tier2/                     # Critical tests (10-15 min)
│   ├── 01-api-compatibility.sh  # ⭐ CRITICAL: API v1.44
│   ├── 02-docker-in-docker.sh
│   └── 03-endpoint-smoke.sh
├── tier3/                     # Full suite (30-45 min)
│   ├── 01-overlaybd.sh
│   ├── 02-storage-pruning.sh
│   └── 03-integration.sh
├── run-tests.sh               # Smart test runner
└── README.md                  # This file
```

## Test Tiers Explained

### Tier 1: Fast Checks (2-5 minutes)

**Purpose**: Quick validation for every PR to provide fast feedback.

**Tests**:
- `01-go-unit-tests.sh` - Go unit tests, `go vet`, module verification
- `02-docker-build-verify.sh` - Verify Docker image builds successfully
- `03-version-check.sh` - Verify Docker 25.0.5 and API v1.44+

**When it runs**:
- ✅ Every PR (default)
- ✅ Every push to any branch
- ✅ Manual workflow dispatch

### Tier 2: Critical Integration (10-15 minutes)

**Purpose**: Essential integration tests that validate the core functionality.

**Tests**: All of Tier 1, plus:
- `01-api-compatibility.sh` ⭐ **CRITICAL** - Validates Docker API v1.44 support (fixes the buildpacks "client version 1.52 is too new" error)
- `02-docker-in-docker.sh` - Docker daemon operation, nested containers
- `03-endpoint-smoke.sh` - Custom rchab endpoints (`/flyio/v1/*`)

**When it runs**:
- ✅ Every push to `main` branch
- ✅ PRs with `test:tier2` label
- ✅ Manual workflow dispatch

**Why Tier 2 is important**: The API v1.44 compatibility test verifies the **primary objective** of the Docker 25 upgrade - ensuring buildpacks lifecycle tools can communicate with the Docker daemon.

### Tier 3: Full Suite (30-45 minutes)

**Purpose**: Comprehensive validation before releases.

**Tests**: All of Tier 1 & 2, plus:
- `01-overlaybd.sh` - overlaybd image conversion functionality
- `02-storage-pruning.sh` - Disk space management and pruning
- `03-integration.sh` - End-to-end multi-stage builds, networking, volumes

**When it runs**:
- ✅ Release tags (`v*.*.*`)
- ✅ PRs with `test:tier3` label
- ✅ Manual workflow dispatch

## The Critical Test: API v1.44 Compatibility

**Location**: `tier2/01-api-compatibility.sh`

**Why it's critical**: This test validates the fix for the buildpacks error:
```
client version 1.52 is too new. Maximum supported API version is 1.43
```

The Docker 25.0.5 upgrade provides API v1.44, which is required by modern buildpacks lifecycle tools. This test:

1. Verifies the API version endpoint reports `1.44`
2. Tests API v1.44 operations (image list, build)
3. Simulates buildpacks-style API client behavior
4. Confirms Docker build works via API v1.44

**This test runs on every push to main and on releases** to ensure the API compatibility is never broken.

## Writing Tests

### Using the Common Library

All tests should source `lib/common.sh`:

```bash
#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

# Your test code here
```

### Available Helper Functions

```bash
# Container management
start_rchab_container "${IMAGE}"  # Start test container
stop_rchab_container              # Stop and remove test container
is_container_running              # Check if container is running

# Assertions
assert_equals "expected" "actual" "error message"
assert_contains "haystack" "needle" "error message"

# Test tracking
run_test "tier2/01-api-compatibility.sh"  # Run and track test
```

### Test Script Template

```bash
#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

echo "=== Tier X.Y: Test Name ==="
echo ""

IMAGE="${IMAGE:-flyio/rchab:test}"

# Start container if not running
if ! is_container_running; then
  start_rchab_container "${IMAGE}"
  trap stop_rchab_container EXIT
fi

# Your tests here
echo "Test 1: Description..."
# ... test code ...
echo "✓ Test 1 passed"

echo ""
echo "✓ Tier X.Y: Test complete"
```

## CI/CD Integration

### GitHub Actions Workflow

The `.github/workflows/ci.yaml` workflow has 3 jobs:

1. **lint** - Code quality checks (go vet, gofmt)
2. **test** - Run tests based on tier
3. **build** - Build and push Docker image (only if tests pass)

### Job Dependencies

```
lint ─┐
      ├─> build (only on success)
test ─┘
```

The `build` job **requires both `lint` and `test` to pass** before running. This ensures:
- ✅ Code is properly formatted
- ✅ Tests pass
- ✅ Only validated images are pushed

### Caching

The CI uses GitHub Actions cache for:
- Docker build layers (`cache-from: type=gha`)
- Go modules (via `setup-go` action)

This significantly speeds up builds (typically 5-10 minutes vs 15-20 minutes).

## Pre-commit Hooks

Install pre-commit hooks to catch issues before pushing:

```bash
# Install pre-commit (if not already installed)
pip install pre-commit  # or: brew install pre-commit

# Install the git hooks
cd /home/sprite/flyctl/rchab
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

Hooks run automatically on `git commit`:
- Trim trailing whitespace
- Fix end-of-file issues
- Validate YAML syntax
- Run `go mod tidy`
- Run `gofmt` on Go files

## Troubleshooting

### Test Container Won't Start

```bash
# Check if port is already in use
sudo netstat -tlnp | grep -E ':(8080|2375)'

# Stop any existing rchab-test container
docker stop rchab-test && docker rm rchab-test

# Check Docker daemon status
sudo systemctl status docker
```

### API v1.44 Test Fails

```bash
# Check container logs
docker logs rchab-test

# Verify Docker version in container
docker exec rchab-test docker version

# Check API version manually
curl -s http://localhost:8080/v1.44/version | jq .
```

### Tests Pass Locally but Fail in CI

Common causes:
- Image not built (CI builds fresh each time)
- Port conflicts in CI environment
- Timing issues (increase sleep duration)
- Missing dependencies in CI environment

Check the GitHub Actions logs for specific errors.

## Performance Tips

### Speed Up Local Testing

```bash
# Build image once, reuse for tests
docker build -t flyio/rchab:test .
IMAGE=flyio/rchab:test ./run-tests.sh tier2

# Run only changed tests
cd tests && bash tier2/01-api-compatibility.sh

# Use cached Go modules
export GOMODCACHE=/tmp/go-mod-cache
```

### Speed Up CI

- Use appropriate tier (don't run tier3 on every PR)
- Leverage caching (already configured)
- Run tests in parallel where possible (lint and test jobs run concurrently)

## Questions?

See the main rchab [README](../README.md) or [CLAUDE.md](../CLAUDE.md) for architecture details.

For CI/CD questions, see `.github/workflows/ci.yaml`.
