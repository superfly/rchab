#!/bin/bash
set -euo pipefail

echo "=== Tier 1.1: Go Unit Tests ==="
echo ""

# Get repository root (tests are run from tests/ directory)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}/dockerproxy"

echo "Running Go tests..."
go test -v ./...
echo "✓ Go tests passed"

echo ""
echo "Running static analysis (go vet)..."
go vet ./...
echo "✓ go vet passed"

echo ""
echo "Verifying Go modules..."
go mod verify
echo "✓ Go modules verified"

echo ""
echo "✓ Go unit tests complete"
