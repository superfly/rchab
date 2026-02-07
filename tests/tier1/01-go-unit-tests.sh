#!/bin/bash
set -euo pipefail

echo "=== Tier 1.1: Go Unit Tests ==="
echo ""

cd /home/sprite/flyctl/rchab/dockerproxy

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
