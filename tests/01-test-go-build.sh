#!/bin/bash
set -euo pipefail

cd /home/sprite/flyctl/rchab/dockerproxy

echo "=== Running Go Tests ==="
go test -v ./...
echo "✓ Go tests passed"

echo ""
echo "=== Verifying Go Module Dependencies ==="
go mod verify
echo "✓ Go modules verified"

echo ""
echo "=== Building Go Binary ==="
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/dockerproxy-test .
ls -lh /tmp/dockerproxy-test
echo "✓ Go binary builds successfully ($(du -h /tmp/dockerproxy-test | cut -f1))"

echo ""
echo "=== Running Static Analysis ==="
go vet ./...
echo "✓ go vet passed"

# Check formatting
if [ -n "$(gofmt -l .)" ]; then
    echo "⚠ Warning: Code formatting issues found:"
    gofmt -l .
else
    echo "✓ Code formatting is correct"
fi

rm -f /tmp/dockerproxy-test
echo ""
echo "✓ Phase 1 complete: Go build verification passed"
