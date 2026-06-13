#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== A2A E2E Test Runner ==="
echo ""

# Generate a test seed for deterministic crypto
TEST_SEED="${KEY_GUARD_SEED:-$(openssl rand -hex 32)}"
export KEY_GUARD_SEED="$TEST_SEED"
echo "Using KEY_GUARD_SEED (first 16 chars): ${TEST_SEED:0:16}..."

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is required for E2E tests"
    exit 1
fi

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    cd "$PROJECT_DIR/tests/e2e"
    docker compose -f docker-compose.e2e.yml down --remove-orphans 2>/dev/null || true
    cd "$PROJECT_DIR"
}

trap cleanup EXIT

# Start services
echo "Starting services (Key Guard + Redis)..."
cd "$PROJECT_DIR/tests/e2e"
docker compose -f docker-compose.e2e.yml up -d --wait
cd "$PROJECT_DIR"

echo ""
echo "Services are healthy. Running tests..."
echo ""

# Install E2E test dependencies if needed
if [ ! -d "tests/e2e/node_modules" ]; then
    echo "Installing E2E test dependencies..."
    cd tests/e2e
    npm install
    cd "$PROJECT_DIR"
fi

# Run E2E tests
cd tests/e2e
npx vitest run --reporter=verbose
EXIT_CODE=$?
cd "$PROJECT_DIR"

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ All E2E tests passed!"
else
    echo "❌ Some E2E tests failed (exit code: $EXIT_CODE)"
fi

exit $EXIT_CODE
