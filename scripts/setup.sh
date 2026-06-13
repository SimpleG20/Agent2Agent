#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Setting up A2A project ==="

# Go modules
echo "--- Downloading key-guard dependencies ---"
cd "$PROJECT_DIR/key-guard" && go mod download

echo "--- Downloading sanity-monitor dependencies ---"
cd "$PROJECT_DIR/tools/sanity-monitor" && go mod download

echo "--- Downloading keygen dependencies ---"
cd "$PROJECT_DIR/tools/keygen" && go mod download

# Node modules
echo "--- Installing agent-sdk dependencies ---"
cd "$PROJECT_DIR/agent-sdk" && npm ci

echo ""
echo "=== Setup complete ==="
echo "Run 'scripts/dev.sh' to start all services"
