#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== Starting A2A services ==="
echo "  key-guard  → http://localhost:3000"
echo "  redis      → localhost:6379"
echo ""

docker compose up --build
