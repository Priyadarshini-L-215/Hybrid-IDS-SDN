#!/bin/bash
# Sentinel Core - WSL-Only Launcher
# Use this to run just the IDS pipeline in WSL without starting the UI
# Usage: bash start_wsl_only.sh [--legacy]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_DIR}"
USE_REDIS_QUEUE="${USE_REDIS_QUEUE:-1}"

# Parse command line arguments
if [ "$1" = "--legacy" ]; then
    USE_REDIS_QUEUE=0
fi

if [ ! -d "$PROJECT_ROOT" ]; then
    echo "[ERROR] PROJECT_ROOT '$PROJECT_ROOT' does not exist."
    exit 1
fi

cd "$PROJECT_ROOT"

echo "================================================"
echo "  Sentinel Core - WSL-Only Pipeline"
echo "================================================"
if [ "$USE_REDIS_QUEUE" = "1" ]; then
    echo "  Mode: Redis Queue Pipeline (Optimized)"
else
    echo "  Mode: Legacy Polling (Compatibility)"
fi
echo "================================================"
echo

# Run the WSL startup script
bash "$SCRIPT_DIR/start_ids.sh"
