#!/usr/bin/env bash
# macOS Launcher for Python Package Scanner

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BASH_SCRIPT="$SCRIPT_DIR/../main_script/pkg_scan.sh"

# Make sure the target script is executable
chmod +x "$BASH_SCRIPT" 2>/dev/null || true

# Run the scanner
exec bash "$BASH_SCRIPT"
