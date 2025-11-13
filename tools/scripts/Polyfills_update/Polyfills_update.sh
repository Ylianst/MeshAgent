#!/bin/bash
# Polyfills Update Demonstration Script
# This script demonstrates how the meshagent -exec command is used to regenerate
# ILibDuktape_Polyfills.c from JavaScript modules
#
# NOTE: This is for demonstration and learning purposes only.
# For actual development, use bin/test-macos-meshagent.sh which includes
# full build, sign, and deployment workflow.

set -e  # Exit on error

# Get the repository root directory (3 levels up from this script)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_DIR="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_DIR"

#==============================================================================
# CONFIGURATION (all relative paths from repo root)
#==============================================================================

MESHAGENT_BINARY="tools/meshagent/macos/meshagent"
MODULES_SOURCE="modules"
MODULES_EXPANDED="tools/test_ILibDuktape_Polyfills/modules_expanded"
OUTPUT_FILE="tools/test_ILibDuktape_Polyfills/ILibDuktape_Polyfills.c"

#==============================================================================
# VALIDATION
#==============================================================================

echo "=========================================="
echo "Polyfills Update Demonstration"
echo "=========================================="
echo ""

# Check if meshagent binary exists
if [ ! -f "$MESHAGENT_BINARY" ]; then
    echo "ERROR: Meshagent binary not found at: $MESHAGENT_BINARY"
    echo ""
    echo "This script requires a minimal meshagent binary to run the -exec command."
    echo "Please ensure the binary exists in tools/meshagent/macos/"
    exit 1
fi

echo "Repository Root: $(pwd)"
echo ""
echo "Configuration:"
echo "  MeshAgent Binary:  $MESHAGENT_BINARY"
echo "  Modules Source:    $MODULES_SOURCE"
echo "  Modules Expanded:  $MODULES_EXPANDED"
echo "  Output File:       $OUTPUT_FILE"
echo ""

#==============================================================================
# STEP 1: CREATE EXPANDED MODULES DIRECTORY
#==============================================================================

echo "[1/3] Creating expanded modules directory..."

# Create the expanded directory if it doesn't exist
mkdir -p "$MODULES_EXPANDED"

echo "  Created: $MODULES_EXPANDED"
echo ""

#==============================================================================
# STEP 2: COPY MODULES
#==============================================================================

echo "[2/3] Copying JavaScript modules..."

# Copy all JS files from modules/ to expanded directory
# Note: In production, this could be filtered by platform
cp "$MODULES_SOURCE"/*.js "$MODULES_EXPANDED/"

MODULE_COUNT=$(ls -1 "$MODULES_EXPANDED"/*.js 2>/dev/null | wc -l)
echo "  Copied $MODULE_COUNT module(s) from $MODULES_SOURCE"
echo ""

#==============================================================================
# STEP 3: REGENERATE POLYFILLS
#==============================================================================

echo "[3/3] Regenerating ILibDuktape_Polyfills.c..."

# This is the key command that demonstrates the -exec functionality
# It runs the meshagent binary with embedded code-utils module to shrink
# all the JS modules into a single C file
"./$MESHAGENT_BINARY" -exec "require('code-utils').shrink({expandedPath: './$MODULES_EXPANDED', filePath: './$OUTPUT_FILE'});process.exit();"

if [ -f "$OUTPUT_FILE" ]; then
    FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
    echo "  Generated: $OUTPUT_FILE ($FILE_SIZE)"
else
    echo "  ERROR: Failed to generate $OUTPUT_FILE"
    exit 1
fi

echo ""

#==============================================================================
# SUMMARY
#==============================================================================

echo "=========================================="
echo "Demonstration Complete!"
echo "=========================================="
echo ""
echo "What this demonstrated:"
echo "  1. The meshagent binary can execute JavaScript code via -exec"
echo "  2. The code-utils module shrinks all JS modules into a C file"
echo "  3. This C file (ILibDuktape_Polyfills.c) is compiled into the binary"
echo ""
echo "The generated file is in:"
echo "  $OUTPUT_FILE"
echo ""
echo "For actual development workflow (build, sign, deploy):"
echo "  sudo ./bin/test-macos-meshagent.sh"
echo ""
echo "=========================================="
