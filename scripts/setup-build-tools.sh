#!/bin/bash

#
# setup-build-tools.sh
#
# Sets up build tools required for generating platform-specific polyfills
# This script prepares the compressed-stream shim for Node.js
#

set -e

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory (works even if called from elsewhere)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

echo -e "${GREEN}[Setup]${NC} Setting up build tools for MeshAgent..."

# Create node_modules directory if it doesn't exist
if [ ! -d "$PROJECT_ROOT/node_modules" ]; then
    echo -e "${GREEN}[Setup]${NC} Creating node_modules directory..."
    mkdir -p "$PROJECT_ROOT/node_modules"
fi

# Copy compressed-stream shim to node_modules
echo -e "${GREEN}[Setup]${NC} Installing compressed-stream shim..."
cp "$SCRIPT_DIR/compressed-stream-shim.js" "$PROJECT_ROOT/node_modules/compressed-stream.js"

if [ -f "$PROJECT_ROOT/node_modules/compressed-stream.js" ]; then
    echo -e "${GREEN}[Setup]${NC} ✓ compressed-stream shim installed successfully"
else
    echo -e "${YELLOW}[Setup]${NC} ✗ Failed to install compressed-stream shim"
    exit 1
fi

# Verify Node.js is available
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo -e "${GREEN}[Setup]${NC} ✓ Node.js detected: $NODE_VERSION"
else
    echo -e "${YELLOW}[Setup]${NC} ⚠ Node.js not found. Install Node.js v12+ to use polyfill generation."
    echo -e "${YELLOW}[Setup]${NC}   Visit: https://nodejs.org/"
fi

echo -e "${GREEN}[Setup]${NC} Build tools setup complete!"
echo ""
echo "You can now:"
echo "  • Generate polyfills: make polyfills-darwin (or linux/win32)"
echo "  • Build MeshAgent: make macos ARCHID=universal"
echo ""
