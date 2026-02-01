#!/bin/bash
# Example: Populate ILibDuktape_Polyfills.c using meshagent_code-utils
#
# This shows why the code-utils binary exists. MeshAgent embeds compressed
# JavaScript modules directly into the C source file ILibDuktape_Polyfills.c.
# The code-utils binary is a minimal MeshAgent build (8 modules, no KVM) whose
# sole purpose is running the -import command to compress and embed modules.
#
# The makefile and build scripts handle this automatically during the build
# process. This script is a standalone example for manual use.
#
# Usage:
#   ./example-populate-polyfills.sh                    # Embed all modules (for Linux/BSD/Windows builds)
#   ./example-populate-polyfills.sh ./modules_macos    # Embed macOS-only modules

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

CODE_UTILS="$SCRIPT_DIR/macos/meshagent_code-utils"
MODULES_DIR="${1:-$REPO_ROOT/modules}"
POLYFILLS="$REPO_ROOT/microscript/ILibDuktape_Polyfills.c"

if [ ! -f "$CODE_UTILS" ]; then
    echo "Error: meshagent_code-utils not found at $CODE_UTILS"
    echo ""
    echo "Build it with:"
    echo "  make macos ARCHID=10005 KVM=0"
    echo "  cp build/output/meshagent_osx-universal-64 $CODE_UTILS"
    exit 1
fi

if [ ! -d "$MODULES_DIR" ]; then
    echo "Error: Modules directory not found: $MODULES_DIR"
    exit 1
fi

MODULE_COUNT=$(find "$MODULES_DIR" -name "*.js" -type f | wc -l | tr -d ' ')

echo "Embedding $MODULE_COUNT modules from $MODULES_DIR"
echo "  into $POLYFILLS"
echo ""

# This is the key command — everything else is just validation
"$CODE_UTILS" -import \
    --expandedPath="$MODULES_DIR" \
    --filePath="$POLYFILLS"

echo ""
echo "Done. Commit ILibDuktape_Polyfills.c to include updated modules in builds."
