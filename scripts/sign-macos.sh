#!/bin/bash
# Sign macOS binaries for distribution
# Signs all meshagent binaries in build/macos/ directories
#
# Usage:
#   export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
#   ./scripts/sign-macos.sh

set -e  # Exit on error

# Check if certificate is specified
if [ -z "$MACOS_SIGN_CERT" ]; then
    echo "Error: MACOS_SIGN_CERT environment variable not set"
    echo ""
    echo "Usage:"
    echo "  export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
    echo "  ./scripts/sign-macos.sh"
    echo ""
    echo "To list available certificates:"
    echo "  security find-identity -v -p codesigning"
    exit 1
fi

BUILD_DIR="build/macos"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo "Signing macOS binaries..."
echo -e "${YELLOW}Certificate:${NC} $MACOS_SIGN_CERT"
echo ""

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    echo "Error: $BUILD_DIR directory not found"
    echo "Build binaries first with: make macos ARCHID=29"
    exit 1
fi

# Find all meshagent binaries (including DEBUG versions)
SIGNED_COUNT=0
find "$BUILD_DIR" -type f \( -name "meshagent" -o -name "DEBUG_meshagent" \) | while read binary; do
    if [ -f "$binary" ]; then
        echo -e "${BLUE}Signing:${NC} $binary"

        # Sign with hardened runtime for distribution
        codesign --sign "$MACOS_SIGN_CERT" \
                 --timestamp \
                 --options runtime \
                 --force \
                 "$binary"

        # Verify signature
        if codesign -vvv --deep --strict "$binary" 2>&1 | grep -q "satisfies its Designated Requirement"; then
            echo -e "${GREEN}✓ Successfully signed and verified${NC}"
            SIGNED_COUNT=$((SIGNED_COUNT + 1))
        else
            echo "⚠ Warning: Signature verification had issues"
        fi
        echo ""
    fi
done

if [ $SIGNED_COUNT -eq 0 ]; then
    echo "No binaries found to sign in $BUILD_DIR"
    exit 1
fi

echo -e "${GREEN}Signing complete!${NC}"
echo ""
echo "Next steps for distribution:"
echo "1. Test the signed binaries"
echo "2. Submit to Apple for notarization (see scripts/notarize-macos.sh)"
echo "3. Staple notarization ticket to the binary"
