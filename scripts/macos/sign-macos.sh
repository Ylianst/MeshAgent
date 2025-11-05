#!/bin/bash
# Sign macOS binaries for distribution
# Signs all meshagent binaries in build/macos/ directories
#
# Usage:
#   export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
#   ./scripts/macos/sign-macos.sh

set -e  # Exit on error

# Get the repository root directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_DIR="$( cd "$SCRIPT_DIR/../.." && pwd )"

# Check if certificate is specified
if [ -z "$MACOS_SIGN_CERT" ]; then
    echo "Error: MACOS_SIGN_CERT environment variable not set"
    echo ""
    echo "Usage:"
    echo "  export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
    echo "  ./scripts/macos/sign-macos.sh"
    echo ""
    echo "To list available certificates:"
    echo "  security find-identity -v -p codesigning"
    exit 1
fi

BUILD_DIR="$REPO_DIR/build/macos"

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

# Step 1: Sign architecture-specific binaries first
SIGNED_COUNT=0

echo -e "${YELLOW}Step 1: Signing architecture-specific binaries${NC}"
echo ""

# Find and sign only arch-specific binaries (not universal)
ARCH_BINARIES=()
while IFS= read -r -d '' binary; do
    # Skip universal directory binaries in this pass
    if [[ "$binary" != *"/universal/"* ]]; then
        ARCH_BINARIES+=("$binary")
    fi
done < <(find "$BUILD_DIR" -type f \( -name "meshagent" -o -name "DEBUG_meshagent" \) -print0)

for binary in "${ARCH_BINARIES[@]}"; do
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

# Step 2: Rebuild universal binaries from signed arch-specific binaries
if [ -d "$BUILD_DIR/macos-x86-64" ] && [ -d "$BUILD_DIR/macos-arm-64" ]; then
    echo -e "${YELLOW}Step 2: Rebuilding universal binaries from signed slices${NC}"
    echo ""

    mkdir -p "$BUILD_DIR/universal"

    # Rebuild release binary if both arch-specific versions exist
    if [ -f "$BUILD_DIR/macos-x86-64/meshagent" ] && [ -f "$BUILD_DIR/macos-arm-64/meshagent" ]; then
        echo -e "${BLUE}Creating universal binary:${NC} meshagent"
        lipo -create \
            "$BUILD_DIR/macos-x86-64/meshagent" \
            "$BUILD_DIR/macos-arm-64/meshagent" \
            -output "$BUILD_DIR/universal/meshagent"
        echo -e "${GREEN}✓ Universal binary created with signed slices${NC}"

        # Sign the universal binary to ensure consistent top-level signature
        echo -e "${BLUE}Signing universal binary:${NC} meshagent"
        codesign --sign "$MACOS_SIGN_CERT" \
                 --timestamp \
                 --options runtime \
                 --force \
                 "$BUILD_DIR/universal/meshagent"

        if codesign -vvv --deep --strict "$BUILD_DIR/universal/meshagent" 2>&1 | grep -q "satisfies its Designated Requirement"; then
            echo -e "${GREEN}✓ Universal binary signed and verified${NC}"
            SIGNED_COUNT=$((SIGNED_COUNT + 1))
        else
            echo "⚠ Warning: Universal binary signature verification had issues"
        fi
        echo ""

        # Replace the binary inside app bundles with the signed universal binary
        while IFS= read -r -d '' bundle; do
            if [ -f "$bundle/Contents/MacOS/meshagent" ]; then
                echo -e "${BLUE}Updating app bundle with signed binary:${NC} $bundle"
                cp "$BUILD_DIR/universal/meshagent" "$bundle/Contents/MacOS/meshagent"
                echo -e "${GREEN}✓ Signed binary copied into app bundle${NC}"
                echo ""
            fi
        done < <(find "$BUILD_DIR" -name "meshagent.app" -type d -print0)
    fi

    # Rebuild DEBUG binary if both arch-specific versions exist
    if [ -f "$BUILD_DIR/macos-x86-64/DEBUG_meshagent" ] && [ -f "$BUILD_DIR/macos-arm-64/DEBUG_meshagent" ]; then
        echo -e "${BLUE}Creating universal binary:${NC} DEBUG_meshagent"
        lipo -create \
            "$BUILD_DIR/macos-x86-64/DEBUG_meshagent" \
            "$BUILD_DIR/macos-arm-64/DEBUG_meshagent" \
            -output "$BUILD_DIR/universal/DEBUG_meshagent"
        echo -e "${GREEN}✓ Universal DEBUG binary created with signed slices${NC}"

        # Sign the universal binary to ensure consistent top-level signature
        echo -e "${BLUE}Signing universal binary:${NC} DEBUG_meshagent"
        codesign --sign "$MACOS_SIGN_CERT" \
                 --timestamp \
                 --options runtime \
                 --force \
                 "$BUILD_DIR/universal/DEBUG_meshagent"

        if codesign -vvv --deep --strict "$BUILD_DIR/universal/DEBUG_meshagent" 2>&1 | grep -q "satisfies its Designated Requirement"; then
            echo -e "${GREEN}✓ Universal DEBUG binary signed and verified${NC}"
            SIGNED_COUNT=$((SIGNED_COUNT + 1))
        else
            echo "⚠ Warning: Universal DEBUG binary signature verification had issues"
        fi
        echo ""

        # Replace DEBUG binary inside app bundles if they exist
        while IFS= read -r -d '' bundle; do
            if [ -f "$bundle/Contents/MacOS/DEBUG_meshagent" ]; then
                echo -e "${BLUE}Updating app bundle with signed DEBUG binary:${NC} $bundle"
                cp "$BUILD_DIR/universal/DEBUG_meshagent" "$bundle/Contents/MacOS/DEBUG_meshagent"
                echo -e "${GREEN}✓ Signed DEBUG binary copied into app bundle${NC}"
                echo ""
            fi
        done < <(find "$BUILD_DIR" -name "*.app" -type d -print0)
    fi
fi

# Step 3: Sign app bundles if they exist
echo -e "${YELLOW}Step 3: Signing app bundles${NC}"
echo ""

# Find all .app bundles in build directory
APP_BUNDLES=()
while IFS= read -r -d '' bundle; do
    APP_BUNDLES+=("$bundle")
done < <(find "$BUILD_DIR" -name "*.app" -type d -print0)

if [ ${#APP_BUNDLES[@]} -gt 0 ]; then
    for bundle in "${APP_BUNDLES[@]}"; do
        echo -e "${BLUE}Signing app bundle:${NC} $bundle"

        # Sign the bundle deeply (sign all nested code)
        codesign --sign "$MACOS_SIGN_CERT" \
                 --timestamp \
                 --options runtime \
                 --deep \
                 --force \
                 "$bundle"

        # Verify bundle signature
        if codesign -vvv --deep --strict "$bundle" 2>&1 | grep -q "satisfies its Designated Requirement"; then
            echo -e "${GREEN}✓ App bundle signed and verified${NC}"
            SIGNED_COUNT=$((SIGNED_COUNT + 1))
        else
            echo "⚠ Warning: Bundle signature verification had issues"
        fi
        echo ""
    done
else
    echo "No app bundles found to sign"
    echo ""
fi

if [ $SIGNED_COUNT -eq 0 ]; then
    echo "No binaries or bundles found to sign in $BUILD_DIR"
    exit 1
fi

echo -e "${GREEN}Signing complete!${NC}"
echo ""
echo "Next steps for distribution:"
echo "1. Test the signed binaries"
echo "2. Submit to Apple for notarization (see scripts/macos/notarize-macos.sh)"
echo "3. Staple notarization ticket to the binary"
