#!/bin/bash
# Notarize macOS binaries with Apple
# Automated notarization using xcrun notarytool
#
# Prerequisites:
# - Binaries must be signed first (see sign-macos.sh)
# - Keychain profile must be set up once:
#   xcrun notarytool store-credentials "meshagent-notary" \
#     --apple-id "developer@example.com" \
#     --team-id "TEAMID" \
#     --password "xxxx-xxxx-xxxx-xxxx"
#
# Usage:
#   ./scripts/macos/notarize-macos.sh [OPTIONS]
#
# Options:
#   --parallel    Submit all binaries concurrently (faster but harder to debug)
#   --verbose     Show detailed notarytool output
#   --help        Show this help message

set -e  # Exit on error

#==============================================================================
# CONFIGURATION
#==============================================================================

# Get script directory and repository root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_DIR="$( cd "$SCRIPT_DIR/../.." && pwd )"
BUILD_DIR="$REPO_DIR/build/macos"
TEMP_DIR=$(mktemp -d)

# Keychain profile name (must match what you configured with notarytool store-credentials)
KEYCHAIN_PROFILE="meshagent-notary"

# Processing mode
PARALLEL=false
VERBOSE=false

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

#==============================================================================
# PARSE COMMAND LINE ARGUMENTS
#==============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --parallel)
            PARALLEL=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Notarize macOS binaries with Apple's notarization service"
            echo ""
            echo "Options:"
            echo "  --parallel    Submit all binaries concurrently (faster)"
            echo "  --verbose     Show detailed notarytool output"
            echo "  --help        Show this help message"
            echo ""
            echo "Prerequisites:"
            echo "  1. Binaries must be signed first"
            echo "  2. Set up keychain profile once:"
            echo "     xcrun notarytool store-credentials \"$KEYCHAIN_PROFILE\" \\"
            echo "       --apple-id \"developer@example.com\" \\"
            echo "       --team-id \"TEAMID\" \\"
            echo "       --password \"xxxx-xxxx-xxxx-xxxx\""
            echo ""
            echo "Get credentials:"
            echo "  - APPLE_ID: Your Apple Developer account email"
            echo "  - TEAM_ID: Found at https://developer.apple.com/account"
            echo "  - PASSWORD: App-specific password from https://appleid.apple.com"
            exit 0
            ;;
        *)
            echo "Error: Unknown option $1"
            echo "Run with --help for usage information"
            exit 1
            ;;
    esac
done

#==============================================================================
# VALIDATION
#==============================================================================

echo -e "${BLUE}====================================${NC}"
echo -e "${BLUE}macOS Notarization${NC}"
echo -e "${BLUE}====================================${NC}"
echo ""

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "${RED}Error: Build directory not found: $BUILD_DIR${NC}"
    echo "Build binaries first with: make macos"
    exit 1
fi

# Verify keychain profile exists
if ! xcrun notarytool history --keychain-profile "$KEYCHAIN_PROFILE" &>/dev/null; then
    echo -e "${RED}Error: Keychain profile '$KEYCHAIN_PROFILE' not found${NC}"
    echo ""
    echo "Set up the keychain profile once with:"
    echo ""
    echo "  xcrun notarytool store-credentials \"$KEYCHAIN_PROFILE\" \\"
    echo "    --apple-id \"developer@example.com\" \\"
    echo "    --team-id \"TEAMID\" \\"
    echo "    --password \"xxxx-xxxx-xxxx-xxxx\""
    echo ""
    echo "Get credentials:"
    echo "  - Apple ID: Your Apple Developer account email"
    echo "  - Team ID: https://developer.apple.com/account (Membership section)"
    echo "  - Password: https://appleid.apple.com → Security → App-Specific Passwords"
    echo ""
    exit 1
fi

echo -e "${GREEN}✓ Keychain profile found${NC}"

#==============================================================================
# FIND BINARIES TO NOTARIZE
#==============================================================================

# Find all release binaries (exclude DEBUG builds and binaries inside .app bundles)
BINARIES=()
while IFS= read -r -d '' binary; do
    BINARIES+=("$binary")
done < <(find "$BUILD_DIR" -type f -name "meshagent" ! -name "DEBUG_*" ! -path "*.app/*" -print0)

# Also find app bundles
BUNDLES=()
while IFS= read -r -d '' bundle; do
    BUNDLES+=("$bundle")
done < <(find "$BUILD_DIR" -name "*.app" -type d -print0)

# Combine for reporting
TOTAL_COUNT=$((${#BINARIES[@]} + ${#BUNDLES[@]}))

if [ $TOTAL_COUNT -eq 0 ]; then
    echo -e "${RED}Error: No binaries or bundles found to notarize${NC}"
    echo "Expected to find: build/macos/*/meshagent or build/macos/*/*.app"
    exit 1
fi

echo "Found $TOTAL_COUNT items to notarize:"
for binary in "${BINARIES[@]}"; do
    ARCH=$(echo "$binary" | sed 's|.*/build/macos/\([^/]*\)/.*|\1|')
    echo "  - meshagent ($ARCH) [standalone binary]"
done
for bundle in "${BUNDLES[@]}"; do
    ARCH=$(echo "$bundle" | sed 's|.*/build/macos/\([^/]*\)/.*|\1|')
    echo "  - meshagent.app ($ARCH) [app bundle]"
done
echo ""

#==============================================================================
# NOTARIZATION FUNCTION
#==============================================================================

notarize_binary() {
    local binary="$1"
    local arch=$(echo "$binary" | sed 's|.*/build/macos/\([^/]*\)/.*|\1|')
    local binary_name=$(basename "$binary")

    # Create unique ZIP path
    local zip_path="$TEMP_DIR/${binary_name}-${arch}.zip"

    if [ "$VERBOSE" = false ]; then
        echo -e "${YELLOW}Notarizing: $binary_name ($arch)${NC}"
    else
        echo -e "${YELLOW}=== Notarizing: $binary_name ($arch) ===${NC}"
    fi

    # Create ZIP archive (Apple requires ZIP format)
    # Note: Don't use --keepParent as it creates path mismatches for stapling
    if [ "$VERBOSE" = true ]; then
        echo "Creating ZIP: $zip_path"
    fi

    # Change to binary's directory and zip just the file
    local binary_dir=$(dirname "$binary")
    local binary_file=$(basename "$binary")
    (cd "$binary_dir" && ditto -c -k "$binary_file" "$zip_path")

    # Submit to Apple and wait for completion
    local submit_args=(
        "$zip_path"
        --keychain-profile "$KEYCHAIN_PROFILE"
        --wait
        --timeout 30m
    )

    if [ "$VERBOSE" = false ]; then
        # Suppress notarytool output, only show our messages
        if xcrun notarytool submit "${submit_args[@]}" &>/dev/null; then
            echo -e "${GREEN}✓ Notarization successful: $binary_name ($arch)${NC}"
            rm -f "$zip_path"
            return 0
        else
            echo -e "${RED}✗ Notarization failed: $binary_name ($arch)${NC}"
            echo "  Run with --verbose for detailed output"
            rm -f "$zip_path"
            return 1
        fi
    else
        # Show full notarytool output
        if xcrun notarytool submit "${submit_args[@]}"; then
            echo -e "${GREEN}✓ Notarization successful: $binary_name ($arch)${NC}"
            echo ""
            rm -f "$zip_path"
            return 0
        else
            echo -e "${RED}✗ Notarization failed: $binary_name ($arch)${NC}"
            echo ""
            rm -f "$zip_path"
            return 1
        fi
    fi
}

notarize_bundle() {
    local bundle="$1"
    local arch=$(echo "$bundle" | sed 's|.*/build/macos/\([^/]*\)/.*|\1|')
    local bundle_name=$(basename "$bundle")

    # Create unique ZIP path
    local zip_path="$TEMP_DIR/${bundle_name%.*}-${arch}.zip"

    if [ "$VERBOSE" = false ]; then
        echo -e "${YELLOW}Notarizing: $bundle_name ($arch)${NC}"
    else
        echo -e "${YELLOW}=== Notarizing: $bundle_name ($arch) ===${NC}"
    fi

    # Create ZIP archive of the entire app bundle
    if [ "$VERBOSE" = true ]; then
        echo "Creating ZIP: $zip_path"
    fi

    # Zip the entire app bundle
    ditto -c -k --keepParent "$bundle" "$zip_path"

    # Submit to Apple and wait for completion
    local submit_args=(
        "$zip_path"
        --keychain-profile "$KEYCHAIN_PROFILE"
        --wait
        --timeout 30m
    )

    if [ "$VERBOSE" = false ]; then
        if xcrun notarytool submit "${submit_args[@]}" &>/dev/null; then
            echo -e "${GREEN}✓ Notarization successful: $bundle_name ($arch)${NC}"
            rm -f "$zip_path"
            return 0
        else
            echo -e "${RED}✗ Notarization failed: $bundle_name ($arch)${NC}"
            echo "  Run with --verbose for detailed output"
            rm -f "$zip_path"
            return 1
        fi
    else
        if xcrun notarytool submit "${submit_args[@]}"; then
            echo -e "${GREEN}✓ Notarization successful: $bundle_name ($arch)${NC}"
            echo ""
            rm -f "$zip_path"
            return 0
        else
            echo -e "${RED}✗ Notarization failed: $bundle_name ($arch)${NC}"
            echo ""
            rm -f "$zip_path"
            return 1
        fi
    fi
}

#==============================================================================
# PROCESS BINARIES
#==============================================================================

NOTARIZED_COUNT=0
FAILED_COUNT=0

if [ "$PARALLEL" = true ]; then
    # Parallel mode: Submit all binaries and bundles concurrently
    echo "Mode: Parallel submission"
    echo ""

    # Submit all binaries in background
    PIDS=()
    for binary in "${BINARIES[@]}"; do
        notarize_binary "$binary" &
        PIDS+=($!)
    done

    # Submit all bundles in background
    for bundle in "${BUNDLES[@]}"; do
        notarize_bundle "$bundle" &
        PIDS+=($!)
    done

    # Wait for all background jobs
    for pid in "${PIDS[@]}"; do
        if wait "$pid"; then
            NOTARIZED_COUNT=$((NOTARIZED_COUNT + 1))
        else
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    done
else
    # Sequential mode: Process one at a time
    echo "Mode: Sequential processing"
    echo ""

    # Process standalone binaries first
    for binary in "${BINARIES[@]}"; do
        if notarize_binary "$binary"; then
            NOTARIZED_COUNT=$((NOTARIZED_COUNT + 1))
        else
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    done

    # Process app bundles second
    for bundle in "${BUNDLES[@]}"; do
        if notarize_bundle "$bundle"; then
            NOTARIZED_COUNT=$((NOTARIZED_COUNT + 1))
        else
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    done
fi

#==============================================================================
# CLEANUP
#==============================================================================

rm -rf "$TEMP_DIR"

#==============================================================================
# SUMMARY
#==============================================================================

echo ""
echo -e "${BLUE}====================================${NC}"
echo -e "${BLUE}Notarization Complete${NC}"
echo -e "${BLUE}====================================${NC}"
echo "Successful: $NOTARIZED_COUNT"
echo "Failed:     $FAILED_COUNT"
echo ""

if [ $FAILED_COUNT -gt 0 ]; then
    echo -e "${RED}Some binaries failed notarization${NC}"
    echo "Run with --verbose to see detailed error messages"
    exit 1
fi

echo -e "${GREEN}All binaries notarized successfully!${NC}"
echo ""
echo "Next steps:"
echo "  1. Staple the notarization tickets (done automatically by build-pipeline-macos.sh)"
echo "  2. Verify with: xcrun stapler validate build/macos/*/meshagent"
echo ""
