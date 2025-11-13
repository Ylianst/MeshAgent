#!/bin/bash
# Sign and/or notarize macOS MeshAgent binaries
# Version: 2.0.0
#
# Usage:
#   ./bin/sign-and-notarize-macos.sh <binary_path> [<binary_path2> ...]
#
# Examples:
#   ./bin/sign-and-notarize-macos.sh build/macos/meshagent_osx-universal-64
#   ./bin/sign-and-notarize-macos.sh build/macos/meshagent_osx-arm-64 build/macos/meshagent_osx-x86-64 build/macos/meshagent_osx-universal-64

set -e  # Exit on error

#==============================================================================
# CONFIGURATION - Edit these variables to control what runs
#==============================================================================

# Your Apple Developer certificate name
CERT="Developer ID Application: Your Name (TEAMID)"

# What to run (set to true/false)
DO_SIGN=true           # Code sign the binary
DO_NOTARIZE=true      # Submit to Apple for notarization (requires keychain profile setup)

# Notarization keychain profile name
# Set it up once with:
#   xcrun notarytool store-credentials "meshagent-notary" \
#     --apple-id "developer@example.com" \
#     --team-id "TEAMID" \
#     --password "xxxx-xxxx-xxxx-xxxx"
# Get credentials:
#   - Apple ID: Your Apple Developer account email
#   - Team ID: https://developer.apple.com/account (Membership section)
#   - Password: https://appleid.apple.com → Security → App-Specific Passwords
KEYCHAIN_PROFILE="meshagent-notary"

#==============================================================================
# END CONFIGURATION
#==============================================================================

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

#==============================================================================
# VALIDATE ARGUMENTS
#==============================================================================

if [ $# -eq 0 ]; then
    echo -e "${RED}Error: No binary path(s) provided${NC}"
    echo ""
    echo "Usage: $0 <binary_path> [<binary_path2> ...]"
    echo ""
    echo "Examples:"
    echo "  $0 build/macos/meshagent_osx-universal-64"
    echo "  $0 build/macos/meshagent_osx-x86-64 build/macos/meshagent_osx-arm-64"
    echo "  $0 build/macos/meshagent_osx-*-64"
    exit 1
fi

# Collect all binary paths
BINARIES=("$@")

# Validate all binaries exist before starting
echo -e "${BLUE}====================================${NC}"
echo -e "${BLUE}MeshAgent Sign & Notarize${NC}"
echo -e "${BLUE}====================================${NC}"
echo ""
echo "Validating ${#BINARIES[@]} binary/binaries..."
echo ""

INVALID_COUNT=0
for binary in "${BINARIES[@]}"; do
    if [ ! -f "$binary" ]; then
        echo -e "${RED}✗ Not found: $binary${NC}"
        INVALID_COUNT=$((INVALID_COUNT + 1))
    else
        echo -e "${GREEN}✓ Found: $binary${NC}"
    fi
done

if [ $INVALID_COUNT -gt 0 ]; then
    echo ""
    echo -e "${RED}Error: $INVALID_COUNT binary/binaries not found${NC}"
    exit 1
fi

echo ""

#==============================================================================
# PROCESS EACH BINARY
#==============================================================================

TOTAL_COUNT=${#BINARIES[@]}
SUCCESS_COUNT=0
FAILED_COUNT=0

for BINARY_INDEX in "${!BINARIES[@]}"; do
    BINARY_PATH="${BINARIES[$BINARY_INDEX]}"
    BINARY_NAME=$(basename "$BINARY_PATH")
    BINARY_NUM=$((BINARY_INDEX + 1))

    echo -e "${BLUE}====================================${NC}"
    echo -e "${BLUE}Processing Binary [$BINARY_NUM/$TOTAL_COUNT]${NC}"
    echo -e "${BLUE}====================================${NC}"
    echo "Binary: $BINARY_PATH"
    echo ""

    # Track if this binary succeeds
    BINARY_FAILED=false

    #==========================================================================
    # STEP 1: CODE SIGNING
    #==========================================================================

    if [ "$DO_SIGN" = true ]; then
        echo -e "${YELLOW}[1/2] Code Signing${NC}"
        echo "Certificate: $CERT"
        echo ""

        # Check if certificate is available (only on first binary)
        if [ $BINARY_INDEX -eq 0 ]; then
            if ! security find-identity -v -p codesigning | grep -q "$CERT"; then
                echo -e "${RED}Error: Certificate not found in keychain${NC}"
                echo ""
                echo "Available certificates:"
                security find-identity -v -p codesigning
                exit 1
            fi
        fi

        echo -e "${BLUE}Signing:${NC} $BINARY_NAME"

        # Sign with hardened runtime for distribution
        if codesign --sign "$CERT" \
                 --timestamp \
                 --options runtime \
                 --force \
                 "$BINARY_PATH" 2>&1; then

            # Verify signature
            if codesign -vvv --deep --strict "$BINARY_PATH" 2>&1 | grep -q "satisfies its Designated Requirement"; then
                echo -e "${GREEN}✓ Successfully signed and verified${NC}"
            else
                echo -e "${RED}⚠ Warning: Signature verification had issues${NC}"
                codesign -vvv --deep --strict "$BINARY_PATH" || true
                BINARY_FAILED=true
            fi
        else
            echo -e "${RED}✗ Signing failed${NC}"
            BINARY_FAILED=true
        fi
        echo ""
    else
        echo -e "${YELLOW}[1/2] Code Signing - SKIPPED${NC}"
        echo ""
    fi

    #==========================================================================
    # STEP 2: NOTARIZATION
    #==========================================================================

    if [ "$DO_NOTARIZE" = true ] && [ "$BINARY_FAILED" = false ]; then
        echo -e "${YELLOW}[2/2] Notarization${NC}"
        echo ""

        # Verify keychain profile exists (only on first binary)
        if [ $BINARY_INDEX -eq 0 ]; then
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
            echo ""
        fi

        # Create temporary directory for ZIP
        TEMP_DIR=$(mktemp -d)
        ZIP_PATH="$TEMP_DIR/${BINARY_NAME}.zip"

        echo -e "${BLUE}Creating ZIP archive...${NC}"
        # Change to binary's directory and zip just the file
        BINARY_DIR=$(dirname "$BINARY_PATH")
        BINARY_FILE=$(basename "$BINARY_PATH")
        (cd "$BINARY_DIR" && ditto -c -k "$BINARY_FILE" "$ZIP_PATH")
        echo -e "${GREEN}✓ ZIP created${NC}"
        echo ""

        # Submit to Apple and wait for completion
        echo -e "${BLUE}Submitting to Apple for notarization...${NC}"
        echo "(This may take several minutes)"
        echo ""

        if xcrun notarytool submit "$ZIP_PATH" \
            --keychain-profile "$KEYCHAIN_PROFILE" \
            --wait \
            --timeout 30m; then
            echo ""
            echo -e "${GREEN}✓ Notarization successful${NC}"
        else
            echo ""
            echo -e "${RED}✗ Notarization failed${NC}"
            BINARY_FAILED=true
        fi

        # Cleanup
        rm -rf "$TEMP_DIR"
        echo ""
    elif [ "$DO_NOTARIZE" = true ] && [ "$BINARY_FAILED" = true ]; then
        echo -e "${YELLOW}[2/2] Notarization - SKIPPED (previous step failed)${NC}"
        echo ""
    else
        echo -e "${YELLOW}[2/2] Notarization - SKIPPED${NC}"
        echo ""
    fi

    # Update counters
    if [ "$BINARY_FAILED" = true ]; then
        FAILED_COUNT=$((FAILED_COUNT + 1))
        echo -e "${RED}✗ Binary processing failed: $BINARY_NAME${NC}"
    else
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo -e "${GREEN}✓ Binary processing complete: $BINARY_NAME${NC}"
    fi
    echo ""
done

#==============================================================================
# EXTRACT ARCHITECTURES FROM UNIVERSAL BINARY
#==============================================================================

# After successful notarization, extract individual architectures from universal binary
# and replace the separate arch-specific binaries with the notarized versions
for BINARY_PATH in "${BINARIES[@]}"; do
    BINARY_NAME=$(basename "$BINARY_PATH")

    # Check if this is a universal binary and was successfully processed
    if [[ "$BINARY_NAME" == *"universal"* ]] && [ -f "$BINARY_PATH" ]; then
        BINARY_DIR=$(dirname "$BINARY_PATH")

        # Derive the individual architecture binary names
        X86_BINARY="${BINARY_PATH//universal/x86}"
        ARM_BINARY="${BINARY_PATH//universal/arm}"

        echo -e "${BLUE}====================================${NC}"
        echo -e "${BLUE}Extracting architectures from universal binary${NC}"
        echo -e "${BLUE}====================================${NC}"
        echo ""
        echo "Universal binary: $BINARY_NAME"
        echo "Extracting to:"
        echo "  - $(basename "$X86_BINARY")"
        echo "  - $(basename "$ARM_BINARY")"
        echo ""

        # Extract x86_64 architecture
        if lipo "$BINARY_PATH" -thin x86_64 -output "$X86_BINARY" 2>/dev/null; then
            echo -e "${GREEN}✓ Extracted x86_64 architecture${NC}"
        else
            echo -e "${YELLOW}⚠ Could not extract x86_64 architecture${NC}"
        fi

        # Extract arm64 architecture
        if lipo "$BINARY_PATH" -thin arm64 -output "$ARM_BINARY" 2>/dev/null; then
            echo -e "${GREEN}✓ Extracted arm64 architecture${NC}"
        else
            echo -e "${YELLOW}⚠ Could not extract arm64 architecture${NC}"
        fi

        echo ""
        echo -e "${GREEN}Individual architecture binaries updated from notarized universal binary${NC}"
        echo ""
    fi
done

#==============================================================================
# SUMMARY
#==============================================================================

echo -e "${BLUE}====================================${NC}"
echo -e "${BLUE}Final Summary${NC}"
echo -e "${BLUE}====================================${NC}"
echo ""

echo "Processed: $TOTAL_COUNT binary/binaries"
echo -e "${GREEN}Success:   $SUCCESS_COUNT${NC}"
if [ $FAILED_COUNT -gt 0 ]; then
    echo -e "${RED}Failed:    $FAILED_COUNT${NC}"
fi
echo ""

if [ "$DO_SIGN" = true ]; then
    echo "  ✓ Signed with: $CERT"
fi
if [ "$DO_NOTARIZE" = true ]; then
    echo "  ✓ Notarized using keychain profile: $KEYCHAIN_PROFILE"
fi
echo ""

if [ $FAILED_COUNT -eq 0 ]; then
    echo -e "${GREEN}All binaries ready for distribution!${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}Some binaries failed processing${NC}"
    echo ""
    exit 1
fi
