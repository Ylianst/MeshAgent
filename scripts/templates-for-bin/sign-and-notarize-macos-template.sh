#!/bin/bash
# Personal wrapper for signing/notarizing macOS MeshAgent binaries
# This is a TEMPLATE - copy to /bin/sign-my-macos-binaries.sh and customize
# Version: 0.0.9

set -e  # Exit on error

#==============================================================================
# CONFIGURATION - Edit these variables to control what runs
#==============================================================================

# Your Apple Developer certificate name
CERT="Developer ID Application: Your Name (TEAMID)"

# What to run (set to true/false)
DO_SIGN=true           # Code sign the binaries
DO_NOTARIZE=false      # Submit to Apple for notarization (requires keychain profile setup)
DO_STAPLE=false        # Staple notarization ticket (only works for .app/.pkg/.dmg bundles, not standalone binaries)

# Notarization uses keychain profile "meshagent-notary"
# Set it up once with:
#   xcrun notarytool store-credentials "meshagent-notary" \
#     --apple-id "developer@example.com" \
#     --team-id "TEAMID" \
#     --password "xxxx-xxxx-xxxx-xxxx"
# Get credentials:
#   - Apple ID: Your Apple Developer account email
#   - Team ID: https://developer.apple.com/account (Membership section)
#   - Password: https://appleid.apple.com → Security → App-Specific Passwords

#==============================================================================
# END CONFIGURATION
#==============================================================================

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get script directory
# If running from /bin, repo is parent
# If running from scripts/templates-for-bin, repo is two levels up
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [[ "$SCRIPT_DIR" == */bin ]]; then
    REPO_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"
elif [[ "$SCRIPT_DIR" == */scripts/templates-for-bin ]]; then
    REPO_DIR="$( cd "$SCRIPT_DIR/../.." && pwd )"
else
    REPO_DIR="$SCRIPT_DIR"
fi

echo -e "${BLUE}====================================${NC}"
echo -e "${BLUE}MeshAgent macOS Build Pipeline${NC}"
echo -e "${BLUE}====================================${NC}"
echo ""

# Step 1: Code Signing
if [ "$DO_SIGN" = true ]; then
    echo -e "${YELLOW}[1/3] Code Signing${NC}"
    echo "Certificate: $CERT"
    echo ""

    export MACOS_SIGN_CERT="$CERT"
    "$REPO_DIR/scripts/macos/sign-macos.sh"

    echo ""
else
    echo -e "${YELLOW}[1/3] Code Signing - SKIPPED${NC}"
    echo ""
fi

# Step 2: Notarization
if [ "$DO_NOTARIZE" = true ]; then
    echo -e "${YELLOW}[2/3] Notarization${NC}"
    echo ""

    # Note: Notarization now uses keychain profile (meshagent-notary)
    # Make sure you've set it up once with:
    #   xcrun notarytool store-credentials "meshagent-notary" \
    #     --apple-id "developer@example.com" \
    #     --team-id "TEAMID" \
    #     --password "xxxx-xxxx-xxxx-xxxx"

    "$REPO_DIR/scripts/macos/notarize-macos.sh"

    echo ""
else
    echo -e "${YELLOW}[2/3] Notarization - SKIPPED${NC}"
    echo ""
fi

# Step 3: Stapling
if [ "$DO_STAPLE" = true ]; then
    echo -e "${YELLOW}[3/3] Stapling Notarization Ticket${NC}"
    echo ""

    # Note: Can staple previously-notarized binaries without re-notarizing
    # Find release binaries only (DEBUG binaries are not notarized)
    # Use array to avoid subshell issues
    BINARIES=()
    while IFS= read -r -d '' binary; do
        BINARIES+=("$binary")
    done < <(find "$REPO_DIR/build/macos" -type f -name "meshagent" ! -name "DEBUG_*" -print0)

    for binary in "${BINARIES[@]}"; do
        echo "Stapling: $binary"

        # Attempt to staple (will fail for standalone binaries with Error 73)
        STAPLE_OUTPUT=$(xcrun stapler staple "$binary" 2>&1)
        STAPLE_EXIT=$?

        if [ $STAPLE_EXIT -eq 0 ]; then
            # Stapling succeeded (bundle or package)
            if xcrun stapler validate "$binary" 2>&1 | grep -q "The validate action worked"; then
                echo -e "${GREEN}✓ Successfully stapled${NC}"
            else
                echo -e "${YELLOW}⚠ Stapling completed but validation unclear${NC}"
            fi
        elif echo "$STAPLE_OUTPUT" | grep -q "Error 73"; then
            # Error 73 means standalone binary (expected - not an error)
            echo -e "${YELLOW}⚠ Note: Stapling is not supported for standalone binaries${NC}"
            echo -e "${GREEN}✓ Binary is notarized and will verify online when first run${NC}"
        else
            # Other error
            echo -e "${RED}⚠ Stapling failed with unexpected error${NC}"
            echo "$STAPLE_OUTPUT"
        fi
        echo ""
    done

    echo ""
else
    echo -e "${YELLOW}[3/3] Stapling - SKIPPED${NC}"
    echo ""
fi

echo -e "${GREEN}====================================${NC}"
echo -e "${GREEN}Pipeline Complete!${NC}"
echo -e "${GREEN}====================================${NC}"
echo ""

# Summary
echo "Summary:"
if [ "$DO_SIGN" = true ]; then
    echo "  ✓ Signed with: $CERT"
fi
if [ "$DO_NOTARIZE" = true ]; then
    echo "  ✓ Notarized using keychain profile"
fi
if [ "$DO_STAPLE" = true ]; then
    echo "  ✓ Stapled notarization tickets"
fi
echo ""
echo "Binaries ready in: build/"
