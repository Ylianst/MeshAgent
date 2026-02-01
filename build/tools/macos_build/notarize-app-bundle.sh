#!/bin/bash
# Notarize a single macOS Application Bundle with Apple
# Usage: notarize-app-bundle.sh <bundle_path>
#
# For notarizing multiple bundles in parallel, use notarize-app-bundles.sh instead.
#
# Environment variables:
#   MACOS_NOTARY_PROFILE - Keychain profile name (default: meshagent-notary)
#   SKIP_STAPLE          - Set to "yes" to skip stapling (default: no)

set -e  # Exit on any error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

BUNDLE_PATH="$1"
PROFILE="${MACOS_NOTARY_PROFILE:-meshagent-notary}"
SKIP_STAPLE="${SKIP_STAPLE:-no}"

if [ -z "$BUNDLE_PATH" ]; then
    echo "Usage: $0 <bundle_path>"
    echo ""
    echo "Environment variables:"
    echo "  MACOS_NOTARY_PROFILE - Keychain profile name (default: meshagent-notary)"
    echo "  SKIP_STAPLE          - Set to \"yes\" to skip stapling (default: no)"
    echo ""
    echo "One-time setup:"
    echo "  xcrun notarytool store-credentials meshagent-notary \\"
    echo "    --apple-id \"developer@example.com\" \\"
    echo "    --team-id \"TEAMID\" \\"
    echo "    --password \"app-specific-password\""
    echo ""
    echo "Example:"
    echo "  $0 build/output/MeshAgent.app"
    exit 1
fi

if [ ! -d "$BUNDLE_PATH" ]; then
    echo -e "${RED}Error: Bundle not found: $BUNDLE_PATH${NC}"
    exit 1
fi

# Verify bundle is signed
if ! codesign --verify --deep --strict "$BUNDLE_PATH" 2>/dev/null; then
    echo -e "${RED}Error: Bundle is not properly signed: $BUNDLE_PATH${NC}"
    echo "  Sign the bundle first with sign-app-bundle.sh"
    exit 1
fi

# Verify notary credentials exist
if ! xcrun notarytool history --keychain-profile "$PROFILE" &>/dev/null; then
    echo -e "${RED}Error: Notary profile not found: $PROFILE${NC}"
    echo ""
    echo "Please set up notary credentials with:"
    echo "  xcrun notarytool store-credentials $PROFILE \\"
    echo "    --apple-id \"developer@example.com\" \\"
    echo "    --team-id \"TEAMID\" \\"
    echo "    --password \"app-specific-password\""
    exit 1
fi

echo -e "${CYAN}Notarizing app bundle${NC}"
echo "  Bundle: $BUNDLE_PATH"
echo "  Notary profile: $PROFILE"

# Create temporary directory for ZIP
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

ZIP_NAME="$(basename "$BUNDLE_PATH" .app).zip"
ZIP_PATH="$TEMP_DIR/$ZIP_NAME"

# Create ZIP of bundle
echo ""
echo "Zipping bundle..."
ditto -c -k --keepParent "$BUNDLE_PATH" "$ZIP_PATH"

if [ ! -f "$ZIP_PATH" ]; then
    echo -e "${RED}Error: Failed to create ZIP archive${NC}"
    exit 1
fi

ZIP_SIZE=$(du -h "$ZIP_PATH" | cut -f1)
echo "  Created: $ZIP_NAME ($ZIP_SIZE)"

# Submit to notary service
echo ""
echo "Submitting to Apple notary service..."

SUBMIT_OUTPUT=$(xcrun notarytool submit "$ZIP_PATH" \
    --keychain-profile "$PROFILE" \
    --wait \
    2>&1)

# Check if notarization succeeded
if echo "$SUBMIT_OUTPUT" | grep -q "status: Accepted"; then
    echo -e "  ${GREEN}Accepted${NC}"

    # Staple the notarization ticket to the bundle
    if [ "$SKIP_STAPLE" = "yes" ]; then
        echo ""
        echo -e "${YELLOW}Stapling skipped (SKIP_STAPLE=yes)${NC}"
    else
        echo ""
        echo "Stapling notarization ticket..."
        if xcrun stapler staple "$BUNDLE_PATH" >/dev/null 2>&1; then
            echo -e "  ${GREEN}Stapled: $BUNDLE_PATH${NC}"
        else
            echo -e "${YELLOW}Warning: Failed to staple notarization ticket${NC}"
            echo "  The bundle is notarized but requires internet for Gatekeeper verification"
        fi
    fi

    # Verify with Gatekeeper
    echo ""
    echo "Verifying with Gatekeeper..."
    if spctl -a -vvv -t install "$BUNDLE_PATH" 2>&1; then
        echo -e "  ${GREEN}Verified: $BUNDLE_PATH${NC}"
    else
        echo -e "${YELLOW}Warning: Gatekeeper verification failed for $BUNDLE_PATH${NC}"
    fi

    echo ""
    echo -e "${GREEN}Notarization complete: $BUNDLE_PATH${NC}"
    exit 0

elif echo "$SUBMIT_OUTPUT" | grep -q "status: Invalid"; then
    echo ""
    echo -e "${RED}Error: Notarization rejected by Apple${NC}"
    echo "$SUBMIT_OUTPUT"
    exit 1

else
    echo ""
    echo -e "${RED}Error: Notarization failed with unknown status${NC}"
    echo "$SUBMIT_OUTPUT"
    exit 1
fi
