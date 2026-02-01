#!/bin/bash
# Sign macOS Application Bundle with hardened runtime
# Usage: sign-app-bundle.sh <bundle_path>
#
# Environment variables:
#   MACOS_SIGN_CERT - Code signing certificate identity (required)

set -e  # Exit on any error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

BUNDLE_PATH="$1"
SIGN_CERT="${MACOS_SIGN_CERT}"

if [ -z "$BUNDLE_PATH" ]; then
    echo "Usage: $0 <bundle_path>"
    echo ""
    echo "Environment variables:"
    echo "  MACOS_SIGN_CERT - Code signing certificate identity (required)"
    echo "                    Example: \"Developer ID Application: Name (TEAMID)\""
    echo ""
    echo "Example:"
    echo "  export MACOS_SIGN_CERT=\"Developer ID Application: Name (TEAMID)\""
    echo "  $0 build/output/MeshAgent.app"
    exit 1
fi

if [ ! -d "$BUNDLE_PATH" ]; then
    echo -e "${RED}Error: Bundle not found: $BUNDLE_PATH${NC}"
    exit 1
fi

if [ -z "$SIGN_CERT" ]; then
    echo -e "${RED}Error: MACOS_SIGN_CERT environment variable not set${NC}"
    echo "  Example: export MACOS_SIGN_CERT=\"Developer ID Application: Name (TEAMID)\""
    exit 1
fi

echo -e "${CYAN}Signing app bundle${NC}"
echo "  Bundle: $BUNDLE_PATH"
echo "  Certificate: $SIGN_CERT"

# Verify certificate exists in keychain
if ! security find-identity -v -p codesigning | grep -q "$SIGN_CERT"; then
    echo -e "${RED}Error: Certificate not found in keychain: $SIGN_CERT${NC}"
    echo ""
    echo "Available certificates:"
    security find-identity -v -p codesigning
    exit 1
fi

# Sign the bundle with hardened runtime
echo ""
echo "Signing..."
codesign --sign "$SIGN_CERT" \
         --options runtime \
         --timestamp \
         --deep \
         --force \
         "$BUNDLE_PATH"

# Verify the signature
echo "Verifying signature..."
if codesign --verify --deep --strict "$BUNDLE_PATH" 2>/dev/null; then
    echo -e "  ${GREEN}Verified: $BUNDLE_PATH${NC}"
else
    echo -e "${RED}Error: Signature verification failed${NC}"
    exit 1
fi

# Display architecture information
EXE_NAME=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$BUNDLE_PATH/Contents/Info.plist" 2>/dev/null || echo "meshagent")
EXECUTABLE="$BUNDLE_PATH/Contents/MacOS/$EXE_NAME"
if [ -f "$EXECUTABLE" ]; then
    echo "  Architecture: $(lipo -info "$EXECUTABLE" 2>/dev/null | sed 's/.*: //')"
fi

echo ""
echo -e "${GREEN}Signing complete: $BUNDLE_PATH${NC}"
