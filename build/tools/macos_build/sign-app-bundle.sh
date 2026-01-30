#!/bin/bash
# Sign macOS Application Bundle with hardened runtime
# This script signs .app bundles for distribution

set -e  # Exit on any error

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
    echo "Error: Bundle not found: $BUNDLE_PATH"
    exit 1
fi

if [ -z "$SIGN_CERT" ]; then
    echo "Error: MACOS_SIGN_CERT environment variable not set"
    echo "Please set it to your Developer ID Application certificate identity"
    echo "Example: export MACOS_SIGN_CERT=\"Developer ID Application: Name (TEAMID)\""
    exit 1
fi

echo "Signing macOS application bundle"
echo "  Bundle: $BUNDLE_PATH"
echo "  Certificate: $SIGN_CERT"

# Verify certificate exists in keychain
if ! security find-identity -v -p codesigning | grep -q "$SIGN_CERT"; then
    echo "Error: Certificate not found in keychain: $SIGN_CERT"
    echo ""
    echo "Available certificates:"
    security find-identity -v -p codesigning
    exit 1
fi

# Sign the bundle with hardened runtime
echo ""
echo "Signing bundle..."
codesign --sign "$SIGN_CERT" \
         --options runtime \
         --timestamp \
         --deep \
         --force \
         "$BUNDLE_PATH"

if [ $? -eq 0 ]; then
    echo "✓ Bundle signed successfully"
else
    echo "✗ Signing failed"
    exit 1
fi

# Verify the signature
echo ""
echo "Verifying signature..."
codesign -dvvv --deep --strict "$BUNDLE_PATH" 2>&1 | head -20

if codesign --verify --deep --strict "$BUNDLE_PATH" 2>/dev/null; then
    echo "✓ Signature verification passed"
else
    echo "✗ Signature verification failed"
    exit 1
fi

# Display architecture information
EXE_NAME=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$BUNDLE_PATH/Contents/Info.plist" 2>/dev/null || echo "meshagent")
EXECUTABLE="$BUNDLE_PATH/Contents/MacOS/$EXE_NAME"
if [ -f "$EXECUTABLE" ]; then
    echo ""
    echo "Bundle architecture:"
    lipo -info "$EXECUTABLE"
fi

echo ""
echo "Bundle signing complete: $BUNDLE_PATH"
echo ""
echo "Next steps:"
echo "  1. Notarize: ./build/tools/macos_build/notarize-app-bundle.sh $BUNDLE_PATH"
echo "  2. Verify: spctl -a -vvv -t install $BUNDLE_PATH"
