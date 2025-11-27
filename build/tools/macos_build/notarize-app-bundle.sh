#!/bin/bash
# Notarize macOS Application Bundle with Apple
# This script submits .app bundles to Apple's notary service and staples the ticket

set -e  # Exit on any error

BUNDLE_PATH="$1"
NOTARY_PROFILE="${MACOS_NOTARY_PROFILE:-meshagent-notary}"
SKIP_STAPLE="${SKIP_STAPLE:-no}"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "$BUNDLE_PATH" ]; then
    echo "Usage: $0 <bundle_path>"
    echo ""
    echo "Environment variables:"
    echo "  MACOS_NOTARY_PROFILE - Keychain profile name (default: meshagent-notary)"
    echo ""
    echo "One-time setup (if not done already):"
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
    echo "Error: Bundle not found: $BUNDLE_PATH"
    exit 1
fi

# Verify bundle is signed
if ! codesign --verify --deep --strict "$BUNDLE_PATH" 2>/dev/null; then
    echo "Error: Bundle is not properly signed"
    echo "Please sign the bundle first with sign-app-bundle.sh"
    exit 1
fi

# Verify notary credentials exist
if ! xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" &>/dev/null; then
    echo "Error: Notary profile not found: $NOTARY_PROFILE"
    echo ""
    echo "Please set up notary credentials with:"
    echo "  xcrun notarytool store-credentials $NOTARY_PROFILE \\"
    echo "    --apple-id \"developer@example.com\" \\"
    echo "    --team-id \"TEAMID\" \\"
    echo "    --password \"app-specific-password\""
    echo ""
    echo "App-specific password can be created at: https://appleid.apple.com"
    exit 1
fi

echo "Notarizing macOS application bundle"
echo "  Bundle: $BUNDLE_PATH"
echo "  Notary profile: $NOTARY_PROFILE"

# Create temporary directory for ZIP
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

ZIP_NAME="$(basename "$BUNDLE_PATH" .app).zip"
ZIP_PATH="$TEMP_DIR/$ZIP_NAME"

# Create ZIP of bundle
echo ""
echo "Creating ZIP archive..."
ditto -c -k --keepParent "$BUNDLE_PATH" "$ZIP_PATH"

if [ ! -f "$ZIP_PATH" ]; then
    echo "Error: Failed to create ZIP archive"
    exit 1
fi

ZIP_SIZE=$(du -h "$ZIP_PATH" | cut -f1)
echo "✓ ZIP created: $ZIP_NAME ($ZIP_SIZE)"

# Submit to notary service
echo ""
echo "Submitting to Apple notary service..."
echo "(This may take several minutes - Apple's service will process the bundle)"

SUBMIT_OUTPUT=$(xcrun notarytool submit "$ZIP_PATH" \
    --keychain-profile "$NOTARY_PROFILE" \
    --wait \
    2>&1)

echo "$SUBMIT_OUTPUT"

# Check if notarization succeeded
if echo "$SUBMIT_OUTPUT" | grep -q "status: Accepted"; then
    echo ""
    echo "✓ Notarization succeeded!"

    # Staple the notarization ticket to the bundle (unless skipped)
    if [ "$SKIP_STAPLE" = "yes" ]; then
        echo ""
        echo "Stapling - SKIPPED (SKIP_STAPLE=yes)"
        echo ""
        echo "Note: The bundle is notarized but the ticket is not stapled."
        echo "Users will need internet connection for Gatekeeper to verify."
    else
        echo ""
        echo "Stapling notarization ticket..."
        if xcrun stapler staple "$BUNDLE_PATH"; then
            echo "✓ Notarization ticket stapled successfully"

            # Verify stapling
            echo ""
            echo "Verifying stapled ticket..."
            if xcrun stapler validate "$BUNDLE_PATH"; then
                echo "✓ Stapled ticket is valid"
            else
                echo "⚠ Warning: Staple validation failed"
            fi
        else
            echo "⚠ Warning: Failed to staple notarization ticket"
            echo "The bundle is notarized but the ticket is not attached"
            echo "Users will need internet connection for Gatekeeper to verify"
        fi
    fi

    # Verify with Gatekeeper
    echo ""
    echo "Verifying with Gatekeeper..."
    spctl -a -vvv -t install "$BUNDLE_PATH"

    if [ $? -eq 0 ]; then
        echo "✓ Gatekeeper verification passed"
    else
        echo "⚠ Warning: Gatekeeper verification failed"
    fi

    # Check if bundle is universal and notarize extracted slices
    EXECUTABLE="$BUNDLE_PATH/Contents/MacOS/meshagent"
    if [ -f "$EXECUTABLE" ]; then
        if lipo -info "$EXECUTABLE" 2>/dev/null | grep -q "Architectures in the fat file"; then
            echo ""
            echo "Universal bundle detected - architecture-specific bundles may need separate notarization"

            BUNDLE_DIR="$(dirname "$BUNDLE_PATH")"
            BUNDLE_NAME="$(basename "$BUNDLE_PATH" .app)"

            # Note about extracted bundles
            if [ -d "$BUNDLE_DIR/${BUNDLE_NAME}-x86_64.app" ] || [ -d "$BUNDLE_DIR/${BUNDLE_NAME}-arm64.app" ]; then
                echo ""
                echo "Note: Architecture-specific bundles found"
                echo "These inherit the signature but may need separate notarization if distributed separately"
                echo ""
                echo "To notarize:"
                if [ -d "$BUNDLE_DIR/${BUNDLE_NAME}-x86_64.app" ]; then
                    echo "  $0 $BUNDLE_DIR/${BUNDLE_NAME}-x86_64.app"
                fi
                if [ -d "$BUNDLE_DIR/${BUNDLE_NAME}-arm64.app" ]; then
                    echo "  $0 $BUNDLE_DIR/${BUNDLE_NAME}-arm64.app"
                fi
            fi
        fi
    fi

    echo ""
    echo "Notarization complete: $BUNDLE_PATH"
    echo ""
    echo "The bundle is now:"
    echo "  ✓ Signed with hardened runtime"
    echo "  ✓ Notarized by Apple"
    if [ "$SKIP_STAPLE" = "yes" ]; then
        echo "  ⊘ Not stapled (SKIP_STAPLE=yes, requires internet for verification)"
    else
        echo "  ✓ Stapled (offline verification enabled)"
    fi
    echo "  ✓ Ready for distribution"

    exit 0

elif echo "$SUBMIT_OUTPUT" | grep -q "status: Invalid"; then
    echo ""
    echo "✗ Notarization failed: Invalid"
    echo ""
    echo "The bundle was rejected by Apple's notary service"
    echo "Common reasons:"
    echo "  - Missing or incorrect code signature"
    echo "  - Missing entitlements"
    echo "  - Binary issues or malware detection"
    echo ""
    echo "Check the full output above for details"
    exit 1

else
    echo ""
    echo "✗ Notarization failed with unknown status"
    echo "Check the output above for details"
    exit 1
fi
