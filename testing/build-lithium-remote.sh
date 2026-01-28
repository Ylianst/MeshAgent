#!/bin/bash
#
# Build LithiumRemote universal macOS app bundle
# Output: ./testing/build/LithiumRemote/LithiumRemote.app
#
# Required environment variables:
#   MACOS_SIGN_CERT      - Code signing certificate identity (required for signing)
#   MACOS_NOTARY_PROFILE - Keychain profile for notarization (default: meshagent-notary)
#
# By default, the script signs, notarizes, and staples the app bundle.
# Use --adhoc to skip signing/notarization for local testing only.
#
# Usage:
#   ./testing/build-lithium-remote.sh [options]
#
# Options:
#   --adhoc             Ad-hoc sign only (skip Developer ID signing and notarization)
#   --sign-only         Sign but skip notarization
#   --skip-build        Skip build, just sign/notarize existing bundle
#   --clean             Clean before building
#   --arm64-only        Build ARM64 only
#   --x86-only          Build x86_64 only
#

set -e

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/build/LithiumRemote"

# App naming
APP_NAME="LithiumRemote"
BINARY_NAME="lithium-remote"
BUNDLE_ID="com.lithiumbridge.remote"

# Custom icon (must exist before running, or will use default)
CUSTOM_ICON="$OUTPUT_DIR/AppIcon.icns"

# Parse arguments
ARCH_MODE="universal"
DO_CLEAN="no"
DO_SIGN="yes"
DO_NOTARIZE="yes"
SKIP_BUILD="no"

while [[ $# -gt 0 ]]; do
    case $1 in
        --adhoc)
            DO_SIGN="no"
            DO_NOTARIZE="no"
            shift
            ;;
        --sign-only)
            DO_SIGN="yes"
            DO_NOTARIZE="no"
            shift
            ;;
        --skip-build)
            SKIP_BUILD="yes"
            shift
            ;;
        --arm64-only)
            ARCH_MODE="arm64"
            shift
            ;;
        --x86-only)
            ARCH_MODE="x86"
            shift
            ;;
        --clean)
            DO_CLEAN="yes"
            shift
            ;;
        -h|--help)
            head -20 "$0" | tail -18
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Determine arch suffix for filenames
case $ARCH_MODE in
    universal) ARCH_SUFFIX="osx-universal-64" ;;
    arm64)     ARCH_SUFFIX="osx-arm-64" ;;
    x86)       ARCH_SUFFIX="osx-x86-64" ;;
esac

BUNDLE_PATH="$OUTPUT_DIR/$APP_NAME.app"
NOTARY_PROFILE="${MACOS_NOTARY_PROFILE:-meshagent-notary}"

# Check signing certificate if needed
if [ "$DO_SIGN" = "yes" ]; then
    if [ -z "$MACOS_SIGN_CERT" ]; then
        echo "Error: MACOS_SIGN_CERT environment variable not set"
        echo ""
        echo "Available certificates:"
        security find-identity -v -p codesigning | grep "Developer ID" || echo "  (none found)"
        exit 1
    fi

    if ! security find-identity -v -p codesigning | grep -q "$MACOS_SIGN_CERT"; then
        echo "Error: Certificate not found in keychain: $MACOS_SIGN_CERT"
        exit 1
    fi
fi

# Check notary profile if needed
if [ "$DO_NOTARIZE" = "yes" ]; then
    if ! xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" &>/dev/null; then
        echo "Error: Notary profile not found: $NOTARY_PROFILE"
        echo ""
        echo "Set up with:"
        echo "  xcrun notarytool store-credentials $NOTARY_PROFILE \\"
        echo "    --apple-id \"you@example.com\" --team-id \"TEAMID\" --password \"app-specific-password\""
        exit 1
    fi
fi

echo "=============================================="
echo "Building $APP_NAME"
echo "=============================================="
echo ""
echo "Architecture:    $ARCH_MODE"
echo "Output:          $OUTPUT_DIR"
echo "Sign:            $([ "$DO_SIGN" = "yes" ] && echo "$MACOS_SIGN_CERT" || echo "ad-hoc")"
echo "Notarize:        $([ "$DO_NOTARIZE" = "yes" ] && echo "$NOTARY_PROFILE" || echo "no")"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build phase
if [ "$SKIP_BUILD" = "no" ]; then
    # Check for custom icon
    if [ -f "$CUSTOM_ICON" ]; then
        echo "Custom icon:     found"
    else
        echo "Custom icon:     not found (using default)"
    fi
    echo ""

    cd "$PROJECT_ROOT"

    if [ "$DO_CLEAN" = "yes" ]; then
        echo "Cleaning..."
        make clean
        echo ""
    fi

    echo "Building..."
    echo ""

    case $ARCH_MODE in
        universal)
            make macos ARCHID=10005 BUNDLE_ID="$BUNDLE_ID"
            BUILT_BUNDLE="$PROJECT_ROOT/build/output/osx-universal-64-app/MeshAgent.app"
            BUILT_BINARY="$PROJECT_ROOT/build/output/meshagent_osx-universal-64"
            ;;
        arm64)
            make macos ARCHID=29 BUNDLE_ID="$BUNDLE_ID"
            BUILT_BUNDLE="$PROJECT_ROOT/build/output/osx-arm-64-app/MeshAgent.app"
            BUILT_BINARY="$PROJECT_ROOT/build/output/meshagent_osx-arm-64"
            ;;
        x86)
            make macos ARCHID=16 BUNDLE_ID="$BUNDLE_ID"
            BUILT_BUNDLE="$PROJECT_ROOT/build/output/osx-x86-64-app/MeshAgent.app"
            BUILT_BINARY="$PROJECT_ROOT/build/output/meshagent_osx-x86-64"
            ;;
    esac

    if [ ! -d "$BUILT_BUNDLE" ]; then
        echo "Error: Build failed - bundle not found: $BUILT_BUNDLE"
        exit 1
    fi

    echo ""
    echo "Build complete: $BUILT_BUNDLE"

    # Remove old app bundle
    rm -rf "$BUNDLE_PATH"

    # Copy bundle with new name
    echo ""
    echo "Creating $APP_NAME.app..."
    cp -R "$BUILT_BUNDLE" "$BUNDLE_PATH"

    # Rename binary
    echo "Renaming binary to $BINARY_NAME..."
    mv "$BUNDLE_PATH/Contents/MacOS/meshagent" "$BUNDLE_PATH/Contents/MacOS/$BINARY_NAME"

    # Update Info.plist
    echo "Updating Info.plist..."
    PLIST="$BUNDLE_PATH/Contents/Info.plist"

    /usr/libexec/PlistBuddy -c "Set :CFBundleExecutable $BINARY_NAME" "$PLIST"
    /usr/libexec/PlistBuddy -c "Set :CFBundleName $APP_NAME" "$PLIST"
    /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $BUNDLE_ID" "$PLIST" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string $BUNDLE_ID" "$PLIST"
    /usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName $APP_NAME" "$PLIST" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :CFBundleDisplayName string $APP_NAME" "$PLIST"
    /usr/libexec/PlistBuddy -c "Set :CFBundleSignature LiRD" "$PLIST" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :CFBundleSignature string LiRD" "$PLIST"
    /usr/libexec/PlistBuddy -c "Set :LSApplicationCategoryType public.app-category.utilities" "$PLIST" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :LSApplicationCategoryType string public.app-category.utilities" "$PLIST"
    /usr/libexec/PlistBuddy -c "Set :LSBackgroundOnly false" "$PLIST" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :LSBackgroundOnly bool false" "$PLIST"
    /usr/libexec/PlistBuddy -c "Set :LSUIElement true" "$PLIST" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :LSUIElement bool true" "$PLIST"
    /usr/libexec/PlistBuddy -c "Set :LSMinimumSystemVersion 10.13" "$PLIST" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :LSMinimumSystemVersion string 10.13" "$PLIST"
    /usr/libexec/PlistBuddy -c "Add :LSEnvironment dict" "$PLIST" 2>/dev/null || true
    /usr/libexec/PlistBuddy -c "Set :LSEnvironment:LAUNCHED_FROM_FINDER 1" "$PLIST" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :LSEnvironment:LAUNCHED_FROM_FINDER string 1" "$PLIST"

    # Install custom icon
    if [ -f "$CUSTOM_ICON" ]; then
        echo "Installing custom icon..."
        cp "$CUSTOM_ICON" "$BUNDLE_PATH/Contents/Resources/AppIcon.icns"
        xattr -cr "$BUNDLE_PATH/Contents/Resources/AppIcon.icns"
        /usr/libexec/PlistBuddy -c "Set :CFBundleIconFile AppIcon.icns" "$PLIST" 2>/dev/null || \
            /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string AppIcon.icns" "$PLIST"
        rm -f "$BUNDLE_PATH/Contents/Resources/meshagent.icns"
    fi

    # Copy standalone binary
    echo "Copying standalone binary..."
    cp "$BUILT_BINARY" "$OUTPUT_DIR/${BINARY_NAME}_${ARCH_SUFFIX}"
fi

# Verify bundle exists
if [ ! -d "$BUNDLE_PATH" ]; then
    echo "Error: Bundle not found: $BUNDLE_PATH"
    exit 1
fi

# Strip extended attributes
echo "Stripping extended attributes..."
xattr -cr "$BUNDLE_PATH"

# Signing
echo ""
echo "=============================================="
echo "Signing"
echo "=============================================="
echo ""

if [ "$DO_SIGN" = "yes" ]; then
    echo "Signing with: $MACOS_SIGN_CERT"
    codesign --sign "$MACOS_SIGN_CERT" \
             --options runtime \
             --timestamp \
             --deep \
             --force \
             "$BUNDLE_PATH"

    # Sign standalone binary too
    if [ -f "$OUTPUT_DIR/${BINARY_NAME}_${ARCH_SUFFIX}" ]; then
        codesign --sign "$MACOS_SIGN_CERT" \
                 --options runtime \
                 --timestamp \
                 --force \
                 "$OUTPUT_DIR/${BINARY_NAME}_${ARCH_SUFFIX}"
    fi
else
    echo "Ad-hoc signing..."
    codesign -s - --deep --force "$BUNDLE_PATH"
    if [ -f "$OUTPUT_DIR/${BINARY_NAME}_${ARCH_SUFFIX}" ]; then
        codesign -s - --force "$OUTPUT_DIR/${BINARY_NAME}_${ARCH_SUFFIX}"
    fi
fi

echo "Verifying signature..."
if codesign --verify --deep --strict "$BUNDLE_PATH" 2>/dev/null; then
    echo "Signature verification passed"
else
    echo "Error: Signature verification failed"
    exit 1
fi

# Notarization
if [ "$DO_NOTARIZE" = "yes" ]; then
    echo ""
    echo "=============================================="
    echo "Notarizing"
    echo "=============================================="
    echo ""

    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT

    ZIP_PATH="$TEMP_DIR/$APP_NAME.zip"
    echo "Creating ZIP for notarization..."
    ditto -c -k --keepParent "$BUNDLE_PATH" "$ZIP_PATH"

    echo "Submitting to Apple notary service..."
    echo "(This may take several minutes)"
    echo ""

    SUBMIT_OUTPUT=$(xcrun notarytool submit "$ZIP_PATH" \
        --keychain-profile "$NOTARY_PROFILE" \
        --wait \
        2>&1)

    echo "$SUBMIT_OUTPUT"

    if echo "$SUBMIT_OUTPUT" | grep -q "status: Accepted"; then
        echo ""
        echo "Notarization succeeded!"

        echo ""
        echo "Stapling notarization ticket..."
        if xcrun stapler staple "$BUNDLE_PATH"; then
            echo "Ticket stapled successfully"

            echo "Validating staple..."
            xcrun stapler validate "$BUNDLE_PATH"
        else
            echo "Warning: Failed to staple ticket"
        fi
    else
        echo ""
        echo "Error: Notarization failed"
        exit 1
    fi
fi

# Create distributable ZIP
echo ""
echo "Creating distributable ZIP..."
rm -f "$OUTPUT_DIR/$APP_NAME.zip"
(cd "$OUTPUT_DIR" && ditto -c -k --keepParent "$APP_NAME.app" "$APP_NAME.zip")

# Verification
echo ""
echo "=============================================="
echo "Verification"
echo "=============================================="
echo ""

if [ "$DO_SIGN" = "yes" ]; then
    echo "Gatekeeper check:"
    spctl -a -vvv -t install "$BUNDLE_PATH" 2>&1 | head -5
    echo ""
fi

echo "Architecture:"
lipo -info "$BUNDLE_PATH/Contents/MacOS/$BINARY_NAME"

echo ""
echo "Version:"
"$BUNDLE_PATH/Contents/MacOS/$BINARY_NAME" -fullversion 2>/dev/null || echo "N/A"

# Summary
echo ""
echo "=============================================="
echo "Build complete!"
echo "=============================================="
echo ""
echo "Output: $OUTPUT_DIR"
echo ""
ls -la "$OUTPUT_DIR"
echo ""
echo "App Info:"
echo "  Name:       $(/usr/libexec/PlistBuddy -c "Print :CFBundleName" "$BUNDLE_PATH/Contents/Info.plist")"
echo "  Identifier: $(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$BUNDLE_PATH/Contents/Info.plist")"
echo "  Executable: $(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$BUNDLE_PATH/Contents/Info.plist")"
echo "  Signed:     $([ "$DO_SIGN" = "yes" ] && echo "Developer ID" || echo "ad-hoc")"
echo "  Notarized:  $([ "$DO_NOTARIZE" = "yes" ] && echo "yes (stapled)" || echo "no")"
echo ""
