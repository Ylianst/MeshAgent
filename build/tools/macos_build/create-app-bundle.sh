#!/bin/bash
# Create macOS Application Bundle from binary
# This script takes a standalone binary and packages it into a .app bundle

set -e  # Exit on any error

BINARY_PATH="$1"
BUNDLE_NAME="${2:-MeshAgent.app}"
BUNDLE_ID="${3:-meshagent}"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Generate timestamp atomically (single date call ensures consistency)
eval $("$PROJECT_ROOT/build/tools/generate-build-timestamp.sh")
BUILD_TIMESTAMP_DATE="${4:-$BUILD_DATE}"
BUILD_TIMESTAMP_TIME="${5:-$BUILD_TIME_ONLY}"

if [ -z "$BINARY_PATH" ]; then
    echo "Usage: $0 <binary_path> [bundle_name] [bundle_id] [build_timestamp_date] [build_timestamp_time]"
    echo ""
    echo "Arguments:"
    echo "  binary_path           Path to the compiled meshagent binary (required)"
    echo "  bundle_name           Name of the .app bundle (default: MeshAgent.app)"
    echo "  bundle_id             Bundle identifier (default: meshagent)"
    echo "  build_timestamp_date  Version date (default: current date as yy.mm.dd)"
    echo "  build_timestamp_time  Version time (default: current time as HH.MM.SS)"
    echo ""
    echo "Example:"
    echo "  $0 build/output/meshagent_osx-arm-64 MeshAgent.app com.meshcentral.meshagent 25.11.19 14.30.45"
    exit 1
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Binary not found: $BINARY_PATH"
    exit 1
fi

echo "Creating app bundle: $BUNDLE_NAME"
echo "  Binary: $BINARY_PATH"
echo "  Bundle ID: $BUNDLE_ID"
echo "  Version Date: $BUILD_TIMESTAMP_DATE"
echo "  Version Time: $BUILD_TIMESTAMP_TIME"
echo "  Project root: $PROJECT_ROOT"

# Detect if binary is universal
if lipo -info "$BINARY_PATH" 2>/dev/null | grep -q "Architectures in the fat file"; then
    echo "  Architecture: Universal ($(lipo -info "$BINARY_PATH" | sed 's/.*: //'))"
elif lipo -info "$BINARY_PATH" 2>/dev/null | grep -q "Non-fat file"; then
    ARCH=$(lipo -info "$BINARY_PATH" | sed 's/.*: //')
    echo "  Architecture: $ARCH"
else
    echo "  Architecture: Unknown"
fi

# Create bundle structure
# Standard macOS bundle layout: Contents/{MacOS,Resources}
mkdir -p "$BUNDLE_NAME/Contents/MacOS"
mkdir -p "$BUNDLE_NAME/Contents/Resources"

# Copy binary
cp "$BINARY_PATH" "$BUNDLE_NAME/Contents/MacOS/meshagent"
chmod +x "$BUNDLE_NAME/Contents/MacOS/meshagent"
echo "  Copied binary to Contents/MacOS/meshagent"

# Generate Info.plist using unified generation script
"$PROJECT_ROOT/build/tools/generate-info-plist.sh" \
    --output "$BUNDLE_NAME/Contents/Info.plist" \
    --bundle-id "$BUNDLE_ID" \
    --build-date "$BUILD_TIMESTAMP_DATE" \
    --build-time "$BUILD_TIMESTAMP_TIME" \
    --mode bundle
echo "  Generated Info.plist (date: $BUILD_TIMESTAMP_DATE, time: $BUILD_TIMESTAMP_TIME)"

# Copy icon
ICON_PATH="$PROJECT_ROOT/build/resources/icon/meshagent.icns"
if [ -f "$ICON_PATH" ]; then
    cp "$ICON_PATH" "$BUNDLE_NAME/Contents/Resources/meshagent.icns"
    echo "  Copied icon: meshagent.icns"
else
    echo "  Warning: Icon not found at $ICON_PATH"
    echo "  Bundle will be created without icon"
fi

# Optional: Copy modules if needed
# Uncomment if JavaScript modules should be bundled
# if [ -d "$PROJECT_ROOT/modules" ]; then
#     mkdir -p "$BUNDLE_NAME/Contents/Resources/modules"
#     cp -r "$PROJECT_ROOT/modules/"* "$BUNDLE_NAME/Contents/Resources/modules/"
#     echo "  Copied modules to Contents/Resources/modules/"
# fi

# Create PkgInfo file (optional but recommended for compatibility)
echo -n "APPLMESH" > "$BUNDLE_NAME/Contents/PkgInfo"
echo "  Created PkgInfo"

echo ""
echo "Bundle created successfully: $BUNDLE_NAME"
echo ""
echo "Bundle structure:"
ls -lR "$BUNDLE_NAME" | head -20
echo ""
echo "To test:"
echo "  $BUNDLE_NAME/Contents/MacOS/meshagent --version"
echo ""
echo "To launch:"
echo "  open $BUNDLE_NAME"
echo ""
echo "To install:"
echo "  cp -R $BUNDLE_NAME /Applications/"
