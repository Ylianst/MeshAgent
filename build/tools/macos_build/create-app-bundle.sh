#!/bin/bash
# Create macOS Application Bundle from binary
# This script takes a standalone binary and packages it into a .app bundle

set -e  # Exit on any error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

BINARY_PATH="$1"
BUNDLE_NAME="${2:-MeshAgent.app}"
BUNDLE_ID="${3:-meshagent}"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Generate timestamp atomically (single date call ensures consistency)
eval $("$PROJECT_ROOT/build/tools/macos_build/generate-build-timestamp.sh")
BUILD_TIMESTAMP_DATE="${4:-$BUILD_DATE}"
BUILD_TIMESTAMP_TIME="${5:-$BUILD_TIME_ONLY}"
EXE_NAME="${6:-meshagent}"
DISPLAY_NAME="${7:-MeshAgent}"
CUSTOM_ICON="${8:-}"

if [ -z "$BINARY_PATH" ]; then
    echo "Usage: $0 <binary_path> [bundle_name] [bundle_id] [build_timestamp_date] [build_timestamp_time] [exe_name] [display_name]"
    echo ""
    echo "Arguments:"
    echo "  binary_path           Path to the compiled binary (required)"
    echo "  bundle_name           Name of the .app bundle (default: MeshAgent.app)"
    echo "  bundle_id             Bundle identifier (default: meshagent)"
    echo "  build_timestamp_date  Version date (default: current date as yy.mm.dd)"
    echo "  build_timestamp_time  Version time (default: current time as HH.MM.SS)"
    echo "  exe_name              Executable name inside bundle (default: meshagent)"
    echo "  display_name          Display name for CFBundleDisplayName (default: MeshAgent)"
    echo "  custom_icon           Path to custom .icns file (optional, default: build/resources/icon/AppIcon.icns)"
    echo ""
    echo "Example:"
    echo "  $0 build/output/meshagent_osx-arm-64 MeshAgent.app meshagent 25.11.19 14.30.45 meshagent MeshAgent"
    exit 1
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo -e "${RED}Error: Binary not found: $BINARY_PATH${NC}"
    exit 1
fi

echo -e "${CYAN}Creating app bundle${NC}"
echo "  Bundle:       $BUNDLE_NAME"
echo "  Binary:       $BINARY_PATH"
echo "  Bundle ID:    $BUNDLE_ID"
echo "  Exe name:     $EXE_NAME"
echo "  Display name: $DISPLAY_NAME"
echo "  Version:      $BUILD_TIMESTAMP_DATE.$BUILD_TIMESTAMP_TIME"

# Detect if binary is universal
if lipo -info "$BINARY_PATH" 2>/dev/null | grep -q "Architectures in the fat file"; then
    echo "  Architecture: Universal ($(lipo -info "$BINARY_PATH" | sed 's/.*: //'))"
elif lipo -info "$BINARY_PATH" 2>/dev/null | grep -q "Non-fat file"; then
    ARCH=$(lipo -info "$BINARY_PATH" | sed 's/.*: //')
    echo "  Architecture: $ARCH"
else
    echo "  Architecture: Unknown"
fi

echo ""

# Create bundle structure
# Standard macOS bundle layout: Contents/{MacOS,Resources}
mkdir -p "$BUNDLE_NAME/Contents/MacOS"
mkdir -p "$BUNDLE_NAME/Contents/Resources"

# Copy binary
cp "$BINARY_PATH" "$BUNDLE_NAME/Contents/MacOS/$EXE_NAME"
chmod +x "$BUNDLE_NAME/Contents/MacOS/$EXE_NAME"
echo -e "  ${GREEN}Copied binary to Contents/MacOS/$EXE_NAME${NC}"

# Generate Info.plist using unified generation script
"$PROJECT_ROOT/build/tools/macos_build/generate-info-plist.sh" \
    --output "$BUNDLE_NAME/Contents/Info.plist" \
    --bundle-id "$BUNDLE_ID" \
    --exe-name "$EXE_NAME" \
    --display-name "$DISPLAY_NAME" \
    --build-date "$BUILD_TIMESTAMP_DATE" \
    --build-time "$BUILD_TIMESTAMP_TIME" \
    --mode bundle
echo -e "  ${GREEN}Generated Info.plist${NC}"

# Copy icon (custom icon path takes priority over default)
if [ -n "$CUSTOM_ICON" ] && [ -f "$CUSTOM_ICON" ]; then
    ICON_FILENAME="$(basename "$CUSTOM_ICON")"
    cp "$CUSTOM_ICON" "$BUNDLE_NAME/Contents/Resources/$ICON_FILENAME"
    # Update CFBundleIconFile in the plist to match the custom filename
    /usr/libexec/PlistBuddy -c "Set :CFBundleIconFile $ICON_FILENAME" "$BUNDLE_NAME/Contents/Info.plist"
    echo -e "  ${GREEN}Copied custom icon: $ICON_FILENAME${NC}"
elif [ -n "$CUSTOM_ICON" ]; then
    echo -e "  ${YELLOW}Warning: Custom icon not found at $CUSTOM_ICON${NC}"
    echo -e "  ${YELLOW}Bundle will be created without icon${NC}"
else
    ICON_PATH="$PROJECT_ROOT/build/resources/icon/AppIcon.icns"
    if [ -f "$ICON_PATH" ]; then
        cp "$ICON_PATH" "$BUNDLE_NAME/Contents/Resources/AppIcon.icns"
        echo -e "  ${GREEN}Copied icon: AppIcon.icns${NC}"
    else
        echo -e "  ${YELLOW}Warning: Icon not found at $ICON_PATH${NC}"
        echo -e "  ${YELLOW}Bundle will be created without icon${NC}"
    fi
fi

# Create PkgInfo file (optional but recommended for compatibility)
echo -n "APPLMESH" > "$BUNDLE_NAME/Contents/PkgInfo"
echo -e "  ${GREEN}Created PkgInfo${NC}"

echo ""
echo -e "${GREEN}Bundle created: $BUNDLE_NAME${NC}"
