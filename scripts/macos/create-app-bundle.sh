#!/bin/bash

# create-app-bundle.sh - Version 0.0.1
# Creates a macOS app bundle structure from a standalone meshagent binary
#
# Usage:
#   ./create-app-bundle.sh [path-to-meshagent-binary]
#
# If no path is provided, defaults to: build/macos/universal/meshagent
#
# Output:
#   Creates meshagent.app bundle in the same directory as the source binary

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_DIR="$( cd "$SCRIPT_DIR/../.." && pwd )"

# Default binary path if not provided
DEFAULT_BINARY="$REPO_DIR/build/macos/universal/meshagent"
BINARY_PATH="${1:-$DEFAULT_BINARY}"

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  MeshAgent App Bundle Creator v0.0.1${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

# Validate binary exists
if [ ! -f "$BINARY_PATH" ]; then
    echo -e "${RED}ERROR: Binary not found at: $BINARY_PATH${NC}"
    echo "Usage: $0 [path-to-meshagent-binary]"
    exit 1
fi

# Get absolute path
BINARY_PATH="$(cd "$(dirname "$BINARY_PATH")" && pwd)/$(basename "$BINARY_PATH")"
BINARY_DIR="$(dirname "$BINARY_PATH")"
BINARY_NAME="$(basename "$BINARY_PATH")"

echo -e "${YELLOW}Source Binary:${NC} $BINARY_PATH"
echo ""

# Validate it's actually a Mach-O executable
if ! file "$BINARY_PATH" | grep -q "Mach-O"; then
    echo -e "${RED}ERROR: File is not a Mach-O executable${NC}"
    file "$BINARY_PATH"
    exit 1
fi

# Define bundle structure
BUNDLE_NAME="meshagent.app"
BUNDLE_PATH="$BINARY_DIR/$BUNDLE_NAME"
CONTENTS_DIR="$BUNDLE_PATH/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

echo -e "${YELLOW}Bundle Location:${NC} $BUNDLE_PATH"
echo ""

# Remove existing bundle if present
if [ -d "$BUNDLE_PATH" ]; then
    echo -e "${YELLOW}Removing existing bundle...${NC}"
    rm -rf "$BUNDLE_PATH"
fi

# Create bundle directory structure
echo -e "${GREEN}Creating bundle structure...${NC}"
mkdir -p "$MACOS_DIR"
mkdir -p "$RESOURCES_DIR"

# Copy binary into bundle
echo -e "${GREEN}Copying binary into bundle...${NC}"
cp "$BINARY_PATH" "$MACOS_DIR/meshagent"
chmod +x "$MACOS_DIR/meshagent"

# Copy Info.plist template
INFOPLIST_TEMPLATE="$SCRIPT_DIR/Info.plist.template"
INFOPLIST_DEST="$CONTENTS_DIR/Info.plist"

if [ ! -f "$INFOPLIST_TEMPLATE" ]; then
    echo -e "${RED}ERROR: Info.plist template not found at: $INFOPLIST_TEMPLATE${NC}"
    exit 1
fi

echo -e "${GREEN}Generating version from commit date...${NC}"

# Read SOURCE_COMMIT_DATE from ILibDuktape_Commit.h
COMMIT_HEADER="$REPO_DIR/microscript/ILibDuktape_Commit.h"
if [ ! -f "$COMMIT_HEADER" ]; then
    echo -e "${RED}ERROR: Commit header not found at: $COMMIT_HEADER${NC}"
    echo "Please build the project first to generate this file."
    exit 1
fi

# Extract SOURCE_COMMIT_DATE (format: "2025-Nov-5 09:28:37-0700")
SOURCE_DATE=$(grep 'SOURCE_COMMIT_DATE' "$COMMIT_HEADER" | sed 's/.*"\(.*\)".*/\1/')

if [ -z "$SOURCE_DATE" ]; then
    echo -e "${RED}ERROR: Could not extract SOURCE_COMMIT_DATE${NC}"
    exit 1
fi

echo -e "${YELLOW}Source Commit Date:${NC} $SOURCE_DATE"

# Parse date components (format: YYYY-Mon-D HH:MM:SS-TZ)
YEAR=$(echo "$SOURCE_DATE" | awk '{print $1}' | cut -d'-' -f1 | cut -c3-4)  # Last 2 digits of year
MONTH=$(echo "$SOURCE_DATE" | awk '{print $1}' | cut -d'-' -f2)
DAY=$(echo "$SOURCE_DATE" | awk '{print $1}' | cut -d'-' -f3)
TIME=$(echo "$SOURCE_DATE" | awk '{print $2}')
HOUR=$(echo "$TIME" | cut -d':' -f1)
MINUTE=$(echo "$TIME" | cut -d':' -f2)

# Convert month name to number
case "$MONTH" in
    Jan) MONTH_NUM="01" ;;
    Feb) MONTH_NUM="02" ;;
    Mar) MONTH_NUM="03" ;;
    Apr) MONTH_NUM="04" ;;
    May) MONTH_NUM="05" ;;
    Jun) MONTH_NUM="06" ;;
    Jul) MONTH_NUM="07" ;;
    Aug) MONTH_NUM="08" ;;
    Sep) MONTH_NUM="09" ;;
    Oct) MONTH_NUM="10" ;;
    Nov) MONTH_NUM="11" ;;
    Dec) MONTH_NUM="12" ;;
    *) echo -e "${RED}ERROR: Invalid month: $MONTH${NC}"; exit 1 ;;
esac

# Pad day with leading zero if needed
DAY_PADDED=$(printf "%02d" "$DAY")

# Generate version: YY.MMDD.HHMM
VERSION="${YEAR}.${MONTH_NUM}${DAY_PADDED}.${HOUR}${MINUTE}"

echo -e "${YELLOW}Generated Version:${NC} $VERSION"
echo ""

echo -e "${GREEN}Creating Info.plist from template...${NC}"
# Copy template and replace {{VERSION}} placeholder
sed "s/{{VERSION}}/$VERSION/g" "$INFOPLIST_TEMPLATE" > "$INFOPLIST_DEST"

# Validate Info.plist
echo -e "${GREEN}Validating Info.plist...${NC}"
if plutil -lint "$INFOPLIST_DEST" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Info.plist is valid${NC}"
else
    echo -e "${RED}ERROR: Info.plist validation failed${NC}"
    plutil -lint "$INFOPLIST_DEST"
    exit 1
fi

# Display bundle info
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Bundle created successfully!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Bundle Path:${NC} $BUNDLE_PATH"
echo -e "${YELLOW}Bundle Version:${NC} $VERSION"
echo -e "${YELLOW}Executable:${NC} $MACOS_DIR/meshagent"
echo -e "${YELLOW}Info.plist:${NC} $INFOPLIST_DEST"
echo ""

# Show bundle structure
echo -e "${YELLOW}Bundle Structure:${NC}"
tree -L 3 "$BUNDLE_PATH" 2>/dev/null || find "$BUNDLE_PATH" -print | sed -e 's;[^/]*/;|____;g;s;____|; |;g'

echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Sign the bundle: codesign --sign \"Developer ID\" --options runtime --deep meshagent.app"
echo "  2. Notarize: xcrun notarytool submit ..."
echo "  3. Staple: xcrun stapler staple meshagent.app"
echo ""
