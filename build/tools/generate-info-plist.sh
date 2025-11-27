#!/bin/bash
# Generate Info.plist from templates
# Supports both binary (minimal) and bundle (full) modes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Defaults
OUTPUT=""
BUNDLE_ID="consulting.artichoke.MeshAgent"
BUILD_DATE=""
BUILD_TIME=""
MODE="bundle"  # bundle or binary

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --bundle-id)
            BUNDLE_ID="$2"
            shift 2
            ;;
        --build-date)
            BUILD_DATE="$2"
            shift 2
            ;;
        --build-time)
            BUILD_TIME="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 --output FILE --bundle-id ID --build-date DATE --build-time TIME --mode [binary|bundle]"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$OUTPUT" ]; then
    echo "Error: --output is required"
    exit 1
fi

if [ -z "$BUILD_DATE" ]; then
    echo "Error: --build-date is required"
    exit 1
fi

if [ -z "$BUILD_TIME" ]; then
    echo "Error: --build-time is required"
    exit 1
fi

# Select template based on mode
case "$MODE" in
    binary)
        TEMPLATE="$PROJECT_ROOT/build/resources/Info/binary/binary_Info.plist"
        ;;
    bundle)
        TEMPLATE="$PROJECT_ROOT/build/resources/Info/bundle/app_Info.plist"
        ;;
    *)
        echo "Error: Invalid mode '$MODE'. Use 'binary' or 'bundle'"
        exit 1
        ;;
esac

if [ ! -f "$TEMPLATE" ]; then
    echo "Error: Template not found: $TEMPLATE"
    exit 1
fi

# Generate Info.plist by substituting placeholders
sed -e "s/BUNDLE_IDENTIFIER/$BUNDLE_ID/g" \
    -e "s/BUILD_TIMESTAMP_DATE/$BUILD_DATE/g" \
    -e "s/BUILD_TIMESTAMP_TIME/$BUILD_TIME/g" \
    "$TEMPLATE" > "$OUTPUT"

echo "Generated $MODE Info.plist: $OUTPUT"
