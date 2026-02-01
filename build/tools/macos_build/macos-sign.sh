#!/bin/bash
# Sign macOS targets (binaries and/or .app bundles)
#
# Usage: macos-sign.sh <target> [target2] [target3] ...
#
# Each target is auto-detected:
#   - Directory ending in .app  → bundle (codesign --deep)
#   - Regular file              → binary (codesign, lipo slice extraction if universal)
#
# Environment Variables:
#   MACOS_SIGN_CERT   - Code signing certificate (required)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

#==============================================================================
# USAGE
#==============================================================================

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target> [target2] [target3] ..."
    echo ""
    echo "Targets can be any mix of .app bundles and bare Mach-O binaries."
    echo ""
    echo "Environment Variables:"
    echo "  MACOS_SIGN_CERT   Code signing certificate (required)"
    echo ""
    echo "Examples:"
    echo "  $0 build/output/meshagent_osx-universal-64"
    echo "  $0 build/output/osx-universal-64-app/MeshAgent.app"
    echo "  $0 binary.bin Bundle1.app Bundle2.app Bundle3.app"
    exit 1
fi

#==============================================================================
# VALIDATION
#==============================================================================

if [ -z "$MACOS_SIGN_CERT" ]; then
    echo -e "${RED}Error: MACOS_SIGN_CERT environment variable not set${NC}"
    echo "  Example: export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
    exit 1
fi

echo -e "${CYAN}macOS code signing${NC}"
echo "  Certificate: $MACOS_SIGN_CERT"
echo "  Targets:     $#"
echo ""

#==============================================================================
# SIGN FUNCTIONS
#==============================================================================

sign_bundle() {
    local bundle="$1"
    local name
    name=$(basename "$bundle")

    if [ ! -d "$bundle" ]; then
        echo -e "${RED}Error: Bundle not found: $bundle${NC}"
        return 1
    fi

    echo "  Signing bundle: $name"
    codesign --sign "$MACOS_SIGN_CERT" \
             --options runtime \
             --timestamp \
             --deep \
             --force \
             "$bundle"

    if codesign --verify --deep --strict "$bundle" 2>/dev/null; then
        echo -e "  ${GREEN}Verified: $name${NC}"
    else
        echo -e "${RED}Error: Signature verification failed for $name${NC}"
        return 1
    fi

    # Display architecture information for the main executable
    local exe_name
    exe_name=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$bundle/Contents/Info.plist" 2>/dev/null || echo "")
    if [ -n "$exe_name" ] && [ -f "$bundle/Contents/MacOS/$exe_name" ]; then
        echo "  Architecture: $(lipo -info "$bundle/Contents/MacOS/$exe_name" 2>/dev/null | sed 's/.*: //')"
    fi

    echo ""
}

sign_binary() {
    local binary="$1"
    local name
    name=$(basename "$binary")

    if [ ! -f "$binary" ]; then
        echo -e "${RED}Error: Binary not found: $binary${NC}"
        return 1
    fi

    echo "  Signing binary: $name"
    codesign --sign "$MACOS_SIGN_CERT" \
             --timestamp \
             --options runtime \
             --force \
             "$binary"

    if codesign -vvv --deep --strict "$binary" 2>&1 | grep -q "satisfies its Designated Requirement"; then
        echo -e "  ${GREEN}Verified: $name${NC}"
    else
        echo -e "${RED}Error: Signature verification failed for $name${NC}"
        return 1
    fi

    # If universal, extract architecture slices and verify each
    if ! lipo -info "$binary" 2>/dev/null | grep -q "Non-fat file"; then
        echo "  Architecture: $(lipo -info "$binary" 2>/dev/null | sed 's/.*: //')"
        echo "  Extracting architecture slices..."

        local output_dir
        output_dir=$(dirname "$binary")
        local base_name
        base_name=$(basename "$binary" | sed 's/-universal-64$//')

        # Extract arm64 slice
        local arm64_path="$output_dir/${base_name}-arm-64"
        if lipo "$binary" -thin arm64 -output "$arm64_path" 2>/dev/null; then
            echo "    arm64:  $arm64_path"
            if codesign -vvv "$arm64_path" &>/dev/null; then
                echo -e "    ${GREEN}arm64 signature verified${NC}"
            else
                echo -e "    ${YELLOW}Warning: arm64 signature could not be verified${NC}"
            fi
        else
            echo -e "    ${YELLOW}Warning: Could not extract arm64 slice${NC}"
        fi

        # Extract x86_64 slice
        local x86_path="$output_dir/${base_name}-x86-64"
        if lipo "$binary" -thin x86_64 -output "$x86_path" 2>/dev/null; then
            echo "    x86_64: $x86_path"
            if codesign -vvv "$x86_path" &>/dev/null; then
                echo -e "    ${GREEN}x86_64 signature verified${NC}"
            else
                echo -e "    ${YELLOW}Warning: x86_64 signature could not be verified${NC}"
            fi
        else
            echo -e "    ${YELLOW}Warning: Could not extract x86_64 slice${NC}"
        fi
    else
        echo -e "  ${YELLOW}Note: Single-architecture binary (no lipo extraction)${NC}"
    fi

    echo ""
}

#==============================================================================
# PROCESS TARGETS
#==============================================================================

SIGNED=0
FAILED=0

for target in "$@"; do
    if [ -d "$target" ] && [[ "$target" == *.app ]]; then
        if sign_bundle "$target"; then
            SIGNED=$((SIGNED + 1))
        else
            FAILED=$((FAILED + 1))
        fi
    elif [ -f "$target" ]; then
        if sign_binary "$target"; then
            SIGNED=$((SIGNED + 1))
        else
            FAILED=$((FAILED + 1))
        fi
    else
        echo -e "${RED}Error: Target not found: $target${NC}"
        FAILED=$((FAILED + 1))
    fi
done

#==============================================================================
# SUMMARY
#==============================================================================

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Signing complete with errors: $SIGNED succeeded, $FAILED failed${NC}"
    exit 1
fi

echo -e "${GREEN}Signing complete: $SIGNED target(s) signed${NC}"
