#!/bin/bash
# Sign macOS universal binaries and extract architecture-specific slices
#
# This script can be sourced or executed:
#   source ./macos-sign.sh && macos_sign_binary /path/to/binary
#   ./macos-sign.sh /path/to/binary
#
# Functions provided when sourced:
#   macos_sign_binary <binary_path>      - Sign a specific binary
#   macos_sign_extract_architectures <binary_path> - Extract arch slices
#
# Environment Variables:
#   MACOS_SIGN_CERT   - Code signing certificate (required)
#   DEBUG=yes         - Also sign DEBUG binaries in default mode

#==============================================================================
# HELPER FUNCTIONS (available when sourced)
#==============================================================================

macos_sign_universal_binary() {
    local binary_path="$1"
    local binary_name=$(basename "$binary_path")

    # Colors for output
    local GREEN='\033[0;32m'
    local YELLOW='\033[0;33m'
    local RED='\033[0;31m'
    local BLUE='\033[0;34m'
    local NC='\033[0m'

    if [ ! -f "$binary_path" ]; then
        echo -e "${RED}Error: Binary not found: $binary_path${NC}"
        return 1
    fi

    echo -e "${YELLOW}Signing universal binary:${NC} $binary_name"

    # Sign with hardened runtime for distribution
    if ! codesign --sign "$MACOS_SIGN_CERT" \
         --timestamp \
         --options runtime \
         --force \
         "$binary_path" 2>&1; then
        echo -e "${RED}✗ Signing failed${NC}"
        return 1
    fi

    # Verify signature
    if codesign -vvv --deep --strict "$binary_path" 2>&1 | grep -q "satisfies its Designated Requirement"; then
        echo -e "${GREEN}✓ Successfully signed${NC}"
    else
        echo -e "${RED}✗ Signature verification failed${NC}"
        return 1
    fi

    # Verify it's actually a universal binary
    if ! lipo -info "$binary_path" 2>/dev/null | grep -q "Non-fat file"; then
        echo -e "${BLUE}Architecture info:${NC}"
        lipo -info "$binary_path" | sed 's/^/  /'
    else
        echo -e "${YELLOW}Warning: Not a universal binary, skipping lipo extraction${NC}"
        echo ""
        return 0
    fi

    echo ""
    return 0
}

macos_sign_extract_architectures() {
    local universal_path="$1"
    local output_dir=$(dirname "$universal_path")
    local base_name=$(basename "$universal_path" | sed 's/-universal-64$//')

    # Colors for output
    local GREEN='\033[0;32m'
    local YELLOW='\033[0;33m'
    local RED='\033[0;31m'
    local NC='\033[0m'

    if [ ! -f "$universal_path" ]; then
        echo -e "${RED}Error: Universal binary not found: $universal_path${NC}"
        return 1
    fi

    # Verify it's a universal binary before extracting
    if lipo -info "$universal_path" 2>/dev/null | grep -q "Non-fat file"; then
        echo -e "${YELLOW}Skipping extraction: Not a universal binary${NC}"
        echo ""
        return 0
    fi

    echo -e "${YELLOW}Extracting architecture slices...${NC}"

    # Extract arm64 slice
    local arm64_path="$output_dir/${base_name}-arm-64"
    if lipo "$universal_path" -thin arm64 -output "$arm64_path" 2>/dev/null; then
        echo -e "${GREEN}✓ Extracted arm64:${NC}  $arm64_path"

        # Verify the extracted binary is signed (should inherit from universal)
        if codesign -vvv "$arm64_path" &>/dev/null; then
            echo -e "${GREEN}  ✓ arm64 signature verified${NC}"
        else
            echo -e "${YELLOW}  ⚠ arm64 signature could not be verified${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Could not extract arm64 slice${NC}"
    fi

    # Extract x86_64 slice
    local x86_path="$output_dir/${base_name}-x86-64"
    if lipo "$universal_path" -thin x86_64 -output "$x86_path" 2>/dev/null; then
        echo -e "${GREEN}✓ Extracted x86_64:${NC} $x86_path"

        # Verify the extracted binary is signed (should inherit from universal)
        if codesign -vvv "$x86_path" &>/dev/null; then
            echo -e "${GREEN}  ✓ x86_64 signature verified${NC}"
        else
            echo -e "${YELLOW}  ⚠ x86_64 signature could not be verified${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Could not extract x86_64 slice${NC}"
    fi

    echo ""
    return 0
}

# Main signing function (can be called when sourced)
macos_sign_binary() {
    local binary_path="$1"

    # Colors for output
    local GREEN='\033[0;32m'
    local BLUE='\033[0;34m'
    local RED='\033[0;31m'
    local NC='\033[0m'

    # Validate certificate
    if [ -z "$MACOS_SIGN_CERT" ]; then
        echo -e "${RED}Error: MACOS_SIGN_CERT environment variable not set${NC}"
        echo ""
        echo "Usage:"
        echo "  export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
        return 1
    fi

    # Validate binary exists
    if [ ! -f "$binary_path" ]; then
        echo -e "${RED}Error: Binary not found: $binary_path${NC}"
        return 1
    fi

    # Verify it's a universal binary
    if lipo -info "$binary_path" 2>/dev/null | grep -q "Non-fat file"; then
        echo -e "${RED}Error: Not a universal binary: $binary_path${NC}"
        echo ""
        echo "This function only accepts universal binaries (containing multiple architectures)."
        echo "Use 'lipo -info' to check binary architecture."
        return 1
    fi

    # Sign the binary
    if ! macos_sign_universal_binary "$binary_path"; then
        return 1
    fi

    # Extract architectures
    if ! macos_sign_extract_architectures "$binary_path"; then
        return 1
    fi

    echo -e "${GREEN}✓ Signing and extraction complete${NC}"
    return 0
}

#==============================================================================
# STANDALONE EXECUTION (only runs if not sourced)
#==============================================================================

# Detect if script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being executed, not sourced

    # Colors for output
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    YELLOW='\033[0;33m'
    RED='\033[0;31m'
    NC='\033[0m'

    # Get the repository root directory
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    REPO_DIR="$( cd "$SCRIPT_DIR/../../.." && pwd )"

    # Build output directories
    OUTPUT_DIR="$REPO_DIR/build/output"
    DEBUG_DIR="$OUTPUT_DIR/DEBUG"

    # Binary names (EXENAME env var allows override, default: meshagent)
    BINARY_BASE="${EXENAME:-meshagent}"
    RELEASE_BINARY="${BINARY_BASE}_osx-universal-64"
    DEBUG_BINARY="DEBUG_${BINARY_BASE}_osx-universal-64"

    # Check if DEBUG binaries should be signed
    SIGN_DEBUG="${DEBUG:-no}"

    # Custom binary path (if provided)
    CUSTOM_BINARY=""

    #==============================================================================
    # PARSE COMMAND LINE ARGUMENTS
    #==============================================================================

    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                echo "Usage: $0 [OPTIONS] [BINARY_PATH]"
                echo ""
                echo "Sign macOS universal binaries and extract architecture slices"
                echo ""
                echo "Arguments:"
                echo "  BINARY_PATH   Path to a universal binary to sign (optional)"
                echo "                If not provided, signs binaries in build/output/"
                echo ""
                echo "Environment Variables:"
                echo "  MACOS_SIGN_CERT   Code signing certificate (required)"
                echo "  DEBUG=yes         Also sign DEBUG binaries (ignored with BINARY_PATH)"
                echo ""
                echo "Examples:"
                echo "  export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
                echo "  ./macos-sign.sh                              # Sign default binaries"
                echo "  ./macos-sign.sh /path/to/meshagent_universal # Sign specific binary"
                echo "  DEBUG=yes ./macos-sign.sh                    # Sign release + DEBUG"
                echo ""
                echo "As a sourceable script:"
                echo "  source ./macos-sign.sh"
                echo "  macos_sign_binary /path/to/binary"
                exit 0
                ;;
            -*)
                echo "Error: Unknown option $1"
                echo "Run with --help for usage information"
                exit 1
                ;;
            *)
                if [ -n "$CUSTOM_BINARY" ]; then
                    echo "Error: Multiple binary paths provided"
                    echo "Run with --help for usage information"
                    exit 1
                fi
                CUSTOM_BINARY="$1"
                shift
                ;;
        esac
    done

    #==============================================================================
    # VALIDATION
    #==============================================================================

    echo -e "${BLUE}====================================${NC}"
    echo -e "${BLUE}macOS Universal Binary Signing${NC}"
    echo -e "${BLUE}====================================${NC}"
    echo ""

    # Check if certificate is specified
    if [ -z "$MACOS_SIGN_CERT" ]; then
        echo -e "${RED}Error: MACOS_SIGN_CERT environment variable not set${NC}"
        echo ""
        echo "Usage:"
        echo "  export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
        echo "  ./macos-sign.sh"
        echo ""
        echo "To list available certificates:"
        echo "  security find-identity -v -p codesigning"
        exit 1
    fi

    echo -e "${YELLOW}Certificate:${NC} $MACOS_SIGN_CERT"

    # Validate custom binary if provided
    if [ -n "$CUSTOM_BINARY" ]; then
        # Resolve to absolute path
        CUSTOM_BINARY=$(cd "$(dirname "$CUSTOM_BINARY")" && pwd)/$(basename "$CUSTOM_BINARY")

        if [ ! -f "$CUSTOM_BINARY" ]; then
            echo -e "${RED}Error: Binary not found: $CUSTOM_BINARY${NC}"
            exit 1
        fi

        # Verify it's a universal binary
        if lipo -info "$CUSTOM_BINARY" 2>/dev/null | grep -q "Non-fat file"; then
            echo -e "${RED}Error: Not a universal binary: $CUSTOM_BINARY${NC}"
            echo ""
            echo "This script only accepts universal binaries (containing multiple architectures)."
            echo "Use 'lipo -info' to check binary architecture."
            exit 1
        fi

        echo -e "${YELLOW}Target binary:${NC} $CUSTOM_BINARY"
        echo -e "${YELLOW}Mode:${NC}          Custom binary"

        # Warn if DEBUG is set (it's ignored in custom mode)
        if [ "$SIGN_DEBUG" = "yes" ]; then
            echo -e "${YELLOW}Note: DEBUG flag is ignored when signing a custom binary${NC}"
        fi
    else
        echo -e "${YELLOW}Sign DEBUG:${NC}    $SIGN_DEBUG"
        echo -e "${YELLOW}Mode:${NC}          Default (build/output/)"

        # Check if output directory exists (only needed for default mode)
        if [ ! -d "$OUTPUT_DIR" ]; then
            echo -e "${RED}Error: $OUTPUT_DIR directory not found${NC}"
            echo "Build binaries first with: make macos ARCHID=10005"
            exit 1
        fi
    fi

    echo ""

    #==============================================================================
    # PROCESS BINARIES
    #==============================================================================

    SIGNED_COUNT=0

    if [ -n "$CUSTOM_BINARY" ]; then
        #==========================================================================
        # CUSTOM BINARY MODE
        #==========================================================================

        echo -e "${BLUE}Signing custom binary${NC}"
        echo ""

        if macos_sign_universal_binary "$CUSTOM_BINARY"; then
            if macos_sign_extract_architectures "$CUSTOM_BINARY"; then
                SIGNED_COUNT=$((SIGNED_COUNT + 1))
            fi
        fi
    else
        #==========================================================================
        # DEFAULT MODE: SIGN RELEASE BINARY
        #==========================================================================

        echo -e "${BLUE}Step 1: Sign release universal binary${NC}"
        echo ""

        RELEASE_PATH="$OUTPUT_DIR/$RELEASE_BINARY"

        if [ -f "$RELEASE_PATH" ]; then
            if macos_sign_universal_binary "$RELEASE_PATH"; then
                if macos_sign_extract_architectures "$RELEASE_PATH"; then
                    SIGNED_COUNT=$((SIGNED_COUNT + 1))
                fi
            fi
        else
            echo -e "${RED}Error: Release binary not found: $RELEASE_PATH${NC}"
            echo "Build the universal binary first with: make macos ARCHID=10005"
            exit 1
        fi

        #==========================================================================
        # DEFAULT MODE: SIGN DEBUG BINARY (if DEBUG=yes)
        #==========================================================================

        if [ "$SIGN_DEBUG" = "yes" ]; then
            echo -e "${BLUE}Step 2: Sign DEBUG universal binary${NC}"
            echo ""

            DEBUG_PATH="$DEBUG_DIR/$DEBUG_BINARY"

            if [ -f "$DEBUG_PATH" ]; then
                if macos_sign_universal_binary "$DEBUG_PATH"; then
                    if macos_sign_extract_architectures "$DEBUG_PATH"; then
                        SIGNED_COUNT=$((SIGNED_COUNT + 1))
                    fi
                fi
            else
                echo -e "${YELLOW}Warning: DEBUG binary not found: $DEBUG_PATH${NC}"
                echo "  (This is normal if you haven't built DEBUG binaries)"
                echo ""
            fi
        fi
    fi

    #==============================================================================
    # SUMMARY
    #==============================================================================

    if [ $SIGNED_COUNT -eq 0 ]; then
        echo -e "${RED}Error: No binaries were signed${NC}"
        exit 1
    fi

    echo -e "${BLUE}====================================${NC}"
    echo -e "${BLUE}Signing Complete${NC}"
    echo -e "${BLUE}====================================${NC}"
    echo -e "${GREEN}✓ Signed $SIGNED_COUNT universal binary/binaries${NC}"
    echo -e "${GREEN}✓ Extracted architecture-specific slices${NC}"
    echo ""

    if [ -n "$CUSTOM_BINARY" ]; then
        echo "Binary locations:"
        echo "  - $CUSTOM_BINARY (universal)"
        local base_name=$(basename "$CUSTOM_BINARY" | sed 's/-universal-64$//')
        local custom_dir=$(dirname "$CUSTOM_BINARY")
        echo "  - ${custom_dir}/${base_name}-arm-64 (arm64)"
        echo "  - ${custom_dir}/${base_name}-x86-64 (x86_64)"
    else
        echo "Binary locations:"
        if [ -f "$RELEASE_PATH" ]; then
            echo "  Release:"
            echo "    - $RELEASE_PATH (universal)"
            echo "    - ${RELEASE_PATH/-universal-64/-arm-64} (arm64)"
            echo "    - ${RELEASE_PATH/-universal-64/-x86-64} (x86_64)"
        fi
        if [ "$SIGN_DEBUG" = "yes" ] && [ -f "$DEBUG_PATH" ]; then
            echo "  DEBUG:"
            echo "    - $DEBUG_PATH (universal)"
            echo "    - ${DEBUG_PATH/-universal-64/-arm-64} (arm64)"
            echo "    - ${DEBUG_PATH/-universal-64/-x86-64} (x86_64)"
        fi
    fi

    echo ""
    echo "Next steps:"
    echo "  1. Test the signed binaries"
    echo "  2. Submit universal binaries to Apple for notarization"
    echo "  3. Staple notarization ticket to all binaries"
    echo ""
fi
