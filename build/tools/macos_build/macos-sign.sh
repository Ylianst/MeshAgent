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

    local RED='\033[0;31m'
    local GREEN='\033[0;32m'
    local YELLOW='\033[0;33m'
    local NC='\033[0m'

    if [ ! -f "$binary_path" ]; then
        echo -e "${RED}Error: Binary not found: $binary_path${NC}"
        return 1
    fi

    echo "  Signing: $binary_name"

    # Sign with hardened runtime for distribution
    if ! codesign --sign "$MACOS_SIGN_CERT" \
         --timestamp \
         --options runtime \
         --force \
         "$binary_path" 2>&1; then
        echo -e "${RED}Error: Signing failed for $binary_name${NC}"
        return 1
    fi

    # Verify signature
    if codesign -vvv --deep --strict "$binary_path" 2>&1 | grep -q "satisfies its Designated Requirement"; then
        echo -e "  ${GREEN}Verified: $binary_name${NC}"
    else
        echo -e "${RED}Error: Signature verification failed for $binary_name${NC}"
        return 1
    fi

    # Show architecture info if universal
    if ! lipo -info "$binary_path" 2>/dev/null | grep -q "Non-fat file"; then
        echo "  Architecture: $(lipo -info "$binary_path" 2>/dev/null | sed 's/.*: //')"
    else
        echo -e "${YELLOW}  Warning: Not a universal binary, skipping lipo extraction${NC}"
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
        echo "  Skipping extraction: Not a universal binary"
        echo ""
        return 0
    fi

    echo "  Extracting architecture slices..."

    # Extract arm64 slice
    local arm64_path="$output_dir/${base_name}-arm-64"
    if lipo "$universal_path" -thin arm64 -output "$arm64_path" 2>/dev/null; then
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
    if lipo "$universal_path" -thin x86_64 -output "$x86_path" 2>/dev/null; then
        echo "    x86_64: $x86_path"
        if codesign -vvv "$x86_path" &>/dev/null; then
            echo -e "    ${GREEN}x86_64 signature verified${NC}"
        else
            echo -e "    ${YELLOW}Warning: x86_64 signature could not be verified${NC}"
        fi
    else
        echo -e "    ${YELLOW}Warning: Could not extract x86_64 slice${NC}"
    fi

    echo ""
    return 0
}

# Main signing function (can be called when sourced)
macos_sign_binary() {
    local binary_path="$1"

    local RED='\033[0;31m'
    local GREEN='\033[0;32m'
    local NC='\033[0m'

    # Validate certificate
    if [ -z "$MACOS_SIGN_CERT" ]; then
        echo -e "${RED}Error: MACOS_SIGN_CERT environment variable not set${NC}"
        echo "  Example: export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
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

    echo -e "  ${GREEN}Signing and extraction complete${NC}"
    return 0
}

#==============================================================================
# STANDALONE EXECUTION (only runs if not sourced)
#==============================================================================

# Detect if script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being executed, not sourced

    # Colors
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
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

    echo -e "${CYAN}macOS universal binary signing${NC}"
    echo ""

    # Check if certificate is specified
    if [ -z "$MACOS_SIGN_CERT" ]; then
        echo -e "${RED}Error: MACOS_SIGN_CERT environment variable not set${NC}"
        echo "  Example: export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
        echo ""
        echo "To list available certificates:"
        echo "  security find-identity -v -p codesigning"
        exit 1
    fi

    echo "  Certificate: $MACOS_SIGN_CERT"

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
            exit 1
        fi

        echo "  Binary: $CUSTOM_BINARY"
        echo "  Mode: custom binary"
    else
        echo "  Sign DEBUG: $SIGN_DEBUG"
        echo "  Mode: default (build/output/)"

        # Check if output directory exists (only needed for default mode)
        if [ ! -d "$OUTPUT_DIR" ]; then
            echo -e "${RED}Error: $OUTPUT_DIR directory not found${NC}"
            echo "  Build binaries first with: make macos ARCHID=10005"
            exit 1
        fi
    fi

    echo ""

    #==============================================================================
    # PROCESS BINARIES
    #==============================================================================

    SIGNED_COUNT=0

    if [ -n "$CUSTOM_BINARY" ]; then
        echo "Signing custom binary..."
        echo ""

        if macos_sign_universal_binary "$CUSTOM_BINARY"; then
            if macos_sign_extract_architectures "$CUSTOM_BINARY"; then
                SIGNED_COUNT=$((SIGNED_COUNT + 1))
            fi
        fi
    else
        echo "Step 1: Sign release universal binary"
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
            echo "  Build the universal binary first with: make macos ARCHID=10005"
            exit 1
        fi

        if [ "$SIGN_DEBUG" = "yes" ]; then
            echo "Step 2: Sign DEBUG universal binary"
            echo ""

            DEBUG_PATH="$DEBUG_DIR/$DEBUG_BINARY"

            if [ -f "$DEBUG_PATH" ]; then
                if macos_sign_universal_binary "$DEBUG_PATH"; then
                    if macos_sign_extract_architectures "$DEBUG_PATH"; then
                        SIGNED_COUNT=$((SIGNED_COUNT + 1))
                    fi
                fi
            else
                echo -e "  ${YELLOW}Warning: DEBUG binary not found: $DEBUG_PATH${NC}"
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

    echo -e "${GREEN}Signing complete${NC}"
    echo "  Signed $SIGNED_COUNT universal binary/binaries"
    echo ""

    if [ -n "$CUSTOM_BINARY" ]; then
        echo "Binary locations:"
        echo "  $CUSTOM_BINARY (universal)"
        local base_name=$(basename "$CUSTOM_BINARY" | sed 's/-universal-64$//')
        local custom_dir=$(dirname "$CUSTOM_BINARY")
        echo "  ${custom_dir}/${base_name}-arm-64 (arm64)"
        echo "  ${custom_dir}/${base_name}-x86-64 (x86_64)"
    else
        echo "Binary locations:"
        if [ -f "$RELEASE_PATH" ]; then
            echo "  Release:"
            echo "    $RELEASE_PATH (universal)"
            echo "    ${RELEASE_PATH/-universal-64/-arm-64} (arm64)"
            echo "    ${RELEASE_PATH/-universal-64/-x86-64} (x86_64)"
        fi
        if [ "$SIGN_DEBUG" = "yes" ] && [ -f "$DEBUG_PATH" ]; then
            echo "  DEBUG:"
            echo "    $DEBUG_PATH (universal)"
            echo "    ${DEBUG_PATH/-universal-64/-arm-64} (arm64)"
            echo "    ${DEBUG_PATH/-universal-64/-x86-64} (x86_64)"
        fi
    fi

    echo ""
fi
