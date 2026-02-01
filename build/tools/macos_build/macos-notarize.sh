#!/bin/bash
# Notarize macOS universal binaries with Apple
#
# This script can be sourced or executed:
#   source ./macos-notarize.sh && macos_notarize_binary /path/to/binary
#   ./macos-notarize.sh /path/to/binary
#
# Functions provided when sourced:
#   macos_notarize_binary <binary_path> [--verbose]  - Notarize a specific binary
#   macos_notarize_extract_architectures <binary_path> - Extract arch slices
#
# Environment Variables:
#   MACOS_NOTARY_PROFILE - Keychain profile name (default: meshagent-notary)
#   DEBUG=yes - Also notarize DEBUG binaries in default mode

#==============================================================================
# HELPER FUNCTIONS (available when sourced)
#==============================================================================

macos_notarize_extract_architectures() {
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
            echo -e "    ${GREEN}arm64 signature verified (inherited)${NC}"
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
            echo -e "    ${GREEN}x86_64 signature verified (inherited)${NC}"
        else
            echo -e "    ${YELLOW}Warning: x86_64 signature could not be verified${NC}"
        fi
    else
        echo -e "    ${YELLOW}Warning: Could not extract x86_64 slice${NC}"
    fi

    echo ""
    return 0
}

# Main notarization function (can be called when sourced)
macos_notarize_binary() {
    local binary_path="$1"
    local verbose=false

    # Check for --verbose flag
    if [ "$2" = "--verbose" ]; then
        verbose=true
    fi

    local RED='\033[0;31m'
    local GREEN='\033[0;32m'
    local NC='\033[0m'

    # Keychain profile
    local KEYCHAIN_PROFILE="${MACOS_NOTARY_PROFILE:-meshagent-notary}"

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

    # Verify binary is signed
    if ! codesign -vvv "$binary_path" &>/dev/null; then
        echo -e "${RED}Error: Binary is not signed: $binary_path${NC}"
        echo "  Sign binaries first with macos-sign.sh"
        return 1
    fi

    # Verify keychain profile exists
    if ! xcrun notarytool history --keychain-profile "$KEYCHAIN_PROFILE" &>/dev/null; then
        echo -e "${RED}Error: Keychain profile not found: $KEYCHAIN_PROFILE${NC}"
        echo ""
        echo "Set up the keychain profile once with:"
        echo "  xcrun notarytool store-credentials \"$KEYCHAIN_PROFILE\" \\"
        echo "    --apple-id \"developer@example.com\" \\"
        echo "    --team-id \"TEAMID\" \\"
        echo "    --password \"xxxx-xxxx-xxxx-xxxx\""
        return 1
    fi

    # Create temporary directory for ZIP
    local TEMP_DIR=$(mktemp -d)
    local binary_name=$(basename "$binary_path")
    local zip_path="$TEMP_DIR/${binary_name}.zip"

    echo "  Notarizing: $binary_name"

    # Create ZIP
    local binary_dir=$(dirname "$binary_path")
    local binary_file=$(basename "$binary_path")
    (cd "$binary_dir" && ditto -c -k "$binary_file" "$zip_path")

    # Submit to Apple and wait for completion
    local submit_args=(
        "$zip_path"
        --keychain-profile "$KEYCHAIN_PROFILE"
        --wait
        --timeout 30m
    )

    local notarize_result=0
    if [ "$verbose" = false ]; then
        if ! xcrun notarytool submit "${submit_args[@]}" &>/dev/null; then
            notarize_result=1
        fi
    else
        if ! xcrun notarytool submit "${submit_args[@]}"; then
            notarize_result=1
        fi
    fi

    # Cleanup ZIP
    rm -f "$zip_path"
    rm -rf "$TEMP_DIR"

    if [ $notarize_result -ne 0 ]; then
        echo -e "${RED}Error: Notarization failed for $binary_name${NC}"
        if [ "$verbose" = false ]; then
            echo "  Run with --verbose for detailed output"
        fi
        echo ""
        return 1
    fi

    echo -e "  ${GREEN}Accepted: $binary_name${NC}"
    echo ""

    # Extract architecture slices
    if ! macos_notarize_extract_architectures "$binary_path"; then
        return 1
    fi

    echo -e "  ${GREEN}Notarization and extraction complete${NC}"
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

    # Get script directory and repository root
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    REPO_DIR="$( cd "$SCRIPT_DIR/../../.." && pwd )"

    # Build output directories
    OUTPUT_DIR="$REPO_DIR/build/output"
    DEBUG_DIR="$OUTPUT_DIR/DEBUG"

    # Binary names (EXENAME env var allows override, default: meshagent)
    BINARY_BASE="${EXENAME:-meshagent}"
    RELEASE_BINARY="${BINARY_BASE}_osx-universal-64"
    DEBUG_BINARY="DEBUG_${BINARY_BASE}_osx-universal-64"

    # Keychain profile name
    KEYCHAIN_PROFILE="${MACOS_NOTARY_PROFILE:-meshagent-notary}"

    # Check if DEBUG binaries should be notarized
    NOTARIZE_DEBUG="${DEBUG:-no}"

    # Custom binary path (if provided)
    CUSTOM_BINARY=""

    # Processing options
    VERBOSE=false

    #==============================================================================
    # PARSE COMMAND LINE ARGUMENTS
    #==============================================================================

    while [[ $# -gt 0 ]]; do
        case $1 in
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS] [BINARY_PATH]"
                echo ""
                echo "Notarize macOS universal binaries with Apple's notarization service"
                echo ""
                echo "Arguments:"
                echo "  BINARY_PATH   Path to a universal binary to notarize (optional)"
                echo "                If not provided, notarizes binaries in build/output/"
                echo ""
                echo "Options:"
                echo "  --verbose     Show detailed notarytool output"
                echo "  --help        Show this help message"
                echo ""
                echo "Environment Variables:"
                echo "  DEBUG=yes              Also notarize DEBUG binaries (ignored with BINARY_PATH)"
                echo "  MACOS_NOTARY_PROFILE   Keychain profile name (default: meshagent-notary)"
                echo ""
                echo "One-time setup:"
                echo "  xcrun notarytool store-credentials \"$KEYCHAIN_PROFILE\" \\"
                echo "    --apple-id \"developer@example.com\" \\"
                echo "    --team-id \"TEAMID\" \\"
                echo "    --password \"xxxx-xxxx-xxxx-xxxx\""
                echo ""
                echo "Examples:"
                echo "  ./macos-notarize.sh                              # Notarize default binaries"
                echo "  ./macos-notarize.sh /path/to/meshagent_universal # Notarize specific binary"
                echo "  DEBUG=yes ./macos-notarize.sh                    # Notarize release + DEBUG"
                echo "  ./macos-notarize.sh --verbose                    # Show detailed output"
                echo ""
                echo "As a sourceable script:"
                echo "  source ./macos-notarize.sh"
                echo "  macos_notarize_binary /path/to/binary"
                echo "  macos_notarize_binary /path/to/binary --verbose"
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

    echo -e "${CYAN}macOS universal binary notarization${NC}"
    echo ""

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
        echo "  Notarize DEBUG: $NOTARIZE_DEBUG"
        echo "  Mode: default (build/output/)"

        # Check if output directory exists (only needed for default mode)
        if [ ! -d "$OUTPUT_DIR" ]; then
            echo -e "${RED}Error: Output directory not found: $OUTPUT_DIR${NC}"
            echo "  Build and sign binaries first"
            exit 1
        fi
    fi

    echo ""

    # Verify keychain profile exists
    if ! xcrun notarytool history --keychain-profile "$KEYCHAIN_PROFILE" &>/dev/null; then
        echo -e "${RED}Error: Keychain profile not found: $KEYCHAIN_PROFILE${NC}"
        echo ""
        echo "Set up the keychain profile once with:"
        echo "  xcrun notarytool store-credentials \"$KEYCHAIN_PROFILE\" \\"
        echo "    --apple-id \"developer@example.com\" \\"
        echo "    --team-id \"TEAMID\" \\"
        echo "    --password \"xxxx-xxxx-xxxx-xxxx\""
        exit 1
    fi

    echo -e "  ${GREEN}Keychain profile OK: $KEYCHAIN_PROFILE${NC}"
    echo ""

    #==============================================================================
    # PROCESS BINARIES
    #==============================================================================

    NOTARIZED_COUNT=0
    FAILED_COUNT=0

    # Prepare verbose flag for function calls
    VERBOSE_FLAG=""
    if [ "$VERBOSE" = true ]; then
        VERBOSE_FLAG="--verbose"
    fi

    if [ -n "$CUSTOM_BINARY" ]; then
        echo "Notarizing custom binary..."
        echo ""

        if macos_notarize_binary "$CUSTOM_BINARY" $VERBOSE_FLAG; then
            NOTARIZED_COUNT=$((NOTARIZED_COUNT + 1))
        else
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    else
        echo "Step 1: Notarize release universal binary"
        echo ""

        RELEASE_PATH="$OUTPUT_DIR/$RELEASE_BINARY"

        if [ -f "$RELEASE_PATH" ]; then
            if macos_notarize_binary "$RELEASE_PATH" $VERBOSE_FLAG; then
                NOTARIZED_COUNT=$((NOTARIZED_COUNT + 1))
            else
                FAILED_COUNT=$((FAILED_COUNT + 1))
            fi
        else
            echo -e "${RED}Error: Release binary not found: $RELEASE_PATH${NC}"
            echo "  Build and sign the universal binary first"
            exit 1
        fi

        if [ "$NOTARIZE_DEBUG" = "yes" ]; then
            echo "Step 2: Notarize DEBUG universal binary"
            echo ""

            DEBUG_PATH="$DEBUG_DIR/$DEBUG_BINARY"

            if [ -f "$DEBUG_PATH" ]; then
                if macos_notarize_binary "$DEBUG_PATH" $VERBOSE_FLAG; then
                    NOTARIZED_COUNT=$((NOTARIZED_COUNT + 1))
                else
                    FAILED_COUNT=$((FAILED_COUNT + 1))
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

    echo ""
    echo -e "${GREEN}Notarization complete${NC}"
    echo "  Successful: $NOTARIZED_COUNT"
    echo "  Failed:     $FAILED_COUNT"

    if [ $FAILED_COUNT -gt 0 ]; then
        echo ""
        echo -e "${RED}Error: Some binaries failed notarization${NC}"
        echo "  Run with --verbose for detailed output"
        exit 1
    fi

    if [ $NOTARIZED_COUNT -eq 0 ]; then
        echo ""
        echo -e "${YELLOW}Warning: No binaries were notarized${NC}"
        exit 0
    fi

    echo ""

    if [ -n "$CUSTOM_BINARY" ]; then
        echo "Binary locations:"
        echo "  $CUSTOM_BINARY (universal, notarized)"
        base_name=$(basename "$CUSTOM_BINARY" | sed 's/-universal-64$//')
        custom_dir=$(dirname "$CUSTOM_BINARY")
        echo "  ${custom_dir}/${base_name}-arm-64 (arm64, inherits notarization)"
        echo "  ${custom_dir}/${base_name}-x86-64 (x86_64, inherits notarization)"
    else
        echo "Binary locations:"
        if [ -f "$RELEASE_PATH" ]; then
            echo "  Release:"
            echo "    $RELEASE_PATH (universal, notarized)"
            echo "    ${RELEASE_PATH/-universal-64/-arm-64} (arm64, inherits notarization)"
            echo "    ${RELEASE_PATH/-universal-64/-x86-64} (x86_64, inherits notarization)"
        fi
        if [ "$NOTARIZE_DEBUG" = "yes" ] && [ -f "$DEBUG_PATH" ]; then
            echo "  DEBUG:"
            echo "    $DEBUG_PATH (universal, notarized)"
            echo "    ${DEBUG_PATH/-universal-64/-arm-64} (arm64, inherits notarization)"
            echo "    ${DEBUG_PATH/-universal-64/-x86-64} (x86_64, inherits notarization)"
        fi
    fi

    echo ""
fi
