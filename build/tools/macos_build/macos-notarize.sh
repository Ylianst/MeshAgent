#!/bin/bash
# Notarize macOS targets (binaries and/or .app bundles)
#
# Usage: macos-notarize.sh <target> [target2] [target3] ...
#
# Each target is auto-detected:
#   - Directory ending in .app  → bundle (zip, submit, staple, Gatekeeper verify)
#   - Regular file              → binary (zip, submit, extract arch slices via lipo)
#
# 1 target  → sequential (submit --wait, then post-process)
# 2+ targets → parallel  (submit all, wait all in parallel, then post-process all)
#
# Environment Variables:
#   MACOS_NOTARY_PROFILE - Keychain profile name (default: meshagent-notary)
#   SKIP_STAPLE          - Set to "yes" to skip stapling bundles (default: no)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PROFILE="${MACOS_NOTARY_PROFILE:-meshagent-notary}"
SKIP_STAPLE="${SKIP_STAPLE:-no}"

#==============================================================================
# USAGE
#==============================================================================

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target> [target2] [target3] ..."
    echo ""
    echo "Targets can be any mix of .app bundles and bare Mach-O binaries."
    echo ""
    echo "Environment Variables:"
    echo "  MACOS_NOTARY_PROFILE   Keychain profile name (default: meshagent-notary)"
    echo "  SKIP_STAPLE            Set to \"yes\" to skip stapling (default: no)"
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

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo -e "${CYAN}macOS notarization${NC}"
echo "  Notary profile: $PROFILE"
echo "  Targets:        $#"
echo ""

# Validate all targets exist and are signed
echo "Validating targets..."
for target in "$@"; do
    if [ -d "$target" ] && [[ "$target" == *.app ]]; then
        if ! codesign --verify --deep --strict "$target" 2>/dev/null; then
            echo -e "${RED}Error: Bundle is not properly signed: $target${NC}"
            exit 1
        fi
        echo -e "  ${GREEN}OK (bundle): $target${NC}"
    elif [ -f "$target" ]; then
        if ! codesign -vvv "$target" &>/dev/null; then
            echo -e "${RED}Error: Binary is not signed: $target${NC}"
            exit 1
        fi
        echo -e "  ${GREEN}OK (binary): $target${NC}"
    else
        echo -e "${RED}Error: Target not found: $target${NC}"
        exit 1
    fi
done

# Verify notary credentials
if ! xcrun notarytool history --keychain-profile "$PROFILE" &>/dev/null; then
    echo -e "${RED}Error: Notary profile not found: $PROFILE${NC}"
    echo ""
    echo "Set up credentials with:"
    echo "  xcrun notarytool store-credentials $PROFILE \\"
    echo "    --apple-id \"developer@example.com\" \\"
    echo "    --team-id \"TEAMID\" \\"
    echo "    --password \"app-specific-password\""
    exit 1
fi

echo ""

#==============================================================================
# POST-PROCESSING FUNCTIONS
#==============================================================================

postprocess_bundle() {
    local bundle="$1"
    local name
    name=$(basename "$bundle")

    # Staple
    if [ "$SKIP_STAPLE" = "yes" ]; then
        echo -e "  ${YELLOW}Stapling skipped (SKIP_STAPLE=yes): $name${NC}"
    else
        if xcrun stapler staple "$bundle" >/dev/null 2>&1; then
            echo -e "  ${GREEN}Stapled: $name${NC}"
        else
            echo -e "  ${YELLOW}Warning: Failed to staple $name${NC}"
        fi
    fi

    # Gatekeeper verify
    if spctl -a -vvv -t install "$bundle" 2>&1 >/dev/null; then
        echo -e "  ${GREEN}Gatekeeper verified: $name${NC}"
    else
        echo -e "  ${YELLOW}Warning: Gatekeeper verification failed for $name${NC}"
    fi
}

postprocess_binary() {
    local binary="$1"
    local name
    name=$(basename "$binary")

    # Binaries cannot be stapled — extract arch slices instead
    if ! lipo -info "$binary" 2>/dev/null | grep -q "Non-fat file"; then
        echo "  Extracting architecture slices from $name..."

        local output_dir
        output_dir=$(dirname "$binary")
        local base_name
        base_name=$(basename "$binary" | sed 's/-universal-64$//')

        # Extract arm64 slice
        local arm64_path="$output_dir/${base_name}-arm-64"
        if lipo "$binary" -thin arm64 -output "$arm64_path" 2>/dev/null; then
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
        if lipo "$binary" -thin x86_64 -output "$x86_path" 2>/dev/null; then
            echo "    x86_64: $x86_path"
            if codesign -vvv "$x86_path" &>/dev/null; then
                echo -e "    ${GREEN}x86_64 signature verified (inherited)${NC}"
            else
                echo -e "    ${YELLOW}Warning: x86_64 signature could not be verified${NC}"
            fi
        else
            echo -e "    ${YELLOW}Warning: Could not extract x86_64 slice${NC}"
        fi
    fi
}

#==============================================================================
# CREATE ZIPS
#==============================================================================

TARGETS=("$@")
ZIP_PATHS=()

echo "Zipping targets..."
for i in "${!TARGETS[@]}"; do
    target="${TARGETS[$i]}"
    if [ -d "$target" ] && [[ "$target" == *.app ]]; then
        zip_path="$TEMP_DIR/bundle-${i}.zip"
        ditto -c -k --keepParent "$target" "$zip_path"
    else
        zip_path="$TEMP_DIR/binary-${i}.zip"
        local_dir=$(dirname "$target")
        local_file=$(basename "$target")
        (cd "$local_dir" && ditto -c -k "$local_file" "$zip_path")
    fi
    ZIP_PATHS+=("$zip_path")
    echo "  Zipped: $(basename "$target")"
done

echo ""

#==============================================================================
# SUBMIT & WAIT
#==============================================================================

NOTARIZED=0
FAILED=0

if [ ${#TARGETS[@]} -eq 1 ]; then
    # Single target: sequential submit --wait
    echo "Submitting to Apple notary service..."
    target="${TARGETS[0]}"
    name=$(basename "$target")

    if xcrun notarytool submit "${ZIP_PATHS[0]}" \
        --keychain-profile "$PROFILE" \
        --wait \
        --timeout 30m 2>&1 | tee "$TEMP_DIR/submit-0.log" | grep -q "status: Accepted"; then
        echo -e "  ${GREEN}Accepted: $name${NC}"
        NOTARIZED=1
    else
        echo -e "${RED}Error: Notarization failed for $name${NC}"
        cat "$TEMP_DIR/submit-0.log"
        FAILED=1
    fi
else
    # Multiple targets: parallel submit, then parallel wait
    echo "Submitting ${#TARGETS[@]} targets to Apple notary service..."
    SUBMISSION_IDS=()

    for i in "${!TARGETS[@]}"; do
        name=$(basename "${TARGETS[$i]}")
        SUBMIT_OUTPUT=$(xcrun notarytool submit "${ZIP_PATHS[$i]}" \
            --keychain-profile "$PROFILE" \
            2>&1)

        id=$(echo "$SUBMIT_OUTPUT" | grep '  id:' | head -1 | awk '{print $2}')
        if [ -z "$id" ]; then
            echo -e "${RED}Error: Failed to get submission ID for $name${NC}"
            echo "$SUBMIT_OUTPUT"
            exit 1
        fi

        SUBMISSION_IDS+=("$id")
        echo -e "  ${GREEN}Submitted: $name${NC} (ID: $id)"
    done

    echo ""
    echo "Waiting for notarization results (parallel)..."
    WAIT_PIDS=()
    for i in "${!SUBMISSION_IDS[@]}"; do
        log_file="$TEMP_DIR/wait-${i}.log"
        xcrun notarytool wait "${SUBMISSION_IDS[$i]}" \
            --keychain-profile "$PROFILE" \
            --timeout 30m > "$log_file" 2>&1 &
        WAIT_PIDS+=($!)
        echo "  Waiting: $(basename "${TARGETS[$i]}") (ID: ${SUBMISSION_IDS[$i]})"
    done

    for i in "${!WAIT_PIDS[@]}"; do
        name=$(basename "${TARGETS[$i]}")
        if wait "${WAIT_PIDS[$i]}"; then
            echo -e "  ${GREEN}Accepted: $name${NC}"
            NOTARIZED=$((NOTARIZED + 1))
        else
            echo -e "${RED}FAILED: $name (ID: ${SUBMISSION_IDS[$i]})${NC}"
            cat "$TEMP_DIR/wait-${i}.log"
            echo ""
            echo "Fetching notarization log..."
            xcrun notarytool log "${SUBMISSION_IDS[$i]}" \
                --keychain-profile "$PROFILE" 2>&1 || true
            FAILED=$((FAILED + 1))
        fi
    done
fi

if [ $FAILED -gt 0 ]; then
    echo ""
    echo -e "${RED}Error: $FAILED target(s) failed notarization${NC}"
    exit 1
fi

#==============================================================================
# POST-PROCESS
#==============================================================================

echo ""
echo "Post-processing..."
for target in "${TARGETS[@]}"; do
    if [ -d "$target" ] && [[ "$target" == *.app ]]; then
        postprocess_bundle "$target"
    else
        postprocess_binary "$target"
    fi
done

#==============================================================================
# SUMMARY
#==============================================================================

echo ""
echo -e "${GREEN}Notarization complete: ${#TARGETS[@]} target(s)${NC}"
for target in "${TARGETS[@]}"; do
    echo "  OK: $target"
done
