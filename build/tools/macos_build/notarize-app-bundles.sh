#!/bin/bash
# Notarize multiple macOS Application Bundles in parallel
# Usage: notarize-app-bundles.sh <bundle1.app> [bundle2.app] [bundle3.app] ...
#
# Submits all bundles to Apple's notary service, waits for all in parallel,
# then staples tickets to all bundles.
#
# Environment variables:
#   MACOS_NOTARY_PROFILE - Keychain profile name (default: meshagent-notary)

set -e  # Exit on any error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PROFILE="${MACOS_NOTARY_PROFILE:-meshagent-notary}"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <bundle1.app> [bundle2.app] [bundle3.app] ..."
    echo ""
    echo "Environment variables:"
    echo "  MACOS_NOTARY_PROFILE - Keychain profile name (default: meshagent-notary)"
    echo ""
    echo "Example:"
    echo "  $0 build/output/osx-universal-64-app/MeshAgent.app \\"
    echo "     build/output/osx-arm-64-app/MeshAgent.app \\"
    echo "     build/output/osx-x86-64-app/MeshAgent.app"
    exit 1
fi

BUNDLES=("$@")
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo -e "${CYAN}Parallel notarization of ${#BUNDLES[@]} bundle(s)${NC}"
echo "  Notary profile: $PROFILE"
echo ""

# Phase 1: Validate all bundles exist and are signed
echo "Phase 1: Validating bundles..."
for bundle in "${BUNDLES[@]}"; do
    if [ ! -d "$bundle" ]; then
        echo -e "${RED}Error: Bundle not found: $bundle${NC}"
        exit 1
    fi
    if ! codesign --verify --deep --strict "$bundle" 2>/dev/null; then
        echo -e "${RED}Error: Bundle is not properly signed: $bundle${NC}"
        echo "  Sign the bundle first with sign-app-bundle.sh"
        exit 1
    fi
    echo -e "  ${GREEN}OK: $bundle${NC}"
done

# Verify notary credentials exist
if ! xcrun notarytool history --keychain-profile "$PROFILE" &>/dev/null; then
    echo -e "${RED}Error: Notary profile not found: $PROFILE${NC}"
    echo ""
    echo "Please set up notary credentials with:"
    echo "  xcrun notarytool store-credentials $PROFILE \\"
    echo "    --apple-id \"developer@example.com\" \\"
    echo "    --team-id \"TEAMID\" \\"
    echo "    --password \"app-specific-password\""
    exit 1
fi

# Phase 2: Zip and submit all bundles
echo ""
echo "Phase 2: Zipping and submitting bundles..."
SUBMISSION_IDS=()
for i in "${!BUNDLES[@]}"; do
    bundle="${BUNDLES[$i]}"
    zip_name="$(basename "$bundle" .app)-${i}.zip"
    zip_path="$TEMP_DIR/$zip_name"

    echo ""
    echo "  Zipping: $bundle"
    ditto -c -k --keepParent "$bundle" "$zip_path"

    echo "  Submitting to Apple notary service..."
    SUBMIT_OUTPUT=$(xcrun notarytool submit "$zip_path" \
        --keychain-profile "$PROFILE" \
        2>&1)

    # Extract submission ID
    id=$(echo "$SUBMIT_OUTPUT" | grep '  id:' | head -1 | awk '{print $2}')
    if [ -z "$id" ]; then
        echo -e "${RED}Error: Failed to get submission ID for $bundle${NC}"
        echo "$SUBMIT_OUTPUT"
        exit 1
    fi

    SUBMISSION_IDS+=("$id")
    echo -e "  ${GREEN}Submitted: $bundle${NC} (ID: $id)"
done

# Phase 3: Wait for all notarizations in parallel
echo ""
echo "Phase 3: Waiting for notarization results (parallel)..."
WAIT_PIDS=()
WAIT_LOGS=()
for i in "${!SUBMISSION_IDS[@]}"; do
    log_file="$TEMP_DIR/wait-${i}.log"
    WAIT_LOGS+=("$log_file")
    xcrun notarytool wait "${SUBMISSION_IDS[$i]}" \
        --keychain-profile "$PROFILE" \
        --timeout 30m > "$log_file" 2>&1 &
    WAIT_PIDS+=($!)
    echo "  Waiting on: ${BUNDLES[$i]} (ID: ${SUBMISSION_IDS[$i]})"
done

FAILED=0
for i in "${!WAIT_PIDS[@]}"; do
    if ! wait "${WAIT_PIDS[$i]}"; then
        echo ""
        echo -e "${RED}FAILED: ${BUNDLES[$i]} (ID: ${SUBMISSION_IDS[$i]})${NC}"
        cat "${WAIT_LOGS[$i]}"
        echo ""
        echo "Fetching notarization log..."
        xcrun notarytool log "${SUBMISSION_IDS[$i]}" \
            --keychain-profile "$PROFILE" 2>&1 || true
        FAILED=1
    else
        echo -e "  ${GREEN}Accepted: ${BUNDLES[$i]}${NC}"
    fi
done

if [ $FAILED -ne 0 ]; then
    echo ""
    echo -e "${RED}Error: One or more notarizations failed${NC}"
    exit 1
fi

# Phase 4: Staple all bundles
echo ""
echo "Phase 4: Stapling notarization tickets..."
for bundle in "${BUNDLES[@]}"; do
    echo "  Stapling: $bundle"
    if xcrun stapler staple "$bundle" >/dev/null 2>&1; then
        echo -e "  ${GREEN}Stapled: $bundle${NC}"
    else
        echo -e "${RED}Error: Failed to staple $bundle${NC}"
        exit 1
    fi
done

# Phase 5: Verify with Gatekeeper
echo ""
echo "Phase 5: Verifying with Gatekeeper..."
for bundle in "${BUNDLES[@]}"; do
    if spctl -a -vvv -t install "$bundle" 2>&1 >/dev/null; then
        echo -e "  ${GREEN}Verified: $bundle${NC}"
    else
        echo -e "${YELLOW}Warning: Gatekeeper verification failed for $bundle${NC}"
    fi
done

echo ""
echo -e "${GREEN}Parallel notarization complete for ${#BUNDLES[@]} bundle(s)${NC}"
for bundle in "${BUNDLES[@]}"; do
    echo "  OK: $bundle"
done
