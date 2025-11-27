#!/bin/bash
#
# populate-polyfills.sh
#
# This script uses meshagent_code-utils to embed all JavaScript modules from ./modules
# into the ILibDuktape_Polyfills.c file for distribution builds.
#
# The script:
# 1. Validates that required paths exist
# 2. Calls meshagent_code-utils with -import flag
# 3. Uses --expandedPath to specify the modules directory
# 4. Uses --filePath to specify the target C file
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Paths
CODE_UTILS_BINARY="$REPO_ROOT/build/tools/code-utils/macos/meshagent_code-utils"
MODULES_DIR="$REPO_ROOT/modules"
POLYFILLS_FILE="$REPO_ROOT/microscript/ILibDuktape_Polyfills.c"

# Parse command line arguments
VERBOSE=0
DRY_RUN=0
BACKUP=0
CUSTOM_MODULES_DIR=""
CUSTOM_POLYFILLS_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --backup)
            BACKUP=1
            shift
            ;;
        --modules-dir)
            CUSTOM_MODULES_DIR="$2"
            shift 2
            ;;
        --polyfills-file)
            CUSTOM_POLYFILLS_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Populate ILibDuktape_Polyfills.c with JavaScript modules using meshagent_code-utils"
            echo ""
            echo "Options:"
            echo "  -v, --verbose              Enable verbose output"
            echo "  --dry-run                  Show what would be done without executing"
            echo "  --backup                   Create backup of polyfills file before modification"
            echo "  --modules-dir DIR          Use custom modules directory (default: ./modules)"
            echo "  --polyfills-file FILE      Use custom polyfills file (default: ./microscript/ILibDuktape_Polyfills.c)"
            echo "  -h, --help                 Show this help message"
            echo ""
            echo "Example:"
            echo "  $0 --verbose"
            echo "  $0 --backup --modules-dir ./modules_custom"
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${NC}"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Override paths if custom ones provided
if [ -n "$CUSTOM_MODULES_DIR" ]; then
    MODULES_DIR="$CUSTOM_MODULES_DIR"
fi

if [ -n "$CUSTOM_POLYFILLS_FILE" ]; then
    POLYFILLS_FILE="$CUSTOM_POLYFILLS_FILE"
fi

# Validate paths
echo "Validating paths..."

if [ ! -f "$CODE_UTILS_BINARY" ]; then
    echo -e "${RED}Error: meshagent_code-utils binary not found at:${NC}"
    echo "  $CODE_UTILS_BINARY"
    echo ""
    echo "Please build the code-utils binary first:"
    echo "  ./build/tools/macos_build/macos-build_with_test.sh --code-utils"
    exit 1
fi

if [ ! -x "$CODE_UTILS_BINARY" ]; then
    echo -e "${RED}Error: meshagent_code-utils binary is not executable${NC}"
    echo "  $CODE_UTILS_BINARY"
    exit 1
fi

if [ ! -d "$MODULES_DIR" ]; then
    echo -e "${RED}Error: Modules directory not found at:${NC}"
    echo "  $MODULES_DIR"
    exit 1
fi

if [ ! -f "$POLYFILLS_FILE" ]; then
    echo -e "${RED}Error: ILibDuktape_Polyfills.c not found at:${NC}"
    echo "  $POLYFILLS_FILE"
    exit 1
fi

# Count modules
MODULE_COUNT=$(find "$MODULES_DIR" -name "*.js" -type f | wc -l | tr -d ' ')

echo -e "${GREEN}✓ All paths validated${NC}"
echo ""
echo "Configuration:"
echo "  Code-utils binary: $CODE_UTILS_BINARY"
echo "  Modules directory: $MODULES_DIR"
echo "  Polyfills file:    $POLYFILLS_FILE"
echo "  Module count:      $MODULE_COUNT .js files"
echo ""

# Backup the polyfills file if requested
if [ $BACKUP -eq 1 ]; then
    BACKUP_FILE="${POLYFILLS_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    echo "Creating backup: $BACKUP_FILE"

    if [ $DRY_RUN -eq 0 ]; then
        cp "$POLYFILLS_FILE" "$BACKUP_FILE"
        echo -e "${GREEN}✓ Backup created${NC}"
    else
        echo -e "${YELLOW}[DRY RUN] Would create backup${NC}"
    fi
    echo ""
fi

# Build the command
CMD_ARRAY=(
    "$CODE_UTILS_BINARY"
    "-import"
    "--expandedPath=$MODULES_DIR"
    "--filePath=$POLYFILLS_FILE"
    "--modulesPath=$MODULES_DIR"
)

if [ $VERBOSE -eq 1 ]; then
    echo "Command to execute:"
    printf '  %s \\\n' "${CMD_ARRAY[@]}"
    echo ""
fi

# Execute the command
echo "Embedding modules into ILibDuktape_Polyfills.c..."
echo ""

if [ $DRY_RUN -eq 1 ]; then
    echo -e "${YELLOW}[DRY RUN] Would execute:${NC}"
    printf '  %s \\\n' "${CMD_ARRAY[@]}"
    echo ""
    echo -e "${YELLOW}[DRY RUN] No changes made${NC}"
    exit 0
fi

# Change to repo root to ensure relative paths work
cd "$REPO_ROOT"

# Execute
if "${CMD_ARRAY[@]}"; then
    echo ""
    echo -e "${GREEN}✓ Success!${NC}"
    echo ""
    echo "Modules have been embedded into:"
    echo "  $POLYFILLS_FILE"

    if [ $BACKUP -eq 1 ]; then
        echo ""
        echo "Backup saved to:"
        echo "  $BACKUP_FILE"
        echo ""

        # Show file size change
        ORIGINAL_SIZE=$(stat -f%z "$BACKUP_FILE")
        NEW_SIZE=$(stat -f%z "$POLYFILLS_FILE")
        SIZE_DIFF=$((NEW_SIZE - ORIGINAL_SIZE))

        echo "File size change:"
        echo "  Original: $(numfmt --to=iec-i --suffix=B $ORIGINAL_SIZE 2>/dev/null || echo "${ORIGINAL_SIZE} bytes")"
        echo "  New:      $(numfmt --to=iec-i --suffix=B $NEW_SIZE 2>/dev/null || echo "${NEW_SIZE} bytes")"
        if [ $SIZE_DIFF -gt 0 ]; then
            echo -e "  Change:   ${GREEN}+$(numfmt --to=iec-i --suffix=B $SIZE_DIFF 2>/dev/null || echo "${SIZE_DIFF} bytes")${NC}"
        elif [ $SIZE_DIFF -lt 0 ]; then
            echo -e "  Change:   ${RED}$(numfmt --to=iec-i --suffix=B $SIZE_DIFF 2>/dev/null || echo "${SIZE_DIFF} bytes")${NC}"
        else
            echo "  Change:   No change"
        fi
    fi
    echo ""
else
    echo ""
    echo -e "${RED}✗ Failed to embed modules${NC}"

    if [ $BACKUP -eq 1 ]; then
        echo ""
        echo "Restoring from backup..."
        cp "$BACKUP_FILE" "$POLYFILLS_FILE"
        echo -e "${YELLOW}Original file restored${NC}"
    fi
    exit 1
fi
