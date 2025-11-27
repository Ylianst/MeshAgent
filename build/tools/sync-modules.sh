#!/bin/bash
# Unified module synchronization script
# Consolidates module sync logic from Makefile and build scripts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Default values
MODE="all"
VERBOSE="no"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE="yes"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--mode MODE] [--verbose]"
            echo ""
            echo "Modes:"
            echo "  all            Copy all modules/*.js to all platform directories (default)"
            echo "  macos-only     Copy modules in .modules_macos to modules_macos/ only"
            echo "  minimal        Copy modules in .modules_macos_minimal to modules_macos/ only"
            exit 1
            ;;
    esac
done

cd "$PROJECT_ROOT"

# Validate mode
case "$MODE" in
    all|macos-only|minimal)
        ;;
    *)
        echo "Error: Invalid mode '$MODE'. Use 'all', 'macos-only', or 'minimal'"
        exit 1
        ;;
esac

[ "$VERBOSE" = "yes" ] && echo "Module sync mode: $MODE"

# Mode: all - Copy all modules/*.js to all platform directories (Makefile behavior)
if [ "$MODE" = "all" ]; then
    [ "$VERBOSE" = "yes" ] && echo "Syncing all modules to platform-specific directories..."

    module_count=0
    for module in modules/*.js; do
        filename=$(basename "$module")
        [ "$VERBOSE" = "yes" ] && echo "  Syncing $filename..."

        # Copy to modules_macos if target exists
        if [ -f "modules_macos/$filename" ]; then
            sudo cp -f "$module" "modules_macos/$filename" 2>/dev/null || cp -f "$module" "modules_macos/$filename"
        fi

        # Copy to modules_linux-bsd if target exists
        if [ -f "modules_linux-bsd/$filename" ]; then
            sudo cp -f "$module" "modules_linux-bsd/$filename" 2>/dev/null || cp -f "$module" "modules_linux-bsd/$filename"
        fi

        # Copy to modules_windows if target exists
        if [ -f "modules_windows/$filename" ]; then
            sudo cp -f "$module" "modules_windows/$filename" 2>/dev/null || cp -f "$module" "modules_windows/$filename"
        fi

        ((module_count++))
    done

    [ "$VERBOSE" = "yes" ] && echo "Module sync complete ($module_count modules processed)"
    exit 0
fi

# Mode: macos-only or minimal - Copy specific modules to modules_macos only
if [ "$MODE" = "macos-only" ] || [ "$MODE" = "minimal" ]; then
    # Select module list file
    if [ "$MODE" = "macos-only" ]; then
        MODULE_LIST="modules/.modules_macos"
    else
        MODULE_LIST="modules/.modules_macos_minimal"
    fi

    if [ ! -f "$MODULE_LIST" ]; then
        echo "Error: Module list not found: $MODULE_LIST"
        exit 1
    fi

    [ "$VERBOSE" = "yes" ] && echo "Syncing macOS modules from $MODULE_LIST..."

    # Create modules_macos directory if needed
    mkdir -p modules_macos

    # Remove unauthorized modules (not in the list)
    deleted_count=0
    if [ -d "modules_macos" ]; then
        for existing_file in modules_macos/*.js; do
            [ ! -f "$existing_file" ] && continue

            module_name=$(basename "$existing_file")

            # Check if this module is in the authorized list
            if ! grep -Fxq "$module_name" "$MODULE_LIST"; then
                [ "$VERBOSE" = "yes" ] && echo "  Removing unauthorized module: $module_name"
                rm -f "$existing_file"
                ((deleted_count++))
            fi
        done
    fi

    [ "$VERBOSE" = "yes" ] && [ $deleted_count -gt 0 ] && echo "  Removed $deleted_count unauthorized modules"

    # Copy authorized modules
    module_count=0
    missing_count=0

    while IFS= read -r module || [ -n "$module" ]; do
        # Skip empty lines and comments
        [ -z "$module" ] && continue
        [[ "$module" =~ ^# ]] && continue

        source_file="modules/$module"
        dest_file="modules_macos/$module"

        if [ -f "$source_file" ]; then
            cp -f "$source_file" "$dest_file"
            ((module_count++))
        else
            [ "$VERBOSE" = "yes" ] && echo "  WARNING: Module not found: $module"
            ((missing_count++))
        fi
    done < "$MODULE_LIST"

    [ "$VERBOSE" = "yes" ] && echo "  Synced $module_count modules to modules_macos"
    [ "$VERBOSE" = "yes" ] && [ $missing_count -gt 0 ] && echo "  WARNING: $missing_count modules not found"

    exit 0
fi
