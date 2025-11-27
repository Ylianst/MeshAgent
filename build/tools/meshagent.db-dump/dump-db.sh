#!/bin/bash

#############################################################################
# MeshAgent Database Dump Utility
# Dumps the contents of a meshagent.db file to readable format
#############################################################################

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get repository root (3 levels up from this script)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_DIR="$( cd "$SCRIPT_DIR/../../.." && pwd )"

# Default paths
MESHAGENT_BINARY="$REPO_DIR/build/tools/code-utils/macos/meshagent_code-utils"
DEFAULT_DB_PATH="/opt/tacticalmesh/meshagent.db"

# Parse arguments
INPUT_PATH="${1:-$DEFAULT_DB_PATH}"
OUTPUT_FILE="${2:-}"

# Determine if input is a file or directory
DB_FILES=()

if [ -f "$INPUT_PATH" ]; then
    # Single file provided
    DB_FILES=("$INPUT_PATH")
elif [ -d "$INPUT_PATH" ]; then
    # Directory provided - find all .db files
    echo -e "${BLUE}Searching for .db files in: $INPUT_PATH${NC}"
    while IFS= read -r -d '' db_file; do
        DB_FILES+=("$db_file")
    done < <(find "$INPUT_PATH" -maxdepth 1 -name "*.db" -type f -print0 2>/dev/null)

    if [ ${#DB_FILES[@]} -eq 0 ]; then
        echo -e "${YELLOW}Error: No .db files found in directory: $INPUT_PATH${NC}"
        exit 1
    fi

    echo -e "${GREEN}Found ${#DB_FILES[@]} .db file(s)${NC}"
    echo ""
else
    echo -e "${YELLOW}Error: Path not found: $INPUT_PATH${NC}"
    echo ""
    echo "Usage: $0 [database-path-or-directory] [output-file]"
    echo ""
    echo "Examples:"
    echo "  $0"
    echo "  $0 /opt/tacticalmesh/meshagent.db"
    echo "  $0 /opt/tacticalmesh/"
    echo "  $0 /opt/tacticalmesh/meshagent.db dump.txt"
    exit 1
fi

# Check if meshagent binary exists
if [ ! -f "$MESHAGENT_BINARY" ]; then
    echo -e "${YELLOW}Error: meshagent binary not found at: $MESHAGENT_BINARY${NC}"
    exit 1
fi

# Function to dump a single database
dump_database() {
    local db_path="$1"
    local output_to_file="$2"
    local output_file="$3"

    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}MeshAgent Database Dump${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "Database: $db_path"
    echo -e "Size: $(ls -lh "$db_path" | awk '{print $5}')"
    echo ""

    # JavaScript code to dump database (single line to avoid parsing issues)
    # NOTE: db.Keys cannot be assigned to a variable - it must be accessed directly each time
    local js_code="var db = require('SimpleDataStore').Create('$db_path', { readOnly: true }); console.log('Total keys in database: ' + db.Keys.length); console.log(''); console.log('Database Contents:'); console.log('------------------------------------------'); for (var i = 0; i < db.Keys.length; i++) { var key = db.Keys[i]; var value = db.Get(key); if (value == null) { console.log(key + ' = <null>'); } else if (typeof value === 'string') { if (value.length === 0) { console.log(key + ' = <empty string>'); } else { var printable = true; for (var j = 0; j < value.length; j++) { var code = value.charCodeAt(j); if (code < 32 && code !== 10 && code !== 13) { printable = false; break; } } if (printable) { var displayValue = value.replace(/\n/g, '\\\\n').replace(/\r/g, '\\\\r'); if (displayValue.length > 200) { displayValue = displayValue.substring(0, 200) + '... (truncated)'; } console.log(key + ' = ' + displayValue); } else { console.log(key + ' = <binary string, ' + value.length + ' bytes>'); } } } else if (Buffer.isBuffer(value)) { console.log(key + ' = <buffer, ' + value.length + ' bytes>'); } else { console.log(key + ' = <' + typeof value + '>'); } } console.log('------------------------------------------'); console.log(''); console.log('Dump complete: ' + db.Keys.length + ' keys'); process.exit(0);"

    # Execute dump
    if [ "$output_to_file" = "true" ]; then
        # Save to file
        "$MESHAGENT_BINARY" -exec "$js_code" >> "$output_file" 2>&1

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Database dumped successfully${NC}"
        else
            echo -e "${YELLOW}Error: Failed to dump database${NC}"
            return 1
        fi
    else
        # Output to console
        "$MESHAGENT_BINARY" -exec "$js_code" 2>&1

        if [ $? -ne 0 ]; then
            echo -e "${YELLOW}Error: Failed to dump database${NC}"
            return 1
        fi
    fi

    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo ""

    return 0
}

# Process all database files
if [ -n "$OUTPUT_FILE" ]; then
    # Save to file - clear file first if multiple databases
    if [ ${#DB_FILES[@]} -gt 1 ]; then
        echo "Processing ${#DB_FILES[@]} database files..." > "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    else
        > "$OUTPUT_FILE"
    fi

    echo -e "${GREEN}Dumping database(s) to: $OUTPUT_FILE${NC}"
    echo ""

    for db_file in "${DB_FILES[@]}"; do
        dump_database "$db_file" "true" "$OUTPUT_FILE"
    done

    echo -e "${GREEN}✓ All databases dumped to: $OUTPUT_FILE${NC}"
    echo ""
    echo "Preview (first 20 lines):"
    head -20 "$OUTPUT_FILE"
else
    # Output to console
    for db_file in "${DB_FILES[@]}"; do
        dump_database "$db_file" "false" ""
    done
fi