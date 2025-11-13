#!/bin/bash

#############################################################################
# MeshAgent Database Dump Utility (using strings)
# Dumps readable strings from meshagent.db file
#############################################################################

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default path
DEFAULT_DB_PATH="/opt/tacticalmesh/meshagent.db"

# Parse arguments
DB_PATH="${1:-$DEFAULT_DB_PATH}"
OUTPUT_FILE="${2:-}"

# Check if database exists
if [ ! -f "$DB_PATH" ]; then
    echo -e "${YELLOW}Error: Database not found at: $DB_PATH${NC}"
    echo ""
    echo "Usage: $0 [database-path] [output-file]"
    exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}MeshAgent Database Dump (strings)${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Database: $DB_PATH"
echo -e "Size: $(ls -lh "$DB_PATH" | awk '{print $5}')"
echo ""

# Function to dump database
dump_database() {
    echo "=== Configuration Keys ==="
    echo ""

    # Extract known configuration keys
    sudo strings "$DB_PATH" | while read -r line; do
        case "$line" in
            meshServiceName*)
                echo "$line"
                ;;
            companyName*)
                echo "$line"
                ;;
            MeshServer*)
                echo "$line"
                ;;
            MeshName*)
                echo "$line"
                ;;
            MeshID*)
                if [ ${#line} -lt 200 ]; then
                    echo "$line"
                fi
                ;;
            ServerID*)
                if [ ${#line} -lt 200 ]; then
                    echo "$line"
                fi
                ;;
            InstallFlags*)
                echo "$line"
                ;;
            Tag*)
                if [ ${#line} -lt 100 ]; then
                    echo "$line"
                fi
                ;;
        esac
    done | sort | uniq

    echo ""
    echo "=== All Readable Strings (first 100) ==="
    echo ""
    sudo strings "$DB_PATH" | head -100
}

# Execute dump
if [ -n "$OUTPUT_FILE" ]; then
    # Save to file
    echo -e "${GREEN}Dumping database to: $OUTPUT_FILE${NC}"
    echo ""

    dump_database > "$OUTPUT_FILE" 2>&1

    echo -e "${GREEN}✓ Database dumped successfully${NC}"
    echo "Output saved to: $OUTPUT_FILE"
    echo ""
    echo "Preview (first 30 lines):"
    head -30 "$OUTPUT_FILE"
else
    # Output to console
    dump_database
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${YELLOW}Note: This uses 'strings' which shows readable text but not the exact database structure.${NC}"
echo -e "${YELLOW}Values shown may include keys with historical/deleted values.${NC}"
echo -e "${BLUE}========================================${NC}"
