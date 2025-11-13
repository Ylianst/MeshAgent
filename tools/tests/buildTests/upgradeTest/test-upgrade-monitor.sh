#!/bin/bash

################################################################################
# MeshAgent -upgrade Monitor & Validation Test
################################################################################
#
# This script tests the -upgrade command by:
# 1. Capturing complete state before upgrade (.msh, .db, plists)
# 2. Running upgrade with specified parameters
# 3. Monitoring process startup (root → run file → user process)
# 4. Capturing complete state after upgrade
# 5. Reporting all changes and validating success
#
# Usage:
#   sudo ./test-upgrade-monitor.sh [--installPath="/opt/tacticalmesh"] \
#                                   [--meshServiceName="TacticalMesh"] \
#                                   [--companyName="Peet, Inc."]
#
# Options:
#   --installPath=PATH          Path to meshagent installation
#                               (default: /usr/local/mesh_services/meshagent)
#   --meshServiceName=NAME      Service name for upgrade (optional)
#   --companyName=NAME          Company name for upgrade (optional)
#   --timeout=SECONDS           Timeout for run file monitoring (default: 90)
#   --verbose                   Show detailed output
#   --help                      Show this help message
#
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
UPGRADE_BINARY="$REPO_ROOT/build/macos/universal/meshagent"
DUMP_DB_SCRIPT="$REPO_ROOT/tests/dump-db.sh"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$SCRIPT_DIR/test-upgrade-monitor_${TIMESTAMP}.log"

# Test parameters
INSTALL_PATH="/usr/local/mesh_services/meshagent"
MESH_SERVICE_NAME=""
COMPANY_NAME=""
TIMEOUT=90
VERBOSE=0

# Calculated values
SERVICE_ID=""
QUEUE_FOLDERS_PATH=""

# State capture
BEFORE_STATE=""
AFTER_STATE=""

################################################################################
# Helper Functions
################################################################################

log() {
    echo "$@" | tee -a "$LOG_FILE"
}

log_verbose() {
    if [ $VERBOSE -eq 1 ]; then
        echo "$@" | tee -a "$LOG_FILE"
    else
        echo "$@" >> "$LOG_FILE"
    fi
}

print_header() {
    if [ -t 1 ]; then
        echo -e "\n${BLUE}==== $1 ====${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "\n==== $1 ====" | tee -a "$LOG_FILE"
    fi
}

print_success() {
    if [ -t 1 ]; then
        echo -e "${GREEN}✓ $1${NC}" | tee -a "$LOG_FILE"
    else
        echo "✓ $1" | tee -a "$LOG_FILE"
    fi
}

print_error() {
    if [ -t 1 ]; then
        echo -e "${RED}✗ $1${NC}" | tee -a "$LOG_FILE"
    else
        echo "✗ $1" | tee -a "$LOG_FILE"
    fi
}

print_warning() {
    if [ -t 1 ]; then
        echo -e "${YELLOW}⚠ $1${NC}" | tee -a "$LOG_FILE"
    else
        echo "⚠ $1" | tee -a "$LOG_FILE"
    fi
}

print_info() {
    if [ -t 1 ]; then
        echo -e "${CYAN}ℹ $1${NC}" | tee -a "$LOG_FILE"
    else
        echo "ℹ $1" | tee -a "$LOG_FILE"
    fi
}

show_help() {
    cat << EOF
MeshAgent -upgrade Monitor & Validation Test

Usage: sudo $0 [options]

Options:
  --installPath=PATH          Path to meshagent installation
                              (default: /usr/local/mesh_services/meshagent)
  --meshServiceName=NAME      Service name for upgrade
  --companyName=NAME          Company name for upgrade
  --timeout=SECONDS           Timeout for run file monitoring (default: 90)
  --verbose                   Show detailed output
  --help                      Show this help message

Examples:
  # Test baseline upgrade with default path
  sudo $0

  # Test baseline upgrade (no parameters)
  sudo $0 --installPath="/opt/tacticalmesh"

  # Test with service name override
  sudo $0 --installPath="/opt/tacticalmesh" --meshServiceName="NewService"

  # Test with full parameters
  sudo $0 --installPath="/opt/tacticalmesh" \\
          --meshServiceName="TacticalMesh" \\
          --companyName="Peet, Inc."

EOF
    exit 0
}

################################################################################
# Service ID Calculation
################################################################################

calculate_service_id() {
    local service_name="$1"
    local company_name="$2"

    if [ -z "$service_name" ]; then
        echo ""
        return
    fi

    # Remove spaces and special characters, replace with hyphens
    local sanitized_service="${service_name// /-}"
    sanitized_service="${sanitized_service//[^a-zA-Z0-9-]/}"

    if [ -n "$company_name" ]; then
        local sanitized_company="${company_name// /-}"
        sanitized_company="${sanitized_company//[^a-zA-Z0-9-]/}"
        echo "meshagent.${sanitized_service}.${sanitized_company}"
    else
        echo "meshagent.${sanitized_service}"
    fi
}

################################################################################
# State Capture Functions
################################################################################

capture_msh_state() {
    local msh_file="$INSTALL_PATH/meshagent.msh"

    if [ -f "$msh_file" ]; then
        echo "=== .msh FILE EXISTS ==="
        cat "$msh_file" 2>/dev/null || echo "ERROR: Could not read .msh file"
    else
        echo "=== .msh FILE DOES NOT EXIST ==="
    fi
}

capture_db_state() {
    echo "=== DATABASE STATE ==="

    if [ -x "$DUMP_DB_SCRIPT" ]; then
        # Pass directory to dump-db.sh - it will find and dump all .db files
        "$DUMP_DB_SCRIPT" "$INSTALL_PATH" 2>/dev/null || echo "ERROR: Could not dump database(s)"
    else
        echo "Note: dump-db.sh not available, skipping database dump"
    fi
}

capture_launchdaemon_state() {
    echo "=== LAUNCHDAEMONS ==="

    local found=0
    for plist in /Library/LaunchDaemons/meshagent*.plist; do
        if [ -f "$plist" ]; then
            found=1
            echo "--- $(basename "$plist") ---"

            # Extract Label
            local label=$(defaults read "$plist" Label 2>/dev/null || echo "N/A")
            echo "Label: $label"

            # Extract ProgramArguments
            local prog_args=$(defaults read "$plist" ProgramArguments 2>/dev/null || echo "N/A")
            if [ "$prog_args" != "N/A" ]; then
                echo "ProgramArguments:"
                echo "$prog_args" | grep -E "^\s+(meshServiceName|companyName)" || echo "  (no arguments)"
            fi
            echo ""
        fi
    done

    if [ $found -eq 0 ]; then
        echo "No LaunchDaemons found"
    fi
}

capture_launchagent_state() {
    echo "=== LAUNCHAGENTS ==="

    local found=0
    for plist in /Library/LaunchAgents/meshagent*.plist; do
        if [ -f "$plist" ]; then
            found=1
            echo "--- $(basename "$plist") ---"

            # Extract Label
            local label=$(defaults read "$plist" Label 2>/dev/null || echo "N/A")
            echo "Label: $label"

            # Extract QueueDirectories (important for monitoring)
            local queue_dirs=$(defaults read "$plist" QueueDirectories 2>/dev/null || echo "N/A")
            if [ "$queue_dirs" != "N/A" ]; then
                echo "QueueDirectories:"
                echo "$queue_dirs" | grep -Eo '"/[^"]+"' | tr -d '"' | sed 's/^/  /'
            else
                echo "QueueDirectories: (none)"
            fi

            # Extract ProgramArguments
            local prog_args=$(defaults read "$plist" ProgramArguments 2>/dev/null || echo "N/A")
            if [ "$prog_args" != "N/A" ]; then
                echo "ProgramArguments:"
                echo "$prog_args" | grep -E "^\s+(meshServiceName|companyName)" || echo "  (no arguments)"
            fi
            echo ""
        fi
    done

    if [ $found -eq 0 ]; then
        echo "No LaunchAgents found"
    fi
}

capture_complete_state() {
    echo "================================================================================"
    echo "SYSTEM STATE CAPTURE - $(date)"
    echo "================================================================================"
    echo ""

    capture_msh_state
    echo ""

    capture_db_state
    echo ""

    capture_launchdaemon_state
    echo ""

    capture_launchagent_state
    echo ""

    echo "================================================================================"
}

################################################################################
# Process Monitoring Functions
################################################################################

check_root_process() {
    # Check for root meshagent process and return PID if found
    pgrep -u root -f "$INSTALL_PATH/meshagent" 2>/dev/null | head -n 1
}

check_user_process() {
    # Check for non-root meshagent process and return PID if found
    # Note: When run as root with sudo, we look for processes NOT owned by root
    pgrep -u $(who am i | awk '{print $1}') -f "$INSTALL_PATH/meshagent" 2>/dev/null | head -n 1
}

get_queue_folders_path() {
    local service_id="$1"

    # Try to find and read from LaunchAgent plist (user process uses QueueDirectories)
    local agent_plist=""

    if [ -n "$service_id" ]; then
        # Try exact match with -agent suffix
        agent_plist="/Library/LaunchAgents/${service_id}-agent.plist"
        if [ ! -f "$agent_plist" ]; then
            # Try without -agent suffix
            agent_plist="/Library/LaunchAgents/${service_id}.plist"
        fi
    fi

    # If no specific plist found, search for any meshagent LaunchAgent
    if [ ! -f "$agent_plist" ]; then
        agent_plist=$(find /Library/LaunchAgents -name "meshagent*.plist" -type f 2>/dev/null | head -n 1)
    fi

    # Try to read QueueDirectories from the plist
    if [ -f "$agent_plist" ]; then
        local queue_dir=$(defaults read "$agent_plist" QueueDirectories 2>/dev/null | grep -Eo '"/[^"]+"' | head -n 1 | tr -d '"')
        if [ -n "$queue_dir" ]; then
            echo "$queue_dir"
            return
        fi
    fi

    # Fallback: Search for QueueDirectories in /var/run
    local qd_path=$(find /var/run -maxdepth 1 -type d -name "meshagent*" 2>/dev/null | head -n 1)
    if [ -n "$qd_path" ]; then
        echo "$qd_path"
        return
    fi

    # Last resort: Search /var/opt for old-style queuefolders
    local qf_path=$(find /var/opt -maxdepth 1 -type d -name "*queuefolders" 2>/dev/null | head -n 1)
    echo "$qf_path"
}

check_run_file() {
    local queue_path="$1"

    if [ -z "$queue_path" ] || [ ! -d "$queue_path" ]; then
        return 1
    fi

    # Look for any files in QueueDirectories (e.g., session-active, *.run, etc.)
    # Exclude just the directory itself (.)
    local file_count=$(find "$queue_path" -mindepth 1 -type f 2>/dev/null | wc -l)
    if [ "$file_count" -gt 0 ]; then
        return 0
    fi
    return 1
}

monitor_startup_sequence() {
    local timeout_seconds="$1"

    print_header "Monitoring Startup Sequence"

    # Step 1: Wait for root meshagent process
    log_verbose "Checking for root meshagent process..."
    local start_time=$(date +%s)
    local root_pid=""

    while [ $(($(date +%s) - start_time)) -lt 10 ]; do
        root_pid=$(check_root_process)
        if [ -n "$root_pid" ]; then
            print_success "Root meshagent process detected (PID: $root_pid)"
            break
        fi
        sleep 0.5
    done

    if [ -z "$root_pid" ]; then
        print_warning "Root meshagent process not detected (may have started before monitoring)"
    fi

    # Step 2: Monitor QueueFolders for run file
    if [ -n "$QUEUE_FOLDERS_PATH" ]; then
        print_info "Monitoring QueueFolders path: $QUEUE_FOLDERS_PATH"
    else
        print_warning "QueueFolders path could not be determined"
    fi
    print_info "Timeout: ${timeout_seconds} seconds"

    start_time=$(date +%s)
    local run_file_found=0

    while [ $(($(date +%s) - start_time)) -lt "$timeout_seconds" ]; do
        if check_run_file "$QUEUE_FOLDERS_PATH"; then
            local elapsed=$(($(date +%s) - start_time))
            local files_found=$(find "$QUEUE_FOLDERS_PATH" -mindepth 1 -type f -exec basename {} \; 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
            print_success "File(s) detected in QueueDirectories after ${elapsed} seconds: $files_found"
            run_file_found=1
            break
        fi
        sleep 1
    done

    if [ $run_file_found -eq 0 ]; then
        print_error "No files detected in QueueDirectories within ${timeout_seconds} seconds"
        return 1
    fi

    # Step 3: Monitor for user meshagent process
    log_verbose "Checking for user meshagent process..."
    start_time=$(date +%s)
    local user_pid=""

    while [ $(($(date +%s) - start_time)) -lt 10 ]; do
        user_pid=$(check_user_process)
        if [ -n "$user_pid" ]; then
            print_success "User meshagent process detected (PID: $user_pid)"
            break
        fi
        sleep 0.5
    done

    if [ -z "$user_pid" ]; then
        print_warning "User meshagent process not detected"
    fi

    return 0
}

################################################################################
# Diff Report Generation
################################################################################

generate_diff_report() {
    log ""
    log "=== .msh FILE CHANGES ==="

    local before_msh=$(echo "$BEFORE_STATE" | sed -n '/=== \.msh FILE/,/^$/p')
    local after_msh=$(echo "$AFTER_STATE" | sed -n '/=== \.msh FILE/,/^$/p')

    if [ "$before_msh" = "$after_msh" ]; then
        log "✓ No changes to .msh file"
    else
        log "⚠ .msh file changed:"
        diff -u <(echo "$before_msh") <(echo "$after_msh") | tail -n +4 || true
    fi

    log ""
    log "=== DATABASE CHANGES ==="

    local before_db=$(echo "$BEFORE_STATE" | sed -n '/Database Contents:/,/Dump complete:/p')
    local after_db=$(echo "$AFTER_STATE" | sed -n '/Database Contents:/,/Dump complete:/p')

    if [ "$before_db" = "$after_db" ]; then
        log "✓ No changes to database"
    else
        log "⚠ Database changed:"
        diff -u <(echo "$before_db") <(echo "$after_db") | tail -n +4 | grep -E "^[\+\-]" | grep -v "^[\+\-][\+\-][\+\-]" || true
    fi

    log ""
    log "=== LAUNCHDAEMON CHANGES ==="

    local before_daemon=$(echo "$BEFORE_STATE" | awk '/=== LAUNCHDAEMONS ===/,/=== LAUNCHAGENTS ===/{if (!/=== LAUNCHAGENTS ===/) print}')
    local after_daemon=$(echo "$AFTER_STATE" | awk '/=== LAUNCHDAEMONS ===/,/=== LAUNCHAGENTS ===/{if (!/=== LAUNCHAGENTS ===/) print}')

    if [ "$before_daemon" = "$after_daemon" ]; then
        log "✓ No changes to LaunchDaemons"
    else
        log "⚠ LaunchDaemon changed:"
        diff -u <(echo "$before_daemon") <(echo "$after_daemon") | tail -n +4 || true
    fi

    log ""
    log "=== LAUNCHAGENT CHANGES ==="

    local before_agent=$(echo "$BEFORE_STATE" | awk '/=== LAUNCHAGENTS ===/,/^========/{if (!/^========/) print}')
    local after_agent=$(echo "$AFTER_STATE" | awk '/=== LAUNCHAGENTS ===/,/^========/{if (!/^========/) print}')

    if [ "$before_agent" = "$after_agent" ]; then
        log "✓ No changes to LaunchAgents"
    else
        log "⚠ LaunchAgent changed:"
        diff -u <(echo "$before_agent") <(echo "$after_agent") | tail -n +4 || true
    fi

    log ""
    log "=== BINARY CHANGES ==="

    local before_size=$(stat -f%z "$INSTALL_PATH/meshagent" 2>/dev/null || echo "0")
    local upgrade_size=$(stat -f%z "$UPGRADE_BINARY" 2>/dev/null || echo "0")

    if [ "$before_size" -eq "$upgrade_size" ]; then
        log "✓ Binary size unchanged: $before_size bytes"
    else
        log "⚠ Binary size changed:"
        log "   Before: $before_size bytes"
        log "   After:  $upgrade_size bytes"
        log "   Diff:   $(( upgrade_size - before_size )) bytes"
    fi

    log ""
}

################################################################################
# Main Test Flow
################################################################################

run_upgrade_test() {
    print_header "MeshAgent -upgrade Monitor Test"
    log "Test started: $(date)"
    log "Log file: $LOG_FILE"
    log ""

    # Validate prerequisites
    print_header "Prerequisites Check"

    if [ ! -x "$UPGRADE_BINARY" ]; then
        print_error "Upgrade binary not found or not executable: $UPGRADE_BINARY"
        exit 1
    fi
    print_success "Upgrade binary found: $UPGRADE_BINARY"

    if [ ! -d "$INSTALL_PATH" ]; then
        print_error "Installation path does not exist: $INSTALL_PATH"
        exit 1
    fi
    print_success "Installation path exists: $INSTALL_PATH"

    # Calculate service ID and QueueFolders path
    if [ -n "$MESH_SERVICE_NAME" ]; then
        SERVICE_ID=$(calculate_service_id "$MESH_SERVICE_NAME" "$COMPANY_NAME")
        print_info "Expected Service ID: $SERVICE_ID"
    else
        print_info "No service name specified - will use existing configuration"
    fi

    QUEUE_FOLDERS_PATH=$(get_queue_folders_path "$SERVICE_ID")
    if [ -n "$QUEUE_FOLDERS_PATH" ]; then
        print_info "QueueFolders path: $QUEUE_FOLDERS_PATH"
    fi

    log ""

    # Capture state BEFORE upgrade
    print_header "Capturing State BEFORE Upgrade"
    BEFORE_STATE=$(capture_complete_state)
    echo "$BEFORE_STATE" | tee -a "$LOG_FILE"

    # Build upgrade command
    local upgrade_cmd="$UPGRADE_BINARY -upgrade --installPath=\"$INSTALL_PATH\""
    if [ -n "$MESH_SERVICE_NAME" ]; then
        upgrade_cmd="$upgrade_cmd --meshServiceName=\"$MESH_SERVICE_NAME\""
    fi
    if [ -n "$COMPANY_NAME" ]; then
        upgrade_cmd="$upgrade_cmd --companyName=\"$COMPANY_NAME\""
    fi

    print_header "Running Upgrade Command"
    log "Command: $upgrade_cmd"
    log ""

    # Run upgrade command
    if eval "$upgrade_cmd" 2>&1 | tee -a "$LOG_FILE"; then
        print_success "Upgrade command completed successfully"
    else
        print_error "Upgrade command failed"
        exit 1
    fi

    log ""

    # Capture state immediately after upgrade (before services start)
    print_header "Capturing State IMMEDIATELY After Upgrade (Pre-Startup)"
    print_info "This shows file changes made by upgrade, before services start"
    echo ""

    capture_msh_state | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    capture_db_state | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    capture_launchdaemon_state | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    capture_launchagent_state | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Monitor startup sequence
    monitor_startup_sequence "$TIMEOUT"

    log ""

    # Wait a moment for everything to settle
    sleep 2

    # Capture state AFTER upgrade
    print_header "Capturing State AFTER Upgrade"
    AFTER_STATE=$(capture_complete_state)
    echo "$AFTER_STATE" | tee -a "$LOG_FILE"

    # Generate diff report
    print_header "Change Report - BEFORE vs AFTER"
    generate_diff_report

    # Report summary
    print_header "Test Summary"
    print_success "Upgrade test completed"
    log ""
    log "Review the BEFORE and AFTER states and Change Report above"
    log "Log file saved to: $LOG_FILE"
}

################################################################################
# Main Script Entry Point
################################################################################

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --installPath=*)
                INSTALL_PATH="${1#*=}"
                shift
                ;;
            --meshServiceName=*)
                MESH_SERVICE_NAME="${1#*=}"
                shift
                ;;
            --companyName=*)
                COMPANY_NAME="${1#*=}"
                shift
                ;;
            --timeout=*)
                TIMEOUT="${1#*=}"
                shift
                ;;
            --verbose)
                VERBOSE=1
                shift
                ;;
            --help)
                show_help
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                ;;
        esac
    done

    # INSTALL_PATH is already set to default, no validation needed

    # Check for root
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root (use sudo)"
        exit 1
    fi

    # Run the test
    run_upgrade_test
}

# Execute main function
main "$@"
