#!/bin/bash
#
# Test script for configurable binary/file names
# Tests that .msh/.db files and service names derive from the binary name
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test directory
TEST_DIR="/tmp/lithium-remote-test"
BUILD_DIR="$(cd "$(dirname "$0")/.." && pwd)/build/output"

# Binary to test (adjust if needed)
BINARY_NAME="meshagent_osx-arm-64"
BINARY_PATH="$BUILD_DIR/$BINARY_NAME"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}=== Cleanup ===${NC}"

    # Stop any running test services
    sudo launchctl bootout system /Library/LaunchDaemons/lithium-remote*.plist 2>/dev/null || true
    sudo launchctl bootout system /Library/LaunchDaemons/meshagent*.plist 2>/dev/null || true
    sudo launchctl bootout system /Library/LaunchDaemons/test-agent*.plist 2>/dev/null || true

    # Remove test plists
    sudo rm -f /Library/LaunchDaemons/lithium-remote*.plist 2>/dev/null || true
    sudo rm -f /Library/LaunchDaemons/test-agent*.plist 2>/dev/null || true

    # Remove test directories
    sudo rm -rf /usr/local/mesh_services/lithium-remote 2>/dev/null || true
    sudo rm -rf /usr/local/mesh_services/test-agent 2>/dev/null || true
    sudo rm -rf /usr/local/mesh_services/TestCompany 2>/dev/null || true
    rm -rf "$TEST_DIR" 2>/dev/null || true

    echo "Cleanup complete"
}

# Check if binary exists
check_binary() {
    if [ ! -f "$BINARY_PATH" ]; then
        echo -e "${RED}ERROR: Binary not found at $BINARY_PATH${NC}"
        echo "Please build the project first: make macos ARCHID=29"
        exit 1
    fi
    echo -e "${GREEN}Found binary: $BINARY_PATH${NC}"
}

# Create test .msh file
create_test_msh() {
    local msh_path="$1"
    cat > "$msh_path" << 'EOF'
MeshName=TestMesh
MeshType=2
MeshID=0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
ServerID=ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890
MeshServer=wss://test.example.com:443/agent.ashx
EOF
    echo "Created test .msh file: $msh_path"
}

# Test 1: Verify file naming with renamed binary
test_file_naming() {
    echo -e "\n${YELLOW}=== Test 1: File Naming with Renamed Binary ===${NC}"

    mkdir -p "$TEST_DIR/test1"

    # Copy and rename binary to "lithium-remote"
    cp "$BINARY_PATH" "$TEST_DIR/test1/lithium-remote"
    chmod +x "$TEST_DIR/test1/lithium-remote"

    # Create .msh file with matching name
    create_test_msh "$TEST_DIR/test1/lithium-remote.msh"

    echo "Testing with binary named 'lithium-remote'..."
    echo "Expected: Should look for lithium-remote.msh and create lithium-remote.db"
    echo ""

    # Run help to see if it starts
    "$TEST_DIR/test1/lithium-remote" -help 2>&1 | head -5 || true

    echo ""
    echo -e "${GREEN}Test 1: Manual verification needed${NC}"
    echo "  - Binary: $TEST_DIR/test1/lithium-remote"
    echo "  - MSH file: $TEST_DIR/test1/lithium-remote.msh"
}

# Test 2: Verify install path construction
test_install_paths() {
    echo -e "\n${YELLOW}=== Test 2: Install Path Construction ===${NC}"

    mkdir -p "$TEST_DIR/test2"

    # Copy and rename binary
    cp "$BINARY_PATH" "$TEST_DIR/test2/lithium-remote"
    chmod +x "$TEST_DIR/test2/lithium-remote"
    create_test_msh "$TEST_DIR/test2/lithium-remote.msh"

    echo "Running -install with verbose logging..."
    echo "Expected: Should use /usr/local/mesh_services/lithium-remote/"
    echo ""

    # Dry run with verbose to see paths (will fail without root, but shows intent)
    "$TEST_DIR/test2/lithium-remote" -install --log=3 2>&1 | grep -E "(installPath|path|Path)" | head -20 || true

    echo ""
    echo -e "${GREEN}Test 2: Check that paths use 'lithium-remote' not 'meshagent'${NC}"
}

# Test 3: Verify custom service name
test_custom_service_name() {
    echo -e "\n${YELLOW}=== Test 3: Custom Service Name ===${NC}"

    mkdir -p "$TEST_DIR/test3"

    # Copy binary with custom name
    cp "$BINARY_PATH" "$TEST_DIR/test3/test-agent"
    chmod +x "$TEST_DIR/test3/test-agent"
    create_test_msh "$TEST_DIR/test3/test-agent.msh"

    echo "Testing with binary named 'test-agent'..."
    echo "Expected default service name: test-agent"
    echo ""

    # Test with explicit service name override
    echo "With --serviceName=CustomService:"
    "$TEST_DIR/test3/test-agent" -install --serviceName=CustomService --log=3 2>&1 | grep -iE "(service|name)" | head -10 || true

    echo ""
    echo -e "${GREEN}Test 3: Verify service name derivation${NC}"
}

# Test 4: Simulate full install (requires sudo)
test_full_install() {
    echo -e "\n${YELLOW}=== Test 4: Full Install Simulation ===${NC}"

    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}Skipping (requires sudo). Run with: sudo $0 --full${NC}"
        return
    fi

    mkdir -p "$TEST_DIR/test4"

    # Copy and rename binary
    cp "$BINARY_PATH" "$TEST_DIR/test4/lithium-remote"
    chmod +x "$TEST_DIR/test4/lithium-remote"
    create_test_msh "$TEST_DIR/test4/lithium-remote.msh"

    echo "Installing lithium-remote..."
    "$TEST_DIR/test4/lithium-remote" -install --log=3

    echo ""
    echo "Checking created files..."

    # Check install directory
    if [ -d "/usr/local/mesh_services/lithium-remote" ]; then
        echo -e "${GREEN}✓ Install directory created: /usr/local/mesh_services/lithium-remote/${NC}"
        ls -la /usr/local/mesh_services/lithium-remote/
    else
        echo -e "${RED}✗ Install directory NOT found${NC}"
    fi

    # Check for .msh file with correct name
    if [ -f "/usr/local/mesh_services/lithium-remote/lithium-remote.msh" ]; then
        echo -e "${GREEN}✓ MSH file has correct name: lithium-remote.msh${NC}"
    else
        echo -e "${RED}✗ MSH file NOT found or wrong name${NC}"
        ls -la /usr/local/mesh_services/lithium-remote/*.msh 2>/dev/null || true
    fi

    # Check for plist with correct prefix
    if ls /Library/LaunchDaemons/lithium-remote*.plist 1>/dev/null 2>&1; then
        echo -e "${GREEN}✓ LaunchDaemon plist has correct prefix${NC}"
        ls -la /Library/LaunchDaemons/lithium-remote*.plist
    else
        echo -e "${RED}✗ LaunchDaemon plist NOT found or wrong prefix${NC}"
        ls -la /Library/LaunchDaemons/*agent*.plist 2>/dev/null || true
    fi
}

# Test 5: Verify uninstall with renamed binary
test_uninstall() {
    echo -e "\n${YELLOW}=== Test 5: Uninstall ===${NC}"

    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}Skipping (requires sudo). Run with: sudo $0 --full${NC}"
        return
    fi

    # Check if we have an installation to uninstall
    if [ ! -d "/usr/local/mesh_services/lithium-remote" ]; then
        echo "No installation to uninstall (run test 4 first)"
        return
    fi

    echo "Uninstalling lithium-remote..."
    /usr/local/mesh_services/lithium-remote/lithium-remote -fulluninstall --log=3 || \
        "$TEST_DIR/test4/lithium-remote" -fulluninstall --log=3 || true

    echo ""
    echo "Verifying uninstall..."

    if [ ! -d "/usr/local/mesh_services/lithium-remote" ]; then
        echo -e "${GREEN}✓ Install directory removed${NC}"
    else
        echo -e "${RED}✗ Install directory still exists${NC}"
        ls -la /usr/local/mesh_services/lithium-remote/
    fi

    if ! ls /Library/LaunchDaemons/lithium-remote*.plist 1>/dev/null 2>&1; then
        echo -e "${GREEN}✓ LaunchDaemon plist removed${NC}"
    else
        echo -e "${RED}✗ LaunchDaemon plist still exists${NC}"
    fi
}

# Print test commands for manual testing
print_manual_tests() {
    echo -e "\n${YELLOW}=== Manual Test Commands ===${NC}"
    echo ""
    echo "# 1. Build the project"
    echo "make clean && make macos ARCHID=29"
    echo ""
    echo "# 2. Create test directory with renamed binary"
    echo "mkdir -p /tmp/lithium-test"
    echo "cp build/output/meshagent_osx-arm-64 /tmp/lithium-test/lithium-remote"
    echo "chmod +x /tmp/lithium-test/lithium-remote"
    echo ""
    echo "# 3. Create matching .msh file"
    echo "cat > /tmp/lithium-test/lithium-remote.msh << 'EOF'"
    echo "MeshName=TestMesh"
    echo "MeshType=2"
    echo "MeshID=0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
    echo "ServerID=ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"
    echo "MeshServer=wss://test.example.com:443/agent.ashx"
    echo "EOF"
    echo ""
    echo "# 4. Test verbose install (shows paths without installing)"
    echo "/tmp/lithium-test/lithium-remote -install --log=3"
    echo ""
    echo "# 5. Actually install (requires sudo)"
    echo "sudo /tmp/lithium-test/lithium-remote -install --log=3"
    echo ""
    echo "# 6. Verify created files"
    echo "ls -la /usr/local/mesh_services/lithium-remote/"
    echo "ls -la /Library/LaunchDaemons/lithium-remote*.plist"
    echo ""
    echo "# 7. Check that .db file is created with correct name"
    echo "ls -la /usr/local/mesh_services/lithium-remote/*.db"
    echo ""
    echo "# 8. Uninstall"
    echo "sudo /usr/local/mesh_services/lithium-remote/lithium-remote -fulluninstall --log=3"
    echo ""
    echo "# 9. Test with custom service name"
    echo "sudo /tmp/lithium-test/lithium-remote -install --serviceName=MyCustomAgent --log=3"
    echo ""
    echo "# 10. Test with company name"
    echo "sudo /tmp/lithium-test/lithium-remote -install --companyName=MyCompany --log=3"
    echo "# Expected path: /usr/local/mesh_services/MyCompany/lithium-remote/"
}

# Main
main() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Configurable Names Test Suite${NC}"
    echo -e "${GREEN}========================================${NC}"

    # Parse arguments
    FULL_TEST=false
    if [ "$1" == "--full" ]; then
        FULL_TEST=true
    fi

    # Always cleanup first
    cleanup

    # Check binary exists
    check_binary

    # Run tests
    test_file_naming
    test_install_paths
    test_custom_service_name

    if [ "$FULL_TEST" = true ]; then
        test_full_install
        test_uninstall
    fi

    # Print manual test commands
    print_manual_tests

    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}Test Suite Complete${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "For full install/uninstall tests, run: sudo $0 --full"
}

main "$@"
