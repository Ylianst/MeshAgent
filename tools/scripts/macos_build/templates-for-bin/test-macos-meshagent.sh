#!/bin/bash
# MeshAgent macOS Development Testing Script v2
# Version: 2.0.0
# Builds, signs, and installs meshagent using built-in installation commands
#
# Features:
# - Build for Intel (ARCHID=16), ARM (ARCHID=29), or Universal (ARCHID=10005)
# - Uses meshagent's built-in installation commands (-install, -fullinstall, -upgrade, -uninstall, -fulluninstall)
# - All launchd operations handled by meshagent automatically
# - Optional polyfills regeneration, build skip, signing skip, git pull
#
# Usage:
#   sudo ./bin/test-macos-meshagent.sh --archid 29 --command install --installPath /opt/meshagent
#   sudo ./bin/test-macos-meshagent.sh --archid universal --command fullinstall --companyName YourCompany --meshServiceName meshagent

set -e  # Exit on error

# Get the repository root directory
# If copied to /bin, repo is parent; if in scripts/templates-for-bin, repo is two levels up
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [[ "$SCRIPT_DIR" == */bin ]]; then
    REPO_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"
else
    REPO_DIR="$( cd "$SCRIPT_DIR/../.." && pwd )"
fi
cd "$REPO_DIR"

#==============================================================================
# DEFAULT CONFIGURATION
#==============================================================================

ARCHID="10005"                     # Default: 10005=Universal (16=Intel x86-64, 29=ARM64, 10005=Universal)
SKIP_POLYFILLS=false           # Skip polyfills regeneration (use existing ILibDuktape_Polyfills.c)
SKIP_BUILD=false               # Skip build step (use existing binary)
SKIP_SIGN=false                # Skip signing step
SKIP_GIT_PULL=true            # Skip git pull before building
COMMAND="upgrade"                     # meshagent command: install, fullinstall, upgrade, uninstall, fulluninstall
INSTALLPATH="/opt/meshagent"                 # Installation path (use "-EMPTY-" to pass empty string to meshagent)
COMPANYNAME=""                 # Company name (use "-EMPTY-" to pass empty string to meshagent) - LEAVE EMPTY FOR UPGRADE
MESHSERVICENAME=""             # Service name (use "-EMPTY-" to pass empty string to meshagent) - LEAVE EMPTY FOR UPGRADE

#==============================================================================
# PARSE COMMAND LINE ARGUMENTS
#==============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --archid)
            ARCHID="$2"
            shift 2
            ;;
        --skip-polyfills)
            SKIP_POLYFILLS=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-sign)
            SKIP_SIGN=true
            shift
            ;;
        --git-pull)
            SKIP_GIT_PULL=false
            shift
            ;;
        --command)
            COMMAND="$2"
            shift 2
            ;;
        --installPath)
            INSTALLPATH="$2"
            shift 2
            ;;
        --companyName)
            COMPANYNAME="$2"
            shift 2
            ;;
        --meshServiceName)
            MESHSERVICENAME="$2"
            shift 2
            ;;
        --help)
            echo "Usage: sudo $0 [OPTIONS]"
            echo ""
            echo "MeshAgent Testing Script v2 - Build and install using meshagent's built-in commands"
            echo ""
            echo "Build Options:"
            echo "  --archid <16|29|10005>        Architecture to build (default: 10005)"
            echo "                                  16 = Intel x86_64 (osx-x86-64)"
            echo "                                  29 = Apple Silicon ARM64 (osx-arm-64)"
            echo "                                  10005 = Universal binary (osx-universal-64)"
            echo "  --skip-polyfills              Skip polyfills regeneration from modules/"
            echo "  --skip-build                  Skip build step, use existing binary"
            echo "  --skip-sign                   Skip signing step"
            echo "  --git-pull                    Pull latest changes before building"
            echo ""
            echo "Installation Commands:"
            echo "  --command <cmd>               Run meshagent installation command:"
            echo "                                  install       - Standard installation (requires .msh file)"
            echo "                                  fullinstall   - Complete installation (downloads config from server)"
            echo "                                  upgrade       - Update existing installation (preserves .db/.msh)"
            echo "                                  uninstall     - Remove installation"
            echo "                                  fulluninstall - Complete removal with cleanup"
            echo "  --installPath <path>          Installation directory (use '-EMPTY-' for empty string)"
            echo "  --companyName <name>          Company name (use '-EMPTY-' for empty string)"
            echo "  --meshServiceName <name>      Service name (use '-EMPTY-' for empty string)"
            echo ""
            echo "Command Details:"
            echo "  -install      : Installs meshagent with existing .msh configuration file."
            echo "                  Requires .msh file to be present in installPath."
            echo "                  Creates LaunchDaemon and LaunchAgent plists."
            echo ""
            echo "  -fullinstall  : Complete installation that downloads configuration from MeshCentral server."
            echo "                  Requires --url parameter with server URL."
            echo "                  Creates LaunchDaemon and LaunchAgent plists."
            echo ""
            echo "  -upgrade      : Updates existing meshagent installation."
            echo "                  Preserves existing .db and .msh files, only replaces binary."
            echo "                  Recreates LaunchDaemon and LaunchAgent plists."
            echo "                  Automatically called by MeshCentral server for updates."
            echo ""
            echo "  -uninstall    : Removes meshagent installation."
            echo "                  Stops and removes LaunchDaemon and LaunchAgent services."
            echo ""
            echo "  -fulluninstall: Complete removal of meshagent."
            echo "                  Removes installation, configuration, and cleans up orphaned plists."
            echo "                  More thorough than -uninstall."
            echo ""
            echo "Examples:"
            echo "  # Build and install with fullinstall (downloads config from server)"
            echo "  sudo $0 --archid 10005 --command fullinstall --installPath /opt/meshagent --companyName YourCompany"
            echo ""
            echo "  # Build and install with existing .msh file"
            echo "  sudo $0 --archid 29 --command install --installPath /usr/local/mesh_services/meshagent"
            echo ""
            echo "  # Upgrade existing installation with pre-built binary"
            echo "  sudo $0 --skip-build --command upgrade --installPath /opt/meshagent"
            echo ""
            echo "  # Uninstall meshagent"
            echo "  sudo $0 --skip-build --skip-sign --command fulluninstall --installPath /opt/meshagent"
            echo ""
            echo "  # Build only (no installation)"
            echo "  sudo $0 --archid 10005"
            echo "  sudo $0 --git-pull --skip-sign"
            exit 0
            ;;
        *)
            echo "Error: Unknown option $1"
            echo "Run with --help for usage information"
            exit 1
            ;;
    esac
done

#==============================================================================
# VALIDATE CONFIGURATION
#==============================================================================

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Validate ARCHID
if [[ "$ARCHID" != "16" && "$ARCHID" != "29" && "$ARCHID" != "10005" ]]; then
    echo "Error: Invalid ARCHID '$ARCHID'. Must be 16, 29, or 10005"
    exit 1
fi

# Validate COMMAND if set
if [ -n "$COMMAND" ]; then
    if [[ "$COMMAND" != "install" && "$COMMAND" != "fullinstall" && "$COMMAND" != "upgrade" && "$COMMAND" != "uninstall" && "$COMMAND" != "fulluninstall" ]]; then
        echo "Error: Invalid COMMAND '$COMMAND'."
        echo "Valid commands: install, fullinstall, upgrade, uninstall, fulluninstall"
        exit 1
    fi
fi

#==============================================================================
# DETERMINE BINARY PATH AND BUILD ARCHID
#==============================================================================

if [ "$ARCHID" = "16" ]; then
    BINARY_PATH="build/macos/meshagent_osx-x86-64"
    ARCH_DESC="Intel x86-64"
    BUILD_ARCHID="16"
elif [ "$ARCHID" = "29" ]; then
    BINARY_PATH="build/macos/meshagent_osx-arm-64"
    ARCH_DESC="Apple Silicon ARM64"
    BUILD_ARCHID="29"
elif [ "$ARCHID" = "10005" ]; then
    BINARY_PATH="build/macos/meshagent_osx-universal-64"
    ARCH_DESC="Universal (Intel + ARM)"
    BUILD_ARCHID="10005"  # Universal binary ARCHID
fi

#==============================================================================
# CONFIGURATION DISPLAY
#==============================================================================

echo "=========================================="
echo "MeshAgent Testing Configuration v2"
echo "=========================================="
echo "Start Time:       $(date '+%Y-%m-%d %H:%M:%S')"
echo "Architecture:     $ARCH_DESC"
echo "Skip Polyfills:   $SKIP_POLYFILLS"
echo "Skip Build:       $SKIP_BUILD"
echo "Skip Sign:        $SKIP_SIGN"
echo "Skip Git Pull:    $SKIP_GIT_PULL"
echo ""
if [ -n "$COMMAND" ]; then
    echo "Command:          -$COMMAND"
    if [ -n "$INSTALLPATH" ]; then
        if [ "$INSTALLPATH" = "-EMPTY-" ]; then
            echo "Install Path:     '' (will pass empty string)"
        else
            echo "Install Path:     $INSTALLPATH"
        fi
    else
        echo "Install Path:     (not set)"
    fi
    if [ -n "$COMPANYNAME" ]; then
        if [ "$COMPANYNAME" = "-EMPTY-" ]; then
            echo "Company Name:     '' (will pass empty string)"
        else
            echo "Company Name:     $COMPANYNAME"
        fi
    else
        echo "Company Name:     (not set)"
    fi
    if [ -n "$MESHSERVICENAME" ]; then
        if [ "$MESHSERVICENAME" = "-EMPTY-" ]; then
            echo "Service Name:     '' (will pass empty string)"
        else
            echo "Service Name:     $MESHSERVICENAME"
        fi
    else
        echo "Service Name:     (not set)"
    fi
    echo "LaunchD Mgmt:     Handled by meshagent"
else
    echo "Command:          (none - build only)"
fi
echo "=========================================="
echo ""

#==============================================================================
# GIT PULL STEP
#==============================================================================

if [ "$SKIP_GIT_PULL" = false ]; then
    echo "[0/5] Updating repository..."
    echo "[$(date '+%H:%M:%S')] Git pull started"
    # Run git pull as the actual user (not root)
    sudo -u $SUDO_USER git pull
    echo "[$(date '+%H:%M:%S')] Git pull complete"
    echo "✓ Repository updated"
    echo ""
else
    echo "[0/5] Git pull - SKIPPED"
    echo ""
fi

#==============================================================================
# POLYFILLS REGENERATION STEP
#==============================================================================

if [ "$SKIP_POLYFILLS" = false ]; then
    echo "[1/5] Regenerating polyfills from modules/..."
    echo "[$(date '+%H:%M:%S')] Polyfills regeneration started"

    # Check if minimal meshagent exists
    if [ ! -f "tools/meshagent/macos/meshagent" ]; then
        echo "  ERROR: Minimal meshagent not found at tools/meshagent/macos/meshagent"
        echo "  Please ensure the minimal meshagent binary exists"
        exit 1
    fi

    # Run as actual user to regenerate polyfills
    echo "  Reading modules from: ./modules/"
    echo "  Updating file: ./microscript/ILibDuktape_Polyfills.c"
    sudo -u $SUDO_USER ./tools/meshagent/macos/meshagent -import --expandedPath="./modules" --filePath="./microscript/ILibDuktape_Polyfills.c"

    echo "[$(date '+%H:%M:%S')] Polyfills regeneration complete"
    echo "✓ Polyfills regenerated from modules/"
    echo ""
else
    echo "[1/5] Polyfills regeneration - SKIPPED"
    echo ""
fi

#==============================================================================
# BUILD STEP
#==============================================================================

if [ "$SKIP_BUILD" = false ]; then
    echo "[2/5] Building meshagent ($ARCH_DESC)..."
    echo "[$(date '+%H:%M:%S')] Build started"
    # Run build as the actual user (not root)
    sudo -u $SUDO_USER make clean
    sudo -u $SUDO_USER make macos ARCHID=$BUILD_ARCHID

    echo "[$(date '+%H:%M:%S')] Build complete"
    echo "✓ Build complete"
    echo ""
else
    echo "[2/5] Build - SKIPPED"

    # If COMMAND is set and build is skipped, verify binary exists
    if [ -n "$COMMAND" ]; then
        if [ ! -f "$BINARY_PATH" ]; then
            echo ""
            echo "ERROR: Binary not found at $BINARY_PATH"
            echo "Cannot run command '$COMMAND' without a binary."
            echo ""
            echo "Solutions:"
            echo "  1. Remove --skip-build to build the binary"
            echo "  2. Build the binary first: make macos ARCHID=$BUILD_ARCHID"
            echo "  3. Ensure the binary exists at: $BINARY_PATH"
            exit 1
        fi
        echo "  ✓ Binary exists at $BINARY_PATH"
    fi
    echo ""
fi

#==============================================================================
# SIGNING STEP
#==============================================================================

if [ "$SKIP_SIGN" = false ]; then
    echo "[3/5] Signing binary..."
    echo "[$(date '+%H:%M:%S')] Signing started"
    sleep 2
    # Run signing as the actual user (not root) to access user's keychain
    # Pass the specific binary path to sign
    sudo -u $SUDO_USER ./bin/sign-and-notarize-macos.sh "$BINARY_PATH"
    echo "[$(date '+%H:%M:%S')] Signing complete"
    echo "✓ Signing complete"
    echo ""
else
    echo "[3/5] Signing - SKIPPED"
    echo ""
fi

#==============================================================================
# COMMAND EXECUTION
#==============================================================================

if [ -n "$COMMAND" ]; then
    echo "[4/5] Executing meshagent command..."
    echo "[$(date '+%H:%M:%S')] Command execution started"
    echo "  Command: -$COMMAND"
    echo "  Binary:  $BINARY_PATH"

    # Build command array - only include parameters that were explicitly set
    CMD_ARRAY=("./$BINARY_PATH" "-$COMMAND")

    # INSTALLPATH: empty string = skip, "-EMPTY-" = pass empty string, anything else = pass value
    if [ -n "$INSTALLPATH" ]; then
        if [ "$INSTALLPATH" = "-EMPTY-" ]; then
            CMD_ARRAY+=("--installPath=")
            echo "  Install Path: '' (empty string)"
        else
            CMD_ARRAY+=("--installPath=${INSTALLPATH}")
            echo "  Install Path: $INSTALLPATH"
        fi
    fi

    # COMPANYNAME: empty string = skip, "-EMPTY-" = pass empty string, anything else = pass value
    if [ -n "$COMPANYNAME" ]; then
        if [ "$COMPANYNAME" = "-EMPTY-" ]; then
            CMD_ARRAY+=("--companyName=")
            echo "  Company: '' (empty string)"
        else
            CMD_ARRAY+=("--companyName=${COMPANYNAME}")
            echo "  Company: $COMPANYNAME"
        fi
    fi

    # MESHSERVICENAME: empty string = skip, "-EMPTY-" = pass empty string, anything else = pass value
    if [ -n "$MESHSERVICENAME" ]; then
        if [ "$MESHSERVICENAME" = "-EMPTY-" ]; then
            CMD_ARRAY+=("--meshServiceName=")
            echo "  Service: '' (empty string)"
        else
            CMD_ARRAY+=("--meshServiceName=${MESHSERVICENAME}")
            echo "  Service: $MESHSERVICENAME"
        fi
    fi

    echo ""
    echo "Running command:"
    printf '  %s ' "${CMD_ARRAY[@]}"
    echo ""
    echo ""

    # Execute meshagent command
    "${CMD_ARRAY[@]}"

    echo ""
    echo "[$(date '+%H:%M:%S')] Command execution complete"
    echo "✓ Command '-$COMMAND' executed successfully"
    echo ""
else
    echo "[4/5] Command execution - SKIPPED (no command specified)"
    echo ""
fi

#==============================================================================
# SUMMARY
#==============================================================================

echo "=========================================="
echo "Script Complete!"
echo "=========================================="
echo "Architecture:     $ARCH_DESC"
echo "Binary:           $BINARY_PATH"

if [ -n "$COMMAND" ]; then
    echo "Command:          -$COMMAND"
    if [ -n "$INSTALLPATH" ]; then
        if [ "$INSTALLPATH" = "-EMPTY-" ]; then
            echo "Install Path:     '' (empty string)"
        else
            echo "Install Path:     $INSTALLPATH"
        fi
    fi
    echo ""
    echo "LaunchD services managed by meshagent"
    echo "To view logs:"
    echo "  sudo log stream --predicate 'process == \"meshagent\"' --level debug"
else
    echo "Command:          (none - binary built only)"
    echo ""
    echo "Binary available at: $BINARY_PATH"
    echo "To install, run with --command option"
fi

echo ""
echo "=========================================="
echo "End Time:         $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="
