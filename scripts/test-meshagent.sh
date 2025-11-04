#!/bin/bash
# MeshAgent macOS Development Testing Script
# Version: 0.0.6
# Builds, signs, and deploys meshagent with configurable options
#
# Usage:
#   sudo ./scripts/test-meshagent.sh --archid 29 --daemon enable --agent disable
#   sudo ./scripts/test-meshagent.sh --archid universal --daemon disable --agent disable

set -e  # Exit on error

# Get the repository root directory (script is in /scripts, repo is parent)
REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "$REPO_DIR"

#==============================================================================
# DEFAULT CONFIGURATION
#==============================================================================

ARCHID="29"                    # Default: ARM64 (16=Intel, 29=ARM, universal=both)
LAUNCHDAEMON="enable"          # enable/disable
LAUNCHAGENT="enable"           # enable/disable
SKIP_BUILD=false               # Skip build step (use existing binary)
SKIP_SIGN=false                # Skip signing step
DEPLOY="enable"                # enable/disable - Deploy built binary to DEPLOY_PATH
DEPLOY_PATH="/usr/local/mesh_services/meshagent"  # Full path to deploy meshagent binary

#==============================================================================
# PARSE COMMAND LINE ARGUMENTS
#==============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --archid)
            ARCHID="$2"
            shift 2
            ;;
        --daemon)
            LAUNCHDAEMON="$2"
            shift 2
            ;;
        --agent)
            LAUNCHAGENT="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-sign)
            SKIP_SIGN=true
            shift
            ;;
        --deploy)
            DEPLOY="$2"
            shift 2
            ;;
        --deploy-path)
            DEPLOY_PATH="$2"
            shift 2
            ;;
        --help)
            echo "Usage: sudo $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --archid <16|29|universal>    Architecture to build (default: 29)"
            echo "                                  16 = Intel x86_64"
            echo "                                  29 = Apple Silicon ARM64"
            echo "                                  universal = Universal binary"
            echo "  --daemon <enable|disable>     LaunchDaemon state (default: enable)"
            echo "  --agent <enable|disable>      LaunchAgent state (default: enable)"
            echo "  --skip-build                  Skip build step, use existing binary"
            echo "  --skip-sign                   Skip signing step"
            echo "  --deploy <enable|disable>     Deploy binary to system (default: enable)"
            echo "  --deploy-path <path>          Deployment path (default: /usr/local/mesh_services/meshagent)"
            echo "  --help                        Show this help message"
            echo ""
            echo "Examples:"
            echo "  sudo $0 --archid 29 --daemon enable --agent enable"
            echo "  sudo $0 --archid universal --daemon disable --agent disable"
            echo "  sudo $0 --skip-build --daemon enable"
            echo "  sudo $0 --deploy disable --skip-build    # Build only, no deployment"
            echo "  sudo $0 --deploy-path /usr/local/bin/meshagent"
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
if [[ "$ARCHID" != "16" && "$ARCHID" != "29" && "$ARCHID" != "universal" ]]; then
    echo "Error: Invalid ARCHID '$ARCHID'. Must be 16, 29, or universal"
    exit 1
fi

# Validate LAUNCHDAEMON
if [[ "$LAUNCHDAEMON" != "enable" && "$LAUNCHDAEMON" != "disable" ]]; then
    echo "Error: Invalid LAUNCHDAEMON value '$LAUNCHDAEMON'. Must be 'enable' or 'disable'"
    exit 1
fi

# Validate LAUNCHAGENT
if [[ "$LAUNCHAGENT" != "enable" && "$LAUNCHAGENT" != "disable" ]]; then
    echo "Error: Invalid LAUNCHAGENT value '$LAUNCHAGENT'. Must be 'enable' or 'disable'"
    exit 1
fi

# Validate DEPLOY
if [[ "$DEPLOY" != "enable" && "$DEPLOY" != "disable" ]]; then
    echo "Error: Invalid DEPLOY value '$DEPLOY'. Must be 'enable' or 'disable'"
    exit 1
fi

#==============================================================================
# CONFIGURATION DISPLAY
#==============================================================================

echo "=========================================="
echo "MeshAgent Testing Configuration"
echo "=========================================="
echo "Start Time:       $(date '+%Y-%m-%d %H:%M:%S')"
echo "Architecture:     $ARCHID"
echo "LaunchDaemon:     $LAUNCHDAEMON"
echo "LaunchAgent:      $LAUNCHAGENT"
echo "Skip Build:       $SKIP_BUILD"
echo "Skip Sign:        $SKIP_SIGN"
echo "Deploy:           $DEPLOY"
echo "Deploy Path:      $DEPLOY_PATH"
echo "=========================================="
echo ""

#==============================================================================
# DETERMINE BINARY PATH
#==============================================================================

if [ "$ARCHID" = "16" ]; then
    BINARY_PATH="build/macos/macos-x86-64/meshagent"
    ARCH_DESC="Intel x86-64"
elif [ "$ARCHID" = "29" ]; then
    BINARY_PATH="build/macos/macos-arm-64/meshagent"
    ARCH_DESC="Apple Silicon ARM64"
elif [ "$ARCHID" = "universal" ]; then
    BINARY_PATH="build/macos/universal/meshagent"
    ARCH_DESC="Universal (Intel + ARM)"
fi

#==============================================================================
# BUILD STEP
#==============================================================================

if [ "$SKIP_BUILD" = false ]; then
    echo "[1/5] Building meshagent ($ARCH_DESC)..."
    echo "[$(date '+%H:%M:%S')] Build started"
    # Run build as the actual user (not root)
    sudo -u $SUDO_USER make clean
    sudo -u $SUDO_USER make macos ARCHID=$ARCHID

    echo "[$(date '+%H:%M:%S')] Build complete"
    echo "✓ Build complete"
    echo ""
else
    echo "[1/5] Build - SKIPPED"
    echo ""
fi

#==============================================================================
# SIGNING STEP
#==============================================================================

if [ "$SKIP_SIGN" = false ]; then
    echo "[2/5] Signing binary..."
    echo "[$(date '+%H:%M:%S')] Signing started"
    sleep 2
    # Run signing as the actual user (not root) to access user's keychain
    sudo -u $SUDO_USER ./bin/sign-my-macos-binaries.sh
    echo "[$(date '+%H:%M:%S')] Signing complete"
    echo "✓ Signing complete"
    echo ""
else
    echo "[2/5] Signing - SKIPPED"
    echo ""
fi

#==============================================================================
# STOP SERVICES
#==============================================================================

echo "[3/5] Stopping services..."
echo "[$(date '+%H:%M:%S')] Stopping services"

# Stop LaunchDaemon (system-wide)
if launchctl print system/meshagent &>/dev/null; then
    echo "  Stopping LaunchDaemon..."
    launchctl bootout system /Library/LaunchDaemons/meshagent.plist || true
else
    echo "  LaunchDaemon not running"
fi

# Stop LaunchAgent (user-level) - try for current user
USER_UID=$(id -u $SUDO_USER)
if launchctl print gui/$USER_UID/meshagent-agent &>/dev/null; then
    echo "  Stopping LaunchAgent..."
    sudo -u $SUDO_USER launchctl bootout gui/$USER_UID /Library/LaunchAgents/meshagent-agent.plist || true
else
    echo "  LaunchAgent not running"
fi

sleep 2
echo "✓ Services stopped"
echo ""

#==============================================================================
# DEPLOY BINARY
#==============================================================================

if [ "$DEPLOY" = "enable" ]; then
    echo "[4/5] Deploying binary..."
    echo "[$(date '+%H:%M:%S')] Deployment started"

    # Ensure destination directory exists
    DEPLOY_DIR=$(dirname "$DEPLOY_PATH")
    mkdir -p "$DEPLOY_DIR"

    # Backup existing binary if it exists
    if [ -f "$DEPLOY_PATH" ]; then
        echo "  Backing up existing binary..."
        cp "$DEPLOY_PATH" "$DEPLOY_PATH.backup.$(date +%Y%m%d_%H%M%S)"
    fi

    # Copy new binary
    echo "  Copying ./$BINARY_PATH to $DEPLOY_PATH"
    cp "./$BINARY_PATH" "$DEPLOY_PATH"

    # Set permissions
    chmod 755 "$DEPLOY_PATH"

    echo "[$(date '+%H:%M:%S')] Deployment complete"
    echo "✓ Binary deployed"
    echo ""
else
    echo "[4/5] Deploy - SKIPPED"
    echo ""
fi

#==============================================================================
# START SERVICES & SET STATE
#==============================================================================

echo "[5/5] Starting services..."
echo "[$(date '+%H:%M:%S')] Starting services"

# Configure and start LaunchDaemon
if [ "$LAUNCHDAEMON" = "enable" ]; then
    echo "  Enabling LaunchDaemon..."
    defaults write /Library/LaunchDaemons/meshagent Disabled -bool false
    chmod 644 /Library/LaunchDaemons/meshagent.plist
    launchctl bootstrap system /Library/LaunchDaemons/meshagent.plist
    echo "  ✓ LaunchDaemon enabled and started"
else
    echo "  Disabling LaunchDaemon..."
    defaults write /Library/LaunchDaemons/meshagent Disabled -bool true
    chmod 644 /Library/LaunchDaemons/meshagent.plist
    echo "  ✓ LaunchDaemon disabled"
fi

# Configure and start LaunchAgent
if [ "$LAUNCHAGENT" = "enable" ]; then
    echo "  Enabling LaunchAgent..."
    defaults write /Library/LaunchAgents/meshagent-agent Disabled -bool false
    chmod 644 /Library/LaunchAgents/meshagent-agent.plist
    sudo -u $SUDO_USER launchctl bootstrap gui/$USER_UID /Library/LaunchAgents/meshagent-agent.plist
    echo "  ✓ LaunchAgent enabled and started"
else
    echo "  Disabling LaunchAgent..."
    defaults write /Library/LaunchAgents/meshagent-agent Disabled -bool true
    chmod 644 /Library/LaunchAgents/meshagent-agent.plist
    echo "  ✓ LaunchAgent disabled"
fi

echo ""

#==============================================================================
# SUMMARY
#==============================================================================

echo "=========================================="
echo "Deployment Complete!"
echo "=========================================="
if [ "$DEPLOY" = "enable" ]; then
    echo "Deployed:         $DEPLOY_PATH"
else
    echo "Deployed:         No (skipped)"
fi
echo "Architecture:     $ARCH_DESC"
echo "Source:           $BINARY_PATH"
echo ""
echo "Service Status:"

# Check LaunchDaemon status
if launchctl print system/meshagent &>/dev/null; then
    echo "  LaunchDaemon:   Running (enabled)"
else
    DAEMON_DISABLED=$(defaults read /Library/LaunchDaemons/meshagent Disabled 2>/dev/null || echo "0")
    if [ "$DAEMON_DISABLED" = "1" ]; then
        echo "  LaunchDaemon:   Stopped (disabled)"
    else
        echo "  LaunchDaemon:   Stopped (enabled but not running)"
    fi
fi

# Check LaunchAgent status
if launchctl print gui/$USER_UID/meshagent-agent &>/dev/null; then
    echo "  LaunchAgent:    Running (enabled)"
else
    AGENT_DISABLED=$(defaults read /Library/LaunchAgents/meshagent-agent Disabled 2>/dev/null || echo "0")
    if [ "$AGENT_DISABLED" = "1" ]; then
        echo "  LaunchAgent:    Stopped (disabled)"
    else
        echo "  LaunchAgent:    Stopped (enabled but not running)"
    fi
fi

echo ""
echo "To view logs:"
echo "  LaunchDaemon: sudo log stream --predicate 'process == \"meshagent\"' --level debug"
echo "  LaunchAgent:  log stream --predicate 'process == \"meshagent\"' --level debug"
echo ""
echo "=========================================="
echo "End Time:         $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="
