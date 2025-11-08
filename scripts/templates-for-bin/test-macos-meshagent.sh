#!/bin/bash
# MeshAgent macOS Development Testing Script
# Version: 0.0.9
# Builds, signs, and deploys meshagent with configurable options
#
# Usage:
#   sudo ./bin/test-meshagent.sh --archid 29 --daemon enable --agent disable
#   sudo ./bin/test-meshagent.sh --archid universal --daemon disable --agent disable

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

ARCHID="universal"                    # Default: ARM64 (16=Intel, 29=ARM, universal=both)
LAUNCHDAEMON="enable"          # enable/disable - Install and load LaunchDaemon for testing on this device (if disabled, can run daemon manually in terminal)
LAUNCHAGENT="enable"           # enable/disable - Install and load LaunchAgent for testing on this device (if disabled, can run agent manually in terminal)
SKIP_POLYFILLS=false           # Skip polyfills regeneration (use existing ILibDuktape_Polyfills.c)
SKIP_BUILD=false               # Skip build step (use existing binary)
SKIP_SIGN=false                # Skip signing step
DEPLOY="enable"                # enable/disable - Deploy built binary to DEPLOY_PATH
DEPLOY_PATH="/opt/tacticalmesh/meshagent"  # Full path to deploy meshagent binary
GIT_PULL=true                 # enable/disable - Pull latest changes before building
REFRESH_PLISTS=true           # Refresh launchd plists from PATH_PLISTS directory
PATH_PLISTS="examples/launchd/tacticalrmm"  # Path to plist directory (required if REFRESH_PLISTS=true)

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
        --deploy)
            DEPLOY="$2"
            shift 2
            ;;
        --deploy-path)
            DEPLOY_PATH="$2"
            shift 2
            ;;
        --git-pull)
            GIT_PULL=true
            shift
            ;;
        --refresh-plists)
            REFRESH_PLISTS=true
            shift
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
            echo "  --skip-polyfills              Skip polyfills regeneration from modules/"
            echo "  --skip-build                  Skip build step, use existing binary"
            echo "  --skip-sign                   Skip signing step"
            echo "  --deploy <enable|disable>     Deploy binary to system (default: enable)"
            echo "  --deploy-path <path>          Deployment path (default: /usr/local/mesh_services/meshagent)"
            echo "  --git-pull                    Pull latest changes before building (default: disabled)"
            echo "  --refresh-plists              Refresh launchd plists from examples/launchd/tacticalrmm/"
            echo "  --help                        Show this help message"
            echo ""
            echo "Examples:"
            echo "  sudo $0 --archid 29 --daemon enable --agent enable"
            echo "  sudo $0 --archid universal --daemon disable --agent disable"
            echo "  sudo $0 --skip-build --daemon enable"
            echo "  sudo $0 --deploy disable --skip-build    # Build only, no deployment"
            echo "  sudo $0 --deploy-path /usr/local/bin/meshagent"
            echo "  sudo $0 --git-pull --refresh-plists      # Update repo and plists"
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
echo "Skip Polyfills:   $SKIP_POLYFILLS"
echo "Skip Build:       $SKIP_BUILD"
echo "Skip Sign:        $SKIP_SIGN"
echo "Deploy:           $DEPLOY"
echo "Deploy Path:      $DEPLOY_PATH"
echo "Git Pull:         $GIT_PULL"
echo "Refresh Plists:   $REFRESH_PLISTS"
echo "Plists Path:      $PATH_PLISTS"
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
# GIT PULL STEP
#==============================================================================

if [ "$GIT_PULL" = true ]; then
    echo "[0/7] Updating repository..."
    echo "[$(date '+%H:%M:%S')] Git pull started"
    # Run git pull as the actual user (not root)
    sudo -u $SUDO_USER git pull
    echo "[$(date '+%H:%M:%S')] Git pull complete"
    echo "✓ Repository updated"
    echo ""
else
    echo "[0/7] Git pull - SKIPPED"
    echo ""
fi

#==============================================================================
# POLYFILLS REGENERATION STEP
#==============================================================================

if [ "$SKIP_POLYFILLS" = false ]; then
    echo "[1/7] Regenerating polyfills from modules/..."
    echo "[$(date '+%H:%M:%S')] Polyfills regeneration started"

    # Check if minimal meshagent exists
    if [ ! -f "scripts/meshagent/macos/meshagent" ]; then
        echo "  ERROR: Minimal meshagent not found at scripts/meshagent/macos/meshagent"
        echo "  Please ensure the minimal meshagent binary exists"
        exit 1
    fi

    # Run as actual user to regenerate polyfills
    echo "  Reading modules from: ./modules/"
    echo "  Updating file: ./microscript/ILibDuktape_Polyfills.c"
    sudo -u $SUDO_USER ./scripts/meshagent/macos/meshagent -exec "require('code-utils').shrink({expandedPath: './modules', filePath: './microscript/ILibDuktape_Polyfills.c'});process.exit();"

    echo "[$(date '+%H:%M:%S')] Polyfills regeneration complete"
    echo "✓ Polyfills regenerated from modules/"
    echo ""
else
    echo "[1/7] Polyfills regeneration - SKIPPED"
    echo ""
fi

#==============================================================================
# BUILD STEP
#==============================================================================

if [ "$SKIP_BUILD" = false ]; then
    echo "[2/7] Building meshagent ($ARCH_DESC)..."
    echo "[$(date '+%H:%M:%S')] Build started"
    # Run build as the actual user (not root)
    sudo -u $SUDO_USER make clean
    sudo -u $SUDO_USER make macos ARCHID=$ARCHID

    echo "[$(date '+%H:%M:%S')] Build complete"
    echo "✓ Build complete"
    echo ""
else
    echo "[2/7] Build - SKIPPED"
    echo ""
fi

#==============================================================================
# SIGNING STEP
#==============================================================================

if [ "$SKIP_SIGN" = false ]; then
    echo "[3/7] Signing binary..."
    echo "[$(date '+%H:%M:%S')] Signing started"
    sleep 2
    # Run signing as the actual user (not root) to access user's keychain
    sudo -u $SUDO_USER ./bin/sign-and-notarize-macos-template.sh
    echo "[$(date '+%H:%M:%S')] Signing complete"
    echo "✓ Signing complete"
    echo ""
else
    echo "[3/7] Signing - SKIPPED"
    echo ""
fi

#==============================================================================
# STOP SERVICES
#==============================================================================

echo "[4/7] Stopping services..."
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
# REFRESH LAUNCHD PLISTS (OPTIONAL)
#==============================================================================

if [ "$REFRESH_PLISTS" = true ]; then
    echo "[4.5/7] Refreshing launchd plists..."
    echo "[$(date '+%H:%M:%S')] Plist refresh started"

    # Validate PATH_PLISTS is set
    if [ -z "$PATH_PLISTS" ]; then
        echo "  ERROR: REFRESH_PLISTS is true but PATH_PLISTS is not defined"
        echo "  Please set PATH_PLISTS to the directory containing your plist files"
        echo "  Example: PATH_PLISTS=\"examples/launchd/tacticalrmm\""
        exit 1
    fi

    # Source plists from configured path
    DAEMON_PLIST_SRC="$REPO_DIR/$PATH_PLISTS/meshagent.plist"
    AGENT_PLIST_SRC="$REPO_DIR/$PATH_PLISTS/meshagent-agent.plist"

    # Destination paths
    DAEMON_PLIST_DEST="/Library/LaunchDaemons/meshagent.plist"
    AGENT_PLIST_DEST="/Library/LaunchAgents/meshagent-agent.plist"

    # Verify source files exist
    if [ ! -f "$DAEMON_PLIST_SRC" ]; then
        echo "  ERROR: Source plist not found: $DAEMON_PLIST_SRC"
        exit 1
    fi
    if [ ! -f "$AGENT_PLIST_SRC" ]; then
        echo "  ERROR: Source plist not found: $AGENT_PLIST_SRC"
        exit 1
    fi

    # Copy LaunchDaemon plist
    echo "  Copying LaunchDaemon plist..."
    echo "    From: $DAEMON_PLIST_SRC"
    echo "    To:   $DAEMON_PLIST_DEST"
    cp "$DAEMON_PLIST_SRC" "$DAEMON_PLIST_DEST"
    chmod 644 "$DAEMON_PLIST_DEST"

    # Copy LaunchAgent plist
    echo "  Copying LaunchAgent plist..."
    echo "    From: $AGENT_PLIST_SRC"
    echo "    To:   $AGENT_PLIST_DEST"
    cp "$AGENT_PLIST_SRC" "$AGENT_PLIST_DEST"
    chmod 644 "$AGENT_PLIST_DEST"

    echo "[$(date '+%H:%M:%S')] Plist refresh complete"
    echo "✓ Plists refreshed from examples/launchd/tacticalrmm/"
    echo ""
else
    echo "[4.5/7] Refresh plists - SKIPPED"
    echo ""
fi

#==============================================================================
# DEPLOY BINARY
#==============================================================================

if [ "$DEPLOY" = "enable" ]; then
    echo "[5/7] Deploying binary..."
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
    echo "[5/7] Deploy - SKIPPED"
    echo ""
fi

#==============================================================================
# START SERVICES & SET STATE
#==============================================================================

echo "[6/7] Starting services..."
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
