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
#   sudo ./build-macos-with-opt-test.sh --archid 29 --msh-command install --msh-installPath /opt/meshagent
#   sudo ./build-macos-with-opt-test.sh --archid universal --msh-command fullinstall --msh-companyName YourCompany

set -e  # Exit on error

# Get the repository root directory
# Script is in build/tools/macos_build/, repo is 3 levels up
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_DIR="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_DIR"

#==============================================================================
# DEFAULT CONFIGURATION
#==============================================================================

ARCHID="10005"                      # Default: 10005=Universal (16=Intel x86-64, 29=ARM64, 10005=Universal)
SKIP_POLYFILLS="no"                 # Skip polyfills regeneration (use existing ILibDuktape_Polyfills.c)
MACOS_ONLY_POLYFILLS="yes"          # Generate polyfills from modules_macos only
CODE_UTILS_BUILD="no"               # Code-utils build: KVM=0, minimal module set (8 modules vs 50) for polyfill generation
SKIP_BUILD="no"                     # Skip build step (use existing binary)
SKIP_SIGN="no"						# Skip signing step
CODE_SIGN="bundle"					# bundle/binary its one or the other NOT both default bundle
SKIP_NOTARY="no"					# Skip notarization step
SKIP_STAPLE="no"                    # Skip notarization stapling step
SKIP_GIT_PULL="yes"                 # Skip git pull before building
MSH_EXEC="no"                       # Execute the meshagent as root at the end of the build process with MSH-* inputs
MSH_COMMAND=""                      # meshagent command: install, fullinstall, upgrade, uninstall, fulluninstall
MSH_INSTALLPATH=""                  # Installation path (use "-EMPTY-" to pass empty string to meshagent)
MSH_COMPANYNAME=""                  # Company name (use "-EMPTY-" to pass empty string to meshagent) - LEAVE EMPTY FOR UPGRADE
MSH_MESHSERVICENAME=""              # Service name (use "-EMPTY-" to pass empty string to meshagent) - LEAVE EMPTY FOR UPGRADE

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
            SKIP_POLYFILLS="yes"
            shift
            ;;
        --macos-only-polyfills)
            MACOS_ONLY_POLYFILLS="yes"
            shift
            ;;
        --all-polyfills)
            MACOS_ONLY_POLYFILLS="no"
            shift
            ;;
        --code-utils)
            CODE_UTILS_BUILD="yes"
            MACOS_ONLY_POLYFILLS="yes"  # Auto-enable macOS-only polyfills for code-utils build
            shift
            ;;
        --skip-build)
            SKIP_BUILD="yes"
            shift
            ;;
        --skip-sign)
            SKIP_SIGN="yes"
            shift
            ;;
        --code-sign)
            CODE_SIGN="$2"
            shift 2
            ;;
        --skip-notary)
            SKIP_NOTARY="yes"
            shift
            ;;
        --skip-staple)
            SKIP_STAPLE="yes"
            shift
            ;;
        --git-pull)
            SKIP_GIT_PULL="no"
            shift
            ;;
        --msh-exec)
            MSH_EXEC="yes"
            shift
            ;;
        --msh-command)
            MSH_COMMAND="$2"
            MSH_EXEC="yes"  # Auto-enable execution if command is specified
            shift 2
            ;;
        --msh-installPath)
            MSH_INSTALLPATH="$2"
            shift 2
            ;;
        --msh-companyName)
            MSH_COMPANYNAME="$2"
            shift 2
            ;;
        --msh-meshServiceName)
            MSH_MESHSERVICENAME="$2"
            shift 2
            ;;
        --help)
            echo "Usage: sudo [-E] $0 [OPTIONS]"
            echo ""
            echo "MeshAgent Testing Script v2 - Build and install using meshagent's built-in commands"
            echo ""
            echo "Note: Use 'sudo -E' when signing or notarizing to preserve environment variables:"
            echo "      - MACOS_SIGN_CERT (for code signing)"
            echo "      The -E flag preserves your user environment when running as root."
            echo ""
            echo "Build Options:"
            echo "  --archid <16|29|10005>        Architecture to build (default: 10005)"
            echo "                                  16 = Intel x86_64 (osx-x86-64)"
            echo "                                  29 = Apple Silicon ARM64 (osx-arm-64)"
            echo "                                  10005 = Universal binary (osx-universal-64)"
            echo "  --skip-polyfills              Skip polyfills regeneration from modules/"
            echo "  --macos-only-polyfills        Generate polyfills from modules_macos only (default)"
            echo "  --all-polyfills               Generate polyfills from all modules/ directory"
            echo "  --code-utils                  Code-utils build: KVM=0, minimal modules (8 vs 50) for polyfill gen"
            echo "  --skip-build                  Skip build step, use existing binary"
            echo "  --skip-sign                   Skip signing step"
            echo "  --code-sign <bundle|binary>   What to sign: 'bundle' (default) or 'binary' (NOT both)"
            echo "                                  bundle = Sign .app bundle (recommended for distribution)"
            echo "                                  binary = Sign standalone binary only"
            echo "  --skip-notary                 Skip notarization step"
            echo "  --skip-staple                 Skip stapling step (notarize but don't staple ticket)"
            echo "  --git-pull                    Pull latest changes before building"
            echo ""
            echo "MeshAgent Execution Options:"
            echo "  --msh-exec                    Execute meshagent command after build"
            echo "  --msh-command <cmd>           Run meshagent installation command (auto-enables --msh-exec):"
            echo "                                  install       - Standard installation (requires .msh file)"
            echo "                                  fullinstall   - Complete installation (downloads config from server)"
            echo "                                  upgrade       - Update existing installation (preserves .db/.msh)"
            echo "                                  uninstall     - Remove installation"
            echo "                                  fulluninstall - Complete removal with cleanup"
            echo "  --msh-installPath <path>      Installation directory (use '-EMPTY-' for empty string)"
            echo "  --msh-companyName <name>      Company name (use '-EMPTY-' for empty string)"
            echo "  --msh-meshServiceName <name>  Service name (use '-EMPTY-' for empty string)"
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
            echo "  # Build, sign, and notarize (requires MACOS_SIGN_CERT and sudo -E)"
            echo "  export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
            echo "  sudo -E $0 --archid 10005"
            echo ""
            echo "  # Build and install with fullinstall (downloads config from server)"
            echo "  sudo -E $0 --archid 10005 --msh-command fullinstall --msh-installPath /opt/meshagent --msh-companyName YourCompany"
            echo ""
            echo "  # Build and install with existing .msh file"
            echo "  sudo -E $0 --archid 29 --msh-command install --msh-installPath /usr/local/mesh_services/meshagent"
            echo ""
            echo "  # Upgrade existing installation with pre-built binary"
            echo "  sudo -E $0 --skip-build --msh-command upgrade --msh-installPath /opt/meshagent"
            echo ""
            echo "  # Uninstall meshagent"
            echo "  sudo $0 --skip-build --skip-sign --skip-notary --msh-command fulluninstall --msh-installPath /opt/meshagent"
            echo ""
            echo "  # Build only without signing or notarization"
            echo "  sudo $0 --archid 10005 --skip-sign --skip-notary"
            echo "  sudo $0 --git-pull --skip-sign --skip-notary"
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

# Validate MSH_COMMAND if set
if [ -n "$MSH_COMMAND" ]; then
    if [[ "$MSH_COMMAND" != "install" && "$MSH_COMMAND" != "fullinstall" && "$MSH_COMMAND" != "upgrade" && "$MSH_COMMAND" != "uninstall" && "$MSH_COMMAND" != "fulluninstall" ]]; then
        echo "Error: Invalid MSH_COMMAND '$MSH_COMMAND'."
        echo "Valid commands: install, fullinstall, upgrade, uninstall, fulluninstall"
        exit 1
    fi
fi

# Validate CODE_SIGN option
if [[ "$CODE_SIGN" != "bundle" && "$CODE_SIGN" != "binary" ]]; then
    echo "Error: Invalid CODE_SIGN value '$CODE_SIGN'"
    echo "Must be either 'bundle' or 'binary'"
    echo ""
    echo "  bundle = Sign .app bundle (recommended for distribution)"
    echo "  binary = Sign standalone binary only (NOT both)"
    exit 1
fi

# Validate signing certificate if signing is enabled
if [ "$SKIP_SIGN" = "no" ]; then
    if [ -z "$MACOS_SIGN_CERT" ]; then
        echo "Error: MACOS_SIGN_CERT environment variable not set"
        echo ""
        echo "Signing is enabled (SKIP_SIGN=no) but no certificate is configured."
        echo ""
        echo "Solutions:"
        echo "  1. Set the certificate and run with sudo -E:"
        echo "     export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
        echo "     sudo -E ./macos-build_with_test.sh"
        echo ""
        echo "     Note: The -E flag preserves your environment variables when using sudo."
        echo "           Without -E, sudo creates a new environment without MACOS_SIGN_CERT."
        echo ""
        echo "  2. Set the certificate in the sudo command:"
        echo "     sudo MACOS_SIGN_CERT=\"Developer ID Application: ...\" ./macos-build_with_test.sh"
        echo ""
        echo "  3. Skip signing with --skip-sign flag:"
        echo "     sudo ./macos-build_with_test.sh --skip-sign"
        echo ""
        echo "To list available certificates:"
        echo "  security find-identity -v -p codesigning"
        exit 1
    fi

    # Verify the certificate exists in keychain
    if ! security find-identity -v -p codesigning | grep -q "$MACOS_SIGN_CERT"; then
        echo "Error: Certificate not found in keychain"
        echo ""
        echo "Certificate specified: $MACOS_SIGN_CERT"
        echo ""
        echo "Available certificates:"
        security find-identity -v -p codesigning
        echo ""
        echo "Please verify the certificate name matches exactly."
        exit 1
    fi

    echo "✓ Code signing certificate verified: $MACOS_SIGN_CERT"
fi

# Validate notarization keychain profile if notarization is enabled
if [ "$SKIP_NOTARY" = "no" ]; then
    KEYCHAIN_PROFILE="meshagent-notary"

    if ! xcrun notarytool history --keychain-profile "$KEYCHAIN_PROFILE" &>/dev/null; then
        echo "Error: Keychain profile '$KEYCHAIN_PROFILE' not found"
        echo ""
        echo "Notarization is enabled (SKIP_NOTARY=no) but keychain profile is not configured."
        echo ""
        echo "Solutions:"
        echo "  1. Set up the keychain profile once with:"
        echo "     xcrun notarytool store-credentials \"$KEYCHAIN_PROFILE\" \\"
        echo "       --apple-id \"developer@example.com\" \\"
        echo "       --team-id \"TEAMID\" \\"
        echo "       --password \"xxxx-xxxx-xxxx-xxxx\""
        echo ""
        echo "  2. Skip notarization with --skip-notary flag:"
        echo "     sudo -E ./macos-build_with_test.sh --skip-notary"
        echo ""
        echo "     Note: Use sudo -E to preserve your environment variables."
        echo ""
        echo "Get credentials:"
        echo "  - Apple ID: Your Apple Developer account email"
        echo "  - Team ID: https://developer.apple.com/account (Membership section)"
        echo "  - Password: https://appleid.apple.com → Security → App-Specific Passwords"
        exit 1
    fi

    echo "✓ Notarization keychain profile verified: $KEYCHAIN_PROFILE"
fi

# Print blank line after validation checks
if [ "$SKIP_SIGN" = "no" ] || [ "$SKIP_NOTARY" = "no" ]; then
    echo ""
fi

#==============================================================================
# DETERMINE BINARY PATH, BUNDLE PATH, AND BUILD ARCHID
#==============================================================================

# Determine binary name prefix based on build type
if [ "$CODE_UTILS_BUILD" = "yes" ]; then
    BINARY_PREFIX="meshagent_code-utils"
else
    BINARY_PREFIX="meshagent"
fi

if [ "$ARCHID" = "16" ]; then
    BINARY_PATH="build/output/${BINARY_PREFIX}_osx-x86-64"
    BUNDLE_PATH="build/output/osx-x86-64-app/MeshAgent.app"
    ARCH_DESC="Intel x86-64"
    BUILD_ARCHID="16"
elif [ "$ARCHID" = "29" ]; then
    BINARY_PATH="build/output/${BINARY_PREFIX}_osx-arm-64"
    BUNDLE_PATH="build/output/osx-arm-64-app/MeshAgent.app"
    ARCH_DESC="Apple Silicon ARM64"
    BUILD_ARCHID="29"
elif [ "$ARCHID" = "10005" ]; then
    BINARY_PATH="build/output/${BINARY_PREFIX}_osx-universal-64"
    BUNDLE_PATH="build/output/osx-universal-64-app/MeshAgent.app"
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
echo "Code-Utils Build: $CODE_UTILS_BUILD"
if [ "$CODE_UTILS_BUILD" = "yes" ]; then
    echo "  → KVM:          Disabled (KVM=0)"
    echo "  → Modules:      8 minimal modules"
    echo "  → Output:       meshagent_code-utils_*"
fi
echo "Skip Polyfills:   $SKIP_POLYFILLS"
if [ "$SKIP_POLYFILLS" = "no" ]; then
    if [ "$CODE_UTILS_BUILD" = "yes" ]; then
        echo "Polyfills Mode:   Minimal macOS (8 modules)"
    else
        echo "Polyfills Mode:   $([ "$MACOS_ONLY_POLYFILLS" = "yes" ] && echo "macOS only (50 modules)" || echo "All modules")"
    fi
fi
echo "Skip Build:       $SKIP_BUILD"
echo "Skip Sign:        $SKIP_SIGN"
if [ "$SKIP_SIGN" = "no" ]; then
    echo "  → Sign Target:  $CODE_SIGN"
fi
echo "Skip Notary:      $SKIP_NOTARY"
if [ "$SKIP_NOTARY" = "no" ]; then
    echo "  → Skip Staple:  $SKIP_STAPLE"
fi
echo "Skip Git Pull:    $SKIP_GIT_PULL"
echo ""
if [ "$MSH_EXEC" = "yes" ] && [ -n "$MSH_COMMAND" ]; then
    echo "Execute MeshAgent: yes"
    echo "Command:          -$MSH_COMMAND"
    if [ -n "$MSH_INSTALLPATH" ]; then
        if [ "$MSH_INSTALLPATH" = "-EMPTY-" ]; then
            echo "Install Path:     '' (will pass empty string)"
        else
            echo "Install Path:     $MSH_INSTALLPATH"
        fi
    else
        echo "Install Path:     (not set)"
    fi
    if [ -n "$MSH_COMPANYNAME" ]; then
        if [ "$MSH_COMPANYNAME" = "-EMPTY-" ]; then
            echo "Company Name:     '' (will pass empty string)"
        else
            echo "Company Name:     $MSH_COMPANYNAME"
        fi
    else
        echo "Company Name:     (not set)"
    fi
    if [ -n "$MSH_MESHSERVICENAME" ]; then
        if [ "$MSH_MESHSERVICENAME" = "-EMPTY-" ]; then
            echo "Service Name:     '' (will pass empty string)"
        else
            echo "Service Name:     $MSH_MESHSERVICENAME"
        fi
    else
        echo "Service Name:     (not set)"
    fi
    echo "LaunchD Mgmt:     Handled by meshagent"
else
    echo "Execute MeshAgent: no (build only)"
fi
echo "=========================================="
echo ""

#==============================================================================
# GIT PULL STEP
#==============================================================================

if [ "$SKIP_GIT_PULL" = "no" ]; then
    echo "[0/6] Updating repository..."
    echo "[$(date '+%H:%M:%S')] Git pull started"
    # Run git pull as the actual user (not root)
    sudo -u $SUDO_USER git pull
    echo "[$(date '+%H:%M:%S')] Git pull complete"
    echo "✓ Repository updated"
    echo ""
else
    echo "[0/6] Git pull - SKIPPED"
    echo ""
fi

#==============================================================================
# POLYFILLS REGENERATION STEP
#==============================================================================

if [ "$SKIP_POLYFILLS" = "no" ]; then
    echo "[1/6] Regenerating polyfills..."
    echo "[$(date '+%H:%M:%S')] Polyfills regeneration started"

    # Check if code-utils meshagent exists for polyfill generation
    if [ ! -f "build/tools/code-utils/macos/meshagent_code-utils" ]; then
        echo "  ERROR: Code-utils meshagent not found at build/tools/code-utils/macos/meshagent_code-utils"
        echo "  Please ensure a code-utils meshagent binary exists"
        echo "  You can build one with: sudo ./build/tools/macos_build/macos-build_with_test.sh --code-utils --skip-sign --skip-notary"
        echo "  Then copy it: cp build/output/meshagent_code-utils_osx-universal-64 build/tools/code-utils/macos/meshagent_code-utils"
        exit 1
    fi

    # Determine module source directory and sync if needed
    if [ "$MACOS_ONLY_POLYFILLS" = "yes" ]; then
        MODULE_DIR="./modules_macos"

        # Use minimal module list if code-utils build is enabled
        if [ "$CODE_UTILS_BUILD" = "yes" ]; then
            echo "  Mode: CODE-UTILS macOS modules (NO KVM)"
            MODULES_LIST="./modules/.modules_macos_minimal"
        else
            echo "  Mode: macOS-only modules"
            MODULES_LIST="./modules/.modules_macos"
        fi

        if [ ! -f "$MODULES_LIST" ]; then
            echo "  ERROR: Module list not found at $MODULES_LIST"
            exit 1
        fi

        echo "  Syncing macOS modules from ./modules to ./modules_macos..."

        # Create modules_macos directory if it doesn't exist
        mkdir -p "./modules_macos"

        # Remove any .js files in modules_macos that are NOT in the .modules_macos list
        deleted_count=0
        if [ -d "./modules_macos" ]; then
            shopt -s nullglob  # Make glob expand to nothing if no matches
            for existing_file in ./modules_macos/*.js; do
                module_name=$(basename "$existing_file")

                # Check if this module is in the authorized list
                if ! grep -Fxq "$module_name" "$MODULES_LIST"; then
                    echo "    Removing unauthorized module: $module_name"
                    rm -f "$existing_file"
                    ((deleted_count++))
                fi
            done
            shopt -u nullglob  # Restore default behavior
        fi

        if [ $deleted_count -gt 0 ]; then
            echo "  ✓ Removed $deleted_count unauthorized modules"
        fi

        # Read module list and copy each module
        module_count=0
        missing_count=0
        while IFS= read -r module || [ -n "$module" ]; do
            # Skip empty lines
            [ -z "$module" ] && continue

            source_file="./modules/$module"
            dest_file="./modules_macos/$module"

            if [ -f "$source_file" ]; then
                # Copy module (byte-perfect copy)
                cp "$source_file" "$dest_file"
                ((module_count++))
            else
                echo "    WARNING: Module not found: $module"
                ((missing_count++))
            fi
        done < "$MODULES_LIST"

        echo "  ✓ Synced $module_count modules to ./modules_macos"

        if [ $missing_count -gt 0 ]; then
            echo "  ⚠ $missing_count modules not found in ./modules"
        fi
    else
        MODULE_DIR="./modules"
        echo "  Mode: All modules"
    fi

    # Run as actual user to regenerate polyfills
    echo "  Reading modules from: $MODULE_DIR"
    echo "  Updating file: ./microscript/ILibDuktape_Polyfills.c"
    sudo -u $SUDO_USER ./build/tools/code-utils/macos/meshagent_code-utils -import --expandedPath="$MODULE_DIR" --filePath="./microscript/ILibDuktape_Polyfills.c"

    echo "[$(date '+%H:%M:%S')] Polyfills regeneration complete"
    echo "✓ Polyfills regenerated"
    echo ""
else
    echo "[1/6] Polyfills regeneration - SKIPPED"
    echo ""
fi

#==============================================================================
# BUILD STEP
#==============================================================================

if [ "$SKIP_BUILD" = "no" ]; then
    echo "[2/6] Building meshagent ($ARCH_DESC)..."
    echo "[$(date '+%H:%M:%S')] Build started"
    # Run build as the actual user (not root)
    sudo -u $SUDO_USER make clean

    # Add KVM=0 for code-utils builds
    if [ "$CODE_UTILS_BUILD" = "yes" ]; then
        echo "  Building with KVM=0 (no remote desktop support)"
        echo "  Building with BUNDLE_ID=meshagent.code-utils"
        sudo -u $SUDO_USER make macos ARCHID=$BUILD_ARCHID KVM=0 BUNDLE_ID=meshagent.code-utils

        # Rename binaries to include "code-utils" in the filename
        echo "  Renaming binaries to include 'code-utils'..."
        if [ "$BUILD_ARCHID" = "10005" ]; then
            # Universal binary - rename all three
            [ -f "build/output/meshagent_osx-universal-64" ] && mv "build/output/meshagent_osx-universal-64" "build/output/meshagent_code-utils_osx-universal-64"
            [ -f "build/output/meshagent_osx-x86-64" ] && mv "build/output/meshagent_osx-x86-64" "build/output/meshagent_code-utils_osx-x86-64"
            [ -f "build/output/meshagent_osx-arm-64" ] && mv "build/output/meshagent_osx-arm-64" "build/output/meshagent_code-utils_osx-arm-64"
            [ -f "build/output/DEBUG/meshagent_osx-universal-64" ] && mv "build/output/DEBUG/meshagent_osx-universal-64" "build/output/DEBUG/meshagent_code-utils_osx-universal-64"
            [ -f "build/output/DEBUG/meshagent_osx-x86-64" ] && mv "build/output/DEBUG/meshagent_osx-x86-64" "build/output/DEBUG/meshagent_code-utils_osx-x86-64"
            [ -f "build/output/DEBUG/meshagent_osx-arm-64" ] && mv "build/output/DEBUG/meshagent_osx-arm-64" "build/output/DEBUG/meshagent_code-utils_osx-arm-64"
        elif [ "$BUILD_ARCHID" = "16" ]; then
            # Intel only
            [ -f "build/output/meshagent_osx-x86-64" ] && mv "build/output/meshagent_osx-x86-64" "build/output/meshagent_code-utils_osx-x86-64"
            [ -f "build/output/DEBUG/meshagent_osx-x86-64" ] && mv "build/output/DEBUG/meshagent_osx-x86-64" "build/output/DEBUG/meshagent_code-utils_osx-x86-64"
        elif [ "$BUILD_ARCHID" = "29" ]; then
            # ARM only
            [ -f "build/output/meshagent_osx-arm-64" ] && mv "build/output/meshagent_osx-arm-64" "build/output/meshagent_code-utils_osx-arm-64"
            [ -f "build/output/DEBUG/meshagent_osx-arm-64" ] && mv "build/output/DEBUG/meshagent_osx-arm-64" "build/output/DEBUG/meshagent_code-utils_osx-arm-64"
        fi
    else
        sudo -u $SUDO_USER make macos ARCHID=$BUILD_ARCHID
    fi

    echo "[$(date '+%H:%M:%S')] Build complete"
    echo "✓ Build complete"
    echo ""
else
    echo "[2/6] Build - SKIPPED"

    # If MSH_EXEC is set and build is skipped, verify bundle exists
    if [ "$MSH_EXEC" = "yes" ] && [ -n "$MSH_COMMAND" ]; then
        if [ ! -d "$BUNDLE_PATH" ]; then
            echo ""
            echo "ERROR: Bundle not found at $BUNDLE_PATH"
            echo "Cannot run command '$MSH_COMMAND' without a bundle."
            echo ""
            echo "Solutions:"
            echo "  1. Remove --skip-build to build the bundle"
            echo "  2. Build the bundle first: make macos ARCHID=$BUILD_ARCHID"
            echo "  3. Ensure the bundle exists at: $BUNDLE_PATH"
            exit 1
        fi
        echo "  ✓ Bundle exists at $BUNDLE_PATH"
    fi
    echo ""
fi

#==============================================================================
# SIGNING STEP
#==============================================================================

if [ "$SKIP_SIGN" = "no" ]; then
    if [ "$CODE_SIGN" = "bundle" ]; then
        echo "[3/6] Signing application bundle..."
        echo "[$(date '+%H:%M:%S')] Signing started"

        # Verify bundle exists
        if [ ! -d "$BUNDLE_PATH" ]; then
            echo "Error: Bundle not found at $BUNDLE_PATH"
            echo "The build step should have created this bundle."
            exit 1
        fi

        echo "  Target: Bundle"
        echo "  Path:   $BUNDLE_PATH"

        # Run signing as the actual user (not root) to access user's keychain
        # Sign the .app bundle (recommended for distribution)
        sudo -u $SUDO_USER MACOS_SIGN_CERT="$MACOS_SIGN_CERT" ./build/tools/macos_build/sign-app-bundle.sh "$BUNDLE_PATH"
        echo "[$(date '+%H:%M:%S')] Signing complete"
        echo "✓ Bundle signing complete"
        echo ""
    elif [ "$CODE_SIGN" = "binary" ]; then
        echo "[3/6] Signing standalone binary..."
        echo "[$(date '+%H:%M:%S')] Signing started"

        # Verify binary exists
        if [ ! -f "$BINARY_PATH" ]; then
            echo "Error: Binary not found at $BINARY_PATH"
            echo "The build step should have created this binary."
            exit 1
        fi

        echo "  Target: Binary"
        echo "  Path:   $BINARY_PATH"

        # Run signing as the actual user (not root) to access user's keychain
        # Sign the standalone binary (NOT the bundle)
        sudo -u $SUDO_USER MACOS_SIGN_CERT="$MACOS_SIGN_CERT" ./build/tools/macos_build/macos-sign.sh "$BINARY_PATH"
        echo "[$(date '+%H:%M:%S')] Signing complete"
        echo "✓ Binary signing complete"
        echo ""
    fi
else
    echo "[3/6] Signing - SKIPPED"
    echo ""
fi

#==============================================================================
# NOTARIZATION STEP
#==============================================================================

if [ "$SKIP_NOTARY" = "no" ]; then
    if [ "$CODE_SIGN" = "bundle" ]; then
        echo "[4/6] Notarizing and stapling application bundle..."
        echo "[$(date '+%H:%M:%S')] Notarization started"

        # Verify bundle exists
        if [ ! -d "$BUNDLE_PATH" ]; then
            echo "Error: Bundle not found at $BUNDLE_PATH"
            echo "The build step should have created this bundle."
            exit 1
        fi

        # Verify bundle is signed (required for notarization)
        if ! codesign --verify --deep --strict "$BUNDLE_PATH" 2>/dev/null; then
            echo "Error: Bundle must be signed before notarization"
            echo "Please enable signing or sign the bundle first."
            exit 1
        fi

        echo "  Target: Bundle"
        echo "  Path:   $BUNDLE_PATH"

        # Run notarization as the actual user (not root) to access user's keychain
        # Notarize the .app bundle (includes signing verification, submission, and optional stapling)
        sudo -u $SUDO_USER SKIP_STAPLE="$SKIP_STAPLE" ./build/tools/macos_build/notarize-app-bundle.sh "$BUNDLE_PATH"

        if [ "$SKIP_STAPLE" = "yes" ]; then
            echo "[$(date '+%H:%M:%S')] Notarization complete (stapling skipped)"
            echo "✓ Bundle notarization complete (not stapled)"
        else
            echo "[$(date '+%H:%M:%S')] Notarization and stapling complete"
            echo "✓ Bundle notarization and stapling complete"
        fi
        echo ""
    elif [ "$CODE_SIGN" = "binary" ]; then
        echo "[4/6] Notarizing standalone binary..."
        echo "[$(date '+%H:%M:%S')] Notarization started"

        # Verify binary exists
        if [ ! -f "$BINARY_PATH" ]; then
            echo "Error: Binary not found at $BINARY_PATH"
            echo "The build step should have created this binary."
            exit 1
        fi

        # Verify binary is signed (required for notarization)
        if ! codesign --verify --strict "$BINARY_PATH" 2>/dev/null; then
            echo "Error: Binary must be signed before notarization"
            echo "Please enable signing or sign the binary first."
            exit 1
        fi

        echo "  Target: Binary"
        echo "  Path:   $BINARY_PATH"

        # Run notarization as the actual user (not root) to access user's keychain
        # Notarize the standalone binary (does NOT include stapling - binaries cannot be stapled)
        sudo -u $SUDO_USER ./build/tools/macos_build/macos-notarize.sh "$BINARY_PATH"
        echo "[$(date '+%H:%M:%S')] Notarization complete"
        echo "✓ Binary notarization complete"
        echo ""
        echo "Note: Standalone binaries cannot be stapled. The notarization is stored in Apple's servers."
        echo ""
    fi
else
    echo "[4/6] Notarization - SKIPPED"
    echo ""
fi

#==============================================================================
# COMMAND EXECUTION
#==============================================================================

if [ "$MSH_EXEC" = "yes" ] && [ -n "$MSH_COMMAND" ]; then
    echo "[5/6] Executing meshagent command..."
    echo "[$(date '+%H:%M:%S')] Command execution started"
    echo "  Command: -$MSH_COMMAND"

    # Use the bundle binary for execution (signed/notarized if those steps were run)
    EXEC_BINARY="$BUNDLE_PATH/Contents/MacOS/meshagent"

    if [ ! -f "$EXEC_BINARY" ]; then
        echo "Error: Binary not found at $EXEC_BINARY"
        echo "Bundle may not have been created properly."
        exit 1
    fi

    echo "  Binary:  $EXEC_BINARY"

    # Build command array - only include parameters that were explicitly set
    CMD_ARRAY=("$EXEC_BINARY" "-$MSH_COMMAND")

    # MSH_INSTALLPATH: empty string = skip, "-EMPTY-" = pass empty string, anything else = pass value
    if [ -n "$MSH_INSTALLPATH" ]; then
        if [ "$MSH_INSTALLPATH" = "-EMPTY-" ]; then
            CMD_ARRAY+=("--installPath=")
            echo "  Install Path: '' (empty string)"
        else
            CMD_ARRAY+=("--installPath=${MSH_INSTALLPATH}")
            echo "  Install Path: $MSH_INSTALLPATH"
        fi
    fi

    # MSH_COMPANYNAME: empty string = skip, "-EMPTY-" = pass empty string, anything else = pass value
    if [ -n "$MSH_COMPANYNAME" ]; then
        if [ "$MSH_COMPANYNAME" = "-EMPTY-" ]; then
            CMD_ARRAY+=("--companyName=")
            echo "  Company: '' (empty string)"
        else
            CMD_ARRAY+=("--companyName=${MSH_COMPANYNAME}")
            echo "  Company: $MSH_COMPANYNAME"
        fi
    fi

    # MSH_MESHSERVICENAME: empty string = skip, "-EMPTY-" = pass empty string, anything else = pass value
    if [ -n "$MSH_MESHSERVICENAME" ]; then
        if [ "$MSH_MESHSERVICENAME" = "-EMPTY-" ]; then
            CMD_ARRAY+=("--meshServiceName=")
            echo "  Service: '' (empty string)"
        else
            CMD_ARRAY+=("--meshServiceName=${MSH_MESHSERVICENAME}")
            echo "  Service: $MSH_MESHSERVICENAME"
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
    echo "✓ Command '-$MSH_COMMAND' executed successfully"
    echo ""
else
    echo "[5/6] Command execution - SKIPPED (MSH_EXEC=no or no command specified)"
    echo ""
fi

#==============================================================================
# SUMMARY
#==============================================================================

echo "=========================================="
echo "Script Complete!"
echo "=========================================="
echo "Architecture:     $ARCH_DESC"
echo "Bundle:           $BUNDLE_PATH"
echo "Binary:           $BUNDLE_PATH/Contents/MacOS/meshagent"

if [ "$MSH_EXEC" = "yes" ] && [ -n "$MSH_COMMAND" ]; then
    echo "Command:          -$MSH_COMMAND"
    if [ -n "$MSH_INSTALLPATH" ]; then
        if [ "$MSH_INSTALLPATH" = "-EMPTY-" ]; then
            echo "Install Path:     '' (empty string)"
        else
            echo "Install Path:     $MSH_INSTALLPATH"
        fi
    fi
    echo ""
    echo "LaunchD services managed by meshagent"
    echo "To view logs:"
    echo "  sudo log stream --predicate 'process == \"meshagent\"' --level debug"
else
    echo "Command:          (none - bundle built only)"
    echo ""
    echo "Application bundle: $BUNDLE_PATH"
    echo ""
    echo "To launch:"
    echo "  open $BUNDLE_PATH"
    echo ""
    echo "To install with command:"
    echo "  sudo $0 --skip-build --msh-command install --msh-installPath /opt/meshagent"
fi

echo ""
echo "=========================================="
echo "End Time:         $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="
echo ""
echo "Press Enter to open build folder (or any other key to exit)..."

# Wait for user input with 15-second timeout
if read -t 15 -n 1 -s key; then
    # User pressed a key before timeout
    if [ -z "$key" ]; then
        # Enter key was pressed (empty string)
        OUTPUT_DIR="$(cd "$(dirname "$BUNDLE_PATH")" && pwd)"
        echo ""
        echo "Opening $OUTPUT_DIR..."
        open "$OUTPUT_DIR"
    fi
else
    # Timeout occurred (15 seconds elapsed with no input)
    echo ""
fi
