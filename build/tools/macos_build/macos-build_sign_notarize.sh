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
EXPANDED_PATH=""                    # Custom module directory for polyfill regeneration (overrides default)

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
        --build-pkg)
            BUILD_PKG="yes"
            shift
            ;;
        --git-pull)
            SKIP_GIT_PULL="no"
            shift
            ;;
        --expandedPath)
            EXPANDED_PATH="$2"
            shift 2
            ;;
        --help)
            echo "Usage: sudo [-E] $0 [OPTIONS]"
            echo ""
            echo "macOS MeshAgent Build, Sign, and Notarize Script"
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
            echo "  --build-pkg                   Build installer .pkg (requires munkipkg, disabled by default)"
            echo "  --git-pull                    Pull latest changes before building"
            echo "  --expandedPath <path>         Custom module directory for polyfill regeneration"
            echo "                                  Overrides default ./modules or ./modules_macos path"
            echo ""
            echo "Examples:"
            echo "  # Build, sign, and notarize (requires MACOS_SIGN_CERT and sudo -E)"
            echo "  export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
            echo "  sudo -E $0 --archid 10005"
            echo ""
            echo "  # Build only without signing or notarization"
            echo "  sudo $0 --archid 10005 --skip-sign --skip-notary"
            echo ""
            echo "  # Build with git pull"
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
    echo "Error: This script must be run as root"
    echo ""
    echo "Usage:"
    echo "  sudo $0                    # Basic build"
    echo "  sudo -E $0                 # When signing or notarizing (preserves MACOS_SIGN_CERT)"
    exit 1
fi

# Validate ARCHID
if [[ "$ARCHID" != "16" && "$ARCHID" != "29" && "$ARCHID" != "10005" ]]; then
    echo "Error: Invalid ARCHID '$ARCHID'. Must be 16, 29, or 10005"
    exit 1
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

    # Verify the certificate exists in keychain (run as user to access user's keychain)
    if ! sudo -u $SUDO_USER security find-identity -v -p codesigning | grep -q "$MACOS_SIGN_CERT"; then
        echo "Error: Certificate not found in keychain"
        echo ""
        echo "Certificate specified: $MACOS_SIGN_CERT"
        echo ""
        echo "Available certificates:"
        sudo -u $SUDO_USER security find-identity -v -p codesigning
        echo ""
        echo "Please verify the certificate name matches exactly."
        exit 1
    fi

    echo "✓ Code signing certificate verified: $MACOS_SIGN_CERT"
fi

# Validate notarization keychain profile if notarization is enabled
if [ "$SKIP_NOTARY" = "no" ] && [ "$SKIP_SIGN" = "no" ]; then
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
    if [ -n "$EXPANDED_PATH" ]; then
        # Custom module directory specified via --expandedPath
        MODULE_DIR="$EXPANDED_PATH"
        echo "  Mode: Custom module directory (--expandedPath)"
        echo "  WARNING: Skipping module sync - using provided path as-is"
    elif [ "$MACOS_ONLY_POLYFILLS" = "yes" ]; then
        MODULE_DIR="./modules_macos"

        # Use minimal module list if code-utils build is enabled
        if [ "$CODE_UTILS_BUILD" = "yes" ]; then
            echo "  Mode: CODE-UTILS macOS modules (NO KVM)"
            ./build/tools/sync-modules.sh --mode minimal --verbose
        else
            echo "  Mode: macOS-only modules"
            ./build/tools/sync-modules.sh --mode macos-only --verbose
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
            [ -f "build/output/meshagent_osx-universal-64" ] && sudo -u $SUDO_USER mv "build/output/meshagent_osx-universal-64" "build/output/meshagent_code-utils_osx-universal-64"
            [ -f "build/output/meshagent_osx-x86-64" ] && sudo -u $SUDO_USER mv "build/output/meshagent_osx-x86-64" "build/output/meshagent_code-utils_osx-x86-64"
            [ -f "build/output/meshagent_osx-arm-64" ] && sudo -u $SUDO_USER mv "build/output/meshagent_osx-arm-64" "build/output/meshagent_code-utils_osx-arm-64"
            [ -f "build/output/DEBUG/meshagent_osx-universal-64" ] && sudo -u $SUDO_USER mv "build/output/DEBUG/meshagent_osx-universal-64" "build/output/DEBUG/meshagent_code-utils_osx-universal-64"
            [ -f "build/output/DEBUG/meshagent_osx-x86-64" ] && sudo -u $SUDO_USER mv "build/output/DEBUG/meshagent_osx-x86-64" "build/output/DEBUG/meshagent_code-utils_osx-x86-64"
            [ -f "build/output/DEBUG/meshagent_osx-arm-64" ] && sudo -u $SUDO_USER mv "build/output/DEBUG/meshagent_osx-arm-64" "build/output/DEBUG/meshagent_code-utils_osx-arm-64"
        elif [ "$BUILD_ARCHID" = "16" ]; then
            # Intel only
            [ -f "build/output/meshagent_osx-x86-64" ] && sudo -u $SUDO_USER mv "build/output/meshagent_osx-x86-64" "build/output/meshagent_code-utils_osx-x86-64"
            [ -f "build/output/DEBUG/meshagent_osx-x86-64" ] && sudo -u $SUDO_USER mv "build/output/DEBUG/meshagent_osx-x86-64" "build/output/DEBUG/meshagent_code-utils_osx-x86-64"
        elif [ "$BUILD_ARCHID" = "29" ]; then
            # ARM only
            [ -f "build/output/meshagent_osx-arm-64" ] && sudo -u $SUDO_USER mv "build/output/meshagent_osx-arm-64" "build/output/meshagent_code-utils_osx-arm-64"
            [ -f "build/output/DEBUG/meshagent_osx-arm-64" ] && sudo -u $SUDO_USER mv "build/output/DEBUG/meshagent_osx-arm-64" "build/output/DEBUG/meshagent_code-utils_osx-arm-64"
        fi
    else
        sudo -u $SUDO_USER make macos ARCHID=$BUILD_ARCHID
    fi

    echo "[$(date '+%H:%M:%S')] Build complete"
    echo "✓ Build complete"
    echo ""
else
    echo "[2/6] Build - SKIPPED"
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
        echo "[$(date '+%H:%M:%S')] Bundle signing complete"
        echo "✓ Bundle signing complete"

        # For universal builds (ARCHID=10005), also sign and split the universal binary
        if [ "$BUILD_ARCHID" = "10005" ]; then
            echo ""
            echo "  Signing universal binary: $BINARY_PATH"
            sudo -u $SUDO_USER MACOS_SIGN_CERT="$MACOS_SIGN_CERT" ./build/tools/macos_build/macos-sign.sh "$BINARY_PATH"
            echo "  ✓ Universal binary signed"

            echo ""
            echo "  Splitting universal binary into architectures..."
            # Extract ARM64 slice
            if sudo -u $SUDO_USER lipo "$BINARY_PATH" -extract arm64 -output "${BINARY_PATH/universal/arm}" 2>/dev/null; then
                echo "    ✓ ARM64 binary created: ${BINARY_PATH/universal/arm}"
            else
                echo "    ⚠ Failed to extract ARM64 binary"
            fi

            # Extract x86_64 slice
            if sudo -u $SUDO_USER lipo "$BINARY_PATH" -extract x86_64 -output "${BINARY_PATH/universal/x86}" 2>/dev/null; then
                echo "    ✓ x86_64 binary created: ${BINARY_PATH/universal/x86}"
            else
                echo "    ⚠ Failed to extract x86_64 binary"
            fi

            echo ""
            echo "  Signing ARM64 bundle..."
            ARM_BUNDLE="build/output/osx-arm-64-app/MeshAgent.app"
            if [ -d "$ARM_BUNDLE" ]; then
                sudo -u $SUDO_USER MACOS_SIGN_CERT="$MACOS_SIGN_CERT" ./build/tools/macos_build/sign-app-bundle.sh "$ARM_BUNDLE"
                echo "    ✓ ARM64 bundle signed: $ARM_BUNDLE"
            else
                echo "    ⚠ ARM64 bundle not found: $ARM_BUNDLE"
            fi

            echo ""
            echo "  Signing x86_64 bundle..."
            X86_BUNDLE="build/output/osx-x86-64-app/MeshAgent.app"
            if [ -d "$X86_BUNDLE" ]; then
                sudo -u $SUDO_USER MACOS_SIGN_CERT="$MACOS_SIGN_CERT" ./build/tools/macos_build/sign-app-bundle.sh "$X86_BUNDLE"
                echo "    ✓ x86_64 bundle signed: $X86_BUNDLE"
            else
                echo "    ⚠ x86_64 bundle not found: $X86_BUNDLE"
            fi
        fi
        echo ""
        echo "[$(date '+%H:%M:%S')] Signing complete"
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
    echo "Note: Ad-hoc signing is delegated to the Makefile."
    echo "      The Makefile automatically ad-hoc signs binaries and bundles after building."
    echo "      See makefile lines 878, 883, 920 for signing implementation."
    echo ""
fi

#==============================================================================
# NOTARIZATION STEP
#==============================================================================

# Skip notarization if signing was skipped (can't notarize unsigned binaries)
if [ "$SKIP_SIGN" = "yes" ]; then
    echo "[4/6] Notarization - SKIPPED (signing was skipped)"
    echo ""
    echo "Note: Notarization requires code signing. Enable signing to use notarization."
    echo ""
elif [ "$SKIP_NOTARY" = "no" ]; then
    if [ "$CODE_SIGN" = "bundle" ]; then
        echo "[4/6] Notarizing and stapling application bundle..."
        echo "[$(date '+%H:%M:%S')] Notarization started"

        # Verify bundle exists
        if [ ! -d "$BUNDLE_PATH" ]; then
            echo "Error: Bundle not found at $BUNDLE_PATH"
            echo "The build step should have created this bundle."
            exit 1
        fi

        # Verify bundle is signed (required for notarization) - run as user
        if ! sudo -u $SUDO_USER codesign --verify --deep --strict "$BUNDLE_PATH" 2>/dev/null; then
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
            echo "[$(date '+%H:%M:%S')] Bundle notarization complete (stapling skipped)"
            echo "✓ Bundle notarization complete (not stapled)"
        else
            echo "[$(date '+%H:%M:%S')] Bundle notarization and stapling complete"
            echo "✓ Bundle notarization and stapling complete"
        fi

        # For universal builds (ARCHID=10005), also notarize the universal binary
        if [ "$BUILD_ARCHID" = "10005" ]; then
            echo ""
            echo "  Notarizing universal binary: $BINARY_PATH"

            # Verify binary is signed (required for notarization) - run as user
            if ! sudo -u $SUDO_USER codesign --verify --strict "$BINARY_PATH" 2>/dev/null; then
                echo "  Error: Universal binary must be signed before notarization"
                exit 1
            fi

            # Notarize the universal binary
            sudo -u $SUDO_USER ./build/tools/macos_build/macos-notarize.sh "$BINARY_PATH"
            echo "  ✓ Universal binary notarized"
            echo ""
            echo "Note: Standalone binaries cannot be stapled. The notarization is stored in Apple's servers."

            echo ""
            echo "  Notarizing ARM64 bundle..."
            ARM_BUNDLE="build/output/osx-arm-64-app/MeshAgent.app"
            if [ -d "$ARM_BUNDLE" ]; then
                if sudo -u $SUDO_USER codesign --verify --deep --strict "$ARM_BUNDLE" 2>/dev/null; then
                    sudo -u $SUDO_USER SKIP_STAPLE="$SKIP_STAPLE" ./build/tools/macos_build/notarize-app-bundle.sh "$ARM_BUNDLE"
                    echo "    ✓ ARM64 bundle notarized"
                else
                    echo "    ⚠ ARM64 bundle not signed, skipping notarization"
                fi
            else
                echo "    ⚠ ARM64 bundle not found"
            fi

            echo ""
            echo "  Notarizing x86_64 bundle..."
            X86_BUNDLE="build/output/osx-x86-64-app/MeshAgent.app"
            if [ -d "$X86_BUNDLE" ]; then
                if sudo -u $SUDO_USER codesign --verify --deep --strict "$X86_BUNDLE" 2>/dev/null; then
                    sudo -u $SUDO_USER SKIP_STAPLE="$SKIP_STAPLE" ./build/tools/macos_build/notarize-app-bundle.sh "$X86_BUNDLE"
                    echo "    ✓ x86_64 bundle notarized"
                else
                    echo "    ⚠ x86_64 bundle not signed, skipping notarization"
                fi
            else
                echo "    ⚠ x86_64 bundle not found"
            fi
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

        # Verify binary is signed (required for notarization) - run as user
        if ! sudo -u $SUDO_USER codesign --verify --strict "$BINARY_PATH" 2>/dev/null; then
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
# UPDATE PKG BUILD-INFO AND COPY BUNDLE TO PAYLOAD
#==============================================================================

echo "[5/6] Updating pkg build-info and copying bundle to payload..."
echo "[$(date '+%H:%M:%S')] PKG preparation started"

# Extract short version from bundle's Info.plist
if [ -f "$BUNDLE_PATH/Contents/Info.plist" ]; then
    SHORT_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$BUNDLE_PATH/Contents/Info.plist" 2>/dev/null || echo "0.1")
    echo "  Bundle version: $SHORT_VERSION"

    # Update build-info.plist version
    BUILD_INFO_PLIST="$REPO_DIR/build/resources/MeshAgent_pkg/build-info.plist"
    if [ -f "$BUILD_INFO_PLIST" ]; then
        /usr/libexec/PlistBuddy -c "Set :version $SHORT_VERSION" "$BUILD_INFO_PLIST" 2>/dev/null || \
            echo "  Warning: Could not update build-info.plist version"
        echo "  ✓ Updated build-info.plist version to $SHORT_VERSION"
    else
        echo "  Warning: build-info.plist not found at $BUILD_INFO_PLIST"
    fi

    # Create payload directory and copy bundle
    PAYLOAD_DIR="$REPO_DIR/build/resources/MeshAgent_pkg/payload/private/tmp"
    sudo -u $SUDO_USER mkdir -p "$PAYLOAD_DIR"

    # Remove existing bundle if present
    if [ -d "$PAYLOAD_DIR/MeshAgent.app" ]; then
        sudo -u $SUDO_USER rm -rf "$PAYLOAD_DIR/MeshAgent.app"
    fi

    # Copy bundle using ditto (preserves all metadata, permissions, and extended attributes)
    sudo -u $SUDO_USER ditto "$BUNDLE_PATH" "$PAYLOAD_DIR/MeshAgent.app"
    echo "  ✓ Copied bundle to $PAYLOAD_DIR/MeshAgent.app"

    # Build the .pkg using munkipkg (only if --build-pkg flag is set)
    if [ "$BUILD_PKG" = "yes" ]; then
        echo ""
        echo "  Building installer package..."
        cd "$REPO_DIR"
        if command -v munkipkg &> /dev/null; then
            sudo -u $SUDO_USER munkipkg ./build/resources/MeshAgent_pkg/
            if [ $? -eq 0 ]; then
                echo "  ✓ Package built successfully"
                # Show the built package location
                PKG_BUILD_DIR="./build/resources/MeshAgent_pkg/build"
                if [ -d "$PKG_BUILD_DIR" ]; then
                    BUILT_PKG=$(ls -t "$PKG_BUILD_DIR"/*.pkg 2>/dev/null | head -1)
                    if [ -n "$BUILT_PKG" ]; then
                        echo "  ✓ Package: $BUILT_PKG"
                    fi
                fi
            else
                echo "  ⚠ Package build failed"
            fi
        else
            echo "  ⚠ munkipkg not found - skipping package build"
            echo "  Install munkipkg from: https://github.com/munki/munki-pkg"
        fi
    else
        echo ""
        echo "  ℹ Skipping .pkg build (use --build-pkg to enable)"
    fi
else
    echo "  Warning: Bundle Info.plist not found, skipping version update"
fi

echo "[$(date '+%H:%M:%S')] PKG preparation complete"
echo "✓ PKG preparation complete"
echo ""

#==============================================================================
# ZIP APP BUNDLES
#==============================================================================

echo "[6/6] Creating app bundle zip archive..."
echo "[$(date '+%H:%M:%S')] Zip creation started"

if [ -d "$BUNDLE_PATH" ]; then
    # Determine output zip filename based on architecture
    if [ "$ARCHID" = "16" ]; then
        ZIP_NAME="${BINARY_PREFIX}_osx-x86-64-app.zip"
    elif [ "$ARCHID" = "29" ]; then
        ZIP_NAME="${BINARY_PREFIX}_osx-arm-64-app.zip"
    elif [ "$ARCHID" = "10005" ]; then
        ZIP_NAME="${BINARY_PREFIX}_osx-universal-64-app.zip"
    fi

    ZIP_PATH="build/output/$ZIP_NAME"

    # Remove existing zip if present
    if [ -f "$ZIP_PATH" ]; then
        sudo -u $SUDO_USER rm -f "$ZIP_PATH"
        echo "  Removed existing: $ZIP_NAME"
    fi

    # Create zip from bundle directory
    # cd into the bundle's parent directory so the zip contains MeshAgent.app/ at root
    BUNDLE_DIR=$(dirname "$BUNDLE_PATH")
    BUNDLE_NAME=$(basename "$BUNDLE_PATH")

    echo "  Creating: $ZIP_NAME"
    echo "  Source:   $BUNDLE_PATH"

    # Use ditto to create zip (preserves all metadata, permissions, code signatures)
    # Run as actual user to preserve ownership
    (cd "$BUNDLE_DIR" && sudo -u $SUDO_USER ditto -c -k --keepParent "$BUNDLE_NAME" "../$ZIP_NAME")

    if [ -f "$ZIP_PATH" ]; then
        ZIP_SIZE=$(du -h "$ZIP_PATH" | cut -f1)
        echo "  ✓ Created: $ZIP_NAME ($ZIP_SIZE)"
    else
        echo "  ⚠ Failed to create zip archive"
    fi

    # For universal builds, also create zips for ARM and x86 bundles
    if [ "$BUILD_ARCHID" = "10005" ]; then
        echo ""
        echo "  Creating ARM64 bundle zip..."
        ARM_BUNDLE="build/output/osx-arm-64-app/MeshAgent.app"
        ARM_ZIP_NAME="${BINARY_PREFIX}_osx-arm-64-app.zip"
        ARM_ZIP_PATH="build/output/$ARM_ZIP_NAME"

        if [ -d "$ARM_BUNDLE" ]; then
            [ -f "$ARM_ZIP_PATH" ] && sudo -u $SUDO_USER rm -f "$ARM_ZIP_PATH"
            (cd "build/output/osx-arm-64-app" && sudo -u $SUDO_USER ditto -c -k --keepParent "MeshAgent.app" "../$ARM_ZIP_NAME")
            if [ -f "$ARM_ZIP_PATH" ]; then
                ARM_ZIP_SIZE=$(du -h "$ARM_ZIP_PATH" | cut -f1)
                echo "    ✓ Created: $ARM_ZIP_NAME ($ARM_ZIP_SIZE)"
            else
                echo "    ⚠ Failed to create ARM64 zip"
            fi
        else
            echo "    ⚠ ARM64 bundle not found"
        fi

        echo ""
        echo "  Creating x86_64 bundle zip..."
        X86_BUNDLE="build/output/osx-x86-64-app/MeshAgent.app"
        X86_ZIP_NAME="${BINARY_PREFIX}_osx-x86-64-app.zip"
        X86_ZIP_PATH="build/output/$X86_ZIP_NAME"

        if [ -d "$X86_BUNDLE" ]; then
            [ -f "$X86_ZIP_PATH" ] && sudo -u $SUDO_USER rm -f "$X86_ZIP_PATH"
            (cd "build/output/osx-x86-64-app" && sudo -u $SUDO_USER ditto -c -k --keepParent "MeshAgent.app" "../$X86_ZIP_NAME")
            if [ -f "$X86_ZIP_PATH" ]; then
                X86_ZIP_SIZE=$(du -h "$X86_ZIP_PATH" | cut -f1)
                echo "    ✓ Created: $X86_ZIP_NAME ($X86_ZIP_SIZE)"
            else
                echo "    ⚠ Failed to create x86_64 zip"
            fi
        else
            echo "    ⚠ x86_64 bundle not found"
        fi
    fi
else
    echo "  Warning: Bundle not found at $BUNDLE_PATH, skipping zip creation"
fi

echo "[$(date '+%H:%M:%S')] Zip creation complete"
echo "✓ Zip creation complete"
echo ""

#==============================================================================
# SUMMARY
#==============================================================================

echo "=========================================="
echo "Script Complete!"
echo "=========================================="
echo "Architecture:     $ARCH_DESC"
echo "Application bundle: $BUNDLE_PATH"
echo "Binary:           $BUNDLE_PATH/Contents/MacOS/meshagent"
echo ""

# Display version information
echo "Version:"
$BUNDLE_PATH/Contents/MacOS/meshagent -version

echo ""
echo "To launch Install UI:"
echo "  1. Navigate to: open $REPO_DIR/$(dirname "$BUNDLE_PATH")/"
echo "  2. Hold CMD and double-click MeshAgent.app (or select it and press CMD+O)"
echo "  3. Keep holding CMD until prompted to authenticate"

echo ""
echo "=========================================="
echo "End Time:         $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="
