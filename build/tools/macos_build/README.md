# macOS Build Tools for MeshAgent

This directory contains the complete build toolchain for creating macOS MeshAgent binaries with signing, notarization, and testing capabilities.

## Directory Contents

```
build/tools/macos_build/
├── README.md                      # This file
├── Info.plist/
│   ├── Info.plist.template        # Template for embedded plist (with BUILD_TIMESTAMP placeholder)
│   └── Info.plist                 # Generated plist (created during build with actual timestamp)
├── macos-build_with_test.sh       # Main development/testing build script
├── macos-sign.sh                  # Code signing script (can be sourced or executed)
└── macos-notarize.sh              # Apple notarization script (can be sourced or executed)
```

---

## Quick Start

### Basic Build (No Signing)
```bash
cd /Users/peet/GitHub/MeshAgent_installer
sudo ./build/tools/macos_build/macos-build_with_test.sh --skip-sign --skip-notary
```

### Full Build (Signed + Notarized)
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
sudo -E ./build/tools/macos_build/macos-build_with_test.sh
```

### Code-Utils Build (Minimal for Polyfill Generation)
```bash
sudo ./build/tools/macos_build/macos-build_with_test.sh --code-utils --skip-sign --skip-notary
```

---

## Scripts Overview

### 1. `macos-build_with_test.sh`

**Purpose:** Main development and testing script that orchestrates the complete build workflow.

**Features:**
- Polyfill regeneration from JavaScript modules
- Build for Intel (x86-64), ARM64, or Universal binaries
- Code signing with hardened runtime
- Apple notarization
- Built-in meshagent installation/testing commands
- Support for code-utils minimal builds

**Default Configuration:**
```bash
ARCHID="10005"                      # Universal binary (Intel + ARM)
SKIP_POLYFILLS="no"                 # Regenerate polyfills
MACOS_ONLY_POLYFILLS="yes"          # Use macOS-specific modules only
CODE_UTILS_BUILD="no"               # Full build (not code-utils)
SKIP_BUILD="no"                     # Perform build
SKIP_SIGN="no"                      # Sign binary
SKIP_NOTARY="no"                    # Notarize binary
SKIP_GIT_PULL="yes"                 # Don't pull git updates
```

**Command-Line Options:**

| Option | Description |
|--------|-------------|
| `--archid <16\|29\|10005>` | Architecture: 16=Intel, 29=ARM, 10005=Universal |
| `--skip-polyfills` | Skip polyfill regeneration |
| `--macos-only-polyfills` | Use modules_macos (50 modules) - default |
| `--all-polyfills` | Use all modules/ directory |
| `--code-utils` | Build minimal binary (8 modules, KVM=0) for polyfill generation |
| `--skip-build` | Skip build step |
| `--skip-sign` | Skip code signing |
| `--skip-notary` | Skip notarization |
| `--git-pull` | Pull latest git changes before building |
| `--msh-command <cmd>` | Execute meshagent command after build (install, fullinstall, upgrade, etc.) |
| `--msh-installPath <path>` | Installation path for meshagent |
| `--msh-companyName <name>` | Company name for installation |
| `--msh-meshServiceName <name>` | Service name for installation |

**Build Workflow (6 Steps):**

1. **Polyfill Generation** (if not skipped)
   - Syncs modules from `modules/` to `modules_macos/`
   - Runs `build/tools/meshagent/macos/meshagent -import` to generate polyfills
   - Updates `microscript/ILibDuktape_Polyfills.c`

2. **Build**
   - Runs `make clean`
   - Builds with `make macos ARCHID=<archid> [KVM=0]`
   - For code-utils builds: renames output to `meshagent_code-utils_*`

3. **Signing** (if not skipped)
   - Calls `macos-sign.sh` with `$MACOS_SIGN_CERT`
   - Signs with hardened runtime (`--options runtime`)
   - Extracts architecture slices from universal binary

4. **Notarization** (if not skipped)
   - Calls `macos-notarize.sh`
   - Submits to Apple's notary service
   - Waits for approval
   - Extracts architecture slices from notarized universal binary

5. **Installation/Testing** (if `--msh-command` specified)
   - Executes meshagent with specified command
   - Example: `-install`, `-fullinstall`, `-upgrade`, `-uninstall`

6. **Completion**
   - Displays build summary
   - Shows binary locations

**Output Locations:**

| Build Type | Universal | Intel | ARM |
|------------|-----------|-------|-----|
| **Regular** | `build/output/meshagent_osx-universal-64` | `build/output/meshagent_osx-x86-64` | `build/output/meshagent_osx-arm-64` |
| **Code-Utils** | `build/output/meshagent_code-utils_osx-universal-64` | `build/output/meshagent_code-utils_osx-x86-64` | `build/output/meshagent_code-utils_osx-arm-64` |
| **Debug** | `build/output/DEBUG/meshagent_*` | `build/output/DEBUG/meshagent_*` | `build/output/DEBUG/meshagent_*` |

**Environment Variables Required:**

For signing:
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
```

For notarization (must be configured once):
```bash
xcrun notarytool store-credentials meshagent-notary \
  --apple-id "your-email@example.com" \
  --team-id "TEAMID" \
  --password "app-specific-password"
```

**Usage Examples:**

```bash
# Build universal binary, skip signing/notarization
sudo ./build/tools/macos_build/macos-build_with_test.sh --skip-sign --skip-notary

# Build Intel only, with signing and notarization
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
sudo -E ./build/tools/macos_build/macos-build_with_test.sh --archid 16

# Build and install to custom location
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
sudo -E ./build/tools/macos_build/macos-build_with_test.sh \
  --msh-command fullinstall \
  --msh-installPath /opt/meshagent \
  --msh-companyName "MyCompany"

# Build code-utils binary for polyfill generation
sudo ./build/tools/macos_build/macos-build_with_test.sh --code-utils --skip-sign --skip-notary
```

---

### 2. `macos-sign.sh`

**Purpose:** Sign macOS universal binaries with Apple Developer ID and extract architecture slices.

**Features:**
- Can be executed standalone or sourced for function use
- Signs universal binaries with hardened runtime
- Automatically extracts x86-64 and ARM64 slices using `lipo`
- Validates certificate before signing

**Standalone Execution:**
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
./build/tools/macos_build/macos-sign.sh /path/to/universal-binary
```

**Sourced Usage:**
```bash
source ./build/tools/macos_build/macos-sign.sh
macos_sign_binary "/path/to/universal-binary"
macos_sign_extract_architectures "/path/to/signed-universal-binary"
```

**Functions Provided:**
- `macos_sign_binary <path>` - Sign binary and extract slices
- `macos_sign_universal_binary <path>` - Sign only (no extraction)
- `macos_sign_extract_architectures <path>` - Extract slices only

**What It Does:**
1. Validates `$MACOS_SIGN_CERT` is set
2. Verifies certificate exists in keychain
3. Checks binary is universal (`lipo -info`)
4. Signs with: `codesign --force --options runtime --sign "$MACOS_SIGN_CERT"`
5. Verifies signature: `codesign --verify --deep --strict`
6. Extracts slices:
   - `lipo -thin x86_64 -output <path>_osx-x86-64`
   - `lipo -thin arm64 -output <path>_osx-arm-64`

**Requirements:**
- Binary must be universal (contains both x86_64 and arm64)
- `MACOS_SIGN_CERT` environment variable must be set
- Certificate must exist in keychain
- Must run as actual user (not root) to access keychain

---

### 3. `macos-notarize.sh`

**Purpose:** Submit universal binaries to Apple's notary service and extract architecture slices.

**Features:**
- Can be executed standalone or sourced for function use
- Creates ZIP, submits to Apple notarization
- Waits for approval (can take 5-30 minutes)
- Extracts architecture slices after notarization
- Optional verbose output

**Standalone Execution:**
```bash
./build/tools/macos_build/macos-notarize.sh /path/to/signed-universal-binary [--verbose]
```

**Sourced Usage:**
```bash
source ./build/tools/macos_build/macos-notarize.sh
macos_notarize_binary "/path/to/signed-universal-binary" [--verbose]
macos_notarize_extract_architectures "/path/to/notarized-universal-binary"
```

**Functions Provided:**
- `macos_notarize_binary <path> [--verbose]` - Notarize and extract slices
- `macos_notarize_extract_architectures <path>` - Extract slices only

**What It Does:**
1. Verifies `meshagent-notary` keychain profile exists
2. Checks binary is universal
3. Creates temporary ZIP: `ditto -c -k --keepParent`
4. Submits to Apple: `xcrun notarytool submit --keychain-profile meshagent-notary --wait`
5. Waits for approval (polls Apple's service)
6. Extracts slices using `lipo`

**Keychain Profile Setup (One-Time):**
```bash
xcrun notarytool store-credentials meshagent-notary \
  --apple-id "your-email@example.com" \
  --team-id "TEAMID" \
  --password "app-specific-password"
```

**Requirements:**
- Binary must be signed first (with `macos-sign.sh`)
- Binary must be universal
- `meshagent-notary` keychain profile must be configured
- Internet connection (submits to Apple servers)

**Note:** Notarization can take 5-30 minutes depending on Apple's service load.

---

## Info.plist Directory

### `Info.plist/Info.plist.template`

**Purpose:** Template for embedding bundle information in the macOS binary.

**Contents:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>meshagent</string>
    <key>CFBundleName</key>
    <string>meshagent</string>
    <key>CFBundleShortVersionString</key>
    <string>BUILD_TIMESTAMP</string>
</dict>
</plist>
```

**Why It Exists:**

macOS binaries benefit from embedded bundle information for:
1. **System Integration** - Better macOS system compatibility
2. **Version Tracking** - Embedded build timestamp in `--version` output
3. **Bundle Identification** - Unique CFBundleIdentifier for the agent

**How It Works:**

During the build process (in `makefile`):

1. **Timestamp Generation:**
   - For universal builds: timestamp generated once, shared between both architectures
   - For single-arch builds: timestamp generated at build time
   - Format: `YY.MM.DD.HH.MM.SS` (e.g., `25.11.13.17.27.44`)

2. **Plist Creation:**
   ```bash
   sed "s/BUILD_TIMESTAMP/$$BUILD_TIME/g" \
     build/tools/macos_build/Info.plist/Info.plist.template \
     > build/tools/macos_build/Info.plist/Info.plist
   ```

3. **Embedding:**
   - Linker flag: `-sectcreate __TEXT __info_plist build/tools/macos_build/Info.plist/Info.plist`
   - Creates `__TEXT` segment, `__info_plist` section in Mach-O binary

4. **Runtime Access:**
   - `meshagent --version` reads embedded plist using `getsectiondata()`
   - Parses XML using CoreFoundation
   - Displays `CFBundleShortVersionString` value

**Verification:**
```bash
# View embedded plist
otool -X -s __TEXT __info_plist build/output/meshagent_osx-universal-64 | xxd -r

# Check --version output
./build/output/meshagent_osx-universal-64 --version
# Output: 25.11.13.17.27.44
```

### `Info.plist/Info.plist`

**Purpose:** Generated plist file with actual build timestamp (created during build).

**Note:** This file is regenerated on every build and should **not** be committed to git. The `.template` file is the source of truth.

---

## Building Code-Utils Binaries

Code-utils binaries are **minimal** MeshAgent builds used exclusively for polyfill generation.

### What is a Code-Utils Build?

A code-utils build is a stripped-down MeshAgent containing only the essential modules needed to run the `code-utils` module for polyfill compression/decompression:

| Feature | Code-Utils Build | Full Build |
|---------|------------------|------------|
| **Modules** | 8 minimal modules | 50 macOS modules |
| **KVM Support** | No (KVM=0) | Yes |
| **Remote Desktop** | No | Yes |
| **Purpose** | Polyfill generation only | Production deployment |
| **Size** | ~Small | ~Large |

### Minimal Module Set (8 modules)

The code-utils build includes only:
- `_agentNodeId.js` - Core agent identification
- `_agentStatus.js` - Core status reporting
- `AgentHashTool.js` - Hash utilities
- `code-utils.js` - Polyfill compression/decompression ⭐
- `daemon.js` - Agent daemon functionality
- `identifiers.js` - System identification
- `promise.js` - Promise/A+ implementation
- `util-agentlog.js` - Logging utilities

### Building Code-Utils Binary

```bash
cd /Users/peet/GitHub/MeshAgent_installer
sudo ./build/tools/macos_build/macos-build_with_test.sh --code-utils --skip-sign --skip-notary
```

**Output:**
- `build/output/meshagent_code-utils_osx-universal-64`
- `build/output/meshagent_code-utils_osx-x86-64`
- `build/output/meshagent_code-utils_osx-arm-64`

### Using Code-Utils Binary

**For Polyfill Generation:**
```bash
./build/output/meshagent_code-utils_osx-universal-64 -exec "require('code-utils').shrink({expandedPath: './modules_expanded', filePath: './microscript/ILibDuktape_Polyfills.c'});process.exit();"
```

**Storage Location:**

Code-utils binaries can be stored at:
```
build/tools/code-utils/macos/meshagent_code-utils_osx-universal-64
```

This allows them to be version-controlled and reused across builds without rebuilding.

### Build Workflow with Code-Utils

**Option 1: Using Pre-Built Code-Utils Binary**
```bash
# 1. Use existing code-utils binary to regenerate polyfills
./build/tools/code-utils/macos/meshagent_code-utils_osx-universal-64 -exec "require('code-utils').shrink(...);"

# 2. Build production agent
sudo -E ./build/tools/macos_build/macos-build_with_test.sh
```

**Option 2: Building Fresh Code-Utils**
```bash
# 1. Build code-utils binary
sudo ./build/tools/macos_build/macos-build_with_test.sh --code-utils --skip-sign --skip-notary

# 2. Copy to tools directory (optional, for reuse)
cp build/output/meshagent_code-utils_osx-universal-64 build/tools/code-utils/macos/

# 3. Use it to regenerate polyfills
./build/output/meshagent_code-utils_osx-universal-64 -exec "require('code-utils').shrink(...);"

# 4. Build production agent
sudo -E ./build/tools/macos_build/macos-build_with_test.sh
```

---

## Common Workflows

### Development Build (Quick Iteration)
```bash
# Skip polyfills, signing, notarization for fast builds
sudo ./build/tools/macos_build/macos-build_with_test.sh \
  --skip-polyfills \
  --skip-sign \
  --skip-notary
```

### Production Build (Full Signing + Notarization)
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
sudo -E ./build/tools/macos_build/macos-build_with_test.sh
```

### Architecture-Specific Builds
```bash
# Intel only
sudo ./build/tools/macos_build/macos-build_with_test.sh --archid 16 --skip-sign --skip-notary

# ARM only
sudo ./build/tools/macos_build/macos-build_with_test.sh --archid 29 --skip-sign --skip-notary
```

### Build with Installation
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
sudo -E ./build/tools/macos_build/macos-build_with_test.sh \
  --msh-command fullinstall \
  --msh-installPath /opt/meshagent \
  --msh-companyName "MyCompany" \
  --msh-meshServiceName "meshagent"
```

---

## Troubleshooting

### Code Signing Issues

**Error: "MACOS_SIGN_CERT environment variable not set"**
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
sudo -E ./build/tools/macos_build/macos-build_with_test.sh
```
**Note:** The `-E` flag preserves environment variables through sudo.

**Error: "Certificate not found in keychain"**
- Verify certificate name: `security find-identity -v -p codesigning`
- Ensure certificate is installed in login keychain
- Check certificate is valid and not expired

### Notarization Issues

**Error: "meshagent-notary keychain profile not found"**

Configure the profile:
```bash
xcrun notarytool store-credentials meshagent-notary \
  --apple-id "your-email@example.com" \
  --team-id "TEAMID" \
  --password "app-specific-password"
```

**Notarization Taking Too Long**

Apple's notary service can take 5-30 minutes. To skip during development:
```bash
sudo -E ./build/tools/macos_build/macos-build_with_test.sh --skip-notary
```

### Build Issues

**Error: "Code-utils meshagent not found"**

Build a code-utils binary first:
```bash
sudo ./build/tools/macos_build/macos-build_with_test.sh --code-utils --skip-sign --skip-notary
cp build/output/meshagent_code-utils_osx-universal-64 build/tools/meshagent/macos/meshagent
```

---

## Additional Resources

- **Main Build Script:** `/Users/peet/GitHub/MeshAgent_installer/build/tools/macos_build/macos-build_with_test.sh`
- **Signing Script:** `/Users/peet/GitHub/MeshAgent_installer/build/tools/macos_build/macos-sign.sh`
- **Notarization Script:** `/Users/peet/GitHub/MeshAgent_installer/build/tools/macos_build/macos-notarize.sh`
- **Makefile:** `/Users/peet/GitHub/MeshAgent_installer/makefile`
- **Module Lists:**
  - Full macOS modules: `/Users/peet/GitHub/MeshAgent_installer/modules/.modules_macos` (50 modules)
  - Minimal modules: `/Users/peet/GitHub/MeshAgent_installer/modules/.modules_macos_minimal` (8 modules)
