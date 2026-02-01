# macOS Build Tools for MeshAgent

This directory contains the macOS-specific build toolchain for signing, notarization, and app bundle creation.

## Directory Contents

```
build/tools/macos_build/
├── README.md                        # This file
├── macos-sign.sh                    # User-facing: sign targets (multi-target)
├── macos-notarize.sh                # User-facing: notarize targets (multi-target)
├── create-app-bundle.sh             # Internal: package binary into .app bundle
├── generate-info-plist.sh           # Internal: generate Info.plist from template
├── generate-build-timestamp.sh      # Internal: emit build timestamp variables
└── macos-build_icns/                # Icon assets and .icns build script
```

---

## Quick Start

### Build via Makefile (Recommended)

```bash
# Build universal binary (no signing)
make macos ARCHID=10005

# Build with signing
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
make macos ARCHID=10005 SIGN=1

# Build with signing + notarization
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
make macos ARCHID=10005 SIGN=1 NOTARIZE=1

# Build code-utils binary (minimal, for polyfill generation)
make macos ARCHID=10005 KVM=0
```

### Sign/Notarize Standalone

```bash
# Sign after building
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
./build/tools/macos_build/macos-sign.sh build/output/meshagent_osx-universal-64

# Notarize after signing
./build/tools/macos_build/macos-notarize.sh build/output/meshagent_osx-universal-64
```

---

## Scripts Overview

### 1. `macos-sign.sh`

**Purpose:** Sign any mix of macOS binaries and `.app` bundles.

**Usage:**
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
./build/tools/macos_build/macos-sign.sh <target> [target2] [target3] ...
```

**Auto-detection:**
- Directory ending in `.app` → bundle signing (`codesign --deep`)
- Regular file → binary signing (`codesign`, plus lipo slice extraction if universal)

**What It Does:**
1. Validates `$MACOS_SIGN_CERT` is set
2. For each target:
   - **Bundle**: Signs with `codesign --sign CERT --options runtime --timestamp --deep --force`, verifies
   - **Binary**: Signs with `codesign --sign CERT --options runtime --timestamp --force`, verifies
     - If universal: extracts arm64 and x86_64 slices via `lipo -thin`, verifies each

**Examples:**
```bash
# Sign a single binary
./macos-sign.sh build/output/meshagent_osx-universal-64

# Sign a single bundle
./macos-sign.sh build/output/osx-universal-64-app/MeshAgent.app

# Sign everything at once
./macos-sign.sh build/output/meshagent_osx-universal-64 \
  build/output/osx-universal-64-app/MeshAgent.app \
  build/output/osx-arm-64-app/MeshAgent.app \
  build/output/osx-x86-64-app/MeshAgent.app
```

**Requirements:**
- `MACOS_SIGN_CERT` environment variable must be set
- Certificate must exist in keychain
- Must run as actual user (not root) to access keychain

---

### 2. `macos-notarize.sh`

**Purpose:** Submit any mix of macOS binaries and `.app` bundles to Apple's notary service.

**Usage:**
```bash
./build/tools/macos_build/macos-notarize.sh <target> [target2] [target3] ...
```

**Auto-detection:**
- Directory ending in `.app` → bundle (zip, submit, staple, Gatekeeper verify)
- Regular file → binary (zip, submit, extract arch slices via lipo)

**Parallelism:**
- 1 target → sequential (`submit --wait`, then post-process)
- 2+ targets → parallel (submit all, wait all in parallel, then post-process all)

**Post-processing:**
- **Bundles**: Staple notarization ticket (unless `SKIP_STAPLE=yes`), Gatekeeper verify
- **Binaries**: Extract architecture slices via lipo (binaries cannot be stapled)

**Environment Variables:**
- `MACOS_NOTARY_PROFILE` — Keychain profile name (default: `meshagent-notary`)
- `SKIP_STAPLE` — Set to `yes` to skip stapling (default: `no`)

**Keychain Profile Setup (One-Time):**
```bash
xcrun notarytool store-credentials meshagent-notary \
  --apple-id "your-email@example.com" \
  --team-id "TEAMID" \
  --password "app-specific-password"
```

**Examples:**
```bash
# Notarize a single binary
./macos-notarize.sh build/output/meshagent_osx-universal-64

# Notarize a single bundle
./macos-notarize.sh build/output/osx-universal-64-app/MeshAgent.app

# Notarize everything in parallel
./macos-notarize.sh build/output/meshagent_osx-universal-64 \
  build/output/osx-universal-64-app/MeshAgent.app \
  build/output/osx-arm-64-app/MeshAgent.app \
  build/output/osx-x86-64-app/MeshAgent.app
```

**Requirements:**
- All targets must be signed first (with `macos-sign.sh`)
- `meshagent-notary` keychain profile must be configured
- Internet connection (submits to Apple servers)

---

## Info.plist Generation

Info.plist files are generated at build time by `generate-info-plist.sh` from templates in `build/resources/Info/`:

| Template | Mode | Used for |
|----------|------|----------|
| `build/resources/Info/binary/binary_Info.plist` | `--mode binary` | Embedded in standalone Mach-O binary via `-sectcreate` |
| `build/resources/Info/bundle/app_Info.plist` | `--mode bundle` | Placed in `.app/Contents/Info.plist` by `create-app-bundle.sh` |

**How It Works:**

1. **Timestamp generation** — `generate-build-timestamp.sh` emits `BUILD_DATE` and `BUILD_TIME_ONLY` variables (format: `YY.MM.DD` / `HH.MM.SS`)
2. **Plist generation** — `generate-info-plist.sh` substitutes placeholders (`BUNDLE_IDENTIFIER`, `BUNDLE_EXE_NAME`, `BUNDLE_DISPLAY_NAME`, `BUILD_TIMESTAMP_DATE`, `BUILD_TIMESTAMP_TIME`) in the template
3. **Binary embedding** — Linker flag `-sectcreate __TEXT __info_plist` embeds the generated plist in the Mach-O binary
4. **Runtime access** — `meshagent --version` reads the embedded plist via `getsectiondata()` and displays `CFBundleShortVersionString`

**Verification:**
```bash
# View embedded plist
otool -X -s __TEXT __info_plist build/output/meshagent_osx-universal-64 | xxd -r

# Check --version output
./build/output/meshagent_osx-universal-64 --version
# Output: 25.11.13.17.27.44
```

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
- `code-utils.js` - Polyfill compression/decompression
- `daemon.js` - Agent daemon functionality
- `identifiers.js` - System identification
- `promise.js` - Promise/A+ implementation
- `util-agentlog.js` - Logging utilities

### Building Code-Utils Binary

```bash
cd /path/to/MeshAgent
make macos ARCHID=10005 KVM=0
```

**Output:**
- `build/output/meshagent_osx-universal-64`
- `build/output/meshagent_osx-x86-64`
- `build/output/meshagent_osx-arm-64`

### Using Code-Utils Binary

See `build/tools/code-utils/example-populate-polyfills.sh` for a working example.

**Storage Location:**

Code-utils binaries can be stored at:
```
build/tools/code-utils/macos/meshagent_code-utils
```

This allows them to be reused across builds without rebuilding.

---

## Common Workflows

### Development Build (Quick Iteration)
```bash
# No signing or notarization
make macos ARCHID=10005
```

### Production Build (Full Signing + Notarization)
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
make macos ARCHID=10005 SIGN=1 NOTARIZE=1
```

### Architecture-Specific Builds
```bash
# Intel only
make macos ARCHID=16

# ARM only
make macos ARCHID=29
```

### Skip Signing for Bundles or Binaries
```bash
# Sign only bundles (skip binary signing)
make macos ARCHID=10005 SIGN=1 SKIPSIGNNOTARY=binary

# Sign only binaries (skip bundle signing)
make macos ARCHID=10005 SIGN=1 SKIPSIGNNOTARY=bundle
```

---

## Troubleshooting

### Code Signing Issues

**Error: "MACOS_SIGN_CERT environment variable not set"**
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
sudo -E make macos ARCHID=10005 SIGN=1
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

Apple's notary service can take 5-30 minutes. To skip during development, omit `NOTARIZE=1`.

---

## Additional Resources

- **Signing Script:** `build/tools/macos_build/macos-sign.sh`
- **Notarization Script:** `build/tools/macos_build/macos-notarize.sh`
- **Plist Templates:** `build/resources/Info/binary/` and `build/resources/Info/bundle/`
- **Makefile:** `makefile`
- **Module Lists:**
  - Full macOS modules: `modules/.modules_macos` (50 modules)
  - Minimal modules: `modules/.modules_macos_minimal` (8 modules)
