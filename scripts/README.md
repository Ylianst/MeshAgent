# Build Scripts

This directory contains scripts for building, signing, and distributing MeshAgent binaries.

## Quick Start: Complete macOS Pipeline

**For the full workflow (signing + notarization + stapling), use the pipeline script:**

```bash
# Set your credentials
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
export APPLE_ID="developer@example.com"
export APPLE_TEAM_ID="TEAMID"
export APPLE_APP_PASSWORD="xxxx-xxxx-xxxx-xxxx"

# Configure what to run (optional, defaults shown)
export DO_SIGN=true
export DO_NOTARIZE=false  # Set to true when ready
export DO_STAPLE=false    # Set to true after notarization works

# Run the pipeline
./scripts/build-pipeline-macos.sh
```

**Or use individual scripts for specific tasks** (see sections below).

---

## build-pipeline-macos.sh

Comprehensive workflow script that orchestrates signing, notarization, and stapling.

### Features

- **Configurable pipeline** - Enable/disable steps via environment variables
- **Validates configuration** - Checks credentials before running
- **Color-coded output** - Clear progress indicators
- **Error handling** - Stops on failure with helpful messages

### Configuration

Control the pipeline with environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MACOS_SIGN_CERT` | If signing | - | Your Developer ID certificate name |
| `APPLE_ID` | If notarizing | - | Your Apple ID email |
| `APPLE_TEAM_ID` | If notarizing | - | Your Apple Developer Team ID |
| `APPLE_APP_PASSWORD` | If notarizing | - | App-specific password |
| `DO_SIGN` | No | `true` | Enable/disable code signing |
| `DO_NOTARIZE` | No | `false` | Enable/disable notarization |
| `DO_STAPLE` | No | `false` | Enable/disable stapling |

### Usage Examples

**Just signing (default):**
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
./scripts/build-pipeline-macos.sh
```

**Signing + Notarization:**
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
export APPLE_ID="developer@example.com"
export APPLE_TEAM_ID="TEAMID"
export APPLE_APP_PASSWORD="xxxx-xxxx-xxxx-xxxx"
export DO_NOTARIZE=true
./scripts/build-pipeline-macos.sh
```

**Full pipeline:**
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
export APPLE_ID="developer@example.com"
export APPLE_TEAM_ID="TEAMID"
export APPLE_APP_PASSWORD="xxxx-xxxx-xxxx-xxxx"
export DO_SIGN=true
export DO_NOTARIZE=true
export DO_STAPLE=true
./scripts/build-pipeline-macos.sh
```

### Personal Wrapper

For frequent use, create a personal wrapper in `/bin/` (gitignored):

```bash
#!/bin/bash
# bin/my-build-pipeline.sh

export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
export APPLE_ID="developer@example.com"
export APPLE_TEAM_ID="TEAMID"
export APPLE_APP_PASSWORD="xxxx-xxxx-xxxx-xxxx"
export DO_SIGN=true
export DO_NOTARIZE=false
export DO_STAPLE=false

./scripts/build-pipeline-macos.sh
```

This keeps your credentials out of git while using the standardized pipeline.

---

## Individual Scripts

Use these for specific tasks or when you need more control.

## macOS Code Signing

### Prerequisites

- macOS with Xcode Command Line Tools
- Valid Apple Developer ID certificate installed in your Keychain
- Built binaries in `build/macos/` directories

### Finding Your Certificate

List available code signing certificates:

```bash
security find-identity -v -p codesigning
```

Look for a line like:
```
1) ABCD1234... "Developer ID Application: Your Name (TEAM123456)"
```

### Signing Binaries

1. Set your certificate name as an environment variable:

```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAM123456)"
```

2. Run the signing script:

```bash
./scripts/sign-macos.sh
```

This will sign all binaries in `build/macos/` including DEBUG versions.

### What Gets Signed

The script automatically finds and signs:
- `build/macos/macos-arm-64/meshagent`
- `build/macos/macos-arm-64/DEBUG_meshagent`
- `build/macos/macos-x86-64/meshagent`
- `build/macos/macos-x86-64/DEBUG_meshagent`
- `build/macos/universal/meshagent`
- `build/macos/universal/DEBUG_meshagent`

### Signing Features

- **Hardened Runtime** - Required for notarization and modern macOS security
- **Timestamp** - Ensures signature remains valid even if certificate expires
- **Verification** - Automatically verifies each signature after signing

### Verifying Signatures

Check if a binary is properly signed:

```bash
codesign -vvv --deep --strict build/macos/macos-arm-64/meshagent
```

Check signature details:

```bash
codesign -d --entitlements - build/macos/macos-arm-64/meshagent
```

## macOS Notarization

**Status: Not yet implemented** (see `notarize-macos.sh` for manual steps)

Notarization is required for distribution outside the Mac App Store on macOS 10.15+.

### Manual Notarization Process

1. Sign the binary first
2. Create a ZIP of the signed binary
3. Submit to Apple's notarization service
4. Wait for approval (minutes to hours)
5. Staple the notarization ticket to the binary

See Apple's documentation:
https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution

## Build Workflow

Complete workflow for building and signing:

```bash
# Build for Apple Silicon
make macos ARCHID=29

# Build for Intel
make macos ARCHID=16

# Build universal binary (both architectures)
make macos ARCHID=universal

# Sign all binaries
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAM123456)"
./scripts/sign-macos.sh

# (Future) Notarize
# ./scripts/notarize-macos.sh
```

## Environment Variables

### MACOS_SIGN_CERT (Required for signing)

Your Apple Developer ID Application certificate name.

Example:
```bash
export MACOS_SIGN_CERT="Developer ID Application: Peet, Inc. (UW6CS5W75L)"
```

### Future Variables (for notarization)

- `APPLE_ID` - Your Apple ID email
- `APPLE_TEAM_ID` - Your Apple Developer Team ID
- `APPLE_APP_PASSWORD` - App-specific password for notarytool

## Troubleshooting

### "No identity found" error

Your certificate may not be in your login keychain. Import it:
```bash
security import certificate.p12 -k ~/Library/Keychains/login.keychain
```

### "User interaction is not allowed" error

Unlock your keychain first:
```bash
security unlock-keychain ~/Library/Keychains/login.keychain
```

### Signature verification fails

- Ensure you're using the correct certificate name
- Check that your certificate is valid and not expired
- Try signing with the `--force` flag (already included in script)

## Additional Resources

- [Apple Code Signing Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/)
- [Notarizing macOS Software](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution)
- [Hardened Runtime](https://developer.apple.com/documentation/security/hardened_runtime)
