# Build Scripts

This directory contains scripts for building, signing, and distributing MeshAgent binaries.

## Directory Structure

Scripts are organized by platform:

- **`macos/`** - macOS-specific scripts (signing, notarization, build pipeline)
  - `sign-macos.sh` - Sign binaries with Developer ID
  - `notarize-macos.sh` - Notarize binaries with Apple (placeholder)
  - `build-pipeline-macos.sh` - Complete signing/notarization workflow
  - `meshagent-macos.entitlements` - Entitlements file for signing
- **`windows/`** - Windows-specific scripts (cleaning build artifacts)
  - `clean-windows.bat` - Clean build artifacts
- **`linux/`** - Linux-specific scripts (multi-architecture builds)
  - `build-linux-all.sh` - Build all Linux architectures
- **`templates-for-bin/`** - Templates to copy to `/bin` for personal use (see [README](templates-for-bin/README.md))
  - `test-meshagent.sh` - Development testing script template
  - `sign-and-notarize-template.sh` - Signing/notarization workflow template

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
./scripts/macos/build-pipeline-macos.sh
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
./scripts/macos/build-pipeline-macos.sh
```

**Signing + Notarization:**
```bash
export MACOS_SIGN_CERT="Developer ID Application: Your Name (TEAMID)"
export APPLE_ID="developer@example.com"
export APPLE_TEAM_ID="TEAMID"
export APPLE_APP_PASSWORD="xxxx-xxxx-xxxx-xxxx"
export DO_NOTARIZE=true
./scripts/macos/build-pipeline-macos.sh
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
./scripts/macos/build-pipeline-macos.sh
```

### Personal Wrapper

For frequent use, create a personal wrapper in `/bin/` (gitignored).

See **[templates-for-bin/README.md](templates-for-bin/README.md)** for ready-to-use templates with detailed setup instructions.

**Quick setup:**

```bash
# Copy signing template to your bin directory
cp scripts/templates-for-bin/sign-and-notarize-template.sh bin/sign-my-macos-binaries.sh

# Edit to add your credentials
nano bin/sign-my-macos-binaries.sh

# Run it
./bin/sign-my-macos-binaries.sh
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
./scripts/macos/sign-macos.sh
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

Automated notarization using `xcrun notarytool`. Notarization is required for distribution outside the Mac App Store on macOS 10.15+.

### One-Time Setup

Before using notarization, set up a keychain profile once:

```bash
xcrun notarytool store-credentials "meshagent-notary" \
  --apple-id "developer@example.com" \
  --team-id "TEAMID" \
  --password "xxxx-xxxx-xxxx-xxxx"
```

**Get your credentials:**

1. **Apple ID**: Your Apple Developer account email
2. **Team ID**: Log in to https://developer.apple.com/account → Membership section
3. **App-Specific Password**:
   - Go to https://appleid.apple.com
   - Sign in → Security → App-Specific Passwords
   - Generate a new password named "MeshAgent Notarization"

This stores credentials securely in your macOS keychain. You only need to do this once per machine.

### Running Notarization

Once the keychain profile is set up:

```bash
# Notarize all release binaries (sequential, default)
./scripts/macos/notarize-macos.sh

# Notarize with parallel submissions (faster)
./scripts/macos/notarize-macos.sh --parallel

# Show detailed notarytool output
./scripts/macos/notarize-macos.sh --verbose

# Combine flags
./scripts/macos/notarize-macos.sh --parallel --verbose
```

**What gets notarized:**
- All release binaries in `build/macos/*/meshagent`
- DEBUG binaries are automatically excluded (not needed for distribution)

**Processing modes:**
- **Sequential** (default): Process binaries one at a time, easier to debug
- **Parallel** (`--parallel`): Submit all at once, faster overall

**Output modes:**
- **Clean** (default): Show only script progress and results
- **Verbose** (`--verbose`): Show full notarytool output with status updates

### Notarization Process

The script automatically:

1. Finds all release binaries in `build/macos/`
2. Creates ZIP archives for each binary
3. Submits to Apple's notarization service
4. Waits for notarization to complete (typically 5-10 minutes)
5. Reports success/failure for each binary

After notarization, the pipeline will staple the tickets to the binaries.

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
./scripts/macos/sign-macos.sh

# Notarize (requires keychain profile setup - see Notarization section)
./scripts/macos/notarize-macos.sh

# Or use the complete pipeline
export DO_SIGN=true
export DO_NOTARIZE=true
export DO_STAPLE=true
./scripts/macos/build-pipeline-macos.sh
```

## Environment Variables

### MACOS_SIGN_CERT (Required for signing)

Your Apple Developer ID Application certificate name.

Example:
```bash
export MACOS_SIGN_CERT="Developer ID Application: Peet, Inc. (UW6CS5W75L)"
```

### Notarization Credentials

Notarization uses a keychain profile instead of environment variables. See the **macOS Notarization** section above for setup instructions.

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
