# Templates for /bin Directory

These are **template scripts** meant to be copied to your personal `/bin` directory (which is gitignored).

## Purpose

The `/bin` directory is gitignored to keep personal credentials and configuration out of the repository. These templates provide starting points for your personal development scripts.

## Usage

### 1. test-macos-meshagent.sh

Development testing script for building, signing, and deploying meshagent.

**Setup:**
```bash
# Copy to bin directory
cp scripts/templates-for-bin/test-macos-meshagent.sh bin/

# The script is ready to use with default settings
# Customize the configuration section if needed
sudo ./bin/test-macos-meshagent.sh
```

**Key Features:**
- Builds meshagent for specified architecture
- Signs binaries (calls your signing script)
- Deploys to system location
- Manages LaunchDaemon and LaunchAgent
- Optional git pull before building
- Optional plist refresh

**Default Configuration:**
- Deploy path: `/opt/tacticalmesh/meshagent` (edit DEPLOY_PATH to change)
- Architecture: ARM64 (use `--archid 16` for Intel, `--archid universal` for both)
- Both daemon and agent enabled

### 2. sign-and-notarize-macos-template.sh

Complete signing, notarization, and stapling workflow.

**Setup:**
```bash
# Copy to bin directory
cp scripts/templates-for-bin/sign-and-notarize-macos-template.sh bin/

# Edit to add your certificate name
nano bin/sign-and-notarize-macos-template.sh
# Update: CERT="Developer ID Application: Your Name (TEAMID)"

# Set up notarization keychain profile (one-time)
xcrun notarytool store-credentials "meshagent-notary" \
  --apple-id "developer@example.com" \
  --team-id "TEAMID" \
  --password "xxxx-xxxx-xxxx-xxxx"

# Run it
./bin/sign-and-notarize-macos-template.sh
```

**What to Configure:**
- `CERT` - Your Apple Developer ID certificate name
- `DO_SIGN` - Enable/disable code signing (default: true)
- `DO_NOTARIZE` - Enable/disable notarization (default: false)
- `DO_STAPLE` - Enable/disable stapling (default: false)
- `SIGN_ENTITLEMENTS` - Entitlements mode (default: "" for standalone binaries)
  - `""` (empty) - No entitlements (recommended for standalone binaries)
  - `"full"` - Use full entitlements (for app bundles only)
  - Custom path - Use specific entitlements file

**Important for Standalone Binaries:**
The default `SIGN_ENTITLEMENTS=""` (no entitlements) is correct for standalone binaries. This allows the binary to appear in System Settings > Privacy & Security so users can grant Full Disk Access, Screen Recording, and Accessibility permissions. Only use `"full"` entitlements if you're packaging as an app bundle (.app).

**Notarization Setup (one-time):**
Notarization now uses a keychain profile instead of credentials in the script. Set it up once with the command above. This stores your credentials securely in macOS keychain.

## Finding Your Credentials

**Certificate Name:**
```bash
security find-identity -v -p codesigning
```

**Team ID:**
- Log in to https://developer.apple.com/account
- Go to Membership details
- Your Team ID is listed there

**App-Specific Password:**
- Go to https://appleid.apple.com/account/manage
- Sign in with your Apple ID
- Under "Security" → "App-Specific Passwords"
- Generate a new password for "MeshAgent Notarization"

## Why These Are Templates

These scripts contain **placeholder values** and are meant to be customized with your personal:
- Apple Developer credentials
- Certificate names
- Team IDs
- Deployment paths
- Other personal preferences

By keeping them in `/bin` (gitignored), you never accidentally commit your credentials to the repository.

## Version

Current version: **0.0.9**

Both templates are kept in sync with the latest features and improvements.
