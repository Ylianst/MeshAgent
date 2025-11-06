# production-ready-macos-kvm1: macOS Multi-Session KVM with Code Signing & Notarization

**Tag:** `production-readv-macos-kvm1-2025.11.6`
**Commit:** `6aa5bc0cc15386e45d7507e5d6f68ae011b4d207`
**Date:** November 5, 2025
**Tagger:** Peet McKinney <68706879+PeetMcK@users.noreply.github.com>

This release represents a complete production-ready implementation of macOS remote desktop (KVM)
functionality with full code signing, notarization, and automated build infrastructure.

**Development Period:** October 28 - November 5, 2025
**Commits:** 95 commits
**Files Changed:** 40 files (+4,630 additions, -554 deletions)

## MAJOR FEATURES

### 1. REVERSED ARCHITECTURE FOR MACOS KVM
- Redesigned KVM architecture to work within macOS security model
- Main daemon creates listening socket at /tmp/meshagent-kvm.sock
- LaunchAgent monitors /var/run/meshagent via QueueDirectories
- KVM process (-kvm1) CONNECTS to daemon (not spawned by daemon)
- Works around Apple bootstrap namespace restrictions
- Ensures -kvm1 runs in correct user context (LoginWindow or Aqua)
- Replaced process pipe IPC with domain socket communication
- Added code signature verification for socket connections (mac_kvm_auth.c/h)

### 2. MULTI-SESSION KVM SUPPORT
- Fixed critical race condition in multi-viewer KVM sessions
- Resolution message now sent IMMEDIATELY before tile data
- Prevents canvas initialization at wrong size for second viewer
- Fixed message ordering issues via direct KVM_SEND() instead of queue
- Supports multiple simultaneous remote desktop viewers
- Fixed CRC tile state bug for session reconnections

### 3. MACOS CODE SIGNING & NOTARIZATION INFRASTRUCTURE
- Complete automated signing pipeline (scripts/macos/sign-macos.sh)
- Automated notarization with xcrun notarytool (scripts/macos/notarize-macos.sh)
- Notarization ticket stapling support for offline verification
- Signs thin binaries (x86_64, arm64) before universal binary creation
- Proper signature propagation from thin to universal binaries
- Hardened runtime enabled, no entitlements required
- Keychain profile-based credentials (no environment variables)
- Parallel or sequential notarization modes
- Comprehensive error handling and status reporting

### 4. MACOS APP BUNDLE SUPPORT (EXPERIMENTAL - NOT DEPLOYED)
- App bundle creation during build (scripts/macos/create-app-bundle.sh)
- Bundle ID: com.ylianst.meshagent
- Auto-versioned from git commit date (YY.MMDD.HHMM format)
- Deep signing support for app bundles
- Bundle notarization and stapling
- NOTE: Standalone binary is the current and planned deployment path
- App bundle infrastructure built for future TCC GUI visibility exploration
- Background agent mode (LSUIElement=true, no Dock icon)
- Info.plist with proper metadata and permissions

### 5. PERMISSION HANDLING IMPROVEMENTS
- Full Disk Access (FDA) check (non-intrusive, no auto-launch)
- Screen Recording permission prompts
- Accessibility permission prompts
- Keyboard/mouse input at macOS loginwindow enabled
- Added -framework ApplicationServices linker flag for CGEventPost
- Disabled automatic System Settings launch for FDA check

## BUILD SYSTEM IMPROVEMENTS

### 1. ORGANIZED BUILD INFRASTRUCTURE
- Centralized scripts into scripts/{macos,linux,windows}/ directories
- Comprehensive build pipeline (scripts/macos/build-pipeline-macos.sh)
- Template scripts for personal use (scripts/templates-for-bin/)
- Test script with git pull and plist refresh (test-macos-meshagent.sh)
- Build output organized: build/{osname}/{arch}/ directories
- Standardized naming: osx → macos throughout codebase

### 2. BUILD OUTPUTS
- build/macos/universal/meshagent (standalone signed binary - PRIMARY DEPLOYMENT)
- build/macos/universal/DEBUG_meshagent (debug binary)
- build/macos/universal/meshagent.app/ (experimental app bundle - not deployed)
- Proper exclusion of DEBUG binaries from notarization/stapling
- Standalone binary is the production deployment target

### 3. MAKEFILE ENHANCEMENTS
- App bundle creation integrated into universal binary builds
- Automatic version generation from git commit timestamps
- Renamed macos-arm-64 and macos-x86-64 (from osx-*)
- Updated library paths for consistency
- Added bundle signing and notarization hooks

## BUG FIXES

### 1. MULTI-SESSION KVM FIXES
- Fixed message ordering race condition for multi-viewer KVM
- Fixed multi-session tile state bug (CRC reset on reconnect)
- Fixed multi-viewer resolution issue (MNG_KVM_REFRESH handling)
- Fixed infinite loop caused by zero-size frames in OnData
- Added MNG_JUMBO frame handling to OnData callback
- Fixed frame processing to handle variable-size messages

### 2. PERMISSION & INPUT FIXES
- Fixed keyboard/mouse input by removing KVM_AGENT_FD checks
- Enabled keyboard/mouse at loginwindow via CGEventPost
- Removed intrusive System Settings auto-launch for FDA

### 3. MACOS-SPECIFIC FIXES
- Fixed JSON parsing in proxy-helper.js (macos_getProxy)
- Fixed JSON parsing in power-monitor.js (_getBatteryLevel)
- Fixed macOS compilation error in zlib fdopen macro
- Fixed QueueDirectories folder deletion (clear contents vs delete)
- Fixed startup cleanup to preserve /var/run/meshagent directory

### 4. SIGNING/NOTARIZATION FIXES
- Fixed universal binary signature conflicts
- Fixed notarization ZIP structure for successful stapling
- Fixed duplicate binary detection (exclude .app bundle internals)
- Graceful handling of Error 73 for standalone binary stapling
- Fixed stapling to exclude DEBUG binaries
- Replace app bundle binary with signed universal before bundle signing

## CODE QUALITY & CLEANUP

### 1. REMOVED VESTIGIAL CODE
- Removed old -kvm0 handler (replaced by -kvm1 LaunchAgent)
- Removed kvm_relay_feeddata() stub (unused on macOS)
- Removed KVM_Listener_FD variable (unused in reversed architecture)
- Removed deprecated process-spawning code
- Removed all debug logging from troubleshooting phase
- Removed entitlements infrastructure (not needed with hardened runtime)

### 2. DOCUMENTATION IMPROVEMENTS
- Comprehensive README.md in scripts/ directory
- Template documentation in scripts/templates-for-bin/
- REVERSED ARCHITECTURE documentation in mac_kvm.c
- Updated terminology: "slave" → "agent" throughout
- Clarified variable naming (restart = socket reconnect, not process)
- Added header documentation explaining architecture decisions

### 3. CODE ORGANIZATION
- Moved LaunchAgent plists to examples/launchd/mesh_services/
- Added TacticalRMM-compatible plists in examples/launchd/tacticalrmm/
- Updated default plists to match TacticalRMM structure
- Organized templates into dedicated templates-for-bin directory
- Cleaner root directory (moved utilities to scripts/)

## LAUNCHD INTEGRATION

### 1. UPDATED PLIST FILES
- Added Disabled key (set to false) for explicit control
- Added StandardErrorPath and StandardOutPath for logging
- Updated QueueDirectories to /var/run/meshagent
- meshagent.plist: LaunchDaemon for root context
- meshagent-agent.plist: LaunchAgent for user context
- Compatible with both default and TacticalRMM installations

### 2. LOGGING & MONITORING
- Daemon logs: /tmp/meshagent-daemon.log
- Agent logs: /tmp/meshagent-agent.log (was KVMSlave.log)
- Proper log rotation and cleanup
- Directory watching via QueueDirectories trigger mechanism

## CONFIGURATION & DEPLOYMENT

### 1. SOCKET & FILE PATHS
- KVM socket: /tmp/meshagent-kvm.sock (changed from /usr/local)
- Queue directory: /var/run/meshagent
- Session signal: /var/run/meshagent/session-active
- Installation: /usr/local/mesh_services/meshagent (default)
- Alternative: /opt/tacticalmesh (TacticalRMM)

### 2. TIMEOUTS & PERFORMANCE
- KVM socket connection timeout: 10s → 30s
- Frame rate throttling removed (caused artifacting)
- Removed 100% CPU usage in KVM loop
- Race condition fixes for socket initialization
- Proper cleanup of stale KVM session files on startup

## DEVELOPER EXPERIENCE

### 1. SCRIPT TEMPLATES
- sign-and-notarize-macos-template.sh (version 0.0.9)
- test-macos-meshagent.sh (version 0.0.9)
- Sanitized templates with placeholder credentials
- Copy to /bin for personal customization (gitignored)
- Comprehensive setup instructions in scripts/templates-for-bin/README.md

### 2. TESTING & DEBUGGING
- Added startup cleanup for stale session files
- Debug logging infrastructure (disabled by default)
- Comprehensive frame processing debugging available
- Test script with optional git pull and plist refresh
- Clear error messages and status reporting

## PLATFORM CONSISTENCY

### 1. CROSS-PLATFORM IMPROVEMENTS
- Standardized macOS naming (osx → macos everywhere)
- Added .clauderc for Claude Code project
- Updated .gitignore for build artifacts and private files
- Added auto-generated ILibDuktape_Commit.h to .gitignore
- Organized build scripts by platform

### 2. SCRIPT VERSIONING
- All scripts version 0.0.9
- Consistent version tracking across templates
- Version bumps documented in commit history

## SECURITY ENHANCEMENTS

### 1. CODE SIGNATURE VERIFICATION
- Peer verification for socket connections
- SecCode API integration (mac_kvm_auth.c)
- Ensures only legitimate meshagent binaries connect
- Self-code signature comparison mechanism

### 2. HARDENED RUNTIME
- All binaries signed with hardened runtime
- No entitlements required (simplified workflow)
- Developer ID signature for all binaries and bundles
- Notarization for malware scanning

## ARCHITECTURE NOTES

The reversed architecture (daemon listens, -kvm1 connects) is a fundamental
design decision for macOS. Traditional architectures where the daemon spawns
a child process do not work properly due to:

1. Apple's bootstrap namespace restrictions
2. LaunchAgent/LaunchDaemon security model
3. User session context requirements for Screen Recording/Accessibility
4. CGEventPost requirements for loginwindow keyboard/mouse input

This architecture has been proven stable through extensive multi-session
testing and resolves all previous race conditions and permission issues.

## TESTING PERFORMED

- Multi-viewer KVM sessions (2+ simultaneous viewers)
- Universal binary signing and notarization
- App bundle signing, notarization, and stapling (experimental)
- Full Disk Access permission handling
- Screen Recording permission prompts
- Accessibility permission prompts
- Loginwindow keyboard/mouse input
- Socket connection verification and authentication
- Session reconnection and cleanup
- Build pipeline on both x86_64 and arm64 architectures

## DEPLOYMENT READY

This release is production-ready for deployment with:
- Fully automated build, sign, notarize, and staple pipeline
- Stable multi-session remote desktop functionality
- Proper macOS security model integration
- Comprehensive error handling and logging
- Clear documentation for setup and troubleshooting
- Standalone binary deployment (meshagent)

---

**Generated for production milestone**
Development: October 28 - November 5, 2025
Tag: production-ready-macos-kvm1
Baseline: master (add1d7f)
HEAD: 6aa5bc0

Signed-off-by: Peet McKinney <68706879+PeetMcK@users.noreply.github.com>
