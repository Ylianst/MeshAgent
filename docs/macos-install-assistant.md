# macOS Installation Assistant

## Overview

The MeshAgent Installation Assistant is a native macOS GUI application that provides an interactive, user-friendly installation and upgrade experience for the MeshAgent. It handles admin privilege elevation, path validation, configuration file management, and optional TCC permissions checking.

### Key Features

- **Interactive GUI** - Cocoa-based native interface with dark mode support
- **Two Installation Modes** - Upgrade existing installations or perform new installations
- **Auto-Detection** - Automatically finds existing installations from LaunchDaemon plists
- **Configuration Viewer** - Built-in .msh file viewer to inspect settings
- **Security Hardening** - Comprehensive path validation and input sanitization
- **Progress Tracking** - Real-time progress display during installation
- **TCC Integration** - Optional TCC permissions check after installation

## Launching the Installation Assistant

### Method 1: Keyboard Shortcut (Recommended)

**CMD + Double-click** the MeshAgent.app bundle to launch the Installation Assistant:

```bash
# User triggers via Finder:
# CMD + Double-click MeshAgent.app
#
# This triggers:
# 1. Launch detection via LAUNCHED_FROM_FINDER environment variable
# 2. Modifier key detection (CMD key pressed)
# 3. Elevation prompt (if not already root)
# 4. Installation Assistant window appears
```

### Method 2: Command-Line

Launch directly from terminal:

```bash
sudo ./meshagent --show-install-ui
```

### Method 3: Programmatic

From code or scripts:

```bash
./meshagent --show-install-ui
# Will automatically elevate if not root
```

## Installation Modes

### Upgrade Existing Installation

Used when updating an existing MeshAgent installation:

1. **Auto-Detection**
   - Scans `/Library/LaunchDaemons` for mesh*.plist files
   - Parses ProgramArguments to find installation path
   - Selects newest installation by plist modification time
   - Pre-fills upgrade path field

2. **Path Selection**
   - User can browse to select different installation
   - Validates selected path contains meshagent.db or meshagent.msh
   - Displays current installed version if detected

3. **Settings Preservation**
   - Reads existing `--disableUpdate` setting from LaunchDaemon
   - Reads existing `--disableTccCheck` setting
   - Pre-configures checkboxes to match current settings

4. **Execution**
   - Runs current executable with `--upgrade` flag
   - Uses elevated privileges via AuthorizationExecuteWithPrivileges
   - Preserves existing .msh configuration
   - Updates binary and restarts service

### New Installation

Used for first-time installations or fresh deployments:

1. **Path Selection**
   - Default: `/usr/local/mesh_services/meshagent`
   - User can browse or manually enter path
   - Validates path doesn't already exist (safety check)

2. **Configuration File**
   - User browses for .msh configuration file
   - Can view .msh contents with "View" button
   - Validates file exists and is readable
   - File size limited to 10 MB for safety

3. **Options**
   - **Disable automatic updates** - Adds `--disableUpdate=1` to LaunchDaemon
   - **Disable TCC check at startup** - Adds `--disableTccCheck=1`

4. **Execution**
   - Creates installation directory
   - Copies meshagent binary
   - Copies .msh configuration file
   - Creates LaunchDaemon plist
   - Loads and starts service

## Configuration Viewer

The built-in .msh file viewer allows inspection of configuration before installation:

**Features:**
- Parses key=value format
- Displays in searchable table view
- Alphabetically sorted by key
- Truncates long values (>100 chars) for readability
- Shows MeshServer, MeshID, ServerID, and all other settings

**Limitations:**
- Read-only (cannot edit .msh files)
- 10 MB file size limit
- Text-based display only

## Keyboard Shortcuts

| Shortcut | Action | Description |
|----------|--------|-------------|
| **CMD + Double-click** | Launch Installation Assistant | Opens GUI installer with admin elevation |
| **SHIFT + Double-click** | TCC Permissions Window | Opens TCC permissions checker (see [TCC Permissions](#tcc-permissions-integration)) |
| No modifier | No action | Agent exits without showing UI |

## Configuration Options

### Disable Automatic Updates

**Checkbox:** "Disable automatic updates"

When enabled:
- Adds `--disableUpdate=1` to LaunchDaemon ProgramArguments
- Agent will NOT self-update when server pushes new version
- Useful for testing, development, or controlled environments

Implementation:
```xml
<!-- LaunchDaemon plist excerpt -->
<key>ProgramArguments</key>
<array>
    <string>/path/to/meshagent</string>
    <string>--disableUpdate=1</string>
</array>
```

### Disable TCC Check at Startup

**Checkbox:** "Disable TCC check UI at startup"

When enabled:
- Adds `--disableTccCheck=1` to LaunchDaemon ProgramArguments
- Agent will NOT show TCC permissions window on startup
- TCC window can still be triggered manually (SHIFT+double-click)
- Useful for headless deployments or MDM-managed systems

Implementation:
```xml
<!-- LaunchDaemon plist excerpt -->
<key>ProgramArguments</key>
<array>
    <string>/path/to/meshagent</string>
    <string>--disableTccCheck=1</string>
</array>
```

## Architecture

### Process Flow

```
┌──────────────────────────────────────────────────────────┐
│  User Action: CMD + Double-click MeshAgent.app          │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ↓
┌──────────────────────────────────────────────────────────┐
│  main.c: LAUNCHED_FROM_FINDER + CMD key detection      │
│  - CGEventSourceFlagsState checks kCGEventFlagMaskCommand│
└────────────────────┬─────────────────────────────────────┘
                     │
                     ↓
┌──────────────────────────────────────────────────────────┐
│  Elevation: ensure_running_as_root()                     │
│  - Checks if euid == 0                                   │
│  - If not root: AuthorizationExecuteWithPrivileges       │
│  - Relaunches with --show-install-ui flag              │
│  - Original process exits                               │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ↓
┌──────────────────────────────────────────────────────────┐
│  Elevated Process (now running as root)                 │
│  - Redirects stdout/stderr to /tmp/meshagent-install-ui.log│
│  - Calls show_install_assistant_window()               │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ↓
┌──────────────────────────────────────────────────────────┐
│  Installation Assistant Window (Cocoa UI)                │
│  - Auto-detects existing installations                  │
│  - User selects mode and paths                          │
│  - Validates all inputs                                 │
│  - Executes install/upgrade with progress display      │
└──────────────────────────────────────────────────────────┘
```

### Security Architecture

The Installation Assistant implements multiple layers of security:

1. **Elevation Control**
   - Uses AuthorizationExecuteWithPrivileges (deprecated but functional)
   - Prompts for admin credentials via macOS security dialog
   - Validates authorization before proceeding

2. **Path Validation** (`mac_authorized_install.m:validate_installation_path`)
   - Checks for dangerous shell characters: `; \n \r \` $ | & < > ( ) { } [ ] ' " \`
   - Prevents directory traversal: Rejects paths containing `..`
   - Canonicalizes paths with realpath() to resolve symlinks
   - Warns if path outside typical install locations

3. **Input Sanitization**
   - Path length validation (max 1024 chars)
   - File size limits (.msh viewer: 10 MB max)
   - NULL pointer checks on all strdup() calls
   - Bounds checking on string operations

4. **Memory Safety**
   - ARC (Automatic Reference Counting) for Objective-C objects
   - Weak/strong pattern for block captures
   - NULL checks after all dynamic allocations
   - Proper cleanup on error paths

## Elevation and Authorization

### Authorization Flow

```c
// 1. Check if already root
if (geteuid() == 0) {
    // Already elevated, proceed
    return 0;
}

// 2. Request authorization
OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
                                     kAuthorizationFlagDefaults, &auth);

AuthorizationItem items = {kAuthorizationRightExecute, 0, NULL, 0};
AuthorizationRights rights = {1, &items};

status = AuthorizationCopyRights(auth, &rights, NULL,
                                kAuthorizationFlagDefaults |
                                kAuthorizationFlagInteractionAllowed |
                                kAuthorizationFlagPreAuthorize |
                                kAuthorizationFlagExtendRights,
                                NULL);

// 3. Execute with privileges
char* args[] = {"--show-install-ui", NULL};
status = AuthorizationExecuteWithPrivileges(auth, exePath,
                                           kAuthorizationFlagDefaults,
                                           args, NULL);

// 4. Original process exits, elevated process continues
exit(0);
```

### Timeout Handling

- Authorization dialog timeout: 120 seconds (macOS default)
- User can cancel authorization prompt
- Cancelled authorization returns error, UI does not appear

## TCC Permissions Integration

The Installation Assistant provides integration with the TCC Permissions system through the **SHIFT+double-click** shortcut.

### Accessing TCC Window

**SHIFT + Double-click** the MeshAgent.app bundle to show the TCC Permissions Window:

```bash
# User triggers via Finder:
# SHIFT + Double-click MeshAgent.app
#
# This triggers:
# 1. Launch detection via LAUNCHED_FROM_FINDER
# 2. Modifier key detection (SHIFT key pressed)
# 3. TCC permissions window appears
# 4. No elevation required
```

### TCC Permissions Window Features

The TCC window checks and displays the status of three critical permissions:

1. **Accessibility** - Required for remote desktop keyboard/mouse control
2. **Screen Recording** - Required for screen capture during remote sessions
3. **Full Disk Access** - Required for file access and protected directories

**Window Behavior:**
- Shows green checkmarks for granted permissions
- Shows red X for missing permissions
- "Open System Settings" buttons for each missing permission
- Real-time status updates (1-second polling)
- "Do not remind me again" checkbox (sets `disableTccCheck=1` in database)

See [macos-tcc-permissions.md](macos-tcc-permissions.md) for complete TCC documentation.

### Post-Installation TCC Check

The Installation Assistant includes an optional checkbox to **enable or disable** the TCC check at agent startup:

**"Disable TCC check UI at startup"**
- When **unchecked** (default): Agent will show TCC window on startup if permissions missing
- When **checked**: Agent will NOT show TCC window automatically (but SHIFT+double-click still works)

This setting is stored in the LaunchDaemon plist as `--disableTccCheck=1`.

## Installation Logs

During GUI installation, detailed logging is written to:

**File:** `/tmp/meshagent-install-ui.log`

**Log Format:**
```
[MAIN] [1732661537] MeshAgent launched with --show-install-ui (elevated relaunch)
[MAIN] [1732661537] ===== STDOUT/STDERR NOW REDIRECTED TO LOG FILE =====
[INSTALL-UI] Opening Installation Assistant
[AUTH-INSTALL] Validating installation path: /usr/local/mesh_services/meshagent
[AUTH-INSTALL] Path validation passed
[INSTALL-UI] User selected: New Installation
[INSTALL-UI] Installation completed successfully
```

**Log Prefixes:**
- `[MAIN]` - Main process events
- `[INSTALL-UI]` - UI window events and user actions
- `[AUTH-INSTALL]` - Authorization and installation execution
- `[READ-SETTING]` - Reading existing settings from LaunchDaemon

## Troubleshooting

### Installation Assistant Won't Launch

**Symptom:** CMD+double-click does nothing

**Causes:**
1. Not holding CMD key when double-clicking
2. App not launched from Finder (LAUNCHED_FROM_FINDER env var missing)
3. Authorization denied or cancelled

**Solution:**
- Ensure CMD key is held BEFORE and DURING double-click
- Launch from Finder, not terminal
- Check `/tmp/meshagent-install-ui.log` for errors
- Try command-line: `sudo ./meshagent --show-install-ui`

### "Installation Path Required" Error

**Symptom:** Cannot proceed with new installation

**Causes:**
1. Path field is empty
2. Path is too long (>1023 characters)
3. Path contains invalid characters

**Solution:**
- Enter a valid installation path
- Use default path: `/usr/local/mesh_services/meshagent`
- Avoid special characters in path

### "Invalid Installation Directory" Error (Upgrade Mode)

**Symptom:** Selected upgrade path rejected

**Causes:**
1. Directory doesn't contain meshagent.db or meshagent.msh
2. Selected path is not a directory
3. Path doesn't exist

**Solution:**
- Verify you selected the correct installation directory
- Directory should contain existing meshagent files
- Check `/Library/LaunchDaemons` for mesh*.plist to find current install path

### "File Too Large" Error (.msh Viewer)

**Symptom:** Cannot view .msh file

**Cause:** Configuration file exceeds 10 MB limit

**Solution:**
- This is a safety limit to prevent memory exhaustion
- .msh files should be < 1 KB typically
- File may be corrupted or not a valid .msh file
- You can still use the file for installation without viewing

### Elevation Fails / Authorization Cancelled

**Symptom:** "Failed to elevate privileges" in log

**Causes:**
1. User cancelled authorization dialog
2. Incorrect admin password
3. User account doesn't have admin privileges

**Solution:**
- Re-attempt installation and approve authorization
- Ensure correct admin password
- Use an administrator account
- Alternative: Use command-line `sudo` installation

### Installation Hangs / No Progress

**Symptom:** Progress window shows but nothing happens

**Causes:**
1. Installation process crashed
2. Authorization timeout (120 seconds)
3. Permissions issue writing to install path

**Solution:**
- Check `/tmp/meshagent-install-ui.log` for errors
- Verify disk space available at install path
- Check permissions on parent directory
- Try different installation path

### TCC Window Doesn't Show (SHIFT+double-click)

**Symptom:** SHIFT+double-click does nothing

**Causes:**
1. Not holding SHIFT key properly
2. App not launched from Finder
3. Wrong modifier key (CMD instead of SHIFT)

**Solution:**
- Hold SHIFT key BEFORE and DURING double-click
- Launch from Finder
- Check `/tmp/meshagent-install-ui.log` for clues
- Verify using SHIFT not CMD (CMD opens Installation Assistant)

## Files and Locations

### Source Files

- `meshcore/MacOS/Install_UI/mac_install_window.h` - UI interface definitions
- `meshcore/MacOS/Install_UI/mac_install_window.m` - Main window implementation
- `meshcore/MacOS/Install_UI/mac_authorized_install.h` - Authorization interface
- `meshcore/MacOS/Install_UI/mac_authorized_install.m` - Elevation and execution
- `meshconsole/main.c` - Entry point and keyboard shortcut detection

### Runtime Files

- `/tmp/meshagent-install-ui.log` - Installation log (debugging)
- `/Library/LaunchDaemons/meshagent*.plist` - Service configuration (installed)
- `/usr/local/mesh_services/meshagent/` - Default installation directory
- `~/Downloads/meshagent.msh` - Typical .msh file location

## Related Documentation

- [macOS TCC Permissions System](macos-tcc-permissions.md) - TCC permissions details
- [Main README](../readme.md) - General MeshAgent documentation

## Developer Notes

### Testing the Installation Assistant

```bash
# 1. Build meshagent with Install UI support
make

# 2. Launch GUI (will prompt for elevation)
./meshagent --show-install-ui

# 3. Check logs
tail -f /tmp/meshagent-install-ui.log

# 4. Test keyboard shortcuts (requires .app bundle)
# CMD+double-click  → Installation Assistant
# SHIFT+double-click → TCC Permissions Window
```

### Debugging Tips

1. **Enable verbose logging**: Check log file after every operation
2. **Test both modes**: Verify upgrade and new install paths
3. **Test elevation**: Ensure authorization flow works
4. **Test path validation**: Try paths with special characters
5. **Test .msh viewer**: Try various .msh file sizes and formats

### Future Enhancements

Potential improvements for future versions:

- [ ] Localization support (NSLocalizedString)
- [ ] .msh file format validation in UI
- [ ] Installation progress percentage
- [ ] Rollback capability on failed upgrade
- [ ] Background file I/O for .msh viewer
- [ ] Screenshots in documentation
- [ ] Logging macro standardization (INSTALL_UI_LOG)
