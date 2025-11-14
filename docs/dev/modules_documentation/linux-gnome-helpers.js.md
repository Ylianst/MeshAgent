# linux-gnome-helpers.js

Provides GNOME desktop environment integration for Linux systems, enabling programmatic control of GNOME Shell settings through gsettings/dconf. Primarily used for enabling remote desktop access by configuring VNC server settings and screen sharing permissions in GNOME.

## Platform

**Supported Platforms:**
- Linux with GNOME desktop environment

**Excluded Platforms:**
- **macOS** - Not supported
- **Windows** - Not supported
- **Linux without GNOME** - Not supported
- **FreeBSD** - Not supported

**Exclusion Reasoning:**

**Lines 30-76:** Module checks for GNOME sessions and gsettings availability

macOS and other platforms are excluded because:

1. **GNOME Desktop Environment** - The module is specifically designed for GNOME Shell, the desktop environment used by Fedora, Ubuntu (with GNOME variant), Debian GNOME edition, and others. Lines 30-76 explicitly check for active GNOME sessions.

2. **gsettings/dconf Backend** - Lines throughout use `gsettings` command to read/write GNOME configuration stored in dconf database. This is GNOME-specific:
   - macOS uses `.plist` files and `defaults` command
   - Windows uses Registry
   - KDE uses KConfig files
   - Other desktops have their own config systems

3. **GNOME Shell Architecture** - The module interacts with GNOME-specific schemas:
   - `org.gnome.desktop.remote-desktop` (Lines 93-115)
   - `org.gnome.Vino` (Lines 135-141)
   - These schemas only exist in GNOME installations

4. **D-Bus Session Detection** - Lines 30-44 use linux-dbus module to detect GNOME sessions via systemd-logind, which is Linux-specific.

5. **macOS Alternatives** - macOS has built-in screen sharing with different APIs:
   - System Preferences → Sharing → Screen Sharing
   - Configured via `com.apple.screensharing` preferences
   - Uses Apple Remote Desktop (ARD) protocol, not VNC

## Functionality

### Core Purpose

Automates GNOME desktop configuration for remote access scenarios, specifically:
- Detecting active GNOME sessions
- Enabling GNOME's built-in VNC server (via remote-desktop service or Vino)
- Configuring authentication and encryption settings
- Allowing remote desktop connections without manual user configuration

### GNOME Session Detection (Lines 30-76)

**Multi-Step Detection Process:**

1. **Query Active Sessions** (Line 31):
   ```javascript
   require('linux-dbus').getUserSessions('system')
   ```
   - Uses D-Bus to get all logged-in user sessions from systemd-logind

2. **Filter for Graphical Sessions** (Lines 34-43):
   - Checks session type is `'x11'` or `'wayland'`
   - Skips TTY-only sessions

3. **Verify GNOME** (Lines 44-54):
   - Checks for `gnome-shell` process
   - Verifies process is owned by session user
   - Confirms GNOME Shell is actually running

4. **Detect gsettings Availability** (Lines 56-73):
   - Tests if `gsettings` command exists
   - Verifies dconf database is accessible
   - Ensures configuration changes are possible

**Result:** Returns array of GNOME session objects with environment info

**Session Object Structure:**
```javascript
{
    user: "john",                    // Username
    uid: 1000,                        // User ID
    sessionId: "c1",                 // systemd session ID
    display: ":0",                   // X11/Wayland display
    xauthority: "/home/john/.Xauthority",  // X11 auth file
    dbus_session: "unix:path=/run/user/1000/bus"  // Session bus address
}
```

### Remote Desktop Configuration

#### enableGnomeRemoteDesktop(session) - Lines 93-115

```javascript
this.enableGnomeRemoteDesktop = function enableGnomeRemoteDesktop(session)
```

**Purpose:** Enable GNOME's built-in remote-desktop service (GNOME 3.30+)

**GNOME Schema:** `org.gnome.desktop.remote-desktop.rdp`

**Settings Configured:**

1. **Enable RDP** (Line 101):
   ```javascript
   gsettings set org.gnome.desktop.remote-desktop.rdp enable true
   ```

2. **View-Only Mode** (Line 104):
   ```javascript
   gsettings set org.gnome.desktop.remote-desktop.rdp view-only false
   ```
   - Allows remote control, not just viewing

3. **TLS Certificate** (Line 110):
   ```javascript
   gsettings set org.gnome.desktop.remote-desktop.rdp tls-cert '/path/to/cert.pem'
   ```
   - Sets path to TLS certificate for encrypted connections

4. **TLS Private Key** (Line 113):
   ```javascript
   gsettings set org.gnome.desktop.remote-desktop.rdp tls-key '/path/to/key.pem'
   ```

**Requirements:**
- GNOME 3.30 or newer
- gnome-remote-desktop package installed
- Certificates generated (typically via `openssl`)

**Modern Approach:** This is the current recommended method for GNOME remote desktop

---

#### disableGnomeRemoteDesktop(session) - Lines 117-133

```javascript
this.disableGnomeRemoteDesktop = function disableGnomeRemoteDesktop(session)
```

**Purpose:** Disable GNOME remote-desktop service

**Implementation:**
1. Sets `org.gnome.desktop.remote-desktop.rdp.enable` to `false`
2. Returns promise resolving when disabled

**Use Case:** Clean up remote access after session ends

---

#### enableVino(session, authType) - Lines 135-141

```javascript
this.enableVino = function enableVino(session, authType)
```

**Purpose:** Enable legacy Vino VNC server (GNOME 3.28 and earlier)

**GNOME Schema:** `org.gnome.Vino`

**Parameters:**
- `session` - GNOME session object from detection
- `authType` (optional) - Authentication type (defaults to none)

**Settings Configured:**

1. **Prompt Enabled** (Line 139):
   ```javascript
   gsettings set org.gnome.Vino prompt-enabled false
   ```
   - Disables user confirmation prompt for connections
   - Allows unattended remote access

2. **Encryption Required** (Line 139):
   ```javascript
   gsettings set org.gnome.Vino require-encryption false
   ```
   - Allows unencrypted VNC connections
   - Required for standard VNC clients

**Legacy System:** Vino is deprecated in favor of gnome-remote-desktop but still used in older GNOME versions

---

#### disableVino(session) - Lines 143-159

```javascript
this.disableVino = function disableVino(session)
```

**Purpose:** Disable Vino VNC server

**Implementation:**
1. Re-enables user prompt: `prompt-enabled true`
2. Re-enables encryption requirement: `require-encryption true`
3. Returns promise resolving when disabled

**Security Note:** Restores more secure default settings

### gsettings Execution (Lines 161-179)

**Helper Function:** `_gsettings(session, args)`

**Purpose:** Execute gsettings command with proper environment

**Environment Variables Set:**
- `DISPLAY` - X11/Wayland display identifier
- `XAUTHORITY` - X11 authentication file path
- `DBUS_SESSION_BUS_ADDRESS` - D-Bus session bus socket
- `HOME` - User home directory (derived from username)

**Why Environment Matters:**
- gsettings needs to connect to user's session bus
- dconf database is per-user
- Without proper environment, gsettings writes to wrong database or fails

**Command Construction:**
```javascript
// Example: Set remote desktop enabled
env DISPLAY=:0 \
    XAUTHORITY=/home/john/.Xauthority \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
    HOME=/home/john \
    gsettings set org.gnome.desktop.remote-desktop.rdp enable true
```

### Known Usage in Codebase

**Purpose in MeshAgent Context:**

The module enables remote desktop access for remote management scenarios:

1. **Automated Setup** - Remote admin needs desktop access without physical presence
2. **No User Interaction** - Enables VNC without user accepting prompts
3. **Security Bypass** - Disables encryption requirements for compatibility
4. **Legacy Support** - Handles both modern (remote-desktop) and legacy (Vino) GNOME versions

**Typical Usage Pattern:**
```javascript
var gnome = require('linux-gnome-helpers');

// Detect GNOME sessions
gnome.getGnomeSessions().then(function(sessions) {
    if (sessions.length > 0) {
        var session = sessions[0];

        // Try modern remote-desktop first
        gnome.enableGnomeRemoteDesktop(session).catch(function() {
            // Fall back to legacy Vino
            gnome.enableVino(session);
        });
    }
});
```

## Dependencies

### MeshAgent Module Dependencies

#### linux-dbus (Lines 30-31, 44)

```javascript
var dbus = require('linux-dbus');
```

**Purpose:** Query systemd-logind for active user sessions

**Methods Used:**
- `getUserSessions('system')` (Line 31) - List all logged-in users
  - Returns session ID, UID, username, seat, session path
  - Required for detecting which users are running GNOME

**Dependency Chain:**
```
linux-gnome-helpers.js
└─── linux-dbus.js (Line 30)
     └─── /usr/bin/dbus-send
          └─── systemd-logind (org.freedesktop.login1)
```

**Why Critical:** Without D-Bus session detection, module cannot find GNOME sessions to configure

### Node.js Core Module Dependencies

#### child_process (Lines 44, 56, 165)

```javascript
var child = require('child_process').execFile(/* ... */);
```

**Purpose:** Execute system commands with proper error handling

**Commands Executed:**
1. **Process Check** (Line 44):
   ```javascript
   execFile('/bin/ps', ['ax'], ...)
   ```
   - Lists all processes to find gnome-shell
   - Verifies GNOME is actually running

2. **gsettings Test** (Line 56):
   ```javascript
   execFile('/usr/bin/gsettings', ['list-schemas'], ...)
   ```
   - Tests if gsettings is available
   - Verifies dconf database is accessible

3. **gsettings Commands** (Line 165):
   ```javascript
   execFile('/usr/bin/gsettings', ['set', schema, key, value], ...)
   ```
   - Reads/writes GNOME configuration
   - All remote desktop settings changes

### Platform Binary Dependencies

#### /usr/bin/gsettings (Lines 56, 165) - GNOME Settings Tool

**Purpose:** Command-line interface to dconf/GSettings

**Package:** `libglib2.0-bin` (Debian/Ubuntu), `glib2` (Red Hat/Fedora)

**Installation:**
```bash
# Debian/Ubuntu
sudo apt-get install libglib2.0-bin

# Red Hat/Fedora
sudo yum install glib2

# Arch Linux
sudo pacman -S glib2
```

**Commands Used:**
- `gsettings list-schemas` - List available configuration schemas
- `gsettings get <schema> <key>` - Read setting value
- `gsettings set <schema> <key> <value>` - Write setting value

**Schemas Required:**
- `org.gnome.desktop.remote-desktop.rdp` - Modern remote desktop
- `org.gnome.Vino` - Legacy VNC server

---

#### /bin/ps (Line 44) - Process Listing

**Purpose:** List running processes to detect gnome-shell

**Usage:**
```javascript
execFile('/bin/ps', ['ax'], ...)
```
- `ax` flags: All processes, even without controlling terminal

**Output Parsed:** Searches for lines containing `gnome-shell`

**Package:** `procps` (Debian/Ubuntu), `procps-ng` (Red Hat/Fedora)

---

#### gnome-shell (Process Check)

**Purpose:** GNOME desktop environment shell

**Detection:** Line 44 searches process list for `gnome-shell` binary

**Package:** `gnome-shell` (all distributions)

**Required:** Must be running for GNOME session to exist

---

#### dconf (Backend Database)

**Purpose:** Low-level configuration system for GNOME

**Relationship:** gsettings is frontend, dconf is backend storage

**Database Location:** `/run/user/<UID>/dconf/user` or `~/.config/dconf/user`

**Package:** `dconf` (Debian/Ubuntu/Fedora/Arch)

---

#### gnome-remote-desktop (Optional) - Modern VNC/RDP Server

**Purpose:** GNOME's built-in remote desktop service (GNOME 3.30+)

**Schema:** `org.gnome.desktop.remote-desktop.rdp`

**Required For:** `enableGnomeRemoteDesktop()` method

**Package:** `gnome-remote-desktop`

**Not Required For:** Legacy Vino support

---

#### vino (Optional) - Legacy VNC Server

**Purpose:** Legacy VNC server for GNOME 3.28 and earlier

**Schema:** `org.gnome.Vino`

**Required For:** `enableVino()` method

**Package:** `vino`

**Deprecated:** Replaced by gnome-remote-desktop in GNOME 3.30+

### Dependency Chain Summary

```
linux-gnome-helpers.js
├─── linux-dbus (Line 30) - Session detection
│    └─── /usr/bin/dbus-send
│         └─── systemd-logind
├─── child_process (Lines 44, 56, 165) - Command execution
│    └─── Node.js core
├─── /bin/ps (Line 44) - Process listing
│    └─── procps package
├─── /usr/bin/gsettings (Lines 56, 165) - GNOME config
│    └─── dconf (Backend database)
├─── gnome-shell (Process detection)
│    └─── GNOME desktop environment
├─── gnome-remote-desktop (Optional)
│    └─── Modern remote desktop service
└─── vino (Optional)
     └─── Legacy VNC server
```

## Technical Notes

### GNOME Version Differences

**GNOME 3.30+ (Modern):**
- Uses `gnome-remote-desktop` service
- Schema: `org.gnome.desktop.remote-desktop.rdp`
- Supports both VNC and RDP protocols
- Better integration with Wayland
- Preferred method

**GNOME 3.28 and Earlier (Legacy):**
- Uses `vino` VNC server
- Schema: `org.gnome.Vino`
- VNC only
- X11 focused
- Deprecated but still widely deployed

**Compatibility Strategy:** Module provides both methods, allowing fallback to legacy Vino if modern remote-desktop fails

### Security Implications

**Settings That Reduce Security:**

1. **Disabled Encryption** (`require-encryption false`):
   - VNC traffic sent in cleartext
   - Vulnerable to network sniffing
   - Required for standard VNC clients

2. **Disabled User Prompts** (`prompt-enabled false`):
   - Users not notified of connections
   - Silent remote access possible
   - Bypasses user consent

3. **Unattended Access**:
   - No physical user approval needed
   - Appropriate for server management
   - Inappropriate for desktop users

**Use Case Justification:** These settings are appropriate for:
- Remote server administration
- Headless systems with GNOME
- Automated management scenarios
- Systems with other security controls (VPN, firewall)

**Inappropriate For:**
- Desktop user machines
- Systems with sensitive data
- Public networks
- Compliance-sensitive environments

### Environment Variable Handling

**Critical Environment Setup (Lines 165-172):**

gsettings must run with the target user's environment:
- `DISPLAY` - Identifies which display/session to configure
- `XAUTHORITY` - Allows X11 access to verify display
- `DBUS_SESSION_BUS_ADDRESS` - Connects to user's dconf daemon
- `HOME` - Locates user's config directory

**Without Proper Environment:**
- gsettings may write to wrong user's config
- Commands may fail with permission errors
- Changes may not persist or affect correct session

### Promise-Based API

All async operations return Promises:
- `getGnomeSessions()` - Resolves to session array
- `enableGnomeRemoteDesktop()` - Resolves when enabled
- `disableGnomeRemoteDesktop()` - Resolves when disabled
- `enableVino()` - Resolves when enabled
- `disableVino()` - Resolves when disabled

**Error Handling:** Rejections include stderr output from failed commands

### Wayland Support

Module supports both X11 and Wayland sessions:
- Line 38: Checks for `session.Type == 'x11'` OR `session.Type == 'wayland'`
- gnome-remote-desktop works with both
- Vino primarily X11-focused but may work via XWayland

### Limitations

- **GNOME Only** - Won't work with KDE, XFCE, MATE, etc.
- **Assumes Paths** - Hardcoded `/usr/bin/gsettings`, `/bin/ps`
- **No Introspection** - Doesn't verify schema keys exist before setting
- **No Rollback** - Failed configuration changes not automatically reverted
- **Single User Focus** - Configures first GNOME session found

## Summary

The linux-gnome-helpers.js module provides programmatic control over GNOME desktop remote access settings, enabling automated configuration of VNC/RDP servers for remote management scenarios. It handles both modern gnome-remote-desktop and legacy Vino systems, with session detection via systemd-logind and configuration via gsettings/dconf.

**macOS is excluded** because:
- Requires GNOME desktop environment (Lines 30-76 detect GNOME sessions)
- Depends on gsettings/dconf configuration system (Lines 56, 165)
- Uses linux-dbus and systemd-logind for session detection (Line 30-31)
- Interacts with GNOME-specific schemas (org.gnome.desktop.remote-desktop, org.gnome.Vino)
- macOS uses different desktop architecture (Aqua/Cocoa) with different remote access APIs

Alternative screen sharing on macOS would require using System Preferences APIs, `com.apple.screensharing` preferences, and Apple Remote Desktop protocol integration.
