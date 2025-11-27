# kvm-helper.js

Helper module for managing KVM (Keyboard/Video/Mouse) remote desktop virtual sessions, primarily on Linux. Provides user session management, virtual session creation with Xvfb, and Wayland configuration management for remote desktop compatibility.

## Platform

**Supported Platforms:**
- Linux - Full support with virtual session creation
- macOS (darwin) - Limited support (user enumeration only)
- Windows (win32) - Limited support (user enumeration only)
- FreeBSD - Limited support (user enumeration only)

**Excluded Platforms:**
- None - Module works on all platforms with varying feature levels

**Exclusion Reasoning:**

This module has no platform exclusions, but platform support varies significantly:

**Full Support (Linux only):**
- Virtual X session creation with Xvfb
- Wayland enable/disable management
- Display manager detection (GDM, GDM3, LXDE, XFCE)
- Virtual UID assignment for spawnable sessions
- Headless desktop environment support

**Limited Support (Other platforms):**
- User enumeration via `user-sessions`
- Allowed UID filtering
- No virtual session creation
- Returns `hasVirtualSessionSupport: false`

The Linux-specific features rely on X Window System components (Xvfb, xvfb-run), systemd's loginctl, and desktop environment managers that don't exist on other platforms. macOS uses Quartz/Cocoa for display management, and Windows uses its own display APIs, neither of which support the virtual session approach used on Linux.

## Functionality

### Purpose

The kvm-helper module provides infrastructure for creating and managing virtual KVM (remote desktop) sessions on Linux systems. It addresses the challenge of providing remote desktop access when no physical display or user session exists:

- **Virtual Session Creation:** Spawns headless X sessions using Xvfb
- **User Session Management:** Enumerates active and spawnable user sessions
- **UID Filtering:** Controls which users can have virtual sessions created
- **Wayland Management:** Disables/enables Wayland for KVM compatibility
- **Display Manager Detection:** Identifies GDM, GDM3, LXDE, XFCE environments

This module is typically used:
- To enable remote desktop when no user is logged in
- For headless servers that need GUI access
- To provide separate virtual desktops for remote sessions
- When Wayland is incompatible with KVM requirements

### Virtual Session Concept

**Traditional Problem:**
Remote desktop requires an active display server (X11/Wayland). On servers or when no user is logged in, no display exists.

**Virtual Session Solution:**
- Uses Xvfb (X Virtual Frame Buffer) to create fake display
- Spawns desktop environment (GNOME, LXDE, XFCE) on virtual display
- Provides full desktop for remote access
- No physical display required

**UID Offset Scheme:**
Virtual sessions are assigned UIDs = real_UID + UID_MAX, ensuring unique identification.

Example: If user UID is 1000 and UID_MAX is 60000:
- Real session UID: 1000
- Virtual session UID: 61000

### Key Functions/Methods

#### hasVirtualSessionSupport - Property

**Purpose:** Indicates if platform supports virtual session creation.

**Value:**
- **Linux with loginctl and xvfb-run:** `true`
- **Other platforms:** `false`

**Usage:**
```javascript
var kvmHelper = require('kvm-helper');

if (kvmHelper.hasVirtualSessionSupport) {
    console.log('Can create virtual sessions');
} else {
    console.log('Virtual sessions not supported');
}
```

---

#### users() / getUsers()

**Purpose:** Enumerates user sessions (both real and virtual).

**Return Value:**
Array of user objects:
```javascript
[
    {
        Username: 'john',
        State: 'active',
        uid: 1000,
        gid: 1000,
        sessionid: 'c1',
        spawnable: false  // Real session, not spawnable
    },
    {
        Username: 'john',
        State: 'spawnable',
        uid: 61000,  // Virtual UID (1000 + 60000)
        gid: 1000,
        sessionid: null,
        spawnable: true  // Virtual session can be spawned
    }
]
```

**Linux Implementation:**
- Queries `loginctl list-users` for active sessions
- Adds virtual session entries with offset UIDs
- Filters based on `allowed` UID list

**Other Platforms:**
- Uses `user-sessions` module
- Only real sessions, no virtual entries

---

#### createVirtualSession(vuid) / spawnVirtualSession(vuid) - Linux Only

**Purpose:** Creates a virtual X session for specified virtual UID.

**Parameters:**
- `vuid` - Virtual UID (real_UID + UID_MAX)

**Process:**

1. **Calculate Real UID:**
   ```javascript
   var realUID = vuid - UID_MAX;
   ```

2. **Detect Available Desktop Environment:**
   - Checks for installed environments: GNOME, LXDE, XFCE
   - Uses `lib-finder` to locate desktop binaries

3. **Spawn Xvfb Session:**
   ```bash
   xvfb-run --auto-servernum <desktop-command>
   ```

   Examples:
   - GNOME: `xvfb-run --auto-servernum gnome-session`
   - LXDE: `xvfb-run --auto-servernum startlxde`
   - XFCE: `xvfb-run --auto-servernum startxfce4`

4. **Set Process UID/GID:**
   - Drops privileges to target user
   - Sets UID and GID to real user values

5. **Return Child Process:**
   - Returns child_process object
   - Caller can monitor for exit

**Requirements:**
- `xvfb-run` binary (from xvfb package)
- Desktop environment installed (gnome-session, startlxde, or startxfce4)
- `loginctl` (systemd) for session management

**Error Handling:**
- Returns `null` if requirements not met
- Throws error if user doesn't exist

---

#### loginUids() - Linux Only

**Purpose:** Gets UIDs that can spawn virtual sessions.

**Return Value:**
Array of virtual UIDs (real_UID + UID_MAX) for users allowed to have virtual sessions.

**Example:**
```javascript
[61000, 61001, 61002]  // Virtual UIDs for users 1000, 1001, 1002
```

---

#### allowed - Property/Array

**Purpose:** List of UIDs allowed to create virtual sessions.

**Configuration:**
Can be set via:
1. Module arguments: `require('kvm-helper')` with allowed UID list
2. Config parameter
3. Defaults to all users if not specified

**Usage:**
```javascript
var kvmHelper = require('kvm-helper');

// Check if UID 1000 is allowed
if (kvmHelper.allowed.includes(1000)) {
    console.log('User 1000 can create virtual sessions');
}
```

---

#### waylandStatus() - Linux Only

**Purpose:** Checks if Wayland is enabled in display manager configuration.

**Return Value:**
- `true` - Wayland enabled
- `false` - Wayland disabled
- `null` - Cannot determine (unsupported display manager)

**Detection:**
Reads GDM configuration:
- GDM3: `/etc/gdm3/custom.conf`
- GDM: `/etc/gdm/custom.conf`

Checks for:
```ini
[daemon]
WaylandEnable=false  # Wayland disabled
```

---

#### disableWayland() - Linux Only

**Purpose:** Disables Wayland in display manager configuration.

**Process:**
1. Detects display manager (GDM, GDM3)
2. Reads configuration file
3. Modifies or adds `WaylandEnable=false` under `[daemon]` section
4. Writes updated configuration

**Use Case:**
Wayland is incompatible with some KVM/VNC implementations. Disabling forces X11 mode.

**Requires:** Root privileges

---

#### enableWayland() - Linux Only

**Purpose:** Enables Wayland in display manager configuration.

**Process:**
1. Reads configuration file
2. Removes `WaylandEnable=false` line or sets to `true`
3. Writes updated configuration

**Requires:** Root privileges

---

#### waylandDM() - Linux Only

**Purpose:** Returns display manager type.

**Return Values:**
- `'gdm3'` - GNOME Display Manager 3
- `'gdm'` - GNOME Display Manager (older)
- `null` - Unknown or unsupported

---

### Usage

#### Check Virtual Session Support

```javascript
var kvmHelper = require('kvm-helper');

if (kvmHelper.hasVirtualSessionSupport) {
    console.log('Platform supports virtual KVM sessions');

    // Get spawnable UIDs
    var spawnableUIDs = kvmHelper.loginUids();
    console.log('Can spawn sessions for UIDs:', spawnableUIDs);
}
```

#### Enumerate Users and Sessions

```javascript
var users = kvmHelper.users();

users.forEach(function(user) {
    console.log('User:', user.Username);
    console.log('UID:', user.uid);
    console.log('State:', user.State);
    console.log('Spawnable:', user.spawnable);
    console.log('---');
});
```

#### Create Virtual Session

```javascript
// Assume user UID 1000, UID_MAX is 60000
var virtualUID = 61000;  // 1000 + 60000

if (kvmHelper.hasVirtualSessionSupport) {
    var session = kvmHelper.createVirtualSession(virtualUID);

    if (session) {
        console.log('Virtual session created, PID:', session.pid);

        session.on('exit', function(code) {
            console.log('Session ended with code:', code);
        });
    } else {
        console.error('Failed to create virtual session');
    }
}
```

#### Manage Wayland Configuration

```javascript
// Check Wayland status
var waylandEnabled = kvmHelper.waylandStatus();
console.log('Wayland enabled:', waylandEnabled);

// Disable Wayland for KVM compatibility
if (waylandEnabled) {
    kvmHelper.disableWayland();
    console.log('Wayland disabled. Restart display manager to apply.');
}

// Re-enable later
kvmHelper.enableWayland();
```

#### Filter Allowed Users

```javascript
// Only allow specific UIDs to create virtual sessions
kvmHelper.allowed = [1000, 1001, 1002];

// Now only these users can spawn virtual sessions
var users = kvmHelper.users();
users.forEach(function(user) {
    if (user.spawnable) {
        console.log('Virtual session available for:', user.Username);
    }
});
```

---

### Dependencies

#### Node.js Core Modules

- **`fs`** - File system operations
  - Reading/writing display manager config files
  - Platform support: Cross-platform

- **`child_process`** - Process spawning
  - Executing xvfb-run, loginctl, desktop environments
  - Platform support: Cross-platform

#### MeshAgent Module Dependencies

- **`user-sessions`** (all platforms)
  - Purpose: User session enumeration
  - Usage: Get active user sessions, UIDs
  - Platform support: Cross-platform

- **`lib-finder`** (Linux only)
  - Purpose: Locate system binaries
  - Locates: `xvfb-run`, `gnome-session`, `startlxde`, `startxfce4`, `loginctl`
  - Platform support: Linux, FreeBSD

#### Platform Binary Dependencies

**Linux:**
- **xvfb-run** - X Virtual Frame Buffer runner
  - Package: `xvfb`
  - Purpose: Creates virtual X displays
  - Required for virtual session support

- **Xvfb** - X Virtual Frame Buffer server
  - Package: `xvfb` or `xorg-server-xvfb`
  - Purpose: Headless X server

- **loginctl** - systemd login manager client
  - Package: `systemd` (standard on modern Linux)
  - Purpose: User session management

- **Desktop Environment** (one required):
  - **gnome-session** - GNOME desktop
  - **startlxde** - LXDE desktop
  - **startxfce4** - XFCE desktop

- **Display Manager** (for Wayland management):
  - **GDM** or **GDM3** - GNOME Display Manager
  - Config: `/etc/gdm/custom.conf` or `/etc/gdm3/custom.conf`

#### Dependency Summary

| Platform | Core Deps | MeshAgent Deps | System Binaries |
|----------|-----------|----------------|-----------------|
| Linux (full) | fs, child_process | user-sessions, lib-finder | xvfb-run, Xvfb, loginctl, desktop environment |
| Linux (limited) | fs, child_process | user-sessions | None |
| Other platforms | - | user-sessions | None |

---

### Technical Notes

**UID Offset Scheme:**

The module uses a clever UID offset to distinguish virtual sessions from real sessions:
```javascript
UID_MAX = 60000  // or system-specific value
Virtual_UID = Real_UID + UID_MAX

Example:
User 'john' has UID 1000
Virtual session UID = 61000
```

This ensures:
- Virtual and real sessions have unique identifiers
- Easy mathematical conversion between real and virtual UIDs
- No conflicts with existing system UIDs

**Xvfb (X Virtual Frame Buffer):**

Xvfb is an X server that performs all graphical operations in memory without displaying to a screen:
- Provides framebuffer for X clients
- No video hardware required
- Perfect for headless servers
- Supports full X11 protocol

**xvfb-run Wrapper:**

The `xvfb-run` script automates Xvfb usage:
- `--auto-servernum`: Automatically finds available display number
- Starts Xvfb
- Sets DISPLAY environment variable
- Runs specified command
- Cleans up on exit

**Desktop Environment Compatibility:**

The module supports multiple desktop environments with automatic detection:
1. **GNOME** - Full-featured, resource-intensive
2. **LXDE** - Lightweight, less resource usage
3. **XFCE** - Balanced between features and performance

Choice depends on system resources and user requirements.

**Wayland vs X11:**

**Wayland:**
- Modern display protocol
- Better security model
- Improved performance
- Incompatible with many VNC/KVM solutions

**X11:**
- Legacy display protocol
- Well-supported by remote desktop tools
- Required for most KVM implementations

The module provides tools to disable Wayland when X11 is needed for KVM compatibility.

**Security Considerations:**

Virtual sessions run with real user privileges (UID/GID):
- Process drops to target user's UID
- User's files and permissions apply
- No privilege escalation
- Secure by design

**Performance Impact:**

Virtual sessions consume resources:
- CPU: Desktop environment overhead
- Memory: ~100-500MB depending on desktop environment
- Disk: Minimal (no persistent data unless saved)

Lighter desktop environments (LXDE) recommended for resource-constrained systems.

## Summary

The kvm-helper.js module is a **Linux-focused KVM session management tool** with limited cross-platform user enumeration. It provides virtual X session creation for headless remote desktop access using Xvfb.

**Key features:**
- Virtual X session creation with Xvfb (Linux only)
- User session enumeration (all platforms)
- UID filtering for allowed users
- Virtual UID offset scheme (real_UID + UID_MAX)
- Wayland enable/disable management (Linux only)
- Display manager detection (GDM, GDM3)
- Desktop environment support (GNOME, LXDE, XFCE)
- Headless server remote desktop capability
- Process privilege dropping for security

**Platform support:**
- **Linux (full):** Virtual session creation, Wayland management, all features
- **Other platforms (limited):** User enumeration only

The module is used within MeshAgent to enable KVM remote desktop functionality on Linux servers without physical displays or active user sessions. It solves the "no display available" problem by creating virtual X sessions on demand, allowing remote administrators to access graphical desktops on headless systems.
