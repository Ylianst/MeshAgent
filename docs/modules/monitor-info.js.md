# monitor-info.js

Comprehensive monitor and display information module providing display enumeration, X11 server detection, workspace management, and window manipulation capabilities. Supports Windows display enumeration with DPI awareness and extensive X11 integration for Linux/FreeBSD.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support with DPI information
- Linux - Full support with extensive X11 integration
- FreeBSD - Full support with X11 integration

**Excluded Platforms:**
- macOS (darwin) - Not implemented

**Exclusion Reasoning:**

This module is implemented for **Windows, Linux, and FreeBSD** only. macOS is not supported because:

1. **Different Display APIs:** macOS uses Quartz/CoreGraphics for display management, completely different from Windows GDI or X11.

2. **No X11 by Default:** Modern macOS doesn't use X11 as the primary display server.

3. **Alternative Tools:** macOS has its own tools for display information (system_profiler, ioreg).

4. **Different Use Case:** The module is heavily focused on X11 session management for Linux remote desktop, which doesn't apply to macOS.

The Windows implementation provides DPI-aware display enumeration. The Linux/FreeBSD implementation provides extensive X11 capabilities including session management, window manipulation, and workspace tracking.

## Functionality

### Purpose

The monitor-info module provides comprehensive display and window management capabilities tailored to remote desktop and KVM needs:

- **Display Enumeration:** List all connected monitors with dimensions and DPI
- **X11 Session Detection:** Find X server and XAUTHORITY for user sessions
- **Desktop Environment Detection:** Identify Unity, Wayland, display managers
- **Window Manipulation:** Remove decorations, set always-on-top, hide icons
- **Workspace Management:** Track virtual desktops, emit workspace change events
- **Multi-Monitor Support:** Handle complex multi-display configurations
- **DPI Awareness:** Detect and report display scaling (Windows 8.1+)

This module is typically used:
- For KVM remote desktop initialization
- To detect available X sessions for display targeting
- To manipulate window properties for borderless overlays
- To track workspace changes for session management
- To enumerate displays for screen capture

### Key Functions/Methods

#### getInfo()

**Purpose:** Enumerates all connected displays with dimensions and properties.

**Platform Implementations:**

**Windows:**
Returns array of display objects:
```javascript
[
    {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 1080,
        dpiX: 96,      // Windows 8.1+ only
        dpiY: 96,      // Windows 8.1+ only
        primary: true  // Primary display flag
    },
    {
        left: 1920,
        top: 0,
        right: 3840,
        bottom: 1080,
        dpiX: 120,
        dpiY: 120,
        primary: false
    }
]
```

**Process (Windows):**
1. Binds to user32.dll `EnumDisplayMonitors` function
2. Enumerates all monitors
3. For Windows 8.1+: Queries SHCore.dll for DPI information
4. Returns array with position and DPI data

**Linux/FreeBSD:**
Returns X11 display information:
```javascript
{
    display: ':0',  // X11 display server
    xauthority: '/run/user/1000/gdm/Xauthority',
    screens: [
        { width: 1920, height: 1080 },
        { width: 2560, height: 1440 }
    ]
}
```

**Process (Linux/FreeBSD):**
1. Detects running X servers
2. Finds XAUTHORITY file path
3. Enumerates X11 screens
4. Returns display and screen information

---

#### getXInfo(consoleuid) - Linux/FreeBSD Only

**Purpose:** Gets XAUTHORITY and DISPLAY environment variables for specific user.

**Parameters:**
- `consoleuid` - User ID (UID) to query

**Return Value:**
Promise resolving to object:
```javascript
{
    XAUTHORITY: '/run/user/1000/gdm/Xauthority',
    DISPLAY: ':0'
}
```

**Process:**
1. Queries loginctl for user sessions
2. Finds active graphical session for UID
3. Reads session environment variables
4. Extracts XAUTHORITY and DISPLAY
5. Returns promise with values

**Use Case:**
Needed to display GUI applications in user's X session when running as different user (e.g., root).

---

#### isUnity() - Linux/FreeBSD Only

**Purpose:** Detects if Unity desktop environment is running.

**Return Value:** Boolean - `true` if Unity detected, `false` otherwise

**Detection Method:**
Checks for running `unity-panel-service` process

**Use Case:**
Unity requires special handling for some graphics operations (see monitor-border.js).

---

#### unDecorateWindow(display, window) - Linux/FreeBSD Only

**Purpose:** Removes window decorations (title bar, borders).

**Parameters:**
- `display` - X11 display connection
- `window` - X11 window ID

**Process:**
Uses Motif window hints to remove decorations:
```c
MotifWmHints {
    flags = MWM_HINTS_DECORATIONS,
    decorations = 0  // No decorations
}
```

**Use Case:**
Creating borderless overlays for remote desktop indicators.

---

#### setWindowSizeHints(display, window, minWidth, minHeight, maxWidth, maxHeight) - Linux/FreeBSD Only

**Purpose:** Sets minimum and maximum window size constraints.

**Use Case:**
Preventing user from resizing critical windows.

---

#### setAlwaysOnTop(display, window) - Linux/FreeBSD Only

**Purpose:** Makes window always stay on top of other windows.

**Process:**
1. Sends _NET_WM_STATE ClientMessage to window manager
2. Sets _NET_WM_STATE_ABOVE property
3. Window floats above normal windows

**Use Case:**
Ensuring remote desktop indicators or notifications remain visible.

---

#### hideWindowIcon(display, window) - Linux/FreeBSD Only

**Purpose:** Hides window's taskbar/dock icon.

**Process:**
Sets _NET_WM_STATE_SKIP_TASKBAR window property

**Use Case:**
Background windows that shouldn't clutter taskbar.

---

#### getCurrentWorkspace(display) - Linux/FreeBSD Only

**Purpose:** Gets current virtual desktop/workspace number.

**Return Value:** Number (0-based workspace index)

**Process:**
1. Queries _NET_CURRENT_DESKTOP root window property
2. Returns workspace number

**Use Case:**
Tracking which virtual desktop user is viewing.

---

### Workspace Change Events - Linux/FreeBSD Only

**Purpose:** Emits events when user switches virtual desktops.

**Event:** `'workspaceChange'`

**Event Data:**
```javascript
{
    workspace: 2  // New workspace number (0-based)
}
```

**Implementation:**
1. Uses DescriptorEvents to monitor X11 connection file descriptor
2. Polls _NET_CURRENT_DESKTOP property
3. Emits event when workspace changes

**Usage:**
```javascript
var monitorInfo = require('monitor-info');

monitorInfo.on('workspaceChange', function(data) {
    console.log('User switched to workspace:', data.workspace);
});
```

---

### Usage

#### Windows Display Enumeration

```javascript
var monitorInfo = require('monitor-info');

var displays = monitorInfo.getInfo();

displays.forEach(function(display, index) {
    console.log('Display', index);
    console.log('  Position:', display.left, display.top);
    console.log('  Size:', (display.right - display.left) + 'x' + (display.bottom - display.top));
    console.log('  DPI:', display.dpiX, 'x', display.dpiY);
    console.log('  Primary:', display.primary);
});
```

#### Linux X11 Session Detection

```javascript
// Get X11 info for user UID 1000
monitorInfo.getXInfo(1000).then(function(xinfo) {
    console.log('Display:', xinfo.DISPLAY);
    console.log('XAuthority:', xinfo.XAUTHORITY);

    // Set environment for spawning GUI applications
    process.env.DISPLAY = xinfo.DISPLAY;
    process.env.XAUTHORITY = xinfo.XAUTHORITY;
});
```

#### Window Manipulation

```javascript
// Assuming you have X11 display and window handles
var display = monitorInfo.openDisplay(':0');
var window = /* window ID */;

// Remove decorations
monitorInfo.unDecorateWindow(display, window);

// Set always on top
monitorInfo.setAlwaysOnTop(display, window);

// Hide from taskbar
monitorInfo.hideWindowIcon(display, window);

// Set size constraints
monitorInfo.setWindowSizeHints(display, window, 800, 600, 1920, 1080);
```

#### Workspace Tracking

```javascript
var monitorInfo = require('monitor-info');

// Get current workspace
var currentWorkspace = monitorInfo.getCurrentWorkspace(display);
console.log('Current workspace:', currentWorkspace);

// Monitor workspace changes
monitorInfo.on('workspaceChange', function(data) {
    console.log('Switched to workspace:', data.workspace);
    // Update UI, move windows, etc.
});
```

#### Unity Detection

```javascript
if (monitorInfo.isUnity()) {
    console.log('Unity desktop detected - using compatibility mode');
    // Use Unity-specific workarounds
} else {
    console.log('Non-Unity desktop - using standard X11');
}
```

---

### Dependencies

#### Node.js Core Modules

- **`child_process`** - Execute system commands
  - Used for process detection, environment reading
  - Platform support: Cross-platform

- **`fs`** - File system operations
  - Reading session files, config files
  - Platform support: Cross-platform

- **`promise`** - Async operations
  - Platform support: Cross-platform

- **`events`** - EventEmitter
  - Workspace change events
  - Platform support: Cross-platform

#### MeshAgent Module Dependencies

**Windows:**
- **`_GenericMarshal`** - Native bindings
  - Binds to user32.dll, SHCore.dll, kernel32.dll

**Linux/FreeBSD:**
- **`_GenericMarshal`** - Native bindings
  - Binds to libX11, libXtst, libXext, libXfixes, libxkbfile

- **`DescriptorEvents`** - File descriptor monitoring
  - Monitors X11 connection for events

- **`user-sessions`** - User and session management
  - Queries loginctl, user info

- **`lib-finder`** (FreeBSD) - Library location
  - Uses ldconfig to find library paths

#### Platform Library Dependencies

**Windows:**
- **user32.dll** - Windows User API
  - Functions: EnumDisplayMonitors
  - Standard Windows component

- **SHCore.dll** - Windows 8.1+ Shell Core
  - Functions: GetDpiForMonitor
  - Available on Windows 8.1 and newer

- **kernel32.dll** - Windows Kernel API
  - Standard Windows component

**Linux/FreeBSD:**
- **libX11.so** - X11 client library
  - Core X11 functions
  - Install: `apt install libx11-6` or `yum install libX11`

- **libXtst.so** - X11 Test extension
  - Input simulation, testing
  - Install: `apt install libxtst6`

- **libXext.so** - X11 extensions
  - Extended X11 functionality
  - Install: `apt install libxext6`

- **libXfixes.so** - X11 Fixes extension
  - Window management enhancements
  - Install: `apt install libxfixes3`

- **libxkbfile.so** - X Keyboard File library
  - Keyboard configuration
  - Install: `apt install libxkbfile1`

#### Dependency Summary

| Platform | Core Deps | MeshAgent Deps | System Libraries |
|----------|-----------|----------------|------------------|
| Windows | child_process, promise, events | _GenericMarshal | user32.dll, SHCore.dll, kernel32.dll |
| Linux/FreeBSD | child_process, fs, promise, events | _GenericMarshal, DescriptorEvents, user-sessions, lib-finder | libX11, libXtst, libXext, libXfixes, libxkbfile |

---

### Technical Notes

**DPI Awareness (Windows):**

Windows 8.1+ introduced per-monitor DPI scaling:
- Each display can have different scaling (96, 120, 144 DPI, etc.)
- Module uses `GetDpiForMonitor` API
- Critical for correct window sizing and positioning
- Fallback to 96 DPI on Windows 7 and earlier

**X11 Server Detection (Linux/FreeBSD):**

Multiple methods to detect X server:
1. Check `DISPLAY` environment variable
2. Scan for Xorg processes
3. Query loginctl for graphical sessions
4. Check common X socket paths (`/tmp/.X11-unix/`)

**XAUTHORITY Discovery:**

XAUTHORITY file locations vary:
- GDM: `/run/user/<uid>/gdm/Xauthority`
- LightDM: `/home/<user>/.Xauthority`
- SDDM: `/tmp/xauth_<random>`

Module checks multiple common locations and queries session manager.

**Motif Window Hints:**

Ancient but still widely supported method for window decoration control:
```c
typedef struct {
    unsigned long flags;
    unsigned long functions;
    unsigned long decorations;
    long input_mode;
    unsigned long status;
} MotifWmHints;
```

Setting `decorations = 0` removes all window decorations.

**EWMH (Extended Window Manager Hints):**

Modern X11 window manager protocol:
- `_NET_WM_STATE` - Window state properties
- `_NET_CURRENT_DESKTOP` - Current workspace
- `_NET_WM_STATE_ABOVE` - Always on top
- `_NET_WM_STATE_SKIP_TASKBAR` - Hide from taskbar

Workspace tracking uses ClientMessage events to window manager.

**Display Manager Detection:**

Multiple display managers supported:
- **GDM/GDM3** - GNOME Display Manager
- **LightDM** - Lightweight Display Manager
- **SDDM** - Simple Desktop Display Manager
- **Xorg** - Direct X server

Each has different session management and XAUTHORITY handling.

**Wayland Detection:**

Checks for Wayland compositor:
- Looks for `wayland-0` socket
- Checks `WAYLAND_DISPLAY` environment variable
- Returns Wayland status for compatibility checks

**Docker Detection:**

Integrated Docker detection helps identify containerized environments where X11 may not be available.

**Raspberry Pi Support:**

Special handling for ARM/Raspberry Pi systems where hardware detection differs.

**Library Path Discovery (FreeBSD):**

FreeBSD requires `ldconfig -r` to find library paths as they're not in standard locations like Linux.

**X11 Event Monitoring:**

Uses file descriptor monitoring to track X11 events:
1. Opens X11 display connection
2. Gets connection file descriptor
3. Uses DescriptorEvents to monitor for readability
4. Processes property change events
5. Emits workspace change events

**Performance Considerations:**

- X11 queries are generally fast (<10ms)
- Workspace polling can be resource-intensive if done too frequently
- Module uses event-driven approach when possible
- DPI queries on Windows are cached

## Summary

The monitor-info.js module is a **comprehensive display and X11 management tool** for Windows, Linux, and FreeBSD, providing display enumeration, X11 session management, window manipulation, and workspace tracking.

**Key features:**
- Multi-monitor enumeration with dimensions
- DPI detection (Windows 8.1+)
- X11 display and XAUTHORITY discovery (Linux/FreeBSD)
- Desktop environment detection (Unity, Wayland)
- Window decoration removal
- Always-on-top window management
- Taskbar icon hiding
- Window size constraints
- Virtual desktop/workspace tracking
- Workspace change events
- Display manager detection (GDM, LightDM, SDDM)
- Motif hints and EWMH support
- Docker and VM detection integration
- Raspberry Pi compatibility

**Platform implementations:**
- **Windows:** GDI display enumeration with DPI awareness
- **Linux/FreeBSD:** Extensive X11 integration with session management

The module is used within MeshAgent for KVM remote desktop functionality, providing essential display information and X11 session management capabilities. It enables targeting specific user sessions, manipulating window properties for overlays, and tracking user workspace changes across all supported platforms.
