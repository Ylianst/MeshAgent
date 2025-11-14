# linux-dbus.js

Provides JavaScript interface to the D-Bus inter-process communication (IPC) system on Linux. Enables interaction with system services, desktop environments, and applications through D-Bus message passing, including systemd/loginctl integration for session management.

## Platform

**Supported Platforms:**
- Linux - Full support with D-Bus daemon

**Excluded Platforms:**
- **macOS** - Not supported
- **Windows** - Not supported
- **FreeBSD** - Not supported

**Exclusion Reasoning:**

**Line 22:** Module checks for `dbus-send` binary availability

macOS and other platforms are excluded because:

1. **D-Bus Architecture** - The module relies on the D-Bus message bus system, which is the standard IPC mechanism on Linux but not on other platforms. Line 22 checks for `dbus-send` binary, which is part of the Linux D-Bus implementation.

2. **systemd Integration** - Lines throughout the module interact with systemd services (loginctl, systemd-logind) which are Linux-specific. macOS uses launchd as its init system, not systemd.

3. **Desktop Environment Integration** - The module interfaces with Linux desktop environments (GNOME, KDE) via D-Bus. macOS desktop services use different IPC mechanisms.

4. **macOS Uses Different IPC** - macOS has its own IPC systems:
   - **XPC (Cross-Process Communication)** - Native macOS IPC framework
   - **Mach ports** - Low-level kernel IPC
   - **NSDistributedNotificationCenter** - Application-level notifications
   - **Apple Events** - Inter-application messaging

5. **Windows Uses Different IPC** - Windows has:
   - **COM/DCOM** - Component Object Model
   - **Named Pipes** - Inter-process pipes
   - **WM_COPYDATA** - Window message-based IPC
   - **RPC** - Remote Procedure Calls

## Functionality

### Core Purpose

Provides high-level JavaScript interface to Linux D-Bus system for:
- Querying system and session bus services
- Invoking D-Bus methods with type marshaling
- Managing user sessions via systemd-logind
- Interacting with desktop environments
- Process management and service control

### D-Bus Basics

**D-Bus Architecture:**
- **System Bus** - System-wide services (root permissions)
- **Session Bus** - Per-user services (user permissions)
- **Service Names** - Unique identifiers (e.g., `org.freedesktop.login1`)
- **Object Paths** - Hierarchical paths (e.g., `/org/freedesktop/login1`)
- **Interfaces** - Method/property collections (e.g., `org.freedesktop.login1.Manager`)

### API Methods

#### getBusCommand() - Lines 24-56

```javascript
this.getBusCommand = function getBusCommand(bus)
```

**Purpose:** Constructs appropriate dbus-send command based on bus type

**Parameters:**
- `bus` (string): Bus type - `'system'`, `'session'`, or `undefined` (defaults to session)

**Returns:** String with base dbus-send command including bus parameter

**Example:**
```javascript
getBusCommand('system')  // Returns: '/usr/bin/dbus-send --system --print-reply'
getBusCommand('session') // Returns: '/usr/bin/dbus-send --session --print-reply'
```

**Flags Used:**
- `--system` - Connect to system bus
- `--session` - Connect to session bus
- `--print-reply` - Print method call replies

---

#### parseDBusReply(data) - Lines 58-151

```javascript
this.parseDBusReply = function parseDBusReply(data)
```

**Purpose:** Parses dbus-send command output into JavaScript objects

**Input Format:** Raw text output from dbus-send
**Output Format:** JavaScript object with typed values

**Supported D-Bus Types:**
- `string` - Text strings
- `int32`, `uint32` - 32-bit integers
- `int64`, `uint64` - 64-bit integers
- `boolean` - true/false values
- `object path` - D-Bus object paths
- `array` - Lists of values
- `dict entry` - Key-value pairs

**Example Parsing:**
```
Input:
   method return time=1234.567 sender=:1.23 -> destination=:1.45 serial=3 reply_serial=2
      string "Hello"
      int32 42

Output:
{
    result: ["Hello", 42]
}
```

**Complex Type Support:**
- Nested arrays and dictionaries
- Mixed-type arrays
- Dictionary entries with typed keys/values
- Object path references

---

#### exec(bus, target, method, params) - Lines 153-204

```javascript
this.exec = function exec(bus, target, method, params)
```

**Purpose:** Execute D-Bus method call with automatic parameter marshaling

**Parameters:**
- `bus` (string) - Bus type: `'system'` or `'session'`
- `target` (string) - D-Bus service and object path (e.g., `'org.freedesktop.login1 /org/freedesktop/login1'`)
- `method` (string) - Interface and method (e.g., `'org.freedesktop.login1.Manager.ListSessions'`)
- `params` (array) - Method parameters with type annotations

**Returns:** Promise resolving to parsed D-Bus reply

**Parameter Type Annotations:**
```javascript
// String parameter
{ type: 'string', value: 'mystring' }

// Integer parameter
{ type: 'int32', value: 42 }

// Boolean parameter
{ type: 'boolean', value: true }

// Object path parameter
{ type: 'objpath', value: '/org/freedesktop/login1/session/c1' }
```

**Example:**
```javascript
dbus.exec('system',
    'org.freedesktop.login1 /org/freedesktop/login1',
    'org.freedesktop.login1.Manager.GetSession',
    [{ type: 'string', value: 'c1' }]
).then(function(result) {
    console.log('Session object path:', result.result[0]);
});
```

---

#### getUserSessions(bus) - Lines 206-250

```javascript
this.getUserSessions = function getUserSessions(bus)
```

**Purpose:** Retrieve all active user sessions from systemd-logind

**Parameters:**
- `bus` (string) - Typically `'system'` for loginctl access

**Returns:** Promise resolving to array of session objects

**Session Object Structure:**
```javascript
{
    sessionId: "c1",              // Session ID
    uid: 1000,                     // User ID
    username: "john",              // Username
    seatId: "seat0",              // Seat ID
    sessionPath: "/org/.../c1"    // D-Bus object path
}
```

**Implementation:**
1. Calls `org.freedesktop.login1.Manager.ListSessions`
2. Returns array of arrays: `[[sessionId, uid, username, seatId, sessionPath], ...]`
3. Parses into structured objects

**Use Case:** Enumerate logged-in users for session management

---

#### getSessionProperties(bus, sessionPath) - Lines 252-269

```javascript
this.getSessionProperties = function getSessionProperties(bus, sessionPath)
```

**Purpose:** Retrieve all properties for a specific session

**Parameters:**
- `bus` (string) - Typically `'system'`
- `sessionPath` (string) - D-Bus object path (e.g., `'/org/freedesktop/login1/session/c1'`)

**Returns:** Promise resolving to object with session properties

**Available Properties:**
- `Id` - Session ID
- `Name` - Session name
- `User` - User ID and name
- `Active` - Whether session is active
- `State` - Session state (active, online, closing)
- `Type` - Session type (x11, wayland, tty)
- `Display` - Display name (e.g., `:0`)
- `Remote` - Whether session is remote
- `TTY` - TTY device if applicable

**Example:**
```javascript
dbus.getSessionProperties('system', '/org/freedesktop/login1/session/c1')
    .then(function(props) {
        console.log('Session ID:', props.Id);
        console.log('Active:', props.Active);
        console.log('Display:', props.Display);
    });
```

---

#### killSession(bus, sessionId, signal) - Lines 271-293

```javascript
this.killSession = function killSession(bus, sessionId, signal)
```

**Purpose:** Send signal to all processes in a session

**Parameters:**
- `bus` (string) - Typically `'system'`
- `sessionId` (string) - Session ID (e.g., `'c1'`)
- `signal` (string) - Signal name (e.g., `'TERM'`, `'KILL'`)

**Returns:** Promise resolving when signal sent

**Common Signals:**
- `'TERM'` - Graceful termination request
- `'KILL'` - Forced termination
- `'HUP'` - Hang up (restart services)
- `'INT'` - Interrupt (Ctrl+C equivalent)

**Implementation:** Calls `org.freedesktop.login1.Session.Kill` method

**Use Case:** Forcibly terminate user sessions or restart session services

---

#### killUser(bus, uid, signal) - Lines 295-317

```javascript
this.killUser = function killUser(bus, uid, signal)
```

**Purpose:** Send signal to all processes owned by a user

**Parameters:**
- `bus` (string) - Typically `'system'`
- `uid` (number) - User ID
- `signal` (string) - Signal name (e.g., `'TERM'`, `'KILL'`)

**Returns:** Promise resolving when signal sent

**Scope:** Affects all processes across all sessions for the user

**Implementation:** Calls `org.freedesktop.login1.Manager.KillUser` method

**Use Case:** System-wide user logout or forced termination

### Known Usage in Codebase

#### linux-gnome-helpers.js - Multiple Lines

The linux-dbus module is heavily used by linux-gnome-helpers for GNOME desktop integration:

**Session Query (Line 31):**
```javascript
getUserSessions('system').then(function(sessions) {
    // Find active X11/Wayland sessions
});
```

**Desktop Environment Detection:**
- Query session properties to detect GNOME
- Check session type (x11 vs wayland)
- Determine active display

**Use Case:** GNOME-specific functionality like gsettings manipulation requires knowing which sessions are running GNOME desktop

## Dependencies

### Node.js Core Module Dependencies

#### child_process (Line 165)

```javascript
var child = require('child_process').execFile(/* ... */);
```

**Purpose:** Execute dbus-send commands

**Usage:**
- Spawns `dbus-send` process for D-Bus method calls
- Captures stdout/stderr output
- Provides async callback interface

**Type:** Used in `exec()` method for all D-Bus communication

### Platform Binary Dependencies

#### dbus-send (Line 22) - D-Bus Command-Line Tool

**Path:** `/usr/bin/dbus-send`

**Purpose:** Command-line interface to D-Bus message bus

**Availability Check:**
```javascript
// Line 22: Module only exports if dbus-send exists
if (!require('fs').existsSync('/usr/bin/dbus-send')) { return; }
```

**Usage:**
- Send method calls to D-Bus services
- Query object properties
- Print replies in parseable format

**Flags Used:**
- `--system` - Connect to system bus
- `--session` - Connect to session bus
- `--print-reply` - Print method return values
- `--type=method_call` - Specify message type

**Package:** `dbus` (Debian/Ubuntu/Fedora/Arch)

**Installation:**
```bash
# Debian/Ubuntu
sudo apt-get install dbus

# Red Hat/Fedora
sudo yum install dbus

# Arch Linux
sudo pacman -S dbus
```

---

#### D-Bus Daemon (dbus-daemon)

**Purpose:** Message bus daemon for IPC

**Services Required:**
- System bus daemon (runs as root)
- Session bus daemon (per-user)

**Startup:**
- System bus: Started by init system (systemd)
- Session bus: Started automatically on user login

**Status Check:**
```bash
# Check system bus
systemctl status dbus

# Check session bus
ps aux | grep dbus-daemon
```

---

#### systemd-logind (Optional but Common)

**Purpose:** Session management daemon

**D-Bus Services Provided:**
- `org.freedesktop.login1` - Login manager interface

**Required For:**
- `getUserSessions()` method
- `killSession()` method
- `killUser()` method
- Session property queries

**Not Required For:**
- Generic D-Bus method calls via `exec()`
- Custom service interaction

### Dependency Chain

```
linux-dbus.js
├─── child_process (Line 165) - Process execution
│    └─── execFile() - Run dbus-send
├─── /usr/bin/dbus-send (Line 22) - D-Bus CLI tool
│    └─── dbus package
└─── dbus-daemon (Platform service)
     ├─── System bus (dbus.service)
     ├─── Session bus (per-user)
     └─── systemd-logind (Optional)
          └─── org.freedesktop.login1 interface
```

## Technical Notes

### Security Model

**System Bus:**
- Requires root permissions for most operations
- PolicyKit integration for privilege escalation
- Careful permission checking by D-Bus daemon

**Session Bus:**
- User-level permissions
- Can only affect user's own services
- No privilege escalation

**Method Call Security:**
- D-Bus daemon enforces access control policies
- Unauthorized calls return permission denied errors
- PolicyKit can prompt for authentication

### Error Handling

**Common Errors:**
- `Failed to open connection` - D-Bus daemon not running
- `The name ... was not provided` - Service not available
- `No such interface` - Wrong interface name
- `Access denied` - Insufficient permissions

**Module Behavior:**
- Errors passed through promise rejection
- Raw stderr output included in error
- No automatic retry logic

### Performance Considerations

- Each method call spawns new dbus-send process (overhead)
- Parsing text output adds latency
- Not suitable for high-frequency calls
- Consider native D-Bus binding for performance-critical code

### String Parsing Complexity

The `parseDBusReply()` function (Lines 58-151) implements a recursive descent parser for dbus-send output:
- Handles nested structures (arrays of dictionaries, etc.)
- Tracks indentation levels for nesting
- Converts D-Bus types to JavaScript types
- Complex but necessary due to text-based interface

### Limitations

- Text-based interface (not binary D-Bus protocol)
- Process spawn overhead on every call
- Limited signal/property monitoring (method calls only)
- No introspection support documented
- Assumes `/usr/bin/dbus-send` path (not configurable)

## Summary

The linux-dbus.js module provides a JavaScript interface to the Linux D-Bus inter-process communication system, with special focus on systemd-logind session management. It wraps the dbus-send command-line tool to enable D-Bus method calls, property queries, and session control from JavaScript code.

**macOS is excluded** because:
- Requires D-Bus daemon and dbus-send binary (Line 22 checks `/usr/bin/dbus-send`)
- Depends on systemd-logind for session management (Linux-specific)
- D-Bus is the standard Linux IPC mechanism but not native to macOS
- macOS uses different IPC systems (XPC, Mach ports, distributed notifications)
- Desktop environment integration targets Linux desktops (GNOME, KDE)

Alternative IPC on macOS would require platform-specific implementation using Foundation framework (NSDistributedNotificationCenter) or XPC framework.
