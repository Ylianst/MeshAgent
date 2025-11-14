# mac-powerutil.js

macOS power management utility providing system sleep, restart, and shutdown functionality. This simple module wraps native macOS commands for power state control operations.

## Platform

**Supported Platforms:**
- macOS (darwin) - Full support

**Excluded Platforms:**
- Windows (win32) - Not supported
- Linux - Not supported
- FreeBSD - Not supported

**Exclusion Reasoning:**

This module is explicitly designed for **macOS only**. Each method (sleep, restart, shutdown) uses a platform check and throws an error on non-macOS systems with the message: "function() not implemented on this platform".

The exclusion is intentional because:

1. **macOS-Specific Commands:** The module uses macOS-specific tools:
   - `osascript` for AppleScript execution (sleep command)
   - `shutdown` with macOS-specific flags (`-r` for restart, `-h` for halt)

2. **Different Power Management APIs:** Other platforms have different power management mechanisms:
   - **Windows:** Uses `shutdown.exe` with different flags or PowerShell cmdlets
   - **Linux:** Uses `systemctl`, `shutdown`, `poweroff`, or `reboot` commands
   - **FreeBSD:** Uses `shutdown` with BSD-specific syntax

3. **Focused Purpose:** As indicated by the "mac-" prefix in the module name, this utility is specifically designed for macOS power operations and does not attempt to provide cross-platform compatibility.

For cross-platform power management, a different module would be needed that detects the platform and uses appropriate commands for each operating system.

## Functionality

### Purpose

The mac-powerutil module provides simple, synchronous power management operations for macOS systems. It serves as a thin wrapper around system commands for:

- **Putting the system to sleep** using AppleScript
- **Restarting the system** using the shutdown command
- **Shutting down the system** using the shutdown command

This module is typically used:
- In remote management scenarios to control macOS machines
- During maintenance operations requiring system restart
- For power-saving operations in automated workflows
- When implementing remote power control in MeshAgent for macOS hosts

All operations are **synchronous** and block until the command completes (using `waitExit()`), ensuring the power state change is initiated before the function returns.

### Key Functions/Methods

#### sleep() - Lines 21-37

**Purpose:** Puts the macOS system to sleep.

**Process:**
1. Checks `process.platform` to verify running on macOS
2. Spawns `/bin/sh` shell process
3. Executes AppleScript command via `osascript`:
   ```applescript
   osascript -e 'tell application "System Events" to sleep'
   ```
4. Waits synchronously for command completion using `waitExit()`
5. System enters sleep mode (display off, disk spins down, processes suspended)

**Parameters:** None

**Return Value:** None (function completes synchronously before sleep occurs)

**Exceptions:**
- Throws error on non-macOS platforms: `"sleep() not implemented on this platform"`

**Platform Behavior:**
- **macOS:** Full support via AppleScript System Events
- **Other platforms:** Throws exception

**Technical Notes:**
- Uses AppleScript for sleep command rather than `pmset sleepnow` or similar
- Requires appropriate system permissions
- May prompt for admin password if agent not running with sufficient privileges
- Command executes but system sleep may be delayed if inhibitors are active (e.g., active SSH sessions, playing media)

---

#### restart() - Lines 38-54

**Purpose:** Restarts the macOS system immediately.

**Process:**
1. Checks `process.platform` to verify running on macOS
2. Spawns `/bin/sh` shell process
3. Executes shutdown command with restart flag:
   ```bash
   shutdown -r now
   ```
4. Waits synchronously for command completion using `waitExit()`
5. System begins restart sequence immediately

**Parameters:** None

**Return Value:** None (function completes before restart occurs)

**Exceptions:**
- Throws error on non-macOS platforms: `"restart() not implemented on this platform"`
- May fail if insufficient privileges (requires root/sudo)

**Platform Behavior:**
- **macOS:** Full support via shutdown command
- **Other platforms:** Throws exception

**Shutdown Command Flags:**
- `-r` : Restart the system
- `now` : Execute immediately without delay

**Technical Notes:**
- Requires root privileges (sudo) to execute
- If agent not running as root, command will fail with permission error
- No warning or confirmation dialog shown to users
- All running processes are terminated
- Open files are closed gracefully if possible

---

#### shutdown() - Lines 55-71

**Purpose:** Shuts down the macOS system immediately.

**Process:**
1. Checks `process.platform` to verify running on macOS
2. Spawns `/bin/sh` shell process
3. Executes shutdown command with halt flag:
   ```bash
   shutdown -h now
   ```
4. Waits synchronously for command completion using `waitExit()`
5. System begins shutdown sequence and powers off

**Parameters:** None

**Return Value:** None (function completes before shutdown occurs)

**Exceptions:**
- Throws error on non-macOS platforms: `"shutdown() not implemented on this platform"`
- May fail if insufficient privileges (requires root/sudo)

**Platform Behavior:**
- **macOS:** Full support via shutdown command
- **Other platforms:** Throws exception

**Shutdown Command Flags:**
- `-h` : Halt the system (shutdown and power off)
- `now` : Execute immediately without delay

**Technical Notes:**
- Requires root privileges (sudo) to execute
- If agent not running as root, command will fail with permission error
- No warning or confirmation dialog shown to users
- All running processes are terminated
- Open files are closed gracefully if possible
- System powers off completely (not just halt)

---

### Usage

#### Sleep System

```javascript
var powerutil = require('mac-powerutil');

try {
    console.log('Putting system to sleep...');
    powerutil.sleep();
    console.log('Sleep command executed');
} catch (e) {
    console.error('Error:', e);
}
```

#### Restart System

```javascript
var powerutil = require('mac-powerutil');

try {
    console.log('Restarting system...');
    powerutil.restart();
    // This line may not execute as system begins restart
    console.log('Restart initiated');
} catch (e) {
    console.error('Error:', e);
}
```

#### Shutdown System

```javascript
var powerutil = require('mac-powerutil');

try {
    console.log('Shutting down system...');
    powerutil.shutdown();
    // This line may not execute as system begins shutdown
    console.log('Shutdown initiated');
} catch (e) {
    console.error('Error:', e);
}
```

#### Cross-Platform Safe Usage

```javascript
var powerutil;

if (process.platform === 'darwin') {
    powerutil = require('mac-powerutil');
    powerutil.restart();
} else {
    console.log('mac-powerutil only works on macOS');
}
```

---

### Dependencies

#### Node.js Core Modules

- **`child_process`** (lines 27, 44, 61)
  - Purpose: Execute shell commands
  - Usage: `execFile('/bin/sh', ['sh'])` to spawn shell
  - Methods used:
    - `execFile()` - Spawn shell process
    - `stdin.write()` - Send commands to shell
    - `stdout.on('data')` - Capture standard output
    - `stderr.on('data')` - Capture standard error
    - `waitExit()` - Wait synchronously for process completion
  - Platform support: Cross-platform, but commands are macOS-specific

#### MeshAgent Module Dependencies

**None** - This module has no MeshAgent-specific dependencies beyond Node.js core modules.

#### Platform Binary Dependencies

**macOS:**

- **`/bin/sh`** (lines 27, 44, 61)
  - Shell interpreter
  - Standard on all macOS systems
  - Used to execute commands

- **`osascript`** (line 30)
  - AppleScript command-line tool
  - Location: `/usr/bin/osascript` (in PATH)
  - Standard on all macOS systems
  - Used for sleep command via System Events

- **`shutdown`** (lines 47, 64)
  - System shutdown utility
  - Location: `/sbin/shutdown` (in PATH)
  - Standard on all macOS systems
  - Requires root/administrator privileges
  - Flags: `-r` (restart), `-h` (halt)

#### Dependency Summary

| Dependency Type | Module/Binary | Required | Platform-Specific |
|----------------|---------------|----------|-------------------|
| Node.js Core | child_process | Yes | No |
| System Binary | /bin/sh | Yes | macOS only |
| System Binary | osascript | Yes (for sleep) | macOS only |
| System Binary | shutdown | Yes (for restart/shutdown) | macOS only |

---

### Technical Notes

**Synchronous Execution:**

All three methods use `waitExit()` to block until the command completes. This synchronous behavior ensures that:
1. The power command has been initiated before the function returns
2. Any errors from the command are captured before proceeding
3. The calling code can execute cleanup logic after the command succeeds

However, `waitExit()` only waits for the command to complete, not for the actual power state change. The system sleep/restart/shutdown occurs after the function returns.

**Privilege Requirements:**

**sleep():**
- May work without root privileges in some cases
- System may prompt for user authentication via GUI
- Behavior depends on system security settings

**restart() and shutdown():**
- **Require root privileges** (sudo or running as root)
- If agent not running as root, commands will fail with permission denied
- Typical MeshAgent deployment runs with root privileges via LaunchDaemon

**Output Handling:**

All methods capture stdout and stderr:
```javascript
child.stdout.str = '';
child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
child.stderr.str = '';
child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
```

However, the captured output is not returned or logged. This suggests the module is designed for command execution only, not output inspection.

**AppleScript for Sleep:**

The sleep command uses AppleScript rather than direct system calls:
```applescript
tell application "System Events" to sleep
```

This approach:
- Leverages macOS's high-level scripting interface
- May prompt for permissions on first use (Accessibility access)
- More reliable than some alternative methods
- Works within macOS security model (TCC - Transparency, Consent, and Control)

**Immediate Execution:**

Both restart and shutdown use the `now` parameter, causing immediate execution:
- No grace period for users to save work
- No confirmation dialogs
- All running applications are terminated forcefully
- Unsaved work will be lost

This is appropriate for remote management scenarios but dangerous for interactive systems with active users.

**Error Handling:**

The module does minimal error handling:
- Platform check throws error on non-macOS systems
- Command execution errors are not explicitly caught
- If commands fail (e.g., permission denied), child process will have non-zero exit code
- Caller should wrap calls in try-catch for robust error handling

**Alternative Implementations:**

For production use, consider:
- Adding platform-specific implementations for Windows/Linux
- Using `pmset sleepnow` for sleep on newer macOS versions
- Adding optional delay parameters for graceful shutdowns
- Returning command output for debugging
- Explicit error handling and logging
- User notification before power state changes

## Summary

The mac-powerutil.js module is a **macOS-only power management utility** providing synchronous sleep, restart, and shutdown operations for macOS systems. It is not cross-platform and explicitly throws errors when used on non-macOS platforms.

**Key features:**
- Simple, focused API with three methods: `sleep()`, `restart()`, `shutdown()`
- Synchronous execution using `waitExit()` for reliable command completion
- AppleScript integration for sleep command
- Native shutdown command for restart and shutdown operations
- Zero external dependencies beyond Node.js core modules
- Platform check with explicit error on non-macOS systems

**Platform support:**
- **macOS:** Full support (requires root for restart/shutdown)
- **Windows/Linux/FreeBSD:** Not supported (throws exceptions)

**Use cases:**
- Remote management of macOS systems via MeshAgent
- Automated maintenance requiring system restart
- Power-saving automation (sleep during idle periods)
- Emergency shutdown procedures
- Integration with remote administration tools

The module is used within MeshAgent to provide power control capabilities for macOS clients, enabling administrators to remotely sleep, restart, or shutdown managed macOS machines. Its focused, macOS-only design keeps the code simple and maintainable while providing reliable power management functionality.
