# service-host.js

Cross-platform service hosting infrastructure that provides a unified interface for running applications as system services on Windows (Windows Services), Linux (systemd/init), and macOS (launchd). The module detects whether the application is running as a service or in normal mode, handles service lifecycle events, and provides command-line installation/uninstallation capabilities.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via Windows Service Control Manager (SCM)
- Linux - Full support via systemd and init/upstart
- macOS (darwin) - Full support via launchd

**Platform Implementation Status:**

All three major platforms are fully supported with platform-specific implementations:

1. **Windows** - Uses Windows Service APIs via Advapi32.dll and Ole32.dll
2. **Linux** - Detects systemd or init and queries service status via shell commands
3. **macOS** - Uses launchctl to detect LaunchDaemons and LaunchAgents

## Functionality

### Purpose

The service-host module serves as a universal service wrapper that allows JavaScript applications to run as native system services across Windows, Linux, and macOS platforms. It provides:

- Automatic detection of service vs. normal execution mode
- Platform-specific service control handler registration
- Lifecycle event management (start, stop, session changes, power events)
- Command-line service installation and uninstallation
- Session change monitoring on Windows
- SIGTERM signal handling on Unix-like platforms

This module is typically used as the foundation for applications that need to run as background services with proper system integration, such as remote management agents, monitoring tools, or background task processors.

### Architecture

The module exports a constructor function that creates a service host object. When `run()` is called, it:

1. Parses command-line arguments for service management operations (-install, -uninstall, start, stop)
2. Detects the current execution context (service or normal mode)
3. Emits appropriate events ('serviceStart' or 'normalStart')
4. Registers platform-specific handlers for service control signals

### Key Functions with Line References

#### Constructor: serviceHost(serviceName) - Lines 43-316

**Purpose:** Creates a new service host instance with platform-specific initialization.

**Parameters:**
- `serviceName` - String service name or options object with properties:
  - `name` - Service name (required)
  - `servicePath` - Path to service executable (defaults to process.execPath)

**Process:**

**Windows Platform (Lines 53-159):**
- Creates native proxies for Advapi32.dll, Kernel32.dll, and Ole32.dll (lines 55-65)
- Sets up ServiceMain callback to handle service initialization (lines 68-127)
- Registers ServiceControlHandler for receiving control commands (lines 128-158)
- Initializes COM via CoInitializeEx for Windows API compatibility (line 104)
- Creates EventEmitter events: 'serviceStart', 'serviceStop', 'normalStart', 'session', 'powerStateChange' (lines 47-51)

**All Platforms:**
- Validates serviceName parameter (lines 161-165)
- Sets default servicePath to current executable (lines 166-169)

**Example:**
```javascript
var serviceHost = require('service-host');
var host = new serviceHost({
    name: 'MyService',
    servicePath: '/opt/myapp/service'
});
```

---

#### ServiceMain Callback - Lines 71-127 (Windows Only)

**Purpose:** Windows service entry point that executes when the Service Control Manager starts the service.

**Process:**
1. Creates SERVICE_STATUS structure (28 bytes) to track service state (line 75)
2. Initializes service status as SERVICE_STOPPED (lines 87-88)
3. Registers service control handler with RegisterServiceCtrlHandlerExA (line 89)
4. Updates status to SERVICE_START_PENDING (lines 96-97)
5. Updates status to RUNNING with accepted controls (lines 100-102):
   - SERVICE_ACCEPT_STOP
   - SERVICE_ACCEPT_POWEREVENT
   - SERVICE_ACCEPT_SESSIONCHANGE
6. Initializes COM for the service process (line 104)
7. Registers finalizer to set STOPPED state on cleanup (lines 105-124)
8. Emits 'serviceStart' event (line 126)

**SERVICE_STATUS Structure:**
```c
typedef struct _SERVICE_STATUS {
    DWORD dwServiceType;              // Offset 0
    DWORD dwCurrentState;             // Offset 4
    DWORD dwControlsAccepted;         // Offset 8
    DWORD dwWin32ExitCode;            // Offset 12
    DWORD dwServiceSpecificExitCode;  // Offset 16
    DWORD dwCheckPoint;               // Offset 20
    DWORD dwWaitHint;                 // Offset 24
} SERVICE_STATUS;
```

---

#### ServiceControlHandler Callback - Lines 131-158 (Windows Only)

**Purpose:** Handles service control commands from Windows Service Control Manager.

**Parameters:**
- `code` - Control code (STOP, SHUTDOWN, SESSIONCHANGE, POWEREVENT)
- `eventType` - Type of event (for SESSIONCHANGE)
- `eventData` - Event-specific data pointer
- `context` - Context pointer for validation

**Supported Control Codes:**

**SERVICE_CONTROL_SHUTDOWN (0x00000005) / SERVICE_CONTROL_STOP (0x00000001):**
- Lines 138-141
- Emits 'serviceStop' event
- Application should gracefully shut down

**SERVICE_CONTROL_SESSIONCHANGE (0x0000000E):**
- Lines 142-151
- Extracts session ID from eventData (line 143)
- Monitors WTS_SESSION_LOGON and WTS_SESSION_LOGOFF events (lines 146-147)
- Emits 'changed' event on user-sessions module (line 148)

**SERVICE_CONTROL_POWEREVENT:**
- Not explicitly handled but accepted via controlsAccepted flags
- Could be extended for power management

**Process:**
1. Validates context matches current handler (lines 133-135)
2. Processes control code via switch statement (lines 136-154)
3. Updates service status with SetServiceStatus (line 156)

---

#### run() Method - Lines 171-315

**Purpose:** Main entry point that handles command-line arguments and starts service or normal execution.

**Command-Line Argument Handling (Lines 183-235):**

**-install (Lines 187-200):**
- Creates service-manager instance if needed (line 188)
- Calls installService() with service options (line 191)
- Logs success message and exits (lines 199-200)
- Catches and displays installation errors (lines 193-196)

**-uninstall (Lines 202-215):**
- Creates service-manager instance if needed (line 203)
- Calls uninstallService() with service options (line 206)
- Logs success message and exits (lines 214-215)

**start / -d (Lines 217-224) - Windows Only:**
- Starts the service using service-manager (line 221)
- Logs starting message and exits (lines 222-223)

**stop / -s (Lines 225-232) - Windows Only:**
- Stops the service using service-manager (line 229)
- Logs stopping message and exits (lines 230-231)

**Platform-Specific Service Detection:**

**Windows (Lines 237-250):**
1. Creates SERVICE_TABLE_ENTRY structure (line 239)
2. Copies service name pointer (line 240)
3. Copies ServiceMain callback pointer (line 241)
4. Calls StartServiceCtrlDispatcherA (line 242)
5. If dispatcher returns 0, emits 'normalStart' (lines 244-248)
6. If dispatcher succeeds, ServiceMain callback handles 'serviceStart'

**Linux (Lines 252-285):**
1. Determines module name from service options or process path (line 254)
2. Detects init system by checking PID 1 process name (line 255)
3. For unknown platforms, emits 'normalStart' (line 259)
4. For systemd or init:
   - Spawns shell to query service status (line 263)
   - **init:** `service <name> status | awk '{print $4}'` (line 269)
   - **systemd:** `systemctl status <name> | grep 'Main PID:' | awk '{print $3}'` (line 272)
5. Waits for command completion (line 275)
6. Compares service PID with process.pid (line 277)
7. If PIDs match, emits 'serviceStart', otherwise 'normalStart' (lines 279-283)

**macOS (Lines 287-314):**
1. Executes `launchctl list` to get all running services (line 290)
2. Captures output (lines 291-294)
3. Parses output by lines and extracts PIDs (lines 296-303)
4. Builds dictionary of PIDs (line 298-302)
5. Checks if current process.pid is in the list (line 305)
6. If found, emits 'serviceStart' (line 308)
7. Otherwise, emits 'normalStart' (line 312)

---

### Usage Examples

#### Example 1: Basic Service Host

```javascript
var serviceHost = require('service-host');

var svcHost = new serviceHost('MyBackgroundService');

svcHost.on('serviceStart', function()
{
    console.log('Service started successfully');
    // Initialize service components
    // Start background tasks
});

svcHost.on('serviceStop', function()
{
    console.log('Service stopping...');
    // Clean up resources
    // Stop background tasks
    process.exit(0);
});

svcHost.on('normalStart', function()
{
    console.log('Running in normal mode');
    // Run as regular application
});

svcHost.run();
```

#### Example 2: Windows Session Monitoring

```javascript
var serviceHost = require('service-host');

var svcHost = new serviceHost({
    name: 'SessionMonitor',
    servicePath: process.execPath
});

if (process.platform == 'win32')
{
    svcHost.on('session', function(sessionId, eventType)
    {
        console.log('Session change: ' + eventType + ' for session ' + sessionId);
    });
}

svcHost.on('serviceStart', function()
{
    console.log('Session monitoring service started');
});

svcHost.run();
```

#### Example 3: Command-Line Installation

```bash
# Install service
node myservice.js -install

# Uninstall service
node myservice.js -uninstall

# Start service (Windows)
node myservice.js start

# Stop service (Windows)
node myservice.js stop
```

#### Example 4: Unix SIGTERM Handling

```javascript
var serviceHost = require('service-host');

var svcHost = new serviceHost('UnixDaemon');

// On Linux/macOS, SIGTERM is automatically handled
svcHost.on('serviceStop', function()
{
    console.log('Received SIGTERM, shutting down gracefully');
    // Clean up and exit
    setTimeout(function() {
        process.exit(0);
    }, 1000);
});

svcHost.on('serviceStart', function()
{
    console.log('Daemon started');
});

svcHost.run();
```

---

### Dependencies

#### Node.js Core Modules
- `events.EventEmitter` (line 46) - Event handling infrastructure for service lifecycle events

#### MeshAgent Module Dependencies
- **`service-manager`** (line 41)
  - Used for installing, uninstalling, starting, and stopping services
  - Methods: `installService()`, `uninstallService()`, `getService().start()`, `getService().stop()`
  - Required for -install, -uninstall, start, stop command-line operations

- **`user-sessions`** (line 148) - Windows only
  - Receives session change notifications
  - Event: 'changed' - Emitted when user logs on or off

#### Platform-Specific Module Dependencies

**Windows:**
- **`_GenericMarshal`** (line 55)
  - Native FFI (Foreign Function Interface) for calling Windows DLLs
  - Methods: `CreateNativeProxy()`, `CreateVariable()`, `GetGenericGlobalCallback()`, `StashObject()`, `UnstashObject()`

**Linux:**
- **`child_process`** (line 263)
  - Spawns shell commands to query systemd or init service status
  - Method: `execFile('/bin/sh', ['sh'])`

- **`process-manager`** (line 255)
  - Detects init system type
  - Method: `getProcessInfo(1).Name` - Returns 'systemd', 'init', or other

**macOS:**
- **`child_process`** (line 290)
  - Executes launchctl commands to query service status
  - Method: `execFile('/bin/sh', ['sh'])`

#### Windows Native API Dependencies (via _GenericMarshal)

**Advapi32.dll:**
- **StartServiceCtrlDispatcherA** (line 57) - Registers service main function with SCM
- **RegisterServiceCtrlHandlerExA** (line 58) - Registers service control handler
- **SetServiceStatus** (line 59) - Updates service status with SCM

**Kernel32.dll:**
- **GetLastError** (line 61) - Retrieves last Windows error code

**Ole32.dll:**
- **CoInitializeEx** (line 64) - Initializes COM library for service
- **CoUninitialize** (line 65) - Uninitializes COM library on cleanup

#### Platform Binary Dependencies

**Windows:**
- No external binaries required (uses native Windows APIs)

**Linux:**
- **systemctl** - systemd service control (for systemd-based systems)
- **service** - init.d service control (for init-based systems)
- **awk** - Text processing for parsing service output
- **/bin/sh** - Shell for executing commands

**macOS:**
- **launchctl** - launchd service control
- **/bin/sh** - Shell for executing commands

---

## Code Structure

The module is organized into these functional sections:

1. **Lines 1-22:** Constants and enumerations
   - SERVICE_WIN32, SERVICE_STATE, SERVICE_ACCEPT flags
   - SERVICE_CONTROL codes
   - SESSION_CHANGE_TYPE enumeration

2. **Lines 39-42:** Module imports
   - service-manager module

3. **Lines 43-169:** Constructor and Windows initialization
   - EventEmitter setup (lines 46-51)
   - Windows native proxy creation (lines 53-66)
   - ServiceMain callback setup (lines 68-127)
   - ServiceControlHandler callback setup (lines 128-158)
   - Options validation (lines 161-169)

4. **Lines 171-315:** run() method implementation
   - Command-line argument parsing (lines 183-235)
   - Windows service dispatcher (lines 237-250)
   - Linux service detection (lines 252-285)
   - macOS service detection (lines 287-314)

5. **Lines 318-322:** Module exports
   - Constructor export (line 318)
   - Factory method export (lines 319-322)

---

## Technical Notes

### Windows Service Control Flow

The Windows implementation uses a two-callback architecture:

1. **ServiceMain Callback** - Called by SCM when service starts
   - Runs on a dedicated thread (threadDispatch: 1)
   - Registers control handler
   - Updates service status through lifecycle states
   - Emits 'serviceStart' event

2. **ServiceControlHandler Callback** - Called by SCM for control requests
   - Receives control codes (STOP, SHUTDOWN, SESSIONCHANGE)
   - Updates service status after handling control
   - Emits appropriate events ('serviceStop', 'session')

### SERVICE_STATUS State Transitions

```
STOPPED (0x00000001)
    ↓
SERVICE_START_PENDING (0x00000002)
    ↓
RUNNING (0x00000004) ← Normal operation
    ↓
SERVICE_STOP_PENDING (0x00000003)
    ↓
STOPPED (0x00000001)
```

### Unix Signal Handling

On Linux and macOS, the module registers a SIGTERM handler (lines 175-180) that emits 'serviceStop'. This provides a consistent interface across platforms:

- **Windows:** ServiceControlHandler receives SERVICE_CONTROL_STOP
- **Linux/macOS:** SIGTERM signal handler triggers
- **Both:** Application receives 'serviceStop' event

### COM Initialization

Windows services that use COM components must call CoInitializeEx (line 104). The module initializes COM with:
- `pvReserved = 0`
- `dwCoInit = 2` (COINIT_APARTMENTTHREADED)

COM is automatically uninitialized on service cleanup (line 123).

### Linux Init System Detection

The module detects the init system by examining the process name of PID 1 (line 255):
- **systemd** - Modern Linux distributions (Ubuntu 16.04+, Debian 8+, CentOS 7+)
- **init** - Traditional init or upstart (older distributions)
- **Other** - Unknown systems default to 'normalStart'

### macOS launchctl Parsing

The launchctl output format:
```
PID    Status  Label
12345  0       com.example.service
-      0       com.example.disabled
```

The parser (lines 296-303):
1. Splits by newlines
2. Skips header line (i = 1)
3. Splits each line by tabs
4. Stores PIDs (skipping '-' for disabled services)
5. Checks if current PID is in the list

---

## Platform-Specific Analysis

### Windows (win32)

**What Works:**
- Full service lifecycle management via SCM
- ServiceMain and ServiceControlHandler callbacks
- Session change monitoring (logon/logoff events)
- Service status updates (STOPPED, START_PENDING, RUNNING, STOP_PENDING)
- COM initialization for service components
- Administrator privilege detection
- Command-line service installation/uninstallation

**Implementation Details:**
- Uses native Windows APIs via _GenericMarshal
- Thread-dispatched callbacks for asynchronous SCM communication
- Proper resource cleanup with finalizers
- Supports 32-bit and 64-bit Windows

**Limitations:**
- Requires administrative privileges for service installation
- Service name must be unique in SCM database

---

### Linux

**What Works:**
- systemd service detection via `systemctl status`
- init/upstart service detection via `service status`
- PID comparison to determine service mode
- SIGTERM signal handling for graceful shutdown
- Command-line installation (via service-manager)

**Implementation Details:**
- Uses shell commands to query service status
- Parses awk output to extract PID
- Synchronous shell execution with waitExit()
- Automatic init system detection

**Limitations:**
- Requires systemd or init/upstart
- Shell command parsing may vary across distributions
- No built-in session change monitoring (would need D-Bus)

**Supported Distributions:**
- systemd: Ubuntu 16.04+, Debian 8+, CentOS 7+, Fedora 15+, Arch Linux
- init/upstart: Ubuntu 14.04, Debian 7, CentOS 6

---

### macOS (darwin)

**What Works:**
- launchd service detection via `launchctl list`
- PID-based service mode determination
- SIGTERM signal handling for graceful shutdown
- LaunchDaemon and LaunchAgent support (via service-manager)
- Command-line installation (via service-manager)

**Implementation Details:**
- Executes launchctl to enumerate running services
- Parses tab-delimited output
- Checks if process.pid exists in service list
- Synchronous command execution

**Limitations:**
- Simple PID-based detection (may have false positives)
- No session change monitoring
- launchctl output format may vary across macOS versions

**Supported Versions:**
- macOS 10.9+ (Mavericks and later)
- Compatible with both legacy and modern launchctl syntax

---

### Cross-Platform Consistency

**Unified Event Model:**
All platforms emit the same events:
- 'serviceStart' - Application running as service
- 'serviceStop' - Service shutdown requested
- 'normalStart' - Application running in normal mode

**Consistent Command-Line Interface:**
- `-install` - Install service (all platforms)
- `-uninstall` - Uninstall service (all platforms)
- `start` - Start service (Windows only, use `launchctl` or `systemctl` on Unix)
- `stop` - Stop service (Windows only, use `launchctl` or `systemctl` on Unix)

**Service Shutdown:**
- Windows: SERVICE_CONTROL_STOP or SERVICE_CONTROL_SHUTDOWN
- Linux/macOS: SIGTERM signal
- Both result in 'serviceStop' event

---

## Summary

The service-host.js module provides a comprehensive, cross-platform service hosting framework with full support for Windows, Linux, and macOS. It abstracts platform-specific service control mechanisms behind a unified event-driven interface, allowing JavaScript applications to run as native system services with proper lifecycle management.

**Key Capabilities:**
- Automatic service vs. normal mode detection on all platforms
- Platform-specific service control handler registration
- Unified event model for service lifecycle
- Command-line installation and management
- Session change monitoring (Windows)
- Graceful shutdown handling via platform-appropriate signals

**Platform Support:**
- **Windows:** Full SCM integration with native API callbacks
- **Linux:** systemd and init/upstart support with shell-based detection
- **macOS:** launchd integration with launchctl-based detection

The module is production-ready and serves as the foundation for the MeshAgent service infrastructure, enabling the agent to run as a background service across all major desktop operating systems. It properly handles service control requests, session changes, and graceful shutdown scenarios, making it suitable for enterprise deployment.
