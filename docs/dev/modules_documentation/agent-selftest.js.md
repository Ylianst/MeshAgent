# agent-selftest.js

Comprehensive diagnostic and testing tool for MeshAgent that performs automated validation of all major agent functionality including WebRTC, terminal access, KVM remote desktop, file transfers, and service management. This is a development/debugging tool used during testing and troubleshooting, not a runtime component of the MeshAgent software.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support for all test functions
- Linux - Full support with X11 detection for GUI features
- FreeBSD - Full support with limitations (CPU info test marked N/A)

**Excluded Platforms:**
- **macOS (darwin)** - Not supported

**Exclusion Reasoning:**

macOS is explicitly excluded from this testing module for several technical reasons:

1. **Dialog Box Testing Skipped** - The `testDialogBox_UTF8()` function (line 1182-1189) uses a switch statement where macOS falls to the default case and immediately skips the test. Linux/FreeBSD use zenity or kdialog for dialog boxes, which don't exist on macOS. Supporting macOS would require implementing native Cocoa/AppKit dialog APIs.

2. **Platform-Specific APIs Not Implemented** - Many tests require platform-specific functionality that hasn't been implemented for macOS:
   - X11 detection logic (used for KVM/terminal consent) doesn't apply to macOS which uses Quartz/Cocoa
   - Service management uses systemd (Linux) or Windows Services, not launchd (macOS)
   - Core dump mechanisms differ significantly between platforms

3. **Intel AMT/LMS Not Applicable** - Mac hardware doesn't support Intel Active Management Technology (AMT), making the LMS (Local Management Service) tests irrelevant.

4. **Development Tool, Not Runtime Requirement** - This is a diagnostic tool for development and troubleshooting. The MeshAgent can function perfectly on macOS without this testing infrastructure.

5. **Limited macOS-Specific Implementation** - While basic tests like `coreInfo()`, `testConsoleHelp()`, and `testTunnel()` would theoretically work on macOS, the platform-specific features (KVM with macOS display capture, launchd service management, macOS crash reporting) have not been implemented.

## Functionality

### Purpose

The agent-selftest module serves as a comprehensive quality assurance and diagnostic tool for MeshAgent deployments. It validates that all major features are functioning correctly by:

- Testing connectivity and information gathering
- Validating remote access features (terminal, KVM)
- Verifying file transfer capabilities
- Testing service management and crash recovery
- Checking platform-specific features (AMT, dialogs)

This module is typically used:
- During development to validate changes
- After installation to verify proper setup
- During troubleshooting to identify failing components
- In CI/CD pipelines for automated testing

### Test Execution Flow

When invoked, the module executes tests in the following sequence:

1. `coreInfo()` - Gather and validate agent information
2. `testLMS()` - Test Intel AMT/LMS (if AMT hardware detected)
3. `testConsoleHelp()` - Validate console command system
4. `testCPUInfo()` - Test CPU information gathering
5. `WebRTC_Test()` - Validate WebRTC data channels
6. `testDialogBox_UTF8()` - Test international character rendering in dialogs
7. `testTunnel()` - Verify tunnel creation capability
8. `testTerminal()` - Test terminal/shell access
9. `testKVM()` - Test remote desktop (KVM) functionality
10. `testFileUpload()` - Validate file upload with CRC verification
11. `testFileDownload()` - Validate file download with CRC verification
12. `testCoreDump()` - Test core restart without crashing
13. `testServiceRestart()` - Test service restart capability
14. `completed()` - Cleanup and restore agent state

### Key Test Functions

#### coreInfo() - Lines 537-663

**Purpose:** Collects and validates agent information including core details, SMBIOS data, network info, and sessions.

**Process:**
- Emits 'Connected' event with parameter 3 to trigger info gathering
- Listens for responses: `netinfo`, `sessions`, `coreinfo`, `smbios`
- Detects Intel AMT support from SMBIOS tables
- Identifies MicroLMS connection status
- 10-second timeout for receiving all information

**Platform Behavior:**
- All platforms supported
- AMT detection only relevant for Intel-based Windows/Linux systems

---

#### testLMS() - Lines 463-535

**Purpose:** Tests connectivity to Intel AMT Local Management Service on port 16992.

**Process:**
- Only runs if AMT support detected in SMBIOS
- Tests both internal MicroLMS and external LMS installations
- Makes HTTP GET request to `http://127.0.0.1:16992/`
- Validates response indicates LMS is running

**Platform Behavior:**
- Only relevant on Intel AMT-capable hardware
- Mac hardware doesn't support Intel AMT - test would skip

---

#### testConsoleHelp() - Lines 1163-1177

**Purpose:** Validates basic console command functionality.

**Process:**
- Executes `help` command via agent console
- Waits for response with 5-second timeout
- Validates command execution system is working

**Platform Behavior:**
- All platforms supported
- Tests fundamental command infrastructure

---

#### testCPUInfo() - Lines 950-980

**Purpose:** Tests CPU information gathering and JSON parsing.

**Process:**
- Executes `cpuinfo` command
- Parses response as JSON
- Validates structure

**Platform Behavior:**
- Marked N/A on FreeBSD (line 953)
- Supported on Windows, Linux, and theoretically macOS

---

#### WebRTC_Test() - Lines 332-361

**Purpose:** Tests WebRTC functionality used for remote desktop data channels.

**Process:**
- Creates WebRTC factory and two connections (server and client)
- Generates offer/counter-offer exchange
- Creates data channel named 'Test Data Channel'
- Transfers 6,665,535 bytes (6.6 MB) to validate functionality
- Confirms data received correctly

**Dependencies:**
- `ILibWebRTC` module (createNewFactory, createConnection)

**Platform Behavior:**
- All platforms with WebRTC support
- Tests critical functionality for remote desktop features

---

#### testDialogBox_UTF8() - Lines 1179-1212

**Purpose:** Tests dialog box rendering with UTF-8 international characters (Chinese).

**Process:**
```javascript
switch(process.platform) {
    default:
        ret._res();  // macOS falls here - test skipped
        break;
    case 'linux':
    case 'freebsd':
        // Test with zenity/kdialog
        var r = require('message-box').create(
            '示例標題 (Example Title)',
            '示例標題 (Example Caption)',
            10,
            ['按鈕_1', '按鈕_2']
        );
        break;
}
```

**Platform Behavior:**
- **Linux/FreeBSD:** Uses zenity or kdialog for native dialogs
- **macOS:** Explicitly skipped (falls to default case)
- **Windows:** Not tested (falls to default case)

**Why macOS is Excluded:**
- Requires `message-box` module with zenity/kdialog
- macOS would need native implementation using osascript/AppleScript or Cocoa APIs
- These are implemented in message-box.js for other purposes, but not integrated here

---

#### testTunnel() - Lines 1214-1231

**Purpose:** Tests basic tunnel creation and WebSocket upgrade functionality.

**Process:**
- Creates HTTP server on port 9250
- Requests tunnel with rights=0, consent=0
- Waits for WebSocket upgrade
- Closes connection upon success

**Platform Behavior:**
- All platforms supported
- Tests fundamental tunneling capability used by all remote features

---

#### testTerminal() - Lines 1084-1162

**Purpose:** Tests terminal/shell access functionality with user consent handling.

**Process:**
- Determines if user consent is required (X11 detection on Linux/FreeBSD)
- Creates tunnel with rights=0x1FF and appropriate consent flag
- Sends terminal mode request (mode 1 = root terminal)
- Waits for terminal data (JSON control messages followed by shell output)
- Sends exit command to close gracefully
- 7-second timeout

**Platform Behavior:**
- Windows: Uses `exit\r\n` command
- Unix-like: Uses `exit\n` command
- Linux/FreeBSD: Checks X11 availability for consent requirement
- macOS: Would work theoretically but X11 check irrelevant (Quartz/Cocoa)

---

#### testKVM() - Lines 982-1076

**Purpose:** Tests Keyboard/Video/Mouse (remote desktop) functionality.

**Process:**
- Checks if KVM support compiled into agent (`require('MeshAgent').hasKVM`)
- On Linux/FreeBSD: Verifies X11 support via `monitor-info.kvm_x11_support`
- Creates tunnel with rights=0x1FF, consent=0xFF
- Requests KVM session (sends 'c' then '2')
- Waits for bitmap data (type 3 packet)
- Handles JUMBO packets (type 27) for large screen captures
- Validates packet structure

**Platform Behavior:**
- Linux/FreeBSD: Requires X11 for display capture
- Windows: Uses Windows display capture APIs
- macOS: Would require macOS-specific display capture (CGDisplayStream/ScreenCaptureKit)

---

#### testFileUpload() - Lines 816-877

**Purpose:** Tests file upload functionality with CRC32C verification.

**Process:**
- Generates 65,535-byte random test buffer
- Creates tunnel for file transfer (rights=0x1FF, consent=0x00)
- Requests upload to 'testFile' in current working directory
- Sends file in 16KB chunks
- Waits for upload acknowledgments
- Confirms successful upload via CRC validation on agent side

**Platform Behavior:**
- All platforms supported
- Tests file transfer protocol used for remote file management

---

#### testFileDownload() - Lines 878-948

**Purpose:** Tests file download functionality with CRC32C verification.

**Process:**
- Creates tunnel for file download
- Requests download of previously uploaded 'testFile'
- Receives file in chunks with flag markers
- Calculates CRC32C of received data
- Compares with CRC from upload test
- Validates file integrity

**Platform Behavior:**
- All platforms supported
- Complements upload test to verify bidirectional file transfer

---

#### testCoreDump() - Lines 708-815

**Purpose:** Tests agent core restart without crashing (core dump recovery).

**Process:**
- Records current agent PID
- On Linux/FreeBSD with X11: Initiates KVM session first, then dumps core
- On other systems: Performs plain core dump test
- Executes `require('MeshAgent').restartCore()`
- Waits for agent to restart via IPC reconnection
- Verifies PID remains same (process didn't crash)
- Confirms core restarted successfully without crash

**Platform Behavior:**
- Requires background agent connection (remote mode)
- Linux/FreeBSD: Enhanced testing with KVM active during dump
- macOS: Would need macOS-specific crash handling implementation

---

#### testServiceRestart() - Lines 665-706

**Purpose:** Tests full service restart capability.

**Process:**
- Queries agent for service name via `require('MeshAgent').serviceName`
- Issues `service restart` console command
- Waits for IPC reconnection after service restarts
- Confirms service successfully restarted

**Platform Behavior:**
- Requires background agent connection (remote mode)
- Windows: Restarts Windows Service
- Linux: Restarts systemd service
- macOS: Would restart launchd service (not implemented)

---

### Usage

#### Command Line Invocation

```bash
# Basic local mode testing
node agent-selftest.js

# Test running Windows service
node agent-selftest.js --serviceName="Mesh Agent"

# Test running Linux service with debug output
node agent-selftest.js --serviceName=meshagent --debugMode=true

# Run only core dump cycle testing
node agent-selftest.js --serviceName=meshagent --dumpOnly=true --cycleCount=50

# Show detailed core information
node agent-selftest.js --serviceName=meshagent --showCoreInfo="1"

# Display SMBIOS tables
node agent-selftest.js --serviceName=meshagent --smbios="1"
```

#### Parameters

**Required:**
- `--serviceName=<name>` - Name of running MeshAgent service (enables remote mode)

**Optional:**
- `--debugMode=<true|false|1|2>` - Enable debug output (2 = debug only, no tests)
- `--dumpOnly=<true|false>` - Run only core dump cycle testing
- `--cycleCount=<number>` - Number of dump test cycles (default: 20)
- `--showCoreInfo="1"` - Display full core info JSON
- `--smbios="1"` - Display parsed SMBIOS data

#### Execution Modes

**Local Mode** (no serviceName):
- Tests run within same process
- Limited capabilities (no service restart, no core dump tests)
- Uses direct `require('MeshAgent').emit()` calls

**Remote Mode** (with serviceName):
- Connects to running agent via DAIPC named pipe
- Full testing capabilities
- Required for service restart and core dump tests
- Implements automatic reconnection

### IPC Communication

#### Connection Mechanism

The module connects to running MeshAgent processes via **DAIPC** (Direct Agent IPC) named pipes:

**Windows** (line 227):
```javascript
// NodeID retrieved from registry: HKLM\Software\Open Source\<serviceName>\NodeId
ipcPath = '\\\\.\\pipe\\' + nodeId + '-DAIPC';
// Example: \\.\pipe\A1B2C3D4E5F6-DAIPC
```

**Linux/FreeBSD** (lines 237-239):
```javascript
// Path from service working directory
ipcPath = serviceWorkingDirectory + '/DAIPC';
// Example: /usr/local/mesh/DAIPC or /opt/mesh/DAIPC
```

#### Message Protocol

**Connection Flow** (lines 106-189):
1. Creates TCP (Windows) or Unix socket (Linux/FreeBSD) connection
2. Injects command hooks into agent's console system:
   ```javascript
   sendConsoleText = function(msg) {
       // Redirect to IPC
       obj.DAIPC._daipc[i]._send({cmd: 'console', value: msg});
   };
   ```
3. Registers for responses via event listeners
4. Implements automatic reconnection on connection loss

**Message Format** (lines 127-161):
- **Length Prefix:** 4 bytes (UInt32LE) indicating total message length
- **Payload:** JSON object
- **Example Command:**
  ```javascript
  {
      cmd: 'console',
      value: 'eval "require(\'MeshAgent\').emit(\'Connected\', 3);"'
  }
  ```
- **Example Response:**
  ```javascript
  {
      cmd: 'server',
      value: { action: 'coreinfo', ... }
  }
  ```

#### Command Helpers

**agentQueryValue()** - Lines 1280-1306:
- Executes JavaScript expression in agent
- Returns value via temporary response handler
- 8-second timeout
- Example: `agentQueryValue('process.pid')` returns agent's PID

**consoleCommand()** - Lines 1308-1331:
- Sends console command to agent
- Captures console text output
- 5-second timeout
- Example: `consoleCommand('help')` returns help text

**toAgent()** - Lines 1260-1264 (local mode) / 265-278 (remote mode):
- Sends commands to agent
- Local: Direct `require('MeshAgent').emit('Command', j)`
- Remote: JSON over IPC pipe

### Dependencies

#### Node.js Core Modules
- `net` (line 106) - TCP/Unix socket connections for IPC communication
- `http` (lines 470, 1239) - HTTP server for tunnel WebSocket upgrades and LMS testing
- `events.EventEmitter` (line 1236) - Event handling infrastructure

#### MeshAgent Module Dependencies

**Core Required Modules:**

- **`promise`** (line 85)
  - Custom promise implementation for async test orchestration
  - Used throughout for chaining test execution
  - Not Node.js native promises

- **`MeshAgent`** (lines 169, 269, 372, 439, 655, 659, 1002, 1263, 1336)
  - Core agent functionality
  - **Methods used:**
    - `SendCommand()` - Server communication (hijacked for testing)
    - `restartCore()` - Core restart functionality
    - `emit('Connected')` - Trigger info gathering
    - `emit('Command')` - Send commands to agent
  - **Properties used:**
    - `serviceName` - Service name for restart testing
    - `hasKVM` - KVM support detection flag

**Platform-Specific Module Dependencies:**

- **`service-manager`** (line 204) - **Windows/Linux only**
  - Service control and management
  - Used to check if service is running before testing
  - Methods: `manager.getService()`, `isRunning()`, `appWorkingDirectory()`
  - **macOS equivalent:** Would need launchd integration

- **`win-registry`** (line 222) - **Windows only**
  - Windows registry access
  - Used to retrieve NodeID for IPC pipe path
  - Queries: `HKLM\Software\Open Source\<serviceName>\NodeId`
  - **Not applicable on macOS/Linux/FreeBSD**

- **`ILibWebRTC`** (lines 337, 339) - **Cross-platform**
  - WebRTC functionality for remote desktop
  - Methods: `createNewFactory()`, `createConnection()`
  - Tests data channel creation and large data transfer
  - Platform support depends on WebRTC implementation

- **`smbios`** (line 587) - **Windows/Linux**
  - SMBIOS/DMI table parsing
  - Used to detect Intel AMT hardware support
  - Parses BIOS/firmware information
  - **macOS:** Has SMBIOS but parsing may differ

- **`monitor-info`** (lines 729, 991, 1006, 1096, 1100) - **Linux/FreeBSD only**
  - Display and X11 detection
  - Property: `kvm_x11_support` - Boolean indicating X11 availability
  - Used for KVM testing and user consent determination
  - **macOS equivalent:** Would need Quartz/Cocoa display detection

- **`message-box`** (lines 1189, 1195) - **Linux/FreeBSD only (for dialog test)**
  - Dialog box display functionality
  - Properties: `kdialog`, `zenity`, `zenity.extra`
  - Methods: `create(title, caption, timeout, buttons)`
  - Requires zenity or kdialog binaries on system
  - **macOS:** Has macOS implementation via osascript, but not integrated in this test

- **`EncryptionStream`** (line 827) - **Cross-platform**
  - Cryptographic utilities
  - Method: `GenerateRandom(size)` - Generate random test data
  - Used to create 64KB test buffer for file transfers

**Implicit/Global Dependencies:**

- **`crc32c()`** (lines 828, 910, 914) - CRC32C checksum function
  - Likely from SHA384Stream or similar module
  - Used for file transfer validation
  - Not explicitly required, may be global function

#### Platform Binary Dependencies

**Linux/FreeBSD:**
- **zenity** or **kdialog** (optional)
  - GUI dialog display tools
  - Required for dialog box testing (testDialogBox_UTF8)
  - Detected via `message-box` module
  - Not present = dialog test marked N/A

- **X11/Xorg** (optional)
  - X Window System
  - Required for KVM and user consent features
  - Detection via `monitor-info.kvm_x11_support`
  - Wayland systems may not have X11

- **dmidecode** (likely, for smbios module)
  - SMBIOS/DMI table reading utility
  - May be used by smbios module on Linux

**Windows:**
- No external binary dependencies
- Uses native Windows APIs via modules:
  - Registry access (win-registry)
  - Service management (service-manager)
  - Device management

**macOS (if it were supported):**
- **osascript** - AppleScript execution (for dialogs via message-box)
- **launchctl** - Service management (for service restart testing)
- **ioreg** or similar - Hardware info (SMBIOS equivalent)
- Display capture frameworks (CGDisplayStream/ScreenCaptureKit for KVM)

#### Dependency Summary by Test Function

| Test Function | Module Dependencies | Binary Dependencies |
|---------------|-------------------|---------------------|
| coreInfo | MeshAgent, smbios | dmidecode (Linux) |
| testLMS | http | None |
| testConsoleHelp | MeshAgent | None |
| testCPUInfo | MeshAgent | None |
| WebRTC_Test | ILibWebRTC | None |
| testDialogBox_UTF8 | message-box | zenity/kdialog (Linux/FreeBSD) |
| testTunnel | http | None |
| testTerminal | MeshAgent, monitor-info | X11 (Linux/FreeBSD) |
| testKVM | MeshAgent, monitor-info | X11 (Linux/FreeBSD) |
| testFileUpload | EncryptionStream | None |
| testFileDownload | EncryptionStream | None |
| testCoreDump | MeshAgent, monitor-info | X11 (Linux/FreeBSD, optional) |
| testServiceRestart | MeshAgent, service-manager | None |

#### Why Dependencies Make macOS Support Difficult

1. **service-manager** - No macOS/launchd implementation
2. **win-registry** - Windows-only, not applicable
3. **monitor-info** - Linux/FreeBSD X11 detection, would need macOS Quartz equivalent
4. **message-box dialog test** - Uses zenity/kdialog, not integrated with macOS osascript
5. **smbios** - May work differently on macOS hardware
6. **Platform-specific binaries** - Would need macOS equivalents (launchctl, ioreg, etc.)

Most core modules (promise, MeshAgent, ILibWebRTC, EncryptionStream) are likely cross-platform, but the platform-specific modules and system integration make comprehensive macOS support impractical for a diagnostic-only tool.

### Test Results Output

The module provides real-time console output showing test progress:

```
Starting Self Test...
   => Waiting for Agent Info
      -> Core Info received..............[OK]

         Windows 10 Pro (x64)
         MeshAgent v2.0.0

         -> SMBIOS Info received.............[OK]
         -> AMT Support...................[YES]
         -> Micro LMS.....................[CONNECTED]
         -> Testing MicroLMS..............[OK]
   => Testing console command: help.......[OK]
   => Testing CPU Info....................[OK]
   => Testing WebRTC
       => WebRTC Data Channel Test........[OK]
   => Dialog Test.........................[N/A]
   => Tunnel Test.........................[OK]
   => Terminal Test
      -> Tunnel...........................[CONNECTED]
      -> Triggering User Consent
      -> Result...........................[OK]
   => KVM Test
      -> Tunnel...........................[CONNECTED]
      -> Triggering User Consent
      -> Received BITMAP
      -> Result...........................[OK]
   => File Transfer Test (Upload)
      -> Tunnel (Upload)..................[CONNECTED]
      -> File Transfer (Upload)...........[OK]
   => File Transfer Test (Download)
      -> Tunnel (Download)................[CONNECTED]
      -> File Transfer (Download).........[OK]
   => Mesh Core Dump Test
      -> Agent PID = 12345
      -> Initiating KVM for dump test
      -> KVM initiated, dumping core
      -> Core Restarted without crashing..[OK]
   => Service Restart Test
      -> Service Name = meshagent
      -> Restarting Service...
         -> Restarted.....................[OK]
End of Self Test
```

### Code Structure

The module is organized into functional sections:

1. **Lines 1-90:** Helper functions and globals
2. **Lines 91-190:** IPC connection management (`agentConnect()`)
3. **Lines 192-330:** Main execution and setup (`start()`, `setup()`)
4. **Lines 332-361:** WebRTC testing
5. **Lines 363-429:** Core dump cycle testing (`DumpOnlyTest()`)
6. **Lines 431-461:** Cleanup (`completed()`, `getFDSnapshot()`)
7. **Lines 463-535:** LMS testing
8. **Lines 537-663:** Core info gathering
9. **Lines 665-706:** Service restart testing
10. **Lines 708-815:** Core dump testing
11. **Lines 816-877:** File upload testing
12. **Lines 878-948:** File download testing
13. **Lines 950-980:** CPU info testing
14. **Lines 982-1076:** KVM testing
15. **Lines 1084-1162:** Terminal testing
16. **Lines 1163-1177:** Console help testing
17. **Lines 1179-1212:** Dialog box testing
18. **Lines 1214-1231:** Tunnel testing
19. **Lines 1233-1360:** Setup infrastructure and command helpers
20. **Lines 1362-1370:** Utility functions

### Technical Notes

**Promise-Based Async Control:**
The module uses a custom promise implementation for coordinating async tests. Each test function returns a promise that resolves on success or rejects on failure, allowing tests to be chained:

```javascript
coreInfo()
    .then(() => testLMS())
    .then(() => testConsoleHelp())
    // ... more tests
    .then(() => completed())
    .catch((error) => {
        console.log(error);
        process._exit();
    });
```

**Timeout Handling:**
Most tests implement timeouts to prevent hanging:
- Core info: 10 seconds
- Console commands: 5 seconds
- Terminal test: 7 seconds
- Query value: 8 seconds

**Event-Driven Architecture:**
The module extends EventEmitter to handle asynchronous communication:
- `command` event - Receives agent responses
- `tunnel` event - Handles tunnel creation

**Stateful Testing:**
Some tests depend on previous tests:
- File download requires successful upload
- CRC values stored globally for validation across tests

### macOS-Specific Analysis

**What Would Work on macOS:**

Theoretically functional tests:
- `coreInfo()` - Agent info gathering (platform-agnostic)
- `testConsoleHelp()` - Console command testing
- `testCPUInfo()` - CPU info (if implemented)
- `testTunnel()` - Basic tunnel creation
- `testFileUpload()` - File upload via tunnel
- `testFileDownload()` - File download via tunnel
- `WebRTC_Test()` - If WebRTC module supports macOS

**What Wouldn't Work on macOS:**

Not implemented or explicitly excluded:
- `testDialogBox_UTF8()` - **Explicitly skipped** (line 1184)
- `testLMS()` - No Intel AMT on Mac hardware
- `testKVM()` - Requires macOS display capture APIs (CGDisplayStream/ScreenCaptureKit)
- `testTerminal()` - Would need macOS-specific consent handling
- `testCoreDump()` - Requires macOS crash reporting integration
- `testServiceRestart()` - Requires launchd service management

**Implementation Effort for macOS Support:**

To fully support macOS would require:
1. Implementing dialog test using osascript or native Cocoa APIs
2. Adding macOS display capture for KVM testing
3. Integrating with macOS consent/TCC framework
4. Implementing launchd service restart handling
5. Adding macOS-specific core dump/crash reporting
6. Testing and validation on macOS systems

Given that this is a diagnostic tool rather than core functionality, and that most MeshAgent deployments are Windows/Linux, implementing macOS support has not been prioritized.

## Summary

The agent-selftest.js module is a sophisticated automated testing framework specifically designed for **Windows, Linux, and FreeBSD** platforms. It validates all major MeshAgent functionality through 13 comprehensive tests covering networking, remote access, file transfer, and system management.

**macOS is not supported** because:
- Dialog testing explicitly skips macOS (default case behavior)
- Platform-specific features require APIs not implemented for macOS (display capture, service management, crash reporting)
- Mac hardware doesn't support Intel AMT
- This is a development/diagnostic tool, not a runtime requirement
- MeshAgent operates normally on macOS without this testing infrastructure

The module connects to running agents via DAIPC named pipes and uses a promise-based async architecture to coordinate test execution. It provides detailed real-time feedback and is invoked via command line with various parameters for controlling test behavior.
