# win-dispatcher.js

Provides inter-process communication and code dispatch framework for executing operations in child processes via IPC. Enables secure execution of code in different user contexts using Windows Task Scheduler or PowerShell with dual IPC channels for command/control and data streaming.

## Platform

**Supported Platforms:**
- Windows (all versions) - Full support

**Excluded Platforms:**
- **macOS** - Not supported (Windows-only)
- **Linux** - Not supported (Windows-only)
- **FreeBSD** - Not supported (Windows-only)

**Exclusion Reasoning:**

Windows-specific module requiring Windows APIs/DLLs unavailable on other platforms.

**Platform Notes:**

**win-dispatcher.js is Windows-only** because:

1. **Windows Named Pipes** - IPC mechanism unique to Windows (\\\\.\\pipe\\...)
2. **Task Scheduler COM API** - Windows scheduling infrastructure
3. **SCHTASKS Utility** - Windows task scheduling command-line tool
4. **PowerShell Dependency** - Windows PowerShell execution model
5. **User Context Switching** - Windows user session/privilege management

---

## Functionality

### Core Purpose

win-dispatcher.js enables child process communication for:

1. **Code Execution** - Execute JavaScript code in separate process
2. **User Context Switching** - Run operations as different user
3. **Module Loading** - Dynamically load modules into child process
4. **Bidirectional Communication** - Dual IPC channels for control and data
5. **Clean Shutdown** - Coordinated cleanup and process termination

### Main Operations

1. **Dispatch Creation** - dispatch(options) - Create child process with IPC
2. **Connection Handling** - Connect(ipcInteger) - Child-side connection
3. **Method Invocation** - invoke(method, args) - Call methods on child
4. **Cleanup** - close() - Shutdown IPC and child process

---

## Dispatcher Creation

### dispatch(options) - Lines 136-278

**Purpose:** Create and manage child process with dual IPC channels

**Parameters - options object:**
```javascript
{
    user: "DOMAIN\\username",  // (optional) User to run child as
    modules: [                 // Array of modules to inject
        { name: 'module-name', script: '...JS code...' }
    ],
    launch: {
        module: 'module-name',          // Module to execute
        method: 'method-name',          // Method to call
        args: [arg1, arg2, ...],       // Method arguments
        split: true/false              // Duplex stream mode
    }
}
```

**Returns:** EventEmitter with properties and methods

**Process:**
1. Validates options (line 139)
2. Creates return object with EventEmitter (line 142-143)
3. Generates random IPC port number (lines 156-170):
   - Loop until unique named pipe paths available
   - Primary: \\\\.\\pipe\\taskRedirection-{ipcInteger}
   - Secondary: \\\\.\\pipe\\taskRedirection-{ipcInteger}C
4. Creates two server sockets (lines 149-150)
5. Attempts Task Scheduler COM API first (lines 180-222):
   - Gets user/domain for target process
   - Creates scheduled task 'MeshUserTask'
   - Executes child process via Task Scheduler
   - Cleans up task after execution
6. Falls back to SCHTASKS + PowerShell (lines 233-276)

**Returned Dispatcher Properties:**
- `options` - Original configuration
- `_ipcPath` - Primary IPC path
- `_control` - Control channel connection
- `invoke(method, args)` - Send command to child
- `close()` - Cleanup
- EventEmitter with 'connection' event

---

### Child-Side Connection - connect(ipc) - Lines 284-356

**Purpose:** Connect from child process to parent via dual IPC channels

**Parameters:**
- `ipc` - IPC identifier string (e.g., "1234")

**Process:**
1. Constructs IPC paths (line 286):
   - ipcPath = '\\\\.\\pipe\\taskRedirection-' + ipc
2. Creates secondary (control) connection (lines 287-310):
   - Connects to ipcPath + 'C'
   - Sets up data handler to parse JSON commands
   - Handles 'invoke' commands (line 304)
   - Stores in global.ipc2Client
3. Creates primary connection (lines 311-353):
   - Connects to ipcPath
   - Receives JSON-encoded commands on connection
   - Handles 'addModule' - Load JavaScript module
   - Handles 'launch' - Execute module/method
   - Sets up bidirectional stream piping if split mode
   - Stores in global.ipcClient

**Command Protocol (JSON over IPC):**
```javascript
{
    command: 'addModule',
    value: { name: 'modname', js: '...source...' }
}
```

---

## Core Methods

### ipc_invoke(method, args) - Lines 56-63

**Purpose:** Send invoke command to child process via control channel

**Parameters:**
- `method` - Method name to invoke
- `args` - Arguments array

**Process:**
1. Creates JSON command object (line 59)
2. Creates header with message length (line 60)
3. Writes header + data to control channel (lines 61-62)

**Message Format:**
- Header: 4-byte little-endian length
- Body: JSON-encoded command

---

### ipc2_connection(s) - Lines 85-93

**Purpose:** Handle secondary (control) IPC connection

**Parameters:**
- `s` - Connected socket

**Process:**
1. Stores control channel reference (line 87)
2. Closes listener server (line 89)
3. Sets up invoke() method on parent (line 90)
4. Registers end/finalize handlers

---

### ipc_connection(s) - Lines 98-122

**Purpose:** Handle primary IPC connection and initialize child

**Parameters:**
- `s` - Connected socket

**Process:**
1. Stores client channel reference (line 100)
2. Closes listener server (line 102)
3. Sends modules via IPC (lines 106-113):
   - For each module in options.modules
   - Sends 'addModule' command with source code
4. Sends launch command (lines 116-119):
   - Module name, method name, arguments
   - Split mode flag
5. Registers finalization handlers (line 120)
6. Emits 'connection' event (line 121)

---

### dispatcher_shutdown() - Lines 125-131

**Purpose:** Clean shutdown of IPC and child process

**Process:**
1. Closes primary IPC server (line 127)
2. Closes secondary IPC server (line 128)
3. Nulls reference to prevent use-after-free

---

## User Context Switching

### Task Scheduler Method (Lines 180-222)

**Advantages:**
- Direct COM API access
- Cleaner process model
- Better error handling

**Process:**
1. Determines target user/domain
2. Creates task with:
   - name: 'MeshUserTask'
   - User credentials
   - Executable path with IPC string
3. Runs task immediately
4. Deletes task after completion

**Fallback Reason:** COM API not available (older Windows or permissions)

---

### SCHTASKS + PowerShell Method (Lines 233-276)

**Advantages:**
- Works on all Windows versions
- PowerShell available on newer systems

**Process:**
1. Creates SCHTASKS commands via PowerShell (line 245)
2. Executes PowerShell with stdin for commands (line 245)
3. PowerShell creates scheduled task
4. Modifies task settings:
   - StopIfGoingOnBatteries = false
   - DisallowStartIfOnBatteries = false
5. Runs task
6. Deletes task

**Commands Sent (lines 248-274):**
```powershell
SCHTASKS /CREATE /F /TN MeshUserTask /SC ONCE /ST 00:00 /RU {user} /TR {cmd}
SCHTASKS /RUN /TN MeshUserTask
SCHTASKS /DELETE /F /TN MeshUserTask
```

---

## Child Process Initialization

### Child Startup String (Line 175)

```javascript
var str = Buffer.from("require('win-console').hide();require('win-dispatcher').connect('" +
ipcInteger + "');").toString('base64');
```

**Actions:**
1. Hide console window (win-console module)
2. Connect to parent via IPC (dispatcher.connect)

**Execution:** Child process receives via command line

---

## Message Protocol

### IPC Message Format

All IPC messages follow structure:
```
[4 bytes: length][JSON payload]
```

**Message Types:**

1. **addModule**
```javascript
{ command: 'addModule', value: { name: 'modname', js: 'source' } }
```

2. **launch**
```javascript
{ command: 'launch', value: {
    module: 'modname',
    method: 'methodname',
    args: [arg1, arg2],
    split: false
}}
```

3. **invoke**
```javascript
{ command: 'invoke', value: { method: 'methodname', args: [...] } }
```

---

## Duplex Stream Mode

### split: true Operation (Lines 335-346)

When split mode enabled:
- Child's stdout piped to parent dispatcher stream (output)
- Parent dispatcher stream piped to child's stdin (input)
- Each direction has independent stream

```javascript
global._proxyStream.out.pipe(this, { end: false });
this.pipe(global._proxyStream.in, { end: false });
```

This enables bidirectional communication for interactive processes.

---

## Dependencies

### Module Dependencies - Lines 151, 152

**require('events').EventEmitter** - Line 143
- EventEmitter base for dispatcher
- createEvent('connection') for notifications

**require('net').createServer()** - Lines 149-150
- Creates IPC server sockets
- Named pipe listening

**require('net').createConnection()** - Lines 287, 311
- Child-side IPC client connections

**require('tls').generateRandomInteger()** - Line 158
- Generate unique IPC port numbers

**require('child_process').execFile()** - Line 245
- Execute PowerShell process

**require('user-sessions')** - Lines 192, 199, 255
- Get user/domain information
- Get process owner details
- Session ID lookups

**require('win-tasks')** - Line 219
- Windows Task Scheduler COM interface
- Task creation and execution

**require('win-console')** - Line 175 (child)
- Hide console window in child process

---

## Error Handling

### Graceful Degradation

1. Try Task Scheduler (COM) first
2. If fails (catch block line 224), fall back to SCHTASKS
3. User and domain detection with try/catch

### IPC Channel Errors

- Error listeners on IPC close (line 354-355)
- Process exit on connection loss
- Cleanup on unexpected closure

---

## Security Considerations

1. **User Credential Handling** - User string parsed and validated
2. **IPC Named Pipe Security** - writableAll flag allows all access
3. **Module Source Control** - Modules passed as strings, not files
4. **Process Isolation** - Child runs with specified user credentials

---

## Technical Notes

### Named Pipe Naming

Windows named pipes use UNC paths:
- Local pipe: \\\\.\\pipe\\{name}
- Remote pipe: \\\\{machine}\\pipe\\{name}

### Spawn Types Reference (Lines 56-63)

The code comments reference spawn type enumeration:
- ILibProcessPipe_SpawnTypes_DEFAULT (0)
- ILibProcessPipe_SpawnTypes_USER (1)
- ILibProcessPipe_SpawnTypes_SPECIFIED_USER (5)

### IPC Channel Purposes

- **Primary (Primary)** - Initialization and module loading
- **Secondary (Control)** - Runtime method invocation

Dual channels prevent blocking:
- Module load via primary
- Method calls via secondary
- Independent data flow

---

## Usage Example

```javascript
var dispatcher = require('win-dispatcher');

var proc = dispatcher.dispatch({
    user: 'DOMAIN\\username',
    modules: [
        { name: 'mymod', script: 'var x = 42;' }
    ],
    launch: {
        module: 'mymod',
        method: 'mymethod',
        args: [param1, param2],
        split: false
    }
});

proc.on('connection', function(conn) {
    conn.on('data', function(chunk) {
        console.log('Child output:', chunk);
    });

    // Invoke methods on child
    proc.invoke('methodName', [arg1, arg2]);
});

// Cleanup
proc.close();
```

---

## Summary

win-dispatcher.js provides robust inter-process communication for Windows, enabling code execution in child processes with user context switching. The module supports both Task Scheduler and SCHTASKS/PowerShell execution, dual IPC channels for independent control/data flow, and dynamic module injection. Comprehensive error handling and graceful fallbacks ensure reliable cross-process communication.
