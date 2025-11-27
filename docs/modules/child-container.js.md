# child-container.js

Sandboxed subprocess execution framework that enables running untrusted or privileged code in isolated child processes with IPC communication. Supports user impersonation, session redirection, and module injection for agent plugin architecture, providing a secure execution environment for dynamic code and multi-user operations.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support with Task Scheduler and Win-Tasks for user impersonation
- Linux - Full support with UID switching and session management
- macOS (darwin) - Full support with session types and UID switching
- FreeBSD - Full support with session management

**Excluded Platforms:**
- None - This module supports all platforms

## Functionality

### Purpose

The child-container module provides secure sandboxed execution for MeshAgent operations requiring:

- **User Impersonation:** Run code as different user (non-root execution)
- **Session Isolation:** Execute in specific user session (console vs background)
- **Module Injection:** Load JavaScript modules dynamically into child process
- **IPC Communication:** Bidirectional messaging between parent and child
- **Security Boundaries:** Isolate untrusted or privileged code from main agent

This module is critical for:
- Running KVM/desktop capture as logged-in user
- Executing user-specific operations (clipboard, GUI dialogs)
- Plugin architecture and dynamic module loading
- Security isolation of risky operations
- Multi-user session management

### Key Functions

#### create(options) - Lines 21-216 (Create Child Container)

**Purpose:** Creates isolated child process with IPC communication and module injection capabilities.

**Parameters:**
```javascript
{
  launch: {
    module: 'moduleName',     // Module to execute
    method: 'methodName',     // Method within module
    args: ['arg1', 'arg2']    // Arguments to pass
  },
  modules: [
    { name: 'moduleName', script: 'module.exports = {...}' }
  ],
  user: 'username',           // Windows: username for impersonation
  uid: 1000,                  // Unix: UID for execution
  sid: SpawnTypes.USER        // Session type
}
```

**Process:**

**1. IPC Server Setup** (lines 40-103):
- Creates named pipe (Windows) or Unix socket (Unix)
- Path: Random number for uniqueness
  - Windows: `\\.\pipe\taskRedirection-{random}`
  - Unix: `{cwd}/taskRedirection-{random}`
- Waits for first client connection
- Closes server after one connection (security)

**2. Child Process Spawn** (lines 105-177):

**Windows with User Impersonation** (lines 139-177):
- **Preferred:** Win-Tasks COM interface (lines 142-156)
  ```javascript
  var task = require('win-tasks').createTask(
    action: executable + ' args',
    user: user
  );
  task.run();
  ```

- **Fallback:** SCHTASKS command (lines 162-176)
  ```bash
  schtasks /Create /TN taskname /TR "executable args" /RU "DOMAIN\User" /SC ONCE /ST 00:00
  schtasks /Run /TN taskname
  schtasks /Delete /TN taskname /F
  ```

**Unix with UID Switching** (lines 178-214):
- Uses `child_process.execFile()` with options:
  ```javascript
  {
    uid: targetUid,
    sessionId: sessionId  // From user-sessions module
  }
  ```
- Session types:
  - `SpawnTypes.WINLOGON`: Terminal services (uid -1)
  - `SpawnTypes.USER`: Specific UID

**3. Module Injection** (lines 57-86):
- Parent sends `addModule` commands via IPC
- Child receives and `eval()` module code
- Modules registered in child's `require()` system

**4. Launch Trigger** (lines 88-92):
- Parent sends `launch` command
- Child executes: `require(module)[method](...args)`

**Return Value:** EventEmitter with methods and events:
- **Methods:**
  - `disconnect()` - Close IPC connection
  - `send(obj)` - Send message to child
  - `message(msg)` - Receive message from child
  - `exit(code)` - Child exited
- **Events:**
  - `'ready'` - Child connected and ready
  - `'message'` - Message from child
  - `'exit'` - Child process terminated

---

#### connect(ipcNumber) - Lines 217-281 (Child-Side Connection)

**Purpose:** Child process connects to parent's IPC server and processes commands.

**Process:**

**1. IPC Connection** (lines 224-242):
- Connects to parent's named pipe/socket
- Path derived from `ipcNumber` parameter
- Implements length-prefixed JSON protocol

**2. Command Processing** (lines 244-266):
- **`addModule`**: `eval()` and register module (line 252)
- **`launch`**: Execute `require(module)[method](...args)` (line 256)
- **`message`**: Emit to parent listeners (line 260)
- **`exit`**: Close connection and exit (line 263)

**3. Parent Disconnect Handling** (lines 240, 243):
- If parent IPC closes, child exits
- Prevents orphaned child processes

**Return Value:** EventEmitter with methods:
- `send(data)` - Send to parent
- `message(msg)` - Receive from parent

---

### IPC Protocol

**Message Format:**
```
[4 bytes: UInt32LE length][length bytes: JSON payload]
```

**Commands (Parent → Child):**
```javascript
// Add module
{ cmd: 'addModule', name: 'mymodule', script: 'module.exports = {...}' }

// Launch execution
{ cmd: 'launch', module: 'mymodule', method: 'run', args: ['arg1'] }

// Send message
{ cmd: 'message', value: { custom: 'data' } }

// Exit child
{ cmd: 'exit' }
```

**Commands (Child → Parent):**
```javascript
// Send message
{ cmd: 'message', value: { custom: 'data' } }

// Disconnect notification
{ cmd: '_disconnect' }
```

### Dependencies

#### Node.js Core Modules
- **`net`** (line 30) - TCP/Unix socket IPC
- **`events.EventEmitter`** (line 29) - Event infrastructure
- **`child_process`** (line 193) - Process spawning

#### MeshAgent Module Dependencies

**Required on All Platforms:**
- **`tls`** (line 33) - Random number generation for IPC path
  - Method: `generateRandomInteger()`
  - Used for unique IPC path

- **`user-sessions`** (lines 171, 176, 201, 203) - Session management
  - Methods: `getSessionIdSync(uid)`, `consoleUid()`
  - UID/session resolution

**Windows-Specific:**
- **`win-tasks`** (line 144) - COM-based task creation (preferred)
  - Method: `createTask(options)`
  - More reliable than SCHTASKS

#### External Dependencies

**Windows:**
- **schtasks.exe** - Task scheduler (fallback)
  - Used if win-tasks COM fails
  - Creates temporary scheduled task for user impersonation

**Unix:**
- None - Uses built-in execFile UID parameter

### Usage

#### Basic Usage - Module Execution

```javascript
var container = require('child-container').create({
  launch: {
    module: 'fs',
    method: 'readFileSync',
    args: ['/etc/passwd', 'utf8']
  }
});

container.on('ready', function() {
  console.log('Child ready');
});

container.on('message', function(msg) {
  console.log('From child:', msg);
});

container.on('exit', function(code) {
  console.log('Child exited:', code);
});
```

#### Custom Module Injection

```javascript
var container = require('child-container').create({
  modules: [
    {
      name: 'mymodule',
      script: `
        module.exports.greet = function(name) {
          return 'Hello, ' + name;
        };
      `
    }
  ],
  launch: {
    module: 'mymodule',
    method: 'greet',
    args: ['World']
  }
});
```

#### User Impersonation (Windows)

```javascript
// Run as specific user
var container = require('child-container').create({
  user: 'DOMAIN\\Username',
  launch: {
    module: 'clipboard',
    method: 'read',
    args: []
  }
});
```

#### UID Switching (Unix)

```javascript
// Run as specific UID
var container = require('child-container').create({
  uid: 1000,  // Target user UID
  sid: require('child-container').SpawnTypes.USER,
  launch: {
    module: 'fs',
    method: 'readFileSync',
    args: ['/home/user/.config/file']
  }
});
```

#### Bidirectional Communication

```javascript
var container = require('child-container').create({
  modules: [
    {
      name: 'worker',
      script: `
        module.exports.process = function(data) {
          // Do work
          this.send({ result: processed });
        };
      `
    }
  ],
  launch: { module: 'worker', method: 'process', args: ['data'] }
});

container.on('message', function(msg) {
  console.log('Result:', msg.result);
});
```

### Technical Notes

**Debug Mode:**
- Set `obj._debugIPC = 1` (line 139) to print spawn command without executing
- Useful for testing impersonation parameters

**Security Features:**
- IPC server closes after first connection (line 100)
- Randomized IPC path prevents collisions (line 33)
- Child exits if parent disconnects (lines 240, 243)
- Process isolation via user/UID boundaries

**Windows User Impersonation:**
- **Format:** `DOMAIN\Username` or `.\LocalUser`
- **Priority:** win-tasks COM (more reliable) → SCHTASKS fallback
- **Mechanism:** Creates temporary scheduled task, runs immediately, deletes
- **Limitations:** Requires administrative privileges

**Unix UID Switching:**
- **Mechanism:** `child_process.execFile({uid: target})`
- **Requirements:** Parent must run as root
- **Session Types:**
  - `SpawnTypes.WINLOGON` (value -1): Terminal services session
  - `SpawnTypes.USER`: User-specific UID

**Session Type Usage:**
```javascript
var SpawnTypes = {
  WINLOGON: -1,  // Terminal/console session
  USER: 0        // Specific UID
};

// Run in console session
create({ sid: SpawnTypes.WINLOGON });

// Run as specific user
create({ uid: 1000, sid: SpawnTypes.USER });
```

**Module Injection Safety:**
- Child uses `eval()` to load modules (security consideration)
- Only load trusted modules
- Used for plugin architecture, not arbitrary code

**IPC Cleanup:**
- Parent closes IPC server after first connection
- Child exits if parent disconnects
- No orphaned processes or IPC resources

### Platform-Specific Analysis

**What Works on macOS:**
- Full UID switching support
- Session type selection (console vs background)
- Module injection
- IPC communication
- User session execution

**macOS-Specific Behavior:**
- Unix socket IPC: `{cwd}/taskRedirection-{random}`
- UID switching via execFile options
- Session types: WINLOGON for console, USER for background
- No user impersonation by name (UID required)

**Platform Differences:**

**Windows:**
- Named pipe IPC: `\\.\pipe\taskRedirection-{random}`
- User impersonation by username
- Task Scheduler mechanism
- COM interface (win-tasks) or SCHTASKS

**Unix (Linux/macOS/FreeBSD):**
- Unix socket IPC: `{cwd}/taskRedirection-{random}`
- UID switching (numeric)
- execFile UID parameter
- Session ID from user-sessions

**Use Cases:**

**KVM/Desktop Capture:**
```javascript
// Run as logged-in user for screen access
create({
  uid: consoleUid,
  launch: { module: 'kvm', method: 'start' }
});
```

**Clipboard Access:**
```javascript
// Access user's clipboard
create({
  uid: targetUid,
  launch: { module: 'clipboard', method: 'read' }
});
```

**Plugin Execution:**
```javascript
// Load and execute untrusted plugin
create({
  modules: [{ name: 'plugin', script: pluginCode }],
  launch: { module: 'plugin', method: 'main' }
});
```

## Summary

The child-container.js module provides secure sandboxed subprocess execution for MeshAgent across all platforms (Windows, Linux, macOS, FreeBSD). It enables user impersonation, session isolation, and dynamic module injection with bidirectional IPC communication.

**Key capabilities:**
- User impersonation (Windows username, Unix UID)
- Session-specific execution (console vs background)
- Dynamic module injection
- Bidirectional IPC messaging
- Security isolation via process boundaries

**macOS support:**
- Full support using Unix socket IPC
- UID switching via execFile options
- Session type selection
- No limitations compared to Linux

**Critical dependencies:**
- `net` for IPC communication
- `child_process` for spawning
- `user-sessions` for UID/session management
- `win-tasks` (Windows only) for user impersonation

The module enables critical multi-user functionality like KVM desktop capture and user-specific operations while maintaining security boundaries through process isolation.
