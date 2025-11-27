# win-virtual-terminal.js

Windows PseudoConsole (ConPTY) implementation that enables terminal emulation on Windows 10 (1809+) and Windows Server 2019+. Creates virtual terminal sessions with full VT100/ANSI support for running command-line applications with proper terminal capabilities.

## Platform

**Supported Platforms:**
- Windows (win32) - Windows 10 version 1809+ and Windows Server 2019+ only

**Excluded Platforms:**
- **macOS** - Explicitly excluded
- **Linux** - Explicitly excluded
- **FreeBSD** - Explicitly excluded
- **All non-Windows platforms** - Explicitly excluded
- **Windows 7/8/8.1/Server 2016 and earlier** - API not available

**Exclusion Reasoning:**

**Line 235:** `if (process.platform == 'win32')`

The module explicitly checks platform and only exports functionality on Windows. Non-Windows platforms receive `undefined`.

**Additional Runtime Check (Line 44):** `if (!this.supported) { throw ('This build of Windows does not have support for PseudoConsoles'); }`

Even on Windows, the module verifies PseudoConsole API availability before allowing operations.

**Why macOS/Linux are excluded:**

1. **PseudoConsole is Windows 10+ Exclusive**
   - Introduced in Windows 10 version 1809 (October 2018 Update)
   - Part of Windows ConPTY (Console Pseudoterminal) infrastructure
   - API: `CreatePseudoConsole()`, `ResizePseudoConsole()`, `ClosePseudoConsole()`
   - Does not exist on Windows 7/8/Server 2016 or any non-Windows platform

2. **POSIX Already Has Real PTY**
   - macOS: Uses BSD-style PTY (`/dev/ttys*`, `openpty()`, `forkpty()`)
   - Linux: Uses Unix98 PTY (`/dev/pts/*`, `posix_openpt()`, `grantpt()`, `unlockpt()`)
   - FreeBSD: Uses BSD-style PTY (same as macOS)
   - These are **native kernel-level terminal devices**, not emulation

3. **Windows-Specific Problem Being Solved**
   - Windows traditionally had limited console capabilities (no VT100/ANSI before Windows 10)
   - PseudoConsole brings Unix-like PTY functionality to Windows
   - Enables SSH servers, terminal multiplexers, and remote shells on Windows
   - Solves Windows-specific legacy console limitations

4. **Windows-Specific DLL Dependencies**
   - **Kernel32.dll** - Contains all PseudoConsole APIs
   - `CreatePseudoConsole`, `ClosePseudoConsole`, `ResizePseudoConsole`
   - `CreatePipe`, `CreateProcessW`, `ReadFile`, `WriteFile`
   - These specific APIs only exist on Windows

5. **Windows Process and Threading Model**
   - Uses Windows `STARTUPINFOEXW` structure with attribute lists (Lines 82-100)
   - `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` attribute (Line 17)
   - `EXTENDED_STARTUPINFO_PRESENT` flag (Line 18)
   - Windows-specific process creation model

**macOS/Linux Alternative:** Use native PTY:
```javascript
// Unix/Linux/macOS - native approach
var pty = require('pty.js');  // or 'node-pty'
var terminal = pty.spawn('bash', [], {
    name: 'xterm-256color',
    cols: 80,
    rows: 25
});
```

**Why Windows Needs PseudoConsole:**
- Before ConPTY: No way to programmatically create terminal sessions
- Legacy console had no VT100 support, limited ANSI codes
- Couldn't run terminal applications (vim, tmux, ssh) properly
- ConPTY enables modern terminal emulation on Windows

## Functionality

### Capability Detection

#### supported (Property) - Lines 26-41

Read-only property that indicates PseudoConsole API availability.

**Implementation:**
```javascript
Object.defineProperty(this, 'supported', {
    value: (function () {
        var gm = require('_GenericMarshal');
        var k32 = gm.CreateNativeProxy('kernel32.dll');
        try {
            k32.CreateMethod('CreatePseudoConsole');
        } catch(e) {
            return (false);
        }
        return (true);
    })()
});
```

**Returns:**
- `true` - PseudoConsole API available (Windows 10 1809+)
- `false` - PseudoConsole API not available (older Windows)

**Detection Method:**
- Attempts to create method proxy for `CreatePseudoConsole`
- If function doesn't exist in Kernel32.dll, throws exception
- Catch indicates API unavailable

**Use Case:**
```javascript
var vt = require('win-virtual-terminal');
if (vt.supported) {
    console.log('ConPTY available - can create virtual terminals');
    var terminal = vt.Start(80, 25);
} else {
    console.log('ConPTY not available - Windows 10 1809+ required');
    // Fall back to legacy console or disable terminal features
}
```

**Windows Version Detection:**
- Windows 10 1809 (Build 17763) and later: `true`
- Windows 10 1803 and earlier: `false`
- Windows Server 2019 and later: `true`
- Windows Server 2016 and earlier: `false`

---

### Terminal Creation Methods

#### Create(path, width, height) - Lines 42-193

Low-level method to create a PseudoConsole with a specified executable.

**Parameters:**
- `path` - Full path to executable (e.g., `'C:\\Windows\\System32\\cmd.exe'`)
- `width` - Terminal width in columns (default: 80)
- `height` - Terminal height in rows (default: 25)

**Returns:**
- Duplex stream object with:
  - Readable stream: Output from terminal
  - Writable stream: Input to terminal
  - `resizeTerminal(w, h)` method
  - `terminal` property: Internal terminal state
  - `_obj` property: PseudoConsole handles

**Throws:**
- `'This build of Windows does not have support for PseudoConsoles'` - If `!this.supported`
- `'Error calling CreatePseudoConsole()'` - If PseudoConsole creation fails
- `'Internal Error'` - If process creation fails

**Implementation Steps:**

**1. Pipe Creation (Lines 71-72):**
```javascript
k32.CreatePipe(ret._consoleInput, ret._input, 0, 0);
k32.CreatePipe(ret._output, ret._consoleOutput, 0, 0);
```
- Creates two anonymous pipes:
  - `_consoleInput` → `_input`: Console reads from this
  - `_output` → `_consoleOutput`: Console writes to this

**2. PseudoConsole Creation (Line 75):**
```javascript
k32.CreatePseudoConsole(
    (height << 16) | width,  // Coordinate: high word = height, low word = width
    ret._consoleInput.Deref(),
    ret._consoleOutput.Deref(),
    0,  // Flags (reserved, must be 0)
    ret._h  // Receives PseudoConsole handle
)
```
- Creates ConPTY with specified dimensions
- Attaches to input/output pipes
- Returns handle in `ret._h`

**3. STARTUPINFOEXW Structure (Lines 90-94):**
```javascript
var startupinfoex = GM.CreateVariable(GM.PointerSize == 8 ? 112 : 72);
startupinfoex.toBuffer().writeUInt32LE(GM.PointerSize == 8 ? 112 : 72, 0);
attrList.pointerBuffer().copy(startupinfoex.Deref(GM.PointerSize == 8 ? 104 : 68, GM.PointerSize).toBuffer());
```
- Creates extended startup info structure
- 32-bit: 72 bytes
- 64-bit: 112 bytes
- Includes attribute list for PseudoConsole handle

**4. Attribute List Initialization (Lines 90-98):**
```javascript
k32.InitializeProcThreadAttributeList(0, 1, 0, attrSize);  // Get size
attrList = GM.CreateVariable(attrSize.toBuffer().readUInt32LE());  // Allocate
k32.InitializeProcThreadAttributeList(attrList, 1, 0, attrSize);  // Initialize
k32.UpdateProcThreadAttribute(
    attrList, 0,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,  // 0x00020016
    ret._h.Deref(),  // PseudoConsole handle
    GM.PointerSize, 0, 0
);
```
- Creates attribute list with one attribute
- Sets PseudoConsole handle as process attribute
- Process will attach to PseudoConsole on creation

**5. Process Creation (Line 100):**
```javascript
k32.CreateProcessW(
    0,  // lpApplicationName (null = use command line)
    GM.CreateVariable(path, { wide: true }),  // lpCommandLine
    0, 0,  // Process and thread security attributes
    1,  // bInheritHandles = TRUE (inherit pipe handles)
    EXTENDED_STARTUPINFO_PRESENT,  // dwCreationFlags (0x00080000)
    0,  // lpEnvironment (null = inherit parent)
    0,  // lpCurrentDirectory (null = same as parent)
    startupinfoex,  // lpStartupInfo (extended)
    pi  // lpProcessInformation (output)
)
```
- Creates process with PseudoConsole attached
- Process inherits pipe handles
- Uses extended startup info with PseudoConsole attribute

**6. Stream Creation (Lines 108-126):**
```javascript
var ds = new duplex({
    'write': function (chunk, flush) {
        var written = require('_GenericMarshal').CreateVariable(4);
        this.terminal.k32.WriteFile(this.terminal._input.Deref(),
            require('_GenericMarshal').CreateVariable(chunk),
            chunk.length, written, 0);
        flush();
        return (true);
    },
    'final': function (flush) {
        if (this.terminal._process) {
            this.terminal._process = null;
            k32.ClosePseudoConsole(this._obj._h.Deref());
        }
        flush();
    }
});
```
- Writable: `WriteFile()` to input pipe
- Cleanup: Closes PseudoConsole when stream finalized

**7. Process Exit Handler (Lines 132-152):**
```javascript
ret._waiter = require('DescriptorEvents').addDescriptor(pi.Deref(0));
ret._waiter.on('signaled', function() {
    k32.CancelIoEx(this._obj._output.Deref(), 0);  // Cancel pending read
    this.ds.push(null);  // End stream
    if (this._obj._process) {
        this._obj._process = null;
        k32.ClosePseudoConsole(this._obj._h.Deref());
    }
    // Close all handles
    k32.CloseHandle(this._obj._input.Deref());
    k32.CloseHandle(this._obj._output.Deref());
    k32.CloseHandle(this._obj._consoleInput.Deref());
    k32.CloseHandle(this._obj._consoleOutput.Deref());
});
```
- Monitors process handle for termination
- When process exits: Cancel I/O, close PseudoConsole, cleanup handles

**8. Asynchronous Reading (Lines 169-182):**
```javascript
ds.__read = function __read() {
    this._rp = this.terminal.k32.ReadFile.async(
        this.terminal._output.Deref(),
        this._rpbuf, this._rpbuf._size,
        this._rpbufRead, 0
    );
    this._rp.then(function() {
        var len = this.parent._rpbufRead.toBuffer().readUInt32LE();
        if (len <= 0) { return; }
        this.parent.push(this.parent._rpbuf.toBuffer().slice(0, len));
        this.parent.__read();  // Continue reading
    });
    this._rp.parent = this;
};
ds.__read();  // Start reading
```
- Reads 4096 bytes at a time from output pipe
- Pushes data to readable stream
- Recursively continues reading until process exits

**Example Usage:**
```javascript
var vt = require('win-virtual-terminal');
var terminal = vt.Create('C:\\Windows\\System32\\cmd.exe', 120, 30);

// Write commands
terminal.write('dir\r\n');
terminal.write('echo Hello from ConPTY\r\n');
terminal.write('exit\r\n');

// Read output
terminal.on('data', function(chunk) {
    process.stdout.write(chunk);
});

terminal.on('end', function() {
    console.log('Terminal session ended');
});
```

---

#### resizeTerminal(w, h) - Lines 153-164

Resizes an active PseudoConsole terminal.

**Parameters:**
- `w` - New width in columns
- `h` - New height in rows

**Implementation:**
```javascript
ds.resizeTerminal = function (w, h) {
    var hr;
    if((hr=k32.ResizePseudoConsole(
        this._obj._h.Deref(),
        (h << 16) | w  // Coordinate: high word = height, low word = width
    ).Val) != 0) {
        throw ('Resize returned HRESULT: ' + hr);
    }
};
```

**Windows API:**
- Calls `ResizePseudoConsole(hPC, size)`
- Size encoded as: `(height << 16) | width`
- Returns HRESULT (0 = success)

**Use Case:**
```javascript
// User resizes terminal window
window.on('resize', function(newWidth, newHeight) {
    var cols = Math.floor(newWidth / charWidth);
    var rows = Math.floor(newHeight / charHeight);
    terminal.resizeTerminal(cols, rows);
});
```

**Error Handling:**
- Throws exception if resize fails
- HRESULT included in error message
- Common failure: PseudoConsole already closed

**Note:** Application running in terminal may not respect resize unless it handles SIGWINCH equivalent

---

#### Start(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT) - Lines 209-212

Convenience method to start Command Prompt (cmd.exe) in a PseudoConsole.

**Parameters:**
- `CONSOLE_SCREEN_WIDTH` - Terminal width (optional, default: 80)
- `CONSOLE_SCREEN_HEIGHT` - Terminal height (optional, default: 25)

**Returns:**
- Duplex stream (same as `Create()`)

**Implementation:**
```javascript
this.Start = function Start(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT) {
    return (this.Create(
        process.env['windir'] + '\\System32\\cmd.exe',
        CONSOLE_SCREEN_WIDTH,
        CONSOLE_SCREEN_HEIGHT
    ));
}
```

**Example:**
```javascript
var vt = require('win-virtual-terminal');
var cmdSession = vt.Start(100, 40);

cmdSession.write('echo %USERNAME%\r\n');
cmdSession.on('data', function(data) {
    console.log(data.toString());
});
```

---

#### PowerShellCapable() - Lines 196-206

Checks if PowerShell is available on the system.

**Returns:**
- `true` - PowerShell executable found
- `false` - PowerShell not found

**Implementation:**
```javascript
this.PowerShellCapable = function () {
    if (require('os').arch() == 'x64') {
        return (require('fs').existsSync(
            process.env['windir'] + '\\SysWow64\\WindowsPowerShell\\v1.0\\powershell.exe'
        ));
    } else {
        return (require('fs').existsSync(
            process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
        ));
    }
}
```

**Architecture Handling:**
- **x64 systems:** Checks `SysWow64\WindowsPowerShell` (32-bit PowerShell)
- **x86 systems:** Checks `System32\WindowsPowerShell`

**Use Case:**
```javascript
var vt = require('win-virtual-terminal');
if (vt.PowerShellCapable()) {
    var ps = vt.StartPowerShell(120, 30);
} else {
    console.log('PowerShell not available, using cmd.exe');
    var cmd = vt.Start(120, 30);
}
```

---

#### StartPowerShell(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT) - Lines 215-232

Convenience method to start PowerShell in a PseudoConsole.

**Parameters:**
- `CONSOLE_SCREEN_WIDTH` - Terminal width (optional, default: 80)
- `CONSOLE_SCREEN_HEIGHT` - Terminal height (optional, default: 25)

**Returns:**
- Duplex stream (same as `Create()`)

**Implementation:**
```javascript
this.StartPowerShell = function StartPowerShell(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT) {
    if (require('os').arch() == 'x64') {
        if (require('fs').existsSync(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe')) {
            return (this.Create(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT));
        } else {
            return (this.Create(process.env['windir'] + '\\SysWow64\\WindowsPowerShell\\v1.0\\powershell.exe', CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT));
        }
    } else {
        return (this.Create(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT));
    }
}
```

**Architecture Handling:**
- **x64 systems:**
  - Prefers 64-bit PowerShell (`System32\WindowsPowerShell`)
  - Falls back to 32-bit (`SysWow64\WindowsPowerShell`)
- **x86 systems:**
  - Uses `System32\WindowsPowerShell` (32-bit only)

**Example:**
```javascript
var vt = require('win-virtual-terminal');
var ps = vt.StartPowerShell(120, 30);

ps.write('Get-Process | Select-Object -First 5\r\n');
ps.write('exit\r\n');

ps.on('data', function(chunk) {
    process.stdout.write(chunk);
});
```

## Dependencies

### Native Module Dependencies

#### _GenericMarshal (Lines 29, 48)

```javascript
var gm = require('_GenericMarshal');
var GM = require('_GenericMarshal');
```

**Purpose:** FFI (Foreign Function Interface) library for calling Windows DLLs

**Capabilities:**
- JavaScript to native DLL function calls
- Memory marshaling and buffer management
- Pointer arithmetic and structure packing
- Wide character string support
- Asynchronous method execution (`.async()`)

**Source:** `/microscript/ILibDuktape_GenericMarshal.c`

---

### Windows System DLL Dependencies

#### Kernel32.dll (Lines 30, 49-63)

```javascript
var k32 = GM.CreateNativeProxy('kernel32.dll');
```

**Methods Used:**

**PseudoConsole Management:**
- **CreatePseudoConsole()** - Line 33 (detection), 53, 75
  - **Purpose:** Creates new PseudoConsole instance
  - **Parameters:** `CreatePseudoConsole(COORD size, HANDLE hInput, HANDLE hOutput, DWORD dwFlags, HPCON* phPC)`
  - **Documentation:** https://learn.microsoft.com/en-us/windows/console/createpseudoconsole
  - **Available:** Windows 10 1809+ only

- **ResizePseudoConsole()** - Line 59, 158
  - **Purpose:** Changes PseudoConsole dimensions
  - **Parameters:** `ResizePseudoConsole(HPCON hPC, COORD size)`
  - **Documentation:** https://learn.microsoft.com/en-us/windows/console/resizepseudoconsole

- **ClosePseudoConsole()** - Line 55, 122, 145
  - **Purpose:** Closes and destroys PseudoConsole
  - **Parameters:** `ClosePseudoConsole(HPCON hPC)`
  - **Documentation:** https://learn.microsoft.com/en-us/windows/console/closepseudoconsole
  - **Note:** Waits for attached process to exit

**Pipe Operations:**
- **CreatePipe()** - Line 51, 71-72
  - **Purpose:** Creates anonymous pipe for I/O redirection
  - **Parameters:** `CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize)`
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe

- **ReadFile()** - Line 62, 172
  - **Purpose:** Reads data from pipe (output from console)
  - **Parameters:** `ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)`
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
  - **Used:** Asynchronously via `.async()` method

- **WriteFile()** - Line 61, 113
  - **Purpose:** Writes data to pipe (input to console)
  - **Parameters:** `WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)`
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile

- **CancelIoEx()** - Line 50, 137
  - **Purpose:** Cancels pending asynchronous I/O operations
  - **Parameters:** `CancelIoEx(HANDLE hFile, LPOVERLAPPED lpOverlapped)`
  - **Used:** Cancel pending ReadFile when process exits
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/fileio/cancelioex-func

- **CloseHandle()** - Line 54, 147-151
  - **Purpose:** Closes handle to kernel object
  - **Parameters:** `CloseHandle(HANDLE hObject)`
  - **Used:** Cleanup pipes and process handle
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle

**Process Management:**
- **CreateProcessW()** - Line 52, 100
  - **Purpose:** Creates new process attached to PseudoConsole
  - **Parameters:** Wide character version, 10 parameters including STARTUPINFOEXW
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw

- **TerminateProcess()** - Line 63
  - **Purpose:** Forcefully terminate process
  - **Parameters:** `TerminateProcess(HANDLE hProcess, UINT uExitCode)`
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
  - **Note:** Method created but not used in current implementation

**Process Thread Attributes:**
- **InitializeProcThreadAttributeList()** - Line 58, 90, 96
  - **Purpose:** Initializes attribute list for process creation
  - **Parameters:** `InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize)`
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
  - **Usage:** Called twice - once to get size, once to initialize

- **UpdateProcThreadAttribute()** - Line 60, 98
  - **Purpose:** Updates attribute in list
  - **Parameters:** `UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize)`
  - **Used:** Set `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` attribute
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute

**Memory Management:**
- **GetProcessHeap()** - Line 56
  - **Purpose:** Retrieves heap handle for current process
  - **Returns:** HANDLE to default heap
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheap
  - **Note:** Method created but not used in current implementation

- **HeapAlloc()** - Line 57
  - **Purpose:** Allocates memory from heap
  - **Parameters:** `HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)`
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
  - **Note:** Method created but not used in current implementation

---

### Module Dependencies

#### stream (Duplex) - Line 21

```javascript
var duplex = require('stream').Duplex;
```

**Purpose:** Base class for bidirectional stream

**Used by:** Terminal stream returned by `Create()`

**Capabilities:**
- Readable stream interface (output from terminal)
- Writable stream interface (input to terminal)
- Backpressure handling
- Event-based data flow

**Implementation (Lines 108-126):**
```javascript
var ds = new duplex({
    'write': function (chunk, flush) { /* Write to terminal */ },
    'final': function (flush) { /* Cleanup on end */ }
});
```

---

#### DescriptorEvents - Line 132

```javascript
ret._waiter = require('DescriptorEvents').addDescriptor(pi.Deref(0));
```

**Purpose:** Monitors Windows kernel objects for signaling

**Used by:** Process exit detection

**Functionality:**
- Adds process handle to descriptor set
- Emits 'signaled' event when process exits
- Enables asynchronous cleanup when process terminates

**Event Handler (Lines 135-152):**
```javascript
ret._waiter.on('signaled', function() {
    // Process exited - cleanup resources
});
```

---

#### os - Line 198

```javascript
if (require('os').arch() == 'x64')
```

**Purpose:** Detect system architecture

**Used by:** `PowerShellCapable()` and `StartPowerShell()`

**Functionality:**
- Returns 'x64' for 64-bit systems
- Returns 'ia32' for 32-bit systems
- Determines PowerShell path

---

#### fs - Lines 200, 219

```javascript
require('fs').existsSync(path)
```

**Purpose:** Check file existence

**Used by:** PowerShell executable detection

**Functionality:**
- Synchronous file existence check
- Returns true if file exists
- Used to verify PowerShell installation

---

### Windows API Constants

**Process Thread Attribute (Line 17):**
```javascript
var PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;
```
- Attribute ID for PseudoConsole handle
- Used with `UpdateProcThreadAttribute()`
- Tells Windows to attach process to PseudoConsole

**Process Creation Flag (Line 18):**
```javascript
var EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
```
- Indicates STARTUPINFOEX structure in use
- Required when using process attribute lists
- Passed to `CreateProcessW()`

**Memory Allocation Flag (Line 19):**
```javascript
var HEAP_ZERO_MEMORY = 0x00000008;
```
- Zero-initialize allocated memory
- Note: Defined but not used in current implementation

---

### Dependency Chain Summary

```
win-virtual-terminal.js
├─── _GenericMarshal (Lines 29, 48) - FFI library
│    └─── Native marshaling layer
├─── Kernel32.dll (Lines 30, 49-63) - Windows core
│    ├─── PseudoConsole APIs
│    │    ├─── CreatePseudoConsole() - Create ConPTY
│    │    ├─── ResizePseudoConsole() - Resize terminal
│    │    └─── ClosePseudoConsole() - Destroy ConPTY
│    ├─── Pipe APIs
│    │    ├─── CreatePipe() - Create I/O pipes
│    │    ├─── ReadFile() - Read output
│    │    ├─── WriteFile() - Write input
│    │    └─── CancelIoEx() - Cancel pending I/O
│    ├─── Process APIs
│    │    ├─── CreateProcessW() - Start process
│    │    ├─── InitializeProcThreadAttributeList() - Setup attributes
│    │    ├─── UpdateProcThreadAttribute() - Set PseudoConsole
│    │    └─── CloseHandle() - Cleanup
│    └─── Memory APIs (unused)
├─── stream (Line 21) - Duplex stream
│    └─── Bidirectional data flow
├─── DescriptorEvents (Line 132) - Process monitoring
│    └─── Exit detection
├─── os (Line 198) - Architecture detection
│    └─── PowerShell path selection
└─── fs (Lines 200, 219) - File system
     └─── PowerShell existence check
```

## Technical Implementation Details

### PseudoConsole Architecture

**Windows ConPTY Stack:**
```
Application (JavaScript)
    ↕ (WriteFile/ReadFile)
Named Pipes
    ↕
PseudoConsole (ConPTY)
    ↕ (VT100/ANSI processing)
Console Process (cmd.exe, powershell.exe, etc.)
    ↕
Actual Program Output
```

**Data Flow:**

**Input (Keyboard to Application):**
1. JavaScript writes data to stream (`terminal.write('dir\r\n')`)
2. Stream's `write()` method calls `WriteFile()`
3. Data goes to `_input` pipe
4. PseudoConsole reads from `_consoleInput` end
5. Console process receives input as if from keyboard
6. Application in console processes input

**Output (Application to Screen):**
1. Application in console writes to stdout/stderr
2. PseudoConsole captures output on `_consoleOutput` pipe
3. ConPTY processes VT100/ANSI sequences
4. Output available on `_output` pipe
5. Asynchronous `ReadFile()` retrieves data
6. Stream pushes data to JavaScript (`'data'` event)
7. JavaScript can display or process output

---

### Memory and Structure Management

**STARTUPINFOEXW Structure:**
- **32-bit:** 72 bytes total
  - STARTUPINFOW: 68 bytes
  - lpAttributeList pointer: 4 bytes (at offset 68)
- **64-bit:** 112 bytes total
  - STARTUPINFOW: 104 bytes
  - lpAttributeList pointer: 8 bytes (at offset 104)

**PROCESS_INFORMATION Structure (Line 68):**
- **32-bit:** 16 bytes
  - hProcess: 4 bytes
  - hThread: 4 bytes
  - dwProcessId: 4 bytes
  - dwThreadId: 4 bytes
- **64-bit:** 24 bytes
  - hProcess: 8 bytes
  - hThread: 8 bytes
  - dwProcessId: 4 bytes
  - dwThreadId: 4 bytes

**Process ID Extraction (Line 107):**
```javascript
ret._pid = pi.Deref(GM.PointerSize == 4 ? 8 : 16, 4).toBuffer().readUInt32LE();
```
- 32-bit: Offset 8
- 64-bit: Offset 16

---

### Asynchronous I/O

**Read Loop (Lines 169-182):**
```javascript
this._rp = this.terminal.k32.ReadFile.async(
    this.terminal._output.Deref(),
    this._rpbuf,  // 4096 byte buffer
    this._rpbuf._size,
    this._rpbufRead,
    0  // lpOverlapped = NULL (synchronous behavior with async wrapper)
);
```

**How it Works:**
- `.async()` runs ReadFile on background thread
- Promise resolves when read completes
- No blocking of main JavaScript thread
- Recursive calls continue reading until process exits

**Cancellation:**
- When process exits, `CancelIoEx()` called (Line 137)
- Pending ReadFile operation cancelled
- Promise may reject or resolve with 0 bytes
- Stream ends gracefully

---

### Resource Lifecycle

**Creation → Operation → Cleanup:**

**Creation (Lines 65-184):**
1. Create pipes
2. Create PseudoConsole
3. Create attribute list
4. Create process with PseudoConsole attached
5. Create duplex stream
6. Start asynchronous reading

**Operation:**
1. Write data via stream.write()
2. Read data via stream.on('data')
3. Resize terminal via stream.resizeTerminal()
4. Process runs attached to PseudoConsole

**Cleanup (Lines 135-152 or 117-125):**

**On Process Exit (automatic):**
```javascript
ret._waiter.on('signaled', function() {
    k32.CancelIoEx(this._obj._output.Deref(), 0);
    this.ds.push(null);  // Signal stream end
    if (this._obj._process) {
        this._obj._process = null;
        k32.ClosePseudoConsole(this._obj._h.Deref());
    }
    k32.CloseHandle(this._obj._input.Deref());
    k32.CloseHandle(this._obj._output.Deref());
    k32.CloseHandle(this._obj._consoleInput.Deref());
    k32.CloseHandle(this._obj._consoleOutput.Deref());
});
```

**On Stream End (manual):**
```javascript
'final': function (flush) {
    if (this.terminal._process) {
        this.terminal._process = null;
        k32.ClosePseudoConsole(this._obj._h.Deref());
    }
    flush();
}
```

**Critical Order:**
1. Cancel pending I/O first
2. Close PseudoConsole (waits for process exit)
3. Close pipe handles
4. Stream ends

---

### Error Handling

**No Support Detection:**
```javascript
if (!this.supported) {
    throw ('This build of Windows does not have support for PseudoConsoles');
}
```

**PseudoConsole Creation Failure:**
```javascript
if (k32.CreatePseudoConsole(...).Val != 0) {
    throw ('Error calling CreatePseudoConsole()');
}
```

**Process Creation Failure:**
```javascript
if (k32.CreateProcessW(...).Val == 0) {
    throw ('Internal Error');
}
```

**Resize Failure:**
```javascript
if((hr=k32.ResizePseudoConsole(...).Val) != 0) {
    throw ('Resize returned HRESULT: ' + hr);
}
```

**Best Practice:**
```javascript
try {
    var terminal = vt.Create('C:\\Windows\\System32\\cmd.exe', 80, 25);
} catch(e) {
    console.error('Failed to create terminal:', e);
    // Fall back to alternative approach
}
```

## Known Usage Patterns

### SSH Server Terminal Session

```javascript
var vt = require('win-virtual-terminal');

sshConnection.on('session', function(accept, reject) {
    var session = accept();
    session.on('pty', function(accept, reject, info) {
        var ptyStream = accept();

        // Create PseudoConsole with requested dimensions
        var terminal = vt.Start(info.cols, info.rows);

        // Pipe data both ways
        ptyStream.pipe(terminal).pipe(ptyStream);

        // Handle resize
        ptyStream.on('window-change', function(info) {
            terminal.resizeTerminal(info.cols, info.rows);
        });
    });
});
```

### Terminal Emulator

```javascript
var vt = require('win-virtual-terminal');
var terminal = vt.Start(80, 25);

// Send to web browser via WebSocket
terminal.on('data', function(chunk) {
    websocket.send(chunk);
});

// Receive from web browser
websocket.on('message', function(data) {
    terminal.write(data);
});

// Handle browser terminal resize
websocket.on('resize', function(cols, rows) {
    terminal.resizeTerminal(cols, rows);
});
```

### PowerShell Remote Session

```javascript
var vt = require('win-virtual-terminal');

if (vt.PowerShellCapable()) {
    var ps = vt.StartPowerShell(120, 30);

    // Execute command
    ps.write('Get-WmiObject Win32_OperatingSystem\r\n');

    // Collect output
    var output = '';
    ps.on('data', function(chunk) {
        output += chunk.toString();
    });

    // Exit PowerShell
    setTimeout(function() {
        ps.write('exit\r\n');
    }, 5000);
}
```

## Limitations

### Windows Version Requirement

**Windows 10 1809+ Required:**
- Released: October 2018
- Build: 17763
- Earlier versions: API doesn't exist, module won't work

**Windows Server 2019+ Required:**
- Server 2016 and earlier: No PseudoConsole support

**Detection Required:**
```javascript
if (!vt.supported) {
    // Fall back to legacy console or alternative approach
}
```

### API Limitations

1. **No Tab Completion Events:** Can't intercept Tab key like native PTY
2. **Limited Control Sequences:** Some advanced VT sequences may not work
3. **Process Attachment:** Can only attach one process per PseudoConsole
4. **Resize Lag:** Application must handle resize signals (not automatic)

### Performance Considerations

1. **Pipe Overhead:** All I/O goes through pipes (slower than direct console)
2. **VT Processing:** ConPTY adds latency for VT100/ANSI processing
3. **Async Read Loop:** Recursive promise chain has some overhead
4. **4KB Buffer:** Fixed 4096 byte read buffer, may cause delays for large outputs

### Security Considerations

1. **Handle Inheritance:** Child process inherits pipe handles (bInheritHandles=TRUE)
2. **No Sandboxing:** Process runs with same privileges as parent
3. **Input Validation:** No built-in sanitization of terminal input
4. **Command Injection:** If constructing command from user input, must sanitize

## Best Practices

### 1. Always Check Support

```javascript
var vt = require('win-virtual-terminal');
if (!vt || !vt.supported) {
    console.log('ConPTY not available');
    return;
}
```

### 2. Handle Process Exit

```javascript
terminal.on('end', function() {
    console.log('Terminal session ended');
    cleanup();
});
```

### 3. Implement Resize Handling

```javascript
window.on('resize', function(width, height) {
    var cols = Math.floor(width / charWidth);
    var rows = Math.floor(height / charHeight);
    try {
        terminal.resizeTerminal(cols, rows);
    } catch(e) {
        console.error('Resize failed:', e);
    }
});
```

### 4. Graceful Degradation

```javascript
var terminal;
if (vt && vt.supported) {
    terminal = vt.Start(80, 25);
} else {
    // Fall back to child_process.spawn
    terminal = require('child_process').spawn('cmd.exe');
}
```

### 5. Clean Shutdown

```javascript
process.on('SIGINT', function() {
    terminal.write('exit\r\n');
    setTimeout(function() {
        process.exit(0);
    }, 1000);
});
```

## License

**Apache License 2.0**
Copyright 2019 Intel Corporation

## Summary

win-virtual-terminal.js is a Windows 10 1809+ exclusive module that provides PseudoConsole (ConPTY) functionality for creating terminal sessions with full VT100/ANSI support. It enables modern terminal emulation, SSH servers, and remote shell capabilities on Windows by bridging the gap between Windows console applications and Unix-style pseudo-terminals.

**Explicitly excludes all non-Windows platforms** because:
- Relies entirely on Windows 10 1809+ exclusive APIs (CreatePseudoConsole, ResizePseudoConsole, ClosePseudoConsole)
- PseudoConsole is a Windows-specific solution to Windows-specific console limitations
- macOS and Linux already have native PTY support via kernel-level `/dev/pts` and `/dev/tty` devices
- Uses Windows-specific process creation with STARTUPINFOEXW and process attribute lists
- Platform check on line 235 prevents export on non-Windows systems
- Capability check on line 44 prevents usage even on older Windows versions (7/8/Server 2016)
- No equivalent needed on Unix-like systems which have had PTY for decades

The module solves a uniquely Windows problem: enabling terminal emulation for applications expecting Unix-like terminal capabilities. On macOS/Linux, native PTY libraries (`node-pty`, `pty.js`) should be used instead, as they interface with the operating system's built-in pseudo-terminal infrastructure.
