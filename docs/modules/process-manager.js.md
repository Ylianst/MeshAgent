# process-manager.js

Cross-platform process enumeration and management module for MeshAgent that provides unified APIs for querying running processes and retrieving detailed process information on Windows, Linux, FreeBSD, and macOS systems.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support using native Win32 APIs via kernel32.dll
- Linux - Full support using ps command with /proc filesystem
- FreeBSD - Full support using ps command with /proc filesystem
- **macOS (darwin)** - Full support using ps command

**Platform-Specific Implementations:**

This module implements platform-specific strategies for each operating system:

1. **Windows** - Uses native Win32 API calls through Generic Marshal (kernel32.dll) to enumerate processes via CreateToolhelp32Snapshot, providing direct access to process structures with full path resolution via QueryFullProcessImageNameW.

2. **Linux** - Uses shell scripts with ps command combined with awk text processing to parse process information, with fallback mechanisms for systems with limited ps functionality. Reads /proc/[pid]/cmdline for accurate command line retrieval.

3. **FreeBSD** - Similar to Linux implementation using ps with awk parsing, enhanced with /proc/[pid]/cmdline reading for detailed command information.

4. **macOS** - Uses ps -axo (all processes, extended output) with awk parsing to extract process ID, user, and command information. This is the simplest implementation as macOS ps provides consistent, reliable output.

**macOS Support:**

macOS is fully supported with dedicated implementation (lines 202-237). The module uses BSD-style ps command with specific flags optimized for macOS:
- `ps -axo pid -o user -o command` - Lists all processes with PID, user, and full command
- Output parsing via awk to generate JSON structure
- Unlike FreeBSD, macOS does not use /proc filesystem for additional command line details
- macOS ps output is reliable and does not require fallback mechanisms

## Functionality

### Purpose

The process-manager module serves as a cross-platform abstraction layer for process enumeration and inspection. It provides:

- **Unified API** for listing all running processes across operating systems
- **Process Information Retrieval** including PID, command, path, and user ownership
- **Detailed Process Inspection** for specific PIDs (Linux/Windows)
- **Process Search** capabilities to find processes by name or path
- **Promise-Based Async Interface** for non-blocking process queries

This module is used throughout MeshAgent for:
- Monitoring running services and detecting conflicts
- Process ownership verification
- System status reporting
- Security auditing and access control
- Remote process management features

### Key Functions

#### processManager() Constructor - Lines 33-59

**Purpose:** Initializes the process manager with platform-specific native bindings or command execution capabilities.

**Platform Behavior:**

**Windows (lines 39-50):**
- Creates native proxy to kernel32.dll via Generic Marshal
- Binds Win32 API methods:
  - `CreateToolhelp32Snapshot` - Creates process snapshot
  - `Process32FirstW/Process32NextW` - Iterates processes
  - `Module32FirstW/Module32NextW` - Enumerates loaded modules
  - `OpenProcess` - Opens process handle
  - `QueryFullProcessImageNameW` - Gets full executable path
  - `CloseHandle` - Releases handles
  - `GetLastError` - Error code retrieval

**Unix-like (Linux/FreeBSD/macOS, lines 51-55):**
- Requires child_process module for executing shell commands
- Stores reference as `this._childProcess`
- All process queries executed via shell scripts

**Unsupported platforms (lines 56-58):**
- Throws exception with platform name

---

#### enumerateProcesses() - Lines 60-71

**Purpose:** Promise-based wrapper for getProcesses() that returns a promise resolving to the process list.

**Process:**
```javascript
var ret = new promise(function (res, rej) {
    this._res = res;
    this._rej = rej;
});
ret.callback = function callback(ps) {
    callback.prom._res(ps);
}
ret.callback.prom = ret;
this.getProcesses(ret.callback);
return (ret);
```

**Returns:** Promise that resolves with process object (PID -> process info mapping)

**Platform Behavior:**
- All platforms supported
- Provides async interface for UI/event-driven code

---

#### getProcesses(callback) - Lines 73-239

**Purpose:** Core function that enumerates all running processes and returns detailed information.

**Windows Implementation (lines 80-118):**
```javascript
// 1. Create process snapshot
var h = this._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

// 2. Allocate structures
var info = GM.CreateVariable(GM.PointerSize == 8 ? 568 : 556); // x64/x86
var fullpath = GM.CreateVariable(2048);

// 3. Iterate processes
info.toBuffer().writeUInt32LE(info._size, 0);
var nextProcess = this._kernel32.Process32FirstW(h, info);
while (nextProcess.Val) {
    // 4. Extract PID and command name
    pid = info.Deref(8, 4).toBuffer().readUInt32LE(0);
    retVal[pid] = {
        pid: pid,
        cmd: info.Deref(GM.PointerSize == 4 ? 36 : 44, 260).Wide2UTF8
    };

    // 5. Get full path
    if ((ph = this._kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)).Val != -1) {
        pathSize.toBuffer().writeUInt32LE(fullpath._size);
        if (this._kernel32.QueryFullProcessImageNameW(ph, 0, fullpath, pathSize).Val != 0) {
            retVal[pid].path = fullpath.Wide2UTF8;
        }
        this._kernel32.CloseHandle(ph);
    }

    // 6. Get process owner
    try {
        retVal[pid].user = require('user-sessions').getProcessOwnerName(pid).name;
    } catch(ee) {}

    nextProcess = this._kernel32.Process32NextW(h, info);
}
this._kernel32.CloseHandle(h);
```

**Linux Implementation (lines 119-201):**

Uses complex awk script with ps command to extract process information:

```bash
ps -e -o pid -o user:99 -o args | tr '\n' '\t' | awk -F"\t" '{
    printf "{";
    for(i=1;i<NF;++i) {
        split($i,A," ");
        gsub(/[ \t]*[0-9]+[ \t]*[^ ^\t]+[ \t]+/,"",$i);
        gsub(/\\/,"\\\\",$i);
        gsub(/"/,"\\\"",$i);
        if($i !~ /^awk /) {
            printf "%s\"%s\":{\"pid\":\"%s\",\"user\":\"%s\",\"cmd\":\"%s\"}",
                (i==1?"":","),A[1],A[1],A[2],$i;
        }
    }
    printf "}";
}'
```

**Fallback mechanism (lines 145-167):**
- If primary method fails (stderr output), uses simplified ps parsing
- Reads /proc/[pid]/cmdline for accurate command information
- Replaces null bytes with spaces in command line

**FreeBSD/macOS Implementation (lines 202-237):**

```bash
ps -axo pid -o user -o command | tr '\n' '\t' | awk -F"\t" '{
    printf "{";
    for(i=2;i<NF;++i) {
        gsub(/^[ ]+/,"",$i);
        split($i,tok," ");
        pid=tok[1];
        user=tok[2];
        cmd=substr($i,length(tok[1])+length(tok[2])+2);
        gsub(/\\/,"\\\\&",cmd);
        gsub(/"/,"\\\\&",cmd);
        gsub(/^[ ]+/,"",cmd);
        printf "%s\"%s\":{\"pid\":\"%s\",\"user\":\"%s\",\"cmd\":\"%s\"}",
            (i!=2?",":""),pid,pid,user,cmd;
    }
    printf "}";
}'
```

**FreeBSD enhancement (lines 215-232):**
- Reads /proc/[pid]/cmdline for more accurate command information
- Replaces null terminators with spaces

**Returns:** Object structure:
```javascript
{
    "1234": {
        "pid": 1234,
        "cmd": "node server.js",
        "user": "meshagent",
        "path": "/usr/bin/node"  // Windows only
    },
    // ... more processes
}
```

**Platform Behavior:**
- **Windows:** Full path always included, uses native APIs, fastest performance
- **Linux:** Best compatibility with fallback, reads /proc for accuracy
- **FreeBSD:** Enhanced with /proc reading when available
- **macOS:** Clean implementation, reliable ps output, no fallback needed

---

#### getProcessInfo(pid) - Lines 242-320

**Purpose:** Retrieves detailed information about a specific process by PID.

**Linux Implementation (lines 249-260):**
```javascript
// Reads /proc/[pid]/status file
var status = require('fs').readFileSync('/proc/' + pid + '/status');
var info = {};
var lines = status.toString().split('\n');
for(var i=0;i<lines.length;++i) {
    var tokens = lines[i].split(':');
    if (tokens.length > 1) { tokens[1] = tokens[1].trim(); }
    info[tokens[0]] = tokens[1];
}
return (info);
```

**Returns:** Object with process status fields:
```javascript
{
    "Name": "node",
    "Umask": "0022",
    "State": "R (running)",
    "Tgid": "1234",
    "Ngid": "0",
    "Pid": "1234",
    "PPid": "1",
    "TracerPid": "0",
    "Uid": "1000\t1000\t1000\t1000",
    "Gid": "1000\t1000\t1000\t1000",
    "VmSize": "12345 kB",
    "VmRSS": "6789 kB",
    // ... many more fields
}
```

**Windows Implementation (lines 261-318):**

Uses PowerShell via named pipe for detailed process query:

```javascript
// 1. Create named pipe for IPC
ret._path = '\\\\.\\pipe\\mesh-' + require('uuid/v4')();
ret.server.listen({ path: ret._path });

// 2. Launch PowerShell
ret.child = require('child_process').execFile(
    process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    ['powershell', '-noprofile', '-nologo', '-command', '-'],
    {}
);

// 3. Execute Get-Process command
ret.child.stdin.write('[reflection.Assembly]::LoadWithPartialName("system.core")\r\n');
ret.child.stdin.write('$pipe = new-object System.IO.Pipes.NamedPipeClientStream(".", "' + ret._clientpath + '", 3);\r\n');
ret.child.stdin.write('$pipe.Connect(); \r\n');
ret.child.stdin.write('$sw = new-object System.IO.StreamWriter($pipe);\r\n');
ret.child.stdin.write('$X = Get-Process -IncludeUserName -id ' + pid + ' | ConvertTo-CSV -NoTypeInformation\r\n');
ret.child.stdin.write('$sw.WriteLine($X[0]); $sw.Flush();\r\n');
ret.child.stdin.write('$sw.WriteLine($X[1]); $sw.Flush();\r\n');

// 4. Parse CSV response
var keys = J[0].split(',');
var values = J[1].split(',');
for (var i = 0; i < keys.length; ++i) {
    if (keys[i][0] == '"') {
        keys[i] = keys[i].substring(1, keys[i].length - 1);
    }
    if (values[i][0] == '"') {
        values[i] = values[i].substring(1, values[i].length - 1);
    }
    if (values[i] != '') {
        rj[keys[i]] = values[i];
    }
}
```

**Returns:** Promise that resolves with PowerShell Get-Process output including:
- Process name, ID, handle count
- CPU time, working set size
- Start time, user name
- Process priority, responding status

**Platform Behavior:**
- **Linux only:** Direct synchronous read from /proc filesystem
- **Windows only:** Async PowerShell query via named pipe, returns promise
- **FreeBSD/macOS:** Not implemented (throws exception)

---

#### getProcess(cmd) - Lines 338-350

**Purpose:** Finds all PIDs running a specific command (Unix systems only).

**Implementation (lines 338-350):**
```bash
pgrep gnome-session | tr '\n' '\t' | awk -F"\t" '{
    printf "[";
    for(i=1;i<NF;++i) {
        if(i>1) { printf ","; }
        printf "%d", $i;
    }
    printf "]";
}'
```

**Prerequisites:**
- Requires pgrep utility (detected at line 325-334)
- Only created if `this._pgrep` path is non-empty
- Unix-like systems only (Linux/FreeBSD/macOS)

**Returns:** Array of PIDs matching the command name

**Platform Behavior:**
- **Linux/FreeBSD/macOS:** Uses pgrep if available
- **Windows:** Not available (method not defined)
- Throws exception if command not found

---

#### getProcessEx(cmd, options) - Lines 353-390

**Purpose:** Advanced process search with optional path filtering.

**Windows Implementation (lines 355-373):**
```javascript
var result = [];
this.getProcesses(function (j) {
    var i;
    for(i in j) {
        if(j[i].cmd.toLowerCase() == cmd.toLowerCase()) {
            if (options == null || options.path.toLowerCase() == j[i].path.toLowerCase()) {
                result.push(j[i].pid);
            }
        }
    }
});
return (result);
```

**Unix Implementation (lines 375-389):**
```bash
ps -ax -o pid -o command | grep [cmd] | tr '\n' '\t' | awk -F"\t" '{
    printf "[";
    for(i=1;i<NF;++i) {
        split($i,r," ");
        if(r[2]!="grep") {
            if(i>1) { printf ","; }
            printf "%s", r[1];
        }
    }
    printf "]";
}'
```

**Parameters:**
- `cmd` (string) - Command name to search for
- `options` (object, optional) - Filter options:
  - `path` (string) - Full path to executable (Windows only)

**Returns:** Array of PIDs matching the criteria

**Platform Behavior:**
- **Windows:** Searches by command name, optionally filters by full path
- **Unix:** Uses ps + grep, filters out grep itself from results
- **All platforms:** Case-insensitive on Windows, case-sensitive on Unix

---

### Usage Examples

#### Basic Process Enumeration

```javascript
var processManager = require('process-manager');

// Callback-based
processManager.getProcesses(function(processes) {
    for(var pid in processes) {
        console.log('PID: ' + pid +
                    ', User: ' + processes[pid].user +
                    ', Command: ' + processes[pid].cmd);
    }
});

// Promise-based
processManager.enumerateProcesses().then(function(processes) {
    console.log('Found ' + Object.keys(processes).length + ' processes');

    // Find all node processes
    for(var pid in processes) {
        if(processes[pid].cmd.indexOf('node') >= 0) {
            console.log('Node process: ' + pid);
        }
    }
});
```

#### Get Specific Process Info

```javascript
// Linux only - get detailed status
try {
    var info = processManager.getProcessInfo(1234);
    console.log('Process Name: ' + info.Name);
    console.log('Memory: ' + info.VmRSS);
    console.log('State: ' + info.State);
} catch(e) {
    console.log('Process not found or not supported on this platform');
}

// Windows - async promise-based
processManager.getProcessInfo(1234).then(function(info) {
    console.log('Process: ' + info.ProcessName);
    console.log('User: ' + info.UserName);
    console.log('CPU Time: ' + info.CPU);
}).catch(function(err) {
    console.log('Error: ' + err);
});
```

#### Search for Processes

```javascript
// Unix systems with pgrep
try {
    var pids = processManager.getProcess('gnome-session');
    console.log('Found gnome-session at PIDs: ' + pids.join(', '));
} catch(e) {
    console.log('gnome-session not running');
}

// Cross-platform search
var meshPids = processManager.getProcessEx('meshagent');
console.log('MeshAgent PIDs: ' + meshPids);

// Windows with path filtering
var nodePids = processManager.getProcessEx('node.exe', {
    path: 'C:\\Program Files\\nodejs\\node.exe'
});
```

#### Check if Service is Running

```javascript
function isServiceRunning(serviceName) {
    try {
        var processes = {};
        processManager.getProcesses(function(p) { processes = p; });

        for(var pid in processes) {
            if(processes[pid].cmd.toLowerCase().indexOf(serviceName.toLowerCase()) >= 0) {
                return true;
            }
        }
        return false;
    } catch(e) {
        return false;
    }
}

if(isServiceRunning('meshagent')) {
    console.log('MeshAgent is running');
}
```

### Dependencies

#### Node.js Core Modules
- None directly required (platform-specific modules loaded conditionally)

#### MeshAgent Module Dependencies

**Cross-Platform Required:**
- **`promise`** (line 25, 62, 262, 563)
  - Custom promise implementation
  - Used for async getProcessInfo on Windows
  - Used for enumerateProcesses wrapper

**Windows-Specific (win32):**
- **`_GenericMarshal`** (line 18)
  - Native code binding framework
  - Creates proxy to kernel32.dll
  - Marshals Win32 API calls and structures
  - Methods: CreateNativeProxy, CreateVariable, CreateMethod

- **`user-sessions`** (line 108)
  - User and session management
  - Method: `getProcessOwnerName(pid)` - Returns process owner details
  - Returns: `{ name: "username", domain: "domain" }`

**Unix-Specific (Linux/FreeBSD/macOS):**
- **`child_process`** (line 54, 73, 122, 148, 204, 269, 327, 340, 375)
  - Executes shell commands
  - Method: `execFile(path, args)` - Spawns shell process
  - Used for all ps/awk/grep operations

- **`fs`** (line 121, 183, 221, 250)
  - File system access
  - Method: `existsSync(path)` - Check file existence
  - Method: `readFileSync(path)` - Read file contents
  - Used to read /proc filesystem and check file existence

**Windows PowerShell Dependencies (getProcessInfo):**
- **`net`** (line 263)
  - Network module for named pipe creation
  - Method: `createServer()` - Creates IPC server
  - Used for PowerShell communication

- **`uuid/v4`** (line 264)
  - UUID generation
  - Generates unique pipe names
  - Prevents pipe name collisions

#### System Binary Dependencies

**Windows:**
- **kernel32.dll** - Win32 API library (always present)
- **PowerShell** - Located at `%windir%\System32\WindowsPowerShell\v1.0\powershell.exe`
  - Required for getProcessInfo functionality
  - Used to execute Get-Process cmdlet

**Linux:**
- **ps** - Process status command (/bin/ps)
- **awk** - Text processing (/usr/bin/awk or /bin/awk)
- **tr** - Character translation utility
- **grep** - Text search (optional, for getProcessEx)
- **pgrep** - Process grep utility (optional, for getProcess)
- **/proc filesystem** - Mounted at /proc (kernel virtual filesystem)
  - /proc/[pid]/status - Process status information
  - /proc/[pid]/cmdline - Command line with arguments

**FreeBSD:**
- **ps** - BSD process status command
- **awk** - Text processing
- **tr** - Character translation
- **/proc filesystem** - Optional, enhanced if mounted
  - Not mounted by default on FreeBSD
  - Mount with: `mount -t procfs proc /proc`

**macOS:**
- **ps** - BSD process status command (/bin/ps)
- **awk** - Text processing (/usr/bin/awk)
- **tr** - Character translation utility (/usr/bin/tr)
- **sh** - Bourne shell (/bin/sh)
- Does NOT use /proc filesystem (not available on macOS)

### Code Structure

The module is organized into functional sections:

1. **Lines 1-23:** Copyright header and Windows API constants
2. **Lines 25-30:** Promise helper function for async operations
3. **Lines 33-59:** Constructor and platform detection
4. **Lines 60-71:** Promise-based enumeration wrapper
5. **Lines 73-239:** Core getProcesses implementation
   - Lines 80-118: Windows native API implementation
   - Lines 119-201: Linux ps + awk with fallback
   - Lines 202-237: FreeBSD/macOS ps + awk
6. **Lines 242-320:** getProcessInfo for detailed process inspection
   - Lines 249-260: Linux /proc reader
   - Lines 261-318: Windows PowerShell query
7. **Lines 322-352:** Unix pgrep-based process finder
8. **Lines 353-390:** Enhanced process search with filtering
9. **Lines 392-393:** Module export

### Technical Notes

**Generic Marshal (Windows):**
The module uses Generic Marshal (_GenericMarshal) to create native bindings to Win32 APIs without requiring compiled native modules. This provides:
- Direct access to kernel32.dll functions
- Proper structure marshaling for PROCESSENTRY32W
- Wide character (Unicode) string handling via Wide2UTF8
- Automatic memory management for native structures

**Pointer Size Detection:**
The code adapts structure sizes based on architecture (line 84, 94):
```javascript
var info = GM.CreateVariable(GM.PointerSize == 8 ? 568 : 556);  // x64 vs x86
var offset = GM.PointerSize == 4 ? 36 : 44;  // Command name offset
```

**Shell Script Complexity:**
Unix implementations use sophisticated awk scripts to parse ps output:
- Escapes special characters (backslashes, quotes)
- Filters out awk itself from results
- Handles variable-width ps output
- Generates valid JSON structure
- Provides fallback for limited ps implementations

**Process Owner Detection:**
- **Windows:** Uses user-sessions module's getProcessOwnerName
- **Linux/macOS:** Extracted from ps output via user column
- Requires appropriate permissions (may fail for system processes)

**Error Handling:**
- Missing processes gracefully handled (try/catch around user lookup)
- Invalid PIDs return empty results or throw exceptions
- Platform-specific methods throw exceptions on unsupported platforms
- Shell command failures handled via stderr checking

**Performance Considerations:**
- **Windows:** Fastest (native APIs, single snapshot)
- **Linux:** Moderate (shell parsing, fallback mechanism)
- **FreeBSD/macOS:** Fast (simple ps parsing, no fallback)
- getProcesses is synchronous on all platforms (blocks until complete)
- getProcessInfo is async on Windows (PowerShell overhead)

### Platform-Specific Analysis

**What Works on macOS:**

Fully functional features:
- `getProcesses()` - Complete process enumeration (lines 202-237)
- `enumerateProcesses()` - Promise-based wrapper
- `getProcess(cmd)` - pgrep-based search (if pgrep available)
- `getProcessEx(cmd, options)` - ps + grep search (lines 375-389)

**What Doesn't Work on macOS:**

Limited functionality:
- `getProcessInfo(pid)` - Not implemented (throws exception at line 247)
  - Would require parsing ps output or using macOS-specific APIs
  - Alternative: Use `ps -p [pid] -o ...` for specific process details
  - macOS libproc APIs could provide detailed info but require native module

**macOS-Specific Behavior:**

1. **ps Command:** Uses BSD-style ps with -axo flags for all processes
2. **Output Format:** Consistent and reliable, no fallback needed
3. **No /proc:** macOS doesn't have /proc filesystem, relies entirely on ps
4. **User Information:** Included in ps output via -o user flag
5. **Command Line:** Full command with arguments from ps -o command

**Implementation Comparison:**

| Feature | Windows | Linux | FreeBSD | macOS |
|---------|---------|-------|---------|-------|
| Process List | Native API | ps + awk | ps + awk | ps + awk |
| Full Path | Yes | No | No | No |
| Process Owner | Yes | Yes | Yes | Yes |
| Detailed Info | PowerShell | /proc | /proc | No |
| Performance | Excellent | Good | Good | Excellent |
| Fallback Logic | No | Yes | No | No |

**macOS Enhancement Opportunities:**

To achieve feature parity with Linux/Windows:
1. Implement getProcessInfo using:
   - Parse `ps -p [pid] -o ...` with detailed flags
   - Use macOS libproc native APIs (proc_pidinfo)
   - Query sysctl kern.procargs2 for process arguments
2. Add process path resolution:
   - Use `lsof -p [pid]` to find executable path
   - Parse `ps -p [pid] -o comm=` for full path
3. Enhanced search:
   - Use `pgrep -lf` for process name + argument matching

## Summary

The process-manager.js module is a comprehensive cross-platform process enumeration and management tool that provides unified APIs for **Windows, Linux, FreeBSD, and macOS**.

**macOS is fully supported** for core functionality including:
- Complete process enumeration with PID, user, and command information
- Process search capabilities (getProcess, getProcessEx)
- Promise-based async interface
- Reliable ps-based implementation without fallback mechanisms

The module uses platform-specific implementations optimized for each operating system: native Win32 APIs on Windows for maximum performance, ps with /proc enhancement on Linux/FreeBSD, and clean ps-based parsing on macOS. The architecture supports easy extension for additional platforms and provides consistent API across all supported systems.

**Limitations on macOS:**
- getProcessInfo(pid) not implemented (lacks detailed process inspection)
- Full executable path not included in process listings
- No /proc filesystem available (inherent platform difference)

The module successfully abstracts platform differences while maintaining optimal performance characteristics for each operating system, making it suitable for production use in cross-platform remote monitoring and management applications like MeshAgent.
