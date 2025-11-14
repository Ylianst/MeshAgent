# util-descriptors.js

System utility module for enumerating and managing open file descriptors on Linux and FreeBSD platforms. Provides functionality to list all open descriptors, close them safely, and execute programs with clean descriptor inheritance using execv. Additionally offers Windows-specific process handle management.

## Platform

**Supported Platforms:**
- Linux - Full support for descriptor enumeration via `/proc/<pid>/fd`
- FreeBSD - Full support for descriptor enumeration via `procstat` utility

**Excluded Platforms:**
- **macOS (darwin)** - Not supported
- **Windows (win32)** - Partial support (process handles only)

**Exclusion Reasoning:**

macOS is excluded from descriptor enumeration functionality:

1. **No /proc Filesystem** - macOS does not provide `/proc/<pid>/fd` like Linux, requiring different system APIs
2. **No procstat Utility** - BSD's `procstat` tool is not available on macOS
3. **Alternative APIs Required** - macOS would need `lsof` command-line tool or native system calls like `proc_pidinfo()`
4. **Different Architecture** - macOS uses different process management APIs than Linux/FreeBSD

Windows receives partial support through `getProcessHandle()` function only, as Windows uses handles instead of file descriptors.

## Functionality

### Purpose

The util-descriptors module provides low-level file descriptor management for Unix-like systems. It enables:

- Enumeration of all open file descriptors for the current process
- Safe closure of file descriptors (avoiding stdin/stdout/stderr)
- Clean process execution via `execv()` with automatic descriptor cleanup
- Prevention of descriptor leaks when spawning child processes
- Windows process handle acquisition for synchronization

This module is critical for:
- Preventing file descriptor exhaustion
- Ensuring clean process replacement during updates
- Avoiding descriptor inheritance in child processes
- Resource cleanup during process lifecycle management

### Descriptor Enumeration

**Linux Implementation (lines 73-103):**
Uses `/proc/<pid>/fd` directory to enumerate descriptors:
```bash
ls /proc/<pid>/fd | tr '\n' '`' | awk -F'`' '{ printf "["; ... printf "]"; }'
```
Returns array of descriptor numbers parsed from directory listing.

**FreeBSD Implementation (lines 37-72):**
Uses `procstat -f <pid>` command:
```bash
procstat -f <pid> | tr '\n' '`' | awk -F'`' '{ ... }'
```
Parses procstat output, extracting descriptor numbers from column 3.

**macOS:**
Not implemented - returns empty array via `default` case (line 104-106).

### Key Functions

#### getOpenDescriptors() - Lines 32-107

**Purpose:** Returns an array of all open file descriptors for the current process.

**Process:**

**Linux (lines 73-103):**
1. Spawns `/bin/sh` subprocess (line 77)
2. Executes `ls /proc/<pid>/fd` to list descriptors
3. Pipes output through `tr` and `awk` to format as JSON array
4. Parses JSON result
5. Returns array of descriptor numbers
6. Returns empty array on parse error

**FreeBSD (lines 37-72):**
1. Spawns `/bin/sh` subprocess (line 41)
2. Executes `procstat -f <pid>` to query descriptors
3. Uses awk to extract descriptor column (column 3)
4. Filters numeric descriptors via regex `/^[0-9]/`
5. Formats output as JSON array
6. Parses and returns array

**Platform Behavior:**
- **Linux**: Fast, uses procfs
- **FreeBSD**: Uses procstat system utility
- **macOS**: Returns empty array (not implemented)
- **Windows**: Returns empty array (uses handles, not descriptors)

**Return Value:**
- Array of integers representing open file descriptors
- Empty array on error or unsupported platform

---

#### closeDescriptors(fdArray) - Lines 111-124

**Purpose:** Closes all file descriptors in the provided array, excluding stdin/stdout/stderr (0, 1, 2).

**Parameters:**
- `fdArray` (array) - Array of file descriptor numbers to close

**Process:**
1. Validates `libc` marshaler is available (line 114)
2. Iterates through array with `while` loop (line 116)
3. Pops descriptor from array (line 118)
4. Skips descriptors 0, 1, 2 (stdin/stdout/stderr) (line 119)
5. Calls `libc.close(fd)` to close descriptor (line 121)

**Platform Behavior:**
- **Linux/FreeBSD**: Closes descriptors via glibc `close()`
- **Other platforms**: Throws 'cannot find libc' error

**Safety:**
- Always preserves stdin (0), stdout (1), stderr (2)
- Prevents closing standard streams

**Error Handling:**
- Throws 'cannot find libc' if libc marshaler unavailable

---

#### _execv(exePath, argarr) - Lines 129-157

**Purpose:** Executes a program via `execv()` system call, automatically closing all open descriptors first.

**Parameters:**
- `exePath` (string) - Path to executable
- `argarr` (array) - Array of command-line arguments

**Process:**
1. Validates `libc` marshaler exists (lines 131-134)
2. Creates native marshaled variables:
   - `path` variable for executable path (line 138)
   - `args` array for arguments (line 139)
3. Converts JavaScript array to native C array (lines 140-146)
   - Allocates pointer array buffer
   - Creates native variable for each argument
   - Copies pointers into args buffer
4. Fetches all open descriptors (line 152)
5. Closes all descriptors except stdin/stdout/stderr (line 153)
6. Calls `libc.execv(path, args)` (line 155)
7. Throws 'exec error' if execv returns (line 156)

**Platform Behavior:**
- **Linux/FreeBSD**: Replaces current process with new executable
- **Other platforms**: Throws 'cannot find libc' error

**Use Case:**
Used during agent updates to replace the running process cleanly without leaking file descriptors to the new process instance.

**Technical Notes:**
- `execv()` does not return on success (process is replaced)
- If `execv()` returns, an error occurred
- All open descriptors are closed before exec to prevent leaks
- Standard streams (0, 1, 2) are preserved

---

#### getLibc() - Lines 162-188

**Purpose:** Loads glibc and creates native marshaler with `execv` and `close` methods.

**Process:**
1. Uses `monitor-info.getLibInfo('libc')` to find libc paths (line 164)
2. Iterates through found libraries (lines 167-185)
3. Attempts to load each library via `CreateNativeProxy()` (line 175)
4. Creates method marshals for:
   - `execv` (line 176)
   - `close` (line 177)
5. Returns first successfully loaded library
6. Returns null if no library loads

**Platform Behavior:**
- **Linux**: Typically finds `/lib/x86_64-linux-gnu/libc.so.6` or similar
- **FreeBSD**: Finds `/lib/libc.so.7` or similar
- **macOS/Windows**: Not applicable

**Why Multiple Libraries:**
Linux distributions often include libc for multiple architectures (x86, x86_64, ARM). The function tries each until finding one compatible with the current process architecture.

---

#### win_getProcessHandle(pid) - Lines 193-214

**Purpose:** Windows-only function to obtain a process HANDLE for synchronization.

**Parameters:**
- `pid` (number) - Process ID

**Process:**
1. Loads `kernel32.dll` if not already loaded (line 203)
2. Creates marshal for `OpenProcess()` function (line 204)
3. Calls `OpenProcess(SYNCHRONIZE, 0, pid)` (line 208)
4. Returns HANDLE value

**Platform Behavior:**
- **Windows only**: Opens process with SYNCHRONIZE access rights
- **Other platforms**: Not exported

**Use Case:**
Allows checking if a process is still running by attempting to wait on its handle.

**Reference:**
Microsoft documentation: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

---

### Dependencies

#### Node.js Core Modules
- `child_process` (lines 41, 77) - Used to execute shell commands:
  - `execFile('/bin/sh', ['sh'])` - Spawns shell for command execution

#### MeshAgent Module Dependencies

**Core Required Modules:**

- **`_GenericMarshal`** (lines 138-139, 143, 145, 175, 203)
  - Native code marshaling for C library calls
  - Methods used:
    - `CreateVariable(size|string)` - Allocate native memory
    - `CreateNativeProxy(libraryPath)` - Load shared library
    - `PointerSize` - Get pointer size for architecture
  - Used to interface with glibc functions

- **`monitor-info`** (line 164)
  - System information gathering module
  - Method used:
    - `getLibInfo('libc')` - Find libc library paths
  - Returns array of library information objects with `path` property

### Technical Notes

**Architecture Detection:**
The `getLibc()` function automatically handles multi-architecture systems by:
1. Getting all libc paths from `monitor-info`
2. Attempting to load each one
3. Using the first that loads successfully

This handles systems with both 32-bit and 64-bit libraries installed.

**Descriptor Leak Prevention:**
The `_execv()` function is critical during agent updates. Without closing descriptors:
- Old network connections would remain open
- File locks would persist
- Memory maps would leak
- IPC channels would stay connected

By closing all descriptors before `execv()`, the new process starts with a clean slate.

**Shell Command Pattern:**
Both Linux and FreeBSD implementations use a consistent pattern:
```javascript
child = require('child_process').execFile('/bin/sh', ['sh']);
child.stdout.str = '';
child.stdout.on('data', function (c) { this.str += c.toString(); });
child.stdin.write("command | awk '...'");
child.stdin.write('\nexit\n');
child.waitExit();
JSON.parse(child.stdout.str.trim());
```

This pattern:
1. Spawns interactive shell
2. Accumulates stdout to string
3. Writes command to stdin
4. Waits for completion
5. Parses JSON output

**Why awk for JSON?**
The awk scripts format output as JSON arrays:
```awk
printf "[";
for(...) { printf "%s%s", DEL, value; DEL=","; }
printf "]";
```

This avoids needing external JSON tools and works on minimal systems.

## Summary

The util-descriptors.js module provides low-level file descriptor management for **Linux and FreeBSD** platforms. It enables enumeration of open descriptors, safe closure excluding standard streams, and clean process execution via `execv()` with automatic descriptor cleanup.

**macOS is not supported** because it lacks the procfs `/proc/<pid>/fd` interface used by Linux and the `procstat` utility available on FreeBSD. macOS would require implementation using `lsof` command or native system calls.

**Windows receives partial support** through the `getProcessHandle()` function, which provides process handle acquisition for synchronization purposes, as Windows uses handles rather than file descriptors.

The module is critical during agent updates to prevent descriptor leaks when replacing the running process, and for general resource cleanup throughout the agent lifecycle on Unix-like platforms.
