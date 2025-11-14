# file-search.js

Cross-platform file search utility that searches for files matching specific criteria (filename patterns) in directory trees. Provides event-driven streaming of search results with support for multiple filename patterns and cancellable operations.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via PowerShell
- Linux - Full support via `/usr/bin/find`
- macOS (darwin) - Full support via `/usr/bin/find`
- FreeBSD - Full support via `/usr/bin/find`

**Excluded Platforms:**
- None - This module is cross-platform

**Exclusion Reasoning:**

This module has no platform exclusions. It implements platform-specific file search strategies that leverage native system tools for optimal performance:
- **Windows:** Uses PowerShell's `Get-ChildItem` cmdlet with named pipe IPC
- **Unix-like systems (Linux, macOS, FreeBSD):** Uses the `/usr/bin/find` command

Both implementations provide identical functionality and API, ensuring consistent behavior across all platforms while utilizing the most efficient search mechanism available on each operating system.

## Functionality

### Purpose

The file-search module serves as a high-performance file searching utility for locating files by name patterns across directory hierarchies. It provides:

- **Recursive directory traversal** through deep file system hierarchies
- **Pattern matching** for single or multiple filename criteria
- **Event-driven results** streaming results as they are found
- **Cancellable operations** to stop long-running searches
- **Promise-based completion** signaling when search finishes
- **Cross-platform abstraction** hiding OS-specific implementation details

This module is typically used:
- To locate configuration files or specific modules across the file system
- During system diagnostics to find files matching patterns
- For file discovery operations in MeshAgent workflows
- To search for log files, executables, or data files

### Platform-Specific Implementations

#### Windows Implementation (Lines 24-80)

**Strategy:** PowerShell with Named Pipe IPC

**Process:**
1. Creates named pipe server for IPC: `\\.\pipe\mesh-<uuid>`
2. Spawns PowerShell process via `child_process.execFile()`
3. PowerShell script connects to named pipe as client
4. Executes `Get-ChildItem` cmdlet with recursive search
5. Results stream through named pipe to Node.js
6. Each matching file path is emitted as 'result' event
7. Pipe closes when search completes, triggering 'end' event

**PowerShell Command:**
```powershell
Get-ChildItem -Path <root> -Include <criteria> -File -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object -Process { $sw.WriteLine($_.FullName); $sw.Flush(); }
```

**Named Pipe Communication:**
- Pipe name: `mesh-<uuid>` (generated with uuid/v4)
- Full path: `\\.\pipe\mesh-<uuid>`
- Direction: PowerShell (client) → Node.js (server)
- Protocol: Text-based, line-delimited file paths

**Advantages:**
- PowerShell's optimized file enumeration
- Streaming results for responsive feedback
- Error suppression prevents permission errors from stopping search
- Separate process isolation

---

#### Unix-like Implementation (Lines 82-143)

**Strategy:** Direct execution of `/usr/bin/find` command

**Process:**
1. Constructs find command with appropriate arguments
2. Spawns `/usr/bin/find` process via `child_process.execFile()`
3. Captures stdout stream containing matching file paths
4. Parses line-delimited output
5. Emits each path as 'result' event
6. Emits 'end' event when find process exits

**Find Command Structure:**

**Linux:**
```bash
/usr/bin/find <root> -type f ( -name <pattern1> -o -name <pattern2> ... )
```

**macOS/FreeBSD:**
```bash
/usr/bin/find <root> -name <pattern1> -o -name <pattern2> ...
```

**Key Differences:**
- **Linux:** Includes `-type f` to restrict to files only, wrapped in parentheses for proper operator precedence
- **macOS/FreeBSD:** No type restriction or parentheses (relies on find's default behavior)

**Advantages:**
- Native find performance
- No intermediate parsing or IPC overhead
- Standard Unix tool available on all systems
- Memory efficient for large result sets

---

### Key Functions/Methods

#### find(root, criteria) - Lines 25-79 (Windows) / 83-142 (Unix-like)

**Purpose:** Searches for files matching specified filename patterns in a directory tree.

**Parameters:**
- `root` - String: Root directory path to start search
- `criteria` - String or Array: Filename pattern(s) to match
  - Single pattern: `"*.txt"`
  - Multiple patterns: `["*.txt", "*.log", "*.md"]`

**Return Value:**
Promise object with EventEmitter capabilities:
```javascript
{
    // Promise methods
    then(callback),
    catch(callback),

    // EventEmitter methods
    on('result', callback),   // Fired for each matching file
    on('end', callback),      // Fired when search completes

    // Control methods
    cancel()                  // Cancels the search operation
}
```

**Events:**
- **`'result'`** - Emitted for each file found
  - Parameter: Full absolute path to matching file
  - Fires as results stream in (not batched)

- **`'end'`** - Emitted when search completes
  - No parameters
  - Fires after all results have been emitted
  - Promise resolves after this event

**Process Flow:**

**Windows:**
1. Generate unique pipe name using uuid/v4
2. Create TCP/named pipe server
3. Wait for PowerShell client connection
4. Stream results through pipe as line-delimited text
5. Parse lines and emit 'result' events
6. Close pipe and emit 'end' when PowerShell exits

**Unix-like:**
1. Construct find command arguments
2. Execute `/usr/bin/find` as child process
3. Buffer stdout data
4. Split on newlines and emit 'result' for complete lines
5. Emit 'end' when find process exits

**Platform Behavior:**
- **Windows:** Named pipe IPC with PowerShell, supports multiple criteria via comma-separated list
- **Linux:** Uses `-type f` restriction and parentheses for proper boolean grouping
- **macOS/FreeBSD:** Standard find without type restriction
- **All platforms:** Case-sensitive pattern matching (depends on filesystem)

---

#### cancel() - Lines 75-78 (Windows) / 138-141 (Unix-like)

**Purpose:** Cancels an ongoing search operation.

**Process:**
- Calls `kill()` on the child process
- Terminates PowerShell (Windows) or find (Unix-like)
- Cleanup handlers close pipes/streams
- Promise remains unresolved (does not reject)

**Usage:**
```javascript
var search = fileSearch.find('/home', '*.log');
search.on('result', function(path) {
    console.log('Found:', path);
});

// Cancel after 5 seconds
setTimeout(function() {
    search.cancel();
}, 5000);
```

**Platform Behavior:**
- All platforms supported
- Immediate termination of search process
- No additional cleanup required

---

### Usage

#### Basic File Search

```javascript
var fileSearch = require('file-search');

// Search for single pattern
fileSearch.find('/var/log', '*.log')
    .then(function() {
        console.log('Search complete');
    });
```

#### Multiple Patterns

```javascript
// Search for multiple file types
fileSearch.find('C:\\Users', ['*.txt', '*.doc', '*.pdf'])
    .then(function() {
        console.log('Search complete');
    });
```

#### Event-Driven Result Processing

```javascript
var search = fileSearch.find('/home/user', '*.js');

search.on('result', function(filePath) {
    console.log('Found JavaScript file:', filePath);
    // Process each file as it's found
});

search.on('end', function() {
    console.log('Search finished');
});

search.catch(function(error) {
    console.error('Search error:', error);
});
```

#### Collecting Results

```javascript
var results = [];

var search = fileSearch.find('/opt', '*.conf');

search.on('result', function(filePath) {
    results.push(filePath);
});

search.then(function() {
    console.log('Found ' + results.length + ' configuration files');
    results.forEach(function(path) {
        console.log('  -', path);
    });
});
```

#### Cancellable Search

```javascript
var search = fileSearch.find('/home', '*.mp4');
var foundCount = 0;

search.on('result', function(filePath) {
    foundCount++;
    console.log('Found:', filePath);

    // Cancel after finding 10 files
    if (foundCount >= 10) {
        search.cancel();
        console.log('Cancelled after finding 10 files');
    }
});
```

---

### Dependencies

#### Node.js Core Modules

- **`promise`** (line 17)
  - Purpose: Custom promise implementation for async operations
  - Usage: Returned promise object from `find()` method
  - Methods used: Constructor with resolver/rejector
  - Platform support: Cross-platform

- **`events`** (lines 28, 86)
  - Purpose: EventEmitter functionality for result streaming
  - Usage: Extends returned promise with event capabilities
  - Events: `'result'`, `'end'`
  - Methods used: `EventEmitter.call()`, `createEvent()`, `emit()`
  - Platform support: Cross-platform

- **`child_process`** (lines 65, 114)
  - Purpose: Spawns search processes (PowerShell or find)
  - Usage: `execFile()` to run external commands
  - Methods used: `execFile()`, `kill()`, stdout/stderr stream handling
  - Platform support: Cross-platform

**Windows-specific:**

- **`net`** (line 31)
  - Purpose: Named pipe server creation for IPC
  - Usage: `createServer()` to create pipe server
  - Methods used: `createServer()`, `listen()`, `close()`
  - Connection events: `'connection'`, `'end'`, `'data'`
  - Platform support: Windows named pipes only

- **`uuid/v4`** (line 33)
  - Purpose: Generate unique pipe names
  - Usage: Creates UUID for pipe naming to avoid conflicts
  - Returns: String like "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  - Platform support: Cross-platform module, used only on Windows

**Unix-like systems:**

- **No additional dependencies** - Uses only standard modules

#### MeshAgent Module Dependencies

- **`promise`** - MeshAgent custom promise module
  - Similar to promise2 but with different feature set
  - Provides promise-based async control flow

#### Platform Binary Dependencies

**Windows:**
- **PowerShell** (`powershell.exe`)
  - Location: `%windir%\System32\WindowsPowerShell\v1.0\powershell.exe`
  - Version: PowerShell 2.0+ (ships with Windows 7+)
  - Required cmdlets: `Get-ChildItem`
  - .NET requirements: System.IO.Pipes namespace

**Linux/macOS/FreeBSD:**
- **find** (`/usr/bin/find`)
  - Standard Unix utility
  - Available on all Unix-like systems
  - Version: Any POSIX-compliant find
  - Required features: `-name`, `-type` (Linux), `-o` (OR operator)

#### Dependency Summary

| Dependency Type | Module/Binary | Required | Platform-Specific |
|----------------|---------------|----------|-------------------|
| Node.js Core | promise | Yes | No |
| Node.js Core | events | Yes | No |
| Node.js Core | child_process | Yes | No |
| Node.js Core | net | Yes | Windows only |
| MeshAgent | uuid/v4 | Yes | Windows only |
| System Binary | powershell.exe | Yes | Windows only |
| System Binary | /usr/bin/find | Yes | Unix-like only |

---

### Technical Notes

**Named Pipe IPC on Windows:**

Windows implementation uses named pipes for inter-process communication between Node.js and PowerShell. This approach is necessary because PowerShell's `Get-ChildItem` output buffering would delay results if using standard stdout. Named pipes provide low-latency streaming of results as they are found.

The pipe name includes a UUID to prevent conflicts when multiple searches run concurrently. The server (Node.js) creates the pipe and waits for the client (PowerShell) to connect before starting the search.

**Line-Delimited Protocol:**

Both implementations use newline-delimited text for result transmission:
- **Windows:** CRLF (`\r\n`) line endings from PowerShell
- **Unix-like:** LF (`\n`) line endings from find

The parser accumulates partial lines in a buffer and emits complete paths only when a newline is encountered. The final line (without trailing newline) is emitted during the 'end' event.

**Error Handling:**

**Windows:**
- PowerShell uses `-ErrorAction SilentlyContinue` to suppress permission errors
- Inaccessible directories are silently skipped
- No error is reported for missing root directory (PowerShell behavior)

**Unix-like:**
- stderr is captured but ignored (line 131)
- Permission errors from find are suppressed
- Missing root directory would cause find to exit with error code (promise still resolves)

**Pattern Matching:**

Pattern matching syntax differs between platforms:
- **Windows PowerShell:** Wildcard patterns in `-Include` parameter (e.g., `*.txt`, `file?.doc`)
- **Unix find:** Shell-style patterns in `-name` parameter (e.g., `*.txt`, `file?.doc`)

Both support standard wildcard characters:
- `*` - Matches any number of any characters
- `?` - Matches exactly one character
- Character classes may vary by platform

**Multiple Criteria Handling:**

**Windows:**
- Criteria array joined with commas: `*.txt,*.log,*.md`
- PowerShell `-Include` parameter accepts comma-separated patterns

**Unix-like:**
- Multiple `-name` patterns joined with `-o` (OR operator)
- Linux wraps in parentheses for proper precedence: `( -name *.txt -o -name *.log )`
- macOS/FreeBSD omits parentheses (different operator precedence handling)

**Memory Efficiency:**

Both implementations stream results incrementally rather than buffering all results in memory. This allows searching large directory trees without memory constraints. Each result is emitted immediately when found, allowing the caller to process results on-the-fly.

**Process Isolation:**

Search operations run in separate child processes, providing isolation from the Node.js runtime. If the search process crashes or hangs, the main process remains unaffected. The `cancel()` method leverages this by simply killing the child process.

**Performance Considerations:**

**Windows:** PowerShell startup has ~1-2 second overhead, but `Get-ChildItem` performance is excellent for large directory trees. Named pipe IPC adds minimal latency.

**Unix-like:** The `/usr/bin/find` command is highly optimized and starts instantly. Performance is limited primarily by filesystem I/O and directory structure.

For repeated searches, the Unix implementation is typically faster due to zero startup overhead. For single large searches, both implementations perform similarly.

## Summary

The file-search.js module is a **cross-platform file searching utility** supporting Windows, Linux, macOS, and FreeBSD with platform-optimized implementations. It provides event-driven, streaming file discovery with support for multiple filename patterns and cancellable operations.

**Key features:**
- Recursive directory tree traversal
- Single or multiple filename pattern matching
- Event-driven result streaming ('result' and 'end' events)
- Promise-based completion notification
- Cancellable search operations
- Platform-specific optimizations (PowerShell on Windows, find on Unix-like)
- Named pipe IPC on Windows for low-latency results
- Memory-efficient streaming (no result buffering)
- Error suppression for permission-denied scenarios
- Identical API across all platforms

**Platform implementations:**
- **Windows:** PowerShell `Get-ChildItem` with named pipe IPC
- **Linux:** `/usr/bin/find` with `-type f` and parenthetical grouping
- **macOS/FreeBSD:** `/usr/bin/find` with standard OR operators

The module is used within MeshAgent for file discovery operations, locating configuration files, modules, and other resources across the filesystem. It provides a consistent interface regardless of the underlying operating system while leveraging the most efficient search mechanism available on each platform.
