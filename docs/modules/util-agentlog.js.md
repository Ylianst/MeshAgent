# util-agentlog.js

Parser module for reading and analyzing MeshAgent log files, extracting structured log entries with timestamps, messages, crash information, and file/line references. Provides both comprehensive parsing and filtered log retrieval based on entry count or timestamp criteria.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support
- Linux - Full support
- macOS (darwin) - Full support
- FreeBSD - Full support

## Functionality

### Purpose

The util-agentlog module parses MeshAgent log files to extract structured information from various log entry types including:

- **Standard log entries** - Timestamped messages with optional file/line references
- **Windows crash entries** - Stack traces with function names, files, and line numbers
- **Linux crash entries** - Stack traces with symbols and crash IDs
- **Generic log messages** - Plain text entries without timestamps

This module enables:
- Log analysis and troubleshooting
- Crash dump investigation
- Historical event tracking
- Log file searching by timestamp or entry count
- Structured access to log data for reporting

### Log Entry Format Parsing

The module recognizes multiple log entry formats:

**Standard Log Entry:**
```
[MM/DD/YYYY HH:MM:SS AM/PM] [hash] message
[MM/DD/YYYY HH:MM:SS AM/PM] [] message
[MM/DD/YYYY HH:MM:SS AM/PM] message
```

**Log Entry with File/Line:**
```
[MM/DD/YYYY HH:MM:SS AM/PM] filename.c:123 (col,row) actual message
```

**Windows Crash Entry:**
```
[FunctionName => filename.c:123]
```

**Linux Crash Stack (no symbols):**
```
./path/to/binary() [0xABCDEF123456]
```

**Linux Crash ID:**
```
[module_0123456789ABCDEF]
```

**Linux Crash Stack (with symbols):**
```
=>/path/to/source.c:123
```

### Key Functions

#### parseLine(entry) - Lines 25-123

**Purpose:** Parses a single log entry line and pushes the structured result to `this.results` array.

**Parameters:**
- `entry` (string) - Raw log entry line

**Process:**

**1. Timestamp Entry Detection (lines 29-30):**
```javascript
var test = entry.match(/^\[.*M\]/);
```
Matches standard log entries with timestamps ending in AM/PM.

**2. Windows Crash Entry (lines 33-44):**
```javascript
test = entry.match(/\[.+ => .+:[0-9]+\]/);
```
Parses format: `[FunctionName => file.c:123]`
- Extracts filename (line 37)
- Extracts line number (line 38)
- Extracts function name (line 39)
- Adds to most recent log entry: `{f, l, fn}`

**3. Linux Crash Stack - No Symbols (lines 48-58):**
```javascript
test = entry.match(/^[\.\/].+\(\) \[0x[0-9a-fA-F]+\]$/);
```
Parses format: `./binary() [0xADDRESS]`
- Extracts memory address
- Adds to `sx` array (stack addresses without symbols)

**4. Linux Crash ID (lines 62-68):**
```javascript
test = entry.match(/^\[.+_[0-9a-fA-F]{16}\]$/);
```
Parses format: `[module_0123456789ABCDEF]`
- Extracts 16-character hex crash ID
- Sets `h` property on most recent entry

**5. Linux Crash Stack - With Symbols (lines 72-78):**
```javascript
test = entry.match(/(?!^=>)\/+.+:[0-9]+$/);
```
Parses format: `=>/path/to/file.c:123`
- Adds to `s` array (stack trace with file/line info)

**6. Standard Timestamp Entry (lines 86-122):**
- Parses timestamp (lines 86-92)
- Handles AM/PM conversion to 24-hour format
- Extracts message (line 93)
- Parses optional hash `[0123456789ABCDEF]` (lines 94-108)
- Creates log object: `{t, m, h?}` (line 110-111)
- Checks for file/line in message (lines 114-120)
- Adds structured entry to results (line 122)

**Return Value:**
- Modifies `this.results` array by pushing parsed entries
- No direct return value

**Parsed Entry Structure:**
```javascript
{
    t: 1234567890,           // Unix timestamp (seconds)
    m: "Log message",        // Message text
    h: "0123456789ABCDEF",  // Optional: 16-char hash
    f: "file.c",            // Optional: Source file
    l: "123",               // Optional: Line number
    fn: "functionName",      // Optional: Function name (Windows crash)
    s: ["file.c:123", ...], // Optional: Stack trace (Linux)
    sx: ["0xABCD", ...]     // Optional: Stack addresses (Linux)
}
```

---

#### readLog_data(buffer) - Lines 129-150

**Purpose:** Stream data handler that accumulates buffer content and parses complete lines.

**Parameters:**
- `buffer` (Buffer) - Chunk of data from file read stream

**Process:**
1. Converts buffer to string (line 131)
2. Prepends any buffered partial line from previous chunk (line 132)
3. Splits by newline into array of lines (line 133)
4. Parses all complete lines (lines 136-139)
5. Stores last incomplete line in buffer for next chunk (lines 141-149)

**Context:**
- `this` refers to the file stream object
- `this.buffered` stores partial lines between chunks
- `this.results` is the output array

**Stream Handling:**
```javascript
for (i = 0; i < (lines.length - 1) ; ++i) {
    parseLine.call(this, lines[i]);
}
```
Processes all lines except the last (which may be incomplete).

---

#### readLogEx(path) - Lines 156-175

**Purpose:** Reads and parses an entire log file, returning array of all log entries.

**Parameters:**
- `path` (string) - Path to log file

**Process:**
1. Creates empty results array (line 158)
2. Creates read stream from file (line 161)
3. Attaches data handler `readLog_data` (line 164)
4. Resumes stream to begin reading (line 165)
5. Processes any remaining buffered data (line 166)
6. Cleans up stream listeners (line 167)
7. Returns complete results array (line 174)

**Error Handling:**
- Wrapped in try-catch (lines 159-172)
- Returns empty array on error

**Return Value:**
- Array of parsed log entry objects
- Empty array on error

---

#### readLog(criteria, path) - Lines 181-219

**Purpose:** Reads log file and returns filtered entries based on criteria.

**Parameters:**
- `criteria` (number|string) - Filter criteria:
  - Number < 1000: Return last N entries
  - Number >= 1000: Treat as Unix timestamp, return entries after timestamp
  - String: Parse as date string, convert to timestamp
- `path` (string, optional) - Log file path (defaults to `process.execPath` + '.log')

**Process:**

**1. Read All Entries (line 183):**
```javascript
var objects = readLogEx(path == null ? (process.execPath.split('.exe').join('') + '.log') : path);
```
Default path: executable path with .exe removed + .log

**2. Parse Criteria (lines 186-196):**
- If string: Convert to Unix timestamp via `Date.parse()`
- If number: Use as-is

**3. Filter by Criteria (lines 198-216):**

**Entry Count Mode (criteria < 1000):**
```javascript
ret = objects.slice(objects.length - criteria);
```
Returns last N entries.

**Timestamp Mode (criteria >= 1000):**
```javascript
for (i = 0; i < objects.length && objects[i].t <= criteria; ++i) { }
ret = objects.slice(i);
```
Returns entries with timestamp > criteria.

**No Criteria:**
Returns all entries.

**Return Value:**
- Filtered array of log entry objects

**Usage Examples:**
```javascript
// Get last 100 entries
var logs = readLog(100);

// Get entries after timestamp
var logs = readLog(1609459200);

// Get entries after date
var logs = readLog('2021-01-01T00:00:00Z');

// Get all entries from specific file
var logs = readLog(null, '/path/to/meshagent.log');
```

---

### Module Export - Line 221

```javascript
module.exports = { read: readLog, readEx: readLogEx }
```

**Exported Functions:**
- `read(criteria, path)` - Filtered log reading
- `readEx(path)` - Full log file parsing

---

### Dependencies

#### Node.js Core Modules
- `fs` (line 161) - File system operations:
  - `createReadStream(path)` - Stream-based file reading

#### MeshAgent Module Dependencies

**None** - This module has no MeshAgent-specific dependencies, only Node.js core modules.

### Technical Notes

**Regex Patterns:**

**Timestamp Entry:**
```javascript
/^\[.*M\]/  // Matches: [MM/DD/YYYY HH:MM:SS AM] or [MM/DD/YYYY HH:MM:SS PM]
```

**Windows Crash:**
```javascript
/\[.+ => .+:[0-9]+\]/  // Matches: [FunctionName => file.c:123]
```

**Linux Crash Stack (no symbols):**
```javascript
/^[\.\/].+\(\) \[0x[0-9a-fA-F]+\]$/  // Matches: ./binary() [0x123ABC]
```

**Linux Crash ID:**
```javascript
/^\[.+_[0-9a-fA-F]{16}\]$/  // Matches: [module_0123456789ABCDEF]
```

**Linux Crash Stack (with symbols):**
```javascript
/(?!^=>)\/+.+:[0-9]+$/  // Matches: =>/path/file.c:123
```

**File/Line in Message:**
```javascript
/^.+:[0-9]+ \([0-9]+,[0-9]+\)/  // Matches: file.c:123 (45,67) message
```

**Stream-Based Parsing:**

The module uses Node.js streams for memory efficiency:
- Reads file in chunks
- Parses complete lines incrementally
- Buffers partial lines across chunks
- Handles large log files without loading entirely into memory

**AM/PM to 24-Hour Conversion:**
```javascript
if (c[2] == 'PM') {
    t[0] = parseInt(t[0]) + 12;
    if (t[0] == 24) { t[0] = 0; }
}
```
Converts 12-hour format to 24-hour, handling midnight (12 AM = 0).

**Hash Format:**

Log entries may include a 16-character hexadecimal hash:
```
[MM/DD/YYYY HH:MM:SS AM/PM] [0123456789ABCDEF] message
```

This likely represents the agent executable hash for version tracking.

**Default Log Path:**

If no path specified, defaults to:
```javascript
process.execPath.split('.exe').join('') + '.log'
```

Examples:
- Windows: `C:\Program Files\Mesh\agent.exe` → `C:\Program Files\Mesh\agent.log`
- Linux: `/usr/local/mesh/meshagent` → `/usr/local/mesh/meshagent.log`

**Error Resilience:**

All functions use try-catch to ensure they never throw:
- `readLogEx()` returns `[]` on error
- JSON parsing failures are caught
- File access errors are silently handled

This makes the module safe to use in production without error handling wrapper code.

## Summary

The util-agentlog.js module is a cross-platform log parser for **Windows, Linux, macOS, and FreeBSD** that extracts structured information from MeshAgent log files. It handles multiple log entry formats including standard timestamped entries, Windows crash stacks, and Linux crash dumps with symbol information.

The module provides two interfaces: `readEx()` for complete log parsing and `read()` for filtered retrieval by entry count or timestamp. It uses stream-based parsing for memory efficiency, allowing analysis of large log files without loading them entirely into memory.

The module has no MeshAgent-specific dependencies, relying only on Node.js core fs module, making it lightweight and portable. It handles errors gracefully by returning empty arrays rather than throwing exceptions, ensuring safe usage in production environments.
