# _agentStatus.js

Diagnostic tool for querying a running MeshAgent's internal state via DAIPC (Direct Agent IPC) named pipes. Provides real-time status information about connection state, open file descriptors, and timer information for troubleshooting and monitoring purposes.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via named pipes
- Linux - Full support via Unix domain sockets
- macOS (darwin) - Full support via Unix domain sockets
- FreeBSD - Full support via Unix domain sockets

**Excluded Platforms:**
- None - This module supports all platforms

## Functionality

### Purpose

The _agentStatus module serves as a diagnostic command-line tool for querying running MeshAgent processes. It provides:

- Real-time connection status to MeshCentral server
- List of open file descriptors (network, files, pipes)
- Active timer information and scheduling
- Internal state verification without stopping the agent

This module is typically used:
- During troubleshooting to verify agent connectivity
- For debugging file descriptor leaks
- To monitor timer activity and event scheduling
- In automated health check scripts

### Execution Flow

When invoked, the module executes the following sequence:

1. Retrieves Node ID via `_agentNodeId()` to construct IPC path
2. Creates TCP (Windows) or Unix socket (Unix) connection to DAIPC pipe
3. Queries connection status: `query('connection')`
4. Queries file descriptors: `query('descriptors')`
5. Queries timer information: `query('timerinfo')`
6. Displays results and exits
7. 3-second timeout if agent doesn't respond

### Key Functions

#### queryAgent(obj, prev, path) - Lines 33-74 (Core Query Function)

**Purpose:** Sends a query to the running agent via IPC and receives the response.

**Parameters:**
- `obj` - Query string ('connection', 'descriptors', 'timerinfo')
- `prev` - Previous connection object for reuse (optional)
- `path` - Custom IPC path (optional, defaults to global `ipcPath`)

**Process:**

**New Connection** (lines 37-53):
- Creates socket via `net.createConnection({path})`
- On 'connect':
  - Attaches `dataHandler` for responses
  - Attaches 'end' handler (rejects promise on disconnect)
  - Constructs JSON message: `{cmd: 'query', value: obj}`
  - Sends length-prefixed packet (4-byte UInt32LE + JSON)

**Connection Reuse** (lines 55-71):
- Reuses existing socket from previous query
- Removes old event listeners
- Attaches new handlers
- Sends query packet

**Return Value:** Promise that resolves with query result

**Promise Attachment:** `ret.client.promise = ret` (line 72) enables dataHandler access

---

#### dataHandler(chunk) - Lines 6-32 (IPC Protocol Parser)

**Purpose:** Parses length-prefixed JSON responses from the agent.

**Protocol Format:**
```
[4 bytes: UInt32LE length][length bytes: JSON payload]
```

**Process:**
1. **Length Check** (lines 9-10):
   - Requires at least 4 bytes for length field
   - Reads length as UInt32LE from offset 0
   - If incomplete packet, unshift and wait for more data

2. **Data Extraction** (line 12):
   - Slices JSON payload from bytes 4 to (length + 4)

3. **JSON Parsing** (lines 14-22):
   - Parses JSON string to object
   - On parse error: Rejects promise with 'Invalid Response Received'

4. **Promise Resolution** (lines 23-30):
   - Resolves promise with `payload.result` and connection object
   - Enables connection reuse for chaining queries

5. **Remaining Data** (line 31):
   - If more data after current packet, unshift remainder for next handler call

**Context:** `this` = socket object, `this.promise` = associated promise

---

#### start() - Lines 76-96 (Main Execution Function)

**Purpose:** Entry point that queries agent and displays results.

**Process:**

1. **Initialization** (lines 78-83):
   - Prints "Querying Mesh Agent state..."
   - Sets 3-second timeout
   - If timeout: Prints error and exits

2. **Query Chain** (lines 85-95):
   - **Connection query** (line 85):
     - Calls `queryAgent('connection')`
     - Displays server URL or "[NOT CONNECTED]"
     - Passes connection to next query for reuse

   - **Descriptors query** (line 89):
     - Calls `queryAgent('descriptors', connection)`
     - Displays file descriptor list
     - Passes connection to next query

   - **Timer info query** (line 91):
     - Calls `queryAgent('timerinfo', connection)`
     - Displays active timer information

   - **Exit** (line 91):
     - Closes connection and exits process

3. **Error Handling** (line 95):
   - Catch block exits process on any error

**Exit:** Always calls `process._exit()` (no cleanup needed)

---

### Module Exports

**Line 98:**
```javascript
module.exports = { start: start, query: queryAgent };
```

- **`start`** - Main execution function (command-line usage)
- **`query`** - Low-level query function (programmatic usage)

### Dependencies

#### Node.js Core Modules
- **`net`** (line 39) - TCP/Unix socket connections
  - Method: `createConnection({path})`
  - Used for IPC communication

#### MeshAgent Module Dependencies

**Required on All Platforms:**
- **`promise`** (line 2) - Custom promise implementation
  - Not Node.js native promises
  - Used for async query orchestration
  - Provides `_res` and `_rej` internal methods

- **`_agentNodeId`** (line 3) - Node ID retrieval
  - Function call: `require('_agentNodeId')()`
  - Returns 64-character hex Node ID
  - Used to construct IPC path on Windows

#### External Dependencies
- None - No external binaries or system calls

### Usage

#### Command-Line Invocation

```bash
# Query running agent
meshagent --eval "require('_agentStatus').start()"

# Or from external script
node -e "require('./_agentStatus').start()"
```

#### Programmatic Usage

```javascript
var query = require('_agentStatus').query;

// Single query
query('connection').then(function(result) {
    console.log('Server:', result);
    process.exit();
});

// Chained queries (reuse connection)
query('connection').then(function(result, connection) {
    console.log('Server:', result);
    return query('descriptors', connection);
}).then(function(result) {
    console.log('Descriptors:', result);
    process.exit();
});
```

#### Query Types

**'connection':**
- Returns: Server URL string or null
- Example: `wss://meshcentral.example.com:443/agent.ashx`
- Null if agent is not connected to server

**'descriptors':**
- Returns: Object with file descriptor information
- Lists: Network connections, open files, pipes, sockets
- Platform-specific format

**'timerinfo':**
- Returns: Object with active timer information
- Lists: Scheduled callbacks, intervals, timeouts
- Shows: Next execution time, repeat status

### Technical Notes

**IPC Path Construction:**

**Windows** (line 4):
```javascript
'\\\\.\\pipe\\' + nodeid + '-DAIPC'
// Example: \\.\pipe\A1B2C3D4E5F6...-DAIPC
```
- Named pipe in Windows pipe namespace
- NodeID ensures unique path per agent installation
- TCP-based connection (Windows named pipes use TCP protocol)

**Unix** (line 4):
```javascript
process.cwd() + '/DAIPC'
// Example: /usr/local/mesh/DAIPC or /opt/mesh/DAIPC
```
- Unix domain socket in agent's working directory
- File-based IPC (no network stack involved)
- Requires agent running from installation directory

**Protocol Security:**
- No authentication required (local IPC only)
- Assumes agent and query tool run on same machine
- Access controlled by filesystem permissions (Unix) or pipe permissions (Windows)
- Not exposed to network

**Connection Reuse:**
The module reuses connections for efficiency:
1. First query opens connection
2. Subsequent queries pass `connection` parameter
3. Avoids reconnection overhead
4. Reduces load on agent's IPC server

**Timeout Behavior:**
- Global 3-second timeout via `setTimeout` (line 79)
- Applies to entire query chain, not individual queries
- On timeout: Prints error and exits
- Does not gracefully close connection (process exit cleans up)

**Error Handling:**
- JSON parse errors reject promise
- Connection close triggers promise rejection
- All errors result in process exit
- No retry logic or recovery attempts

### Platform-Specific Analysis

**What Works on macOS:**
- All functionality works identically to Linux
- Unix domain socket IPC
- File descriptor and timer queries

**macOS-Specific Behavior:**
- IPC path: `{cwd}/DAIPC` (Unix socket)
- Requires agent running from installation directory
- Same behavior as Linux and FreeBSD

**Platform Differences:**

**Windows:**
- Named pipe: `\\.\pipe\{NodeID}-DAIPC`
- TCP-based connection
- NodeID-based path uniqueness

**Unix (Linux/macOS/FreeBSD):**
- Unix socket: `{cwd}/DAIPC`
- File-based IPC
- Working directory-based path

### Example Output

```
Querying Mesh Agent state...
Mesh Agent connected to: wss://meshcentral.example.com:443/agent.ashx
{
  "tcp": [
    "127.0.0.1:16990 -> 127.0.0.1:54321 (ESTABLISHED)",
    "0.0.0.0:16990 (LISTENING)"
  ],
  "udp": [
    "0.0.0.0:16990"
  ],
  "files": [
    "/usr/local/mesh/meshagent.db",
    "/usr/local/mesh/meshagent.log"
  ]
}

{
  "timers": [
    {
      "callback": "periodicServerCheck",
      "nextExecution": "2025-01-15T10:30:45.123Z",
      "interval": 300000,
      "repeat": true
    }
  ]
}
```

## Summary

The _agentStatus.js module is a lightweight diagnostic tool for querying running MeshAgent processes across all supported platforms (Windows, Linux, macOS, FreeBSD). It connects to the agent's DAIPC pipe and retrieves real-time status information including connection state, file descriptors, and timer activity.

**Key capabilities:**
- Real-time connection status to MeshCentral server
- File descriptor enumeration for leak detection
- Timer information for debugging event scheduling
- Connection reuse for efficient multi-query operations

**macOS support:**
- Full support using Unix domain sockets
- IPC path: `{cwd}/DAIPC`
- Identical behavior to Linux and FreeBSD
- No platform-specific limitations

**Critical dependencies:**
- `net` for socket communication
- `promise` for async query coordination
- `_agentNodeId` for IPC path construction (Windows)

The module provides essential diagnostic capabilities for troubleshooting agent connectivity and internal state without requiring agent shutdown or intrusive debugging tools.
