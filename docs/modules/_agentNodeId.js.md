# _agentNodeId.js

Utility module for retrieving and managing the MeshAgent's unique Node ID, service name, and identity reset functionality. Provides methods to identify the agent instance across platforms and manage its identity configuration through registry (Windows) or service enumeration (Unix).

## Platform

**Supported Platforms:**
- Windows (win32) - Full support with registry-based service name lookup (includes NodeID reset)
- Linux - Full support with service-manager enumeration*
- macOS (darwin) - Full support with service-manager enumeration*
- FreeBSD - Full support with service-manager enumeration*

*NodeID reset functionality (resetNodeId/checkResetNodeId) is Windows-only

**Excluded Platforms:**
- None - This module supports all platforms for core functionality

## Functionality

### Purpose

The _agentNodeId module serves as the core identity management system for MeshAgent installations. It provides:

- Retrieval of the agent's unique 64-character hexadecimal Node ID
- Service name discovery across different platforms
- NodeID reset functionality (Windows-only)
- Cross-platform identity persistence via database storage

This module is critical for:
- Agent identification in MeshCentral networks
- Service management operations
- Configuration file discovery
- IPC (Inter-Process Communication) path generation

### Key Functions

#### _meshNodeId() - Lines 17-63 (Main Export Function)

**Purpose:** Retrieves the agent's unique Node ID from the certificate or database.

**Process:**
- **Linux/macOS** (lines 22-32):
  - Attempts to open database at `process.execPath + '.db'` in read-only mode
  - Retrieves `SelfNodeCert` buffer from database
  - Loads certificate with passphrase 'hidden'
  - Extracts SHA384 hash of certificate key using `getKeyHash()`
  - Returns 64-character hex string
  - Returns empty string on error (database missing, cert invalid)

- **Windows** (lines 33-58):
  - Opens database at `process.execPath.replace('.exe', '.db')`
  - **First tries:** Loading `SelfNodeCert` as certificate → extract key hash
  - **Fallback:** If cert parse fails, directly read `NodeID` buffer (line 50)
  - Returns 64-character hex string from either source
  - Returns empty string if both methods fail

**Return Value:** String (64-char hex) or empty string

**Platform Behavior:**
- All platforms use same certificate extraction method
- Windows has fallback to direct NodeID buffer
- Database path differs by platform (.exe.db vs .db extension)

---

#### _meshName() - Lines 65-115 (Service Name Discovery)

**Purpose:** Discovers the installed service name for the MeshAgent.

**Process:**

1. **Check .msh file first** (line 67):
   - Calls `_MSH().meshServiceName`
   - If .msh contains service name, return immediately

2. **Windows Registry Search** (lines 72-98):
   - Requires `win-registry` module
   - Retrieves current NodeID via `_meshNodeId()`
   - Searches registry under `Software\Open Source\*` in both:
     - `HKEY_LocalMachine` (line 77)
     - `HKEY_CurrentUser` (line 77)
   - For each subkey:
     - Reads `NodeId` registry value (line 87)
     - Decodes from modified base64 (@→+, $→/) to hex
     - Compares with current NodeID
     - Returns matching service name
   - Falls back to "Mesh Agent" if not found (line 98)

3. **Unix Service Enumeration** (lines 100-111):
   - Uses `service-manager.manager.enumerateService()`
   - Iterates through all services
   - Compares `service.appLocation()` with `process.execPath`
   - Returns matching service name
   - Falls back to "meshagent" if not found (line 102)

**Return Value:** String (service name)

**Platform Behavior:**
- Windows: Registry-based, supports user-specific installs
- Linux/macOS/FreeBSD: Service manager-based, system-wide only
- Defaults: "Mesh Agent" (Windows), "meshagent" (Unix)

---

#### _resetNodeId() - Lines 117-122 (Windows Only)

**Purpose:** Sets registry flag to trigger NodeID regeneration on next agent startup.

**Process:**
- Retrieves current service name via `_meshName()`
- Writes registry key: `HKLM\Software\Open Source\{serviceName}\ResetNodeId` = 1
- Logs message: "Resetting NodeID for: {serviceName}"

**Platform Behavior:**
- **Windows only** - No platform check, will throw on Unix
- Requires administrative privileges (HKLM write)
- Agent must be restarted for change to take effect

**Use Case:** Factory reset, duplicate agent resolution, identity conflict repair

---

#### _checkResetNodeId(name) - Lines 123-148 (Windows Only)

**Purpose:** Checks if NodeID reset was requested and clears the flag.

**Process:**
1. **Check Registry** (lines 126-133):
   - Reads `HKLM\Software\Open Source\{name}\ResetNodeId`
   - Returns false if key doesn't exist or != 1

2. **Delete Flag** (lines 134-146):
   - If reset requested, attempts to delete registry key
   - **Critical safety:** If deletion fails, returns false (line 144)
   - Prevents infinite reset loop if key can't be deleted
   - Returns true only if flag exists AND can be deleted

**Return Value:** Boolean (true = reset requested and cleared)

**Platform Behavior:**
- **Windows only** - No platform check, will throw on Unix
- Called by agent during startup initialization
- Atomic read-and-clear operation

**Safety Features:**
- Returns false if flag can't be deleted (prevents loops)
- Silent error handling (try/catch, no exceptions)

---

### Module Exports

**Lines 150-153:**
```javascript
module.exports = _meshNodeId;                    // Main function
module.exports.serviceName = _meshName;          // Service name getter
module.exports.resetNodeId = _resetNodeId;       // Reset trigger (Windows)
module.exports.checkResetNodeId = _checkResetNodeId;  // Reset checker (Windows)
```

### Dependencies

#### Node.js Core Modules
- None required

#### MeshAgent Module Dependencies

**Required on All Platforms:**
- **`SimpleDataStore`** (lines 26, 37) - Database access
  - Methods: `Create(path, {readOnly: true})`, `GetBuffer(key)`
  - Reads agent's certificate and NodeID from .db file

- **`tls`** (lines 27, 43) - TLS/Certificate operations
  - Methods: `loadCertificate({pfx, passphrase})`, `getKeyHash()`
  - Extracts SHA384 hash from certificate key

**Windows-Specific:**
- **`win-registry`** (line 74, 120, 129, 139) - Windows Registry access
  - Constants: `HKEY.LocalMachine`, `HKEY.CurrentUser`
  - Methods: `QueryKey(hkey, path, valueName)`, `WriteKey(hkey, path, valueName, value)`, `DeleteKey(hkey, path, valueName)`
  - Used for service name discovery and NodeID reset

**Unix-Specific:**
- **`service-manager`** (line 101) - Service enumeration
  - Methods: `manager.enumerateService()`
  - Properties: `service.name`, `service.appLocation()`
  - Used to find service name by executable path

#### External Dependencies
- None - No external binaries or system calls

### Usage

#### Basic Usage

```javascript
// Get Node ID
var nodeid = require('_agentNodeId')();
console.log('Node ID:', nodeid);  // 64-char hex string

// Get service name
var serviceName = require('_agentNodeId').serviceName();
console.log('Service:', serviceName);

// Reset NodeID (Windows only)
require('_agentNodeId').resetNodeId();
// Agent must be restarted after this

// Check for pending reset (Windows only, called during agent startup)
var resetPending = require('_agentNodeId').checkResetNodeId(serviceName);
if (resetPending) {
    // Regenerate NodeID, create new certificate
}
```

#### Integration with Other Modules

**_agentStatus.js** (line 3):
```javascript
var nodeid = require('_agentNodeId')();
var ipcPath = process.platform == 'win32'
    ? ('\\\\.\\pipe\\' + nodeid + '-DAIPC')
    : (process.cwd() + '/DAIPC');
```

**agent-installer.js** (lines 330, 1701):
```javascript
// Detect service name for upgrade
var serviceName = require('_agentNodeId').serviceName();

// Find installation directory
var service = require('service-manager').manager.getService(serviceName);
```

### Technical Notes

**Certificate-Based Identity:**
The Node ID is derived from the SHA384 hash of the agent's TLS certificate private key. This ensures:
- Unique identification across MeshCentral network
- Cryptographic binding to agent's identity
- Persistence across agent updates (stored in .db file)
- Impossible to forge without private key

**Database Storage Format:**
- **Location:** `{execPath}.db` (Unix) or `{execPath.replace('.exe', '.db')}` (Windows)
- **Key:** `SelfNodeCert` - PKCS#12 certificate bundle (pfx format)
- **Key:** `NodeID` (Windows fallback) - Raw 32-byte buffer (64 hex chars)
- **Passphrase:** 'hidden' (hardcoded, not secret - obfuscation only)

**Windows Registry Format:**
- **Path:** `HKLM\Software\Open Source\{ServiceName}\NodeId`
- **Encoding:** Modified base64 (@ instead of +, $ instead of /)
- **Purpose:** Service name → NodeID lookup for multi-install support

**Service Name Discovery Priority:**
1. .msh file `meshServiceName` field (if available)
2. Windows: Registry search by NodeID
3. Unix: Service manager enumeration by execPath
4. Fallback: "Mesh Agent" (Windows) or "meshagent" (Unix)

**NodeID Reset Mechanism (Windows):**
- Registry flag triggers reset on next agent startup
- Agent generates new certificate and NodeID
- Old identity is abandoned (unrecoverable)
- Requires re-enrollment with MeshCentral server
- Use cases: Duplicate agent resolution, factory reset

**Error Handling:**
- All functions use try/catch with silent failures
- Returns empty string or default values on error
- No exceptions thrown to prevent agent crashes
- Critical for stability during startup

### Platform-Specific Analysis

**What Works on macOS:**
- Node ID retrieval from database
- Service name discovery via service-manager
- All functionality except NodeID reset

**macOS-Specific Behavior:**
- Database path: `/path/to/meshagent.db`
- Service enumeration via `service-manager` (launchd services)
- Default service name: "meshagent"
- No registry operations (Unix-based)

**What Doesn't Work on macOS:**
- `resetNodeId()` - Will throw `win-registry` not found error
- `checkResetNodeId()` - Will throw `win-registry` not found error

**Implementation Recommendations for macOS:**
To add NodeID reset functionality on macOS:
1. Store reset flag in .db file instead of registry
2. Add platform check in `resetNodeId()` and `checkResetNodeId()`
3. Use `SimpleDataStore.Put('ResetNodeId', Buffer.from('1'))` for flag
4. Check and delete during startup

## Summary

The _agentNodeId.js module provides essential identity management for MeshAgent across all supported platforms (Windows, Linux, macOS, FreeBSD). It retrieves the agent's unique 64-character hexadecimal Node ID from the TLS certificate stored in the database, and discovers the installed service name through platform-specific mechanisms.

**Key capabilities:**
- Certificate-based Node ID extraction (SHA384 hash of private key)
- Cross-platform service name discovery (registry on Windows, service enumeration on Unix)
- NodeID reset functionality (Windows only via registry)
- Database persistence for identity

**macOS support:**
- Full support for Node ID retrieval and service name discovery
- NodeID reset functions will throw errors on macOS (Windows-only feature)
- Uses service-manager for launchd service enumeration
- Default service name: "meshagent"

**Critical dependencies:**
- SimpleDataStore for database access
- tls for certificate operations
- win-registry (Windows only)
- service-manager (Unix only)

The module is essential for agent identification, IPC communication, configuration discovery, and service management operations throughout the MeshAgent ecosystem.
