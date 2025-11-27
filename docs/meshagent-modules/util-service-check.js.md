# util-service-check.js

Windows-specific utility module that attempts to determine the service name for the currently running MeshAgent service by querying the Windows registry and Service Control Manager. This module is used primarily during troubleshooting and diagnostics to identify which service instance is executing.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via registry and service manager APIs

**Excluded Platforms:**
- **Linux** - Not supported (returns null)
- **macOS (darwin)** - Not supported (returns null)
- **FreeBSD** - Not supported (returns null)

**Exclusion Reasoning:**

Non-Windows platforms are excluded because:

1. **Windows-Specific APIs** - Module uses Windows Registry and Service Control Manager, which don't exist on other platforms
2. **Different Service Managers** - Linux uses systemd/init, macOS uses launchd - each requires platform-specific implementation
3. **Registry Dependency** - The module relies on Windows Registry keys under `HKLM\SOFTWARE\Open Source` where MeshAgent stores installation info
4. **Service Manager Integration** - Uses `service-manager` module's Windows-specific features (`isMe()` method)
5. **Design Purpose** - Solves Windows-specific problem of multiple service instances

On non-Windows platforms, service name determination would require completely different implementations using platform-specific tools (systemctl, launchctl, etc.).

## Functionality

### Purpose

The util-service-check module determines which Windows service corresponds to the currently running process. This is useful when:

- Multiple MeshAgent instances are installed on the same system
- Debugging which service instance is executing
- Programmatically identifying the service for management operations
- Verifying the agent is running as an installed service

The module uses a two-phase approach:
1. **Phase 1**: Check registry entries under `HKLM\SOFTWARE\Open Source` (standard MeshAgent installation location)
2. **Phase 2**: Brute-force enumerate all Windows services if Phase 1 fails

### Service Detection Strategy

**Phase 1 - Registry Lookup (lines 30-64):**
1. Query `HKLM\SOFTWARE\Open Source` for subkeys
2. For each subkey (potential service name):
   - Open service via Service Control Manager
   - Call `service.isMe()` to check if PID matches current process
   - If match found, return service name
   - Close service handle

**Phase 2 - Service Enumeration (lines 66-112):**
If Phase 1 fails (no match in Open Source registry key):
1. Enumerate all services in `HKLM\SYSTEM\CurrentControlSet\Services`
2. For each service:
   - Read `ImagePath` registry value
   - Extract executable path
   - Compare with `process.execPath`
   - If paths match:
     - Open service handle
     - Call `service.isMe()` to verify PID
     - If PID matches, return service name

### Key Functions

#### win_serviceCheck() - Lines 25-114

**Purpose:** Determines the service name for the currently running process.

**Process:**

**Phase 1 - Standard Registry Check (lines 30-64):**
```javascript
var reg = require('win-registry');
var values = reg.QueryKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Open Source');

if (values.subkeys) {
    for (var i in values.subkeys) {
        s = require('service-manager').manager.getService(values.subkeys[i]);
        if(s.isMe()) {
            s.close();
            return (values.subkeys[i]);
        }
    }
}
```

1. Queries registry for MeshAgent installation entries
2. Each subkey represents a potential service name
3. Opens service handle for each candidate
4. Checks if service PID matches current process
5. Returns service name if match found

**Phase 2 - Full Service Enumeration (lines 66-112):**
```javascript
values = reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services');

for(var i in values.subkeys) {
    path = reg.QueryKey(reg.HKEY.LocalMachine,
        'SYSTEM\\CurrentControlSet\\Services\\' + values.subkeys[i], 'ImagePath');

    path = path.split('.exe')[0] + '.exe';
    if (path.startsWith('"')) { path = path.substring(1); }

    if(path == process.execPath) {
        s = require('service-manager').manager.getService(values.subkeys[i]);
        if(s.isMe()) {
            s.close();
            return (values.subkeys[i]);
        }
    }
}
```

1. Enumerates all Windows services
2. Reads ImagePath for each service
3. Normalizes path (removes quotes, ensures .exe extension)
4. Compares with current process executable path
5. If paths match, verifies PID with `isMe()`
6. Returns service name if both checks pass

**Return Value:**
- Service name (string) if found
- `null` if not running as a service or service cannot be determined

**Platform Behavior:**
- **Windows**: Full functionality
- **Other platforms**: Returns `null` (lines 121-123)

**Error Handling:**
- Uses try-catch blocks around service operations (lines 40-62, 77-108)
- Silently continues on errors (empty catch blocks)
- Returns `null` if no match found

---

### Module Export - Lines 116-124

```javascript
switch(process.platform)
{
    case 'win32':
        module.exports = win_serviceCheck;
        break;
    default:
        module.exports = function () { return (null); }
        break;
}
```

**Usage:**
```javascript
var serviceCheck = require('util-service-check');
var serviceName = serviceCheck();
// Windows: "Mesh Agent" or "MyMeshAgent" or null
// Linux/macOS: null
```

---

### Dependencies

#### Node.js Core Modules
None - Uses only MeshAgent-specific modules

#### MeshAgent Module Dependencies

**Core Required Modules:**

- **`win-registry`** (lines 28, 30, 67, 80) - **Windows only**
  - Windows Registry access module
  - Methods used:
    - `QueryKey(hive, path, value?)` - Query registry keys/values
  - Constants used:
    - `HKEY.LocalMachine` - HKLM registry hive
  - Properties accessed:
    - `subkeys` array - List of subkey names

- **`service-manager`** (lines 46, 98) - **Windows only**
  - Windows Service Control Manager interface
  - Objects used:
    - `manager.getService(name)` - Get service object by name
  - Service object methods:
    - `isMe()` - Returns true if service PID matches current process
    - `close()` - Closes service handle

#### Platform System Dependencies

**Windows:**
- **Windows Registry** - Must have access to:
  - `HKLM\SOFTWARE\Open Source` (standard MeshAgent install location)
  - `HKLM\SYSTEM\CurrentControlSet\Services` (all services)
- **Service Control Manager** - Must have permissions to:
  - Query service information
  - Compare service PIDs

### Technical Notes

**Why Two-Phase Approach:**

Phase 1 is optimized for standard MeshAgent installations:
- Faster - only checks known locations
- Most reliable - uses standard installation registry structure

Phase 2 is fallback for non-standard installations:
- Comprehensive - checks all services
- Slower - must enumerate entire service database
- Handles custom installation paths

**ImagePath Normalization:**

Service ImagePaths can have various formats:
```
"C:\Program Files\Mesh\agent.exe"         <- Quoted
C:\Program Files\Mesh\agent.exe           <- Unquoted
C:\Program Files\Mesh\agent.exe --args    <- With arguments
```

The code normalizes by:
1. Splitting on `.exe` and taking first part
2. Adding `.exe` back
3. Removing leading quote if present

```javascript
path = path.split('.exe')[0] + '.exe';
if (path.startsWith('"')) { path = path.substring(1); }
```

**Service Handle Management:**

Always closes service handles:
```javascript
if(s.isMe()) {
    s.close();
    return (serviceName);
}
else {
    s.close();
}
```

This prevents handle leaks even when service is found.

**Process Identity Check:**

The `isMe()` method compares service PID with current process PID. This is critical because:
- Multiple services may use the same executable
- Executable path alone is insufficient for identification
- PID provides definitive identification

**Registry Structure:**

MeshAgent installations store data in:
```
HKLM\SOFTWARE\Open Source\
    <ServiceName>\
        NodeId
        InstallPath
        ... other config ...
```

Each subkey name is a potential service name.

**Empty Catch Blocks:**

The code uses empty catch blocks:
```javascript
catch(x) { }
```

This is intentional - the function should never throw exceptions, only return null if service cannot be determined.

**Why Return Null:**

Returning `null` instead of throwing indicates:
- Not running as a service (running interactively)
- Service cannot be determined
- Not on Windows platform

This allows callers to gracefully handle non-service scenarios.

## Summary

The util-service-check.js module is a **Windows-only** utility that determines the service name for the currently running MeshAgent process. It uses a two-phase approach: first checking standard MeshAgent registry entries, then falling back to enumerating all Windows services if necessary.

**Non-Windows platforms** (Linux, macOS, FreeBSD) are not supported and return `null` because the module relies on Windows-specific APIs including the Registry and Service Control Manager. Each platform would require a completely different implementation using its own service management system (systemd, launchd, etc.).

The module is primarily used for diagnostics, troubleshooting, and programmatic service identification when multiple MeshAgent instances may be installed on the same Windows system. It safely handles errors and edge cases, never throwing exceptions, making it suitable for use in production environments.
