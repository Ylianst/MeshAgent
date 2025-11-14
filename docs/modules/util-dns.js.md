# util-dns.js

Cross-platform utility module for querying the system's configured DNS server addresses. Provides platform-specific implementations for Windows, Linux, FreeBSD, and macOS using native system APIs and command-line utilities.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via Iphlpapi.dll GetNetworkParams() API
- Linux - Full support via `/etc/resolv.conf` parsing
- FreeBSD - Full support via `/etc/resolv.conf` parsing
- macOS (darwin) - Full support via `scutil --dns` system utility

## Functionality

### Purpose

The util-dns module provides a consistent interface for discovering DNS server addresses across different operating systems. Each platform uses its native method for DNS configuration retrieval:

- **Windows**: Windows IP Helper API (`GetNetworkParams()`)
- **Linux/FreeBSD**: Parse `/etc/resolv.conf` configuration file
- **macOS**: Query system configuration via `scutil --dns`

This module is used by MeshAgent to:
- Diagnose network connectivity issues
- Validate DNS configuration
- Report system network settings
- Troubleshoot name resolution problems

### Platform-Specific Implementations

#### Windows Implementation - Lines 21-46

Uses Windows IP Helper API to retrieve network parameters:

**API Reference:**
https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getnetworkparams

**Process:**
1. Loads `Iphlpapi.dll` native library (line 29)
2. Creates method marshal for `GetNetworkParams()` (line 30)
3. Allocates 1024-byte buffer for FIXED_INFO structure (line 32)
4. Calls `GetNetworkParams(buffer, &length)` (line 36)
5. Parses IP_ADDR_STRING linked list starting at offset 268/272:
   - 32-bit systems: offset 268
   - 64-bit systems: offset 272
6. Iterates through linked list of DNS servers (lines 40-43)
7. Extracts IP address strings at offset 16 (line 42)
8. Returns array of DNS server addresses

**Data Structure:**
```
FIXED_INFO structure contains:
- Offset 268/272: Pointer to first IP_ADDR_STRING
- IP_ADDR_STRING.IpAddress (offset 16): DNS server IP
- IP_ADDR_STRING.Next (offset 0): Pointer to next entry
```

---

#### Linux/FreeBSD Implementation - Lines 47-82

Parses `/etc/resolv.conf` to extract nameserver entries:

**Process:**
1. Spawns `/bin/sh` subprocess (line 53)
2. Executes command pipeline:
   ```bash
   cat /etc/resolv.conf | grep nameserver | tr '\n' '`' | awk -F'`' '...'
   ```
3. Filters lines starting with `nameserver` (line 62)
4. Skips commented lines (lines starting with `#`) (line 62)
5. Extracts second token (IP address) from each line (line 64-66)
6. Formats as JSON array with quoted strings (line 66)
7. Parses JSON result (line 76)
8. Returns array of DNS server addresses
9. Returns empty array on parse error (line 80)

**resolv.conf Format:**
```
nameserver 8.8.8.8
nameserver 8.8.4.4
# nameserver 1.1.1.1  <- skipped (commented)
```

---

#### macOS Implementation - Lines 84-121

Uses `scutil --dns` system configuration utility:

**Process:**
1. Spawns `/bin/sh` subprocess (line 89)
2. Executes command:
   ```bash
   scutil --dns | grep nameserver | tr '\n' '`' | awk -F'`' '...'
   ```
3. Filters lines matching pattern: `nameserver[0]` through `nameserver[9]` (line 99)
4. Extracts nameserver index (token 3) and IP address (token 1) (line 102)
5. Builds JSON object with nameserver indices as keys:
   ```json
   {
     "nameserver[0]": "8.8.8.8",
     "nameserver[1]": "8.8.4.4"
   }
   ```
6. Parses JSON object (line 114)
7. Extracts keys (IP addresses) using `table.keys()` (line 115)
8. Returns array of unique DNS server addresses
9. Returns empty array on error (line 119)

**scutil --dns Output Format:**
```
DNS configuration

resolver #1
  nameserver[0] : 8.8.8.8
  nameserver[1] : 8.8.4.4
  if_index : 4 (en0)
```

The awk script parses nameserver entries and creates a JSON mapping where keys are IP addresses, ensuring uniqueness.

---

### Key Functions

#### windows_dns() - Lines 21-46

**Purpose:** Queries DNS servers on Windows via IP Helper API.

**Return Value:**
- Array of DNS server IP address strings
- Example: `["8.8.8.8", "8.8.4.4"]`

**Platform Behavior:**
- Windows only
- Uses native Windows API
- Follows DNS server priority order

---

#### linux_dns() - Lines 47-82

**Purpose:** Queries DNS servers on Linux/FreeBSD by parsing `/etc/resolv.conf`.

**Return Value:**
- Array of DNS server IP address strings
- Empty array if file cannot be parsed

**Platform Behavior:**
- Linux and FreeBSD
- Parses system configuration file
- Returns servers in configuration file order
- Filters out commented entries

---

#### macos_dns() - Lines 84-121

**Purpose:** Queries DNS servers on macOS using `scutil --dns`.

**Return Value:**
- Array of DNS server IP address strings (deduplicated)
- Empty array on error

**Platform Behavior:**
- macOS only
- Uses system configuration utility
- Returns unique DNS servers across all resolvers
- Order may not reflect priority

---

### Module Export - Lines 123-138

The module exports the appropriate function based on platform:

```javascript
switch (process.platform) {
    case 'linux':
    case 'freebsd':
        module.exports = linux_dns;
        break;
    case 'win32':
        module.exports = windows_dns;
        break;
    case 'darwin':
        module.exports = macos_dns;
        break;
    default:
        module.exports = function () { return ([]); };
}
```

**Usage:**
```javascript
var getDNS = require('util-dns');
var dnsServers = getDNS();
// Returns: ["8.8.8.8", "8.8.4.4", "192.168.1.1"]
```

---

### Dependencies

#### Node.js Core Modules
- `child_process` (lines 53, 89) - Used on Linux/FreeBSD/macOS:
  - `execFile('/bin/sh', ['sh'])` - Executes shell commands

#### MeshAgent Module Dependencies

**Core Required Modules:**

- **`_GenericMarshal`** (lines 29, 32-34) - **Windows only**
  - Native code marshaling for Windows API calls
  - Methods used:
    - `CreateNativeProxy('Iphlpapi.dll')` - Load Windows IP Helper library
    - `CreateVariable(size)` - Allocate native memory buffers
    - `Deref(offset, size)` - Dereference pointers with offset

**Platform Binary Dependencies:**

**Linux/FreeBSD:**
- `/etc/resolv.conf` file must exist and be readable
- Standard POSIX tools: `cat`, `grep`, `tr`, `awk`

**macOS:**
- `scutil` - System Configuration utility (standard on macOS)
- Shell tools: `grep`, `tr`, `awk`

**Windows:**
- `Iphlpapi.dll` - Windows IP Helper API (standard system library)

### Technical Notes

**Why Different Methods per Platform:**

Each platform stores DNS configuration differently:
- **Windows**: Centralized in registry, accessed via API
- **Linux/FreeBSD**: Plain text file `/etc/resolv.conf`
- **macOS**: System configuration database via `scutil`

**Linked List Traversal (Windows):**
The Windows implementation traverses a linked list in native memory:
```javascript
do {
    ret.push(dnsList.Deref(offset, 16).toBuffer().toString());
} while ((dnsList = dnsList.Deref(0, PointerSize).Deref().Deref(0, 48)).Val != 0);
```

This:
1. Reads IP address at offset 16
2. Follows pointer at offset 0 to next node
3. Continues until pointer is NULL (Val == 0)

**JSON Formatting Pattern:**
All implementations use awk to format output as JSON:
```awk
printf "["; DEL="";
for(i=1;i<NF;++i) {
    printf "%s\"%s\"", DEL, $i;
    DEL=",";
}
printf "]";
```

This generates valid JSON without external tools.

**macOS Deduplication:**
The macOS implementation uses an object to deduplicate DNS servers:
```javascript
var table = JSON.parse(child.stdout.str.trim());
return(table.keys());  // Returns unique IPs
```

This is necessary because `scutil --dns` may list the same DNS server in multiple resolver configurations.

**Error Handling:**
All implementations use try-catch around JSON parsing:
```javascript
try {
    return (JSON.parse(output));
} catch(e) {
    return ([]);
}
```

This ensures the function never throws, returning an empty array instead.

**Shell Command Safety:**
The shell commands use single quotes to prevent injection:
```javascript
child.stdin.write("awk -F'`' '{ ... }'");
```

No user input is interpolated into commands.

## Summary

The util-dns.js module provides cross-platform DNS server discovery for **Windows, Linux, FreeBSD, and macOS**. Each platform uses its native method:

- **Windows**: IP Helper API (`GetNetworkParams()`) via native marshaling
- **Linux/FreeBSD**: Parse `/etc/resolv.conf` text file
- **macOS**: Query `scutil --dns` system configuration utility

The module exports a single function that returns an array of DNS server IP addresses. The implementation is automatically selected based on `process.platform`, providing a consistent interface across all supported operating systems while using the most appropriate method for each platform.

This module requires no configuration and handles errors gracefully by returning an empty array when DNS information cannot be retrieved.
