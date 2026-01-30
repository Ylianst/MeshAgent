# macOS MeshAgent ServiceID System

## Table of Contents
1. [Introduction](#introduction)
2. [ServiceID Values](#serviceid-values)
3. [How ServiceID is Determined](#how-serviceid-is-determined)
4. [Input Sanitization](#input-sanitization)
5. [Storage Mechanisms](#storage-mechanisms)
6. [Usage in File Paths](#usage-in-file-paths)
7. [KVM Path Resolution](#kvm-path-resolution)
8. [Runtime Loading](#runtime-loading)
9. [Installation Flow](#installation-flow)
10. [Command-Line Parameters](#command-line-parameters)
11. [Real-World Examples](#real-world-examples)
12. [Implementation Reference](#implementation-reference)

---

## Introduction

The **serviceID** is a unique identifier that distinguishes different MeshAgent installations on the same macOS system. It enables multiple independent agents to coexist by providing namespace separation for:

- LaunchDaemon/LaunchAgent plist files
- Runtime sockets and directories
- Service lookup via `launchctl`
- Logging paths

The serviceID system supports:
- **Multi-tenancy**: Multiple agents with different identities on one machine
- **Clean upgrades**: Correct identification of existing services during version transitions
- **Name collision prevention**: Unique identifiers in system directories

Note: The serviceID controls **plist naming and runtime paths**. The **installation directory structure** is determined separately by `serviceName` and `companyName` (see [Installation Flow](#installation-flow)).

---

## ServiceID Values

A serviceID is a **flat string** — not a dotted composite or reverse-DNS format. It is the sanitized executable basename by default, or an explicit override.

**Examples of real serviceID values:**

| Scenario | ServiceID |
|----------|-----------|
| Default (binary named `meshagent`) | `meshagent` |
| Binary renamed to `acmemesh` | `acmemesh` |
| Explicit `--serviceId=com.acme.remote` | `com.acme.remote` |
| Explicit `--setServiceID=acmemesh` | `acmemesh` |
| `.msh` contains `ServiceID=acmemesh` | `acmemesh` |

The `buildServiceId()` function accepts `serviceName` and `companyName` parameters for API compatibility, but **ignores them both**. It returns the sanitized executable basename (or an explicit override if provided).

---

## How ServiceID is Determined

### JavaScript-Level Priority (agent-installer.js checkParameters)

During installation, `checkParameters()` resolves the serviceID in this order:

```
Priority 1: --setServiceID command-line flag
             (mapped to --serviceId before .msh injection)

Priority 2: --serviceId command-line flag (direct)

Priority 3: ServiceID field from embedded .msh file

Priority 4: buildServiceId() → sanitized executable basename
```

**Code Location:** `modules/agent-installer.js` lines 263-333

```javascript
// --setServiceID is the user-facing flag for fresh install/finstall.
// Map to --serviceId so downstream code picks it up (before .msh injection).
var setServiceID = parms.getParameter('setServiceID', null);
if (setServiceID && parms.getParameter('serviceId', null) == null) {
    parms.push('--serviceId="' + setServiceID + '"');
}

// Inject ServiceID from embedded .msh if not provided on command line
var mshServiceId = msh.ServiceID || msh.serviceId;
if (parms.getParameter('serviceId', null) == null && mshServiceId != null) {
    parms.push('--serviceId="' + mshServiceId + '"');
}
```

### C-Level Priority (agentcore.c runtime)

At runtime, `agentcore.c` loads the serviceID:

```
Priority 1: --serviceId= command-line parameter (overrides database)

Priority 2: ServiceID key from .db database file

Priority 3: NULL (no serviceID set — meshServiceName used for service lookup)
```

**Code Location:** `meshcore/agentcore.c` lines 5616-5641

### buildServiceId() Implementation

```javascript
// modules/macOSHelpers.js lines 87-98
function buildServiceId(serviceName, companyName, options) {
    options = options || {};
    var explicitServiceId = options.explicitServiceId || null;

    if (explicitServiceId !== null) {
        return explicitServiceId;
    }

    var agentPaths = require('agent-paths');
    var baseName = options.baseName || agentPaths.getAgentBaseName();
    return sanitizeIdentifier(baseName);
}
```

Key points:
- `serviceName` and `companyName` are **accepted but ignored** (vestigial parameters)
- No platform branching — identical behavior on all platforms
- Returns explicit override if provided via `options.explicitServiceId`
- Otherwise returns the sanitized executable basename

---

## Input Sanitization

### Sanitization Rules

The `sanitizeIdentifier()` function transforms input into valid identifiers:

```javascript
// modules/macOSHelpers.js lines 77-81
function sanitizeIdentifier(str) {
    if (!str) return null;
    return str
        .replace(/\s+/g, '-')           // Spaces → hyphens
        .replace(/[^a-zA-Z0-9_-]/g, '') // Remove special chars
        .toLowerCase();                  // Convert to lowercase
}
```

### Transformation Examples

| Input | After Space→Hyphen | After Special Char Removal | After Lowercase | Final Result |
|-------|-------------------|---------------------------|----------------|--------------|
| `ACME, Inc.` | `ACME,-Inc.` | `ACME-Inc` | `acme-inc` | `acme-inc` |
| `ACME Mesh` | `ACME-Mesh` | `ACME-Mesh` | `acme-mesh` | `acme-mesh` |
| `ACMEmesh` | `ACMEmesh` | `ACMEmesh` | `acmemesh` | `acmemesh` |
| `ACME_Remote` | `ACME_Remote` | `ACME_Remote` | `acme_remote` | `acme_remote` |
| `@#$%^&*()` | `@#$%^&*()` | (empty) | (empty) | `null` |

### Character Allowlist

**Allowed Characters:**
- Lowercase letters: `a-z`
- Uppercase letters: `A-Z` (converted to lowercase)
- Digits: `0-9`
- Hyphen: `-`
- Underscore: `_`

**Converted Characters:**
- Spaces → Hyphens

**Removed Characters:**
- All other special characters: `!@#$%^&*()+={}[]|\\:;"'<>,.?/~`

---

## Storage Mechanisms

### Where ServiceID is Stored

```
1. Command-Line Flags (Transient)
   └─ --serviceId=acmemesh  or  --setServiceID=acmemesh

2. LaunchDaemon Plist (Persistent)
   └─ /Library/LaunchDaemons/{serviceId}.plist
      ├─ Label: {serviceId}
      └─ ProgramArguments: [binary, --serviceId={serviceId}, ...]

3. LaunchAgent Plist (Persistent)
   └─ ~/Library/LaunchAgents/{serviceId}-agent.plist
      ├─ Label: {serviceId}-agent
      └─ ProgramArguments: [binary, -kvm1, --serviceId={serviceId}]

4. .msh Configuration File (Persistent)
   └─ {installPath}/meshagent.msh
      ├─ ServiceID=acmemesh
      ├─ MeshServiceName=ACME Mesh
      └─ CompanyName=ACME, Inc.

5. .db Database File (Persistent)
   └─ {installPath}/meshagent.db
      ├─ ServiceID (key-value)
      ├─ meshServiceName (key-value)
      └─ companyName (key-value)
```

### Storage Details

#### 1. LaunchDaemon Plist

**Path:** `/Library/LaunchDaemons/{serviceId}.plist`

**Example (default agent):**
```xml
<key>Label</key>
<string>meshagent</string>

<key>ProgramArguments</key>
<array>
    <string>/usr/local/mesh_services/meshagent/meshagent</string>
    <string>--serviceId=meshagent</string>
</array>
```

**Example (custom serviceID):**
```xml
<key>Label</key>
<string>acmemesh</string>

<key>ProgramArguments</key>
<array>
    <string>/opt/acmemesh/meshagent</string>
    <string>--meshServiceName=ACME Mesh</string>
    <string>--companyName=ACME, Inc.</string>
    <string>--serviceId=acmemesh</string>
</array>
```

#### 2. LaunchAgent Plist

**Path:** `~/Library/LaunchAgents/{serviceId}-agent.plist`

The LaunchAgent is used for the `-kvm1` (KVM child) process. It receives the serviceID via `--serviceId=` so it can connect to the correct daemon socket.

```xml
<key>Label</key>
<string>acmemesh-agent</string>

<key>ProgramArguments</key>
<array>
    <string>/opt/acmemesh/meshagent</string>
    <string>-kvm1</string>
    <string>--serviceId=acmemesh</string>
</array>

<key>QueueDirectories</key>
<array>
    <string>/var/run/acmemesh</string>
</array>
```

#### 3. .msh Configuration File

**Path:** `{installPath}/meshagent.msh`

**Example:**
```
MeshName=ACMEnet
MeshType=2
MeshID=0x1234567890ABCDEF
ServerID=server1
MeshServer=wss://mesh.acme.example.com:443/agent.ashx
MeshServiceName=ACME Mesh
CompanyName=ACME, Inc.
ServiceID=acmemesh
```

The `ServiceID` field in the .msh is used during `checkParameters()` as a fallback when no `--serviceId` is provided on the command line.

#### 4. .db Database File

**Path:** `{installPath}/meshagent.db`

**Type:** SimpleDataStore (key-value store)

**Relevant Keys:**
- `ServiceID` — the serviceID string
- `meshServiceName` — service display name
- `companyName` — company name

Loaded by `agentcore.c` at startup (lines 5592-5624). The `--serviceId` command-line flag overrides the database value (lines 5626-5641).

---

## Usage in File Paths

### Path Template Matrix

| Component | Template | Default Example | Custom Example (`--serviceId=acmemesh`) |
|-----------|----------|-----------------|------------------------------------------|
| **LaunchDaemon plist** | `/Library/LaunchDaemons/{serviceId}.plist` | `meshagent.plist` | `acmemesh.plist` |
| **LaunchAgent plist** | `~/Library/LaunchAgents/{serviceId}-agent.plist` | `meshagent-agent.plist` | `acmemesh-agent.plist` |
| **Socket** | `/tmp/{serviceId}.sock` | `/tmp/meshagent.sock` | `/tmp/acmemesh.sock` |
| **Queue directory** | `/var/run/{serviceId}/` | `/var/run/meshagent/` | `/var/run/acmemesh/` |
| **Session signal** | `/var/run/{serviceId}/session-active` | `/var/run/meshagent/session-active` | `/var/run/acmemesh/session-active` |

### Install Directory (Separate from ServiceID)

The install directory is constructed from `serviceName` and `companyName`, **not** from the serviceID. It can also be overridden explicitly with `--installPath`:

| Scenario | Install Path |
|----------|-------------|
| Default | `/usr/local/mesh_services/meshagent/` |
| Custom service only (`ACME Mesh`) | `/usr/local/mesh_services/acme-mesh/` |
| Company + service (`ACME, Inc.` + `ACME Mesh`) | `/usr/local/mesh_services/acme-inc/acme-mesh/` |
| Explicit `--installPath=/opt/acmemesh` | `/opt/acmemesh/` |

**Code Location:** `modules/agent-installer.js` lines 1906-1930

### Launchd Service Paths

**Format:**
```
{domain}/{serviceId}
{domain}/{serviceId}-agent
```

**Examples:**
```
system/meshagent                    # Default daemon
system/acmemesh                     # Custom daemon

gui/502/meshagent-agent             # Default agent (uid 502)
gui/502/acmemesh-agent              # Custom agent (uid 502)
```

---

## KVM Path Resolution

The C-level KVM code in `mac_kvm.c` resolves the serviceID independently to build socket and directory paths.

### `kvm_build_dynamic_paths()` (mac_kvm.c lines 458-519)

```c
static void kvm_build_dynamic_paths(char *serviceID, char *exePath)
{
    // Priority 1: Explicit serviceID (from --serviceId or database)
    if (serviceID != NULL && strlen(serviceID) > 0)
    {
        strncpy(serviceId, serviceID, sizeof(serviceId) - 1);
    }
    // Priority 2: Discover from LaunchDaemon plist Label
    else if (exePath != NULL && strlen(exePath) > 0)
    {
        char *plistServiceId = mesh_plist_find_service_id(
            "/Library/LaunchDaemons", exePath);
        if (plistServiceId != NULL) {
            strncpy(serviceId, plistServiceId, sizeof(serviceId) - 1);
            free(plistServiceId);
        }
    }
    // Priority 3: Fallback
    // serviceId defaults to "unknown-agent"

    // Build paths
    snprintf(KVM_Listener_Path, PATH_MAX, "/tmp/%s.sock", serviceId);
    snprintf(KVM_Queue_Directory, PATH_MAX, "/var/run/%s", serviceId);
    snprintf(KVM_Session_Signal_File, PATH_MAX, "/var/run/%s/session-active", serviceId);
}
```

### Plist Discovery (`mesh_plist_find_service_id`)

**Code Location:** `meshcore/MacOS/mac_plist_utils.c` lines 169-203

This function scans `/Library/LaunchDaemons/` for a plist whose `ProgramArguments[0]` matches the current binary path. If found, it returns the plist's `Label` field as the serviceID.

This is the fallback discovery mechanism used when no explicit `--serviceId` is passed to the C layer.

### KVM Session Flow

1. **Daemon** (`kvm_create_session`): Calls `kvm_build_dynamic_paths(serviceID, exePath)` to determine the socket path, then creates a Unix domain socket at `/tmp/{serviceId}.sock` and a signal file at `/var/run/{serviceId}/session-active`.

2. **Agent** (`kvm_server_mainloop`): The `-kvm1` child process receives `--serviceId=` on its command line, calls `kvm_build_dynamic_paths()`, and connects to the daemon's socket at `/tmp/{serviceId}.sock`.

---

## Runtime Loading

### agentcore.c Database Loading (lines 5592-5641)

At startup, the C agent loads three identity values from the `.db` file:

```c
// Load meshServiceName (default: "meshagent" on Unix, "Mesh Agent" on Windows)
agentHost->meshServiceName = db.Get("meshServiceName") || "meshagent";

// Load companyName (default: NULL)
agentHost->companyName = db.Get("companyName") || NULL;

// Load ServiceID (default: NULL)
agentHost->serviceID = db.Get("ServiceID") || NULL;
```

Then the `--serviceId=` command-line flag is checked and overrides the database value if present:

```c
for (int si = 0; si < paramLen; ++si) {
    if (strncmp(param[si], "--serviceId=", 12) == 0) {
        agentHost->serviceID = param[si] + 12;  // Override database value
        break;
    }
}
```

### Service Lookup (lines 5653-5656)

The agent uses `serviceID` for service-manager lookups when available, falling back to `meshServiceName`:

```c
char *serviceNameForLookup = (agentHost->serviceID != NULL)
    ? agentHost->serviceID
    : agentHost->meshServiceName;
```

### KVM Relay Setup (line 1519-1520)

When starting a KVM session, the C layer passes `serviceID` to `kvm_relay_setup()`, which forwards it to `kvm_create_session()`:

```c
kvm_relay_setup(agent->exePath, agent->pipeManager,
    ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink,
    ptrs, console_uid, agent->serviceID);
```

---

## Installation Flow

### Fresh Install

```
User runs: ./meshagent -install --setServiceID=acmemesh \
             --meshServiceName="ACME Mesh" --companyName="ACME, Inc." \
             --installPath=/opt/acmemesh

Step 1: checkParameters()
  • --setServiceID=acmemesh → mapped to --serviceId=acmemesh
  • serviceId = "acmemesh"

Step 2: Determine install path
  • --installPath=/opt/acmemesh provided explicitly
  • installPath = /opt/acmemesh/

Step 3: Copy binary
  • /opt/acmemesh/meshagent

Step 4: Write .msh file
  • ServiceID=acmemesh
  • MeshServiceName=ACME Mesh
  • CompanyName=ACME, Inc.

Step 5: Create LaunchDaemon plist
  • Path: /Library/LaunchDaemons/acmemesh.plist
  • Label: acmemesh
  • ProgramArguments includes --serviceId=acmemesh

Step 6: Create LaunchAgent plist
  • Path: ~/Library/LaunchAgents/acmemesh-agent.plist
  • Label: acmemesh-agent
  • ProgramArguments: [-kvm1, --serviceId=acmemesh]
  • QueueDirectories: /var/run/acmemesh/

Step 7: Bootstrap services
  • launchctl bootstrap system /Library/LaunchDaemons/acmemesh.plist
  • launchctl bootstrap gui/502 ~/Library/LaunchAgents/acmemesh-agent.plist
```

### Upgrade

During upgrade, the installer discovers the existing service by looking up the serviceID in the existing plist or database. The `--setServiceID` flag can change the serviceID during an upgrade, which causes old plists to be removed and new ones created with the new serviceID.

### Default Install (No Custom Parameters)

```
User runs: ./meshagent -install

Step 1: checkParameters()
  • No --setServiceID, no --serviceId, no .msh ServiceID
  • Falls through to buildServiceId()
  • buildServiceId() returns sanitized basename: "meshagent"

Step 2: Install path
  • /usr/local/mesh_services/meshagent/

Step 3: Plist
  • /Library/LaunchDaemons/meshagent.plist (Label: meshagent)

Step 4: Runtime paths
  • Socket: /tmp/meshagent.sock
  • Queue: /var/run/meshagent/
```

---

## Command-Line Parameters

| Flag | Effect | Priority |
|------|--------|----------|
| `--setServiceID=<value>` | Sets serviceID (mapped to `--serviceId` in `checkParameters`) | Highest — mapped before .msh injection |
| `--serviceId=<value>` | Sets serviceID directly | High — overrides .msh and database |
| `--meshServiceName=<value>` | Sets display/service name (used for install path, NOT serviceID) | N/A for serviceID |
| `--companyName=<value>` | Sets company name (used for install path, NOT serviceID) | N/A for serviceID |
| `--installPath=<value>` | Explicit install directory (overrides company/service path construction) | N/A for serviceID |

**Important distinctions:**
- `--setServiceID` and `--serviceId` control the **serviceID** (plist Label, socket paths, runtime identity)
- `--meshServiceName` and `--companyName` control the **install directory structure** but do NOT affect serviceID
- `buildServiceId()` ignores both `meshServiceName` and `companyName`

---

## Real-World Examples

### Example 1: Default Installation

**Command:**
```bash
./meshagent -install
```

**ServiceID:** `meshagent` (from executable basename)

**Files Created:**
```
/Library/LaunchDaemons/meshagent.plist
~/Library/LaunchAgents/meshagent-agent.plist
/usr/local/mesh_services/meshagent/meshagent
/usr/local/mesh_services/meshagent/meshagent.msh
/usr/local/mesh_services/meshagent/meshagent.db
```

**Runtime Paths:**
```
Socket: /tmp/meshagent.sock
Queue:  /var/run/meshagent/
Signal: /var/run/meshagent/session-active
```

---

### Example 2: Full ACME Deployment with Custom ServiceID

**Command:**
```bash
./meshagent -install \
  --setServiceID=acmemesh \
  --meshServiceName="ACME Mesh" \
  --companyName="ACME, Inc." \
  --installPath=/opt/acmemesh
```

**Sanitization:**
```javascript
sanitize("ACME Mesh")  → "acme-mesh"    // Used for install path (overridden here)
sanitize("ACME, Inc.")  → "acme-inc"     // Comma and period stripped; path overridden here
// --installPath=/opt/acmemesh overrides the computed path
```

**ServiceID:** `acmemesh` (from `--setServiceID`)

**Install path:** `/opt/acmemesh/` (explicit `--installPath`)

**Plists:**
```
/Library/LaunchDaemons/acmemesh.plist  (Label: acmemesh)
~/Library/LaunchAgents/acmemesh-agent.plist  (Label: acmemesh-agent)
```

**Runtime Paths:**
```
Socket: /tmp/acmemesh.sock
Queue:  /var/run/acmemesh/
Signal: /var/run/acmemesh/session-active
```

**Plist ProgramArguments:**
```xml
<array>
    <string>/opt/acmemesh/meshagent</string>
    <string>--meshServiceName=ACME Mesh</string>
    <string>--companyName=ACME, Inc.</string>
    <string>--serviceId=acmemesh</string>
</array>
```

---

### Example 3: ServiceID from .msh File (No Command-Line Override)

**Setup:** Binary has an embedded `.msh` file containing:
```
ServiceID=acmemesh
MeshServiceName=ACME Mesh
CompanyName=ACME, Inc.
```

**Command:**
```bash
./meshagent -install
```

**ServiceID:** `acmemesh` (from .msh `ServiceID` field, injected by `checkParameters()`)

**Install path:** `/usr/local/mesh_services/acme-inc/acme-mesh/` (computed from company + service)

**Plists:**
```
/Library/LaunchDaemons/acmemesh.plist  (Label: acmemesh)
~/Library/LaunchAgents/acmemesh-agent.plist  (Label: acmemesh-agent)
```

---

### Example 4: Renamed Binary, No Other Configuration

**Setup:** Binary renamed from `meshagent` to `acmemesh`.

**Command:**
```bash
./acmemesh -install
```

**ServiceID:** `acmemesh` (sanitized executable basename, via `buildServiceId()`)

**Install path:** `/usr/local/mesh_services/acmemesh/`

**Plists:**
```
/Library/LaunchDaemons/acmemesh.plist  (Label: acmemesh)
~/Library/LaunchAgents/acmemesh-agent.plist  (Label: acmemesh-agent)
```

---

### Example 5: ACME Service + Company, No Explicit ServiceID

**Command:**
```bash
./meshagent -install \
  --meshServiceName="ACME Mesh" \
  --companyName="ACME, Inc."
```

**Sanitization:**
```javascript
sanitize("ACME Mesh")  → "acme-mesh"
sanitize("ACME, Inc.")  → "acme-inc"    // Comma and period removed by special char strip
```

**ServiceID:** `meshagent` (from executable basename — `buildServiceId()` ignores both parameters)

**Install path:** `/usr/local/mesh_services/acme-inc/acme-mesh/` (company + service directory structure)

**Plists:**
```
/Library/LaunchDaemons/meshagent.plist  (Label: meshagent)
~/Library/LaunchAgents/meshagent-agent.plist  (Label: meshagent-agent)
```

**Runtime Paths:**
```
Socket: /tmp/meshagent.sock
Queue:  /var/run/meshagent/
```

Note: Despite the custom service and company names, the serviceID is still `meshagent` because `buildServiceId()` only looks at the executable basename. To get a custom serviceID, use `--setServiceID` or embed `ServiceID=` in the .msh file.

---

## Implementation Reference

### Core Functions

| Function | File | Lines | Purpose |
|----------|------|-------|---------|
| `buildServiceId()` | `modules/macOSHelpers.js` | 87-98 | Returns sanitized basename or explicit override (ignores serviceName/companyName) |
| `sanitizeIdentifier()` | `modules/macOSHelpers.js` | 77-81 | Sanitizes input: spaces→hyphens, strip special chars, lowercase |
| `getPlistPath()` | `modules/macOSHelpers.js` | 106-113 | Returns plist file path for a serviceID |
| `checkParameters()` | `modules/agent-installer.js` | 263-333 | Maps `--setServiceID` → `--serviceId`, injects .msh ServiceID |
| `kvm_build_dynamic_paths()` | `meshcore/KVM/MacOS/mac_kvm.c` | 458-519 | Builds socket/queue paths from serviceID |
| `mesh_plist_find_service_id()` | `meshcore/MacOS/mac_plist_utils.c` | 169-203 | Discovers serviceID from plist Label by matching binary path |
| `kvm_create_session()` | `meshcore/KVM/MacOS/mac_kvm.c` | 965-1086 | Creates KVM socket and signal file using resolved paths |

### Key Constants

| Constant | Value | File |
|----------|-------|------|
| `MACOS_PATHS.LAUNCH_DAEMONS` | `/Library/LaunchDaemons/` | `modules/macOSHelpers.js` |
| `MACOS_PATHS.LAUNCH_AGENTS` | `/Library/LaunchAgents/` | `modules/macOSHelpers.js` |
| Default service name | `'meshagent'` | `meshcore/agentcore.c` |
| Default install path | `/usr/local/mesh_services/` | `modules/agent-installer.js` |
| KVM fallback serviceId | `"unknown-agent"` | `meshcore/KVM/MacOS/mac_kvm.c` |

---

**Document Version:** 2.0
**Last Updated:** 2026-01-29
**Applies to:** Current macOS MeshAgent implementation
