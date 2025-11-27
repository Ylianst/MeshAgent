# macOS MeshAgent ServiceID System

## Table of Contents
1. [Introduction](#introduction)
2. [ServiceID Composition](#serviceid-composition)
3. [Creation Algorithm](#creation-algorithm)
4. [Input Sanitization](#input-sanitization)
5. [Storage Mechanisms](#storage-mechanisms)
6. [Resolution Priority](#resolution-priority)
7. [Usage in File Paths](#usage-in-file-paths)
8. [Validation Rules](#validation-rules)
9. [Creation Flow Visualizations](#creation-flow-visualizations)
10. [Real-World Examples](#real-world-examples)
11. [Implementation Reference](#implementation-reference)

---

## Introduction

The **serviceID** is a unique identifier that distinguishes different MeshAgent installations on the same macOS system. It enables multiple independent agents to coexist by providing namespace separation for:

- LaunchDaemon/LaunchAgent plist files
- Installation directories
- Configuration files
- Runtime sockets and directories
- Logging paths

The serviceID system supports:
- **Multi-tenancy**: Multiple companies can run separate agents
- **Service variants**: Different service configurations (tactical, standard, custom)
- **Clean upgrades**: Proper identification during version transitions
- **Name collision prevention**: Unique identifiers in system directories

---

## ServiceID Composition

### macOS Composite Format

On macOS, the serviceID follows a **reverse DNS-style composite pattern**:

```
meshagent[.serviceName][.companyName]
```

**Components:**
- **Base**: `meshagent` (fixed prefix, always present)
- **serviceName**: Optional custom service identifier
- **companyName**: Optional company/organization identifier

### Component Combinations

| serviceName | companyName | Resulting ServiceID | Use Case |
|-------------|-------------|---------------------|----------|
| (default) | (none) | `meshagent` | Standard installation |
| (default) | `acme-corp` | `meshagent.acme-corp` | Company-specific, default service |
| `tactical` | (none) | `meshagent.tactical` | Custom service, no company branding |
| `tactical` | `acme-corp` | `meshagent.tactical.acme-corp` | Company-specific custom service |

### Non-macOS Platforms

On Windows and Linux, serviceID is simplified:

```
serviceName (sanitized)
```

Example: `meshagent` or `customservice`

---

## Creation Algorithm

### Decision Tree

```
┌─────────────────────────────────────────────────────────────┐
│ buildServiceId(serviceName, companyName, options)           │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
        ┌──────────────────────────────┐
        │ explicitServiceId provided?  │
        └───────────┬──────────────────┘
                    │
         ┌──────────┴──────────┐
         │ YES                 │ NO
         ↓                     ↓
    ┌─────────┐          ┌──────────────┐
    │ Return  │          │ Platform =   │
    │ as-is   │          │ darwin?      │
    └─────────┘          └──────┬───────┘
                                │
                     ┌──────────┴──────────┐
                     │ YES (macOS)         │ NO (Win/Linux)
                     ↓                     ↓
         ┌───────────────────────┐    ┌────────────────┐
         │ Sanitize inputs:      │    │ Return         │
         │ - serviceName         │    │ sanitized      │
         │ - companyName         │    │ serviceName    │
         └──────────┬────────────┘    └────────────────┘
                    ↓
         ┌──────────────────────┐
         │ companyName present? │
         └──────────┬───────────┘
                    │
         ┌──────────┴──────────┐
         │ YES                 │ NO
         ↓                     ↓
    ┌────────────────┐    ┌─────────────────┐
    │ serviceName =  │    │ serviceName =   │
    │ 'meshagent'?   │    │ 'meshagent'?    │
    └────┬───────────┘    └────┬────────────┘
         │                     │
    ┌────┴────┐           ┌────┴────┐
    │YES   NO │           │YES   NO │
    ↓         ↓           ↓         ↓
┌───────┐ ┌───────────┐ ┌─────┐ ┌──────────┐
│meshag-│ │meshagent. │ │mesh-│ │meshagent.│
│ent.   │ │serviceName│ │agent│ │serviceName
│company│ │.company   │ └─────┘ └──────────┘
└───────┘ └───────────┘
```

### Pseudocode

```javascript
function buildServiceId(serviceName, companyName, options) {
    // Priority 1: Explicit override
    if (options.explicitServiceId) {
        return options.explicitServiceId;
    }

    // Priority 2: Platform check
    if (platform !== 'darwin') {
        return sanitize(serviceName);
    }

    // Priority 3: macOS composite logic
    serviceName = sanitize(serviceName);
    companyName = sanitize(companyName);

    if (companyName) {
        if (serviceName && serviceName !== 'meshagent') {
            return 'meshagent.' + serviceName + '.' + companyName;
        }
        return 'meshagent.' + companyName;
    }

    if (serviceName && serviceName !== 'meshagent') {
        return 'meshagent.' + serviceName;
    }

    return 'meshagent';
}
```

**Code Location:** `modules/macOSHelpers.js` lines 91-126

---

## Input Sanitization

### Sanitization Rules

The `sanitizeIdentifier()` function transforms user input into valid identifiers:

```javascript
function sanitizeIdentifier(str) {
    if (!str) return null;

    return str
        .replace(/\s+/g, '-')           // Spaces → hyphens
        .replace(/[^a-zA-Z0-9_-]/g, '') // Remove special chars
        .toLowerCase();                  // Convert to lowercase
}
```

**Code Location:** `modules/macOSHelpers.js` lines 77-81

### Transformation Examples

| Input | After Space→Hyphen | After Special Char Removal | After Lowercase | Final Result |
|-------|-------------------|---------------------------|----------------|--------------|
| `ACME Corp` | `ACME-Corp` | `ACME-Corp` | `acme-corp` | `acme-corp` |
| `Tactical RMM` | `Tactical-RMM` | `Tactical-RMM` | `tactical-rmm` | `tactical-rmm` |
| `My Service!@#` | `My-Service!@#` | `My-Service` | `my-service` | `my-service` |
| `Company_Name` | `Company_Name` | `Company_Name` | `company_name` | `company_name` |
| `@#$%^&*()` | `@#$%^&*()` | (empty) | (empty) | `null` |
| ` ` (spaces only) | `-` | `-` | `-` | `-` |

### Character Allowlist

**Allowed Characters:**
- Lowercase letters: `a-z`
- Uppercase letters: `A-Z` (converted to lowercase)
- Digits: `0-9`
- Hyphen: `-`
- Underscore: `_`

**Converted Characters:**
- Spaces ` ` → Hyphens `-`

**Removed Characters:**
- All special characters: `!@#$%^&*()+={}[]|\\:;"'<>,.?/~`

---

## Storage Mechanisms

### 5 Storage Locations

```
┌─────────────────────────────────────────────────────────────┐
│                    ServiceID Storage                        │
└─────────────────────────────────────────────────────────────┘

1. Command-Line Flags (Transient)
   └─ --meshServiceName=Tactical --companyName="ACME Corp"

2. LaunchDaemon Plist (Persistent, Authoritative)
   └─ /Library/LaunchDaemons/{serviceId}.plist
      ├─ Label: {serviceId}
      └─ ProgramArguments: [binary, --meshServiceName=..., --companyName=...]

3. LaunchAgent Plist (Persistent)
   └─ ~/Library/LaunchAgents/{serviceId}-agent.plist
      ├─ Label: {serviceId}-agent
      └─ ProgramArguments: [binary, -kvm1]

4. .msh Configuration File (Persistent)
   └─ {installPath}/meshagent.msh
      ├─ MeshServiceName=Tactical
      ├─ CompanyName=ACME Corp
      └─ ServiceID=meshagent.tactical.acme-corp

5. .db Database File (Persistent)
   └─ {installPath}/meshagent.db
      ├─ MeshServiceName=Tactical
      └─ CompanyName=ACME Corp
```

### Storage Details

#### 1. LaunchDaemon Plist

**Path:** `/Library/LaunchDaemons/{serviceId}.plist`

**Key Fields:**
```xml
<key>Label</key>
<string>meshagent.tactical.acme-corp</string>

<key>ProgramArguments</key>
<array>
    <string>/usr/local/mesh_services/acme-corp/tactical/meshagent</string>
    <string>--meshServiceName=Tactical</string>
    <string>--companyName=ACME Corp</string>
</array>
```

**Why Authoritative:** This plist reflects the **actual running service** configuration. If the service is loaded, this is the ground truth.

#### 2. .msh Configuration File

**Path:** `{installPath}/meshagent.msh`

**Format:** Key=Value pairs (one per line)

**Example:**
```
MeshName=MyMesh
MeshType=2
MeshID=0x1234567890ABCDEF
ServerID=server1
MeshServer=wss://meshcentral.example.com:443/agent.ashx
MeshServiceName=Tactical
CompanyName=ACME Corp
ServiceID=meshagent.tactical.acme-corp
disableUpdate=0
disableTccCheck=0
```

**Created by:** Installer during fresh installation or upgrade

**Code Location:** `modules/agent-installer.js` lines 3214-3224

#### 3. .db Database File

**Path:** `{installPath}/meshagent.db`

**Type:** SimpleDataStore (SQLite-like key-value store)

**Relevant Keys:**
- `MeshServiceName` (String)
- `CompanyName` (String)
- `SelfNodeCert` (Buffer)
- `NodeID` (Buffer)

**Access Pattern:**
```javascript
var db = require('SimpleDataStore').Create(dbPath, { readOnly: true });
var serviceName = db.Get('MeshServiceName');
var companyName = db.Get('CompanyName');
```

**Code Location:** `modules/agent-installer.js` lines 3154-3168

#### 4. Installation Directory Structure

**Pattern:** `/usr/local/mesh_services/{companyName?}/{serviceName}/`

**Encoding:** Directory hierarchy encodes serviceName and companyName

**Examples:**
```
/usr/local/mesh_services/meshagent/
  → serviceName='meshagent', companyName=null

/usr/local/mesh_services/tactical/
  → serviceName='tactical', companyName=null

/usr/local/mesh_services/acme-corp/tactical/
  → serviceName='tactical', companyName='acme-corp'
```

---

## Resolution Priority

### 5-Tier Priority System

When the agent needs to determine its serviceID at runtime, it follows this priority order:

```
┌─────────────────────────────────────────────────────────────┐
│              ServiceID Resolution Priority                  │
│                (Highest → Lowest)                           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ PRIORITY 1: User-Provided Command-Line Flags               │
│ ──────────────────────────────────────────────────────────  │
│ Source: --meshServiceName=, --companyName=, --serviceId=    │
│ Reliability: HIGHEST (explicit user intent)                 │
│ Use Case: Fresh install, upgrade, manual override           │
└─────────────────────────────────────────────────────────────┘
                            ↓ (if not provided)
┌─────────────────────────────────────────────────────────────┐
│ PRIORITY 2: LaunchDaemon Plist ProgramArguments            │
│ ──────────────────────────────────────────────────────────  │
│ Source: /Library/LaunchDaemons/{serviceId}.plist            │
│ Extracts: --meshServiceName=, --companyName= from args      │
│ Reliability: HIGHEST (reflects running service)             │
│ Use Case: Runtime resolution, upgrade detection             │
└─────────────────────────────────────────────────────────────┘
                            ↓ (if not found)
┌─────────────────────────────────────────────────────────────┐
│ PRIORITY 3: .msh Configuration File                         │
│ ──────────────────────────────────────────────────────────  │
│ Source: {installPath}/meshagent.msh                         │
│ Extracts: MeshServiceName=, CompanyName=                    │
│ Reliability: HIGH (installer-managed)                       │
│ Use Case: First-run, configuration persistence              │
└─────────────────────────────────────────────────────────────┘
                            ↓ (if not found)
┌─────────────────────────────────────────────────────────────┐
│ PRIORITY 4: .db Database File                               │
│ ──────────────────────────────────────────────────────────  │
│ Source: {installPath}/meshagent.db                          │
│ Extracts: MeshServiceName, CompanyName keys                 │
│ Reliability: MEDIUM (may be stale)                          │
│ Use Case: Legacy installations, fallback                    │
└─────────────────────────────────────────────────────────────┘
                            ↓ (if not found)
┌─────────────────────────────────────────────────────────────┐
│ PRIORITY 5: Installation Path or Plist Label               │
│ ──────────────────────────────────────────────────────────  │
│ Source: Path pattern parsing, plist Label field             │
│ Parses: /usr/local/mesh_services/{company}/{service}/       │
│ Reliability: LOWEST (ambiguous, assumes conventions)        │
│ Use Case: Last resort, path-based inference                 │
└─────────────────────────────────────────────────────────────┘
                            ↓ (if all fail)
┌─────────────────────────────────────────────────────────────┐
│ DEFAULT FALLBACK                                            │
│ ──────────────────────────────────────────────────────────  │
│ serviceName = 'meshagent'                                   │
│ companyName = null                                          │
│ serviceID = 'meshagent'                                     │
└─────────────────────────────────────────────────────────────┘
```

### Resolution Algorithm

**Code Location:** `modules/agent-installer.js` lines 1104-1595

```javascript
function resolveServiceId() {
    var serviceName, companyName, source;

    // Priority 1: Command-line flags
    if (process.argv.includes('--meshServiceName') ||
        process.argv.includes('--companyName')) {
        serviceName = parseFlag('--meshServiceName') || 'meshagent';
        companyName = parseFlag('--companyName') || null;
        source = 'user-flags';
        return { serviceName, companyName, source };
    }

    // Priority 2: Plist ProgramArguments
    var plistConfig = getServiceConfigFromPlist(binaryPath);
    if (plistConfig) {
        serviceName = plistConfig.serviceName;
        companyName = plistConfig.companyName;
        source = 'plist-args';
        return { serviceName, companyName, source };
    }

    // Priority 3: .msh file
    var mshPath = installPath + 'meshagent.msh';
    if (fs.existsSync(mshPath)) {
        var config = parseMshFile(mshPath);
        if (config.meshServiceName || config.companyName) {
            serviceName = config.meshServiceName || 'meshagent';
            companyName = config.companyName || null;
            source = 'msh-file';
            return { serviceName, companyName, source };
        }
    }

    // Priority 4: .db file
    var dbPath = installPath + 'meshagent.db';
    if (fs.existsSync(dbPath)) {
        var db = require('SimpleDataStore').Create(dbPath, { readOnly: true });
        serviceName = db.Get('MeshServiceName');
        companyName = db.Get('CompanyName');
        if (serviceName || companyName) {
            serviceName = serviceName || 'meshagent';
            source = 'db-file';
            return { serviceName, companyName, source };
        }
    }

    // Priority 5: Path parsing
    var pathConfig = parseServiceIdFromInstallPath(installPath);
    if (pathConfig) {
        serviceName = pathConfig.serviceName;
        companyName = pathConfig.companyName;
        source = 'install-path';
        return { serviceName, companyName, source };
    }

    // Default fallback
    return { serviceName: 'meshagent', companyName: null, source: 'default' };
}
```

---

## Usage in File Paths

### Path Template Matrix

| Component | Template | Example (default) | Example (custom) |
|-----------|----------|-------------------|------------------|
| **LaunchDaemon plist** | `/Library/LaunchDaemons/{serviceId}.plist` | `meshagent.plist` | `meshagent.tactical.acme-corp.plist` |
| **LaunchAgent plist** | `~/Library/LaunchAgents/{serviceId}-agent.plist` | `meshagent-agent.plist` | `meshagent.tactical.acme-corp-agent.plist` |
| **Install directory** | `/usr/local/mesh_services/{company?}/{service}/` | `/usr/local/mesh_services/meshagent/` | `/usr/local/mesh_services/acme-corp/tactical/` |
| **Binary** | `{installPath}meshagent` | Same | Same |
| **Config (.msh)** | `{installPath}meshagent.msh` | Same | Same |
| **Database (.db)** | `{installPath}meshagent.db` | Same | Same |
| **Socket** | `/tmp/{serviceId}.sock` | `/tmp/meshagent.sock` | `/tmp/meshagent.tactical.acme-corp.sock` |
| **Queue directory** | `/var/run/{serviceId}` | `/var/run/meshagent` | `/var/run/meshagent.tactical.acme-corp` |
| **Daemon log** | `/tmp/{serviceId}-daemon.log` | `/tmp/meshagent-daemon.log` | `/tmp/meshagent.tactical.acme-corp-daemon.log` |
| **Agent log** | `/tmp/{serviceId}-agent.log` | `/tmp/meshagent-agent.log` | `/tmp/meshagent.tactical.acme-corp-agent.log` |

### Launchd Service Paths

**Domain:** `system` (daemon) or `gui/{uid}` (agent)

**Full Service Path Format:**
```
{domain}/{serviceId}
{domain}/{serviceId}-agent
```

**Examples:**
```
system/meshagent                              # Default daemon
system/meshagent.tactical.acme-corp          # Custom daemon

gui/502/meshagent-agent                       # Default agent (uid 502)
gui/502/meshagent.tactical.acme-corp-agent   # Custom agent (uid 502)
```

**Code Location:** `modules/macOSHelpers.js` lines 148-160

---

## Validation Rules

### Character Restrictions

**Allowlist:**
- Alphanumeric: `a-z A-Z 0-9`
- Hyphens: `-`
- Underscores: `_`

**Transformations:**
- Spaces ` ` → `-`
- Mixed case → `lowercase`

**Removed:**
- All other special characters

### Length Limits

**Practical Limits:**
- Minimum: 1 character (after sanitization)
- Maximum (recommended): 63 characters per component (DNS label limit)
- Maximum (filesystem): 255 characters total (macOS filename limit)

**Recommended Total Length:** ≤ 100 characters for plist filenames

### Invalid Inputs

| Input | Sanitized Result | Valid? |
|-------|------------------|--------|
| `""` (empty string) | `null` | ❌ No |
| `"   "` (spaces only) | `null` or `-` | ❌ No |
| `"@#$%"` (special chars only) | `""` → `null` | ❌ No |
| `"Service_Name"` | `service_name` | ✅ Yes |
| `"Service Name"` | `service-name` | ✅ Yes |
| `"Valid-123"` | `valid-123` | ✅ Yes |
| `"ACME Corp!"` | `acme-corp` | ✅ Yes |

---

## Creation Flow Visualizations

### Flow 1: Fresh Installation with Custom Service and Company

```
┌───────────────────────────────────────────────────────────────┐
│ USER ACTION: Install with custom parameters                  │
│ $ ./meshagent -install                                        │
│     --installPath=/opt/services                               │
│     --meshServiceName="Tactical RMM"                          │
│     --companyName="ACME Corporation"                          │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 1: Parse and Normalize Parameters                       │
│ ────────────────────────────────────────────────────────────  │
│ serviceName = "Tactical RMM"                                  │
│ companyName = "ACME Corporation"                              │
│ installPath = "/opt/services"                                 │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 2: Sanitize Inputs                                      │
│ ────────────────────────────────────────────────────────────  │
│ "Tactical RMM" → "tactical-rmm"                               │
│   • Spaces → hyphens                                          │
│   • Convert to lowercase                                      │
│                                                               │
│ "ACME Corporation" → "acme-corporation"                       │
│   • Spaces → hyphens                                          │
│   • Convert to lowercase                                      │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 3: Build ServiceID                                      │
│ ────────────────────────────────────────────────────────────  │
│ Call: buildServiceId('tactical-rmm', 'acme-corporation')      │
│                                                               │
│ Logic:                                                        │
│   • companyName exists? YES                                   │
│   • serviceName != 'meshagent'? YES                           │
│   • Result = 'meshagent.' + 'tactical-rmm' + '.' +            │
│              'acme-corporation'                               │
│                                                               │
│ ServiceID: "meshagent.tactical-rmm.acme-corporation"          │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 4: Create Directory Structure                           │
│ ────────────────────────────────────────────────────────────  │
│ Install path pattern:                                         │
│   /usr/local/mesh_services/{companyName}/{serviceName}/       │
│                                                               │
│ Creates:                                                      │
│   /opt/services/acme-corporation/tactical-rmm/                │
│                                                               │
│ Copies binary to:                                             │
│   /opt/services/acme-corporation/tactical-rmm/meshagent       │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 5: Create .msh Configuration File                       │
│ ────────────────────────────────────────────────────────────  │
│ Path: /opt/services/acme-corporation/tactical-rmm/           │
│       meshagent.msh                                           │
│                                                               │
│ Contents:                                                     │
│   MeshName=MyMesh                                             │
│   MeshServiceName=Tactical RMM                                │
│   CompanyName=ACME Corporation                                │
│   ServiceID=meshagent.tactical-rmm.acme-corporation           │
│   MeshServer=wss://example.com/agent.ashx                     │
│   ...                                                         │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 6: Generate LaunchDaemon Plist                          │
│ ────────────────────────────────────────────────────────────  │
│ Path: /Library/LaunchDaemons/                                 │
│       meshagent.tactical-rmm.acme-corporation.plist           │
│                                                               │
│ Key Fields:                                                   │
│   <key>Label</key>                                            │
│   <string>meshagent.tactical-rmm.acme-corporation</string>    │
│                                                               │
│   <key>ProgramArguments</key>                                 │
│   <array>                                                     │
│     <string>/opt/services/acme-corporation/tactical-rmm/      │
│             meshagent</string>                                │
│     <string>--meshServiceName=Tactical RMM</string>           │
│     <string>--companyName=ACME Corporation</string>           │
│   </array>                                                    │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 7: Generate LaunchAgent Plist                           │
│ ────────────────────────────────────────────────────────────  │
│ Path: ~/Library/LaunchAgents/                                 │
│       meshagent.tactical-rmm.acme-corporation-agent.plist     │
│                                                               │
│ Key Fields:                                                   │
│   <key>Label</key>                                            │
│   <string>meshagent.tactical-rmm.acme-corporation-agent       │
│   </string>                                                   │
│                                                               │
│   <key>QueueDirectories</key>                                 │
│   <array>                                                     │
│     <string>/var/run/meshagent.tactical-rmm.acme-corporation  │
│     </string>                                                 │
│   </array>                                                    │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 8: Bootstrap Services                                   │
│ ────────────────────────────────────────────────────────────  │
│ Load LaunchDaemon:                                            │
│   $ launchctl bootstrap system \                              │
│       /Library/LaunchDaemons/                                 │
│       meshagent.tactical-rmm.acme-corporation.plist           │
│                                                               │
│ Load LaunchAgent:                                             │
│   $ launchctl bootstrap gui/502 \                             │
│       ~/Library/LaunchAgents/                                 │
│       meshagent.tactical-rmm.acme-corporation-agent.plist     │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ RESULT: Services Running                                     │
│ ────────────────────────────────────────────────────────────  │
│ Daemon Service:                                               │
│   system/meshagent.tactical-rmm.acme-corporation              │
│                                                               │
│ Agent Service:                                                │
│   gui/502/meshagent.tactical-rmm.acme-corporation-agent       │
│                                                               │
│ Socket (when KVM active):                                     │
│   /tmp/meshagent.tactical-rmm.acme-corporation.sock           │
│                                                               │
│ Queue Directory:                                              │
│   /var/run/meshagent.tactical-rmm.acme-corporation/           │
└───────────────────────────────────────────────────────────────┘
```

### Flow 2: Upgrade with Service Name Change

```
┌───────────────────────────────────────────────────────────────┐
│ INITIAL STATE: Running with old serviceID                    │
│ ────────────────────────────────────────────────────────────  │
│ ServiceID: meshagent.old-service.acme-corp                    │
│ Plist: /Library/LaunchDaemons/                                │
│        meshagent.old-service.acme-corp.plist                  │
│ InstallPath: /usr/local/mesh_services/acme-corp/old-service/  │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ USER ACTION: Upgrade with new service name                   │
│ $ ./meshagent -upgrade                                        │
│     --meshServiceName="New Service"                           │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 1: Detect Existing Installation                         │
│ ────────────────────────────────────────────────────────────  │
│ Priority 2: Read existing plist ProgramArguments              │
│   Found: --companyName="ACME Corp"                            │
│                                                               │
│ Current state:                                                │
│   serviceName = "old-service" (from plist)                    │
│   companyName = "acme-corp" (from plist)                      │
│   oldServiceId = "meshagent.old-service.acme-corp"            │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 2: Apply New Parameters                                 │
│ ────────────────────────────────────────────────────────────  │
│ Priority 1: User-provided flags override                      │
│   New serviceName = "New Service" → "new-service"             │
│   Keep companyName = "acme-corp" (from existing)              │
│                                                               │
│ Build new serviceID:                                          │
│   newServiceId = "meshagent.new-service.acme-corp"            │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 3: Unload Old Services                                  │
│ ────────────────────────────────────────────────────────────  │
│ $ launchctl bootout system/meshagent.old-service.acme-corp   │
│ $ launchctl bootout gui/502/                                  │
│     meshagent.old-service.acme-corp-agent                     │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 4: Remove Old Plists                                    │
│ ────────────────────────────────────────────────────────────  │
│ Delete:                                                       │
│   /Library/LaunchDaemons/                                     │
│     meshagent.old-service.acme-corp.plist                     │
│                                                               │
│   ~/Library/LaunchAgents/                                     │
│     meshagent.old-service.acme-corp-agent.plist               │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 5: Update Binary and Config                             │
│ ────────────────────────────────────────────────────────────  │
│ Replace binary (same location):                               │
│   /usr/local/mesh_services/acme-corp/old-service/meshagent   │
│                                                               │
│ Update .msh file:                                             │
│   MeshServiceName=New Service                                 │
│   ServiceID=meshagent.new-service.acme-corp                   │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 6: Create New Plists with New ServiceID                 │
│ ────────────────────────────────────────────────────────────  │
│ Create:                                                       │
│   /Library/LaunchDaemons/                                     │
│     meshagent.new-service.acme-corp.plist                     │
│     • Label: meshagent.new-service.acme-corp                  │
│     • ProgramArguments includes --meshServiceName=New Service │
│                                                               │
│   ~/Library/LaunchAgents/                                     │
│     meshagent.new-service.acme-corp-agent.plist               │
│     • Label: meshagent.new-service.acme-corp-agent            │
│     • QueueDirectories: /var/run/                             │
│                          meshagent.new-service.acme-corp      │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ STEP 7: Bootstrap New Services                               │
│ ────────────────────────────────────────────────────────────  │
│ $ launchctl bootstrap system \                                │
│     /Library/LaunchDaemons/                                   │
│     meshagent.new-service.acme-corp.plist                     │
│                                                               │
│ $ launchctl bootstrap gui/502 \                               │
│     ~/Library/LaunchAgents/                                   │
│     meshagent.new-service.acme-corp-agent.plist               │
└──────────────────────┬────────────────────────────────────────┘
                       ↓
┌───────────────────────────────────────────────────────────────┐
│ RESULT: Services Running with New ServiceID                  │
│ ────────────────────────────────────────────────────────────  │
│ Old ServiceID: meshagent.old-service.acme-corp (removed)      │
│ New ServiceID: meshagent.new-service.acme-corp (active)       │
│                                                               │
│ New Daemon: system/meshagent.new-service.acme-corp            │
│ New Agent: gui/502/meshagent.new-service.acme-corp-agent      │
│ New Socket: /tmp/meshagent.new-service.acme-corp.sock         │
└───────────────────────────────────────────────────────────────┘
```

---

## Real-World Examples

### Example 1: Default Installation (No Custom Parameters)

**Command:**
```bash
./meshagent -install --installPath=/usr/local/mesh_services/
```

**Parameters:**
- `serviceName`: Not provided → defaults to `'meshagent'`
- `companyName`: Not provided → `null`

**Sanitization:** (none needed)

**ServiceID Construction:**
```javascript
buildServiceId('meshagent', null)
  → companyName is null
  → serviceName === 'meshagent'
  → return 'meshagent'
```

**Result:** `meshagent`

**Files Created:**
```
✓ /Library/LaunchDaemons/meshagent.plist
✓ ~/Library/LaunchAgents/meshagent-agent.plist
✓ /usr/local/mesh_services/meshagent/meshagent (binary)
✓ /usr/local/mesh_services/meshagent/meshagent.msh
✓ /usr/local/mesh_services/meshagent/meshagent.db
```

**Plist Label:**
```xml
<key>Label</key>
<string>meshagent</string>
```

**Runtime Paths:**
```
Socket: /tmp/meshagent.sock
Queue: /var/run/meshagent/
Logs: /tmp/meshagent-daemon.log, /tmp/meshagent-agent.log
```

---

### Example 2: Company-Branded Installation

**Command:**
```bash
./meshagent -install \
  --companyName="ACME Corporation"
```

**Parameters:**
- `serviceName`: Not provided → defaults to `'meshagent'`
- `companyName`: `'ACME Corporation'`

**Sanitization:**
```javascript
sanitize('ACME Corporation')
  → 'ACME-Corporation'          // Spaces → hyphens
  → 'ACMECorporation'            // Special chars removed
  → 'acmecorporation'            // Lowercase
```

**ServiceID Construction:**
```javascript
buildServiceId('meshagent', 'acmecorporation')
  → companyName exists
  → serviceName === 'meshagent'
  → return 'meshagent.' + companyName
  → 'meshagent.acmecorporation'
```

**Result:** `meshagent.acmecorporation`

**Files Created:**
```
✓ /Library/LaunchDaemons/meshagent.acmecorporation.plist
✓ ~/Library/LaunchAgents/meshagent.acmecorporation-agent.plist
✓ /usr/local/mesh_services/acmecorporation/meshagent/meshagent
✓ /usr/local/mesh_services/acmecorporation/meshagent/meshagent.msh
```

**Plist ProgramArguments:**
```xml
<array>
    <string>/usr/local/mesh_services/acmecorporation/meshagent/meshagent</string>
    <string>--companyName=ACME Corporation</string>
</array>
```

---

### Example 3: Custom Service (Tactical RMM)

**Command:**
```bash
./meshagent -install \
  --meshServiceName="Tactical RMM"
```

**Parameters:**
- `serviceName`: `'Tactical RMM'`
- `companyName`: Not provided → `null`

**Sanitization:**
```javascript
sanitize('Tactical RMM')
  → 'Tactical-RMM'               // Spaces → hyphens
  → 'Tactical-RMM'               // No special chars
  → 'tactical-rmm'               // Lowercase
```

**ServiceID Construction:**
```javascript
buildServiceId('tactical-rmm', null)
  → companyName is null
  → serviceName !== 'meshagent'
  → return 'meshagent.' + serviceName
  → 'meshagent.tactical-rmm'
```

**Result:** `meshagent.tactical-rmm`

**Files Created:**
```
✓ /Library/LaunchDaemons/meshagent.tactical-rmm.plist
✓ ~/Library/LaunchAgents/meshagent.tactical-rmm-agent.plist
✓ /usr/local/mesh_services/tactical-rmm/meshagent
✓ /usr/local/mesh_services/tactical-rmm/meshagent.msh
```

**Plist Label:**
```xml
<key>Label</key>
<string>meshagent.tactical-rmm</string>
```

---

### Example 4: Full Custom Service + Company

**Command:**
```bash
./meshagent -install \
  --meshServiceName="Tactical RMM" \
  --companyName="MSP Solutions Inc"
```

**Parameters:**
- `serviceName`: `'Tactical RMM'`
- `companyName`: `'MSP Solutions Inc'`

**Sanitization:**
```javascript
sanitize('Tactical RMM')
  → 'tactical-rmm'

sanitize('MSP Solutions Inc')
  → 'MSP-Solutions-Inc'          // Spaces → hyphens
  → 'MSP-Solutions-Inc'          // No special chars
  → 'msp-solutions-inc'          // Lowercase
```

**ServiceID Construction:**
```javascript
buildServiceId('tactical-rmm', 'msp-solutions-inc')
  → companyName exists
  → serviceName !== 'meshagent'
  → return 'meshagent.' + serviceName + '.' + companyName
  → 'meshagent.tactical-rmm.msp-solutions-inc'
```

**Result:** `meshagent.tactical-rmm.msp-solutions-inc`

**Files Created:**
```
✓ /Library/LaunchDaemons/meshagent.tactical-rmm.msp-solutions-inc.plist
✓ ~/Library/LaunchAgents/meshagent.tactical-rmm.msp-solutions-inc-agent.plist
✓ /usr/local/mesh_services/msp-solutions-inc/tactical-rmm/meshagent
✓ /usr/local/mesh_services/msp-solutions-inc/tactical-rmm/meshagent.msh
```

**Plist ProgramArguments:**
```xml
<array>
    <string>/usr/local/mesh_services/msp-solutions-inc/tactical-rmm/meshagent</string>
    <string>--meshServiceName=Tactical RMM</string>
    <string>--companyName=MSP Solutions Inc</string>
</array>
```

**Runtime Paths:**
```
Socket: /tmp/meshagent.tactical-rmm.msp-solutions-inc.sock
Queue: /var/run/meshagent.tactical-rmm.msp-solutions-inc/
Daemon Log: /tmp/meshagent.tactical-rmm.msp-solutions-inc-daemon.log
Agent Log: /tmp/meshagent.tactical-rmm.msp-solutions-inc-agent.log
```

---

### Example 5: Special Characters in Input

**Command:**
```bash
./meshagent -install \
  --meshServiceName="My Service!@#" \
  --companyName="Company & Co., Ltd."
```

**Parameters:**
- `serviceName`: `'My Service!@#'`
- `companyName`: `'Company & Co., Ltd.'`

**Sanitization:**
```javascript
sanitize('My Service!@#')
  → 'My-Service!@#'              // Spaces → hyphens
  → 'My-Service'                 // Remove !@#
  → 'my-service'                 // Lowercase

sanitize('Company & Co., Ltd.')
  → 'Company-&-Co.,-Ltd.'        // Spaces → hyphens
  → 'Company--Co-Ltd'            // Remove &, ., commas
  → 'company--co-ltd'            // Lowercase
```

**ServiceID Construction:**
```javascript
buildServiceId('my-service', 'company--co-ltd')
  → 'meshagent.my-service.company--co-ltd'
```

**Result:** `meshagent.my-service.company--co-ltd`

**Note:** Double hyphens are allowed (not removed during sanitization).

---

## Implementation Reference

### Core Functions

| Function | File | Lines | Purpose |
|----------|------|-------|---------|
| `buildServiceId()` | `modules/macOSHelpers.js` | 91-126 | Constructs serviceID from components |
| `sanitizeIdentifier()` | `modules/macOSHelpers.js` | 77-81 | Sanitizes user input |
| `getPlistPath()` | `modules/macOSHelpers.js` | 134-141 | Returns plist file path |
| `installService()` | `modules/service-manager.js` | 2856-2922 | Creates LaunchDaemon plist |
| `installLaunchAgent()` | `modules/service-manager.js` | 2944-3043 | Creates LaunchAgent plist |
| `installServiceUnified()` | `modules/agent-installer.js` | 1104-1798 | Orchestrates installation |
| `getServiceConfigFromPlist()` | `modules/agent-installer.js` | 2947-3009 | Reads plist ProgramArguments |
| `parseMshFile()` | `modules/agent-installer.js` | 1561-1575 | Parses .msh config file |

### Key Constants

| Constant | Value | File |
|----------|-------|------|
| `MACOS_PATHS.LAUNCH_DAEMONS` | `/Library/LaunchDaemons/` | `modules/macOSHelpers.js` |
| `MACOS_PATHS.LAUNCH_AGENTS` | `/Library/LaunchAgents/` | `modules/macOSHelpers.js` |
| Default service name | `'meshagent'` | Various |
| Default install path | `/usr/local/mesh_services/` | `modules/agent-installer.js` |

---

**Document Version:** 1.0
**Last Updated:** 2025-01-27
**Applies to:** Current macOS MeshAgent implementation
