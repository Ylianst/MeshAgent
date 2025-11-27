# agent-installer.js

Comprehensive service installation, uninstallation, and upgrade framework for MeshAgent. Handles all aspects of deploying the agent as a background service across platforms, including firewall configuration, service management, and seamless upgrades with advanced macOS support featuring sophisticated multi-tier configuration discovery and safe process lifecycle management.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support with firewall rules, registry management, SafeMode configuration
- Linux - Full support with systemd service management
- macOS (darwin) - **EXTENSIVE** support with advanced upgrade logic, dual-service architecture, orphaned plist cleanup
- FreeBSD - Supported via service-manager (limited testing)

**Excluded Platforms:**
- None - This module supports all platforms with platform-specific optimizations

## Functionality

### Purpose

The agent-installer module serves as the complete lifecycle management system for MeshAgent deployments. It provides:

- **Installation:** Service registration, binary deployment, configuration setup
- **Uninstallation:** Complete removal with optional data cleanup
- **Upgrade:** In-place binary replacement with configuration preservation
- **Service Management:** LaunchDaemon/LaunchAgent (macOS), systemd (Linux), Windows Services
- **Firewall Configuration:** Windows WebRTC UDP port management
- **Safety Features:** Process verification, launchd state checking, orphaned service cleanup

This module is critical for:
- Automated agent deployment and management
- Seamless agent updates without user intervention
- Multi-user KVM support via session-specific services
- Service rename/migration without orphaning old installations
- Factory reset and complete removal scenarios

### Installation Functions

#### fullInstallEx(parms, gOptions) - Lines 1639-1756 (Main Installation Entry)

**Purpose:** Top-level installation orchestrator that handles both fresh installs and upgrades.

**Process:**
1. **Parameter Parsing** (lines 1645-1649):
   - Parses JSON array: `'["--meshServiceName=MyAgent","--installPath=/opt/"]'`
   - Calls `checkParameters()` for validation and normalization

2. **Installation Path Detection** (lines 1651-1667):
   - Calls `findInstallation()` to locate existing installation
   - **If found:** Runs upgrade via `upgradeAgent()` (macOS) or `fullUninstall()→fullInstallEx()` (other platforms)
   - **If not found:** Fresh installation via `installService()`

3. **Platform-Specific Logic:**
   - **macOS** (line 1659): Direct call to `upgradeAgent()` with sophisticated config discovery
   - **Other platforms** (line 1663): Uninstall old, then fresh install

**Parameters:**
- `parms` - JSON string array of command-line arguments
- `gOptions` - Optional global options object

**Key Features:**
- Auto-detects existing installations
- Seamless upgrade path
- Configuration migration
- Cross-platform entry point

---

#### check

Parameters(parms) - Lines 119-177 (Parameter Validation)

**Purpose:** Validates and normalizes installation parameters from various sources.

**Process:**
1. **Parse JSON Array** (lines 121-130):
   - Handles both array and already-parsed object
   - Extracts flags like --meshServiceName, --companyName, --installPath

2. **Load .msh File** (lines 136-145):
   - If .msh file specified or exists in current directory
   - Reads configuration: MeshServer, MeshID, etc.
   - Merges with command-line arguments (CLI takes precedence)

3. **Compatibility Mapping** (lines 156-161):
   - **Legacy support:** Maps --serviceName → --meshServiceName
   - Ensures backward compatibility with older scripts

4. **macOS Service ID** (lines 163-169):
   - Calls `calculateServiceId()` to generate service identifier
   - Format: `meshagent.{serviceName}.{companyName}` or just `meshagent`
   - Used for LaunchDaemon/LaunchAgent plist naming

**Return Value:** Normalized parameters object with all fields populated

---

#### installService(params) - Lines 902-1162 (Core Installation Logic)

**Purpose:** Performs actual service installation after parameters are validated.

**Process:**

**1. Pre-Installation Checks** (lines 909-959):
- **Service Running Check** (lines 913-925):
  - Throws error if service already installed and running
  - Prevents duplicate installations
- **Binary Copy** (lines 933-959):
  - Creates installation directory structure
  - Copies `process.execPath` to target location
  - Sets executable permissions (755 on Unix)

**2. Configuration File Creation** (lines 962-1000):
- **.msh File** (lines 962-995):
  - Creates mesh policy file with MeshServer, MeshID, MeshName
  - Sets permissions: root:wheel 600 (macOS/Unix)
  - Format: key=value pairs
- **.db File** (lines 996-1000):
  - Copies existing database if present
  - Preserves NodeID and certificates

**3. Windows-Specific Setup** (lines 1002-1043):
- **Firewall Rules** (lines 1004-1020):
  - Calls `win_setfirewall()` for WebRTC UDP
  - Creates inbound/outbound rules
- **SafeMode Configuration** (lines 1022-1043):
  - Uses `win-bcd` module to enable network in SafeMode
  - Allows agent to run during Windows recovery

**4. Service Registration** (lines 1045-1150):
- **Windows** (lines 1054-1069):
  ```javascript
  var svc = svcManager.installService({
      name: serviceName,
      displayName: serviceName,
      description: 'MeshCentral Agent',
      servicePath: binaryPath,
      parameters: params,
      startType: 'AUTO_START'
  });
  ```

- **macOS** (lines 1073-1128):
  - **LaunchDaemon** (root background service):
    ```xml
    <plist>
      <Label>meshagent.myservice.mycompany</Label>
      <ProgramArguments>
        <string>/path/meshagent</string>
        <string>--companyName=MyCompany</string>
        <string>--meshServiceName=MyService</string>
      </ProgramArguments>
      <RunAtLoad>true</RunAtLoad>
      <KeepAlive>true</KeepAlive>
    </plist>
    ```
  - **LaunchAgent** (user session for KVM):
    - Same structure, service ID += '-agent'
    - LimitLoadToSessionType: Aqua, LoginWindow

- **Linux/FreeBSD** (lines 1130-1148):
  - systemd service or rc.d script
  - Single service installation

**5. Service Start** (lines 1152-1158):
- Starts service via `service.start()`
- Verifies successful startup

**Platform Behavior:**
- macOS creates TWO services (daemon + agent)
- Windows configures firewall and SafeMode
- Linux uses systemd exclusively
- All platforms preserve .msh and .db files

---

### Uninstallation Functions

#### fullUninstall(jsonString) - Lines 1512-1630 (Complete Removal)

**Purpose:** Removes agent installation completely with optional data cleanup.

**Process:**
1. **Parameter Parsing** (lines 1516-1522):
   - Parses `'["--meshServiceName=MyAgent","--_deleteData=1"]'`
   - Extracts service name and data deletion flag

2. **Service Location** (lines 1530-1564):
   - Tries `service-manager.getService(serviceName)`
   - **macOS fallback** (lines 1545-1560):
     - If service lookup fails, scans plists
     - Reads `/Library/LaunchDaemons/meshagent.*.plist`
     - Finds service by matching binary path or config

3. **Uninstall Execution** (lines 1569-1625):
   - **With service object:** Calls `uninstallService()`
   - **Without service:** Calls `uninstallService2()` with parsed config
   - Passes `_deleteData` flag for data cleanup

**Safety Features:**
- Won't fail if service already uninstalled
- Cleans up orphaned plists on macOS
- Optional data preservation

---

#### uninstallService(params) / uninstallService2(params) / uninstallService3(params) - Lines 1269-1510 (Three-Stage Uninstall)

**Purpose:** Three-stage uninstall process for thorough cleanup.

**Stage 1: uninstallService()** (lines 1269-1316):
- Stop running service
- Wait for service to stop
- Call `uninstallService2()`

**Stage 2: uninstallService2()** (lines 1318-1383):
- **Service Uninstall** (lines 1324-1338):
  - Calls `service.uninstall()` via service-manager
  - Removes LaunchDaemon/systemd unit/Windows service

- **Data Cleanup** (lines 1340-1364):
  - If `_deleteData` flag set:
    - Deletes .msh file
    - Deletes .db file
    - Deletes binary
    - Removes installation directory

- **Secondary Agent Cleanup** (lines 1366-1377):
  - **macOS:** Checks for diagnostic agent via task-scheduler
  - Uninstalls secondary agent if found

- Call `uninstallService3()`

**Stage 3: uninstallService3()** (lines 1385-1510):
- **macOS-Specific Orphaned Plist Cleanup** (lines 1391-1500):
  - Calls `cleanupOrphanedPlists(installPath)`
  - Finds ALL plists pointing to binary path
  - Unloads and deletes orphaned service definitions

- **Windows Firewall Cleanup** (lines 1502-1508):
  - Calls `win_clearfirewall()` to remove WebRTC rules

**Why Three Stages:**
- Stage 1: Graceful service shutdown
- Stage 2: Remove service registration and data
- Stage 3: Clean up orphans and platform-specific settings

---

#### cleanupOrphanedPlists(installPath) - Lines 387-460 (macOS Plist Scanner)

**Purpose:** Finds and removes ALL launchd plists pointing to specific binary path. Critical for handling service renames and preventing duplicate installations.

**Process:**
1. **Plist Scanning** (lines 395-417):
   - Scans `/Library/LaunchDaemons/meshagent*.plist`
   - Scans `/Library/LaunchAgents/meshagent*.plist`
   - For each plist:
     - Extracts ProgramArguments[0] via PlistBuddy
     - Compares with installPath

2. **Orphan Detection** (lines 419-438):
   - If ProgramArguments[0] matches installPath → orphan
   - **Unload Service** (lines 425-432):
     ```bash
     launchctl unload /Library/LaunchDaemons/orphan.plist
     ```
   - **Delete Plist** (lines 434-438):
     ```bash
     rm /Library/LaunchDaemons/orphan.plist
     ```

3. **Logging** (lines 445-457):
   - Logs found orphans
   - Logs cleanup actions
   - Reports total cleanup count

**Use Cases:**
- Service renamed from "MeshAgent" to "CustomAgent" → remove old plist
- Binary path changed → remove old location's plists
- Multiple installs attempted → cleanup duplicates
- Ensures clean state before fresh install

---

### Upgrade Functions (macOS)

#### upgradeAgent(params) - Lines 1950-2527 (Advanced macOS Upgrade - 577 Lines!)

**Purpose:** Sophisticated in-place agent upgrade with multi-tier configuration discovery, safe process termination, and comprehensive plist management.

**Configuration Discovery Hierarchy** (lines 1972-2096):

**Priority 1: User-Provided Flags** (lines 1980-1989):
- `--installPath=...`
- `--meshServiceName=...`
- `--companyName=...`
- **Highest priority** - Explicit user intent

**Priority 2: LaunchDaemon Plist (AUTHORITATIVE)** (lines 1991-2009):
- Calls `getServiceConfigFromPlist(binaryPath)`
- Reads ProgramArguments from LaunchDaemon plist
- Extracts:
  - `--meshServiceName=...`
  - `--companyName=...`
- **Most reliable source** - Reflects running configuration

**Priority 3: .msh Configuration File** (lines 2011-2027):
- Reads key=value pairs from .msh
- Fields: meshServiceName, companyName, MeshServer, etc.
- **Persistent config** - Survives binary updates

**Priority 4: .db Database (Read-Only)** (lines 2029-2050):
- Opens SimpleDataStore in read-only mode
- Retrieves meshServiceName, companyName from DB
- **Fallback source** - Rarely used

**Priority 5: Installation Path Inference** (lines 2052-2065):
- For `/usr/local/mesh_services/{company}/{service}/` paths
- Calls `parseServiceIdFromInstallPath()`
- **Path-based discovery** - Works when config missing

**Auto-Migration Logic** (lines 2067-2096):
- If .msh missing but plist has config → create .msh from plist
- If .msh differs from plist → sync .msh to match plist
- Ensures configuration consistency across upgrade

**Upgrade Workflow** (lines 2098-2500):

**1. Plist Discovery and Cleanup** (lines 2105-2176):
```javascript
// Find ALL plists pointing to this binary
var plists = cleanupOrphanedPlists(installPath);
// Example result:
// [
//   '/Library/LaunchDaemons/meshagent.oldservice.plist',
//   '/Library/LaunchAgents/meshagent.oldservice-agent.plist'
// ]
```
- Handles service renames
- Prevents multiple services for same binary
- Critical for clean state

**2. Service Unload Verification** (lines 2178-2224):
```javascript
// Verify launchd unloaded services
var verifyResult = verifyServiceUnloaded(serviceId, maxAttempts);
// Returns: { loaded: false, domain: null } or { loaded: true, domain: 'system' }
```
- Checks launchd doesn't have service loaded
- Polls system and all gui domains
- **CRITICAL:** Prevents launchd from auto-restarting after kill

**3. Process Termination with Path Verification** (lines 2226-2280):
```javascript
// Find processes and verify they're from this installation
var terminateResult = verifyProcessesTerminated(binaryPath, maxWaitSeconds);
// Returns: { success: true, pids: [] } or { success: false, pids: [1234, 5678] }
```
- Uses `pgrep meshagent` to find PIDs
- Uses `lsof -p {PID}` to verify binary path
- **Path isolation:** Only touches processes from this installation
- Graceful wait period (e.g., 10 seconds)

**4. Force Bootout (If Needed)** (lines 2282-2300):
```javascript
if (!unloadResult.success) {
    forceBootoutService(serviceId, domain);
    // Executes: launchctl bootout system/meshagent.myservice
}
```
- Explicit bootout command if unload failed
- Per-domain bootout (system vs gui/501)
- 1-second wait after bootout

**5. Force Kill (If Needed)** (lines 2302-2330):
```javascript
if (!terminateResult.success) {
    forceKillProcesses(terminateResult.pids);
    // Executes: kill -9 1234 5678
}
```
- **Only after launchd verification** (no auto-restart)
- SIGKILL for stubborn processes
- 1-second cleanup delay

**6. Binary Replacement** (lines 2342-2400):
- **Backup Old Binary** (lines 2350-2365):
  ```javascript
  var timestamp = Math.floor(Date.now() / 1000);
  var backupPath = oldBinary + '.backup.' + timestamp;
  fs.renameSync(oldBinary, backupPath);
  ```

- **Copy New Binary** (lines 2367-2385):
  - Detect in-place upgrade: `process.execPath == targetPath`
  - **In-place:** Use intermediate temp file
  - **Remote:** Direct copy
  - Set permissions: chmod 755

**7. Service Recreation** (lines 2402-2470):
- **LaunchDaemon** (lines 2410-2440):
  - Write new plist with updated config
  - Preserves --meshServiceName, --companyName
  - KeepAlive, RunAtLoad settings

- **LaunchAgent** (lines 2442-2470):
  - Write agent plist (serviceId + '-agent')
  - LimitLoadToSessionType: Aqua, LoginWindow

**8. Service Bootstrap** (lines 2472-2498):
```bash
# Bootstrap (load) services
launchctl load /Library/LaunchDaemons/meshagent.myservice.plist
launchctl load /Library/LaunchAgents/meshagent.myservice-agent.plist

# Start services
launchctl start meshagent.myservice
launchctl start meshagent.myservice-agent
```

**Safety Features:**
- **No race conditions:** Verifies launchd unload BEFORE killing processes
- **Path-based isolation:** lsof prevents touching wrong binaries
- **Configuration preservation:** .msh and .db never deleted
- **Orphan cleanup:** Removes ALL old plists before creating new ones
- **Idempotent:** Can run multiple times safely
- **Multi-installation safe:** Path verification prevents collisions

**Why 577 Lines:**
- Multi-tier config discovery: ~100 lines
- Auto-migration logic: ~50 lines
- Service state verification: ~150 lines
- Process lifecycle management: ~100 lines
- Plist management: ~100 lines
- Error handling and logging: ~77 lines

---

#### verifyServiceUnloaded(serviceId, maxAttempts) - Lines 654-701 (LaunchD State Verification)

**Purpose:** Verifies service is NOT loaded in launchd to prevent auto-restart after process kill.

**Process:**
1. **System Domain Check** (lines 664-672):
   ```bash
   launchctl print system/meshagent.myservice
   ```
   - Exit code 0 = loaded
   - Exit code != 0 = not loaded

2. **User GUI Domains Check** (lines 674-693):
   - Enumerates all user sessions
   - For each UID:
     ```bash
     launchctl print gui/501/meshagent.myservice-agent
     ```
   - Checks LaunchAgent status per user

3. **Retry Logic** (lines 660-699):
   - Polls up to `maxAttempts` times
   - 500ms delay between checks
   - Returns immediately if unloaded

**Return Value:**
```javascript
{ loaded: false, domain: null }  // Success - not in launchd
{ loaded: true, domain: 'system' }  // Still loaded in system domain
{ loaded: true, domain: 'gui/501' }  // Still loaded in user 501
```

**Critical for:**
- Preventing launchd from respawning killed processes
- Ensures kill is permanent, not temporary
- Multi-user LaunchAgent tracking

---

#### verifyProcessesTerminated(binaryPath, maxWaitSeconds) - Lines 730-805 (Process Path Verification)

**Purpose:** Finds processes AND verifies they're actually running the specified binary path. Prevents touching wrong installations.

**Process:**
1. **Find PIDs** (lines 740-748):
   ```bash
   pgrep -x meshagent
   # Returns: 1234\n5678\n
   ```

2. **Path Verification** (lines 750-783):
   - For each PID:
     ```bash
     lsof -p 1234 | grep txt | awk '{print $NF}'
     # Returns: /usr/local/mesh_services/mycompany/myservice/meshagent
     ```
   - Compares with expected `binaryPath`
   - **Only include PIDs with matching path**

3. **Wait and Retry** (lines 785-800):
   - Polls every 500ms up to `maxWaitSeconds`
   - Rechecks process list each iteration
   - Returns success if all processes terminated

**Return Value:**
```javascript
{ success: true, pids: [] }  // All processes terminated
{ success: false, pids: [1234, 5678] }  // These PIDs still running from this path
```

**Why Path Verification:**
- Multiple MeshAgent installations may run simultaneously
- Each installation in different directory
- Path check isolates specific installation
- Prevents killing wrong agent

**Example Scenario:**
```
Installation A: /opt/mesh/meshagent (PID 1000)
Installation B: /usr/local/mesh/meshagent (PID 2000)

Upgrading Installation B:
- pgrep finds: 1000, 2000
- lsof filters to: 2000 only (matches /usr/local/mesh/meshagent)
- Only PID 2000 touched, Installation A unaffected
```

---

#### forceBootoutService(serviceId, domain) - Lines 704-725 (Explicit LaunchD Bootout)

**Purpose:** Forces launchd to bootout (unload and disable) a service when normal unload fails.

**Process:**
```bash
# System domain (LaunchDaemon)
launchctl bootout system/meshagent.myservice

# User domain (LaunchAgent)
launchctl bootout gui/501/meshagent.myservice-agent
```

- 1-second sleep after bootout for launchd processing
- More forceful than `unload`
- Required when service in crashed or inconsistent state

**When Used:**
- Service unload failed
- Process still running after unload
- Service in error state

---

#### forceKillProcesses(pids) - Lines 808-830 (SIGKILL Execution)

**Purpose:** Sends SIGKILL (kill -9) to stubborn processes that didn't terminate gracefully.

**Process:**
```bash
kill -9 1234 5678
```

- **Only called after launchd verification** (critical!)
- 1-second cleanup delay after kill
- No retry logic (SIGKILL is final)

**Safety:**
- Must verify launchd unloaded first
- Otherwise launchd immediately respawns process
- Path verification ensures killing correct processes

---

### Helper Functions

#### sanitizeIdentifier(str) - Lines 112-116 (Service ID Sanitization)

**Purpose:** Converts service names to valid macOS service identifiers.

**Process:**
```javascript
'My Service Name!' → 'my-service-name'
```
- Convert to lowercase
- Replace spaces with hyphens
- Remove special characters except hyphens
- Matches service-manager.js sanitization

---

#### findInstallation(installPath, serviceName, companyName) - Lines 268-327 (Installation Discovery)

**Purpose:** Locates existing installation for upgrade operations.

**Priority:**
1. **Explicit installPath** - User provided path
2. **Service Manager Lookup** - Find via service name
3. **Self-Upgrade Detection** - Check if running from install dir (.msh file present)
4. **Default Path** - `/usr/local/mesh_services/`

**macOS-Specific:**
- Detects running from installation directory
- Checks for .msh file in current directory
- Supports both daemon and agent service names

---

#### normalizeInstallPath(path) - Lines 272-278 (Path Normalization)

**Purpose:** Normalizes installation directory paths by ensuring trailing slash.

**Process:**
```javascript
'/opt/mesh/meshagent/' → '/opt/mesh/meshagent/'
'/opt/mesh/meshagent' → '/opt/mesh/meshagent/'
'/opt/mesh/' → '/opt/mesh/'
```
- Returns default path if input is null: `/usr/local/mesh_services/meshagent/`
- Ensures trailing slash for consistency
- **Does NOT strip path components** (fixed in commit 1022fb28)

**Recent Bug Fix (Nov 2025):**

Previously, the function incorrectly treated paths ending with 'meshagent' as if they were binary paths rather than directory paths:

**Old behavior (INCORRECT):**
```javascript
'/usr/local/mesh_services/meshagent' → '/usr/local/mesh_services/'
// Stripped 'meshagent' thinking it was the binary filename
```

**New behavior (CORRECT):**
```javascript
'/usr/local/mesh_services/meshagent' → '/usr/local/mesh_services/meshagent/'
// Preserves full directory path, only adds trailing slash
```

**Why the fix was needed:**
- `--installPath` parameter is explicitly a directory path, never a binary path
- Users specifying `/usr/local/mesh_services/meshagent` expected that directory to be created
- Old logic would incorrectly create the parent directory instead
- Installation GUI was affected, creating wrong directory structure

**Technical Notes:**
- Simple function now: checks null, adds trailing slash if missing
- No path component stripping logic
- Consistent with directory path semantics

---

#### parseMshFile(mshPath) / updateMshFile(mshPath, updates) - Lines 201-265 (.msh File Management)

**Purpose:** Read/write MeshAgent configuration files in key=value format.

**Format:**
```
MeshServer=wss://meshcentral.example.com:443/agent.ashx
MeshID=ABC123
meshServiceName=MyService
companyName=MyCompany
```

**parseMshFile:**
- Reads file line by line
- Splits on first '=' sign
- Returns object with keys/values

**updateMshFile:**
- Preserves existing keys
- Updates specified keys
- Writes back to file
- Supports blank values: `key=` (triggers DB deletion on import)

---

#### parseServiceIdFromInstallPath(installPath) - Lines 1834-1883 (Path-Based Service ID Discovery)

**Purpose:** Extracts service name and company from `/usr/local/mesh_services/` paths.

**Patterns:**
```javascript
'/usr/local/mesh_services/meshagent/' → { serviceName: 'meshagent', companyName: null }
'/usr/local/mesh_services/MyService/' → { serviceName: 'MyService', companyName: null }
'/usr/local/mesh_services/MyCompany/MyService/' → { serviceName: 'MyService', companyName: 'MyCompany' }
```

**Limitations:**
- **ONLY works for /usr/local/mesh_services/ paths**
- Returns null for other paths
- Used as fallback when config files missing

---

#### getServiceConfigFromPlist(binaryPath) - Lines 1887-1947 (AUTHORITATIVE Config Source)

**Purpose:** Extracts running configuration from LaunchDaemon plist ProgramArguments.

**Process:**
1. **Find Plist** (lines 1895-1912):
   - Scans `/Library/LaunchDaemons/meshagent.*.plist`
   - For each plist:
     - Extracts ProgramArguments[0] via PlistBuddy
     - Matches against binaryPath

2. **Extract ProgramArguments** (lines 1914-1937):
   ```bash
   /usr/libexec/PlistBuddy -c "Print ProgramArguments" /Library/LaunchDaemons/meshagent.myservice.plist
   ```
   - Parses XML array output
   - Extracts `--meshServiceName=...`
   - Extracts `--companyName=...`

**Return Value:**
```javascript
{
  serviceName: 'MyService',
  companyName: 'MyCompany'
}
```

**Why AUTHORITATIVE:**
- Reflects actual running configuration
- launchd uses plist to start service
- Most reliable source of truth
- Used to sync .msh file during upgrade

---

#### getProgramPathFromPlist(plistPath) - Lines 372-384 (Binary Path Extraction)

**Purpose:** Extracts executable path from plist ProgramArguments[0].

**Process:**
```bash
/usr/libexec/PlistBuddy -c "Print ProgramArguments:0" /path/to/plist
# Returns: /usr/local/mesh_services/mycompany/myservice/meshagent
```

**Used By:**
- `cleanupOrphanedPlists()` - Match plists to binary
- Orphan detection logic

---

### Windows-Specific Functions

#### win_checkfirewall() / win_clearfirewall() / win_setfirewall() - Lines 2751-2795 (Firewall Management)

**Purpose:** Manage Windows Firewall rules for WebRTC UDP traffic.

**win_checkfirewall:**
- Enumerates existing "MeshCentral*" firewall rules
- Returns array of rule names

**win_clearfirewall:**
- Removes all MeshCentral firewall rules
- Async with progress reporting

**win_setfirewall:**
- Creates inbound and outbound UDP rules
- Port range: Configurable (typically 16384-32767)
- Rule names: "MeshCentral Agent Inbound", "MeshCentral Agent Outbound"

---

#### sys_update(isservice, b64) / win_consoleUpdate() - Lines 2540-2813 (Legacy Windows Self-Update)

**Purpose:** Legacy Windows self-update mechanism (replaced by agent-installer upgrade).

**Process:**
1. Decode base64 binary to .update.exe
2. Stop service (if service mode)
3. Copy .update.exe → .exe
4. Restart service
5. Exit

**Notes:**
- Legacy code, mostly unused
- Replaced by `upgradeAgent()` / `fullInstallEx()` upgrade path
- Kept for backward compatibility

---

### Dependencies

#### Node.js Core Modules
- **`fs`** (lines 331, 393, etc.) - File I/O operations
- **`child_process`** (lines 426, 665, etc.) - Shell command execution (macOS)

#### MeshAgent Module Dependencies

**Required on All Platforms:**
- **`service-manager`** (lines 332, 920, 1543) - Service installation/management
  - Methods: `installService()`, `uninstall()`, `start()`, `stop()`, `getService()`, `enumerateService()`
  - Core service lifecycle management

- **`_agentNodeId`** (lines 330, 1701) - Service name detection
  - Method: `serviceName()`
  - Used when service name not provided

- **`fs`** - File operations
  - Read/write .msh files
  - Copy binaries
  - Delete data files

**Platform-Specific:**

**Windows:**
- **`win-registry`** (line 919) - Registry operations
  - Service configuration storage

- **`win-firewall`** (line 2758) - Firewall rule management
  - WebRTC UDP port configuration

- **`win-bcd`** (line 1031) - Boot Configuration Data
  - SafeMode network enablement

**macOS:**
- **`user-sessions`** (lines 975, 1077) - Session management
  - Methods: `consoleUid()`, `isRoot()`
  - UID lookup for LaunchAgent

- **`task-scheduler`** (line 1368) - Secondary agent management
  - Diagnostic agent cleanup

- **`SimpleDataStore`** (line 2034) - Database access
  - Configuration discovery fallback

- **`process-manager`** (line 2667) - Process enumeration
  - Method: `enumerateProcesses()`
  - Used during upgrade for process verification

**Unix:**
- **`user-sessions`** - UID tracking

#### External Dependencies (macOS)

**Required Binaries:**
- **`launchctl`** - Service management
  - Commands: load, unload, start, stop, print, bootout
  - Critical for all service operations

- **`lsof`** - Process path verification
  - Usage: `lsof -p {PID}`
  - Verifies binary path for process isolation

- **`pgrep`** - Process discovery
  - Usage: `pgrep -x meshagent`
  - Finds all meshagent PIDs

- **`/usr/libexec/PlistBuddy`** - Plist parsing
  - Usage: Extract ProgramArguments
  - AUTHORITATIVE config source

- **`chown`** - File ownership
  - Usage: `chown root:wheel`
  - Sets .msh file permissions

- **`chmod`** - File permissions
  - Usage: `chmod 755` (binary), `chmod 600` (.msh)
  - Security and execution permissions

**Windows Binaries:**
- **netsh** - Firewall management
- **schtasks** - Task scheduling (fallback for user switching)

**Linux Binaries:**
- **systemctl** - systemd service management

### Usage

#### Installation

```bash
# Fresh install
meshagent --eval "require('agent-installer').fullInstall('[\"--meshServiceName=MyAgent\",\"--installPath=/opt/mesh/\",\"--companyName=MyCompany\"]')"

# Install with .msh file
meshagent --eval "require('agent-installer').fullInstall('[\"--msh=/path/to/config.msh\"]')"

# Install from running agent
require('agent-installer').fullInstallEx([
  '--meshServiceName=MyAgent',
  '--installPath=/opt/mesh/',
  '--companyName=MyCompany'
]);
```

#### Uninstallation

```bash
# Uninstall, preserve data
meshagent --eval "require('agent-installer').fullUninstall('[\"--meshServiceName=MyAgent\"]')"

# Uninstall, delete everything
meshagent --eval "require('agent-installer').fullUninstall('[\"--meshServiceName=MyAgent\",\"--_deleteData=1\"]')"
```

#### Upgrade (macOS)

```bash
# Upgrade from running agent
meshagent --eval "require('agent-installer').upgradeAgent('[\"--installPath=/opt/mesh/\"]')"

# Upgrade with config discovery (no parameters needed)
meshagent --eval "require('agent-installer').upgradeAgent('[]')"

# Upgrade with explicit config
meshagent --eval "require('agent-installer').upgradeAgent('[\"--meshServiceName=MyAgent\",\"--companyName=MyCompany\"]')"
```

### Technical Notes

**macOS Dual-Service Architecture:**

**Why Two Services:**
- **LaunchDaemon (root):** Background operations, server communication
- **LaunchAgent (user):** KVM/desktop capture, requires user session

**Service ID Naming:**
```
LaunchDaemon: meshagent.{serviceName}.{companyName}
LaunchAgent:  meshagent.{serviceName}.{companyName}-agent

Examples:
- meshagent (default)
- meshagent.customname
- meshagent.customname.mycompany
- meshagent.customname.mycompany-agent (LaunchAgent)
```

**LaunchDaemon Plist:**
```xml
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>meshagent.myservice.mycompany</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/mesh_services/mycompany/myservice/meshagent</string>
    <string>--meshServiceName=myservice</string>
    <string>--companyName=mycompany</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
```

**LaunchAgent Plist:**
```xml
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>meshagent.myservice.mycompany-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/mesh_services/mycompany/myservice/meshagent</string>
    <string>--meshServiceName=myservice</string>
    <string>--companyName=mycompany</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>LimitLoadToSessionType</key>
  <array>
    <string>Aqua</string>
    <string>LoginWindow</string>
  </array>
</dict>
</plist>
```

**Installation Path Structure (macOS):**
```
/usr/local/mesh_services/
├── default/
│   └── meshagent                  (default service)
├── CustomService/
│   └── meshagent                  (custom service name)
└── MyCompany/
    ├── Service1/
    │   └── meshagent              (company + service)
    └── Service2/
        └── meshagent              (company + different service)
```

**Configuration Priority During Upgrade:**
1. Command-line flags (user override)
2. **LaunchDaemon plist** (AUTHORITATIVE - actual running config)
3. .msh file (persistent config)
4. .db database (fallback)
5. Path inference (last resort)

**Why Plist is Authoritative:**
- launchd uses plist to start service
- Reflects actual running configuration
- Can diverge from .msh after manual plist edits
- Upgrade syncs .msh to match plist

**Safe Upgrade Sequence (macOS):**
1. Discover configuration from multiple sources
2. Find ALL plists pointing to binary → cleanup orphans
3. **Verify launchd unloaded** (prevent auto-restart)
4. **Verify processes terminated** (with path check)
5. Force bootout if needed
6. Force kill if needed (only after launchd check!)
7. Backup old binary
8. Copy new binary
9. Recreate LaunchDaemon and LaunchAgent plists
10. Bootstrap (load) services
11. Start services

**Critical Safety Features:**

**Race Condition Prevention:**
- Always verify launchd unload BEFORE killing processes
- Otherwise: kill → launchd restart → kill → restart (loop)
- `verifyServiceUnloaded()` ensures launchd won't respawn

**Multi-Installation Safety:**
- Path verification via `lsof -p {PID}`
- Only touches processes from specific installation
- Prevents affecting other agent installations

**Idempotency:**
- Orphan cleanup removes ALL old plists first
- Can run upgrade multiple times
- Each run starts from clean state

**Configuration Preservation:**
- .msh and .db files NEVER deleted during upgrade
- Only binary replaced
- Identity and enrollment preserved

**Windows SafeMode Support:**

**Problem:** Windows SafeMode disables network by default
**Solution:** Use BCD (Boot Configuration Data) to enable network for specific service

**Process:**
```javascript
require('win-bcd').addSafeNetworkStartup(serviceName);
```
- Adds service to SafeMode network startup list
- Allows agent to run during Windows recovery/troubleshooting
- Enables remote support during SafeMode sessions

**Windows Firewall Configuration:**

**Purpose:** Allow WebRTC UDP for remote desktop
**Process:**
- Create inbound rule: Allow UDP on port range
- Create outbound rule: Allow UDP on port range
- Rule names: "MeshCentral Agent Inbound/Outbound"

**Why Needed:**
- WebRTC uses UDP for peer-to-peer media
- Windows Firewall blocks by default
- Required for KVM remote desktop

### Platform-Specific Analysis

**What Works on macOS:**

**All Core Functionality:**
- Fresh installation with LaunchDaemon + LaunchAgent
- Complete uninstallation with orphan cleanup
- **Advanced upgrade** with multi-tier config discovery
- Service start/stop/restart
- Configuration file management
- Path-based process isolation

**macOS-Specific Features:**
- Dual-service architecture (daemon + agent)
- Orphaned plist scanner and cleanup
- launchd state verification before kill
- Process path verification via lsof
- Service ID generation (meshagent.service.company)
- PlistBuddy-based config extraction
- LaunchAgent for KVM in user sessions

**What Doesn't Work on macOS:**
- Windows firewall management (not applicable)
- Windows SafeMode configuration (not applicable)
- Win-registry operations (not applicable)
- Windows self-update mechanism (not applicable)

**macOS Upgrade Sophistication:**

**Why 577 Lines:**
The macOS upgrade function is the most sophisticated in the codebase:

1. **Multi-Tier Config Discovery** (~100 lines)
   - 5 priority levels
   - Auto-migration from plist to .msh
   - Configuration sync logic

2. **Safe Process Lifecycle** (~150 lines)
   - launchd state verification
   - Path-based process isolation
   - Graceful wait periods
   - Force bootout/kill with safety checks

3. **Comprehensive Plist Management** (~100 lines)
   - Orphan detection and cleanup
   - LaunchDaemon + LaunchAgent creation
   - Service ID calculation
   - Multi-installation support

4. **Error Handling** (~75 lines)
   - Logging at each step
   - Fallback mechanisms
   - State recovery

5. **Configuration Preservation** (~50 lines)
   - .msh file management
   - .db database handling
   - Identity persistence

**Comparison to Other Platforms:**

**Linux Upgrade:**
- Simple: Stop service → Copy binary → Start service
- ~50 lines of code
- No multi-installation considerations
- No orphan cleanup needed

**Windows Upgrade:**
- Medium: Stop service → Copy binary → Update registry → Start service
- ~100 lines of code
- Registry handles configuration
- No orphan cleanup needed

**macOS Upgrade:**
- Complex: 577 lines
- Multi-tier config discovery
- Dual-service management
- Orphan cleanup critical
- Process isolation required
- launchd state verification essential

**Why macOS is More Complex:**
- **Dual services:** LaunchDaemon + LaunchAgent
- **No centralized config:** Plists scattered in system directories
- **Service renames:** Old plists become orphans
- **Multi-installation:** Multiple agents can coexist
- **launchd auto-restart:** Must verify unload before kill
- **Session types:** Aqua vs LoginWindow vs Background

## Summary

The agent-installer.js module is the complete lifecycle management system for MeshAgent across all supported platforms (Windows, Linux, macOS, FreeBSD). It provides installation, uninstallation, and upgrade capabilities with platform-specific optimizations.

**Key capabilities:**
- Fresh service installation with configuration setup
- Complete uninstallation with optional data cleanup
- Seamless in-place upgrades with configuration preservation
- Windows: Firewall management, SafeMode support, registry configuration
- Linux: systemd service management
- **macOS: Advanced dual-service architecture with sophisticated upgrade logic**

**macOS highlights:**
- **Dual services:** LaunchDaemon (root) + LaunchAgent (user session)
- **577-line upgrade function** with multi-tier configuration discovery
- **Safe process lifecycle:** launchd verification before kill, path-based isolation
- **Orphan cleanup:** Finds and removes ALL old plists
- **Configuration auto-migration:** Syncs .msh with plist
- **Multi-installation safe:** Path verification prevents collisions
- **Idempotent upgrades:** Can run multiple times safely

**Critical dependencies:**
- service-manager for cross-platform service operations
- Platform-specific: win-registry, win-firewall, win-bcd (Windows)
- Platform-specific: launchctl, lsof, pgrep, PlistBuddy (macOS)
- user-sessions for UID management

The module represents the most comprehensive service management implementation in the MeshAgent ecosystem, with macOS receiving exceptional attention to handle the complexities of launchd, dual-service architecture, and multi-installation scenarios.
