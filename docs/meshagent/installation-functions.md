# macOS MeshAgent Installation Functions

## Overview

The macOS MeshAgent provides five main installation/management functions:

- **`-upgrade`** - Update existing installation (recreate plists with correct serviceId)
- **`-install`** - Standard installation (requires .msh file)
- **`-fullinstall`** - Complete installation (includes configuration download)
- **`-uninstall`** - Remove installation
- **`-fulluninstall`** - Complete removal with cleanup

This document provides comprehensive reference for each function, with special emphasis on the **-upgrade** function which is **automatically called by MeshCentral during agent updates**.

---

## Table of Contents

- [-upgrade Function](#-upgrade-function)
  - [When It's Called](#when-its-called)
  - [What It Does](#what-it-does)
  - [Safety Checks](#safety-checks)
  - [Configuration Discovery](#configuration-discovery)
  - [Plist Recreation](#plist-recreation)
  - [Service Lookup Mechanisms](#service-lookup-mechanisms)
  - [Orphaned Plist Cleanup](#orphaned-plist-cleanup)
  - [Usage Examples](#upgrade-usage-examples)
- [-install Function](#-install-function)
- [-fullinstall Function](#-fullinstall-function)
- [-uninstall Function](#-uninstall-function)
- [-fulluninstall Function](#-fulluninstall-function)
- [Helper Functions](#helper-functions)
- [Troubleshooting](#troubleshooting)

---

## -upgrade Function

### CRITICAL: When It's Called

The `-upgrade` function is **automatically invoked by MeshCentral** when it sends down an updated meshagent binary.

**Code Reference:** `/meshcore/agentcore.c:6449-6453`

```c
case MeshAgent_Posix_PlatformTypes_LAUNCHD:
    if (agentHost->logUpdate != 0) {
        ILIBLOGMESSSAGE("SelfUpdate -> Complete... [running -upgrade to recreate plists]");
    }
    // Call -upgrade to recreate LaunchDaemon and LaunchAgent plists with --serviceId parameters
    // This ensures plists are updated with correct QueueDirectories and serviceId parameter
    sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "\"%s\" -upgrade", agentHost->exePath);
    ignore_result(system(ILibScratchPad));
    break;
```

**This happens during:**
1. MeshCentral administrator pushes agent update
2. Agent receives `MeshCommand_AgentUpdate` command
3. New binary is downloaded and installed
4. C code automatically calls: `./meshagent -upgrade`
5. Plists are recreated with current configuration

**YOU DON'T MANUALLY RUN -upgrade DURING UPDATES** - it happens automatically.

### When You Might Manually Run -upgrade

Manual `-upgrade` is useful for:
- **Testing** - Verify upgrade process works
- **Plist repair** - Fix corrupted plists
- **Service rename** - Change serviceId without reinstalling
- **Configuration sync** - Ensure plists match current config
- **Troubleshooting** - Diagnose installation issues

---

### What It Does

The `-upgrade` function performs a comprehensive update of the MeshAgent installation:

**High-Level Flow:**

```
1. Verify root privileges
   ↓
2. Discover current configuration
   ├─> Parse command-line flags
   ├─> Find installation path
   ├─> Read plist (authoritative source)
   ├─> Read .msh file
   └─> Read .db database
   ↓
3. Calculate serviceId from discovered config
   ↓
4. Unload services from launchd
   ↓
5. Verify services unloaded (SAFETY CHECK)
   ↓
6. Kill any running processes
   ↓
7. Verify processes terminated (SAFETY CHECK)
   ↓
8. Clean up orphaned plists
   ↓
9. Create socket directory
   ↓
10. Recreate LaunchDaemon plist
    ↓
11. Recreate LaunchAgent plist
    ↓
12. Reload services
    ↓
13. Verify successful startup
```

**Code Reference:** `/modules/agent-installer.js:1949-2527`

---

### Safety Checks

The `-upgrade` function implements **comprehensive safety checks** to prevent system instability.

#### Safety Check 1: Verify Services Unloaded

**CRITICAL:** This must happen BEFORE killing processes!

**Why?** If you kill a process while launchd thinks the service is loaded:
- launchd will immediately restart it (KeepAlive=true)
- You create a restart loop
- Update fails

**Code Reference:** `/modules/agent-installer.js:2245-2290`

```javascript
function verifyServiceUnloaded(serviceId, maxRetries) {
    for (var i = 0; i < maxRetries; i++) {
        // Check system domain (LaunchDaemon)
        var systemCheck = child_process.execSync(
            'launchctl print system/' + serviceId + ' 2>&1',
            { encoding: 'utf8' }
        );

        if (systemCheck.indexOf('Could not find service') >= 0) {
            // Service unloaded from system - good!
        } else {
            return { loaded: true, domain: 'system' };
        }

        // Check gui domain (LaunchAgent) - check all user sessions
        var guiCheck = child_process.execSync(
            'launchctl print gui/501/' + serviceId + '-agent 2>&1',
            { encoding: 'utf8' }
        );

        if (guiCheck.indexOf('Could not find service') >= 0) {
            // Service unloaded from gui - good!
        } else {
            return { loaded: true, domain: 'gui/501' };
        }

        if (i < maxRetries - 1) {
            // Wait before retry
            child_process.execSync('sleep 1');
        }
    }

    return { loaded: false, domain: null };
}
```

**Usage in -upgrade:**

```javascript
process.stdout.write('Step 1: Verifying services unloaded from launchd...\n');
var unloadCheck = verifyServiceUnloaded(currentServiceId, 3);

if (unloadCheck.loaded) {
    process.stdout.write('   WARNING: Service still loaded in launchd (' + unloadCheck.domain + ')\n');
    process.stdout.write('   Attempting force bootout...\n');

    var bootoutSuccess = forceBootoutService(currentServiceId, unloadCheck.domain);

    if (bootoutSuccess) {
        // Verify bootout worked
        unloadCheck = verifyServiceUnloaded(currentServiceId, 2);
        if (unloadCheck.loaded) {
            process.stdout.write('   ERROR: Cannot unload service from launchd\n');
            process.stdout.write('   This is dangerous - aborting upgrade\n');
            process.exit(1);
        }
    } else {
        process.stdout.write('   ERROR: Force bootout failed\n');
        process.exit(1);
    }
}

process.stdout.write('   ✓ Services verified unloaded from launchd\n');
```

**What it checks:**
- System domain (`launchctl print system/{serviceId}`)
- GUI domains (`launchctl print gui/501/{serviceId}-agent`)
- Retries with delays (launchd operations aren't instant)

---

#### Safety Check 2: Verify Processes Terminated

**Why?** Ensure old processes are gone before recreating plists.

**Code Reference:** `/modules/agent-installer.js:2292-2321`

```javascript
function verifyProcessesTerminated(binaryPath, maxRetries) {
    for (var i = 0; i < maxRetries; i++) {
        // Use pgrep to find meshagent processes
        try {
            var pids = child_process.execSync('pgrep meshagent', { encoding: 'utf8' }).trim().split('\n');

            // Verify each PID is actually running our binary (not a different meshagent)
            var ourPids = [];
            pids.forEach(function(pid) {
                if (!pid) return;

                // Use lsof to get actual binary path for this PID
                try {
                    var lsofOutput = child_process.execSync(
                        'lsof -p ' + pid + ' 2>/dev/null | grep meshagent',
                        { encoding: 'utf8' }
                    );

                    if (lsofOutput.indexOf(binaryPath) >= 0) {
                        ourPids.push(pid);
                    }
                } catch (e) {
                    // Process may have exited - ignore
                }
            });

            if (ourPids.length === 0) {
                return { success: true, pids: [] };
            }

            if (i < maxRetries - 1) {
                child_process.execSync('sleep 1');
            } else {
                return { success: false, pids: ourPids };
            }
        } catch (e) {
            // No meshagent processes found
            return { success: true, pids: [] };
        }
    }

    return { success: false, pids: [] };
}
```

**What it checks:**
- Finds all `meshagent` processes (via `pgrep`)
- Verifies each PID is running OUR binary (via `lsof`)
- Only targets processes from the specific installation path
- Retries with delays

**Usage in -upgrade:**

```javascript
process.stdout.write('Step 2: Verifying processes terminated (path: ' + binaryPath + ')...\n');
var processCheck = verifyProcessesTerminated(binaryPath, 5);

if (!processCheck.success) {
    process.stdout.write('   WARNING: Processes still running (PIDs: ' + processCheck.pids.join(', ') + ')\n');
    process.stdout.write('   Attempting force kill...\n');

    var killSuccess = forceKillProcesses(processCheck.pids);

    if (killSuccess) {
        // Verify processes are gone
        processCheck = verifyProcessesTerminated(binaryPath, 2);

        if (!processCheck.success) {
            process.stdout.write('   ERROR: Cannot terminate processes\n');
            process.stdout.write('   PIDs: ' + processCheck.pids.join(', ') + '\n');
            process.exit(1);
        }
    } else {
        process.stdout.write('   ERROR: Force kill failed\n');
        process.exit(1);
    }
}

process.stdout.write('   ✓ Processes verified terminated\n');
```

---

#### Force Bootout (Emergency Unload)

If normal unload fails, force bootout via launchctl:

**Code Reference:** `/modules/agent-installer.js:704-725`

```javascript
function forceBootoutService(serviceId, domain) {
    try {
        if (domain === 'system') {
            // Bootout from system domain
            child_process.execSync(
                'launchctl bootout system/' + serviceId + ' 2>&1',
                { encoding: 'utf8' }
            );
        } else if (domain && domain.indexOf('gui/') === 0) {
            // Bootout from gui domain
            child_process.execSync(
                'launchctl bootout ' + domain + '/' + serviceId + '-agent 2>&1',
                { encoding: 'utf8' }
            );
        }

        return true;
    } catch (e) {
        return false;
    }
}
```

---

#### Force Kill (Emergency Termination)

If processes don't exit gracefully, force kill:

**Code Reference:** `/modules/agent-installer.js:807-829`

```javascript
function forceKillProcesses(pids) {
    try {
        pids.forEach(function(pid) {
            if (!pid) return;

            // Send SIGKILL to process
            child_process.execSync('kill -9 ' + pid + ' 2>/dev/null');
        });

        // Wait for kills to take effect
        child_process.execSync('sleep 1');

        return true;
    } catch (e) {
        return false;
    }
}
```

**IMPORTANT:** This is only called AFTER verifying launchd has unloaded the service!

---

### Configuration Discovery

The `-upgrade` function must discover the current installation configuration.

**Priority Chain:**

```
1. Command-line flags         (explicit overrides)
   ↓
2. Plist ProgramArguments     (AUTHORITATIVE - what's running)
   ↓
3. .msh file                  (config file)
   ↓
4. .db database               (read-only)
   ↓
5. Installation path          (fallback)
```

See [naming-and-configuration.md](./naming-and-configuration.md#configuration-sources-and-priority) for details.

#### Discovery Code

**Code Reference:** `/modules/agent-installer.js:2004-2109`

```javascript
// Start with command-line flags (highest priority)
var currentServiceName = explicitServiceName || null;
var currentCompanyName = explicitCompanyName || null;
var currentServiceId = explicitServiceId || null;

// Find installation
var installPath = findInstallation(currentServiceName, currentCompanyName, null);

if (!installPath) {
    console.log('ERROR: Could not find existing meshagent installation');
    process.exit(1);
}

// Get plist configuration (AUTHORITATIVE SOURCE)
if (!currentServiceId) {
    // Try to discover serviceId from running service
    // This finds the LaunchDaemon plist and extracts --serviceId parameter
    var plistConfig = getServiceConfigFromPlist(currentServiceId || 'meshagent');

    if (plistConfig) {
        if (!currentServiceName) currentServiceName = plistConfig.serviceName;
        if (!currentCompanyName) currentCompanyName = plistConfig.companyName;
        if (!currentServiceId) currentServiceId = plistConfig.serviceId;
    }
}

// Fall back to .msh file
if (!currentServiceName || !currentCompanyName) {
    var mshConfig = parseMshFile(installPath + 'meshagent.msh');

    if (mshConfig) {
        if (!currentServiceName) currentServiceName = mshConfig.meshServiceName;
        if (!currentCompanyName) currentCompanyName = mshConfig.companyName;
    }
}

// Fall back to .db database (read-only)
if (!currentServiceName || !currentCompanyName) {
    try {
        var db = require('SimpleDataStore').Create(
            installPath + 'meshagent.db',
            { readOnly: true }
        );

        if (!currentServiceName) {
            currentServiceName = db.Get('meshServiceName');
        }

        if (!currentCompanyName) {
            currentCompanyName = db.Get('companyName');
        }
    } catch (e) {
        // Database may be locked - not critical
    }
}

// Calculate final serviceId
if (!currentServiceId) {
    currentServiceId = calculateServiceId(currentServiceName, currentCompanyName);
}

console.log('Discovered configuration:');
console.log('  Installation path: ' + installPath);
console.log('  Service name: ' + (currentServiceName || '(default)'));
console.log('  Company name: ' + (currentCompanyName || '(none)'));
console.log('  Service ID: ' + currentServiceId);
```

---

### Plist Recreation

After discovering configuration and performing safety checks, `-upgrade` recreates both plists.

**Code Reference:** `/modules/agent-installer.js:2461-2482`

```javascript
// Recreate LaunchDaemon plist
process.stdout.write('Recreating LaunchDaemon...\n');
try {
    createLaunchDaemon(currentServiceName, currentCompanyName, installPath, currentServiceId);
    process.stdout.write('   ✓ LaunchDaemon created: /Library/LaunchDaemons/' + currentServiceId + '.plist\n');
} catch (e) {
    console.log('ERROR: Failed to create LaunchDaemon: ' + e.message);
    console.log('You may need to manually reinstall the agent.');
    process.exit(1);
}

// Recreate LaunchAgent plist
process.stdout.write('Recreating LaunchAgent...\n');
try {
    createLaunchAgent(currentServiceName, currentCompanyName, installPath, currentServiceId);
    process.stdout.write('   ✓ LaunchAgent created: /Library/LaunchAgents/' + currentServiceId + '-agent.plist\n');
} catch (e) {
    console.log('ERROR: Failed to create LaunchAgent: ' + e.message);
    console.log('LaunchDaemon should still work, but KVM functionality may be limited.');
    // Continue - LaunchAgent failure is not fatal
}
```

**createLaunchDaemon() Function:**

**Code Reference:** `/modules/agent-installer.js:833-850`

```javascript
function createLaunchDaemon(serviceName, companyName, installPath, serviceId) {
    var options = {
        name: serviceName,
        target: 'meshagent',
        servicePath: installPath + 'meshagent',
        startType: 'AUTO_START',
        installPath: installPath,
        parameters: ['--serviceId=' + serviceId],
        companyName: companyName
    };

    require('service-manager').manager.installService(options);
}
```

**createLaunchAgent() Function:**

**Code Reference:** `/modules/agent-installer.js:853-867`

```javascript
function createLaunchAgent(serviceName, companyName, installPath, serviceId) {
    require('service-manager').manager.installLaunchAgent({
        name: serviceName,
        companyName: companyName,
        servicePath: installPath + 'meshagent',
        startType: 'AUTO_START',
        sessionTypes: ['Aqua', 'LoginWindow'],
        parameters: ['-kvm1', '--serviceId=' + serviceId]
    });
}
```

**Result:** Both plists now have:
- Correct `--serviceId` parameter in ProgramArguments
- Correct Label (matches serviceId)
- Correct QueueDirectories path (`/var/run/{serviceId}`)

---

### Service Lookup Mechanisms

The `findInstallation()` function uses multiple strategies to locate the existing installation.

**Code Reference:** `/modules/agent-installer.js:280-383`

#### Strategy 1: Service Manager Lookup

If serviceId is known, query the service manager:

```javascript
if (serviceId) {
    try {
        var svc = require('service-manager').manager.getService(serviceId);
        var path = svc.appWorkingDirectory();

        if (path && require('fs').existsSync(path + 'meshagent')) {
            return { path: path, serviceId: serviceId };
        }
    } catch (e) {
        // Service not found - try other methods
    }
}
```

**How it works:**
- Queries launchd via service-manager module
- Gets installation path from plist WorkingDirectory
- Verifies binary exists at that path

---

#### Strategy 2: Self-Upgrade Detection

Check if we're running FROM an installed location:

```javascript
// Check if we're running from an installed location
var selfDir = process.execPath.substring(0, process.execPath.lastIndexOf('/') + 1);
var selfMshPath = selfDir + 'meshagent.msh';

if (require('fs').existsSync(selfMshPath)) {
    console.log('Detected self-upgrade scenario (found .msh alongside running binary)');
    return { path: selfDir, serviceId: null };
}
```

**How it works:**
- Gets directory of currently running binary
- Checks for `.msh` file in same directory
- If found, we're running from an installation

**Use case:** Server-initiated updates (binary runs from installation directory)

---

#### Strategy 3: Plist Scan

Scan `/Library/LaunchDaemons` for meshagent plists:

```javascript
var launchdDir = '/Library/LaunchDaemons/';
var files = require('fs').readdirSync(launchdDir);

files.forEach(function(file) {
    if (file.indexOf('meshagent') === 0 && file.endsWith('.plist')) {
        // Read plist
        var plistPath = launchdDir + file;
        var plistContent = require('fs').readFileSync(plistPath).toString();

        // Extract binary path from ProgramArguments
        // Extract WorkingDirectory
        // Verify binary exists
        // Return { path, serviceId }
    }
});
```

**How it works:**
- Lists all files in `/Library/LaunchDaemons/`
- Finds files starting with "meshagent" and ending with ".plist"
- Parses each plist to extract installation path
- Verifies binary exists

---

#### Strategy 4: Default Path Fallback

Check standard installation location:

```javascript
var defaultPath = '/usr/local/mesh_services/meshagent/';

if (require('fs').existsSync(defaultPath + 'meshagent')) {
    console.log('Found installation at default path: ' + defaultPath);
    return { path: defaultPath, serviceId: null };
}
```

**Use case:** Last resort for standard installations

---

### Orphaned Plist Cleanup

During upgrade, the system cleans up ALL plists pointing to the same binary.

**Why?** Handles service renames and prevents duplicates.

**Code Reference:** `/modules/agent-installer.js:387-465`

```javascript
function cleanupOrphanedPlists(installPath) {
    var cleaned = { daemons: [], agents: [] };

    // Clean LaunchDaemons
    var daemonDir = '/Library/LaunchDaemons/';
    var daemonFiles = require('fs').readdirSync(daemonDir);

    daemonFiles.forEach(function(file) {
        if (!file.endsWith('.plist')) return;

        var plistPath = daemonDir + file;
        var plistContent = require('fs').readFileSync(plistPath).toString();

        // Extract binary path from ProgramArguments
        var binaryPath = extractBinaryPath(plistContent);

        // Does it match our installation?
        if (binaryPath && binaryPath.indexOf(installPath + 'meshagent') >= 0) {
            // This plist points to our binary!

            // Extract serviceId from Label
            var serviceId = extractLabel(plistContent);

            // Unload service
            try {
                child_process.execSync('launchctl unload ' + plistPath + ' 2>/dev/null');
            } catch (e) {
                // May not be loaded
            }

            // Delete plist
            require('fs').unlinkSync(plistPath);

            cleaned.daemons.push(file);
            console.log('  Cleaned orphaned LaunchDaemon: ' + file);
        }
    });

    // Repeat for LaunchAgents
    var agentDir = '/Library/LaunchAgents/';
    var agentFiles = require('fs').readdirSync(agentDir);

    agentFiles.forEach(function(file) {
        // Same logic as LaunchDaemons
    });

    return cleaned;
}
```

**Example scenario:**

```
Before (service renamed from "meshagent" to "meshagent.tactical"):
/Library/LaunchDaemons/meshagent.plist                    ← OLD
/Library/LaunchDaemons/meshagent.tactical.plist           ← NEW

After cleanup:
/Library/LaunchDaemons/meshagent.tactical.plist           ← Only new one remains
```

---

### -upgrade Usage Examples

#### Example 1: Server-Initiated Update (Automatic)

**Scenario:** MeshCentral pushes agent update

```
1. MeshCentral sends AgentUpdate command
2. Agent downloads new binary
3. Agent replaces binary (old → .meshagent.backup.{timestamp})
4. C code calls: ./meshagent -upgrade
5. -upgrade runs automatically:
   - Discovers config from existing plist
   - Unloads services
   - Kills processes
   - Recreates plists with same config
   - Reloads services
6. Done - agent running with new binary
```

**User doesn't need to do anything!**

---

#### Example 2: Manual Upgrade Test

**Scenario:** Test upgrade process

```bash
# Run upgrade manually
sudo /opt/tacticalmesh/meshagent -upgrade

# Output:
# Verifying root privileges...
# Discovering configuration...
#   Found installation: /opt/tacticalmesh/
#   Service name: (default)
#   Company name: tacticalmesh
#   Service ID: meshagent.tacticalmesh
# Unloading services...
# Verifying services unloaded...
#   ✓ Services verified unloaded
# Verifying processes terminated...
#   ✓ Processes verified terminated
# Cleaning up orphaned plists...
# Recreating LaunchDaemon...
#   ✓ LaunchDaemon created
# Recreating LaunchAgent...
#   ✓ LaunchAgent created
# Reloading services...
#   ✓ Services loaded
# Upgrade complete!
```

---

#### Example 3: Service Rename

**Scenario:** Change serviceId from "meshagent" to "meshagent.production"

```bash
# Run upgrade with new config
sudo /usr/local/mesh_services/meshagent/meshagent -upgrade \
  --meshServiceName=production

# What happens:
# 1. Discovers old config (serviceId: meshagent)
# 2. Accepts new serviceName from command line
# 3. Calculates new serviceId: meshagent.production
# 4. Cleans up old plist (meshagent.plist)
# 5. Creates new plist (meshagent.production.plist)
# 6. Creates new socket dir (/var/run/meshagent.production/)
```

**Result:** Service renamed without reinstallation!

---

#### Example 4: Plist Repair

**Scenario:** Corrupted plist (missing --serviceId parameter)

```bash
# Check current plist
sudo plutil -p /Library/LaunchDaemons/meshagent.plist
# ProgramArguments: ["/opt/mesh/meshagent"]  ← Missing --serviceId!

# Run upgrade to repair
sudo /opt/mesh/meshagent -upgrade

# Check fixed plist
sudo plutil -p /Library/LaunchDaemons/meshagent.plist
# ProgramArguments: ["/opt/mesh/meshagent", "--serviceId=meshagent"]  ← Fixed!
```

---

## -install Function

The `-install` function performs a **standard installation** of MeshAgent.

**Requirements:**
- `.msh` configuration file must exist
- Root privileges required

**Code Reference:** `/modules/agent-installer.js:902-1162`

### Key Changes (macOS-Specific)

#### 1. serviceId Calculation

**Code Reference:** `/modules/agent-installer.js:1029-1066`

```javascript
// If serviceId was specified, extract it but keep it in parameters
if ((i = options.parameters.getParameterIndex('serviceId')) >= 0) {
    options.serviceId = options.parameters.getParameterValue(i);
    // Don't remove from parameters - agent needs it to write to .msh file
}
else if (process.platform == 'darwin') {
    // macOS only: Calculate serviceId from serviceName + companyName
    var calculatedServiceId;

    var sanitizedServiceName = sanitizeIdentifier(options.name);
    var sanitizedCompanyName = sanitizeIdentifier(options.companyName);

    if (sanitizedCompanyName) {
        if (sanitizedServiceName && sanitizedServiceName !== 'meshagent') {
            // Case 1: Both custom
            calculatedServiceId = 'meshagent.' + sanitizedServiceName + '.' + sanitizedCompanyName;
        } else {
            // Case 2: Company only
            calculatedServiceId = 'meshagent.' + sanitizedCompanyName;
        }
    } else if (sanitizedServiceName && sanitizedServiceName !== 'meshagent') {
        // Case 3: Service only
        calculatedServiceId = 'meshagent.' + sanitizedServiceName;
    } else {
        // Case 4: Default
        calculatedServiceId = 'meshagent';
    }

    // Always add to parameters (even if default 'meshagent')
    if (calculatedServiceId) {
        options.parameters.push('--serviceId=' + calculatedServiceId);
        options.serviceId = calculatedServiceId;
    }
}
```

**Result:** serviceId is calculated and added to options.parameters

---

#### 2. LaunchAgent Creation

**Code Reference:** `/modules/agent-installer.js:1098-1121`

```javascript
// macOS needs a LaunchAgent to help with some usages that need to run from within the user session
if (process.platform == 'darwin') {
    svc.load();

    process.stdout.write('   -> setting up launch agent...');

    require('service-manager').manager.installLaunchAgent({
        name: options.name,
        companyName: options.companyName,
        servicePath: svc.appLocation(),
        startType: 'AUTO_START',
        sessionTypes: ['Aqua', 'LoginWindow'],
        parameters: ['-kvm1', '--serviceId=' + (options.serviceId || serviceId)]
    });

    process.stdout.write('\r   -> setting up launch agent...OK.\n');
}
```

**What this does:**
- Creates LaunchAgent plist with `-kvm1` and `--serviceId` parameters
- Sets up QueueDirectories for on-demand activation
- Enables KVM functionality

---

### Usage Example

```bash
# Create .msh file first
sudo cat > /opt/tacticalmesh/meshagent.msh << 'EOF'
MeshName=Production Servers
MeshType=2
MeshID=<base64 mesh ID>
ServerID=<base64 server cert>
MeshServer=wss://mesh.example.com:443
MeshServiceName=
CompanyName=tacticalmesh
EOF

# Run install
sudo /opt/tacticalmesh/meshagent -install

# What happens:
# 1. Reads .msh file
# 2. Calculates serviceId: meshagent.tacticalmesh
# 3. Creates LaunchDaemon with --serviceId parameter
# 4. Creates LaunchAgent with --serviceId parameter
# 5. Creates /var/run/meshagent.tacticalmesh/ directory
# 6. Loads both services
```

---

## -fullinstall Function

The `-fullinstall` function performs a **complete installation** including configuration download from MeshCentral server.

**Requirements:**
- `--url` parameter (MeshCentral invite URL)
- Root privileges
- Network connectivity to MeshCentral server

**Code Reference:** `/modules/agent-installer.js:1633-1758`

### Key Changes (macOS-Specific)

#### 1. serviceId Calculation

**Code Reference:** `/modules/agent-installer.js:1652-1682`

```javascript
// Calculate serviceId early (needed for service existence check)
if (explicitServiceId) {
    serviceId = explicitServiceId;
} else if (process.platform == 'darwin') {
    // macOS composite naming
    var sanitizedServiceName = sanitizeIdentifier(serviceName);
    var sanitizedCompanyName = sanitizeIdentifier(companyName);

    if (sanitizedCompanyName) {
        if (sanitizedServiceName && sanitizedServiceName !== 'meshagent') {
            serviceId = 'meshagent.' + sanitizedServiceName + '.' + sanitizedCompanyName;
        } else {
            serviceId = 'meshagent.' + sanitizedCompanyName;
        }
    } else if (sanitizedServiceName && sanitizedServiceName !== 'meshagent') {
        serviceId = 'meshagent.' + sanitizedServiceName;
    } else {
        serviceId = 'meshagent';
    }
}
```

---

#### 2. Fallback Installation Discovery

**Code Reference:** `/modules/agent-installer.js:1710-1742`

```javascript
// Try to find ANY existing meshagent installation (handles service renames)
if (process.platform == 'darwin') {
    console.log('Searching for existing meshagent installation (any serviceId)...');

    // Try findInstallation without serviceName/companyName
    // This searches all LaunchDaemon plists
    loc = findInstallation(null, null, null);

    if (loc) {
        console.log('Found existing installation: ' + loc.path);
        console.log('  serviceId: ' + (loc.serviceId || 'unknown'));
        console.log('This installation will be replaced.');

        // Continue to serviceExists check to properly clean up old installation
    } else {
        console.log('No existing installation found.');
    }
}
```

**Why?** Handles service renames - finds installation even if serviceId changed.

---

### Usage Examples

#### Example 1: Standard Installation

```bash
sudo ./meshagent -fullinstall \
  --url="https://mesh.example.com/agent.ashx?id=xxxxx"

# Prompts:
# Installation path? [/usr/local/mesh_services/meshagent/]
# Service name? [meshagent]
# Company name? []

# Result: serviceId = "meshagent"
```

---

#### Example 2: Custom Installation

```bash
sudo ./meshagent -fullinstall \
  --url="https://mesh.example.com/agent.ashx?id=xxxxx" \
  --installPath=/opt/tacticalmesh/ \
  --companyName=tacticalmesh

# No prompts (all parameters provided)
# Result: serviceId = "meshagent.tacticalmesh"
```

---

#### Example 3: Full Customization

```bash
sudo ./meshagent -fullinstall \
  --url="https://mesh.example.com/agent.ashx?id=xxxxx" \
  --installPath=/opt/custom/ \
  --meshServiceName=production \
  --companyName=acme

# Result: serviceId = "meshagent.production.acme"
```

---

## -uninstall Function

The `-uninstall` function removes a MeshAgent installation.

**Code Reference:** `/modules/agent-installer.js:1402-1479`

### Key Changes (macOS-Specific)

#### 1. Composite serviceId Calculation

**Code Reference:** `/modules/agent-installer.js:1408-1426`

```javascript
// macOS composite serviceId
if (process.platform == 'darwin') {
    var sanitizedServiceName = sanitizeIdentifier(serviceName);
    var sanitizedCompanyName = sanitizeIdentifier(companyName);

    if (sanitizedCompanyName) {
        if (sanitizedServiceName && sanitizedServiceName !== 'meshagent') {
            serviceId = 'meshagent.' + sanitizedServiceName + '.' + sanitizedCompanyName;
        } else {
            serviceId = 'meshagent.' + sanitizedCompanyName;
        }
    } else if (sanitizedServiceName && sanitizedServiceName !== 'meshagent') {
        serviceId = 'meshagent.' + sanitizedServiceName;
    } else {
        serviceId = 'meshagent';
    }
}
```

---

#### 2. LaunchAgent Cleanup

**Code Reference:** `/modules/agent-installer.js:1461-1465`

```javascript
if (process.platform == 'darwin') {
    // macOS requires us to unload the service before removal
    svc.unload();
}
```

---

### Usage Examples

```bash
# Uninstall default service
sudo ./meshagent -uninstall

# Uninstall custom service
sudo ./meshagent -uninstall \
  --meshServiceName=production \
  --companyName=acme
```

---

## -fulluninstall Function

The `-fulluninstall` function performs **complete removal** with comprehensive cleanup.

**Code Reference:** `/modules/agent-installer.js:1512-1630`

### Key Changes (macOS-Specific)

#### 1. serviceId Calculation

**Code Reference:** `/modules/agent-installer.js:1531-1548`

Identical 4-case logic as other functions (see above).

---

#### 2. Comprehensive Cleanup

**Code Reference:** `/modules/agent-installer.js:1167-1194` (uninstallService3 function)

```javascript
function uninstallService3(loc) {
    // macOS comprehensive cleanup
    if (process.platform == 'darwin') {
        process.stdout.write('   -> Cleaning up all LaunchAgent/LaunchDaemon plists...');

        var cleaned = cleanupOrphanedPlists(loc);

        console.log('Cleaned ' + cleaned.daemons.length + ' LaunchDaemon(s)');
        console.log('Cleaned ' + cleaned.agents.length + ' LaunchAgent(s)');

        // Also check for LaunchAgent with -agent suffix
        try {
            var serviceName = extractServiceNameFromPath(loc);
            var launchagent = require('service-manager').manager.getLaunchAgent(serviceName + '-agent');
            launchagent.unload();
            console.log('Unloaded LaunchAgent: ' + serviceName + '-agent');
        } catch (e) {
            // May not exist
        }

        process.stdout.write('\r   -> Cleaning up all LaunchAgent/LaunchDaemon plists...OK.\n');
    }

    // Delete installation directory
    require('fs').rmSync(loc, { recursive: true, force: true });
}
```

---

### Usage Examples

```bash
# Full uninstall with cleanup
sudo ./meshagent -fulluninstall

# Custom service
sudo ./meshagent -fulluninstall \
  --meshServiceName=production \
  --companyName=acme
```

---

## Helper Functions

### createLaunchDaemon()

Creates LaunchDaemon plist with --serviceId parameter.

**Code Reference:** `/modules/agent-installer.js:833-850`

See [Plist Recreation](#plist-recreation) section above.

---

### createLaunchAgent()

Creates LaunchAgent plist with -kvm1 and --serviceId parameters.

**Code Reference:** `/modules/agent-installer.js:853-867`

See [Plist Recreation](#plist-recreation) section above.

---

### cleanupOrphanedPlists()

Removes all plists pointing to a specific binary path.

**Code Reference:** `/modules/agent-installer.js:387-465`

See [Orphaned Plist Cleanup](#orphaned-plist-cleanup) section above.

---

### verifyServiceUnloaded()

Checks if service is unloaded from launchd.

**Code Reference:** `/modules/agent-installer.js:654-703`

See [Safety Checks](#safety-checks) section above.

---

### verifyProcessesTerminated()

Checks if all processes are terminated.

**Code Reference:** `/modules/agent-installer.js:730-805`

See [Safety Checks](#safety-checks) section above.

---

### findInstallation()

Finds existing installation using multiple strategies.

**Code Reference:** `/modules/agent-installer.js:280-383`

See [Service Lookup Mechanisms](#service-lookup-mechanisms) section above.

---

### getServiceConfigFromPlist()

Extracts configuration from plist ProgramArguments.

**Code Reference:** `/modules/agent-installer.js:1887-1947`

Parses LaunchDaemon plist to extract:
- serviceId (from --serviceId parameter)
- serviceName (from --meshServiceName parameter)
- companyName (from --companyName parameter)

**Returns authoritative configuration** (what's actually running).

---

### parseMshFile()

Parses .msh configuration file.

**Code Reference:** `/modules/agent-installer.js:201-218`

See [naming-and-configuration.md](./naming-and-configuration.md#msh-file-format) for details.

---

### sanitizeIdentifier()

Sanitizes serviceName and companyName.

**Code Reference:** `/modules/agent-installer.js:112-116`

See [naming-and-configuration.md](./naming-and-configuration.md#input-sanitization) for details.

---

## Troubleshooting

### Problem: -upgrade Fails "Service still loaded"

**Symptom:**
```
ERROR: Cannot unload service from launchd
This is dangerous - aborting upgrade
```

**Cause:** Service won't unload from launchd

**Debug:**
```bash
# Check service status
sudo launchctl print system/meshagent

# Try manual unload
sudo launchctl unload /Library/LaunchDaemons/meshagent.plist

# Force bootout
sudo launchctl bootout system/meshagent

# Check again
sudo launchctl print system/meshagent
```

---

### Problem: -upgrade Fails "Cannot terminate processes"

**Symptom:**
```
ERROR: Cannot terminate processes
PIDs: 1234, 5678
```

**Cause:** Processes won't die

**Debug:**
```bash
# Check what's running
ps auxww | grep meshagent

# Try manual kill
sudo kill -9 1234 5678

# Check if they're really gone
ps auxww | grep meshagent
```

**Solution:** Reboot if processes are unkillable

---

### Problem: -upgrade Can't Find Installation

**Symptom:**
```
ERROR: Could not find existing meshagent installation
```

**Debug:**
```bash
# Check for LaunchDaemon plists
ls -l /Library/LaunchDaemons/meshagent*.plist

# Check default path
ls -l /usr/local/mesh_services/meshagent/

# Check running processes
ps aux | grep meshagent

# Use lsof to find binary location
sudo lsof -p $(pgrep meshagent) | grep meshagent
```

**Solution:** Specify installation path explicitly:
```bash
sudo ./meshagent -upgrade --installPath=/path/to/installation/
```

---

### Problem: Orphaned Plists After Rename

**Symptom:** Multiple plists for same installation

**Debug:**
```bash
# List all meshagent plists
ls -1 /Library/LaunchDaemons/meshagent*.plist
ls -1 /Library/LaunchAgents/meshagent*.plist

# Check which are loaded
sudo launchctl print system | grep meshagent
```

**Solution:** -upgrade automatically cleans these up
```bash
sudo /path/to/meshagent -upgrade
```

---

### Problem: Configuration Mismatch

**Symptom:** .msh file shows different config than plist

**Debug:**
```bash
# Check plist
sudo plutil -p /Library/LaunchDaemons/meshagent.plist | grep serviceId

# Check .msh
grep -E "MeshServiceName|CompanyName" /opt/mesh/meshagent.msh

# Check database
/opt/mesh/meshagent -exec "var db=require('SimpleDataStore').Create('./meshagent.db'); console.log('ServiceName:', db.Get('meshServiceName')); console.log('Company:', db.Get('companyName')); process.exit(0);"
```

**Solution:** -upgrade will auto-sync (plist wins as authoritative source)

---

## Quick Command Reference

### Installation

```bash
# Full install (downloads config from server)
sudo ./meshagent -fullinstall --url="https://mesh.example.com/agent.ashx?id=xxxxx"

# Standard install (requires .msh file)
sudo ./meshagent -install

# Custom serviceId
sudo ./meshagent -fullinstall \
  --url="..." \
  --meshServiceName=production \
  --companyName=acme
```

### Upgrade

```bash
# Upgrade (recreate plists)
sudo /opt/mesh/meshagent -upgrade

# Upgrade with new config
sudo /opt/mesh/meshagent -upgrade \
  --meshServiceName=production \
  --companyName=acme
```

### Uninstall

```bash
# Standard uninstall
sudo ./meshagent -uninstall

# Full uninstall (with cleanup)
sudo ./meshagent -fulluninstall

# Custom service
sudo ./meshagent -fulluninstall \
  --meshServiceName=production \
  --companyName=acme
```

---

## Related Documentation

- **[architecture.md](./architecture.md)** - LaunchDaemon/LaunchAgent architecture, QueueDirectories
- **[naming-and-configuration.md](./naming-and-configuration.md)** - serviceId calculation, configuration priority
- **[TLDReadMe.md](./TLDReadMe.md)** - Quick reference cheat sheet

---

## Code References

### Main Implementation

**Agent Installer:**
- `/modules/agent-installer.js:1949-2527` - upgradeAgent function
- `/modules/agent-installer.js:902-1162` - install function
- `/modules/agent-installer.js:1633-1758` - fullInstall function
- `/modules/agent-installer.js:1402-1479` - uninstall function
- `/modules/agent-installer.js:1512-1630` - fullUninstall function

**Helper Functions:**
- `/modules/agent-installer.js:833-867` - createLaunchDaemon/createLaunchAgent
- `/modules/agent-installer.js:387-465` - cleanupOrphanedPlists
- `/modules/agent-installer.js:654-703` - verifyServiceUnloaded
- `/modules/agent-installer.js:730-805` - verifyProcessesTerminated
- `/modules/agent-installer.js:280-383` - findInstallation
- `/modules/agent-installer.js:1887-1947` - getServiceConfigFromPlist

**Agent Core:**
- `/meshcore/agentcore.c:6449-6453` - Automatic -upgrade invocation during server update

---

*Last Updated: 2025-11-10*
*Documentation Version: 1.0*
