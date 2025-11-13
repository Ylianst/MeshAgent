# macOS MeshAgent Naming and Configuration

## Overview

The macOS MeshAgent uses a **dynamic naming system** that allows multiple independent installations on the same system. The core of this system is the **serviceId**, calculated from two configurable values:

- **meshServiceName** (or serviceName) - Service identifier
- **companyName** - Organization identifier

These values are sanitized, combined, and used to generate unique service identifiers, file paths, and socket directories.

---

## Table of Contents

- [The serviceId Concept](#the-serviceid-concept)
- [serviceId Calculation: The 4 Cases](#serviceid-calculation-the-4-cases)
- [Input Sanitization](#input-sanitization)
- [Real-World Examples](#real-world-examples)
- [The --serviceId Parameter](#the---serviceid-parameter)
- [Configuration Sources and Priority](#configuration-sources-and-priority)
- [.msh File Format](#msh-file-format)
- [Configuration Migration and Sync](#configuration-migration-and-sync)
- [Database Storage](#database-storage)
- [Multi-Instance Support](#multi-instance-support)
- [Configuration Discovery](#configuration-discovery)
- [Troubleshooting](#troubleshooting)

---

## The serviceId Concept

### What is a serviceId?

The **serviceId** is a unique identifier for a MeshAgent installation. It's used for:

1. **LaunchDaemon Label** - `/Library/LaunchDaemons/{serviceId}.plist`
2. **LaunchAgent Label** - `/Library/LaunchAgents/{serviceId}-agent.plist`
3. **Socket directory** - `/var/run/{serviceId}/`
4. **Service identification** - Process and service management
5. **Multi-instance support** - Multiple installations without conflicts

### Format

```
serviceId ::= "meshagent" [ "." serviceName ] [ "." companyName ]
```

The serviceId always starts with `meshagent` and may include additional components based on configuration.

### Why serviceId?

**Problem:** Traditional single-service model
- Only one MeshAgent installation possible
- Service rename requires full reinstall
- No isolation between environments (prod/dev/test)

**Solution:** Dynamic serviceId
- Multiple installations coexist
- Service identity persists through updates
- Clean separation between instances

---

## serviceId Calculation: The 4 Cases

### Calculation Logic

**Code Reference:** `/modules/agent-installer.js:280-296`, `1660-1678`, `2160-2184`

```javascript
function calculateServiceId(serviceName, companyName) {
    // Sanitize inputs (removes spaces, special chars, lowercase)
    var sanitizedServiceName = sanitizeIdentifier(serviceName);
    var sanitizedCompanyName = sanitizeIdentifier(companyName);

    var serviceId;

    if (sanitizedCompanyName) {
        // Company name is present
        if (sanitizedServiceName && sanitizedServiceName !== 'meshagent') {
            // CASE 1: Both custom service name AND company name
            serviceId = 'meshagent.' + sanitizedServiceName + '.' + sanitizedCompanyName;
        } else {
            // CASE 2: Only company name (default service name)
            serviceId = 'meshagent.' + sanitizedCompanyName;
        }
    } else if (sanitizedServiceName && sanitizedServiceName !== 'meshagent') {
        // CASE 3: Only custom service name (no company)
        serviceId = 'meshagent.' + sanitizedServiceName;
    } else {
        // CASE 4: Neither provided (all defaults)
        serviceId = 'meshagent';
    }

    return serviceId;
}
```

### The 4 Cases Explained

#### Case 1: Custom Service + Company

**Input:**
- `meshServiceName` = "Tactical"
- `companyName` = "ACME Corp"

**Calculation:**
```
sanitizedServiceName = "tactical"     (sanitized)
sanitizedCompanyName = "acme-corp"    (sanitized)

serviceId = "meshagent.tactical.acme-corp"
```

**Resulting Files:**
```
/Library/LaunchDaemons/meshagent.tactical.acme-corp.plist
/Library/LaunchAgents/meshagent.tactical.acme-corp-agent.plist
/var/run/meshagent.tactical.acme-corp/
```

**Use Case:** Multiple services for the same company

---

#### Case 2: Default Service + Company

**Input:**
- `meshServiceName` = "meshagent" (or not provided)
- `companyName` = "ACME Corp"

**Calculation:**
```
sanitizedServiceName = "meshagent"    (default)
sanitizedCompanyName = "acme-corp"    (sanitized)

serviceId = "meshagent.acme-corp"
```

**Resulting Files:**
```
/Library/LaunchDaemons/meshagent.acme-corp.plist
/Library/LaunchAgents/meshagent.acme-corp-agent.plist
/var/run/meshagent.acme-corp/
```

**Use Case:** Single company deployment, company branding

---

#### Case 3: Custom Service Only

**Input:**
- `meshServiceName` = "Tactical"
- `companyName` = (not provided)

**Calculation:**
```
sanitizedServiceName = "tactical"     (sanitized)
sanitizedCompanyName = null

serviceId = "meshagent.tactical"
```

**Resulting Files:**
```
/Library/LaunchDaemons/meshagent.tactical.plist
/Library/LaunchAgents/meshagent.tactical-agent.plist
/var/run/meshagent.tactical/
```

**Use Case:** Custom branding without company identifier

---

#### Case 4: All Defaults

**Input:**
- `meshServiceName` = "meshagent" (or not provided)
- `companyName` = (not provided)

**Calculation:**
```
sanitizedServiceName = "meshagent"    (default)
sanitizedCompanyName = null

serviceId = "meshagent"
```

**Resulting Files:**
```
/Library/LaunchDaemons/meshagent.plist
/Library/LaunchAgents/meshagent-agent.plist
/var/run/meshagent/
```

**Use Case:** Standard MeshCentral deployment, no customization

---

## Input Sanitization

### sanitizeIdentifier Function

**Code Reference:** `/modules/agent-installer.js:112-116`

```javascript
function sanitizeIdentifier(str) {
    if (!str) return null;

    // 1. Replace spaces with hyphens
    // 2. Remove all non-alphanumeric except hyphens and underscores
    // 3. Convert to lowercase
    return str.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase();
}
```

### Sanitization Rules

| Input | Output | Notes |
|-------|--------|-------|
| `"ACME Corp"` | `"acme-corp"` | Spaces → hyphens, lowercase |
| `"Tactical_RMM"` | `"tactical_rmm"` | Underscores preserved, lowercase |
| `"My-Service-123"` | `"my-service-123"` | Hyphens preserved, lowercase |
| `"Test@Service!"` | `"testservice"` | Special chars removed |
| `""` (empty) | `null` | Empty treated as not provided |
| `null` | `null` | Null preserved |
| `"meshagent"` | `"meshagent"` | Already clean |

### Why Sanitize?

**Safety:**
- Prevents shell injection via service names
- Ensures valid plist filenames
- Safe for use in file paths

**Consistency:**
- Predictable serviceId format
- Case-insensitive matching
- Standard identifier format

**Compatibility:**
- Works with launchd requirements
- Valid in URLs and file systems
- No escaping needed

### Examples

```bash
# Input variations all produce the same serviceId
--companyName="ACME Corp"
--companyName="acme corp"
--companyName="Acme_Corp"
--companyName="acme-corp"

# All result in: meshagent.acme-corp
```

---

## Real-World Examples

### Example 1: TacticalRMM Deployment

**Configuration:**
```bash
--meshServiceName="meshagent"
--companyName="tacticalmesh"
```

**Result:**
```
serviceId: meshagent.tacticalmesh

Files:
/Library/LaunchDaemons/meshagent.tacticalmesh.plist
/Library/LaunchAgents/meshagent.tacticalmesh-agent.plist
/var/run/meshagent.tacticalmesh/

Installation path:
/opt/tacticalmesh/
```

---

### Example 2: Multi-Environment Setup

**Production:**
```bash
--meshServiceName="production"
--companyName="acme"
```
Result: `meshagent.production.acme`

**Staging:**
```bash
--meshServiceName="staging"
--companyName="acme"
```
Result: `meshagent.staging.acme`

**Development:**
```bash
--meshServiceName="development"
--companyName="acme"
```
Result: `meshagent.development.acme`

All three can run simultaneously without conflict!

---

### Example 3: MSP with Multiple Clients

**Client 1 (ABC Corp):**
```bash
--companyName="abc-corp"
```
Result: `meshagent.abc-corp`

**Client 2 (XYZ Inc):**
```bash
--companyName="xyz-inc"
```
Result: `meshagent.xyz-inc`

Each client's installation is isolated.

---

### Example 4: Complex Organization

**Organization:** "My Company LLC"
**Service:** "Remote Management Service"

**Input:**
```bash
--meshServiceName="Remote Management Service"
--companyName="My Company LLC"
```

**Sanitization:**
```
serviceName: "remote-management-service"
companyName: "my-company-llc"
```

**Result:**
```
serviceId: meshagent.remote-management-service.my-company-llc
```

---

## The --serviceId Parameter

### Purpose

The `--serviceId` parameter is passed to the meshagent binary to tell it **which service identity it's running as**.

### How It's Used

**In LaunchDaemon plist:**

**Code Reference:** `/modules/agent-installer.js:833-850`

```xml
<key>ProgramArguments</key>
<array>
    <string>/usr/local/mesh_services/meshagent/meshagent</string>
    <string>--serviceId=meshagent.tacticalmesh</string>
</array>
```

**In LaunchAgent plist:**

**Code Reference:** `/modules/agent-installer.js:853-867`

```xml
<key>ProgramArguments</key>
<array>
    <string>/usr/local/mesh_services/meshagent/meshagent</string>
    <string>-kvm1</string>
    <string>--serviceId=meshagent.tacticalmesh</string>
</array>
```

### What meshagent Does with --serviceId

1. **Stores in configuration** - Written to .msh file
2. **Uses for socket path** - `/var/run/{serviceId}/`
3. **Service identification** - Knows which service it is
4. **Configuration lookup** - Finds correct .db and .msh files

### Explicit --serviceId Override

You can explicitly set serviceId to bypass calculation:

```bash
sudo ./meshagent -fullinstall \
  --url=https://mesh.example.com \
  --installPath=/opt/custom/ \
  --serviceId=my.custom.id
```

**Result:** serviceId will be exactly `my.custom.id` regardless of serviceName/companyName

**Use Case:** Legacy compatibility or very specific naming requirements

---

## Configuration Sources and Priority

### The Configuration Priority Chain

When `-upgrade` runs, it discovers configuration from multiple sources in **priority order**:

**Code Reference:** `/modules/agent-installer.js:2004-2104`

```
1. Command-line flags         (HIGHEST PRIORITY)
   ↓
2. Plist ProgramArguments     (AUTHORITATIVE SOURCE)
   ↓
3. .msh file                  (Configuration file)
   ↓
4. .db database               (Read-only via SimpleDataStore)
   ↓
5. Installation path          (LOWEST PRIORITY)
```

### 1. Command-Line Flags (Highest Priority)

**Example:**
```bash
sudo ./meshagent -upgrade --meshServiceName=tactical --companyName=acme
```

**Code Reference:** `/modules/agent-installer.js:118-177` (checkParameters function)

**Supported flags:**
- `--meshServiceName=value` or `--serviceName=value`
- `--companyName=value`
- `--serviceId=value` (explicit override)

**When used:** Manual upgrades, testing, override scenarios

---

### 2. Plist ProgramArguments (Authoritative Source)

**THIS IS THE AUTHORITATIVE SOURCE** - represents what's actually running.

**Code Reference:** `/modules/agent-installer.js:1887-1947` (getServiceConfigFromPlist)

The upgrade function reads the **currently loaded plist** to discover configuration:

```javascript
function getServiceConfigFromPlist(serviceId) {
    try {
        var plistPath = '/Library/LaunchDaemons/' + serviceId + '.plist';
        var plistContent = fs.readFileSync(plistPath).toString();

        // Parse ProgramArguments array
        // Extract --serviceId=value
        // Extract --meshServiceName=value
        // Extract --companyName=value

        return {
            serviceId: extractedServiceId,
            serviceName: extractedServiceName,
            companyName: extractedCompanyName
        };
    } catch (e) {
        return null;
    }
}
```

**Why authoritative?**
- Reflects actual running configuration
- Can't be out of sync (it IS the config)
- Survives .msh file deletion

**Plist example:**
```xml
<key>ProgramArguments</key>
<array>
    <string>/opt/tacticalmesh/meshagent</string>
    <string>--serviceId=meshagent.tacticalmesh</string>
</array>
```

From this, we extract: `serviceId = "meshagent.tacticalmesh"`

---

### 3. .msh File (Configuration File)

**Location:** `{installPath}/meshagent.msh`

**Code Reference:** `/modules/agent-installer.js:201-218` (parseMshFile)

```javascript
function parseMshFile(mshPath) {
    if (!fs.existsSync(mshPath)) return null;

    var content = fs.readFileSync(mshPath).toString();
    var lines = content.split('\n');
    var config = {};

    lines.forEach(function(line) {
        if (line.indexOf('=') > 0) {
            var parts = line.split('=');
            var key = parts[0].trim();
            var value = parts[1] ? parts[1].trim() : '';
            config[key] = value;
        }
    });

    return {
        meshServiceName: config['MeshServiceName'] || null,
        companyName: config['CompanyName'] || null,
        meshServer: config['MeshServer'] || null,
        // ... other fields
    };
}
```

**Format:** See [.msh File Format](#msh-file-format) section below

**When used:** First install, configuration reference

---

### 4. .db Database (Read-Only)

**Location:** `{installPath}/meshagent.db`

**Format:** SimpleDataStore (custom binary format)

**Relevant keys:**
- `meshServiceName` - Service name
- `companyName` - Company name
- `ServiceID` - Explicit serviceId (if stored)

**Read-only access:**
```javascript
var db = require('SimpleDataStore').Create(dbPath, { readOnly: true });
var meshServiceName = db.Get('meshServiceName');
var companyName = db.Get('companyName');
```

**Note:** Database is opened read-only during upgrade to avoid locking issues.

---

### 5. Installation Path (Lowest Priority)

If all else fails, try to infer from installation path:

```javascript
// Example: /opt/tacticalmesh/
// Might infer: companyName = "tacticalmesh"
```

**This is a last resort and may not be reliable.**

---

### Priority Example

Scenario: What configuration is used?

**Plist says:**
```xml
<string>--serviceId=meshagent.production.acme</string>
```

**.msh says:**
```
MeshServiceName=staging
CompanyName=acme
```

**Command line:**
```bash
sudo ./meshagent -upgrade --meshServiceName=development
```

**Result:**
```
Used configuration:
  serviceName: development      (from command line - highest priority)
  companyName: acme            (from plist - no command line override)

  Final serviceId: meshagent.development.acme
```

**Priority applied:**
1. `serviceName` from command line (highest)
2. `companyName` from plist (no command line override)
3. .msh values ignored (lower priority)

---

## .msh File Format

### File Structure

The `.msh` file is a simple key=value configuration file.

**Location:** `{installPath}/meshagent.msh`

**Format:**
```
MeshName=Production Servers
MeshType=2
MeshID=<base64 encoded mesh ID>
ServerID=<base64 encoded server cert hash>
MeshServer=wss://mesh.example.com:443
MeshServiceName=production
CompanyName=acme-corp
```

### Key Fields

| Key | Description | Example |
|-----|-------------|---------|
| `MeshName` | Mesh group name | `Production Servers` |
| `MeshType` | Mesh type code | `2` |
| `MeshID` | Unique mesh identifier | `<48-byte base64>` |
| `ServerID` | Server certificate hash | `<48-byte base64>` |
| `MeshServer` | WebSocket URL | `wss://mesh.example.com:443` |
| `MeshServiceName` | Service name for serviceId | `production` |
| `CompanyName` | Company name for serviceId | `acme-corp` |

### serviceId-Relevant Fields

Only these affect serviceId calculation:
- `MeshServiceName`
- `CompanyName`

### Creating .msh File

**During installation:**

**Code Reference:** `/modules/agent-installer.js:1029-1066`

```javascript
// serviceId is calculated
var serviceId = calculateServiceId(serviceName, companyName);

// Added to parameters array
options.parameters.push('--serviceId=' + serviceId);

// Written to .msh during agent startup
// Agent imports .msh into .db on first run
```

**Manual creation:**
```bash
cat > /opt/tacticalmesh/meshagent.msh << 'EOF'
MeshName=
MeshType=
MeshID=
ServerID=
MeshServer=
MeshServiceName=tactical
CompanyName=acme
EOF
```

---

## Configuration Migration and Sync

### Auto-Migration

If `.msh` doesn't exist but configuration was discovered from other sources:

**Code Reference:** `/modules/agent-installer.js:2110-2132`

```javascript
if (!fs.existsSync(mshPath)) {
    console.log('Auto-migrating configuration to .msh file...');

    var mshData = 'MeshName=\n';
    mshData += 'MeshType=\n';
    mshData += 'MeshID=\n';
    mshData += 'ServerID=\n';
    mshData += 'MeshServer=\n';

    if (currentServiceName && currentServiceName !== 'meshagent') {
        mshData += 'MeshServiceName=' + currentServiceName + '\n';
    }

    if (currentCompanyName) {
        mshData += 'CompanyName=' + currentCompanyName + '\n';
    }

    fs.writeFileSync(mshPath, mshData);
    console.log('✓ Configuration migrated to .msh');
}
```

**Use case:** Legacy installations without .msh, plist-only configs

---

### Auto-Sync

If `.msh` exists but differs from plist (the authoritative source):

**Code Reference:** `/modules/agent-installer.js:2133-2158`

```javascript
var existingConfig = parseMshFile(mshPath);
var plistConfig = getServiceConfigFromPlist(currentServiceId);

var needsSync = false;
var syncUpdates = {};

if (existingConfig.meshServiceName !== plistConfig.serviceName) {
    needsSync = true;
    syncUpdates.meshServiceName = plistConfig.serviceName;
}

if (existingConfig.companyName !== plistConfig.companyName) {
    needsSync = true;
    syncUpdates.companyName = plistConfig.companyName;
}

if (needsSync) {
    console.log('Auto-syncing .msh file with plist configuration...');
    updateMshFile(mshPath, syncUpdates);
    console.log('✓ Configuration synced');
}
```

**Use case:** .msh file was manually edited but plist is authoritative

**Result:** Plist configuration overwrites .msh to ensure consistency

---

## Database Storage

### SimpleDataStore Format

The `meshagent.db` file uses a custom binary format (SimpleDataStore).

**Access:**
```javascript
var db = require('SimpleDataStore').Create('/path/to/meshagent.db');

// Write
db.Put('meshServiceName', 'production');
db.Put('companyName', 'acme');

// Read
var serviceName = db.Get('meshServiceName');
var companyName = db.Get('companyName');
```

### Relevant Keys

| Key | Type | Description |
|-----|------|-------------|
| `meshServiceName` | String | Service name |
| `companyName` | String | Company name |
| `ServiceID` | String | Explicit serviceId (if set) |
| `MeshServer` | String | Server URL |
| `MeshID` | Buffer | Mesh identifier (binary) |
| `ServerID` | Buffer | Server cert hash (binary) |

### Database in -upgrade

**Read-only access during upgrade:**

**Code Reference:** `/modules/agent-installer.js:2079-2104`

```javascript
try {
    var db = require('SimpleDataStore').Create(dbPath, { readOnly: true });

    if (!currentServiceName) {
        var dbServiceName = db.Get('meshServiceName');
        if (dbServiceName) {
            console.log('  Found meshServiceName in .db: ' + dbServiceName);
            currentServiceName = dbServiceName;
        }
    }

    if (!currentCompanyName) {
        var dbCompanyName = db.Get('companyName');
        if (dbCompanyName) {
            console.log('  Found companyName in .db: ' + dbCompanyName);
            currentCompanyName = dbCompanyName;
        }
    }
} catch (e) {
    console.log('  Could not read .db file (may be locked): ' + e.message);
    // Continue - not critical
}
```

**Why read-only?**
- Avoid database locks (main service may be using it)
- Safe access during upgrade process
- Database is informational only during upgrade

---

## Multi-Instance Support

### Running Multiple Installations

The serviceId system enables multiple MeshAgent installations on the same machine.

**Example Setup:**

```bash
# Installation 1: Production
sudo ./meshagent -fullinstall \
  --url=https://mesh.example.com \
  --meshServiceName=production \
  --companyName=acme \
  --installPath=/opt/mesh_production/

# Result: meshagent.production.acme

# Installation 2: Staging
sudo ./meshagent -fullinstall \
  --url=https://mesh-staging.example.com \
  --meshServiceName=staging \
  --companyName=acme \
  --installPath=/opt/mesh_staging/

# Result: meshagent.staging.acme

# Installation 3: Development
sudo ./meshagent -fullinstall \
  --url=https://mesh-dev.example.com \
  --meshServiceName=development \
  --companyName=acme \
  --installPath=/opt/mesh_development/

# Result: meshagent.development.acme
```

### Isolation Guarantees

Each installation has:

**Unique serviceId:**
- `meshagent.production.acme`
- `meshagent.staging.acme`
- `meshagent.development.acme`

**Separate plists:**
```
/Library/LaunchDaemons/meshagent.production.acme.plist
/Library/LaunchDaemons/meshagent.staging.acme.plist
/Library/LaunchDaemons/meshagent.development.acme.plist

/Library/LaunchAgents/meshagent.production.acme-agent.plist
/Library/LaunchAgents/meshagent.staging.acme-agent.plist
/Library/LaunchAgents/meshagent.development.acme-agent.plist
```

**Separate socket paths:**
```
/var/run/meshagent.production.acme/
/var/run/meshagent.staging.acme/
/var/run/meshagent.development.acme/
```

**Separate installation directories:**
```
/opt/mesh_production/
/opt/mesh_staging/
/opt/mesh_development/
```

### Managing Multiple Instances

**List all services:**
```bash
sudo launchctl print system | grep meshagent
```

**Control specific instance:**
```bash
# Unload production
sudo launchctl unload /Library/LaunchDaemons/meshagent.production.acme.plist

# Load staging
sudo launchctl load /Library/LaunchDaemons/meshagent.staging.acme.plist

# Check development status
sudo launchctl print system/meshagent.development.acme
```

---

## Configuration Discovery

### How -upgrade Discovers Configuration

The `-upgrade` function must discover the current configuration to recreate plists correctly.

**Discovery Process:**

**Code Reference:** `/modules/agent-installer.js:1961-2109`

```
1. Parse command-line flags
   └─> Extract --meshServiceName, --companyName, --serviceId
       └─> Store as explicit overrides

2. Try to find existing installation
   └─> findInstallation(serviceName, companyName, installPath)
       └─> Returns: { path, serviceId }

3. If found, read plist (AUTHORITATIVE)
   └─> getServiceConfigFromPlist(serviceId)
       └─> Extract serviceName and companyName from ProgramArguments
           └─> This is the TRUTH (what's actually running)

4. Fall back to .msh file
   └─> parseMshFile(installPath + 'meshagent.msh')
       └─> Read MeshServiceName and CompanyName

5. Fall back to .db database
   └─> db.Get('meshServiceName'), db.Get('companyName')
       └─> Read-only access

6. Calculate final serviceId
   └─> calculateServiceId(finalServiceName, finalCompanyName)
```

### findInstallation Function

**Code Reference:** `/modules/agent-installer.js:280-383`

This function searches for existing installations:

**Search strategies:**

1. **Service Manager Lookup** (if serviceId known)
   ```javascript
   var svc = require('service-manager').manager.getService(serviceId);
   var path = svc.appWorkingDirectory();
   ```

2. **Self-Upgrade Detection** (running from installed location)
   ```javascript
   var selfDir = process.execPath.substring(0, process.execPath.lastIndexOf('/') + 1);
   if (fs.existsSync(selfDir + 'meshagent.msh')) {
       return selfDir;  // Found it!
   }
   ```

3. **Default Path Fallback**
   ```javascript
   var defaultPath = '/usr/local/mesh_services/meshagent/';
   if (fs.existsSync(defaultPath + 'meshagent')) {
       return defaultPath;
   }
   ```

**Return value:**
```javascript
{
    path: "/opt/tacticalmesh/",
    serviceId: "meshagent.tacticalmesh"
}
```

---

## Troubleshooting

### Problem: Wrong serviceId Calculated

**Symptom:** Unexpected serviceId result

**Debug:**
```bash
# Check what inputs are being used
sudo ./meshagent -upgrade --meshServiceName=test --companyName=demo

# Should output discovery process:
# "Found serviceName: test"
# "Found companyName: demo"
# "Calculated serviceId: meshagent.test.demo"
```

**Common causes:**
- Input has special characters (gets sanitized)
- serviceName is "meshagent" (treated as default, not used)
- Empty/null values (treated as not provided)

---

### Problem: Configuration Mismatch

**Symptom:** .msh file differs from plist

**Solution:** -upgrade will auto-sync (plist wins)

**Manual check:**
```bash
# Check plist
sudo plutil -p /Library/LaunchDaemons/meshagent.plist | grep serviceId

# Check .msh
grep -E "MeshServiceName|CompanyName" /opt/tacticalmesh/meshagent.msh

# Check database
/opt/tacticalmesh/meshagent -exec "var db=require('SimpleDataStore').Create('./meshagent.db'); console.log('ServiceName:', db.Get('meshServiceName')); console.log('Company:', db.Get('companyName')); process.exit(0);"
```

---

### Problem: Can't Find Installation

**Symptom:** -upgrade says "Could not find installation"

**Debug:**
```bash
# Check service manager
sudo launchctl print system | grep meshagent

# Check default path
ls -la /usr/local/mesh_services/meshagent/

# Check running processes
ps aux | grep meshagent

# Use lsof to find binary path
sudo lsof -p $(pgrep meshagent) | grep meshagent
```

**Manual override:**
```bash
# Specify installation path explicitly
sudo ./meshagent -upgrade --installPath=/opt/custom/path/
```

---

### Problem: Multiple Installations Conflict

**Symptom:** Services interfere with each other

**Check:**
```bash
# List all meshagent plists
ls -1 /Library/LaunchDaemons/meshagent*.plist
ls -1 /Library/LaunchAgents/meshagent*.plist

# Check which are loaded
sudo launchctl print system | grep meshagent

# Check for duplicate serviceIds
sudo launchctl print system | grep meshagent | awk '{print $NF}'
```

**Fix:**
```bash
# Unload duplicates
sudo launchctl unload /Library/LaunchDaemons/meshagent.OLD.plist

# Remove orphaned plists
sudo rm /Library/LaunchDaemons/meshagent.OLD.plist
sudo rm /Library/LaunchAgents/meshagent.OLD-agent.plist
```

---

### Problem: Sanitization Changed My Name

**Symptom:** serviceId doesn't match expected input

**Examples:**
```bash
# Input: "ACME Corp!"
# Output: "acme-corp"  (special chars removed, lowercase, spaces→hyphens)

# Input: "Tactical_RMM"
# Output: "tactical_rmm"  (lowercase only)

# Input: "My Service 123"
# Output: "my-service-123"  (spaces→hyphens, lowercase)
```

**Solution:** Use only alphanumeric, hyphens, underscores
```bash
# Good inputs
--companyName="acme-corp"
--meshServiceName="tactical_rmm"

# Will be sanitized
--companyName="ACME Corp!!!"  # becomes: acme-corp
```

---

## Quick Reference

### serviceId Calculation Cheat Sheet

```
Inputs              →  serviceId Result
=====================================
service  company
--------  ---------    ---------------
(none)    (none)    →  meshagent
(none)    acme      →  meshagent.acme
tactical  (none)    →  meshagent.tactical
tactical  acme      →  meshagent.tactical.acme
```

### Command-Line Examples

```bash
# Case 1: Both custom
sudo ./meshagent -fullinstall \
  --meshServiceName=tactical \
  --companyName=acme \
  --url=https://mesh.example.com

# Case 2: Company only
sudo ./meshagent -fullinstall \
  --companyName=acme \
  --url=https://mesh.example.com

# Case 3: Service only
sudo ./meshagent -fullinstall \
  --meshServiceName=tactical \
  --url=https://mesh.example.com

# Case 4: Defaults
sudo ./meshagent -fullinstall \
  --url=https://mesh.example.com

# Explicit override
sudo ./meshagent -fullinstall \
  --serviceId=custom.service.id \
  --url=https://mesh.example.com
```

---

## Related Documentation

- **[architecture.md](./architecture.md)** - LaunchDaemon/LaunchAgent architecture, QueueDirectories, socket communication
- **[installation-functions.md](./installation-functions.md)** - How -install, -upgrade, -uninstall use serviceId
- **[TLDReadMe.md](./TLDReadMe.md)** - Quick reference cheat sheet

---

## Code References

### Key Functions

**serviceId Calculation:**
- `/modules/agent-installer.js:280-296` - findInstallation (includes calculation)
- `/modules/agent-installer.js:1660-1678` - fullInstall calculation
- `/modules/agent-installer.js:2160-2184` - upgrade calculation

**Sanitization:**
- `/modules/agent-installer.js:112-116` - sanitizeIdentifier function

**Configuration Discovery:**
- `/modules/agent-installer.js:201-218` - parseMshFile
- `/modules/agent-installer.js:1887-1947` - getServiceConfigFromPlist
- `/modules/agent-installer.js:118-177` - checkParameters

**Configuration Migration:**
- `/modules/agent-installer.js:2110-2132` - Auto-migration
- `/modules/agent-installer.js:2133-2158` - Auto-sync

---

*Last Updated: 2025-11-10*
*Documentation Version: 1.0*
