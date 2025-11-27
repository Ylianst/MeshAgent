# macOSHelpers.js

macOS platform helper functions centralizing macOS-specific utilities for bundle detection, service naming, launchd domain management, and system operations. Provides consistent APIs for handling macOS application bundles, reverse DNS service identifiers, and launchd service control.

## Platform

**Supported Platforms:**
- macOS (darwin) - Full support

**Excluded Platforms:**
- Windows (win32) - Not supported
- Linux - Not supported
- FreeBSD - Not supported

**Exclusion Reasoning:**

This module is explicitly designed for **macOS only**. All functions are macOS-specific and rely on macOS conventions:

1. **App Bundle Structure:** .app bundles with Contents/MacOS/ hierarchy
2. **launchd Service Management:** LaunchDaemons and LaunchAgents
3. **Reverse DNS Naming:** com.company.service-name convention
4. **macOS System Binaries:** PlistBuddy, ditto, launchctl
5. **Path Conventions:** /Library/LaunchDaemons, /Library/LaunchAgents

For cross-platform functionality, other modules use platform detection:
```javascript
if (process.platform === 'darwin') {
    var macOSHelpers = require('./macOSHelpers');
    // Use macOS-specific features
}
```

The module name prefix "macOS" explicitly indicates platform-specific implementation. Functions will fail or return null/error on non-macOS platforms.

## Functionality

### Purpose

The macOSHelpers module centralizes macOS-specific utility functions used throughout MeshAgent's macOS implementation. It serves as a shared library for:

- **Bundle Detection:** Identifying .app bundles and extracting paths
- **Service ID Generation:** Creating consistent service identifiers following reverse DNS conventions
- **Path Management:** Handling plist paths for LaunchDaemons and LaunchAgents
- **LaunchD Domain Management:** Mapping UIDs to launchd domains (system, gui/uid)
- **System Operations:** Wrapping macOS-specific commands (ditto, PlistBuddy)

This module is critical for:
- Agent installation and service registration
- Upgrade operations with service discovery
- Multi-installation support (isolating multiple agents)
- Service rename operations
- KVM support via LaunchAgents

All functionality follows macOS conventions and best practices, ensuring compatibility with macOS system service management.

### Constants - Lines 12-30

#### MACOS_PATHS - Lines 12-19

**Purpose:** Centralized definitions of macOS system paths.

**Constants:**
```javascript
{
    LAUNCH_DAEMONS: '/Library/LaunchDaemons/',
    LAUNCH_AGENTS: '/Library/LaunchAgents/',
    SYSTEM_LAUNCH_DAEMONS: '/System/Library/LaunchDaemons/',
    PLIST_BUDDY: '/usr/libexec/PlistBuddy',
    DITTO: '/usr/bin/ditto',
    LAUNCHCTL: '/bin/launchctl'
}
```

**Usage:**
- `LAUNCH_DAEMONS` - User-installed LaunchDaemons (root background services)
- `LAUNCH_AGENTS` - User-installed LaunchAgents (user session services)
- `SYSTEM_LAUNCH_DAEMONS` - Apple's system LaunchDaemons (read-only)
- `PLIST_BUDDY` - Binary for reading/writing plist files
- `DITTO` - Binary for copying app bundles with metadata preservation
- `LAUNCHCTL` - Binary for controlling launchd services

---

#### LAUNCHD_DOMAINS - Lines 21-24

**Purpose:** launchd domain identifiers for service control.

**Constants:**
```javascript
{
    SYSTEM: 'system',
    GUI_PREFIX: 'gui/'
}
```

**Usage:**
- `SYSTEM` - System domain for LaunchDaemons (root services)
- `GUI_PREFIX` - Prefix for user session domains (e.g., 'gui/501')

**LaunchD Domain Examples:**
- `system` - System-wide services
- `gui/501` - User 501's login session services
- `gui/502` - User 502's login session services

---

#### BUNDLE_STRUCTURE - Lines 26-30

**Purpose:** App bundle path components.

**Constants:**
```javascript
{
    CONTENTS_PATH: '.app/Contents/',
    MACOS_PATH: '.app/Contents/MacOS/',
    RESOURCES_PATH: '.app/Contents/Resources/'
}
```

**Usage:**
- `CONTENTS_PATH` - Contents directory inside bundle
- `MACOS_PATH` - Executable location inside bundle
- `RESOURCES_PATH` - Resources location inside bundle

**Bundle Path Example:**
```
/opt/meshagent/MeshAgent.app/           (bundle root)
    Contents/                           (CONTENTS_PATH)
        MacOS/                          (MACOS_PATH)
            meshagent                   (executable)
        Resources/                      (RESOURCES_PATH)
            icon.icns
        Info.plist
```

---

### Bundle Helpers - Lines 32-69

#### isRunningFromBundle(execPath) - Lines 37-45

**Purpose:** Checks if a given executable path is from an app bundle.

**Process:**
1. Defaults to `process.execPath` if no path provided
2. Searches for `.app/Contents/MacOS/` substring in path
3. Returns true if found AND platform is darwin
4. Returns false otherwise

**Parameters:**
- `execPath` (string, optional) - Path to check. Defaults to `process.execPath`

**Return Value:** Boolean
- `true` - Path is inside .app bundle on macOS
- `false` - Path is standalone binary or not macOS

**Technical Notes:**
- Uses indexOf (not regex) for simple substring match
- Checks both path pattern AND platform
- Does not validate bundle structure (only checks path format)
- Will match any path containing `.app/Contents/MacOS/`

**Examples:**
```javascript
var macOSHelpers = require('./macOSHelpers');

// Bundle path
isRunningFromBundle('/opt/MeshAgent.app/Contents/MacOS/meshagent');
// Returns: true (on macOS)

// Standalone binary
isRunningFromBundle('/opt/meshagent');
// Returns: false

// Non-macOS platform
isRunningFromBundle('/opt/MeshAgent.app/Contents/MacOS/meshagent');
// Returns: false (on Linux/Windows)

// Use current process
isRunningFromBundle();
// Returns: true if current process is in bundle
```

---

#### getBundleParentDirectory(execPath) - Lines 49-56

**Purpose:** Extracts the parent directory of a bundle (e.g., `/opt/meshagent/` from bundle path).

**Process:**
1. Defaults to `process.execPath` if no path provided
2. Calls `isRunningFromBundle()` to validate
3. If not bundle: Returns null
4. Splits path on `.app/Contents/MacOS/` → takes first part
5. Splits by `/` and removes last component (bundle name)
6. Joins back with `/` and adds trailing slash

**Parameters:**
- `execPath` (string, optional) - Path to check. Defaults to `process.execPath`

**Return Value:**
- String - Parent directory with trailing slash
- `null` - Not a bundle path

**Technical Notes:**
- Returns null (not error) for non-bundle paths
- Always includes trailing slash in result
- Removes bundle name from path

**Examples:**
```javascript
var macOSHelpers = require('./macOSHelpers');

// Extract parent directory
getBundleParentDirectory('/opt/meshagent/MeshAgent.app/Contents/MacOS/meshagent');
// Returns: '/opt/meshagent/'

// Nested path
getBundleParentDirectory('/usr/local/mesh_services/company/MeshAgent.app/Contents/MacOS/meshagent');
// Returns: '/usr/local/mesh_services/company/'

// Not a bundle
getBundleParentDirectory('/opt/meshagent');
// Returns: null

// Root level bundle
getBundleParentDirectory('/Applications/MeshAgent.app/Contents/MacOS/meshagent');
// Returns: '/Applications/'
```

---

#### getBundlePathFromBinaryPath(binaryPath) - Lines 61-69

**Purpose:** Extracts the full .app bundle path from a binary path inside the bundle.

**Process:**
1. Checks if path is bundle via `isRunningFromBundle()`
2. If not bundle: Returns null
3. Splits path on `.app/Contents/MacOS/` → takes first part
4. Appends `.app` to reconstruct bundle path

**Parameters:**
- `binaryPath` (string) - Binary path to extract from

**Return Value:**
- String - Full path to .app bundle
- `null` - Not a bundle path

**Technical Notes:**
- Returns complete bundle path (ends with .app)
- Does not validate bundle exists
- Simple string manipulation (not filesystem access)

**Examples:**
```javascript
var macOSHelpers = require('./macOSHelpers');

// Extract bundle path
getBundlePathFromBinaryPath('/opt/meshagent/MeshAgent.app/Contents/MacOS/meshagent');
// Returns: '/opt/meshagent/MeshAgent.app'

// Works with any depth
getBundlePathFromBinaryPath('/Applications/Utilities/MyApp.app/Contents/MacOS/helper');
// Returns: '/Applications/Utilities/MyApp.app'

// Not a bundle
getBundlePathFromBinaryPath('/usr/local/bin/meshagent');
// Returns: null
```

---

### Service ID & Naming - Lines 72-126

#### sanitizeIdentifier(str) - Lines 77-81

**Purpose:** Sanitizes strings to follow reverse DNS naming conventions for service identifiers.

**Process:**
1. Returns null if input is null/undefined
2. Replaces spaces with hyphens
3. Removes all non-alphanumeric except hyphens and underscores
4. Converts to lowercase

**Parameters:**
- `str` (string) - String to sanitize

**Return Value:**
- String - Sanitized identifier (lowercase, hyphens, alphanumeric only)
- `null` - Input was null/undefined

**Technical Notes:**
- Regex: `/[^a-zA-Z0-9_-]/g` removes disallowed characters
- Allows: a-z, A-Z, 0-9, hyphen (-), underscore (_)
- Dots (.) are NOT allowed here (added by buildServiceId)
- Follows macOS bundle identifier conventions

**Examples:**
```javascript
var macOSHelpers = require('./macOSHelpers');

sanitizeIdentifier('My Service Name');
// Returns: 'my-service-name'

sanitizeIdentifier('Company123');
// Returns: 'company123'

sanitizeIdentifier('Service_Name-v2');
// Returns: 'service_name-v2'

sanitizeIdentifier('Invalid@#$Name!');
// Returns: 'invalidname'

sanitizeIdentifier(null);
// Returns: null
```

---

#### buildServiceId(serviceName, companyName, options) - Lines 91-126

**Purpose:** Builds composite service identifier following macOS conventions for LaunchDaemons/LaunchAgents.

**Process:**
1. **Parse Options** (lines 92-95):
   - Extract platform (default: process.platform)
   - Extract explicitServiceId (override mechanism)

2. **Explicit ID Check** (lines 97-99):
   - If explicitServiceId provided: Return it as-is

3. **Non-macOS Platforms** (lines 102-104):
   - Return sanitized service name only

4. **macOS Service ID Logic** (lines 107-125):
   - Sanitize serviceName and companyName
   - Build identifier based on presence of components:
     - **Both present + custom name:** `meshagent.ServiceName.CompanyName`
     - **Both present + default name:** `meshagent.CompanyName`
     - **Service only (custom):** `meshagent.ServiceName`
     - **Service only (default):** `meshagent`

**Parameters:**
- `serviceName` (string) - Service name (e.g., "MeshAgent", "CustomService")
- `companyName` (string, optional) - Company name (e.g., "MyCompany")
- `options` (object, optional) - Options:
  - `platform` (string) - Platform override (default: process.platform)
  - `explicitServiceId` (string) - Explicit ID to use (bypasses all logic)

**Return Value:** String - Service identifier

**Platform Behavior:**
- **macOS:** Composite identifier with dots (e.g., `meshagent.service.company`)
- **Other platforms:** Simple sanitized name (e.g., `meshagent`)

**Technical Notes:**
- Default service name is 'meshagent' (lowercase)
- macOS IDs follow reverse DNS convention
- Explicit ID bypasses all sanitization and logic
- Matches service-manager.js conventions

**Service ID Patterns:**

| serviceName | companyName | Result |
|------------|-------------|--------|
| 'meshagent' | null | `meshagent` |
| 'meshagent' | 'MyCompany' | `meshagent.mycompany` |
| 'CustomService' | null | `meshagent.customservice` |
| 'CustomService' | 'MyCompany' | `meshagent.customservice.mycompany` |

**Examples:**
```javascript
var macOSHelpers = require('./macOSHelpers');

// Default service, no company
buildServiceId('meshagent', null);
// Returns (macOS): 'meshagent'
// Returns (Linux): 'meshagent'

// Default service, with company
buildServiceId('meshagent', 'MyCompany');
// Returns (macOS): 'meshagent.mycompany'
// Returns (Linux): 'meshagent'

// Custom service, no company
buildServiceId('CustomAgent', null);
// Returns (macOS): 'meshagent.customagent'
// Returns (Linux): 'customagent'

// Custom service, with company
buildServiceId('CustomAgent', 'MyCompany');
// Returns (macOS): 'meshagent.customagent.mycompany'
// Returns (Linux): 'customagent'

// Explicit override
buildServiceId('anything', 'anything', { explicitServiceId: 'com.custom.id' });
// Returns: 'com.custom.id' (on all platforms)
```

---

### Path Helpers - Lines 128-141

#### getPlistPath(serviceId, type) - Lines 134-141

**Purpose:** Gets the full plist file path for a given service ID and type.

**Process:**
1. Check type parameter
2. **If 'daemon':** Return LaunchDaemon path
   - `/Library/LaunchDaemons/<serviceId>.plist`
3. **If 'agent':** Return LaunchAgent path
   - `/Library/LaunchAgents/<serviceId>-agent.plist`
4. **Otherwise:** Return null

**Parameters:**
- `serviceId` (string) - Service identifier (e.g., 'meshagent.mycompany')
- `type` (string) - 'daemon' or 'agent'

**Return Value:**
- String - Full plist path
- `null` - Invalid type

**Technical Notes:**
- LaunchDaemon plists do NOT have suffix
- LaunchAgent plists have '-agent' suffix
- Uses MACOS_PATHS constants
- Does not check if file exists

**Examples:**
```javascript
var macOSHelpers = require('./macOSHelpers');

// LaunchDaemon
getPlistPath('meshagent', 'daemon');
// Returns: '/Library/LaunchDaemons/meshagent.plist'

// LaunchAgent
getPlistPath('meshagent', 'agent');
// Returns: '/Library/LaunchAgents/meshagent-agent.plist'

// With company name
getPlistPath('meshagent.mycompany', 'daemon');
// Returns: '/Library/LaunchDaemons/meshagent.mycompany.plist'

getPlistPath('meshagent.mycompany', 'agent');
// Returns: '/Library/LaunchAgents/meshagent.mycompany-agent.plist'

// Invalid type
getPlistPath('meshagent', 'invalid');
// Returns: null
```

---

### LaunchD Domain Helpers - Lines 143-160

#### getLaunchdDomain(uid) - Lines 149-154

**Purpose:** Gets the launchd domain identifier for a given UID.

**Process:**
1. Check if uid is null or undefined
2. **If null/undefined:** Return 'system' (system domain)
3. **Otherwise:** Return 'gui/' + uid (user GUI domain)

**Parameters:**
- `uid` (number or null) - User ID, or null for system domain

**Return Value:** String - LaunchD domain identifier
- `'system'` - For system-wide services (LaunchDaemons)
- `'gui/<uid>'` - For user session services (LaunchAgents)

**Technical Notes:**
- null/undefined maps to system domain (root services)
- Numeric UIDs map to user GUI domains
- Domain format matches launchctl expectations
- Used with launchctl commands:
  - `launchctl print system/<service>`
  - `launchctl print gui/501/<service>`

**Examples:**
```javascript
var macOSHelpers = require('./macOSHelpers');

// System domain (root service)
getLaunchdDomain(null);
// Returns: 'system'

getLaunchdDomain(undefined);
// Returns: 'system'

// User domains
getLaunchdDomain(501);
// Returns: 'gui/501'

getLaunchdDomain(502);
// Returns: 'gui/502'

// Usage with launchctl
var domain = getLaunchdDomain(501);
var cmd = 'launchctl print ' + domain + '/meshagent-agent';
// cmd = 'launchctl print gui/501/meshagent-agent'
```

---

#### getLaunchdPath(domain, serviceId) - Lines 158-160

**Purpose:** Builds a launchd service path for launchctl commands.

**Process:**
1. Concatenates domain + '/' + serviceId
2. Returns combined path string

**Parameters:**
- `domain` (string) - LaunchD domain (e.g., 'system', 'gui/501')
- `serviceId` (string) - Service identifier (e.g., 'meshagent')

**Return Value:** String - Full launchd service path

**Technical Notes:**
- Simple string concatenation
- Used with launchctl commands:
  - `launchctl print <path>`
  - `launchctl bootout <path>`
  - `launchctl start <service>` (just serviceId, not path)
- Domain from `getLaunchdDomain()`
- ServiceId from `buildServiceId()`

**Examples:**
```javascript
var macOSHelpers = require('./macOSHelpers');

// System service
getLaunchdPath('system', 'meshagent');
// Returns: 'system/meshagent'

// User service
getLaunchdPath('gui/501', 'meshagent-agent');
// Returns: 'gui/501/meshagent-agent'

// Usage with launchctl
var domain = getLaunchdDomain(501);
var serviceId = 'meshagent.mycompany-agent';
var path = getLaunchdPath(domain, serviceId);
// path = 'gui/501/meshagent.mycompany-agent'

var cmd = 'launchctl print ' + path;
// cmd = 'launchctl print gui/501/meshagent.mycompany-agent'
```

---

### Utility Wrappers - Lines 162-197

#### copyBundleWithDitto(sourcePath, targetPath) - Lines 168-188

**Purpose:** Copies an app bundle using macOS ditto command, preserving all metadata, signatures, and extended attributes.

**Process:**
1. Spawn ditto command: `ditto <source> <target>`
2. Capture stderr for error messages
3. Wait for command completion via `waitExit()`
4. Verify target exists after copy
5. If errors or target missing: Throw exception
6. Return true on success

**Parameters:**
- `sourcePath` (string) - Source bundle path (e.g., '/tmp/MeshAgent.app')
- `targetPath` (string) - Target bundle path (e.g., '/opt/MeshAgent.app')

**Return Value:**
- `true` - Copy succeeded
- **Throws Error** - Copy failed

**Exceptions:**
- `Error('Bundle copy failed: <reason>')` - If ditto fails or target not created

**Technical Notes:**
- Uses `ditto` instead of `cp` for bundle preservation
- Ditto preserves:
  - File permissions and ownership
  - Extended attributes (xattr)
  - Code signatures
  - Resource forks
  - Finder metadata
- Requires ditto binary at `/usr/bin/ditto`
- Blocks until copy completes (synchronous)
- Stderr is logged to process.stderr

**Why ditto vs cp:**
- `cp -R` may break code signatures
- `cp` doesn't preserve all extended attributes
- `ditto` is Apple's recommended tool for bundles

**Examples:**
```javascript
var macOSHelpers = require('./macOSHelpers');

try {
    copyBundleWithDitto(
        '/tmp/MeshAgent.app',
        '/opt/meshagent/MeshAgent.app'
    );
    console.log('Bundle copied successfully');
} catch (e) {
    console.log('Copy failed: ' + e.message);
}
```

---

#### executePlistBuddy(command, plistPath) - Lines 192-197

**Purpose:** Executes a PlistBuddy command on a plist file and returns the output.

**Process:**
1. Build command: `/usr/libexec/PlistBuddy -c "<command>" "<plistPath>"`
2. Execute via `child_process.execSync()`
3. Capture output as UTF-8 string
4. Trim whitespace from result
5. Return trimmed output

**Parameters:**
- `command` (string) - PlistBuddy command (e.g., 'Print Label')
- `plistPath` (string) - Path to plist file

**Return Value:** String - Command output (trimmed)

**Exceptions:**
- Throws exception if command fails or plist invalid

**Technical Notes:**
- Uses execSync (blocks until complete)
- Command is wrapped in double quotes
- Plist path is wrapped in double quotes
- Returns stdout only (stderr discarded)
- Throws on non-zero exit code

**Common PlistBuddy Commands:**
- `Print` - Print entire plist
- `Print :Label` - Print specific key
- `Print :ProgramArguments` - Print array
- `Print :ProgramArguments:0` - Print array element
- `Set :Label "newvalue"` - Set value (requires write access)
- `Add :NewKey string "value"` - Add new key

**Examples:**
```javascript
var macOSHelpers = require('./macOSHelpers');

// Read service label
var label = executePlistBuddy(
    'Print :Label',
    '/Library/LaunchDaemons/meshagent.plist'
);
console.log('Label: ' + label);
// Output: "Label: meshagent"

// Read first program argument
var binaryPath = executePlistBuddy(
    'Print :ProgramArguments:0',
    '/Library/LaunchDaemons/meshagent.plist'
);
console.log('Binary: ' + binaryPath);
// Output: "Binary: /opt/meshagent/meshagent"

// Read entire ProgramArguments array
var args = executePlistBuddy(
    'Print :ProgramArguments',
    '/Library/LaunchDaemons/meshagent.plist'
);
console.log('Arguments:\n' + args);
// Output: Array in plist XML format
```

---

## Module Exports - Lines 203-228

**Purpose:** Exports all public APIs for use by other modules.

**Exported Properties:**
```javascript
module.exports = {
    // Constants
    PATHS: MACOS_PATHS,
    DOMAINS: LAUNCHD_DOMAINS,
    BUNDLE: BUNDLE_STRUCTURE,

    // Bundle Helpers
    isRunningFromBundle: isRunningFromBundle,
    getBundleParentDirectory: getBundleParentDirectory,
    getBundlePathFromBinaryPath: getBundlePathFromBinaryPath,

    // Service ID & Naming
    sanitizeIdentifier: sanitizeIdentifier,
    buildServiceId: buildServiceId,

    // Path Helpers
    getPlistPath: getPlistPath,

    // LaunchD Domain Helpers
    getLaunchdDomain: getLaunchdDomain,
    getLaunchdPath: getLaunchdPath,

    // Utility Wrappers
    copyBundleWithDitto: copyBundleWithDitto,
    executePlistBuddy: executePlistBuddy
};
```

---

## Usage

### Bundle Detection

```javascript
var macOSHelpers = require('./macOSHelpers');

// Check if running from bundle
if (macOSHelpers.isRunningFromBundle()) {
    var bundlePath = macOSHelpers.getBundlePathFromBinaryPath(process.execPath);
    var parentDir = macOSHelpers.getBundleParentDirectory();
    console.log('Running from bundle: ' + bundlePath);
    console.log('Parent directory: ' + parentDir);
}
```

### Service ID Generation

```javascript
var macOSHelpers = require('./macOSHelpers');

// Build service ID for installation
var serviceName = 'MeshAgent';
var companyName = 'MyCompany';
var serviceId = macOSHelpers.buildServiceId(serviceName, companyName);
// Result: 'meshagent.meshagent.mycompany' on macOS

// Get plist paths
var daemonPlist = macOSHelpers.getPlistPath(serviceId, 'daemon');
var agentPlist = macOSHelpers.getPlistPath(serviceId, 'agent');
console.log('Daemon plist: ' + daemonPlist);
console.log('Agent plist: ' + agentPlist);
```

### LaunchD Control

```javascript
var macOSHelpers = require('./macOSHelpers');
var child_process = require('child_process');

// Build launchd path for system service
var serviceId = 'meshagent';
var domain = macOSHelpers.getLaunchdDomain(null); // 'system'
var launchdPath = macOSHelpers.getLaunchdPath(domain, serviceId);

// Check service status
var cmd = 'launchctl print ' + launchdPath;
var result = child_process.execSync(cmd).toString();
console.log(result);

// For user service (UID 501)
var userDomain = macOSHelpers.getLaunchdDomain(501); // 'gui/501'
var userPath = macOSHelpers.getLaunchdPath(userDomain, serviceId + '-agent');
console.log('User service path: ' + userPath);
```

### Bundle Operations

```javascript
var macOSHelpers = require('./macOSHelpers');

// Copy bundle during installation
try {
    macOSHelpers.copyBundleWithDitto(
        '/tmp/MeshAgent.app',
        '/opt/meshagent/MeshAgent.app'
    );
    console.log('Bundle installed successfully');
} catch (e) {
    console.log('Installation failed: ' + e.message);
}
```

### Plist Reading

```javascript
var macOSHelpers = require('./macOSHelpers');

// Read service configuration from plist
var plistPath = '/Library/LaunchDaemons/meshagent.plist';

var label = macOSHelpers.executePlistBuddy('Print :Label', plistPath);
var binaryPath = macOSHelpers.executePlistBuddy('Print :ProgramArguments:0', plistPath);

console.log('Service Label: ' + label);
console.log('Binary Path: ' + binaryPath);
```

---

## Dependencies

### Node.js Core Modules

- **`child_process`** (lines 169, 194)
  - Methods: `execFile()`, `execSync()`
  - Used for executing system commands
  - Required for ditto and PlistBuddy operations

- **`fs`** (line 170)
  - Methods: `existsSync()`
  - Used for verifying file existence
  - Required for bundle copy verification

### MeshAgent Module Dependencies

**None** - This module has no MeshAgent-specific dependencies. It only uses Node.js core modules.

### Platform Binary Dependencies

**macOS Binaries (Required):**

- **`/usr/bin/ditto`** (line 17, 172)
  - macOS file copy utility
  - Preserves extended attributes and code signatures
  - Standard on all macOS systems
  - Required for `copyBundleWithDitto()`

- **`/usr/libexec/PlistBuddy`** (line 16, 194)
  - macOS plist manipulation utility
  - Read/write property list files
  - Standard on all macOS systems
  - Required for `executePlistBuddy()`

- **`/bin/launchctl`** (line 18)
  - macOS service control utility
  - Not directly used in module (used by callers)
  - Standard on all macOS systems

### Dependency Summary

| Dependency Type | Module/Binary | Required | Platform-Specific |
|----------------|---------------|----------|-------------------|
| Node.js Core | child_process | Yes | No |
| Node.js Core | fs | Yes | No |
| System Binary | ditto | Yes | macOS only |
| System Binary | PlistBuddy | Yes | macOS only |
| System Binary | launchctl | No (used by callers) | macOS only |

---

## Technical Notes

**Reverse DNS Naming Convention:**

macOS service identifiers follow reverse DNS format:
- Format: `com.company.product` or `meshagent.service.company`
- Rules:
  - Lowercase only
  - Dots separate components
  - Alphanumeric with hyphens and underscores
  - No spaces or special characters

**Service ID Hierarchy:**

MeshAgent uses a modified reverse DNS scheme:
- Base prefix: `meshagent` (not `com.meshagent`)
- Hierarchy: `meshagent.{serviceName}.{companyName}`
- Allows multiple installations per company
- Examples:
  - `meshagent` - Default installation
  - `meshagent.mycompany` - Company-specific default
  - `meshagent.customservice.mycompany` - Custom service for company

**LaunchDaemon vs LaunchAgent:**

- **LaunchDaemon:**
  - Runs as root in system domain
  - Starts at boot (before user login)
  - No GUI access
  - Background services
  - Plist: `/Library/LaunchDaemons/<id>.plist`

- **LaunchAgent:**
  - Runs in user session
  - Starts at user login
  - GUI access (for KVM)
  - User context services
  - Plist: `/Library/LaunchAgents/<id>-agent.plist`

**Bundle Structure:**

macOS app bundles are directories with `.app` extension:
```
MeshAgent.app/
    Contents/
        MacOS/
            meshagent           (executable)
        Resources/
            icon.icns
            meshagent.db
        Info.plist
        PkgInfo
```

**ditto vs cp:**

Using ditto ensures:
- Code signatures remain valid
- Extended attributes preserved
- Resource forks maintained
- Spotlight metadata retained
- Finder info preserved

**PlistBuddy Command Format:**

```bash
/usr/libexec/PlistBuddy -c "<command>" "<path>"
```

Commands:
- `Print` - Read values
- `Set` - Modify values
- `Add` - Add new keys
- `Delete` - Remove keys
- Supports key paths: `:Key:Subkey:0` (array index)

**LaunchD Domains:**

launchctl uses domain/service paths:
- System domain: `system/<serviceId>`
- User domain: `gui/<uid>/<serviceId>`
- Login domain: `gui/<uid>` (all services for user)

**Service ID Sanitization:**

Characters allowed in sanitized identifiers:
- Letters: a-z, A-Z (converted to lowercase)
- Numbers: 0-9
- Hyphen: -
- Underscore: _

Characters removed:
- Spaces (replaced with hyphens)
- Special characters: @#$%^&*()[]{}|<>?/\
- Quotes: "'`

---

## Summary

The macOSHelpers.js module is a macOS-specific utility library centralizing common macOS platform operations used throughout MeshAgent. It provides consistent APIs for bundle detection, service naming, launchd management, and system operations.

**Key capabilities:**
- Bundle detection and path extraction
- Service ID generation following reverse DNS conventions
- LaunchD domain mapping (system vs gui/uid)
- Plist path construction for daemons and agents
- Bundle copying with metadata preservation (ditto)
- Plist manipulation via PlistBuddy

**Design philosophy:**
- macOS-only (no cross-platform abstractions)
- Centralized constants for system paths
- Consistent naming conventions
- Utility wrappers for system commands
- No external dependencies

**Common usage patterns:**
- Import once: `var macOSHelpers = require('./macOSHelpers');`
- Check bundle: `if (macOSHelpers.isRunningFromBundle())`
- Build service ID: `var id = macOSHelpers.buildServiceId(name, company);`
- Get plist path: `var path = macOSHelpers.getPlistPath(id, 'daemon');`
- Copy bundle: `macOSHelpers.copyBundleWithDitto(src, dst);`

The module represents best practices for macOS service management in MeshAgent, ensuring compatibility with macOS conventions and system service requirements. It serves as the foundation for agent-installer.js and service-manager.js macOS implementations.
