# security-permissions.js

MeshAgent Security Permissions Module centralizing all file/folder permission management for security-critical files. Provides functions to set, verify, and remediate file permissions across platforms with comprehensive policy definitions for .msh configuration files, .db databases, binaries, and service files.

## Platform

**Supported Platforms:**
- Linux - Full support (POSIX permissions, chown, chmod)
- macOS (darwin) - Full support (POSIX permissions with wheel group)
- FreeBSD - Full support (POSIX permissions)
- Windows (win32) - Partial support (planned, ACL management not yet implemented)

**Excluded Platforms:**
- None (Windows support planned)

**Exclusion Reasoning:**

No platforms are excluded, but Windows implementation is incomplete:

**Windows:**
- Current status: Functions return without error but don't enforce permissions
- Issue: Windows uses Access Control Lists (ACLs), not POSIX permissions
- Future work: Implement ACL-based permission management
- Temporary: Windows installation functions directly (no module enforcement)

**POSIX Platforms (Linux/macOS/FreeBSD):**
- Full support for chmod/chown operations
- Enforces root ownership for critical files
- Platform-specific group names (wheel vs root)

## Functionality

### Purpose

The security-permissions module centralizes permission management for security-critical MeshAgent files, ensuring:

- **.msh files (600):** Server credentials and configuration readable only by root
- **.db files (600):** Agent identity, certificates, and private keys readable only by root
- **Binaries (755):** Root-owned executables preventing privilege escalation
- **Bundles (755):** macOS app bundles with proper ownership
- **Service files (644/755):** LaunchDaemon plists, systemd units, init scripts

This module is critical for:
- Initial installation (setting correct permissions from the start)
- Verification at startup (detecting tampering)
- Periodic checks (continuous security monitoring)
- Remediation (auto-fixing permission issues)
- Compliance (meeting security requirements)

### Security Model

**Security Principles:**

1. **Principle of Least Privilege:**
   - Critical files readable only by root
   - Configuration files not world-readable
   - Prevents credential theft

2. **Integrity Protection:**
   - Root ownership prevents modification by non-root users
   - Prevents malicious binary replacement
   - Protects against privilege escalation attacks

3. **Atomic File Creation:**
   - `createFileSecure()` sets permissions during creation
   - Eliminates race condition where file briefly has default permissions
   - Prevents window of vulnerability

4. **Verification and Remediation:**
   - `verifyPermissions()` checks current state
   - `setSecurePermissions()` fixes issues
   - `verifyInstallation()` checks entire installation
   - Supports warn-only, auto-fix, or fail-fast modes

**Security Levels:**

Files are classified as critical or non-critical:
- **Critical:** .msh, .db, binary, bundle (strict enforcement)
- **Non-critical:** .log, plist, service files (less strict)

Verification can be configured to:
- **Warn:** Log issues but continue
- **Fix:** Automatically remediate issues
- **Strict:** Refuse to run if critical files have wrong permissions

### Key Functions/Methods

#### getEffectiveUid() - Lines 40-54 (UID Detection)

**Purpose:** Gets current effective user ID for permission checks.

**Process:**
1. Check if `process.getuid()` available (Node.js)
2. If yes: Return UID from `process.getuid()`
3. If no: Load user-sessions module (Duktape fallback)
4. Call `userSessions.Self()` for UID
5. If error: Return -1 (unknown)

**Parameters:** None

**Return Value:**
- Number - Effective UID (0 = root)
- -1 - Unable to determine UID

**Technical Notes:**
- Lazy-loads user-sessions module (avoids circular dependencies)
- Works in both Node.js and Duktape environments
- Returns -1 gracefully on error (doesn't throw)
- UID 0 = root (all POSIX systems)

---

#### SECURE_FILE_PERMISSIONS - Lines 67-184 (Permission Policy)

**Purpose:** Centralized policy definitions for all file types with comprehensive security metadata.

**Policy Structure:**

Each file type has:
- `mode` (octal) - Permission bits (e.g., 0o600)
- `owner` (string) - Required owner username ("root")
- `group` (string) - Required group name for macOS ("wheel")
- `groupLinux` (string) - Required group name for Linux/BSD ("root")
- `critical` (boolean) - Whether file is security-critical
- `description` (string) - Human-readable purpose

**File Type Policies:**

**`.msh` - Server Configuration (Lines 73-80):**
```javascript
{
    mode: 0o600,        // rw------- (owner read/write only)
    owner: 'root',
    group: 'wheel',     // macOS
    groupLinux: 'root', // Linux
    critical: true,
    description: 'Server configuration and credentials'
}
```
- Contains: MeshServer URL, MeshID, credentials
- Security: Must be readable only by root
- Risk: Credential theft if world-readable

**`.db` - Agent Database (Lines 86-94):**
```javascript
{
    mode: 0o600,        // rw-------
    owner: 'root',
    group: 'wheel',
    groupLinux: 'root',
    critical: true,
    description: 'Agent identity and certificates'
}
```
- Contains: NodeID, TLS certificates, private keys
- Security: Must be readable only by root
- Risk: Identity theft, man-in-the-middle attacks

**`binary` - Executable (Lines 115-122):**
```javascript
{
    mode: 0o755,        // rwxr-xr-x (world-executable)
    owner: 'root',
    group: 'wheel',
    groupLinux: 'root',
    critical: true,
    description: 'Agent binary executable'
}
```
- Contains: Agent executable
- Security: Must be root-owned
- Risk: Privilege escalation if non-root can modify

**`bundle` - macOS App Bundle (Lines 128-134):**
```javascript
{
    mode: 0o755,        // rwxr-xr-x
    owner: 'root',
    group: 'wheel',
    critical: true,
    description: 'macOS application bundle'
}
```
- Contains: .app directory structure
- Security: Must be root-owned
- Risk: Bundle modification, code injection

**`.log` - Log Files (Lines 101-108):**
```javascript
{
    mode: 0o644,        // rw-r--r-- (world-readable)
    owner: 'root',
    group: 'wheel',
    groupLinux: 'root',
    critical: false,
    description: 'Agent log file'
}
```
- Contains: Log messages (may include sensitive debug info)
- Security: World-readable for troubleshooting
- Non-critical: Can be read by all users

**`plist` - LaunchDaemon Plist (Lines 153-159):**
```javascript
{
    mode: 0o644,        // rw-r--r--
    owner: 'root',
    group: 'wheel',
    critical: false,
    description: 'LaunchDaemon/LaunchAgent plist'
}
```
- Contains: Service definition for launchd
- Security: World-readable (no secrets)
- Location: /Library/LaunchDaemons/

**`initScript` - Linux Init Script (Lines 165-171):**
```javascript
{
    mode: 0o755,        // rwxr-xr-x
    owner: 'root',
    group: 'root',
    critical: false,
    description: 'Linux init script'
}
```
- Contains: SysV init script
- Security: Must be executable
- Location: /etc/init.d/

**`systemdService` - systemd Unit File (Lines 177-183):**
```javascript
{
    mode: 0o644,        // rw-r--r--
    owner: 'root',
    group: 'root',
    critical: false,
    description: 'Systemd service file'
}
```
- Contains: systemd service unit
- Security: World-readable (no secrets)
- Location: /etc/systemd/system/

**`installDir` - Installation Directory (Lines 140-147):**
```javascript
{
    mode: 0o755,        // rwxr-xr-x
    owner: 'root',
    group: 'wheel',
    groupLinux: 'root',
    critical: false,
    description: 'Installation parent directory'
}
```
- Contains: Parent directory for all agent files
- Security: World-executable (traverse)
- Allows: Access to public files within

---

#### setSecurePermissions(filePath, fileType, options) - Lines 208-307 (Apply Permissions)

**Purpose:** Sets secure permissions and ownership for a specific file according to policy.

**Process:**

1. **Validation** (lines 215-223):
   - Validate fileType against SECURE_FILE_PERMISSIONS
   - Throw error if unknown type
   - Check file exists
   - Log policy details

2. **Platform Check** (lines 226-229):
   - If Windows: Return (ACL management not implemented)
   - Continue for POSIX platforms

3. **Set Mode (chmod)** (lines 237-241):
   - If not dry-run: Execute `fs.chmodSync(filePath, policy.mode)`
   - Record action for reporting

4. **Set Ownership (chown)** (lines 244-295):
   - **Check Root** (lines 246-248):
     - Get current UID via `getEffectiveUid()`
     - Only proceed if UID = 0 (root)
   - **Build Command** (lines 250-252):
     - Select group: `policy.group` (macOS) or `policy.groupLinux` (Linux)
     - Command: `chown <owner>:<group> "<filePath>"`
   - **Execute** (lines 254-288):
     - Spawn shell via `child_process.execFile('/bin/sh', ['sh'])`
     - Send chown command
     - Capture stdout and stderr
     - Check exit code (EXITCODE:0 = success)
   - **Error Handling** (lines 278-284):
     - If chown fails: Log warning, record error, set success=false
     - Doesn't throw exception (warns instead)

5. **Logging** (line 297):
   - INFO log on success

**Parameters:**
- `filePath` (string) - Absolute path to file
- `fileType` (string) - Type key from SECURE_FILE_PERMISSIONS
- `options` (object, optional):
  - `dryRun` (boolean) - If true, don't execute (just report actions)
  - `skipChown` (boolean) - If true, skip ownership change (chmod only)

**Return Value:**
```javascript
{
    success: true,               // Overall success
    actions: [                   // Actions performed/planned
        'chmod 600 "/path/file"',
        'chown root:wheel "/path/file"'
    ],
    errors: []                   // Errors encountered
}
```

**Exceptions:**
- Throws Error if fileType unknown
- Throws Error if file doesn't exist
- Doesn't throw on chown failure (returns error in result)

**Platform Behavior:**
- **Linux:** Uses groupLinux ('root') for chown
- **macOS:** Uses group ('wheel') for chown
- **Windows:** Returns immediately (no-op)

**Technical Notes:**
- chmod always succeeds (file owner can change mode)
- chown requires root privileges (ordinary users can't change owner)
- Uses shell execution for Duktape compatibility (no native fs.chownSync)
- Captures exit code via echo trick: `echo "EXITCODE:$?"`
- Non-root users see "Skipped chown" warning

**Usage Example:**
```javascript
var secPerms = require('./security-permissions');

// Set .msh file permissions
var result = secPerms.setSecurePermissions(
    '/opt/meshagent/meshagent.msh',
    '.msh'
);

if (result.success) {
    console.log('Actions: ' + result.actions.join(', '));
} else {
    console.log('Errors: ' + result.errors.join(', '));
}

// Dry-run (preview actions)
var preview = secPerms.setSecurePermissions(
    '/opt/meshagent/meshagent.db',
    '.db',
    { dryRun: true }
);
console.log('Would execute: ' + preview.actions.join(', '));

// Skip ownership change (chmod only)
var chmodOnly = secPerms.setSecurePermissions(
    '/opt/meshagent/meshagent.log',
    '.log',
    { skipChown: true }
);
```

---

#### verifyPermissions(filePath, fileType) - Lines 327-402 (Check Permissions)

**Purpose:** Verifies file has correct permissions and ownership according to policy. Does not modify file.

**Process:**

1. **Validation** (lines 333-337):
   - Validate fileType against SECURE_FILE_PERMISSIONS
   - Check file exists
   - Return issues if not found

2. **Get Current State** (lines 348-356):
   - Call `fs.statSync(filePath)`
   - Extract mode (permissions): `stats.mode & 0o777`
   - Extract uid (owner)
   - Extract gid (group)
   - Store in result.stats

3. **Verify Mode** (lines 362-368):
   - Compare currentMode with policy.mode
   - If mismatch: Add issue to result
   - Record expected and actual values

4. **Verify Ownership** (lines 370-386):
   - **Only if root** (line 371): Skip if not running as root
   - **Check UID** (lines 372-375):
     - Expect uid = 0 (root)
     - Add issue if non-root
   - **Check GID** (lines 377-385):
     - Get expected GID via `getGidForGroup(expectedGroup)`
     - Compare with actual GID
     - Add issue if mismatch

5. **Logging** (lines 388-394):
   - WARN log if critical file has issues
   - WARN log if non-critical file has issues

**Parameters:**
- `filePath` (string) - Absolute path to file
- `fileType` (string) - Type key from SECURE_FILE_PERMISSIONS

**Return Value:**
```javascript
{
    valid: false,               // true if all checks pass
    issues: [                   // List of problems found
        'Incorrect mode: expected 600, got 644',
        'Incorrect owner: expected root (uid 0), got uid 501'
    ],
    stats: {                    // Current file state
        mode: '0644',           // Octal mode string
        uid: 501,               // Owner UID
        gid: 20                 // Group GID
    }
}
```

**Exceptions:** None (returns errors in result.issues)

**Platform Behavior:**
- **All POSIX:** Full verification
- **Non-root users:** Skip ownership checks
- **Windows:** Not implemented (would need ACL parsing)

**Technical Notes:**
- Read-only operation (no modifications)
- Ownership checks only when running as root
- Mode check always performed (no root required)
- Critical files generate WARNING logs when invalid
- Uses `fs.statSync()` (synchronous stat call)

**Usage Example:**
```javascript
var secPerms = require('./security-permissions');

// Verify .msh file
var result = secPerms.verifyPermissions(
    '/opt/meshagent/meshagent.msh',
    '.msh'
);

if (!result.valid) {
    console.log('Issues found:');
    result.issues.forEach(function(issue) {
        console.log('  - ' + issue);
    });
    console.log('Current state:');
    console.log('  Mode: ' + result.stats.mode);
    console.log('  UID: ' + result.stats.uid);
    console.log('  GID: ' + result.stats.gid);
} else {
    console.log('Permissions OK');
}
```

---

#### verifyInstallation(installPath, options) - Lines 428-505 (Full Installation Check)

**Purpose:** Verifies all critical files in installation directory, optionally auto-fixing issues.

**Process:**

1. **Path Normalization** (lines 441-443):
   - Ensure installPath ends with '/'

2. **Build File List** (lines 446-457):
   - Critical files to check:
     - `meshagent.msh` (.msh type)
     - `meshagent.db` (.db type)
     - `meshagent` (binary type)
   - **macOS Bundle** (lines 453-457):
     - Call `findBundle(installPath)` to locate .app
     - Add bundle to list if found

3. **Verify Each File** (lines 462-498):
   - **Skip if doesn't exist** (lines 465-469):
     - Files may not exist yet (.db created later)
     - Log skip message
   - **Call verifyPermissions()** (line 471):
     - Check file permissions
   - **Handle Failures** (lines 474-495):
     - If invalid and autoFix: Call `setSecurePermissions()`
     - If fixed: Add to results.fixed array
     - If fix failed: Add error to results.errors
     - If failOnError + critical: Throw exception
   - **Track Results** (lines 497):
     - Log success for valid files

4. **Return Summary** (lines 501-503):
   - allValid: Boolean (all files passed)
   - files: Object mapping path → verification result
   - fixed: Array of paths that were fixed
   - errors: Array of error messages

**Parameters:**
- `installPath` (string) - Installation directory (must end with /)
- `options` (object, optional):
  - `autoFix` (boolean, default: false) - Automatically fix issues
  - `failOnError` (boolean, default: false) - Throw exception on critical issues

**Return Value:**
```javascript
{
    allValid: false,            // true if all files valid
    files: {                    // Per-file results
        '/opt/meshagent/meshagent.msh': {
            valid: false,
            issues: ['Incorrect mode: expected 600, got 644'],
            stats: { mode: '0644', uid: 0, gid: 0 }
        },
        '/opt/meshagent/meshagent.db': {
            valid: true,
            issues: [],
            stats: { mode: '0600', uid: 0, gid: 0 }
        }
    },
    fixed: [                    // Files that were auto-fixed
        '/opt/meshagent/meshagent.msh'
    ],
    errors: []                  // Errors during fixing
}
```

**Exceptions:**
- Throws Error if failOnError=true and critical file has issues

**Platform Behavior:**
- **macOS:** Includes bundle in checks
- **Linux:** Only checks standard files
- **All:** Skips missing files (no error)

**Technical Notes:**
- Automatically finds .app bundle on macOS
- Optional files (.db) are skipped if not present
- AutoFix mode attempts remediation
- FailOnError mode for strict security enforcement
- Suitable for startup checks and periodic audits

**Usage Example:**
```javascript
var secPerms = require('./security-permissions');

// Basic verification
var result = secPerms.verifyInstallation('/opt/meshagent/');
if (!result.allValid) {
    console.log('Issues found in:');
    for (var path in result.files) {
        if (!result.files[path].valid) {
            console.log('  ' + path);
            console.log('    ' + result.files[path].issues.join(', '));
        }
    }
}

// Auto-fix mode
var fixed = secPerms.verifyInstallation('/opt/meshagent/', {
    autoFix: true
});
console.log('Fixed ' + fixed.fixed.length + ' file(s)');
if (fixed.errors.length > 0) {
    console.log('Failed to fix:');
    fixed.errors.forEach(function(err) {
        console.log('  ' + err);
    });
}

// Strict mode (fail on critical issues)
try {
    secPerms.verifyInstallation('/opt/meshagent/', {
        failOnError: true
    });
    console.log('All security checks passed');
} catch (e) {
    console.log('CRITICAL: ' + e.message);
    process.exit(1);
}
```

---

#### createFileSecure(filePath, content, fileType) - Lines 522-571 (Atomic Secure Creation)

**Purpose:** Creates file with secure permissions atomically, eliminating race condition.

**Process:**

1. **Validate Policy** (lines 523-527):
   - Look up policy for fileType
   - Throw error if unknown type

2. **Write with Mode** (lines 533):
   - Call `fs.writeFileSync(filePath, content, { mode: policy.mode })`
   - File is created with correct mode atomically
   - No window where file has default permissions

3. **Set Ownership** (lines 536-561):
   - **Only if root on POSIX** (line 536):
     - Check platform (not Windows)
     - Check UID = 0 (root)
   - **Build chown Command** (lines 537-545):
     - Select group (macOS wheel or Linux root)
     - Command: `chown <owner>:<group> "<filePath>"`
   - **Execute** (lines 539-556):
     - Spawn shell and execute chown
     - Check exit code
     - Warn on failure (but don't throw)

4. **Logging** (lines 563-564):
   - INFO log on success

**Parameters:**
- `filePath` (string) - Path to create
- `content` (string or Buffer) - File content
- `fileType` (string) - Type key from SECURE_FILE_PERMISSIONS

**Return Value:** None

**Exceptions:**
- Throws Error if fileType unknown
- Throws Error if file write fails
- Doesn't throw on chown failure (logs warning)

**Platform Behavior:**
- **POSIX:** Full implementation (mode + ownership)
- **Windows:** Mode ignored (uses default permissions)

**Technical Notes:**
- **Atomic permission setting:** File created with mode option
- **Race condition eliminated:** No gap between create and chmod
- **Security benefit:** File never world-readable, even briefly
- Mode is atomic, ownership requires separate call (OS limitation)
- Suitable for creating .msh and .db files during installation

**Race Condition Example (Avoided):**

**Bad (race condition):**
```javascript
// File created with default permissions (644)
fs.writeFileSync('/opt/meshagent/meshagent.msh', mshData);
// Brief window where file is world-readable!
fs.chmodSync('/opt/meshagent/meshagent.msh', 0o600);
```

**Good (atomic):**
```javascript
// File created with secure permissions immediately
createFileSecure('/opt/meshagent/meshagent.msh', mshData, '.msh');
// No vulnerable window
```

**Usage Example:**
```javascript
var secPerms = require('./security-permissions');

// Create .msh file securely
var mshData = 'MeshServer=wss://example.com\nMeshID=ABC123\n';
secPerms.createFileSecure(
    '/opt/meshagent/meshagent.msh',
    mshData,
    '.msh'
);
// File is immediately 600, no race condition

// Create .db file securely
var dbData = Buffer.from([0x01, 0x02, 0x03, ...]);
secPerms.createFileSecure(
    '/opt/meshagent/meshagent.db',
    dbData,
    '.db'
);
```

---

#### getGidForGroup(groupName) - Lines 583-617 (Private Helper)

**Purpose:** Looks up numeric group ID for a group name by parsing /etc/group.

**Process:**
1. Return null if Windows
2. Execute shell command: `grep "^<groupName>:" /etc/group`
3. Parse output format: `groupname:x:gid:members`
4. Split on ':' and extract 3rd field (GID)
5. Return GID as integer or null if not found

**Parameters:**
- `groupName` (string) - Group name (e.g., 'wheel', 'root')

**Return Value:**
- Number - Group ID (e.g., 0, 20)
- `null` - Group not found or error

**Technical Notes:**
- Private function (not exported)
- Used by verifyPermissions for group checking
- Parses /etc/group directly (portable across POSIX)
- Doesn't throw on error (returns null)
- Logs debug message on error

**Group IDs:**
- 0 = root (most systems)
- 20 = staff (macOS)
- 80 = wheel (macOS)
- Varies by system

---

#### findBundle(installPath) - Lines 629-649 (Private Helper)

**Purpose:** Finds .app bundle in directory, returns full path to bundle.

**Process:**
1. Return null if not macOS
2. Read directory contents via `fs.readdirSync()`
3. For each file:
   - Check if ends with '.app'
   - Verify it's a directory
   - Return full path if found
4. Return null if no bundle found

**Parameters:**
- `installPath` (string) - Directory to search

**Return Value:**
- String - Full path to .app bundle
- `null` - No bundle found or not macOS

**Technical Notes:**
- Private function (not exported)
- Used by verifyInstallation to include bundle
- Only searches one level (not recursive)
- Ignores errors (returns null)

---

#### getSecurityMode() - Lines 662-677

**Purpose:** Reads SecurityMode setting from database or defaults to 'fix'.

**Process:**
1. Check if ILibSimpleDataStore available (global)
2. Read 'SecurityMode' key from database
3. Return mode if found
4. Default to 'fix' if database unavailable or key missing

**Return Value:**
- String - Security mode ('warn', 'fix', or 'strict')

**Modes:**
- **'warn':** Log warnings but continue operation
- **'fix':** Automatically remediate issues (default)
- **'strict':** Refuse to run if issues found

**Technical Notes:**
- Uses global ILibSimpleDataStore (if available)
- Gracefully handles missing database
- Default is 'fix' (safe and automatic)
- Can be configured per-installation
- Not currently used by module (for future expansion)

---

#### logSecurityEvent(event, details) - Lines 687-709 (Private Helper)

**Purpose:** Logs security events locally and sends to remote server if connected.

**Process:**
1. **Local Logging** (line 690):
   - INFO log with [SECURITY-EVENT] prefix
   - Includes event type and JSON details

2. **Remote Logging** (lines 693-707):
   - Check if MeshAgent module available
   - Check if SendCommand method available
   - Send security event message:
     - action: 'msg'
     - type: 'security_event'
     - event: Event type string
     - details: Event details object
     - timestamp: Current time

**Parameters:**
- `event` (string) - Event type (e.g., 'permission_violation', 'tampering_detected')
- `details` (object) - Event details (arbitrary structure)

**Return Value:** None

**Technical Notes:**
- Private function (not exported)
- Dual logging (local + remote)
- Gracefully handles missing MeshAgent module
- No error if not connected
- Suitable for security monitoring and alerting

**Example Events:**
- 'permission_violation' - File has wrong permissions
- 'tampering_detected' - Binary modified
- 'ownership_changed' - Non-root ownership detected
- 'unauthorized_modification' - Configuration file altered

---

### Module Exports - Lines 712-748

**Purpose:** Exports public API for use by other modules.

**Exported Properties:**
```javascript
module.exports = {
    PERMISSIONS: SECURE_FILE_PERMISSIONS,  // Policy object (read-only)
    setSecurePermissions: setSecurePermissions,
    verifyPermissions: verifyPermissions,
    verifyInstallation: verifyInstallation,
    createFileSecure: createFileSecure,
    getSecurityMode: getSecurityMode
};
```

**Not Exported (Private):**
- getEffectiveUid()
- getGidForGroup()
- findBundle()
- logSecurityEvent()

---

## Usage

### Setting Permissions

```javascript
var secPerms = require('./security-permissions');

// Set .msh file permissions
secPerms.setSecurePermissions(
    '/opt/meshagent/meshagent.msh',
    '.msh'
);

// Set binary permissions
secPerms.setSecurePermissions(
    '/opt/meshagent/meshagent',
    'binary'
);

// Dry-run mode (preview)
var result = secPerms.setSecurePermissions(
    '/opt/meshagent/meshagent.db',
    '.db',
    { dryRun: true }
);
console.log('Would execute:');
result.actions.forEach(function(action) {
    console.log('  ' + action);
});
```

### Verifying Permissions

```javascript
var secPerms = require('./security-permissions');

// Verify single file
var result = secPerms.verifyPermissions(
    '/opt/meshagent/meshagent.msh',
    '.msh'
);

if (!result.valid) {
    console.log('Permission issues:');
    result.issues.forEach(function(issue) {
        console.log('  ' + issue);
    });
}
```

### Full Installation Verification

```javascript
var secPerms = require('./security-permissions');

// Verify entire installation
var result = secPerms.verifyInstallation('/opt/meshagent/', {
    autoFix: true,
    failOnError: false
});

console.log('Verification complete:');
console.log('  All valid: ' + result.allValid);
console.log('  Fixed: ' + result.fixed.length);
console.log('  Errors: ' + result.errors.length);

if (result.errors.length > 0) {
    console.log('Failed to fix:');
    result.errors.forEach(function(err) {
        console.log('  ' + err);
    });
}
```

### Creating Files Securely

```javascript
var secPerms = require('./security-permissions');

// Create .msh file with secure permissions
var mshContent = 'MeshServer=wss://example.com\nMeshID=ABC123\n';
secPerms.createFileSecure(
    '/opt/meshagent/meshagent.msh',
    mshContent,
    '.msh'
);
// File created with 600 permissions immediately

// Create .db file
var dbContent = Buffer.from(...);
secPerms.createFileSecure(
    '/opt/meshagent/meshagent.db',
    dbContent,
    '.db'
);
```

### Startup Security Check

```javascript
var secPerms = require('./security-permissions');
var logger = require('./logger');

// Run at agent startup
function performStartupSecurityCheck() {
    logger.info('[SECURITY] Verifying installation permissions');

    var result = secPerms.verifyInstallation('/opt/meshagent/', {
        autoFix: true,
        failOnError: false
    });

    if (!result.allValid) {
        if (result.fixed.length > 0) {
            logger.warn('[SECURITY] Auto-fixed ' + result.fixed.length + ' permission issue(s)');
        }
        if (result.errors.length > 0) {
            logger.error('[SECURITY] Failed to fix some issues: ' + result.errors.join(', '));
        }
    } else {
        logger.info('[SECURITY] All permissions verified');
    }
}

performStartupSecurityCheck();
```

---

## Dependencies

### Node.js Core Modules

- **`fs`** (line 31)
  - Methods: `writeFileSync()`, `statSync()`, `existsSync()`, `readdirSync()`
  - Used for file I/O and permission checking
  - Required for all operations

- **`child_process`** (line 32)
  - Methods: `execFile()`
  - Used for executing chown commands
  - Required for ownership changes

### MeshAgent Module Dependencies

- **`logger`** (line 33)
  - Methods: `debug()`, `info()`, `warn()`, `error()`
  - Used for logging throughout module
  - Required for visibility

- **`user-sessions`** (line 34, lazy-loaded)
  - Methods: `Self()`
  - Used as fallback for UID detection (Duktape)
  - Optional: Falls back to -1 if unavailable

### Global Variables (Optional)

- **`ILibSimpleDataStore`** (line 665)
  - Method: `Get(key)`
  - Used for reading SecurityMode setting
  - Optional: Defaults if unavailable

- **`require('MeshAgent')`** (line 695)
  - Method: `SendCommand()`
  - Used for remote security event logging
  - Optional: Skipped if unavailable

### Platform Binary Dependencies

**POSIX Platforms:**

- **`/bin/sh`** (line 257, 540, 591)
  - Shell interpreter
  - Used for executing chown and grep commands
  - Standard on all POSIX systems

- **`chown`** (line 251, 545)
  - Change file ownership utility
  - Required for setting owner and group
  - Standard on all POSIX systems

- **`grep`** (line 596)
  - Text search utility
  - Used for parsing /etc/group
  - Standard on all POSIX systems

**Windows:**
- No binaries required (ACL management not implemented)

### Dependency Summary

| Dependency Type | Module/Binary | Required | Platform-Specific |
|----------------|---------------|----------|-------------------|
| Node.js Core | fs | Yes | No |
| Node.js Core | child_process | Yes (POSIX) | POSIX only |
| MeshAgent Module | logger | Yes | No |
| MeshAgent Module | user-sessions | No | No |
| MeshAgent Global | ILibSimpleDataStore | No | No |
| MeshAgent Global | MeshAgent | No | No |
| System Binary | /bin/sh | Yes (POSIX) | POSIX only |
| System Binary | chown | Yes (POSIX) | POSIX only |
| System Binary | grep | Yes (POSIX) | POSIX only |

---

## Technical Notes

**POSIX Permissions:**

Permission format: `rwxrwxrwx` (owner, group, other)
- r = read (4)
- w = write (2)
- x = execute (1)

Common modes:
- `0o600` = `rw-------` (owner read/write only)
- `0o644` = `rw-r--r--` (owner write, all read)
- `0o755` = `rwxr-xr-x` (owner write/execute, all read/execute)

**Group Differences:**

- **macOS:** Default group is 'wheel' (GID typically 0 or 80)
- **Linux:** Default group is 'root' (GID 0)
- **FreeBSD:** Uses 'wheel' like macOS

Module handles this via `policy.group` (macOS) and `policy.groupLinux` (Linux).

**Ownership Requirements:**

- **chmod:** Can be performed by file owner
- **chown:** Requires root privileges (UID 0)
- Non-root users can change mode but not owner

**Atomic File Creation:**

Standard approach (VULNERABLE):
```javascript
fs.writeFileSync(path, data);  // Created with default permissions (644)
// RACE CONDITION: File briefly world-readable!
fs.chmodSync(path, 0o600);     // Now restricted
```

Secure approach (ATOMIC):
```javascript
fs.writeFileSync(path, data, { mode: 0o600 });  // Created with secure permissions
// No vulnerable window
```

**Critical vs Non-Critical:**

| File Type | Critical | Reason |
|-----------|----------|--------|
| .msh | Yes | Contains server credentials |
| .db | Yes | Contains private keys and certificates |
| binary | Yes | Privilege escalation risk if modified |
| bundle | Yes | Code injection risk if modified |
| .log | No | Non-sensitive information |
| plist | No | No secrets, read by launchd |
| service files | No | No secrets, read by init systems |

**Security Modes:**

Three enforcement levels:
1. **Warn:** Log issues, continue operation
2. **Fix:** Automatically remediate (default)
3. **Strict:** Refuse to run if issues found

Currently 'fix' is hardcoded, but framework supports configuration.

**Race Condition Prevention:**

Classic TOCTOU (Time-Of-Check-Time-Of-Use) vulnerability:
```
1. Create file (default 644)
2. [WINDOW: File is world-readable]
3. Change to 600
```

Attacker can:
- Read credentials during window
- Create symlink during window
- Modify file during window

Solution: Atomic creation with mode option eliminates window.

**Future Windows Support:**

Windows ACL structure:
- Security Descriptor
  - Owner SID
  - Group SID
  - DACL (Discretionary ACL)
    - ACE (Access Control Entries)
      - Allow/Deny
      - SID (user/group)
      - Access Mask (permissions)

Implementation would use Windows APIs:
- `SetNamedSecurityInfo()` - Set ACL
- `GetNamedSecurityInfo()` - Read ACL
- `ConvertStringSidToSid()` - Parse SIDs

**Verification Frequency:**

Recommended schedule:
- Installation: Immediate (via setSecurePermissions)
- Startup: Every launch (via verifyInstallation)
- Periodic: Every N hours (continuous monitoring)
- Pre-operation: Before reading sensitive files

**Tampering Detection:**

Signs of tampering:
- Mode changed to world-readable (644 instead of 600)
- Owner changed to non-root
- Binary modified (different size/hash)
- Files in wrong location

Module detects permission and ownership changes. File integrity (hash) is separate concern.

---

## Summary

The security-permissions.js module is a comprehensive permission management system for MeshAgent, providing centralized policy definitions and enforcement for security-critical files. It ensures proper file permissions and ownership across POSIX platforms, with planned Windows ACL support.

**Key capabilities:**
- Centralized permission policies for all file types
- Atomic secure file creation (eliminates race conditions)
- Permission verification (read-only checking)
- Automatic remediation (fixing permission issues)
- Full installation auditing
- Critical vs non-critical file classification

**Security model:**
- Principle of least privilege (root-only access to secrets)
- Integrity protection (root ownership prevents tampering)
- Atomic operations (no vulnerable windows)
- Configurable enforcement (warn/fix/strict modes)

**Platform support:**
- **Linux:** Full support (chmod, chown, group handling)
- **macOS:** Full support (wheel group, bundle handling)
- **FreeBSD:** Full support (POSIX compliance)
- **Windows:** Planned (ACL management needed)

**Common usage patterns:**
- Install: `createFileSecure()` for .msh and .db
- Startup: `verifyInstallation()` with autoFix
- Maintenance: `setSecurePermissions()` for remediation
- Auditing: `verifyPermissions()` for checking

The module represents security best practices for daemon/agent installations, ensuring that sensitive configuration files and executables maintain proper permissions throughout their lifecycle. It serves as the foundation for MeshAgent security enforcement across POSIX platforms.
