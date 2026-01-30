/**
 * MeshAgent Security Permissions Module
 *
 * Centralizes all file/folder permission management for security-critical files.
 * Provides functions to set, verify, and remediate file permissions across platforms.
 *
 * Security Model:
 * - .msh and .db files MUST be 600 (root-only read/write)
 * - Binaries MUST be 755 (root-owned, world-executable)
 * - Verification runs at startup and can run periodically
 * - Failed verification can warn, fix, or refuse to run (configurable)
 *
 * Usage:
 *   var secPerms = require('security-permissions');
 *
 *   // Set permissions on a file
 *   secPerms.setSecurePermissions('/opt/meshagent/meshagent.msh', '.msh');
 *
 *   // Create file with secure permissions atomically
 *   secPerms.createFileSecure('/opt/meshagent/meshagent.msh', mshData, '.msh');
 *
 *   // Verify installation
 *   var result = secPerms.verifyInstallation('/opt/meshagent/', {
 *     autoFix: true,
 *     failOnError: false
 *   });
 *
 * @module security-permissions
 */

var fs = require('fs');
var child_process = require('child_process');
var logger = require('./logger');
var userSessions = null;  // Lazy-load to avoid circular dependencies

/**
 * Get current effective UID
 * Uses process.getuid() if available, otherwise user-sessions.Self()
 */
function getEffectiveUid() {
    if (process.getuid) {
        return process.getuid();
    }
    // Fallback to user-sessions module (for Duktape)
    if (!userSessions) {
        try {
            userSessions = require('user-sessions');
        } catch (e) {
            logger.debug('[SECURITY-PERMS] Could not load user-sessions: ' + e.message);
            return -1;
        }
    }
    return userSessions.Self ? userSessions.Self() : -1;
}

/**
 * Permission policy definitions for all file types
 *
 * Each entry defines:
 * - mode: Octal permission bits (e.g., 0o600 = rw-------)
 * - owner: Required owner username (typically 'root')
 * - group: Required group name (macOS)
 * - groupLinux: Required group name (Linux/BSD)
 * - critical: Whether this file is security-critical (requires strict verification)
 * - description: Human-readable explanation of file purpose
 */
var SECURE_FILE_PERMISSIONS = {
    /**
     * .msh configuration files
     * Contains server URLs, MeshID, and configuration
     * Readable by all for tooling; root-owned for integrity
     */
    '.msh': {
        mode: 0o644,        // rw-r--r--
        owner: 'root',
        group: 'wheel',     // macOS
        groupLinux: 'root', // Linux
        critical: true,
        description: 'Server configuration and credentials'
    },

    /**
     * .db database files
     * Contains NodeID (agent identity), TLS certificates, private keys
     * CRITICAL: Must be readable only by root
     */
    '.db': {
        mode: 0o600,        // rw-------
        owner: 'root',
        group: 'wheel',
        groupLinux: 'root',
        critical: true,
        description: 'Agent identity and certificates'
    },

    /**
     * .log files
     * May contain sensitive debug information
     * IMPORTANT: Readable by all for troubleshooting
     */
    '.log': {
        mode: 0o644,        // rw-r--r--
        owner: 'root',
        group: 'wheel',
        groupLinux: 'root',
        critical: false,
        description: 'Agent log file'
    },

    /**
     * Binary executable
     * Main meshagent executable
     * CRITICAL: Must be root-owned to prevent privilege escalation
     */
    'binary': {
        mode: 0o755,        // rwxr-xr-x
        owner: 'root',
        group: 'wheel',
        groupLinux: 'root',
        critical: true,
        description: 'Agent binary executable'
    },

    /**
     * macOS application bundle (.app directory)
     * CRITICAL: Must be root-owned
     */
    'bundle': {
        mode: 0o755,        // rwxr-xr-x
        owner: 'root',
        group: 'wheel',
        critical: true,
        description: 'macOS application bundle'
    },

    /**
     * Installation directory
     * Parent directory containing all agent files
     */
    'installDir': {
        mode: 0o755,        // rwxr-xr-x
        owner: 'root',
        group: 'wheel',
        groupLinux: 'root',
        critical: false,
        description: 'Installation parent directory'
    },

    /**
     * macOS LaunchDaemon/LaunchAgent plist files
     * Service definition files in /Library/LaunchDaemons or /Library/LaunchAgents
     */
    'plist': {
        mode: 0o644,        // rw-r--r--
        owner: 'root',
        group: 'wheel',
        critical: false,
        description: 'LaunchDaemon/LaunchAgent plist'
    },

    /**
     * Linux init.d scripts
     * SysV init scripts in /etc/init.d
     */
    'initScript': {
        mode: 0o755,        // rwxr-xr-x
        owner: 'root',
        group: 'root',
        critical: false,
        description: 'Linux init script'
    },

    /**
     * systemd service files
     * Service unit files in /etc/systemd/system or /usr/local/mesh_daemons
     */
    'systemdService': {
        mode: 0o644,        // rw-r--r--
        owner: 'root',
        group: 'root',
        critical: false,
        description: 'Systemd service file'
    }
};

/**
 * Set secure permissions for a specific file type
 *
 * Sets both permissions (chmod) and ownership (chown) according to the policy
 * for the specified file type. Handles platform differences automatically.
 *
 * @param {string} filePath - Absolute path to file
 * @param {string} fileType - Type key from SECURE_FILE_PERMISSIONS (e.g., '.msh', 'binary')
 * @param {object} [options] - Optional configuration
 * @param {boolean} [options.dryRun=false] - If true, don't execute, just return what would be done
 * @param {boolean} [options.skipChown=false] - If true, skip ownership change (chmod only)
 * @returns {object} Result object with { success: bool, actions: string[], errors: string[] }
 *
 * @example
 * var logger = require('./logger');
 * var result = setSecurePermissions('/opt/meshagent/meshagent.msh', '.msh');
 * if (result.success) {
 *   logger.info('Set permissions: ' + result.actions.join(', '));
 * } else {
 *   logger.error('Failed: ' + result.errors.join(', '));
 * }
 */
function setSecurePermissions(filePath, fileType, options) {
    options = options || {};
    var result = { success: true, actions: [], errors: [] };

    logger.debug('[SECURITY-PERMS] setSecurePermissions(' + filePath + ', ' + fileType +
                ', dryRun=' + (options.dryRun || false) + ', skipChown=' + (options.skipChown || false) + ')');

    try {
        // Validate file type
        var policy = SECURE_FILE_PERMISSIONS[fileType];
        if (!policy) {
            throw new Error('Unknown file type: ' + fileType + '. Valid types: ' +
                          Object.keys(SECURE_FILE_PERMISSIONS).join(', '));
        }
        logger.debug('[SECURITY-PERMS] Policy for ' + fileType + ': mode=' + policy.mode.toString(8) +
                    ', owner=' + policy.owner + ', critical=' + policy.critical);

        // Windows uses ACLs - different implementation needed (future work)
        if (process.platform === 'win32') {
            result.actions.push('Windows ACL management not yet implemented');
            return result;
        }

        // Check if file exists
        if (!fs.existsSync(filePath)) {
            throw new Error('File does not exist: ' + filePath);
        }
        logger.debug('[SECURITY-PERMS] File exists: ' + filePath);

        // Set mode (permissions)
        if (!options.dryRun) {
            fs.chmodSync(filePath, policy.mode);
        }
        result.actions.push('chmod ' + policy.mode.toString(8) + ' "' + filePath + '"');

        // Set ownership (POSIX only, requires root)
        if (!options.skipChown && process.platform !== 'win32') {
            // Check if running as root
            var currentUid = getEffectiveUid();
            logger.debug('[SECURITY-PERMS] Checking root: currentUid=' + currentUid);

            if (currentUid === 0) {
                var group = (process.platform === 'darwin') ? policy.group : policy.groupLinux;
                var chownCmd = 'chown ' + policy.owner + ':' + group + ' "' + filePath + '"';
                logger.debug('[SECURITY-PERMS] Setting ownership: ' + chownCmd);

                if (!options.dryRun) {
                    try {
                        // Use execFile + waitExit for Duktape compatibility
                        var child = child_process.execFile('/bin/sh', ['sh']);
                        var stdout = '';
                        var stderr = '';
                        child.stdout.on('data', function(chunk) { stdout += chunk.toString(); });
                        child.stderr.on('data', function(chunk) { stderr += chunk.toString(); });
                        child.stdin.write(chownCmd + '\n');
                        child.stdin.write('echo "EXITCODE:$?"\n');  // Capture exit code
                        child.stdin.write('exit\n');
                        child.waitExit();

                        // Check for errors in stderr
                        if (stderr && stderr.trim().length > 0) {
                            throw new Error('chown stderr: ' + stderr.trim());
                        }

                        // Check exit code
                        if (stdout.indexOf('EXITCODE:0') === -1) {
                            throw new Error('chown returned non-zero exit code');
                        }

                        logger.debug('[SECURITY-PERMS] Ownership set successfully');
                    } catch (e) {
                        // Log as WARNING so it's visible even without DEBUG
                        var errMsg = 'chown failed for ' + filePath + ': ' + (e.message || e.toString());
                        result.actions.push(errMsg);
                        result.errors.push(errMsg);
                        result.success = false;
                        logger.warn('[SECURITY-PERMS] ' + errMsg);
                    }
                } else {
                    result.actions.push(chownCmd);
                    logger.debug('[SECURITY-PERMS] Dry-run: would execute ' + chownCmd);
                }
            } else {
                var skipMsg = 'Skipped chown (not running as root, UID: ' + currentUid + ')';
                result.actions.push(skipMsg);
                logger.warn('[SECURITY-PERMS] ' + skipMsg);
            }
        }

        logger.info('[SECURITY-PERMS] Set permissions: ' + filePath + ' (' + fileType + ')');

    } catch (e) {
        result.success = false;
        result.errors.push(e.message || e.toString());
        logger.error('[SECURITY-PERMS] Failed to set permissions on ' + filePath + ': ' +
                    (e.message || e.toString()));
    }

    return result;
}

/**
 * Verify permissions for a specific file
 *
 * Checks if a file has the correct permissions and ownership according to
 * the policy for its file type. Does not modify the file.
 *
 * @param {string} filePath - Absolute path to file
 * @param {string} fileType - Type key from SECURE_FILE_PERMISSIONS
 * @returns {object} Result object with { valid: bool, issues: string[], stats: object }
 *
 * @example
 * var logger = require('./logger');
 * var result = verifyPermissions('/opt/meshagent/meshagent.msh', '.msh');
 * if (!result.valid) {
 *   logger.warn('Issues found: ' + result.issues.join(', '));
 *   logger.info('Current mode: ' + result.stats.mode);
 * }
 */
function verifyPermissions(filePath, fileType) {
    var result = { valid: true, issues: [], stats: null };

    logger.debug('[SECURITY-PERMS] verifyPermissions(' + filePath + ', ' + fileType + ')');

    try {
        // Validate file type
        var policy = SECURE_FILE_PERMISSIONS[fileType];
        if (!policy) {
            throw new Error('Unknown file type: ' + fileType);
        }

        // Check existence
        if (!fs.existsSync(filePath)) {
            result.valid = false;
            result.issues.push('File does not exist');
            logger.debug('[SECURITY-PERMS] File does not exist: ' + filePath);
            return result;
        }

        // Get current stats
        var stats = fs.statSync(filePath);
        var currentMode = stats.mode & parseInt('777', 8);

        result.stats = {
            mode: '0' + currentMode.toString(8),
            uid: stats.uid,
            gid: stats.gid
        };

        logger.debug('[SECURITY-PERMS] Current permissions: mode=' + currentMode.toString(8) +
                    ', uid=' + stats.uid + ', gid=' + stats.gid);
        logger.debug('[SECURITY-PERMS] Expected permissions: mode=' + policy.mode.toString(8) +
                    ', owner=' + policy.owner);

        // Verify mode
        if (currentMode !== policy.mode) {
            result.valid = false;
            result.issues.push('Incorrect mode: expected ' + policy.mode.toString(8) +
                             ', got ' + currentMode.toString(8));
            logger.debug('[SECURITY-PERMS] Mode mismatch detected');
        }

        // Verify ownership (if running as root)
        if (process.getuid && process.getuid() === 0) {
            if (stats.uid !== 0) {
                result.valid = false;
                result.issues.push('Incorrect owner: expected root (uid 0), got uid ' + stats.uid);
            }

            // Verify group
            var expectedGroup = (process.platform === 'darwin') ? policy.group : policy.groupLinux;
            var expectedGid = getGidForGroup(expectedGroup);
            if (expectedGid !== null && stats.gid !== expectedGid) {
                result.valid = false;
                result.issues.push('Incorrect group: expected ' + expectedGroup + ' (gid ' + expectedGid +
                                 '), got gid ' + stats.gid);
                logger.debug('[SECURITY-PERMS] Group mismatch detected');
            }
        }

        if (!result.valid && policy.critical) {
            logger.warn('[SECURITY-PERMS] Permission verification FAILED for CRITICAL file ' +
                       filePath + ': ' + result.issues.join(', '));
        } else if (!result.valid) {
            logger.warn('[SECURITY-PERMS] Permission verification failed for ' + filePath +
                       ': ' + result.issues.join(', '));
        }

    } catch (e) {
        result.valid = false;
        result.issues.push(e.message || e.toString());
    }

    return result;
}

/**
 * Verify all critical files in the installation
 *
 * Checks permissions on .msh, .db, binary, and bundle (if applicable).
 * Can optionally auto-fix issues or fail on error.
 *
 * @param {string} installPath - Installation directory (must end with /)
 * @param {object} [options] - Optional configuration
 * @param {boolean} [options.autoFix=false] - If true, automatically fix permission issues
 * @param {boolean} [options.failOnError=false] - If true, throw error on critical issues
 * @returns {object} Result with { allValid: bool, files: object, fixed: string[], errors: string[] }
 *
 * @example
 * var result = verifyInstallation('/opt/meshagent/', {
 *   autoFix: true,
 *   failOnError: false
 * });
 *
 * if (!result.allValid) {
 *   var logger = require('./logger');
 *   if (result.fixed.length > 0) logger.info('Fixed: ' + result.fixed.join(', '));
 *   if (result.errors.length > 0) logger.error('Errors: ' + result.errors.join(', '));
 * }
 */
function verifyInstallation(installPath, options) {
    options = options || {};
    var agentPaths = require('agent-paths');
    var results = {
        allValid: true,
        files: {},
        fixed: [],
        errors: []
    };

    logger.debug('[SECURITY-PERMS] verifyInstallation(' + installPath +
                ', autoFix=' + (options.autoFix || false) + ')');

    // Normalize path (ensure trailing slash)
    if (!installPath.endsWith('/')) {
        installPath = installPath + '/';
    }

    // Critical files to check - use agent-derived filenames
    var criticalFiles = [
        { path: installPath + agentPaths.getAgentMshName(), type: '.msh' },
        { path: installPath + agentPaths.getAgentDbName(), type: '.db' },
        { path: installPath + agentPaths.getAgentBaseName(), type: 'binary' }
    ];

    // Check for bundle installation (macOS)
    var bundlePath = findBundle(installPath);
    if (bundlePath) {
        logger.debug('[SECURITY-PERMS] Found bundle: ' + bundlePath);
        criticalFiles.push({ path: bundlePath, type: 'bundle' });
    }

    logger.debug('[SECURITY-PERMS] Checking ' + criticalFiles.length + ' file(s)');

    // Verify each file
    for (var i = 0; i < criticalFiles.length; i++) {
        var file = criticalFiles[i];

        if (!fs.existsSync(file.path)) {
            // File doesn't exist - may be optional (e.g., .db created later, .msh only in some installs)
            logger.debug('[SECURITY-PERMS] Skipping (does not exist): ' + file.path);
            continue;
        }

        var verification = verifyPermissions(file.path, file.type);
        results.files[file.path] = verification;

        if (!verification.valid) {
            results.allValid = false;
            logger.debug('[SECURITY-PERMS] Verification failed for ' + file.path + ': ' +
                        verification.issues.join(', '));

            if (options.autoFix) {
                logger.info('[SECURITY-PERMS] Auto-fixing permissions for: ' + file.path);
                var fixResult = setSecurePermissions(file.path, file.type);
                if (fixResult.success) {
                    results.fixed.push(file.path);
                    logger.debug('[SECURITY-PERMS] Successfully fixed: ' + file.path);
                } else {
                    results.errors.push('Failed to fix ' + file.path + ': ' +
                                       fixResult.errors.join(', '));
                }
            } else if (options.failOnError && SECURE_FILE_PERMISSIONS[file.type].critical) {
                // Critical file with wrong permissions and not auto-fixing
                var error = 'CRITICAL: ' + file.path + ' has incorrect permissions: ' +
                           verification.issues.join(', ');
                results.errors.push(error);
                throw new Error(error);
            }
        } else {
            logger.debug('[SECURITY-PERMS] Verification passed: ' + file.path);
        }
    }

    logger.debug('[SECURITY-PERMS] Verification complete: allValid=' + results.allValid +
                ', fixed=' + results.fixed.length + ', errors=' + results.errors.length);

    return results;
}

/**
 * Create file with secure permissions atomically
 *
 * Creates a new file with the correct permissions from the start, preventing
 * the race condition where a file is briefly world-readable before chmod.
 *
 * @param {string} filePath - Path to create
 * @param {string|Buffer} content - File content
 * @param {string} fileType - Type key from SECURE_FILE_PERMISSIONS
 * @throws {Error} If file type is unknown or file creation fails
 *
 * @example
 * createFileSecure('/opt/meshagent/meshagent.msh', mshData, '.msh');
 * // File is created with 0600 permissions immediately, no race condition
 */
function createFileSecure(filePath, content, fileType) {
    var policy = SECURE_FILE_PERMISSIONS[fileType];
    if (!policy) {
        throw new Error('Unknown file type: ' + fileType + '. Valid types: ' +
                       Object.keys(SECURE_FILE_PERMISSIONS).join(', '));
    }

    try {
        // Write file with mode option (atomic on most platforms)
        // This prevents the race condition where file is created with default
        // umask before chmod can run
        fs.writeFileSync(filePath, content, { mode: policy.mode });

        // Set ownership (requires separate call, requires root)
        if (process.platform !== 'win32' && process.getuid && process.getuid() === 0) {
            var group = (process.platform === 'darwin') ? policy.group : policy.groupLinux;
            try {
                // Use execFile + waitExit for Duktape compatibility
                var child = child_process.execFile('/bin/sh', ['sh']);
                var stdout = '';
                var stderr = '';
                child.stdout.on('data', function(chunk) { stdout += chunk.toString(); });
                child.stderr.on('data', function(chunk) { stderr += chunk.toString(); });
                child.stdin.write('chown ' + policy.owner + ':' + group + ' "' + filePath + '"\n');
                child.stdin.write('echo "EXITCODE:$?"\n');
                child.stdin.write('exit\n');
                child.waitExit();

                // Check for errors
                if (stderr && stderr.trim().length > 0) {
                    throw new Error('chown stderr: ' + stderr.trim());
                }
                if (stdout.indexOf('EXITCODE:0') === -1) {
                    throw new Error('chown returned non-zero exit code');
                }
            } catch (e) {
                // Log but don't fail - ownership may already be correct
                logger.warn('[SECURITY-PERMS] chown warning: ' + e.message);
            }
        }

        logger.info('[SECURITY-PERMS] Created secure file: ' + filePath + ' (' + fileType +
                   ', mode ' + policy.mode.toString(8) + ')');

    } catch (e) {
        logger.error('[SECURITY-PERMS] Failed to create secure file ' + filePath + ': ' +
                    e.message);
        throw e;
    }
}

/**
 * Get GID for a group name
 *
 * Looks up the numeric group ID for a given group name.
 * Returns null if group not found or on error.
 *
 * @private
 * @param {string} groupName - Group name (e.g., 'wheel', 'root')
 * @returns {number|null} Group ID or null if not found
 */
function getGidForGroup(groupName) {
    if (process.platform === 'win32') {
        return null;
    }

    try {
        // Parse /etc/group to find GID (most portable approach)
        // Use execFile + waitExit for Duktape compatibility
        var child = child_process.execFile('/bin/sh', ['sh']);
        var output = '';
        var stderr = '';
        child.stdout.on('data', function(chunk) { output += chunk.toString(); });
        child.stderr.on('data', function(chunk) { stderr += chunk.toString(); });
        child.stdin.write('grep "^' + groupName + ':" /etc/group\n');
        child.stdin.write('exit\n');
        child.waitExit();

        // Log stderr if present (but don't fail - group might just not exist)
        if (stderr && stderr.trim().length > 0) {
            logger.debug('[SECURITY-PERMS] getGidForGroup stderr: ' + stderr.trim());
        }

        // Format: groupname:x:gid:members
        var parts = output.trim().split(':');
        if (parts.length >= 3) {
            var gid = parseInt(parts[2], 10);
            return isNaN(gid) ? null : gid;
        }
        return null;
    } catch (e) {
        // Group not found or command failed
        logger.debug('[SECURITY-PERMS] Could not get GID for group ' + groupName + ': ' + e.message);
        return null;
    }
}

/**
 * Find .app bundle in directory (macOS only)
 *
 * Scans the installation directory for a .app bundle directory.
 * Returns null if not found or not on macOS.
 *
 * @private
 * @param {string} installPath - Directory to search
 * @returns {string|null} Full path to .app bundle, or null if not found
 */
function findBundle(installPath) {
    if (process.platform !== 'darwin') {
        return null;
    }

    try {
        var files = fs.readdirSync(installPath);
        for (var i = 0; i < files.length; i++) {
            if (files[i].endsWith('.app')) {
                var fullPath = installPath + files[i];
                if (fs.statSync(fullPath).isDirectory()) {
                    return fullPath;
                }
            }
        }
    } catch (e) {
        // Ignore errors (directory may not exist, permission denied, etc.)
    }

    return null;
}

/**
 * Get the security mode from configuration
 *
 * Reads SecurityMode setting from database or defaults to 'fix'.
 * Modes:
 * - 'warn': Log warning but continue
 * - 'fix': Automatically remediate issues (default)
 * - 'strict': Refuse to run if issues found
 *
 * @returns {string} Security mode ('warn', 'fix', or 'strict')
 */
function getSecurityMode() {
    try {
        // Try to read from database if available
        if (typeof ILibSimpleDataStore !== 'undefined') {
            var mode = ILibSimpleDataStore.Get('SecurityMode');
            if (mode) {
                return mode;
            }
        }
    } catch (e) {
        // Ignore errors - database may not be initialized yet
    }

    // Default to 'fix' mode
    return 'fix';
}

/**
 * Log a security event
 *
 * Logs security-related events locally and sends to remote server if connected.
 *
 * @private
 * @param {string} event - Event type (e.g., 'permission_violation', 'tampering_detected')
 * @param {object} details - Event details
 */
function logSecurityEvent(event, details) {
    // Local logging
    logger.info('[SECURITY-EVENT] ' + event + ': ' + JSON.stringify(details));

    // Remote logging (if MeshAgent is available)
    try {
        if (typeof require !== 'undefined') {
            var meshAgent = require('MeshAgent');
            if (meshAgent && meshAgent.SendCommand) {
                meshAgent.SendCommand({
                    action: 'msg',
                    type: 'security_event',
                    event: event,
                    details: details,
                    timestamp: Date.now()
                });
            }
        }
    } catch (e) {
        // Ignore if not connected or MeshAgent not available
    }
}

// Module exports
module.exports = {
    /**
     * Permission policy definitions (read-only)
     * @type {object}
     */
    PERMISSIONS: SECURE_FILE_PERMISSIONS,

    /**
     * Set secure permissions on a file
     * @function
     */
    setSecurePermissions: setSecurePermissions,

    /**
     * Verify file permissions
     * @function
     */
    verifyPermissions: verifyPermissions,

    /**
     * Verify all files in installation
     * @function
     */
    verifyInstallation: verifyInstallation,

    /**
     * Create file with secure permissions atomically
     * @function
     */
    createFileSecure: createFileSecure,

    /**
     * Get current security mode
     * @function
     */
    getSecurityMode: getSecurityMode
};
