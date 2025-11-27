/*
Copyright 2024

macOS Platform Helper Functions
Centralizes macOS-specific utilities for bundle detection, service naming, and system operations
*/

// ============================================================================
// CONSTANTS
// ============================================================================

var MACOS_PATHS = {
    LAUNCH_DAEMONS: '/Library/LaunchDaemons/',
    LAUNCH_AGENTS: '/Library/LaunchAgents/',
    SYSTEM_LAUNCH_DAEMONS: '/System/Library/LaunchDaemons/',
    PLIST_BUDDY: '/usr/libexec/PlistBuddy',
    DITTO: '/usr/bin/ditto',
    LAUNCHCTL: '/bin/launchctl'
};

var LAUNCHD_DOMAINS = {
    SYSTEM: 'system',
    GUI_PREFIX: 'gui/'
};

var BUNDLE_STRUCTURE = {
    CONTENTS_PATH: '.app/Contents/',
    MACOS_PATH: '.app/Contents/MacOS/',
    RESOURCES_PATH: '.app/Contents/Resources/'
};

// ============================================================================
// BUNDLE HELPERS
// ============================================================================

// Check if a given path is from an app bundle
function isRunningFromBundle(execPath) {
    if (!execPath) execPath = process.execPath;
    return process.platform === 'darwin' && execPath.indexOf('.app/Contents/MacOS/') !== -1;
}

// Extract the parent directory of a bundle (e.g., /opt/meshagent/ from /opt/meshagent/MeshAgent.app/Contents/MacOS/meshagent)
// Returns null if not a bundle path
function getBundleParentDirectory(execPath) {
    if (!execPath) execPath = process.execPath;
    if (!isRunningFromBundle(execPath)) return null;

    var parts = execPath.split('.app/Contents/MacOS/')[0].split('/');
    parts.pop();  // Remove bundle name
    return parts.join('/') + '/';
}

// Extract the bundle path from a binary path
// e.g., /opt/meshagent/MeshAgent.app/Contents/MacOS/meshagent -> /opt/meshagent/MeshAgent.app
// Returns null if not a bundle path
function getBundlePathFromBinaryPath(binaryPath) {
    if (!isRunningFromBundle(binaryPath)) return null;
    return binaryPath.split('.app/Contents/MacOS/')[0] + '.app';
}

// ============================================================================
// SERVICE ID & NAMING
// ============================================================================

// Sanitize identifier to follow reverse DNS naming conventions
// Only allow alphanumeric, hyphens, and underscores (dots will be added between components)
function sanitizeIdentifier(str) {
    if (!str) return null;
    // Replace spaces with hyphens, remove all non-alphanumeric except hyphens/underscores, convert to lowercase
    return str.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase();
}

// Build composite service identifier from service name and company name
// Handles all macOS service ID patterns consistently across the codebase
// Format examples:
//   - meshagent.ServiceName.CompanyName (custom service name + company)
//   - meshagent.CompanyName (default service name + company)
//   - meshagent.ServiceName (custom service name only)
//   - meshagent (default service name only)
//   - ServiceName (non-macOS platforms)
function buildServiceId(serviceName, companyName, options) {
    options = options || {};
    var platform = options.platform || process.platform;
    var explicitServiceId = options.explicitServiceId || null;

    // If an explicit serviceId is provided, use it directly
    if (explicitServiceId !== null) {
        return explicitServiceId;
    }

    // Non-macOS platforms use simple sanitized identifier
    if (platform !== 'darwin') {
        return sanitizeIdentifier(serviceName);
    }

    // macOS composite identifier logic
    var sanitizedServiceName = sanitizeIdentifier(serviceName);
    var sanitizedCompanyName = sanitizeIdentifier(companyName);

    if (sanitizedCompanyName) {
        // Company name present
        if (sanitizedServiceName && sanitizedServiceName !== 'meshagent') {
            // Custom service name + company: meshagent.ServiceName.CompanyName
            return 'meshagent.' + sanitizedServiceName + '.' + sanitizedCompanyName;
        } else {
            // Default service name + company: meshagent.CompanyName
            return 'meshagent.' + sanitizedCompanyName;
        }
    } else if (sanitizedServiceName && sanitizedServiceName !== 'meshagent') {
        // Only custom service name (no company): meshagent.ServiceName
        return 'meshagent.' + sanitizedServiceName;
    } else {
        // Default service name only: meshagent
        return 'meshagent';
    }
}

// ============================================================================
// PATH HELPERS
// ============================================================================

// Get the plist path for a given service ID and type
// type: 'daemon' for LaunchDaemon, 'agent' for LaunchAgent
function getPlistPath(serviceId, type) {
    if (type === 'daemon') {
        return MACOS_PATHS.LAUNCH_DAEMONS + serviceId + '.plist';
    } else if (type === 'agent') {
        return MACOS_PATHS.LAUNCH_AGENTS + serviceId + '-agent.plist';
    }
    return null;
}

// ============================================================================
// LAUNCHD DOMAIN HELPERS
// ============================================================================

// Get the launchd domain for a given UID
// Returns 'system' for system domain (uid=null), or 'gui/{uid}' for user domain
function getLaunchdDomain(uid) {
    if (uid === null || uid === undefined) {
        return LAUNCHD_DOMAINS.SYSTEM;
    }
    return LAUNCHD_DOMAINS.GUI_PREFIX + uid;
}

// Build a launchd service path in the format 'domain/serviceId'
// Used for launchctl commands like 'launchctl print system/meshagent'
function getLaunchdPath(domain, serviceId) {
    return domain + '/' + serviceId;
}

// ============================================================================
// UTILITY WRAPPERS
// ============================================================================

// Copy an app bundle using ditto (preserves all macOS metadata, signatures, etc.)
// Returns true on success, throws error on failure
function copyBundleWithDitto(sourcePath, targetPath) {
    var child_process = require('child_process');
    var fs = require('fs');

    var dittoError = null;
    var child = child_process.execFile(MACOS_PATHS.DITTO, ['ditto', sourcePath, targetPath]);

    child.stderr.on('data', function(d) {
        dittoError = d.toString();
        process.stderr.write(d);
    });

    child.waitExit();

    // Verify the copy succeeded by checking if target exists
    if (dittoError || !fs.existsSync(targetPath)) {
        throw new Error('Bundle copy failed: ' + (dittoError || 'Target not created'));
    }

    return true;
}

// Execute PlistBuddy command on a plist file
// Returns the output string, throws on error
function executePlistBuddy(command, plistPath) {
    var child_process = require('child_process');
    return child_process.execSync(MACOS_PATHS.PLIST_BUDDY + ' -c "' + command + '" "' + plistPath + '"', {
        encoding: 'utf8'
    }).trim();
}

// ============================================================================
// EXPORTS
// ============================================================================

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
