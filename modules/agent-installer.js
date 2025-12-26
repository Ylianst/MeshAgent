/*
Copyright 2020 Intel Corporation
@author Bryan Roe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


//
// This is a helper utility that is used by the Mesh Agent to install itself
// as a background service, on all platforms that the agent supports.
//

try
{
    // This peroperty is a polyfill for an Array, to fetch the specified element if it exists, removing the surrounding quotes if they are there
    Object.defineProperty(Array.prototype, 'getParameterEx',
        {
            value: function (name, defaultValue)
            {
                var i, ret;
                for (i = 0; i < this.length; ++i)
                {
                    if (this[i].startsWith(name + '='))
                    {
                        ret = this[i].substring(name.length + 1);
                        // Strip surrounding quotes (double or single)
                        if ((ret.startsWith('"') && ret.endsWith('"')) || (ret.startsWith("'") && ret.endsWith("'"))) {
                            ret = ret.substring(1, ret.length - 1);
                        }
                        return (ret);
                    }
                }
                return (defaultValue);
            }
        });

    // This property is a polyfill for an Array, to fetch the specified element if it exists 
    Object.defineProperty(Array.prototype, 'getParameter',
        {
            value: function (name, defaultValue)
            {
                return (this.getParameterEx('--' + name, defaultValue));
            }
        });
}
catch(x)
{ }
try
{
    // This property is a polyfill for an Array, to fetch the index of the specified element, if it exists
    Object.defineProperty(Array.prototype, 'getParameterIndex',
        {
            value: function (name)
            {
                var i;
                for (i = 0; i < this.length; ++i)
                {
                    if (this[i].startsWith('--' + name + '='))
                    {
                        return (i);
                    }
                }
                return (-1);
            }
        });
}
catch(x)
{ }
try
{
    // This property is a polyfill for an Array, to remove the specified element, if it exists
    Object.defineProperty(Array.prototype, 'deleteParameter',
        {
            value: function (name)
            {
                var i = this.getParameterIndex(name);
                if(i>=0)
                {
                    this.splice(i, 1);
                }
            }
        });
}
catch(x)
{ }
try
{
    // This property is a polyfill for an Array, to to fetch the value YY of an element XX in the format --XX=YY, if it exists
    Object.defineProperty(Array.prototype, 'getParameterValue',
        {
            value: function (i)
            {
                var ret = this[i].substring(this[i].indexOf('=')+1);
                if (ret.startsWith('"')) { ret = ret.substring(1, ret.length - 1); }
                return (ret);
            }
        });
}
catch(x)
{ }

// Import macOS platform helpers (only on macOS)
var macOSHelpers = process.platform === 'darwin' ? require('./macOSHelpers') : null;

// Import security permissions module
var securityPermissions = require('./security-permissions');

// Import logger for unified timestamped logging
var logger = require('./logger');

// Configure logger output mode from command line parameters
// Default for install/uninstall is QUIET; user can override with flags
function configureLoggerFromParams(parms) {
    // Set install/uninstall default to QUIET (overrides logger's INFO default)
    logger.forceOutputMode('QUIET');

    // Parse --log=0,1,2,3 (0=silent, 1=quiet, 2=info, 3=verbose)
    var logParam = parms.getParameter('log', null);
    if (logParam !== null) {
        switch (logParam) {
            case '0': logger.forceOutputMode('SILENT'); break;
            case '1': logger.forceOutputMode('QUIET'); break;
            case '2': logger.forceOutputMode('INFO'); break;
            case '3':
                logger.forceOutputMode('VERBOSE');
                logger.setLevel('DEBUG');
                break;
        }
        return;  // --log takes precedence, skip other flags
    }

    // Parse --verbose, --info, --quiet, --silent parameters
    var verboseParam = parms.getParameter('verbose', null);
    var infoParam = parms.getParameter('info', null);
    var quietParam = parms.getParameter('quiet', null);
    var silentParam = parms.getParameter('silent', null);

    // Apply output modes - most verbose wins (order doesn't matter due to setOutputMode logic)
    // Order from least to most verbose: SILENT < QUIET < INFO < VERBOSE
    if (silentParam === '1' || silentParam === 'true') {
        logger.setOutputMode('SILENT');
    }
    if (quietParam === '1' || quietParam === 'true') {
        logger.setOutputMode('QUIET');
    }
    if (infoParam === '1' || infoParam === 'true') {
        logger.setOutputMode('INFO');
    }
    if (verboseParam === '1' || verboseParam === 'true') {
        logger.setOutputMode('VERBOSE');
        logger.setLevel('DEBUG');  // Enable debug logging in verbose mode
    }
    // If --verbose=0 or --quiet=0 explicitly, use INFO mode
    if (verboseParam === '0' || verboseParam === 'false' || quietParam === '0' || quietParam === 'false') {
        logger.setOutputMode('INFO');
    }
}

// Case-insensitive file lookup
// Returns the actual filename if found, or null if not found
function findFileCaseInsensitive(directory, targetFilename) {
    var fs = require('fs');

    try {
        var files = fs.readdirSync(directory);
        var targetLower = targetFilename.toLowerCase();

        for (var i = 0; i < files.length; i++) {
            if (files[i].toLowerCase() === targetLower) {
                return directory + '/' + files[i];
            }
        }
    } catch (e) {
        // Directory doesn't exist or not readable
    }

    return null;
}

// Find any .app bundle in a directory that contains a meshagent binary
// Returns the bundle name (e.g., "MeshAgent.app") or null if not found
// This allows support for custom bundle names instead of hard-coding "MeshAgent.app"
function findBundleInDirectory(installPath) {
    var fs = require('fs');

    try {
        var files = fs.readdirSync(installPath);
        for (var i = 0; i < files.length; i++) {
            if (files[i].endsWith('.app')) {
                // Check if this bundle contains a meshagent binary
                var binaryPath = installPath + files[i] + '/Contents/MacOS/meshagent';
                if (fs.existsSync(binaryPath)) {
                    return files[i];
                }
            }
        }
    } catch (e) {
        // Directory doesn't exist or not readable
    }

    return null;
}

// Helper function to detect if running from app bundle or standalone binary
function detectSourceType() {
    var execPath = process.execPath;


    // Check if running from .app bundle using shared helper
    if (macOSHelpers && macOSHelpers.isRunningFromBundle(execPath)) {
        var isBundle = macOSHelpers.isRunningFromBundle(execPath);

        // Extract bundle path (everything up to and including .app)
        var bundlePath = macOSHelpers.getBundlePathFromBinaryPath(execPath);

        return {
            type: 'bundle',
            bundlePath: bundlePath,
            binaryPath: execPath
        };
    } else {
        // Running from standalone binary
        return {
            type: 'standalone',
            binaryPath: execPath
        };
    }
}

// Helper function to detect what type of installation exists at a path
function detectInstallationType(installPath) {
    var fs = require('fs');

    // Check for bundle installation using dynamic discovery
    if (findBundleInDirectory(installPath)) {
        return 'bundle';
    }

    // Check for standalone binary installation
    if (fs.existsSync(installPath + 'meshagent')) {
        return 'standalone';
    }

    // Nothing installed
    return null;
}

// This function performs some checks on the parameter structure, to make sure the minimum set of requried elements are present
function checkParameters(parms)
{
    // Normalize --serviceName to --meshServiceName for backward compatibility
    // Priority: --serviceName > --meshServiceName
    var serviceNameIdx = parms.getParameterIndex('serviceName');
    if (serviceNameIdx >= 0)
    {
        var serviceNameValue = parms.getParameterValue(serviceNameIdx);
        parms.splice(serviceNameIdx, 1);
        // Only add as meshServiceName if one wasn't already specified
        if (parms.getParameter('meshServiceName', null) == null)
        {
            parms.push('--meshServiceName="' + serviceNameValue + '"');
        }
    }


    var msh = _MSH();
    if (parms.getParameter('description', null) == null && msh.description != null) { parms.push('--description="' + msh.description + '"'); }
    if (parms.getParameter('displayName', null) == null && msh.displayName != null) { parms.push('--displayName="' + msh.displayName + '"'); }
    if (parms.getParameter('companyName', null) == null && msh.companyName != null) { parms.push('--companyName="' + msh.companyName + '"'); }

    if (msh.fileName != null)
    {
        // This converts the --fileName parameter of the installer, to the --target=XXX format required by service-manager.js
        var i = parms.getParameterIndex('fileName');
        if(i>=0)
        {
            parms.splice(i, 1);
        }
        parms.push('--target="' + msh.fileName + '"');
    }

    if (parms.getParameter('meshServiceName', null) == null)
    {
        if(msh.meshServiceName != null)
        {
            // This adds the specified service name, to be consumed by service-manager.js
            parms.push('--meshServiceName="' + msh.meshServiceName + '"');
        }
        else
        {
            // Still no meshServiceName specified... Let's also check installed services...
            var tmp = process.platform == 'win32' ? 'Mesh Agent' : 'meshagent';
            try
            {
                tmp = require('_agentNodeId').serviceName();
            }
            catch(xx)
            {
            }

            // The default is 'Mesh Agent' for Windows, and 'meshagent' for everything else...
            if(tmp != (process.platform == 'win32' ? 'Mesh Agent' : 'meshagent'))
            {
                parms.push('--meshServiceName="' + tmp + '"');
            }
        }
    }
}

// ===== UPGRADE HELPER FUNCTIONS =====

// Helper to normalize install paths - handles both directory and binary paths
function normalizeInstallPath(path) {
    if (!path) return '/usr/local/mesh_services/meshagent/';

    // Ensure trailing slash
    if (!path.endsWith('/')) {
        return path + '/';
    }

    return path;
}

// Helper to parse .msh configuration file
function parseMshFile(mshPath) {
    try {
        var f = require('fs').readFileSync(mshPath).toString();
        var lines = f.split('\r').join('').split('\n');
        var msh = {};

        for (var i in lines) {
            var tokens = lines[i].split('=');
            if (tokens.length == 2) {
                msh[tokens[0]] = tokens[1];
            }
        }

        return msh;
    } catch (e) {
        throw new Error('Could not read .msh file: ' + e.message);
    }
}

// Validate .msh file has minimum required settings for agent to connect
// Required: MeshServer, MeshID, ServerID
// Returns: { valid: boolean, missing: string[] }
function validateMshConfig(mshPath) {
    var result = { valid: false, missing: [] };

    if (!require('fs').existsSync(mshPath)) {
        result.missing.push('file not found');
        return result;
    }

    try {
        var msh = parseMshFile(mshPath);

        // Check required settings
        if (!msh.MeshServer || msh.MeshServer.trim() === '') {
            result.missing.push('MeshServer');
        }
        if (!msh.MeshID || msh.MeshID.trim() === '') {
            result.missing.push('MeshID');
        }
        if (!msh.ServerID || msh.ServerID.trim() === '') {
            result.missing.push('ServerID');
        }

        result.valid = (result.missing.length === 0);
        return result;
    } catch (e) {
        result.missing.push('parse error: ' + e.message);
        return result;
    }
}

// Helper to update .msh configuration file
function updateMshFile(mshPath, updates) {
    try {
        var f = require('fs').readFileSync(mshPath).toString();
        var lines = f.split('\r').join('').split('\n');
        var newLines = [];
        var updatedKeys = {};

        // Update existing keys
        for (var i in lines) {
            var tokens = lines[i].split('=');
            if (tokens.length == 2) {
                var key = tokens[0];
                if (updates[key] !== undefined) {
                    // Handle null/blank: write "key=" to trigger DB deletion on import
                    if (updates[key] !== null && updates[key] !== '') {
                        newLines.push(key + '=' + updates[key]);
                    } else {
                        newLines.push(key + '=');  // Blank value
                    }
                    updatedKeys[key] = true;
                } else {
                    newLines.push(lines[i]);
                }
            } else if (lines[i].trim() !== '') {
                newLines.push(lines[i]);
            }
        }

        // Add new keys that weren't already in the file
        for (var key in updates) {
            if (!updatedKeys[key]) {
                // Handle null/blank: write "key=" to trigger DB deletion on import
                if (updates[key] !== null && updates[key] !== '') {
                    newLines.push(key + '=' + updates[key]);
                } else {
                    newLines.push(key + '=');  // Blank value
                }
            }
        }

        require('fs').writeFileSync(mshPath, newLines.join('\n') + '\n');
    } catch (e) {
        throw new Error('Could not update .msh file: ' + e.message);
    }
}

// Helper to find existing installation
function findInstallation(installPath, serviceName, companyName) {
    logger.debug('[findInstallation] Called with installPath=' + installPath + ', serviceName=' + serviceName + ', companyName=' + companyName);

    // If explicit path provided
    if (installPath) {
        logger.debug('[findInstallation] Checking explicit path: ' + installPath);
        installPath = normalizeInstallPath(installPath);
        // Check for bundle first using dynamic discovery, then standalone binary
        var bundleName = findBundleInDirectory(installPath);
        if (bundleName) {
            return installPath;
        }
        if (require('fs').existsSync(installPath + 'meshagent')) {
            return installPath;
        }
        // Not found - return null (caller will log appropriately based on context)
        return null;
    }

    // Try to find service by name
    if (serviceName || companyName) {
        logger.debug('[findInstallation] Trying to find service by name');
        try {
            var serviceId = macOSHelpers.buildServiceId(serviceName || 'meshagent', companyName);

            var svc = require('service-manager').manager.getService(serviceId);
            var path = svc.appWorkingDirectory();
            svc.close();
            logger.debug('[findInstallation] Found service at: ' + path);
            return path;
        } catch (e) {
            logger.debug('[findInstallation] Service not found by name');
            // Service not found - return null (caller will log appropriately)
            return null;
        }
    }

    logger.debug('[findInstallation] Scanning plists for current binary: ' + process.execPath);
    // Check if current binary is registered in any LaunchDaemon/LaunchAgent
    // This handles upgrade/install from an already-installed location
    var currentBinary = process.execPath;
    var dirs = ['/Library/LaunchDaemons', '/Library/LaunchAgents'];

    for (var d = 0; d < dirs.length; d++) {
        try {
            var files = require('fs').readdirSync(dirs[d]);
            for (var i = 0; i < files.length; i++) {
                if (files[i].endsWith('.plist')) {
                    var plistPath = dirs[d] + '/' + files[i];
                    var binaryPath = getProgramPathFromPlist(plistPath);

                    // Check if this plist points to the CURRENT binary
                    if (binaryPath === currentBinary) {
                        logger.debug('[findInstallation] Found plist pointing to current binary: ' + plistPath);
                        // Extract installation path
                        var bundleParent = macOSHelpers.getBundleParentDirectory(binaryPath);
                        if (bundleParent) {
                            logger.debug('[findInstallation] Returning bundle parent: ' + bundleParent);
                            return bundleParent;
                        } else {
                            var parts = binaryPath.split('/');
                            parts.pop();
                            var result = parts.join('/') + '/';
                            logger.debug('[findInstallation] Returning binary directory: ' + result);
                            return result;
                        }
                    }
                }
            }
        } catch (e) {
            // Continue to next directory
        }
    }

    logger.debug('[findInstallation] No plist found, checking default location');
    // Try default location
    var defaultPath = '/usr/local/mesh_services/meshagent/';
    if (require('fs').existsSync(defaultPath + 'meshagent')) {
        logger.debug('[findInstallation] Found installation at default path: ' + defaultPath);
        return defaultPath;
    }

    // Not found anywhere - return null (caller will log appropriately)
    logger.debug('[findInstallation] No installation found, returning null');
    return null;
}

// Helper to stop LaunchDaemon
function stopLaunchDaemon(serviceId) {
    try {
        var svc = require('service-manager').manager.getService(serviceId);

        if (svc.isRunning == null || svc.isRunning()) {
            svc.unload();
            logger.info('LaunchDaemon stopped');
        } else {
            logger.info('LaunchDaemon already stopped');
        }

        svc.close();
        return true;
    } catch (e) {
        logger.warn('Could not stop LaunchDaemon: ' + e);
        return false;
    }
}

// Helper to stop LaunchAgent
function stopLaunchAgent(serviceId) {
    try {
        // LaunchAgent name has '-agent' suffix
        var launchAgent = require('service-manager').manager.getLaunchAgent(serviceId + '-agent');

        // Get console UID for bootout
        var uid = require('user-sessions').consoleUid();

        if (uid && uid > 0) {
            launchAgent.unload(uid);
            logger.info('LaunchAgent stopped');
        } else {
            logger.info('No console user logged in, LaunchAgent not running');
        }
        return true;
    } catch (e) {
        logger.warn('Could not stop LaunchAgent: ' + e);
        return false;
    }
}

// Helper to extract ProgramArguments path from plist file
function getProgramPathFromPlist(plistPath) {
    try {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = '';
        child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
        // Extract first ProgramArguments string (the binary path)
        child.stdin.write("cat '" + plistPath + "' | tr '\\n' '.' | awk '{ split($0, a, \"<key>ProgramArguments</key>\"); split(a[2], b, \"</array>\"); split(b[1], c, \"<string>\"); split(c[2], d, \"</string>\"); print d[1]; }'\nexit\n");
        child.waitExit();
        var result = child.stdout.str.trim();
        return result || '';  // Return empty string instead of null/undefined
    } catch (e) {
        logger.warn('Failed to parse plist: ' + plistPath + ' - ' + e.message);
        return '';  // Return empty string on error, never null
    }
}

// Helper to extract extra ProgramArguments from plist (returns all args for filtering later)
function extractExtraProgramArguments(plistPath) {
    try {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = '';
        child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
        child.stderr.on('data', function (chunk) { });

        // Count ProgramArguments array elements
        child.stdin.write('/usr/libexec/PlistBuddy -c "Print :ProgramArguments" "' + plistPath + '" 2>/dev/null | grep -c "    "\n');
        child.stdin.write('exit\n');
        child.waitExit();

        var count = parseInt(child.stdout.str.trim()) || 0;
        if (count === 0) return [];

        // Read each argument
        var allArgs = [];
        for (var i = 0; i < count; i++) {
            var argChild = require('child_process').execFile('/bin/sh', ['sh']);
            argChild.stdout.str = '';
            argChild.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            argChild.stderr.on('data', function (chunk) { });
            argChild.stdin.write('/usr/libexec/PlistBuddy -c "Print :ProgramArguments:' + i + '" "' + plistPath + '" 2>/dev/null\n');
            argChild.stdin.write('exit\n');
            argChild.waitExit();
            var arg = argChild.stdout.str.trim();
            if (arg) allArgs.push(arg);
        }

        return allArgs;
    } catch (e) {
        logger.warn('Could not extract ProgramArguments: ' + e);
        return [];
    }
}

// Helper to extract all keys from plist as key-value objects
function extractNonStandardKeys(plistPath) {
    try {
        var plistXml = require('fs').readFileSync(plistPath).toString();
        var dictMatch = plistXml.match(/<dict>([\s\S]*)<\/dict>/);
        if (!dictMatch) return [];

        var dictContent = dictMatch[1];
        var keyValuePattern = /\s*<key>([^<]+)<\/key>\s*((?:<[^>]+>(?:(?!<key>)[\s\S])*?<\/[^>]+>)|(?:<[^\/]+\/>))/g;
        var match;
        var allKeyValueXml = [];

        while ((match = keyValuePattern.exec(dictContent)) !== null) {
            allKeyValueXml.push({
                key: match[1],
                xml: match[0]
            });
        }

        return allKeyValueXml;
    } catch (e) {
        logger.warn('Could not extract keys from plist: ' + e);
        return [];
    }
}

// Helper to cache plist customizations before cleanup (for surgical updates)
function cachePlistCustomizations(serviceId) {
    var daemonPlistPath = '/Library/LaunchDaemons/' + serviceId + '.plist';
    var agentPlistPath = '/Library/LaunchAgents/' + serviceId + '.plist';
    var fs = require('fs');

    var cached = {
        daemon: { allArgs: [], allKeys: [] },
        agent: { allArgs: [], allKeys: [] }
    };

    // Cache LaunchDaemon customizations
    if (fs.existsSync(daemonPlistPath)) {
        try {
            cached.daemon.allArgs = extractExtraProgramArguments(daemonPlistPath);
            cached.daemon.allKeys = extractNonStandardKeys(daemonPlistPath);
            if (cached.daemon.allArgs.length > 0 || cached.daemon.allKeys.length > 0) {
                logger.info('Cached LaunchDaemon: ' + cached.daemon.allArgs.length + ' args, ' +
                           cached.daemon.allKeys.length + ' keys');
            }
        } catch (e) {
            logger.warn('Could not cache LaunchDaemon customizations: ' + e);
        }
    }

    // Cache LaunchAgent customizations
    if (fs.existsSync(agentPlistPath)) {
        try {
            cached.agent.allArgs = extractExtraProgramArguments(agentPlistPath);
            cached.agent.allKeys = extractNonStandardKeys(agentPlistPath);
            if (cached.agent.allArgs.length > 0 || cached.agent.allKeys.length > 0) {
                logger.info('Cached LaunchAgent: ' + cached.agent.allArgs.length + ' args, ' +
                           cached.agent.allKeys.length + ' keys');
            }
        } catch (e) {
            logger.warn('Could not cache LaunchAgent customizations: ' + e);
        }
    }

    return cached;
}

// Helper to find and clean up all plists pointing to the same binary
function cleanupOrphanedPlists(installPath) {
    var binaryPath = installPath + 'meshagent';
    var bundleBinaryPath = null;

    // Dynamically discover bundle name instead of hard-coding
    var bundleName = findBundleInDirectory(installPath);
    if (bundleName) {
        bundleBinaryPath = installPath + bundleName + '/Contents/MacOS/meshagent';
    }

    var cleaned = [];

    // Check LaunchDaemons
    try {
        var daemonDir = '/Library/LaunchDaemons';
        var files = require('fs').readdirSync(daemonDir);
        for (var i = 0; i < files.length; i++) {
            // SAFETY GUARD #1: Only process plists with "meshagent" in filename
            if (files[i].endsWith('.plist') && files[i].indexOf('meshagent') !== -1) {
                var plistPath = daemonDir + '/' + files[i];
                var plistBinary = getProgramPathFromPlist(plistPath);

                // Check if plist points to our installation:
                // 1. Exact match for standalone binary
                // 2. Exact match for current bundle binary
                // 3. Any bundle in the install directory (e.g., /opt/tacticalmesh/*.app/Contents/MacOS/meshagent)
                var matchesInstallPath = false;

                // CRITICAL: Only match if plistBinary is a valid non-empty string
                // Prevents matching null===null when parse fails and no bundle exists
                if (plistBinary && plistBinary.length > 0) {
                    if (plistBinary === binaryPath || (bundleBinaryPath && plistBinary === bundleBinaryPath)) {
                        matchesInstallPath = true;
                    } else if (plistBinary.indexOf(installPath) === 0 && plistBinary.indexOf('.app/Contents/MacOS/meshagent') > 0) {
                        // Plist points to a bundle in our install directory
                        matchesInstallPath = true;
                    }
                }

                if (matchesInstallPath) {
                    // SAFETY GUARD #2: Abort if we're about to delete more than 3 plists
                    if (cleaned.length > 3) {
                        logger.error('SAFETY ABORT: Attempted to delete more than 3 LaunchDaemon plists');
                        logger.error('Already deleted: ' + cleaned.join(', '));
                        logger.error('Attempted to delete: ' + plistPath);
                        logger.error('This may indicate a bug. Stopping cleanup to prevent data loss.');
                        process.exit(1);
                    }

                    // SAFETY GUARD #6: Log what will be deleted
                    logger.warn('WILL DELETE LaunchDaemon: ' + files[i] + ' (points to ' + plistBinary + ')');

                    // This plist points to our installation - unload and delete it
                    try {
                        var serviceName = files[i].replace('.plist', '');
                        var svc = require('service-manager').manager.getService(serviceName);

                        logger.info('Unloading LaunchDaemon: ' + serviceName);
                        svc.unload();
                        svc.close();
                        logger.info('Successfully unloaded LaunchDaemon: ' + serviceName);
                    } catch (e) {
                        // Log unload errors for diagnostics (except "not loaded")
                        if (e.message && e.message.indexOf('not loaded') === -1 && e.message.indexOf('Could not find') === -1) {
                            logger.warn('Unload error for ' + serviceName + ': ' + e.message);
                        } else {
                            logger.info('LaunchDaemon not loaded: ' + serviceName + ' (OK)');
                        }
                        // Continue - will be verified in safety checks
                    }

                    require('fs').unlinkSync(plistPath);
                    cleaned.push(plistPath);
                    logger.info('Deleted: ' + plistPath);
                }
            }
        }
    } catch (e) {
        // Directory might not exist or other error
    }

    // Check LaunchAgents
    try {
        var agentDir = '/Library/LaunchAgents';
        var files = require('fs').readdirSync(agentDir);
        for (var i = 0; i < files.length; i++) {
            // SAFETY GUARD #1: Only process plists with "meshagent" in filename
            if (files[i].endsWith('.plist') && files[i].indexOf('meshagent') !== -1) {
                var plistPath = agentDir + '/' + files[i];
                var plistBinary = getProgramPathFromPlist(plistPath);

                // Check if plist points to our installation (same logic as LaunchDaemons)
                var matchesInstallPath = false;

                // CRITICAL: Only match if plistBinary is a valid non-empty string
                // Prevents matching null===null when parse fails and no bundle exists
                if (plistBinary && plistBinary.length > 0) {
                    if (plistBinary === binaryPath || (bundleBinaryPath && plistBinary === bundleBinaryPath)) {
                        matchesInstallPath = true;
                    } else if (plistBinary.indexOf(installPath) === 0 && plistBinary.indexOf('.app/Contents/MacOS/meshagent') > 0) {
                        // Plist points to a bundle in our install directory
                        matchesInstallPath = true;
                    }
                }

                if (matchesInstallPath) {
                    // SAFETY GUARD #2: Abort if we're about to delete more than 3 plists
                    if (cleaned.length > 3) {
                        logger.error('SAFETY ABORT: Attempted to delete more than 3 LaunchAgent plists');
                        logger.error('Already deleted: ' + cleaned.join(', '));
                        logger.error('Attempted to delete: ' + plistPath);
                        logger.error('This may indicate a bug. Stopping cleanup to prevent data loss.');
                        process.exit(1);
                    }

                    // SAFETY GUARD #6: Log what will be deleted
                    logger.warn('WILL DELETE LaunchAgent: ' + files[i] + ' (points to ' + plistBinary + ')');

                    // This plist points to our installation - unload and delete it
                    try {
                        var serviceName = files[i].replace('.plist', '');
                        var launchAgent = require('service-manager').manager.getLaunchAgent(serviceName);

                        logger.info('Unloading LaunchAgent: ' + serviceName);

                        // Unload for ALL logged in users, not just console user
                        var unloadedCount = 0;
                        var foundValidSessions = false;
                        try {
                            // Get logged-in users using 'users' command - returns space-separated unique usernames
                            var userSessions = require('user-sessions');
                            var child = require('child_process').execFile('/usr/bin/users', ['users']);
                            child.stdout.str = '';
                            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                            child.waitExit();

                            // Parse space-separated usernames
                            var usernames = child.stdout.str.trim().split(/\s+/).filter(function(u) { return u.length > 0; });
                            var activeUids = [];

                            // Convert usernames to UIDs
                            for (var i = 0; i < usernames.length; i++) {
                                try {
                                    var uid = userSessions.getUid(usernames[i]);
                                    if (uid && uid > 0) {
                                        activeUids.push(uid);
                                    }
                                } catch (e) {
                                    logger.warn('Could not get UID for user "' + usernames[i] + '": ' + e.message);
                                }
                            }

                            logger.info('Found ' + activeUids.length + ' active user(s)' +
                                       (usernames.length > 0 ? ' (' + usernames.join(', ') + ')' : ''));

                            // Unload LaunchAgent for each active user
                            if (activeUids.length > 0) {
                                for (var j = 0; j < activeUids.length; j++) {
                                    var uid = activeUids[j];
                                    foundValidSessions = true;
                                    try {
                                        logger.info('Attempting bootout for uid ' + uid);
                                        launchAgent.unload(uid);
                                        unloadedCount++;
                                        logger.info('Successfully booted out LaunchAgent for uid ' + uid);
                                    } catch (unloadErr) {
                                        // Agent might not be loaded for this user - that's OK
                                        if (unloadErr.message && unloadErr.message.indexOf('not loaded') === -1 && unloadErr.message.indexOf('Could not find') === -1) {
                                            logger.warn('Unload error for ' + serviceName + ' (uid ' + uid + '): ' + unloadErr.message);
                                        } else {
                                            logger.info('LaunchAgent not loaded for uid ' + uid + ' (OK)');
                                        }
                                    }
                                }
                            }

                            if (!foundValidSessions) {
                                logger.warn('No active users found, falling back to console user');
                                throw new Error('No active users');
                            }
                        } catch (enumErr) {
                            logger.warn('User enumeration failed: ' + (enumErr.message || 'unknown error') + ', falling back to console user');
                            // If we can't enumerate users, fall back to console user
                            var uid = require('user-sessions').consoleUid();
                            logger.info('Console UID: ' + uid);
                            if (uid && uid > 0) {
                                logger.info('Attempting bootout for console uid ' + uid);
                                try {
                                    launchAgent.unload(uid);
                                    unloadedCount++;
                                    logger.info('Successfully booted out LaunchAgent for console uid ' + uid);
                                } catch (consoleUnloadErr) {
                                    if (consoleUnloadErr.message && consoleUnloadErr.message.indexOf('not loaded') === -1 && consoleUnloadErr.message.indexOf('Could not find') === -1) {
                                        logger.warn('Console unload error: ' + consoleUnloadErr.message);
                                    } else {
                                        logger.info('LaunchAgent not loaded for console user (OK)');
                                    }
                                }
                            } else {
                                logger.warn('No console user found (uid: ' + uid + ')');
                            }
                        }

                        if (unloadedCount > 0) {
                            logger.info('Unloaded LaunchAgent for ' + unloadedCount + ' user(s)');
                        } else {
                            logger.warn('LaunchAgent was not unloaded for any users - may still be running!');
                        }
                    } catch (e) {
                        // Log unload errors for diagnostics (except "not loaded")
                        if (e.message && e.message.indexOf('not loaded') === -1 && e.message.indexOf('Could not find') === -1) {
                            logger.warn('Unload error for ' + serviceName + ': ' + e.message);
                        }
                        // Continue - will be verified in safety checks
                    }

                    require('fs').unlinkSync(plistPath);
                    cleaned.push(plistPath);
                    logger.info('Deleted: ' + plistPath);
                }
            }
        }
    } catch (e) {
        // Directory might not exist or other error
    }

    return cleaned;
}

// Helper to find installation directory by searching plists
// Used as fallback when service lookup fails
function findInstallationByPlist() {
    var fs = require('fs');
    var dirs = [
        '/Library/LaunchDaemons',
        '/Library/LaunchAgents'
    ];

    for (var d = 0; d < dirs.length; d++) {
        try {
            var files = fs.readdirSync(dirs[d]);
            for (var i = 0; i < files.length; i++) {
                // Only check plists that contain "meshagent" in the name
                if (files[i].endsWith('.plist') && files[i].indexOf('meshagent') !== -1) {
                    var plistPath = dirs[d] + '/' + files[i];
                    var binaryPath = getProgramPathFromPlist(plistPath);

                    // Check if this plist points to a meshagent binary
                    if (binaryPath && binaryPath.indexOf('meshagent') !== -1) {
                        // Extract directory from binary path using shared helpers
                        // For bundles: "/opt/mesh/MeshAgent.app/Contents/MacOS/meshagent" -> "/opt/mesh/"
                        // For standalone: "/opt/mesh/meshagent" -> "/opt/mesh/"
                        var installPath;
                        var bundleParent = macOSHelpers.getBundleParentDirectory(binaryPath);
                        if (bundleParent) {
                            // Bundle installation - return parent of .app
                            installPath = bundleParent;
                        } else {
                            // Standalone installation
                            var parts = binaryPath.split('/');
                            parts.pop();  // Remove 'meshagent' filename
                            installPath = parts.join('/') + '/';
                        }
                        return installPath;
                    }
                }
            }
        } catch (e) {
            // Directory might not exist or not readable - continue to next
        }
    }

    return null;
}

// Determine installation mode based on existing installation and user flags
// Returns: { mode: 'upgrade'|'fresh'|'error', path: string, reason: string, fatal: boolean }
function determineInstallMode(existingInstallPath, installPath, explicitMshPath, copyMsh, upgradeMode) {
    // Check if --mshPath or --copy-msh="1" is specified (forces fresh install with new config)
    var hasMshOverride = (explicitMshPath || copyMsh === '1');

    if (existingInstallPath && !hasMshOverride) {
        // Existing installation + no msh override → UPGRADE mode
        return {
            mode: 'upgrade',
            path: existingInstallPath,
            reason: 'UPGRADE (preserve configuration)',
            fatal: false
        };
    } else if (existingInstallPath && hasMshOverride) {
        // Existing installation + msh override → FRESH INSTALL mode
        var mshFlag = explicitMshPath ? '--mshPath' : '--copy-msh="1"';
        return {
            mode: 'fresh',
            path: existingInstallPath,
            reason: 'FRESH INSTALL (' + mshFlag + ' will overwrite configuration)',
            fatal: false
        };
    } else if (!existingInstallPath && installPath) {
        // No existing installation + explicit installPath → FRESH INSTALL
        return {
            mode: 'fresh',
            path: installPath,
            reason: 'FRESH INSTALL (no existing installation)',
            fatal: false
        };
    } else {
        // No existing installation + no installPath
        if (upgradeMode) {
            // -upgrade requires existing installation - this is an error
            return {
                mode: 'error',
                path: null,
                reason: 'No installation found at default location: /usr/local/mesh_services/meshagent/',
                fatal: true
            };
        } else {
            // -fullinstall: Default to standard location
            return {
                mode: 'fresh',
                path: '/usr/local/mesh_services/meshagent/',
                reason: 'FRESH INSTALL (default location)',
                fatal: false
            };
        }
    }
}

// Helper to recursively remove a directory and all its contents
function removeDirectoryRecursive(dirPath) {
    var fs = require('fs');

    if (!fs.existsSync(dirPath)) {
        return;
    }

    var files = fs.readdirSync(dirPath);
    for (var i = 0; i < files.length; i++) {
        var filePath = dirPath + '/' + files[i];
        var stat = fs.statSync(filePath);

        if (stat.isDirectory()) {
            // Recursively remove subdirectory
            removeDirectoryRecursive(filePath);
        } else {
            // Remove file
            fs.unlinkSync(filePath);
        }
    }

    // Remove the now-empty directory
    fs.rmdirSync(dirPath);
}

// Helper to delete installation files from a directory
// Used when uninstalling without service manager access
function deleteInstallationFiles(installPath, deleteData) {
    var fs = require('fs');
    var child_process = require('child_process');
    var logger = require('./logger');
    var deletedFiles = [];

    logger.info('Removing installation files from: ' + installPath);

    // Check if there's a bundle in this directory
    var bundleRemoved = false;
    try {
        var files = fs.readdirSync(installPath);
        for (var i = 0; i < files.length; i++) {
            if (files[i].endsWith('.app')) {
                // Found a bundle - remove it completely
                var bundlePath = installPath + files[i];
                logger.info('Removing bundle: ' + bundlePath);
                try {
                    child_process.execSync('rm -rf "' + bundlePath + '"');
                    deletedFiles.push(files[i]);
                    bundleRemoved = true;
                } catch (e) {
                    logger.warn('Could not delete bundle: ' + e);
                }
                break;  // Only one bundle expected
            }
        }
    } catch (e) {
        logger.warn('Could not scan directory for bundles: ' + e);
    }

    // Always remove .msh file (contains server URL configuration)
    try {
        var mshFile = installPath + 'meshagent.msh';
        if (fs.existsSync(mshFile)) {
            fs.unlinkSync(mshFile);
            deletedFiles.push('meshagent.msh');
        }
    } catch (e) {
        logger.warn('Could not delete .msh file: ' + e);
    }

    // If fulluninstall (deleteData=true), remove all data files
    if (deleteData) {
        // Remove DAIPC socket
        try {
            var daipSocket = installPath + 'DAIPC';
            if (fs.existsSync(daipSocket)) {
                fs.unlinkSync(daipSocket);
                deletedFiles.push('DAIPC');
            }
        } catch (e) {
            logger.warn('Could not delete DAIPC socket: ' + e);
        }

        // Remove all meshagent.* files, meshagent binary, and MeshAgent* bundles
        try {
            var files = fs.readdirSync(installPath);
            for (var i = 0; i < files.length; i++) {
                // Match: meshagent.*, meshagent (standalone binary), MeshAgent* (.app bundles and backups)
                if (files[i].startsWith('meshagent.') ||
                    files[i] === 'meshagent' ||
                    files[i].startsWith('MeshAgent')) {
                    var filePath = installPath + files[i];
                    try {
                        var stat = fs.statSync(filePath);
                        if (stat.isFile()) {
                            fs.unlinkSync(filePath);
                            deletedFiles.push(files[i]);
                        } else if (stat.isDirectory()) {
                            // Recursively remove directories (bundles, backups)
                            removeDirectoryRecursive(filePath);
                            deletedFiles.push(files[i] + '/');
                        }
                    } catch (fileErr) {
                        logger.warn('Could not delete ' + files[i] + ': ' + fileErr);
                    }
                }
            }
        } catch (e) {
            logger.warn('Could not scan directory: ' + e);
        }

        // Try to remove the installation directory itself
        try {
            fs.rmdirSync(installPath);
            logger.info('Removed installation directory: ' + installPath);
        } catch (e) {
            // Directory might not be empty (other files present) - that's okay
        }
    }

    if (deletedFiles.length > 0) {
        logger.info('Deleted ' + deletedFiles.length + ' file(s)');
    }

    return deletedFiles;
}

// Helper to delete plist files
function deletePlists(serviceId) {
    var deleted = false;

    // LaunchDaemon plist
    var daemonPlist = macOSHelpers.getPlistPath(serviceId, 'daemon');
    try {
        if (require('fs').existsSync(daemonPlist)) {
            require('fs').unlinkSync(daemonPlist);
            logger.info('Removed: ' + daemonPlist);
            deleted = true;
        }
    } catch (e) {
        logger.warn('Could not delete LaunchDaemon plist: ' + e);
    }

    // LaunchAgent plist
    var agentPlist = macOSHelpers.getPlistPath(serviceId, 'agent');
    try {
        if (require('fs').existsSync(agentPlist)) {
            require('fs').unlinkSync(agentPlist);
            logger.info('Removed: ' + agentPlist);
            deleted = true;
        }
    } catch (e) {
        logger.warn('Could not delete LaunchAgent plist: ' + e);
    }

    if (!deleted) {
        logger.info('No plist files found to delete');
    }
}

// Helper to backup existing installation (bundle or standalone binary) with timestamp
function backupInstallation(installPath) {
    var fs = require('fs');
    var timestamp = Date.now().toString();
    var backupName = null;
    var backedUpFiles = [];

    try {
        // Check for bundle and back it up using dynamic discovery
        var bundleName = findBundleInDirectory(installPath);
        if (bundleName) {
            // Backup bundle by renaming
            var bundlePath = installPath + bundleName;
            var backupPath = installPath + bundleName + '.' + timestamp;
            fs.renameSync(bundlePath, backupPath);
            backupName = bundleName + '.' + timestamp;
            backedUpFiles.push(backupName);
        }

        // Check for standalone binary and back it up (handles edge case where both exist)
        if (fs.existsSync(installPath + 'meshagent')) {
            var binaryPath = installPath + 'meshagent';
            var backupPath = installPath + 'meshagent.' + timestamp;
            fs.copyFileSync(binaryPath, backupPath);
            fs.unlinkSync(binaryPath);
            backupName = 'meshagent.' + timestamp;
            backedUpFiles.push(backupName);
        }

        // Backup .msh configuration file (if exists)
        if (fs.existsSync(installPath + 'meshagent.msh')) {
            var mshPath = installPath + 'meshagent.msh';
            var mshBackupPath = installPath + 'meshagent.msh.' + timestamp;
            fs.copyFileSync(mshPath, mshBackupPath);
            backedUpFiles.push('meshagent.msh.' + timestamp);
        }

        // Backup .db database file (if exists)
        if (fs.existsSync(installPath + 'meshagent.db')) {
            var dbPath = installPath + 'meshagent.db';
            var dbBackupPath = installPath + 'meshagent.db.' + timestamp;
            fs.copyFileSync(dbPath, dbBackupPath);
            backedUpFiles.push('meshagent.db.' + timestamp);
        }

        return { primary: backupName, files: backedUpFiles };
    } catch (e) {
        var errorMsg = 'Could not backup installation: ';
        if (e && e.message) {
            errorMsg += e.message;
        } else if (e && typeof e === 'string') {
            errorMsg += e;
        } else {
            errorMsg += JSON.stringify(e) || 'Unknown error';
        }
        throw new Error(errorMsg);
    }
}

// Helper to recursively copy a directory
function copyDirectoryRecursive(source, target) {
    var fs = require('fs');

    // Create target directory
    if (!fs.existsSync(target)) {
        fs.mkdirSync(target, { recursive: true });
    }

    // Copy directory permissions
    var stats = fs.statSync(source);
    fs.chmodSync(target, stats.mode);

    // Read directory contents
    var files = fs.readdirSync(source);

    for (var i = 0; i < files.length; i++) {
        var file = files[i];
        var sourcePath = path.join(source, file);
        var targetPath = path.join(target, file);
        var fileStats = fs.statSync(sourcePath);

        if (fileStats.isDirectory()) {
            // Recursively copy subdirectory
            copyDirectoryRecursive(sourcePath, targetPath);
        } else {
            // Copy file
            fs.copyFileSync(sourcePath, targetPath);
            // Preserve permissions
            fs.chmodSync(targetPath, fileStats.mode);
        }
    }
}

// Helper to replace installation (bundle or standalone binary)
function replaceInstallation(sourceType, installPath) {

    var fs = require('fs');
    var child_process = require('child_process');
    var logger = require('./logger');

    try {
        // Ensure installation directory exists (create if needed)
        if (!fs.existsSync(installPath)) {
            logger.info('Creating installation directory structure:');
            logger.info('  Target: ' + installPath);

            // Show which parent directories need to be created
            var pathParts = installPath.split('/').filter(function(p) { return p.length > 0; });
            var buildPath = '/';
            var newDirs = [];

            for (var i = 0; i < pathParts.length; i++) {
                buildPath += pathParts[i] + '/';
                if (!fs.existsSync(buildPath)) {
                    newDirs.push(buildPath);
                }
            }

            if (newDirs.length > 0) {
                logger.info('  Creating ' + newDirs.length + ' director' + (newDirs.length === 1 ? 'y' : 'ies') + ':');
                for (var j = 0; j < newDirs.length; j++) {
                    logger.info('    ' + newDirs[j]);
                }
            }

            // Create directories one at a time (recursive option doesn't work in embedded JS engine)
            for (var k = 0; k < newDirs.length; k++) {
                try {
                    fs.mkdirSync(newDirs[k]);
                    fs.chmodSync(newDirs[k], 0o755);
                } catch (mkdirErr) {
                    // If directory already exists, that's OK (race condition)
                    if (mkdirErr.code !== 'EEXIST') {
                        throw new Error('Could not create directory ' + newDirs[k] + ': ' + mkdirErr.message);
                    }
                }
            }

            logger.info('Installation directory created successfully');
        } else {
            logger.info('Installation directory already exists: ' + installPath);
        }

        if (sourceType.type === 'bundle') {

            // Copy entire bundle - always install as MeshAgent.app
            var sourceBundlePath = sourceType.bundlePath;
            var sourceBundleName = sourceBundlePath.substring(sourceBundlePath.lastIndexOf('/') + 1);

            // Always use standard bundle name regardless of source name
            var targetBundlePath = installPath + 'MeshAgent.app';

            logger.info('Installing bundle: ' + sourceBundleName + ' → MeshAgent.app');

            // Source bundle should already be backed up by backupInstallation()
            // Just copy the new bundle
            logger.info('Copying application bundle');

            // Use ditto on macOS to properly copy app bundles with all attributes
            // ditto preserves resource forks, extended attributes, ACLs, metadata, and code signatures

            var dittoError = null;
            var child = child_process.execFile('/usr/bin/ditto', ['ditto', sourceType.bundlePath, targetBundlePath]);
            child.stdout.on('data', function(d) { logger.debug('[DITTO] ' + d.toString().trim()); });
            child.stderr.on('data', function(d) { dittoError = d.toString(); logger.warn('[DITTO] ' + dittoError.trim()); });
            child.waitExit();

            // Check if bundle was actually copied by verifying the binary exists
            var binaryPath = targetBundlePath + '/Contents/MacOS/meshagent';
            if (!fs.existsSync(binaryPath)) {
                throw new Error('Bundle copy failed. ' + (dittoError || 'Binary not found after copy'));
            }

            // Ensure binary is executable with secure permissions
            var binaryResult = securityPermissions.setSecurePermissions(binaryPath, 'binary');
            if (!binaryResult.success) {
                logger.warn('Could not set binary permissions: ' + binaryResult.errors.join(', '));
            }
            logger.info('Bundle installed: ' + targetBundlePath);
        } else {
            // Copy standalone binary
            var targetBinaryPath = installPath + 'meshagent';
            var sourceBinaryPath = sourceType.binaryPath;

            // Check if we're trying to copy the binary over itself (self-upgrade)
            if (sourceBinaryPath === targetBinaryPath) {
                logger.info('Skipping binary copy (self-upgrade: binary already in place)');
                return;
            }

            // Old binary should already be backed up by backupInstallation()
            // Copy new binary to install location
            logger.info('Copying standalone binary');

            // Use ditto on macOS to properly copy binary with all attributes
            // ditto also automatically creates parent directories if they don't exist
            var dittoError = null;
            var child = child_process.execFile('/usr/bin/ditto', ['ditto', sourceBinaryPath, targetBinaryPath]);
            child.stdout.on('data', function(d) { logger.debug('[DITTO] ' + d.toString().trim()); });
            child.stderr.on('data', function(d) { dittoError = d.toString(); logger.warn('[DITTO] ' + dittoError.trim()); });
            child.waitExit();

            // Check if binary was actually copied
            if (!fs.existsSync(targetBinaryPath)) {
                throw new Error('Binary copy failed. ' + (dittoError || 'Binary not found after copy'));
            }

            // Ensure executable permissions with secure ownership
            var binaryResult = securityPermissions.setSecurePermissions(targetBinaryPath, 'binary');
            if (!binaryResult.success) {
                logger.warn('Could not set binary permissions: ' + binaryResult.errors.join(', '));
            }

            logger.info('Binary installed: ' + targetBinaryPath);
        }
    } catch (e) {
        var errorMsg = 'Could not replace installation: ';
        if (e && e.message) {
            errorMsg += e.message;
        } else if (e && typeof e === 'string') {
            errorMsg += e;
        } else {
            errorMsg += JSON.stringify(e) || 'Unknown error';
        }
        throw new Error(errorMsg);
    }
}

// Verify service is NOT loaded in launchd (prevents restart after kill)
// Returns: { loaded: true/false, domain: 'system'/'gui/501'/null }
function verifyServiceUnloaded(serviceId, maxAttempts) {
    maxAttempts = maxAttempts || 3;
    var child_process = require('child_process');

    for (var attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            // Check system domain (LaunchDaemon)
            try {
                var output = child_process.execSync('launchctl print system/' + serviceId + ' 2>/dev/null', { encoding: 'utf8' });
                if (output && output.indexOf('state = ') !== -1) {
                    return { loaded: true, domain: 'system' };
                }
            } catch (e) {
                // Not found in system domain (expected after unload)
            }

            // Check gui domain (LaunchAgent - check all user sessions)
            try {
                var sessions = require('user-sessions').enumerateUsers();
                for (var i = 0; i < sessions.length; i++) {
                    var uid = sessions[i].uid;
                    try {
                        var agentId = serviceId + '-agent'; // LaunchAgent has -agent suffix
                        var agentOutput = child_process.execSync('launchctl print gui/' + uid + '/' + agentId + ' 2>/dev/null', { encoding: 'utf8' });
                        if (agentOutput && agentOutput.indexOf('state = ') !== -1) {
                            return { loaded: true, domain: 'gui/' + uid };
                        }
                    } catch (e) {
                        // Not found for this user (expected)
                    }
                }
            } catch (e) {
                // user-sessions might fail, that's OK
            }

            // Not found in any domain - successfully unloaded!
            return { loaded: false, domain: null };

        } catch (e) {
            if (attempt < maxAttempts) {
                child_process.execSync('sleep 0.5');
            }
        }
    }

    // After max attempts, assume not loaded
    return { loaded: false, domain: null };
}

// Force bootout service from launchd using explicit domain
function forceBootoutService(serviceId, domain) {
    var child_process = require('child_process');

    try {
        if (domain === 'system') {
            logger.info('Forcing bootout from system domain...');
            child_process.execSync('launchctl bootout system/' + serviceId + ' 2>/dev/null', { encoding: 'utf8' });
        } else if (domain && domain.startsWith('gui/')) {
            var agentId = serviceId + '-agent';
            logger.info('Forcing bootout from ' + domain + '...');
            child_process.execSync('launchctl bootout ' + domain + '/' + agentId + ' 2>/dev/null', { encoding: 'utf8' });
        }

        // Give launchd time to process
        child_process.execSync('sleep 1');

        return true;
    } catch (e) {
        logger.warn('Bootout failed: ' + e.message);
        return false;
    }
}

// Verify no meshagent processes are running from specific path
// Uses lsof to verify actual executable path (won't touch other installations)
// Returns: { success: true/false, pids: [array of PIDs from binaryPath] }
function verifyProcessesTerminated(binaryPath, maxWaitSeconds) {
    var startTime = Date.now();
    var timeout = maxWaitSeconds * 1000;
    var child_process = require('child_process');

    while (Date.now() - startTime < timeout) {
        try {
            // Step 1: Get ALL meshagent PIDs
            var output = child_process.execSync('pgrep -x meshagent 2>/dev/null', { encoding: 'utf8' });
            var allPids = output.trim().split('\n').map(function(p) {
                return parseInt(p);
            }).filter(function(p) {
                return !isNaN(p);
            });

            if (allPids.length === 0) {
                return { success: true, pids: [] };
            }

            // Step 2: For each PID, get actual executable path using lsof
            var matchingPids = [];
            for (var i = 0; i < allPids.length; i++) {
                var pid = allPids[i];
                try {
                    // lsof shows actual file being executed
                    var lsofCmd = 'lsof -p ' + pid + ' 2>/dev/null | grep txt | awk \'{print $NF}\'';
                    var exePath = child_process.execSync(lsofCmd, { encoding: 'utf8' }).trim();

                    // Step 3: Only include if it matches our binaryPath
                    if (exePath === binaryPath) {
                        matchingPids.push(pid);
                    }
                } catch (e) {
                    // lsof failed for this PID (might have exited already)
                }
            }

            if (matchingPids.length === 0) {
                return { success: true, pids: [] };
            }

            // Still have processes from our path, wait and retry
            child_process.execSync('sleep 0.5');

        } catch (e) {
            // pgrep failed (no meshagent processes at all)
            return { success: true, pids: [] };
        }
    }

    // Timeout reached - get final list of matching PIDs
    try {
        var output = child_process.execSync('pgrep -x meshagent 2>/dev/null', { encoding: 'utf8' });
        var allPids = output.trim().split('\n').map(function(p) {
            return parseInt(p);
        }).filter(function(p) {
            return !isNaN(p);
        });

        var matchingPids = [];
        for (var i = 0; i < allPids.length; i++) {
            var pid = allPids[i];
            try {
                var lsofCmd = 'lsof -p ' + pid + ' 2>/dev/null | grep txt | awk \'{print $NF}\'';
                var exePath = child_process.execSync(lsofCmd, { encoding: 'utf8' }).trim();
                if (exePath === binaryPath) {
                    matchingPids.push(pid);
                }
            } catch (e) {}
        }

        return { success: false, pids: matchingPids };
    } catch (e) {
        return { success: true, pids: [] };
    }
}

// Force kill meshagent processes (ONLY safe after launchd unload verified)
function forceKillProcesses(pids) {
    var child_process = require('child_process');

    if (pids.length === 0) return true;

    logger.info('Forcing termination of ' + pids.length + ' process(es): ' + pids.join(', '));

    var allKilled = true;
    for (var i = 0; i < pids.length; i++) {
        try {
            process.kill(pids[i], 9); // SIGKILL
            logger.info('Killed PID ' + pids[i]);
        } catch (e) {
            logger.warn('Failed to kill PID ' + pids[i] + ': ' + e.message);
            allKilled = false;
        }
    }

    // Give system time to clean up
    child_process.execSync('sleep 1');

    return allKilled;
}

// Helper to create LaunchDaemon
function createLaunchDaemon(serviceName, companyName, installPath, serviceId, installType, surgical, cachedCustomizations, meshAgentLogging) {
    var logger = require('./logger');

    logger.info('[CREATE-DAEMON] Starting LaunchDaemon creation');
    logger.info('[CREATE-DAEMON] serviceName=' + serviceName + ', serviceId=' + serviceId + ', installType=' + installType + ', surgical=' + surgical);

    try {
        // Determine binary path based on installation type
        var servicePath;
        var options = {
            name: serviceName,
            target: 'meshagent',
            startType: 'AUTO_START',
            parameters: [],  // serviceId from .msh, appBundle auto-detected
            companyName: companyName,
            surgicalUpdate: surgical,  // Enable surgical plist updates (preserve customizations)
            meshAgentLogging: meshAgentLogging  // Enable launchd logging to /tmp
        };

        // Pass cached customizations if available (for surgical updates)
        if (cachedCustomizations && cachedCustomizations.daemon) {
            options.cachedCustomizations = cachedCustomizations.daemon;
            logger.info('[CREATE-DAEMON] Passing cached customizations to service-manager');
        }

        if (installType === 'bundle') {
            // For bundle installations, reference the binary inside the bundle
            // Dynamically discover bundle name instead of hard-coding
            var bundleName = findBundleInDirectory(installPath);
            if (!bundleName) {
                throw new Error('Bundle installation type specified but no bundle found at: ' + installPath);
            }
            servicePath = installPath + bundleName + '/Contents/MacOS/meshagent';
            options.servicePath = servicePath;
            // WorkingDirectory must be parent of bundle, not inside it
            options.installPath = installPath;
            options.target = 'meshagent';
            // For bundle installations, do NOT copy binary to installPath - binary should stay inside bundle
            options.skipBinaryCopy = true;
            // Note: appBundle mode is auto-detected via is_running_from_bundle() in C code
        } else {
            // For standalone installations, let service-manager copy the binary if needed
            servicePath = installPath + 'meshagent';
            options.servicePath = servicePath;
            options.installPath = installPath;
        }

        logger.info('[CREATE-DAEMON] Calling service-manager.installService with options: ' + JSON.stringify(options));
        require('service-manager').manager.installService(options);
        logger.info('[CREATE-DAEMON] LaunchDaemon created successfully');
    } catch (e) {
        var errorMsg = 'Could not create LaunchDaemon: ';
        if (e && e.message) {
            errorMsg += e.message;
        } else if (e && typeof e === 'string') {
            errorMsg += e;
        } else {
            errorMsg += JSON.stringify(e) || 'Unknown error';
        }
        throw new Error(errorMsg);
    }
}

// Helper to create LaunchAgent
function createLaunchAgent(serviceName, companyName, installPath, serviceId, installType, surgical, cachedCustomizations, meshAgentLogging) {
    var logger = require('./logger');

    try {
        // Determine binary path based on installation type
        var servicePath;
        var options = {
            name: serviceName,
            companyName: companyName,
            startType: 'AUTO_START',
            sessionTypes: ['Aqua', 'LoginWindow'],
            parameters: ['-kvm1', '--serviceId=' + serviceId],
            surgicalUpdate: surgical,  // Enable surgical plist updates (preserve customizations)
            meshAgentLogging: meshAgentLogging  // Enable launchd logging to /tmp
        };

        // Pass cached customizations if available (for surgical updates)
        if (cachedCustomizations && cachedCustomizations.agent) {
            options.cachedCustomizations = cachedCustomizations.agent;
            logger.info('[CREATE-AGENT] Passing cached customizations to service-manager');
        }

        if (installType === 'bundle') {
            // Dynamically discover bundle name instead of hard-coding
            var bundleName = findBundleInDirectory(installPath);
            if (!bundleName) {
                throw new Error('Bundle installation type specified but no bundle found at: ' + installPath);
            }
            servicePath = installPath + bundleName + '/Contents/MacOS/meshagent';
            // WorkingDirectory must be parent of bundle, not inside it
            options.workingDirectory = installPath;
            // For bundle installations, do NOT copy binary to installPath - binary should stay inside bundle
            options.skipBinaryCopy = true;
        } else {
            servicePath = installPath + 'meshagent';
        }

        options.servicePath = servicePath;

        require('service-manager').manager.installLaunchAgent(options);
        logger.info('LaunchAgent created');
    } catch (e) {
        var errorMsg = 'Could not create LaunchAgent: ';
        if (e && e.message) {
            errorMsg += e.message;
        } else if (e && typeof e === 'string') {
            errorMsg += e;
        } else {
            errorMsg += JSON.stringify(e) || 'Unknown error';
        }
        throw new Error(errorMsg);
    }
}

// Helper to bootstrap/start services
function bootstrapServices(serviceId) {
    var logger = require('./logger');

    // Load LaunchDaemon
    try {
        var svc = require('service-manager').manager.getService(serviceId);
        svc.load();
        svc.start();
        logger.info('LaunchDaemon started');
        svc.close();
    } catch (e) {
        logger.warn('Could not start LaunchDaemon: ' + e);
    }

    // Bootstrap LaunchAgent
    try {
        var uid = require('user-sessions').consoleUid();

        if (uid && uid > 0) {
            // LaunchAgent name has '-agent' suffix
            var launchAgent = require('service-manager').manager.getLaunchAgent(serviceId + '-agent');
            launchAgent.load(uid);
            logger.info('LaunchAgent started');
        } else {
            logger.info('LaunchAgent will start at next user login');
        }
    } catch (e) {
        logger.warn('Could not start LaunchAgent: ' + e);
    }
}

// ===== END UPGRADE HELPER FUNCTIONS =====

// ===== UNIFIED INSTALL/UPGRADE (macOS) =====
// This function merges install and upgrade logic for macOS
// Future: Will be migrated to Linux, then Windows
function installServiceUnified(params) {

    // Register cleanup handler for launchctl job (runs on ANY exit)
    // This removes the meshagent.upgrade job and terminates the process cleanly
    var cleanupRegistered = false;
    process.once('exit', function() {
        if (!cleanupRegistered) {
            cleanupRegistered = true;
            try {
                require('child_process').execFile('/bin/launchctl', ['launchctl', 'remove', 'meshagent.upgrade']);
            } catch (ex) {
                // Ignore errors
            }
        }
    });

    // Parse JSON string from C code (same as fullInstall)
    var parms = JSON.parse(params);

    var child_process = require('child_process');
    var fs = require('fs');

    // Configure logger output mode from command line flags
    configureLoggerFromParams(parms);

    // Verify root permissions
    var userSessions = require('user-sessions');
    var effectiveUid = userSessions.Self();
    logger.info('Installer running as UID: ' + effectiveUid + ' (isRoot: ' + userSessions.isRoot() + ')');

    if (!userSessions.isRoot()) {
        logger.error('Installation/upgrade requires root privileges. Please run with sudo.');
        logger.result(false, 'Installation failed - root privileges required');
        process.exit(1);
    }

    // Detect source type (bundle or standalone binary)
    var sourceType = detectSourceType();

    // Log source information
    if (sourceType.type === 'bundle') {
        logger.info('Running from bundle: ' + sourceType.bundlePath);
    } else {
        // For standalone, show the directory (not full binary path for cleaner output)
        var binaryDir = sourceType.binaryPath.substring(0, sourceType.binaryPath.lastIndexOf('/'));
        logger.info('Running as standalone binary from: ' + binaryDir);
    }

    // Normalize parameters (handles --serviceName alias, etc.)
    checkParameters(parms);

    // Parse key parameters
    var installPath = parms.getParameter('installPath', null);
    var explicitInstallPathProvided = (installPath !== null);

    // Normalize installPath (ensure trailing slash)
    if (installPath) {
        installPath = normalizeInstallPath(installPath);
        logger.info('Using explicit --installPath: ' + installPath);
    } else {
        // No explicit installPath - will construct from serviceName/companyName if provided
        logger.info('No --installPath specified, will use default or construct from service/company names');
    }

    var newServiceName = parms.getParameter('meshServiceName', null);
    var newCompanyName = parms.getParameter('companyName', null);
    var newServiceId = parms.getParameter('serviceId', null);
    var disableUpdateParam = parms.getParameter('disableUpdate', null);
    var disableTccCheckParam = parms.getParameter('disableTccCheck', null);
    var meshAgentLoggingParam = parms.getParameter('meshAgentLogging', null);
    var copyMsh = parms.getParameter('copy-msh', null);
    var explicitMshPath = parms.getParameter('mshPath', null);  // Explicit path to .msh file
    // Check for --backup flag to enable backup of existing installation
    // Default behavior: NO backup (for speed and simplicity)
    // C code converts simple flag --backup to --backup=1 when passing to JavaScript
    var backupParam = parms.getParameter('backup', null);
    var createBackup = (backupParam === '1' || backupParam === 'true');
    var upgradeMode = (parms.indexOf('--_upgradeMode=1') >= 0);

    // Parse --allowNoMsh flag: allows install without valid .msh configuration (agent will wait for config)
    var allowNoMshParam = parms.getParameter('allowNoMsh', null);
    var allowNoMsh = (parms.indexOf('--allowNoMsh') >= 0) ||
                     (allowNoMshParam === '1' || allowNoMshParam === 'true');

    // Parse --disableUpdate parameter: null=not specified, true=disable, false=enable, 'clear'=write blank
    var disableUpdate = null;
    if (disableUpdateParam === '1' || disableUpdateParam === 'true') {
        disableUpdate = true;
    } else if (disableUpdateParam === '0' || disableUpdateParam === 'false') {
        disableUpdate = false;
    } else if (disableUpdateParam === '') {
        disableUpdate = 'clear';  // Explicitly provided with blank value - write blank to .msh
    }

    // Parse --disableTccCheck parameter: null=not specified, true=disable, false=enable, 'clear'=write blank
    var disableTccCheck = null;
    if (disableTccCheckParam === '1' || disableTccCheckParam === 'true') {
        disableTccCheck = true;
    } else if (disableTccCheckParam === '0' || disableTccCheckParam === 'false') {
        disableTccCheck = false;
    } else if (disableTccCheckParam === '') {
        disableTccCheck = 'clear';  // Explicitly provided with blank value - write blank to .msh
    }

    // Parse --meshAgentLogging parameter: enable launchd logging to /tmp for debugging
    var meshAgentLogging = (meshAgentLoggingParam === '1' || meshAgentLoggingParam === 'true');

    // Determine operation mode
    var isFreshInstall = false;
    var isUpgrade = false;
    var currentServiceName = 'meshagent';
    var currentCompanyName = null;
    var currentServiceId = null;
    var existingInstallPath = null;
    var sourceMshFile = null;  // Path to .msh file (found during early validation)

    // Detect operation type
    var isLocalService = (parms.indexOf('--_localService="1"') >= 0 || parms.indexOf('--_localService=\\"1\\"') >= 0);

    // OPTIMIZATION: For -install without explicit params, check for in-place .msh file FIRST
    // This prevents spurious errors and avoids wrong-location upgrades
    if (isLocalService && !installPath && !newServiceName && !newCompanyName) {
        // Check for .msh file in current directory for in-place install
        if (sourceType.type === 'bundle') {
            var bundleDir = sourceType.bundlePath.substring(0, sourceType.bundlePath.lastIndexOf('/'));
            sourceMshFile = bundleDir + '/meshagent.msh';
            installPath = bundleDir + '/';
        } else {
            var binaryDir = sourceType.binaryPath.substring(0, sourceType.binaryPath.lastIndexOf('/'));
            sourceMshFile = binaryDir + '/meshagent.msh';
            installPath = binaryDir + '/';
        }

        if (fs.existsSync(sourceMshFile)) {
            // In-place install - skip findInstallation() entirely
            isFreshInstall = true;
            logger.info('Mode: FRESH INSTALL (in-place, .msh file found)');
        } else {
            // No .msh file - fallback to findInstallation()
            logger.error('.msh file not found at: ' + sourceMshFile);
            logger.error('For -install without --installPath, place meshagent.msh next to the binary');
            logger.result(false, 'Installation failed - .msh file not found');
            process.exit(1);
        }
    } else {
        // Not an in-place install scenario - construct installPath from service/company names if not provided
        if (!installPath && (newServiceName || newCompanyName)) {
            // Construct path following pattern: /usr/local/mesh_services/{company}/{service}/
            var sanitizedServiceName = macOSHelpers.sanitizeIdentifier(newServiceName || 'meshagent');
            var sanitizedCompanyName = macOSHelpers.sanitizeIdentifier(newCompanyName);

            if (sanitizedCompanyName) {
                // Company provided: /usr/local/mesh_services/{company}/{service}/
                installPath = '/usr/local/mesh_services/' + sanitizedCompanyName + '/' + sanitizedServiceName + '/';
                logger.info('Constructed installPath from company and service names:');
                logger.info('  Company: "' + newCompanyName + '" → "' + sanitizedCompanyName + '"');
                logger.info('  Service: "' + (newServiceName || 'meshagent') + '" → "' + sanitizedServiceName + '"');
                logger.info('  Path: ' + installPath);
            } else if (sanitizedServiceName && sanitizedServiceName !== 'meshagent') {
                // No company, custom service: /usr/local/mesh_services/{service}/
                installPath = '/usr/local/mesh_services/' + sanitizedServiceName + '/';
                logger.info('Constructed installPath from service name:');
                logger.info('  Service: "' + newServiceName + '" → "' + sanitizedServiceName + '"');
                logger.info('  Path: ' + installPath);
            } else {
                // Default path for standard meshagent installation
                installPath = '/usr/local/mesh_services/meshagent/';
                logger.info('Using default installPath: ' + installPath);
            }
        }

        // Try to find existing installation
        try {
            existingInstallPath = findInstallation(installPath, newServiceName, newCompanyName);
        } catch (e) {
        }

        // IMPORTANT: Don't treat the source binary's location as an "existing installation"
        // This prevents the installer from doing a "self-upgrade" when running -fullinstall
        // from a distribution bundle (e.g., downloaded to /Downloads) that happens to have
        // a leftover plist from a previous test installation pointing to the same location.
        // For fresh installs, we want to install to the DEFAULT location, not the source location.
        if (existingInstallPath) {
            var sourceParent;
            if (sourceType.type === 'bundle') {
                sourceParent = macOSHelpers.getBundleParentDirectory(sourceType.binaryPath);
            } else {
                sourceParent = sourceType.binaryPath.substring(0, sourceType.binaryPath.lastIndexOf('/') + 1);
            }

            logger.debug('[SOURCE-CHECK] existingInstallPath=' + existingInstallPath);
            logger.debug('[SOURCE-CHECK] sourceParent=' + sourceParent);
            logger.debug('[SOURCE-CHECK] match=' + (existingInstallPath === sourceParent));

            if (existingInstallPath === sourceParent) {
                logger.info('Ignoring source location as existing installation (use --installPath to override)');
                existingInstallPath = null;
            }
        }

        // Determine operation mode based on existing installation and flags
        var installMode = determineInstallMode(existingInstallPath, installPath, explicitMshPath, copyMsh, upgradeMode);

        if (installMode.fatal) {
            // Fatal error - cannot proceed
            logger.error(installMode.reason);
            logger.error('Please specify --installPath, --serviceName, or --companyName');
            logger.result(false, 'Installation failed - cannot determine target location');
            process.exit(1);
        }

        // Set mode flags and path based on determination
        isUpgrade = (installMode.mode === 'upgrade');
        isFreshInstall = (installMode.mode === 'fresh');
        installPath = installMode.path;

        // Log the determined mode
        if (existingInstallPath) {
            logger.info('Existing installation detected at: ' + existingInstallPath);
        } else if (installPath) {
            logger.info('No existing installation found at: ' + installPath);
        }
        logger.info('Mode: ' + installMode.reason);
        if (!existingInstallPath && installPath) {
            logger.info('Target installation path: ' + installPath);
        }
    }

    // EARLY VALIDATION: Check for .msh file if --mshPath or --copy-msh="1" is specified
    // Priority: --mshPath (explicit path) takes precedence over --copy-msh="1" (auto-detect)
    if (explicitMshPath) {
        // Mode 1: Explicit path provided via --mshPath parameter
        logger.info('Using explicit .msh file path: ' + explicitMshPath);

        // Validate the file exists
        if (!fs.existsSync(explicitMshPath)) {
            logger.error('Specified .msh file not found: ' + explicitMshPath);
            logger.error('Please verify the path and try again.');
            process.exit(1);
        }

        // Warn if file doesn't have .msh extension (case-insensitive)
        if (!explicitMshPath.toLowerCase().endsWith('.msh')) {
            logger.warn('Warning: Specified file does not have .msh extension: ' + explicitMshPath);
        }

        sourceMshFile = explicitMshPath;
    } else if (copyMsh === '1') {
        // Mode 2: Auto-detect .msh file in binary's directory
        // Determine search directory based on bundle vs standalone:
        //   - Bundle mode (.app): Parent directory of the .app bundle
        //   - Standalone mode: Directory containing the binary
        var searchDir;
        var searchName;
        var bundleMarker = '.app/Contents/MacOS/';
        var appIndex = process.execPath.indexOf(bundleMarker);
        if (appIndex !== -1) {
            // Running from bundle - extract parent directory of .app
            // E.g., /Applications/MeshAgent.app/Contents/MacOS/meshagent -> /Applications/
            var bundlePath = process.execPath.substring(0, appIndex + 4); // Include '.app'
            searchDir = bundlePath.substring(0, bundlePath.lastIndexOf('/'));

            // Extract bundle name (without .app extension) for .msh file matching
            // E.g., /Applications/MeshAgent67.app -> MeshAgent67
            var bundleName = bundlePath.substring(bundlePath.lastIndexOf('/') + 1);
            searchName = bundleName.substring(0, bundleName.length - 4); // Remove '.app'

            logger.info('Bundle mode: searching for .msh based on bundle name: ' + bundleName);
        } else {
            // Standalone binary - use binary's directory and name
            searchDir = process.execPath.substring(0, process.execPath.lastIndexOf('/'));
            searchName = process.execPath.substring(process.execPath.lastIndexOf('/') + 1);

            logger.info('Standalone mode: searching for .msh based on binary name: ' + searchName);
        }

        // Step 1: Try bundle/binary-specific name first
        //   - Bundle: {BundleName}.msh (e.g., MeshAgent67.msh for MeshAgent67.app)
        //   - Standalone: {BinaryName}.msh (e.g., meshagent_osx-universal-64.msh)
        sourceMshFile = findFileCaseInsensitive(searchDir, searchName + '.msh');

        // Step 2: Try generic meshagent.msh (case-insensitive)
        if (!sourceMshFile) {
            sourceMshFile = findFileCaseInsensitive(searchDir, 'meshagent.msh');
        }

        // Step 3: Look for any .msh file (if steps 1 & 2 failed)
        if (!sourceMshFile) {
            var files = fs.readdirSync(searchDir);
            var mshFiles = files.filter(function(f) {
                return f.toLowerCase().endsWith('.msh');
            });

            if (mshFiles.length === 1) {
                // Exactly one .msh file - use it
                sourceMshFile = searchDir + '/' + mshFiles[0];
                logger.info('Using discovered .msh file: ' + mshFiles[0]);
            } else if (mshFiles.length > 1) {
                // Multiple .msh files and none match preferred names
                logger.error('Multiple .msh files found: ' + mshFiles.join(', '));
                logger.error('Please rename one to:');
                logger.error('  - ' + searchName + '.msh (preferred)');
                logger.error('  - meshagent.msh (generic)');
                logger.error('Or use --mshPath=/path/to/specific.msh');
                process.exit(1);
            } else {
                // No .msh files found at all
                logger.error('No .msh file found in: ' + searchDir);
                logger.error('Expected: ' + searchName + '.msh or meshagent.msh');
                logger.error('Please place the .msh file next to the bundle/binary and try again.');
                process.exit(1);
            }
        }

        logger.info('Found source .msh file: ' + sourceMshFile);
    }


    // MSH CONFIGURATION VALIDATION (unless --allowNoMsh is specified)
    // For fresh installs: require sourceMshFile with valid settings
    // For upgrades: validate existing .db has required settings
    if (!allowNoMsh) {
        var hasValidConfig = false;
        var validationResult = { valid: false, missing: [] };

        if (isFreshInstall) {
            // Fresh install: MUST have a source .msh file with valid settings
            if (!sourceMshFile) {
                logger.error('Fresh install requires a .msh configuration file');
                logger.error('Options:');
                logger.error('  1. Use --copy-msh=1 and place .msh file next to the binary');
                logger.error('  2. Use --mshPath=/path/to/file.msh to specify explicit location');
                logger.error('  3. Use --allowNoMsh=1 to install without config (agent will wait for .msh)');
                logger.result(false, 'Installation failed - no .msh configuration file');
                process.exit(1);
            }

            // Validate the source .msh file has required settings
            validationResult = validateMshConfig(sourceMshFile);
            hasValidConfig = validationResult.valid;

            if (!hasValidConfig) {
                logger.error('Invalid .msh configuration: ' + sourceMshFile);
                logger.error('Missing required settings: ' + validationResult.missing.join(', '));
                logger.error('Required: MeshServer, MeshID, ServerID');
                logger.error('Use --allowNoMsh=1 to install without configuration (agent will wait for .msh)');
                logger.result(false, 'Installation failed - invalid configuration');
                process.exit(1);
            }
            logger.info('MSH configuration validated: MeshServer, MeshID, ServerID present');
        } else if (isUpgrade) {
            // Upgrade: check existing .db file for required settings
            logger.info('=== UPGRADE VALIDATION START ===');
            logger.info('installPath: ' + installPath);
            logger.info('sourceMshFile: ' + (sourceMshFile || 'NOT SET'));

            var dbPath = installPath + 'meshagent.db';
            logger.info('Checking for existing .db at: ' + dbPath);

            if (fs.existsSync(dbPath)) {
                logger.info('.db file EXISTS, attempting to read settings...');
                try {
                    var db = require('SimpleDataStore').Create(dbPath);
                    var meshServer = db.Get('MeshServer');
                    var meshId = db.Get('MeshID');
                    var serverId = db.Get('ServerID');

                    logger.info('DB read results: MeshServer=' + (meshServer ? 'PRESENT' : 'MISSING') +
                                ', MeshID=' + (meshId ? 'PRESENT' : 'MISSING') +
                                ', ServerID=' + (serverId ? 'PRESENT' : 'MISSING'));

                    if (meshServer && meshId && serverId) {
                        hasValidConfig = true;
                        logger.info('Existing .db configuration validated - VALID');
                    } else {
                        logger.warn('Existing .db configuration INCOMPLETE');
                        if (!meshServer) validationResult.missing.push('MeshServer');
                        if (!meshId) validationResult.missing.push('MeshID');
                        if (!serverId) validationResult.missing.push('ServerID');
                    }
                } catch (e) {
                    logger.warn('Could not read existing .db: ' + e);
                }
            } else {
                logger.info('.db file does NOT exist');
            }

            // For upgrade, also check if a new .msh file is being provided
            if (!hasValidConfig && sourceMshFile) {
                logger.info('Checking sourceMshFile: ' + sourceMshFile);
                validationResult = validateMshConfig(sourceMshFile);
                hasValidConfig = validationResult.valid;
                logger.info('sourceMshFile validation result: ' + (hasValidConfig ? 'VALID' : 'INVALID'));
            }

            // If still no valid config, check for existing .msh at installation location
            // (mirrors install mode logic - lines 1851-1862)
            if (!hasValidConfig) {
                var mshPath = installPath + 'meshagent.msh';
                logger.info('Checking for existing .msh at installation location: ' + mshPath);

                if (fs.existsSync(mshPath)) {
                    logger.info('Existing .msh file found, validating...');
                    validationResult = validateMshConfig(mshPath);
                    hasValidConfig = validationResult.valid;

                    if (hasValidConfig) {
                        logger.info('Existing .msh configuration validated - VALID');
                    } else {
                        logger.warn('Existing .msh configuration INVALID');
                        logger.warn('Missing settings: ' + validationResult.missing.join(', '));
                    }
                } else {
                    logger.info('No .msh file exists at installation location');
                }
            }

            logger.info('Final hasValidConfig: ' + hasValidConfig);
            logger.info('=== UPGRADE VALIDATION END ===');

            if (!hasValidConfig) {
                logger.error('Cannot upgrade: no valid configuration found');
                if (validationResult.missing.length > 0) {
                    logger.error('Missing required settings: ' + validationResult.missing.join(', '));
                }
                logger.error('Provide a valid .msh file or use --allowNoMsh=1 to proceed');
                logger.result(false, 'Upgrade failed - invalid configuration');
                process.exit(1);
            }
        }
    } else {
        logger.info('--allowNoMsh specified: skipping configuration validation (agent will wait for .msh)');
    }

    // For UPGRADE mode: Discover current configuration
    if (isUpgrade) {
        logger.info('Discovering current service configuration');
        var mshPath = installPath + 'meshagent.msh';
        var configSource = 'default';

        // Priority 1: User-provided flags (highest priority)
        if (newServiceName !== null || newCompanyName !== null || newServiceId !== null) {
            currentServiceName = newServiceName || 'meshagent';
            currentCompanyName = newCompanyName;
            currentServiceId = newServiceId;
            configSource = 'user-flags';
            logger.info('Using user-provided configuration: Service=' + currentServiceName +
                       (currentCompanyName ? ', Company=' + currentCompanyName : '') +
                       (currentServiceId ? ', ServiceId=' + currentServiceId : ''));
        }
        // Priority 2: Plist ProgramArguments (AUTHORITATIVE)
        else {
            var plistConfig = getServiceConfigFromPlist(installPath);
            if (plistConfig) {
                currentServiceName = plistConfig.serviceName || 'meshagent';
                currentCompanyName = plistConfig.companyName;
                currentServiceId = plistConfig.serviceId;
                configSource = 'plist-args';
                logger.info('Found in plist ProgramArguments: Service=' + currentServiceName +
                           (currentCompanyName ? ', Company=' + currentCompanyName : ''));
            }
            // Priority 3: .msh file
            else if (fs.existsSync(mshPath)) {
                try {
                    var config = parseMshFile(mshPath);
                    if (config.meshServiceName || config.companyName) {
                        currentServiceName = config.meshServiceName || 'meshagent';
                        currentCompanyName = config.companyName || null;
                        configSource = 'msh-file';
                        logger.info('Found in .msh file: Service=' + currentServiceName +
                                   (currentCompanyName ? ', Company=' + currentCompanyName : ''));
                    }
                } catch (e) {
                    logger.warn('Could not parse .msh file: ' + e);
                }
            }
            // Priority 4: Try .db file
            else {
                try {
                    var dbPath = installPath + 'meshagent.db';
                    if (fs.existsSync(dbPath)) {
                        var db = require('SimpleDataStore').Create(dbPath);
                        var dbServiceName = db.Get('MeshServiceName');
                        var dbCompanyName = db.Get('CompanyName');
                        if (dbServiceName || dbCompanyName) {
                            currentServiceName = dbServiceName || 'meshagent';
                            currentCompanyName = dbCompanyName || null;
                            configSource = 'database';
                            logger.info('Found in .db database: Service=' + currentServiceName +
                                       (currentCompanyName ? ', Company=' + currentCompanyName : ''));
                        }
                    }
                } catch (e) {
                    logger.warn('Could not read .db database: ' + e);
                }
            }
        }

        logger.info('Configuration source: ' + configSource);

        // Build serviceId if not already set
        if (!currentServiceId) {
            currentServiceId = macOSHelpers.buildServiceId(currentServiceName, currentCompanyName);
        }
    } else {
        // FRESH INSTALL mode: Use provided params or defaults
        currentServiceName = newServiceName || 'meshagent';
        currentCompanyName = newCompanyName || null;
        currentServiceId = newServiceId || macOSHelpers.buildServiceId(currentServiceName, currentCompanyName);
    }

    logger.info('Current Service ID: ' + currentServiceId);

    // Check for .msh and .db files (for reporting purposes)
    var mshExists = fs.existsSync(installPath + 'meshagent.msh');
    var dbExists = fs.existsSync(installPath + 'meshagent.db');

    if (!mshExists && !dbExists && !isFreshInstall) {
        logger.warn('Identity file not found: ' + installPath + 'meshagent.db');
        logger.warn('Agent will need to re-register with server after upgrade');
    }

    // CACHE PLIST CUSTOMIZATIONS (before cleanup, for surgical updates)
    var cachedCustomizations = null;
    var shouldCacheCustomizations = (isLocalService || isUpgrade || upgradeMode);

    if (shouldCacheCustomizations) {
        logger.info('Caching plist customizations for surgical update');
        try {
            cachedCustomizations = cachePlistCustomizations(currentServiceId);
        } catch (e) {
            logger.warn('Could not cache plist customizations: ' + e);
        }
    }

    // Cleanup orphaned plists (always deletes - customizations already cached if needed)
    logger.info('Cleaning up service definitions pointing to ' + installPath + 'meshagent');
    try {
        var cleanedCount = cleanupOrphanedPlists(installPath);
        if (cleanedCount > 0) {
            logger.info('Cleaned up ' + cleanedCount + ' orphaned plist(s)');
        } else {
            logger.info('No service definitions found to clean up');
        }
    } catch (e) {
        logger.warn('Could not clean up orphaned plists: ' + e);
    }

    // SAFETY VERIFICATION (Always mandatory)
    logger.info('Verifying services unloaded from launchd');
    try {
        var unloadSuccess = verifyServiceUnloaded(currentServiceId, 3);
        if (unloadSuccess) {
            logger.info('Services verified unloaded from launchd');
        } else {
            logger.error('Could not verify service unload');
            process.exit(1);
        }
    } catch (e) {
        logger.error('Service unload verification failed: ' + e);
        process.exit(1);
    }

    // Verify processes terminated
    var binaryPath = installPath + 'meshagent';
    var installType = detectInstallationType(installPath);
    if (installType === 'bundle') {
        var bundleName = findBundleInDirectory(installPath);
        if (bundleName) {
            binaryPath = installPath + bundleName + '/Contents/MacOS/meshagent';
        }
    }

    logger.info('Verifying processes terminated (path: ' + binaryPath + ')');
    try {
        var terminateSuccess = verifyProcessesTerminated(binaryPath, 10);
        if (terminateSuccess) {
            logger.info('All processes terminated, other meshagent installations unaffected');
        } else {
            logger.error('Could not verify process termination');
            process.exit(1);
        }
    } catch (e) {
        logger.error('Process termination verification failed: ' + e);
        process.exit(1);
    }

    logger.info('Safety verification complete - ready for binary replacement');

    // DETECT SELF-UPGRADE SCENARIO (running installed binary with -upgrade)
    // In this case, skip backup and binary copy, but continue with service updates
    var isSelfUpgrade = false;
    if (sourceType.type === 'standalone') {
        var targetBinaryPath = installPath + 'meshagent';
        isSelfUpgrade = (sourceType.binaryPath === targetBinaryPath);
    } else {
        // For bundles, check if source bundle is at the install location
        var bundleName = sourceType.bundlePath.substring(sourceType.bundlePath.lastIndexOf('/') + 1);
        var targetBundlePath = installPath + bundleName;
        isSelfUpgrade = (sourceType.bundlePath === targetBundlePath);
    }

    if (isSelfUpgrade) {
        logger.info('Self-upgrade detected (running from install location)');
        logger.info('Will skip binary copy (service configuration will be updated)');
    }

    // BACKUP (Only if --backup flag explicitly specified)
    if (createBackup && existingInstallPath) {
        logger.info('Backing up current installation (--backup specified)');
        try {
            var backupResult = backupInstallation(installPath);
            if (backupResult && backupResult.files && backupResult.files.length > 0) {
                logger.info('Created backup (' + backupResult.files.length + ' file(s)):');
                for (var i = 0; i < backupResult.files.length; i++) {
                    logger.info('  - ' + backupResult.files[i]);
                }
            } else {
                logger.warn('No files found to backup (installation may be incomplete)');
            }
        } catch (e) {
            logger.error('Backup failed: ' + e);
            process.exit(1);
        }
    } else if (existingInstallPath) {
        logger.info('Skipping backup (not requested, use --backup to enable)');
    }

    // INSTALL/REPLACE BINARY
    logger.info('Installing new version');
    try {
        replaceInstallation(sourceType, installPath);
    } catch (e) {
        logger.error('Installation failed: ' + e);
        logger.result(false, 'Installation failed - could not copy files');
        process.exit(1);
    }

    logger.info('Installation type: ' + (sourceType.type === 'bundle' ? 'bundle' : 'standalone'));

    // HANDLE .msh FILE
    // Copy .msh if --mshPath or --copy-msh="1" was specified
    if (isFreshInstall && (explicitMshPath || copyMsh === '1')) {
        // Copy .msh file from source location (already found and validated during early validation)
        logger.info('Copying .msh configuration file');

        // sourceMshFile was already found using case-insensitive lookup in early validation
        if (!sourceMshFile || !fs.existsSync(sourceMshFile)) {
            logger.error('Cannot find .msh file (should have been found during early validation)');
            logger.error('This is an internal error - please report it');
            process.exit(1);
        }

        var targetMshFile = installPath + 'meshagent.msh';
        try {
            // Check if source and target are the same file (prevent self-copy)
            // Normalize paths by removing any duplicate slashes for comparison
            var normalizedSource = sourceMshFile.split('//').join('/');
            var normalizedTarget = targetMshFile.split('//').join('/');

            if (normalizedSource === normalizedTarget) {
                logger.info('.msh file already at target location');
            } else {
                fs.copyFileSync(sourceMshFile, targetMshFile);
                logger.info('Copied .msh file from: ' + sourceMshFile);
                logger.info('                   to: ' + targetMshFile);
            }

            // Set secure permissions on .msh file
            var mshResult = securityPermissions.setSecurePermissions(targetMshFile, '.msh');
            if (!mshResult.success) {
                logger.warn('Could not set .msh permissions: ' + mshResult.errors.join(', '));
            }
        } catch (e) {
            logger.error('Failed to copy .msh file: ' + e);
            process.exit(1);
        }
    }

    // Write disableUpdate to .msh file if specified
    // null = not provided, true/false = write value, 'clear' = write blank
    if (disableUpdate !== null) {
        var targetMshFile = installPath + 'meshagent.msh';
        try {
            if (disableUpdate === 'clear') {
                updateMshFile(targetMshFile, { disableUpdate: null });
                logger.info('Updated .msh with disableUpdate= (blank)');
            } else {
                updateMshFile(targetMshFile, { disableUpdate: disableUpdate ? '1' : '0' });
                logger.info('Updated .msh with disableUpdate=' + (disableUpdate ? '1' : '0'));
            }
        } catch (e) {
            logger.warn('Could not update .msh with disableUpdate: ' + e.message);
        }
    }

    // Write disableTccCheck to .msh file if specified
    // null = not provided, true/false = write value, 'clear' = write blank
    if (disableTccCheck !== null) {
        var targetMshFile = installPath + 'meshagent.msh';
        try {
            if (disableTccCheck === 'clear') {
                updateMshFile(targetMshFile, { disableTccCheck: null });
                logger.info('Updated .msh with disableTccCheck= (blank)');
            } else {
                updateMshFile(targetMshFile, { disableTccCheck: disableTccCheck ? '1' : '0' });
                logger.info('Updated .msh with disableTccCheck=' + (disableTccCheck ? '1' : '0'));
            }
        } catch (e) {
            logger.warn('Could not update .msh with disableTccCheck: ' + e.message);
        }
    }

    // Write ServiceID to .msh file if explicitly provided via command line
    // null = not provided, '' = write blank, 'value' = write value
    // Note: currentServiceId is auto-calculated, but newServiceId tracks explicit --serviceId parameter
    if (newServiceId !== null) {
        var targetMshFile = installPath + 'meshagent.msh';
        try {
            updateMshFile(targetMshFile, { ServiceID: newServiceId || null });
            if (newServiceId) {
                logger.info('Updated .msh with ServiceID=' + newServiceId);
            } else {
                logger.info('Updated .msh with ServiceID= (blank)');
            }
        } catch (e) {
            logger.warn('Could not update .msh with ServiceID: ' + e.message);
        }
    } else if (currentServiceId) {
        // Auto-write calculated ServiceID (not explicitly provided)
        var targetMshFile = installPath + 'meshagent.msh';
        try {
            updateMshFile(targetMshFile, { ServiceID: currentServiceId });
            logger.info('Updated .msh with ServiceID=' + currentServiceId);
        } catch (e) {
            logger.warn('Could not update .msh with ServiceID: ' + e.message);
        }
    }

    // Write MeshServiceName to .msh file if explicitly provided via command line
    // null = not provided (don't change), '' = explicitly set to empty (write blank), 'value' = write value
    if (newServiceName !== null) {
        var targetMshFile = installPath + 'meshagent.msh';
        try {
            // Empty string writes blank entry (clears value), non-empty writes the value
            updateMshFile(targetMshFile, { MeshServiceName: newServiceName || null });
            if (newServiceName) {
                logger.info('Updated .msh with MeshServiceName=' + newServiceName);
            } else {
                logger.info('Updated .msh with MeshServiceName= (blank - will clear from DB on import)');
            }
        } catch (e) {
            logger.warn('Could not update .msh with MeshServiceName: ' + e.message);
        }
    }

    // Write CompanyName to .msh file if explicitly provided via command line
    // null = not provided (don't change), '' = explicitly set to empty (write blank), 'value' = write value
    if (newCompanyName !== null) {
        var targetMshFile = installPath + 'meshagent.msh';
        try {
            // Empty string writes blank entry (clears value), non-empty writes the value
            updateMshFile(targetMshFile, { CompanyName: newCompanyName || null });
            if (newCompanyName) {
                logger.info('Updated .msh with CompanyName=' + newCompanyName);
            } else {
                logger.info('Updated .msh with CompanyName= (blank - will clear from DB on import)');
            }
        } catch (e) {
            logger.warn('Could not update .msh with CompanyName: ' + e.message);
        }
    }

    // CREATE SERVICES
    // Determine if we should use surgical update (preserve customizations)
    // Surgical mode: -install (isLocalService), -upgrade (isUpgrade/upgradeMode)
    // Atomic mode: -finstall (neither flag set)
    var surgicalUpdate = (isLocalService || isUpgrade || upgradeMode);
    logger.info('Plist mode: ' + (surgicalUpdate ? 'surgical (preserve customizations)' : 'atomic (full replacement)'));

    logger.info('Creating LaunchDaemon');
    try {
        createLaunchDaemon(currentServiceName, currentCompanyName, installPath, currentServiceId, sourceType.type, surgicalUpdate, cachedCustomizations, meshAgentLogging);
    } catch (e) {
        logger.error('Failed to create LaunchDaemon: ' + e);
        logger.result(false, 'Installation failed - could not create LaunchDaemon');
        process.exit(1);
    }

    logger.info('Creating LaunchAgent');
    try {
        createLaunchAgent(currentServiceName, currentCompanyName, installPath, currentServiceId, sourceType.type, surgicalUpdate, cachedCustomizations, meshAgentLogging);
    } catch (e) {
        logger.error('Failed to create LaunchAgent: ' + e);
        logger.result(false, 'Installation failed - could not create LaunchAgent');
        process.exit(1);
    }

    // FINAL VERIFICATION
    logger.info('Final verification before starting services');
    try {
        var finalVerify = verifyServiceUnloaded(currentServiceId, 1);
        if (finalVerify) {
            logger.info('Clean state verified - ready to start services');
        }
    } catch (e) {
        logger.warn('Final verification failed: ' + e);
    }

    // FIX PERMISSIONS ON PRESERVED FILES (before starting services)
    logger.info('Fixing permissions on preserved files before starting services...');
    var mshPath = installPath + 'meshagent.msh';
    var dbPath = installPath + 'meshagent.db';
    var logPath = installPath + 'meshagent.log';

    // Fix .msh file permissions if it exists
    if (fs.existsSync(mshPath)) {
        try {
            var mshResult = securityPermissions.setSecurePermissions(mshPath, '.msh');
            if (!mshResult.success) {
                logger.warn('Could not fix .msh permissions: ' + mshResult.errors.join(', '));
            } else {
                logger.debug('Fixed .msh file permissions');
            }
        } catch (e) {
            logger.warn('Error fixing .msh permissions: ' + e.message);
        }
    }

    // Fix .db file permissions if it exists
    if (fs.existsSync(dbPath)) {
        try {
            var dbResult = securityPermissions.setSecurePermissions(dbPath, '.db');
            if (!dbResult.success) {
                logger.warn('Could not fix .db permissions: ' + dbResult.errors.join(', '));
            } else {
                logger.debug('Fixed .db file permissions');
            }
        } catch (e) {
            logger.warn('Error fixing .db permissions: ' + e.message);
        }
    }

    // Fix .log file permissions if it exists
    if (fs.existsSync(logPath)) {
        try {
            var logResult = securityPermissions.setSecurePermissions(logPath, '.log');
            if (!logResult.success) {
                logger.warn('Could not fix .log permissions: ' + logResult.errors.join(', '));
            } else {
                logger.debug('Fixed .log file permissions');
            }
        } catch (e) {
            logger.warn('Error fixing .log permissions: ' + e.message);
        }
    }

    // Fix installation directory permissions
    try {
        var dirResult = securityPermissions.setSecurePermissions(installPath, 'installDir');
        if (!dirResult.success) {
            logger.warn('Could not fix directory permissions: ' + dirResult.errors.join(', '));
        } else {
            logger.debug('Fixed installation directory permissions');
        }
    } catch (e) {
        logger.warn('Error fixing directory permissions: ' + e.message);
    }

    // COMPREHENSIVE PERMISSION VERIFICATION (before starting services)
    logger.info('Running comprehensive permission verification...');
    try {
        var verifyResult = securityPermissions.verifyInstallation(installPath, { autoFix: true });

        if (verifyResult.fixed && verifyResult.fixed.length > 0) {
            logger.info('Fixed permissions on ' + verifyResult.fixed.length + ' additional file(s)');
        }

        if (!verifyResult.allValid && verifyResult.failed && verifyResult.failed.length > 0) {
            logger.error('Could not fix permissions on ' + verifyResult.failed.length + ' file(s):');
            verifyResult.failed.forEach(function(filePath) {
                logger.error('  - ' + filePath);
            });
            logger.error('Installation cannot proceed with incorrect file permissions');
            process.exit(1);
        } else if (verifyResult.allValid) {
            logger.info('All file permissions verified');
        }
    } catch (e) {
        logger.error('Permission verification failed: ' + e);
        process.exit(1);
    }

    // START SERVICES
    logger.info('Starting services');
    try {
        bootstrapServices(currentServiceId);
    } catch (e) {
        logger.error('Failed to start services: ' + e);
        logger.result(false, (isUpgrade ? 'Upgrade' : 'Installation') + ' failed - could not start services');
        process.exit(1);
    }

    // SUCCESS MESSAGE (shown even in quiet mode)
    var operation = isUpgrade ? 'Upgrade' : 'Installation';
    logger.result(true, operation + ' complete - ' + currentServiceId + ' at ' + installPath);
    logger.info('Service ID: ' + currentServiceId);
    if (isUpgrade && (mshExists || dbExists)) {
        logger.info('Configuration (.msh) and identity (.db) files preserved');
    }

    process.exit(0);
}

// This is the entry point for installing the service
function installService(params)
{

    // Route macOS to unified install/upgrade function
    if (process.platform == 'darwin') {
        // Convert params to JSON string if it's not already
        var paramsStr = (typeof params === 'string') ? params : JSON.stringify(params);
        return installServiceUnified(paramsStr);
    }

    // Linux/Windows continue with legacy install code below
    logger.info('Installing service');
    console.info1('');

    var target = null;
    var targetx = params.getParameterIndex('target');
    if (targetx >= 0)
    {
        // Let's remove any embedded spaces in 'target' as that can mess up some OSes
        target = params.getParameterValue(targetx);
        params.splice(targetx, 1);
        target = target.split(' ').join('');
        if (target.length == 0) { target = null; }
    }

    var proxyFile = process.execPath;
    if (process.platform == 'win32')
    {
        proxyFile = proxyFile.split('.exe').join('.proxy');
        try
        {
            // Add this parameter, so the agent instance will be embedded with the Windows User that installed the service
            params.push('--installedByUser="' + require('win-registry').usernameToUserKey(require('user-sessions').getProcessOwnerName(process.pid).name) + '"');
        }
        catch(exc)
        {
        }
    }
    else
    {
        // On Linux, the --installedByUser property is populated with the UID of the user that is installing the service
        var u = require('user-sessions').tty();
        var uid = 0;
        try
        {
            uid = require('user-sessions').getUid(u);
        }
        catch(e)
        {
        }
        params.push('--installedByUser=' + uid);
        proxyFile += '.proxy';
    }


    // We're going to create the OPTIONS object to hand to service-manager.js. We're going to populate all the properties we can, using
    // values that were passed into the installer, using default values for the ones that aren't specified.
    var options =
        {
            name: params.getParameter('meshServiceName', process.platform == 'win32' ? 'Mesh Agent' : 'meshagent'),
            target: target==null?(process.platform == 'win32' ? 'MeshAgent' : 'meshagent'):target,
            servicePath: process.execPath,
            startType: 'AUTO_START',
            parameters: params,
            _installer: true
        };
    options.displayName = params.getParameter('displayName', options.name); params.deleteParameter('displayName');
    options.description = params.getParameter('description', options.name + ' background service'); params.deleteParameter('description');

    if (process.platform == 'win32') { options.companyName = ''; }
    if (global.gOptions != null)
    {
        if(Array.isArray(global.gOptions.files))
        {
            options.files = global.gOptions.files;
        }
        if(global.gOptions.binary != null)
        {
            options.servicePath = global.gOptions.binary;
        }
    }

    // If a .proxy file was found, we'll include it in the list of files to be copied when installing the agent
    if (require('fs').existsSync(proxyFile))
    {
        if (options.files == null) { options.files = []; }
        options.files.push({ source: proxyFile, newName: options.target + '.proxy' });
    }
    
    // if '--copy-msh' is specified, we will try to copy the .msh configuration file
    var i;
    if ((i = params.indexOf('--copy-msh="1"')) >= 0)
    {
        var mshFile;
        if (process.platform == 'win32') {
            mshFile = process.execPath.split('.exe').join('.msh');
        } else {
            // Linux: .msh file next to binary
            mshFile = process.execPath + '.msh';
        }

        // Validate that the .msh file exists before attempting to copy it
        if (!require('fs').existsSync(mshFile)) {
            logger.error('Cannot find .msh file at: ' + mshFile);
            logger.error('The --copy-msh="1" parameter requires a .msh configuration file.');
            logger.error('Please place the .msh file next to the binary and try again.');
            process.exit(1);
        }

        if (options.files == null) { options.files = []; }
        var newtarget = (process.platform == 'linux' && require('service-manager').manager.getServiceType() == 'systemd') ? options.target.split("'").join('-') : options.target;
        options.files.push({ source: mshFile, newName: newtarget + '.msh' });
        options.parameters.splice(i, 1);
    }
    if ((i=params.indexOf('--_localService="1"'))>=0)
    {
        // install in place
        options.parameters.splice(i, 1);
        options.installInPlace = true;
    }

    // We're going to specify what folder the agent should be installed into
    if (global._workingpath != null && global._workingpath != '' && global._workingpath != '/')
    {
        for (i = 0; i < options.parameters.length; ++i)
        {
            if (options.parameters[i].startsWith('--installPath='))
            {
                global._workingpath = null;
                break;
            }
        }
        if(global._workingpath != null)
        {
            options.parameters.push('--installPath=' + global._workingpath);
        }
    }
    if ((i = options.parameters.getParameterIndex('installPath')) >= 0)
    {
        options.installPath = options.parameters.getParameterValue(i);
        options.installInPlace = false;
        options.parameters.splice(i, 1);
    }

    // If companyName was specified, extract it but keep it in parameters so it gets written to .msh
    if ((i = options.parameters.getParameterIndex('companyName')) >= 0)
    {
        options.companyName = options.parameters.getParameterValue(i);
        // Don't remove from parameters - agent needs it to write to .msh file
    }

    // If serviceId was specified, extract it but keep it in parameters so it gets written to .msh
    if ((i = options.parameters.getParameterIndex('serviceId')) >= 0)
    {
        options.serviceId = options.parameters.getParameterValue(i);
        // Don't remove from parameters - agent needs it to write to .msh file
    }

    // Handle --disableUpdate flag - write to .msh file instead of passing to service
    if ((i = options.parameters.getParameterIndex('disableUpdate')) >= 0) {
        var disableValue = options.parameters.getParameterValue(i);
        // Remove from parameters (it's written to .msh, not passed as service arg)
        options.parameters.splice(i, 1);
        // Write to .msh file
        try {
            var mshFile = (process.platform == 'win32')
                ? process.execPath.split('.exe').join('.msh')
                : process.execPath + '.msh';
            if (require('fs').existsSync(mshFile)) {
                updateMshFile(mshFile, { disableUpdate: (disableValue === '1' || disableValue === 'true') ? '1' : '0' });
            }
        } catch (e) {
            // Ignore errors writing to .msh
        }
    }

    // Handle --disableTccCheck flag - write to .msh file instead of passing to service
    if ((i = options.parameters.getParameterIndex('disableTccCheck')) >= 0) {
        var disableValue = options.parameters.getParameterValue(i);
        // Remove from parameters (it's written to .msh, not passed as service arg)
        options.parameters.splice(i, 1);
        // Write to .msh file
        try {
            var mshFile = (process.platform == 'win32')
                ? process.execPath.split('.exe').join('.msh')
                : process.execPath + '.msh';
            if (require('fs').existsSync(mshFile)) {
                updateMshFile(mshFile, { disableTccCheck: (disableValue === '1' || disableValue === 'true') ? '1' : '0' });
            }
        } catch (e) {
            // Ignore errors writing to .msh
        }
    }

    if (global.gOptions != null && global.gOptions.noParams === true) { options.parameters = []; }

    try
    {
        // Let's actually install the service
        require('service-manager').manager.installService(options);
        logger.info('Service installation completed');
        if(process.platform == 'win32')
        {
            // On Windows, we're going to enable this service to be runnable from SafeModeWithNetworking
            require('win-bcd').enableSafeModeService(options.name);
        }
    }
    catch(sie)
    {
        logger.error('Service installation failed: ' + sie);
        process.exit();
    }
    // Get the service object for starting
    var svc = require('service-manager').manager.getService(options.name);

    // For Windows, we're going to add an INBOUND UDP rule for WebRTC Data
    if(process.platform == 'win32')
    {
        var loc = svc.appLocation();
        logger.info('Writing firewall rules for ' + options.name + ' Service...');

        var rule = 
            {
                DisplayName: options.name + ' WebRTC Traffic',
                direction: 'inbound',
                Program: loc,
                Protocol: 'UDP',
                Profile: 'Public, Private, Domain',
                Description: 'Mesh Central Agent WebRTC P2P Traffic',
                EdgeTraversalPolicy: 'allow',
                Enabled: true
            };
        require('win-firewall').addFirewallRule(rule);
        logger.info('Firewall rules added');
    }

    // Let's try to start the service that we just installed
    logger.info('Starting service...');
    try
    {
        svc.start();
        logger.info('Service started successfully');
    }
    catch(ee)
    {
        logger.error('Failed to start service');
    }

    // On Windows we should explicitly close the service manager when we are done, instead of relying on the Garbage Collection, so the service object isn't unnecessarily locked
    if (process.platform == 'win32') { svc.close(); }   
    if (parseInt(params.getParameter('__skipExit', 0)) == 0)
    {
        process.exit();
    }
}

// The last step in uninstalling a service
function uninstallService3(params, installPath)
{
    // Linux/Windows: No platform-specific cleanup needed here
    // macOS plist cleanup is handled in uninstallServiceUnified()

    if (params != null && !params.includes('_stop'))
    {
        // Since we are done uninstalling a previously installed service, we can continue with installation
        installService(params);
    }
    else
    {
        // We are going to stop here, if we are only intending to uninstall the service
        process.exit();
    }
}

// Step 2 in service uninstallation
function uninstallService2(params, msh)
{
    var secondaryagent = false;
    var i;
    var dataFolder = null;
    var appPrefix = null;
    var uninstallOptions = null;
    var serviceName = params.getParameter('meshServiceName', process.platform == 'win32' ? 'Mesh Agent' : 'meshagent'); // get the service name, using the provided defaults if not specified
    var companyName = params.getParameter('companyName', null);

    // Extract install path from msh file path for cleanupOrphanedPlists
    var installPath = null;
    if (msh) {
        // msh is like "/opt/tacticalmesh/meshagent.msh", extract directory with trailing slash
        var parts = msh.split(process.platform == 'win32' ? '\\' : '/');
        parts.pop(); // Remove filename
        installPath = parts.join(process.platform == 'win32' ? '\\' : '/') + (process.platform == 'win32' ? '\\' : '/');
    }

    // Build service identifier (Linux/Windows use simple serviceName)
    var serviceId = serviceName;

    // Remove the .msh file if present
    try { require('fs').unlinkSync(msh); } catch (mshe) { }
    if ((i = params.indexOf('__skipBinaryDelete')) >= 0)
    {
        // We will skip deleting of the actual binary, if this option was provided. 
        // This will happen if we try to install the service to a location where we are running the installer from.
        params.splice(i, 1);
        uninstallOptions = { skipDeleteBinary: true };
    }
    if (params && params.includes('--_deleteData="1"'))
    {
        // This will facilitate cleanup of the files associated with the agent
        dataFolder = params.getParameterEx('_workingDir', null);
        appPrefix = params.getParameterEx('_appPrefix', null);
    }

    logger.info('Uninstalling previous installation...');
    try
    {
        // Linux/Windows: use service-manager's uninstallService
        require('service-manager').manager.uninstallService(serviceId, uninstallOptions);
        logger.info('Previous installation uninstalled');
        if (process.platform == 'win32')
        {
            // For Windows, we can remove the entry to enable this service to be runnable from SafeModeWithNetworking
            require('win-bcd').disableSafeModeService(serviceId);
        }

        // Lets try to cleanup the uninstalled service
        if (dataFolder && appPrefix)
        {
            logger.info('Deleting agent data...');
            if (process.platform != 'win32')
            {
                // On Non-Windows platforms, we're going to cleanup using the shell
                var levelUp = dataFolder.split('/');
                levelUp.pop();
                levelUp = levelUp.join('/');

                console.info1('   Cleaning operation =>');
                console.info1('      cd "' + dataFolder + '"');
                console.info1('      rm "' + appPrefix + '.*"');
                console.info1('      rm DAIPC');
                console.info1('      cd /');
                console.info1('      rmdir "' + dataFolder + '"');
                console.info1('      rmdir "' + levelUp + '"');

                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.on('data', function (c) { console.info1(c.toString()); });
                child.stderr.on('data', function (c) { console.info1(c.toString()); });
                child.stdin.write('cd "' + dataFolder + '"\n');
                child.stdin.write('rm DAIPC\n');

                child.stdin.write("ls | awk '");
                child.stdin.write('{');
                child.stdin.write('   if($0 ~ /^' + appPrefix + '\\./)');
                child.stdin.write('   {');
                child.stdin.write('      sh=sprintf("rm \\"%s\\"", $0);');
                child.stdin.write('      system(sh);');
                child.stdin.write('   }');
                child.stdin.write("}'\n");

                child.stdin.write('cd /\n');
                child.stdin.write('rmdir "' + dataFolder + '"\n');
                child.stdin.write('rmdir "' + levelUp + '"\n');
                child.stdin.write('exit\n');       
                child.waitExit();    
            }
            else
            {
                // On Windows, we're going to spawn a command shell to cleanup
                var levelUp = dataFolder.split('\\');
                levelUp.pop();
                levelUp = levelUp.join('\\');
                var child = require('child_process').execFile(process.env['windir'] + '\\system32\\cmd.exe', ['/C del "' + dataFolder + '\\' + appPrefix + '.*" && rmdir "' + dataFolder + '" && rmdir "' + levelUp + '"']);
                child.stdout.on('data', function (c) { });
                child.stderr.on('data', function (c) { });
                child.waitExit();
            }

            logger.info('Agent data deleted');
        }
    }
    catch (e)
    {
        var errorMsg = e.message || e.toString() || 'Unknown error';
        logger.error('Uninstall error: ' + errorMsg);
        console.log('   Uninstall error details:', e);
    }

    // Check for secondary agent
    // Build diagnostic service ID (Linux/Windows use simple serviceName)
    var diagnosticServiceId = serviceName + 'Diagnostic';
    try
    {
        logger.info('Checking for secondary agent...');
        var s = require('service-manager').manager.getService(diagnosticServiceId);
        var loc = s.appLocation();
        s.close();
        logger.info('Secondary agent found');
        logger.info('Uninstalling secondary agent...');
        secondaryagent = true;
        try
        {
            require('service-manager').manager.uninstallService(diagnosticServiceId);
            logger.info('Secondary agent uninstalled');
        }
        catch (e)
        {
            logger.error('Failed to uninstall secondary agent');
        }
    }
    catch (e)
    {
        logger.info('No secondary agent found');
    }

    if(secondaryagent)
    {
        // If a secondary agent was found, remove the CRON job for it
        logger.info('Removing secondary agent from task scheduler...');
        var p = require('task-scheduler').delete(diagnosticServiceId + '/periodicStart');
        p._params = params;
        p._installPath = installPath;
        p.then(function ()
        {
            logger.info('Task scheduler entry removed');
            uninstallService3(this._params, this._installPath);
        }, function ()
        {
            logger.error('Failed to remove task scheduler entry');
            uninstallService3(this._params, this._installPath);
        });
    }
    else
    {
        uninstallService3(params, installPath);
    }
}

// First step in service uninstall
function uninstallService(params)
{
    // Before we uninstall, we need to fetch the service from service-manager.js
    var serviceName = params.getParameter('meshServiceName', process.platform == 'win32' ? 'Mesh Agent' : 'meshagent');
    var companyName = params.getParameter('companyName', null);

    // Build composite service identifier (Linux/Windows use simple serviceName)
    var serviceId = serviceName;

    var svc = require('service-manager').manager.getService(serviceId);

    // We can calculate what the .msh file location is, based on the appLocation of the service
    var msh = svc.appLocation();
    if (process.platform == 'win32')
    {
        msh = msh.substring(0, msh.length - 4) + '.msh';
    }
    else
    {
        msh = msh + '.msh';
    }

    // Let's try to stop the service if we think it might be running
    if (svc.isRunning == null || svc.isRunning())
    {
        logger.info('Stopping Service...');
        if(process.platform=='win32')
        {
            svc.stop().then(function ()
            {
                logger.info('Service stopped');
                svc.close();
                uninstallService2(this._params, msh);
            }, function ()
            {
                logger.error('Failed to stop service');
                svc.close();
                uninstallService2(this._params, ms);
            }).parentPromise._params = params;
        }
        else
        {
            // Linux: stop the service
            svc.stop();
            logger.info('Service stopped');
            uninstallService2(params, msh);
        }
    }
    else
    {
        if (process.platform == 'win32') { svc.close(); }
        uninstallService2(params, msh);
    }
}

// A previous service installation was found, so lets do some extra processing
function serviceExists(loc, params)
{
    logger.info('Previous installation found: ' + loc);
    if(process.platform == 'win32')
    {
        // On Windows, we need to cleanup the firewall rules associated with our install path
        logger.info('Checking firewall rules for previous installation...');
        var p = require('win-firewall').getFirewallRulesAsync({ program: loc, noResult: true, minimal: true, timeout: 15000 });
        p.on('progress', function (c)
        {
            logger.debug('Checking firewall rules progress: ' + c);
        });
        p.on('rule', function (r)
        {
            // Remove firewall entries for our install path
            require('win-firewall').removeFirewallRule(r.DisplayName);
        });
        p.finally(function ()
        {
            logger.info('Firewall rules check completed');
            uninstallService(params);
        });
    }
    else
    {
        uninstallService(params);
    }
}

// Unified uninstall function - handles all platforms
function uninstallServiceUnified(params) {
    var parms = JSON.parse(params);
    var fs = require('fs');
    var child_process = require('child_process');

    // Configure logger output mode from command line flags
    configureLoggerFromParams(parms);

    // Verify root permissions
    if (!require('user-sessions').isRoot()) {
        logger.error('Uninstallation requires root privileges. Please run with sudo.');
        process.exit(1);
    }

    // Parse parameters
    var serviceName = parms.getParameter('meshServiceName', process.platform == 'win32' ? 'Mesh Agent' : 'meshagent');
    var companyName = parms.getParameter('companyName', null);
    var serviceId = macOSHelpers.buildServiceId(serviceName, companyName);
    var installPathParam = parms.getParameter('installPath', null);
    var skipDeleteBinary = parms.includes('__skipBinaryDelete');
    var deleteData = parms.includes('--_deleteData="1"');

    // Find installation
    var installPath = null;
    var servicePath = null;
    var workingDir = null;
    var svc = null;

    logger.info('Checking for installation of service: ' + serviceId);

    try {
        svc = require('service-manager').manager.getService(serviceId);
        servicePath = svc.appLocation();
        workingDir = svc.appWorkingDirectory();
        installPath = workingDir;
        logger.info('Installation found: ' + servicePath);
    } catch (e) {
        // Fallback methods (macOS only)
        if (process.platform == 'darwin') {
            // Try provided installPath parameter
            if (installPathParam) {
                var normalized = installPathParam.endsWith('/') ? installPathParam : installPathParam + '/';
                if (fs.existsSync(normalized) && (
                    fs.existsSync(normalized + 'meshagent.msh') ||
                    fs.existsSync(normalized + 'meshagent.db') ||
                    fs.existsSync(normalized + 'DAIPC') ||
                    findBundleInDirectory(normalized)
                )) {
                    installPath = normalized;
                    logger.info('Installation found at provided path: ' + installPath);
                }
            }

            // Try plist scan
            if (!installPath) {
                installPath = findInstallationByPlist();
                if (installPath) {
                    logger.info('Installation found via plist scan: ' + installPath);
                }
            }

            // Try current directory
            if (!installPath) {
                var bundleParent = macOSHelpers.getBundleParentDirectory();
                var selfDir = bundleParent || process.execPath.substring(0, process.execPath.lastIndexOf('/') + 1);
                if (fs.existsSync(selfDir + 'meshagent.msh') ||
                    fs.existsSync(selfDir + 'meshagent.db') ||
                    fs.existsSync(selfDir + 'DAIPC')) {
                    installPath = selfDir;
                    logger.info('Installation found in current directory: ' + installPath);
                }
            }
        }

        if (!installPath) {
            logger.error('No installation found');
            process.exit(1);
        }
    }

    // PLATFORM-SPECIFIC UNINSTALL
    if (process.platform == 'darwin') {

        // Stop/unload service
        if (svc) {
            logger.info('Stopping service');
            try {
                if (svc.isRunning && svc.isRunning()) {
                    svc.stop();
                }
                svc.unload();
                svc.close();
                logger.info('Service stopped');
            } catch (e) {
                logger.error('Failed to stop service: ' + (e.message || e));
            }
        }

        // Delete binary/bundle
        if (!skipDeleteBinary) {
            try {
                var bundleName = findBundleInDirectory(installPath);
                if (bundleName) {
                    var bundlePath = installPath + bundleName;
                    // Remove bundle directory recursively
                    removeDirectoryRecursive(bundlePath);
                    logger.info('Removed bundle: ' + bundleName);
                } else {
                    var binaryPath = installPath + 'meshagent';
                    if (fs.existsSync(binaryPath)) {
                        fs.unlinkSync(binaryPath);
                        logger.info('Removed binary');
                    }
                }

                // Clean up backup files (meshagent.TIMESTAMP, BundleName.app.TIMESTAMP, meshagent.msh.TIMESTAMP, meshagent.db.TIMESTAMP)
                try {
                    var files = fs.readdirSync(installPath);
                    var backupCount = 0;
                    for (var i = 0; i < files.length; i++) {
                        var file = files[i];
                        // Match backup pattern: meshagent.DIGITS, *.app.DIGITS, meshagent.msh.DIGITS, meshagent.db.DIGITS
                        if ((file.match(/^meshagent\.\d+$/) ||
                             file.match(/\.app\.\d+$/) ||
                             file.match(/^meshagent\.msh\.\d+$/) ||
                             file.match(/^meshagent\.db\.\d+$/))) {
                            var backupPath = installPath + file;
                            var stats = fs.statSync(backupPath);
                            if (stats.isDirectory()) {
                                removeDirectoryRecursive(backupPath);
                            } else {
                                fs.unlinkSync(backupPath);
                            }
                            backupCount++;
                        }
                    }
                    if (backupCount > 0) {
                        logger.info('Removed ' + backupCount + ' backup file(s)');
                    }
                } catch (e) {
                    logger.warn('Failed to clean up backup files: ' + (e.message || e.toString()));
                }
            } catch (e) {
                var errorMsg = e.message || e.toString() || 'Unknown error';
                logger.error('Failed to remove binary/bundle: ' + errorMsg);
            }
        }

        // Cleanup plists
        logger.info('Cleaning up LaunchAgent/LaunchDaemon plists');
        try {
            var cleaned = cleanupOrphanedPlists(installPath);
            if (cleaned.length > 0) {
                for (var j = 0; j < cleaned.length; j++) {
                    logger.info('Removed plist: ' + cleaned[j]);
                }
            }
        } catch (e) {
            logger.error('Failed to clean up plists: ' + (e.message || e));
        }

        // DISABLED: Legacy diagnostic service cleanup
        // No code in the codebase creates this "Diagnostic" service
        // Keeping commented for reference but not actively checking
        /*
        var diagnosticServiceId = macOSHelpers.buildServiceId(serviceName + 'Diagnostic', companyName);
        logger.info('Checking for secondary agent...');
        try {
            var diagSvc = require('service-manager').manager.getService(diagnosticServiceId);
            diagSvc.stop();
            diagSvc.unload();
            diagSvc.close();
            logger.info('Secondary agent removed: ' + diagnosticServiceId);
        } catch (e) {
            logger.info('No secondary agent found');
        }
        */

        // Remove data files if requested
        if (deleteData) {
            logger.info('Deleting agent data');
            try {
                deleteInstallationFiles(installPath, true);
                logger.info('Agent data deleted');
            } catch (e) {
                logger.error('Failed to delete agent data: ' + (e.message || e));
            }
        }

        // Remove working directory (if not already removed by deleteData)
        if (fs.existsSync(installPath)) {
            try {
                fs.rmdirSync(installPath);
            } catch (e) {
                // Directory may not be empty - that's okay
            }
        }
    } else {
        // Non-macOS platforms: delegate to service-manager
        logger.info('Uninstalling service');
        try {
            var options = skipDeleteBinary ? { skipDeleteBinary: true } : null;
            require('service-manager').manager.uninstallService(serviceId, options);
            logger.info('Service uninstalled');
        } catch (e) {
            var errorMsg = e.message || e.toString() || 'Unknown error';
            logger.error('Failed to uninstall service: ' + errorMsg);
        }
    }

    logger.info('Uninstall completed successfully');
    process.exit(0);
}

// Entry point for -fulluninstall and -uninstall (called from C code)
function fullUninstall(jsonString)
{
    // macOS → unified implementation
    if (process.platform == 'darwin') {
        return uninstallServiceUnified(jsonString);
    }

    // Linux/Windows → legacy implementation
    var parms = JSON.parse(jsonString);

    if (parseInt(parms.getParameter('verbose', 0)) != 0)
    {
        console.setInfoLevel(1);
    }
    else
    {
        console.setDestination(console.Destinations.DISABLED);
    }

    parms.push('_stop'); // Since we are intending to halt after uninstalling the service, we specify this, since we are re-using the uninstall code with the installer.

    checkParameters(parms); // Perform some checks on the passed in parameters

    var name = parms.getParameter('meshServiceName', process.platform == 'win32' ? 'Mesh Agent' : 'meshagent');
    var companyName = parms.getParameter('companyName', null);
    var serviceId = name;

    // Check for a previous installation of the service
    try
    {
        logger.info('Checking for previous installation of "' + serviceId + '"');
        var s = require('service-manager').manager.getService(serviceId);
        var loc = s.appLocation();
        var appPrefix = loc.split(process.platform == 'win32' ? '\\' : '/').pop();
        if (process.platform == 'win32') { appPrefix = appPrefix.substring(0, appPrefix.length - 4); }

        parms.push('_workingDir=' + s.appWorkingDirectory());
        parms.push('_appPrefix=' + appPrefix);

        s.close();
    }
    catch (e)
    {
        // Service lookup failed
        logger.error('Previous installation not found');
        logger.error('Could not locate installation');
        process.exit(1);
    }
    serviceExists(loc, parms);
}

// Entry point for -fullinstall, using JSON string
function fullInstall(jsonString, gOptions)
{

    // Route macOS to unified install/upgrade function
    if (process.platform == 'darwin') {
        return installServiceUnified(jsonString);
    }

    // Linux/Windows continue with legacy fullInstall code
    var parms = JSON.parse(jsonString);
    fullInstallEx(parms, gOptions);
}

// Entry point for -fullinstall, using JSON object
function fullInstallEx(parms, gOptions)
{
    if (gOptions != null) { global.gOptions = gOptions; }

    // Perform some checks on the specified parameters
    checkParameters(parms);

    var loc = null;
    var i;
    var name = parms.getParameter('meshServiceName', process.platform == 'win32' ? 'Mesh Agent' : 'meshagent'); // Set the service name, using defaults if not specified
    if (process.platform != 'win32') { name = name.split(' ').join('_'); }
    var companyName = parms.getParameter('companyName', null);
    var explicitServiceId = parms.getParameter('serviceId', null);

    // Build composite service identifier to match installation naming convention
    var serviceId = macOSHelpers.buildServiceId(name, companyName, { explicitServiceId: explicitServiceId });

    // No-op console.log() if verbose is not specified, otherwise set the verbosity level to level 1
    if (parseInt(parms.getParameter('verbose', 0)) == 0)
    {
        console.setDestination(console.Destinations.DISABLED);
    }
    else
    {
        console.setInfoLevel(1);
    }

    // Check for a previous installation of the service
    try
    {
        logger.info('Checking for previous installation of "' + serviceId + '"');
        var s = require('service-manager').manager.getService(serviceId);
        loc = s.appLocation();

        global._workingpath = s.appWorkingDirectory();
        console.info1('');
        console.info1('Previous Working Path: ' + global._workingpath);
        s.close();
    }
    catch (e)
    {
        // Service not found with the provided name
        // On macOS, try to find ANY existing meshagent installation (handles service renames)
        if (process.platform == 'darwin')
        {
            logger.info('Service not found by name');
            logger.info('Searching for any existing meshagent installation...');
            try
            {
                // Check if explicit installPath was provided (takes priority over self-upgrade detection)
                var explicitInstallPath = null;
                var installPathIndex = parms.getParameterIndex('installPath');
                if (installPathIndex >= 0) {
                    explicitInstallPath = parms.getParameterValue(installPathIndex);
                }

                loc = findInstallation(explicitInstallPath, null, null);
                if (loc)
                {
                    logger.info('Found existing installation: ' + loc);
                    // Determine working directory from location
                    var parts = loc.split('/');
                    parts.pop(); // Remove 'meshagent' binary name
                    global._workingpath = parts.join('/') + '/';
                    console.info1('Previous Working Path: ' + global._workingpath);
                    // Continue to serviceExists to properly clean up old installation
                }
                else
                {
                    // Truly no installation found
                    logger.info('No existing installation found');
                    installService(parms);
                    return;
                }
            }
            catch (findErr)
            {
                // No installation found, proceed with fresh install
                logger.info('No existing installation found');
                installService(parms);
                return;
            }
        }
        else
        {
            // On non-macOS platforms, no fallback search - just install fresh
            logger.info('No existing installation found');
            installService(parms);
            return;
        }
    }
    if (process.execPath == loc)
    {
        parms.push('__skipBinaryDelete'); // If the installer is running from the installed service path, skip deleting the binary
    }
    serviceExists(loc, parms); // Previous installation was found, so we need to do some extra processing before we continue with installation
}

// Parse serviceId from LaunchDaemon plist Label
// Label format: "meshagent.CompanyName.ServiceName" or "meshagent"
function parseServiceIdFromLabel(label) {
    if (!label) return null;

    // Remove .plist extension if present
    if (label.endsWith('.plist')) {
        label = label.substring(0, label.length - 6);
    }

    var parts = label.split('.');

    // Simple format: "meshagent" or "TacticalMesh"
    if (parts.length === 1) {
        return {
            serviceName: parts[0],
            companyName: null,
            source: 'label-simple'
        };
    }

    // Standard format: "meshagent.CompanyName.ServiceName"
    if (parts.length === 3 && parts[0] === 'meshagent') {
        return {
            companyName: parts[1],
            serviceName: parts[2],
            source: 'label-standard'
        };
    }

    // Fallback for non-standard formats
    return null;
}

// Extract Label from LaunchDaemon plist file
function getLabelFromLaunchDaemon(binaryPath) {
    if (process.platform !== 'darwin') return null;

    var fs = require('fs');
    var child_process = require('child_process');

    // Find all plists in /Library/LaunchDaemons/ that reference this binary
    try {
        var plistDir = '/Library/LaunchDaemons';
        var plists = fs.readdirSync(plistDir).filter(function(f) {
            return f.endsWith('.plist') && (f.startsWith('meshagent') || f.indexOf('mesh') !== -1);
        });

        for (var i = 0; i < plists.length; i++) {
            var plistPath = plistDir + '/' + plists[i];
            try {
                // Check if this plist references our binary
                var progArray = child_process.execSync('/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "' + plistPath + '"', { encoding: 'utf8' }).trim();
                if (progArray === binaryPath || progArray === binaryPath + '/meshagent') {
                    // This is our plist, get the Label
                    var label = child_process.execSync('/usr/libexec/PlistBuddy -c "Print :Label" "' + plistPath + '"', { encoding: 'utf8' }).trim();
                    return label;
                }
            } catch (e) {
                // Skip plists we can't read
                continue;
            }
        }
    } catch (e) {
        return null;
    }

    return null;
}

// Parse serviceId from installation path
// ONLY supports /usr/local/mesh_services/ paths - all other paths return null
// Supported patterns:
//   /usr/local/mesh_services/meshagent/ → service: meshagent, company: null
//   /usr/local/mesh_services/{serviceName}/ → service: {serviceName}, company: null
//   /usr/local/mesh_services/{companyName}/{serviceName}/ → service: {serviceName}, company: {companyName}
function parseServiceIdFromInstallPath(installPath) {
    if (!installPath) return null;

    // Normalize path (remove trailing slash)
    if (installPath.endsWith('/')) {
        installPath = installPath.substring(0, installPath.length - 1);
    }

    var parts = installPath.split('/').filter(function(p) { return p.length > 0; });

    // Must be under /usr/local/mesh_services/ - reject all other paths
    // Expected: ['usr', 'local', 'mesh_services', ...]
    if (parts.length < 4) return null;
    if (parts[0] !== 'usr' || parts[1] !== 'local' || parts[2] !== 'mesh_services') {
        return null;
    }

    var lastPart = parts[parts.length - 1];
    var secondLastPart = parts.length >= 5 ? parts[parts.length - 2] : null;

    // Pattern: /usr/local/mesh_services/meshagent/
    if (parts.length === 4 && lastPart === 'meshagent') {
        return {
            serviceName: 'meshagent',
            companyName: null,
            source: 'path-default'
        };
    }

    // Pattern: /usr/local/mesh_services/{serviceName}/
    if (parts.length === 4) {
        return {
            serviceName: lastPart,
            companyName: null,
            source: 'path-single-folder'
        };
    }

    // Pattern: /usr/local/mesh_services/{companyName}/{serviceName}/
    if (parts.length === 5) {
        return {
            serviceName: lastPart,
            companyName: secondLastPart,
            source: 'path-two-folder'
        };
    }

    // Reject paths deeper than expected
    return null;
}

// AUTHORITATIVE: Extract service config from plist ProgramArguments
// This is the most reliable source as it reflects the actual running configuration
function getServiceConfigFromPlist(binaryPath) {
    if (process.platform !== 'darwin') return null;

    var fs = require('fs');
    var child_process = require('child_process');

    try {
        var plistDir = '/Library/LaunchDaemons';
        var plists = fs.readdirSync(plistDir).filter(function(f) {
            return f.endsWith('.plist') && (f.startsWith('meshagent') || f.indexOf('mesh') !== -1);
        });

        for (var i = 0; i < plists.length; i++) {
            var plistPath = plistDir + '/' + plists[i];
            try {
                // Check if this plist references our binary
                var progArray0 = child_process.execSync('/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "' + plistPath + '"', { encoding: 'utf8' }).trim();
                if (progArray0 === binaryPath || progArray0 === binaryPath + '/meshagent') {
                    // This is our plist, extract all ProgramArguments
                    var serviceName = null;
                    var companyName = null;

                    // Try to get array length
                    var argsLenStr = child_process.execSync('/usr/libexec/PlistBuddy -c "Print :ProgramArguments" "' + plistPath + '" | grep "Array {" -A 999 | grep -c "^ "', { encoding: 'utf8' }).trim();
                    var argsLen = parseInt(argsLenStr) || 0;

                    // Parse each argument looking for --meshServiceName and --companyName
                    for (var j = 1; j < argsLen; j++) {
                        try {
                            var arg = child_process.execSync('/usr/libexec/PlistBuddy -c "Print :ProgramArguments:' + j + '" "' + plistPath + '"', { encoding: 'utf8' }).trim();

                            if (arg.indexOf('--meshServiceName=') === 0 || arg.indexOf('--serviceName=') === 0) {
                                serviceName = arg.split('=')[1];
                            } else if (arg.indexOf('--companyName=') === 0) {
                                companyName = arg.split('=')[1];
                            }
                        } catch (e) {
                            // Skip args we can't read
                        }
                    }

                    // If we found config in ProgramArguments, return it
                    if (serviceName || companyName) {
                        return {
                            serviceName: serviceName || 'meshagent',
                            companyName: companyName || null,
                            source: 'plist-args'
                        };
                    }
                }
            } catch (e) {
                // Skip plists we can't read
                continue;
            }
        }
    } catch (e) {
        return null;
    }

    return null;
}

// Entry point for -upgrade (macOS only)
function upgradeAgent(params) {

    // LOG: -upgrade command received
    var timestamp = new Date().toISOString();
    try {
        process.stderr.write('=== -UPGRADE COMMAND RECEIVED === ' + timestamp + '\n');
        process.stderr.write('Process PID: ' + process.pid + '\n');
        process.stderr.write('Parent PID: ' + (process.ppid || 'unknown') + '\n');
    } catch (ex) {
        console.log('=== -UPGRADE COMMAND RECEIVED === ' + timestamp);
    }

    // Route macOS to unified install/upgrade function
    if (process.platform == 'darwin') {
        // Parse and add upgrade mode flag
        var parms = JSON.parse(params);
        parms.push('--_upgradeMode=1');
        return installServiceUnified(JSON.stringify(parms));
    }

    // Non-macOS platforms: Keep legacy upgrade code below
    // Parse JSON string from C code (same as fullInstall)
    var parms = JSON.parse(params);
    var child_process = require('child_process');

    // Verify this is macOS
    if (process.platform != 'darwin') {
        console.log('ERROR: The -upgrade function is currently only supported on macOS');
        process.exit(1);
    }

    // Verify root permissions
    if (!require('user-sessions').isRoot()) {
        console.log('ERROR: Upgrade requires root privileges. Please run with sudo.');
        process.exit(1);
    }

    console.log('Starting MeshAgent upgrade...\n');

    // Detect source type (bundle or standalone binary)
    var sourceType = detectSourceType();
    console.log('Source type: ' + sourceType.type);
    if (sourceType.type === 'bundle') {
        console.log('Source bundle: ' + sourceType.bundlePath);
    } else {
        console.log('Source binary: ' + sourceType.binaryPath);
    }
    console.log('');

    // Normalize parameters (handles --serviceName alias, etc.)
    checkParameters(parms);

    // Parse parameters
    var installPath = parms.getParameter('installPath', null);
    var newServiceName = parms.getParameter('meshServiceName', null);
    var newCompanyName = parms.getParameter('companyName', null);
    var newServiceId = parms.getParameter('serviceId', null);
    var disableUpdateParam = parms.getParameter('disableUpdate', null);
    var disableTccCheckParam = parms.getParameter('disableTccCheck', null);
    var meshAgentLoggingParam = parms.getParameter('meshAgentLogging', null);

    // Track if installPath was explicitly provided by user (for path inference logic)
    var installPathWasUserProvided = (installPath !== null);

    // Parse --disableUpdate parameter: null=not specified, true=disable, false=enable
    var disableUpdate = null;
    if (disableUpdateParam === '1' || disableUpdateParam === 'true') {
        disableUpdate = true;
    } else if (disableUpdateParam === '0' || disableUpdateParam === 'false') {
        disableUpdate = false;
    }

    // Parse --disableTccCheck parameter: null=not specified, true=disable, false=enable
    var disableTccCheck = null;
    if (disableTccCheckParam === '1' || disableTccCheckParam === 'true') {
        disableTccCheck = true;
    } else if (disableTccCheckParam === '0' || disableTccCheckParam === 'false') {
        disableTccCheck = false;
    }

    // Parse --meshAgentLogging parameter: enable launchd logging to /tmp for debugging
    var meshAgentLogging = (meshAgentLoggingParam === '1' || meshAgentLoggingParam === 'true');

    // Determine if we should update configuration
    var useProvidedParams = (newServiceName !== null || newCompanyName !== null);

    // Find the installation
    // NOTE: We don't pass newServiceName/newCompanyName to findInstallation because
    // those are values from the database, not the current serviceId. The findInstallation
    // function will use self-upgrade detection to find the installation directory.
    logger.info('Locating existing installation...');
    installPath = findInstallation(installPath, null, null);

    if (!installPath) {
        process.exit(1);
    }
    logger.info('Found existing installation: ' + installPath);

    // Discover service configuration using 4-tier priority system
    console.log('Discovering current service configuration...');
    var mshPath = installPath + 'meshagent.msh';
    var currentServiceName = 'meshagent';
    var currentCompanyName = null;
    var configSource = 'default';
    var fs = require('fs');

    // Priority 1: User-provided flags (highest priority)
    if (newServiceName !== null || newCompanyName !== null || newServiceId !== null) {
        currentServiceName = newServiceName || 'meshagent';
        currentCompanyName = newCompanyName;
        configSource = 'user-flags';
        console.log('   Using user-provided configuration:');
        console.log('      Service: ' + currentServiceName);
        if (currentCompanyName) {
            console.log('      Company: ' + currentCompanyName);
        }
        if (newServiceId !== null) {
            console.log('      ServiceId: ' + newServiceId);
        }
    }
    // Priority 2: Plist ProgramArguments (AUTHORITATIVE - reflects running config)
    else {
        var plistConfig = getServiceConfigFromPlist(installPath);
        if (plistConfig) {
            currentServiceName = plistConfig.serviceName || 'meshagent';
            currentCompanyName = plistConfig.companyName;
            configSource = 'plist-args';
            console.log('   Found in plist ProgramArguments:');
            console.log('      Service: ' + currentServiceName);
            if (currentCompanyName) {
                console.log('      Company: ' + currentCompanyName);
            }
        }
        // Priority 3: .msh file
        else if (fs.existsSync(mshPath)) {
            try {
                var config = parseMshFile(mshPath);
                if (config.meshServiceName || config.companyName) {
                    currentServiceName = config.meshServiceName || 'meshagent';
                    currentCompanyName = config.companyName || null;
                    configSource = 'msh-file';
                    console.log('   Found in .msh file:');
                    console.log('      Service: ' + currentServiceName);
                    if (currentCompanyName) {
                        console.log('      Company: ' + currentCompanyName);
                    }
                }
                // If no values in .msh, leave configSource='default' to try Priority 4
            } catch (e) {
                // Fall through to next priority
                console.log('   WARNING: Could not read .msh file: ' + e.message);
            }
        }
        // Priority 4: .db database (read-only access via SimpleDataStore)
        if (configSource === 'default') {
            try {
                var dbPath = installPath + 'meshagent.db';
                var db = require('SimpleDataStore').Create(dbPath, { readOnly: true });
                var meshServiceName = db.Get('meshServiceName');
                var companyName = db.Get('companyName');

                if (meshServiceName || companyName) {
                    currentServiceName = meshServiceName || 'meshagent';
                    currentCompanyName = companyName || null;
                    configSource = 'db-file';
                    console.log('   Found in .db database:');
                    console.log('      Service: ' + currentServiceName);
                    if (currentCompanyName) {
                        console.log('      Company: ' + currentCompanyName);
                    }
                }
            } catch (e) {
                // Fall through to next priority
                console.log('   WARNING: Could not read database: ' + e.message);
            }
        }
        // Priority 5: Installation path or plist Label (lowest priority)
        if (configSource === 'default' && !installPathWasUserProvided) {
            var pathConfig = parseServiceIdFromInstallPath(installPath);
            if (pathConfig) {
                currentServiceName = pathConfig.serviceName || 'meshagent';
                currentCompanyName = pathConfig.companyName;
                configSource = pathConfig.source;
                console.log('   Inferred from installation path:');
                console.log('      Service: ' + currentServiceName);
                if (currentCompanyName) {
                    console.log('      Company: ' + currentCompanyName);
                }
            } else {
                // Last resort: try plist Label
                var label = getLabelFromLaunchDaemon(installPath);
                if (label) {
                    var labelConfig = parseServiceIdFromLabel(label);
                    if (labelConfig) {
                        currentServiceName = labelConfig.serviceName || 'meshagent';
                        currentCompanyName = labelConfig.companyName;
                        configSource = labelConfig.source;
                        console.log('   Found in plist Label:');
                        console.log('      Service: ' + currentServiceName);
                        if (currentCompanyName) {
                            console.log('      Company: ' + currentCompanyName);
                        }
                    }
                }
            }
        }
    }

    console.log('');
    console.log('Configuration source: ' + configSource);
    console.log('');

    // Auto-migration: Create .msh file if it doesn't exist
    if (!fs.existsSync(mshPath) && configSource !== 'default') {
        try {
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
            console.log('   Created .msh file with discovered configuration');
            console.log('');
        } catch (e) {
            console.log('   WARNING: Could not create .msh file: ' + e.message);
            console.log('');
        }
    }
    // Auto-sync: Update .msh if it exists but differs from plist
    else if (fs.existsSync(mshPath) && configSource === 'plist-args') {
        try {
            var existingConfig = parseMshFile(mshPath);
            var needsSync = false;
            var syncUpdates = {};

            if (existingConfig.meshServiceName !== currentServiceName) {
                needsSync = true;
                syncUpdates.meshServiceName = currentServiceName;
            }
            if (existingConfig.companyName !== currentCompanyName) {
                needsSync = true;
                syncUpdates.companyName = currentCompanyName;
            }

            if (needsSync) {
                console.log('Auto-syncing .msh file with plist configuration...');
                updateMshFile(mshPath, syncUpdates);
                console.log('   Synced .msh file to match plist ProgramArguments');
                console.log('');
            }
        } catch (e) {
            // Ignore sync errors, continue with upgrade
        }
    }

    // Build CURRENT service identifier (for stopping old services)
    var currentServiceId = macOSHelpers.buildServiceId(currentServiceName, currentCompanyName, { explicitServiceId: newServiceId });

    console.log('Current Service ID: ' + currentServiceId);
    console.log('');

    // Update .msh file if parameters were provided
    if (useProvidedParams) {
        console.log('Updating configuration...');
        if (require('fs').existsSync(mshPath)) {
            try {
                var mshUpdates = {};
                if (newServiceName !== null) {
                    mshUpdates.meshServiceName = newServiceName;
                }
                if (newCompanyName !== null) {
                    mshUpdates.companyName = newCompanyName;
                }

                updateMshFile(mshPath, mshUpdates);
                console.log('   Updated .msh file:');
                if (newServiceName !== null) {
                    console.log('   Service Name: ' + newServiceName);
                }
                if (newCompanyName !== null) {
                    console.log('   Company Name: ' + newCompanyName);
                }
                console.log('');
            } catch (e) {
                console.log('   WARNING: Could not update .msh file: ' + e.message);
                console.log('   Continuing with upgrade using provided parameters.\n');
            }
        }
    } else {
        console.log('Using existing configuration from .msh file');
        console.log('   Service Name: ' + currentServiceName);
        if (currentCompanyName) {
            console.log('   Company Name: ' + currentCompanyName);
        }
        console.log('');
    }

    // Verify .db file exists (NodeID/identity)
    var dbPath = installPath + 'meshagent.db';
    if (!require('fs').existsSync(dbPath)) {
        console.log('WARNING: Identity file not found: ' + dbPath);
        console.log('Agent will need to re-register with server after upgrade.\n');
    }

    // Clean up ALL plists pointing to this binary (handles renames and orphans)
    logger.info('Cleaning up all service definitions pointing to ' + installPath + 'meshagent...');
    var cleaned = cleanupOrphanedPlists(installPath);
    if (cleaned.length > 0) {
        for (var i = 0; i < cleaned.length; i++) {
            logger.info('   Unloaded and removed: ' + cleaned[i]);
        }
    } else {
        logger.info('   No service definitions found to clean up');
    }
    console.log('');

    // ============================================================================
    // CRITICAL SAFETY CHECKS: Verify services unloaded and processes terminated
    // ============================================================================

    logger.info('');
    logger.info('========================================');
    logger.info('SAFETY VERIFICATION');
    logger.info('========================================');

    var binaryPath = installPath + 'meshagent';

    // STEP 1: Verify services are unloaded from launchd
    // This is CRITICAL - prevents launchd from auto-restarting killed processes
    logger.info('Step 1: Verifying services unloaded from launchd...');
    var unloadCheck = verifyServiceUnloaded(currentServiceId, 3);

    if (unloadCheck.loaded) {
        logger.warn('   Service still loaded in launchd (' + unloadCheck.domain + ')');
        logger.info('   Attempting force bootout...');

        var bootoutSuccess = forceBootoutService(currentServiceId, unloadCheck.domain);

        if (bootoutSuccess) {
            // Verify bootout worked
            unloadCheck = verifyServiceUnloaded(currentServiceId, 2);
            if (unloadCheck.loaded) {
                console.log('\nERROR: Could not bootout service from launchd');
                console.log('Domain: ' + unloadCheck.domain);
                console.log('Service: ' + currentServiceId);
                console.log('\nPlease manually unload the service:');
                if (unloadCheck.domain === 'system') {
                    console.log('  sudo launchctl bootout system/' + currentServiceId);
                } else {
                    console.log('  sudo launchctl bootout ' + unloadCheck.domain + '/' + currentServiceId + '-agent');
                }
                console.log('\nThen run upgrade again.');
                process.exit(1);
            }
        } else {
            console.log('\nERROR: Force bootout failed');
            console.log('Please manually unload the service and try again.');
            process.exit(1);
        }
    }
    logger.info('   Services unloaded from launchd [VERIFIED]');
    logger.info('');

    // STEP 2: Verify processes terminated
    // Now safe - launchd won't restart them after kill
    // Only targets processes from our specific binaryPath
    logger.info('Step 2: Verifying processes terminated (path: ' + binaryPath + ')...');
    var processCheck = verifyProcessesTerminated(binaryPath, 5);

    if (!processCheck.success) {
        logger.warn('   ' + processCheck.pids.length + ' process(es) still running from this path');
        logger.info('   PIDs: ' + processCheck.pids.join(', '));
        logger.info('   Attempting force kill (safe - launchd unloaded)...');

        var killSuccess = forceKillProcesses(processCheck.pids);

        // Verify processes are gone
        processCheck = verifyProcessesTerminated(binaryPath, 2);

        if (!processCheck.success) {
            console.log('\nERROR: Could not terminate all meshagent processes');
            console.log('PIDs still running from ' + binaryPath + ': ' + processCheck.pids.join(', '));
            console.log('\nPlease manually kill these processes:');
            for (var i = 0; i < processCheck.pids.length; i++) {
                console.log('  sudo kill -9 ' + processCheck.pids[i]);
            }
            console.log('\nThen run upgrade again.');
            process.exit(1);
        }
    }
    logger.info('   All processes terminated [VERIFIED]');
    logger.info('   Other meshagent installations unaffected');
    logger.info('');

    logger.info('Safety verification complete - ready for binary replacement');
    logger.info('========================================');
    logger.info('');

    // Ensure .msh file reflects determined configuration (after services stopped)
    // This writes the final determined values to .msh so they'll be in .db on next startup
    try {
        var mshExists = fs.existsSync(mshPath);
        var existingMshConfig = mshExists ? parseMshFile(mshPath) : { MeshServiceName: null, CompanyName: null, ServiceID: null };
        var mshUpdates = {};
        var needsMshUpdate = false;

        // Determine what to write for meshServiceName
        // Use current (discovered) values for auto-migration
        var serviceNameToWrite = (newServiceName !== null) ? newServiceName : currentServiceName;
        var companyNameToWrite = (newCompanyName !== null) ? newCompanyName : currentCompanyName;

        if (serviceNameToWrite && serviceNameToWrite !== 'meshagent') {
            // Non-default value: write it
            if (existingMshConfig.MeshServiceName !== serviceNameToWrite) {
                mshUpdates.MeshServiceName = serviceNameToWrite;
                needsMshUpdate = true;
            }
        } else {
            // Default value ('meshagent'): only write blank if key exists
            if (existingMshConfig.MeshServiceName) {
                mshUpdates.MeshServiceName = null;  // Blank entry to trigger DB deletion
                needsMshUpdate = true;
            }
        }

        // Determine what to write for companyName
        if (companyNameToWrite && companyNameToWrite !== '') {
            // Has value: write it
            if (existingMshConfig.CompanyName !== companyNameToWrite) {
                mshUpdates.CompanyName = companyNameToWrite;
                needsMshUpdate = true;
            }
        } else {
            // Null/empty value: only write blank if key exists
            if (existingMshConfig.CompanyName) {
                mshUpdates.CompanyName = null;  // Blank entry to trigger DB deletion
                needsMshUpdate = true;
            }
        }

        // Determine what to write for serviceId
        // Write the calculated currentServiceId (mirrors meshServiceName/companyName pattern)
        // Always write ServiceID (including default 'meshagent') for consistency and easy discovery
        var serviceIdToWrite = currentServiceId;

        if (serviceIdToWrite) {
            if (existingMshConfig.ServiceID !== serviceIdToWrite) {
                mshUpdates.ServiceID = serviceIdToWrite;
                needsMshUpdate = true;
            }
        }

        if (needsMshUpdate) {
            if (!mshExists) {
                // Create new .msh file with proper permissions
                console.log('Creating .msh file with determined configuration...');
                var mshData = 'MeshName=\n';
                mshData += 'MeshType=\n';
                mshData += 'MeshID=\n';
                mshData += 'ServerID=\n';
                mshData += 'MeshServer=\n';
                if (mshUpdates.MeshServiceName) {
                    mshData += 'MeshServiceName=' + mshUpdates.MeshServiceName + '\n';
                }
                if (mshUpdates.CompanyName) {
                    mshData += 'CompanyName=' + mshUpdates.CompanyName + '\n';
                }
                if (mshUpdates.ServiceID) {
                    mshData += 'ServiceID=' + mshUpdates.ServiceID + '\n';
                }
                fs.writeFileSync(mshPath, mshData);

                // Set secure ownership and permissions
                var mshResult = securityPermissions.setSecurePermissions(mshPath, '.msh');
                if (mshResult.success) {
                    console.log('   Created .msh file with secure permissions (root:wheel 600)');
                } else {
                    console.log('   WARNING: Could not set .msh permissions: ' + mshResult.errors.join(', '));
                }
            } else {
                // Update existing .msh file
                console.log('Updating .msh file with determined configuration...');
                updateMshFile(mshPath, mshUpdates);
                console.log('   Updated .msh file');
            }

            // Show what was written
            if (mshUpdates.MeshServiceName !== undefined) {
                if (mshUpdates.MeshServiceName) {
                    console.log('      MeshServiceName=' + mshUpdates.MeshServiceName);
                } else {
                    console.log('      MeshServiceName= (blank - will delete from DB on import)');
                }
            }
            if (mshUpdates.CompanyName !== undefined) {
                if (mshUpdates.CompanyName) {
                    console.log('      CompanyName=' + mshUpdates.CompanyName);
                } else {
                    console.log('      CompanyName= (blank - will delete from DB on import)');
                }
            }
            if (mshUpdates.ServiceID !== undefined) {
                if (mshUpdates.ServiceID) {
                    console.log('      ServiceID=' + mshUpdates.ServiceID);
                } else {
                    console.log('      ServiceID= (blank - will delete from DB on import)');
                }
            }
            console.log('');
        }
    } catch (e) {
        console.log('   WARNING: Could not update .msh file: ' + e.message);
        console.log('   Continuing with upgrade...');
        console.log('');
    }

    // Backup existing installation (bundle or standalone)
    logger.info('Backing up current installation...');
    try {
        var backupResult = backupInstallation(installPath);
        if (backupResult && backupResult.files && backupResult.files.length > 0) {
            for (var i = 0; i < backupResult.files.length; i++) {
                console.log('Backed up: ' + backupResult.files[i]);
            }
        }
    } catch (e) {
        console.log('ERROR: ' + e.message);
        console.log('Upgrade aborted.');
        process.exit(1);
    }
    console.log('');

    // Install new version (based on source type)
    logger.info('Installing new version...');
    try {
        replaceInstallation(sourceType, installPath);
    } catch (e) {
        console.log('ERROR: ' + e.message);
        console.log('Upgrade aborted. You can restore from backup if needed.');
        process.exit(1);
    }
    console.log('');

    // Determine what we just installed (bundle or standalone)
    var newInstallType = (sourceType.type === 'bundle') ? 'bundle' : 'standalone';
    console.log('Installation type: ' + newInstallType);
    console.log('');

    // Write disableUpdate to .msh file if specified
    if (disableUpdate !== null) {
        var mshPath = installPath + 'meshagent.msh';
        try {
            updateMshFile(mshPath, { disableUpdate: disableUpdate ? '1' : '0' });
            logger.info('Updated .msh with disableUpdate=' + (disableUpdate ? '1' : '0'));
        } catch (e) {
            logger.warn('Could not update .msh with disableUpdate: ' + e.message);
        }
    }

    // Write disableTccCheck to .msh file if specified
    if (disableTccCheck !== null) {
        var mshPath = installPath + 'meshagent.msh';
        try {
            updateMshFile(mshPath, { disableTccCheck: disableTccCheck ? '1' : '0' });
            logger.info('Updated .msh with disableTccCheck=' + (disableTccCheck ? '1' : '0'));
        } catch (e) {
            logger.warn('Could not update .msh with disableTccCheck: ' + e.message);
        }
    }

    // Recreate LaunchDaemon plist (using discovered/current service configuration)
    // Note: We use currentServiceName/currentCompanyName (not Final values) so that
    // plists are created with the existing configuration, even if user blanked .msh
    logger.info('Recreating LaunchDaemon...');
    try {
        createLaunchDaemon(currentServiceName, currentCompanyName, installPath, currentServiceId, newInstallType, false, null, meshAgentLogging);
    } catch (e) {
        console.log('ERROR: ' + e.message);
        console.log('You may need to manually reinstall the agent.');
        process.exit(1);
    }
    console.log('');

    // Recreate LaunchAgent plist (using discovered/current service configuration)
    logger.info('Recreating LaunchAgent...');
    try {
        createLaunchAgent(currentServiceName, currentCompanyName, installPath, currentServiceId, newInstallType, false, null, meshAgentLogging);
    } catch (e) {
        console.log('ERROR: ' + e.message);
        console.log('LaunchDaemon should still work, but KVM functionality may be limited.');
    }
    console.log('');

    // Final safety check before starting services
    logger.info('');
    logger.info('Final verification before starting services...');

    var finalLaunchdCheck = verifyServiceUnloaded(currentServiceId, 1);
    if (finalLaunchdCheck.loaded) {
        console.log('WARNING: Service unexpectedly loaded in launchd: ' + finalLaunchdCheck.domain);
        console.log('This should not happen. Proceeding with caution...');
    }

    var finalProcessCheck = verifyProcessesTerminated(binaryPath, 1);
    if (!finalProcessCheck.success) {
        console.log('WARNING: Unexpected processes detected: ' + finalProcessCheck.pids.join(', '));
        console.log('This should not happen. Proceeding with caution...');
    }

    if (!finalLaunchdCheck.loaded && finalProcessCheck.success) {
        logger.info('   Clean state verified - ready to start services');
    }

    // Small delay for system cleanup
    try {
        child_process.execSync('sleep 0.5');
    } catch (sleepError) {
        // Sleep may fail in some environments, continue anyway
    }

    logger.info('');

    // Bootstrap services (using current service ID since plists created with current config)
    logger.info('Starting services...');
    bootstrapServices(currentServiceId);
    console.log('');

    // VERIFY AND FIX FILE PERMISSIONS
    logger.info('Verifying file permissions...');
    try {
        var verifyResult = securityPermissions.verifyInstallation(installPath, { autoFix: true });

        if (verifyResult.fixed && verifyResult.fixed.length > 0) {
            console.log('   Fixed permissions on ' + verifyResult.fixed.length + ' file(s)');
        }

        if (!verifyResult.allValid && verifyResult.failed && verifyResult.failed.length > 0) {
            console.log('   WARNING: Could not fix permissions on ' + verifyResult.failed.length + ' file(s)');
        } else if (verifyResult.allValid) {
            console.log('   All file permissions verified');
        }
    } catch (e) {
        console.log('   WARNING: Permission verification failed: ' + e.message);
    }
    console.log('');

    console.log('========================================');
    console.log('Upgrade complete!');
    console.log('========================================');
    console.log('Installation path: ' + installPath);
    console.log('Service ID: ' + currentServiceId);
    console.log('');
    console.log('Configuration (.msh) and identity (.db) files preserved.');
    console.log('');

    process.exit(0);
}


module.exports =
    {
        fullInstallEx: fullInstallEx,
        fullInstall: fullInstall,
        fullUninstall: fullUninstall,
        upgradeAgent: upgradeAgent
    };


// Legacy Windows Helper function, to perform a self-update
function sys_update(isservice, b64)
{
    // This is run on the 'updated' agent. 
    
    var service = null;
    var serviceLocation = "";
    var px;

    if (isservice)
    {
        var parm = b64 != null ? JSON.parse(Buffer.from(b64, 'base64').toString()) : null;
        if (parm != null)
        {
            console.info1('sys_update(' + isservice + ', ' + JSON.stringify(parm) + ')');
            if ((px = parm.getParameterIndex('fakeUpdate')) >= 0)
            {
                console.info1('Removing "fakeUpdate" parameter');
                parm.splice(px, 1);
            }
        }

        //
        // Service  Mode
        //

        // Check if we have sufficient permission
        if (!require('user-sessions').isRoot())
        {
            // We don't have enough permissions, so copying the binary will likely fail, and we can't start...
            // This is just to prevent looping, because agentcore.c should not call us in this scenario
            console.log('* insufficient permission to continue with update');
            process._exit();
            return;
        }
        var servicename = parm != null ? (parm.getParameter('meshServiceName', process.platform == 'win32' ? 'Mesh Agent' : 'meshagent')) : (process.platform == 'win32' ? 'Mesh Agent' : 'meshagent');
        var companyName = parm != null ? parm.getParameter('companyName', null) : null;

        // Build composite service identifier to match installation naming convention (macOS only)
        var serviceId = macOSHelpers.buildServiceId(servicename, companyName);

        try
        {
            if (b64 == null) { throw ('legacy'); }
            service = require('service-manager').manager.getService(serviceId)
            serviceLocation = service.appLocation();
            console.log(' Updating service: ' + serviceId);
        }
        catch (f)
        {
            // Check to see if we can figure out the service name before we fail
            var old = process.execPath.split('.update.exe').join('.exe');
            var child = require('child_process').execFile(old, [old.split('\\').pop(), '-name']);
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.waitExit();
              
            if (child.stdout.str.trim() == '' && b64 == null) { child.stdout.str = 'Mesh Agent'; }
            if (child.stdout.str.trim() != '')
            {
                if (child.stdout.str.trim().split('\n').length > 1) { child.stdout.str = 'Mesh Agent'; }
                try
                {
                    service = require('service-manager').manager.getService(child.stdout.str.trim())
                    serviceLocation = service.appLocation();
                    console.log(' Updating service: ' + child.stdout.str.trim());
                }
                catch (ff)
                {
                    console.log(' * ' + servicename + ' SERVICE NOT FOUND *');
                    console.log(' * ' + child.stdout.str.trim() + ' SERVICE NOT FOUND *');
                    process._exit();
                }
            }
            else
            {
                console.log(' * ' + servicename + ' SERVICE NOT FOUND *');
                process._exit();
            }
        }
    }

    if (!global._interval)
    {
        global._interval = setInterval(sys_update, 60000, isservice, b64);
    }

    if (isservice === false)
    {
        //
        // Console Mode (LEGACY)
        //
        if (process.platform == 'win32')
        {
            serviceLocation = process.execPath.split('.update.exe').join('.exe');
        }
        else
        {
            serviceLocation = process.execPath.substring(0, process.execPath.length - 7);
        }

        if (serviceLocation != process.execPath)
        {
            try
            {
                require('fs').copyFileSync(process.execPath, serviceLocation);
            }
            catch (ce)
            {
                console.log('\nAn error occured while updating agent.');
                process.exit();
            }
        }

        // Copied agent binary... Need to start agent in console mode
        console.log('\nAgent update complete... Please re-start agent.');
        process.exit();
    }


    service.stop().finally(function ()
    {
        require('process-manager').enumerateProcesses().then(function (proc)
        {
            for (var p in proc)
            {
                if (proc[p].path == serviceLocation)
                {
                    process.kill(proc[p].pid);
                }
            }

            try
            {
                require('fs').copyFileSync(process.execPath, serviceLocation);
            }
            catch (ce)
            {
                console.log('Could not copy file.. Trying again in 60 seconds');
                service.close();
                return;
            }

            console.log('Agent update complete. Starting service...');
            service.start();
            process._exit();
        });
    });
}

// Another Windows Legacy Helper for Self-Update, that shows the updater version
function agent_updaterVersion(updatePath)
{
    var ret = 0;
    if (updatePath == null) { updatePath = process.execPath; }
    var child;

    try
    {
        child = require('child_process').execFile(updatePath, [updatePath.split(process.platform == 'win32' ? '\\' : '/').pop(), '-updaterversion']);
    }
    catch(x)
    {
        return (0);
    }
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();

    if(child.stdout.str.trim() == '')
    {
        ret = 0;
    }
    else
    {
        ret = parseInt(child.stdout.str);
        if (isNaN(ret)) { ret = 0; }
    }
    return (ret);
}


// Windows Helper to clear firewall entries
function win_clearfirewall(passthru)
{
    logger.info('Clearing firewall rules...');
    var p = require('win-firewall').getFirewallRulesAsync({ program: process.execPath, noResult: true, minimal: true, timeout: 15000 });
    p.on('progress', function (c)
    {
        logger.debug('Clearing firewall rules progress: ' + c);
    });
    p.on('rule', function (r)
    {
        require('win-firewall').removeFirewallRule(r.DisplayName);
    });
    p.finally(function ()
    {
        logger.info('Firewall rules cleared');
        if (passthru == null) { process.exit(); }
    });
    if(passthru!=null)
    {
        return (p);
    }
}

// Windows Helper for enumerating Firewall Rules associated with our binary
function win_checkfirewall()
{
    logger.info('Checking firewall rules...');
    var p = require('win-firewall').getFirewallRulesAsync({ program: process.execPath, noResult: true, minimal: true, timeout: 15000 });
    p.foundItems = 0;
    p.on('progress', function (c)
    {
        logger.debug('Checking firewall rules progress: ' + c);
    });
    p.on('rule', function (r)
    {
        this.foundItems++;
    });
    p.finally(function ()
    {
        logger.info('Firewall rules check completed');
        logger.info('Rules found: ' + this.foundItems);

        process.exit();
    });
}

// Windows Helper for setting a firewall rule entry
function win_setfirewall()
{
    var p = win_clearfirewall(true);
    p.finally(function ()
    {
        var rule =
            {
                DisplayName: 'MeshCentral WebRTC Traffic',
                direction: 'inbound',
                Program: process.execPath,
                Protocol: 'UDP',
                Profile: 'Public, Private, Domain',
                Description: 'Mesh Central Agent WebRTC P2P Traffic',
                EdgeTraversalPolicy: 'allow',
                Enabled: true
            };
        require('win-firewall').addFirewallRule(rule);
        logger.info('Firewall rules added');
        process.exit();
    });

}

// Windows Helper, for performing SelfUpdate on Console Mode Agent
function win_consoleUpdate()
{
    // This is run from the 'old' agent, to copy the 'updated' agent.
    var copy = [];
    copy.push("try { require('fs').copyFileSync(process.execPath, process.execPath.split('.update.exe').join('.exe')); }");
    copy.push("catch (x) { console.log('\\nError updating Mesh Agent.'); process.exit(); }");
    copy.push("if(require('child_process')._execve==null) { console.log('\\nMesh Agent was updated... Please re-run from the command line.'); process.exit(); }");
    copy.push("require('child_process')._execve(process.execPath.split('.update.exe').join('.exe'), [process.execPath.split('.update.exe').join('.exe'), 'run']);");
    var args = [];
    args.push(process.execPath.split('.exe').join('.update.exe'));
    args.push('-b64exec');
    args.push(Buffer.from(copy.join('\r\n')).toString('base64'));
    console.info1('_execve("' + process.execPath.split('.exe').join('.update.exe') + '", ' + JSON.stringify(args) + ');');
    require('child_process')._execve(process.execPath.split('.exe').join('.update.exe'), args);
}


// Legacy Helper for Windows Self-Update. Shouldn't really be used anymore, but is still here for Legacy Support
module.exports.update = sys_update;
module.exports.updaterVersion = agent_updaterVersion;

if (process.platform == 'win32')
{
    module.exports.consoleUpdate = win_consoleUpdate;   // Windows Helper, for performing SelfUpdate on Console Mode Agent
    module.exports.clearfirewall = win_clearfirewall;   // Windows Helper, to clear firewall entries
    module.exports.setfirewall = win_setfirewall;       // Windows Helper, to set firewall entries
    module.exports.checkfirewall = win_checkfirewall;   // Windows Helper, to check firewall rules
}
