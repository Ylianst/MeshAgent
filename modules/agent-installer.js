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
                        if (ret.startsWith('"')) { ret = ret.substring(1, ret.length - 1); }
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

    // If path ends with 'meshagent' (binary name), extract directory
    if (path.endsWith('/meshagent') || path.endsWith('meshagent')) {
        var parts = path.split('/');
        parts.pop();
        return parts.join('/') + '/';
    }

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
    // If explicit path provided
    if (installPath) {
        installPath = normalizeInstallPath(installPath);
        // Check for bundle first using dynamic discovery, then standalone binary
        var bundleName = findBundleInDirectory(installPath);
        if (bundleName) {
            return installPath;
        }
        if (require('fs').existsSync(installPath + 'meshagent')) {
            return installPath;
        }
        console.log('ERROR: No installation found at: ' + installPath);
        return null;
    }

    // Try to find service by name
    if (serviceName || companyName) {
        try {
            var serviceId = macOSHelpers.buildServiceId(serviceName || 'meshagent', companyName);

            var svc = require('service-manager').manager.getService(serviceId);
            var path = svc.appWorkingDirectory();
            svc.close();
            return path;
        } catch (e) {
            console.log('ERROR: Service not found: ' + (serviceName || 'meshagent'));
            return null;
        }
    }

    // Check if we're running from an installed location (self-upgrade scenario)
    // Look for .msh file alongside process.execPath
    var selfDir = process.execPath.substring(0, process.execPath.lastIndexOf('/') + 1);
    var selfMshPath = selfDir + 'meshagent.msh';

    if (require('fs').existsSync(selfMshPath)) {
        console.log('Detected self-upgrade scenario (found .msh alongside running binary)');
        return selfDir;
    }

    // Try default location
    var defaultPath = '/usr/local/mesh_services/meshagent/';
    if (require('fs').existsSync(defaultPath + 'meshagent')) {
        return defaultPath;
    }

    console.log('ERROR: No installation found at default location: ' + defaultPath);
    console.log('Please specify --installPath, --serviceName, or --companyName');
    return null;
}

// Helper to stop LaunchDaemon
function stopLaunchDaemon(serviceId) {
    try {
        var svc = require('service-manager').manager.getService(serviceId);

        if (svc.isRunning == null || svc.isRunning()) {
            svc.unload();
            process.stdout.write('   LaunchDaemon stopped\n');
        } else {
            process.stdout.write('   LaunchDaemon already stopped\n');
        }

        svc.close();
        return true;
    } catch (e) {
        process.stdout.write('   WARNING: Could not stop LaunchDaemon: ' + e + '\n');
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
            process.stdout.write('   LaunchAgent stopped\n');
        } else {
            process.stdout.write('   No console user logged in, LaunchAgent not running\n');
        }
        return true;
    } catch (e) {
        process.stdout.write('   WARNING: Could not stop LaunchAgent: ' + e + '\n');
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
        return child.stdout.str.trim();
    } catch (e) {
        return null;
    }
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
            if (files[i].endsWith('.plist')) {
                var plistPath = daemonDir + '/' + files[i];
                var plistBinary = getProgramPathFromPlist(plistPath);

                // Check if plist points to our installation:
                // 1. Exact match for standalone binary
                // 2. Exact match for current bundle binary
                // 3. Any bundle in the install directory (e.g., /opt/tacticalmesh/*.app/Contents/MacOS/meshagent)
                var matchesInstallPath = false;
                if (plistBinary === binaryPath || plistBinary === bundleBinaryPath) {
                    matchesInstallPath = true;
                } else if (plistBinary && plistBinary.indexOf(installPath) === 0 && plistBinary.indexOf('.app/Contents/MacOS/meshagent') > 0) {
                    // Plist points to a bundle in our install directory
                    matchesInstallPath = true;
                }

                if (matchesInstallPath) {
                    // This plist points to our installation - unload and delete it
                    try {
                        var serviceName = files[i].replace('.plist', '');
                        var svc = require('service-manager').manager.getService(serviceName);
                        svc.unload();
                        svc.close();
                    } catch (e) {
                        // Log unload errors for diagnostics (except "not loaded")
                        if (e.message && e.message.indexOf('not loaded') === -1 && e.message.indexOf('Could not find') === -1) {
                            process.stdout.write('      WARNING: Unload error for ' + serviceName + ': ' + e.message + '\n');
                        }
                        // Continue - will be verified in safety checks
                    }

                    require('fs').unlinkSync(plistPath);
                    cleaned.push(plistPath);
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
            if (files[i].endsWith('.plist')) {
                var plistPath = agentDir + '/' + files[i];
                var plistBinary = getProgramPathFromPlist(plistPath);

                // Check if plist points to our installation (same logic as LaunchDaemons)
                var matchesInstallPath = false;
                if (plistBinary === binaryPath || plistBinary === bundleBinaryPath) {
                    matchesInstallPath = true;
                } else if (plistBinary && plistBinary.indexOf(installPath) === 0 && plistBinary.indexOf('.app/Contents/MacOS/meshagent') > 0) {
                    matchesInstallPath = true;
                }

                if (matchesInstallPath) {
                    // This plist points to our installation - unload and delete it
                    try {
                        var serviceName = files[i].replace('.plist', '');
                        var launchAgent = require('service-manager').manager.getLaunchAgent(serviceName);

                        // Unload for ALL logged in users, not just console user
                        try {
                            var sessions = require('user-sessions').enumerateUsers();
                            for (var j = 0; j < sessions.length; j++) {
                                if (sessions[j].uid && sessions[j].uid > 0) {
                                    try {
                                        launchAgent.unload(sessions[j].uid);
                                    } catch (unloadErr) {
                                        // Agent might not be loaded for this user - that's OK
                                        if (unloadErr.message && unloadErr.message.indexOf('not loaded') === -1 && unloadErr.message.indexOf('Could not find') === -1) {
                                            process.stdout.write('      WARNING: Unload error for ' + serviceName + ' (uid ' + sessions[j].uid + '): ' + unloadErr.message + '\n');
                                        }
                                    }
                                }
                            }
                        } catch (enumErr) {
                            // If we can't enumerate users, fall back to console user
                            var uid = require('user-sessions').consoleUid();
                            if (uid && uid > 0) {
                                launchAgent.unload(uid);
                            }
                        }
                    } catch (e) {
                        // Log unload errors for diagnostics (except "not loaded")
                        if (e.message && e.message.indexOf('not loaded') === -1 && e.message.indexOf('Could not find') === -1) {
                            process.stdout.write('      WARNING: Unload error for ' + serviceName + ': ' + e.message + '\n');
                        }
                        // Continue - will be verified in safety checks
                    }

                    require('fs').unlinkSync(plistPath);
                    cleaned.push(plistPath);
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
    var deletedFiles = [];

    process.stdout.write('   Removing installation files from: ' + installPath + '\n');

    // Check if there's a bundle in this directory
    var bundleRemoved = false;
    try {
        var files = fs.readdirSync(installPath);
        for (var i = 0; i < files.length; i++) {
            if (files[i].endsWith('.app')) {
                // Found a bundle - remove it completely
                var bundlePath = installPath + files[i];
                process.stdout.write('   Removing bundle: ' + bundlePath + '\n');
                try {
                    child_process.execSync('rm -rf "' + bundlePath + '"');
                    deletedFiles.push(files[i]);
                    bundleRemoved = true;
                } catch (e) {
                    process.stdout.write('   WARNING: Could not delete bundle: ' + e + '\n');
                }
                break;  // Only one bundle expected
            }
        }
    } catch (e) {
        process.stdout.write('   WARNING: Could not scan directory for bundles: ' + e + '\n');
    }

    // Always remove .msh file (contains server URL configuration)
    try {
        var mshFile = installPath + 'meshagent.msh';
        if (fs.existsSync(mshFile)) {
            fs.unlinkSync(mshFile);
            deletedFiles.push('meshagent.msh');
        }
    } catch (e) {
        process.stdout.write('   WARNING: Could not delete .msh file: ' + e + '\n');
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
            process.stdout.write('   WARNING: Could not delete DAIPC socket: ' + e + '\n');
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
                        process.stdout.write('   WARNING: Could not delete ' + files[i] + ': ' + fileErr + '\n');
                    }
                }
            }
        } catch (e) {
            process.stdout.write('   WARNING: Could not scan directory: ' + e + '\n');
        }

        // Try to remove the installation directory itself
        try {
            fs.rmdirSync(installPath);
            process.stdout.write('   Removed installation directory: ' + installPath + '\n');
        } catch (e) {
            // Directory might not be empty (other files present) - that's okay
        }
    }

    if (deletedFiles.length > 0) {
        process.stdout.write('   Deleted ' + deletedFiles.length + ' file(s)\n');
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
            process.stdout.write('   Removed: ' + daemonPlist + '\n');
            deleted = true;
        }
    } catch (e) {
        process.stdout.write('   WARNING: Could not delete LaunchDaemon plist: ' + e + '\n');
    }

    // LaunchAgent plist
    var agentPlist = macOSHelpers.getPlistPath(serviceId, 'agent');
    try {
        if (require('fs').existsSync(agentPlist)) {
            require('fs').unlinkSync(agentPlist);
            process.stdout.write('   Removed: ' + agentPlist + '\n');
            deleted = true;
        }
    } catch (e) {
        process.stdout.write('   WARNING: Could not delete LaunchAgent plist: ' + e + '\n');
    }

    if (!deleted) {
        process.stdout.write('   No plist files found to delete\n');
    }
}

// Helper to backup existing installation (bundle or standalone binary) with timestamp
function backupInstallation(installPath) {
    var fs = require('fs');
    var timestamp = Date.now().toString();
    var backedUp = false;

    try {
        // Check for bundle and back it up using dynamic discovery
        var bundleName = findBundleInDirectory(installPath);
        if (bundleName) {
            // Backup bundle by renaming
            var bundlePath = installPath + bundleName;
            var backupPath = installPath + bundleName + '.' + timestamp;
            fs.renameSync(bundlePath, backupPath);
            process.stdout.write('   Created backup: ' + bundleName + '.' + timestamp + '\n');
            backedUp = true;
        }

        // Check for standalone binary and back it up (handles edge case where both exist)
        if (fs.existsSync(installPath + 'meshagent')) {
            var binaryPath = installPath + 'meshagent';
            var backupPath = installPath + 'meshagent.' + timestamp;
            fs.copyFileSync(binaryPath, backupPath);
            fs.unlinkSync(binaryPath);
            process.stdout.write('   Created backup: meshagent.' + timestamp + '\n');
            backedUp = true;
        }

        if (!backedUp) {
            process.stdout.write('   No existing installation to backup\n');
        }

        return null;
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
    var path = require('path');

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

    try {
        if (sourceType.type === 'bundle') {

            // Copy entire bundle - get bundle name from source
            var sourceBundlePath = sourceType.bundlePath;

            var bundleName = sourceBundlePath.substring(sourceBundlePath.lastIndexOf('/') + 1);

            var targetBundlePath = installPath + bundleName;

            // Source bundle should already be backed up by backupInstallation()
            // Just copy the new bundle
            process.stdout.write('   Copying application bundle...\n');

            // Use ditto on macOS to properly copy app bundles with all attributes
            // ditto preserves resource forks, extended attributes, ACLs, metadata, and code signatures
            var dittoError = null;
            var child = child_process.execFile('/usr/bin/ditto', ['ditto', sourceType.bundlePath, targetBundlePath]);
            child.stdout.on('data', function(d) { process.stdout.write(d); });
            child.stderr.on('data', function(d) { dittoError = d.toString(); process.stderr.write(d); });
            child.waitExit();

            // Check if bundle was actually copied by verifying the binary exists
            var binaryPath = targetBundlePath + '/Contents/MacOS/meshagent';
            if (!fs.existsSync(binaryPath)) {
                throw new Error('Bundle copy failed. ' + (dittoError || 'Binary not found after copy'));
            }

            // Ensure binary is executable
            fs.chmodSync(binaryPath, 0o755);
            process.stdout.write('   Bundle installed: ' + targetBundlePath + '\n');
        } else {
            // Copy standalone binary
            var targetBinaryPath = installPath + 'meshagent';
            var sourceBinaryPath = sourceType.binaryPath;

            // Check if we're trying to copy the binary over itself (in-place upgrade)
            if (sourceBinaryPath === targetBinaryPath) {
                process.stdout.write('   Skipping binary copy (already running from install location)\n');
                process.stdout.write('   NOTE: To upgrade with a new binary, run the new meshagent with -upgrade\n');
                process.stdout.write('         Example: sudo /path/to/new/meshagent -upgrade --installPath="' + installPath + '"\n');
                return;
            }

            // Old binary should already be backed up by backupInstallation()
            // Copy new binary to install location
            process.stdout.write('   Copying standalone binary...\n');
            fs.copyFileSync(sourceBinaryPath, targetBinaryPath);

            // Ensure executable permissions
            fs.chmodSync(targetBinaryPath, 0o755);

            process.stdout.write('   Binary installed: ' + targetBinaryPath + '\n');
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
            process.stdout.write('   Forcing bootout from system domain...\n');
            child_process.execSync('launchctl bootout system/' + serviceId + ' 2>/dev/null', { encoding: 'utf8' });
        } else if (domain && domain.startsWith('gui/')) {
            var agentId = serviceId + '-agent';
            process.stdout.write('   Forcing bootout from ' + domain + '...\n');
            child_process.execSync('launchctl bootout ' + domain + '/' + agentId + ' 2>/dev/null', { encoding: 'utf8' });
        }

        // Give launchd time to process
        child_process.execSync('sleep 1');

        return true;
    } catch (e) {
        process.stdout.write('   Bootout failed: ' + e.message + '\n');
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

    process.stdout.write('   Forcing termination of ' + pids.length + ' process(es): ' + pids.join(', ') + '\n');

    var allKilled = true;
    for (var i = 0; i < pids.length; i++) {
        try {
            process.kill(pids[i], 9); // SIGKILL
            process.stdout.write('   Killed PID ' + pids[i] + '\n');
        } catch (e) {
            process.stdout.write('   Failed to kill PID ' + pids[i] + ': ' + e.message + '\n');
            allKilled = false;
        }
    }

    // Give system time to clean up
    child_process.execSync('sleep 1');

    return allKilled;
}

// Helper to create LaunchDaemon
function createLaunchDaemon(serviceName, companyName, installPath, serviceId, installType, disableUpdate) {
    try {
        // Determine binary path based on installation type
        var servicePath;
        var options = {
            name: serviceName,
            target: 'meshagent',
            startType: 'AUTO_START',
            parameters: ['--serviceId=' + serviceId],
            companyName: companyName
        };

        // Add --disableUpdate flag if requested (for bundle installations)
        if (disableUpdate) {
            options.parameters.push('--disableUpdate=1');
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
            // Add --configUsesCWD so agent looks for config files in WorkingDirectory
            options.parameters.push('--configUsesCWD="1"');
        } else {
            // For standalone installations, let service-manager copy the binary if needed
            servicePath = installPath + 'meshagent';
            options.servicePath = servicePath;
            options.installPath = installPath;
        }

        require('service-manager').manager.installService(options);
        process.stdout.write('   LaunchDaemon created\n');
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
function createLaunchAgent(serviceName, companyName, installPath, serviceId, installType) {
    try {
        // Determine binary path based on installation type
        var servicePath;
        var options = {
            name: serviceName,
            companyName: companyName,
            startType: 'AUTO_START',
            sessionTypes: ['Aqua', 'LoginWindow'],
            parameters: ['-kvm1', '--serviceId=' + serviceId]
        };

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
        process.stdout.write('   LaunchAgent created\n');
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
    // Load LaunchDaemon
    try {
        var svc = require('service-manager').manager.getService(serviceId);
        svc.load();
        svc.start();
        process.stdout.write('   LaunchDaemon started\n');
        svc.close();
    } catch (e) {
        process.stdout.write('   WARNING: Could not start LaunchDaemon: ' + e + '\n');
    }

    // Bootstrap LaunchAgent
    try {
        var uid = require('user-sessions').consoleUid();

        if (uid && uid > 0) {
            // LaunchAgent name has '-agent' suffix
            var launchAgent = require('service-manager').manager.getLaunchAgent(serviceId + '-agent');
            launchAgent.load(uid);
            process.stdout.write('   LaunchAgent started\n');
        } else {
            process.stdout.write('   LaunchAgent will start at next user login\n');
        }
    } catch (e) {
        process.stdout.write('   WARNING: Could not start LaunchAgent: ' + e + '\n');
    }
}

// ===== END UPGRADE HELPER FUNCTIONS =====

// ===== UNIFIED INSTALL/UPGRADE (macOS) =====
// This function merges install and upgrade logic for macOS
// Future: Will be migrated to Linux, then Windows
function installServiceUnified(params) {
    // Parse JSON string from C code (same as fullInstall)
    var parms = JSON.parse(params);
    var child_process = require('child_process');
    var fs = require('fs');

    // Verify root permissions
    if (!require('user-sessions').isRoot()) {
        console.log('ERROR: Installation/upgrade requires root privileges. Please run with sudo.');
        process.exit(1);
    }

    // Detect source type (bundle or standalone binary)
    var sourceType = detectSourceType();

    // Normalize parameters (handles --serviceName alias, etc.)
    checkParameters(parms);

    // Parse key parameters
    var installPath = parms.getParameter('installPath', null);
    var newServiceName = parms.getParameter('meshServiceName', null);
    var newCompanyName = parms.getParameter('companyName', null);
    var newServiceId = parms.getParameter('serviceId', null);
    var enableDisableUpdate = parms.getParameter('enableDisableUpdate', null);
    var copyMsh = parms.getParameter('copy-msh', null);
    var omitBackup = (parms.indexOf('--omit-backup') >= 0);
    var upgradeMode = (parms.indexOf('--_upgradeMode=1') >= 0);

    // Convert enableDisableUpdate to boolean
    var disableUpdate = (enableDisableUpdate === '1' || enableDisableUpdate === 'true');

    // Determine operation mode
    var isFreshInstall = false;
    var isUpgrade = false;
    var currentServiceName = 'meshagent';
    var currentCompanyName = null;
    var currentServiceId = null;

    // Try to find existing installation
    var existingInstallPath = null;
    try {
        existingInstallPath = findInstallation(installPath, null, null);
    } catch (e) {
        // No existing installation found
    }

    // Determine operation mode based on existing installation and flags
    if (existingInstallPath && copyMsh !== '1') {
        // Existing installation + no --copy-msh="1" → UPGRADE mode
        isUpgrade = true;
        installPath = existingInstallPath;
        console.log('Existing installation detected at: ' + installPath);
        console.log('Mode: UPGRADE (preserve configuration)\n');
    } else if (existingInstallPath && copyMsh === '1') {
        // Existing installation + --copy-msh="1" → FRESH INSTALL mode
        isFreshInstall = true;
        installPath = existingInstallPath;
        console.log('Existing installation detected at: ' + installPath);
        console.log('Mode: FRESH INSTALL (--copy-msh="1" will overwrite configuration)\n');
    } else if (!existingInstallPath && installPath) {
        // No existing installation + explicit installPath → FRESH INSTALL
        isFreshInstall = true;
        console.log('Mode: FRESH INSTALL (no existing installation)\n');
        console.log('Target installation path: ' + installPath);
    } else {
        // No existing installation + no installPath → ERROR
        console.log('ERROR: No existing installation found and no --installPath specified');
        process.exit(1);
    }

    // For UPGRADE mode: Discover current configuration
    if (isUpgrade) {
        console.log('Discovering current service configuration...');
        var mshPath = installPath + 'meshagent.msh';
        var configSource = 'default';

        // Priority 1: User-provided flags (highest priority)
        if (newServiceName !== null || newCompanyName !== null || newServiceId !== null) {
            currentServiceName = newServiceName || 'meshagent';
            currentCompanyName = newCompanyName;
            currentServiceId = newServiceId;
            configSource = 'user-flags';
            console.log('   Using user-provided configuration:');
            console.log('      Service: ' + currentServiceName);
            if (currentCompanyName) {
                console.log('      Company: ' + currentCompanyName);
            }
            if (currentServiceId) {
                console.log('      ServiceId: ' + currentServiceId);
            }
        }
        // Priority 2: Plist ProgramArguments (AUTHORITATIVE)
        else {
            var plistConfig = getServiceConfigFromPlist(installPath);
            if (plistConfig) {
                currentServiceName = plistConfig.serviceName || 'meshagent';
                currentCompanyName = plistConfig.companyName;
                currentServiceId = plistConfig.serviceId;
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
                } catch (e) {
                    console.log('   Warning: Could not parse .msh file: ' + e);
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
                            console.log('   Found in .db database:');
                            console.log('      Service: ' + currentServiceName);
                            if (currentCompanyName) {
                                console.log('      Company: ' + currentCompanyName);
                            }
                        }
                    }
                } catch (e) {
                    console.log('   Warning: Could not read .db database: ' + e);
                }
            }
        }

        console.log('\nConfiguration source: ' + configSource + '\n');

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

    console.log('Current Service ID: ' + currentServiceId + '\n');

    // Check for .msh and .db files (for reporting purposes)
    var mshExists = fs.existsSync(installPath + 'meshagent.msh');
    var dbExists = fs.existsSync(installPath + 'meshagent.db');

    if (!mshExists && !dbExists && !isFreshInstall) {
        console.log('WARNING: Identity file not found: ' + installPath + 'meshagent.db');
        console.log('Agent will need to re-register with server after upgrade.\n');
    }

    // Cleanup orphaned plists
    console.log('Cleaning up all service definitions pointing to ' + installPath + 'meshagent...');
    try {
        var cleanedCount = cleanupOrphanedPlists(installPath);
        if (cleanedCount > 0) {
            console.log('   Cleaned up ' + cleanedCount + ' orphaned plist(s)\n');
        } else {
            console.log('   No service definitions found to clean up\n');
        }
    } catch (e) {
        console.log('   Warning: Could not clean up orphaned plists: ' + e + '\n');
    }

    // SAFETY VERIFICATION (Always mandatory)
    console.log('========================================');
    console.log('SAFETY VERIFICATION');
    console.log('========================================');

    // Step 1: Verify services unloaded from launchd
    console.log('Step 1: Verifying services unloaded from launchd...');
    try {
        var unloadSuccess = verifyServiceUnloaded(currentServiceId, 3);
        if (unloadSuccess) {
            console.log('   Services unloaded from launchd [VERIFIED]');
        } else {
            console.log('   ERROR: Could not verify service unload');
            process.exit(1);
        }
    } catch (e) {
        console.log('   ERROR: Service unload verification failed: ' + e);
        process.exit(1);
    }

    // Step 2: Verify processes terminated
    var binaryPath = installPath + 'meshagent';
    var installType = detectInstallationType(installPath);
    if (installType === 'bundle') {
        var bundleName = findBundleInDirectory(installPath);
        if (bundleName) {
            binaryPath = installPath + bundleName + '/Contents/MacOS/meshagent';
        }
    }

    console.log('\nStep 2: Verifying processes terminated (path: ' + binaryPath + ')...');
    try {
        var terminateSuccess = verifyProcessesTerminated(binaryPath, 10);
        if (terminateSuccess) {
            console.log('   All processes terminated [VERIFIED]');
            console.log('   Other meshagent installations unaffected');
        } else {
            console.log('   ERROR: Could not verify process termination');
            process.exit(1);
        }
    } catch (e) {
        console.log('   ERROR: Process termination verification failed: ' + e);
        process.exit(1);
    }

    console.log('\nSafety verification complete - ready for binary replacement');
    console.log('========================================\n');

    // BACKUP (Unless --omit-backup specified)
    if (!omitBackup && existingInstallPath) {
        console.log('Backing up current installation...');
        try {
            var backupName = backupInstallation(installPath);
            console.log('   Created backup: ' + backupName + '\n');
        } catch (e) {
            console.log('   ERROR: Backup failed: ' + e);
            process.exit(1);
        }
    } else if (omitBackup) {
        console.log('Skipping backup (--omit-backup specified)\n');
    }

    // INSTALL/REPLACE BINARY
    console.log('Installing new version...');
    try {
        replaceInstallation(sourceType, installPath);
        console.log('');
    } catch (e) {
        console.log('ERROR: Installation failed: ' + e);
        process.exit(1);
    }

    console.log('Installation type: ' + (sourceType.type === 'bundle' ? 'bundle' : 'standalone') + '\n');

    // HANDLE .msh FILE
    if (isFreshInstall && copyMsh === '1') {
        // Copy .msh file from source location
        console.log('Copying .msh configuration file...');
        var sourceMshFile;
        var bundleParent = macOSHelpers.getBundleParentDirectory();
        if (bundleParent) {
            sourceMshFile = bundleParent + 'meshagent.msh';
        } else {
            sourceMshFile = process.execPath + '.msh';
        }

        if (!fs.existsSync(sourceMshFile)) {
            console.log('ERROR: Cannot find .msh file at: ' + sourceMshFile);
            process.exit(1);
        }

        var targetMshFile = installPath + 'meshagent.msh';
        try {
            fs.copyFileSync(sourceMshFile, targetMshFile);
            console.log('   .msh file copied to: ' + targetMshFile + '\n');
        } catch (e) {
            console.log('ERROR: Failed to copy .msh file: ' + e);
            process.exit(1);
        }
    }

    // CREATE SERVICES
    console.log('Recreating LaunchDaemon...');
    try {
        var daemonParams = parms.slice(); // Copy parameters
        if (disableUpdate) {
            daemonParams.push('--disableUpdate=1');
        }
        createLaunchDaemon(currentServiceName, currentCompanyName, installPath, currentServiceId, sourceType.type, daemonParams);
    } catch (e) {
        console.log('ERROR: Failed to create LaunchDaemon: ' + e);
        process.exit(1);
    }

    console.log('\nRecreating LaunchAgent...');
    try {
        createLaunchAgent(currentServiceName, currentCompanyName, installPath, currentServiceId, sourceType.type);
    } catch (e) {
        console.log('ERROR: Failed to create LaunchAgent: ' + e);
        process.exit(1);
    }

    // FINAL VERIFICATION
    console.log('\n\nFinal verification before starting services...');
    try {
        var finalVerify = verifyServiceUnloaded(currentServiceId, 1);
        if (finalVerify) {
            console.log('   Clean state verified - ready to start services\n');
        }
    } catch (e) {
        console.log('   Warning: Final verification failed: ' + e + '\n');
    }

    // START SERVICES
    console.log('Starting services...');
    try {
        bootstrapServices(currentServiceId);
    } catch (e) {
        console.log('ERROR: Failed to start services: ' + e);
        process.exit(1);
    }

    // SUCCESS MESSAGE
    console.log('\n========================================');
    if (isUpgrade) {
        console.log('Upgrade complete!');
    } else {
        console.log('Installation complete!');
    }
    console.log('========================================');
    console.log('Installation path: ' + installPath);
    console.log('Service ID: ' + currentServiceId);
    console.log('');
    if (isUpgrade && (mshExists || dbExists)) {
        console.log('Configuration (.msh) and identity (.db) files preserved.');
    }
    console.log('');
}

// This is the entry point for installing the service
function installService(params)
{
    // Route macOS to unified install/upgrade function
    if (process.platform == 'darwin') {
        return installServiceUnified(params);
    }

    // Linux/Windows continue with legacy install code below
    process.stdout.write('...Installing service');
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
            process.stdout.write('\nError: Cannot find .msh file at: ' + mshFile + '\n');
            process.stdout.write('The --copy-msh="1" parameter requires a .msh configuration file.\n');
            process.stdout.write('Please place the .msh file next to the binary and try again.\n\n');
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
            options.parameters.push('--installPath="' + global._workingpath + '"');
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

    // Check if --enableDisableUpdate flag was passed to enable disableUpdate
    if ((i = options.parameters.getParameterIndex('enableDisableUpdate')) >= 0) {
        var enableValue = options.parameters.getParameterValue(i);
        if (enableValue === '1' || enableValue === 'true') {
            // Add --disableUpdate=1 to prevent self-updates
            options.parameters.push('--disableUpdate=1');
        }
        // Remove the enableDisableUpdate flag itself (it's only used during installation)
        options.parameters.splice(i, 1);
    }

    if (global.gOptions != null && global.gOptions.noParams === true) { options.parameters = []; }

    try
    {
        // Let's actually install the service
        require('service-manager').manager.installService(options);
        process.stdout.write(' [DONE]\n');
        if(process.platform == 'win32')
        {
            // On Windows, we're going to enable this service to be runnable from SafeModeWithNetworking
            require('win-bcd').enableSafeModeService(options.name);
        }
    }
    catch(sie)
    {
        process.stdout.write(' [ERROR] ' + sie);
        process.exit();
    }
    // Get the service object for starting
    var svc = require('service-manager').manager.getService(options.name);

    // For Windows, we're going to add an INBOUND UDP rule for WebRTC Data
    if(process.platform == 'win32')
    {
        var loc = svc.appLocation();
        process.stdout.write('   -> Writing firewall rules for ' + options.name + ' Service...');

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
        process.stdout.write(' [DONE]\n');
    }

    // Let's try to start the service that we just installed
    process.stdout.write('   -> Starting service...');
    try
    {
        svc.start();
        process.stdout.write(' [OK]\n');
    }
    catch(ee)
    {
        process.stdout.write(' [ERROR]\n');
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
    // macOS needs comprehensive cleanup of all plists pointing to the binary
    if (process.platform == 'darwin' && installPath)
    {
        process.stdout.write('   -> Cleaning up all LaunchAgent/LaunchDaemon plists...');
        try
        {
            // Use cleanupOrphanedPlists to remove ALL plists pointing to this binary
            // This handles service renames, orphaned plists, and ensures clean reinstall
            var cleaned = cleanupOrphanedPlists(installPath);
            if (cleaned.length > 0) {
                process.stdout.write(' [DONE - Removed ' + cleaned.length + ' plist(s)]\n');
            } else {
                process.stdout.write(' [NONE FOUND]\n');
            }
        }
        catch (e)
        {
            process.stdout.write(' [ERROR: ' + e.message + ']\n');
        }
    }
    else if (process.platform == 'darwin')
    {
        // Fallback to old method if installPath not available (shouldn't happen)
        process.stdout.write('   -> Uninstalling launch agent (fallback method)...');
        try
        {
            var serviceName = params.getParameter('meshServiceName', 'meshagent');
            var launchagent = require('service-manager').manager.getLaunchAgent(serviceName + '-agent');
            launchagent.unload();
            require('fs').unlinkSync(launchagent.plist);
            process.stdout.write(' [DONE]\n');
        }
        catch (e)
        {
            process.stdout.write(' [ERROR]\n');
        }
    }

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

    // Build composite service identifier to match installation naming convention
    var serviceId = macOSHelpers.buildServiceId(serviceName, companyName);

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

    process.stdout.write('   -> Uninstalling previous installation...');
    try
    {
        // Let's actually try to uninstall the service
        require('service-manager').manager.uninstallService(serviceId, uninstallOptions);
        process.stdout.write(' [DONE]\n');
        if (process.platform == 'win32')
        {
            // For Windows, we can remove the entry to enable this service to be runnable from SafeModeWithNetworking
            require('win-bcd').disableSafeModeService(serviceId);
        }

        // Lets try to cleanup the uninstalled service
        if (dataFolder && appPrefix)
        {
            process.stdout.write('   -> Deleting agent data...');
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

            process.stdout.write(' [DONE]\n');
        }
    }
    catch (e)
    {
        process.stdout.write(' [ERROR]\n');
    }

    // Check for secondary agent
    // Build diagnostic service ID following the same composite naming pattern (macOS only)
    var diagnosticServiceId = macOSHelpers.buildServiceId(serviceName + 'Diagnostic', companyName);
    try
    {
        process.stdout.write('   -> Checking for secondary agent...');
        var s = require('service-manager').manager.getService(diagnosticServiceId);
        var loc = s.appLocation();
        s.close();
        process.stdout.write(' [FOUND]\n');
        process.stdout.write('      -> Uninstalling secondary agent...');
        secondaryagent = true;
        try
        {
            require('service-manager').manager.uninstallService(diagnosticServiceId);
            process.stdout.write(' [DONE]\n');
        }
        catch (e)
        {
            process.stdout.write(' [ERROR]\n');
        }
    }
    catch (e)
    {
        process.stdout.write(' [NONE]\n');
    }

    if(secondaryagent)
    {
        // If a secondary agent was found, remove the CRON job for it
        process.stdout.write('      -> removing secondary agent from task scheduler...');
        var p = require('task-scheduler').delete(diagnosticServiceId + '/periodicStart');
        p._params = params;
        p._installPath = installPath;
        p.then(function ()
        {
            process.stdout.write(' [DONE]\n');
            uninstallService3(this._params, this._installPath);
        }, function ()
        {
            process.stdout.write(' [ERROR]\n');
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

    // Build composite service identifier to match installation naming convention (macOS only)
    var serviceId = macOSHelpers.buildServiceId(serviceName, companyName);

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
        process.stdout.write('   -> Stopping Service...');
        if(process.platform=='win32')
        {
            svc.stop().then(function ()
            {
                process.stdout.write(' [STOPPED]\n');
                svc.close();
                uninstallService2(this._params, msh);
            }, function ()
            {
                process.stdout.write(' [ERROR]\n');
                svc.close();
                uninstallService2(this._params, ms);
            }).parentPromise._params = params;
        }
        else
        {
            if (process.platform == 'darwin')
            {
                // macOS requries us to unload the service
                svc.unload();
            }
            else
            {
                svc.stop();
            }
            process.stdout.write(' [STOPPED]\n');
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
    process.stdout.write(' [FOUND: ' + loc + ']\n');
    if(process.platform == 'win32')
    {
        // On Windows, we need to cleanup the firewall rules associated with our install path
        process.stdout.write('   -> Checking firewall rules for previous installation... [0%]');
        var p = require('win-firewall').getFirewallRulesAsync({ program: loc, noResult: true, minimal: true, timeout: 15000 });
        p.on('progress', function (c)
        {
            process.stdout.write('\r   -> Checking firewall rules for previous installation... [' + c + ']');
        });
        p.on('rule', function (r)
        {
            // Remove firewall entries for our install path
            require('win-firewall').removeFirewallRule(r.DisplayName);
        });
        p.finally(function ()
        {
            process.stdout.write('\r   -> Checking firewall rules for previous installation... [DONE]\n');
            uninstallService(params);
        });
    }
    else
    {
        uninstallService(params);
    }
}

// Entry point for -fulluninstall
function fullUninstall(jsonString)
{
    var parms = JSON.parse(jsonString);
    if (parseInt(parms.getParameter('verbose', 0)) == 0)
    {
        console.setDestination(console.Destinations.DISABLED); // IF verbose is disabled(default), we will no-op console.log
    }
    else
    {
        console.setInfoLevel(1); // IF verbose is specified, we will show info level 1 messages
    }
    parms.push('_stop'); // Since we are intending to halt after uninstalling the service, we specify this, since we are re-using the uninstall code with the installer.

    checkParameters(parms); // Perform some checks on the passed in parameters

    var name = parms.getParameter('meshServiceName', process.platform == 'win32' ? 'Mesh Agent' : 'meshagent'); // Set the service name, using the defaults if not specified
    var companyName = parms.getParameter('companyName', null);

    // Build composite service identifier to match installation naming convention (macOS only)
    var serviceId = macOSHelpers.buildServiceId(name, companyName);

    // Check for a previous installation of the service
    try
    {
        process.stdout.write('...Checking for previous installation of "' + serviceId + '"');
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
        // Service lookup failed - try fallback: search plists for installation
        process.stdout.write(' [NOT FOUND]\n');

        // Only use fallback on macOS (other platforms don't have plists)
        if (process.platform == 'darwin') {
            process.stdout.write('   Searching for installation via plist scan... ');

            var installPath = findInstallationByPlist();

            if (installPath) {
                process.stdout.write('[FOUND: ' + installPath + ']\n');

                // Setup minimal params for cleanup
                var msh = installPath + 'meshagent.msh';
                parms.push('_workingDir=' + installPath);
                parms.push('_appPrefix=meshagent');  // Assume default binary name

                // Skip straight to file cleanup
                // Note: service.uninstallService() will fail in uninstallService2, but
                // cleanupOrphanedPlists() will still remove plists and data files
                uninstallService2(parms, msh);
                return;  // uninstallService2 calls process.exit()
            } else {
                process.stdout.write('[NOT FOUND]\n');
            }

            // Third fallback: Check if we're running from an installation directory
            if (!installPath) {
                process.stdout.write('   Checking if running from installation directory... ');

                var fs = require('fs');
                var selfDir;

                // Check if running from bundle using shared helper
                var bundleParent = macOSHelpers.getBundleParentDirectory();
                if (bundleParent) {
                    // Bundle: look for files next to .app, not inside it
                    selfDir = bundleParent;
                } else {
                    // Standalone: use directory containing binary
                    selfDir = process.execPath.substring(0, process.execPath.lastIndexOf('/') + 1);
                }

                var hasMsh = fs.existsSync(selfDir + 'meshagent.msh');
                var hasDb = fs.existsSync(selfDir + 'meshagent.db');
                var hasSocket = fs.existsSync(selfDir + 'DAIPC');

                if (hasMsh || hasDb || hasSocket) {
                    process.stdout.write('[YES]\n');
                    installPath = selfDir;

                    // Clean up plists that point to this binary
                    process.stdout.write('   Removing plists for this installation...\n');
                    var cleaned = cleanupOrphanedPlists(installPath);
                    if (cleaned.length > 0) {
                        process.stdout.write('   Removed ' + cleaned.length + ' plist(s)\n');
                    }

                    // Delete installation files
                    var deleteData = parms.includes('--_deleteData="1"');
                    deleteInstallationFiles(installPath, deleteData);

                    process.stdout.write('\nUninstall completed\n');
                    process.exit(0);
                } else {
                    process.stdout.write('[NO]\n');
                }
            }
        }

        // No installation found via service lookup, plist scan, or self-directory
        console.log('ERROR: Could not locate meshagent installation');
        process.exit();
    }
    serviceExists(loc, parms);
}

// Entry point for -fullinstall, using JSON string
function fullInstall(jsonString, gOptions)
{
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
        process.stdout.write('...Checking for previous installation of "' + serviceId + '"');
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
            process.stdout.write(' [NOT FOUND]\n');
            process.stdout.write('...Searching for any existing meshagent installation...');
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
                    process.stdout.write(' [FOUND: ' + loc + ']\n');
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
                    process.stdout.write(' [NONE]\n');
                    installService(parms);
                    return;
                }
            }
            catch (findErr)
            {
                // No installation found, proceed with fresh install
                process.stdout.write(' [NONE]\n');
                installService(parms);
                return;
            }
        }
        else
        {
            // On non-macOS platforms, no fallback search - just install fresh
            process.stdout.write(' [NONE]\n');
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
// Label format: "meshagent.ServiceName.CompanyName" or "meshagent"
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

    // Standard format: "meshagent.ServiceName.CompanyName"
    if (parts.length === 3 && parts[0] === 'meshagent') {
        return {
            serviceName: parts[1],
            companyName: parts[2],
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
    var enableDisableUpdate = parms.getParameter('enableDisableUpdate', null);

    // Track if installPath was explicitly provided by user (for path inference logic)
    var installPathWasUserProvided = (installPath !== null);

    // Convert enableDisableUpdate to boolean
    var disableUpdate = (enableDisableUpdate === '1' || enableDisableUpdate === 'true');

    // Determine if we should update configuration
    var useProvidedParams = (newServiceName !== null || newCompanyName !== null);

    // Find the installation
    // NOTE: We don't pass newServiceName/newCompanyName to findInstallation because
    // those are values from the database, not the current serviceId. The findInstallation
    // function will use self-upgrade detection to find the installation directory.
    process.stdout.write('Locating existing installation... ');
    installPath = findInstallation(installPath, null, null);

    if (!installPath) {
        process.exit(1);
    }
    process.stdout.write('[FOUND: ' + installPath + ']\n');

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
    process.stdout.write('Cleaning up all service definitions pointing to ' + installPath + 'meshagent...\n');
    var cleaned = cleanupOrphanedPlists(installPath);
    if (cleaned.length > 0) {
        for (var i = 0; i < cleaned.length; i++) {
            process.stdout.write('   Unloaded and removed: ' + cleaned[i] + '\n');
        }
    } else {
        process.stdout.write('   No service definitions found to clean up\n');
    }
    console.log('');

    // ============================================================================
    // CRITICAL SAFETY CHECKS: Verify services unloaded and processes terminated
    // ============================================================================

    process.stdout.write('\n');
    process.stdout.write('========================================\n');
    process.stdout.write('SAFETY VERIFICATION\n');
    process.stdout.write('========================================\n');

    var binaryPath = installPath + 'meshagent';

    // STEP 1: Verify services are unloaded from launchd
    // This is CRITICAL - prevents launchd from auto-restarting killed processes
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
    process.stdout.write('   Services unloaded from launchd [VERIFIED]\n\n');

    // STEP 2: Verify processes terminated
    // Now safe - launchd won't restart them after kill
    // Only targets processes from our specific binaryPath
    process.stdout.write('Step 2: Verifying processes terminated (path: ' + binaryPath + ')...\n');
    var processCheck = verifyProcessesTerminated(binaryPath, 5);

    if (!processCheck.success) {
        process.stdout.write('   WARNING: ' + processCheck.pids.length + ' process(es) still running from this path\n');
        process.stdout.write('   PIDs: ' + processCheck.pids.join(', ') + '\n');
        process.stdout.write('   Attempting force kill (safe - launchd unloaded)...\n');

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
    process.stdout.write('   All processes terminated [VERIFIED]\n');
    process.stdout.write('   Other meshagent installations unaffected\n\n');

    process.stdout.write('Safety verification complete - ready for binary replacement\n');
    process.stdout.write('========================================\n\n');

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

                // Set ownership and permissions: root:wheel 600
                child_process.execSync('chown root:wheel "' + mshPath + '"');
                child_process.execSync('chmod 600 "' + mshPath + '"');
                console.log('   Created .msh file (root:wheel 600)');
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
    process.stdout.write('Backing up current installation...\n');
    try {
        backupInstallation(installPath);
    } catch (e) {
        console.log('ERROR: ' + e.message);
        console.log('Upgrade aborted.');
        process.exit(1);
    }
    console.log('');

    // Install new version (based on source type)
    process.stdout.write('Installing new version...\n');
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

    // Recreate LaunchDaemon plist (using discovered/current service configuration)
    // Note: We use currentServiceName/currentCompanyName (not Final values) so that
    // plists are created with the existing configuration, even if user blanked .msh
    process.stdout.write('Recreating LaunchDaemon...\n');
    try {
        createLaunchDaemon(currentServiceName, currentCompanyName, installPath, currentServiceId, newInstallType, disableUpdate);
    } catch (e) {
        console.log('ERROR: ' + e.message);
        console.log('You may need to manually reinstall the agent.');
        process.exit(1);
    }
    console.log('');

    // Recreate LaunchAgent plist (using discovered/current service configuration)
    process.stdout.write('Recreating LaunchAgent...\n');
    try {
        createLaunchAgent(currentServiceName, currentCompanyName, installPath, currentServiceId, newInstallType);
    } catch (e) {
        console.log('ERROR: ' + e.message);
        console.log('LaunchDaemon should still work, but KVM functionality may be limited.');
    }
    console.log('');

    // Final safety check before starting services
    process.stdout.write('\nFinal verification before starting services...\n');

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
        process.stdout.write('   Clean state verified - ready to start services\n');
    }

    // Small delay for system cleanup
    try {
        child_process.execSync('sleep 0.5');
    } catch (sleepError) {
        // Sleep may fail in some environments, continue anyway
    }

    process.stdout.write('\n');

    // Bootstrap services (using current service ID since plists created with current config)
    process.stdout.write('Starting services...\n');
    bootstrapServices(currentServiceId);
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
    process.stdout.write('Clearing firewall rules... [0%]');
    var p = require('win-firewall').getFirewallRulesAsync({ program: process.execPath, noResult: true, minimal: true, timeout: 15000 });
    p.on('progress', function (c)
    {
        process.stdout.write('\rClearing firewall rules... [' + c + ']');
    });
    p.on('rule', function (r)
    {
        require('win-firewall').removeFirewallRule(r.DisplayName);
    });
    p.finally(function ()
    {
        process.stdout.write('\rClearing firewall rules... [DONE]\n');
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
    process.stdout.write('Checking firewall rules... [0%]');
    var p = require('win-firewall').getFirewallRulesAsync({ program: process.execPath, noResult: true, minimal: true, timeout: 15000 });
    p.foundItems = 0;
    p.on('progress', function (c)
    {
        process.stdout.write('\rChecking firewall rules... [' + c + ']');
    });
    p.on('rule', function (r)
    {
        this.foundItems++;
    });
    p.finally(function ()
    {
        process.stdout.write('\rChecking firewall rules... [DONE]\n');
        process.stdout.write('Rules found: ' + this.foundItems + '\n');

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
        process.stdout.write('Adding firewall rules..... [DONE]\n');
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
