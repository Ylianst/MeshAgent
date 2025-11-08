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

// Helper function to sanitize service identifiers
// Matches the sanitization logic in service-manager.js for consistent naming
function sanitizeIdentifier(str) {
    if (!str) return null;
    // Replace spaces with hyphens, remove all non-alphanumeric except hyphens/underscores
    return str.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9_-]/g, '');
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
                    newLines.push(key + '=' + updates[key]);
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
                newLines.push(key + '=' + updates[key]);
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
        if (require('fs').existsSync(installPath + 'meshagent')) {
            return installPath;
        }
        console.log('ERROR: No binary found at: ' + installPath);
        return null;
    }

    // Try to find service by name
    if (serviceName || companyName) {
        try {
            var sanitizedServiceName = sanitizeIdentifier(serviceName || 'meshagent');
            var sanitizedCompanyName = sanitizeIdentifier(companyName);
            var serviceId;

            if (sanitizedCompanyName) {
                serviceId = 'meshagent.' + sanitizedServiceName + '.' + sanitizedCompanyName;
            } else {
                serviceId = sanitizedServiceName;
            }

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
    var cleaned = [];

    // Check LaunchDaemons
    try {
        var daemonDir = '/Library/LaunchDaemons';
        var files = require('fs').readdirSync(daemonDir);
        for (var i = 0; i < files.length; i++) {
            if (files[i].startsWith('meshagent') && files[i].endsWith('.plist')) {
                var plistPath = daemonDir + '/' + files[i];
                var plistBinary = getProgramPathFromPlist(plistPath);

                if (plistBinary === binaryPath) {
                    // This plist points to our binary - unload and delete it
                    try {
                        var serviceName = files[i].replace('.plist', '');
                        var svc = require('service-manager').manager.getService(serviceName);
                        svc.unload();
                        svc.close();
                    } catch (e) {
                        // Service might not be loaded, that's OK
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
            if ((files[i].startsWith('meshagent') || files[i].includes('meshagent')) &&
                files[i].includes('-agent') && files[i].endsWith('.plist')) {
                var plistPath = agentDir + '/' + files[i];
                var plistBinary = getProgramPathFromPlist(plistPath);

                if (plistBinary === binaryPath) {
                    // This plist points to our binary - unload and delete it
                    try {
                        var serviceName = files[i].replace('.plist', '');
                        var uid = require('user-sessions').consoleUid();
                        var launchAgent = require('service-manager').manager.getLaunchAgent(serviceName);
                        if (uid && uid > 0) {
                            launchAgent.unload(uid);
                        }
                    } catch (e) {
                        // Service might not be loaded, that's OK
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

// Helper to delete plist files
function deletePlists(serviceId) {
    var deleted = false;

    // LaunchDaemon plist
    var daemonPlist = '/Library/LaunchDaemons/' + serviceId + '.plist';
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
    var agentPlist = '/Library/LaunchAgents/' + serviceId + '-agent.plist';
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

// Helper to backup binary with timestamp
function backupBinary(installPath) {
    var binaryPath = installPath + 'meshagent';
    var timestamp = Date.now().toString();
    var backupPath = installPath + 'meshagent.' + timestamp;

    try {
        require('fs').copyFileSync(binaryPath, backupPath);
        process.stdout.write('   Created backup: meshagent.' + timestamp + '\n');
        return backupPath;
    } catch (e) {
        throw new Error('Could not backup binary: ' + e.message);
    }
}

// Helper to replace binary
function replaceBinary(installPath) {
    var targetPath = installPath + 'meshagent';
    var sourcePath = process.execPath;  // Current running binary

    // Check if we're trying to copy the binary over itself (in-place upgrade)
    if (sourcePath === targetPath) {
        process.stdout.write('   Skipping binary copy (already running from install location)\n');
        process.stdout.write('   NOTE: To upgrade with a new binary, run the new meshagent with -upgrade\n');
        process.stdout.write('         Example: sudo /path/to/new/meshagent -upgrade --installPath="' + installPath + '"\n');
        return;
    }

    try {
        // Copy new binary over old one
        require('fs').copyFileSync(sourcePath, targetPath);

        // Ensure executable permissions
        require('fs').chmodSync(targetPath, 0o755);

        process.stdout.write('   Binary replaced: ' + targetPath + '\n');
    } catch (e) {
        throw new Error('Could not replace binary: ' + e.message);
    }
}

// Helper to create LaunchDaemon
function createLaunchDaemon(serviceName, companyName, installPath) {
    try {
        var options = {
            name: serviceName,
            target: 'meshagent',
            servicePath: installPath + 'meshagent',
            startType: 'AUTO_START',
            installPath: installPath,
            parameters: [],
            companyName: companyName
        };

        require('service-manager').manager.installService(options);
        process.stdout.write('   LaunchDaemon created\n');
    } catch (e) {
        throw new Error('Could not create LaunchDaemon: ' + e.message);
    }
}

// Helper to create LaunchAgent
function createLaunchAgent(serviceName, companyName, installPath) {
    try {
        require('service-manager').manager.installLaunchAgent({
            name: serviceName,
            companyName: companyName,
            servicePath: installPath + 'meshagent',
            startType: 'AUTO_START',
            sessionTypes: ['Aqua', 'LoginWindow'],
            parameters: ['-kvm1']
        });
        process.stdout.write('   LaunchAgent created\n');
    } catch (e) {
        throw new Error('Could not create LaunchAgent: ' + e.message);
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

// This is the entry point for installing the service
function installService(params)
{
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
    
    // if '--copy-msh' is specified, we will try to copy the .msh configuration file found in the current working directory
    var i;
    if ((i = params.indexOf('--copy-msh="1"')) >= 0)
    {
        var mshFile = process.platform == 'win32' ? (process.execPath.split('.exe').join('.msh')) : (process.execPath + '.msh');
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
    // Build composite service identifier to match what was created during installation
    // Format: meshagent.{serviceName}.{companyName} when companyName provided (macOS only)
    var sanitizedServiceName = sanitizeIdentifier(options.name);
    var sanitizedCompanyName = sanitizeIdentifier(options.companyName);
    var serviceId;
    if (process.platform == 'darwin' && sanitizedCompanyName) {
        serviceId = 'meshagent.' + sanitizedServiceName + '.' + sanitizedCompanyName;
    } else {
        serviceId = sanitizedServiceName;
    }
    var svc = require('service-manager').manager.getService(serviceId);

    // macOS needs a LaunchAgent to help with some usages that need to run from within the user session, 
    // so we can setup ourselves to accomplish that.
    if (process.platform == 'darwin')
    {
        svc.load();
        process.stdout.write('   -> setting up launch agent...');
        try
        {
            require('service-manager').manager.installLaunchAgent(
                {
                    name: options.name,
                    companyName: options.companyName,
                    servicePath: svc.appLocation(),
                    startType: 'AUTO_START',
                    sessionTypes: ['Aqua', 'LoginWindow'],
                    parameters: ['-kvm1']
                });
            process.stdout.write(' [DONE]\n');
        }
        catch (sie)
        {
            process.stdout.write(' [ERROR] ' + sie);
        }
    }

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
    // Format: meshagent.{serviceName}.{companyName} when companyName provided (macOS only)
    var sanitizedServiceName = sanitizeIdentifier(serviceName);
    var sanitizedCompanyName = sanitizeIdentifier(companyName);
    var serviceId;
    if (process.platform == 'darwin' && sanitizedCompanyName) {
        serviceId = 'meshagent.' + sanitizedServiceName + '.' + sanitizedCompanyName;
    } else {
        serviceId = sanitizedServiceName;
    }

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
    var diagnosticServiceId;
    if (process.platform == 'darwin' && sanitizedCompanyName) {
        diagnosticServiceId = 'meshagent.' + sanitizedServiceName + 'Diagnostic.' + sanitizedCompanyName;
    } else {
        diagnosticServiceId = sanitizedServiceName + 'Diagnostic';
    }
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
    var sanitizedServiceName = sanitizeIdentifier(serviceName);
    var sanitizedCompanyName = sanitizeIdentifier(companyName);
    var serviceId;
    if (process.platform == 'darwin' && sanitizedCompanyName) {
        serviceId = 'meshagent.' + sanitizedServiceName + '.' + sanitizedCompanyName;
    } else {
        serviceId = sanitizedServiceName;
    }

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
    var sanitizedServiceName = sanitizeIdentifier(name);
    var sanitizedCompanyName = sanitizeIdentifier(companyName);
    var serviceId;
    if (process.platform == 'darwin' && sanitizedCompanyName) {
        serviceId = 'meshagent.' + sanitizedServiceName + '.' + sanitizedCompanyName;
    } else {
        serviceId = sanitizedServiceName;
    }

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
        // No previous installation was found, so we can just exit
        process.stdout.write(' [NONE]\n');
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

    // Build composite service identifier to match installation naming convention
    var sanitizedServiceName = sanitizeIdentifier(name);
    var sanitizedCompanyName = sanitizeIdentifier(companyName);
    var serviceId;
    if (process.platform == 'darwin' && sanitizedCompanyName) {
        serviceId = 'meshagent.' + sanitizedServiceName + '.' + sanitizedCompanyName;
    } else {
        serviceId = sanitizedServiceName;
    }

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
                loc = findInstallation(null, null, null);
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

// Entry point for -upgrade (macOS only)
function upgradeAgent(params) {
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

    // Normalize parameters (handles --serviceName alias, etc.)
    checkParameters(params);

    // Parse parameters
    var installPath = params.getParameter('installPath', null);
    var newServiceName = params.getParameter('meshServiceName', null);
    var newCompanyName = params.getParameter('companyName', null);

    // Determine if we should update configuration
    var useProvidedParams = (installPath != null || newServiceName != null || newCompanyName != null);

    // Find the installation
    process.stdout.write('Locating existing installation... ');
    installPath = findInstallation(installPath, newServiceName, newCompanyName);

    if (!installPath) {
        process.exit(1);
    }
    process.stdout.write('[FOUND: ' + installPath + ']\n');

    // ALWAYS read the CURRENT configuration from .msh file first
    // This tells us what the EXISTING service names are
    var mshPath = installPath + 'meshagent.msh';
    var currentServiceName = 'meshagent';
    var currentCompanyName = null;

    if (require('fs').existsSync(mshPath)) {
        try {
            var config = parseMshFile(mshPath);
            currentServiceName = config.meshServiceName || 'meshagent';
            currentCompanyName = config.companyName || null;
        } catch (e) {
            console.log('WARNING: Could not read .msh file: ' + e.message);
            console.log('Assuming default service name: meshagent\n');
        }
    } else {
        console.log('WARNING: .msh file not found at: ' + mshPath);
        console.log('Assuming default service name: meshagent\n');
    }

    // Build CURRENT service identifier (for stopping old services)
    var currentSanitizedServiceName = sanitizeIdentifier(currentServiceName);
    var currentSanitizedCompanyName = sanitizeIdentifier(currentCompanyName);
    var currentServiceId;
    if (currentSanitizedCompanyName) {
        currentServiceId = 'meshagent.' + currentSanitizedServiceName + '.' + currentSanitizedCompanyName;
    } else {
        currentServiceId = currentSanitizedServiceName;
    }

    console.log('Current Service ID: ' + currentServiceId);

    // Determine NEW service names
    var newServiceNameFinal = newServiceName || currentServiceName;
    var newCompanyNameFinal = (newCompanyName !== null) ? newCompanyName : currentCompanyName;

    // Build NEW service identifier (for creating new services)
    var newSanitizedServiceName = sanitizeIdentifier(newServiceNameFinal);
    var newSanitizedCompanyName = sanitizeIdentifier(newCompanyNameFinal);
    var newServiceId;
    if (newSanitizedCompanyName) {
        newServiceId = 'meshagent.' + newSanitizedServiceName + '.' + newSanitizedCompanyName;
    } else {
        newServiceId = newSanitizedServiceName;
    }

    if (currentServiceId !== newServiceId) {
        console.log('New Service ID: ' + newServiceId);
    }
    console.log('');

    // Update .msh file if parameters were provided
    if (useProvidedParams) {
        console.log('Updating configuration...');
        if (require('fs').existsSync(mshPath)) {
            try {
                var mshUpdates = {};
                if (newServiceName) {
                    mshUpdates.meshServiceName = newServiceName;
                }
                if (newCompanyName !== null) {
                    mshUpdates.companyName = newCompanyName;
                }

                updateMshFile(mshPath, mshUpdates);
                console.log('   Updated .msh file:');
                console.log('   Service Name: ' + newServiceNameFinal);
                if (newCompanyNameFinal) {
                    console.log('   Company Name: ' + newCompanyNameFinal);
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

    // Backup old binary
    process.stdout.write('Backing up current installation...\n');
    try {
        backupBinary(installPath);
    } catch (e) {
        console.log('ERROR: ' + e.message);
        console.log('Upgrade aborted.');
        process.exit(1);
    }
    console.log('');

    // Replace binary
    process.stdout.write('Installing new binary...\n');
    try {
        replaceBinary(installPath);
    } catch (e) {
        console.log('ERROR: ' + e.message);
        console.log('Upgrade aborted. You can restore from backup if needed.');
        process.exit(1);
    }
    console.log('');

    // Recreate LaunchDaemon plist (using NEW service name and company)
    process.stdout.write('Recreating LaunchDaemon...\n');
    try {
        createLaunchDaemon(newServiceNameFinal, newCompanyNameFinal, installPath);
    } catch (e) {
        console.log('ERROR: ' + e.message);
        console.log('You may need to manually reinstall the agent.');
        process.exit(1);
    }
    console.log('');

    // Recreate LaunchAgent plist (using NEW service name and company)
    process.stdout.write('Recreating LaunchAgent...\n');
    try {
        createLaunchAgent(newServiceNameFinal, newCompanyNameFinal, installPath);
    } catch (e) {
        console.log('ERROR: ' + e.message);
        console.log('LaunchDaemon should still work, but KVM functionality may be limited.');
    }
    console.log('');

    // Bootstrap both NEW services (using new service ID)
    process.stdout.write('Starting services...\n');
    bootstrapServices(newServiceId);
    console.log('');

    console.log('========================================');
    console.log('Upgrade complete!');
    console.log('========================================');
    console.log('Installation path: ' + installPath);
    if (currentServiceId !== newServiceId) {
        console.log('Old Service ID: ' + currentServiceId);
        console.log('New Service ID: ' + newServiceId);
    } else {
        console.log('Service ID: ' + newServiceId);
    }
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
        var sanitizedServiceName = sanitizeIdentifier(servicename);
        var sanitizedCompanyName = sanitizeIdentifier(companyName);
        var serviceId;
        if (process.platform == 'darwin' && sanitizedCompanyName) {
            serviceId = 'meshagent.' + sanitizedServiceName + '.' + sanitizedCompanyName;
        } else {
            serviceId = sanitizedServiceName;
        }

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
