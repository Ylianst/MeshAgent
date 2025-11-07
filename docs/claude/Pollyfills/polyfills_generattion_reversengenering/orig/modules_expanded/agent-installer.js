// Module: agent-installer
// Timestamp: 2025-10-29T18:22:33.000-06:00
// Original compressed size: 8050 bytes
// Decompressed size: 35961 bytes
// Compression ratio: 77.6%

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

// This function performs some checks on the parameter structure, to make sure the minimum set of requried elements are present
function checkParameters(parms)
{
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

    // If companyName was specified, we're going to move it into the structure
    if ((i = options.parameters.getParameterIndex('companyName')) >= 0)
    {
        options.companyName = options.parameters.getParameterValue(i);
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
    var svc = require('service-manager').manager.getService(options.name);

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
                    servicePath: svc.appLocation(),
                    startType: 'AUTO_START',
                    sessionTypes: ['LoginWindow'],
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
function uninstallService3(params)
{
    // macOS has a LaunchAgent, that we need to uninstall
    if (process.platform == 'darwin')
    {
        process.stdout.write('   -> Uninstalling launch agent...');
        try
        {
            var launchagent = require('service-manager').manager.getLaunchAgent(params.getParameter('meshServiceName', 'meshagent'));
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
        require('service-manager').manager.uninstallService(serviceName, uninstallOptions);
        process.stdout.write(' [DONE]\n');
        if (process.platform == 'win32')
        {
            // For Windows, we can remove the entry to enable this service to be runnable from SafeModeWithNetworking
            require('win-bcd').disableSafeModeService(serviceName);
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
    try
    {
        process.stdout.write('   -> Checking for secondary agent...');
        var s = require('service-manager').manager.getService(serviceName + 'Diagnostic');
        var loc = s.appLocation();
        s.close();
        process.stdout.write(' [FOUND]\n');
        process.stdout.write('      -> Uninstalling secondary agent...');
        secondaryagent = true;
        try
        {
            require('service-manager').manager.uninstallService(serviceName + 'Diagnostic');
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
        var p = require('task-scheduler').delete(serviceName + 'Diagnostic/periodicStart');
        p._params = params;
        p.then(function ()
        {
            process.stdout.write(' [DONE]\n');
            uninstallService3(this._params);
        }, function ()
        {
            process.stdout.write(' [ERROR]\n');
            uninstallService3(this._params);
        });
    }
    else
    {
        uninstallService3(params);
    }
}

// First step in service uninstall
function uninstallService(params)
{
    // Before we uninstall, we need to fetch the service from service-manager.js
    var svc = require('service-manager').manager.getService(params.getParameter('meshServiceName', process.platform == 'win32' ? 'Mesh Agent' : 'meshagent'));

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


    // Check for a previous installation of the service
    try
    {
        process.stdout.write('...Checking for previous installation of "' + name + '"');
        var s = require('service-manager').manager.getService(name);
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
        process.stdout.write('...Checking for previous installation of "' + name + '"');
        var s = require('service-manager').manager.getService(name);
        loc = s.appLocation();

        global._workingpath = s.appWorkingDirectory();
        console.info1('');
        console.info1('Previous Working Path: ' + global._workingpath);
        s.close();
    }
    catch (e)
    {
        // No previous installation was found, so we can continue with installation
        process.stdout.write(' [NONE]\n');
        installService(parms);
        return;
    }
    if (process.execPath == loc)
    {
        parms.push('__skipBinaryDelete'); // If the installer is running from the installed service path, skip deleting the binary
    }
    serviceExists(loc, parms); // Previous installation was found, so we need to do some extra processing before we continue with installation
}


module.exports =
    {
        fullInstallEx: fullInstallEx,
        fullInstall: fullInstall,
        fullUninstall: fullUninstall
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
        try
        {
            if (b64 == null) { throw ('legacy'); }
            service = require('service-manager').manager.getService(servicename)
            serviceLocation = service.appLocation();
            console.log(' Updating service: ' + servicename);
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
