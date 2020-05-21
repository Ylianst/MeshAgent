/*
Copyright 2020 Intel Corporation

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


function installService(params)
{
    process.stdout.write('...Installing service');


    var options =
        {
            name: process.platform == 'win32' ? 'Mesh Agent' : 'meshagent',
            target: process.platform == 'win32' ? 'MeshAgent' : 'meshagent',
            displayName: 'Mesh Agent background service',
            servicePath: process.execPath,
            startType: 'AUTO_START',
            parameters: params
        };
    var i;
    if ((i=params.indexOf('--_localService="1"'))>=0)
    {
        // install in place
        options.parameters.splice(i, 1);
        options.installInPlace = true;
    }
    for (i = 0; i < options.parameters.length; ++i)
    {
        if(options.parameters[i].startsWith('--installPath='))
        {
            options.installPath = options.parameters[i].split('=')[1];
            if (options.installPath.startsWith('"')) { options.installPath = options.installPath.substring(1, options.installPath.length - 1); }
            options.parameters.splice(i, 1);
            options.installInPlace = false;
            break;
        }
    }

    try
    {
        require('service-manager').manager.installService(options);
        process.stdout.write(' [DONE]\n');
    }
    catch(sie)
    {
        process.stdout.write(' [ERROR] ' + sie);
        process.exit();
    }
    var svc = require('service-manager').manager.getService(process.platform=='win32'?'Mesh Agent':'meshagent');
    if (process.platform == 'darwin')
    {
        svc.load();
        process.stdout.write('   -> setting up launch agent...');
        try
        {
            require('service-manager').manager.installLaunchAgent(
                {
                    name: 'meshagent',
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


    if(process.platform == 'win32')
    {
        var loc = svc.appLocation();
        process.stdout.write('   -> Writing firewall rules for Mesh Agent Service...');

        var rule = 
            {
                DisplayName: 'Mesh Agent Management Traffic (TCP-1)',
                direction: 'inbound',
                Program: loc,
                Protocol: 'TCP',
                Profile: 'Public, Private, Domain',
                LocalPort: 16990,
                Description: 'Mesh Central Agent Management Traffic',
                EdgeTraversalPolicy: 'allow',
                Enabled: true
            };
        require('win-firewall').addFirewallRule(rule);

        rule = 
            {
                DisplayName: 'Mesh Agent Management Traffic (TCP-2)',
                direction: 'inbound',
                Program: loc,
                Protocol: 'TCP',
                Profile: 'Public, Private, Domain',
                LocalPort: 16991,
                Description: 'Mesh Central Agent Management Traffic',
                EdgeTraversalPolicy: 'allow',
                Enabled: true
            };
        require('win-firewall').addFirewallRule(rule); 

        rule =
        {
            DisplayName: 'Mesh Agent Peer-to-Peer Traffic (UDP-1)',
            direction: 'inbound',
            Program: loc,
            Protocol: 'UDP',
            Profile: 'Public, Private, Domain',
            LocalPort: 16990,
            Description: 'Mesh Central Agent Peer-to-Peer Traffic',
            EdgeTraversalPolicy: 'allow',
            Enabled: true
        };
        require('win-firewall').addFirewallRule(rule);

        rule =
            {
                DisplayName: 'Mesh Agent Peer-to-Peer Traffic (UDP-2)',
                direction: 'inbound',
                Program: loc,
                Protocol: 'UDP',
                Profile: 'Public, Private, Domain',
                LocalPort: 16991,
                Description: 'Mesh Central Agent Peer-to-Peer Traffic',
                EdgeTraversalPolicy: 'allow',
                Enabled: true
            };
        require('win-firewall').addFirewallRule(rule);
        process.stdout.write(' [DONE]\n');
    }
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

    if (process.platform == 'win32') { svc.close(); }
    process.exit();
}

function uninstallService3(params)
{
    if (process.platform == 'darwin')
    {
        process.stdout.write('   -> Uninstalling launch agent...');
        try
        {
            var launchagent = require('service-manager').manager.getLaunchAgent('meshagent');
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
        installService(params);
    }
    else
    {
        process.exit();
    }
}

function uninstallService2(params)
{
    var secondaryagent = false;
    var i;
    var dataFolder = null;
    var appPrefix = null;

    if (params && params.includes('--_deleteData="1"'))
    {
        for (i = 0; i < params.length; ++i)
        {
            if (params[i].startsWith('_workingDir='))
            {
                dataFolder = params[i].split('=')[1];
                if (dataFolder.startsWith('"')) { dataFolder = dataFolder.substring(1, dataFolder.length - 1); }
            }
            if (params[i].startsWith('_appPrefix='))
            {
                appPrefix = params[i].split('=')[1];
                if (appPrefix.startsWith('"')) { appPrefix = appPrefix.substring(1, appPrefix.length - 1); }
            }
        }
    }

    process.stdout.write('   -> Uninstalling previous installation...');
    try
    {
        require('service-manager').manager.uninstallService(process.platform == 'win32' ? 'Mesh Agent' : 'meshagent');
        process.stdout.write(' [DONE]\n');
        if (dataFolder && appPrefix)
        {
            process.stdout.write('   -> Deleting agent data...');
            if (process.platform != 'win32')
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.on('data', function (c) { });
                child.stderr.on('data', function (c) { });
                child.stdin.write('cd ' + dataFolder + '\n');
                child.stdin.write('rm ' + appPrefix + '.*\r\n');
                child.stdin.write('exit\n');       
                child.waitExit();
            }
            else
            {
                var child = require('child_process').execFile(process.env['windir'] + '\\system32\\cmd.exe', ['/C del "' + dataFolder + '\\' + appPrefix + '.*"']);
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
        var s = require('service-manager').manager.getService('meshagentDiagnostic');
        var loc = s.appLocation();
        s.close();
        process.stdout.write(' [FOUND]\n');
        process.stdout.write('      -> Uninstalling secondary agent...');
        secondaryagent = true;
        try
        {
            require('service-manager').manager.uninstallService('meshagentDiagnostic');
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
        process.stdout.write('      -> removing secondary agent from task scheduler...');
        var p = require('task-scheduler').delete('meshagentDiagnostic/periodicStart');
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
function uninstallService(params)
{
    var svc = require('service-manager').manager.getService(process.platform == 'win32' ? 'Mesh Agent' : 'meshagent');
    if (svc.isRunning())
    {
        process.stdout.write('   -> Stopping Service...');
        if(process.platform=='win32')
        {
            svc.stop().then(function ()
            {
                process.stdout.write(' [STOPPED]\n');
                svc.close();
                uninstallService2(this._params);
            }, function ()
            {
                process.stdout.write(' [ERROR]\n');
                svc.close();
                uninstallService2(this._params);
            }).parentPromise._params = params;
        }
        else
        {
            if (process.platform == 'darwin')
            {
                svc.unload();
            }
            else
            {
                svc.stop();
            }
            process.stdout.write(' [STOPPED]\n');
            uninstallService2(params);
        }
    }
    else
    {
        if (process.platform == 'win32') { svc.close(); }
        uninstallService2(params);
    }
}
function serviceExists(loc, params)
{
    process.stdout.write(' [FOUND: ' + loc + ']\n');
    if(process.platform == 'win32')
    {
        process.stdout.write('   -> Checking firewall rules for previous installation...');
        require('win-firewall').removeFirewallRule({ program: loc }).then(function ()
        {
            // SUCCESS
            process.stdout.write(' [DELETED]\n');
            uninstallService(this._params);
        }, function ()
        {
            // FAILED
            process.stdout.write(' [No Rules Found]\n');
            uninstallService(this._params);
        }).parentPromise._params = params;
    }
    else
    {
        uninstallService(params);
    }
}

function fullUninstall(jsonString)
{
    console.setDestination(console.Destinations.DISABLED);
    var parms = JSON.parse(jsonString);
    parms.push('_stop');

    try
    {
        process.stdout.write('...Checking for previous installation');
        var s = require('service-manager').manager.getService(process.platform == 'win32' ? 'Mesh Agent' : 'meshagent');
        var loc = s.appLocation();
        var appPrefix = loc.split(process.platform == 'win32' ? '\\' : '/').pop();
        if (process.platform == 'win32') { appPrefix = appPrefix.substring(0, appPrefix.length - 4); }

        parms.push('_workingDir=' + s.appWorkingDirectory());
        parms.push('_appPrefix=' + appPrefix);

        s.close();
    }
    catch (e)
    {
        process.stdout.write(' [NONE]\n');
        process.exit();
    }
    serviceExists(loc, parms);
}

function fullInstall(jsonString)
{
    console.setDestination(console.Destinations.DISABLED);
    var parms = JSON.parse(jsonString);

    try
    {
        process.stdout.write('...Checking for previous installation');
        var s = require('service-manager').manager.getService(process.platform == 'win32' ? 'Mesh Agent' : 'meshagent');
        var loc = s.appLocation();
        s.close();
    }
    catch (e)
    {
        process.stdout.write(' [NONE]\n');
        installService(parms);
        return;
    }
    serviceExists(loc, parms);
}


module.exports =
    {
        fullInstall: fullInstall,
        fullUninstall: fullUninstall
    };

if (process.platform == 'win32')
{
    function win_update()
    {
        console.setDestination(console.Destinations.LOGFILE);
        var updateLocation = process.argv[1].substring(8);
        var service = null;
        var serviceLocation = "";

        if(!global._interval)
        {
            global._interval = setInterval(win_update, 60000);
        }

        try
        {
            service = require('service-manager').manager.getService('Mesh Agent');
            serviceLocation = service.appLocation();
        }
        catch(e)
        {
            console.log('Service Manager Error: ' + e);
            console.log('Trying again in one minute...');
            return;
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
                    require('fs').copyFileSync(process.execPath, updateLocation);
                }
                catch (ce)
                {
                    console.log('Could not copy file.. Trying again in 60 seconds');
                    service.close();
                    return;
                }

                service.start();
                process._exit();
            });
        });
    }
    module.exports.update = win_update;
}