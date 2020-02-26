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
    try
    {
        require('service-manager').manager.installService(
            {
                name: process.platform == 'win32' ? 'Mesh Agent' : 'meshagent',
                target: process.platform == 'win32' ? 'MeshAgent' : 'meshagent',
                displayName: 'Mesh Agent background service',
                servicePath: process.execPath,
                startType: 'AUTO_START',
                parameters: params
            });
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
function uninstallService2(params)
{
    process.stdout.write('   -> Uninstalling previous installation...');
    try
    {
        require('service-manager').manager.uninstallService(process.platform == 'win32' ? 'Mesh Agent' : 'meshagent');
        process.stdout.write(' [DONE]\n');
    }
    catch (e)
    {
        process.stdout.write(' [ERROR]\n');
    }
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
    if (params != null)
    {
        installService(params);
    }
    else
    {
        process.exit();
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
            svc.stop();
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

function fullUninstall()
{
    console.setDestination(console.Destinations.DISABLED);

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
        process.exit();
    }
    serviceExists(loc, null);
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