/*
Copyright 2019 Intel Corporation

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

function posix_proxyCheck(uid, checkAddr)
{
    var g;
    var x = process.env['no_proxy'] ? process.env['no_proxy'].split(',') : [];
    var t;

    if (require('linux-gnome-helpers').available && (g = require('linux-gnome-helpers').getProxySettings(uid)).mode != 'none')
    {
        x = g.exceptions;
    }

    for(var i in x)
    {
        if (x[i] == checkAddr) { return (true); }               // Direct Match
        if (checkAddr.endsWith('.' + x[i])) { return (true); }  // Subdomain Match
        if ((v = x[i].split('/')).length == 2)
        {
            try
            {
                if(require('ip-address').Address4.fromString(v[0]).mask(parseInt(v[1])) == require('ip-address').Address4.fromString(checkAddr).mask(parseInt(v[1])))
                {
                    return(true);
                }
            }
            catch (ex)
            {
            }
        }
    }
    return (false);
}

function windows_proxyCheck(key, checkAddr)
{
    if(!key)
    {
        var i;
        // Key wasn't specified, so lets try to figure it out
        if((i=require('user-sessions').getProcessOwnerName(process.pid)).tsid == 0)
        {
            // We are a service, so we should check the user that installed the Mesh Agent
            try
            {
                key = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\Mesh Agent', '_InstalledBy');
            }
            catch(xx)
            {
                // This info isn't available, so let's try to use the currently logged in user
                try
                {
                    key = require('win-registry').usernameToUserKey(require('user-sessions').getUsername(require('user-sessions').consoleUid()));
                }
                catch(xxx)
                {
                    // No users are logged in, so as a last resort, let's try the last logged in user.
                    var entries = require('win-registry').QueryKey(require('win-registry').HKEY.Users);
                    for(i in entries.subkeys)
                    {
                        if(entries.subkeys[i].split('-').length>5 && !entries.subkeys[i].endsWith('_Classes'))
                        {
                            key = entries.subkeys[i];
                            break;
                        }
                    }
                }
            }
        }
        else
        {
            // We are a logged in user
            key = require('win-registry').usernameToUserKey(i.name);
        }
        if(!key) {throw('Could not determine which user proxy setting to query');}
    }
    var proxyOverride = require('win-registry').QueryKey(require('win-registry').HKEY.Users, key + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 'ProxyOverride').split(';');
    for(var i in proxyOverride)
    {
        proxyOverride[i] = proxyOverride[i].trim();
        if ((checkAddr == '127.0.0.1' || checkAddr == '::1') && proxyOverride[i] == '<local>') { return (true); }
        if (checkAddr == proxyOverride[i]) { return (true); } // Exact Match
        if (proxyOverride[i].startsWith('*.') && checkAddr.endsWith(proxyOverride[i].substring(1))) { return (true); }
        if (proxyOverride[i].endsWith('.*') && checkAddr.startsWith(proxyOverride[i].substring(0, proxyOverride[i].length - 1))) { return (true); }
    }
    return (false);
}

switch (process.platform)
{
    case 'linux':
    case 'freebsd':
        module.exports = { ignoreProxy: posix_proxyCheck };
        break;
    case 'win32':
        module.exports = { ignoreProxy: windows_proxyCheck };
        break;
    case 'darwin':
        break;
}
