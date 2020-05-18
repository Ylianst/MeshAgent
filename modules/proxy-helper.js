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


function linux_getProxy()
{
    // Check Environment Variabels
    if(require('fs').existsSync('/etc/environment'))
    {
	    var e = require('fs').readFileSync('/etc/environment').toString();
	    var tokens = e.split('\\n');
	    for(var line in tokens)
	    {
		    var val = tokens[line].split('=');
		    if(val.length == 2 && (val[0].trim() == 'http_proxy' || val[0].trim() == 'https_proxy'))
		    {
			    return(val[1].split('//')[1]);
		    }
	    }
    }

    // Check profile.d
    if(require('fs').existsSync('/etc/profile.d/proxy_setup'))
    {
	    var child = require('child_process').execFile('/bin/sh', ['sh']);
	    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
	    child.stdin.write("cat /etc/profile.d/proxy_setup | awk '" + '{ split($2, tok, "="); if(tok[1]=="http_proxy") { print tok[2]; }}\'\nexit\n');
	    child.waitExit();
	    child.ret = child.stdout.str.trim().split('\n')[0].split('//')[1];
	    if(child.ret != '') { return(child.ret); }
    }

    // Check gsettings
    if (require('fs').existsSync('/usr/bin/gsettings'))
    {
	    var setting;
	    var ids = require('user-sessions').loginUids(); 
	    for (var i in ids)
	    {
		    setting = require('linux-gnome-helpers').getProxySettings(ids[i]);
		    if (setting.mode == 'manual') { return(setting.host + ':' + setting.port);} 
	    }
    }

    if (require('fs').existsSync('/etc/apt/apt.conf.d/proxy.conf'))
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.stderr.on('data', function (c) { console.log(c.toString()); });
        child.stdin.write("cat /etc/apt/apt.conf.d/proxy.conf | tr '\\n' '`' | awk -F'`' '{");
        child.stdin.write('for(n=1;n<NF;++n) { ln=split($n,tok,"::"); split(tok[ln],px,"\\""); split(px[2],x,"://"); if(x[2]!="") { print x[2]; break; } }');
        child.stdin.write("}'\nexit\n");
        child.waitExit();
        if (child.stdout.str.trim() != "") { return (child.stdout.str.trim()); }
    }
    if (require('fs').existsSync('/etc/yum.conf'))
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.stderr.on('data', function (c) { console.log(c.toString()); });
        child.stdin.write('cat /etc/yum.conf | grep "proxy=" | ' + "tr '\\n' '`' | awk -F'`' '{");
        child.stdin.write('for(n=1;n<NF;++n) { cl=split($n,c,"#"); split($n,px,"://"); if(px[2]!="" && cl==1) { print px[2]; break; } }');
        child.stdin.write("}'\nexit\n");
        child.waitExit();
        if (child.stdout.str.trim() != "") { return (child.stdout.str.trim()); }
    }
    if (require('fs').existsSync('/etc/sysconfig/proxy'))
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.stderr.on('data', function (c) { console.log(c.toString()); });
        child.stdin.write('cat /etc/sysconfig/proxy | grep PROXY_ENABLED= | awk \'{');
        child.stdin.write('split($0,res,"\\""); if(res[2]=="yes") { print res[2]; }')
        child.stdin.write("}'\nexit\n");
        child.waitExit();
        if (child.stdout.str.trim() != "")
        {
            // Enabled
            child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.stderr.on('data', function (c) { console.log(c.toString()); });
            child.stdin.write('cat /etc/sysconfig/proxy | grep _PROXY | ' + "tr '\\n' '`' | awk -F'`' '{");
            child.stdin.write('for(i=1;i<NF;++i) { if(split($i,r,"HTTP_PROXY=")>1 || split($i,r,"HTTPS_PROXY=")>1) {');
            child.stdin.write('cl=split($i,c,"#");');
            child.stdin.write('split($i,px,"\\""); split(px[2],pxx,"://"); if(pxx[2]!="" && cl==1) { print pxx[2]; break; }');
            child.stdin.write('} }');
            child.stdin.write("}'\nexit\n");
            child.waitExit();
            if (child.stdout.str.trim() != '') { return (child.stdout.str.trim()); }
        }
    }
    throw ('No proxies');
}
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
        module.exports = { ignoreProxy: posix_proxyCheck, getProxy: linux_getProxy };
        break;
    case 'win32':
        module.exports = { ignoreProxy: windows_proxyCheck };
        break;
    case 'darwin':
        break;
}
