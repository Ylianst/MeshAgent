// Module: linux-gnome-helpers
// Timestamp: 2025-08-19T13:12:47.000-06:00
// Original compressed size: 2123 bytes
// Decompressed size: 8258 bytes
// Compression ratio: 74.3%

/*
Copyright 2019 - 2020 Intel Corporation

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


function linux_getMountPoints()
{
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write("mount  | tr '\\n' '`' | awk '");
    child.stdin.write('{');
    child.stdin.write('   printf "{";');
    child.stdin.write('   n=split($0,lines,"`");');
    child.stdin.write('   for(i=1;i<n;++i)');
    child.stdin.write('   {');
    child.stdin.write('      x=split(lines[i], tokens, " ");');
    child.stdin.write('      j=sprintf(" type %s", tokens[x-1]);');
    child.stdin.write('      e=index(lines[i], j);');
    child.stdin.write('      s=index(lines[i], " on ");');
    child.stdin.write('      point=substr(lines[i], s+4, e-s-4);');
    child.stdin.write('      printf "%s\\"%s\\":\\"%s\\"",(i!=1?",":""), point, tokens[x-1];');
    child.stdin.write('   }');
    child.stdin.write('   printf "}";');
    child.stdin.write("}'\nexit\n");
    child.waitExit();
    
    try
    {
        return (JSON.parse(child.stdout.str));
    }
    catch (exc)
    {
        return ({});
    }
}

function gnome_getProxySettings(uid)
{
    var child = require('child_process').execFile('/bin/sh', ['sh'], { env: { HOME: require('user-sessions').getHomeFolder(uid) }});
    child.stderr.str = ''; child.stderr.on('data', function (c) { });
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });

    child.stdin.write('gsettings list-recursively org.gnome.system.proxy | tr "\\n" "\\|" | awk \'');
    child.stdin.write('{');
    child.stdin.write('   count=split($0, res, "|");')
    child.stdin.write('   exc="[]"; auth=""; pwd=""; username=""; enabled="";');
    child.stdin.write('   for(a=0;a<count;++a)');
    child.stdin.write('   {');
    child.stdin.write('      split(res[a], modecheck, " ");');
    child.stdin.write('      if(modecheck[2] == "mode")');
    child.stdin.write('      {');
    child.stdin.write('         split(modecheck[3], prx, "\\047"); mode = prx[2];');
    child.stdin.write('      }');
    child.stdin.write('      if(modecheck[1]=="org.gnome.system.proxy.http" && modecheck[2]=="host") { split(modecheck[3], hst, "\\047"); host = hst[2]; }');
    child.stdin.write('      if(modecheck[1]=="org.gnome.system.proxy.http" && modecheck[2]=="port") { port = modecheck[3]; }');
    child.stdin.write('      if(modecheck[1]=="org.gnome.system.proxy.http" && modecheck[2]=="use-authentication") { auth=modecheck[3]; }');
    child.stdin.write('      if(modecheck[1]=="org.gnome.system.proxy" && modecheck[2]=="ignore-hosts") { exc = substr(res[a], 36); gsub("\\047", "\\"", exc); }');
    child.stdin.write('      if(modecheck[1]=="org.gnome.system.proxy.http" && modecheck[2]=="enabled") { enabled = modecheck[3]; }');
    child.stdin.write('      if(modecheck[1]=="org.gnome.system.proxy.http" && modecheck[2]=="authentication-user")');
    child.stdin.write('      {');
    child.stdin.write('          split(res[a],dummy,"\\047"); username=dummy[2];');
    child.stdin.write('      }');
    child.stdin.write('      if(modecheck[1]=="org.gnome.system.proxy.http" && modecheck[2]=="authentication-password")');
    child.stdin.write('      {');
    child.stdin.write('          pwd=substr(res[a],53);');
    child.stdin.write('      }');
    child.stdin.write('   }');
    child.stdin.write('   if(pwd~/^\\047/) { gsub("\\"", "\\\\\\"", pwd); gsub("\\047", "\\"", pwd); }');
    child.stdin.write('   printf "{\\"mode\\": \\"%s\\", \\"enabled\\": %s, \\"host\\": \\"%s\\", \\"port\\": %s, \\"authEnabled\\": %s, \\"username\\": \\"%s\\", \\"password\\": %s, \\"exceptions\\": %s}", mode, enabled, host, port, auth, username, pwd, exc;');
    child.stdin.write("}'\nexit\n");
    child.waitExit();
    try
    {
        return (JSON.parse(child.stdout.str.trim()));
    }
    catch(e)
    {
        return ({});
    }
}

function gnome_getDesktopWallpaper(uid)
{
    var child = require('child_process').execFile('/bin/sh', ['sh'], { env: { HOME: require('user-sessions').getHomeFolder(uid) } });
    child.stderr.str = ''; child.stderr.on('data', function (c) { });
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('gsettings get org.gnome.desktop.background picture-uri\nexit\n');
    child.waitExit();
    child.stdout.str = child.stdout.str.trim().split('file://').pop();
    if (child.stdout.str.endsWith('"') || child.stdout.str.endsWith("'"))
    {
        return (child.stdout.str.substring(0, child.stdout.str.length - 1));
    }
    else
    {
        return (child.stdout.str);
    }
}

function gnome_setDesktopWallpaper(uid, filePath)
{
    if (!filePath) { filePath = '/dev/null'; }

    var v = { HOME: require('user-sessions').getHomeFolder(uid) };
    var pids = require('process-manager').getProcess('gnome-session');
    for (var i in pids)
    {
        var e = require('user-sessions').getEnvFromPid(pids[i]);
        if (e.USER && require('user-sessions').getUid(e.USER)!=uid)
        {
            continue;
        }
        v.DBUS_SESSION_BUS_ADDRESS = e.DBUS_SESSION_BUS_ADDRESS;
        if (v.DBUS_SESSION_BUS_ADDRESS) { break; }
    }

    var child = require('child_process').execFile('/bin/sh', ['sh'], { uid: uid, env: v });
    child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('gsettings set org.gnome.desktop.background picture-uri file://' + filePath + '\nexit\n');
    child.waitExit();
}

switch(process.platform)
{
    case 'linux':
        module.exports =
            {
                getProxySettings: gnome_getProxySettings,
                getDesktopWallpaper: gnome_getDesktopWallpaper,
                setDesktopWallpaper: gnome_setDesktopWallpaper,
                mounts: linux_getMountPoints
            };
        Object.defineProperty(module.exports, '_location', {
            value: (function ()
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = '';
                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write("whereis gsettings | awk '{ print $2 }'\nexit\n");
                child.waitExit();
                return (child.stdout.str.trim());
            })()
        });
        Object.defineProperty(module.exports, 'available', { get: function () { return (this._location != '' ? true : false); } });
        Object.defineProperty(module.exports, 'scriptVersion',
            {
                value: (function()
                {
                    var ret = { major: 0, minor: 0 };
                    if(require('fs').existsSync('/usr/bin/script'))
                    {
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stderr.on('data', function () { });
                        child.stdin.write('script -V | awk \'{ split($NF, T, "."); printf "{\\"major\\":%s, \\"minor\\":%s}",T[1],T[2]; }\'\nexit\n');
                        child.waitExit();
                        try
                        {
                            ret = JSON.parse(child.stdout.str.trim());
                        }
                        catch (x)
                        { }
                    }
                    return (ret);
                })()
            });
        break;
}