

function gnome_getProxySettings(uid)
{
    var child = require('child_process').execFile('/bin/sh', ['sh'], { env: { HOME: require('user-sessions').getHomeFolder(uid) }});
    child.stderr.str = ''; child.stderr.on('data', function (c) { });
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });

    child.stdin.write('gsettings list-recursively org.gnome.system.proxy | tr "\\n" "\\|" | tr "\\\'" "\\`" | awk \'{ count=split($0, res, "|");')
    child.stdin.write('exc="[]";');
    child.stdin.write('for(a=0;a<count;++a)');
    child.stdin.write('{');
    child.stdin.write('split(res[a], modecheck, " ");');
    child.stdin.write('if(modecheck[2] == "mode")');
    child.stdin.write('{');
    child.stdin.write('split(modecheck[3], prx, "`"); mode = prx[2];');
    child.stdin.write('}');
    child.stdin.write('if(modecheck[1]=="org.gnome.system.proxy.http" && modecheck[2]=="host") { split(modecheck[3], hst, "`"); host = hst[2]; }');
    child.stdin.write('if(modecheck[1]=="org.gnome.system.proxy.http" && modecheck[2]=="port") { port = modecheck[3]; }');
    child.stdin.write('if(modecheck[1]=="org.gnome.system.proxy" && modecheck[2]=="ignore-hosts") { exc = substr(res[a], 36); gsub("`", "\\"", exc); }');
    child.stdin.write('}');
    child.stdin.write('printf "{\\"mode\\": \\"%s\\", \\"host\\": \\"%s\\", \\"port\\": %s, \\"exceptions\\": %s}", mode, host, port, exc; }\'\nexit\n');
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
                setDesktopWallpaper: gnome_setDesktopWallpaper
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
        Object.defineProperty(module.exports, 'available', { get: function () { return (this._location!='' ? true : false); } });
        break;
}