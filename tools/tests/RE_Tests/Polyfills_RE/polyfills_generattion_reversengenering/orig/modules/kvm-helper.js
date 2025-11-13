

function getUsers()
{
    var res, i, uu = {};
    require('user-sessions').Current(function (u) { res = u; });

    for (i in res)
    {
        if (process.platform != 'win32') { res[i].SessionId = res[i].uid; }
        if (res[i].State == 'Active' || res[i].State == 'Connected') { uu[process.platform == 'win32' ? res[i].SessionId : res[i].uid] = res[i]; }
    }

    if (process.platform == 'linux')
    {
        var spawnable = this.loginUids();
        for (i in spawnable)
        {
            if (uu[spawnable[i].uid] == null)
            {
                uu[spawnable[i].uid] = spawnable[i];
            }
        }
    }

    return (uu);
}

if (process.platform == 'linux')
{
    var allowedUIDs = [];
    var startDM = '';
    const uid_max = require('user-sessions').getUidConfig().MAX;
    const hasXvfb = require('lib-finder').hasBinary('xvfb-run');
    const hasGnomeSession = require('lib-finder').hasBinary('gnome-session');
    const hasLxde = require('lib-finder').hasBinary('startlxde');
    const hasXfce = require('lib-finder').hasBinary('startxfce4');

    var arg = _MSH().allowedUIDs;
    if (arg) { try { allowedUIDs = JSON.parse(arg) } catch (z) { allowedUIDs = []; } }
    if (!Array.isArray(allowedUIDs)) { allowedUIDs = []; }

    if (allowedUIDs.length == 0)
    {
        arg = process.argv.find(function (a) { return (a.startsWith('--allowedUIDs=')); });
        if (arg) { try { allowedUIDs = JSON.parse(arg.split('=')[1]); } catch (z) { allowedUIDs = []; } }
        if (!Array.isArray(allowedUIDs)) { allowedUIDs = []; }
    }
    if (allowedUIDs.length == 0) { allowedUIDs = require('user-sessions').loginUids(); }

    arg = _MSH().virtualDM;
    if (arg == null)
    {
        arg = process.argv.find(function (a) { return (a.startsWith('--virtualDM=')); });
        if (arg != null) { arg = arg.split('=').pop(); }
    }
    if (arg == null) { arg = ''; }

    switch(arg.toUpperCase())
    {
        case 'GDM':
            if (hasGnomeSession) { startDM = 'gnome-session'; }
            break;
        case 'LXDE':
            if (hasLxde) { startDM = 'startlxde'; }
            break;
        case 'XFCE':
            if (hasXfce) { startDM = 'startxfce4'; }
            break;
        default:
            if (hasGnomeSession) { startDM = 'gnome-session'; }
            if (hasLxde) { startDM = 'startlxde'; }
            if (hasXfce) { startDM = 'startxfce4'; }
            break;
    }


    function spawnVirtualSession(vuid)
    {
        if (vuid > uid_max)
        {
            var uid = vuid - uid_max;
            var username = require('user-sessions').getUsername(uid);
            var childProcess = require('child_process');
            var options = { type: childProcess.SpawnTypes.TERM, env: { HISTCONTROL: 'ignoreboth' } };
            var terminal = childProcess.execFile('/bin/sh', options);

            terminal.stdout.on('data', function (c) { console.info1(c.toString()); });
            terminal.stdin.write('su ' + username + '\n');
            terminal.stdin.write('xvfb-run -n 99 -a ' + startDM + ' &\n');
            terminal.stdin.write('exit\nexit\n');
            terminal.waitExit();
            return (uid);
        }
        else
        {
            return (vuid);
        }
    }

    function hasVirtualSessionSupport()
    {
        return (require('user-sessions').hasLoginCtl && hasXvfb && (hasGnomeSession || hasLxde))
    }


    function loginUids()
    {
        var lids = module.exports.allowed
        var uu = {};
        for (i in lids)
        {
            try
            {
                uu[lids[i]] = { SessionId: lids[i] + uid_max, State: 'Spawnable', uid: lids[i], StationName: 'xvfb-' + lids[i], Username: require('user-sessions').getUsername(lids[i]) };
            }
            catch (z)
            { }
        }
        return (uu);
    }


    function waylandStatus()
    {
        var wayland = true;

        if (require('fs').existsSync('/etc/gdm/custom.conf'))
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.stdin.write("cat /etc/gdm/custom.conf | grep WaylandEnable= | tr '\\n' '`' | awk -F'`' '");
            child.stdin.write('{');
            child.stdin.write('   wayland=1;');
            child.stdin.write('   for(n=1;n<NF;++n) ');
            child.stdin.write('   {');
            child.stdin.write('      if($n~/^#/) { continue; }')
            child.stdin.write('      gsub(/ /, "", $n);');
            child.stdin.write('      if($n~/^WaylandEnable=/)');
            child.stdin.write('      {');
            child.stdin.write('         split($n, dummy, "WaylandEnable=");');
            child.stdin.write('         if(dummy[2]=="false")');
            child.stdin.write('         {');
            child.stdin.write('            wayland=0;');
            child.stdin.write('         }');
            child.stdin.write('         break;');
            child.stdin.write('      }');
            child.stdin.write('   }');
            child.stdin.write('   print wayland;');
            child.stdin.write("}'\nexit\n");
            child.waitExit();
            if (child.stdout.str.trim() == '0')
            {
                wayland = false;
            }
        }
        if (require('fs').existsSync('/etc/gdm3/custom.conf'))
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.stdin.write("cat /etc/gdm3/custom.conf | grep WaylandEnable= | tr '\\n' '`' | awk -F'`' '");
            child.stdin.write('{');
            child.stdin.write('   wayland=1;');
            child.stdin.write('   for(n=1;n<NF;++n) ');
            child.stdin.write('   {');
            child.stdin.write('      if($n~/^#/) { continue; }')
            child.stdin.write('      gsub(/ /, "", $n);');
            child.stdin.write('      if($n~/^WaylandEnable=/)');
            child.stdin.write('      {');
            child.stdin.write('         split($n, dummy, "WaylandEnable=");');
            child.stdin.write('         if(dummy[2]=="false")');
            child.stdin.write('         {');
            child.stdin.write('            wayland=0;');
            child.stdin.write('         }');
            child.stdin.write('         break;');
            child.stdin.write('      }');
            child.stdin.write('   }');
            child.stdin.write('   print wayland;');
            child.stdin.write("}'\nexit\n");
            child.waitExit();
            if (child.stdout.str.trim() == '0')
            {
                wayland = false;
            }
        }
        return (wayland);
    }

    function disableWayland()
    {
        if (waylandStatus())
        {
            if (require('fs').existsSync('/etc/gdm/custom.conf'))
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write('sed "s/#WaylandEnable=false/WaylandEnable=false/g" /etc/gdm/custom.conf > /etc/gdm/custom_2.conf\n');
                child.stdin.write("mv /etc/gdm/custom_2.conf /etc/gdm/custom.conf\n");
                child.stdin.write("\nexit\n");
                child.waitExit();
            }
            if (require('fs').existsSync('/etc/gdm3/custom.conf'))
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write('sed "s/#WaylandEnable=false/WaylandEnable=false/g" /etc/gdm3/custom.conf > /etc/gdm3/custom_2.conf\n');
                child.stdin.write("mv /etc/gdm3/custom_2.conf /etc/gdm3/custom.conf\n");
                child.stdin.write("\nexit\n");
                child.waitExit();
            }
        }
    }
    function enableWayland()
    {
        if (!waylandStatus())
        {
            if (require('fs').existsSync('/etc/gdm/custom.conf'))
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write('sed "s/WaylandEnable=false/#WaylandEnable=false/g" /etc/gdm/custom.conf > /etc/gdm/custom_2.conf\n');
                child.stdin.write("mv /etc/gdm/custom_2.conf /etc/gdm/custom.conf\n");
                child.stdin.write("\nexit\n");
                child.waitExit();
            }
            if (require('fs').existsSync('/etc/gdm3/custom.conf'))
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write('sed "s/WaylandEnable=false/#WaylandEnable=false/g" /etc/gdm3/custom.conf > /etc/gdm3/custom_2.conf\n');
                child.stdin.write("mv /etc/gdm3/custom_2.conf /etc/gdm3/custom.conf\n");
                child.stdin.write("\nexit\n");
                child.waitExit();
            }
        }
    }
    function waylandDM()
    {
        if (require('fs').existsSync('/etc/gdm/custom.conf')) { return ('gdm'); }
        if (require('fs').existsSync('/etc/gdm3/custom.conf')) { return ('gdm3'); }
        return ('');
    }
    module.exports =
        {
            createVirtualSession: spawnVirtualSession,
            hasVirtualSessionSupport: hasVirtualSessionSupport(),
            users: getUsers,
            loginUids: loginUids,
            allowed: allowedUIDs,
            waylandStatus: waylandStatus,
            disableWayland: disableWayland,
            enableWayland: enableWayland,
            waylandDM: waylandDM
        }
}
else
{
    module.exports =
        {
            createVirtualSession: function (uid) { return (uid); },
            hasVirtualSessionSupport: false,
            users: getUsers,
            allowed: allowedUIDs
        }
}