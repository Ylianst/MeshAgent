

function getUsers()
{
    var res, i, uu = {};
    require('user-sessions').Current(function (u) { res = u; });

    for (i in res)
    {
        if (process.platform != 'win32') { res[i].SessionId = res[i].uid; }
        if (res[i].State == 'Active' || res[i].State == 'Connected') { uu[process.platform == 'win32' ? res[i].SessionId : res[i].uid] = res[i]; }
    }

    if (process.platform != 'win32')
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

    res = [];
    for (i in uu)
    {
        res.push(uu[i]);
    }
    return (res);
}

if (process.platform == 'linux')
{
    var allowedUIDs = [];
    const uid_max = require('user-sessions').getUidConfig().MAX;
    const hasXvfb = require('lib-finder').hasBinary('xvfb-run');
    const hasGnomeSession = require('lib-finder').hasBinary('gnome-session');

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
            terminal.stdin.write('xvfb-run -n 99 -a gnome-session &\n');
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
        return (require('user-sessions').hasLoginCtl && hasXvfb && hasGnomeSession);
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

    module.exports =
        {
            createVirtualSession: spawnVirtualSession,
            hasVirtualSessionSupport: hasVirtualSessionSupport(),
            users: getUsers,
            loginUids: loginUids,
            allowed: allowedUIDs,
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