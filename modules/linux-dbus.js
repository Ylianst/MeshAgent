/*
Copyright 2018 Intel Corporation

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

try { Object.defineProperty(Array.prototype, "peek", { value: function () { return (this.length > 0 ? this[this.length - 1] : undefined); } }); } catch (e) { }



function dbus(address, uid, env)
{
    console.log(address, uid, env);
    this._ObjectID = 'linux-dbus';
    require('events').EventEmitter.call(this, true)
        .createEvent('signal');
    Object.defineProperty(this, "uid", { value: uid });
    //this._child = require('child_process').execFile("/bin/sh", ["sh"], { type: require('child_process').SpawnTypes.TERM, uid: uid == null ? -1 : uid });
    this._child = require('child_process').execFile("/bin/sh", ["sh"], { env: env, uid: uid == null ? -1 : uid });
    this._child.stdin.write('dbus-monitor --session "type=\'signal\', interface=\'' + address + '\'" | ( while read X; do echo "$X"; done )\n');
    this._child.stderr.on('data', function (c) {  });
    this._child.stdout.dbus = this;
    this._child.stdout._str = '';
    this._child.stdout._pending = [];
    this._child.on('exit', function () { });
    this._child.stdout._processPending = function _processPending()
    {
        //console.log(JSON.stringify(this._pending, null, 1));

        this._pendingTimeout = null;
        var sig = {};
        var tmp, tmp2;

        var info = this._pending[0].split(';');
        for (i = 1; i < info.length; ++i)
        {
            var info2 = info[i].split('=');
            sig[info2[0].trim()] = info2[1].trim();
        }
        for (i = 1; i < this._pending.length; ++i)
        {
            if (this._pending[i].startsWith('string '))
            {
                sig['value'] = this._pending[i].split('"')[1];
            }
            else if (this._pending[i].startsWith('boolean '))
            {
                sig['value'] = JSON.parse(this._pending[i].split(' ')[1]);
            }
            if (this._pending[i].startsWith('array '))
            {
                sig['data'] = [];
                for (i = i + 1; i < this._pending.length; ++i)
                {
                    if (this._pending[i].startsWith('string '))
                    {
                        tmp = this._pending[i].split('"')[1].split('=');
                        tmp2 = {};
                        tmp2[tmp[0].trim()] = tmp[1].trim();
                        sig['data'].push(tmp2);
                    }
                }
                break;
            }
        }
        this._pending = [];

        setImmediate(function (e, s)
        {
            e.dbus.emit('signal', s);
        }, this, sig);
    };
    this._child.stdout.on('data', function (chunk)
    {
        // Parse DBUS Data
        if (this._pendingTimeout) { clearTimeout(this._pendingTimeout); this._pendingTimeout = null; }
        //console.log('=>' + chunk.toString() + '<=');

        var i;
        var tokens = chunk.toString().split('\n');
        for (i in tokens)
        {
            if (tokens[i].startsWith('signal '))
            {
                if (this._pending.length > 0) { this._processPending(); }
            }
            this._pending.push(tokens[i]);
        }

        if (this._pending.length > 0)
        {
            this._pendingTimeout = setTimeout(function (self) { self._processPending(); }, 500, this);
        }
    });
}

module.exports = dbus;
module.exports.hasService = function hasService(name)
{
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('cat /usr/share/dbus-1/services/*.service | grep "' + name + '" | awk -F= \'{ if( $2=="' + name + '" ) { print $2; } }\'\nexit\n');
    child.waitExit();
    return (child.stdout.str.trim() != '');
};
module.exports.getServices = function getServices()
{
    var grep = null;
    var options = null;
    for (var ax in arguments)
    {
        if(typeof(arguments[ax])=='string')
        {
            grep = arguments[ax];
        }
        if(typeof(arguments[ax])=='object')
        {
            options = arguments[ax];
        }
    }

    if (grep) { grep = ' | grep "' + grep + '"'; } else { grep = ''; }
    var child = require('child_process').execFile('/bin/sh', ['sh'], options);
    child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames' + grep + '\nexit\n');
    child.waitExit();

    var ret = [];
    var i, tmp;
    var tokens = child.stdout.str.trim().split('\n');
    for (i = 0; i < tokens.length; ++i)
    {
        if ((tmp = tokens[i].trim()).startsWith('array '))
        {
            for (i = i + 1; i < tokens.length; ++i)
            {
                tmp = tokens[i].trim();
                if (tmp.startsWith('string '))
                {
                    ret.push(JSON.parse(tmp.split(' ')[1]));
                }
            }
        }
        else if(tmp.startsWith('string '))
        {
            ret.push(JSON.parse(tmp.split(' ')[1]));
        }
    }
    return (ret);
}
