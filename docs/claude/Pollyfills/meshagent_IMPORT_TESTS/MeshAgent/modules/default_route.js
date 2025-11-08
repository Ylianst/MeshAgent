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

function windows_defaultRoute()
{
    var ret = null;
    var GM = require('_GenericMarshal');
    IP = GM.CreateNativeProxy('Iphlpapi.dll');
    IP.CreateMethod('GetIpForwardTable');

    var size = GM.CreateVariable(4);
    var result = IP.GetIpForwardTable(0, size, 1);
    if(result.Val == 122)
    {
        var table = GM.CreateVariable(size.toBuffer().readUInt32LE());
        result = IP.GetIpForwardTable(table, size, 1);
        if(result.Val == 0)
        {
            var entries = table.Deref(0, 4).toBuffer().readUInt32LE();
            var row;
            
            for(var i=0;i<entries;++i)
            {
                row = table.Deref(4 + (i * 56), 56);
                if (row.Deref(0, 4).toBuffer().readUInt32LE() == 0)
                {
                    // Default Route
                    if (!ret || ret.metric > row.Deref(36, 4).toBuffer().readUInt32LE())
                    {
                        ret = { interface: row.Deref(16, 4).toBuffer().readUInt32LE(), metric: row.Deref(36, 4).toBuffer().readUInt32LE() };
                    }
                }
            }
        }
    }
    return (ret);
}

function linux_defaultRoute()
{
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stderr.on('data', function (c) { });
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('ip route | grep default | awk \'{ if( $1=="default" && $4=="dev" ) { print $5; } }\'\nexit\n');
    child.waitExit();
    return (child.stdout.str.trim() == '' ? null : { interface: child.stdout.str.trim(), metric: 1 });
}

function bsd_defaultRoute()
{
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stderr.on('data', function (c) { });
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('netstat -rn -f inet | grep default | awk \'{ print $NF }\'\nexit\n');
    child.waitExit();
    return (child.stdout.str.trim() == '' ? null : { interface: child.stdout.str.trim(), metric: 1 });
}

switch(process.platform)
{
    case 'win32':
        module.exports = windows_defaultRoute;
        break;
    case 'linux':
        module.exports = linux_defaultRoute;
        break;
    case 'freebsd':
    case 'darwin':
        module.exports = bsd_defaultRoute;
        break;
}

