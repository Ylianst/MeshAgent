/*
Copyright 2021 Intel Corporation

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

//
// This module is used to query the DNS server address from the OS
//

function windows_dns()
{
    //
    // Reference for GetNetworkParams() can be found at:
    // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getnetworkparams
    //

    var ret = [];
    var ip = require('_GenericMarshal').CreateNativeProxy('Iphlpapi.dll');
    ip.CreateMethod('GetNetworkParams');

    var data = require('_GenericMarshal').CreateVariable(1024);
    var len = require('_GenericMarshal').CreateVariable(4);
    len.toBuffer().writeUInt32LE(1024);

    if (ip.GetNetworkParams(data, len).Val == 0)
    {
        var dnsList = data.Deref(require('_GenericMarshal').PointerSize == 8 ? 272 : 268, 48);

        do
        {
            ret.push(dnsList.Deref(require('_GenericMarshal').PointerSize, 16).toBuffer().toString());
        } while ((dnsList = dnsList.Deref(0, require('_GenericMarshal').PointerSize).Deref().Deref(0, 48)).Val != 0); // Itereate the list
    }
    return (ret);
}
function linux_dns()
{

    //
    // The linux implementation will look for the dns address in /etc/resolve.conf
    //
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.on('data', function () { });
    child.stdin.write("cat /etc/resolv.conf | grep nameserver | tr '\n' '`' | awk -F'`' '");
    child.stdin.write('{');
    child.stdin.write('   DEL="";');
    child.stdin.write('   printf "[";');
    child.stdin.write('   for(i=1;i<NF;++i)');
    child.stdin.write('   {');
    child.stdin.write('      if($i~/^#/) { continue; }')
    child.stdin.write('      z=split($i,T," ");');
    child.stdin.write('      if(z==2 && T[1]=="nameserver")');
    child.stdin.write('      {');
    child.stdin.write('         printf "%s\\\"%s\\\"",DEL,T[2];');
    child.stdin.write('         DEL=",";');
    child.stdin.write('      }');
    child.stdin.write('   }');
    child.stdin.write('   printf "]";');
    child.stdin.write("}'");
    child.stdin.write('\nexit\n');
    child.waitExit();
    try
    {
        return(JSON.parse(child.stdout.str.trim()));
    }
    catch(e)
    {
        return ([]);
    }
}

function macos_dns()
{
    //
    // macOS implementation will use the system utility scutil to fetch the dns address
    //
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.on('data', function () { });

    child.stdin.write("scutil --dns | grep nameserver | tr '\\n' '`' | awk -F'`' '");
    child.stdin.write('{');
    child.stdin.write('   DEL="";');
    child.stdin.write('   printf "{";');
    child.stdin.write('   for(i=1;i<NF;++i)');
    child.stdin.write('   {');
    child.stdin.write('      if($i ~ /^\\s* *\\t*nameserver\\[[0-9]]/)');
    child.stdin.write('      {');
    child.stdin.write('         A=split($i,TOK," ");');
    child.stdin.write('         printf "%s\\"%s\\": \\"%s\\"", DEL, TOK[3], TOK[1];');
    child.stdin.write('         DEL=",";');
    child.stdin.write('      }');
    child.stdin.write('   }');
    child.stdin.write('   printf "}";');
    child.stdin.write("}'");

    child.stdin.write('\nexit\n');
    child.waitExit();

    try
    {
        var table = JSON.parse(child.stdout.str.trim());
        return(table.keys());
    }
    catch(e)
    {
        return ([]);
    }
}

switch (process.platform)
{
    case 'linux':
    case 'freebsd':
        module.exports = linux_dns;     // Linux and BSD will use /etc/resolve.conf
        break;
    case 'win32':
        module.exports = windows_dns;   // Windows will use Iphlpapi
        break;
    case 'darwin':
        module.exports = macos_dns;     // macOS will use scutil
        break;
    default:
        module.exports = function () { return ([]); };
        break;
}
