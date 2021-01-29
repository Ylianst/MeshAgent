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


function invalid()
{
    throw ('Not supported on ' + process.platform);
}

function getOpenDescriptors()
{

    switch (process.platform)
    {
        case "freebsd":
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.stderr.on('data', function (c) { });

            child.stdin.write("procstat -f " + process.pid + " | tr '\\n' '`' | awk -F'`' '");
            child.stdin.write('{');
            child.stdin.write('   DEL="";');
            child.stdin.write('   printf "[";');
            child.stdin.write('   for(i=1;i<NF;++i)');
            child.stdin.write('   {');
            child.stdin.write('      A=split($i,B," ");');
            child.stdin.write('      if(B[3] ~ /^[0-9]/)');
            child.stdin.write('      {');
            child.stdin.write('         printf "%s%s", DEL, B[3];');
            child.stdin.write('         DEL=",";');
            child.stdin.write('      }');
            child.stdin.write('   }');
            child.stdin.write('   printf "]";');
            child.stdin.write("}'");

            child.stdin.write('\nexit\n');
            child.waitExit();

            try
            {
                return (JSON.parse(child.stdout.str.trim()));
            }
            catch (e)
            {
                return ([]);
            }
            break;
        case "linux":
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.stderr.on('data', function (c) { });

            child.stdin.write("ls /proc/" + process.pid + "/fd | tr '\\n' '`' | awk -F'`' '");
            child.stdin.write('{');
            child.stdin.write('   printf "[";');
            child.stdin.write('   DEL="";');
            child.stdin.write('   for(i=1;i<NF;++i)');
            child.stdin.write('   {');
            child.stdin.write('      printf "%s%s",DEL,$i;');
            child.stdin.write('      DEL=",";');
            child.stdin.write('   }');
            child.stdin.write('   printf "]";');
            child.stdin.write("}'");
            child.stdin.write('\nexit\n');
            child.waitExit();

            try
            {
                return (JSON.parse(child.stdout.str.trim()));
            }
            catch (e)
            {
                return ([]);
            }
            break;
        default:
            return ([]);
    }
}
function closeDescriptors(fdArray, libc)
{
    var fd = null;
    if (libc == null)
    {
        var libs = require('monitor-info').getLibInfo('libc');
        while (libs.length > 0)
        {
            try
            {
                libc = require('_GenericMarshal').CreateNativeProxy(libs.shift().path);
                libc.CreateMethod('close');
                break;
            }
            catch (e)
            {
                libc = null;
            }
        }
        if (libc == null) { throw ('cannot find libc'); }
    }

    while (fdArray.length > 0)
    {
        fd = fdArray.pop();
        if (fd > 2)
        {
            libc.close(fd);
        }
    }
}

switch (process.platform)
{
    case 'linux':
    case 'freebsd':
        module.exports = { getOpenDescriptors: getOpenDescriptors, closeDescriptors: closeDescriptors };
        break;
    default:
        module.exports = { getOpenDescriptors: invalid, closeDescriptors: invalid };
        break;
}