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

const SYNCHRONIZE = 0x00100000;

//
// util-descriptors is a helper module that will enable enumeration of all open descriptors, as well as a means to close them
//


function invalid()
{
    throw ('Not supported on ' + process.platform);
}

//
// Returns an array containing all the open descriptors for the current process
//
function getOpenDescriptors()
{

    switch (process.platform)
    {
        case "freebsd":
            //
            // BSD will use the system utility procstat to fetch the list of descriptors
            //
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
            //
            // Linux we will just rely on procfs to find the descriptors for our PID
            //
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
//
// This function will enumerate the specified array of descriptors, and close each one
//
function closeDescriptors(fdArray)
{
    var fd = null;
    if (this.libc == null) { throw ('cannot find libc'); }

    while (fdArray.length > 0)
    {
        fd = fdArray.pop();
        if (fd > 2)
        {
            this.libc.close(fd); // use glibc to close the descriptor
        }
    }
}

//
// execv helper function, which will close all open descriptors immediately before invoking execv()
//
function _execv(exePath, argarr)
{
    if (this.libc == null)
    {
        throw ('cannot find libc');
    }

    var i;
    var tmp = [];
    var path = require('_GenericMarshal').CreateVariable(exePath);
    var args = require('_GenericMarshal').CreateVariable((1 + argarr.length) * require('_GenericMarshal').PointerSize);
    for (i = 0; i < argarr.length; ++i)
    {
        // convert the JS array into a native array to be passed to execv
        var arg = require('_GenericMarshal').CreateVariable(argarr[i]);
        tmp.push(arg);
        arg.pointerBuffer().copy(args.toBuffer(), i * require('_GenericMarshal').PointerSize);
    }

    //
    // Fetch the list of all open descriptors, then close all of them. We need to do this, becuase
    // execv() is going to inherit all the descriptors, so they will probably leak if the new process doesn't know what to do with them
    //
    var fds = this.getOpenDescriptors();
    this.closeDescriptors(fds);

    this.libc.execv(path, args);
    throw('exec error');
}

//
// This function returns the native marshaler for glibc, specifically for 'execv' and 'close'
//
function getLibc()
{
    var libs = require('monitor-info').getLibInfo('libc'); // This will fetch the location of all the libc modules on the platform.
    var libc = null;

    while (libs.length > 0)
    {
        try
        {
            //
            // We need to enumerate each libc module, and try to load it, becuase it is common for a linux distribution
            // to include modules for several different architectures. So only the correct one will load. We need to find it.
            //
            libc = require('_GenericMarshal').CreateNativeProxy(libs.pop().path);
            libc.CreateMethod('execv');
            libc.CreateMethod('close');
            break;
        }
        catch (e)
        {
            libc = null;
            continue;
        }
    }

    return (libc);
}

//
// Windows helper function to fetch a HANDLE to the specified process
//
function win_getProcessHandle(pid)
{
    try
    {
        if(!this.kernel32)
        {
            //
            // Reference to OpenProcess() can be found at:
            // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
            //
            this.kernel32 = require('_GenericMarshal').CreateNativeProxy('kernel32.dll');
            this.kernel32.CreateMethod('OpenProcess');  
        }

        // This will return a HANDLE to the specified prcoess
        return (this.kernel32.OpenProcess(SYNCHRONIZE, 0, pid));
    }
    catch(e)
    {
        return (null);
    }
}

switch (process.platform)
{
    case 'linux':
    case 'freebsd':
        // Only Linux and FreeBSD support finding the list of open descriptors
        module.exports = { getOpenDescriptors: getOpenDescriptors, closeDescriptors: closeDescriptors, _execv: _execv, libc: getLibc() };
        break;
    default:
        // For other platforms, we will return an error
        module.exports = { getOpenDescriptors: invalid, closeDescriptors: invalid };
        break;
}

if (process.platform == 'win32')
{
    module.exports.getProcessHandle = win_getProcessHandle;
}