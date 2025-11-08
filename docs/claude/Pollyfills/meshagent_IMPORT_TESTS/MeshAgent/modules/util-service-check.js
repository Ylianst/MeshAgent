/*
Copyright 2020 Intel Corporation

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
// This is a windows helper that will try to determine the service name for the currently running service
//

//
// Will return the name of the currently running service if it can be determined, null otherwise
//
function win_serviceCheck()
{
    var s;
    var reg = require('win-registry');
    var path;
    var values = reg.QueryKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Open Source');

    //
    // The MeshAgent will normally add a registry entry into the above registry path, at installation time
    //

    if (values.subkeys)
    {
        for (var i in values.subkeys)
        {
            try
            {
                //
                // We are enumerating all the Mesh Agents listed in the registry above, and check with the
                // windows service manager to see if the PID matches the PID of the current process
                //
                s = require('service-manager').manager.getService(values.subkeys[i]);
                if(s.isMe())
                {
                    //
                    // This service is us, so we can return the results
                    //           
                    s.close();
                    return (values.subkeys[i]);
                }
                else
                {
                    s.close();
                }
            }
            catch (x)
            {
            }
        }
    }

    // Unable to find a match in LocalMachine/SOFTWARE/Open Source'
    values = reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services');
    if (values.subkeys)
    {
        //
        // We couldn't find a match in the registry where the Mesh Agent normally saves information about installation,
        // so we're going to just enumerate all the windows services, and try to manually brute force it
        //

        for(var i in values.subkeys)
        {
            try
            {
                // We're going to look at the exe path for each enumerated service
                path = reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + values.subkeys[i], 'ImagePath');
            }
            catch(xx)
            {
                continue;
            }
            path = path.split('.exe');
            if(path.length>1)
            {
                path = (path[0] + '.exe');
                if (path.startsWith('"')) { path = path.substring(1); }
                if(path == process.execPath)
                {
                    //
                    // If the service's exe path matches the exe path of the current process, we'll check the PID to see if it is indeed us
                    //
                    try
                    {
                        s = require('service-manager').manager.getService(values.subkeys[i]);
                        if(s.isMe())
                        {
                            s.close();
                            return (values.subkeys[i]); // It is a match!
                        }
                        s.close();
                    }
                    catch(ee)
                    {
                    }
                }
            }
        }
    }
    return (null); // We couldn't find the right service
}

switch(process.platform)
{
    case 'win32':
        module.exports = win_serviceCheck;
        break;
    default:
        module.exports = function () { return (null); }
        break;
}

