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


function win_serviceCheck()
{
    var s;
    var reg = require('win-registry');
    var path;
    var values = reg.QueryKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Open Source');
    if (values.subkeys)
    {
        for (var i in values.subkeys)
        {
            try
            {
                s = require('service-manager').manager.getService(values.subkeys[i]);
                if(s.isMe())
                {
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
        for(var i in values.subkeys)
        {
            try
            {
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
                    try
                    {
                        s = require('service-manager').manager.getService(values.subkeys[i]);
                        if(s.isMe())
                        {
                            s.close();
                            return (values.subkeys[i]);
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
    return (null);
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

