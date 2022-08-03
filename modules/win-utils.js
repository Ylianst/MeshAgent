/*
Copyright 2022 Intel Corporation
@author Bryan Roe

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
// win-utils provides helper functions for Windows Platforms
//
var reg = require('win-registry');

function winutils()
{
    this._ObjectID = 'win-utils';
    this.taskBar =
        {
            autoHide: function autoHide(tsid, value)
            {
                var domain = require('user-sessions').getDomain(tsid);
                var user = require('user-sessions').getUsername(tsid);
                var key = reg.usernameToUserKey({ domain: domain, user: user });
                if(value==null)
                {
                    // Query the Current State
                    var rv = reg.QueryKey(reg.HKEY.Users, key + '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StuckRects3', 'Settings');
                    return (rv[8] == 3);
                }
                else
                {
                    var rv = reg.QueryKey(reg.HKEY.Users, key + '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StuckRects3', 'Settings');
                    rv[8] = value === true ? 3 : 2;
                    reg.WriteKey(reg.HKEY.Users, key + '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StuckRects3', 'Settings', rv);
                    var pids = require('process-manager').getProcessEx('explorer.exe');
                    if(pids.length == 1)
                    {
                        process.kill(pids[0]);
                    }
                    return (this.autoHide(tsid));
                }
            }
        };
}


module.exports = new winutils();