// Module: win-bcd
// Timestamp: 2025-08-19T13:12:47.000-06:00
// Original compressed size: 1775 bytes
// Decompressed size: 5731 bytes
// Compression ratio: 69.0%

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

//
// win-bcd interacts with Windows BCD to be able to modify Safe Mode related settings
//


//
// This function uses the Windows System Utility 'bcdedit' to fetch metadata about the bootloader configuration
//
function getKeys()
{
    var ret = {};
    child = require('child_process').execFile(process.env['windir'] + "\\System32\\bcdedit.exe", ['bcdedit', '/enum', '{current}']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.on('data', function () { });
    child.waitExit();

    var lines = child.stdout.str.trim().split('\r\n');
    lines.shift(); lines.shift();

    //
    // Enumerate each line entry, and parse out the key/value pair
    //
    for (var i in lines)
    {
        var tokens = lines[i].split(' ');
        var key = tokens.shift();
        var value = tokens.join(' ').trim();
        ret[key] = value;
    }
    return (ret);
}

//
// Returns the value associated with the specified key
//
function getKey(key)
{
    return (this.getKeys()[key]);
}

//
// Using the Windows System Utility 'bcdedit', set a key/value to the current bootloader configuration
//
function setKey(key, value)
{
    var child = require('child_process').execFile(process.env['windir'] + "\\System32\\bcdedit.exe", ['bcdedit', '/set', '{current}', key, value]);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.on('data', function () { });
    child.waitExit();
}

//
// Using the Windows System Utility 'bcdedit', delete a key/value pair from the current bootloader configuration
//
function deleteKey(key)
{
    var child = require('child_process').execFile(process.env['windir'] + "\\System32\\bcdedit.exe", ['bcdedit', '/deletevalue', '{current}', key]);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.on('data', function () { });
    child.waitExit();
}

//
// Add the specified service name, to Window's list of services allowed to run in SafeMode with Networking
//
function enableSafeModeService(serviceName)
{
    require('win-registry').WriteKey(require('win-registry').HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Control\\Safeboot\\Network\\' + serviceName, null, 'Service');
}

//
// Query if the specified service name is allowed to run in Safe Mode
//
function isSafeModeService(serviceName)
{
    var reg = require('win-registry');
    var key = { default: 'none' };
    try { key = reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Control\\Safeboot\\Network\\' + serviceName); } catch (qke) { }
    return (key.default == 'Service');
}

//
// Remove the specified service from the allowed list of services that can run in Safe Mode
//
function disableSafeModeService(serviceName)
{
    try
    {
        require('win-registry').DeleteKey(require('win-registry').HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Control\\Safeboot\\Network\\' + serviceName);
    }
    catch(x)
    {
    }
}

//
// Use the windows system utility, 'shutdown' to restart the PC immediately
//
function restart(delay)
{
    var child = require('child_process').execFile(process.env['windir'] + "\\System32\\shutdown.exe", ['shutdown', '/r', '/t', delay!=null?delay.toString():'0']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.on('data', function (c) { console.log(c.toString());});
    child.waitExit();
}

if (require('_GenericMarshal').PointerSize == 4 && require('os').arch() == 'x64')
{
    //
    // 32 bit agent running on 64 bit windows, we do not expose BCD functions, because bcdedit does not work from a 32 bit process on 64 bit windows
    //
    module.exports =
    {
        enableSafeModeService: enableSafeModeService,
        disableSafeModeService: disableSafeModeService, restart: restart, isSafeModeService: isSafeModeService
    };
}
else
{
    module.exports =
        {
            getKeys: getKeys, setKey: setKey, deleteKey: deleteKey, enableSafeModeService: enableSafeModeService,
            disableSafeModeService: disableSafeModeService, getKey: getKey, restart: restart, isSafeModeService: isSafeModeService
        };

    //
    // Query what the next boot mode is currently set to... NORMAL, SAFEMODE, or SAFEMODE w/Networking
    //
    Object.defineProperty(module.exports, "bootMode",
        {
            get: function ()
            {
                try
                {
                    var v = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Control\\Safeboot\\Option', 'OptionValue');
                    switch (v)
                    {
                        case 2:
                            return ('SAFE_MODE_NETWORK');
                            break;
                        default:
                            return ('SAFE_MODE');
                            break;
                    }
                    return (v);
                }
                catch (x)
                {
                    return ('NORMAL');
                }
            }
        });
}