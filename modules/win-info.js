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

function qfe()
{
    var child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', 'qfe', 'list', 'full', '/FORMAT:CSV']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();

    var lines = child.stdout.str.trim().split('\r\n');
    var keys = lines[0].split(',');
    var i, key;
    var tokens;
    var result = [];

    for (i = 1; i < lines.length; ++i)
    {
        var obj = {};
        tokens = lines[i].split(',');
        for (key = 0; key < keys.length; ++key)
        {
            if (tokens[key]) { obj[keys[key]] = tokens[key]; }
        }
        result.push(obj);
    }
    return (result);
}
function av()
{
    var child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', '/Namespace:\\\\root\\SecurityCenter2', 'Path', 'AntiVirusProduct', 'get', '/FORMAT:CSV']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();

    var lines = child.stdout.str.trim().split('\r\n');
    var keys = lines[0].split(',');
    var i, key;
    var tokens;
    var result = [];

    for (i = 1; i < lines.length; ++i)
    {
        var obj = {};
        var status = {};
        tokens = lines[i].split(',');
        for (key = 0; key < keys.length; ++key)
        {
            if (tokens[key] != undefined) { obj[keys[key].trim()] = tokens[key]; }
        }
        status.product = obj.displayName;
        status.updated = (parseInt(obj.productState) & 0x10) == 0;
        status.enabled = (parseInt(obj.productState) & 0x1000) == 0x1000;
        result.push(status);
    }
    return (result);
}

module.exports = { qfe: qfe, av: av }