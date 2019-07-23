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

function linux_identifiers()
{
    var identifiers = {};
    var ret = {};
    var values = {};
    if (!require('fs').existsSync('/sys/class/dmi/id')) { throw ('this platform does not have DMI statistics'); }
    var entries = require('fs').readdirSync('/sys/class/dmi/id');
    for(var i in entries)
    {
        if (require('fs').statSync('/sys/class/dmi/id/' + entries[i]).isFile())
        {
            ret[entries[i]] = require('fs').readFileSync('/sys/class/dmi/id/' + entries[i]).toString().trim();

            if (ret[entries[i]] == 'None') { delete ret[entries[i]];}
        }
    }
    identifiers['bios_date'] = ret['bios_date'];
    identifiers['bios_vendor'] = ret['bios_vendor'];
    identifiers['bios_version'] = ret['bios_version'];
    identifiers['board_name'] = ret['board_name'];
    identifiers['board_serial'] = ret['board_serial'];
    identifiers['board_vendor'] = ret['board_vendor'];
    identifiers['board_version'] = ret['board_version'];
    
    values.identifiers = identifiers;
    values.linux = ret;
    return (values);
}
function windows_identifiers()
{
    var ret = {}; values = {}; var items; var i; var item;
    var child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', 'bios', 'get', '/VALUE']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();

    var items = child.stdout.str.split('\r\r\n');
    for(i in items)
    {
        item = items[i].split('=');
        values[item[0]] = item[1];
    }

    ret['identifiers'] = {};
    ret['identifiers']['bios_date'] = values['ReleaseDate'];
    ret['identifiers']['bios_vendor'] = values['Manufacturer'];
    ret['identifiers']['bios_version'] = values['SMBIOSBIOSVersion'];

    child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', 'BASEBOARD', 'get', '/VALUE']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();

    var items = child.stdout.str.split('\r\r\n');
    for (i in items)
    {
        item = items[i].split('=');
        values[item[0]] = item[1];
    }
    ret['identifiers']['board_name'] = values['Product'];
    ret['identifiers']['board_serial'] = values['SerialNumber'];
    ret['identifiers']['board_vendor'] = values['Manufacturer'];
    ret['identifiers']['board_version'] = values['Version'];
    return (ret);
}


switch(process.platform)
{
    case 'linux':
        module.exports = { _ObjectID: 'identifiers', get: linux_identifiers };
        break;
    case 'win32':
        module.exports = { _ObjectID: 'identifiers', get: windows_identifiers };
        break;
    default:
        module.exports = { get: function () { throw ('Unsupported Platform'); } };
        break;
}


// bios_date = BIOS->ReleaseDate
// bios_vendor = BIOS->Manufacturer
// bios_version = BIOS->SMBIOSBIOSVersion
// board_name = BASEBOARD->Product
// board_serial = BASEBOARD->SerialNumber
// board_vendor = BASEBOARD->Manufacturer
// board_version = BASEBOARD->Version

