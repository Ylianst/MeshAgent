/*
Copyright 2019-2020 Intel Corporation

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

function trimIdentifiers(val)
{
    for(var v in val)
    {
        if (!val[v] || val[v] == 'None' || val[v] == '') { delete val[v]; }
    }
}

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
    identifiers['product_uuid'] = ret['product_uuid'];

    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('cat /proc/cpuinfo | grep "model name" | ' + "tr '\\n' ':' | awk -F: '{ print $2 }'\nexit\n");
    child.waitExit();
    identifiers['cpu_name'] = child.stdout.str.trim();


    // Fetch GPU info
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write("lspci | grep ' VGA ' | tr '\\n' '`' | awk '{ a=split($0,lines" + ',"`"); printf "["; for(i=1;i<a;++i) { split(lines[i],gpu,"r: "); printf "%s\\"%s\\"", (i==1?"":","),gpu[2]; } printf "]"; }\'\nexit\n');
    child.waitExit();
    try { identifiers['gpu_name'] = JSON.parse(child.stdout.str.trim()); } catch (xx) { }

    // Fetch Storage Info
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write("lshw -class disk | tr '\\n' '`' | awk '" + '{ len=split($0,lines,"*"); printf "["; for(i=2;i<=len;++i) { model=""; caption=""; size=""; clen=split(lines[i],item,"`"); for(j=2;j<clen;++j) { split(item[j],tokens,":"); split(tokens[1],key," "); if(key[1]=="description") { caption=substr(tokens[2],2); } if(key[1]=="product") { model=substr(tokens[2],2); } if(key[1]=="size") { size=substr(tokens[2],2);  } } if(model=="") { model=caption; } if(caption!="" || model!="") { printf "%s{\\"Caption\\":\\"%s\\",\\"Model\\":\\"%s\\",\\"Size\\":\\"%s\\"}",(i==2?"":","),caption,model,size; }  } printf "]"; }\'\nexit\n');
    child.waitExit();
    try { identifiers['storage_devices'] = JSON.parse(child.stdout.str.trim()); } catch (xx) { }

    values.identifiers = identifiers;
    values.linux = ret;
    trimIdentifiers(values.identifiers);
    return (values);
}

function windows_wmic_results(str)
{
    var lines = str.trim().split('\r\n');
    var keys = lines[0].split(',');
    var i, key, keyval;
    var tokens;
    var result = [];

    for (i = 1; i < lines.length; ++i)
    {
        var obj = {};
        tokens = lines[i].split(',');
        for (key = 0; key < keys.length; ++key)
        {
            if (tokens[key].trim())
            {
                obj[keys[key].trim()] = tokens[key].trim();
            }
        }
        delete obj.Node;
        result.push(obj);
    }
    return (result);
}


function windows_identifiers()
{
    var ret = { windows: {}}; values = {}; var items; var i; var item;
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

    child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', 'CSProduct', 'get', '/VALUE']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();

    var items = child.stdout.str.split('\r\r\n');
    for (i in items)
    {
        item = items[i].split('=');
        values[item[0]] = item[1];
    }
    ret['identifiers']['product_uuid'] = values['UUID'];
    trimIdentifiers(ret.identifiers);

    var CSV = '/FORMAT:"' + require('util-language').wmicXslPath + 'csv"';

    child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', 'MEMORYCHIP', 'LIST', CSV]);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();
    ret.windows.memory = windows_wmic_results(child.stdout.str);

    child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', 'OS', 'GET', CSV]);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();
    ret.windows.osinfo = windows_wmic_results(child.stdout.str)[0];

    child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', 'PARTITION', 'LIST', CSV]);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();
    ret.windows.partitions = windows_wmic_results(child.stdout.str);

    child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', 'CPU', 'LIST', 'BRIEF', CSV]);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();
    ret.windows.cpu = windows_wmic_results(child.stdout.str);

    child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', 'PATH', 'Win32_VideoController', 'GET', 'Name,CurrentHorizontalResolution,CurrentVerticalResolution', CSV]);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();
    ret.windows.gpu = windows_wmic_results(child.stdout.str);

    child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', 'diskdrive', 'LIST', 'BRIEF', CSV]);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();
    ret.windows.drives = windows_wmic_results(child.stdout.str);

    // Insert GPU names
    ret.identifiers.gpu_name = [];
    for (var gpuinfo in ret.windows.gpu)
    {
        if (ret.windows.gpu[gpuinfo].Name) { ret.identifiers.gpu_name.push(ret.windows.gpu[gpuinfo].Name); }
    }

    // Insert Storage Devices
    ret.identifiers.storage_devices = [];
    for (var dv in ret.windows.drives)
    {
        ret.identifiers.storage_devices.push({ Caption: ret.windows.drives[dv].Caption, Model: ret.windows.drives[dv].Model, Size: ret.windows.drives[dv].Size });
    }

    try { ret.identifiers.cpu_name = ret.windows.cpu[0].Name; } catch (x) { }
    return (ret);
}
function macos_identifiers()
{
    var ret = { identifiers: {} };
    var child;

    child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('ioreg -d2 -c IOPlatformExpertDevice | grep board-id | awk -F= \'{ split($2, res, "\\""); print res[2]; }\'\nexit\n');
    child.waitExit();
    ret.identifiers.board_name = child.stdout.str.trim();

    child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('ioreg -d2 -c IOPlatformExpertDevice | grep IOPlatformSerialNumber | awk -F= \'{ split($2, res, "\\""); print res[2]; }\'\nexit\n');
    child.waitExit();
    ret.identifiers.board_serial = child.stdout.str.trim();

    child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('ioreg -d2 -c IOPlatformExpertDevice | grep manufacturer | awk -F= \'{ split($2, res, "\\""); print res[2]; }\'\nexit\n');
    child.waitExit();
    ret.identifiers.board_vendor = child.stdout.str.trim();

    child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('ioreg -d2 -c IOPlatformExpertDevice | grep version | awk -F= \'{ split($2, res, "\\""); print res[2]; }\'\nexit\n');
    child.waitExit();
    ret.identifiers.board_version = child.stdout.str.trim();

    child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('ioreg -d2 -c IOPlatformExpertDevice | grep IOPlatformUUID | awk -F= \'{ split($2, res, "\\""); print res[2]; }\'\nexit\n');
    child.waitExit();
    ret.identifiers.product_uuid = child.stdout.str.trim();

    child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write('sysctl -n machdep.cpu.brand_string\nexit\n');
    child.waitExit();
    ret.identifiers.cpu_name = child.stdout.str.trim();


    trimIdentifiers(ret.identifiers);
    return (ret);
}

function win_chassisType()
{
    var child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', 'SystemEnclosure', 'get', 'ChassisTypes']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();

    try
    {
        var tok = child.stdout.str.split('{')[1].split('}')[0];
        var val = tok.split(',')[0];
        return (parseInt(val));
    }
    catch (e)
    {
        return (2); // unknown
    }
}

function win_systemType()
{
    var CSV = '/FORMAT:"' + require('util-language').wmicXslPath + 'csv"';
    var child = require('child_process').execFile(process.env['windir'] + '\\System32\\wbem\\wmic.exe', ['wmic', 'ComputerSystem', 'get', 'PCSystemType', CSV]);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();

    return (parseInt(child.stdout.str.trim().split(',').pop()));
}

function win_formFactor(chassistype)
{
    var ret = 'DESKTOP';
    switch (chassistype)
    {
        case 11:    // Handheld
        case 30:    // Tablet
        case 31:    // Convertible
        case 32:    // Detachable
            ret = 'TABLET';
            break;
        case 9:     // Laptop
        case 10:    // Notebook
        case 14:    // Sub Notebook
            ret = 'LAPTOP';
            break;
        default:
            ret = win_systemType() == 2 ? 'MOBILE' : 'DESKTOP';
            break;
    }

    return (ret);
}

switch(process.platform)
{
    case 'linux':
        module.exports = { _ObjectID: 'identifiers', get: linux_identifiers };
        break;
    case 'win32':
        module.exports = { _ObjectID: 'identifiers', get: windows_identifiers, chassisType: win_chassisType, formFactor: win_formFactor, systemType: win_systemType };
        break;
    case 'darwin':
        module.exports = { _ObjectID: 'identifiers', get: macos_identifiers };
        break;
    default:
        module.exports = { get: function () { throw ('Unsupported Platform'); } };
        break;
}
module.exports.isDocker = function isDocker()
{
    if (process.platform != 'linux') { return (false); }

    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write("cat /proc/self/cgroup | tr '\n' '`' | awk -F'`' '{ split($1, res, " + '"/"); if(res[2]=="docker"){print "1";} }\'\nexit\n');
    child.waitExit();
    return (child.stdout.str != '');
};
module.exports.isBatteryPowered = function isBatteryOperated()
{
    var ret = false;
    switch(process.platform)
    {
        default:
            break;
        case 'linux':
            var devices = require('fs').readdirSync('/sys/class/power_supply');
            for (var i in devices)
            {
                if (require('fs').readFileSync('/sys/class/power_supply/' + devices[i] + '/type').toString().trim() == 'Battery')
                {
                    ret = true;
                    break;
                }
            }
            break;
        case 'win32':
            var GM = require('_GenericMarshal');
            var stats = GM.CreateVariable(12);
            var kernel32 = GM.CreateNativeProxy('Kernel32.dll');
            kernel32.CreateMethod('GetSystemPowerStatus');
            if (kernel32.GetSystemPowerStatus(stats).Val != 0)
            {
                if(stats.toBuffer()[1] != 128 && stats.toBuffer()[1] != 255)
                {
                    ret = true;
                }
                else
                {
                    // No Battery detected, so lets check if there is supposed to be one
                    var formFactor = win_formFactor(win_chassisType());
                    return (formFactor == 'LAPTOP' || formFactor == 'TABLET' || formFactor == 'MOBILE');
                }
            }
            break;
        case 'darwin':
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function(c){ this.str += c.toString(); });
            child.stderr.str = ''; child.stderr.on('data', function(c){ this.str += c.toString(); });
            child.stdin.write("pmset -g batt | tr '\\n' '`' | awk -F'`' '{ if(NF>2) { print \"true\"; }}'\nexit\n");
            child.waitExit();
            if(child.stdout.str.trim() != '') { ret = true; }
            break;
    }
    return (ret);
};
module.exports.isVM = function isVM()
{
    var ret = false;
    var id = this.get();
    if (id.linux && id.linux.sys_vendor)
    {
        switch (id.linux.sys_vendor)
        {
            case 'VMware, Inc.':
            case 'QEMU':
            case 'Xen':
                ret = true;
                break;
            default:
                break;
        }
    }
    if (id.identifiers.bios_vendor)
    {
        switch(id.identifiers.bios_vendor)
        {
            case 'VMware, Inc.':
            case 'Xen':
            case 'SeaBIOS':
                ret = true;
                break;
            default:
                break;
        }
    }
    if (id.identifiers.board_vendor && id.identifiers.board_vendor == 'VMware, Inc.') { ret = true; }
    if (id.identifiers.board_name)
    {
        switch (id.identifiers.board_name)
        {
            case 'VirtualBox':
            case 'Virtual Machine':
                ret = true;
                break;
            default:
                break;
        }
    }

    if (process.platform == 'win32' && !ret)
    {
        for(var i in id.identifiers.gpu_name)
        {
            if(id.identifiers.gpu_name[i].startsWith('VMware '))
            {
                ret = true;
                break;
            }
        }
    }


    if (!ret) { ret = this.isDocker(); }
    return (ret);
};


// bios_date = BIOS->ReleaseDate
// bios_vendor = BIOS->Manufacturer
// bios_version = BIOS->SMBIOSBIOSVersion
// board_name = BASEBOARD->Product = ioreg/board-id
// board_serial = BASEBOARD->SerialNumber = ioreg/serial-number | ioreg/IOPlatformSerialNumber
// board_vendor = BASEBOARD->Manufacturer = ioreg/manufacturer
// board_version = BASEBOARD->Version

