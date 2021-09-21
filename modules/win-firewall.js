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

var promise = require('promise');
var winreg = require('win-registry');

//attachDebugger({ webport: 9995, wait: true }).then(console.log, console.log);

function netsecurityExists()
{
    var child;
    var command = 'Get-Module -ListAvailable -Name netsecurity';
    if (require('os').arch() == 'x64')
    {
        child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['/C "' + command + '"']);
    }
    else
    {
        child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['/C "' + command + '"']);
    }
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
    try
    {
        child.waitExit(2000);
    }
    catch(e)
    {
        return (false);
    }

    return (child.stdout.str != '');
}

function stripUnrecognizedKeys(obj, allowedKeys)
{
    for(var key in obj)
    {
        if(!allowedKeys.includes(key))
        {
            delete obj[key];
        }
    }
}

function parseCmdletOutput(data)
{
    var touched;
    var ret = [];
    var chunks = data.trim().split('\r\n\r\n');
    var lines, x, obj;
    for (var i = 0; i < chunks.length; ++i)
    {
        obj = {}; touched = false;
        lines = chunks[i].split('\r\n');
        for (x = 0; x < lines.length; ++x)
        {
            var d = lines[x].indexOf(':');
            var key = lines[x].substring(0, d).trim();
            var value = lines[x].substring(d + 1).trim();
            if (key != "") { obj[key] = value; touched = true; }
        }
        if (touched) { ret.push(obj); }
    }
    return (ret);
}
function fetchPortFilters(rules)
{
    var i;
    if (!Array.isArray(rules))
    {
        rules = [rules];
    }
    for (i = 0; i < rules.length; ++i)
    {
        try
        {
            filter = winreg.QueryKey(winreg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules', rules[i].Name);
        }
        catch(fe)
        {
            continue;
        }
        tokens = filter.split('|');
        for (k = 0; k < tokens.length; ++k)
        {
            if ((tokenX = tokens[k].indexOf('=')) > 0)
            {
                switch (tokens[k].substring(0, tokenX))
                {
                    case 'Protocol':
                        rules[i].Protocol = tokens[k].substring(tokenX + 1);
                        break;
                    case 'LPort':
                        rules[i].LocalPort = tokens[k].substring(tokenX + 1);
                        break;
                    case 'RPort':
                        rules[i].RemotePort = tokens[k].substring(tokenX + 1);
                        break;
                    case 'App':
                        rules[i].Program = tokens[k].substring(tokenX + 1);
                        break;
                }
            }
        }
    }
}

function getFirewallRules(options)
{
    var p = new promise(function (a, r) { this._res = a; this._rej = r; });
    require('events').EventEmitter.call(p, true)
        .createEvent('firewallRule');

    var retVal = [], filter = [];
    var command = 'Get-NetFirewallRule';
    if (options.program) { options.Program = options.program; delete options.program; }
    if (options.Program) { command = 'Get-NetFirewallApplicationFilter -Program \\"' + options.Program + '\\" | ' + command; }

    if (require('os').arch() == 'x64')
    {
        p.child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['/C "' + command + '"']);
    }
    else
    {
        p.child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['/C "' + command + '"']);
    }
    p.options = options;
    p.child.parent = p;
    p.child.stdout.str = ''; p.child.stdout.on('data', function (c)
    {
        var command;
        this.str += c.toString();
        if(this.parent.parent.listenerCount('firewallRule')>0)
        {
            var i;
            if((i=this.str.indexOf('\r\n\r\n'))>=0)
            {
                var filter, k, tokens, tokenX;
                var j = this.str.substring(0, i);
                this.str = this.str.substring(i + 4);

                j = parseCmdletOutput(j);
                fetchPortFilters(j);

                for(i=0;i<j.length;++i)
                {                    
                    this.parent.parent.emit('firewallRule', j[i]);
                }
            }
        }
    });
    p.child.stderr.str = ''; p.child.stderr.on('data', function (c) { this.str += c.toString(); });

    p.child.on('exit', function ()
    {
        var command, i, j, child, filter;
        if (this.stderr.str.trim() != "") { this.parent._rej(this.stderr.str.trim()); return; }

        if (this.parent.listenerCount('firewallRule') > 0)
        {
            this.parent._res();
            return;
        }

        var objArr = parseCmdletOutput(this.stdout.str);
        fetchPortFilters(objArr);
        this.parent._res(objArr);
    });

    return (p);
}


function disableFirewallRules(options)
{
    var ret = new promise(function (a, r) { this._res = a; this._rej = r; });
    var command = 'Disable-NetFirewallRule';
    if (options.program) { options.Program = options.program; delete options.program; }

    if (options.Program)
    {
        command = 'Get-NetFirewallApplicationFilter -Program \\"' + options.Program + '\\" | ' + command;
    }
    else
    {
        var key, value;
        for (key in options)
        {
            value = options[key];
            if (value.indexOf(' ') >= 0) { value = '\\"' + options[key] + '\\"'; }
            command += ('-' + key + ' ' + value);
        }
    }

    if (require('os').arch() == 'x64')
    {
        ret.child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['/C "' + command + '"']);
    }
    else
    {
        ret.child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['/C "' + command + '"']);
    }

    ret.child.ret = ret;
    ret.child.stdout.str = ''; ret.child.stdout.on('data', function (c) { this.str += c.toString(); });
    ret.child.stderr.str = ''; ret.child.stderr.on('data', function (c) { this.str += c.toString(); });
    ret.child.on('exit', function ()
    {
        if (this.stderr.str != '')
        {
            this.ret._rej(this.stderr.str.trim());
        }
        else
        {
            this.ret._res();
        }
    });

    return (ret);
}

function enableFirewallRules(options)
{
    var ret = new promise(function (a, r) { this._res = a; this._rej = r; });
    if (options.program) { options.Program = options.program; delete options.program; }

    var command = 'Enable-NetFirewallRule';
    if (options.Program)
    {
        command = 'Get-NetFirewallApplicationFilter -Program \\"' + options.Program + '\\" | ' + command;
    }
    else
    {
        var key, value;
        for (key in options)
        {
            value = options[key];
            if (value.indexOf(' ') >= 0) { value = '\\"' + options[key] + '\\"'; }
            command += ('-' + key + ' ' + value);
        }
    }

    if (require('os').arch() == 'x64')
    {
        ret.child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['/C "' + command + '"']);
    }
    else
    {
        ret.child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['/C "' + command + '"']);
    }

    ret.child.ret = ret;
    ret.child.stdout.str = ''; ret.child.stdout.on('data', function (c) { this.str += c.toString(); });
    ret.child.stderr.str = ''; ret.child.stderr.on('data', function (c) { this.str += c.toString(); });
    ret.child.on('exit', function ()
    {
        if(this.stderr.str != '')
        {
            this.ret._rej(this.stderr.str.trim());
        }
        else
        {
            this.ret._res();
        }
    });

    return (ret);
}


function verifyValues(optionsInput, keyName, keyValues, defaultValue)
{
    var i, j, tmp, ok;
    for (var key in optionsInput)
    {
        if(keyName.toLowerCase() == key.toLowerCase())
        {
            tmp = optionsInput[key];
            delete optionsInput[key];

            if (keyValues == null)
            {
                optionsInput[keyName] = tmp;
                return;
            }
            else
            {
                if (tmp!=null) { tmp = tmp.toString().split(','); }
                for (j = 0; j < tmp.length; ++j)
                {
                    ok = false;
                    for (i=0;i<keyValues.length;++i)
                    {
                        if (keyValues[i].toString().toLowerCase() == tmp[j].toString().trim().toLowerCase())
                        {
                            optionsInput[keyName] = (optionsInput[keyName] == null ? keyValues[i] : (optionsInput[keyName] + ', ' + keyValues[i]));
                            ok = true;
                            break;
                        }
                    }
                    if (!ok)
                    {
                        throw ('Invalid value for [' + keyName + ']: ' + tmp[j]);
                    }
                }
                if (optionsInput[keyName] != null) { return; }
            }
        }
    }

    // If we got here, then the key doesn't exist... Check to see if we need to put in a default value
    if(defaultValue != null)
    {
        optionsInput[keyName] = defaultValue;
    }
}

function remapValues(obj, oldname, newname, table)
{
    if(obj[oldname] != null)
    {
        var value = obj[oldname];
        delete obj[oldname]

        if(!table)
        {
            obj[newname] = value;
        }
        else
        {
            if (value.indexOf(',') < 0)
            {
                obj[newname] = table[value];
            }
            else
            {
                var tokens = value.split(',');
                for(var i=0;i<tokens.length;++i)
                {
                    if(obj[newname] == null)
                    {
                        obj[newname] = table[tokens[i].trim()];
                    }
                    else
                    {
                        obj[newname] = (obj[newname] + ',' + table[tokens[i].trim()]);
                    }
                }
            }
        }
    }
}

function convertNetshValues(obj)
{
    remapValues(obj, 'Rule Name', 'Name');
    remapValues(obj, 'Enabled', 'Enabled', { No: 'False', Yes: 'True' });
    remapValues(obj, 'Profiles', 'Profile', { Any: 'Any', Domain: 'Domain', Public: 'Public', Private: 'Private' });
    remapValues(obj, 'Edge traversal', 'EdgeTraversalPolicy', { No: 'Block', Yes: 'Allow' });
    remapValues(obj, 'Direction', 'Direction', { In: 'Inbound', Out: 'Outbound' });
}
function convertNetSecurityValues(obj)
{
    remapValues(obj, 'Action', 'action', { Allow: 'allow', Block: 'block' });
    remapValues(obj, 'Description', 'description');
    remapValues(obj, 'Direction', 'dir', { Inbound: 'in', Outbound: 'out' });
    remapValues(obj, 'DisplayName', 'displayname');
    remapValues(obj, 'Enabled', 'enabled', { False: 'no', True: 'yes' });

    remapValues(obj, 'Program', 'program');
    remapValues(obj, 'Protocol', 'protocol');
    remapValues(obj, 'Profile', 'profile', { Any: 'any', Domain: 'domain', Private: 'private', Public: 'public', NotApplicable: 'any' });
    remapValues(obj, 'InterfaceType', 'interfacetype', { Any: 'any', Wired: 'lan', Wireless: 'wireless', RemoteAccess: 'ras' });
    remapValues(obj, 'EdgeTraversalPolicy', 'edge', { Allow: 'yes', Block: 'no', DeferToUser: 'deferuser', DeferToApp: 'deferapp' });

    remapValues(obj, 'LocalAddress', 'localip');
    remapValues(obj, 'LocalPort', 'localport');
    remapValues(obj, 'RemoteAddress', 'remoteip');
    remapValues(obj, 'RemotePort', 'remoteport');
}

function convertOptions(options)
{
    verifyValues(options, 'Action', ['NotConfigured', 'Allow', 'Block'], 'Allow');
    verifyValues(options, 'Authentication', ['NotRequired', 'Required', 'NoEncap']);
    verifyValues(options, 'Description');
    verifyValues(options, 'Direction', ['Inbound', 'Outbound']);
    verifyValues(options, 'DisplayName');
    verifyValues(options, 'DynamicTarget', ['Any', 'ProximityApps', 'ProximitySharing', 'WifiDirectPrinting', 'WifiDirectDisplay', 'WifiDirectDevices']);
    verifyValues(options, 'EdgeTraversalPolicy', ['Block', 'Allow', 'DeferToUser', 'DeferToApp']);
    verifyValues(options, 'Enabled', ['True', 'False'], 'True');
    verifyValues(options, 'Encryption', ['NotRequired', 'Required', 'Dynamic']);
    verifyValues(options, 'InterfaceType', ['Any', 'Wired', 'Wireless', 'RemoteAccess]'], 'Any');
    verifyValues(options, 'LocalAddress');
    verifyValues(options, 'LocalOnlyMapping', ['True', 'False']);
    verifyValues(options, 'LocalPort');
    verifyValues(options, 'LocalUser');
    verifyValues(options, 'LooseSourceMapping', ['True', 'False']);
    verifyValues(options, 'Name');
    verifyValues(options, 'OverrideBlockRules', ['True', 'False']);
    verifyValues(options, 'Owner');
    verifyValues(options, 'Package');
    verifyValues(options, 'Platform');
    verifyValues(options, 'PolicyStore');
    verifyValues(options, 'Profile', ['Any', 'Domain', 'Private', 'Public', 'NotApplicable'], 'Any');
    verifyValues(options, 'Program');
    verifyValues(options, 'Protocol');
    verifyValues(options, 'RemoteAddress');
    verifyValues(options, 'RemoteMachine');
    verifyValues(options, 'RemotePort');
    
    return (options);
}

function removeFirewallRule(options)
{
    if (typeof (options) == 'string') { options = { Name: options }; }
    var ret = new promise(function (a, r) { this._res = a; this._rej = r; });
    if (options.program) { options.Program = options.program; delete options.program; }

    var command = 'Remove-NetFirewallRule';
    if (options.Program)
    {
        command = 'Get-NetFirewallApplicationFilter -Program \\"' + options.Program + '\\" | ' + command;
    }
    else
    {
        var key, value;
        for(key in options)
        {
            value = options[key];
            if (value.indexOf(' ') >= 0) { value = '\\"' + options[key] + '\\"'; }
            command += ('-' + key + ' ' + value);
        }
    }

    try
    {
        if (require('os').arch() == 'x64')
        {
            ret.child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['/C "' + command + '"']);
        }
        else
        {
            ret.child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['/C "' + command + '"']);
        }
    }
    catch(f)
    {
        ret._rej(f.toString());
        return (ret);
    }

    ret.child.ret = ret;
    ret.child.stdout.str = ''; ret.child.stdout.on('data', function (c) { this.str += c.toString(); });
    ret.child.stderr.str = ''; ret.child.stderr.on('data', function (c) { this.str += c.toString(); });
    ret.child.on('exit', function ()
    {
        if(this.stderr.str != '')
        {
            this.ret._rej(this.stderr.str.trim());
        }
        else
        {
            this.ret._res();
        }
    });
    return (ret);
}

function addFirewallRule(options)
{
    var command = 'New-NetFirewallRule';
    var val = convertOptions(options);
    var key;

    for (key in val)
    {
        if (val[key].toString().indexOf(' ') >= 0)
        {
            command += (' -' + key + ' \\"' + val[key] + '\\"');
        }
        else
        {
            command += (' -' + key + ' ' + val[key] + '');
        }
    }

    var child;
    try
    {
        if (require('os').arch() == 'x64')
        {
            child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['/C "' + command + '"']);
        }
        else
        {
            child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['/C "' + command + '"']);
        }
    }
    catch(f)
    {
        // Unable to call powershell
        return (true);
    }

    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();

    if(child.stderr.str.trim() != '')
    {
        throw (child.stderr.str.trim());
    }
}

function netsh_parseResults(str)
{
    var ret = [];
    var i, j, k, obj, tokens;
    var blocks = str.split('\r\n\r\n');
    for(i=0;i<blocks.length;++i)
    {
        obj = {};
        tokens = blocks[i].split('\r\n');
        for(j=0;j<tokens.length;++j)
        {
            if ((k = tokens[j].indexOf(':')) > 0)
            {
                obj[tokens[j].substring(0, k).trim()] = tokens[j].substring(k + 1).trim();
            }
        }
        convertNetshValues(obj);
        ret.push(obj);
    }
    return (ret);
}

function netsh_getFirewallRules(options)
{
    if (options.program) { options.Program = options.program; delete options.program; }
    var p = new promise(function (a, r) { this._res = a; this._rej = r; });
    require('events').EventEmitter.call(p, true)
        .createEvent('firewallRule');

    var command = 'netsh advfirewall firewall show rule name=all verbose';
    p.options = options;
    p._results = [];
    p.child = require('child_process').execFile(process.env['windir'] + '\\System32\\cmd.exe', ['/C "' + command + '"']);
    p.child.ret = p;
    p.child.stderr.str = ''; p.child.stderr.on('data', function (c) { this.str += c.toString(); });
    p.child.stdout.str = '';
    p.child.stdout.on('data', function (b)
    {
        var key, ok;
        this.str += b.toString();
        var eX = this.str.lastIndexOf('\r\n\r\n');

        if (eX >= 0)
        {
            var rules = netsh_parseResults(this.str.substring(0, eX));
            for (var i in rules)
            {
                ok = true;
                for (key in this.parent.ret.options)
                {
                    if(this.parent.ret.options[key] == null || this.parent.ret.options[key] != rules[i][key])
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok)
                {
                    if (this.parent.ret.listenerCount('firewallRule') > 0)
                    {
                        this.parent.ret.emit('firewallRule', rules[i]);
                    }
                    else
                    {
                        this.parent.ret._results.push(rules[i]);
                    }
                }
            }

            if (this.str.length - eX > 4)
            {
                this.str = this.str.substring(eX + 4);
            }
        }
    });
    p.child.on('exit', function ()
    {
        if (this.ret.listenerCount('firewallRule') > 0)
        {
            this.ret._res();
        }
        else
        {
            if(this.ret._results.length>0)
            {
                this.ret._res(this.ret._results);
            }
            else
            {
                this.ret._rej('No matches');
            }
        }
    });


    return (p);
}
function netsh_disableFirewallRules(options)
{
    var ret = new promise(function (a, r) { this._res = a; this._rej = r; });
    ret.getp = netsh_getFirewallRules(options);
    ret.getp.ret = ret;
    ret.getp.then(function (rules)
    {
        var child;
        var command;
        for (var i in rules)
        {
            command = 'netsh advfirewall firewall set rule name="' + rules[i].Name + '"' + ' new enable=no';
            child = require('child_process').execFile(process.env['windir'] + '\\System32\\cmd.exe', ['/C "' + command + '"']);
            child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.waitExit();
        }
        this.ret._res();
    }, function (e)
    {
        this.ret._rej(e);
    });
    return (ret);
}
function netsh_enableFirewallRules(options)
{
    var ret = new promise(function (a, r) { this._res = a; this._rej = r; });
    ret.getp = netsh_getFirewallRules(options);
    ret.getp.ret = ret;
    ret.getp.then(function (rules)
    {
        var child;
        var command;
        for (var i in rules)
        {
            command = 'netsh advfirewall firewall set rule name="' + rules[i].Name + '"' + ' new enable=yes';
            child = require('child_process').execFile(process.env['windir'] + '\\System32\\cmd.exe', ['/C "' + command + '"']);
            child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.waitExit();
        }
        this.ret._res();
    }, function (e)
    {
        this.ret._rej(e);
    });
    return (ret);
}
function netsh_addFirewallRule(options)
{
    var val = convertOptions(options);
    convertNetSecurityValues(val);

    if (!val.name)
    {
        if(val.displayname)
        {
            val.name = val.displayname + ' ' + require('uuid/v4')();
            delete val.displayname;
        }
        else
        {
            val.name = require('uuid/v4')();
        }
    }
    stripUnrecognizedKeys(val, ['name', 'dir', 'action', 'program', 'service', 'description', 'enable',
                                'profile', 'localip', 'remoteip', 'localport', 'remoteport', 'protocol',
                                'interfacetype', 'rmtcomputergrp', 'rmtusrgrp', 'edge', 'security']);

    var command = 'netsh advfirewall firewall add rule name="' + val.name + '"'
    delete val.name;

    for (var i in val)
    {
        if (val[i].toString().indexOf(' ') >= 0 || val[i].toString().indexOf(',') >= 0) { val[i] = ('"' + val[i] + '"'); }
        command += (' ' + i + '=' + val[i]);
    }

    var child = require('child_process').execFile(process.env['windir'] + '\\System32\\cmd.exe', ['/C "' + command + '"']);
    child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.waitExit();
}
function netsh_removeFirewallRule(options)
{
    var ret = new promise(function (a, r) { this._res = a; this._rej = r; });
    ret.options = options;
    ret.getp = netsh_getFirewallRules(options);
    ret.getp.ret = ret;
    ret.getp.then(function (rules)
    {
        var child, command, key, value;
        convertNetSecurityValues(this.ret.options);

        for(var i in rules)
        {
            command = 'netsh advfirewall firewall delete rule name="' + rules[i].Name + '"';
            for(key in this.ret.options)
            {
                value = this.ret.options[key].toString();
                if (value.indexOf(' ') >= 0) { value = ('"' + value + '"'); }
                command += (' ' + key + '=' + value);
            }

            child = require('child_process').execFile(process.env['windir'] + '\\System32\\cmd.exe', ['/C "' + command + '"']);
            child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.waitExit();
        }
        this.ret._res();
    }, function (e) { this.ret._rej(e); });
    return(ret);
}


if (netsecurityExists())
{
    module.exports =
        {
            getFirewallRules:       getFirewallRules,
            disableFirewallRules:   disableFirewallRules,
            enableFirewallRules:    enableFirewallRules,
            addFirewallRule:        addFirewallRule,
            removeFirewallRule:     removeFirewallRule,
            netsecurityExists:      netsecurityExists
        };
}
else
{
    module.exports =
        {
            getFirewallRules:       netsh_getFirewallRules,
            disableFirewallRules:   netsh_disableFirewallRules,
            enableFirewallRules:    netsh_enableFirewallRules,
            addFirewallRule:        netsh_addFirewallRule,
            removeFirewallRule:     netsh_removeFirewallRule,
            netsecurityExists:      netsecurityExists
        };
}