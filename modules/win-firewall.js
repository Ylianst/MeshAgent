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
        filter = winreg.QueryKey(winreg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules', rules[i].Name);
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
    if (options.program) { command = 'Get-NetFirewallApplicationFilter -Program \\"' + options.program + '\\" | ' + command; }

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
    var p = getFirewallRules(options).on('firewallRule', function (r) { if (this._count == null) { this._count = 0; } ++this._count; });
    p.options = options;
    p.ret = ret;
    p.then(function (a)
    {
        if(this._count > 0)
        {
            var command = 'Disable-NetFirewallRule';
            if (this.options.program) { command = 'Get-NetFirewallApplicationFilter -Program \\"' + this.options.program + '\\" | ' + command; }

            var child;
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
            child.waitExit();

            if (child.stderr.str.trim() != "")
            {
                this.ret._rej(child.stderr.str.trim());
            }
            else
            {
                this.ret._res();
            }
        }
    }, function (e) { this.ret._rej(e); });
    return (ret);
}

function enableFirewallRules(options)
{
    var ret = new promise(function (a, r) { this._res = a; this._rej = r; });
    var p = getFirewallRules(options).on('firewallRule', function (r) { if (this._count == null) { this._count = 0; } ++this._count; });
    p.options = options;
    p.ret = ret;
    p.then(function (a)
    {
        if (this._count > 0)
        {
            var command = 'Enable-NetFirewallRule';
            if (this.options.program) { command = 'Get-NetFirewallApplicationFilter -Program \\"' + this.options.program + '\\" | ' + command; }

            var child;
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
            child.waitExit();

            if (child.stderr.str.trim() != "")
            {
                this.ret._rej(child.stderr.str.trim());
            }
            else
            {
                this.ret._res();
            }
        }
    }, function (e) { this.ret._rej(e); });
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

function convertOptions(options)
{
    verifyValues(options, 'Action', ['NotConfigured', 'Allow', 'Block']);
    verifyValues(options, 'Authentication', ['NotRequired', 'Required', 'NoEncap']);
    verifyValues(options, 'Description');
    verifyValues(options, 'Direction', ['Inbound', 'Outbound']);
    verifyValues(options, 'DisplayName');
    verifyValues(options, 'DynamicTarget', ['Any', 'ProximityApps', 'ProximitySharing', 'WifiDirectPrinting', 'WifiDirectDisplay', 'WifiDirectDevices'], 'Any');
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

function addFirewallRule(options)
{
    var command = 'New-NetFirewallRule';
    var val = convertOptions(options);
    var key;
    console.log(JSON.stringify(val, null, 1));

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

    console.log(command);
    var child;

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
    child.waitExit();

    if(child.stderr.str.trim() != '')
    {
        throw (child.stderr.str.trim());
    }
}


module.exports =
    {
        getFirewallRules: getFirewallRules,
        disableFirewallRules: disableFirewallRules,
        enableFirewallRules: enableFirewallRules,
        addFirewallRule: addFirewallRule
    };
