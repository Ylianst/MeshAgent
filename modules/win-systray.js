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
var TH32CS_SNAPTHREAD = 0x00000004;
var WM_QUIT = 0x0012;
var WM_CLOSE = 0x0010;

function postMessage(tid)
{
    console.log('Post WM_QUIT to: ' + tid);
    var gm = require('_GenericMarshal');
    var user = gm.CreateNativeProxy('User32.dll');
    user.CreateMethod('PostThreadMessageA');
    user.PostThreadMessageA(tid, WM_QUIT, 0, 0);
}

function createTrayIcon(trayOptions)
{
    var i;
    var retVal = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    var cid;
    var options = { env: { _title: trayOptions.title } };
    retVal.options = options;
    retVal.trayOptions = trayOptions;

    for (i in trayOptions.menuItems)
    {
        options.env['_menu' + i + '_text'] = trayOptions.menuItems[i].text;
    }

    options.env['_tidsig'] = '[DllImport("kernel32.dll")]\r\npublic static extern uint GetCurrentThreadId();';

    for (var c1e in process.env)
    {
        options.env[c1e] = process.env[c1e];
    }
    try
    {
        options.uid = trayOptions.tsid == null ? require('user-sessions').consoleUid() : trayOptions.tsid;
        if (options.uid == (cid = require('user-sessions').getProcessOwnerName(process.pid).tsid))
        {
            delete options.uid;
        }
        else
        {
            if (trayOptions.tsid != null && cid != 0)
            {
                retVal._rej('Insufficient permission to set tray icon as uid: ' + trayOptions.tsid);
                return (retVal);
            }
            retVal.options.type = require('child_process').SpawnTypes.USER;
        }
    }
    catch (ee)
    {
        retVal._rej('Cannot set tray icon when a user is not logged in');
        return (retVal);
    }

    retVal.child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['powershell', '-noprofile', '-nologo', '-command', '-'], retVal.options);
    retVal.child.ret = retVal;
    retVal.child.on('exit', function () { this.ret._res(); });
    retVal.child.descriptorMetadata = 'win-systray';
    retVal.child.stdout.on('data', function (c) 
    {
        var val = c.toString();
        if(val.includes('<<TID:'))
        {
            var t = val.split('<<TID:').pop().split('>>').shift();
            this.parent.ret.tid = parseInt(t);
        }
        else if (val.includes('<<menuitem:'))
        {
            var i = parseInt(val.split('<<menuitem:').pop().split('>>').shift());
            if (this.parent.ret.trayOptions.menuItems[i].func != null)
            {
                this.parent.ret.trayOptions.menuItems[i].func.call(this.parent.ret.trayOptions);
            }
        }
    });
    retVal.child.stderr.on('data', function (c) { });

    retVal.child.stdin.write('$signature_gctid = $env:_tidsig\r\n');
    retVal.child.stdin.write('Add-Type -MemberDefinition $signature_gctid -Name MyName -Namespace MyNameSpace -PassThru\r\n');
    retVal.child.stdin.write('$tid = [MyNameSpace.MyName]::GetCurrentThreadId();\r\n');
    retVal.child.stdin.write('Write-Host "<<TID:$tid>>"\r\n');

    retVal.child.stdin.write('[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")\r\n');
    retVal.child.stdin.write('[System.Reflection.Assembly]::LoadWithPartialName("presentationframework")\r\n');
    retVal.child.stdin.write('[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")\r\n');
    retVal.child.stdin.write('[System.Reflection.Assembly]::LoadWithPartialName("WindowsFormsIntegration")\r\n');
    retVal.child.stdin.write('$icon = [System.Drawing.Icon]::ExtractAssociatedIcon("' + process.execPath + '")\r\n');

    retVal.child.stdin.write('$Main_Tool_Icon = New-Object System.Windows.Forms.NotifyIcon\r\n');
    retVal.child.stdin.write('$Main_Tool_Icon.Text = $env:_title\r\n');
    retVal.child.stdin.write('$Main_Tool_Icon.Icon = $icon\r\n');
    retVal.child.stdin.write('$Main_Tool_Icon.Visible = $true\r\n');

    for(i in trayOptions.menuItems)
    {
        retVal.child.stdin.write('$menuitem_' + i + ' = New-Object System.Windows.Forms.MenuItem\r\n');
        retVal.child.stdin.write('$menuitem_' + i + '.Text = $env:_menu' + i + '_text\r\n');
        retVal.child.stdin.write('$menuitem_' + i + '.Add_Click({ Write-Host "<<menuitem:' + i + '>>" })\r\n');
    }

    retVal.child.stdin.write('$contextmenu = New-Object System.Windows.Forms.ContextMenu\r\n');
    for (i in trayOptions.menuItems)
    {
        retVal.child.stdin.write('$contextmenu.MenuItems.Add($menuitem_' + i + ')\r\n');
    }
    retVal.child.stdin.write('$Main_Tool_Icon.ContextMenu = $contextmenu\r\n');
    retVal.child.stdin.write('$Main_Tool_Icon.add_MouseDown({ $Main_Tool_Icon.ContextMenu = $contextmenu; $Main_Tool_Icon.GetType().GetMethod("ShowContextMenu",[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic).Invoke($Main_Tool_Icon,$null) });\r\n');

    retVal.child.stdin.write('$appContext = New-Object System.Windows.Forms.ApplicationContext\r\n');
    retVal.child.stdin.write('[void][System.Windows.Forms.Application]::Run($appContext)\r\n');
    retVal.child.stdin.write('$Main_Tool_Icon.dispose();\r\n');
    retVal.child.stdin.write('exit\r\n');
    retVal._cleanup = function _cleanup() { postMessage(_cleanup.self.tid); };
    retVal._cleanup.self = retVal;
    process.on('exit', retVal._cleanup);
    retVal.remove = function ()
    {
        this._cleanup();
        process.removeListener('exit', this._cleanup);
    };
    return (retVal);
}

module.exports = { createTrayIcon: process.platform == 'win32' ? createTrayIcon : function () { throw (process.platform + ' not supported') } };
