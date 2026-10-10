/*
Copyright 2018 Intel Corporation

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

var NOTIFY_FOR_THIS_SESSION = 0;
var NOTIFY_FOR_ALL_SESSIONS = 1;
var WM_WTSSESSION_CHANGE = 0x02B1;
var WM_POWERBROADCAST = 0x218;
var PBT_POWERSETTINGCHANGE = 0x8013;
var PBT_APMSUSPEND = 0x4;
var PBT_APMRESUMESUSPEND = 0x7;
var PBT_APMRESUMEAUTOMATIC = 0x12;
var PBT_APMPOWERSTATUSCHANGE = 0xA;
var PROCESS_QUERY_INFORMATION = 0x0400;
var TOKEN_QUERY = 0x0008;
var TokenUser = 1;
var TokenType = 8;
var TokenSessionId = 12;
var ERROR_INSUFFICIENT_BUFFER = 122;
var HEAP_ZERO_MEMORY = 0x00000008;

var WTS_CONSOLE_CONNECT         = (0x1);
var WTS_CONSOLE_DISCONNECT      = (0x2);
var WTS_REMOTE_CONNECT          = (0x3);
var WTS_REMOTE_DISCONNECT       = (0x4);
var WTS_SESSION_LOGON           = (0x5);
var WTS_SESSION_LOGOFF          = (0x6);
var WTS_SESSION_LOCK            = (0x7);
var WTS_SESSION_UNLOCK          = (0x8);
var WTS_SESSION_REMOTE_CONTROL  = (0x9);
var WTS_SESSION_CREATE          = (0xA);
var WTS_SESSION_TERMINATE       = (0xB);

var GUID_ACDC_POWER_SOURCE;
var GUID_BATTERY_PERCENTAGE_REMAINING;
var GUID_CONSOLE_DISPLAY_STATE;

function columnParse(data, delimiter)
{
    var tokens = data.split(delimiter);
    var ret = [];
    for(var i in tokens)
    {
        if (tokens[i].length > 0) { ret.push(tokens[i]); }
    }
    return (ret);
}


function UserSessions()
{
    this._ObjectID = 'user-sessions';
    require('events').EventEmitter.call(this, true)
        .createEvent('changed')
        .createEvent('locked')
        .createEvent('unlocked')
        .addMethod('locked', function () { return (this._locked); })
        .addMethod('unlocked', function () { return (!this._locked); });
    this._locked = false;
    this.on('locked', function () { this._locked = true; });
    this.on('unlocked', function () { this._locked = false; });

    if (process.platform == 'win32')
    {
        this._serviceHooked = false;
        this._marshal = require('_GenericMarshal');
        this._kernel32 = this._marshal.CreateNativeProxy('Kernel32.dll');
        this._kernel32.CreateMethod('GetLastError');
        this._kernel32.CreateMethod('WTSGetActiveConsoleSessionId')
        this._kernel32.CreateMethod('CloseHandle');

        try
        {
            this._wts = this._marshal.CreateNativeProxy('Wtsapi32.dll');
            this._wts.CreateMethod('WTSEnumerateSessionsA');
            this._wts.CreateMethod('WTSQuerySessionInformationW');
            this._wts.CreateMethod('WTSRegisterSessionNotification');
            this._wts.CreateMethod('WTSUnRegisterSessionNotification');
            this._wts.CreateMethod('WTSFreeMemory');
        }
        catch(exc)
        {
        }

        this._advapi = this._marshal.CreateNativeProxy('Advapi32.dll');
        this._advapi.CreateMethod('AllocateAndInitializeSid');
        this._advapi.CreateMethod('CheckTokenMembership');
        this._advapi.CreateMethod('FreeSid');

        this._user32 = this._marshal.CreateNativeProxy('user32.dll');
        this._user32.CreateMethod({ method: 'RegisterPowerSettingNotification', threadDispatch: 1});
        this._user32.CreateMethod('UnregisterPowerSettingNotification');
        this._rpcrt = this._marshal.CreateNativeProxy('Rpcrt4.dll');
        this._rpcrt.CreateMethod('UuidFromStringA');
        this._rpcrt.StringToUUID = function StringToUUID(guid)
        {
            var retVal = StringToUUID.us._marshal.CreateVariable(16);
            if(StringToUUID.us._rpcrt.UuidFromStringA(StringToUUID.us._marshal.CreateVariable(guid), retVal).Val == 0)
            {
                return (retVal);
            }
            else
            {
                throw ('Could not convert string to UUID');
            }
        }
        this._rpcrt.StringToUUID.us = this;

        try
        {
            this._kernel32.CreateMethod('OpenProcess')
            this._advapi.CreateMethod('OpenProcessToken');
            this._advapi.CreateMethod('GetTokenInformation');
            this._advapi.CreateMethod('LookupAccountSidW');
            this._advapi.CreateMethod('OpenThreadToken');
        }
        catch(e)
        {
        }


        GUID_ACDC_POWER_SOURCE = this._rpcrt.StringToUUID('5d3e9a59-e9D5-4b00-a6bd-ff34ff516548');
        GUID_BATTERY_PERCENTAGE_REMAINING = this._rpcrt.StringToUUID('a7ad8041-b45a-4cae-87a3-eecbb468a9e1');
        GUID_CONSOLE_DISPLAY_STATE = this._rpcrt.StringToUUID('6fe69556-704a-47a0-8f24-c28d936fda47');

        this.SessionStates = ['Active', 'Connected', 'ConnectQuery', 'Shadow', 'Disconnected', 'Idle', 'Listening', 'Reset', 'Down', 'Init'];
        this.InfoClass =
            {
                'WTSInitialProgram': 0,
                'WTSApplicationName': 1,
                'WTSWorkingDirectory': 2,
                'WTSOEMId': 3,
                'WTSSessionId': 4,
                'WTSUserName': 5,
                'WTSWinStationName': 6,
                'WTSDomainName': 7,
                'WTSConnectState': 8,
                'WTSClientBuildNumber': 9,
                'WTSClientName': 10,
                'WTSClientDirectory': 11,
                'WTSClientProductId': 12,
                'WTSClientHardwareId': 13,
                'WTSClientAddress': 14,
                'WTSClientDisplay': 15,
                'WTSClientProtocolType': 16,
                'WTSIdleTime': 17,
                'WTSLogonTime': 18,
                'WTSIncomingBytes': 19,
                'WTSOutgoingBytes': 20,
                'WTSIncomingFrames': 21,
                'WTSOutgoingFrames': 22,
                'WTSClientInfo': 23,
                'WTSSessionInfo': 24,
                'WTSSessionInfoEx': 25,
                'WTSConfigInfo': 26,
                'WTSValidationInfo': 27,
                'WTSSessionAddressV4': 28,
                'WTSIsRemoteSession': 29
            };

        this.isRoot = function isRoot()
        {
            var NTAuthority = this._marshal.CreateVariable(6);
            NTAuthority.toBuffer().writeInt8(5, 5);

            var AdministratorsGroup = this._marshal.CreatePointer();
            var admin = false;

            if (this._advapi.AllocateAndInitializeSid(NTAuthority, 2, 32, 544, 0, 0, 0, 0, 0, 0, AdministratorsGroup).Val != 0)
            {
                var member = this._marshal.CreateInteger();
                if (this._advapi.CheckTokenMembership(0, AdministratorsGroup.Deref(), member).Val != 0)
                {
                    if (member.toBuffer().readUInt32LE() != 0) { admin = true; }
                }
                this._advapi.FreeSid(AdministratorsGroup.Deref());
            }
            return admin;
        }
        this.getProcessOwnerName = function getProcessOwnerName(pid)
        {
            var ret = null;
            var name = this._marshal.CreateVariable(1024);
            var domain = this._marshal.CreateVariable(1024);
            var nameDomainLength = this._marshal.CreateVariable(4); nameDomainLength.toBuffer().writeUInt32LE(1024);
            var bufferLength = this._marshal.CreateVariable(4);
            var sidtype = this._marshal.CreateVariable(4);
            var tokenuser = 0;
            var token = this._marshal.CreatePointer();

            var h = this._kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, 1, pid);
            if (h.Val == 0) { throw ('Failed to query process id: ' + pid); }

            if(this._advapi.OpenProcessToken(h, TOKEN_QUERY, token).Val==0)
            {
                this._kernel32.CloseHandle(h);
                throw ('Failed to Query Process Token for pid: ' + pid);
            }

            var tsid = this._marshal.CreateVariable(4);
            this._advapi.GetTokenInformation(token.Deref(), TokenSessionId, tsid, 4, bufferLength);
            this._advapi.GetTokenInformation(token.Deref(), TokenUser, tokenuser, 0, bufferLength);
            tokenuser = this._marshal.CreateVariable(bufferLength.toBuffer().readUInt32LE());

            if (this._advapi.GetTokenInformation(token.Deref(), TokenUser, tokenuser, bufferLength.toBuffer().readUInt32LE(), bufferLength).Val == 0) { throw ('Internal Error'); }
            if(this._advapi.LookupAccountSidW(0, tokenuser.Deref(), name, nameDomainLength, domain, nameDomainLength, sidtype).Val == 0)
            {
                throw ('Lookup Error');
            }
            else
            {
                name._size = 0; domain._size = 0;
                ret = { name: name.Wide2UTF8, domain: domain.Wide2UTF8, tsid: tsid.toBuffer().readUInt32LE() };
            }

            this._kernel32.CloseHandle(token.Deref());
            this._kernel32.CloseHandle(h);
            return (ret);
        };

        this.getRawSessionAttribute = function getRawSessionAttribute(sessionId, attr)
        {
            var buffer = this._marshal.CreatePointer();
            var bytesReturned = this._marshal.CreateVariable(4);

            if (this._wts.WTSQuerySessionInformationW(0, sessionId, attr, buffer, bytesReturned).Val == 0)
            {
                throw ('Error calling WTSQuerySessionInformationW: ' + this._kernel32.GetLastError.Val);
            }

            var b = buffer.Deref().Deref(0, bytesReturned.toBuffer().readUInt32LE()).toBuffer();
            var ret = Buffer.alloc(bytesReturned.toBuffer().readUInt32LE());
            b.copy(ret);
            this._wts.WTSFreeMemory(buffer.Deref());
            return (ret);
        }
        this.getSessionAttribute = function getSessionAttribute(sessionId, attr)
        {
            var buffer = this._marshal.CreatePointer();
            var bytesReturned = this._marshal.CreateVariable(4);

            if (this._wts.WTSQuerySessionInformationW(0, sessionId, attr, buffer, bytesReturned).Val == 0)
            {
                throw ('Error calling WTSQuerySessionInformationW: ' + this._kernel32.GetLastError.Val);
            }

            var retVal = buffer.Deref().Wide2UTF8;

            this._wts.WTSFreeMemory(buffer.Deref());
            return (retVal);
        };
        this.consoleUid = function consoleUid()
        {
            var id = this._kernel32.WTSGetActiveConsoleSessionId().Val;
            if(id==0xFFFFFFFF) {throw('Nobody logged in');}
            return (id);
        };
        this.getUsername = function getUsername(uid)
        {
            return (this.getSessionAttribute(uid, this.InfoClass.WTSUserName));
        }
        this.getDomain = function getDomain(uid)
        {
            return (this.getSessionAttribute(uid, this.InfoClass.WTSDomainName));
        }
        this.Current = function Current(cb)
        {
            var retVal = {};
            var pinfo = this._marshal.CreatePointer();
            var count = this._marshal.CreateVariable(4);
            if (this._wts.WTSEnumerateSessionsA(0, 0, 1, pinfo, count).Val == 0)
            {
                throw ('Error calling WTSEnumerateSessionsA: ' + this._kernel32.GetLastError().Val);
            }

            for (var i = 0; i < count.toBuffer().readUInt32LE() ; ++i)
            {
                var info = pinfo.Deref().Deref(i * (this._marshal.PointerSize == 4 ? 12 : 24), this._marshal.PointerSize == 4 ? 12 : 24);
                var j = { SessionId: info.toBuffer().readUInt32LE() };
                j.StationName = info.Deref(this._marshal.PointerSize == 4 ? 4 : 8, this._marshal.PointerSize).Deref().String;
                j.State = this.SessionStates[info.Deref(this._marshal.PointerSize == 4 ? 8 : 16, 4).toBuffer().readUInt32LE()];
                if (j.State == 'Active') {
                    j.Username = this.getSessionAttribute(j.SessionId, this.InfoClass.WTSUserName);
                    j.Domain = this.getSessionAttribute(j.SessionId, this.InfoClass.WTSDomainName);
                }
                retVal[j.SessionId] = j;
            }

            this._wts.WTSFreeMemory(pinfo.Deref());

            Object.defineProperty(retVal, 'Active', { value: showActiveOnly(retVal) });
            if (cb) { cb(retVal); }
            return (retVal);
        };

        if (!global._noMessagePump)
        {
            // We need to spin up a message pump, and fetch a window handle
            var message_pump = require('win-message-pump');
            this._messagepump = new message_pump({ filter: WM_WTSSESSION_CHANGE }); this._messagepump.parent = this;
            this._messagepump.on('exit', function (code) { this.parent._wts.WTSUnRegisterSessionNotification(this.parent.hwnd); });
            this._messagepump.on('hwnd', function (h)
            {
                this.parent.hwnd = h;

                // We need to yield, and do this in the next event loop pass, becuase we don't want to call 'RegisterPowerSettingNotification'
                // from the messagepump 'thread', because we are actually on the microstack thread, such that the message pump thread, is holding
                // on a semaphore for us to return. If we call now, we may deadlock on Windows 7, becuase it will try to notify immediately
                this.immediate = setImmediate(function (self)
                {
                    // Now that we have a window handle, we can register it to receive Windows Messages
                    if (self.parent._wts) { self.parent._wts.WTSRegisterSessionNotification(self.parent.hwnd, NOTIFY_FOR_ALL_SESSIONS); }
                    self.parent._user32.ACDC_H = self.parent._user32.RegisterPowerSettingNotification(self.parent.hwnd, GUID_ACDC_POWER_SOURCE, 0);
                    self.parent._user32.BATT_H = self.parent._user32.RegisterPowerSettingNotification(self.parent.hwnd, GUID_BATTERY_PERCENTAGE_REMAINING, 0);
                    self.parent._user32.DISP_H = self.parent._user32.RegisterPowerSettingNotification(self.parent.hwnd, GUID_CONSOLE_DISPLAY_STATE, 0);
                    //console.log(self.parent._user32.ACDC_H.Val, self.parent._user32.BATT_H.Val, self.parent._user32.DISP_H.Val);
                }, this);
            });
            this._messagepump.on('message', function (msg)
            {
                switch (msg.message)
                {
                    case WM_WTSSESSION_CHANGE:
                        switch (msg.wparam)
                        {
                            case WTS_SESSION_LOCK:
                                this.parent.enumerateUsers().then(function (users)
                                {
                                    if (users[msg.lparam]) { this.parent.emit('locked', users[msg.lparam]); }
                                });
                                break;
                            case WTS_SESSION_UNLOCK:
                                this.parent.enumerateUsers().then(function (users)
                                {
                                    if (users[msg.lparam]) { this.parent.emit('unlocked', users[msg.lparam]); }
                                });
                                break;
                            case WTS_SESSION_LOGON:
                            case WTS_SESSION_LOGOFF:
                                this.parent.emit('changed');
                                break;
                        }
                        break;
                    case WM_POWERBROADCAST:
                        switch (msg.wparam)
                        {
                            default:
                                console.log('WM_POWERBROADCAST [UNKNOWN wparam]: ' + msg.wparam);
                                break;
                            case PBT_APMSUSPEND:
                                require('power-monitor').emit('sx', 'SLEEP');
                                break;
                            case PBT_APMRESUMEAUTOMATIC:
                                require('power-monitor').emit('sx', 'RESUME_NON_INTERACTIVE');
                                break;
                            case PBT_APMRESUMESUSPEND:
                                require('power-monitor').emit('sx', 'RESUME_INTERACTIVE');
                                break;
                            case PBT_APMPOWERSTATUSCHANGE:
                                require('power-monitor').emit('changed');
                                break;
                            case PBT_POWERSETTINGCHANGE:
                                var lparam = this.parent._marshal.CreatePointer(Buffer.from(msg.lparam_hex, 'hex'));
                                var data = lparam.Deref(20, lparam.Deref(16, 4).toBuffer().readUInt32LE(0)).toBuffer();
                                switch (lparam.Deref(0, 16).toBuffer().toString('hex'))
                                {
                                    case GUID_ACDC_POWER_SOURCE.Deref(0, 16).toBuffer().toString('hex'):
                                        switch (data.readUInt32LE(0))
                                        {
                                            case 0:
                                                require('power-monitor').emit('acdc', 'AC');
                                                break;
                                            case 1:
                                                require('power-monitor').emit('acdc', 'BATTERY');
                                                break;
                                            case 2:
                                                require('power-monitor').emit('acdc', 'HOT');
                                                break;
                                        }
                                        break;
                                    case GUID_BATTERY_PERCENTAGE_REMAINING.Deref(0, 16).toBuffer().toString('hex'):
                                        require('power-monitor').emit('batteryLevel', data.readUInt32LE(0));
                                        break;
                                    case GUID_CONSOLE_DISPLAY_STATE.Deref(0, 16).toBuffer().toString('hex'):
                                        switch (data.readUInt32LE(0))
                                        {
                                            case 0:
                                                require('power-monitor').emit('display', 'OFF');
                                                break;
                                            case 1:
                                                require('power-monitor').emit('display', 'ON');
                                                break;
                                            case 2:
                                                require('power-monitor').emit('display', 'DIMMED');
                                                break;
                                        }
                                        break;
                                }
                                break;
                        }
                        break;
                    default:
                        break;
                }
            });
        }
    }
    else if(process.platform == 'linux' || process.platform == 'freebsd')
    {
        Object.defineProperty(this, 'hasLoginCtl', 
            {
                get: function ()
                {
                    if (this._hasLoginCtl != null) { return (this._hasLoginCtl); }
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = '';
                    child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    child.stdin.write("whereis loginctl | awk '{ print $2 }'\nexit\n");
                    child.waitExit();
                    this._hasLoginCtl = child.stdout.str.trim() != "";
                    return (this._hasLoginCtl);
                }
            });
        Object.defineProperty(this, "gdmUid", {
            get: function ()
            {
                var ret = null;
                var min = this.minUid();
                var child;
                if (process.platform == 'linux' || process.platform == 'freebsd')
                {
                    if(this.hasLoginCtl)
                    {
                        var pwd = null;
                        var uids = [];
                        child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });

                        child.stdin.write("getent passwd | tr '\\n' '`' ");
                        child.stdin.write(" | awk '{ ");
                        child.stdin.write('         first="";');
                        child.stdin.write('         printf("{");');
                        child.stdin.write('         n=split($0, lines, "`");');
                        child.stdin.write('         for(i=1;i<n;++i)');
                        child.stdin.write('         {');
                        child.stdin.write('             split(lines[i],A,":");');
                        child.stdin.write('             printf "%s\\"%s\\": {\\"user\\":\\"%s\\", \\"desc\\":\\"%s\\"}", first, A[3], A[1], A[5];');
                        child.stdin.write('             first=",";');
                        child.stdin.write("         }");
                        child.stdin.write('         printf("}");');
                        child.stdin.write("}' ");

                        child.stdin.write('\nexit\n');
                        child.waitExit();
                        try
                        {
                            pwd = JSON.parse(child.stdout.str);
                            console.info1(JSON.stringify(pwd, null, 1));
                        }
                        catch(z)
                        {
                        }

                        child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                        child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                        child.stdin.write("loginctl list-sessions | tr '\\n' '`' | awk '{");
                        child.stdin.write('printf "[";');
                        child.stdin.write('del="";');
                        child.stdin.write('n=split($0, lines, "`");');
                        child.stdin.write('for(i=2;i<n;++i)');
                        child.stdin.write('{');
                        child.stdin.write('   split(lines[i], tok, " ");');
                        child.stdin.write('   if(tok[4]=="") { continue; }');
                        child.stdin.write('   printf "%s{\\"Username\\": \\"%s\\", \\"SessionId\\": \\"%s\\", \\"State\\": \\"Online\\", \\"uid\\": \\"%s\\"}", del, tok[3], tok[1], tok[2];');
                        child.stdin.write('   del=",";');
                        child.stdin.write('}');
                        child.stdin.write('printf "]";');
                        child.stdin.write("}'\nexit\n");
                        child.waitExit();

                        try
                        {
                            var info1 = JSON.parse(child.stdout.str);
                            var i;
                            for (i = 0; i < info1.length; ++i) { uids.push(info1[i].uid); }
                            console.info1(JSON.stringify(uids));
                        }
                        catch(z)
                        {
                        }

                        if (pwd != null && uids.length > 0)
                        {
                            while(uids.length>0)
                            {
                                var tst = uids.pop();
                                if (pwd[tst].desc.toLowerCase().indexOf('display manager') >= 0 || pwd[tst].user == 'gdm' || pwd[tst].user == 'lightdm' || pwd[tst].user == 'sddm' || pwd[tst].user == '_ldm')
                                {
                                    if (parseInt(tst) < min)
                                    {
                                        return (parseInt(tst));
                                    }
                                }
                            }
                        }
                    }
                }

                child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write('getent passwd | grep "Gnome Display Manager" | ' + "tr '\\n' '`' | awk -F: '{ print $3 }'\nexit\n");
                child.waitExit();
                if (child.stdout.str.trim() != '' && (ret = parseInt(child.stdout.str.trim())) < min) { return (parseInt(child.stdout.str.trim())); }

                child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (c) { console.log(c.toString()); });
                child.stdin.write('getent passwd | grep gdm | ' + "tr '\\n' '`' | awk -F'`' '" + '{ for(i=1;i<NF;++i) { split($i, f, ":"); if(f[3]+0<' + min + '+0) { print f[3]; break; } } }' + "'\nexit\n");
                child.waitExit();
                if (child.stdout.str.trim() != '' && (ret = parseInt(child.stdout.str.trim())) < min) { return (parseInt(child.stdout.str.trim())); }

                child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write('getent passwd | grep "Light Display Manager" | ' + "tr '\\n' '`' | awk -F: '{ print $3 }'\nexit\n");
                child.waitExit();
                if (child.stdout.str.trim() != '' && (ret = parseInt(child.stdout.str.trim())) < min) { return (parseInt(child.stdout.str.trim())); }

                return (0);
            }
        });
        this.getUid = function getUid(username)
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("getent passwd \"" + username + "\" | awk -F: '{print $3}'\nexit\n");
            child.waitExit();

            var ret = parseInt(child.stdout.str);
            if (ret >= 0) { return (ret); }
            throw ('username: ' + username + ' NOT FOUND');
        };
        
        function linux_sh(cmd)
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write(cmd + '\nexit\n');
            child.waitExit();
            return (child.stdout.str);
        }

        // Every logind session as { Id, User, Name, Seat, TTY, Class, State, Active }. Read from
        // show-session properties because the list-sessions columns moved between systemd releases,
        // one call per session because show-session stops at the first id that vanished meanwhile.
        function linux_logindSessions()
        {
            var ret = [], ids = [], i;
            var lines = linux_sh('loginctl list-sessions --no-legend 2>/dev/null').split('\n');
            for (i = 0; i < lines.length; ++i)
            {
                var id = lines[i].trim().split(' ')[0];
                if (id != '') { ids.push(id); }
            }
            if (ids.length == 0) { return (ret); }
            var cmd = '';
            for (i = 0; i < ids.length; ++i)
            {
                cmd += 'loginctl show-session -p Id -p User -p Name -p Seat -p TTY -p Class -p State -p Active "' + ids[i] + '" 2>/dev/null; echo; ';
            }
            var blocks = linux_sh(cmd).split('\n\n');
            for (i = 0; i < blocks.length; ++i)
            {
                var s = { Id: '', User: '', Name: '', Seat: '', TTY: '', Class: '', State: '', Active: '' };
                var kv = blocks[i].split('\n');
                for (var k = 0; k < kv.length; ++k)
                {
                    var eq = kv[k].indexOf('=');
                    if (eq > 0) { s[kv[k].substring(0, eq)] = kv[k].substring(eq + 1).trim(); }
                }
                if (s.Id != '') { ret.push(s); }
            }
            return (ret);
        }
        // logind reports every seatless session (SSH, systemd 256+ "manager") as active, so only a
        // seat-attached session can be the console.
        function linux_isConsoleSession(s) { return (s.Seat != ''); }
        // Greeter, lock screen and service-manager sessions are not someone logged in
        function linux_isLoginSession(s)
        {
            return (s.Class != 'greeter' && s.Class != 'lock-screen' && s.Class.indexOf('manager') != 0 && s.Class.indexOf('background') != 0);
        }
        // What a 'changed' consumer can observe: the login sessions and which one holds the console.
        // Greeter, manager and background sessions, idle/lock hints and device lists also rewrite
        // logind state but are left out on purpose.
        function linux_sessionSignature(sessions)
        {
            var parts = [];
            for (var i = 0; i < sessions.length; ++i)
            {
                var s = sessions[i];
                if (!linux_isLoginSession(s)) { continue; }
                parts.push(s.Id + ':' + s.User + ':' + s.Seat + ':' + s.TTY + ':' + s.Class + ':' + (linux_isConsoleSession(s) ? s.Active : ''));
            }
            parts.sort();
            return (parts.join('|'));
        }

        function linux_Onchange()
        {
            if (!(require('user-sessions').hasLoginCtl && require('fs').existsSync('/run/systemd/sessions')))
            {
                // without logind state there is nothing to compare against, so emit like before
                require('user-sessions').emit('changed');
                return;
            }
            // a pending check (debounce or retry) will see whatever state this event leads to
            if (linux_Onchange_checkLoginCtl.timer != null) { return; }
            linux_Onchange_checkLoginCtl.timer = setTimeout(linux_Onchange_run, 1000);
        }
        function linux_Onchange_run()
        {
            linux_Onchange_checkLoginCtl.timer = null;
            linux_Onchange_checkLoginCtl.counter = 0;
            linux_Onchange_checkLoginCtl();
        }
        function linux_Onchange_checkLoginCtl()
        {
            var state = linux_Onchange_checkLoginCtl;
            state.timer = null;
            var sessions;
            try
            {
                sessions = linux_logindSessions();
            }
            catch (e)
            {
                // Timers also fire inside another caller's waitExit(), and only one can be in
                // progress. Look again once it has returned; the last snapshot stays the baseline.
                if (e.toString().indexOf('already in progress') >= 0) { state.timer = setTimeout(linux_Onchange_checkLoginCtl, 500); }
                else { console.info1('loginctl failed: ' + e); }
                return;
            }
            var sig = linux_sessionSignature(sessions);
            var consoleActive = false, loginActive = false;
            for (var i = 0; i < sessions.length; ++i)
            {
                if (!linux_isConsoleSession(sessions[i]) || sessions[i].Active != 'yes') { continue; }
                consoleActive = true;
                if (linux_isLoginSession(sessions[i])) { loginActive = true; }
            }
            if (sig == state.lastSig)
            {
                console.info1("sessions unchanged, not emitting 'changed'");
                state.lastConsoleActive = consoleActive;
                state.counter = 0;
                return;
            }
            if (!loginActive && (consoleActive || state.lastConsoleActive) && state.counter <= 10)
            {
                // The console is between users (logout, user switch, login still starting). Wait for
                // the next user to activate so one event carries the final state, then give up and
                // report the greeter.
                console.info1('No active console login, try again');
                state.counter++;
                state.timer = setTimeout(linux_Onchange_checkLoginCtl, 500);
                return;
            }
            console.info1("emitting 'changed'" + (loginActive ? '' : ' (no active console login)'));
            state.lastSig = sig;
            state.lastConsoleActive = consoleActive;
            state.counter = 0;
            require('user-sessions').emit('changed');
        }
        linux_Onchange_checkLoginCtl.timer = null;
        linux_Onchange_checkLoginCtl.counter = 0;
        linux_Onchange_checkLoginCtl.lastSig = null;
        linux_Onchange_checkLoginCtl.lastConsoleActive = false;
        function linux_baseline()
        {
            var state = linux_Onchange_checkLoginCtl;
            if (state.timer != null || state.lastSig != null) { return; }
            var base;
            try
            {
                base = linux_logindSessions();
            }
            catch (e)
            {
                // The first consumer usually enumerates synchronously right after loading this
                // module, so the next tick lands inside its waitExit(). Try again after it.
                if (e.toString().indexOf('already in progress') >= 0) { setTimeout(linux_baseline, 500); }
                return;
            }
            state.lastSig = linux_sessionSignature(base);
            for (var b = 0; b < base.length; ++b)
            {
                if (linux_isConsoleSession(base[b]) && base[b].Active == 'yes') { state.lastConsoleActive = true; }
            }
        }


        this.Current = function Current(cb)
        {
            var ret = null;
            var child = null;

            if (process.platform == 'freebsd' || !this.hasLoginCtl)
            {
                child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write("who | tr '\\n' '`' | awk -F'`' '" + '{ printf "{"; for(a=1;a<NF;++a) { n=split($a, tok, " "); printf "%s\\"%s\\": \\"%s\\"", (a>1?",":""), tok[2], tok[1];  } printf "}";  }\'\nexit\n');
                child.waitExit();
            }
            else
            {
                var min = this.minUid();
                var sessions = linux_logindSessions();
                var i, firstActive = -1, consoleSeen = false;
                ret = [];
                for (i = 0; i < sessions.length; ++i)
                {
                    var s = sessions[i];
                    if (parseInt(s.User) < min || !linux_isLoginSession(s)) { continue; }
                    var isConsole = linux_isConsoleSession(s);
                    if (isConsole) { consoleSeen = true; }
                    if (firstActive < 0 && s.State == 'active') { firstActive = ret.length; }
                    ret.push({ Username: s.Name, Domain: '', SessionId: s.Id, State: (isConsole && s.Active == 'yes') ? 'Active' : 'Online', uid: s.User, StationName: (!isConsole && s.TTY != '') ? s.TTY : 'Console' });
                }
                // Headless: no seat, so keep showing the first session logind calls active (an SSH
                // login) the way this always did, rather than nobody.
                if (!consoleSeen && firstActive >= 0) { ret[firstActive].State = 'Active'; }
            }
            
            if (ret == null)
            {
                try
                {
                    ret = JSON.parse(child.stdout.str.trim());
                    for (var key in ret)
                    {
                        ret[key] = { Username: ret[key], SessionId: key, State: 'Active', uid: this.getUid(ret[key]) };
                        if (key.startsWith('pts/')) { delete ret[key]; }
                    }
                }
                catch (e)
                {
                }
            }

            var vids = this.virtualUids();
            for (i in vids)
            {
                var u = this.getUsername(vids[i].uid);
                ret.push({ Username: u, SessionId: vids[i].pid, State: 'Connected', uid: vids[i].uid, StationName: 'Xvfb-' + vids[i].uid });
            }

            Object.defineProperty(ret, 'Active', { value: showActiveOnly(ret) });

            if (cb)
            {
                cb.call(this, ret);
            }
        }

        if (process.platform == 'linux')
        {
            if (require('fs').watch)
            {
                // systemd 258+ no longer writes utmp (Ubuntu 26.04 has no /var/run/utmp at all), so
                // watch logind's per-session state files; utmp still covers systems without logind.
                var sessionsDir = '/run/systemd/sessions';
                var watchPaths = [sessionsDir, '/var/run/utmp'];
                this._linuxWatchers = [];
                for (var wp = 0; wp < watchPaths.length; ++wp)
                {
                    if (!require('fs').existsSync(watchPaths[wp])) { continue; }
                    var watcher = require('fs').watch(watchPaths[wp]);
                    watcher.on('change', linux_Onchange);
                    this._linuxWatchers.push(watcher);
                }
                if (require('fs').existsSync(sessionsDir))
                {
                    // Baseline on the next tick so loading the module stays cheap. Skipped when an
                    // event already arrived, so that check emits rather than comparing against a
                    // snapshot taken after the change.
                    setImmediate(linux_baseline);
                }
                else if (require('fs').existsSync('/run/systemd'))
                {
                    // At boot the agent can be up before logind has created its state directory
                    var self = this;
                    var parent = require('fs').watch('/run/systemd');
                    parent.on('change', function ()
                    {
                        if (!require('fs').existsSync(sessionsDir)) { return; }
                        parent.close();
                        var watcher = require('fs').watch(sessionsDir);
                        watcher.on('change', linux_Onchange);
                        self._linuxWatchers.push(watcher);
                        linux_Onchange();
                    });
                    this._linuxWatchers.push(parent);
                }
            }
            
            this.getUidConfig = function getUidConfig() {
                var ret = {};
                var cfg = require('fs').readFileSync('/etc/login.defs').toString().split('\n');
                var tokens;
                for (var i in cfg) {
                    tokens = columnParse(cfg[i], '\t'); //console.log(tokens);
                    if (tokens[0] == 'UID_MIN') { ret.MIN = parseInt(tokens[1]); }
                    if (tokens[0] == 'UID_MAX') { ret.MAX = parseInt(tokens[1]); }
                    if (ret.MIN != null && ret.MAX != null) { break; }
                }
                return (ret);
            };
        }

        this.minUid =  function minUid()
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("cat /etc/login.defs | grep UID_ | awk '{ if($1==\"UID_MIN\") { print $2; } }'\nexit\n");
            child.waitExit();
            return (parseInt(child.stdout.str.trim()) >= 0 ? parseInt(child.stdout.str.trim()) : 500);
        }
        this._users = function _users()
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("getent passwd | awk -F: '{ if($3>=0) { printf \"%s:%s\\n\", $1, $3; } }'\nexit\n");
            child.waitExit();

            var lines = child.stdout.str.split('\n');
            var ret = {}, tokens;
            for (var ln in lines)
            {
                tokens = lines[ln].split(':');
                if (tokens[0]) { ret[tokens[0]] = tokens[1]; }           
            }
            return (ret);
        }
        this._uids = function _uids() {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("getent passwd | awk -F: '{ if($3>=0) { printf \"%s:%s\\n\", $1, $3; } }'\nexit\n");
            child.waitExit();

            var lines = child.stdout.str.split('\n');
            var ret = {}, tokens;
            for (var ln in lines) {
                tokens = lines[ln].split(':');
                if (tokens[0]) { ret[tokens[1]] = tokens[0]; }
            }
            return (ret);
        }
        this.loginUids = function loginUids()
        {
            var min = this.minUid();
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write('getent passwd | awk -F: \'{ if($3 >= ' + min + ') { a=split($7,b,"/"); if(b[a]!="nologin") { print $3; } }}\' | tr "\\n" "\\," | awk \'{ printf "[%s]", $0; }\'\nexit\n');
            child.waitExit();
            return (JSON.parse(child.stdout.str.trim().replace(',]',']')));
        }
        this.activeUids = function activeUids()
        {
            return (this.consoleUid({ active: true }));
        };
        this.virtualUids = function virtualUids()
        {
            var active = this.activeUids();

            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("ps -e -o uid -o pid -o cmd | grep Xvfb | tr '\\n' '`' | awk '{");
            child.stdin.write('printf "[";');
            child.stdin.write('del="";');
            child.stdin.write('n=split($0, lines, "`");');
            child.stdin.write('for(i=1;i<n;++i)');
            child.stdin.write('{');
            child.stdin.write('   split(lines[i], tok, " ");');
            child.stdin.write('   if((tok[3])=="Xvfb")');
            child.stdin.write('   {');
            child.stdin.write('        match(lines[i], /:[0-9]+/);');
            child.stdin.write('        _display = substr(lines[i],RSTART,RLENGTH);');
            child.stdin.write('        match(lines[i], /-auth .+/);');
            child.stdin.write('        _auth = substr(lines[i],RSTART+6,RLENGTH-6);');
            child.stdin.write('        printf("%s{\\"uid\\": %s, \\"display\\": \\"%s\\", \\"xauth\\": \\"%s\\", \\"pid\\": %s}", del, tok[1], _display, _auth, tok[2]);');
            child.stdin.write('        del=",";');
            child.stdin.write('   }');
            child.stdin.write('}');
            child.stdin.write('printf "]";');
            child.stdin.write("}'\nexit\n");
            child.waitExit();

            try
            {
                return(JSON.parse(child.stdout.str));
            }
            catch (x)
            {
                return ([]);
            }
        };
        this.consoleUid = function consoleUid(options)
        {
            var greeter = null;
            var child = null;

            if (process.platform == 'freebsd' || !this.hasLoginCtl)
            {
                child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write("who | tr '\\n' '`' | awk -F'`' '{");
                child.stdin.write("  for(i=1;i<NF;++i) ");
                child.stdin.write("  { ");
                child.stdin.write('     split($i,tok," "); x=split(tok[2],itm,"pts"); ');
                if (process.platform != 'freebsd')
                {
                    child.stdin.write(' if(x==1) ');
                }
                child.stdin.write('     { ');
                child.stdin.write('        print tok[1]; ');
                child.stdin.write('        break;  ');
                child.stdin.write('     }');
                child.stdin.write('   }');
                child.stdin.write("}'\nexit\n");
                child.waitExit();

                if (child.stderr.str != '') { return (0); }
                if (child.stdout.str.trim() != '')
                {
                    try
                    {
                        return (this.getUid(child.stdout.str.trim()));
                    }
                    catch (e)
                    {
                    }
                }
            }
            else
            {
                var min = this.minUid();
                var sessions = linux_logindSessions();
                var i, uid;
                if (options && options.active == true)
                {
                    var active = [];
                    for (i = 0; i < sessions.length; ++i)
                    {
                        uid = parseInt(sessions[i].User);
                        if (uid >= min && linux_isLoginSession(sessions[i]) && sessions[i].State == 'active') { active.push(uid); }
                    }
                    return (active);
                }
                for (i = 0; i < sessions.length; ++i)
                {
                    if (!linux_isConsoleSession(sessions[i]) || sessions[i].Active != 'yes') { continue; }
                    uid = parseInt(sessions[i].User);
                    if (uid >= min && linux_isLoginSession(sessions[i])) { return (uid); }
                    if (sessions[i].Class == 'greeter') { greeter = uid; }
                }
            }

            // Before we say nobody is logged on, let's check to see if there is a GDM session.
            // A greeter holding the seat names the display manager account directly.
            var gdm = (greeter != null) ? greeter : this.gdmUid;
            var info = require('monitor-info').getXInfo(gdm);
            if (info == null || !info.xauthority || !info.display)
            {
                if (gdm == 0)
                {
                    // Before we give up, lets see if there is an X session somewhere, probably from VNC
                    child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                    child.stdin.write("loginctl list-sessions | tr '\\n' '`' | awk '{");
                    child.stdin.write('printf "[";');
                    child.stdin.write('del="";');
                    child.stdin.write('n=split($0, lines, "`");');
                    child.stdin.write('for(i=1;i<n;++i)');
                    child.stdin.write('{');
                    child.stdin.write('   split(lines[i], tok, " ");');
                    child.stdin.write('   if((tok[2]+0)>=' + min + ')');
                    child.stdin.write('   {');
                    child.stdin.write('      printf "%s{\\"uid\\": \\"%s\\", \\"sid\\": \\"%s\\"}", del, tok[2], tok[1];');
                    child.stdin.write('      del=",";');
                    child.stdin.write('   }');
                    child.stdin.write('}');
                    child.stdin.write('printf "]";');
                    child.stdin.write("}'\nexit\n");
                    child.waitExit();
                    var info1 = JSON.parse(child.stdout.str);
                    var uids = [];
                    var i;
                    for (i = 0; i < info1.length; ++i) { uids.push(info1[i].uid); }
                    console.info1('UIDS => ' + JSON.stringify(uids));

                    while(uids.length>0)
                    {
                        var id = uids.pop();
                        info = require('monitor-info').getXInfo(id);
                        if(info!=null && info.xauthority != null && info.display != null)
                        {
                            return (parseInt(id));
                        }
                    }
                }

                throw ('nobody logged into console');
            }
            else
            {
                return (gdm);
            }
        }
        
        this.getHomeFolder = function getHomeFolder(id)
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("getent passwd " + id + " | awk -F: '{print $6}'\nexit\n");
            child.waitExit();
            return (child.stdout.str.trim());
        }

        this.getUsername = function getUsername(uid)
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("getent passwd " + uid + " | awk -F: '{print $1}'\nexit\n");
            child.waitExit();
            if (child.stdout.str.length > 0) { return (child.stdout.str.trim()); }
            throw ('uid: ' + uid + ' NOT FOUND');
        };
        this.getGroupname = function getGroupname(gid)
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("getent group " + gid + " | awk -F: '{print $1}'\nexit\n");
            child.waitExit();
            if (child.stdout.str.length > 0) { return (child.stdout.str.trim()); }
            throw ('gid: ' + gid + ' NOT FOUND');
        };
        this.whoami = function whoami()
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("whoami\nexit\n");
            child.waitExit();
            return (child.stdout.str.trim());
        };
        this.getPids = function getPids(options)
        {
            var grep = '';
            switch(typeof(options))
            {
                default:
                    throw ('Invalid type specified: ' + typeof (options));
                    break;
                case 'number':
                    grep = ' | grep "' + this.getUsername(options) + '"';
                    break;
                case 'string':
                    grep = ' | grep "' + options + '"';
                    break;
                case 'object':
                    if (options.username) { grep = ' | grep "' + options.username + '"'; }
                    else if (options.uid != null) { grep = ' | grep "' + this.getUsername(options.uid) + '"'; }
                    if (options.grep)
                    {
                        grep += (' | grep "' + options.grep + '"');
                    }
                    break;
            }

            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function(c){this.str += c.toString();});
            child.stderr.str = ''; child.stderr.on('data', function(c){this.str += c.toString();});
            child.stdin.write('ps -e -o pid -o user -o cmd ' + grep + ' |' + " tr '\n' '`' | awk -F'`' '{ " + 'printf "["; for(i=1;i<NF;++i) { split($i, tok, " "); printf "%s%s",(i!=1?",":""), tok[1];  } printf "]"; }\'\nexit\n');
            child.waitExit();

            try
            {
                return (JSON.parse(child.stdout.str.trim()));
            }
            catch(ee)
            {
                return([]);
            }
        };
        this.findEnvEntry = function findEnvEntry(options)
        {
            var broke = false;
            var ret = {};
            var pids = this.getPids(options);

            var vals;
            var j;
            for(var i in pids)
            {
                broke = false;
                ret = {};
                vals = this.getEnvFromPid(pids[i]);

                for (j in options.values)
                {
                    if(vals[options.values[j]])
                    {
                        ret[options.values[j]] = vals[options.values[j]];
                    }
                    else
                    {
                        broke = true;
                        break;
                    }
                }
            }
            if (broke)
            {
                return ({});
            }
            else
            {
                return (ret);
            }
        };
        this.getEnvFromPid = function getEnvFromPid(pid)
        {
            var ret = {};
            if (process.platform == 'linux')
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });

                child.stdin.write("cat /proc/" + pid + "/environ | tr '\\0' '\\t' |" + ' awk -F"\t" \'{ printf "{"; for(i=1;i<NF;++i) { if(i>1) {printf ",";} x=split($i, tok, "="); printf "\\"%s\\": \\"%s\\"", tok[1], substr($i, 2+length(tok[1])); } printf "}"; }\'');
                child.stdin.write('\nexit\n');
                child.waitExit();

                try
                {
                    return (JSON.parse(child.stdout.str.trim()));
                }
                catch(ee)
                {
                    return ({});
                }
            }
            else if (process.platform == 'freebsd')
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write("procstat -e " + pid + " | grep " + pid + " | awk '{ $1=\"\"; $2=\"\"; print $0 }' | tr \"\\ \" \"\\n\"\nexit\n"); 
                child.waitExit();
		
                var env;
                var tokens = child.stdout.str.trim().split('\n');
                for(var i in tokens)
                {
                    env = tokens[i].split('=');
                    ret[env[0]] = env[1];
                }
            }
            return (ret);
        };
        this.findEnv = function findEnv(uid, env)
        {
            var uname = this.getUsername(uid);
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("ps " + (process.platform == 'freebsd' ? "-ax ":"") + "-e -o pid -o user | grep " + uname + " | awk '{ print $1 }'\nexit\n");
            child.waitExit();

            var lines = child.stdout.str.split('\n');
            for (var n in lines)
            {
                var ln = lines[n].trim();
                if (ln.length > 0)
                {
                    var e = this.getEnvFromPid(ln);
                    if (e[env])
                    {
                        return (e[env]);
                    }
                }
            }
            return (null);
        };
    }
    else if(process.platform == 'darwin')
    {
        this.getUid = function getUid(username)
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("id " + username + " | awk '{ split($1, token, \"=\"); split(token[2], uid, \"(\"); print uid[1]; }'\nexit\n");
            child.waitExit();
            var ret = parseInt(child.stdout.str.trim());
            child = null;
            return (ret);
        };
        this.getGroupID = function getGroupID(uid)
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("id " + uid + " | awk '{ split($2, gid, \"=\"); if(gid[1]==\"gid\") { split(gid[2], gidnum, \"(\"); print gidnum[1];  } }'\nexit\n");
            child.waitExit();
            return (parseInt(child.stdout.str.trim()));
        }
        this.getUsername = function getUsername(uid)
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stderr.str = '';
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("dscl . list /Users UniqueID | grep " + uid + " | awk '{ if($2==" + uid + "){ print $1 }}'\nexit\n");
            child.waitExit();
            var ret = child.stdout.str.trim();
            child = null;
            if(ret != '')
            {
                return (ret);
            }
            else
            {
                // The local directory node (".") only lists local accounts, so network
                // accounts (LDAP / Open Directory / Active Directory) are not found above.
                // Fall back to "id -un", which resolves both local and network users.
                child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stderr.str = '';
                child.stdout.str = '';
                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write("id -un " + uid + " 2>/dev/null\nexit\n");
                child.waitExit();
                var netret = child.stdout.str.trim();
                child = null;
                if (netret != '')
                {
                    return (netret);
                }
                throw ('uid: ' + uid + ' not found');
            }
        };
        this.getGroupname = function getGroupname(gid)
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stderr.str = '';
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("dscl . list /Groups PrimaryGroupID | grep " + gid + " | awk '{ if($2==" + gid + "){ print $1 }}'\nexit\n");
            child.waitExit();
            if(child.stdout.str.trim() != '')
            {
                return (child.stdout.str.trim());
            }
            else
            {
                throw ('gid: ' + gid + ' not found');
            }
        };
        this.consoleUid = function consoleUid()
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("who | tr '\n' '\.' | awk '{ print $1 }'\nexit\n");
            child.waitExit();

            var ret = child.stdout.str.trim();
            child = null;
            if (ret != '')
            {
                return (this.getUid(ret));
            }
            throw ('nobody logged into console');     
        }
        this.getHomeFolder = function getHomeFolder(user)
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("dscl . -read /Users/" + user + " | grep NFSHomeDirectory | awk -F: '{ print $2 }'\nexit\n");
            child.waitExit();
            if (child.stdout.str.trim() != '')
            {
                return (child.stdout.str.trim());
            }
            else
            {
                throw ('user: ' + user + ' not found');
            }
        };
        this._users = function ()
        {
            var child = require('child_process').execFile('/usr/bin/dscl', ['dscl', '.', 'list', '/Users', 'UniqueID']);
            child.stdout.str = '';
            child.stderr.str = '';
            child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write('exit\n');
            child.waitExit();


            var lines = child.stdout.str.split('\n');
            var tokens, i;
            var users = {};

            for (i = 0; i < lines.length; ++i) {
                tokens = lines[i].split(' ');
                if (tokens[0]) { users[tokens[0]] = tokens[tokens.length - 1]; }
            }

            return (users);
        }
        this._uids = function () {
            var child = require('child_process').execFile('/usr/bin/dscl', ['dscl', '.', 'list', '/Users', 'UniqueID']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write('exit\n');
            child.waitExit();

            var lines = child.stdout.str.split('\n');
            var tokens, i;
            var users = {};

            for (i = 0; i < lines.length; ++i) {
                tokens = lines[i].split(' ');
                if (tokens[0]) { users[tokens[tokens.length - 1]] = tokens[0]; }
            }

            return (users);
        }
        this._idTable = function()
        {
            var table = {};
            var child = require('child_process').execFile('/usr/bin/id', ['id']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.waitExit();

            var lines = child.stdout.str.split('\n')[0].split(' ');
            child = null;
            for (var i = 0; i < lines.length; ++i) {
                var types = lines[i].split('=');
                var tokens = types[1].split(',');
                table[types[0]] = {};

                for (var j in tokens) {
                    var idarr = tokens[j].split('(');
                    var id = idarr[0];
                    var name = idarr[1].substring(0, idarr[1].length - 1).trim();
                    table[types[0]][name] = id;
                    table[types[0]][id] = name;
                }
            }
            return (table);
        }
        this.Current = function (cb)
        {
            var users = {};
            var table = this._idTable();
            var child = require('child_process').execFile('/usr/bin/last', ['last']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.waitExit();

            var lines = child.stdout.str.split('\n');
            for (var i = 0; i < lines.length && lines[i].length > 0; ++i)
            {
                if (!users[lines[i].split(' ')[0]])
                {
                    try
                    {
                        users[lines[i].split(' ')[0]] = { Username: lines[i].split(' ')[0], State: lines[i].split('still logged in').length > 1 ? 'Active' : 'Inactive', uid: table.uid[lines[i].split(' ')[0]] };
                    }
                    catch(e)
                    {}
                }
                else
                {
                    if(users[lines[i].split(' ')[0]].State != 'Active' && lines[i].split('still logged in').length > 1)
                    {
                        users[lines[i].split(' ')[0]].State = 'Active';
                    }
                }
            }

            Object.defineProperty(users, 'Active', { value: showActiveOnly(users) });
            if (cb) { cb.call(this, users); }
        }
    }

    if(process.platform != 'win32') // Linux, MacOS, FreeBSD
    {
        this.tty = function tty()
        {
            var child = require('child_process').execFile('/bin/sh', ['sh'], { type: require('child_process').SpawnTypes.TERM });
            child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("tty | awk -F/ '{ printf \"\\x1e%s\\x1e\",$2; }'\nexit\n");
            child.stdin.write("tty\nexit\n");
            child.waitExit();

            var val = child.stdout.str.split('\x1e');
            return (val.length > 1 ? val[1] : 'root');
        }
        this.Self = function Self()
        {
            var child = require('child_process').execFile('/usr/bin/id', ['id', '-u']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.waitExit();
            var ret = parseInt(child.stdout.str);
            child = null;
            return (ret);
        }
        this.isRoot = function isRoot()
        {
            return (this.Self() == 0);
        }
    }

    this.enumerateUsers = function enumerateUsers()
    {
        var promise = require('promise');
        var p = new promise(function (res, rej)
        {
            this.__resolver = res;
            this.__rejector = rej;
        });
        p.__handler = function __handler(users)
        {
            p.__resolver(users);
        };
        try
        {
            this.Current(p.__handler);
        }
        catch (e)
        {
            p.__rejector(e);
        }
        p.parent = this;
        return (p);
    }
}
function showActiveOnly(source)
{
    var retVal = [];
    var unique = {};
    var usernames = [];
    var tmp;

    for (var i in source)
    {
        if (source[i].State == 'Active')
        {
            retVal.push(source[i]);
            tmp = (source[i].Domain ? (source[i].Domain + '\\') : '') + source[i].Username;
            if (!unique[tmp]) { unique[tmp] = tmp;}
        }
    }

    for (var i in unique)
    {
        usernames.push(i);
    }

    Object.defineProperty(retVal, 'usernames', { value: usernames });
    return (retVal);
}
function getTokens(str)
{
    var columns = [];
    var i;

    columns.push(str.substring(0, (i=str.indexOf(' '))));
    while (str[++i] == ' ');
    columns.push(str.substring(i, (i=str.substring(i).indexOf(' ') + i)));
    while (str[++i] == ' ');
    columns.push(str.substring(i, (i=str.substring(i).indexOf(' ') + i)));
    while (str[++i] == ' ');
    var status = str.substring(i).trim();
    columns.push(status);

    return (columns);
}

module.exports = new UserSessions();
