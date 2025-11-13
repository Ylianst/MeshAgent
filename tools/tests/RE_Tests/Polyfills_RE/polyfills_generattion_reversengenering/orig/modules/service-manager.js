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
var promise = require('promise');
var systemd_escape = null;

function failureActionToInteger(action)
{
    var ret;
    switch(action)
    {
        default:
        case 'NONE':
            ret=0;
            break;
        case 'SERVICE_RESTART':
            ret=1;
            break;
        case 'REBOOT':
            ret=2;
            break;
    }
    return(ret);
}

function extractFileName(filePath)
{
    if (typeof (filePath) == 'string')
    {
        var tokens = filePath.split('\\').join('/').split('/');
        var name;

        while ((name = tokens.pop()) == '');
        return (name);
    }
    else
    {
        return(filePath.newName)
    }
}
function extractFileSource(filePath)
{
    return (typeof (filePath) == 'string' ? filePath : filePath.source);
}

function prepareFolders(folderPath)
{
    var dlmtr = process.platform == 'win32' ? '\\' : '/';

    var tokens = folderPath.split(dlmtr);
    var path = null;

    while (tokens.length>0)
    {
        path = (path == null ? tokens.shift() : (path + dlmtr + tokens.shift()));
        if (path.indexOf(process.platform == 'win32' ? '\\' : '/') < 0) { continue; }
        if (!require('fs').existsSync(path)) { require('fs').mkdirSync(path); }
    }
}

function parseServiceStatus(token)
{
    var j = {};
    var serviceType = token.Deref(0, 4).IntVal;
    j.isFileSystemDriver = ((serviceType & 0x00000002) == 0x00000002);
    j.isKernelDriver = ((serviceType & 0x00000001) == 0x00000001);
    j.isSharedProcess = ((serviceType & 0x00000020) == 0x00000020);
    j.isOwnProcess = ((serviceType & 0x00000010) == 0x00000010);
    j.isInteractive = ((serviceType & 0x00000100) == 0x00000100);
    j.waitHint = token.Deref((6 * 4), 4).toBuffer().readUInt32LE();
    j.rawState = token.Deref((1 * 4), 4).toBuffer().readUInt32LE();
    switch (j.rawState)
    {
        case 0x00000005:
            j.state = 'CONTINUE_PENDING';
            break;
        case 0x00000006:
            j.state = 'PAUSE_PENDING';
            break;
        case 0x00000007:
            j.state = 'PAUSED';
            break;
        case 0x00000004:
            j.state = 'RUNNING';
            break;
        case 0x00000002:
            j.state = 'START_PENDING';
            break;
        case 0x00000003:
            j.state = 'STOP_PENDING';
            break;
        case 0x00000001:
            j.state = 'STOPPED';
            break;
    }
    var controlsAccepted = token.Deref((2 * 4), 4).toBuffer().readUInt32LE();
    j.controlsAccepted = [];
    if ((controlsAccepted & 0x00000010) == 0x00000010)
    {
        j.controlsAccepted.push('SERVICE_CONTROL_NETBINDADD');
        j.controlsAccepted.push('SERVICE_CONTROL_NETBINDREMOVE');
        j.controlsAccepted.push('SERVICE_CONTROL_NETBINDENABLE');
        j.controlsAccepted.push('SERVICE_CONTROL_NETBINDDISABLE');
    }
    if ((controlsAccepted & 0x00000008) == 0x00000008) { j.controlsAccepted.push('SERVICE_CONTROL_PARAMCHANGE'); }
    if ((controlsAccepted & 0x00000002) == 0x00000002) { j.controlsAccepted.push('SERVICE_CONTROL_PAUSE'); j.controlsAccepted.push('SERVICE_CONTROL_CONTINUE'); }
    if ((controlsAccepted & 0x00000100) == 0x00000100) { j.controlsAccepted.push('SERVICE_CONTROL_PRESHUTDOWN'); }
    if ((controlsAccepted & 0x00000004) == 0x00000004) { j.controlsAccepted.push('SERVICE_CONTROL_SHUTDOWN'); }
    if ((controlsAccepted & 0x00000001) == 0x00000001) { j.controlsAccepted.push('SERVICE_CONTROL_STOP'); }
    if ((controlsAccepted & 0x00000020) == 0x00000020) { j.controlsAccepted.push('SERVICE_CONTROL_HARDWAREPROFILECHANGE'); }
    if ((controlsAccepted & 0x00000040) == 0x00000040) { j.controlsAccepted.push('SERVICE_CONTROL_POWEREVENT'); }
    if ((controlsAccepted & 0x00000080) == 0x00000080) { j.controlsAccepted.push('SERVICE_CONTROL_SESSIONCHANGE'); }
    j.pid = token.Deref((7 * 4), 4).toBuffer().readUInt32LE();
    return (j);
}

if (process.platform == 'linux')
{
    function _upstart_GetServiceTable()
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.stdin.write("initctl list | tr '\n' '`' | awk -F'`' '");
        child.stdin.write('{');
        child.stdin.write('   printf "{"; ');
        child.stdin.write('   for(i=1;i<NF;++i) ');
        child.stdin.write('   {');
        child.stdin.write('      c=split($i,name,","); ');
        child.stdin.write('      c2=split(name[1],state," "); ');
        child.stdin.write('      sname=substr(name[1],0,length(name[1])-length(state[c2])-1); ');
        child.stdin.write('      split(state[c2],rstate,"/"); ');
        child.stdin.write('      rs = rstate[2]=="running"?"RUNNING":"STOPPED";');
        child.stdin.write('      spid=""; ');
        child.stdin.write('      if(c==2) ');
        child.stdin.write('      { ');
        child.stdin.write('         split(name[2],pid," "); ');
        child.stdin.write('         spid=pid[2]; ');
        child.stdin.write('      } ');
        child.stdin.write('      printf "%s\\"%s\\": {\\"state\\": \\"%s\\", \\"pid\\":\\"%s\\"}",(i==1?"":","),sname,rs,spid; ');
        child.stdin.write('   } ');
        child.stdin.write('   printf "}"; ');
        child.stdin.write("}'\nexit\n");
        child.waitExit();
        var ret = {};
        try
        {
            ret = JSON.parse(child.stdout.str);
        }
        catch(e)
        {
        }
        return (ret);
    }
    function _systemd_GetServiceTable()
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.stdin.write("systemctl --type=service --state=running | grep .service | tr '\n' '`' | awk -F'`' '");
        child.stdin.write('{');
        child.stdin.write('   printf "{"; ');
        child.stdin.write('   for(i=1;i<NF;++i) ');
        child.stdin.write('   {');
        child.stdin.write('      c=split($i,name," "); ');
        child.stdin.write('      printf "%s\\"%s\\": \\"%s\\"", (i==1?"":","), name[1], name[4]; ');
        child.stdin.write('   } ');
        child.stdin.write('   printf "}"; ');
        child.stdin.write("}'\nexit\n");
        child.waitExit();

        var ret = {};
        try
        {
            ret = JSON.parse(child.stdout.str);
        }
        catch (e)
        {
        }
        return (ret);
    }
}







if (process.platform == 'darwin')
{
    function getOSVersion()
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = '';
        child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
        child.stdin.write("sw_vers | grep ProductVersion | awk '{ print $2 }'\nexit\n");
        child.waitExit();

        //child.stdout.str = '10.9';

        var ret = { raw: child.stdout.str.trim().split('.'), toString: function () { return (this.raw.join('.')); } };
        ret.compareTo = function compareTo(val)
        {
            var raw = (typeof (val) == 'string') ? val.split('.') : val.raw; if (!raw) { throw ('Invalid parameter'); }
            var self = this.raw.join('.').split('.');

            var r = null, s = null;
            while (self.length > 0 && raw.length > 0)
            {
                s = parseInt(self.shift()); r = parseInt(raw.shift());
                if (s < r) { return (-1); }
                if (s > r) { return (1); }
            }
            if (self.length == raw.length) { return (0); }
            if (self.length < raw.length) { return (-1); } else { return (1); }    
        }
        return (ret);
    };


    function fetchPlist(folder, name, userid)
    {
        if (folder.endsWith('/')) { folder = folder.substring(0, folder.length - 1); }
        var ret = { name: name, close: function () { }, _uid: userid };
        if (!require('fs').existsSync(folder + '/' + name + '.plist'))
        {
            // Before we throw in the towel, let's enumerate all the plist files, and see if one has a matching label
            var files = require('fs').readdirSync(folder);
            for (var file in files)
            {
                if (!files[file].endsWith('.plist')) { continue; }
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = '';
                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write("cat " + folder + '/' + files[file] + " | tr '\n' '\.' | awk '{ split($0, a, \"<key>Label</key>\"); split(a[2], b, \"</string>\"); split(b[1], c, \"<string>\"); print c[2]; }'\nexit\n");
                child.waitExit();
                if (child.stdout.str.trim() == name)
                {
                    ret.name = files[file].endsWith('.plist') ? files[file].substring(0, files[file].length - 6) : files[file];
                    Object.defineProperty(ret, 'alias', { value: name });
                    Object.defineProperty(ret, 'plist', { value: folder + '/' + files[file] });
                    break;
                }
            }
            if (ret.name == name) { throw (' ' + (folder.split('LaunchDaemon').length>1 ? 'LaunchDaemon' : 'LaunchAgent') + ' (' + name + ') NOT FOUND'); }
        }
        else
        {
            Object.defineProperty(ret, 'plist', { value: folder + '/' + name + '.plist' });
            Object.defineProperty(ret, 'alias',
                {
                    get: function ()
                        {
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stdout.str = '';
                            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                            child.stdin.write("cat " + ret.plist + " | tr '\n' '\.' | awk '{ split($0, a, \"<key>Label</key>\"); split(a[2], b, \"</string>\"); split(b[1], c, \"<string>\"); print c[2]; }'\nexit\n");
                            child.waitExit();
                            return (child.stdout.str.trim());
                        }
                });
        }
        Object.defineProperty(ret, 'daemon', { value: ret.plist.split('/LaunchDaemons/').length > 1 ? true : false });
        try
        {
            Object.defineProperty(ret, 'installedDate', { value: require('fs').statSync(ret.plist).ctime });
        }
        catch(xx)
        {
        }
        ret.appWorkingDirectory = function appWorkingDirectory()
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("cat " + this.plist + " | tr '\n' '\.' | awk '{ split($0, a, \"<key>WorkingDirectory</key>\"); split(a[2], b, \"</string>\"); split(b[1], c, \"<string>\"); gsub(/\\/$/,\"\",c[2]); printf \"%s/\",c[2]; }'\nexit\n");
            child.waitExit();
            child.stdout.str = child.stdout.str.trim();

            return (child.stdout.str);
        };
        ret.appLocation = function appLocation()
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write("cat " + this.plist + " | tr '\n' '\.' | awk '{ split($0, a, \"<key>ProgramArguments</key>\"); split(a[2], b, \"</string>\"); split(b[1], c, \"<string>\"); print c[2]; }'\nexit\n");
            child.waitExit();
            return (child.stdout.str.trim());
        };
        Object.defineProperty(ret, '_runAtLoad',
            {
                get: function ()
                {
                    // We need to see if this is an Auto-Starting service, in order to figure out how to implement 'start'
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = '';
                    child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    child.stdin.write("cat " + ret.plist + " | tr '\n' '\.' | awk '{ split($0, a, \"<key>RunAtLoad</key>\"); split(a[2], b, \"/>\"); split(b[1], c, \"<\"); print c[2]; }'\nexit\n");
                    child.waitExit();
                    return (child.stdout.str.trim().toUpperCase() == "TRUE");
                }
            });
        Object.defineProperty(ret, 'startType',
            {
                get: function()
                {
                    if(this.daemon)
                    {
                        return (this._runAtLoad ? 'AUTO_START' : 'DEMAND_START');
                    }
                    else
                    {
                        return ('AUTO_START');
                    }
                }
            });
        Object.defineProperty(ret, "_keepAlive",
            {
                get: function () 
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = '';
                    child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    child.stdin.write("cat " + ret.plist + " | tr '\n' '\.' | awk '{split($0, a, \"<key>KeepAlive</key>\"); split(a[2], b, \"<\"); split(b[2], c, \">\"); ");
                    child.stdin.write(" if(c[1]==\"dict\"){ split(a[2], d, \"</dict>\"); if(split(d[1], truval, \"<true/>\")>1) { split(truval[1], kn1, \"<key>\"); split(kn1[2], kn2, \"</key>\"); print kn2[1]; } }");
                    child.stdin.write(" else { split(c[1], ka, \"/\"); if(ka[1]==\"true\") {print \"ALWAYS\";} } }'\nexit\n");
                    child.waitExit();
                    return (child.stdout.str.trim());
                }
            });
        ret.getPID = function getPID(uid, asString)
        {
            var options = undefined;
            var command;
            if (this._uid != null) { uid = this._uid; }

            if (getOSVersion().compareTo('10.10') < 0)
            {
                command = "launchctl list | grep '" + this.alias + "' | awk '{ if($3==\"" + this.alias + "\"){print $1;}}'\nexit\n";
                options = { uid: uid };
            }
            else
            {
                if (uid == null)
                {
                    command = 'launchctl print system | grep "' + this.alias + '" | awk \'{ if(split($0, tmp, " ")==3) { if($3=="' + this.alias + '") { print $1; } }}\'\nexit\n';
                }
                else
                {
                    command = 'launchctl print gui/' + uid + ' | grep "' + this.alias + '" | awk \'{ if(split($0, tmp, " ")==3) { if($3=="' + this.alias + '") { print $1; } }}\'\nexit\n';
                }
            }

            var child = require('child_process').execFile('/bin/sh', ['sh'], options);
            child.stdout.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write(command);
            child.waitExit();

            if (asString == null || asString != true)
            {
                return (parseInt(child.stdout.str.trim()));
            }
            else
            {
                return (child.stdout.str.trim());
            }
        };
        ret.isLoaded = function isLoaded(uid)
        {
            if (this._uid != null) { uid = this._uid; }
            return (this.getPID(uid, true) != '');
        };
        ret.isRunning = function isRunning(uid)
        {
            if (this._uid != null) { uid = this._uid; }
            return (this.getPID(uid) > 0);
        };
        ret.isMe = function isMe(uid)
        {
            if (this._uid != null) { uid = this._uid; }
            return (this.getPID(uid) == process.pid);
        };
        ret.load = function load(uid)
        {
            var self = require('user-sessions').Self();
            var ver = getOSVersion();
            var options = undefined;
            var command = 'load';
            if (this._uid != null) { uid = this._uid; }

            if (this.daemon)
            {
                if(uid!=null && uid!=0)
                {
                    throw ('LaunchDaemon must run as root');
                }
            }
            else
            {
                if (uid == null) { uid = self; }
                if(ver.compareTo('10.10') < 0 && uid != self && self != 0)
                {
                    throw ('On this version of MacOS, must be root to load this service into the specified user space');
                }
                else if (ver.compareTo('10.10') < 0)
                {
                    options = { uid: uid };
                }
                else
                {
                    command = 'bootstrap gui/' + uid;
                }
            }

            var child = require('child_process').execFile('/bin/sh', ['sh'], options);
            child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stdin.write('launchctl ' + command + ' ' + this.plist + '\n\exit\n');
            child.waitExit();
        };
        ret.unload = function unload(uid)
        {
            var child = null;
            var v = getOSVersion();
            var self = require('user-sessions').Self();
            var options = undefined;
            var useBootout = false;
            if (this._uid != null) { uid = this._uid; }

            if(uid!=null)
            {
                if (v.compareTo('10.10') <= 0 && self == 0)
                {
                    // We must switch to user context to unload the service
                    options = { uid: uid };
                }
                else
                {
                    if(v.compareTo('10.10') > 0)
                    {
                        if(self == 0 || self == uid)
                        {
                            // use bootout
                            useBootout = true;
                        }
                        else
                        {
                            // insufficient access
                            throw ('Needs elevated privileges')
                        }
                    }
                    else
                    {
                        if (self == uid)
                        {
                            // just unload, becuase we are already in the right context
                            useBootout = false;
                        }
                        else
                        {
                            // insufficient access
                            throw ('Needs elevated privileges')
                        }
                    }
                }
            }
            else
            {
                if(self == 0)
                {
                    if(v.compareTo('10.10') > 0)
                    {
                        // use bootout
                        useBootout = true;
                    }
                    else
                    {
                        // just unload
                        useBootout = false;
                    }
                }
                else
                {
                    // Insufficient access
                    throw ('Needs elevated privileges')
                }
            }

            child = require('child_process').execFile('/bin/sh', ['sh'], options);
            child.stdout.str = '';
            child.stderr.str = '';
            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
            child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
            if (useBootout)
            {
                if (uid == null)
                {
                    child.stdin.write('launchctl bootout system ' + this.plist + '\nexit\n');
                }
                else
                {
                    child.stdin.write('launchctl bootout gui/' + uid + ' ' + this.plist + '\nexit\n');
                }
            }
            else
            {
                child.stdin.write('launchctl unload ' + this.plist + '\nexit\n');
            }
            child.waitExit();
        };
        ret.start = function start(uid)
        {
            var options = undefined;
            var self = require('user-sessions').Self();
            if (this._uid != null) { uid = this._uid; }
            if (!this.daemon && uid == null) { uid = self; }
            if (!this.daemon && uid > 0 && self == 0) { options = { uid: uid }; }
            if (!this.daemon && uid > 0 && self != 0 && uid != self) { throw ('Cannot start LaunchAgent into another user domain while not root'); }
            if (this.daemon && self != 0) { throw ('Cannot start LaunchDaemon while not root'); }

            this.load(uid);

            var child = require('child_process').execFile('/bin/sh', ['sh'], options);
            child.stdout.on('data', function (chunk) { });
            child.stdin.write('launchctl start ' + this.alias + '\n\exit\n');
            child.waitExit();
        };
        ret.stop = function stop(uid)
        {
            var options = undefined;
            var self = require('user-sessions').Self();
            if (this._uid != null) { uid = this._uid; }
            if (!this.daemon && uid == null) { uid = self; }
            if (!this.daemon && uid > 0 && self == 0) { options = { uid: uid }; }
            if (!this.daemon && uid > 0 && self != 0 && uid != self) { throw ('Cannot stop LaunchAgent in another user domain while not root'); }
            if (this.daemon && self != 0) { throw ('Cannot stop LaunchDaemon while not root'); }

            if (!(this._keepAlive == 'Crashed' || this._keepAlive == ''))
            {
                // We must unload the service, rather than stopping it, because otherwise it'll likely restart
                this.unload(uid);
            }
            else
            {
                var child = require('child_process').execFile('/bin/sh', ['sh'], options);
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write('launchctl stop ' + this.alias + '\nexit\n');
                child.waitExit();
            }
        };
        ret.restart = function restart(uid)
        {
            if (this._uid != null) { uid = this._uid; }
            if (getOSVersion().compareTo('10.10') < 0)
            {
                if (!this.daemon && uid == null) { uid = require('user-sessions').Self(); }
                var command = 'launchctl unload ' + this.plist + '\nlaunchctl load ' + this.plist + '\nlaunchctl start ' + this.alias + '\nexit\n';
                var child = require('child_process').execFile('/bin/sh', ['sh'], { detached: true, uid: uid });
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write(command);
                child.waitExit();
            }
            else
            {
                var command = this.daemon ? ('system/' + this.alias) : ('gui/' + (uid != null ? uid : require('user-sessions').Self()) + '/' + this.alias);
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write('launchctl kickstart -k ' + command + '\nexit\n');
                child.waitExit();
            }
        };
        ret.parameters = function parameters()
        {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
            child.stdin.write("cat " + this.plist + " | tr '\\n' '`' | awk '");
            child.stdin.write('{');
            child.stdin.write('   a=split($0,A,"<key>ProgramArguments</key>");');
            child.stdin.write('   split(A[2],B,"<array>");');
            child.stdin.write('   split(B[2],C,"</array>");');
            child.stdin.write('   num=split(C[1],tokens,"</string>");');
            child.stdin.write('   for(i=1;i<num;++i)');
            child.stdin.write('   {');
            child.stdin.write('      gsub(/^.+<string>/,"",tokens[i]);');
            child.stdin.write('      printf "%s%s",(i==1)?"":"\\n", tokens[i];');
            child.stdin.write('   }');
            child.stdin.write("}'\nexit\n");
            child.waitExit();
            return (child.stdout.str.split('\n'));
        };
        return (ret);
    };
}



function serviceManager()
{
    this._ObjectID = 'service-manager';
    if (process.platform == 'win32') 
    {
        this.GM = require('_GenericMarshal');
        this.proxy = this.GM.CreateNativeProxy('Advapi32.dll');
        this.proxy.CreateMethod('OpenSCManagerA');
        this.proxy.CreateMethod('EnumServicesStatusExW');
        this.proxy.CreateMethod('OpenServiceW');
        this.proxy.CreateMethod('QueryServiceStatusEx');
        this.proxy.CreateMethod('QueryServiceConfigA');
        this.proxy.CreateMethod('QueryServiceConfig2A');
        this.proxy.CreateMethod('ControlService');
        this.proxy.CreateMethod('StartServiceA');
        this.proxy.CreateMethod('CloseServiceHandle');
        this.proxy.CreateMethod('CreateServiceW');
        this.proxy.CreateMethod('ChangeServiceConfig2W');
        this.proxy.CreateMethod('DeleteService');
        this.proxy.CreateMethod('AllocateAndInitializeSid');
        this.proxy.CreateMethod('CheckTokenMembership');
        this.proxy.CreateMethod('FreeSid');

        this.proxy2 = this.GM.CreateNativeProxy('Kernel32.dll');
        this.proxy2.CreateMethod('GetLastError');

        this.isAdmin = function isAdmin() {
            var NTAuthority = this.GM.CreateVariable(6);
            NTAuthority.toBuffer().writeInt8(5, 5);
            var AdministratorsGroup = this.GM.CreatePointer();
            var admin = false;

            if (this.proxy.AllocateAndInitializeSid(NTAuthority, 2, 32, 544, 0, 0, 0, 0, 0, 0, AdministratorsGroup).Val != 0)
            {
                var member = this.GM.CreateInteger();
                if (this.proxy.CheckTokenMembership(0, AdministratorsGroup.Deref(), member).Val != 0)
                {
                    if (member.toBuffer().readUInt32LE() != 0) { admin = true; }
                }
                this.proxy.FreeSid(AdministratorsGroup.Deref());
            }
            return admin;
        };
        this.getProgramFolder = function getProgramFolder()
        {
            if (require('os').arch() == 'x64')
            {
                // 64 bit Windows
                if (this.GM.PointerSize == 4)
                {
                    return (process.env['ProgramFiles(x86)'] ? process.env['ProgramFiles(x86)'] : process.env['ProgramFiles']);
                } 
                return process.env['ProgramFiles'];             // 64 bit App
            }

            // 32 bit Windows
            return process.env['ProgramFiles'];                 
        };

        this.enumerateService = function () {
            var machineName = this.GM.CreatePointer();
            var dbName = this.GM.CreatePointer();
            var handle = this.proxy.OpenSCManagerA(0x00, 0x00, 0x0001 | 0x0004);

            var bytesNeeded = this.GM.CreatePointer();
            var servicesReturned = this.GM.CreatePointer();
            var resumeHandle = this.GM.CreatePointer();
            //var services = this.proxy.CreateVariable(262144);
            var success = this.proxy.EnumServicesStatusExW(handle, 0, 0x00000030, 0x00000003, 0x00, 0x00, bytesNeeded, servicesReturned, resumeHandle, 0x00);

            var ptrSize = dbName._size;
            var sz = bytesNeeded.Deref(0, dbName._size).toBuffer().readUInt32LE();

            if (sz < 0) { throw ('error enumerating services'); }

            var services = this.GM.CreateVariable(sz);
            this.proxy.EnumServicesStatusExW(handle, 0, 0x00000030, 0x00000003, services, sz, bytesNeeded, servicesReturned, resumeHandle, 0x00);

            var blockSize = 36 + (2 * ptrSize);
            blockSize += ((ptrSize - (blockSize % ptrSize)) % ptrSize);
            var retVal = [];
            for (var i = 0; i < servicesReturned.Deref(0, dbName._size).toBuffer().readUInt32LE(); ++i)
            {
                var token = services.Deref(i * blockSize, blockSize);
                var j = {};
                j.name = token.Deref(0, ptrSize).Deref().Wide2UTF8;
                j.displayName = token.Deref(ptrSize, ptrSize).Deref().Wide2UTF8;
                j.status = parseServiceStatus(token.Deref(2 * ptrSize, 36));
                retVal.push(j);
            }
            this.proxy.CloseServiceHandle(handle);
            return (retVal);
        }
        this.getService = function getService(name)
        {
            var isroot = this.isAdmin();

            var serviceName = this.GM.CreateVariable(name, { wide: true });
            var ptr = this.GM.CreatePointer();
            var bytesNeeded = this.GM.CreateVariable(ptr._size);
            var handle = this.proxy.OpenSCManagerA(0x00, 0x00, 0x0001 | 0x0004 | 0x0010 | (isroot ? 0x0020 : 0x00));
            if (handle.Val == 0) { throw ('could not open ServiceManager'); }
            var h = this.proxy.OpenServiceW(handle, serviceName, 0x0001 | 0x0004 | (isroot ? (0x0002 | 0x0020 | 0x0010 | 0x00010000): 0x00));
            if (h.Val != 0)
            {
                var retVal = { _ObjectID: 'service-manager.service' }
                retVal._scm = handle;
                retVal._service = h;
                retVal._GM = this.GM;
                retVal._proxy = this.proxy;
                retVal._proxy2 = this.proxy2;
                retVal.name = name;

                Object.defineProperty(retVal, 'status', 
                    { 
                        get: function()
                        {
                            var bytesNeeded = this._GM.CreateVariable(this._GM.PointerSize);
                            this._proxy.QueryServiceStatusEx(this._service, 0, 0, 0, bytesNeeded);
                            var st = this._GM.CreateVariable(bytesNeeded.toBuffer().readUInt32LE());
                            if (this._proxy.QueryServiceStatusEx(this._service, 0, st, st._size, bytesNeeded).Val != 0)
                            {
                                return(parseServiceStatus(st));
                            }
                            else
                            {
                                return ({ state: 'UNKNOWN' });
                            }
                        }
                    });
                Object.defineProperty(retVal, 'installedBy',
                    {
                        get: function()
                        {
                            var reg = require('win-registry');
                            try
                            {
                                return(reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + this.name, '_InstalledBy'));
                            }
                            catch(xx)
                            {
                                return (null);
                            }
                        }
                    });
                try
                {
                    Object.defineProperty(retVal, 'installedDate',
                        {
                            value: require('win-registry').QueryKeyLastModified(require('win-registry').HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + name, 'ImagePath')
                        });
                }
                catch(xx)
                {
                }
                if (retVal.status.state != 'UNKNOWN')
                {
                    require('events').EventEmitter.call(retVal);
                    retVal.close = function ()
                    {
                        if(this._service && this._scm)
                        {
                            this._proxy.CloseServiceHandle(this._service);
                            this._proxy.CloseServiceHandle(this._scm);
                            this._service = this._scm = null;
                        }
                    };
                    retVal.on('~', retVal.close);
                    retVal.isMe = function isMe()
                    {
                        return (parseInt(this.status.pid) == process.pid);
                    }
                    retVal.update = function update()
                    {
                        if (this.failureActions)
                        {
                            var actions = this._GM.CreateVariable(this.failureActions.actions.length * 8);                                // len*sizeof(SC_ACTION)
                            for (var i = 0; i < this.failureActions.actions.length && i < 3; ++i)
                            {
                                actions.Deref(i*8, 4).toBuffer().writeUInt32LE(failureActionToInteger(this.failureActions.actions[i].type));   // SC_ACTION[i].type
                                actions.Deref(4+(i*8), 4).toBuffer().writeUInt32LE(this.failureActions.actions[i].delay);                      // SC_ACTION[i].delay
                            }

                            var updatedFailureActions = this._GM.CreateVariable(40);                                         // sizeof(SERVICE_FAILURE_ACTIONS)
                            updatedFailureActions.Deref(0, 4).toBuffer().writeUInt32LE(this.failureActions.resetPeriod);    // dwResetPeriod
                            updatedFailureActions.Deref(this._GM.PointerSize == 8 ? 24 : 12, 4).toBuffer().writeUInt32LE(this.failureActions.actions.length); // cActions
                            actions.pointerBuffer().copy(updatedFailureActions.Deref(this._GM.PointerSize == 8 ? 32 : 16, this._GM.PointerSize).toBuffer());
                            if (this._proxy.ChangeServiceConfig2W(this._service, 2, updatedFailureActions).Val == 0)
                            {
                                throw('Unable to set FailureActions...');
                            }
                        }
                    };
                    retVal.appLocation = function ()
                    {
                        var reg = require('win-registry');
                        var imagePath = reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + this.name, 'ImagePath').toString();
                        var ret = imagePath.split('.exe')[0] + '.exe';
                        if (ret.startsWith('"')) { ret = ret.substring(1); }
                        return (ret);
                    };
                    retVal.appWorkingDirectory = function ()
                    {
                        var tokens = this.appLocation().split('\\');
                        tokens.pop();
                        return (tokens.join('\\'));
                    };
                    retVal.isRunning = function ()
                    {
                        return (this.status.state == 'RUNNING');
                    };

                    retVal._stopEx = function(s, p)
                    {
                        var current = s.status.state;
                        var pid = s.status.pid;

                        switch (current)
                        {
                            case 'STOPPED':
                                p._res('STOPPED');
                                break;
                            case 'STOP_PENDING':
                                p._elapsedTime = Date.now() - p._startTime;
                                if (p._elapsedTime < 10000)
                                {
                                    p.timer = setTimeout(s._stopEx, p._waitTime, s, p);
                                }
                                else
                                {
                                    if (pid > 0)
                                    {
                                        process.kill(pid);
                                        p._res('STOPPED/KILLED');
                                    }
                                    else
                                    {
                                        p._rej('timeout waiting for service to stop');
                                    }
                                }
                                break;
                            default:
                                if (pid > 0)
                                {

                                }
                                else
                                {
                                    p._rej('Unexpected state: ' + current);
                                }
                                break;
                        }
                    }

                    retVal.stop = function ()
                    {
                        var ret = new promise(function (a, r) { this._res = a; this._rej = r; });
                        var status = this.status;
                        var pid = this.status.pid;
                        if(status.state == 'RUNNING')
                        {
                            // Stop Service
                            var newstate = this._GM.CreateVariable(36);
                            var reason;
                            if(this._proxy.ControlService(this._service, 0x00000001, newstate).Val == 0 && (reason = this._proxy2.GetLastError().Val)!=0)
                            {
                                ret._rej(this.name + '.stop() failed with error: ' + reason);
                            }
                            else
                            {
                                // Now we need to setup a timed callback to check the status
                                ret._startTime = Date.now();
                                ret._elapsedTime = 0;
                                ret._waitTime = status.waitHint / 10;
                                if (ret._waitTime < 500) { ret._waitTime = 500; }
                                if (ret._waitTime > 5000) { ret._waitTime = 5000; }
                                ret.timer = setTimeout(this._stopEx, ret._waitTime, this, ret);
                            }
                        }
                        else if (status.state == 'STOP_PENDING' && pid > 0)
                        {
                            process.kill(pid);
                            ret._res('STOPPED/KILLED');
                        }
                        else
                        {
                            ret._rej('cannot call ' + this.name + '.stop(), when current state is: ' + this.status.state);
                        }
                        return (ret);
                    }
                    retVal.start = function ()
                    {
                        if (this.status.state == 'STOPPED')
                        {
                            var success = this._proxy.StartServiceA(this._service, 0, 0);
                            if (success == 0)
                            {
                                throw (this.name + '.start() failed');
                            }
                        }
                        else
                        {
                            throw ('cannot call ' + this.name + '.start(), when current state is: ' + this.status.state);
                        }
                    }
                    retVal.restart = function ()
                    {
                        if (this.isMe())
                        {
                            // In order to restart ourselves on Windows, we must spawn a detached child process, becuase we need to call start, once we are stopped
                            require('child_process')._execve(process.env['windir'] + '\\system32\\cmd.exe', ['cmd.exe', '/C net stop "' + this.name + '" & net stop "' + this.name + '"']);
                    }
                        else
                        {
                            var p = this.stop();
                            p.startp = new promise(function (a, r) { this._a = a; this._r = r; });
                            p.service = this;
                            p.then(function ()
                            {
                                try
                                {
                                    this.service.start();
                                }
                                catch (e)
                                {
                                    this.startp._r(e);
                                    return;
                                }
                                this.startp._a();
                            }, function (e) { this.startp._r(e); });
                            return (p.startp);
                        }
                    }
                    var query_service_configa_DWORD = this.GM.CreateVariable(4);
                    this.proxy.QueryServiceConfigA(h, 0, 0, query_service_configa_DWORD);
                    if (query_service_configa_DWORD.toBuffer().readUInt32LE() > 0)
                    {
                        var query_service_configa = this.GM.CreateVariable(query_service_configa_DWORD.toBuffer().readUInt32LE());
                        if(this.proxy.QueryServiceConfigA(h, query_service_configa, query_service_configa._size, query_service_configa_DWORD).Val != 0)
                        {
                            var val = query_service_configa.Deref(this.GM.PointerSize == 4 ? 28 : 48, this.GM.PointerSize).Deref().String;
                            Object.defineProperty(retVal, 'user', { value: val });
                            switch(query_service_configa.Deref(4,4).toBuffer().readUInt32LE())
                            {
                                case 0x00:
                                case 0x01:
                                case 0x02:
                                    retVal.startType = 'AUTO_START';
                                    break;
                                case 0x03:
                                    retVal.startType = 'DEMAND_START';
                                    break;
                                case 0x04:
                                    retVal.startType = 'DISABLED';
                                    break;
                            }
                        }
                    }


                    var failureactions = this.GM.CreateVariable(8192);
                    var bneeded = this.GM.CreateVariable(4);        
                    if (this.proxy.QueryServiceConfig2A(h, 2, failureactions, 8192, bneeded).Val != 0)
                    {
                        var cActions = failureactions.toBuffer().readUInt32LE(this.GM.PointerSize == 8 ? 24 : 12);
                        retVal.failureActions = {};
                        retVal.failureActions.resetPeriod = failureactions.Deref(0, 4).toBuffer().readUInt32LE(0);
                        retVal.failureActions.actions = [];
                        for(var act = 0 ; act < cActions; ++act)
                        {
                            var action = failureactions.Deref(this.GM.PointerSize == 8 ? 32 : 16, this.GM.PointerSize).Deref().Deref(act*8,8).toBuffer();
                            switch(action.readUInt32LE())
                            {
                                case 0:
                                    retVal.failureActions.actions.push({ type: 'NONE' });
                                    break;
                                case 1:
                                    retVal.failureActions.actions.push({ type: 'SERVICE_RESTART' });
                                    break;
                                case 2:
                                    retVal.failureActions.actions.push({ type: 'REBOOT' });
                                    break;
                                default:
                                    retVal.failureActions.actions.push({ type: 'OTHER' });
                                    break;
                            }
                            retVal.failureActions.actions.peek().delay = action.readUInt32LE(4);
                        }
                    }
                    return (retVal);
                }
                else {

                }
            }

            this.proxy.CloseServiceHandle(handle);
            throw ('could not find service: ' + name);
        }
    }
    else
    {
        // Linux, MacOS, FreeBSD

        this.isAdmin = function isAdmin() 
        {
            return (require('user-sessions').isRoot());
        }

        if (process.platform == 'freebsd')
        {
            Object.defineProperty(this, 'OPNsense',
                {
                    get: function()
                    {
                        if (this.__opnsense != null) { return (this.__opnsense); }
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stderr.on('data', function (c) { });
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("opnsense-version | awk '{ print $2; }'\nexit\n");
                        child.waitExit();
                        this.__opnsense = child.stdout.str.trim() != '' ? true : false;
                        return (this.__opnsense);
                    }
                });
            Object.defineProperty(this, 'pfSense',
                {
                    get: function ()
                    {
                        if (this.__ispfsense != null) { return (this.__ispfsense); }
                        try
                        {
                            if (require('fs').existsSync('/etc/psSense-rc') || require('fs').readFileSync('/etc/platform').toString().trim() == 'pfSense')
                            {
                                this.__ispfsense = true;
                                return (true);
                            }
                        }
                        catch (e)
                        {
                        }
                        this.__ispfsense = false;
                        return (false);
                    }
                });
            this.getService = function getService(name)
            {
                var ret = { name: name, close: function () { } };
                Object.defineProperty(ret, "OpenBSD", { value: !require('fs').existsSync('/usr/sbin/daemon') });

                if(require('fs').existsSync('/etc/rc.d/' + name)) 
                {
                    Object.defineProperty(ret, 'rc', { value: '/etc/rc.d/' + name });
                }
                else if(require('fs').existsSync('/usr/local/etc/rc.d/' + name))
                {
                    Object.defineProperty(ret, 'rc', { value: '/usr/local/etc/rc.d/' + name });
                }
                else
                {
                    throw ('Service: ' + name + ' not found');
                }
                Object.defineProperty(ret, "startType",
                    {
                        get: function ()
                        {
                            if (!this.OpenBSD)
                            {
                                // FreeBSD
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stderr.on('data', function (c) { });
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stdin.write('service ' + this.name + ' rcvar | grep _enable= | awk \'{ a=split($0, b, "\\""); if(b[2]=="YES") { print "YES"; } }\'\nexit\n');
                                child.waitExit();
                                return (child.stdout.str.trim() == '' ? 'DEMAND_START' : 'AUTO_START');
                            }
                            else
                            {
                                // OpenBSD
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stderr.on('data', function (c) { });
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stdin.write('rcctl ls on | awk \'{ if($0=="' + this.name + '") { print "AUTO_START"; } }\'\nexit\n');
                                child.waitExit();
                                return (child.stdout.str.trim() == '' ? 'DEMAND_START' : 'AUTO_START');
                            }
                        }
                    });

                ret.description = function description()
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("cat " + this.rc + " | grep desc= | awk -F= '" + '{ if($1=="desc") { $1=""; a=split($0, res, "\\""); if(a>1) { print res[2]; } else { print $0; } } }\'\nexit\n');
                    child.waitExit();
                    return (child.stdout.str.trim());
                };
                ret.appWorkingDirectory = function appWorkingDirectory()
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("cat " + this.rc + " | grep " + this.name + "_chdir= | awk -F= '");
                    child.stdin.write('{');
                    child.stdin.write('   gsub(/"/,"",$2);');
                    child.stdin.write('   gsub("/$","",$2);');
                    child.stdin.write('   gsub(/\\\\ /," ",$2);');
                    child.stdin.write('   printf "%s/",$2;');
                    child.stdin.write("}'");
                    child.stdin.write('\nexit\n');
                    child.waitExit();
                    return (child.stdout.str.trim());
                };
                try
                {
                    Object.defineProperty(ret, 'installedDate', { value: require('fs').statSync(ret.rc).ctime });
                }
                catch (xx)
                {
                }

                ret.appLocation = function appLocation()
                {
                    if (this.OpenBSD)
                    {
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("cat " + this.rc + " | grep daemon= | awk '{ if($0 ~ /_loader\"$/) { gsub(/^daemon=/,\"\", $0); gsub(/_loader\"$/,\"\\\"\",$0); print $0; } else { gsub(/^daemon=/,\"\",$0); print $0; } }'\nexit\n");
                        child.waitExit();
                        var ret = child.stdout.str.trim();
                        if (ret != '') { ret = ret.substring(1, ret.length - 1); }
                        return (ret);
                    }
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("cat " + this.rc + " | grep command= | awk -F= '{ print $2 }' | awk -F\\\" '{ print $2 }'\nexit\n");
                    child.waitExit();
                    var tmp = child.stdout.str.trim().split('${name}').join(this.name);
                    if(tmp=='/usr/sbin/daemon')
                    {
                        child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("cat " + this.rc + " | grep command_args= | awk NR==1'");
                        child.stdin.write('{');
                        child.stdin.write('   split($0,V,"-f ");');
                        child.stdin.write('   if(V[2] ~ /^\\\\"/)');
                        child.stdin.write('   {');
                        child.stdin.write('      split(V[2],RET,"\\"");');
                        child.stdin.write('      gsub(/\\\\$/,"",RET[2]);');
                        child.stdin.write('      print RET[2];');
                        child.stdin.write('   }');
                        child.stdin.write('   else');
                        child.stdin.write('   {');
                        child.stdin.write('      split(V[2],RET," ");');
                        child.stdin.write('      print RET[1];');
                        child.stdin.write('   }');
                        child.stdin.write("}'");
                        child.stdin.write('\nexit\n');
                        child.waitExit();
                        return(child.stdout.str.trim());
                    }
                    else
                    {
                        return(tmp);
                    }
                };
                ret.isRunning = function isRunning()
                {
                    if (this.OpenBSD)
                    {
                        // OpenBSD
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stderr.on('data', function (c) { });
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write('rcctl ls started | awk \'{ if($0=="' + this.name + '") { print "STARTED"; } }\'\nexit\n');
                        child.waitExit();
                        return (child.stdout.str.trim() == '' ? false : true);
                    }
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("service " + this.name + " onestatus | awk '{ print $3 }'\nexit\n");
                    child.waitExit();
                    return (child.stdout.str.trim() == 'running');
                };
                ret.pid = function pid()
                {
                    if (this.OpenBSD)
                    {
                        // OpenBSD
                        try
                        {
                            var pid = require('fs').readFileSync('/var/run/' + this.name + '.pid');
                            return(parseInt(pid.toString().trim()));
                        }
                        catch(e)
                        {
                            return (-1);
                        }
                    }
                    else
                    {
                        // FreeBSD
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("service " + this.name + " onestatus | awk '");
                        child.stdin.write('{ split($6, res, ".");  ');
                        child.stdin.write('  cm=sprintf("ps -p %s -w", res[1]);');
                        child.stdin.write('  system(cm); ')
                        child.stdin.write('}\' | awk \'NR>1\' | awk \'');
                        child.stdin.write('{');
                        child.stdin.write('   if($5=="daemon:") { split($0, T, "["); split(T[2], X, "]"); print X[1]; } else { print $1; }');
                        child.stdin.write('}\'\nexit\n');
                        child.waitExit();
                        return (parseInt(child.stdout.str.trim()));
                    }
                };
                ret.isMe = function isMe()
                {
                    return (this.pid() == process.pid);
                };
                ret.stop = function stop()
                {
                    if (this.OpenBSD)
                    {
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("rcctl stop " + this.name + "\nexit\n");
                        child.waitExit();
                    }
                    else
                    {
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("service " + this.name + " onestop\nexit\n");
                        child.waitExit();
                    }
                };
                ret.start = function start()
                {
                    if (this.OpenBSD)
                    {
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("rcctl start " + this.name + "\nexit\n");
                        child.waitExit();
                    }
                    else
                    {
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("service " + this.name + " onestart\nexit\n");
                        child.waitExit();
                    }
                };
                ret.restart = function restart()
                {
                    if (this.isMe())
                    {
                        var parameters = this.parameters();
                        parameters.unshift(process.execPath);
                        require('child_process')._execve(process.execPath, parameters);
                        throw ('Error Restarting via execve()');
                    }

                    if (this.OpenBSD)
                    {
                        // OpenBSD
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("rcctl restart " + this.name + "\nexit\n");
                        child.waitExit();
                    }
                    else
                    {
                        // FreeBSD
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("service " + this.name + " onerestart\nexit\n");
                        child.waitExit();
                    }
                };
                ret.parameters = function parameters()
                {
                    if (this.OpenBSD)
                    {
                        var s = require('fs').readFileSync('/etc/rc.d/' + this.name).toString();

                        var loader = s.match('\ndaemon=.*\n');
                        if (loader && loader[0].match('/' + this.name + '_loader"\n$'))
                        {
                            // This is our daemon
                            var i;
                            var lines = s.split('\n');
                            for (i = 0; i < lines.length; ++i)
                            {
                                if (lines[i].match('^daemon_flags='))
                                {
                                    var b64 = lines[i].split(' ')[1];
                                    b64 = Buffer.from(b64, 'base64').toString();
                                    var match = b64.match('\\[.*\\]');
                                    match = JSON.parse(match);
                                    return (match);
                                }
                            }
                            return ([]);
                        }
                        else
                        {
                            // Non-Daemon
                            return ([]);
                        }
                    }

                    // FreeBSD
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("cat " + this.rc + ' | grep "^\\s*command_args=" | awk \'NR==1');
                    child.stdin.write('{ gsub(/^\\s*command_args=/,"",$0); gsub(/^"([^\\\\^\\/]+)/,"\\"",$0); print $0; }\'\nexit\n');
                    child.waitExit();
                    var str = JSON.parse(child.stdout.str.trim());
                    return (str.match(/(?:[^\s"]+|"[^"]*")+/g));
                };
                return (ret);
            };
        }

        if (process.platform == 'darwin')
        {
            this.getService = function getService(name) { return (fetchPlist('/Library/LaunchDaemons', name)); };
            this.getLaunchAgent = function getLaunchAgent(name, userid)
            {
                if (userid == null)
                {
                    return (fetchPlist('/Library/LaunchAgents', name));
                }
                else
                {
                    return (fetchPlist(require('user-sessions').getHomeFolder(require('user-sessions').getUsername(userid)) + '/Library/LaunchAgents', name, userid));
                }
            };
        }
        if(process.platform == 'linux')
        {
            this.getService = function getService(name, platform)
            {
                if (!platform) { platform = this.getServiceType(); }
                var ret = { name: name, close: function () { }, serviceType: platform};
                switch(platform)
                {
                    case 'procd':
                        if (!require('fs').existsSync('/etc/init.d/' + name)) { throw (platform + ' Service (' + name + ') NOT FOUND'); }
                        ret.conf = '/etc/init.d/' + name;
                        ret.appWorkingDirectory = function appWorkingDirectory()
                        {
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stderr.on('data', function (c) { });
                            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                            child.stdin.write('cat ' + this.conf + ' | grep "procd_set_param command /bin/sh " | tr ' + "'\\n' '`' | awk -F'`' '");
                            child.stdin.write('{');
                            child.stdin.write('   for(n=1;n<NF;++n)');
                            child.stdin.write('   {');
                            child.stdin.write('      if($n~/^#/) { continue; }');
                            child.stdin.write('      v=split($n,tokens,"\\"");');
                            child.stdin.write('      if(v==1) { continue; }');
                            child.stdin.write('      sh=sprintf("cat \\"%s\\"", tokens[2]);');
                            child.stdin.write('      shval=system(sh);');
                            child.stdin.write('   }');
                            child.stdin.write("}'");
                            child.stdin.write(' | grep "cd " | awk ' + "NR==1'");
                            child.stdin.write('{');
                            child.stdin.write('   gsub(/^[ \\t]+/, "", $0);');
                            child.stdin.write('   p=substr($0,4);');
                            child.stdin.write('   gsub(/"/,"",p);');
                            child.stdin.write('   gsub("/$","",p);');
                            child.stdin.write('   printf "%s/",p;');
                            child.stdin.write("}'");
                            child.stdin.write('\nexit\n');
                            child.waitExit();
                            return (child.stdout.str.trim() == '' ? '/' : child.stdout.str.trim());
                        };
                        ret.appLocation = function appLocation()
                        {
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stderr.on('data', function (c) { });
                            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                            child.stdin.write('cat ' + this.conf + ' | grep "procd_set_param command"' + " | awk NR==1'");
                            child.stdin.write('{');
                            child.stdin.write('   gsub(/^[ \\t]+/, "", $0);');
                            child.stdin.write('   cmd=substr($0, 25);')
                            child.stdin.write('   if(substr(cmd,0,8)=="/bin/sh ")');
                            child.stdin.write('   {');
                            child.stdin.write('      cmd=substr(cmd,8);');
                            child.stdin.write('      x=split(cmd,tok,"\\"");');
                            child.stdin.write('      cmd = (x==1?cmd:tok[2]);');
                            child.stdin.write('   }');
                            child.stdin.write('   print cmd;');
                            child.stdin.write("}'");
                            child.stdin.write('\nexit\n');
                            child.waitExit();

                            var ret = child.stdout.str.trim();
                            if (ret.endsWith('.sh'))
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stderr.on('data', function (c) { });
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stdin.write('cat "' +ret + '" | grep "exec "' + " | awk NR==1'");
                                child.stdin.write('{');
                                child.stdin.write('   gsub(/^[ \\t]+/, "", $0);');
                                child.stdin.write('   if($0 ~ "^exec \\"")');
                                child.stdin.write('   {');
                                child.stdin.write('      split($0,V,"\\"");');
                                child.stdin.write('      val=V[2];');
                                child.stdin.write('   }');
                                child.stdin.write('   else');
                                child.stdin.write('   {');
                                child.stdin.write('      split($0,V," ");');
                                child.stdin.write('      val=V[2];');
                                child.stdin.write('   }');
                                child.stdin.write('   gsub("^./","",val);');
                                child.stdin.write('   print val;');
                                child.stdin.write("}'");
                                child.stdin.write('\nexit\n');
                                child.waitExit();

                                ret = child.stdout.str.trim();
                                if(!ret.startsWith('/'))
                                {
                                    ret = (this.appWorkingDirectory() + ret);
                                }
                            }
                            return (ret);
                        };
                        ret.start = function start()
                        {
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stderr.on('data', function (c) { });
                            child.stdout.on('data', function (c) { });
                            child.stdin.write('/etc/init.d/' + this.name + ' start\nexit\n');
                            child.waitExit();
                        };
                        ret.stop = function stop()
                        {
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stderr.on('data', function (c) { });
                            child.stdout.on('data', function (c) { });
                            child.stdin.write('/etc/init.d/' + this.name + ' stop\nexit\n');
                            child.waitExit();
                        };
                        ret.restart = function restart()
                        {
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stderr.on('data', function (c) { });
                            child.stdout.on('data', function (c) { });
                            child.stdin.write('/etc/init.d/' + this.name + ' restart\nexit\n');
                            child.waitExit();
                        };
                        ret.isMe = function isMe() { return (true); } 
                        break;
                    case 'init':
                    case 'upstart':
                        if (require('fs').existsSync('/etc/init.d/' + name)) { platform = 'init'; }
                        if (require('fs').existsSync('/etc/init/' + name + '.conf')) { platform = 'upstart'; }
                        if ((platform == 'init' && require('fs').existsSync('/etc/init.d/' + name)) ||
                            (platform == 'upstart' && require('fs').existsSync('/etc/init/' + name + '.conf')))
                        {
                            ret.conf = (platform == 'upstart' ? ('/etc/init/' + name + '.conf') : ('/etc/init.d/' + name));
                            ret.serviceType = platform;
                            if (platform == 'init')
                            {
                                Object.defineProperty(ret, 'OpenRC', { value: require('fs').existsSync('/sbin/openrc-run') });
                                if(ret.OpenRC)
                                {
                                    Object.defineProperty(ret, '_autorestart', {
                                        value: (function ()
                                        {
                                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                                            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                            child.stderr.on('data', function () { });
                                            child.stdin.write('cat ' + ret.conf + ' | grep "^\\s*supervisor=\\"supervise-daemon\\""\nexit\n');
                                            child.waitExit();
                                            return (child.stdout.str.trim() != '');
                                        })()
                                    });
                                }
                            }
                            Object.defineProperty(ret, "startType",
                                {
                                    get: function ()
                                    {
                                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                                        child.stderr.on('data', function (c) { });
                                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                        if (this.OpenRC)
                                        {
                                            child.stdin.write('rc-status default | grep "^\\s' + this.name + ' *\\["\n\exit\n');
                                        }
                                        else
                                        {
                                            if (this.serviceType == 'upstart')
                                            {
                                                child.stdin.write('cat ' + this.conf + ' | grep "start on runlevel"\nexit\n');
                                            }
                                            else
                                            {
                                                child.stdin.write('find /etc/rc* -maxdepth 2 -type l -ls | grep " ../init.d/' + this.name + '" | awk -F"-> " \'{ if($2=="../init.d/' + this.name + '") { print "true"; } }\'\nexit\n');
                                            }
                                        }
                                        child.waitExit();
                                        return (child.stdout.str.trim() == '' ? 'DEMAND_START' : 'AUTO_START');

                                    }
                                });

                            ret.description = function description()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                if(description.platform == 'upstart')
                                {
                                    child.stdin.write("cat /etc/init/" + this.name + ".conf | grep description | awk '" + '{ if($1=="description") { $1=""; a=split($0, res, "\\""); if(a>1) { print res[2]; } else { print $0; }}}\'\nexit\n');
                                }
                                else
                                {
                                    child.stdin.write("cat /etc/init.d/" + this.name + " | grep Short-Description: | awk '" + '{ if($2=="Short-Description:") { $1=""; $2=""; print $0; }}\'\nexit\n');
                                }
                                child.waitExit();
                                return (child.stdout.str.trim());
                            }
                            ret.description.platform = platform;
                            ret.appWorkingDirectory = function appWorkingDirectory()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if (appWorkingDirectory.platform == 'init')
                                {
                                    if (this.OpenRC)
                                    {
                                        if (this._autorestart)
                                        {
                                            child.stdin.write('cat /etc/init.d/' + this.name + ' | grep "^\\s*supervise_daemon_args=" | awk \'NR==1{ split($0,A,"--chdir "); split(A[2],B,"\\\\\\\\\\""); gsub("/$","",B[2]); printf "%s/",B[2]; }\'\nexit\n');
                                        }
                                        else
                                        {
                                            child.stdin.write('cat /etc/init.d/' + this.name + ' | grep "^\\s*start_stop_daemon_args=" | awk \'NR==1{ split($0,A,"--chdir "); split(A[2],B,"\\\\\\\\\\""); gsub("/$","",B[2]); printf "%s/",B[2]; }\'\nexit\n');
                                        }
                                    }
                                    else
                                    {
                                        child.stdin.write("cat /etc/init.d/" + this.name + " | grep 'SCRIPT=' | awk -F= '{ len=split($2, a, \"/\"); print substr($2,0,length($2)-length(a[len])); }'\nexit\n");
                                    }
                                }
                                else
                                {
                                    child.stdin.write("cat /etc/init/" + this.name + ".conf | grep 'chdir ' | awk '");
                                    child.stdin.write('{');
                                    child.stdin.write('   if(split($0,v,"\\\"")>1)');
                                    child.stdin.write('   {');
                                    child.stdin.write('      gsub(/\\/$/,"",v[2]);');
                                    child.stdin.write('      print v[2];');
                                    child.stdin.write('   }');
                                    child.stdin.write('   else');
                                    child.stdin.write('   {');
                                    child.stdin.write('      gsub(/\\/$/,"",$2);');
                                    child.stdin.write('      print $2;');
                                    child.stdin.write('   }');
                                    child.stdin.write("}'");
                                    child.stdin.write('\nexit\n');

                                }
                                child.waitExit();
                                if (child.stdout.str.trim() == '') { return ('/'); }
                                return (child.stdout.str.trim());
                            };
                            ret.appWorkingDirectory.platform = platform;
                            ret.appLocation = function appLocation()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if (appLocation.platform == 'init')
                                {
                                    if (this.OpenRC)
                                    {
                                        child.stdin.write('cat /etc/init.d/' + this.name + ' | grep "\\s*command=" | awk \'NR==1{ split($0,A,"\\""); print A[2]; }\'\nexit\n');
                                    }
                                    else
                                    {
                                        child.stdin.write("cat /etc/init.d/" + this.name + " | grep 'SCRIPT=' | awk -F= '{print $2}'\nexit\n");
                                    }
                                }
                                else
                                {
                                    child.stdin.write("cat /etc/init/" + this.name + ".conf | grep 'exec ' | awk '");
                                    child.stdin.write('{');
                                    child.stdin.write('   if(split($0,v,"\\\"")>1)');
                                    child.stdin.write('   {');
                                    child.stdin.write('      print v[2];');
                                    child.stdin.write('   }');
                                    child.stdin.write('   else');
                                    child.stdin.write('   {');
                                    child.stdin.write('      print $2;');
                                    child.stdin.write('   }');
                                    child.stdin.write("}'");
                                    child.stdin.write('\nexit\n');
                                }
                                child.waitExit();
                                return (child.stdout.str.trim());
                            };
                            ret.appLocation.platform = platform;
                            ret.isMe = function isMe()
                            {
                                if (this.OpenRC)
                                {
                                    return (this.pid() == process.pid);
                                }
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if (isMe.platform == 'upstart')
                                {
                                    child.stdin.write("initctl status " + this.name + " | awk '{print $NF}'\nexit\n");
                                }
                                else
                                {
                                    child.stdin.write("service " + this.name + " status | awk '");
                                    child.stdin.write('{');
                                    child.stdin.write('   sh=sprintf("ps -e -o pid -o ppid | grep %s", $NF);');
                                    child.stdin.write('   shval=system(sh);');
                                    child.stdin.write("}'");
                                    child.stdin.write(' | tr ' + "'\\n' '`' | awk -F'`' '");
                                    child.stdin.write('{');
                                    child.stdin.write('   root="";');
                                    child.stdin.write('   pid="";');
                                    child.stdin.write('   for(n=1;n<NF;++n)');
                                    child.stdin.write('   {');
                                    child.stdin.write('      split($n, i, " ");');
                                    child.stdin.write('      if(i[2]=="1") { root=i[1]; } else { pid=i[1]; }');
                                    child.stdin.write('   }');
                                    child.stdin.write('   printf("%s", pid==""?root:pid);');
                                    child.stdin.write("}'\nexit\n");
                                }
                                child.waitExit();
                                return (parseInt(child.stdout.str.trim()) == process.pid);
                            };
                            ret.isMe.platform = platform;
                            ret.isRunning = function isRunning()
                            {
                                if (this.OpenRC) { return (!isNaN(this.pid())); }
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if (isRunning.platform == 'upstart')
                                {
                                    child.stdin.write("initctl status " + this.name + " | awk '{print $2}' | awk -F, '{print $1}'\nexit\n");
                                }
                                else
                                {
                                    child.stdin.write("service " + this.name + " status | awk '{print $2}' | awk -F, '{print $1}'\nexit\n");
                                }
                                child.waitExit();
                                return (child.stdout.str.trim() == 'start/running');
                            };
                            ret.isRunning.platform = platform;
                            ret.start = function start()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh'], this.OpenRC ? { type: require('child_process').SpawnTypes.TERM } : null);
                                child.stdout.on('data', function (chunk) { });
                                if (start.platform == 'upstart')
                                {
                                    child.stdin.write('initctl start ' + this.name + '\nexit\n');
                                }
                                else
                                {
                                    child.stdin.write('service ' + this.name + ' start\nexit\n');
                                }
                                child.waitExit();
                            };
                            ret.start.platform = platform;
                            ret.stop = function stop()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh'], this.OpenRC ? { type: require('child_process').SpawnTypes.TERM } : null);
                                child.stdout.on('data', function (chunk) { });
                                if (stop.platform == 'upstart')
                                {
                                    child.stdin.write('initctl stop ' + this.name + '\nexit\n');
                                }
                                else
                                {
                                    child.stdin.write('service ' + this.name + ' stop\nexit\n');
                                }
                                child.waitExit();
                            };
                            ret.stop.platform = platform;
                            ret.restart = function restart()
                            {
                                if (this.isMe() && this.OpenRC)
                                {
                                    // On OpenRC platforms, we cannot restart our own service using rc-service, so we must use execv
                                    var args = this.parameters();
                                    args.unshift(process.execPath);
                                    require('child_process')._execve(process.execPath, args);
                                }
                                else
                                {
                                    var child = require('child_process').execFile('/bin/sh', ['sh'], this.OpenRC ? { type: require('child_process').SpawnTypes.TERM } : null);
                                    child.stdout.on('data', function (chunk) { });
                                    if (restart.platform == 'upstart')
                                    {
                                        child.stdin.write('initctl restart ' + this.name + '\nexit\n');
                                    }
                                    else
                                    {
                                        child.stdin.write('service ' + this.name + ' restart\nexit\n');
                                    }
                                    child.waitExit();
                                }
                            };
                            ret.restart.platform = platform;
                            ret.status = function status()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout._str = '';
                                child.stdout.on('data', function (chunk) { this._str += chunk.toString(); });
                                if (status.platform == 'upstart')
                                {
                                    child.stdin.write('initctl status ' + this.name + '\nexit\n');
                                }
                                else
                                {
                                    if (this.OpenRC)
                                    {
                                        child.stdin.write('rc-status | grep "\\s*' + this.name + ' "\nexit\n');
                                    }
                                    else
                                    {
                                        child.stdin.write('service ' + this.name + ' status\nexit\n');
                                    }
                                }
                                child.waitExit();
                                return (child.stdout._str);
                            };
                            if (ret.OpenRC)
                            {
                                ret.pid = function pid()
                                {
                                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                    child.stderr.on('data', function () { });
                                    if (this._autorestart)
                                    {
                                        child.stdin.write('cat /var/run/' + this.name + ".pid | awk 'NR==1{ sh=sprintf(\"ps -o pid -o ppid | grep %s\",$0); system(sh); }' | awk '{ if($2!=\"1\") { print $1; }}' | awk 'NR==1{ print $0; }'\nexit\n");
                                    }
                                    else
                                    {
                                        child.stdin.write('cat /var/run/' + this.name + '.pid\nexit\n');
                                    }
                                    child.waitExit();
                                    return (parseInt(child.stdout.str.trim()));
                                }
                                ret.parameters = function()
                                {
                                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                    child.stderr.on('data', function () { });
                                    child.stdin.write('cat ' + this.conf + ' | grep "^\\s*command_args=" | awk \'NR==1{ gsub(/^\\s*command_args=/,"",$0); print $0; }\'\nexit\n');
                                    child.waitExit();
                                    var val = JSON.parse(child.stdout.str.trim());
                                    val = val.match(/(?:[^\s"]+|"[^"]*")+/g);
                                    return (val);
                                }
                            }
                            ret.status.platform = platform;
                            if(platform == "upstart")
                            {
                                ret.parameters = function parameters()
                                {
                                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                                    child.stdout._str = '';
                                    child.stdout.on('data', function (chunk) { this._str += chunk.toString(); });
                                    child.stdin.write('cat ' + this.conf + ' | grep "^exec " | awk \'NR==1{ gsub(/^exec /,"",$0); print $0; }\'\nexit\n');
                                    child.waitExit();
                                    var str = child.stdout._str.trim();
                                    return (str.match(/(?:[^\s"]+|"[^"]*")+/g));

                                };
                            }
                        }
                        else
                        {
                            throw (platform + ' Service (' + name + ') NOT FOUND');
                        }
                        break;
                    case 'systemd':
                        var tries = 0;
                        do
                        {
                            ret.escname = tries == 0 ? this.escape(name) : name;
                            if (require('fs').existsSync('/lib/systemd/system/' + ret.escname + '.service'))
                            {
                                ret.conf = '/lib/systemd/system/' + ret.escname + '.service';
                            }
                            else if (require('fs').existsSync('/usr/lib/systemd/system/' + ret.escname + '.service'))
                            {
                                ret.conf = '/usr/lib/systemd/system/' + ret.escname + '.service';
                            }
                        } while (ret.conf == null && tries++<1);

                        if (ret.conf)
                        {
                            Object.defineProperty(ret, "startType",
                                {
                                    get: function ()
                                    {
                                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                                        child.stderr.on('data', function (c) { });
                                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                        child.stdin.write('systemctl status ' + this.escname.split('\\').join('\\\\') + ' | grep Loaded: | awk \'{ a=split($0, b, ";"); for(c=1;c<=a;++c) { if(b[c]=="enabled" || b[c]==" enabled") { print "true"; } } }\'\nexit\n');
                                        child.waitExit();
                                        return (child.stdout.str.trim() == '' ? 'DEMAND_START' : 'AUTO_START');
                                    }
                                });
                            ret.description = function description()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                if (require('fs').existsSync('/lib/systemd/system/' + this.escname.split('\\').join('\\\\') + '.service'))
                                {
                                    console.info1('cat /lib/systemd/system/' + this.escname.split('\\').join('\\\\') + '.service')
                                    child.stdin.write('cat /lib/systemd/system/' + this.escname.split('\\').join('\\\\') + '.service');
                                }
                                else
                                {
                                    console.info1('cat /usr/lib/systemd/system/' + this.escname.split('\\').join('\\\\') + '.service')
                                    child.stdin.write('cat /usr/lib/systemd/system/' + this.escname.split('\\').join('\\\\') + '.service');
                                }
                                child.stdin.write(' | grep Description= | awk -F= \'{ if($1=="Description") { $1=""; print $0; }}\'\nexit\n');
                                child.waitExit();
                                return (child.stdout.str.trim());
                            }
                            ret.appWorkingDirectory = function appWorkingDirectory()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if (require('fs').existsSync('/lib/systemd/system/' + this.escname.split('\\').join('\\\\') + '.service'))
                                {
                                    child.stdin.write("cat /lib/systemd/system/" + this.escname.split('\\').join('\\\\') + ".service | grep 'WorkingDirectory=' | awk 'NR==1" + '{ gsub(/^.+=/,"",$0); gsub("/$","",$0); printf "%s/",$0; }\'\n\exit\n');
                                }
                                else
                                {
                                    child.stdin.write("cat /usr/lib/systemd/system/" + this.escname.split('\\').join('\\\\') + ".service | grep 'WorkingDirectory=' | awk 'NR==1" + '{ gsub(/^.+=/,"",$0); gsub("/$","",$0); printf "%s/",$0; }\'\n\exit\n');
                                }
                                child.waitExit();
                                return (child.stdout.str.trim());
                            };
                            ret.appLocation = function ()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if (require('fs').existsSync('/lib/systemd/system/' + this.escname.split('\\').join('\\\\') + '.service'))
                                {
                                    child.stdin.write("cat /lib/systemd/system/" + this.escname.split('\\').join('\\\\') + ".service | grep 'ExecStart=' | awk -F= '");
                                }
                                else
                                {
                                    child.stdin.write("cat /usr/lib/systemd/system/" + this.escname.split('\\').join('\\\\') + ".service | grep 'ExecStart=' | awk -F= '");
                                }
                                child.stdin.write('{');
                                child.stdin.write('   split($2, a, " ");');
                                child.stdin.write('   gsub(/-/,"\\\\x2d",a[1]);');
                                child.stdin.write('   sh=sprintf("systemd-escape -u \\"%s\\"",a[1]);');
                                child.stdin.write('   system(sh);')
                                child.stdin.write("}'\nexit\n");
                                child.waitExit();
                                return (child.stdout.str.trim());
                            };
                            ret.isMe = function isMe()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                console.info1("systemctl status " + this.escname.split('\\').join('\\\\') + ".service");
                                child.stdin.write("systemctl status " + this.escname.split('\\').join('\\\\') + ".service | grep 'Main PID:' | awk 'NR==1{print $3}'\nexit\n");
                                child.waitExit();
                                return (parseInt(child.stdout.str.trim()) == process.pid);
                            };
                            ret.isRunning = function isRunning()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                child.stdin.write("systemctl status " + this.escname.split('\\').join('\\\\') + ".service | grep 'Active:' | awk 'NR==1{print $2}'\nexit\n");
                                child.waitExit();
                                return (child.stdout.str.trim() == 'active');         
                            };
                            ret.start = function start()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh'], { type: require('child_process').SpawnTypes.TERM });
                                child.stdout.on('data', function (chunk) { });
                                child.stdin.write('systemctl start ' + this.escname.split('\\').join('\\\\') + '.service\nexit\n');
                                child.waitExit();
                            };
                            ret.stop = function stop() {
                                var child = require('child_process').execFile('/bin/sh', ['sh'], { type: require('child_process').SpawnTypes.TERM });
                                child.stdout.on('data', function (chunk) { });
                                child.stdin.write('systemctl stop ' + this.escname.split('\\').join('\\\\') + '.service\nexit\n');
                                child.waitExit();
                            };
                            ret.restart = function restart() {
                                var child = require('child_process').execFile('/bin/sh', ['sh'], { type: require('child_process').SpawnTypes.TERM });
                                child.stdout.on('data', function (chunk) { });
                                child.stdin.write('systemctl restart ' + this.escname.split('\\').join('\\\\') + '.service\nexit\n');
                                child.waitExit();
                            };
                            ret.status = function status() {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout._str = '';
                                child.stdout.on('data', function (chunk) { this._str += chunk.toString(); });
                                child.stdin.write('systemctl status ' + this.escname.split('\\').join('\\\\') + '.service\nexit\n');
                                child.waitExit();
                                return (child.stdout._str);
                            };
                            ret.parameters = function parameters()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout._str = '';
                                child.stdout.on('data', function (chunk) { this._str += chunk.toString(); });
                                child.stdin.write('cat ' + this.conf.split('\\').join('\\\\') + ' | grep "^ExecStart=" | awk \'NR==1{ gsub(/^ExecStart=/,"",$0); print $0; }\'\nexit\n');
                                child.waitExit();
                                var str = child.stdout._str.trim();
                                return (str.match(/(?:[^\s"]+|"[^"]*")+/g));
                            };
                        }
                        else
                        {
                            throw (platform + ' Service (' + name + ') NOT FOUND');
                        }
                        break;
                    default:
                        // Pseudo Service (meshDaemon)
                        if (require('fs').existsSync('/usr/local/mesh_daemons/' + name + '.service'))
                        {
                            ret.conf = '/usr/local/mesh_daemons/' + name + '.service';
                            ret.parameters = function parameters()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stderr.on('data', function (c) { });
                                child.stdin.write('cat ' + this.conf + ' | grep "^[ \\t]*parameters=" | awk \'NR==1{ gsub(/^[ \t]*parameters=/,"",$0); print $0; }\'\nexit\n');
                                child.waitExit();
                                try
                                {
                                    return (JSON.parse(child.stdout.str.trim()));
                                }
                                catch(e)
                                {
                                    return ([]);
                                }
                            };
                            ret.start = function start()
                            {
                                var child;
                                child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stderr.on('data', function (c) {  });
                                child.stdin.write('cat ' + this.conf + ' | grep "^[ \\t]*respawn$"\nexit\n');
                                child.waitExit();

                                var respawn = child.stdout.str.trim() != '';
                                var wd = this.appWorkingDirectory();
                                var parameters = this.parameters();
                                var location = wd + parameters.shift();

                                var options = { pidPath: wd + 'pid', logOutputs: true, crashRestart: respawn, cwd: wd };
                                require('service-manager').manager.daemon(location, parameters, options);
                            };
                            ret.stop = function stop()
                            {
                                var pidpath = this.appWorkingDirectory().split(' ').join('\\ ') + 'pid';
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stdin.write('cat ' + pidpath + '\nexit\n');
                                child.waitExit();
                                try
                                {
                                    process.kill(parseInt(child.stdout.str.trim()), 'SIGTERM');
                                }
                                catch(x)
                                {
                                }
                            };
                            ret.restart = function restart()
                            {
                                if(!this.isMe())
                                {
                                    this.stop();
                                    this.start();
                                    return;
                                }

                                var p = this.parameters();
                                p.unshift(process.execPath);
                                require('child_process')._execve(process.execPath, p);
                            }
                            ret.isMe = function isMe()
                            {
                                var pidpath = this.appWorkingDirectory().split(' ').join('\\ ') + 'pid';
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stdin.write('cat ' + pidpath + '\nexit\n');
                                child.waitExit();
                                var pid = child.stdout.str.trim();
                                if (pid == '') { return (false); }

                                child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stdin.write('ps -e -o pid -o ppid | grep "[ \\t]*' + pid + '$" | awk \'NR==1{ print $1; }\'\nexit\n');
                                child.waitExit();

                                return (parseInt(child.stdout.str.trim()) == process.pid);
                            };
                            ret.appWorkingDirectory = function appWorkingDirectory()
                            {
                                var child;
                                child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stderr.on('data', function (c) { });
                                child.stdin.write('cat ' + this.conf + " | grep 'workingDirectory=' | awk 'NR==1" +  '{ gsub(/^.+=/,"",$0); gsub("/$","",$0); printf "%s/",$0; }\'\nexit\n');
                                child.waitExit();
                                return (child.stdout.str.trim());
                            };
                            ret.appLocation = function appLocation()
                            {
                                return (this.appWorkingDirectory() + this.parameters().shift());
                            };
                            ret.isRunning = function isRunning()
                            {
                                var pidpath = this.appWorkingDirectory() + 'pid';
                                console.log('pidpath', pidpath);

                                if(require('fs').existsSync(pidpath))
                                {
                                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                    child.stdin.write('cat ' + pidpath.split(' ').join('\\ ') + '\nexit\n');
                                    child.waitExit();
                                    var pid = child.stdout.str.trim();

                                    child = require('child_process').execFile('/bin/sh', ['sh']);
                                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                    child.stdin.write('ps -p ' + pid + ' -o pid h\nexit\n');
                                    child.waitExit();
                                    if(child.stdout.str.trim() == pid)
                                    {
                                        return (true);
                                    }
                                    else
                                    {
                                        try
                                        {
                                            require('fs').unlinkSync('/usr/local/mesh_daemons/' + name + '/pid');
                                        }
                                        catch(x)
                                        {
                                        }
                                        return (false);
                                    }
                                }
                                else
                                {
                                    return (false);
                                }
                            };
                        }
                        else
                        {
                            throw ('MeshDaemon (' + name + ') NOT FOUND');
                        }
                        break;
                }
                try
                {
                    Object.defineProperty(ret, 'installedDate', { value: require('fs').statSync(ret.conf).ctime });
                }
                catch (xx)
                {
                    console.log(xx);
                }
                return (ret);
            };
        }
        this.enumerateService = function (options)
        {
            var results = [];
            var paths = [];
            var runtable = {};
            switch(process.platform)
            {
                case 'linux':
                    switch((options && options.platformType)?options.platformType : this.getServiceType())
                    {
                        case 'init':
                            paths.push('/etc/init.d');
                            break;
                        case 'upstart':
                            paths.push('/etc/init');
                            runtable = _upstart_GetServiceTable();
                            break;
                        case 'systemd':
                            paths.push('/lib/systemd/system');
                            paths.push('/usr/lib/systemd/system');
                            runtable = _systemd_GetServiceTable();
                            break;
                        default:
                            paths.push('/usr/local/mesh_daemons');
                            break;
                    }
                    break;
                case 'freebsd':
                    paths.push('/etc/rc.d');
                    paths.push('/usr/local/etc/rc.d');
                    break;
                case 'darwin':
                    paths.push('/Library/LaunchDaemons');
                    paths.push('/System/Library/LaunchDaemons');
                    break;
            }

            for(var i in paths)
            {
                var files = require('fs').readdirSync(paths[i]);
                for(var j in files)
                {
                    switch(process.platform)
                    {
                        case 'linux':
                            switch ((options && options.platformType) ? options.platformType : this.getServiceType())
                            {
                                case 'init':
                                    try
                                    {
                                        results.push(this.getService(files[j], 'init'));
                                    }
                                    catch (e)
                                    {
                                    }
                                    break;
                                case 'upstart':
                                    if (files[j].endsWith('.conf'))
                                    {
                                        try
                                        {
                                            results.push(this.getService(files[j].split('.conf')[0], 'upstart'));
                                            if(runtable[results.peek().name])
                                            {
                                                results.peek().state = runtable[results.peek().name].state;
                                                if(runtable[results.peek().name].pid != '')
                                                {
                                                    try
                                                    {
                                                        results.peek().pid = parseInt(runtable[results.peek().name].pid);
                                                    }
                                                    catch(px)
                                                    {
                                                    }
                                                }
                                            }
                                        }
                                        catch (e)
                                        {
                                        }
                                    }
                                    break;
                                case 'systemd':
                                    if (files[j].endsWith('.service'))
                                    {
                                        try
                                        {
                                            results.push(this.getService(files[j].split('.service')[0], 'systemd'));
                                            if (runtable[results.peek().conf.split('/').pop()]) { results.peek().state = 'RUNNING'; }
                                        }
                                        catch(e)
                                        {
                                        }
                                    }
                                    break;
                                default:
                                    if (files[j].endsWith('.service'))
                                    {
                                        try
                                        {
                                            results.push(this.getService(files[j].split('.service')[0], 'unknown'));
                                        }
                                        catch (e)
                                        {
                                        }
                                    }
                                    break;
                            }
                            break;
                        case 'freebsd':
                            try
                            {
                                results.push(this.getService(files[j]));
                            }
                            catch (e)
                            {
                            }
                            break;
                        case 'darwin':
                            if (files[j].endsWith('.plist'))
                            {
                                try
                                {
                                    results.push(fetchPlist(paths[i], files[j].split('.plist')[0]));
                                }
                                catch (e)
                                {
                                }
                            }
                            break;
                    }
                }
            }
            for (var k in results)
            {
                if (results[k].description) { results[k].description = results[k].description(); }
            }
            return (results);
        };
    }
    this.installService = function installService(options)
    {
        if (process.platform == 'linux') { options.name = this.escape(options.name); }
        if (!options.target) { options.target = options.name; }
        if (!options.displayName) { options.displayName = options.name; }
        if (options.installPath && options.installInPlace) { throw ('Cannot specify both installPath and installInPlace'); }
        if (process.platform != 'win32')
        {
            if (!options.servicePlatform) { options.servicePlatform = this.getServiceType(); }
            if (options.servicePlatform == 'systemd') { options.target = options.target.split("'").join('-'); }
            if (options.installInPlace)
            {
                options.installPath = options.servicePath.split('/');
                if(options.installPath.length>1)
                {
                    options.installPath.pop();
                    options.installPath = options.installPath.join('/');
                }
                else
                {
                    options.installPath = '/';
                }
            }
            if (options.installPath == null)
            {
                if (options.servicePlatform == 'unknown')
                {
                    options.installPath = '/usr/local/mesh_daemons/' + (options.companyName!=null?(options.companyName + '/'):('')) + options.name;
                }
                else
                {
                    options.installPath = '/usr/local/mesh_services/' + (options.companyName != null ? (options.companyName + '/') : ('')) + this.unescape(options.name).split("'").join('-');
                }
            }
        }
        if (options.installPath) { if (!options.installPath.endsWith(process.platform == 'win32' ? '\\' : '/')) { options.installPath += (process.platform == 'win32' ? '\\' : '/'); } }
        console.info1('Service Install Path = ' + options.installPath);
        if (process.platform == 'win32')
        {
            var reg = require('win-registry');
            if (!this.isAdmin()) { throw ('Installing as Service, requires admin'); }

            // Before we start, we need to copy the binary to the right place
            if(!options.installPath)
            {
                options.installPath = this.getProgramFolder();
                switch(options.companyName)
                {
                    case null:
                        options.installPath += ('\\mesh\\' + options.name + '\\');
                        break;
                    case '':
                        options.installPath += ('\\' + options.name + '\\');
                        break;
                    default:
                        options.installPath += ('\\' + options.companyName + '\\' + options.name + '\\');
                        break;
                }
            }
            if (!options.installInPlace) { prepareFolders(options.installPath); }
            if (options.servicePath == process.execPath) { options._isMeshAgent = true; }

            if (!options.installInPlace)
            {
                if (options.servicePath != (options.installPath + options.target + '.exe'))
                {
                    require('fs').copyFileSync(options.servicePath, options.installPath + options.target + '.exe');
                }
                options.servicePath = options.installPath + options.target + '.exe';
            }
            else
            {
                options.servicePath = process.execPath;
                options.installPath = process.execPath.split('\\');
                options.installPath.pop();
                options.installPath = options.installPath.join('\\') + '\\';
            }

            console.info1('   Install Path = ' + options.installPath);
            console.info1('   OpenSCManagerA()');
            var servicePath = this.GM.CreateVariable('"' + options.servicePath + '"', { wide: true });
            var handle = this.proxy.OpenSCManagerA(0x00, 0x00, 0x0002);
            if (handle.Val == 0) { throw ('error opening SCManager'); }
            console.info1('      => SUCCESS');
            var serviceName = this.GM.CreateVariable(options.name, { wide: true });
            var displayName = this.GM.CreateVariable(options.displayName, { wide: true});
            var allAccess = 0x000F01FF;
            var serviceType;
            

            switch (options.startType) {
                case 'AUTO_START':
                    serviceType = 0x02; // Automatic
                    console.info1('   startType = automatic');
                    break;
                case 'DEMAND_START':
                default:
                    serviceType = 0x03; // Manual
                    console.info1('   startType = manual');
                    break;
                case 'DISABLED':
                    serviceType = 0x04; // Disabled
                    console.info1('   startType = disabled');
                    break;
            }

            console.info1('   CreateServiceW()');
            var h = this.proxy.CreateServiceW(handle, serviceName, displayName, allAccess, 0x10 | 0x100, serviceType, 0, servicePath, 0, 0, 0, 0, 0);
            if (h.Val == 0) { this.proxy.CloseServiceHandle(handle); throw ('Error Creating Service: ' + this.proxy2.GetLastError().Val); }
            console.info1('      => SUCCESS');

            if (options.description)
            {
                var dsc = this.GM.CreateVariable(options.description, { wide: true });
                var serviceDescription = this.GM.CreateVariable(this.GM.PointerSize);
                dsc.pointerBuffer().copy(serviceDescription.Deref(0, this.GM.PointerSize).toBuffer());

                if (this.proxy.ChangeServiceConfig2W(h, 1, serviceDescription).Val == 0)
                {
                    console.log('unable to set description...');
                }
            }
            if (options.failureRestart == null || options.failureRestart > 0)
            {
                var delay = options.failureRestart == null ? 5000 : options.failureRestart;             // Delay in milliseconds
                var actions = this.GM.CreateVariable(3 * 8);                                            // 3*sizeof(SC_ACTION)
                actions.Deref(0, 4).toBuffer().writeUInt32LE(1);                                        // SC_ACTION[0].type
                actions.Deref(4, 4).toBuffer().writeUInt32LE(delay);                                     // SC_ACTION[0].delay
                actions.Deref(8, 4).toBuffer().writeUInt32LE(1);                                        // SC_ACTION[1].type
                actions.Deref(12, 4).toBuffer().writeUInt32LE(delay);                                    // SC_ACTION[1].delay
                actions.Deref(16, 4).toBuffer().writeUInt32LE(1);                                       // SC_ACTION[2].type
                actions.Deref(20, 4).toBuffer().writeUInt32LE(delay);                                    // SC_ACTION[2].delay

                var failureActions = this.GM.CreateVariable(40);                                        // sizeof(SERVICE_FAILURE_ACTIONS)
                failureActions.Deref(0, 4).toBuffer().writeUInt32LE(7200);                              // dwResetPeriod: 2 Hours
                failureActions.Deref(this.GM.PointerSize == 8 ? 24 : 12, 4).toBuffer().writeUInt32LE(3);// cActions: 3
                actions.pointerBuffer().copy(failureActions.Deref(this.GM.PointerSize == 8 ? 32 : 16, this.GM.PointerSize).toBuffer());
                if (this.proxy.ChangeServiceConfig2W(h, 2, failureActions).Val == 0)
                {
                    console.log('Unable to set FailureActions...');
                }
            }
            this.proxy.CloseServiceHandle(h);
            this.proxy.CloseServiceHandle(handle);

            if (options.parameters)
            {
                try
                {
                    var imagePath = reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + options.name, 'ImagePath');
                    imagePath += (' ' + options.parameters.join(' '));
                    reg.WriteKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + options.name, 'ImagePath', imagePath);
                }
                catch(xxx)
                {
                    console.info1(xxx);
                }
            }

            try
            {
                reg.WriteKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + options.name, '_InstalledBy', reg.usernameToUserKey(require('user-sessions').getProcessOwnerName(process.pid).name));
            }
            catch (xx)
            {
            }


            if (options._isMeshAgent)
            {
                //
                // For now, we'll only provide an uninstaller if the binary is the mesh agent binary, so we
                // won't need to copy the binary to run the uninstall script
                //
                var script = Buffer.from("try{require('service-manager').manager.uninstallService('" + options.name + "');}catch(x){}process.exit();").toString('base64');
                try
                {
                    reg.WriteKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + options.name, 'DisplayName', options.displayName);
                    reg.WriteKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + options.name, 'DisplayIcon', options.servicePath);
                    reg.WriteKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + options.name, 'InstallDate', new Date().toISOString().slice(0,10).replace(/-/g,""));
                    if (options.publisher) { reg.WriteKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + options.name, 'Publisher', options.publisher); }
                    reg.WriteKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + options.name, 'InstallLocation', options.installPath);
                    reg.WriteKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + options.name, 'EstimatedSize', Math.floor(require('fs').statSync(options.servicePath).size / 1024));
                    reg.WriteKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + options.name, 'NoModify', 0x1);
                    reg.WriteKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + options.name, 'NoRepair', 0x1);
                    if (options.name == 'Mesh Agent' || options._installer == true)
                    {
                        reg.WriteKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + options.name, 'UninstallString', options.servicePath + ' -funinstall --meshServiceName="' + options.name + '"');
                    }
                    else
                    {
                        reg.WriteKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + options.name, 'UninstallString', options.servicePath + ' -b64exec ' + script);
                    }
                    reg.WriteKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + options.name, 'DisplayVersion', process.versions.commitDate.toString());
                }
                catch (xx)
                {
                }
            }
        }
        else
        {
            if (options.installPath == null) { options.installPath = '/usr/local/mesh_services/' + options.name + '/'; }
            prepareFolders(options.installPath);

            if (options.binary)
            {
                require('fs').writeFileSync(options.installPath + options.target, options.binary);
            }
            else
            {
                if (options.servicePath != (options.installPath + options.target))
                {
                    require('fs').copyFileSync(options.servicePath, options.installPath + options.target);
                }
            }
            console.info1('Files Copied');
            var m = require('fs').statSync(options.installPath + options.target).mode;
            m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
            require('fs').chmodSync(options.installPath + options.target, m);
        }
        if (process.platform == 'freebsd')
        {
            if (!this.isAdmin()) { console.log('Installing a Service requires root'); throw ('Installing as Service, requires root'); }
            var parameters = options.parameters ? options.parameters.join(' ') : '';
            var m;
            if (require('fs').existsSync('/usr/sbin/daemon'))
            {
                // FreeBSD
                var rc = require('fs').createWriteStream('/usr/local/etc/rc.d/' + options.name, { flags: 'wb' });
                rc.write('#!/bin/sh\n');
                rc.write('# PROVIDE: ' + options.name + '\n');
                rc.write('# REQUIRE: FILESYSTEMS NETWORKING\n');
                rc.write('# KEYWORD: shutdown\n');
                rc.write('. /etc/rc.subr\n\n');
                rc.write('name="' + options.name + '"\n');
                rc.write('desc="' + (options.description ? options.description : 'MeshCentral Agent') + '"\n');
                rc.write('rcvar=${name}_enable\n');
                rc.write('pidfile="/var/run/' + options.name + '.pid"\n');
                rc.write(options.name + '_chdir="' + options.installPath.split(' ').join('\\ ') + '"\n');

                rc.write('command="/usr/sbin/daemon"\n');
                rc.write('command_args="-P ${pidfile} ' + ((options.failureRestart == null || options.failureRestart > 0) ? '-r' : '') + ' -f \\"' + options.installPath + options.target + '\\" ' + parameters.split('"').join('\\"') + '"\n');

                rc.write('\n');
                rc.write('load_rc_config $name\n');
                rc.write(': ${' + options.name + '_enable="' + ((options.startType == 'AUTO_START' || options.startType == 'BOOT_START') ? 'YES' : 'NO') + '"}\n');
                rc.write('run_rc_command "$1"\n');
                rc.end();
                m = require('fs').statSync('/usr/local/etc/rc.d/' + options.name).mode;
                m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
                require('fs').chmodSync('/usr/local/etc/rc.d/' + options.name, m);
            }
            else
            {
                // OpenBSD
                var script = "require('service-manager').manager.daemonEx('" + options.installPath + options.target + "', " + JSON.stringify(options.parameters) + ", {crashRestart: " + ((options.failureRestart == null || options.failureRestart > 0) ? "true" : "false") + ', cwd: "' + options.installPath.split(' ').join('\\ ') + '"});';
                script = Buffer.from(script).toString('base64');

                var rc = require('fs').createWriteStream('/etc/rc.d/' + options.name, { flags: 'wb' });
                rc.write('#!/bin/sh\n');
                rc.write('# PROVIDE: ' + options.name + '\n');
                rc.write('name="' + options.name + '"\n');
                rc.write('desc="' + (options.description ? options.description : 'MeshCentral Agent') + '"\n');
                rc.write(options.name + '_chdir="' + options.installPath.split(' ').join('\\ ') + '"\n');
                rc.write('daemon="' + options.installPath + options.target + '_loader"\n');
                rc.write('daemon_flags="-b64exec ' + script + ' &"\n');
                rc.write('. /etc/rc.d/rc.subr\n\n');
                rc.write('rc_cmd "$1"\n');
                rc.end();
                m = require('fs').statSync('/etc/rc.d/' + options.name).mode;
                m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
                require('fs').chmodSync('/etc/rc.d/' + options.name, m);

                require('fs').copyFileSync(process.execPath, options.installPath + options.target + '_loader');
                require('fs').chmodSync(options.installPath + options.target + '_loader', m);
                if(options.startType == 'AUTO_START' || options.startType == 'BOOT_START')
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("rcctl enable " + options.name + "\nexit\n");
                    child.waitExit();
                }
            }

            if ((this.pfSense || this.OPNsense) && (options.startType == 'AUTO_START' || options.startType == 'BOOT_START'))
            {
                if (this.pfSense)
                {
                    // pfSense requries scripts in rc.d to end with .sh, unlike other *bsd, for AUTO_START to work
                    require('fs').copyFileSync('/usr/local/etc/rc.d/' + options.name, '/usr/local/etc/rc.d/' + options.name + '.sh');
                    require('fs').chmodSync('/usr/local/etc/rc.d/' + options.name + '.sh', m);
                }
                if (this.OPNsense)
                {
                    // OPNsense requires a syshook start script
                    var s = require('fs').createWriteStream('/usr/local/etc/rc.syshook.d/start/50-' + options.name.split(' ').join(''), { flags: 'wb' });
                    s.write('#!/bin/sh\n');
                    s.write('echo -n "Starting ' + options.name + ': "\n');
                    s.write('service "' + options.name + '" start\n\n');
                    s.end();
                    require('fs').chmodSync('/usr/local/etc/rc.syshook.d/start/50-' + options.name.split(' ').join(''), m);
                }

                // pfSense and OPNsense needs to have rc.conf.local override enable, for AUTO_START to work correctly, unlike other *BSD
                var s = require('fs').createWriteStream('/etc/rc.conf.local', { flags: 'a' });
                s.write('\n' + options.name + '_enable="YES"\n');
                s.end();
            }
        }
        if(process.platform == 'linux')
        {
            if (!this.isAdmin()) { console.log('Installing a Service requires root'); throw ('Installing as Service, requires root'); }
            var parameters = options.parameters ? options.parameters.join(' ') : '';
            var conf;
           
            switch (options.servicePlatform)
            {
                case 'procd':
                    var conf = require('fs').createWriteStream('/etc/init.d/' + options.name, { flags: 'wb' });    
                    conf.write('#!/bin/sh /etc/rc.common\n');
                    conf.write('USE_PROCD=1\n');
                    conf.write('START=95\n');
                    conf.write('STOP=01\n');
                    conf.write('start_service()\n');
                    conf.write('{\n');
                    conf.write('    procd_open_instance\n');
                    conf.write('    procd_set_param command /bin/sh "' + options.installPath + options.name + '.sh"\n');
                    if (options.failureRestart == null || options.failureRestart > 0)
                    {
                        conf.write('    procd_set_param respawn ${threshold:-10} ${timeout:-' + (options.failureRestart == null ? 2 : (options.failureRestart / 1000)) + '} ${retry:-0}\n');
                    }
                    conf.write('    procd_close_instance\n');
                    conf.write('}\n');
                    conf.end();

                    conf = require('fs').createWriteStream(options.installPath + options.name + '.sh', { flags: 'wb' });
                    conf.write('#!/bin/sh\n');
                    conf.write('cd "' + options.installPath + '"\n');
                    conf.write('exec "./' + options.target + '" ' + options.parameters.join(' ') + '\n');
                    conf.end();

                    m = require('fs').statSync('/etc/init.d/' + options.name).mode;
                    m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
                    require('fs').chmodSync('/etc/init.d/' + options.name, m);

                    m = require('fs').statSync(options.installPath + options.name + '.sh').mode;
                    m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
                    require('fs').chmodSync(options.installPath + options.name + '.sh', m);

                    switch (options.startType)
                    {
                        case 'BOOT_START':
                        case 'SYSTEM_START':
                        case 'AUTO_START':
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stdout.on('data', function (chunk) { });
                            child.stdin.write('/etc/init.d/' + options.name + ' enable\nexit\n');
                            child.waitExit();
                            break;
                        default:
                            break;
                    }

                    break;
                case 'init':
                    conf = require('fs').createWriteStream('/etc/init.d/' + options.name, { flags: 'wb' });
                    var isOpenRC = false;
                    if (require('fs').existsSync('/sbin/openrc-run'))
                    {
                        // OpenRC
                        isOpenRC = true;
                        conf.write('#!/sbin/openrc-run\n\n');
                        conf.write('name="' + options.name + '"\n');
                        conf.write('command="' + options.installPath + options.target + '"\n');
                        conf.write('command_args="' + parameters.split('"').join('\\"') + '"\n');
                        if (options.failureRestart == null || options.failureRestart > 0)
                        {
                            // Auto Crash Restart
                            conf.write('supervisor="supervise-daemon"\n');
                            conf.write('supervise_daemon_args="--chdir \\"' + options.installPath + '\\""\n\n');
                        }
                        else
                        {
                            // No Auto Crash Restartclear
                            conf.write('command_background=true\n');
                            conf.write('start_stop_daemon_args="--chdir \\"' + options.installPath + '\\""\n\n');                     
                        }
                        conf.write('pidfile="/var/run/' + options.name + '.pid"\n');
                        conf.write('depend() {\n');
                        conf.write(' want net\n');
                        conf.write('}\n');
                        conf.end();
                    }
                    else
                    {
                        // Traditional init.d

                        if (options.failureRestart == null || options.failureRestart > 0)
                        {
                            // Crash Restart is enabled, but it isn't inherently supported by INIT, so we must fake it with JS
                            var tmp_parameters = options.parameters ? options.parameters.slice() : [];
                            tmp_parameters.unshift('{{{}}}');
                            tmp_parameters = JSON.stringify(tmp_parameters).split('"{{{}}}"').join('process.argv0');
                            parameters = "var child; process.on('SIGTERM', function () { child.removeAllListeners('exit'); child.kill(); process.exit(); }); function start() { child = require('child_process').execFile(process.execPath, " + tmp_parameters + "); child.stdout.on('data', function (c) { }); child.stderr.on('data', function (c) { }); child.on('exit', function (status) { start(); }); } start();";
                            parameters = '-b64exec ' + Buffer.from(parameters).toString('base64');
                        }

                        // The following is the init.d script I wrote. Rather than having to deal with escaping the thing, I just Base64 encoded it to prevent issues.
                        conf.write(Buffer.from('IyEvYmluL3NoCgoKU0NSSVBUPVpaWlpaWVlZWVkKUlVOQVM9cm9vdAoKUElERklMRT0vdmFyL3J1bi9YWFhYWC5waWQKTE9HRklMRT0vdmFyL2xvZy9YWFhYWC5sb2cKCnN0YXJ0KCkgewogIGlmIFsgLWYgIiRQSURGSUxFIiBdICYmIGtpbGwgLTAgJChjYXQgIiRQSURGSUxFIikgMj4vZGV2L251bGw7IHRoZW4KICAgIGVjaG8gJ1NlcnZpY2UgYWxyZWFkeSBydW5uaW5nJyA+JjIKICAgIHJldHVybiAxCiAgZmkKICBlY2hvICdTdGFydGluZyBzZXJ2aWNl4oCmJyA+JjIKICBsb2NhbCBDTUQ9IiRTQ1JJUFQge3tQQVJNU319ICY+IFwiJExPR0ZJTEVcIiAmIGVjaG8gXCQhIgogIGxvY2FsIENNRFBBVEg9JChlY2hvICRTQ1JJUFQgfCBhd2sgJ3sgbGVuPXNwbGl0KCQwLCBhLCAiLyIpOyBwcmludCBzdWJzdHIoJDAsIDAsIGxlbmd0aCgkMCktbGVuZ3RoKGFbbGVuXSkpOyB9JykKICBjZCAkQ01EUEFUSAogIHN1IC1jICIkQ01EIiAkUlVOQVMgPiAiJFBJREZJTEUiCiAgZWNobyAnU2VydmljZSBzdGFydGVkJyA+JjIKfQoKc3RvcCgpIHsKICBpZiBbICEgLWYgIiRQSURGSUxFIiBdOyB0aGVuCiAgICBlY2hvICdTZXJ2aWNlIG5vdCBydW5uaW5nJyA+JjIKICAgIHJldHVybiAxCiAgZWxzZQoJcGlkPSQoIGNhdCAiJFBJREZJTEUiICkKCWlmIGtpbGwgLTAgJHBpZCAyPi9kZXYvbnVsbDsgdGhlbgogICAgICBlY2hvICdTdG9wcGluZyBzZXJ2aWNl4oCmJyA+JjIKICAgICAga2lsbCAtMTUgJHBpZAogICAgICBlY2hvICdTZXJ2aWNlIHN0b3BwZWQnID4mMgoJZWxzZQoJICBlY2hvICdTZXJ2aWNlIG5vdCBydW5uaW5nJwoJZmkKCXJtIC1mICQiUElERklMRSIKICBmaQp9CnJlc3RhcnQoKXsKCXN0b3AKCXN0YXJ0Cn0Kc3RhdHVzKCl7CglpZiBbIC1mICIkUElERklMRSIgXQoJdGhlbgoJCXBpZD0kKCBjYXQgIiRQSURGSUxFIiApCgkJaWYga2lsbCAtMCAkcGlkIDI+L2Rldi9udWxsOyB0aGVuCgkJCWVjaG8gIlhYWFhYIHN0YXJ0L3J1bm5pbmcsIHByb2Nlc3MgJHBpZCIKCQllbHNlCgkJCWVjaG8gJ1hYWFhYIHN0b3Avd2FpdGluZycKCQlmaQoJZWxzZQoJCWVjaG8gJ1hYWFhYIHN0b3Avd2FpdGluZycKCWZpCgp9CgoKY2FzZSAiJDEiIGluCglzdGFydCkKCQlzdGFydAoJCTs7CglzdG9wKQoJCXN0b3AKCQk7OwoJcmVzdGFydCkKCQlzdG9wCgkJc3RhcnQKCQk7OwoJc3RhdHVzKQoJCXN0YXR1cwoJCTs7CgkqKQoJCWVjaG8gIlVzYWdlOiBzZXJ2aWNlIFhYWFhYIHtzdGFydHxzdG9wfHJlc3RhcnR8c3RhdHVzfSIKCQk7Owplc2FjCmV4aXQgMAoK', 'base64').toString()
                            .split('ZZZZZ').join(options.installPath)
                            .split('XXXXX').join(options.name)
                            .split('YYYYY').join(options.target)
                            .replace('{{PARMS}}', parameters));
                        conf.end();
                    }

                    m = require('fs').statSync('/etc/init.d/' + options.name).mode;
                    m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
                    require('fs').chmodSync('/etc/init.d/' + options.name, m);
                    switch (options.startType)
                    {
                        case 'BOOT_START':
                        case 'SYSTEM_START':
                        case 'AUTO_START':
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stdout.on('data', function (chunk) { });
                            if (isOpenRC)
                            {
                                child.stdin.write('rc-update add ' + options.name + ' default\nexit\n');
                            }
                            else
                            {
                                child.stdin.write('update-rc.d ' + options.name + ' defaults\nexit\n');
                            }
                            child.waitExit();
                            break;
                        default:
                            break;
                    }
                    break;
                case 'upstart':
                    conf = require('fs').createWriteStream('/etc/init/' + options.name + '.conf', { flags: 'wb' });
                    switch (options.startType)
                    {
                        case 'BOOT_START':
                        case 'SYSTEM_START':
                        case 'AUTO_START':
                            if (require('os').Name.startsWith('CHROMEOS_'))
                            {
                                conf.write('start on started system-services\n');
                            }
                            else
                            {
                                conf.write('start on runlevel [2345]\n');
                            }
                            break;
                        default:
                            break;
                    }
                    conf.write('stop on runlevel [016]\n\n');
                    if (options.failureRestart == null || options.failureRestart > 0)
                    {
                        conf.write('respawn\n\n');
                    }
                    conf.write('chdir "' + options.installPath + '"\n');
                    conf.write('exec "' + options.installPath + options.target + '" ' + parameters + '\n\n');
                    conf.end();
                    break;
                case 'systemd':
                    var serviceDescription = options.description ? options.description : 'MeshCentral Agent';
                    if (require('fs').existsSync('/lib/systemd/system'))
                    {
                        conf = require('fs').createWriteStream('/lib/systemd/system/' + options.name + '.service', { flags: 'wb' });
                        console.info1('/lib/systemd/system/' + options.name + '.service');
                    }
                    else if (require('fs').existsSync('/usr/lib/systemd/system'))
                    {
                        conf = require('fs').createWriteStream('/usr/lib/systemd/system/' + options.name + '.service', { flags: 'wb' });
                        console.info1('/usr/lib/systemd/system/' + options.name + '.service');
                    }
                    else
                    {
                        throw ('unknown location for systemd configuration files');
                    }
                    conf.write('[Unit]\n');
                    conf.write('Description=' + serviceDescription + '\n');
                    conf.write('Wants=network-online.target\n');
                    conf.write('After=network-online.target\n');
                    conf.write('[Service]\n');
                    conf.write('WorkingDirectory=' + options.installPath + '\n');
                    conf.write('ExecStart=' + options.installPath.split(' ').join('\\x20') + options.target.split(' ').join('\\x20') + ' ' + parameters + '\n');
                    conf.write('StandardOutput=null\n');
                    if (options.failureRestart == null || options.failureRestart > 0)
                    {
                        conf.write('Restart=on-failure\n');
                        if (options.failureRestart == null)
                        {
                            conf.write('RestartSec=3\n');
                        }
                        else
                        {
                            conf.write('RestartSec=' + (options.failureRestart / 1000) + '\n');
                        }
                    }
                    switch (options.startType)
                    {
                        case 'BOOT_START':
                        case 'SYSTEM_START':
                        case 'AUTO_START':
                            conf.write('[Install]\n');
                            conf.write('WantedBy=multi-user.target\n');
                            conf.write('Alias=' + options.name + '.service\n');
                            conf.end();
                            this._update = require('child_process').execFile('/bin/sh', ['sh']);
                            this._update._moduleName = options.name;
                            this._update.stdout.on('data', function (chunk) { });
                            this._update.stderr.on('data', function (chunk) { console.info1(chunk.toString()); });
                            this._update.stdin.write('systemctl --system daemon-reload\n');
                            console.info1('systemctl enable ' + options.name + '.service');
                            this._update.stdin.write('systemctl enable ' + options.name.split('\\').join('\\\\') + '.service\n');
                            this._update.stdin.write('exit\n');
                            this._update.waitExit();
                        default:
                            conf.end();
                            this._update = require('child_process').execFile('/bin/sh', ['sh']);
                            this._update._moduleName = options.name;
                            this._update.stdout.on('data', function (chunk) { });
                            this._update.stdin.write('systemctl --system daemon-reload\n');
                            this._update.stdin.write('exit\n');
                            this._update.waitExit();
                            break;
                    }
                    break;
                default: // Unknown Service Type, install as a Pseudo Service (MeshDaemon)
                    if (!require('fs').existsSync('/usr/local/mesh_daemons/')) { require('fs').mkdirSync('/usr/local/mesh_daemons'); }
                    if (!require('fs').existsSync('/usr/local/mesh_daemons/' + options.name)) { require('fs').mkdirSync('/usr/local/mesh_daemons/' + options.name); }
                    if (!require('fs').existsSync('/usr/local/mesh_daemons/daemon'))
                    {
                        var exeGuid = 'B996015880544A19B7F7E9BE44914C18';
                        var daemonJS = Buffer.from('LyoKQ29weXJpZ2h0IDIwMTkgSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCgppZiAocHJvY2Vzcy5hcmd2Lmxlbmd0aCA8IDMpCnsKICAgIGNvbnNvbGUubG9nKCd1c2FnZTogZGFlbW9uIFsgc3RhcnQgfCBzdG9wIHwgc3RhdHVzIF0gW3NlcnZpY2VdJyk7CiAgICBwcm9jZXNzLmV4aXQoKTsKfQoKdmFyIHMgPSBudWxsOwp0cnkKewogICAgcyA9IHJlcXVpcmUoJ3NlcnZpY2UtbWFuYWdlcicpLm1hbmFnZXIuZ2V0U2VydmljZShwcm9jZXNzLmFyZ3ZbMl0pOwp9CmNhdGNoKHgpCnsKICAgIGNvbnNvbGUubG9nKHgpOwogICAgcHJvY2Vzcy5leGl0KCk7Cn0KCnN3aXRjaChwcm9jZXNzLmFyZ3ZbMV0pCnsKICAgIGNhc2UgJ3N0YXJ0JzoKICAgICAgICBzLnN0YXJ0KCk7CiAgICAgICAgY29uc29sZS5sb2coJ1N0YXJ0aW5nLi4uJyk7CiAgICAgICAgYnJlYWs7CiAgICBjYXNlICdzdG9wJzoKICAgICAgICBzLnN0b3AoKTsKICAgICAgICBjb25zb2xlLmxvZygnU3RvcHBpbmcuLi4nKTsKICAgICAgICBicmVhazsKICAgIGNhc2UgJ3N0YXR1cyc6CiAgICAgICAgaWYgKHMuaXNSdW5uaW5nKCkpCiAgICAgICAgewogICAgICAgICAgICBjb25zb2xlLmxvZygnUnVubmluZywgUElEID0gJyArIHJlcXVpcmUoJ2ZzJykucmVhZEZpbGVTeW5jKCcvdXNyL2xvY2FsL21lc2hfZGFlbW9ucy8nICsgcHJvY2Vzcy5hcmd2WzJdICsgJy9waWQnKS50b1N0cmluZygpKTsKICAgICAgICB9CiAgICAgICAgZWxzZQogICAgICAgIHsKICAgICAgICAgICAgY29uc29sZS5sb2coJ05vdCBydW5uaW5nJyk7CiAgICAgICAgfQogICAgICAgIGJyZWFrOwogICAgZGVmYXVsdDoKICAgICAgICBjb25zb2xlLmxvZygnVW5rbm93biBjb21tYW5kOiAnICsgcHJvY2Vzcy5hcmd2WzFdKTsKICAgICAgICBicmVhazsKfQoKcHJvY2Vzcy5leGl0KCk7Cg==', 'base64');
                        var exe = require('fs').readFileSync(process.execPath);
                        var padding = Buffer.alloc(8 - ((exe.length + daemonJS.length + 16 + 4) % 8));
                        var w = require('fs').createWriteStream('/usr/local/mesh_daemons/daemon', { flags: "wb" });
                        var daemonJSLen = Buffer.alloc(4);
                        daemonJSLen.writeUInt32BE(daemonJS.length);

                        w.write(exe);
                        if (padding.length > 0) { w.write(padding); }
                        w.write(daemonJS);
                        w.write(daemonJSLen);
                        w.write(Buffer.from(exeGuid, 'hex'));
                        w.end();

                        require('fs').chmodSync('/usr/local/mesh_daemons/daemon', require('fs').statSync('/usr/local/mesh_daemons/daemon').mode | require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP);
                    }

                    if (options.servicePath != '/usr/local/mesh_daemons/' + options.name + '/' + options.target)
                    {
                        require('fs').copyFileSync(options.servicePath, '/usr/local/mesh_daemons/' + options.name + '/' + options.target);
                    }
                    var m = require('fs').statSync('/usr/local/mesh_daemons/' + options.name + '/' + options.target).mode;
                    m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
                    require('fs').chmodSync('/usr/local/mesh_daemons/' + options.name + '/' + options.target, m);

                    conf = require('fs').createWriteStream('/usr/local/mesh_daemons/' + options.name + '.service', { flags: 'wb' });
                    conf.write('workingDirectory=' + '/usr/local/mesh_daemons/' + (options.companyName!=null?(options.companyName + '/'):'') + options.name + '\n');

                    if(!options.parameters) {options.parameters = [];}
                    options.parameters.unshift(options.target);
                    conf.write('parameters=' + JSON.stringify(options.parameters) + '\n');
                    options.parameters.shift();
                    if (options.failureRestart == null || options.failureRestart > 0)
                    {
                        conf.write('respawn\n');
                    }
                    conf.end();
                    break;
            }
        }
        if(process.platform == 'darwin')
        {
            if (!this.isAdmin()) { throw ('Installing as Service, requires root'); }

            // Mac OS
            var stdoutpath = (options.stdout ? ('<key>StandardOutPath</key>\n<string>' + options.stdout + '</string>') : '');
            var autoStart = (options.startType == 'AUTO_START' ? '<true/>' : '<false/>');
            var params =  '     <key>ProgramArguments</key>\n';
            params += '     <array>\n';
            params += ('         <string>' + options.installPath + options.target + '</string>\n');
            if(options.parameters)
            {
                for(var itm in options.parameters)
                {
                    params += ('         <string>' + options.parameters[itm] + '</string>\n');
                }
            }        
            params += '     </array>\n';
            
            var plist = '<?xml version="1.0" encoding="UTF-8"?>\n';
            plist += '<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n';
            plist += '<plist version="1.0">\n';
            plist += '  <dict>\n';
            plist += '      <key>Label</key>\n';
            plist += ('     <string>' + options.name + '</string>\n');
            plist += (params + '\n');
            plist += '      <key>WorkingDirectory</key>\n';
            plist += ('     <string>' + options.installPath + '</string>\n');
            plist += (stdoutpath + '\n');
            plist += '      <key>RunAtLoad</key>\n';
            plist += (autoStart + '\n');
            plist += '      <key>KeepAlive</key>\n';
            if(options.failureRestart == null || options.failureRestart > 0)
            {
                plist += '      <dict>\n';
                plist += '         <key>Crashed</key>\n';
                plist += '         <true/>\n';
                plist += '      </dict>\n';
            }
            else
            {
                plist += '      <false/>\n';
            }
            if(options.failureRestart != null)
            {
                plist += '      <key>ThrottleInterval</key>\n';
                plist += '      <integer>' + (options.failureRestart / 1000) + '</integer>\n';
            }

            plist += '  </dict>\n';
            plist += '</plist>';
            if (!require('fs').existsSync('/Library/LaunchDaemons/' + options.name + '.plist'))
            {
                require('fs').writeFileSync('/Library/LaunchDaemons/' + options.name + '.plist', plist);
            }
            else
            {
                throw ('Service: ' + options.name + ' already exists');
            }
        }

        if (options.files)
        {
            for (var i in options.files)
            {
                if (options.files[i]._buffer)
                {
                    console.log('writing ' + extractFileName(options.files[i]));
                    require('fs').writeFileSync(options.installPath + extractFileName(options.files[i]), options.files[i]._buffer);
                }
                else
                {
                    console.log('copying ' + extractFileSource(options.files[i]));
                    require('fs').copyFileSync(extractFileSource(options.files[i]), options.installPath + extractFileName(options.files[i]));
                }
            }
        }

    }
    if (process.platform == 'darwin')
    {
        this.installLaunchAgent = function installLaunchAgent(options)
        {
            if (!(options.uid || options.user) && !this.isAdmin())
            {
                throw ('Installing a Global Agent/Daemon, requires admin');
            }

            var servicePathTokens = options.servicePath.split('/');
            servicePathTokens.pop();
            if (servicePathTokens.peek() == '.') { servicePathTokens.pop(); }
            options.workingDirectory = servicePathTokens.join('/');

            var autoStart = (options.startType == 'AUTO_START' ? '<true/>' : '<false/>');
            var stdoutpath = (options.stdout ? ('<key>StandardOutPath</key>\n<string>' + options.stdout + '</string>') : '');
            var params =         '     <key>ProgramArguments</key>\n';
            params +=            '     <array>\n';
            params +=           ('         <string>' + options.servicePath + '</string>\n');
            if (options.parameters) {
                for (var itm in options.parameters)
                {
                    params +=   ('         <string>' + options.parameters[itm] + '</string>\n');
                }
            }
            params +=            '     </array>\n';

            var plist = '<?xml version="1.0" encoding="UTF-8"?>\n';
            plist += '<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n';
            plist += '<plist version="1.0">\n';
            plist += '  <dict>\n';
            plist += '      <key>Label</key>\n';
            plist += ('     <string>' + options.name + '-launchagent</string>\n');
            plist += (params + '\n');
            plist += '      <key>WorkingDirectory</key>\n';
            plist += ('     <string>' + options.workingDirectory + '</string>\n');
            plist += (stdoutpath + '\n');
            plist += '      <key>RunAtLoad</key>\n';
            plist += (autoStart + '\n');
            if (options.sessionTypes && options.sessionTypes.length > 0)
            {
                plist += '      <key>LimitLoadToSessionType</key>\n';
                plist += '      <array>\n';
                for (var stype in options.sessionTypes)
                {
                    plist += ('          <string>' + options.sessionTypes[stype] + '</string>\n');
                }
                plist += '      </array>\n';
            }
            plist += '      <key>KeepAlive</key>\n';
            if (options.failureRestart == null || options.failureRestart > 0) {
                plist += '      <dict>\n';
                plist += '         <key>Crashed</key>\n';
                plist += '         <true/>\n';
                plist += '      </dict>\n';
            }
            else {
                plist += '      <false/>\n';
            }
            if (options.failureRestart != null) {
                plist += '      <key>ThrottleInterval</key>\n';
                plist += '      <integer>' + (options.failureRestart / 1000) + '</integer>\n';
            }

            plist += '  </dict>\n';
            plist += '</plist>';

            if (options.uid)
            {
                options.user = require('user-sessions').getUsername(options.uid);
            }
            
            var folder = options.user ? (require('user-sessions').getHomeFolder(options.user) + '/Library/LaunchAgents/') : '/Library/LaunchAgents/';
            options.gid = require('user-sessions').getGroupID(options.uid);
            if (!require('fs').existsSync(folder))
            {
                require('fs').mkdirSync(folder);
                require('fs').chownSync(folder, options.uid, options.gid);
            }
            require('fs').writeFileSync(folder + options.name + '.plist', plist);
            if(options.user)
            {
                require('fs').chownSync(folder + options.name + '.plist', options.uid, options.gid);
            }
        };
    }
    this.uninstallService = function uninstallService(name, options)
    {
        if (!this.isAdmin()) { throw ('Uninstalling a service, requires admin'); }

        if (typeof (name) == 'object') { name = name.name; }
        var service = this.getService(name);
        var servicePath = service.appLocation();
        var workingPath = service.appWorkingDirectory();

        if (process.platform == 'win32')
        {
            if (!options || !options.skipDeleteBinary)
            {
                try
                {
                    require('fs').unlinkSync(servicePath);
                }
                catch (e)
                {
                    var child = require('child_process').execFile(process.env['windir'] + '\\system32\\cmd.exe', ['/C CHOICE /C Y /N /D Y /T 10 & del "' + servicePath + '"'], { type: 4 });
                }
            }
            if (this.proxy.DeleteService(service._service) == 0)
            {
                throw ('Uninstall Service for: ' + name + ', failed with error: ' + this.proxy2.GetLastError());
            }
            
            service.close();
            service = null;

            try
            {
                var reg = require('win-registry');
                reg.DeleteKey(reg.HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + name);
            }
            catch(ee)
            {
            }
        }
        else if(process.platform == 'linux')
        {
            switch (this.getServiceType())
            {
                case 'procd':
                    this._update = require('child_process').execFile('/bin/sh', ['sh']);
                    this._update.stdout.on('data', function (chunk) { });
                    this._update.stdin.write('/etc/init.d/' + name + ' stop\n');
                    this._update.stdin.write('/etc/init.d/' + name + ' disable\n');
                    this._update.stdin.write('exit\n');
                    this._update.waitExit();
                    try
                    {
                        require('fs').unlinkSync(service.conf);
                        if (!options || !options.skipDeleteBinary)
                        {
                            require('fs').unlinkSync(servicePath);
                            require('fs').unlinkSync(workingPath + name + '.sh');
                        }
                        console.log(name + ' uninstalled');
                    }
                    catch (e)
                    {
                        console.log(name + ' could not be uninstalled', e)
                    }
                    
                    break;
                case 'init':
                case 'upstart':
                    if (require('fs').existsSync('/etc/init.d/' + name))
                    {
                        // init.d service
                        this._update = require('child_process').execFile('/bin/sh', ['sh']);
                        this._update.stdout.on('data', function (chunk) { });
                        this._update.stdin.write('service ' + name + ' stop\n');
                        if (service.OpenRC)
                        {
                            if (service.startType == 'AUTO_START')
                            {
                                this._update.stdin.write('rc-update del ' + name + ' default\n');
                            }
                        }
                        else
                        {
                            this._update.stdin.write('update-rc.d -f ' + name + ' remove\n');
                        }
                        this._update.stdin.write('exit\n');
                        this._update.waitExit();
                        try
                        {
                            require('fs').unlinkSync('/etc/init.d/' + name);
                            if (!options || !options.skipDeleteBinary)
                            {
                                require('fs').unlinkSync(servicePath);
                            }
                            console.log(name + ' uninstalled');
                        }
                        catch (e) {
                            console.log(name + ' could not be uninstalled', e)
                        }
                    }
                    if (require('fs').existsSync('/etc/init/' + name + '.conf'))
                    {
                        // upstart service
                        this._update = require('child_process').execFile('/bin/sh', ['sh']);
                        this._update.stdout.on('data', function (chunk) { });
                        this._update.stdin.write('service ' + name + ' stop\n');
                        this._update.stdin.write('exit\n');
                        this._update.waitExit();
                        try
                        {
                            require('fs').unlinkSync('/etc/init/' + name + '.conf');
                            if (!options || !options.skipDeleteBinary)
                            {
                                require('fs').unlinkSync(servicePath);
                            }
                            console.log(name + ' uninstalled');
                        }
                        catch (e) {
                            console.log(name + ' could not be uninstalled', e)
                        }
                    }
                    break;
                case 'systemd':
                    this._update = require('child_process').execFile('/bin/sh', ['sh'], { type: require('child_process').SpawnTypes.TERM });
                    this._update.stdout.on('data', function (chunk) { });
                    this._update.stdin.write('systemctl stop ' + name + '.service\n');
                    this._update.stdin.write('systemctl disable ' + name + '.service\n');
                    this._update.stdin.write('exit\n');
                    this._update.waitExit();
                    try
                    {
                        if (!options || !options.skipDeleteBinary)
                        {
                            if (require('fs').existsSync(servicePath)) { require('fs').unlinkSync(servicePath); }                 
                        }
                        if (require('fs').existsSync('/lib/systemd/system/' + name + '.service')) { require('fs').unlinkSync('/lib/systemd/system/' + name + '.service'); }
                        if (require('fs').existsSync('/usr/lib/systemd/system/' + name + '.service')) { require('fs').unlinkSync('/usr/lib/systemd/system/' + name + '.service'); }
                        var escname = this.escape(name);
                        if (require('fs').existsSync('/lib/systemd/system/' + escname + '.service')) { require('fs').unlinkSync('/lib/systemd/system/' + escname + '.service'); }
                        if (require('fs').existsSync('/usr/lib/systemd/system/' + escname + '.service')) { require('fs').unlinkSync('/usr/lib/systemd/system/' + escname + '.service'); }
                        console.log(name + ' uninstalled');
                    }
                    catch (e)
                    {
                        console.log(name + ' could not be uninstalled', e)
                    }
                    break;
                default: // unknown platform service type
                    if (service.isRunning())
                    {
                        service.stop();
                    }
                    if (!options || !options.skipDeleteBinary)
                    {
                        try
                        {
                            require('fs').unlinkSync(servicePath);
                        }
                        catch (x)
                        {
                        }
                    }
                    try
                    {
                        require('fs').unlinkSync(service.conf);
                    }
                    catch(x)
                    {
                    }
                    console.log(name + ' uninstalled');
                    break;
            }
        }
        else if(process.platform == 'darwin')
        {
            service.unload();
            try
            {
                require('fs').unlinkSync(service.plist);
                if (!options || !options.skipDeleteBinary)
                {
                    require('fs').unlinkSync(servicePath);
                }
            }
            catch (e)
            {
                throw ('Error uninstalling service: ' + name + ' => ' + e);
            }

            try
            {
                require('fs').rmdirSync(workingPath);
            }
            catch (e)
            {
            }
        }
        else if(process.platform == 'freebsd')
        {
            service.stop();
            if (!options || !options.skipDeleteBinary)
            {
                require('fs').unlinkSync(service.appLocation());
            }
            if (service.OpenBSD)
            {
                // OpenBSD specific 
                try
                {
                    require('fs').unlinkSync(workingPath + name + '_loader');
                }
                catch(e)
                {
                }
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write("rcctl disable " + name + "\nexit\n");
                child.waitExit();
            }
            if (this.pfSense)
            {
                try
                {
                    require('fs').unlinkSync(service.rc + '.sh');
                }
                catch (ee)
                {
                }
            }
            if (this.OPNsense)
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stderr.on('data', function (c) { });
                child.stdin.write("ls /usr/local/etc/rc.syshook.d/start | tr '\\n' '`' | awk -F'`' '");
                child.stdin.write('{');
                child.stdin.write('   DEL="";');
                child.stdin.write('   printf "[";');
                child.stdin.write('   for(i=1;i<NF;++i)');
                child.stdin.write('   {');
                child.stdin.write('      if($i ~ /^[0-9][0-9]-' + name.split(' ').join('') + '$/)');
                child.stdin.write('      {');
                child.stdin.write('         printf "%s\\"%s\\"", DEL, $i;');
                child.stdin.write('         DEL=",";');
                child.stdin.write('      }');
                child.stdin.write('   }');
                child.stdin.write('   printf "]";');
                child.stdin.write("}'");
                child.stdin.write('\nexit\n');
                child.waitExit();

                var hooks = JSON.parse(child.stdout.str.trim());
                for (var i in hooks)
                {
                    try
                    {
                        require('fs').unlinkSync('/usr/local/etc/rc.syshook.d/start/' + hooks[i]);
                    }
                    catch (ee)
                    {
                    }
                }
            }
            require('fs').unlinkSync(service.rc);
            if ((this.pfSense || this.OPNsense) && require('fs').existsSync('/etc/rc.conf.local'))
            {
                var local = null;
                try
                {
                    local = require('fs').readFileSync('/etc/rc.conf.local');
                }
                catch(ee)
                {
                }
                if(local!=null)
                {
                    var lines = local.toString().split('\n');
                    var i;
                    var m = require('fs').createWriteStream('/etc/rc.conf.local', { flags: 'wb' });
                    for(i=0;i<lines.length;++i)
                    {
                        if (lines[i].split('=')[0].trim() != (name + '_enable') && lines[i].trim() != '')
                        {
                            m.write(lines[i] + '\n');
                        }
                    }
                    m.end();
                }
            }


            try
            {
                require('fs').rmdirSync(workingPath);
            }
            catch (e)
            { }
        }
    }

    this.getServiceType = function getServiceType()
    {
        if (this._platform != null) { return (this._platform); }
        var platform = 'unknown';
        switch(process.platform)
        {
            case 'win32':
                platform = 'windows';
                break;
            case 'freebsd':
                platform = 'freebsd';
                break;
            case 'darwin':
                platform = 'launchd';
                break;
            case 'linux':
                platform = require('process-manager').getProcessInfo(1).Name;
                if (platform == "busybox")
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("ps -ax -o pid -o command | awk '{ if($1==\"1\") { $1=\"\"; split($0, res, \" \"); print res[2]; }}'\nexit\n");
                    child.waitExit();
                    platform = child.stdout.str.trim();
                }
                if (platform == 'init')
                {
                    if (require('fs').existsSync('/etc/init'))
                    {
                        platform = 'upstart';
                    }
                }
                switch (platform)
                {
                    case 'init':
                    case 'upstart':
                    case 'systemd':
                    case 'procd':
                        break;
                    default:
                        platform = 'unknown';
                        break;
                }
                break;
        }

        this._platform = platform;
        return (platform);
    };

    this.escape = function escape(str)
    {
        if (this.getServiceType() != 'systemd') { return (str); }
        if (systemd_escape == null)
        {
            systemd_escape = require('lib-finder').findBinary('systemd-escape');
            if (systemd_escape == null) { systemd_escape = false; }
        }
        if (systemd_escape === false) { return (str); }

        var child = require('child_process').execFile(systemd_escape, ['systemd-escape', str]);
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.waitExit();

        return (child.stdout.str.trim());
    }
    this.unescape = function unescape(str)
    {
        if (this.getServiceType() != 'systemd') { return (str); }
        if (systemd_escape == null)
        {
            systemd_escape = require('lib-finder').findBinary('systemd-escape');
            if (systemd_escape == null) { systemd_escape = false; }
        }
        if (systemd_escape === false) { return (str); }

        var child = require('child_process').execFile(systemd_escape, ['systemd-escape', '-u', str]);
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.waitExit();

        return (child.stdout.str.trim());
    }


    this.daemon = function daemon(path, parameters, options)
    {
        require('code-utils');
        console.log('PATH => ' + JSON.stringify(path, null, 1));
        console.log('parameters => ' + JSON.stringify(parameters, null, 1));
        console.log('options => ' + JSON.stringify(options, null, 1));
    
        var z =  parameters.getParameterIndex('meshServiceName');
        console.log('meshServiceName => ' + z);
        if (z >= 0)
        {
            parameters.splice(z, 1);
            console.log('parameters => ' + JSON.stringify(parameters, null, 1));
        }

        var tmp = JSON.stringify(parameters);
        tmp = tmp.substring(1, tmp.length - 1);

        if (options.cwd)
        {
            process.chdir(options.cwd);
            console.log('Setting CWD to: ' + options.cwd);
        }


        console.log('\n\n');
        console.log("child = require('child_process').execFile('" + path + "', ['" + (process.platform == 'win32' ? path.split('\\').pop() : path.split('/').pop() + "'" + (tmp != '' ? (", " + tmp) : "")) + "]);");
        console.log('\n\n');



        if (!options) { options = {}; }
        var childParms = "\
            var child = null; \
            var options = " + JSON.stringify(options) + ";\
            if(options.logOutputs)\
            { console.setDestination(console.Destinations.LOGFILE); console.log('Logging Outputs...'); }\
            else\
            {\
              console.setDestination(console.Destinations.DISABLED);\
            }\
            if(options.cwd) { process.chdir(options.cwd); }\
            function cleanupAndExit()\
            {\
                if(options.pidPath) { try{require('fs').unlinkSync(options.pidPath);} catch(x){} }\
            }\
            function spawnChild()\
            {\
                child = require('child_process').execFile('" + path + "', ['" + (process.platform == 'win32' ? path.split('\\').pop() : path.split('/').pop() + "'" + (tmp != '' ? (", " + tmp) : "")) + "]);\
                if(child)\
                {\
                    child.stdout.on('data', function(c) { console.log(c.toString()); });\
                    child.stderr.on('data', function(c) { console.log(c.toString()); });\
                    child.once('exit', function (code) \
                    {\
                        console.log('Child Exited');\
                        if(options.crashRestart) { spawnChild(); } else { cleanupAndExit(); }\
                    });\
                    console.log('Child Spawned');\
                }\
                else\
                {\
                    console.log('Child Spawn Failed');\
                }\
            }\
            if(options.pidPath) { require('fs').writeFileSync(options.pidPath, process.pid.toString()); }\
            spawnChild();\
            process.on('SIGTERM', function()\
            {\
                if(child) { child.kill(); }\
                cleanupAndExit();\
                process.exit();\
            });";
        
        var parms = [process.platform == 'win32' ? process.execPath.split('\\').pop() : process.execPath.split('/').pop()];
        parms.push('-b64exec');
        parms.push(Buffer.from(childParms).toString('base64'));
        options._parms = parms;
        options.detached = true;
        options.type = 4;

        var child = require('child_process').execFile(process.execPath, options._parms, options);       
        if (!child) { throw ('Error spawning process'); }
    }
    this.daemonEx = function daemonEx(path, parameters, options)
    {
        parameters.unshift(process.platform == 'win32' ? path.split('\\').pop() : path.split('/').pop());
        var name = options.name ? options.name : parameters[0];
        if (options.cwd) { process.chdir(options.cwd); }

        function spawnChild()
        {
            global.child = require('child_process').execFile(path, parameters);
            if(global.child)
            {
                require('fs').writeFileSync('/var/run/' + name + '.pid', global.child.pid.toString() + '\n');
                global.child.stdout.on('data', function(c) { console.log(c.toString()); });
                global.child.stderr.on('data', function(c) { console.log(c.toString()); });
                global.child.once('exit', function (code) 
                {
                    require('fs').unlinkSync('/var/run/' + name + '.pid');
                    if(options.crashRestart) { spawnChild(); } 
                });
            }
        }
        
        if(options.logOutput)
        {
            console.setDestination(console.Destinations.LOGFILE);
            console.log('Logging Outputs...'); 
        }
        else
        {
            console.setDestination(console.Destinations.DISABLED);
        }
        if(options.cwd) { process.chdir(options.cwd); }
        spawnChild();
        process.on('SIGTERM', function()
        {
            if (global.child)
            {
                child.kill();
                require('fs').unlinkSync('/var/run/' + name + '.pid');
            }
            process.exit();
        });
    }
}

module.exports = serviceManager;
module.exports.manager = new serviceManager();

if (process.platform == 'darwin')
{
    module.exports.getOSVersion = getOSVersion;
}

