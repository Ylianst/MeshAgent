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

function parseServiceStatus(token)
{
    var j = {};
    var serviceType = token.Deref(0, 4).IntVal;
    j.isFileSystemDriver = ((serviceType & 0x00000002) == 0x00000002);
    j.isKernelDriver = ((serviceType & 0x00000001) == 0x00000001);
    j.isSharedProcess = ((serviceType & 0x00000020) == 0x00000020);
    j.isOwnProcess = ((serviceType & 0x00000010) == 0x00000010);
    j.isInteractive = ((serviceType & 0x00000100) == 0x00000100);
    switch (token.Deref((1 * 4), 4).toBuffer().readUInt32LE())
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

function serviceManager()
{
    this._ObjectID = 'service-manager';
    if (process.platform == 'win32') 
    {
        this.GM = require('_GenericMarshal');
        this.proxy = this.GM.CreateNativeProxy('Advapi32.dll');
        this.proxy.CreateMethod('OpenSCManagerA');
        this.proxy.CreateMethod('EnumServicesStatusExA');
        this.proxy.CreateMethod('OpenServiceA');
        this.proxy.CreateMethod('QueryServiceStatusEx');
        this.proxy.CreateMethod('QueryServiceConfig2A');
        this.proxy.CreateMethod('ControlService');
        this.proxy.CreateMethod('StartServiceA');
        this.proxy.CreateMethod('CloseServiceHandle');
        this.proxy.CreateMethod('CreateServiceA');
        this.proxy.CreateMethod('ChangeServiceConfig2A');
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
                    return process.env['ProgramFiles(x86)'];    // 32 Bit App
                } 
                return process.env['ProgramFiles'];             // 64 bit App
            }

            // 32 bit Windows
            return process.env['ProgramFiles'];                 
        };
        this.getServiceFolder = function getServiceFolder() { return this.getProgramFolder() + '\\mesh'; };

        this.enumerateService = function () {
            var machineName = this.GM.CreatePointer();
            var dbName = this.GM.CreatePointer();
            var handle = this.proxy.OpenSCManagerA(0x00, 0x00, 0x0001 | 0x0004);

            var bytesNeeded = this.GM.CreatePointer();
            var servicesReturned = this.GM.CreatePointer();
            var resumeHandle = this.GM.CreatePointer();
            //var services = this.proxy.CreateVariable(262144);
            var success = this.proxy.EnumServicesStatusExA(handle, 0, 0x00000030, 0x00000003, 0x00, 0x00, bytesNeeded, servicesReturned, resumeHandle, 0x00);
            if (bytesNeeded.IntVal <= 0) {
                throw ('error enumerating services');
            }
            var sz = bytesNeeded.IntVal;
            var services = this.GM.CreateVariable(sz);
            this.proxy.EnumServicesStatusExA(handle, 0, 0x00000030, 0x00000003, services, sz, bytesNeeded, servicesReturned, resumeHandle, 0x00);
            console.log("servicesReturned", servicesReturned.IntVal);

            var ptrSize = dbName._size;
            var blockSize = 36 + (2 * ptrSize);
            blockSize += ((ptrSize - (blockSize % ptrSize)) % ptrSize);
            var retVal = [];
            for (var i = 0; i < servicesReturned.IntVal; ++i) {
                var token = services.Deref(i * blockSize, blockSize);
                var j = {};
                j.name = token.Deref(0, ptrSize).Deref().String;
                j.displayName = token.Deref(ptrSize, ptrSize).Deref().String;
                j.status = parseServiceStatus(token.Deref(2 * ptrSize, 36));
                retVal.push(j);
            }
            this.proxy.CloseServiceHandle(handle);
            return (retVal);
        }
        this.getService = function (name) {
            var serviceName = this.GM.CreateVariable(name);
            var ptr = this.GM.CreatePointer();
            var bytesNeeded = this.GM.CreateVariable(ptr._size);
            var handle = this.proxy.OpenSCManagerA(0x00, 0x00, 0x0001 | 0x0004 | 0x0020 | 0x0010);
            if (handle.Val == 0) { throw ('could not open ServiceManager'); }
            var h = this.proxy.OpenServiceA(handle, serviceName, 0x0001 | 0x0004 | 0x0020 | 0x0010 | 0x00010000);
            if (h.Val != 0) {
                var success = this.proxy.QueryServiceStatusEx(h, 0, 0, 0, bytesNeeded);
                var status = this.GM.CreateVariable(bytesNeeded.toBuffer().readUInt32LE());
                success = this.proxy.QueryServiceStatusEx(h, 0, status, status._size, bytesNeeded);
                if (success != 0) {
                    retVal = {};
                    retVal.status = parseServiceStatus(status);
                    retVal._scm = handle;
                    retVal._service = h;
                    retVal._GM = this.GM;
                    retVal._proxy = this.proxy;
                    require('events').inherits(retVal);
                    retVal.on('~', function () { this._proxy.CloseServiceHandle(this); this._proxy.CloseServiceHandle(this._scm); });
                    retVal.name = name;

                    retVal.appLocation = function ()
                    {
                        var reg = require('win-registry');
                        var imagePath = reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + this.name, 'ImagePath').toString();
                        var ret = imagePath.split('.exe')[0] + '.exe';
                        if (ret.startsWith('"')) { ret = ret.substring(1); }
                        return (ret);
                    };
                    retVal.isRunning = function ()
                    {
                        var bytesNeeded = this._GM.CreateVariable(this._GM.PointerSize);
                        this._proxy.QueryServiceStatusEx(this._service, 0, 0, 0, bytesNeeded);
                        var st = this._GM.CreateVariable(bytesNeeded.toBuffer().readUInt32LE());
                        if(this._proxy.QueryServiceStatusEx(this._service, 0, st, st._size, bytesNeeded).Val != 0)
                        {
                            var state = parseServiceStatus(st);
                            return (state.state == 'RUNNING');
                        }
                        return (false);
                    };
                    retVal.stop = function () {
                        if (this.status.state == 'RUNNING') {
                            var newstate = this._GM.CreateVariable(36);
                            var success = this._proxy.ControlService(this._service, 0x00000001, newstate);
                            if (success == 0) {
                                throw (this.name + '.stop() failed');
                            }
                        }
                        else {
                            throw ('cannot call ' + this.name + '.stop(), when current state is: ' + this.status.state);
                        }
                    }
                    retVal.start = function () {
                        if (this.status.state == 'STOPPED') {
                            var success = this._proxy.StartServiceA(this._service, 0, 0);
                            if (success == 0) {
                                throw (this.name + '.start() failed');
                            }
                        }
                        else {
                            throw ('cannot call ' + this.name + '.start(), when current state is: ' + this.status.state);
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
        this.isAdmin = function isAdmin() 
        {
            return (require('user-sessions').isRoot());
        }
        if(process.platform == 'linux')
        {
            this.getService = function (name, platform)
            {
                if (!platform) { platform = this.getServiceType(); }
                var ret = { name: name };
                switch(platform)
                {
                    case 'init':
                    case 'upstart':
                        if (require('fs').existsSync('/etc/init.d/' + name)) { platform = 'init'; }
                        if (require('fs').existsSync('/etc/init/' + name + '.conf')) { platform = 'upstart'; }
                        if ((platform == 'init' && require('fs').existsSync('/etc/init.d/' + name)) ||
                            (platform == 'upstart' && require('fs').existsSync('/etc/init/' + name + '.conf')))
                        {
                            ret.appLocation = function appLocation()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if(appLocation.platform == 'init')
                                {
                                    child.stdin.write("cat /etc/init.d/" + this.name + " | grep 'SCRIPT=' | awk -F= '{print $2}'\nexit\n");
                                }
                                else
                                {
                                    child.stdin.write("cat /etc/init/" + this.name + ".conf | grep 'exec ' | awk '{print $2}'\nexit\n");
                                }
                                child.waitExit();
                                return (child.stdout.str.trim());
                            };
                            ret.appLocation.platform = platform;
                            ret.isMe = function isMe()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if (isMe.platform == 'upstart')
                                {
                                    child.stdin.write("initctl status " + this.name + " | awk '{print $2}' | awk -F, '{print $4}'\nexit\n");
                                }
                                else
                                {
                                    child.stdin.write("service " + this.name + " status | awk '{print $2}' | awk -F, '{print $4}'\nexit\n");
                                }
                                child.waitExit();
                                return (parseInt(child.stdout.str.trim()) == process.pid);
                            };
                            ret.isMe.platform = platform;
                            ret.isRunning = function isRunning()
                            {
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
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
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
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
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
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
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
                                    child.stdin.write('service ' + this.name + ' status\nexit\n');
                                }
                                child.waitExit();
                                return (child.stdout._str);
                            };
                            ret.status.platform = platform;
                            return (ret);
                        }
                        else
                        {
                            throw (platform + ' Service (' + name + ') NOT FOUND');
                        }
                        break;
                    case 'systemd':
                        if (require('fs').existsSync('/lib/systemd/system/' + name + '.service') ||
                            require('fs').existsSync('/usr/lib/systemd/system/' + name + '.service'))
                        {
                            ret.appLocation = function ()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if (require('fs').existsSync('/lib/systemd/system/' + this.name + '.service'))
                                {
                                    child.stdin.write("cat /lib/systemd/system/" + this.name + ".service | grep 'ExecStart=' | awk -F= '{ split($2, a, \" \"); print a[1] }'\n\exit\n");
                                }
                                else
                                {
                                    child.stdin.write("cat /usr/lib/systemd/system/" + this.name + ".service | grep 'ExecStart=' | awk -F= '{ split($2, a, \" \"); print a[1] }'\n\exit\n");
                                }
                                child.waitExit();
                                return (child.stdout.str.trim());
                            };
                            ret.isMe = function isMe()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                child.stdin.write("systemctl status " + this.name + " | grep 'Main PID:' | awk '{print $3}'\nexit\n");
                                child.waitExit();
                                return (parseInt(child.stdout.str.trim()) == process.pid);
                            };
                            ret.isRunning = function isRunning()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                child.stdin.write("systemctl status " + this.name + " | grep 'Active:' | awk '{print $2}'\nexit\n");
                                child.waitExit();
                                return (child.stdout.str.trim() == 'active');         
                            };
                            ret.start = function start() {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.on('data', function (chunk) { });
                                child.stdin.write('systemctl start ' + this.name + '\nexit\n');
                                child.waitExit();
                            };
                            ret.stop = function stop() {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.on('data', function (chunk) { });
                                child.stdin.write('systemctl stop ' + this.name + '\nexit\n');
                                child.waitExit();
                            };
                            ret.restart = function restart() {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.on('data', function (chunk) { });
                                child.stdin.write('systemctl restart ' + this.name + '\nexit\n');
                                child.waitExit();
                            };
                            ret.status = function status() {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout._str = '';
                                child.stdout.on('data', function (chunk) { this._str += chunk.toString(); });
                                child.stdin.write('systemctl status ' + this.name + '\nexit\n');
                                child.waitExit();
                                return (child.stdout._str);
                            };
                            return (ret);
                        }
                        else
                        {
                            throw (platform + ' Service (' + name + ') NOT FOUND');
                        }
                        break;
                    default:
                        throw ('Unknown Service Platform: ' + platform);
                        break;
                }
            };
        }
    }
    this.installService = function installService(options)
    {
        if (!options.target) { options.target = options.name; }
        if (!options.displayName) { options.displayName = options.name; }

        if (process.platform == 'win32')
        {
            if (!this.isAdmin()) { throw ('Installing as Service, requires admin'); }

            // Before we start, we need to copy the binary to the right place
            var folder = this.getServiceFolder();
            if (!require('fs').existsSync(folder)) { require('fs').mkdirSync(folder); }
            if (!require('fs').existsSync(folder + '\\' + options.name)) { require('fs').mkdirSync(folder + '\\' + options.name); }

            require('fs').copyFileSync(options.servicePath, folder + '\\' + options.name + '\\' + options.target + '.exe');
            options.servicePath = folder + '\\' + options.name + '\\' + options.target + '.exe';

            var servicePath = this.GM.CreateVariable('"' + options.servicePath + '"');
            var handle = this.proxy.OpenSCManagerA(0x00, 0x00, 0x0002);
            if (handle.Val == 0) { throw ('error opening SCManager'); }
            var serviceName = this.GM.CreateVariable(options.name);
            var displayName = this.GM.CreateVariable(options.displayName);
            var allAccess = 0x000F01FF;
            var serviceType;
            

            switch (options.startType) {
                case 'AUTO_START':
                    serviceType = 0x02; // Automatic
                    break;
                case 'DEMAND_START':
                default:
                    serviceType = 0x03; // Manual
                    break;
                case 'DISABLED':
                    serviceType = 0x04; // Disabled
                    break;
            }

            var h = this.proxy.CreateServiceA(handle, serviceName, displayName, allAccess, 0x10 | 0x100, serviceType, 0, servicePath, 0, 0, 0, 0, 0);
            if (h.Val == 0) { this.proxy.CloseServiceHandle(handle); throw ('Error Creating Service: ' + this.proxy2.GetLastError().Val); }
            if (options.description)
            {
                var dsc = this.GM.CreateVariable(options.description);
                var serviceDescription = this.GM.CreateVariable(this.GM.PointerSize);
                dsc.pointerBuffer().copy(serviceDescription.Deref(0, this.GM.PointerSize).toBuffer());

                if (this.proxy.ChangeServiceConfig2A(h, 1, serviceDescription).Val == 0)
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
                if (this.proxy.ChangeServiceConfig2A(h, 2, failureActions).Val == 0)
                {
                    console.log('Unable to set FailureActions...');
                }
            }
            this.proxy.CloseServiceHandle(h);
            this.proxy.CloseServiceHandle(handle);

            if (options.files)
            {
                for(var i in options.files)
                {
                    console.log('copying ' + extractFileSource(options.files[i]));
                    require('fs').copyFileSync(extractFileSource(options.files[i]), folder + '\\' + options.name + '\\' + extractFileName(options.files[i]));
                }
            }
            if (options.parameters)
            {
                var reg = require('win-registry');
                var imagePath = reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + options.name, 'ImagePath');
                imagePath += (' ' + options.parameters.join(' '));
                reg.WriteKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + options.name, 'ImagePath', imagePath);
            }

            return (this.getService(options.name));
        }
        if(process.platform == 'linux')
        {
            if (!this.isAdmin()) { console.log('Installing a Service requires root'); throw ('Installing as Service, requires root'); }
            var parameters = options.parameters ? options.parameters.join(' ') : '';
            var conf;
            if (!options.servicePlatform) { options.servicePlatform = this.getServiceType(); }
           
            switch (options.servicePlatform)
            {
                case 'init':
                    if (!require('fs').existsSync('/usr/local/mesh_services/')) { require('fs').mkdirSync('/usr/local/mesh_services'); }
                    if (!require('fs').existsSync('/usr/local/mesh_services/' + options.name)) { require('fs').mkdirSync('/usr/local/mesh_services/' + options.name); }

                    require('fs').copyFileSync(options.servicePath, '/usr/local/mesh_services/' + options.name + '/' + options.target);
                    console.log('copying ' + options.servicePath);

                    var m = require('fs').statSync('/usr/local/mesh_services/' + options.name + '/' + options.target).mode;
                    m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP);
                    require('fs').chmodSync('/usr/local/mesh_services/' + options.name + '/' + options.target, m);

                    // The following is the init.d script I wrote. Rather than having to deal with escaping the thing, I just Base64 encoded it to prevent issues.
                    conf = require('fs').createWriteStream('/etc/init.d/' + options.name, { flags: 'wb' });
                    conf.write(Buffer.from('IyEvYmluL3NoCgoKU0NSSVBUPS91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy9YWFhYWC9ZWVlZWQpSVU5BUz1yb290CgpQSURGSUxFPS92YXIvcnVuL1hYWFhYLnBpZApMT0dGSUxFPS92YXIvbG9nL1hYWFhYLmxvZwoKc3RhcnQoKSB7CiAgaWYgWyAtZiAiJFBJREZJTEUiIF0gJiYga2lsbCAtMCAkKGNhdCAiJFBJREZJTEUiKSAyPi9kZXYvbnVsbDsgdGhlbgogICAgZWNobyAnU2VydmljZSBhbHJlYWR5IHJ1bm5pbmcnID4mMgogICAgcmV0dXJuIDEKICBmaQogIGVjaG8gJ1N0YXJ0aW5nIHNlcnZpY2XigKYnID4mMgogIGxvY2FsIENNRD0iJFNDUklQVCB7e1BBUk1TfX0gJj4gXCIkTE9HRklMRVwiICYgZWNobyBcJCEiCiAgc3UgLWMgIiRDTUQiICRSVU5BUyA+ICIkUElERklMRSIKICBlY2hvICdTZXJ2aWNlIHN0YXJ0ZWQnID4mMgp9CgpzdG9wKCkgewogIGlmIFsgISAtZiAiJFBJREZJTEUiIF07IHRoZW4KICAgIGVjaG8gJ1NlcnZpY2Ugbm90IHJ1bm5pbmcnID4mMgogICAgcmV0dXJuIDEKICBlbHNlCglwaWQ9JCggY2F0ICIkUElERklMRSIgKQoJaWYga2lsbCAtMCAkcGlkIDI+L2Rldi9udWxsOyB0aGVuCiAgICAgIGVjaG8gJ1N0b3BwaW5nIHNlcnZpY2XigKYnID4mMgogICAgICBraWxsIC0xNiAkcGlkCiAgICAgIGVjaG8gJ1NlcnZpY2Ugc3RvcHBlZCcgPiYyCgllbHNlCgkgIGVjaG8gJ1NlcnZpY2Ugbm90IHJ1bm5pbmcnCglmaQoJcm0gLWYgJCJQSURGSUxFIgogIGZpCn0KcmVzdGFydCgpewoJc3RvcAoJc3RhcnQKfQpzdGF0dXMoKXsKCWlmIFsgLWYgIiRQSURGSUxFIiBdCgl0aGVuCgkJcGlkPSQoIGNhdCAiJFBJREZJTEUiICkKCQlpZiBraWxsIC0wICRwaWQgMj4vZGV2L251bGw7IHRoZW4KCQkJZWNobyAiWFhYWFggc3RhcnQvcnVubmluZywgcHJvY2VzcyAkcGlkIgoJCWVsc2UKCQkJZWNobyAnWFhYWFggc3RvcC93YWl0aW5nJwoJCWZpCgllbHNlCgkJZWNobyAnWFhYWFggc3RvcC93YWl0aW5nJwoJZmkKCn0KCgpjYXNlICIkMSIgaW4KCXN0YXJ0KQoJCXN0YXJ0CgkJOzsKCXN0b3ApCgkJc3RvcAoJCTs7CglyZXN0YXJ0KQoJCXN0b3AKCQlzdGFydAoJCTs7CglzdGF0dXMpCgkJc3RhdHVzCgkJOzsKCSopCgkJZWNobyAiVXNhZ2U6IHNlcnZpY2UgWFhYWFgge3N0YXJ0fHN0b3B8cmVzdGFydHxzdGF0dXN9IgoJCTs7CmVzYWMKZXhpdCAwCgo=', 'base64').toString().split('XXXXX').join(options.name).split('YYYYY').join(options.target).replace('{{PARMS}}', parameters));
                    conf.end();

                    m = require('fs').statSync('/etc/init.d/' + options.name).mode;
                    m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP);
                    require('fs').chmodSync('/etc/init.d/' + options.name, m);
                    switch (options.startType)
                    {
                        case 'BOOT_START':
                        case 'SYSTEM_START':
                        case 'AUTO_START':
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stdout.on('data', function (chunk) { });
                            child.stdin.write('update-rc.d ' + options.name + ' defaults\nexit\n');
                            child.waitExit();
                            break;
                        default:
                            break;
                    }
                    break;
                case 'upstart':
                    if (!require('fs').existsSync('/usr/local/mesh_services/')) { require('fs').mkdirSync('/usr/local/mesh_services'); }
                    if (!require('fs').existsSync('/usr/local/mesh_services/' + options.name)) { require('fs').mkdirSync('/usr/local/mesh_services/' + options.name); }

                    require('fs').copyFileSync(options.servicePath, '/usr/local/mesh_services/' + options.name + '/' + options.target);
                    console.log('copying ' + options.servicePath);

                    var m = require('fs').statSync('/usr/local/mesh_services/' + options.name + '/' + options.target).mode;
                    m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP);
                    require('fs').chmodSync('/usr/local/mesh_services/' + options.name + '/' + options.target, m);

                    conf = require('fs').createWriteStream('/etc/init/' + options.name + '.conf', { flags: 'wb' });
                    switch (options.startType)
                    {
                        case 'BOOT_START':
                        case 'SYSTEM_START':
                        case 'AUTO_START':
                            conf.write('start on runlevel [2345]\n');
                            break;
                        default:
                            break;
                    }
                    conf.write('stop on runlevel [016]\n\n');
                    if (options.failureRestart == null || options.failureRestart > 0)
                    {
                        conf.write('respawn\n\n');
                    }
                    conf.write('chdir /usr/local/mesh_services/' + options.name + '\n');
                    conf.write('exec /usr/local/mesh_services/' + options.name + '/' + options.target + ' ' + parameters + '\n\n');
                    conf.end();
                    break;
                case 'systemd':
                    var serviceDescription = options.description ? options.description : 'MeshCentral Agent';

                    if (!require('fs').existsSync('/usr/local/mesh_services/')) { require('fs').mkdirSync('/usr/local/mesh_services'); }
                    if (!require('fs').existsSync('/usr/local/mesh_services/' + options.name)) { require('fs').mkdirSync('/usr/local/mesh_services/' + options.name); }

                    console.log('copying ' + options.servicePath);
                    require('fs').copyFileSync(options.servicePath, '/usr/local/mesh_services/' + options.name + '/' + options.target);

                    var m = require('fs').statSync('/usr/local/mesh_services/' + options.name + '/' + options.target).mode;
                    m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP);
                    require('fs').chmodSync('/usr/local/mesh_services/' + options.name + '/' + options.target, m);

                    if (require('fs').existsSync('/lib/systemd/system'))
                    {
                        conf = require('fs').createWriteStream('/lib/systemd/system/' + options.name + '.service', { flags: 'wb' });
                    }
                    else if (require('fs').existsSync('/usr/lib/systemd/system'))
                    {
                        conf = require('fs').createWriteStream('/usr/lib/systemd/system/' + options.name + '.service', { flags: 'wb' });
                    }
                    else
                    {
                        throw ('unknown location for systemd configuration files');
                    }

                    conf.write('[Unit]\nDescription=' + serviceDescription + '\n');
                    conf.write('[Service]\n');
                    conf.write('WorkingDirectory=/usr/local/mesh_services/' + options.name + '\n');
                    conf.write('ExecStart=/usr/local/mesh_services/' + options.name + '/' + options.target + ' ' + parameters + '\n');
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
                            conf.write('Alias=' + options.name + '.service\n'); break;
                            this._update = require('child_process').execFile('/bin/sh', ['sh'], { type: require('child_process').SpawnTypes.TERM });
                            this._update._moduleName = options.name;
                            this._update.stdout.on('data', function (chunk) { });
                            this._update.stdin.write('systemctl enable ' + options.name + '.service\n');
                            this._update.stdin.write('exit\n');
                            this._update.waitExit();
                        default:
                            break;
                    }
                    conf.end();

                    break;
                default: // unknown platform service type
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
            params += ('         <string>/usr/local/mesh_services/' + options.name + '/' + options.target + '</string>\n');
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
            plist += ('     <string>/usr/local/mesh_services/' + options.name + '</string>\n');
            plist += (stdoutpath + '\n');
            plist += '      <key>RunAtLoad</key>\n';
            plist += (autoStart + '\n');
            plist += '      <key>KeepAlive</key>\n';
            if(options.failureRestart == null || options.failureRestart > 0)
            {
                plist += '      <true/>\n';
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

            if (!require('fs').existsSync('/usr/local/mesh_services')) { require('fs').mkdirSync('/usr/local/mesh_services'); }
            if (!require('fs').existsSync('/Library/LaunchDaemons/' + options.name + '.plist'))
            {
                if (!require('fs').existsSync('/usr/local/mesh_services/' + options.name)) { require('fs').mkdirSync('/usr/local/mesh_services/' + options.name); }
                if (options.binary)
                {
                    require('fs').writeFileSync('/usr/local/mesh_services/' + options.name + '/' + options.target, options.binary);
                }
                else
                {
                    require('fs').copyFileSync(options.servicePath, '/usr/local/mesh_services/' + options.name + '/' + options.target);
                }
                require('fs').writeFileSync('/Library/LaunchDaemons/' + options.name + '.plist', plist);
                var m = require('fs').statSync('/usr/local/mesh_services/' + options.name + '/' + options.target).mode;
                m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP);
                require('fs').chmodSync('/usr/local/mesh_services/' + options.name + '/' + options.target, m);
            }
            else
            {
                throw ('Service: ' + options.name + ' already exists');
            }
        }

        if (options.files) {
            for (var i in options.files) {
                console.log('copying ' + extractFileSource(options.files[i]));
                require('fs').copyFileSync(extractFileSource(options.files[i]), '/usr/local/mesh_services/' + options.name + '/' + extractFileName(options.files[i]));
            }
        }
    }
    this.uninstallService = function uninstallService(name)
    {
        if (!this.isAdmin()) { throw ('Uninstalling a service, requires admin'); }

        if (typeof (name) == 'object') { name = name.name; }
        var service = this.getService(name);
        var servicePath = service.appLocation();

        if (process.platform == 'win32')
        {
            if (service.status.state == undefined || service.status.state == 'STOPPED')
            {
                try
                {
                    require('fs').unlinkSync(servicePath);
                }
                catch (e)
                {
                }
                if (this.proxy.DeleteService(service._service) == 0)
                {
                    throw ('Uninstall Service for: ' + name + ', failed with error: ' + this.proxy2.GetLastError());
                }
            }
            else
            {
                throw ('Cannot uninstall service: ' + name + ', because it is: ' + service.status.state);
            }
        }
        else if(process.platform == 'linux')
        {
            switch (this.getServiceType())
            {
                case 'init':
                case 'upstart':
                    if (require('fs').existsSync('/etc/init.d/' + name))
                    {
                        // init.d service
                        this._update = require('child_process').execFile('/bin/sh', ['sh']);
                        this._update.stdout.on('data', function (chunk) { });
                        this._update.stdin.write('service ' + name + ' stop\n');
                        this._update.stdin.write('update-rc.d -f ' + name + ' remove\n');
                        this._update.stdin.write('exit\n');
                        this._update.waitExit();
                        try {
                            require('fs').unlinkSync('/etc/init.d/' + name);
                            require('fs').unlinkSync(servicePath);
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
                        try {
                            require('fs').unlinkSync('/etc/init/' + name + '.conf');
                            require('fs').unlinkSync(servicePath);
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
                        require('fs').unlinkSync(servicePath);
                        if (require('fs').existsSync('/lib/systemd/system/' + name + '.service')) { require('fs').unlinkSync('/lib/systemd/system/' + name + '.service'); }
                        if (require('fs').existsSync('/usr/lib/systemd/system/' + name + '.service')) { require('fs').unlinkSync('/usr/lib/systemd/system/' + name + '.service'); }
                        console.log(name + ' uninstalled');
                    }
                    catch (e)
                    {
                        console.log(name + ' could not be uninstalled', e)
                    }
                    break;
                default: // unknown platform service type
                    break;
            }
        }
        else if(process.platform == 'darwin')
        {
            if (require('fs').existsSync('/Library/LaunchDaemons/' + name + '.plist'))
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.on('data', function (chunk) { });
                child.stdin.write('launchctl stop ' + name + '\n');
                child.stdin.write('launchctl unload /Library/LaunchDaemons/' + name + '.plist\n');
                child.stdin.write('exit\n');
                child.waitExit();

                try
                {
                    require('fs').unlinkSync(servicePath);
                    require('fs').unlinkSync('/Library/LaunchDaemons/' + name + '.plist');
                }
                catch(e)
                {
                    throw ('Error uninstalling service: ' + name + ' => ' + e);
                }

                try
                {
                    require('fs').rmdirSync('/usr/local/mesh_services/' + name);
                }
                catch(e)
                {}
            }
            else
            {
                throw ('Service: ' + name + ' does not exist');
            }
        }
    }
    if(process.platform == 'linux')
    {
        this.getServiceType = function getServiceType()
        {
            var platform = require('process-manager').getProcessInfo(1).Name;
            if (platform == 'init')
            {
                if(require('fs').existsSync('/etc/init'))
                {
                    platform = 'upstart';
                }
            }
            return (platform);
        };
    }
}

module.exports = serviceManager;
module.exports.manager = new serviceManager();