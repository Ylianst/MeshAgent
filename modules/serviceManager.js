

function parseServiceStatus(token)
{
    var j = {};
    var serviceType = token.Deref(0, 4).IntVal;
    j.isFileSystemDriver = ((serviceType & 0x00000002) == 0x00000002);
    j.isKernelDriver = ((serviceType & 0x00000001) == 0x00000001);
    j.isSharedProcess = ((serviceType & 0x00000020) == 0x00000020);
    j.isOwnProcess = ((serviceType & 0x00000010) == 0x00000010);
    j.isInteractive = ((serviceType & 0x00000100) == 0x00000100);
    switch (token.Deref((1 * 4), 4).IntVal)
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
    var controlsAccepted = token.Deref((2 * 4), 4).IntVal
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
    j.pid = token.Deref((7 * 4), 4).IntVal
    return (j);
}

function serviceManager()
{
    this.GM = require('_GenericMarshal');
    this.proxy = this.GM.CreateNativeProxy('Advapi32.dll');
    this.proxy.CreateMethod('OpenSCManagerA');
    this.proxy.CreateMethod('EnumServicesStatusExA');
    this.proxy.CreateMethod('OpenServiceA');
    this.proxy.CreateMethod('QueryServiceStatusEx');
    this.proxy.CreateMethod('ControlService');
    this.proxy.CreateMethod('StartServiceA');
    this.proxy.CreateMethod('CloseServiceHandle');
    this.proxy.CreateMethod('CreateServiceA');
    this.proxy.CreateMethod('ChangeServiceConfig2A');
    this.proxy.CreateMethod('DeleteService');
    this.proxy2 = this.GM.CreateNativeProxy('Kernel32.dll');
    this.proxy2.CreateMethod('GetLastError');

    this.enumerateService = function()
    {
        var machineName = this.GM.CreatePointer();
        var dbName = this.GM.CreatePointer();
        var handle = this.proxy.OpenSCManagerA(0x00, 0x00, 0x0001 | 0x0004);

        var bytesNeeded = this.GM.CreateVariable(4);
        var servicesReturned = this.GM.CreateVariable(4);
        var resumeHandle = this.GM.CreateVariable(4);
        //var services = this.proxy.CreateVariable(262144);

        var success = this.proxy.EnumServicesStatusExA(handle, 0, 0x00000030, 0x00000003, 0x00, 0x00, bytesNeeded, servicesReturned, resumeHandle, 0x00);
        if(bytesNeeded.IntVal <= 0)
        {
            throw ('error enumerating services');
        }

        var sz = bytesNeeded.IntVal;
        var services = this.GM.CreateVariable(sz);
        this.proxy.EnumServicesStatusExA(handle, 0, 0x00000030, 0x00000003, services, sz, bytesNeeded, servicesReturned, resumeHandle, 0x00);
        console.log("servicesReturned", servicesReturned.IntVal, 'PtrSize = ' + dbName._size);

        var ptrSize = dbName._size;
        var blockSize = 36 + (2 * ptrSize);
        console.log('blockSize', blockSize);

        var retVal = [];
        for (var i = 0; i < servicesReturned.IntVal; ++i)
        {
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
    this.getService = function(name)
    {
        var serviceName = this.GM.CreateVariable(name);
        var ptr = this.GM.CreatePointer();
        var bytesNeeded = this.GM.CreateVariable(ptr._size);
        var handle = this.proxy.OpenSCManagerA(0x00, 0x00, 0x0001 | 0x0004 | 0x0020 | 0x0010);
        if (handle == 0) { throw ('could not open ServiceManager'); }
        var h = this.proxy.OpenServiceA(handle, serviceName, 0x0004 | 0x0020 | 0x0010 | 0x00010000);
        if (h != 0)
        {
            var success = this.proxy.QueryServiceStatusEx(h, 0, 0, 0, bytesNeeded);
            var status = this.GM.CreateVariable(bytesNeeded.IntVal);
            success = this.proxy.QueryServiceStatusEx(h, 0, status, status._size, bytesNeeded);
            if (success != 0)
            {
                retVal = {};
                retVal.status = parseServiceStatus(status);
                retVal._scm = handle;
                retVal._service = h;
                retVal._GM = this.GM;
                retVal._proxy = this.proxy;
                require('events').inherits(retVal);
                retVal.on('~', function () { this._proxy.CloseServiceHandle(this); this._proxy.CloseServiceHandle(this._scm); });
                retVal.name = name;
                retVal.stop = function()
                {
                    if(this.status.state == 'RUNNING')
                    {
                        var newstate = this._GM.CreateVariable(36);
                        var success = this._proxy.ControlService(this._service, 0x00000001, newstate);
                        if(success == 0)
                        {
                            throw (this.name + '.stop() failed');
                        }
                    }
                    else
                    {
                        throw ('cannot call ' + this.name + '.stop(), when current state is: ' + this.status.state);
                    }
                }
                retVal.start = function()
                {
                    if(this.status.state == 'STOPPED')
                    {
                        var success = this._proxy.StartServiceA(this._service, 0, 0);
                        if(success == 0)
                        {
                            throw (this.name + '.start() failed');
                        }
                    }
                    else
                    {
                        throw ('cannot call ' + this.name + '.start(), when current state is: ' + this.status.state);
                    }
                }
                return (retVal);
            }
            else
            {

            }
        }

        this.proxy.CloseServiceHandle(handle);
        throw ('could not find service: ' + name);
    }
    this.installService = function(options)
    {
        var handle = this.proxy.OpenSCManagerA(0x00, 0x00, 0x0002);
        if (handle == 0) { throw ('error opening SCManager'); }
        var serviceName = this.GM.CreateVariable(options.name);
        var displayName = this.GM.CreateVariable(options.displayName);
        var allAccess = 0x000F01FF;
        var serviceType;
        var servicePath = this.GM.CreateVariable(options.servicePath);

        switch(options.startType)
        {
            case 'BOOT_START':
                serviceType = 0x00;
                break;
            case 'SYSTEM_START':
                serviceType = 0x01;
                break;
            case 'AUTO_START':
                serviceType = 0x02;
                break;
            case 'DEMAND_START':
                serviceType = 0x03;
                break;
            default:
                serviceType = 0x04; // Disabled
                break;
        }
        var h = this.proxy.CreateServiceA(handle, serviceName, displayName, allAccess, 0x10 | 0x100, serviceType, 0, servicePath, 0, 0, 0, 0, 0);
        if (h == 0) { this.proxy.CloseServiceHandle(handle); throw ('Error Creating Service'); }
        if(options.description)
        {
            console.log(options.description);

            var dscPtr = this.GM.CreatePointer();
            dscPtr.Val = this.GM.CreateVariable(options.description);

            if(this.proxy.ChangeServiceConfig2A(h, 1, dscPtr)==0)
            {
                this.proxy.CloseServiceHandle(h);
                this.proxy.CloseServiceHandle(handle);
                throw ('Unable to set description');
            }
        }
        this.proxy.CloseServiceHandle(h);
        this.proxy.CloseServiceHandle(handle);
        return (this.getService(options.name));
    }
    this.uninstallService = function(name)
    {
        var service = this.getService(name);
        if(service.status.state == 'STOPPED')
        {
            if (this.proxy.DeleteService(service._service) == 0) { throw ('Uninstall Service for: ' + name + ', failed with error: ' + this.proxy2.GetLastError()); }
        }
        else
        {
            throw ('Cannot uninstall service: ' + name + ', because it is: ' + service.status.state);
        }
    }
}

module.exports = serviceManager;