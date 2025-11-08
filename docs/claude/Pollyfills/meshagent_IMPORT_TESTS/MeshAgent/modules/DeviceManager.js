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

try { Object.defineProperty(Array.prototype, "peek", { value: function () { return (this.length > 0 ? this[this.length - 1] : undefined); } }); }
catch (e) { }


var DIGCF_PRESENT = 0x00000002;
var DIGCF_ALLCLASSES = 0x00000004;
var SPDRP_DEVICEDESC                 = 0x00000000;  // DeviceDesc (R/W)
var SPDRP_HARDWAREID                 = 0x00000001;  // HardwareID (R/W)
var SPDRP_COMPATIBLEIDS              = 0x00000002;  // CompatibleIDs (R/W)
var SPDRP_UNUSED0                    = 0x00000003;  // unused
var SPDRP_SERVICE                    = 0x00000004;  // Service (R/W)
var SPDRP_UNUSED1                    = 0x00000005;  // unused
var SPDRP_UNUSED2                    = 0x00000006;  // unused
var SPDRP_CLASS                      = 0x00000007;  // Class (R--tied to ClassGUID)
var SPDRP_CLASSGUID                  = 0x00000008;  // ClassGUID (R/W)
var SPDRP_DRIVER                     = 0x00000009;  // Driver (R/W)
var SPDRP_CONFIGFLAGS                = 0x0000000A;  // ConfigFlags (R/W)
var SPDRP_MFG                        = 0x0000000B;  // Mfg (R/W)
var SPDRP_FRIENDLYNAME               = 0x0000000C;  // FriendlyName (R/W)
var SPDRP_LOCATION_INFORMATION       = 0x0000000D;  // LocationInformation (R/W)
var SPDRP_PHYSICAL_DEVICE_OBJECT_NAME= 0x0000000E;  // PhysicalDeviceObjectName (R)
var SPDRP_CAPABILITIES               = 0x0000000F;  // Capabilities (R)
var SPDRP_UI_NUMBER                  = 0x00000010;  // UiNumber (R)
var SPDRP_UPPERFILTERS               = 0x00000011;  // UpperFilters (R/W)
var SPDRP_LOWERFILTERS               = 0x00000012;  // LowerFilters (R/W)
var SPDRP_BUSTYPEGUID                = 0x00000013;  // BusTypeGUID (R)
var SPDRP_LEGACYBUSTYPE              = 0x00000014;  // LegacyBusType (R)
var SPDRP_BUSNUMBER                  = 0x00000015;  // BusNumber (R)
var SPDRP_ENUMERATOR_NAME            = 0x00000016;  // Enumerator Name (R)
var SPDRP_SECURITY                   = 0x00000017;  // Security (R/W, binary form)
var SPDRP_SECURITY_SDS               = 0x00000018;  // Security (W, SDS form)
var SPDRP_DEVTYPE                    = 0x00000019;  // Device Type (R/W)
var SPDRP_EXCLUSIVE                  = 0x0000001A;  // Device is exclusive-access (R/W)
var SPDRP_CHARACTERISTICS            = 0x0000001B;  // Device Characteristics (R/W)
var SPDRP_ADDRESS                    = 0x0000001C;  // Device Address (R)
var SPDRP_UI_NUMBER_DESC_FORMAT      = 0X0000001D;  // UiNumberDescFormat (R/W)
var SPDRP_DEVICE_POWER_DATA          = 0x0000001E;  // Device Power Data (R)
var SPDRP_REMOVAL_POLICY             = 0x0000001F;  // Removal Policy (R)
var SPDRP_REMOVAL_POLICY_HW_DEFAULT  = 0x00000020;  // Hardware Removal Policy (R)
var SPDRP_REMOVAL_POLICY_OVERRIDE    = 0x00000021;  // Removal Policy Override (RW)
var SPDRP_INSTALL_STATE              = 0x00000022;  // Device Install State (R)
var SPDRP_LOCATION_PATHS             = 0x00000023;  // Device Location Paths (R)
var SPDRP_BASE_CONTAINERID           = 0x00000024;  // Base ContainerID (R)
var ERROR_INSUFFICIENT_BUFFER = 122;
var DN_HAS_PROBLEM                   = 0x00000400;
var DN_DISABLEABLE                   = 0x00002000;

var CM_PROB_CODE = 
{
    0x00000001: 'NOT_CONFIGURED',
    0x00000002: 'DEVLOADER_FAILED',
    0x00000003: 'OUT_OF_MEMORY',
    0x00000004: 'ENTRY_IS_WRONG_TYPE',
    0x00000005: 'LACKED_ARBITRATOR',
    0x00000006: 'BOOT_CONFIG_CONFLICT',
    0x00000007: 'FAILED_FILTER',
    0x00000008: 'DEVLOADER_NOT_FOUND',
    0x00000009: 'INVALID_DATA',
    0x0000000A: 'FAILED_START',
    0x0000000B: 'LIAR',
    0x0000000C: 'NORMAL_CONFLICT',
    0x0000000D: 'NOT_VERIFIED',
    0x0000000E: 'NEED_RESTART',
    0x0000000F: 'REENUMERATION',
    0x00000010: 'PARTIAL_LOG_CONF',
    0x00000011: 'UNKNOWN_RESOURCE',
    0x00000012: 'REINSTALL',
    0x00000013: 'REGISTRY',
    0x00000014: 'VXDLDR',
    0x00000015: 'WILL_BE_REMOVED',
    0x00000016: 'DISABLED',
    0x00000017: 'DEVLOADER_NOT_READY',
    0x00000018: 'DEVICE_NOT_THERE',
    0x00000019: 'MOVED',
    0x0000001A: 'TOO_EARLY',
    0x0000001B: 'NO_VALID_LOG_CONF',
    0x0000001C: 'FAILED_INSTALL',
    0x0000001D: 'HARDWARE_DISABLED',
    0x0000001E: 'CANT_SHARE_IRQ',
    0x0000001F: 'FAILED_ADD',
    0x00000020: 'DISABLED_SERVICE',
    0x00000021: 'TRANSLATION_FAILED',
    0x00000022: 'NO_SOFTCONFIG',
    0x00000023: 'BIOS_TABLE',
    0x00000024: 'IRQ_TRANSLATION_FAILED',
    0x00000025: 'FAILED_DRIVER_ENTRY',
    0x00000026: 'DRIVER_FAILED_PRIOR_UNLOAD',
    0x00000027: 'DRIVER_FAILED_LOAD',
    0x00000028: 'DRIVER_SERVICE_KEY_INVALID',
    0x00000029: 'LEGACY_SERVICE_NO_DEVICES',
    0x0000002A: 'DUPLICATE_DEVICE',
    0x0000002B: 'FAILED_POST_START',
    0x0000002C: 'HALTED',
    0x0000002D: 'PHANTOM',
    0x0000002E: 'SYSTEM_SHUTDOWN',
    0x0000002F: 'HELD_FOR_EJECT',
    0x00000030: 'DRIVER_BLOCKED',
    0x00000031: 'REGISTRY_TOO_LARGE',
    0x00000032: 'SETPROPERTIES_FAILED',
};

//DEFINE_DEVPROPKEY(DEVPKEY_Device_DevNodeStatus, 0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7, 2);     // DEVPROP_TYPE_UINT32
//DEFINE_DEVPROPKEY(DEVPKEY_Device_ProblemCode, 0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7, 3);

function DeviceManager()
{
    if (process.platform != 'win32') { throw ('Only Supported on Windows'); }

    this._marshal = require('_GenericMarshal');
    this._Kernel32 = this._marshal.CreateNativeProxy('Kernel32.dll');
    this._Kernel32.CreateMethod('GetLastError');
    this._SetupAPI = this._marshal.CreateNativeProxy("SetupAPI.dll");
    this._SetupAPI.CreateMethod('SetupDiGetClassDevsA');
    this._SetupAPI.CreateMethod('SetupDiGetDevicePropertyKeys');
    this._SetupAPI.CreateMethod('SetupDiGetDevicePropertyW');
    this._SetupAPI.CreateMethod('SetupDiEnumDeviceInfo');
    this._SetupAPI.CreateMethod('SetupDiEnumDriverInfoA');
    this._SetupAPI.CreateMethod('SetupDiBuildDriverInfoList');
    this._SetupAPI.CreateMethod('SetupDiGetDeviceInstallParamsA');
    this._SetupAPI.CreateMethod('SetupDiGetDeviceRegistryPropertyA');
    this._SetupAPI.CreateMethod('SetupDiDestroyDeviceInfoList');
    this._CfgMgr32 = this._marshal.CreateNativeProxy('CfgMgr32.dll');
    this._CfgMgr32.CreateMethod('CM_Get_DevNode_Status');
    this._CfgMgr32.DEVPKEY_Device_DevNodeStatus = this._marshal.CreateVariable(20);
    this._CfgMgr32.DEVPKEY_Device_ProblemCode = this._marshal.CreateVariable(20);

    Buffer.from('C5A64043FA930647972C7B648008A5A7', 'hex').copy(this._CfgMgr32.DEVPKEY_Device_DevNodeStatus.toBuffer());
    this._CfgMgr32.DEVPKEY_Device_DevNodeStatus.toBuffer().writeUInt32LE(2, 16);
    Buffer.from('C5A64043FA930647972C7B648008A5A7', 'hex').copy(this._CfgMgr32.DEVPKEY_Device_ProblemCode.toBuffer());
    this._CfgMgr32.DEVPKEY_Device_ProblemCode.toBuffer().writeUInt32LE(3, 16);

    this.getDevices = function getDevices(options)
    {
        var nf;
        var ret = [];
        var i;
        var di = this._SetupAPI.SetupDiGetClassDevsA(0, 0, 0, DIGCF_PRESENT | DIGCF_ALLCLASSES);
        if(di.Val == -1) {throw('Error Enumerating Drivers');}

        var devInfoData = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 28 : 32);
        var DataT = this._marshal.CreateVariable(4);
        devInfoData.toBuffer().writeUInt32LE(devInfoData._size, 0);

        var buf = this._marshal.CreateVariable(1024);
        var buflen = this._marshal.CreateVariable(4);
        buflen.toBuffer().writeUInt32LE(1024,0);
        buf.buflen = 1024;

        // Enumerate devices
        for (i = 0; this._SetupAPI.SetupDiEnumDeviceInfo(di, i, devInfoData).Val; i++)
        {
            while (!this._SetupAPI.SetupDiGetDeviceRegistryPropertyA(di, devInfoData, SPDRP_HARDWAREID, DataT, buf, buf.buflen, buflen).Val)
            {
                if (this._Kernel32.GetLastError().Val == ERROR_INSUFFICIENT_BUFFER)
                {
                    buf = this._marshal.CreateVariable(buflen.toBuffer().readUInt32LE());
                    buf.buflen = buflen.toBuffer().readUInt32LE();
                }
                else 
                {
                    break;
                }
            }
            ret.push({ hwid: buf.toBuffer().slice(0, buflen.toBuffer().readUInt32LE() - 1).toString() });

            nf = 0;
            while (!this._SetupAPI.SetupDiGetDeviceRegistryPropertyA(di, devInfoData, SPDRP_FRIENDLYNAME, DataT, buf, buf.buflen, buflen).Val)
            {
                if (this._Kernel32.GetLastError().Val == ERROR_INSUFFICIENT_BUFFER)
                {
                    buf = this._marshal.CreateVariable(buflen.toBuffer().readUInt32LE());
                    buf.buflen = buflen.toBuffer().readUInt32LE();
                }
                else
                {
                    nf = 1;
                    break;
                }
            }
            if (!nf) { ret.peek().friendlyName = buf.toBuffer().slice(0, buflen.toBuffer().readUInt32LE() - 1).toString(); }

            nf = 0;
            while (!this._SetupAPI.SetupDiGetDeviceRegistryPropertyA(di, devInfoData, SPDRP_MFG, DataT, buf, buf.buflen, buflen).Val) {
                if (this._Kernel32.GetLastError().Val == ERROR_INSUFFICIENT_BUFFER) {
                    buf = this._marshal.CreateVariable(buflen.toBuffer().readUInt32LE());
                    buf.buflen = buflen.toBuffer().readUInt32LE();
                }
                else {
                    nf = 1;
                    break;
                }
            }
            if (!nf) { ret.peek().manufacturer = buf.toBuffer().slice(0, buflen.toBuffer().readUInt32LE() - 1).toString(); }

            nf = 0;
            while (!this._SetupAPI.SetupDiGetDeviceRegistryPropertyA(di, devInfoData, SPDRP_CLASS, DataT, buf, buf.buflen, buflen).Val) {
                if (this._Kernel32.GetLastError().Val == ERROR_INSUFFICIENT_BUFFER) {
                    buf = this._marshal.CreateVariable(buflen.toBuffer().readUInt32LE());
                    buf.buflen = buflen.toBuffer().readUInt32LE();
                }
                else {
                    nf = 1;
                    break;
                }
            }
            if (!nf) { ret.peek().class = buf.toBuffer().slice(0, buflen.toBuffer().readUInt32LE() - 1).toString(); }

            nf = 0;
            while (!this._SetupAPI.SetupDiGetDeviceRegistryPropertyA(di, devInfoData, SPDRP_DEVICEDESC, DataT, buf, buf.buflen, buflen).Val) {
                if (this._Kernel32.GetLastError().Val == ERROR_INSUFFICIENT_BUFFER) {
                    buf = this._marshal.CreateVariable(buflen.toBuffer().readUInt32LE());
                    buf.buflen = buflen.toBuffer().readUInt32LE();
                }
                else {
                    nf = 1;
                    break;
                }
            }
            if (!nf) { ret.peek().description = buf.toBuffer().slice(0, buflen.toBuffer().readUInt32LE() - 1).toString(); }

            nf = 0;
            while (!this._SetupAPI.SetupDiGetDeviceRegistryPropertyA(di, devInfoData, SPDRP_LOCATION_PATHS, DataT, buf, buf.buflen, buflen).Val) {
                if (this._Kernel32.GetLastError().Val == ERROR_INSUFFICIENT_BUFFER) {
                    buf = this._marshal.CreateVariable(buflen.toBuffer().readUInt32LE());
                    buf.buflen = buflen.toBuffer().readUInt32LE();
                }
                else {
                    nf = 1;
                    break;
                }
            }
            if (!nf) { ret.peek().locationPath = buf.toBuffer().slice(0, buflen.toBuffer().readUInt32LE() - 1).toString(); }

            nf = 0;
            while (!this._SetupAPI.SetupDiGetDeviceRegistryPropertyA(di, devInfoData, SPDRP_INSTALL_STATE, DataT, buf, buf.buflen, buflen).Val) {
                if (this._Kernel32.GetLastError().Val == ERROR_INSUFFICIENT_BUFFER) {
                    buf = this._marshal.CreateVariable(buflen.toBuffer().readUInt32LE());
                    buf.buflen = buflen.toBuffer().readUInt32LE();
                }
                else {
                    nf = 1;
                    break;
                }
            }
            if (!nf)
            {
                switch(buf.toBuffer().readUInt32LE())
                {
                    case 0:
                        ret.peek().installState = 'INSTALLED';
                        break;
                    case 1:
                        ret.peek().installState = 'NEED_REINSTALL';
                        break;
                    case 2:
                        ret.peek().installState = 'FAILED';
                        break;
                    case 3:
                        ret.peek().installState = 'INCOMPLETE';
                        break;
                    default:
                        ret.peek().installState = 'UNKNOWN';
                        break;
                }
            }

            var proptype = this._marshal.CreateVariable(4);
            var reqsize = this._marshal.CreateVariable(4);
            this._SetupAPI.SetupDiGetDevicePropertyW(di, devInfoData, this._CfgMgr32.DEVPKEY_Device_DevNodeStatus, proptype, 0, 0, reqsize, 0);
            if (reqsize.toBuffer().readUInt32LE() > 0)
            {
                var propbuffer = this._marshal.CreateVariable(reqsize.toBuffer().readUInt32LE());
                this._SetupAPI.SetupDiGetDevicePropertyW(di, devInfoData, this._CfgMgr32.DEVPKEY_Device_DevNodeStatus, proptype, propbuffer, reqsize.toBuffer().readUInt32LE(), reqsize, 0);
                if ((propbuffer.toBuffer().readUInt32LE() & DN_HAS_PROBLEM) == DN_HAS_PROBLEM)
                {
                    this._SetupAPI.SetupDiGetDevicePropertyW(di, devInfoData, this._CfgMgr32.DEVPKEY_Device_ProblemCode, proptype, propbuffer, reqsize.toBuffer().readUInt32LE(), reqsize, 0);
                    if (!CM_PROB_CODE[propbuffer.toBuffer().readUInt32LE()])
                    {
                        ret.peek().status = 'HAS_PROBLEM';
                    }
                    else
                    {
                        ret.peek().status = CM_PROB_CODE[propbuffer.toBuffer().readUInt32LE()];
                    }                 
                }
                else
                {
                    if ((propbuffer.toBuffer().readUInt32LE() & DN_HAS_PROBLEM) == 0)
                    {
                        ret.peek().status = 'ENABLED';
                    }
                }
            }

            if(options)
            {
                var match = true;
                if (options.manufacturer && options.manufacturer.endsWith('*'))
                {
                    if (!ret.peek().manufacturer || !ret.peek().manufacturer.startsWith(options.manufacturer.substring(0, options.manufacturer.length - 1)))
                    {
                        match = false;
                    }
                    if (options.class && ret.peek().class != options.class)
                    {
                        match = false;
                    }
                }
                else if ((options.class && ret.peek().class != options.class) ||
                    (options.manufacturer && ret.peek().manufacturer != options.manufacturer))
                {
                    match = false;
                }
                if (!match) { ret.pop(); }
                else
                {

                    // GetDriverVersion
                    if (this._SetupAPI.SetupDiBuildDriverInfoList(di, devInfoData, 2).Val) {
                        var drvinfo = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 796 : 800);
                        drvinfo.toBuffer().writeUInt32LE(this._marshal.PointerSize == 4 ? 796 : 800);
                        if (this._SetupAPI.SetupDiEnumDriverInfoA(di, devInfoData, 2, 0, drvinfo).Val) {
                            var drversion = drvinfo.toBuffer().slice(this._marshal.PointerSize == 4 ? 788 : 792);
                            ret.peek().version = drversion.readUInt16LE(6) + '.' + drversion.readUInt16LE(4) + '.' + drversion.readUInt16LE(2) + '.' + drversion.readUInt16LE(0);
                        }
                        else {
                            ret.peek().version = 'FAILED [' + this._Kernel32.GetLastError().Val + ']';
                        }
                    }
                }
            }
        }
        this._SetupAPI.SetupDiDestroyDeviceInfoList(di);
        return (ret);
    };
}

module.exports = new DeviceManager();