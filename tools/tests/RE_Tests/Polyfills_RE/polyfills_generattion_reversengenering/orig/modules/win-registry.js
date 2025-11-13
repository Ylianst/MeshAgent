/*
Copyright 2018-2022 Intel Corporation

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

var KEY_QUERY_VALUE = 0x0001;
var KEY_ENUMERATE_SUB_KEYS = 0x0008;
var KEY_WRITE = 0x20006;

//
// Registry
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/25cce700-7fcf-4bb6-a2f3-0f6d08430a55
//
var KEY_DATA_TYPES =
    {
        REG_NONE: 0,
        REG_SZ: 1,
        REG_EXPAND_SZ: 2,
        REG_BINARY: 3,
        REG_DWORD: 4,
        REG_DWORD_BIG_ENDIAN: 5,
        REG_LINK: 6,
        REG_MULTI_SZ: 7,
        REG_RESOURCE_LIST: 8,
        REG_FULL_RESOURCE_DESCRIPTOR: 9,
        REG_RESOURCE_REQUIREMENTS_LIST: 10,
        REG_QWORD: 11
    };

function windows_registry()
{
    this._ObjectId = 'win-registry';
    this._marshal = require('_GenericMarshal');
    this._Kernel32 = this._marshal.CreateNativeProxy('Kernel32.dll');
    this._Kernel32.CreateMethod('FileTimeToSystemTime');                // https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-filetimetosystemtime
    this._AdvApi = this._marshal.CreateNativeProxy('Advapi32.dll');
    this._AdvApi.CreateMethod('RegCreateKeyExW');                       // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw
    this._AdvApi.CreateMethod('RegEnumKeyExW');                         // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw
    this._AdvApi.CreateMethod('RegEnumValueW');                         // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew
    this._AdvApi.CreateMethod('RegOpenKeyExW');                         // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw
    this._AdvApi.CreateMethod('RegQueryInfoKeyW');                      // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw
    this._AdvApi.CreateMethod('RegQueryValueExW');                      // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw
    this._AdvApi.CreateMethod('RegCloseKey');                           // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey
    this._AdvApi.CreateMethod('RegDeleteKeyW');                         // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletekeyw
    this._AdvApi.CreateMethod('RegDeleteValueW');                       // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletevaluew
    this._AdvApi.CreateMethod('RegSetValueExW');                        // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw
    this.HKEY = { Root: Buffer.from('80000000', 'hex').swap32(), CurrentUser: Buffer.from('80000001', 'hex').swap32(), LocalMachine: Buffer.from('80000002', 'hex').swap32(), Users: Buffer.from('80000003', 'hex').swap32() };

    this.QueryKey = function QueryKey(hkey, path, key)
    {
        var err;
        var h = this._marshal.CreatePointer();
        var len = this._marshal.CreateVariable(4);
        var valType = this._marshal.CreateVariable(4);
        var HK = this._marshal.CreatePointer(hkey);
        var retVal = null;
        if (key) { key = this._marshal.CreateVariable(key, { wide: true }); }
        if (!path) { path = ''; }


        // Try to open the registry key for enumeration first.
        if ((err = this._AdvApi.RegOpenKeyExW(HK, this._marshal.CreateVariable(path, { wide: true }), 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, h).Val) != 0)
        {
            throw ('Opening Registry Key: ' + path + ' => Returned Error: ' + err);
        }
  

        if (this._AdvApi.RegQueryValueExW(h.Deref(), key ? key : 0, 0, 0, 0, len).Val == 0)
        {
            var data = this._marshal.CreateVariable(len.toBuffer().readUInt32LE());
            if (this._AdvApi.RegQueryValueExW(h.Deref(), key ? key : 0, 0, valType, data, len).Val == 0)
            {
                switch (valType.toBuffer().readUInt32LE())
                {
                    //
                    // Registry Value Types can be found at:
                    // https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
                    //
                    case KEY_DATA_TYPES.REG_DWORD:
                        retVal = data.toBuffer().readUInt32LE();
                        break;
                    case KEY_DATA_TYPES.REG_DWORD_BIG_ENDIAN:
                        retVal = data.toBuffer().readUInt32BE();
                        break;
                    case KEY_DATA_TYPES.REG_SZ:
                    case KEY_DATA_TYPES.REG_EXPAND_SZ:
                        retVal = data.Wide2UTF8;
                        break;
                    case KEY_DATA_TYPES.REG_BINARY:
                    default:
                        retVal = data.toBuffer();
                        retVal._data = data;
                        retVal._type = valType.toBuffer().readUInt32LE();
                        break;
                }
            }
        }
        else
        {
            if (key)    // Only throw an exception if an explicit key was specified, becuase it wasn't found. Otherwise, all we know is that a default value wasn't set
            {
                this._AdvApi.RegCloseKey(h.Deref());
                throw ('Not Found');
            }
        }



        if ((path == '' && !key) || !key)
        {
            var result = { subkeys: [], values: [], default: retVal };
            if (!key && !retVal) { delete result.default; }

            // Enumerate  keys
            var achClass = this._marshal.CreateVariable(1024);
            var achKey = this._marshal.CreateVariable(1024);
            var achValue = this._marshal.CreateVariable(32768);
            var achValueSize = this._marshal.CreateVariable(4);
            var nameSize = this._marshal.CreateVariable(4); 
            var achClassSize = this._marshal.CreateVariable(4); achClassSize.toBuffer().writeUInt32LE(1024);
            var numSubKeys = this._marshal.CreateVariable(4);
            var numValues = this._marshal.CreateVariable(4);
            var longestSubkeySize = this._marshal.CreateVariable(4);
            var longestClassString = this._marshal.CreateVariable(4);
            var longestValueName = this._marshal.CreateVariable(4);
            var longestValueData = this._marshal.CreateVariable(4);
            var securityDescriptor = this._marshal.CreateVariable(4);
            var lastWriteTime = this._marshal.CreateVariable(8);

            retVal = this._AdvApi.RegQueryInfoKeyW(h.Deref(), achClass, achClassSize, 0,
                numSubKeys, longestSubkeySize, longestClassString, numValues,
                longestValueName, longestValueData, securityDescriptor, lastWriteTime);
            if (retVal.Val != 0) { throw ('RegQueryInfoKeyW() returned error: ' + retVal.Val); }
            for(var i = 0; i < numSubKeys.toBuffer().readUInt32LE(); ++i)
            {
                nameSize.toBuffer().writeUInt32LE(1024);
                retVal = this._AdvApi.RegEnumKeyExW(h.Deref(), i, achKey, nameSize, 0, 0, 0, lastWriteTime);
                if(retVal.Val == 0)
                {
                    result.subkeys.push(achKey.Wide2UTF8);
                }
            }
            for (var i = 0; i < numValues.toBuffer().readUInt32LE() ; ++i)
            {
                achValueSize.toBuffer().writeUInt32LE(32768);
                if(this._AdvApi.RegEnumValueW(h.Deref(), i, achValue, achValueSize, 0, 0, 0, 0).Val == 0)
                {
                    result.values.push(achValue.Wide2UTF8);
                }
            }
            this._AdvApi.RegCloseKey(h.Deref());
            return (result);
        }

        this._AdvApi.RegCloseKey(h.Deref());
        return (retVal);
    };

    // Query the last time the key was modified
    this.QueryKeyLastModified = function QueryKeyLastModified(hkey, path, key)
    {
        var v;
        var err;
        var h = this._marshal.CreatePointer();
        var HK = this._marshal.CreatePointer(hkey);
        var retVal = null;
        if (key) { key = this._marshal.CreateVariable(key, { wide: true }); }
        if (!path) { path = ''; }

        // Open the registry key
        if ((err = this._AdvApi.RegOpenKeyExW(HK, this._marshal.CreateVariable(path, { wide: true }), 0, KEY_QUERY_VALUE, h).Val) != 0)
        {
            throw ('Opening Registry Key: ' + path + ' => Returned Error: ' + err);
        }

        var achClass = this._marshal.CreateVariable(1024);
        var achKey = this._marshal.CreateVariable(1024);
        var achValue = this._marshal.CreateVariable(32768);
        var achValueSize = this._marshal.CreateVariable(4);
        var nameSize = this._marshal.CreateVariable(4);
        var achClassSize = this._marshal.CreateVariable(4); achClassSize.toBuffer().writeUInt32LE(1024);
        var numSubKeys = this._marshal.CreateVariable(4);
        var numValues = this._marshal.CreateVariable(4);
        var longestSubkeySize = this._marshal.CreateVariable(4);
        var longestClassString = this._marshal.CreateVariable(4);
        var longestValueName = this._marshal.CreateVariable(4);
        var longestValueData = this._marshal.CreateVariable(4);
        var securityDescriptor = this._marshal.CreateVariable(4);
        var lastWriteTime = this._marshal.CreateVariable(8);

        // Get the metadata for the registry value
        v = this._AdvApi.RegQueryInfoKeyW(h.Deref(), achClass, achClassSize, 0,
            numSubKeys, longestSubkeySize, longestClassString, numValues,
            longestValueName, longestValueData, securityDescriptor, lastWriteTime);
        if (v.Val != 0) { throw ('RegQueryInfoKeyW() returned error: ' + v.Val); }

        // Convert the time format
        var systime = this._marshal.CreateVariable(16);
        if (this._Kernel32.FileTimeToSystemTime(lastWriteTime, systime).Val == 0) { throw ('Error parsing time'); }
        return (require('fs').convertFileTime(lastWriteTime));
    };

    this.WriteKey = function WriteKey(hkey, path, key, value)
    {
        var result;
        var h = this._marshal.CreatePointer();

        // Create the registry key
        if (this._AdvApi.RegCreateKeyExW(this._marshal.CreatePointer(hkey), this._marshal.CreateVariable(path, { wide: true }), 0, 0, 0, KEY_WRITE, 0, h, 0).Val != 0)
        {
            throw ('Error Opening Registry Key: ' + path);
        }

        var data;
        var dataType;

        // Create the value entry
        switch(typeof(value))
        {
            //
            // Registry Value Types can be found at:
            // https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
            //
            case 'boolean':
                dataType = KEY_DATA_TYPES.REG_DWORD;
                data = this._marshal.CreateVariable(4);
                data.toBuffer().writeUInt32LE(value ? 1 : 0);
                break;
            case 'number':
                dataType = KEY_DATA_TYPES.REG_DWORD;
                data = this._marshal.CreateVariable(4);
                data.toBuffer().writeUInt32LE(value);
                break;
            case 'string':
                dataType = KEY_DATA_TYPES.REG_SZ;
                data = this._marshal.CreateVariable(value, { wide: true });
                break;
            default:
                dataType = KEY_DATA_TYPES.REG_BINARY;
                data = this._marshal.CreateVariable(value.length);
                value.copy(data.toBuffer());
                break;
        }

        // Save the registry value
        if (this._AdvApi.RegSetValueExW(h.Deref(), key?this._marshal.CreateVariable(key, { wide: true }):0, 0, dataType, data, data._size).Val != 0)
        {           
            this._AdvApi.RegCloseKey(h.Deref());
            throw ('Error writing reg key: ' + key);
        }
        this._AdvApi.RegCloseKey(h.Deref());
    };

    // Delete a registry entry
    this.DeleteKey = function DeleteKey(hkey, path, key)
    {
        if(!key)
        {
            if (this._AdvApi.RegDeleteKeyW(this._marshal.CreatePointer(hkey), this._marshal.CreateVariable(path, { wide: true })).Val != 0)
            {
                throw ('Error Deleting Key: ' + path);
            }
        }
        else
        {
            var h = this._marshal.CreatePointer();
            var result;
            if (this._AdvApi.RegOpenKeyExW(this._marshal.CreatePointer(hkey), this._marshal.CreateVariable(path, { wide: true }), 0, KEY_QUERY_VALUE | KEY_WRITE, h).Val != 0)
            {
                throw ('Error Opening Registry Key: ' + path);
            }
            if ((result = this._AdvApi.RegDeleteValueW(h.Deref(), this._marshal.CreateVariable(key, { wide: true })).Val) != 0)
            {
                this._AdvApi.RegCloseKey(h.Deref());
                throw ('Error[' + result + '] Deleting Key: ' + path + '.' + key);
            }
            this._AdvApi.RegCloseKey(h.Deref());
        }
    };

    //
    // This function trys to convert a user name, to a windows security descriptor, which is used as the registry key for user entries
    //
    this.usernameToUserKey = function usernameToUserKey(user)
    {
        var domain = null
        if (typeof (user) == 'object' && user.user)
        {
            if (user.domain) { domain = user.domain; }      
            user = user.user;
        }

        try
        {
            // Try to fetch the current domain
            if(domain==null)
            {
                domain = require('win-wmi').query('ROOT\\CIMV2', "SELECT * FROM Win32_ComputerSystem", ['Name'])[0].Name;
                console.info1('usernameToUserKey("' + user + '") => domain: ' + domain);
            }
        }
        catch(z)
        {
        }

        try
        {
            var sid = user;
            if (typeof (user) == 'string')
            {
                // Try to find the Session ID for the specified local user
                var r = this.QueryKey(this.HKEY.LocalMachine, 'SAM\\SAM\\Domains\\Account\\Users\\Names\\' + user);
                sid = r.default._type;
            }
            var u = this.QueryKey(this.HKEY.Users);
            for(i in u.subkeys)
            {
                if(u.subkeys[i].endsWith('-' + sid))
                {
                    if (this.QueryKey(this.HKEY.Users, u.subkeys[i] + '\\Volatile Environment', 'USERDOMAIN') == domain)
                    {
                        // Try to find the Descriptor Key with the SID that we found
                        return (u.subkeys[i]);
                    }
                }
            }
        }
        catch(e)
        {
        }

        // Not Found yet, so let's try to brute-force it
        var entries = this.QueryKey(this.HKEY.Users);
        for(i in entries.subkeys)
        {
            if(entries.subkeys[i].split('-').length>5 && !entries.subkeys[i].endsWith('_Classes'))
            {
                // This will look at the list of domain users that have recently logged into the system
                try
                {
                    if (this.QueryKey(this.HKEY.Users, entries.subkeys[i] + '\\Volatile Environment', 'USERDOMAIN') == domain)
                    {
                        if (this.QueryKey(this.HKEY.Users, entries.subkeys[i] + '\\Volatile Environment', 'USERNAME') == user)
                        {
                            return (entries.subkeys[i]);
                        }
                    }
                }
                catch(ee)
                {
                }
            }
        }
        throw ('Unable to determine HKEY_USERS key for: ' + domain + '\\' + user);
    };
}

module.exports = new windows_registry();

