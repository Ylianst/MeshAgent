/*
Copyright 2021 Intel Corporation

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

const CLSCTX_INPROC_SERVER = 1;
const CLSCTX_LOCAL_SERVER = 4;
const EOAC_NONE = 0;
const RPC_C_AUTHN_LEVEL_DEFAULT = 0;
const RPC_C_IMP_LEVEL_IMPERSONATE = 3;
const COINIT_MULTITHREADED = 0;

var GM = require('_GenericMarshal');
var ole32 = GM.CreateNativeProxy('ole32.dll');
ole32.CreateMethod('CLSIDFromString');
ole32.CreateMethod('CoCreateInstance');
ole32.CreateMethod('CoInitializeSecurity');
ole32.CreateMethod('CoInitialize');
ole32.CreateMethod('CoInitializeEx');
ole32.CreateMethod('IIDFromString');
ole32.CreateMethod('StringFromCLSID');
ole32.CreateMethod('StringFromIID');

function createInstance(RFCLSID, RFIID, options)
{
    ole32.CoInitializeEx(0, COINIT_MULTITHREADED);
    ole32.CoInitializeSecurity(0, -1, 0, 0, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, 0, EOAC_NONE, 0);

    var ppv = GM.CreatePointer();
    var h;
    if ((h = ole32.CoCreateInstance(RFCLSID, 0, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER, RFIID, ppv)).Val == 0)
    {
        return (ppv.Deref());
    }
    throw ('Error calling CoCreateInstance(' + h.Val + ')');
}

function CLSIDFromString(CLSIDString)
{
    var v = GM.CreateVariable(CLSIDString, { wide: true });
    var rfclsid = GM.CreateVariable(16);

    if(ole32.CLSIDFromString(v, rfclsid).Val == 0)
    {
        return (rfclsid);
    }
    else
    {
        throw ('Error Converting CLSIDString');
    }
}
function IIDFromString(IIDString)
{
    var v = GM.CreateVariable(IIDString, { wide: true });
    var rfiid = GM.CreateVariable(16);

    if(ole32.IIDFromString(v, rfiid).Val==0)
    {
        return (rfiid);
    }
    else
    {
        throw ('Error Converting IIDString');
    }
}

function marshalFunctions(obj, arr)
{
    return (GM.MarshalFunctions(obj.Deref(), arr));IID_IUnknown
}
function marshalInterface(arr)
{
    var vtbl = GM.CreateVariable(arr.length * GM.PointerSize);
    var obj = GM.CreatePointer();
    vtbl.pointerBuffer().copy(obj.toBuffer());
    obj._gcallbacks = [];

    obj.cleanup = function ()
    {
        var v;
        while (this._gcallbacks.length > 0)
        {
            v = this._gcallbacks.pop();
            v.removeAllListeners('GlobalCallback');
            GM.PutGenericGlobalCallbackEx(v);
        }
    };

    for (var i = 0; i < arr.length; ++i)
    {
        _hide(GM.GetGenericGlobalCallbackEx(arr[i].parms));
        _hide()._ObjectID = 'GlobalCallback_' + arr[i].name;
        obj._gcallbacks.push(_hide());
        _hide().obj = arr[i];
        _hide().pointerBuffer().copy(vtbl.Deref(i * GM.PointerSize, GM.PointerSize).toBuffer());
        _hide(true).on('GlobalCallback', function ()
        {
            if (arguments[0]._ptr == obj._ptr)
            {
                var args = [];
                for (var i in arguments)
                {
                    args.push(arguments[i]);
                }
                return (this.obj.func.apply(obj, args));
            }
        });
    }

    return (obj);
}
module.exports = { createInstance: createInstance, marshalFunctions: marshalFunctions, marshalInterface: marshalInterface, CLSIDFromString: CLSIDFromString, IIDFromString: IIDFromString, IID_IUnknown: IIDFromString('{00000000-0000-0000-C000-000000000046}') };
