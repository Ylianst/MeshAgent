/*
Copyright 2019 Intel Corporation

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

const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;
const EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
const HEAP_ZERO_MEMORY = 0x00000008;

var duplex = require('stream').Duplex;

function vt()
{
    this._ObjectID = 'win-virtual-terminal';
    this._GM = require('_GenericMarshal');
    this._kernel32 = this._GM.CreateNativeProxy('kernel32.dll');
    try
    {
        this._kernel32.CreateMethod('CreatePipe');
        this._kernel32.CreateMethod('CreateProcessW');
        this._kernel32.CreateMethod('CreatePseudoConsole');
        this._kernel32.CreateMethod('GetProcessHeap');
        this._kernel32.CreateMethod('HeapAlloc');
        this._kernel32.CreateMethod('InitializeProcThreadAttributeList');
        this._kernel32.CreateMethod('UpdateProcThreadAttribute');
        this._kernel32.CreateMethod('WriteFile');
        this._kernel32.CreateMethod('ReadFile');
    }
    catch (e)
    {
    }

    Object.defineProperty(this, 'supported', { value: this._kernel32.CreatePseudoConsole != null });
    this.Create = function Create(path, width, height)
    {
        if (!this.supported) { throw ('This build of Windows does not have support for PseudoConsoles'); }
        if (!width) { width = 80; }
        if (!height) { height = 25; }
        var ret = { _h: this._GM.CreatePointer(), _consoleInput: this._GM.CreatePointer(), _consoleOutput: this._GM.CreatePointer(), _input: this._GM.CreatePointer(), _output: this._GM.CreatePointer(), vt: this };
        var attrSize = this._GM.CreateVariable(8);
        var attrList;
        var pi = this._GM.CreateVariable(this._GM.PointerSize == 4 ? 16 : 24);

        // Create the necessary pipes
        if (this._kernel32.CreatePipe(ret._consoleInput, ret._input, 0, 0).Val == 0) { console.log('PIPE/FAIL'); }
        if (this._kernel32.CreatePipe(ret._output, ret._consoleOutput, 0, 0).Val == 0) { console.log('PIPE/FAIL'); }


        if (this._kernel32.CreatePseudoConsole((height << 16) | width, ret._consoleInput.Deref(), ret._consoleOutput.Deref(), 0, ret._h).Val != 0)
        {
            console.log('CreatePseudoConsole Error');
            throw ('Error calling CreatePseudoConsole()');
        }

        this._kernel32.InitializeProcThreadAttributeList(0, 1, 0, attrSize);
        attrList = this._GM.CreateVariable(attrSize.toBuffer().readUInt32LE());
        var startupinfoex = this._GM.CreateVariable(this._GM.PointerSize == 8 ? 112 : 72);
        startupinfoex.toBuffer().writeUInt32LE(this._GM.PointerSize == 8 ? 112 : 72, 0);
        attrList.pointerBuffer().copy(startupinfoex.Deref(this._GM.PointerSize == 8 ? 104 : 68, this._GM.PointerSize).toBuffer());

        if(this._kernel32.InitializeProcThreadAttributeList(attrList, 1, 0, attrSize).Val != 0)
        {
            if (this._kernel32.UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, ret._h.Deref(), this._GM.PointerSize, 0, 0).Val != 0)
            {
                if(this._kernel32.CreateProcessW(0, this._GM.CreateVariable(path, { wide: true }), 0, 0, 1, EXTENDED_STARTUPINFO_PRESENT, 0, 0, startupinfoex, pi).Val != 0)
                {
                    ret._startupinfoex = startupinfoex;
                    ret._pid = pi.Deref(this._GM.PointerSize == 4 ? 8 : 16, 4).toBuffer().readUInt32LE();

                    var ds = new duplex(
                    {
                        'write': function (chunk, flush)
                        {
                            var written = this.terminal.vt._GM.CreateVariable(4);
                            this.terminal.vt._kernel32.WriteFile(this.terminal._input.Deref(), this.terminal.vt._GM.CreateVariable(chunk), chunk.length, written, 0);
                            flush();
                            return (true);
                        },
                        'final': function (flush)
                        {
                            flush();
                        }
                    });
                    ds.terminal = ret;
                    ds._kernel32 = this._kernel32;
                    ds._rpbuf = this._GM.CreateVariable(4096);
                    ds._rpbufRead = this._GM.CreateVariable(4);

                    ds._read = function _read()
                    {
                        this._rp = this._kernel32.ReadFile.async(this.terminal._output.Deref(), this._rpbuf, this._rpbuf._size, this._rpbufRead, 0);
                        this._rp.then(function ()
                        {
                            var len = this.parent._rpbufRead.toBuffer().readUInt32LE();
                            this.parent.push(this.parent._rpbuf.toBuffer().slice(0, len));
                            this.parent._read();
                        });
                        this._rp.parent = this;
                    };
                    ds._read();
                    return (ds);
                }
                else
                {
                    console.log('FAILED!');
                }
            }

        }
        throw ('Internal Error');
    }
}

if (process.platform == 'win32')
{
    module.exports = new vt();
}