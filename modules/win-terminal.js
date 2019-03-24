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
var duplex = require('stream').Duplex;

var GM = require('_GenericMarshal');

function windows_terminal()
{
    this._ObjectID = 'windows_terminal';
    this.BufferLines = 512;
    this.BufferSize = 4096;

    this._kernel32 = GM.CreateNativeProxy('Kernel32.dll');
    this._kernel32.CreateMethod('CreatePipe');
    this._kernel32.CreateMethod('CreatePseudoConsole');
    this._kernel32.CreateMethod('ReadFile');
    this._kernel32.CreateMethod('WriteFile');

    
    
    this.Start = function Start(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT)
    {
        // Create the anonymous pipes that we'll use for input/output
        var inPipe_readend = GM.CreatePointer();
        var inPipe_writeend = GM.CreatePointer();
        var outPipe_readend = GM.CreatePointer();
        var outPipe_writeend = GM.CreatePointer();
        var pseudoConsole = GM.CreatePointer();

        if(this._kernel32.CreatePipe(inPipe_readend, inPipe_writeend, 0, this.BufferSize).Val !=0 &&
            this._kernel32.CreatePipe(outPipe_readend, outPipe_writeend, 0, this.BufferSize).Val !=0)
        {
            if(this._kernel32.CreatePseudoConsole(CONSOLE_SCREEN_WIDTH * CONSOLE_SCREEN_HEIGHT * this.BufferLines,
                inPipe_readend, outPipe_writeend, 1, pseudoConsole).Val == 0)
            {
                // Success
                this.ptty = pseudoConsole;
                this.ptty.stdin = inPipe_writeend;
                this.ptty.stdout = outPipe_readend;

                this._stream = new duplex(
                {
                    'write': function (chunk, flush)
                    {
                        this.ptty.stdin.write(chunk);
                        flush();
                        return (true);
                    },
                    'final': function (flush)
                    {
                        var p = this.terminal._stop();
                        p.__flush = flush;
                        p.then(function () { this.__flush(); });
                    }
                });
                this._stream.ptty = this.ptty;
            }
        }

        
        this._stream.terminal = this;
        this._stream._promise = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        this._stream._promise.terminal = this;
        return (this._stream);
    };
    this._stop = function ()
    {
        if (this.stopping) { return (this.stopping); }
        //console.log('Stopping Terminal...');
        this._ConsoleWinEventProc.removeAllListeners('GlobalCallback');
        this.stopping = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        
        var threadID = this._kernel32.GetThreadId(this._user32.SetWinEventHook.async.thread()).Val;
        this._user32.PostThreadMessageA(threadID, WM_QUIT, 0, 0);
        this._stream.emit('end');
        return (this.stopping);
    }
    
}


module.exports = new windows_terminal();