/*
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

var WINPTY_MOUSE_MODE_AUTO = 1;
var WINPTY_SPAWN_FLAG_AUTO_SHUTDOWN = 1;
var GENERIC_WRITE = 0x40000000;
var GENERIC_READ = 0x80000000;
var OPEN_EXISTING = 3

var duplex = require('stream').Duplex;

function windows_terminal()
{
    this._ObjectID = 'windows_terminal';
    this.Create = function Create(path, width, height)
    {
        if (!width) { width = 80; }
        if (!height) { height = 25; }

        var GM = require('_GenericMarshal');

        // Register all required WinPTY API functions.
        var winptyDll = GM.CreateNativeProxy('winpty.dll');
        winptyDll.CreateMethod('winpty_config_new');
        winptyDll.CreateMethod('winpty_config_set_initial_size');
        winptyDll.CreateMethod('winpty_config_set_mouse_mode');
        winptyDll.CreateMethod('winpty_config_set_agent_timeout');
        winptyDll.CreateMethod('winpty_open');
        winptyDll.CreateMethod('winpty_config_free');
        winptyDll.CreateMethod('winpty_agent_process');
        winptyDll.CreateMethod('winpty_conin_name');
        winptyDll.CreateMethod('winpty_conout_name');
        winptyDll.CreateMethod('winpty_conerr_name');
        winptyDll.CreateMethod('winpty_spawn_config_new');
        winptyDll.CreateMethod('winpty_spawn');
        winptyDll.CreateMethod('winpty_spawn_config_free');
        winptyDll.CreateMethod('winpty_set_size');
        winptyDll.CreateMethod('winpty_free');
        
        // Register all required Kernel32 API functions.
        var kernel32Dll = GM.CreateNativeProxy('kernel32.dll');
        kernel32Dll.CreateMethod('CreateFileW');
        kernel32Dll.CreateMethod('GetProcessId');
        kernel32Dll.CreateMethod('ReadFile');
        kernel32Dll.CreateMethod('WriteFile');
        kernel32Dll.CreateMethod('CancelIoEx');
        kernel32Dll.CreateMethod('CloseHandle');

        //
        // Reference for WinPTY can be found at:
        // https://github.com/rprichard/winpty
        // https://github.com/rprichard/winpty/blob/0.4.3/src/include/winpty.h
        //

        // Allocate a WinPTY config.
        var config = winptyDll.winpty_config_new(
            0, // [in] Agent flags
            0  // [out, optional] Config error object
        );

        // Check for failure.
        if (config.Val == 0) {
            throw ('winpty_config_new failed');
        }

        // Set initial terminal size, mouse mode and agent timeout.
        winptyDll.winpty_config_set_initial_size(config, width, height);
        winptyDll.winpty_config_set_mouse_mode(config, WINPTY_MOUSE_MODE_AUTO);
        // Amount of time to wait for the agent to startup and to wait for any given agent RPC request.
        winptyDll.winpty_config_set_agent_timeout(config, 1000);

        // Start the agent.
        // This process will connect to the agent over a control pipe,
        // and the agent will open data pipes (e.g. CONIN and CONOUT).
        var winpty = winptyDll.winpty_open(
            config, // [in] WinPTY config
            0       // [out, optional] Error object
        );

        // Free the config object after passing it to winpty_open.
        winptyDll.winpty_config_free(config);

        // Check for failure.
        if (winpty.Val == 0) {
            throw ('winpty_open failed');
        }

        // Get a handle to the agent process.
        // This value is valid for the lifetime of the winpty_t object.
        // Do not close it.
        var agentProcess = winptyDll.winpty_agent_process(winpty);

        // Determine the names of named pipes used for terminal I/O.
        // Each input or output direction uses a different half-duplex pipe.
        // The agent creates these pipes, and the client can connect to them
        // using ordinary I/O methods.
        // The strings are freed when the winpty_t object is freed.
        var coninPipeName = winptyDll.winpty_conin_name(winpty);
        var conoutPipeName = winptyDll.winpty_conout_name(winpty);
        var conerrPipeName = winptyDll.winpty_conerr_name(winpty);

        // Open handles to the terminal pipes.
        var conin = kernel32Dll.CreateFileW(coninPipeName, GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
        var conout = kernel32Dll.CreateFileW(conoutPipeName, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
        var conerr = kernel32Dll.CreateFileW(conerrPipeName, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);

        // Allocate a WinPTY spawn config.
        var spawnConfig = winptyDll.winpty_spawn_config_new(
            WINPTY_SPAWN_FLAG_AUTO_SHUTDOWN,         // [in] Spawn flags
            GM.CreateVariable(path, { wide: true }), // [in, optional] App name
            0,                                       // [in, optional] Command line arguments
            0,                                       // [in, optional] Current working directory
            0,                                       // [in, optional] Environment block passed to CreateProcess
            0                                        // [out, optional] Error object
        );

        // Check for failure.
        if (spawnConfig.Val == 0) {
            kernel32Dll.CloseHandle(conout);
            kernel32Dll.CloseHandle(conerr);
            kernel32Dll.CloseHandle(conin);
            winptyDll.winpty_free(winpty);
            throw ('winpty_spawn_config_new failed');
        }

        var process = GM.CreatePointer();
        // Spawn the new process.
        var spawnSuccess = winptyDll.winpty_spawn(
            winpty,      // [in] WinPTY object
            spawnConfig, // [in] Spawn config
            process,     // [out, optional] Process
            0,           // [out, optional] Thread
            0,           // [out, optional] Value of GetLastError if CreateProcess fails.
            0            // [out, optional] Error object
        );
    
        // Free the spawn config object after passing it to winpty_spawn.
        winptyDll.winpty_spawn_config_free(spawnConfig);

        // Check for failure.
        if (!spawnSuccess) {
            kernel32Dll.CloseHandle(conout);
            kernel32Dll.CloseHandle(conerr);
            kernel32Dll.CloseHandle(conin);
            winptyDll.winpty_free(winpty);
            throw ('winpty_spawn failed');
        }

        var processId = kernel32Dll.GetProcessId(process.Deref());

        //
        // Create a Stream Object, to be able to read/write data to WinPTY.
        //
        var ret = { _winpty: winpty, _input: conin, _output: conout, _error: conerr, kernel32Dll: kernel32Dll };
        ret._process = process;
        ret._pid = processId;
        var ds = new duplex(
        {
            'write': function (chunk, flush)
            {
                var written = require('_GenericMarshal').CreateVariable(4);
                this.terminal.kernel32Dll.WriteFile(this.terminal._input, require('_GenericMarshal').CreateVariable(chunk), chunk.length, written, 0);
                flush();
                return true;
            },
            'final': function (flush)
            {
                if (this.terminal._process)
                {
                    this.terminal._process = null;
                    winptyDll.winpty_free(this.terminal._winpty);
                }
                flush();
            }
        });
        
        //
        // The ProcessInfo object is signaled when the process exits
        //
        ds._obj = ret;
        ret._waiter = require('DescriptorEvents').addDescriptor(process.Deref());
        ret._waiter.ds = ds;
        ret._waiter._obj = ret;
        ret._waiter.on('signaled', function ()
        {
            kernel32Dll.CancelIoEx(this._obj._output, 0);

            // Child process has exited
            this.ds.push(null);

            kernel32Dll.CloseHandle(this._obj._input);
            kernel32Dll.CloseHandle(this._obj._output);
            kernel32Dll.CloseHandle(this._obj._error);

            if (this._obj._process) {
                this._obj._process = null;
                winptyDll.winpty_free(this._obj._winpty);
            }
        });
        ds.resizeTerminal = function (w, h)
        {
            var resizeSuccess = winptyDll.winpty_set_size(
                winpty, // [in] WinPTY object
                w,      // [in] Columns
                h,      // [in] Rows
                0       // [out, optional] Error object
            );

            if (!resizeSuccess) {
                console.log('winpty_set_size failed');
            }
        };

        ds.terminal = ret;
        ds._rpbuf = GM.CreateVariable(4096);
        ds._rpbufRead = GM.CreateVariable(4);
        ds.__read = function __read()
        {
            // Asyncronously read data from WinPTY
            this._rp = this.terminal.kernel32Dll.ReadFile.async(this.terminal._output, this._rpbuf, this._rpbuf._size, this._rpbufRead, 0);
            this._rp.then(function ()
            {
                var len = this.parent._rpbufRead.toBuffer().readUInt32LE();
                if (len <= 0) { return; }

                this.parent.push(this.parent._rpbuf.toBuffer().slice(0, len));
                this.parent.__read();
            });
            this._rp.parent = this;
        };
        ds.__read();
        return ds;
    }

    // This evaluates whether or not the powershell binary exists
    this.PowerShellCapable = function ()
    {
        if (require('os').arch() == 'x64')
        {
            return (require('fs').existsSync(process.env['windir'] + '\\SysWow64\\WindowsPowerShell\\v1.0\\powershell.exe'));
        }
        else
        {
            return (require('fs').existsSync(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'));
        }
    }

    // Start WinPTY with the Command Prompt
    this.Start = function Start(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT)
    {
        return (this.Create(process.env['windir'] + '\\System32\\cmd.exe', CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT));
    }

    // Start WinPTY with PowerShell
    this.StartPowerShell = function StartPowerShell(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT)
    {
        if (require('os').arch() == 'x64')
        {
            if (require('fs').existsSync(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'))
            {
                return (this.Create(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT));
            }
            else
            {
                return (this.Create(process.env['windir'] + '\\SysWow64\\WindowsPowerShell\\v1.0\\powershell.exe', CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT));
            }
        }
        else
        {
            return (this.Create(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT));
        }
    }
}

if (process.platform == 'win32')
{
    module.exports = new windows_terminal();
}
