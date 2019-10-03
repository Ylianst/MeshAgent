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

var ptrsize = require('_GenericMarshal').PointerSize;

function windows_notifybar_check(title)
{
    if(require('user-sessions').getProcessOwnerName(process.pid).tsid == 0)
    {
        return (windows_notifybar_system(title));
    }
    else
    {
        return (windows_notifybar_local(title));
    }
}
function windows_notifybar_system(title)
{
    var ret = {};

    var script = Buffer.from("require('notifybar-desktop')('" + title + "').on('close', function(){process.exit();});").toString('base64');

    require('events').EventEmitter.call(ret, true).createEvent('close');

    console.log('switching');
    ret.child = require('child_process').execFile(process.execPath, [process.execPath.split('\\').pop(), '-b64exec', script], { type: 1 });
    ret.child.parent = ret;
    ret.child.stdout.on('data', function (c) { });
    ret.child.stderr.on('data', function (c) { });
    ret.child.on('exit', function (code) { this.parent.emit('close', code); });

    return (ret);
}

function windows_notifybar_local(title)
{
    var MessagePump;
    var ret;

    MessagePump = require('win-message-pump');
    ret = { _ObjectID: 'notifybar-desktop.Windows', title: title, _pumps: [], _promise: require('monitor-info').getInfo() };

    ret._promise.notifybar = ret;
    require('events').EventEmitter.call(ret, true)
    .createEvent('close');

    ret._promise.then(function (m)
    {
        var offset;
        var barWidth, monWidth, offset, barHeight, monHeight;

        for (var i in m)
        {
            //console.log('Monitor: ' + i + ' = Width[' + (m[i].right - m[i].left) + ']');
            monWidth = (m[i].right - m[i].left);
            monHeight = (m[i].bottom - m[i].top);
            barWidth = Math.floor(monWidth * 0.30);
            barHeight = Math.floor(monHeight * 0.035);
            offset = Math.floor(monWidth * 0.50) - Math.floor(barWidth * 0.50);
            start = m[i].left + offset;
            //console.log('   ' + start + ', ' + barWidth + ', ' + barHeight);

            var options =
                {
                    window:
                    {
                        winstyles: MessagePump.WindowStyles.WS_VISIBLE | MessagePump.WindowStyles.WS_BORDER | MessagePump.WindowStyles.WS_CAPTION | MessagePump.WindowStyles.WS_SYSMENU,
                        x: start, width: barWidth, height: barHeight, title: this.notifybar.title
                    }
                };
            
            this.notifybar._pumps.push(new MessagePump(options));
            this.notifybar._pumps.peek().notifybar = this.notifybar;
            this.notifybar._pumps.peek().on('hwnd', function (h)
            {
                this._HANDLE = h;
            });
            this.notifybar._pumps.peek().on('exit', function (h)
            {
                for(var i in this.notifybar._pumps)
                {
                    this.notifybar._pumps[i].removeAllListeners('exit');
                    this.notifybar._pumps[i].close();
                }
                this.notifybar.emit('close');
            });
            this.notifybar._pumps.peek().on('message', function onWindowsMessage(msg)
            {
                if (msg.message == 133)
                {
                    //console.log("WM_NCPAINT");
                }
                if (msg.message == 70)   // We are intercepting WM_WINDOWPOSCHANGING to DISABLE moving the window
                {
                    if (this._HANDLE)
                    {
                        var flags = 0;
                        switch (ptrsize)
                        {
                            case 4:
                                flags = msg.lparam_raw.Deref(24, 4).toBuffer().readUInt32LE() | 0x0002; // Set SWP_NOMOVE
                                msg.lparam_raw.Deref(24, 4).toBuffer().writeUInt32LE(flags);
                                break;
                            case 8:
                                flags = msg.lparam_raw.Deref(32, 4).toBuffer().readUInt32LE() | 0x0002  // Set SWP_NOMOVE
                                msg.lparam_raw.Deref(32, 4).toBuffer().writeUInt32LE(flags);
                                break;
                        }
                    }
                }
            });
        }
    });

    return (ret);
}







switch(process.platform)
{
    case 'win32':
        module.exports = windows_notifybar_check;
        break;
    case 'linux':
    case 'freebsd':
        break;
}


