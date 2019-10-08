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
var ClientMessage = 33;


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

    require('events').EventEmitter.call(ret, true)
        .createEvent('close')
        .addMethod('close', function close() { this.child.kill(); });

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
        .createEvent('close')
        .addMethod('close', function close()
        {
            for (var i in this._pumps)
            {
                this._pumps[i].removeAllListeners('exit');
                this._pumps[i].close();
            }
        });

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


function x_notifybar_check(title)
{
    if(require('user-sessions').Self()!=0)
    {
        return (x_notifybar(title)); // No Dispatching necessary
    }
    else
    {
        // We are root, so we should try to spawn a child into the user's desktop
        var uid = require('user-sessions').consoleUid();
        var xinfo = require('monitor-info').getXInfo(uid);
        
        if (!xinfo || !xinfo.xauthority)
        {
            throw('XServer Initialization Error')
        }

        var ret = {};
        var script = Buffer.from("require('notifybar-desktop')('" + title + "').on('close', function(){process.exit();});").toString('base64');

        require('events').EventEmitter.call(ret, true)
            .createEvent('close')
            .addMethod('close', function close() { this.child.kill(); });

        ret.child = require('child_process').execFile(process.execPath, [process.execPath.split('/').pop(), '-b64exec', script], { uid: uid, env: xinfo.exportEnv() });
        ret.child.parent = ret;
        ret.child.stdout.on('data', function (c) { });
        ret.child.stderr.on('data', function (c) { });
        ret.child.on('exit', function (code) { this.parent.emit('close', code); });

        return (ret);
    }
}

function x_notifybar(title)
{
    ret = { _ObjectID: 'notifybar-desktop.X', title: title, _windows: [], _promise: require('monitor-info').getInfo() };

    ret._promise.notifybar = ret;
    require('events').EventEmitter.call(ret, true)
        .createEvent('close')
        .addMethod('close', function close()
        {
        });

    ret._promise.then(function (m)
    {
        var offset;
        var barWidth, monWidth, offset, barHeight, monHeight;
        for (var i in m)
        {
            monWidth = (m[i].right - m[i].left);
            monHeight = (m[i].bottom - m[i].top);
            barWidth = Math.floor(monWidth * 0.30);
            barHeight = Math.floor(monHeight * 0.035);
            offset = Math.floor(monWidth * 0.50) - Math.floor(barWidth * 0.50);
            start = m[i].left + offset;
            console.log(start, barWidth, barHeight);

            var white = require('monitor-info')._X11.XWhitePixel(m[i].display, m[i].screenId).Val;
            this.notifybar._windows.push({
                root: require('monitor-info')._X11.XRootWindow(m[i].display, m[i].screenId),
                display: m[i].display, id: m[i].screedId
            });

            this.notifybar._windows.peek().notifybar = require('monitor-info')._X11.XCreateSimpleWindow(m[i].display, this.notifybar._windows.peek().root, start, 0, barWidth, 1, 0, white, white);
            require('monitor-info')._X11.XStoreName(m[i].display, this.notifybar._windows.peek().notifybar, require('_GenericMarshal').CreateVariable(this.notifybar.title));

            require('monitor-info').setWindowSizeHints(m[i].display, this.notifybar._windows.peek().notifybar, start, 0, barWidth, 1, barWidth, 1, barWidth, 1);
            require('monitor-info').hideWindowIcon(m[i].display, this.notifybar._windows.peek().root, this.notifybar._windows.peek().notifybar);

            require('monitor-info').setAllowedActions(m[i].display, this.notifybar._windows.peek().notifybar, require('monitor-info').MOTIF_FLAGS.MWM_FUNC_CLOSE);
            require('monitor-info').setAlwaysOnTop(m[i].display, this.notifybar._windows.peek().root, this.notifybar._windows.peek().notifybar);


            var wm_delete_window_atom = require('monitor-info')._X11.XInternAtom(m[i].display, require('_GenericMarshal').CreateVariable('WM_DELETE_WINDOW'), 0).Val;
            var atoms = require('_GenericMarshal').CreateVariable(4);
            atoms.toBuffer().writeUInt32LE(wm_delete_window_atom);
            require('monitor-info')._X11.XSetWMProtocols(m[i].display, this.notifybar._windows.peek().notifybar, atoms, 1);

            require('monitor-info')._X11.XMapWindow(m[i].display, this.notifybar._windows.peek().notifybar);
            require('monitor-info')._X11.XFlush(m[i].display);

            this.notifybar._windows.peek().DescriptorEvent = require('DescriptorEvents').addDescriptor(require('monitor-info')._X11.XConnectionNumber(m[i].display).Val, { readset: true });
            console.log(this.notifybar._windows.peek().DescriptorEvent);
            this.notifybar._windows.peek().DescriptorEvent.atom = wm_delete_window_atom;
            this.notifybar._windows.peek().DescriptorEvent.ret = this.notifybar;
            this.notifybar._windows.peek().DescriptorEvent._display = m[i].display;
            this.notifybar._windows.peek().DescriptorEvent.on('readset', function (fd)
            {
                var XE = require('_GenericMarshal').CreateVariable(1024);
                while (require('monitor-info')._X11.XPending(this._display).Val)
                {
                    require('monitor-info')._X11.XNextEventSync(this._display, XE);
                    if (XE.Deref(0, 4).toBuffer().readUInt32LE() == ClientMessage)
                    {
                        var clientType = XE.Deref(require('_GenericMarshal').PointerSize == 8 ? 56 : 28, 4).toBuffer().readUInt32LE();
                        if (clientType == this.atom)
                        {
                            require('DescriptorEvents').removeDescriptor(fd);
                            require('monitor-info')._X11.XCloseDisplay(this._display);
                            ret.emit('close');
                            ret._windows.clear();
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
        module.exports = x_notifybar_check;
        break;
}


