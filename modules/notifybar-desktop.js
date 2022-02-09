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
var GM = require('_GenericMarshal');
const FW_DONTCARE = 0;
const DEFAULT_CHARSET = 1;
const OUT_DEFAULT_PRECIS = 0;
const CLIP_DEFAULT_PRECIS = 0;
const DEFAULT_QUALITY = 0;
const DEFAULT_PITCH = 0;
const FF_SWISS = (2 << 4);  /* Variable stroke width, sans-serifed. */

const WM_NCLBUTTONDOWN = 0x00A1;
const HT_CAPTION = 2;
const WM_WINDOWPOSCHANGING = 70;
const CS_DROPSHADOW = 0x00020000;

const WM_COMMAND = 0x0111;
const WM_CTLCOLORSTATIC = 0x0138;
const WM_MOUSEMOVE = 0x0200;
const WM_SETFONT = 0x0030;
const WM_LBUTTONDOWN = 0x0201;

const WS_CHILD = 0x40000000;
const WS_TABSTOP = 0x00010000;
const WS_VISIBLE = 0x10000000;

const STM_SETIMAGE = 0x0172;
const STM_GETIMAGE = 0x0173;
const IMAGE_BITMAP = 0;
const SmoothingModeAntiAlias = 5;
const InterpolationModeBicubic = 8;

const BS_BITMAP = 0x00000080;
const BS_DEFPUSHBUTTON = 0x00000001;
const BM_SETIMAGE = 0x00F7;

const SS_BITMAP = 0x0000000E;
const SS_REALSIZECONTROL = 0x00000040;
const SS_LEFT = 0x00000000;
const SS_CENTERIMAGE = 0x00000200;

const SS_PATHELLIPSIS = 0x00008000;
const SS_WORDELLIPSIS = 0x0000C000;
const SS_ELLIPSISMASK = 0x0000C000;


const MK_LBUTTON = 0x001;
const SWP_NOSIZE = 0x0001;
const SWP_NOZORDER = 0x0004;

const WS_SIZEBOX = 0x00040000;

var SHM = GM.CreateNativeProxy('Shlwapi.dll');
SHM.CreateMethod('SHCreateMemStream');
var gdip = GM.CreateNativeProxy('Gdiplus.dll');
gdip.CreateMethod('GdipBitmapSetResolution');
gdip.CreateMethod('GdipCreateBitmapFromStream');
gdip.CreateMethod('GdipCreateBitmapFromScan0');
gdip.CreateMethod('GdipCreateHBITMAPFromBitmap');
gdip.CreateMethod('GdipDisposeImage');
gdip.CreateMethod('GdipDrawImageRectI');
gdip.CreateMethod('GdipFree');
gdip.CreateMethod('GdipLoadImageFromStream');
gdip.CreateMethod('GdipGetImageGraphicsContext');
gdip.CreateMethod('GdipGetImageHorizontalResolution');
gdip.CreateMethod('GdipGetImagePixelFormat');
gdip.CreateMethod('GdipGetImageVerticalResolution');
gdip.CreateMethod('GdipSetInterpolationMode');
gdip.CreateMethod('GdipSetSmoothingMode');
gdip.CreateMethod('GdiplusStartup');
gdip.CreateMethod('GdiplusShutdown');

const x_icon = 'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAAAXNSR0IArs4c6QAABKlJREFUeF7t3U1S20AQBeAZmaIw5A7ANpfxKmyS4yUbZeXLsMXhDrYpB6SUBBK2kDT66X7zqDRbTNzuT29mNJYU7+yHqgOeqhorxhkI2UFgIAZC1gGyciwhBkLWAbJyLCEGQtYBsnIsIQZC1gGyciwhBkLWAbJyLCEGQtYBsnIsIQZC1gGyciwhBuLc82KxSi4uvvvr6x/+/v7A1JP869fz5z+PP/3T4dfZy2GNrg2ekHyxWOVZlro8P3fL5drf3t6xoBQYLw+b1D/tV875Q56c3aFRoCAnGNWhR4JyjOHzvKwu9wkcBQbSikGC0oZRlYZGgYCUc0Y1THUNypGSUs4Zm8c02W9XVTKaJSJR1EEGYURKyhAMdFJUQUZhgFH6hqmuECOSogbSO2eE1pLKw9cUDFRSVEBmYSgnpcTYbFK/33fOGaHjRTMp4iAFRpZlqS/OM+b+CCdFAkM7KaIgk+aMEJoQypgJPFSSJooYSInxkqXOCSSj2ZGZKK8YmzSZMUyhJnoxkL9XX9Jku/3m3etZrvjPRBTJYarzMy2vfif77Z3EZxYDef3gj6nvOcGaXfBIlDmrqcG1jqwp9O+KgZR7P0QonxGj6KEoyDvKvGVl6CgK7RJjhimdnWpxkNhJqVdTu+1KbT67XK79jc7XBiogFUq5aafZmMb4/ZmTUY0KaiBolOL9qi+XunZtg0Nh6AWKyYCAnKAor74y513xTZ8ahvBqqsteNSH1GS1g9VWc/ah9GBCGyiqr84z26PtqtaM4NORM+T0QAwoCW31NaXrX3wDmjOZbq6W8Lynqqy8JFHAyYJN6W28g5wpzUCJhwIes4x5BtlmmoETEiApCOadExogO8o6ivPc1JCkEGBQgJ0nR3GbpQyHBoAE5OaNHoxBhUIFEQSHDoAM5nlOS3W41ZOif/BpCDF6Qh4fygoTJzR7yhwYS7pLGpTq970qIAt86CW6paG7Tt705GQoFCOSCBFv2hoeoehJ/u40s6rY8SVKiJiR6MprHDAFKNBDIBQnDQnr6qsgoUUDgq6mxMBFR4CC02+4kwxcUhG7OCCUnQlJgILRzBhkKBASRjLy4LovsVoiQddvv1UEgc8Zyuc68d3PuGww2DzR8qYJALmZ4u1SnaCjb/SlB5JYXqIFAktG4bqp+T80vuZSTogKCmDO67hGBpFIRRRwkJkY1AkDSqYQiCsKAcYqifDWLAooYCOQ8Y2QDGGsKTfRiINS3RWtv7zPeFq364IDLy7W/uZn8KEDN1Zf0c0/EElJE8VM8WkNwSSyNoXLViciTgKqBduScERqfJVdfGhgqIOXXshJPBBLGkFx9aWGogVQo9eNgQ4du8/fKdy7NSYomhipIPaeMfUKQUjKa5vWSeLcf/IABbQx1kNEoM1dTY4M4ZpsFgQEBGbz6AiWjLSmhex5RGDCQ4JwSCWPI3hcSAwrSiRIZo2/1hcaAg3xAIcFoS8p/8TD+6oPbf1fRvfwQ3ToZu8qx13/sgIGQHRUGYiBkHSArxxJiIGQdICvHEmIgZB0gK8cSYiBkHSArxxJiIGQdICvHEmIgZB0gK8cSYiBkHSArxxJiIGQdICvnH1Bw7aEQPNppAAAAAElFTkSuQmCC';

function RGB(r, g, b)
{
    return (r | (g << 8) | (b << 16));
}
function gdip_RGB(r, g, b)
{
    if (g != null && b != null)
    {
        return (b | (g << 8) | (r << 16));
    }
    else
    {
        var _r = (r & 0xFF);
        var _g = ((r >> 8) & 0xFF);
        var _b = ((r >> 16) & 0xFF);
        return (RGB(_b, _g, _r));
    }
}
function getScaledImage(b64, width, height)
{

    var startupinput = require('_GenericMarshal').CreateVariable(24);
    var gdipToken = require('_GenericMarshal').CreatePointer();

    startupinput.toBuffer().writeUInt32LE(1);
    gdip.GdiplusStartup(gdipToken, startupinput, 0);

    var raw = Buffer.from(b64, 'base64');
    var nbuff = require('_GenericMarshal').CreateVariable(raw.length);
    raw.copy(nbuff.toBuffer());
    var istream = SHM.SHCreateMemStream(nbuff, raw.length);

    var pimage = require('_GenericMarshal').CreatePointer();
    var hbitmap = require('_GenericMarshal').CreatePointer();
    var status = gdip.GdipCreateBitmapFromStream(istream, pimage);
    status = gdip.GdipCreateHBITMAPFromBitmap(pimage.Deref(), hbitmap, RGB(0, 54, 105)); 
    if (status.Val == 0)
    {
        var format = GM.CreateVariable(4);
        console.info1('PixelFormatStatus: ' + gdip.GdipGetImagePixelFormat(pimage.Deref(), format).Val);
        console.info1('PixelFormat: ' + format.toBuffer().readInt32LE());
        var nb = GM.CreatePointer();

        console.info1('FromScan0: ' + gdip.GdipCreateBitmapFromScan0(width, height, 0, format.toBuffer().readInt32LE(), 0, nb).Val);

        var REAL_h = GM.CreateVariable(4);
        var REAL_w = GM.CreateVariable(4);
        console.info1('GetRes_W: ' + gdip.GdipGetImageHorizontalResolution(pimage.Deref(), REAL_w).Val);
        console.info1('GetRes_H: ' + gdip.GdipGetImageVerticalResolution(pimage.Deref(), REAL_h).Val);
        console.info1('Source DPI: ' + REAL_w.toBuffer().readFloatLE() + ' X ' + REAL_h.toBuffer().readFloatLE());
        console.info1('SetRes: ' + gdip.GdipBitmapSetResolution(nb.Deref(), REAL_w.toBuffer().readFloatLE(), REAL_h.toBuffer().readFloatLE()).Val);

        var graphics = GM.CreatePointer();
        console.info1('GdipGetImageGraphicsContext: ' + gdip.GdipGetImageGraphicsContext(nb.Deref(), graphics).Val);
        console.info1('GdipSetSmoothingMode: ' + gdip.GdipSetSmoothingMode(graphics.Deref(), SmoothingModeAntiAlias).Val);
        console.info1('InterpolationModeBicubic: ' + gdip.GdipSetInterpolationMode(graphics.Deref(), InterpolationModeBicubic).Val);
        console.info1('DrawImage: ' + gdip.GdipDrawImageRectI(graphics.Deref(), pimage.Deref(), 0, 0, width, height).Val);

        var scaledhbitmap = GM.CreatePointer();
        //console.info1('GetScaledHBITMAP: ' + gdip.GdipCreateHBITMAPFromBitmap(nb.Deref(), scaledhbitmap, options.background).Val);
        console.info1('GetScaledHBITMAP: ' + gdip.GdipCreateHBITMAPFromBitmap(nb.Deref(), scaledhbitmap, gdip_RGB(0, 54, 105)).Val);
        console.info1('ImageDispose: ' + gdip.GdipDisposeImage(pimage.Deref()).Val);
        scaledhbitmap._token = gdipToken;
        return (scaledhbitmap);
    }
    
    return (null);
}

function windows_notifybar_check(title, tsid)
{
    if(require('user-sessions').getProcessOwnerName(process.pid).tsid == 0)
    {
        return (windows_notifybar_system(title, tsid));
    }
    else
    {
        return (windows_notifybar_local(title));
    }
}
function windows_notifybar_system(title, tsid)
{
    var ret = {};
    
    var script = Buffer.from("require('notifybar-desktop')('" + title + "').on('close', function(){process._exit();});require('DescriptorEvents').addDescriptor(require('util-descriptors').getProcessHandle(" + process.pid + ")).on('signaled', function(){process._exit();});").toString('base64');

    require('events').EventEmitter.call(ret, true)
        .createEvent('close')
        .addMethod('close', function close() { this.child.kill(); });

    ret.child = require('child_process').execFile(process.execPath, [process.execPath.split('\\').pop(), '-b64exec', script], { type: 1, uid: tsid });
    ret.child.descriptorMetadata = 'notifybar-desktop';
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
            for (var i = 0; i < this._pumps.length; ++i)
            {
                this._pumps[i].removeAllListeners('exit');
                this._pumps[i].close();
            }
            this._pumps = [];
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
            console.info1('Monitor: ' + i + ' = Width[' + (m[i].right - m[i].left) + '] BarHeight[' + barHeight + '] BarWidth[' + barWidth + ']');

            offset = Math.floor(monWidth * 0.50) - Math.floor(barWidth * 0.50);
            start = m[i].left + offset;
            var options =
                {
                    window:
                    {
                        winstyles: MessagePump.WindowStyles.WS_VISIBLE | MessagePump.WindowStyles.WS_POPUP | MessagePump.WindowStyles.WS_BORDER | CS_DROPSHADOW,
                        x: start, y: m[i].top, left: m[i].left, right: m[i].right, width: barWidth, height: barHeight, title: this.notifybar.title, background: RGB(0, 54, 105)
                    }
                };
            
            this.notifybar._pumps.push(new MessagePump(options));
            this.notifybar._pumps.peek().brush = this.notifybar._pumps.peek()._gdi32.CreateSolidBrush(RGB(0, 54, 105));
            this.notifybar._pumps.peek()._L = m[i].left;
            this.notifybar._pumps.peek()._R = m[i].right;

            this.notifybar._pumps.peek()._X = options.window.x;
            this.notifybar._pumps.peek()._Y = options.window.y;
            this.notifybar._pumps.peek().i = i;
            this.notifybar._pumps.peek().notifybar = this.notifybar;
            this.notifybar._pumps.peek().width = barWidth;
            this.notifybar._pumps.peek().height = barHeight;
            this.notifybar._pumps.peek().font = this.notifybar._pumps.peek()._gdi32.CreateFontW(barHeight/2, 0, 0, 0, FW_DONTCARE, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, require('_GenericMarshal').CreateVariable('Arial', { wide: true }));
            this.notifybar._pumps.peek()._title = this.notifybar.title;
            this.notifybar._pumps.peek().on('hwnd', function (h)
            {
                this._HANDLE = h;
                this._icon = getScaledImage(x_icon, this.height * 0.75, this.height * 0.75);
                this._addCreateWindowEx(0, GM.CreateVariable('BUTTON', { wide: true }), GM.CreateVariable('X', { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | BS_BITMAP,
                    this.width - (this.height * 0.75) - (this.height * 0.125),    // x position 
                    this.height * 0.125,                                        // y position 
                    this.height * 0.75,                                         // Button width
                    this.height * 0.75,                                         // Button height
                    h,          // Parent window
                    0xFFF0,     // Child ID
                    0,
                    0).then(function (c)
                    {
                        this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [c, BM_SETIMAGE, IMAGE_BITMAP, this.pump._icon.Deref()]);
                    }).parentPromise.pump = this;
                this._addCreateWindowEx(0, GM.CreateVariable('STATIC', { wide: true }), GM.CreateVariable(this._title, { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | SS_LEFT | SS_CENTERIMAGE | SS_WORDELLIPSIS,
                    this.height * 0.125,                // x position 
                    this.height * 0.125,                // y position 
                    this.width - (this.height),  // Button width
                    this.height * 0.75,                 // Button height
                    h,          // Parent window
                    0xFFF1,     // Child ID
                    0,
                    0).then(function (h)
                    {
                        this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [h, WM_SETFONT, this.pump.font, 1]);
                    }).parentPromise.pump = this;
                //this._addAsyncMethodCall(this._user32.SendMessageW.async, [h, WM_SETFONT, this.font, 1]).then(function (r) { console.log('FONT: ' + r.Val); });
            });
            this.notifybar._pumps.peek().on('exit', function (h)
            {             
                for (var i = 0; i < this.notifybar._pumps.length; ++i)
                {
                    this.notifybar._pumps[i].removeAllListeners('exit');
                    this.notifybar._pumps[i].close();
                }
                this.notifybar.emit('close');
                this.notifybar._pumps = [];
            });
            this.notifybar._pumps.peek().on('message', function onWindowsMessage(msg)
            {
                switch (msg.message)
                {
                    case WM_COMMAND:
                        switch (msg.wparam)
                        {
                            case 0xFFF0:
                                this.close();
                                break;
                        }
                        break;
                    case WM_LBUTTONDOWN:
                        this._addAsyncMethodCall(this._user32.ReleaseCapture.async, []).then(function ()
                        {
                            this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [this.pump._HANDLE, WM_NCLBUTTONDOWN, HT_CAPTION, 0]);
                        }).parentPromise.pump = this;
                        break;

                    case WM_CTLCOLORSTATIC:
                        console.info1('WM_CTLCOLORSTATIC => ' + msg.lparam, msg.wparam);
                        var hdcStatic = msg.wparam;
                        this._gdi32.SetTextColor(hdcStatic, RGB(200, 200, 200));
                        this._gdi32.SetBkColor(hdcStatic, RGB(0, 54, 105));
                        return (this.brush);
                        break;
                    case WM_WINDOWPOSCHANGING:
                        if (this._HANDLE)
                        {
                            // If the bar is too far left, adjust to left most position
                            if (msg.lparam_raw.Deref(ptrsize == 4 ? 8 : 16, 4).toBuffer().readInt32LE() < this._options.window.left)
                            {
                                msg.lparam_raw.Deref(ptrsize == 4 ? 8 : 16, 4).toBuffer().writeInt32LE(this._options.window.left);
                            }

                            // If the bar is too far right, adjust to right most position
                            if ( (msg.lparam_raw.Deref(ptrsize == 4 ? 8 : 16, 4).toBuffer().readInt32LE()+this._options.window.width) > this._options.window.right)
                            {
                                msg.lparam_raw.Deref(ptrsize == 4 ? 8 : 16, 4).toBuffer().writeInt32LE(this._options.window.right - this._options.window.width);
                            }

                            // Lock the bar to the y axis
                            msg.lparam_raw.Deref(ptrsize == 4 ? 12 : 20, 4).toBuffer().writeInt32LE(this._options.window.y);
                        }
                        break;
                }
            });
        }
    });

    return (ret);
}


function x_notifybar_check(title)
{
    var script = Buffer.from("require('notifybar-desktop')('" + title + "').on('close', function(){process.exit();});").toString('base64');

    var min = require('user-sessions').minUid();
    var uid = -1;
    var self = require('user-sessions').Self();

    try
    {
        uid = require('user-sessions').consoleUid();
    }
    catch(xx)
    {
    }

    if (self != 0 || uid == 0)
    {
        return (x_notifybar(title)); // No Dispatching necessary
    }
    else
    {
        // We are root, so we should try to spawn a child into the user's desktop
        if (uid < min && uid != 0)
        {
            // Lets hook login event, so we can respawn the bars later
            var ret = { min: min };
            require('events').EventEmitter.call(ret, true)
                .createEvent('close')
                .addMethod('close', function close()
                {
                    require('user-sessions').removeListener('changed', this._changed);
                    this._close2();
                });
            ret._changed = function _changed()
            {
                var that = _changed.self;
                var uid = require('user-sessions').consoleUid();
                if (uid >= that.min)
                {
                    require('user-sessions').removeListener('changed', _changed);
                    var xinfo = require('monitor-info').getXInfo(uid);
                    that.child = require('child_process').execFile(process.execPath, [process.execPath.split('/').pop(), '-b64exec', script], { uid: uid, env: xinfo.exportEnv() });
                    that.child.descriptorMetadata = 'notifybar-desktop';
                    that.child.parent = that;
                    that.child.stdout.on('data', function (c) { });
                    that.child.stderr.on('data', function (c) { });
                    that.child.on('exit', function (code) { this.parent.emit('close', code); });
                    that._close2 = function _close2()
                    {
                        _close2.child.kill();
                    };
                    that._close2.child = that.child;

                }
            };
            ret._changed.self = ret;
            require('user-sessions').on('changed', ret._changed);
            ret._close2 = function _close2()
            {
                this.emit('close');
            };
            return (ret);
        }

        var xinfo = require('monitor-info').getXInfo(uid);
        if (!xinfo)
        {
            throw('XServer Initialization Error')
        }
        var ret = {};
        require('events').EventEmitter.call(ret, true)
            .createEvent('close')
            .addMethod('close', function close() { this.child.kill(); });

        ret.child = require('child_process').execFile(process.execPath, [process.execPath.split('/').pop(), '-b64exec', script], { uid: uid, env: xinfo.exportEnv() });
        ret.child.descriptorMetadata = 'notifybar-desktop';
        ret.child.parent = ret;
        ret.child.stdout.on('data', function (c) { });
        ret.child.stderr.on('data', function (c) { });
        ret.child.on('exit', function (code) { this.parent.emit('close', code); });

        return (ret);
    }
}

function x_notifybar(title)
{
    ret = { _ObjectID: 'notifybar-desktop.X', title: title, _windows: [], _promise: require('monitor-info').getInfo(), monitors: [], workspaces: {} };

    ret._promise.notifybar = ret;
    require('events').EventEmitter.call(ret, true)
        .createEvent('close')
        .addMethod('close', function close()
        {
        });

    ret._promise.createBars = function (m)
    {
        for (var i in m)
        {
            monWidth = (m[i].right - m[i].left);
            monHeight = (m[i].bottom - m[i].top);
            barWidth = Math.floor(monWidth * 0.30);
            barHeight = Math.floor(monHeight * 0.035);
            offset = Math.floor(monWidth * 0.50) - Math.floor(barWidth * 0.50);
            start = m[i].left + offset;

            var white = require('monitor-info')._X11.XWhitePixel(m[i].display, m[i].screenId).Val;
            this.notifybar._windows.push({
                root: require('monitor-info')._X11.XRootWindow(m[i].display, m[i].screenId),
                display: m[i].display, id: m[i].screedId
            });

            this.notifybar._windows.peek().notifybar = require('monitor-info')._X11.XCreateSimpleWindow(m[i].display, this.notifybar._windows.peek().root, start, 0, barWidth, 1, 0, white, white);
            require('monitor-info')._X11.XStoreName(m[i].display, this.notifybar._windows.peek().notifybar, require('_GenericMarshal').CreateVariable(this.notifybar.title));
            require('monitor-info')._X11.Xutf8SetWMProperties(m[i].display, this.notifybar._windows.peek().notifybar, require('_GenericMarshal').CreateVariable(this.notifybar.title), 0, 0, 0, 0, 0, 0);

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
    };
    ret._promise.then(function (m)
    {
        var offset;
        var barWidth, monWidth, offset, barHeight, monHeight;
        this.notifybar.monitors = m;
        if (m.length > 0)
        {
            var ws = 0;
            try
            {
                ws = m[0].display.getCurrentWorkspace();
                this.notifybar.workspaces[ws] = true;
                this.createBars(m);
            } 
            catch(wex)
            {
            }

            m[0].display._notifyBar = this.notifybar;
            m[0].display.on('workspaceChanged', function (w)
            {
                if(!this._notifyBar.workspaces[w])
                {
                    this._notifyBar.workspaces[w] = true;
                    this._notifyBar._promise.createBars(this._notifyBar.monitors);
                }
            });
        }
       
    });
    return (ret);
}

function macos_messagebox(title)
{
    var ret = {};
    require('events').EventEmitter.call(ret, true)
        .createEvent('close')
        .addMethod('close', function close() { this._messageBox.close(); });
    ret._messageBox = require('message-box').create('', title, 0, ['Disconnect']);
    ret._messageBox.that = ret;
    ret._messageBox.then(function () { this.that.emit('close'); }, function () { this.that.emit('close'); });
    return (ret);
}

switch(process.platform)
{
    case 'win32':
        module.exports = windows_notifybar_check;
        module.exports.system = windows_notifybar_system;
        break;
    case 'linux':
    case 'freebsd':
        module.exports = x_notifybar_check;
        break;
    case 'darwin':
        module.exports = macos_messagebox;
        break;
}


