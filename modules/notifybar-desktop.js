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
const IDC_ARROW = 32512;

const SW_SHOW = 5;
const SW_HIDE = 0;

const WM_COMMAND = 0x0111;
const WM_CTLCOLORSTATIC = 0x0138;
const WM_MOUSEMOVE = 0x0200;
const WM_SETFONT = 0x0030;
const WM_LBUTTONDOWN = 0x0201;
const WM_USER = 0x0400;

const WS_CHILD = 0x40000000;
const WS_TABSTOP = 0x00010000;
const WS_VISIBLE = 0x10000000;

const STM_SETIMAGE = 0x0172;
const STM_GETIMAGE = 0x0173;
const IMAGE_BITMAP = 0;
const SmoothingModeAntiAlias = 5;
const InterpolationModeBicubic = 8;

const BS_BITMAP = 0x00000080;
const BS_PUSHBUTTON = 0x00000000;
const BS_DEFPUSHBUTTON = 0x00000001;
const BM_SETIMAGE = 0x00F7;
const BS_FLAT = 0x00008000;

const SS_BITMAP = 0x0000000E;
const SS_REALSIZECONTROL = 0x00000040;
const SS_LEFT = 0x00000000;
const SS_CENTERIMAGE = 0x00000200;

const SS_PATHELLIPSIS = 0x00008000;
const SS_WORDELLIPSIS = 0x0000C000;
const SS_ELLIPSISMASK = 0x0000C000;
const SS_NOTIFY = 0x00000100;


const MK_LBUTTON = 0x001;
const SWP_NOSIZE = 0x0001;
const SWP_NOZORDER = 0x0004;
const SWP_NOMOVE = 0x0002;

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
const pin_icon_1 = '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';
const pin_icon_2 = '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';


function string_RGB(s)
{
    var ret = RGB(0, 54, 105);
    try
    {
        var t = s.split(',');
        ret = RGB(parseInt(t[0]), parseInt(t[1]), parseInt(t[2]));
    }
    catch (x)
    {
    }
    return (ret);
}
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
function getScaledImage(b64, width, height, options)
{
    if (!options) { options = {}; }
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
        console.info1('GetScaledHBITMAP: ' + gdip.GdipCreateHBITMAPFromBitmap(nb.Deref(), scaledhbitmap, options.background == null ? gdip_RGB(0, 54, 105) : gdip_RGB(options.background)).Val);
        console.info1('ImageDispose: ' + gdip.GdipDisposeImage(pimage.Deref()).Val);
        scaledhbitmap._token = gdipToken;
        return (scaledhbitmap);
    }
    
    return (null);
}

function windows_notifybar_check(title, tsid, options)
{
    if(require('user-sessions').getProcessOwnerName(process.pid).tsid == 0)
    {
        return (windows_notifybar_system(title, tsid, options));
    }
    else
    {
        return (windows_notifybar_local(title, typeof (tsid) == 'object' ? tsid : options));
    }
}
function windows_notifybar_system(title, tsid, options)
{
    var ret = {};
    if (!options) { options = {}; }

    var script = Buffer.from("require('notifybar-desktop')('" + title + "', " + JSON.stringify(options) + ").on('close', function(){process._exit();});require('DescriptorEvents').addDescriptor(require('util-descriptors').getProcessHandle(" + process.pid + ")).on('signaled', function(){process._exit();});").toString('base64');

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

function windows_notifybar_local(title, bar_options)
{
    var MessagePump;
    var ret;
    if (!bar_options) { bar_options = {}; }
    if (bar_options.foreground == null) { bar_options.foreground = RGB(200, 200, 200); }
    if (bar_options.background == null) { bar_options.background = RGB(0, 54, 105); }
    if (typeof (bar_options.foreground) == 'string') { bar_options.foreground = string_RGB(bar_options.foreground); }
    if (typeof (bar_options.background) == 'string') { bar_options.background = string_RGB(bar_options.background); }

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
            if (m[i].dpi != null)
            {
                barHeight = Math.floor(m[i].dpi / 3);
                barWidth = Math.floor(m[i].dpi * 9);
                if (barWidth > monWidth) { barWidth = monWidth; }
            }
            console.info1('Monitor: ' + i + ' = Width[' + (m[i].right - m[i].left) + '] BarHeight[' + barHeight + '] BarWidth[' + barWidth + ']');

            offset = Math.floor(monWidth * 0.50) - Math.floor(barWidth * 0.50);
            start = m[i].left + offset;
            var options =
                {
                    window:
                    {
                        winstyles: MessagePump.WindowStyles.WS_VISIBLE | MessagePump.WindowStyles.WS_POPUP | MessagePump.WindowStyles.WS_BORDER,
                        x: start, y: m[i].top, left: m[i].left, right: m[i].right, width: barWidth, height: barHeight, title: this.notifybar.title, background: bar_options.background
                    }
                };
            
            this.notifybar._pumps.push(new MessagePump(options));
            this.notifybar._pumps.peek().brush = this.notifybar._pumps.peek()._gdi32.CreateSolidBrush(bar_options.background);
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
                this._icon = getScaledImage(x_icon, this.height * 0.75, this.height * 0.75, bar_options);
                this._addCreateWindowEx(0, GM.CreateVariable('STATIC', { wide: true }), GM.CreateVariable('X', { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | SS_BITMAP | SS_CENTERIMAGE | SS_NOTIFY,
                    this.width - (this.height * 0.75) - (this.height * 0.125),  // x position 
                    this.height * 0.0625,                                        // y position 
                    this.height * 0.75,                                         // Button width
                    this.height * 0.75,                                         // Button height
                    h,          // Parent window
                    0xFFF0,     // Child ID
                    0,
                    0).then(function (c)
                    {
                        this.pump._closebutton = c;
                        this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [c, STM_SETIMAGE, IMAGE_BITMAP, this.pump._icon.Deref()]);
                    }).parentPromise.pump = this;
                this._pin1 = getScaledImage(pin_icon_1, this.height * 0.75, this.height * 0.75, bar_options);
                this._pin2 = getScaledImage(pin_icon_2, this.height * 0.75, this.height * 0.75, bar_options);
                this._addCreateWindowEx(0, GM.CreateVariable('STATIC', { wide: true }), GM.CreateVariable('P', { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | SS_BITMAP | SS_CENTERIMAGE | SS_NOTIFY,
                    this.height * 0.125,                                        // x position 
                    this.height * 0.0625,                                       // y position 
                    this.height * 0.75,                                         // Button width
                    this.height * 0.75,                                         // Button height
                    h,          // Parent window
                    0xFFA0,     // Child ID
                    0,
                    0).then(function (c)
                    {
                        this.pump._pushpin = c;
                        this.pump._pinned = true;
                        this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [c, STM_SETIMAGE, IMAGE_BITMAP, this.pump._pin1.Deref()]);
                    }).parentPromise.pump = this;
                this._addCreateWindowEx(0, GM.CreateVariable('STATIC', { wide: true }), GM.CreateVariable(this._title, { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | SS_LEFT | SS_CENTERIMAGE | SS_WORDELLIPSIS,
                    this.height,                        // x position 
                    this.height * 0.125,                // y position 
                    this.width - (this.height * 2),         // Button width
                    this.height * 0.75,                 // Button height
                    h,          // Parent window
                    0xFFF1,     // Child ID
                    0,
                    0).then(function (c)
                    {
                        this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [c, WM_SETFONT, this.pump.font, 1]);
                    }).parentPromise.pump = this;
                this._addAsyncMethodCall(this._user32.LoadCursorA.async, [0, IDC_ARROW]).then(function (cs)
                {
                    this.pump._addAsyncMethodCall(this.pump._user32.SetCursor.async, [cs]);
                }).parentPromise.pump = this;
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
            this.notifybar._pumps.peek()._idleTimeout = function ()
            {
                this._minimized = true;
                this._idle = null;
                this._addAsyncMethodCall(this._user32.SetWindowPos.async, [this._HANDLE, 0, 0, 0, this.width, this.height * 0.125, SWP_NOMOVE | SWP_NOZORDER]);
                this._user32.PostMessageA(this._HANDLE, WM_USER, 0, 0);
            };
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
                            case 0xFFA0:
                                switch(this._pinned)
                                {
                                    case true:  // UNPIN
                                        this._addAsyncMethodCall(this._user32.SendMessageW.async, [this._pushpin, STM_SETIMAGE, IMAGE_BITMAP, this._pin2.Deref()]);
                                        if (this._idle) { clearTimeout(this._idle); this._idle = null; }
                                        this._idle = setTimeout(this._idleTimeout.bind(this), 3000);
                                        break;
                                    case false: // PIN
                                        if (this._idle) { clearTimeout(this._idle); this._idle = null; }
                                        this._addAsyncMethodCall(this._user32.SendMessageW.async, [this._pushpin, STM_SETIMAGE, IMAGE_BITMAP, this._pin1.Deref()]);
                                        break;
                                }
                                this._pinned = !this._pinned;
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
                        this._gdi32.SetTextColor(hdcStatic, bar_options.foreground);
                        this._gdi32.SetBkColor(hdcStatic, bar_options.background);
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
                    case WM_MOUSEMOVE:
                        if (!this._pinned)
                        {
                            if (this._minimized)
                            {
                                this._minimized = false;
                                this._addAsyncMethodCall(this._user32.SetWindowPos.async, [this._HANDLE, 0, 0, 0, this.width, this.height, SWP_NOMOVE | SWP_NOZORDER]);
                                this._user32.PostMessageA(this._HANDLE, WM_USER, 0, 0);
                            }
                            if (this._idle) { clearTimeout(this._idle); this._idle = null; }
                            this._idle = setTimeout(this._idleTimeout.bind(this), 3000);
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
        module.exports.RGB = RGB;
        break;
    case 'linux':
    case 'freebsd':
        module.exports = x_notifybar_check;
        break;
    case 'darwin':
        module.exports = macos_messagebox;
        break;
}


