/*
Copyright 2021 Intel Corporation
@author Bryan Roe

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

const HALFTONE = 4;
const SmoothingModeAntiAlias = 5;
const InterpolationModeBicubic = 8;

const x_icon = 'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAAAXNSR0IArs4c6QAABKlJREFUeF7t3U1S20AQBeAZmaIw5A7ANpfxKmyS4yUbZeXLsMXhDrYpB6SUBBK2kDT66X7zqDRbTNzuT29mNJYU7+yHqgOeqhorxhkI2UFgIAZC1gGyciwhBkLWAbJyLCEGQtYBsnIsIQZC1gGyciwhBkLWAbJyLCEGQtYBsnIsIQZC1gGyciwhBuLc82KxSi4uvvvr6x/+/v7A1JP869fz5z+PP/3T4dfZy2GNrg2ekHyxWOVZlro8P3fL5drf3t6xoBQYLw+b1D/tV875Q56c3aFRoCAnGNWhR4JyjOHzvKwu9wkcBQbSikGC0oZRlYZGgYCUc0Y1THUNypGSUs4Zm8c02W9XVTKaJSJR1EEGYURKyhAMdFJUQUZhgFH6hqmuECOSogbSO2eE1pLKw9cUDFRSVEBmYSgnpcTYbFK/33fOGaHjRTMp4iAFRpZlqS/OM+b+CCdFAkM7KaIgk+aMEJoQypgJPFSSJooYSInxkqXOCSSj2ZGZKK8YmzSZMUyhJnoxkL9XX9Jku/3m3etZrvjPRBTJYarzMy2vfif77Z3EZxYDef3gj6nvOcGaXfBIlDmrqcG1jqwp9O+KgZR7P0QonxGj6KEoyDvKvGVl6CgK7RJjhimdnWpxkNhJqVdTu+1KbT67XK79jc7XBiogFUq5aafZmMb4/ZmTUY0KaiBolOL9qi+XunZtg0Nh6AWKyYCAnKAor74y513xTZ8ahvBqqsteNSH1GS1g9VWc/ah9GBCGyiqr84z26PtqtaM4NORM+T0QAwoCW31NaXrX3wDmjOZbq6W8Lynqqy8JFHAyYJN6W28g5wpzUCJhwIes4x5BtlmmoETEiApCOadExogO8o6ivPc1JCkEGBQgJ0nR3GbpQyHBoAE5OaNHoxBhUIFEQSHDoAM5nlOS3W41ZOif/BpCDF6Qh4fygoTJzR7yhwYS7pLGpTq970qIAt86CW6paG7Tt705GQoFCOSCBFv2hoeoehJ/u40s6rY8SVKiJiR6MprHDAFKNBDIBQnDQnr6qsgoUUDgq6mxMBFR4CC02+4kwxcUhG7OCCUnQlJgILRzBhkKBASRjLy4LovsVoiQddvv1UEgc8Zyuc68d3PuGww2DzR8qYJALmZ4u1SnaCjb/SlB5JYXqIFAktG4bqp+T80vuZSTogKCmDO67hGBpFIRRRwkJkY1AkDSqYQiCsKAcYqifDWLAooYCOQ8Y2QDGGsKTfRiINS3RWtv7zPeFq364IDLy7W/uZn8KEDN1Zf0c0/EElJE8VM8WkNwSSyNoXLViciTgKqBduScERqfJVdfGhgqIOXXshJPBBLGkFx9aWGogVQo9eNgQ4du8/fKdy7NSYomhipIPaeMfUKQUjKa5vWSeLcf/IABbQx1kNEoM1dTY4M4ZpsFgQEBGbz6AiWjLSmhex5RGDCQ4JwSCWPI3hcSAwrSiRIZo2/1hcaAg3xAIcFoS8p/8TD+6oPbf1fRvfwQ3ToZu8qx13/sgIGQHRUGYiBkHSArxxJiIGQdICvHEmIgZB0gK8cSYiBkHSArxxJiIGQdICvHEmIgZB0gK8cSYiBkHSArxxJiIGQdICvnH1Bw7aEQPNppAAAAAElFTkSuQmCC';

const MONITOR_DEFAULTTOPRIMARY = 0x00000001;
const SS_CENTERIMAGE = 0x00000200;
const WM_LBUTTONDOWN = 0x0201;
const WM_NCLBUTTONDOWN = 0x00A1;
const HT_CAPTION = 2;
const SS_NOTIFY = 0x00000100;
const WM_WINDOWPOSCHANGING = 70;
const WM_NCCALCSIZE = 0x0083;
const ptrsize = require('_GenericMarshal').PointerSize;
const SWP_NOZORDER = 0x0004;
const IDC_ARROW = 32512;
const WM_MOUSEMOVE = 0x0200;


const WM_SETFONT = 0x0030;
const WM_CTLCOLORSTATIC = 0x0138;
const WM_CREATE = 0x0001;
const WS_TABSTOP = 0x00010000;
const WS_VISIBLE = 0x10000000;
const WS_CHILD = 0x40000000;
const BS_DEFPUSHBUTTON = 0x00000001;
const BS_CHECKBOX = 0x00000002;
const WM_ERASEBKGND = 0x0014;
const WM_USER = 0x0400;
const EM_SETBKGNDCOLOR = (WM_USER + 67);
const WM_COMMAND = 0x0111;

const SPI_GETWORKAREA = 0x0030;

const BS_MULTILINE = 0x00002000;
const BST_UNCHECKED = 0x0000;
const BST_CHECKED = 0x0001;
const SS_BLACKRECT = 0x00000004;
const SS_GRAYRECT = 0x00000005;

const SS_LEFT = 0x00000000;
const SS_CENTER = 0x00000001;
const SS_RIGHT = 0x00000002;
const SS_REALSIZECONTROL = 0x00000040;
const DS_CENTER = 0x0800;


const FW_DONTCARE = 0;
const FW_THIN = 100;
const FW_EXTRALIGHT = 200;
const FW_LIGHT = 300;
const FW_NORMAL = 400;
const FW_MEDIUM = 500;
const FW_SEMIBOLD = 600;
const FW_BOLD = 700;
const FW_EXTRABOLD = 800;
const FW_HEAVY = 900;

const DEFAULT_CHARSET = 1;

const OUT_DEFAULT_PRECIS = 0;
const OUT_STRING_PRECIS = 1;
const OUT_CHARACTER_PRECIS = 2;
const OUT_STROKE_PRECIS = 3;
const OUT_TT_PRECIS = 4;
const OUT_DEVICE_PRECIS = 5;
const OUT_RASTER_PRECIS = 6;
const OUT_TT_ONLY_PRECIS = 7;
const OUT_OUTLINE_PRECIS = 8;
const OUT_SCREEN_OUTLINE_PRECIS = 9;
const OUT_PS_ONLY_PRECIS = 10;

const CLIP_DEFAULT_PRECIS = 0;
const CLIP_CHARACTER_PRECIS = 1;
const CLIP_STROKE_PRECIS = 2;
const CLIP_MASK = 0xf;
const CLIP_LH_ANGLES = (1 << 4);
const CLIP_TT_ALWAYS = (2 << 4);

const DEFAULT_QUALITY = 0;
const DRAFT_QUALITY = 1;
const PROOF_QUALITY = 2;

const DEFAULT_PITCH = 0;
const FIXED_PITCH = 1;
const VARIABLE_PITCH = 2;

const FF_DONTCARE = (0 << 4);  /* Don't care or don't know. */
const FF_ROMAN = (1 << 4);  /* Variable stroke width, serifed. */
const FF_SWISS = (2 << 4);  /* Variable stroke width, sans-serifed. */
const FF_MODERN = (3 << 4);  /* Constant stroke width, serifed or sans-serifed. */
const FF_SCRIPT = (4 << 4);  /* Cursive, etc. */
const FF_DECORATIVE = (5 << 4);  /* Old English, etc. */

const ES_LEFT = 0x0000;
const ES_CENTER = 0x0001;
const ES_RIGHT = 0x0002;
const ES_MULTILINE = 0x0004;
const ES_UPPERCASE = 0x0008;
const ES_LOWERCASE = 0x0010;
const ES_PASSWORD = 0x0020;
const ES_AUTOVSCROLL = 0x0040;
const ES_AUTOHSCROLL = 0x0080;
const ES_NOHIDESEL = 0x0100;
const ES_OEMCONVERT = 0x0400;
const ES_READONLY = 0x0800;
const ES_WANTRETURN = 0x1000;

const STM_SETIMAGE = 0x0172;
const STM_GETIMAGE = 0x0173;
const IMAGE_BITMAP = 0;
const SS_BITMAP = 0x0000000E;


const TRANSPARENT = 1;
const OPAQUE = 2;
const COLOR_BACKGROUND = 1;

var promise = require('promise');
var GM = require('_GenericMarshal');
var MessagePump = require('win-message-pump');

var sh = require('monitor-info')._shcore;
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


function SCALE(val, dpi)
{
    var factor = val / 96;
    return (dpi * factor);
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

function CENTER(w, cx, cw)
{
    var a = cw / 2;
    var b = w / 2;
    return (Math.floor(cx + (a - b)));
}
function pump_onTimeout(pump)
{
    pump.promise.reject('TIMEOUT');
    pump.close();
}
function pump_onExit()
{
    console.info1('message pump exited');
    this.promise.reject('CLOSED');
}
function pump_onMessage(msg)
{
    switch (msg.message)
    {
        case WM_MOUSEMOVE:
            var x = msg.lparam & 0xFFFF;
            var y = msg.lparam >> 16;
            if (x >= 0 && x <= SCALE(580, this.dpi) && y >= 0 && y <= (this.dpi / 3))
            {
                this._addAsyncMethodCall(this._user32.LoadCursorA.async, [0, IDC_ARROW]).then(function (cs)
                {
                    this.pump._addAsyncMethodCall(this.pump._user32.SetCursor.async, [cs]);
                }).parentPromise.pump = this;
            }
            break;
        case WM_COMMAND:
            switch(msg.wparam)
            {
                case 0xFFF0:
                    this._addAsyncMethodCall(this._user32.IsDlgButtonChecked.async, [this._HANDLE, 0xFFF0]).then(function (v)
                    {
                        if (v.Val == 0)
                        {
                            this.pump.autoAccept = true;
                            this.pump._addAsyncMethodCall(this.pump._user32.CheckDlgButton.async, [this.pump._HANDLE, 0xFFF0, BST_CHECKED]);
                        }
                        else
                        {
                            this.pump.autoAccept = false;
                            this.pump._addAsyncMethodCall(this.pump._user32.CheckDlgButton.async, [this.pump._HANDLE, 0xFFF0, BST_UNCHECKED]);
                        }
                    }).parentPromise.pump = this;
                    break;
                case 0xFFF2: // Allow
                    if (this.timeout != null) { clearTimeout(this.timeout); this.timeout = null; }
                    this.promise.resolve(this.autoAccept);
                    this.close();
                    break;
                case 0xFFE0: // X
                case 0xFFF3: // Deny
                    if (this.timeout != null) { clearTimeout(this.timeout); this.timeout = null; }
                    this.promise.reject('DENIED');
                    this.close();
                    break;
            }
            break;
        case WM_CTLCOLORSTATIC:
            console.info1('WM_CTLCOLORSTATIC => ' + msg.lparam, msg.wparam);
            if (msg.lparam == this._faketitle)
            {
                break;
            }
            var hdcStatic = msg.wparam;
            this._gdi32.SetTextColor(hdcStatic, this.options.foreground);
            this._gdi32.SetBkColor(hdcStatic, this.options.background);
            return (this.brush);
            break;
        case WM_CREATE:
            console.info1('WM_CREATE');
            break;
        case WM_ERASEBKGND:
            console.info1('WM_ERASEBKGND');
            break;
        case WM_LBUTTONDOWN:
            var x = msg.lparam & 0xFFFF;
            var y = msg.lparam >> 16;
            if (x >= 0 && x <= SCALE(580, this.dpi) && y >= 0 && y <= (this.dpi / 3))
            {
                this._addAsyncMethodCall(this._user32.ReleaseCapture.async, []).then(function ()
                {
                    this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [this.pump._HANDLE, WM_NCLBUTTONDOWN, HT_CAPTION, 0]);
                }).parentPromise.pump = this;
            }
            break;
        case WM_WINDOWPOSCHANGING:
            if (this._HANDLE)
            {
                if (sh != null)
                {
                    var hmon = require('monitor-info')._user32.MonitorFromWindow(this._HANDLE, MONITOR_DEFAULTTOPRIMARY);
                    var xdpi = require('_GenericMarshal').CreateVariable(4);
                    var ydpi = require('_GenericMarshal').CreateVariable(4);
                    sh.GetDpiForMonitor(hmon, 0, xdpi, ydpi);

                    var x = msg.lparam_raw.Deref(ptrsize == 4 ? 8 : 16, 4).toBuffer().readInt32LE();
                    var y = msg.lparam_raw.Deref(ptrsize == 4 ? 12 : 20, 4).toBuffer().readInt32LE();

                    this.dpi = xdpi.toBuffer().readUInt32LE();
                    msg.lparam_raw.Deref(ptrsize == 4 ? 16 : 24, 4).toBuffer().writeInt32LE(SCALE(580, this.dpi));
                    msg.lparam_raw.Deref(ptrsize == 4 ? 20 : 28, 4).toBuffer().writeInt32LE(SCALE(295, this.dpi));

                    var ret = GM.CreatePointer();
                    ret.increment(0, true);
                    return (ret);
                }
            }
            break;
        case WM_NCCALCSIZE:
            if (msg.wparam != 0)
            {
                var buff = msg.lparam_raw.Deref(0, 16).toBuffer();
                var dpi = (buff.readInt32LE(8) - buff.readInt32LE(0)) / 580 * 96;

                console.info1('[' + (buff.readInt32LE(8) - buff.readInt32LE(0)) + ' x ' + (buff.readInt32LE(12) - buff.readInt32LE(4)) + ']', dpi);
                this.font = this._gdi32.CreateFontW(SCALE(20, dpi), 0, 0, 0, FW_DONTCARE, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, GM.CreateVariable(this.options.font, { wide: true }));
                this.buttonfont = this._gdi32.CreateFontW(SCALE(15, dpi), 0, 0, 0, FW_DONTCARE, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, GM.CreateVariable(this.options.font, { wide: true }));

                this._addAsyncMethodCall(this._user32.BeginDeferWindowPos.async, [8]).then(function (HDWP)
                {
                    this.pump._user32.DeferWindowPos(HDWP, this.pump._faketitle, 0, 0, 0, SCALE(580, dpi), dpi / 3, SWP_NOZORDER);
                    HDWP = this.pump._user32.DeferWindowPos(HDWP, this.pump._fakeclose, 0, SCALE(580, dpi) - ((dpi / 3) * 0.75) - ((dpi / 3) * 0.125), (dpi / 3) * 0.125, (dpi / 3) * 0.75, (dpi / 3) * 0.75, SWP_NOZORDER);
                    HDWP = this.pump._user32.DeferWindowPos(HDWP, this.pump._allowbutton, 0, SCALE(345, dpi), SCALE(215 + 32, dpi), SCALE(100, dpi), SCALE(30, dpi), SWP_NOZORDER);
                    HDWP = this.pump._user32.DeferWindowPos(HDWP, this.pump._denybutton, 0, SCALE(455, dpi), SCALE(215 + 32, dpi), SCALE(100, dpi), SCALE(30, dpi), SWP_NOZORDER);
                    HDWP = this.pump._user32.DeferWindowPos(HDWP, this.pump._checkbox, 0, SCALE(210, dpi), SCALE(150 + 32, dpi), SCALE(335, dpi), SCALE(60, dpi), SWP_NOZORDER);
                    HDWP = this.pump._user32.DeferWindowPos(HDWP, this.pump._avatar, 0, SCALE(10, dpi), SCALE(10 + 32, dpi), SCALE(192, dpi), SCALE(192, dpi), SWP_NOZORDER);
                    HDWP = this.pump._user32.DeferWindowPos(HDWP, this.pump._username, 0, SCALE(10, dpi), SCALE(215 + 32, dpi), SCALE(335, dpi), SCALE(30, dpi), SWP_NOZORDER);
                    HDWP = this.pump._user32.DeferWindowPos(HDWP, this.pump._caption, 0, SCALE(210, dpi), SCALE(10 + 32, dpi), SCALE(350, dpi), SCALE(150, dpi), SWP_NOZORDER);

                    this.pump._addAsyncMethodCall(this.pump._user32.InvalidateRect.async, [this.pump._HANDLE, 0, 0]);
                    this.pump._addAsyncMethodCall(this.pump._user32.EndDeferWindowPos.async, [HDWP]).then(function ()
                    {
                        this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [this.pump._faketitle, WM_SETFONT, this.pump.buttonfont, 1]);
                        this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [this.pump._allowbutton, WM_SETFONT, this.pump.buttonfont, 1]);
                        this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [this.pump._denybutton, WM_SETFONT, this.pump.buttonfont, 1]);
                        this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [this.pump._username, WM_SETFONT, this.pump.buttonfont, 1]);
                        this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [this.pump._caption, WM_SETFONT, this.pump.font, 1]);
                        this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [this.pump._checkbox, WM_SETFONT, this.pump.buttonfont, 1]);
                    }).parentPromise.pump = this.pump;
                }).parentPromise.pump = this;
            }
            break;
        default:
            //console.log(msg.message);
            break;
    }
}
function pump_onHwnd(h)
{
    this._HANDLE = h;
    this._icon = getScaledImage(x_icon, SCALE(32, this.dpi) * 0.75, SCALE(32, this.dpi) * 0.75);
    this._addAsyncMethodCall(this._user32.LoadCursorA.async, [0, IDC_ARROW]).then(function (cs)
    {
        this.pump._addAsyncMethodCall(this.pump._user32.SetCursor.async, [cs]);
    }).parentPromise.pump = this;

    this._addCreateWindowEx(0, GM.CreateVariable('STATIC', { wide: true }), GM.CreateVariable(' ' + this.translations.Title, { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | SS_LEFT | SS_CENTERIMAGE,
        SCALE(0, this.dpi),         // x position 
        SCALE(0, this.dpi),         // y position 
        SCALE(580, this.dpi),       // Button width
        SCALE(32, this.dpi),        // Button height
        h,          // Parent window
        0xFFE1,     // Child ID
        0,
        0).then(function (h)
        {
            this.pump._faketitle = h.Val;
            this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [h, WM_SETFONT, this.pump.buttonfont, 1]);
        }).parentPromise.pump = this;
    this._addCreateWindowEx(0, GM.CreateVariable('STATIC', { wide: true }), GM.CreateVariable('X', { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | SS_BITMAP | SS_REALSIZECONTROL | SS_NOTIFY,
        SCALE(580, this.dpi) - (SCALE(32, this.dpi) * 0.75) - (SCALE(32, this.dpi) * 0.125),        // x position 
        SCALE(32, this.dpi) * 0.125,                                                                // y position 
        SCALE(32, this.dpi) * 0.75,                                                                 // Button width
        SCALE(32, this.dpi) * 0.75,                                                                 // Button height
        h,          // Parent window
        0xFFE0,     // Child ID
        0,
        0).then(function (c)
        {
            this.pump._fakeclose = c;
            //this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [c, BM_SETIMAGE, IMAGE_BITMAP, this.pump._icon.Deref()]);
            this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [c, STM_SETIMAGE, IMAGE_BITMAP, this.pump._icon.Deref()]);
        }).parentPromise.pump = this;



    this._addCreateWindowEx(0, GM.CreateVariable('BUTTON', { wide: true }), GM.CreateVariable(this.translations.Allow, { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        SCALE(345, this.dpi),        // x position 
        SCALE(215 + 32, this.dpi),   // y position 
        SCALE(100, this.dpi),        // Button width
        SCALE(30, this.dpi),         // Button height
        h,          // Parent window
        0xFFF2,     // Child ID
        0,
        0).then(function (c)
        {
            this.pump._allowbutton = c;
            this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [c, WM_SETFONT, this.pump.buttonfont, 1]);
        }).parentPromise.pump = this;
    this._addCreateWindowEx(0, GM.CreateVariable('BUTTON', { wide: true }), GM.CreateVariable(this.translations.Deny, { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        SCALE(455, this.dpi),        // x position 
        SCALE(215 + 32, this.dpi),        // y position 
        SCALE(100, this.dpi),        // Button width
        SCALE(30, this.dpi),         // Button height
        h,          // Parent window
        0xFFF3,     // Child ID
        0,
        0).then(function (c)
        {
            this.pump._denybutton = c;
            this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [c, WM_SETFONT, this.pump.buttonfont, 1]);
        }).parentPromise.pump = this;
    this._addCreateWindowEx(0, GM.CreateVariable('BUTTON', { wide: true }), GM.CreateVariable(this.translations.Auto, { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_CHECKBOX | BS_MULTILINE,
        SCALE(210, this.dpi),        // x position 
        SCALE(150 + 32, this.dpi),   // y position 
        SCALE(335, this.dpi),        // Button width
        SCALE(60, this.dpi),         // Button height
        h,          // Parent window
        0xFFF0,     // Child ID
        0,
        0).then(function (c)
        {
            this.pump._checkbox = c;
            this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [c, WM_SETFONT, this.pump.buttonfont, 1]);
        }).parentPromise.pump = this;
    this._addCreateWindowEx(0, GM.CreateVariable('STATIC', { wide: true }), GM.CreateVariable('NONE', { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | SS_BLACKRECT | SS_BITMAP | SS_REALSIZECONTROL,
        SCALE(10, this.dpi),         // x position 
        SCALE(10 + 32, this.dpi),    // y position 
        SCALE(192, this.dpi),        // Button width
        SCALE(192, this.dpi),        // Button height
        h,          // Parent window
        0xFFF1,     // Child ID
        0,
        0).then(function (h)
        {
            this.pump._avatar = h;
            if (this.pump.options.bitmap != null)
            {
                this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [h, STM_SETIMAGE, IMAGE_BITMAP, this.pump.options.bitmap.Deref()]);
            }
        }).parentPromise.pump = this;
    this._addCreateWindowEx(0, GM.CreateVariable('STATIC', { wide: true }), GM.CreateVariable(this.username, { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | SS_LEFT,
        SCALE(10, this.dpi),         // x position 
        SCALE(215 + 32, this.dpi),   // y position 
        SCALE(335, this.dpi),        // Button width
        SCALE(30, this.dpi),         // Button height
        h,          // Parent window
        0xFFF2,     // Child ID
        0,
        0).then(function (c)
        {
            this.pump._username = c;
            this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [c, WM_SETFONT, this.pump.buttonfont, 1]);
        }).parentPromise.pump = this;
    this._addCreateWindowEx(0, GM.CreateVariable('STATIC', { wide: true }), GM.CreateVariable(this.translations.Caption, { wide: true }), WS_TABSTOP | WS_VISIBLE | WS_CHILD | SS_LEFT,
        SCALE(210, this.dpi),        // x position 
        SCALE(10 + 32, this.dpi),    // y position 
        SCALE(350, this.dpi),        // Button width
        SCALE(150, this.dpi),        // Button height
        h,          // Parent window
        0xFFF3,     // Child ID
        0,
        0).then(function (h)
        {
            this.pump._caption = h;
            this.pump._addAsyncMethodCall(this.pump._user32.SendMessageW.async, [h, WM_SETFONT, this.pump.font, 1]);
        }).parentPromise.pump = this;
}
function createLocal(title, caption, username, options)
{
    if (options == null) { options = {}; }
    if (!options.translations)
    {
        options.translations =
            {
                Allow: 'Allow',
                Deny: 'Deny',
                Auto: 'Auto accept all connections for next 5 minutes',
                Caption: caption
            };
    }

    if (!options.translations.Title) { options.translations.Title = title; }
    if (!options.font) { options.font = 'Arial'; }
    if (!options.background) { options.background = RGB(0, 54, 105); }
    if (!options.foreground) { options.foreground = RGB(200, 200, 200); }

    var ret = new promise(promise.defaultInit);
    ret.opt =
    {
        window:
        {
            winstyles: MessagePump.WindowStyles.WS_VISIBLE | MessagePump.WindowStyles.WS_BORDER | MessagePump.WindowStyles.WS_POPUP,
            x: 300, y: 300, left: 0, right: 300, width: 580, height: 295, title: title, background: options.background, dpi: 96
        },
    };
    if (sh != null)
    {
        var primary = require('monitor-info')._user32.MonitorFromWindow(0, MONITOR_DEFAULTTOPRIMARY);
        var xdpi = require('_GenericMarshal').CreateVariable(4);
        var ydpi = require('_GenericMarshal').CreateVariable(4);

        sh.GetDpiForMonitor(primary, 0, xdpi, ydpi);
        ret.opt.window.dpi = xdpi.toBuffer().readUInt32LE();

        console.info1('DPI of Primary Display is: ' + ret.opt.window.dpi);
        ret.opt.window.width = SCALE(580, ret.opt.window.dpi);
        ret.opt.window.height = SCALE(295, ret.opt.window.dpi);
    }
    var rect = GM.CreateVariable(16);
    var startupinput = require('_GenericMarshal').CreateVariable(24);
    ret.gdipToken = require('_GenericMarshal').CreatePointer();
    ret.pump = new MessagePump(ret.opt);
    if (ret.pump._user32.SystemParametersInfoA(SPI_GETWORKAREA, 0, rect, 0).Val != 0)
    {
        var r = { x: rect.toBuffer().readInt32LE(0), y: rect.toBuffer().readInt32LE(4), w: rect.toBuffer().readInt32LE(8), h: rect.toBuffer().readInt32LE(12) };
        r.w = r.w - r.x;
        r.h = r.h - r.y;
        console.info1('Primary Display: ' + JSON.stringify(r));
        console.info1('   => x: ' + CENTER(ret.opt.window.width, r.x, r.w) + ', y: ' + CENTER(ret.opt.window.height, r.y, r.h));
        ret.opt.window.x = CENTER(ret.opt.window.width, r.x, r.w);
        ret.opt.window.y = CENTER(ret.opt.window.height, r.y, r.h);
    }

    ret.pump.dpi = ret.opt.window.dpi;
    ret.pump.autoAccept = false;
    ret.pump.promise = ret;
    ret.pump.brush = ret.pump._gdi32.CreateSolidBrush(options.background);
    ret.pump.translations = options.translations;
    ret.pump.username = username;
    ret.pump.options = options;
    ret.pump.font = ret.pump._gdi32.CreateFontW(SCALE(20, ret.pump.dpi), 0, 0, 0, FW_DONTCARE, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, GM.CreateVariable(options.font, { wide: true }));
    ret.pump.buttonfont = ret.pump._gdi32.CreateFontW(SCALE(15, ret.pump.dpi), 0, 0, 0, FW_DONTCARE, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, GM.CreateVariable(options.font, { wide: true }));

    if (options.b64Image)
    {
        startupinput.toBuffer().writeUInt32LE(1);
        gdip.GdiplusStartup(ret.gdipToken, startupinput, 0);

        var raw = Buffer.from(options.b64Image, 'base64');

        var nbuff = require('_GenericMarshal').CreateVariable(raw.length);
        raw.copy(nbuff.toBuffer());
        var istream = SHM.SHCreateMemStream(nbuff, raw.length);

        var pimage = require('_GenericMarshal').CreatePointer();
        var hbitmap = require('_GenericMarshal').CreatePointer();
        var status = gdip.GdipCreateBitmapFromStream(istream, pimage);
        status = gdip.GdipCreateHBITMAPFromBitmap(pimage.Deref(), hbitmap, options.background); // RGB(0, 54, 105);
        if (status.Val == 0)
        {
            options.bitmap = hbitmap;
            var format = GM.CreateVariable(4);
            console.info1('PixelFormatStatus: ' + gdip.GdipGetImagePixelFormat(pimage.Deref(), format).Val);
            console.info1('PixelFormat: ' + format.toBuffer().readInt32LE());
            var nb = GM.CreatePointer();

            console.info1('FromScan0: ' + gdip.GdipCreateBitmapFromScan0(192, 192, 0, format.toBuffer().readInt32LE(), 0, nb).Val);

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
            console.info1('DrawImage: ' + gdip.GdipDrawImageRectI(graphics.Deref(), pimage.Deref(), 0, 0, 192, 192).Val);

            var scaledhbitmap = GM.CreatePointer();
            //console.info1('GetScaledHBITMAP: ' + gdip.GdipCreateHBITMAPFromBitmap(nb.Deref(), scaledhbitmap, options.background).Val);
            console.info1('GetScaledHBITMAP: ' + gdip.GdipCreateHBITMAPFromBitmap(nb.Deref(), scaledhbitmap, gdip_RGB(options.background)).Val);
            options.bitmap = scaledhbitmap;

            console.info1('ImageDispose: ' + gdip.GdipDisposeImage(pimage.Deref()).Val);
        }
    }

    ret.pump.on('message', pump_onMessage);
    ret.pump.on('hwnd', pump_onHwnd);
    ret.pump.on('exit', pump_onExit);

    if (options.timeout != null)
    {
        ret.pump.timeout = setTimeout(pump_onTimeout, options.timeout, ret.pump);
    }
    ret.close = function close()
    {
        this.pump.close();
    }
    return (ret);
}

function create(title, caption, username, options)
{
    if (options == null) { options = {}; }
    if (options.uid == null) { options.uid = require('user-sessions').consoleUid(); }
    var self = require('user-sessions').getProcessOwnerName(process.pid).tsid;
    if (self != 0)
    {
        if(options.uid == self)
        {
            // No need to dispatch, we can do this locally
            return (createLocal(title, caption, username, options));
        }
        else
        {
            // Need to dispatch, but we don't have enough permissions to do that
            var ret = new promise(promise.defaultInit);
            ret.reject('Insufficient permission to dispatch to different user session');
            return (ret);
        }
    }
    if (options.uid == 0)
    {
        // TSID 0 doesn't have access to draw on the desktop
        var ret = new promise(promise.defaultInit);
        ret.reject('Cannot create dialog on this session');
        return (ret);
    }

    // Need to dispatch to user session to display dialog
    var ret = new promise(promise.defaultInit);
    ret.options = { launch: { module: 'win-userconsent', method: '_child', args: [] }, uid: options.uid };

    ret._ipc = require('child-container').create(ret.options);
    ret._ipc.master = ret;
    ret._ipc.once('exit', function () { console.info1('user consent child exited'); });
    ret._ipc.on('ready', function ()
    {
        this.descriptorMetadata = 'win-userconsent';
        this.message({ command: 'dialog', title: title, caption: caption, username: username, options: options });
    });
    ret._ipc.on('message', function (msg)
    {
        try
        {
            switch (msg.command)
            {
                case 'allow':
                    this.master.resolve(msg.always);
                    break;
                case 'deny':
                    this.master.reject(msg.reason);
                    break;
                case 'log':
                    console.log(msg.text);
                    break;
                default:
                    break;
            }
        }
        catch (ff)
        {
        }
    });
    ret.close = function close()
    {
        this._ipc.exit();
    }
    return (ret);
}

function _child()
{
    global.master = require('child-container');
    global.master.on('message', function (msg)
    {
        switch (msg.command)
        {
            case 'dialog':
                var p = createLocal(msg.title, msg.caption, msg.username, msg.options);
                p.then(function (always)
                {
                    global.master.message({ command: 'allow', always: always });
                }, function (msg)
                {
                    global.master.message({ command: 'deny', reason: msg });
                }).finally(function (msg)
                {
                    process._exit();
                });
                break;
        }
    });
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
module.exports =
    {
        create: create, _child: _child
    };
