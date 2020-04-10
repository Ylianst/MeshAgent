/*
Copyright 2020 Intel Corporation

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

try
{

    var X11 = require('monitor-info')._X11;
    var GM = require('monitor-info')._gm;

    if (!require('monitor-info').Location_X11FIXES)
    {
        throw ('XFixes Extension is required');
    }

    var XFIXES = GM.CreateNativeProxy(require('monitor-info').Location_X11FIXES);
    XFIXES.CreateMethod('XFixesSelectCursorInput');
    XFIXES.CreateMethod('XFixesGetCursorImage');
    XFIXES.CreateMethod('XFixesGetCursorName');
    XFIXES.CreateMethod('XFixesQueryExtension');

}
catch(e)
{
    console.log('error: ' + e);
}


if (!process.env.XAUTHORITY || !process.env.DISPLAY)
{
    try
    {
        var xinfo = this.getXInfo(require('user-sessions').getUid(require('user-sessions').whoami()));
        process.setenv('XAUTHORITY', xinfo.xauthority);
        process.setenv('DISPLAY', xinfo.display);
    }
    catch(ff)
    {
        console.log(ff);
    }
}

var display = X11.XOpenDisplay(GM.CreateVariable(process.env.DISPLAY));
if (display.Val == 0)
{
    console.log('XOpen Failed');
    throw('XOpen Failed');
}

var screenCount = X11.XScreenCount(display).Val;
var ifo = [];
for(var i=0;i<screenCount;++i)
{
    var screen = X11.XScreenOfDisplay(display, i);
    ifo.push({ left: 0, top: 0, right: X11.XDisplayWidth(display, i).Val, bottom: X11.XDisplayHeight(display, i).Val, screen: screen, screenId: i, display: display });
}
var white = X11.XWhitePixel(ifo[0].display, ifo[0].screenId).Val;
var ROOTWIN = X11.XRootWindow(ifo[0].display, ifo[0].screenId);
var FAKEWIN = X11.XCreateSimpleWindow(ifo[0].display, ROOTWIN, 0, 0, ifo[0].right, 5, 0, white, white);
var XFixesCursorNotify = 1;

var eventbase = GM.CreateVariable(4);
var errorbase = GM.CreateVariable(4);

console.log(eventbase.toBuffer().readUInt32LE());
XFIXES.XFixesQueryExtension(ifo[0].display, eventbase, errorbase);

console.log(eventbase.toBuffer().readUInt32LE());

console.log('done');
XFIXES.XFixesSelectCursorInput(ifo[0].display, ROOTWIN, 1);
console.log('SelectCursorInput DONE');

X11.XSync(ifo[0].display, 0);

XFIXES.DescriptorEvent = require('DescriptorEvents').addDescriptor(X11.XConnectionNumber(ifo[0].display).Val, { readset: true });
XFIXES.DescriptorEvent._display = ifo[0].display;
XFIXES.DescriptorEvent.on('readset', function (fd)
{
    var notification;
    var XE = GM.CreateVariable(1024);
    while (X11.XPending(this._display).Val)
    {
        X11.XNextEventSync(this._display, XE);
        notification = XE.Deref(0, 4).toBuffer().readUInt32LE();
        
        if (notification == (eventbase.toBuffer().readUInt32LE() + XFixesCursorNotify))
        {
            var serial;
            if (GM.PointerSize == 4)
            {
                serial = XE.Deref(24, 4).toBuffer().readUInt32LE();
            }
            else
            {
                serial = require('bignum').fromBuffer(XE.Deref(48, 8).toBuffer()).toString();
            }
            console.log('\ncursor_serial: ' + serial);

		    var cursor_image = XFIXES.XFixesGetCursorImage(ifo[0].display);
		    //console.log(cursor_image.Deref(4,2).toBuffer().readUInt16LE(), cursor_image.Deref(6,2).toBuffer().readUInt16LE());
		    var w = cursor_image.Deref(4,2).toBuffer().readUInt16LE();
		    var h = cursor_image.Deref(6,2).toBuffer().readUInt16LE();
		    var p = cursor_image.Deref(GM.PointerSize == 8 ? 24 : 16, w * h * GM.PointerSize).toBuffer();

		    var pp = Buffer.alloc(w * h);
		    for(var i=0;i<(w*h);++i)
		    {
		        //pp[i] = p[GM.PointerSize == 8 ? (7 + (i * 8)) : (3 + (i * 4))];
		        pp[i] = p[GM.PointerSize == 8 ? (3 + (i * 8)) : (3 + (i * 4))];
		    }
		    pp = pp.slice(6);

		    console.log(w,h,'CRC: ' + crc32c(pp));
		    if ((GM.PointerSize == 8 ? (XE.Deref(64, 8).Deref()).Val : (XE.Deref(32, 4).Deref()).Val) != 0)
            {
                var name = X11.XGetAtomName(ifo[0].display, GM.PointerSize == 8 ? (XE.Deref(64, 8).Deref()) : (XE.Deref(32, 4).Deref()));
                console.log('NAME => ' + name.String);
            }
        }
        else
        {
            console.log('NOTIFY: ' + notification, eventbase, XFixesCursorNotify);
        }
    }
});

console.log(' -- ');
