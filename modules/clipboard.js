
function nativeAddModule(name)
{
    var value = getJSModule(name);
    var ret = "duk_peval_string_noresult(ctx, \"addModule('" + name + "', Buffer.from('" + Buffer.from(value).toString('base64') + "', 'base64').toString());\");";
    module.exports(ret);
}


function win_readtext()
{
    var ret = '';
    var CF_TEXT = 1;
    var GM = require('_GenericMarshal');
    var user32 = GM.CreateNativeProxy('user32.dll');
    var kernel32 = GM.CreateNativeProxy('kernel32.dll');
    kernel32.CreateMethod('GlobalAlloc');
    kernel32.CreateMethod('GlobalLock');
    kernel32.CreateMethod('GlobalUnlock');
    user32.CreateMethod('OpenClipboard');
    user32.CreateMethod('CloseClipboard');
    user32.CreateMethod('GetClipboardData');

    user32.OpenClipboard(0);
    var h = user32.GetClipboardData(CF_TEXT);
    if(h.Val!=0)
    {
        var hbuffer = kernel32.GlobalLock(h);
        ret = hbuffer.String;
        kernel32.GlobalUnlock(h);
    }
    user32.CloseClipboard();
    return (ret);
}

function win_copytext(txt)
{
    var GMEM_MOVEABLE = 0x0002;
    var CF_TEXT = 1;

    var GM = require('_GenericMarshal');
    var user32 = GM.CreateNativeProxy('user32.dll');
    var kernel32 = GM.CreateNativeProxy('kernel32.dll');
    kernel32.CreateMethod('GlobalAlloc');
    kernel32.CreateMethod('GlobalLock');
    kernel32.CreateMethod('GlobalUnlock');
    user32.CreateMethod('OpenClipboard');
    user32.CreateMethod('EmptyClipboard');
    user32.CreateMethod('CloseClipboard');
    user32.CreateMethod('SetClipboardData');

    var h = kernel32.GlobalAlloc(GMEM_MOVEABLE, txt.length + 2);
    h.autoFree(false);
    var hbuffer = kernel32.GlobalLock(h);
    hbuffer.autoFree(false);
    var tmp = Buffer.alloc(txt.length + 1);
    Buffer.from(txt).copy(tmp);
    tmp.copy(hbuffer.Deref(0, txt.length + 1).toBuffer());
    kernel32.GlobalUnlock(h);

    user32.OpenClipboard(0);
    user32.EmptyClipboard();
    user32.SetClipboardData(CF_TEXT, h);
    user32.CloseClipboard();
}

switch(process.platform)
{
    case 'win32':
        module.exports = win_copytext;
        module.exports.read = win_readtext;
        break;
    case 'linux':
        break;
    case 'darwin':
        break;
}
module.exports.nativeAddModule = nativeAddModule;