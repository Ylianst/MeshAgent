

function WindowsConsole()
{
    if (process.platform == 'win32')
    {
        this._Marshal = require('_GenericMarshal');
        this._kernel32 = this._Marshal.CreateNativeProxy("kernel32.dll");
        this._user32 = this._Marshal.CreateNativeProxy("user32.dll");
        this._kernel32.CreateMethod("GetConsoleWindow");
        this._user32.CreateMethod("ShowWindow");
        this._user32.CreateMethod("LoadImage");

        this._handle = this._kernel32.GetConsoleWindow();
        this.minimize = function () {
            this._user32.ShowWindow(this._handle, 6);
        };
        this.restore = function () {
            this._user32.ShowWindow(this._handle, 9);
        };
        this.hide = function () {
            this._user32.ShowWindow(this._handle, 0);
        };
        this.show = function () {
            this._user32.ShowWindow(this._handle, 5);
        };


        this._loadicon = function (imagePath) {
            var h = this._user32.LoadImage(0, imagePath, 1, 0, 0, 0x00000010 | 0x00008000 | 0x00000040); // LR_LOADFROMFILE | LR_SHARED | LR_DEFAULTSIZE
            return (h);
        }
    }
}

module.exports = new WindowsConsole();