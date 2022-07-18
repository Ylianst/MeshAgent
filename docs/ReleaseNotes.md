## Mesh Agent Release Notes

### Changes since v1.0.0
- AutoAccept timer added for Windows User Consent
- Fixed Column Resize Mouse Cursor on Windows
- Fixed Key mapping issues with Windows Extended Keys
- Fixed POSIX bug where invalid descriptors could cause other descriptors to not get serviced
- Added logic to flush invalid Windows socket handles from event loop
- Fixed Linux bug, where resolve() fail could cause FD(0) to get closed
- Updated win-disaptcher to use win-tasks (COM) by default instead of SCHTASKS
- Added COM/WMI support for fetching Windows Volumes and Bitlocker Status
- Updated OpenSSL to 1.1.1n
- Fixed possible xauth truncation with getXInfo()

### Changes since v1.0.1
- Added better support for marshaling event callbacks in 32 bit windows
- Updated windows installer to enable SafeMode with Networking
- Added fix for behaviorial differences of awk in Ubuntu 20, and a few other xauth related issues
- Fixed bug with running installer from non graphical session on Linux
- Added support for custom COM dispatch handlers
- Added Asynchronous Capability to win-firewall enumeration
- Capped maximum width of PRivacy bar to 45% of display width
- stability improvement for windows message pump
- Added support for acknowledgement dialog
- Updated windows installer to show firewall enumeration progress
- Updated systemd escaping in linux installer
- Fixed WebRTC DataChannel interop with Chromium/Edge
- Fixed issues with UTF8 and Zenity
- Fixed resetnodeid, checkfirewall, clearfirewall, and setfirewall switches on Windows.
- Updated Product Version on windows to include Commit Date
- Added workaround for Self-signed certificates bug with Chromium v75+
- Added autoproxy support
- fixed process.stdin support, and added support for hiding input and enabling character support.
- Added PCI bus enumeration support for Linux
- Added USB bus enumeration support for Linux
- Fixed bug where global-tunnel.end() didn't clear proxy settings
- Updated systemd service ordering to require network start
- Updated threading for ILibLifeTime_Remove(), to defer to event loop thread_
- Fixed bug with websocket fragment re-assembly
- Fixed bug on Linux, where service stop, didn't gracefully shutdown agent
- Fixed support for digest auth and auth-int support, so it correctly negotiates
- Fixed memory corruption bug in WebRTC
- Fixed race that could occur with ILibLifeTime_Remove() and Timer OnElapse()_
- Fixed process enumeration that could result in JSON error on some linux distros
- Updated to OpenSSL/1.1.1q
- Fixed bug with ScriptContainer JSON dispatcher, that caused clipboard to not work correctly if xclip isn't installed

