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
- Added ability to set default pinning behavior for Privacy Bar on Windows
- Fixed potential 100% CPU utilization by WebRTC, caused iterating on buffer length without 4 byte aligning it
- Fixed Windows Handle Leak, by win-registry not closing a registry key in one of the code paths
- Fixed Windows Handle Leaks, by win-dispatcher caused by Read/Write overlapped event handles not getting closed
- Fixed Windows Handle Leak, by windows IPC socket overlapped handle not getting closed if close was called before overlapped IO returned
- Added ability for process-manager to search processes on Windows
- Added ability to set/query autohide of system taskbar on Windows
- Fixed Memory leak in ILibLifeTime, where DeleteList was not destroyed
- Fixed Memory Leak of Certificate Chain, by MeshAgent.ControlChannelCertificate property
- Fixed Memory Leak of Metadata string by Windows IPC Socket
- Fixed Memory Leak of Read/Write overlapped data structure by Windows IPC Socket, in certain edge cases
- Fixed Memory Leak in Windows KVM, caused by Windows APC not getting dispatched becuase the event loop thread was not waiting for shutdown in an alertable state
- Fixed Edge case crash in Windows KVM when dispatcher is shut down
- Fixed Memory Leak in WebRTC DataChannel, of metadata string
- Fixed Memory leak of TCP Server Socket metadata that occurs when an error occurs
- Fixed Memory Leak of image data by Linux/BSD KVM
- Fixed user-consent issue on BSD with Zenity
- Updated Windows Installer to populate DisplayVersion in registry, with Commit Date
- Added close() method to win-dispatcher to try to mitigate an edge case crash

**Known Issues**
- Quickly/Repeatedly opening tunnels can accumulate descriptors faster than they are released
- Quickly/Repeatedly calling 'setclip' on Windows could cause the service to crash/restart if repeated quickly enough
- Garbage Collection (Finalization) of some objects can be delayed when there is a circular loop in the referencing. These objects only get finalized with a mark-and-sweep. The biggest culprit is anonymous functions, where the runtime automatically will reference locally scoped objects by the anonymous function object

