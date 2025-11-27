# win-console.js

Windows console window and system tray management module that provides control over console window visibility and system tray icon creation with notification balloon support. Enables background applications to create system tray presence and manage console window states.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support

**Excluded Platforms:**
- **macOS** - Explicitly excluded
- **Linux** - Explicitly excluded
- **FreeBSD** - Explicitly excluded
- **All non-Windows platforms** - Explicitly excluded

**Exclusion Reasoning:**

**Line 44:** `if (process.platform == 'win32')`

The module explicitly checks platform and only initializes functionality on Windows. Non-Windows platforms receive an empty object.

**Why macOS/Linux are excluded:**

1. **Windows Console Model Doesn't Exist on Other Platforms**
   - Windows has a dedicated console window subsystem (`conhost.exe`, `openconsole.exe`)
   - macOS uses terminal emulators (Terminal.app, iTerm2) that are separate processes
   - Linux uses terminal emulators (xterm, gnome-terminal, konsole) not tied to process
   - No direct equivalent to Windows console window handle

2. **Windows System Tray is Platform-Specific**
   - Windows: System notification area in taskbar (Shell_NotifyIcon API)
   - macOS: Menu bar items (NSStatusBar API - completely different)
   - Linux: Varies by desktop environment (GNOME, KDE, systray protocol)
   - Different APIs, behaviors, and capabilities across platforms

3. **Windows-Specific DLL Dependencies**
   - **User32.dll** - Windows windowing, message loop, system tray
   - **Shell32.dll** - Windows shell integration, notification icons
   - **Kernel32.dll** - Windows process/thread management
   - These DLLs only exist on Windows systems

4. **Windows Message Pump Architecture**
   - **Line 114:** `require('win-message-pump')` - Windows-specific message loop
   - Uses Windows HWND (window handle) system
   - Windows message filtering and routing
   - No equivalent on other platforms

5. **Windows-Specific Data Structures**
   - NOTIFYICONDATA structure (Lines 83-111)
   - Different sizes for 32-bit (508 bytes) vs 64-bit (528 bytes)
   - Windows message constants (WM_APP, etc.)
   - Shell notification flags

**macOS Alternative:**
- Console window: No equivalent (terminal is separate process)
- System tray: NSStatusBar/NSStatusItem API for menu bar items

**Linux Alternative:**
- Console window: No equivalent (terminal is separate process)
- System tray: StatusNotifierItem/AppIndicator (varies by desktop environment)

## Functionality

### Console Window Management Methods

The module provides direct control over the Windows console window associated with the current process.

#### minimize() - Line 59-61

Minimizes the console window to the taskbar.

**Implementation:**
```javascript
this.minimize = function () {
    this._user32.ShowWindow(this._handle, 6);
};
```

**Windows API:**
- Calls `ShowWindow(hWnd, SW_MINIMIZE)`
- `SW_MINIMIZE = 6` - Minimizes window and activates next top-level window

**Use Case:**
- Background services that occasionally need console output
- Reduce screen clutter while keeping console accessible

---

#### restore() - Line 62-64

Restores a minimized console window to its previous size and position.

**Implementation:**
```javascript
this.restore = function () {
    this._user32.ShowWindow(this._handle, 9);
};
```

**Windows API:**
- Calls `ShowWindow(hWnd, SW_RESTORE)`
- `SW_RESTORE = 9` - Activates and displays window in original size/position

**Use Case:**
- Restore console after minimizing
- Bring console back to user's attention

---

#### hide() - Line 65-67

Completely hides the console window (not minimized, invisible).

**Implementation:**
```javascript
this.hide = function () {
    this._user32.ShowWindow(this._handle, 0);
};
```

**Windows API:**
- Calls `ShowWindow(hWnd, SW_HIDE)`
- `SW_HIDE = 0` - Hides window and activates another window

**Use Case:**
- Background services running without user interaction
- Silent operation mode
- Hide console while showing GUI

**Note:** Window remains in memory, just invisible

---

#### show() - Line 68-70

Shows a hidden console window.

**Implementation:**
```javascript
this.show = function () {
    this._user32.ShowWindow(this._handle, 5);
};
```

**Windows API:**
- Calls `ShowWindow(hWnd, SW_SHOW)`
- `SW_SHOW = 5` - Activates window and displays in current size/position

**Use Case:**
- Make hidden console visible again
- Debug mode activation
- User interaction required

---

### System Tray Icon Management

#### SetTrayIcon(options) - Lines 81-169

Creates a system tray icon with optional balloon notification and event handling.

**Parameters (options object):**

**Icon Options:**
- `icon` - Icon handle (from `_loadicon()`)
- `szTip` - Tooltip text when hovering over icon (128 chars max)

**Balloon Notification Options:**
- `szInfo` - Balloon message text (256 chars max)
- `szInfoTitle` - Balloon title text (64 chars max)
- `noBalloon` - Set to true to disable balloon notification
- `balloonOnly` - Set to true to auto-remove icon when balloon dismissed

**Message Filtering:**
- `filter` - Automatically set to `WM_APP + 1 (0x8001)` for message routing

**Returns:** TrayIcon object with properties:
- `MessagePump` - Windows message pump instance
- `Options` - Original options object
- `remove()` - Method to remove tray icon

**Events Emitted:**
- `'ToastClicked'` - User clicked on balloon notification (Line 144)
- `'IconHover'` - Mouse hovering over tray icon (Line 149)
- `'ToastDismissed'` - Balloon notification closed (Line 154)

**Implementation Details:**

**Structure Creation (Lines 83-111):**
```javascript
var data = this._Marshal.CreateVariable(this._Marshal.PointerSize == 4 ? 508 : 528);
```
- Creates NOTIFYICONDATA structure
- 32-bit: 508 bytes
- 64-bit: 528 bytes

**Structure Layout:**
- **Offset 0:** Structure size (cbSize)
- **Offset +4/8:** Window handle (hWnd) - set when message pump creates window
- **Offset +8/16:** Icon ID (uID = 1)
- **Offset +12/20:** Flags (uFlags) - NIF_TIP | NIF_MESSAGE | NIF_ICON | NIF_INFO
- **Offset +16/24:** Callback message (uCallbackMessage = WM_APP + 1)
- **Offset +20/32:** Icon handle (hIcon)
- **Offset +24/40:** Tooltip text (szTip, 128 chars)
- **Offset +160/176:** Balloon text (szInfo, 256 chars)
- **Offset +416/432:** Version (4 = NOTIFYICON_VERSION_4)
- **Offset +420/436:** Balloon title (szInfoTitle, 64 chars)

**Message Pump Integration (Lines 114-159):**
1. Creates Windows message pump with options
2. Waits for window creation ('hwnd' event)
3. Calls `Shell_NotifyIconA(NIM_ADD)` to add tray icon
4. Listens for Windows messages matching filter
5. Emits events based on message type

**Message Handling:**
- `wparam == 1, lparam == 1029` → 'ToastClicked' (Line 142-145)
- `wparam == 1, lparam == 512` → 'IconHover' (Line 147-150)
- `wparam == 1, lparam == 1028` → 'ToastDismissed' (auto-remove if balloonOnly)

**Auto-removal (Lines 152-157):**
If `balloonOnly` is true, icon automatically removed when balloon dismissed/clicked.

**Example Usage:**
```javascript
var console = require('win-console');

// Load icon from file
var iconHandle = console._loadicon('C:\\path\\to\\icon.ico');

// Create tray icon with balloon
var tray = console.SetTrayIcon({
    icon: iconHandle,
    szTip: 'My Application',
    szInfo: 'Application is running in background',
    szInfoTitle: 'App Status',
    balloonOnly: true  // Remove after balloon dismissed
});

// Handle events
tray.on('ToastClicked', function() {
    console.log('User clicked notification balloon');
});

tray.on('IconHover', function() {
    console.log('User hovering over icon');
});

// Manually remove icon
tray.remove();
```

**Resource Cleanup:**
```javascript
tray.remove = function remove() {
    this.MessagePump.WindowsConsole._shell32.Shell_NotifyIconA(
        TrayIconFlags.NIM_DELETE,
        this.MessagePump.NotifyData
    );
    this.MessagePump.stop();
    delete this.MessagePump.TrayIcon;
    delete this.MessagePump;
};
```

---

#### _loadicon(imagePath) - Lines 74-78 (Private)

Loads an icon from a file and returns a handle for use with `SetTrayIcon()`.

**Parameters:**
- `imagePath` - Full path to icon file (.ico)

**Returns:**
- Icon HANDLE (pointer to icon resource)

**Implementation:**
```javascript
this._loadicon = function (imagePath) {
    var h = this._user32.LoadImageA(
        0,  // hInst = 0 (load from file)
        this._Marshal.CreateVariable(imagePath),
        1,  // IMAGE_ICON
        0,  // cx = 0 (default width)
        0,  // cy = 0 (default height)
        0x00000010 | 0x00008000 | 0x00000040  // Flags
    );
    return (h);
};
```

**Flags:**
- `LR_LOADFROMFILE (0x00000010)` - Load from file path
- `LR_SHARED (0x00008000)` - Share icon, don't destroy
- `LR_DEFAULTSIZE (0x00000040)` - Use system default icon size

**Windows API:**
- `LoadImageA()` - Loads icon, cursor, or bitmap
- Returns HANDLE that can be used with Shell_NotifyIcon

**Example:**
```javascript
var icon = console._loadicon('C:\\myapp\\icon.ico');
var tray = console.SetTrayIcon({ icon: icon, szTip: 'MyApp' });
```

---

### Constants and Flags

#### Tray Icon Flags (Lines 22-38)

```javascript
var TrayIconFlags = {
    // Flags (uFlags field)
    NIF_MESSAGE: 0x00000001,    // uCallbackMessage is valid
    NIF_ICON: 0x00000002,       // hIcon is valid
    NIF_TIP: 0x00000004,        // szTip is valid
    NIF_STATE: 0x00000008,      // dwState and dwStateMask are valid
    NIF_INFO: 0x00000010,       // Balloon notification fields valid
    NIF_GUID: 0x00000020,       // guidItem is valid
    NIF_REALTIME: 0x00000040,   // Balloon shown immediately
    NIF_SHOWTIP: 0x00000080,    // Show tooltip (Vista+)

    // Messages (dwMessage parameter)
    NIM_ADD: 0x00000000,        // Add icon
    NIM_MODIFY: 0x00000001,     // Modify existing icon
    NIM_DELETE: 0x00000002,     // Delete icon
    NIM_SETFOCUS: 0x00000003,   // Focus on icon
    NIM_SETVERSION: 0x00000004  // Set version (for new features)
};
```

**Usage in Code:**
- **Line 88:** `NIF_TIP | NIF_MESSAGE` - Enable tooltip and message callback
- **Line 92:** Add `NIF_INFO` if balloon enabled
- **Line 96:** Add `NIF_ICON` if icon provided
- **Line 131:** `NIM_ADD` - Add tray icon to system tray
- **Line 162:** `NIM_DELETE` - Remove tray icon

---

#### Message Types (Line 40)

```javascript
var MessageTypes = {
    WM_APP: 0x8000,     // Start of application-defined messages
    WM_USER: 0x0400     // Start of user-defined messages
};
```

**Usage:**
- **Line 89:** `filter = WM_APP + 1` - Tray icon messages sent to 0x8001

---

#### Notification Icon Version (Line 39)

```javascript
var NOTIFYICON_VERSION_4 = 4;
```

**Purpose:** Use Windows Vista+ notification features
- **Line 103:** Written to structure at offset 416/432

## Dependencies

### Native Module Dependencies

#### _GenericMarshal (Line 47)

```javascript
this._Marshal = require('_GenericMarshal');
```

**Purpose:** FFI (Foreign Function Interface) library for calling Windows DLLs

**Capabilities:**
- JavaScript to native DLL function calls
- Memory marshaling and buffer management
- Pointer arithmetic and structure packing
- String conversion (ANSI/Wide character)

**Source:** `/microscript/ILibDuktape_GenericMarshal.c`

---

### Windows System DLL Dependencies

#### Kernel32.dll (Lines 48, 50-51)

```javascript
this._kernel32 = this._Marshal.CreateNativeProxy("kernel32.dll");
this._kernel32.CreateMethod("GetConsoleWindow");
this._kernel32.CreateMethod('GetCurrentThread');
```

**Methods Used:**

- **GetConsoleWindow()** - Line 50, 58
  - **Purpose:** Retrieves window handle for current console
  - **Returns:** HWND (window handle) of console window
  - **Used by:** All console window management methods (minimize, restore, hide, show)
  - **Documentation:** https://learn.microsoft.com/en-us/windows/console/getconsolewindow

- **GetCurrentThread()** - Line 51
  - **Purpose:** Returns pseudo-handle to current thread
  - **Used by:** Message pump threading operations
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthread

---

#### User32.dll (Lines 49, 52-54)

```javascript
this._user32 = this._Marshal.CreateNativeProxy("user32.dll");
```

**Methods Used:**

- **ShowWindow()** - Line 52
  - **Purpose:** Sets window show state (hide, show, minimize, restore, etc.)
  - **Used by:** `minimize()`, `restore()`, `hide()`, `show()` methods
  - **Parameters:** `ShowWindow(HWND hWnd, int nCmdShow)`
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow

- **LoadImageA()** - Line 53
  - **Purpose:** Loads icon, cursor, or bitmap from file
  - **Used by:** `_loadicon()` method
  - **Parameters:** `LoadImageA(HINSTANCE, LPCSTR, UINT, int, int, UINT)`
  - **Returns:** HANDLE to loaded image
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadimagea

- **GetMessageA()** - Line 54
  - **Purpose:** Retrieves message from thread's message queue
  - **Used by:** Message pump (via win-message-pump)
  - **Parameters:** `threadDispatch: 1` - Special marshaling for message loop
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagea

---

#### Shell32.dll (Lines 55-56)

```javascript
this._shell32 = this._Marshal.CreateNativeProxy('Shell32.dll');
this._shell32.CreateMethod('Shell_NotifyIconA');
```

**Methods Used:**

- **Shell_NotifyIconA()** - Line 56
  - **Purpose:** Sends message to system to add, modify, or delete tray icon
  - **Used by:** `SetTrayIcon()` - Lines 131 (add), 162 (delete)
  - **Parameters:** `Shell_NotifyIconA(DWORD dwMessage, PNOTIFYICONDATAA lpData)`
  - **Messages:** NIM_ADD, NIM_MODIFY, NIM_DELETE, NIM_SETFOCUS, NIM_SETVERSION
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shell_notifyicona

**NOTIFYICONDATA Structure:**
- Contains all icon configuration data
- Size varies: 32-bit (508 bytes) vs 64-bit (528 bytes)
- Includes: handle, icon, tooltip, balloon text, callback message

---

### Module Dependencies

#### win-message-pump (Line 114)

```javascript
var MessagePump = require('win-message-pump');
```

**Purpose:** Windows message loop implementation

**Used by:** `SetTrayIcon()` to receive tray icon events

**Functionality:**
- Creates hidden window for receiving messages
- Processes Windows message queue
- Routes messages to event handlers
- Manages HWND lifecycle

**Events:**
- **'hwnd'** (Line 125) - Window created, HWND available
- **'message'** (Line 136) - Windows message received
- **'exit'** (Line 124) - Message pump stopping

**Integration:**
1. `SetTrayIcon()` creates MessagePump instance with options
2. MessagePump creates hidden window
3. When window created, tray icon added with window's HWND
4. Messages filtered by `filter` value (WM_APP + 1)
5. Events emitted based on message parameters

**Lifecycle:**
```javascript
var pump = new MessagePump(options);
pump.on('hwnd', function(h) {
    // Window created, add tray icon
    Shell_NotifyIconA(NIM_ADD, data);
});
pump.on('message', function(msg) {
    // Handle tray icon messages
    if (msg.message == filter) {
        // Process click, hover, etc.
    }
});
pump.on('exit', function(code) {
    // Cleanup tray icon
    trayIcon.remove();
});
```

---

#### events (Line 116)

```javascript
var emitterUtils = require('events').inherits(retVal);
```

**Purpose:** Event emitter functionality

**Used by:** TrayIcon object to emit events

**Events Created:**
- `'ToastClicked'` - Line 117
- `'IconHover'` - Line 118
- `'ToastDismissed'` - Line 119

**Usage:**
```javascript
tray.on('ToastClicked', function() { /* ... */ });
tray.emit('ToastClicked');
```

---

### Dependency Chain Summary

```
win-console.js
├─── _GenericMarshal (Line 47) - FFI library
│    └─── Native marshaling layer
├─── Kernel32.dll (Lines 48, 50-51)
│    ├─── GetConsoleWindow() - Console window handle
│    └─── GetCurrentThread() - Thread management
├─── User32.dll (Lines 49, 52-54)
│    ├─── ShowWindow() - Window visibility control
│    ├─── LoadImageA() - Icon loading
│    └─── GetMessageA() - Message retrieval
├─── Shell32.dll (Lines 55-56)
│    └─── Shell_NotifyIconA() - System tray operations
└─── Module Dependencies
     ├─── win-message-pump (Line 114) - Windows message loop
     └─── events (Line 116) - Event emitter
```

## Technical Implementation Details

### Console Window Handle

**Line 58:** `this._handle = this._kernel32.GetConsoleWindow();`

- Retrieved once during initialization
- Stored for all subsequent ShowWindow() calls
- Handle remains valid for lifetime of console
- Will be 0 (null) if process has no console window

**Console-less Processes:**
If application started without console (GUI subsystem), `_handle` will be null and console methods will fail silently or have no effect.

---

### NOTIFYICONDATA Structure Layout

**32-bit Windows (508 bytes):**
```
Offset  Size  Field
------  ----  -----
0       4     cbSize (508)
4       4     hWnd
8       4     uID (1)
12      4     uFlags
16      4     uCallbackMessage (WM_APP + 1)
20      4     hIcon
24      128   szTip
152     8     Reserved
160     256   szInfo
416     4     uVersion (4)
420     64    szInfoTitle
484     4     dwInfoFlags
488-508 ...   Additional fields
```

**64-bit Windows (528 bytes):**
```
Offset  Size  Field
------  ----  -----
0       4     cbSize (528)
8       8     hWnd
16      4     uID (1)
20      4     uFlags
24      4     Padding
32      8     hIcon
40      128   szTip
168     8     Reserved
176     256   szInfo
432     4     uVersion (4)
436     64    szInfoTitle
500     4     dwInfoFlags
504-528 ...   Additional fields
```

**Pointer Size Detection (Line 83, 101-108):**
```javascript
var data = this._Marshal.CreateVariable(
    this._Marshal.PointerSize == 4 ? 508 : 528
);
```

All offsets adjusted based on pointer size for structure field alignment.

---

### Message Loop Architecture

**Tray Icon Message Flow:**

1. User interacts with tray icon (click, hover)
2. Windows sends message to window specified in `hWnd`
3. Message has `msg.message == WM_APP + 1` (filter value)
4. Message parameters indicate event type:
   - `wparam == 1, lparam == 1029` - Balloon clicked
   - `wparam == 1, lparam == 512` - Icon hover (WM_MOUSEMOVE)
   - `wparam == 1, lparam == 1028` - Balloon timeout/dismissed

**Message Pump Handles:**
- Message retrieval (GetMessageA)
- Message translation
- Message dispatching
- Event emission to JavaScript

**Thread Safety:**
- Message pump runs on dedicated thread (threadDispatch: 1)
- JavaScript callbacks execute on main thread
- Synchronization handled by marshaling layer

---

### Resource Lifecycle

**Tray Icon Lifecycle:**

1. **Creation:**
   - `SetTrayIcon()` called
   - MessagePump created
   - Hidden window created
   - `Shell_NotifyIconA(NIM_ADD)` called

2. **Operation:**
   - Icon visible in system tray
   - Messages routed to window
   - Events emitted to JavaScript

3. **Destruction:**
   - `tray.remove()` called
   - `Shell_NotifyIconA(NIM_DELETE)` removes icon
   - Message pump stopped
   - Window destroyed
   - Resources cleaned up

**Auto-cleanup (Line 124):**
```javascript
retVal.MessagePump.on('exit', function onExit(code) {
    if (this.TrayIcon) { this.TrayIcon.remove(); }
});
```

If message pump exits unexpectedly, tray icon automatically removed.

---

### Memory Management

**Buffer Allocation:**
- NOTIFYICONDATA structure: 508/528 bytes (Line 83)
- String buffers copied directly into structure (Lines 109-111)
- Icon handle pointer copied into structure (Line 98)

**String Handling:**
- szTip: 128 bytes (ANSI)
- szInfo: 256 bytes (ANSI)
- szInfoTitle: 64 bytes (ANSI)
- Buffers null-terminated automatically by Buffer.from()

**No Manual Cleanup Required:**
- Structure automatically garbage collected
- Icon handle marked LR_SHARED (doesn't need DestroyIcon)
- Window cleanup handled by message pump

## Known Usage Patterns

### Background Service with Tray Icon

```javascript
var console = require('win-console');

// Hide console window
console.hide();

// Create tray icon
var icon = console._loadicon('C:\\app\\icon.ico');
var tray = console.SetTrayIcon({
    icon: icon,
    szTip: 'MyService - Running',
    szInfo: 'Service started successfully',
    szInfoTitle: 'MyService'
});

tray.on('IconHover', function() {
    console.log('User checking tray icon');
});
```

### Temporary Notification

```javascript
var console = require('win-console');

// Show notification balloon only
var icon = console._loadicon('C:\\app\\icon.ico');
var tray = console.SetTrayIcon({
    icon: icon,
    szTip: 'Update Available',
    szInfo: 'A new version is available for download',
    szInfoTitle: 'Software Update',
    balloonOnly: true  // Auto-remove after balloon dismissed
});

tray.on('ToastClicked', function() {
    // Open update URL
    require('child_process').exec('start https://example.com/update');
});
```

### Console Window Control

```javascript
var console = require('win-console');

// Start minimized
console.minimize();

// Show on error
try {
    // Application logic
} catch(e) {
    console.restore();  // Bring console to front
    console.error('Error:', e);
}
```

## Limitations

### Platform Limitations

1. **Windows Only:** Module exports empty object on non-Windows (Line 44 check)
2. **Console Requirement:** Console methods require process to have allocated console
3. **GUI Applications:** Won't work for pure GUI apps without console window

### Tray Icon Limitations

1. **Single Icon:** Code creates one icon with ID=1, multiple icons would need modification
2. **Balloon Timeout:** Balloon display time controlled by Windows (typically 5-30 seconds)
3. **Icon Size:** Uses system default size, cannot specify custom dimensions
4. **ANSI Strings:** Text limited to ANSI characters, no full Unicode support
5. **Windows Vista+:** NOTIFYICON_VERSION_4 features require Vista or later

### Message Handling

1. **Filter Collision:** Uses WM_APP + 1, could conflict with other application messages
2. **Event Types:** Only handles specific lparam values (1028, 1029, 512)
3. **No Context Menu:** Doesn't implement right-click context menu functionality

## Error Handling

### Silent Failures

- **No Console:** Console methods fail silently if no console window
- **Invalid Icon Path:** LoadImageA returns null handle, tray icon creation may fail
- **Shell_NotifyIconA Failure:** Line 131-134 checks return value but only logs

### Exception Scenarios

None documented - module designed for graceful degradation

### Best Practices

1. **Check Platform:** Always verify `process.platform == 'win32'` before using
2. **Validate Paths:** Ensure icon file exists before calling `_loadicon()`
3. **Error Events:** Listen for message pump 'error' event
4. **Cleanup:** Always call `tray.remove()` before application exit

## License

**Apache License 2.0**
Copyright 2018-2020 Intel Corporation

## Summary

win-console.js is a Windows-specific module providing console window visibility control and system tray icon management with notification balloon support. It offers simple methods for minimizing/hiding console windows and creating persistent or temporary system tray presence.

**Explicitly excludes all non-Windows platforms** because:
- Relies entirely on Windows-specific DLLs (User32.dll, Shell32.dll, Kernel32.dll)
- Windows console window model doesn't exist on other platforms (terminals are separate processes)
- Windows system tray API is fundamentally different from macOS menu bar items and Linux systray
- Uses Windows message pump architecture (win-message-pump) with HWND and message queue
- Platform check on line 44 prevents initialization on non-Windows systems
- No cross-platform equivalent - would require complete rewrite for macOS (NSStatusBar) or Linux (StatusNotifierItem)

The module is designed specifically for Windows background services and applications that need system tray presence while managing console window visibility. Alternative approaches using platform-specific APIs would be required for macOS menu bar items or Linux system tray functionality.
