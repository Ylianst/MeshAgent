# win-message-pump.js

Windows message loop implementation that creates hidden windows and processes Windows messages asynchronously. Enables JavaScript applications to receive Windows UI events, create custom windows, and integrate with the Windows messaging system through event-driven architecture.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support (implicit)

**Excluded Platforms:**
- **macOS** - Implicitly excluded (no platform check, module will fail on instantiation)
- **Linux** - Implicitly excluded (no platform check, module will fail on instantiation)
- **FreeBSD** - Implicitly excluded (no platform check, module will fail on instantiation)
- **All non-Windows platforms** - Implicitly excluded

**Exclusion Reasoning:**

The module has **no explicit platform check** but is fundamentally Windows-only. It will fail immediately upon instantiation when attempting to load Windows-specific DLLs:

**Lines 34-40:** Module initialization loads Windows-exclusive DLLs:
```javascript
this._kernel32 = GM.CreateNativeProxy('Kernel32.dll');
this._user32 = GM.CreateNativeProxy('User32.dll');
this._gdi32 = GM.CreateNativeProxy('Gdi32.dll');
```

**Why macOS/Linux are excluded:**

1. **Windows Message Loop Architecture Doesn't Exist**
   - Windows: Message queue per thread, GetMessage/DispatchMessage loop
   - macOS: Event loop via NSRunLoop/CFRunLoop (completely different)
   - Linux: Event loops vary (X11, Wayland, GTK+, Qt) - no unified system
   - Fundamental architectural difference in how UI events are processed

2. **Windows Window Classes and HWND System**
   - Windows: RegisterClassEx creates window classes, CreateWindowEx creates instances
   - Every window has HWND (unique handle) and receives messages
   - macOS: NSWindow/NSView hierarchy (object-oriented, not handle-based)
   - Linux: X11 Window IDs or Wayland surfaces (different APIs entirely)

3. **Windows-Specific DLL Dependencies**
   - **User32.dll** - All windowing, message loop, and UI functions
   - **Kernel32.dll** - Module handle and thread management
   - **Gdi32.dll** - Graphics Device Interface for fonts and brushes
   - These DLLs only exist on Windows systems

4. **Windows Message Constants and Structures**
   - Lines 17-21: WM_QUIT (0x0012), WM_CLOSE (0x0010), WH_CALLWNDPROC (4)
   - Lines 351-367: Window style constants (WS_BORDER, WS_CAPTION, etc.)
   - WNDCLASSEX structure (Lines 100-117)
   - MSG structure (Line 33)
   - No equivalents on other platforms

5. **Windows Callback Architecture**
   - Lines 112-200: Window procedure (WndProc) callback
   - Called directly by Windows for each message
   - Requires C calling convention and specific signature
   - DefWindowProc for default message handling
   - No equivalent callback system on other platforms

**macOS Alternative:**
- NSApplication with NSRunLoop
- NSWindow and NSWindowDelegate
- Event handling via NSResponder chain

**Linux Alternative:**
- X11: XNextEvent/XPending event loop
- Wayland: wl_display_dispatch
- GTK+: gtk_main() event loop
- Qt: QApplication::exec()

## Functionality

### Core Concept

The module creates a hidden window and processes Windows messages asynchronously, allowing JavaScript code to:
1. Receive Windows UI events
2. Create custom windows with message handling
3. Integrate with Windows system tray, dialogs, etc.
4. Handle user input (mouse, keyboard)
5. Process window lifecycle events (create, destroy, paint, resize)

### Constructor: WindowsMessagePump(options)

**Lines 23-231:** Creates message pump instance

**Parameters (options object):**

**Window Configuration (optional):**
- `window.background` - Background color brush (Line 104-108)
- `window.exstyles` - Extended window styles (default: 0x00000088 - topmost tool window)
- `window.winstyles` - Window styles (default: 0x00800000 - border)
- `window.x` - X position (default: 0)
- `window.y` - Y position (default: 0)
- `window.width` - Window width (default: 100)
- `window.height` - Window height (default: 100)
- `window.title` - Window title (wide string)

**Events Emitted:**

- **'hwnd'** (Line 28) - Window created, HWND available
  - Parameter: `h` - Window handle (HWND)
  - Fired once after successful window creation

- **'error'** (Line 29) - Error occurred
  - Parameter: Error message string
  - Fired if window creation fails

- **'message'** (Line 30) - Windows message received
  - Parameter: Object with properties:
    - `message` - Message ID (e.g., WM_PAINT, WM_CLOSE)
    - `wparam` - First message parameter
    - `lparam` - Second message parameter
    - `lparam_hex` - lparam as hex string
    - `lparam_raw` - Raw lparam pointer
    - `hwnd` - Window handle
    - `dispatcher` - Message dispatcher for async responses

- **'exit'** (Line 31) - Message pump stopped
  - Parameter: `code` - Exit code (0 for normal exit)
  - Fired when WM_QUIT received or pump manually stopped

**Returns:** WindowsMessagePump instance with methods and properties

---

### Instance Methods

#### stop() - Lines 298-305

Stops the message pump gracefully by posting WM_QUIT to the message queue.

**Implementation:**
```javascript
this.stop = function stop() {
    if (this._hwnd) {
        this._user32.PostMessageA(this._hwnd, WM_QUIT, 0, 0);
        this.once('exit', function() { this.wndclass.wndproc.close() });
    }
};
```

**Behavior:**
- Posts WM_QUIT (0x0012) to message queue
- Message loop exits on next iteration
- 'exit' event fired
- Window procedure callback cleaned up

**Use Case:**
- Graceful shutdown of message pump
- Cleanup before application exit

---

#### close() - Lines 306-313

Sends WM_CLOSE message to window, triggering close sequence.

**Implementation:**
```javascript
this.close = function close() {
    if (this._hwnd) {
        this._user32.PostMessageA(this._hwnd, WM_CLOSE, 0, 0);
        this.once('exit', function() { this.wndclass.wndproc.close(); });
    }
};
```

**Behavior:**
- Posts WM_CLOSE (0x0010) to window
- Allows window to process close (save state, confirm, etc.)
- Default WndProc destroys window if not handled
- 'exit' event fired after destruction

**Difference from stop():**
- `close()` - Polite close request (can be cancelled)
- `stop()` - Immediate quit (cannot be cancelled)

---

#### hookChild(childHwnd) - Lines 319-347

Hooks into another window's message stream by replacing its window procedure.

**Parameters:**
- `childHwnd` - Handle to child window to hook

**Returns:**
- `true` if hook successful
- `false` if hook failed

**Implementation (Lines 340-346):**
```javascript
var old = this._user32.SetWindowLongPtrA(childHwnd, GWLP_WNDPROC, newval);
if (old.Val != 0) {
    GM.PutData(childHwnd, old, newval);
    return (true);
}
return (false);
```

**How It Works:**
1. Creates new window procedure callback (Line 323)
2. Replaces child window's WndProc with new callback
3. Stores original WndProc for restoration
4. New callback emits 'message' events to this pump

**Use Case:**
- Monitor messages for windows created by other APIs
- Subclass controls (buttons, edit boxes, etc.)
- Intercept messages before default handling

**Example:**
```javascript
var pump = new WindowsMessagePump({});
pump.on('hwnd', function(hwnd) {
    // Create child button
    var button = pump._user32.CreateWindowExW(...);

    // Hook button messages
    pump.hookChild(button);
});

pump.on('message', function(msg) {
    if (msg.hwnd.Val == buttonHwnd.Val) {
        console.log('Button message:', msg.message);
    }
});
```

**Warning:**
- Advanced feature, requires understanding of Windows message flow
- Original WndProc must be preserved for proper operation
- Improper hooking can crash application

---

### Internal Methods (Private)

#### _startPump() - Lines 255-296

**Purpose:** Main message loop - retrieves and dispatches Windows messages

**Algorithm:**
1. **Pending Window Creation** (Lines 257-267)
   - Processes queued CreateWindowEx calls
   - Returns immediately to continue creating windows

2. **Message Retrieval** (Line 268)
   - Calls `GetMessageW()` asynchronously
   - Blocks until message available

3. **Message Processing** (Lines 270-278)
   - If `r.Val > 0`: Message received
     - TranslateMessage() - Translates virtual-key messages
     - DispatchMessageW() - Dispatches to window procedure
     - Recursively calls `_startPump()` to continue loop

4. **Quit Handling** (Lines 280-294)
   - If `r.Val == 0`: WM_QUIT received
     - DestroyWindow() called
     - UnregisterClassW() called
     - Message loop thread aborted
     - Window handle deleted
     - 'exit' event emitted
     - Window procedure callback cleaned up

**Asynchronous Operation:**
- All Windows API calls use `.async()` method
- Runs on dedicated thread (threadDispatch)
- JavaScript callbacks execute on main thread
- No blocking of main event loop

---

#### _addCreateWindowEx(...) - Lines 240-248

**Purpose:** Queue CreateWindowEx call for later execution

**Parameters:** All parameters for CreateWindowExW API

**Returns:** Promise that resolves with window handle

**Use Case:**
- Create child windows after main window exists
- Deferred window creation during message processing

---

#### _addAsyncMethodCall(func, args) - Lines 232-239

**Purpose:** Generic method for queuing asynchronous function calls

**Parameters:**
- `func` - Function to call
- `args` - Array of arguments

**Returns:** Promise that resolves with function result

**Implementation:**
- Stores function, arguments, and promise in queue
- `_startPump()` processes queue before message loop
- Ensures proper sequencing of window operations

---

### Window Procedure Callback (WndProc)

**Lines 118-200:** Central message handling logic

**Callback Signature:**
```javascript
function onWndProc(xhwnd, xmsg, wparam, lparam)
```

**Parameters:**
- `xhwnd` - Window handle receiving message
- `xmsg` - Message ID
- `wparam` - First message parameter (meaning varies by message)
- `lparam` - Second message parameter (meaning varies by message)

**Message Routing Logic:**

**Case 1: Main Window Messages** (Lines 122-163)
- If `this.mp._hwnd != null && this.mp._hwnd.Val == xhwnd.Val`
- Message is for our main window
- Emit 'message' event
- Check for return value from event handlers
- If no return value: Call DefWindowProcW() for default handling
- If return value: Use as message result

**Case 2: Pre-Creation Messages** (Lines 164-197)
- If `this.mp._hwnd == null` and on message pump thread
- Messages generated during CreateWindowExA
- Emit 'message' event
- Same default handling logic as Case 1

**Return Value Handling:**
- JavaScript event handler can return value
- Value becomes Windows message result (LRESULT)
- Allows custom message processing
- If null/undefined returned, DefWindowProc handles message

**Example Custom Handling:**
```javascript
pump.on('message', function(msg) {
    if (msg.message == 0x000F) {  // WM_PAINT
        // Custom paint handling
        return 0;  // Message handled
    }
    // Return nothing - use default handling
});
```

---

### Window Class Registration

**Lines 100-117:** WNDCLASSEX structure creation

**Structure Fields:**
- **cbSize** (Line 114) - Structure size (48 bytes on 32-bit, 80 on 64-bit)
- **lpfnWndProc** (Line 116) - Window procedure callback pointer
- **hInstance** (Line 102, 117) - Module instance handle
- **lpszClassName** (Line 111, 115) - Class name (unique per instance)
- **hbrBackground** (Line 107-108) - Background brush (optional)

**Class Name Generation (Line 111):**
```javascript
this.wndclass.cnamew = GM.CreateVariable(
    'MainWWWClass_' + this.wndclass._hashCode(),
    { wide: true }
);
```
- Unique name per instance prevents conflicts
- Wide character encoding (UTF-16)

**Registration (Line 202):**
```javascript
this._user32.RegisterClassExW.async(this.wndclass).then(...)
```
- Asynchronous registration on dedicated thread
- Promise resolves when class registered
- Window creation follows immediately

---

### Window Creation

**Lines 214-230:** CreateWindowExW call

**Window Creation Parameters:**
- `dwExStyle` - Extended styles (e.g., WS_EX_TOPMOST, WS_EX_TOOLWINDOW)
- `lpClassName` - Registered class name
- `lpWindowName` - Window title (wide string or 0)
- `dwStyle` - Window styles (e.g., WS_BORDER, WS_VISIBLE)
- `x, y` - Position
- `nWidth, nHeight` - Size
- `hWndParent` - Parent window (0 for top-level)
- `hMenu` - Menu handle (0 for none)
- `hInstance` - Module instance (0 for current)
- `lpParam` - Creation parameters (0 for none)

**Success Handling (Lines 226-229):**
- Store HWND in `this._hwnd`
- Emit 'hwnd' event
- Start message pump

**Failure Handling (Lines 219-223):**
- Check if `h.Val == 0`
- Emit 'error' event with message
- No window created, pump not started

---

### Exported Constants

#### WindowStyles - Lines 351-358

Standard window styles for CreateWindowEx:

```javascript
module.exports.WindowStyles = {
    WS_BORDER: 0x00800000,          // Window has thin-line border
    WS_CAPTION: 0x00C00000,         // Window has title bar
    WS_CHILD: 0x40000000,           // Child window
    WS_CHILDWINDOW: 0x40000000,     // Same as WS_CHILD
    WS_CLIPCHILDREN: 0x02000000,    // Exclude child area when drawing
    WS_CLIPSIBLINGS: 0x04000000,    // Clip sibling windows
    WS_DISABLED: 0x08000000,        // Initially disabled
    WS_DLGFRAME: 0x00400000,        // Dialog frame (no title bar)
    WS_GROUP: 0x00020000,           // First control in group
    WS_HSCROLL: 0x00100000,         // Horizontal scroll bar
    WS_ICONIC: 0x20000000,          // Initially minimized
    WS_MAXIMIZE: 0x01000000,        // Initially maximized
    WS_MAXIMIZEBOX: 0x00010000,     // Has maximize button
    WS_MINIMIZE: 0x20000000,        // Initially minimized
    WS_MINIMIZEBOX: 0x00020000,     // Has minimize button
    WS_OVERLAPPED: 0x00000000,      // Overlapped window
    WS_POPUP: 0x80000000,           // Popup window
    WS_SIZEBOX: 0x00040000,         // Resizable border
    WS_SYSMENU: 0x00080000,         // Has system menu
    WS_TABSTOP: 0x00010000,         // Can receive keyboard focus
    WS_THICKFRAME: 0x00040000,      // Resizable border
    WS_TILED: 0x00000000,           // Same as WS_OVERLAPPED
    WS_VISIBLE: 0x10000000,         // Initially visible
    WS_VSCROLL: 0x00200000          // Vertical scroll bar
};
```

**Usage:**
```javascript
var styles = require('win-message-pump').WindowStyles;
var pump = new WindowsMessagePump({
    window: {
        winstyles: styles.WS_VISIBLE | styles.WS_CAPTION | styles.WS_SYSMENU
    }
});
```

---

#### WindowStylesEx - Lines 359-367

Extended window styles:

```javascript
module.exports.WindowStylesEx = {
    WS_EX_ACCEPTFILES: 0x00000010,      // Accept drag-drop files
    WS_EX_APPWINDOW: 0x00040000,        // Force on taskbar when visible
    WS_EX_CLIENTEDGE: 0x00000200,       // Sunken edge border
    WS_EX_COMPOSITED: 0x02000000,       // Double-buffered painting
    WS_EX_CONTEXTHELP: 0x00000400,      // Question mark in title bar
    WS_EX_CONTROLPARENT: 0x00010000,    // Allow tab navigation
    WS_EX_DLGMODALFRAME: 0x00000001,    // Double border
    WS_EX_LAYERED: 0x0008000,           // Layered window
    WS_EX_LAYOUTRTL: 0x00400000,        // Right-to-left layout
    WS_EX_LEFT: 0x00000000,             // Left-aligned (default)
    WS_EX_LEFTSCROLLBAR: 0x00004000,    // Scrollbar on left
    WS_EX_LTRREADING: 0x00000000,       // Left-to-right reading order
    WS_EX_MDICHILD: 0x00000040,         // MDI child window
    WS_EX_NOACTIVATE: 0x08000000,       // Don't activate when clicked
    WS_EX_NOINHERITLAYOUT: 0x00100000,  // Don't inherit layout
    WS_EX_NOPARENTNOTIFY: 0x00000004,   // Don't notify parent
    WS_EX_NOREDIRECTIONBITMAP: 0x00200000, // No redirection bitmap
    WS_EX_RIGHT: 0x00001000,            // Right-aligned properties
    WS_EX_RIGHTSCROLLBAR: 0x00000000,   // Scrollbar on right (default)
    WS_EX_RTLREADING: 0x00002000,       // Right-to-left reading order
    WS_EX_STATICEDGE: 0x00020000,       // 3D border
    WS_EX_TOOLWINDOW: 0x00000080,       // Tool window (small title bar)
    WS_EX_TOPMOST: 0x00000008,          // Above all non-topmost windows
    WS_EX_TRANSPARENT: 0x00000020,      // Transparent window
    WS_EX_WINDOWEDGE: 0x00000100        // Raised edge border
};
```

**Usage:**
```javascript
var exStyles = require('win-message-pump').WindowStylesEx;
var pump = new WindowsMessagePump({
    window: {
        exstyles: exStyles.WS_EX_TOPMOST | exStyles.WS_EX_TOOLWINDOW
    }
});
```

## Dependencies

### Native Module Dependencies

#### _GenericMarshal (Line 20)

```javascript
var GM = require('_GenericMarshal');
const GWLP_WNDPROC = -4;
```

**Purpose:** FFI (Foreign Function Interface) library for calling Windows DLLs

**Capabilities:**
- JavaScript to native DLL function calls
- Memory marshaling and buffer management
- Callback creation (`GetGenericGlobalCallback`, `GetGenericGlobalCallbackEx`)
- Pointer arithmetic and structure packing
- Asynchronous method execution (`.async()`)
- Data association (`PutData`, `GetData`)

**Source:** `/microscript/ILibDuktape_GenericMarshal.c`

**Special Features Used:**
- **GetGenericGlobalCallback(4)** - Line 112: Create 4-parameter callback
- **GetGenericGlobalCallbackEx(4, 55)** - Line 323: Create callback with specific calling convention
- **async** property - All Windows API calls use async execution
- **threadDispatch** - Dedicated thread for message loop

---

### Windows System DLL Dependencies

#### Kernel32.dll (Lines 34, 36-37)

```javascript
this._kernel32 = GM.CreateNativeProxy('Kernel32.dll');
this._kernel32.CreateMethod('GetLastError');
this._kernel32.CreateMethod('GetModuleHandleA');
```

**Methods Used:**

- **GetLastError()** - Line 36
  - **Purpose:** Retrieves last Windows error code
  - **Used by:** Error diagnostics
  - **Returns:** DWORD error code

- **GetModuleHandleA()** - Line 37, 102
  - **Purpose:** Retrieves module instance handle
  - **Used by:** Window class registration
  - **Parameters:** `GetModuleHandleA(NULL)` gets current process handle
  - **Returns:** HMODULE for use as hInstance

---

#### User32.dll (Lines 39-88) - Primary Windowing API

```javascript
this._user32 = GM.CreateNativeProxy('User32.dll');
```

**Methods Used:**

**Window Creation and Destruction:**
- **CreateWindowExW()** - Line 42, 214
  - **Purpose:** Creates overlapped, popup, or child window
  - **Parameters:** Extended style, class, title, style, position, size, parent, menu, instance, param
  - **Returns:** HWND window handle
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowexw

- **DestroyWindow()** - Line 44, 283
  - **Purpose:** Destroys window and removes from screen
  - **Used by:** Cleanup when message pump exits
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-destroywindow

**Window Class Management:**
- **RegisterClassExW()** - Line 56, 202
  - **Purpose:** Registers window class for subsequent use
  - **Parameters:** WNDCLASSEXW structure pointer
  - **Returns:** Class atom (non-zero on success)
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerclassexw

- **UnregisterClassW()** - Line 81, 285
  - **Purpose:** Unregisters window class
  - **Used by:** Cleanup when message pump exits
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unregisterclassw

**Message Loop:**
- **GetMessageW()** - Line 51, 268
  - **Purpose:** Retrieves message from calling thread's message queue
  - **Blocks:** Until message available
  - **Returns:** Non-zero except for WM_QUIT
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagew

- **TranslateMessage()** - Line 80, 272
  - **Purpose:** Translates virtual-key messages into character messages
  - **Used by:** Keyboard input processing
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-translatemessage

- **DispatchMessageW()** - Line 45, 274
  - **Purpose:** Dispatches message to window procedure
  - **Used by:** Message routing to WndProc
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-dispatchmessagew

- **DefWindowProcW()** - Line 43, 142, 184
  - **Purpose:** Calls default window procedure
  - **Used by:** Default message handling when no custom handler
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-defwindowprocw

- **PostMessageA()** - Line 55, 302, 310
  - **Purpose:** Posts message to message queue (non-blocking)
  - **Used by:** `stop()` and `close()` methods
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagea

**Window Manipulation:**
- **SetWindowPos()** - Line 75
  - **Purpose:** Changes window size, position, and Z order
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowpos

- **SetWindowTextW()** - Line 76
  - **Purpose:** Changes window title
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowtextw

- **ShowWindow()** - Line 77
  - **Purpose:** Sets window show state
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow

**Window Properties:**
- **SetWindowLongA()** / **SetWindowLongPtrA()** - Lines 60-72, 340
  - **Purpose:** Changes window attribute
  - **Used by:** `hookChild()` to replace window procedure
  - **Parameters:** `GWLP_WNDPROC = -4` for window procedure
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowlongptra

- **SetClassLongA()** / **SetClassLongPtrA()** - Lines 60-72
  - **Purpose:** Replaces class attribute
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setclasslongptra

**Architecture-Specific** (Lines 63-72):
32-bit systems use SetWindowLongA/SetClassLongA
64-bit systems use SetWindowLongPtrA/SetClassLongPtrA

**Painting:**
- **BeginPaint()** - Line 41
- **EndPaint()** - Line 47
- **InvalidateRect()** - Line 52
- **GetClientRect()** - Line 49
- **FillRect()** - Line 48

**Drawing:**
- **DrawTextExW()** - Line 46
- **GetDC()** - Line 50

**Input:**
- **LoadCursorA()** - Line 53
- **SetCursor()** - Line 74
- **TrackMouseEvent()** - Line 79
- **ReleaseCapture()** - Line 57

**Dialogs:**
- **IsDlgButtonChecked()** - Line 83
- **CheckDlgButton()** - Line 84

**Window Positioning:**
- **BeginDeferWindowPos()** - Line 86
- **DeferWindowPos()** - Line 87
- **EndDeferWindowPos()** - Line 88

**Monitors:**
- **MonitorFromWindow()** - Line 54

**System:**
- **SystemParametersInfoA()** - Line 78
- **SendMessageW()** - Line 58

---

#### Gdi32.dll (Lines 90-96) - Graphics Device Interface

```javascript
this._gdi32 = GM.CreateNativeProxy('Gdi32.dll');
```

**Methods Used:**

- **CreateFontW()** - Line 92
  - **Purpose:** Creates logical font
  - **Used by:** Text rendering

- **CreateSolidBrush()** - Line 93, 107
  - **Purpose:** Creates solid color brush
  - **Used by:** Window background (if specified in options)

- **SetBkColor()** - Line 94
  - **Purpose:** Sets background color for text

- **SetBkMode()** - Line 95
  - **Purpose:** Sets background mode (transparent/opaque)

- **SetTextColor()** - Line 96
  - **Purpose:** Sets text color

---

### Module Dependencies

#### events (Line 27)

```javascript
var emitterUtils = require('events').inherits(this);
```

**Purpose:** Event emitter functionality

**Events Created:**
- `'hwnd'` - Line 28
- `'error'` - Line 29
- `'message'` - Line 30
- `'exit'` - Line 31

**Usage:**
```javascript
pump.on('message', function(msg) { /* ... */ });
pump.emit('message', { message: 0x000F, ... });
```

---

### Dependency Chain Summary

```
win-message-pump.js
├─── _GenericMarshal (Line 20) - FFI library
│    ├─── CreateNativeProxy() - DLL proxies
│    ├─── GetGenericGlobalCallback() - WndProc callback
│    ├─── GetGenericGlobalCallbackEx() - Hook callback
│    └─── Async execution and threading
├─── Kernel32.dll (Lines 34, 36-37)
│    ├─── GetLastError() - Error codes
│    └─── GetModuleHandleA() - Module instance
├─── User32.dll (Lines 39-88) - Windowing
│    ├─── RegisterClassExW() - Class registration
│    ├─── CreateWindowExW() - Window creation
│    ├─── GetMessageW() - Message retrieval
│    ├─── TranslateMessage() - Key translation
│    ├─── DispatchMessageW() - Message dispatch
│    ├─── DefWindowProcW() - Default handling
│    ├─── PostMessageA() - Message posting
│    ├─── DestroyWindow() - Window cleanup
│    ├─── UnregisterClassW() - Class cleanup
│    └─── 30+ other windowing functions
├─── Gdi32.dll (Lines 90-96) - Graphics
│    ├─── CreateSolidBrush() - Background brush
│    └─── Font and color functions
└─── events (Line 27) - Event emitter
     └─── Event creation and emission
```

## Technical Implementation Details

### Asynchronous Architecture

**Dedicated Message Loop Thread:**

All Windows API calls use `.async()` method:
```javascript
this._user32.GetMessageW.async(
    this._user32.RegisterClassExW.async,  // Thread context
    this._msg, this._hwnd, 0, 0
).then(...)
```

**Benefits:**
- Main JavaScript thread never blocked
- Windows message loop runs continuously
- UI remains responsive
- Multiple pumps can coexist

**Thread Dispatch:**
- Line 54: `{ method: 'GetMessageA', threadDispatch: 1 }`
- Creates dedicated thread for message pump
- All `.async()` calls with same context run on same thread
- JavaScript callbacks execute on main thread via marshaling

---

### Memory Management

**MSG Structure (Line 33):**
```javascript
this._msg = GM.CreateVariable(GM.PointerSize == 4 ? 28 : 48);
```
- 32-bit: 28 bytes
- 64-bit: 48 bytes
- Reused for all GetMessage calls

**WNDCLASSEX Structure (Line 100):**
```javascript
this.wndclass = GM.CreateVariable(GM.PointerSize == 4 ? 48 : 80);
```
- 32-bit: 48 bytes
- 64-bit: 80 bytes
- Stored in `this.wndclass` for lifetime of pump

**Pointer Buffers:**
- **Line 115:** Class name pointer copied to structure
- **Line 116:** WndProc pointer copied to structure
- **Line 117:** Instance handle copied to structure

**No Manual Cleanup:**
- Structures automatically garbage collected
- Window procedure callback closed on exit (Line 303)
- Window handle deleted when pump stops (Line 288)

---

### Window Procedure Callback Details

**Callback Creation (Lines 112-113):**
```javascript
this.wndclass.wndproc = GM.GetGenericGlobalCallback(4);
this.wndclass.wndproc.mp = this;
```

**Callback Lifetime:**
- Created during construction
- Registered with Windows during RegisterClassExW
- Called by Windows for every message
- Closed during cleanup (Lines 290, 303, 311)

**Event Dispatcher (Lines 126-127, 169):**
```javascript
var d = this.StartDispatcher();
```
- Manages async response to Windows
- Allows DefWindowProc to run asynchronously
- Handles message result properly

**Return Value Flow:**
1. JavaScript event handler returns value (or undefined)
2. `emit_returnValue('message')` retrieves it (Lines 132, 180)
3. If null: DefWindowProc called asynchronously (Lines 142, 184)
4. If value: Converted to pointer and returned (Lines 152-161, 193-195)
5. `EndDispatcher()` sends result back to Windows (Lines 146, 154, 188, 195)

---

### Architecture-Specific Code

**Pointer Size Detection:**
```javascript
if (GM.PointerSize == 4) {
    // 32-bit code
} else {
    // 64-bit code
}
```

**32-bit vs 64-bit:**
- **MSG:** 28 vs 48 bytes
- **WNDCLASSEX:** 48 vs 80 bytes
- **SetWindowLongPtrA:** Different functions (Lines 63-72)
- **Structure offsets:** Adjusted for pointer size

**Example Offset Calculation (Line 108):**
```javascript
this.wndclass.bkbrush.pointerBuffer().copy(
    this.wndclass.Deref(GM.PointerSize == 4 ? 32 : 48, GM.PointerSize).toBuffer()
)
```

---

### Error Handling

**Window Creation Failure (Lines 219-223):**
```javascript
if (h.Val == 0) {
    this.nativeProxy.mp.emit('error', 'Error creating hidden window');
}
```

**GetMessage Error (Line 295):**
```javascript
}, function (err) { this.nativeProxy.mp.stop(); });
```
- Promise rejection handler
- Stops pump on critical error

**Best Practice:**
Always listen for 'error' event:
```javascript
pump.on('error', function(err) {
    console.error('Message pump error:', err);
});
```

---

### Garbage Collection Safety

**Line 199:** `if (processed) { _debugGC(); }`

Triggers garbage collection after message processing to:
- Free temporary buffers
- Clean up marshal variables
- Prevent memory leaks in long-running message loops

---

### Performance Considerations

**Message Loop Efficiency:**
- Asynchronous GetMessage blocks efficiently (no busy-wait)
- Only wakes when messages available
- Minimal CPU usage when idle

**Callback Overhead:**
- Every message requires JavaScript callback
- Marshaling overhead for parameters
- Consider filtering messages if high-frequency

**Multiple Pumps:**
- Each pump has own thread and window class
- No interference between pumps
- Resource usage scales linearly

## Known Usage in Codebase

### System Tray Integration (win-console.js)

**Lines 114-169 of win-console.js:**
```javascript
var MessagePump = require('win-message-pump');
retVal = { MessagePump: new MessagePump(options) };

retVal.MessagePump.on('hwnd', function onHwnd(h) {
    // Add tray icon once window created
    Shell_NotifyIconA(NIM_ADD, notifyData);
});

retVal.MessagePump.on('message', function onWindowsMessage(msg) {
    // Handle tray icon clicks, hovers
    if (msg.message == filter) {
        // Process tray events
    }
});
```

**Purpose:**
- Creates hidden window for tray icon
- Receives system tray events
- Routes to JavaScript event handlers

---

### Custom Window Creation

**Example Pattern:**
```javascript
var MP = require('win-message-pump');
var pump = new MP({
    window: {
        title: 'My Window',
        width: 640,
        height: 480,
        winstyles: MP.WindowStyles.WS_VISIBLE |
                   MP.WindowStyles.WS_CAPTION |
                   MP.WindowStyles.WS_SYSMENU,
        exstyles: MP.WindowStylesEx.WS_EX_APPWINDOW
    }
});

pump.on('hwnd', function(hwnd) {
    console.log('Window created:', hwnd.Val);
});

pump.on('message', function(msg) {
    if (msg.message == 0x0010) {  // WM_CLOSE
        console.log('User closing window');
        pump.stop();
        return 0;
    }
});
```

## Limitations

### Platform Limitations

1. **Windows Only:** No platform check, fails on non-Windows
2. **Message Loop Model:** Tied to Windows threading model
3. **Window Required:** Cannot pump messages without window

### API Limitations

1. **Single Window Per Pump:** One HWND per pump instance
2. **No Window Parenting:** Cannot easily create parent/child hierarchies
3. **Limited GDI:** Basic GDI functions only, not full drawing API
4. **No Direct Input:** Must handle WM_KEYDOWN, WM_MOUSEMOVE manually

### Performance Limitations

1. **JavaScript Marshaling:** Every message crosses FFI boundary
2. **Callback Overhead:** Can be slow for high-frequency messages (WM_MOUSEMOVE)
3. **Single-Threaded JS:** Despite async, JavaScript handlers run sequentially

### Security Considerations

1. **Window Hooking:** `hookChild()` can intercept sensitive data
2. **Message Injection:** No validation of message sources
3. **Callback Safety:** JavaScript errors in WndProc can crash process

## Best Practices

### 1. Always Handle Errors

```javascript
pump.on('error', function(err) {
    console.error('Pump error:', err);
    cleanup();
});
```

### 2. Clean Up Resources

```javascript
process.on('SIGINT', function() {
    pump.stop();
});

pump.on('exit', function() {
    console.log('Pump stopped cleanly');
});
```

### 3. Filter High-Frequency Messages

```javascript
pump.on('message', function(msg) {
    // Ignore mouse move to reduce overhead
    if (msg.message == 0x0200) return;  // WM_MOUSEMOVE

    // Process other messages
    handleMessage(msg);
});
```

### 4. Use Async Handlers

```javascript
pump.on('message', function(msg) {
    if (msg.message == 0x000F) {  // WM_PAINT
        // Use dispatcher for async painting
        setImmediate(function() {
            doPainting();
            msg.dispatcher.EndDispatcher(0);
        });
        return msg.dispatcher;  // Return dispatcher, not value
    }
});
```

### 5. Validate Window Creation

```javascript
var pump = new MessagePump(options);
pump.on('hwnd', function(hwnd) {
    if (hwnd.Val == 0) {
        console.error('Invalid window handle');
        return;
    }
    console.log('Window created successfully');
});
```

## License

**Apache License 2.0**
Copyright 2018 Intel Corporation

## Summary

win-message-pump.js is a sophisticated Windows message loop implementation that bridges Windows windowing APIs with JavaScript event-driven programming. It creates hidden or visible windows and processes Windows messages asynchronously, enabling JavaScript applications to integrate deeply with the Windows UI system.

**Implicitly excludes all non-Windows platforms** because:
- Relies entirely on Windows-specific DLLs (User32.dll, Kernel32.dll, Gdi32.dll)
- Windows message loop architecture doesn't exist on other platforms (fundamentally different event systems)
- Uses Windows-specific HWND system, window classes, and message constants
- Window procedure callbacks require Windows calling conventions and DefWindowProc
- No platform check - will fail immediately when trying to load Windows DLLs on macOS/Linux
- No cross-platform equivalent - macOS uses NSRunLoop/NSApplication, Linux uses X11/Wayland event loops
- Intentionally designed for Windows UI integration only

The module is foundational for Windows UI features in the codebase, particularly system tray integration (win-console.js) and custom window creation. Alternative approaches using platform-specific APIs (NSApplication for macOS, X11/GTK+/Qt for Linux) would be required for cross-platform UI functionality.
