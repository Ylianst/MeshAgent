# win-terminal.js

Provides Windows console terminal emulation with VT100 escape sequence support. Implements console input/output redirection, window event hooking for screen updates, and duplex stream interface for remote terminal access.

## Platform

**Supported Platforms:**
- Windows (all versions) - Full support

**Excluded Platforms:**
- **macOS** - Not supported (Windows-only)
- **Linux** - Not supported (Windows-only)
- **FreeBSD** - Not supported (Windows-only)

**Exclusion Reasoning:**

Windows-specific module requiring Windows APIs/DLLs unavailable on other platforms.

**Platform Notes:**

**win-terminal.js is Windows-only** because:

1. **Windows Console API** - User32.dll and Kernel32.dll specific functions
2. **WinEventHook** - Windows event notification system
3. **Console Screen Buffer** - Windows-specific console model
4. **Message Pump** - Windows message queue processing

---

## Functionality

### Core Purpose

win-terminal.js provides console terminal access:

1. **Console Initialization** - Allocate/setup console
2. **Screen Buffering** - Read/write console buffer
3. **Input Injection** - Send keystrokes to console
4. **Event Notification** - Monitor console changes
5. **VT100 Emulation** - Convert console output to escape sequences

### Main Operations

1. **Terminal Start** - Start(), StartPowerShell(), StartEx()
2. **Buffer Operations** - ClearScreen(), SendCursorUpdate()
3. **Input/Output** - _WriteBuffer(), _GetScreenBuffer()

---

## Constants - Lines 20-37

```javascript
SW_HIDE (0), SW_MINIMIZE (6)              // Window display
STARTF_USESHOWWINDOW (0x1)                // Startup flags
STD_INPUT_HANDLE (-10)                    // Standard input
STD_OUTPUT_HANDLE (-11)                   // Standard output
EVENT_CONSOLE_CARET (0x4001)              // Console events
EVENT_CONSOLE_UPDATE_* (0x4002-0x4004)    // Screen updates
EVENT_CONSOLE_START/END_APPLICATION       // Process events
KEY_EVENT (0x1)                           // Keyboard input
MAPVK_VK_TO_VSC (0)                       // Key code mapping
```

---

## Core Methods

### Start(width, height) / StartPowerShell(width, height) - Lines 290-311

**Purpose:** Start terminal with cmd.exe or PowerShell

**Parameters:**
- width - Console width (defaults to 80)
- height - Console height (defaults to 25)

**Returns:** Duplex stream for terminal I/O

**Process:**
1. Allocates console if needed
2. Sets buffer size and window
3. Sets up event hooking
4. Starts shell process (cmd.exe or powershell.exe)
5. Returns stream for terminal communication

---

### StartEx(width, height, terminalTarget) - Lines 178-289

**Purpose:** Start terminal with custom executable

**Parameters:**
- terminalTarget - Full path to executable (e.g., cmd.exe path)

**Returns:** Duplex stream

---

### ClearScreen() - Lines 104-162

**Purpose:** Clear console and reset cursor

**Implementation:**
1. Gets console buffer info
2. Fills entire buffer with spaces
3. Sets text attributes
4. Moves cursor to home (0,0)
5. Adjusts window info

---

### _GetScreenBuffer(sx, sy, ex, ey) - Lines 549-622

**Purpose:** Read console screen buffer region

**Parameters:**
- sx, sy - Start coordinates
- ex, ey - End coordinates

**Returns:** Object with:
```javascript
{
    data: [lines],       // Character buffers per line
    attributes: [attrs], // Color attributes per line
    width: w,
    height: h,
    x: sx,
    y: sy
}
```

---

### _WriteBuffer(buf) - Lines 507-519

**Purpose:** Send input to console

**Parameters:**
- buf - String or Buffer to write

**Process:**
- For each character, calls _WriteCharacter()

---

### _WriteCharacter(key, bControlKey) - Lines 520-546

**Purpose:** Send single keystroke to console

**Implementation:**
- Creates INPUT_RECORD with KEY_EVENT
- Sets key code and repeat count
- Calls WriteConsoleInput()

---

## Event Hooking

### _hookThread() - Lines 329-437

**Purpose:** Set up Windows event hook for console monitoring

**Implementation:**
1. Calls SetWinEventHook() for console events (line 344)
2. Sets up callback for EVENT_CONSOLE_CARET through EVENT_CONSOLE_END_APPLICATION
3. Registers _GetMessage() loop
4. Handles event types:
   - EVENT_CONSOLE_UPDATE_REGION - Screen change
   - EVENT_CONSOLE_UPDATE_SIMPLE - Single character change
   - EVENT_CONSOLE_UPDATE_SCROLL - Scroll event
   - EVENT_CONSOLE_END_APPLICATION - Process exit

---

### _GetMessage() - Lines 440-505

**Purpose:** Process Windows messages

**Implementation:**
- GetMessageA() gets next message
- TranslateMessage() for keyboard events
- DispatchMessageA() routes to handler
- Continues until WM_QUIT received

---

## VT100 Emulation

### TranslateLine(x, y, data, attributes) - Lines 689-719

**Purpose:** Convert console buffer to VT100 escape sequences

**Implementation:**
1. Generates cursor positioning: ESC[{y};{x}H
2. For each character:
   - Checks attribute changes
   - Generates color codes (30-37 for foreground, 40-47 for background)
   - Handles bright text (1 for bright, 2 for dim)
   - Generates SGR (Select Graphic Rendition) sequences
3. Returns buffer with escape sequences

**Color Mapping:**
- Converts console attributes to ANSI colors
- Supports bright foreground/background
- Reverse video support

---

## Dependencies

### Native DLLs - Lines 39, 51, 63

**User32.dll** (line 51)
- DispatchMessageA() - Dispatch Windows message
- GetMessageA() - Get window message
- MapVirtualKeyA() - Convert virtual key codes
- PostThreadMessageA() - Post message to thread
- SetWinEventHook() - Hook Windows event
- ShowWindow() - Show/hide window
- TranslateMessage() - Translate virtual key message
- UnhookWinEvent() - Remove event hook
- VkKeyScanA() - Virtual key to scan code

**Kernel32.dll** (line 63)
- AllocConsole() - Allocate console
- CreateProcessA() - Create process
- CloseHandle() - Close handle
- FillConsoleOutput* - Fill console buffer
- GetConsoleScreenBufferInfo() - Get buffer info
- GetConsoleWindow() - Get console window
- GetLastError() - Get error code
- GetStdHandle() - Get standard handle
- ReadConsoleOutputA() - Read console buffer
- SetConsole* - Set console properties
- TerminateProcess() - End process
- WriteConsoleInputA() - Send input

### Module Dependencies

**require('promise')**
- Promise for async operations

**require('stream').Duplex**
- Stream interface for terminal

---

## Usage Examples

### Create Terminal Stream

```javascript
var terminal = require('win-terminal');
var stream = terminal.Start(80, 25);
stream.write('dir\r\n');
stream.on('data', function(chunk) {
    console.log('Terminal:', chunk);
});
```

### Start PowerShell Terminal

```javascript
var terminal = require('win-terminal');
var stream = terminal.StartPowerShell(120, 40);
```

---

## Technical Notes

### Console Model

- Standard input (stdin) - Keyboard input
- Standard output (stdout) - Screen buffer
- Separate handles for read/write

### Event Hooking

- SetWinEventHook() monitors console events
- Callback fired on screen changes
- GetMessage() loop keeps event processing active
- Proper cleanup via UnhookWinEvent()

### Screen Buffer Format

- Each character has:
  - ASCII/Unicode value
  - Foreground color (3 bits)
  - Background color (3 bits)
  - Bright flag
  - Reverse video flag

---

## Summary

win-terminal.js provides comprehensive Windows console terminal emulation with VT100 escape sequence output. The module handles console initialization, screen buffer management, input injection, and real-time event monitoring. Duplex stream interface enables seamless remote terminal access with proper console cleanup and resource management.
