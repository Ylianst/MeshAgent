# clipboard.js

Cross-platform clipboard access module providing unified read/write API for text clipboard operations with support for both local and remote clipboard access via session redirection. Enables clipboard sharing and manipulation across user sessions for remote administration and multi-user environments.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support using Win32 API (CF_UNICODETEXT format)
- Linux - Full support with dual-mode: X11 native protocol or xclip binary
- macOS (darwin) - Full support using message-box module integration (pbcopy/pbpaste)
- FreeBSD - Requires xclip binary installation at `/usr/local/bin/xclip`

**Excluded Platforms:**
- None - All major platforms supported

## Functionality

### Purpose

The clipboard module provides cross-platform clipboard operations for:

- Reading text from system clipboard
- Writing text to system clipboard
- Session-specific clipboard access (multi-user support)
- Remote clipboard synchronization
- User session isolation

This module is critical for:
- Remote desktop clipboard sharing
- Multi-user session clipboard access
- Administrative clipboard operations
- Terminal/console clipboard integration
- Automated clipboard manipulation

### Key Functions

#### write(text) / module.exports(text) - Clipboard Write

**Purpose:** Writes text to system clipboard.

**Windows Implementation - win_copytext() (Lines 593-623):**
```javascript
// Allocate global memory
GlobalAlloc(GMEM_MOVEABLE, size);
// Lock memory
ptr = GlobalLock(hMem);
// Convert to UTF-16LE
buffer.StringToWideStr(text, ptr);
// Open clipboard
OpenClipboard(NULL);
// Clear and set
EmptyClipboard();
SetClipboardData(CF_UNICODETEXT, hMem);
// Close
CloseClipboard();
```

**Linux Implementation - lin_copytext() (Lines 455-547):**
- **With xclip** (line 464): Spawns `xclip -selection c`, pipes text, maintains ownership
- **Without xclip** (lines 465-547):
  - Creates fake X11 window
  - XSetSelectionOwner for CLIPBOARD and PRIMARY
  - Listens for SelectionRequest events
  - Responds with UTF8_STRING via XChangeProperty
  - Maintains DescriptorEvent for X11 connection

**macOS Implementation - macos_copytext() (Line 624):**
```javascript
require('message-box').setClipboard(clipText);
```
- Delegates to message-box module
- Uses pbcopy or native AppKit APIs

**FreeBSD Implementation (Lines 660-670):**
- Requires `/usr/local/bin/xclip`
- Throws error if not installed
- Uses xclip-based implementation

---

#### read() / module.exports.read() - Clipboard Read

**Purpose:** Reads text from system clipboard, returns promise.

**Windows Implementation - win_readtext() (Lines 549-591):**
```javascript
// Open clipboard
OpenClipboard(NULL);
// Check format
IsClipboardFormatAvailable(CF_UNICODETEXT);
// Get data handle
hMem = GetClipboardData(CF_UNICODETEXT);
// Lock and read
ptr = GlobalLock(hMem);
text = buffer.Wide2UTF8(ptr);
// Unlock and close
GlobalUnlock(hMem);
CloseClipboard();
return promise.resolve(text);
```

**Linux Implementation - lin_readtext() (Lines 285-364):**
- **With xclip** (lines 289-319): Spawns `xclip -selection c -o`, captures stdout
- **Without xclip** (lines 321-364):
  - Creates fake window
  - XConvertSelection CLIPBOARD → UTF8_STRING
  - Waits for SelectionNotify event
  - XGetWindowProperty to retrieve data
  - Returns promise

**macOS Implementation - macos_readtext() (Line 628):**
```javascript
return require('message-box').getClipboard();
```

---

#### dispatchRead(sid) / dispatchWrite(data, sid) - Session-Specific Access (Lines 121-243)

**Purpose:** Access clipboard in specific user session (multi-user environments).

**Process:**
1. **Session 0 or darwin/freebsd** (line 131): Direct access, no redirection
2. **Other sessions** (lines 133-240):
   - Uses ScriptContainer to spawn process in target session
   - Injects clipboard module code
   - Executes read/write in user's session
   - Returns result via IPC

**Session Isolation:**
- Windows: Different users have different clipboards
- Linux X11: XAUTHORITY and DISPLAY per session
- macOS: Per-user clipboard

---

### Platform-Specific Implementations

#### Windows - Win32 API (Lines 549-623)

**CF_UNICODETEXT Format:**
- UTF-16LE encoding
- Wide character strings
- Global memory allocation
- Clipboard lock/unlock mechanism

**Functions Used:**
- `GlobalAlloc(GMEM_MOVEABLE, size)`
- `GlobalLock(hMem)` / `GlobalUnlock(hMem)`
- `OpenClipboard(NULL)` / `CloseClipboard()`
- `EmptyClipboard()`
- `SetClipboardData(CF_UNICODETEXT, hMem)`
- `GetClipboardData(CF_UNICODETEXT)`
- `IsClipboardFormatAvailable(CF_UNICODETEXT)`

---

#### Linux - X11/xclip Dual Mode (Lines 245-547)

**xclip Mode (Preferred):**
- Binary: `/usr/bin/xclip` or detected via `whereis`
- **Write:** `xclip -selection c` (stdin pipe)
- **Read:** `xclip -selection c -o` (stdout capture)
- **Process Management:** xclip persists to maintain ownership

**X11 Native Mode (Fallback):**
- Direct X11 protocol via libX11.so
- SelectionRequest/SelectionNotify protocol
- UTF8_STRING data type
- Fake window for selection ownership

**xclip Lifecycle:**
- Spawns persistent process
- 20-second timeout after exit (line 437-440)
- SIGKILL cleanup (line 440)
- Tracks PIDs via `_helper()` function

---

#### macOS - message-box Integration (Lines 624-631)

**Delegation:**
```javascript
module.exports = function(text) {
  return require('message-box').setClipboard(text);
};

module.exports.read = function() {
  return require('message-box').getClipboard();
};
```

**Implementation Details (in message-box):**
- **pbcopy/pbpaste:** Shell command execution
- **Or AppKit:** Native Cocoa clipboard APIs
- Returns promises for consistency

---

#### FreeBSD - xclip Required (Lines 660-670)

**Detection:**
```javascript
if (!require('fs').existsSync('/usr/local/bin/xclip')) {
  throw ('xclip is not installed');
}
```

**Requirement:**
- Must install xclip package
- Uses same xclip-based logic as Linux
- No native X11 fallback

---

### Dependencies

#### Node.js Core Modules
- **`child_process`** - xclip process spawning (Linux/FreeBSD)
- **`fs`** (line 661) - File operations for clipboard persistence

#### MeshAgent Module Dependencies

**Required on All Platforms:**
- **`promise`** - Custom promise implementation
  - Used for async read operations

**Windows-Specific:**
- **`_GenericMarshal`** (lines 551, 595) - Win32 API access
  - Libraries: `user32.dll`, `kernel32.dll`
  - Functions: OpenClipboard, GetClipboardData, SetClipboardData, GlobalAlloc, etc.

**Linux-Specific:**
- **`monitor-info`** (line 147) - X11 library access
  - Methods: `getXInfo()` → XAUTHORITY, DISPLAY
  - Properties: X11 shared library handle

**macOS-Specific:**
- **`message-box`** (lines 624, 628) - Native clipboard implementation
  - Methods: `setClipboard(text)`, `getClipboard()`

**Cross-Platform:**
- **`ScriptContainer`** (line 189) - Session redirection
  - Used for multi-user clipboard access

- **`user-sessions`** (line 186) - Console UID detection
  - Method: `consoleUid()`

- **`compressed-stream`** (line 119) - Module compression
  - Used for build system integration

- **`DescriptorEvents`** (lines 332, 487) - Event-driven descriptor management
  - Used for monitoring clipboard file descriptor states

#### External Dependencies

**Linux:**
- **libX11.so** - X Window System library (optional, for native mode)
- **xclip** - Clipboard utility (optional, `/usr/bin/xclip`)

**FreeBSD:**
- **xclip** - Required, `/usr/local/bin/xclip`

**macOS:**
- **pbcopy/pbpaste** - macOS clipboard commands (via message-box)
- **Or AppKit** - Native Cocoa APIs (via message-box)

### Usage

#### Basic Write

```javascript
require('clipboard')('Hello, clipboard!');

// Or explicitly
require('clipboard').write('Text to clipboard');
```

#### Basic Read

```javascript
require('clipboard').read().then(function(text) {
  console.log('Clipboard:', text);
});
```

#### Session-Specific Access

```javascript
// Write to specific session
require('clipboard').dispatchWrite('Hello', sessionId).then(function() {
  console.log('Written to session', sessionId);
});

// Read from specific session
require('clipboard').dispatchRead(sessionId).then(function(text) {
  console.log('Session clipboard:', text);
});
```

#### Error Handling

```javascript
require('clipboard').read().then(function(text) {
  console.log('Success:', text);
}).catch(function(err) {
  console.log('Clipboard read failed:', err);
});
```

### Technical Notes

**Windows CF_UNICODETEXT:**
- UTF-16LE encoding (2 bytes per character)
- Null-terminated wide strings
- Global memory handle ownership transfer
- Clipboard serializes access (only one process at a time)

**Linux Selection Types:**
- **CLIPBOARD:** Standard clipboard (Ctrl+C/Ctrl+V)
- **PRIMARY:** X11 primary selection (middle-click paste)
- **SECONDARY:** Rarely used

**xclip Process Lifecycle:**
- Spawns and persists to maintain selection ownership
- If xclip exits early, selection lost
- 20-second grace period before SIGKILL
- Tracks multiple xclip instances via PID table

**X11 Selection Protocol:**
1. Owner calls XSetSelectionOwner (claim ownership)
2. Requestor calls XConvertSelection (request data)
3. Owner receives SelectionRequest event
4. Owner calls XChangeProperty (provide data)
5. Owner sends SelectionNotify to requestor
6. Requestor calls XGetWindowProperty (retrieve data)

**Session Redirection Requirements:**
- **XAUTHORITY:** X11 authentication cookie file path
- **DISPLAY:** X server address (`:0`, `:1`, etc.)
- **Session ID:** For user-sessions module

**macOS vs pbcopy/pbpaste:**
- **pbcopy:** Shell command, simple but slow
- **AppKit:** Native API, faster, more reliable
- message-box module chooses best method

**Promise-Based API:**
- Read operations async (may require IPC or process spawn)
- Write operations sync on Windows, async on Linux (xclip spawn)
- Consistent promise API across platforms

### Platform-Specific Analysis

**What Works on macOS:**
- Full read/write functionality
- Local clipboard access
- Session redirection (via ScriptContainer)
- Promise-based async API

**macOS-Specific Behavior:**
- Delegates to message-box module
- No direct X11 or Win32 code
- Uses pbcopy/pbpaste or AppKit
- Per-user clipboard (no selection types)

**Platform Differences:**

**Windows:**
- CF_UNICODETEXT format (UTF-16LE)
- Global memory handles
- Synchronous operations
- Per-user clipboard

**Linux:**
- UTF8_STRING format (UTF-8)
- Dual mode: xclip or X11 native
- CLIPBOARD and PRIMARY selections
- Per-session clipboard (XAUTHORITY/DISPLAY)

**macOS:**
- UTF-8 format
- Single clipboard (no PRIMARY)
- message-box delegation
- Per-user clipboard

**FreeBSD:**
- Same as Linux but requires xclip
- No X11 native fallback
- Must install xclip package

**Use Cases:**

**Remote Desktop Clipboard Sync:**
```javascript
// Copy from remote to local
remoteClipboard.dispatchRead(remoteSessionId).then(function(text) {
  require('clipboard')(text);  // Write to local
});
```

**Automated Copy/Paste:**
```javascript
// Read file, copy to clipboard
var fs = require('fs');
var content = fs.readFileSync('/path/file', 'utf8');
require('clipboard')(content);
```

**Multi-User Administration:**
```javascript
// Copy to all active user sessions
var sessions = require('user-sessions').enumerateUsers();
sessions.forEach(function(session) {
  require('clipboard').dispatchWrite('Message', session.uid);
});
```

## Summary

The clipboard.js module provides cross-platform text clipboard access for MeshAgent across Windows, Linux, macOS, and FreeBSD. It supports both local operations and session-specific access for multi-user environments with platform-optimized implementations.

**Key capabilities:**
- Cross-platform read/write text clipboard
- Session-specific clipboard access (multi-user)
- Windows: Win32 API with CF_UNICODETEXT
- Linux: Dual-mode (xclip or X11 native)
- macOS: message-box integration (pbcopy/AppKit)
- Promise-based async API

**macOS support:**
- Full support via message-box delegation
- Uses pbcopy/pbpaste or native AppKit APIs
- Per-user clipboard access
- Session redirection supported

**Critical dependencies:**
- `_GenericMarshal` (Windows) for Win32 API
- `monitor-info` (Linux) for X11 access
- `message-box` (macOS) for native clipboard
- `ScriptContainer` for session redirection

The module enables critical remote desktop features like clipboard sharing and multi-user clipboard management while abstracting platform differences behind a unified API.
