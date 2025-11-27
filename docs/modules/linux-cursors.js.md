# linux-cursors.js

Provides cursor theme management and cursor hiding functionality for Linux X11 window systems. Enables applications to temporarily hide the mouse cursor when the user is not actively moving it, useful for fullscreen applications and remote desktop scenarios.

## Platform

**Supported Platforms:**
- Linux - Full support with X11 window system

**Excluded Platforms:**
- **macOS** - Not supported
- **Windows** - Not supported
- **FreeBSD** - Not supported

**Exclusion Reasoning:**

**Line 17-23:** Module checks for X11 and XFixes library availability

macOS and Windows are excluded because:

1. **X11 Window System** - The module requires the X11 window system (Lines 17-18). While X11 can be installed on macOS via XQuartz, it's not the native window system. macOS uses Quartz/Cocoa for window management, which has completely different APIs for cursor control.

2. **XFixes Extension** - Lines 19-23 check for the XFixes extension library (`libXfixes.so.3`). This is a Linux-specific X11 extension library not available on macOS or Windows.

3. **Native Cursor APIs** - Each platform has its own cursor management:
   - **macOS** uses `CGDisplayHideCursor()` and `CGDisplayShowCursor()` from CoreGraphics framework
   - **Windows** uses `ShowCursor()` from User32.dll
   - **Linux X11** uses `XFixesHideCursor()` and `XFixesShowCursor()` from XFixes extension

4. **Library Linking** - Lines 28-49 use dynamic library loading to link against X11 libraries (`libX11.so.6`, `libXfixes.so.3`) which don't exist on macOS or Windows.

## Functionality

### Core Purpose

Provides automatic cursor hiding for Linux X11 applications based on mouse movement detection. The cursor reappears when the mouse moves and automatically hides after a configurable timeout period.

### Cursor Hiding Mechanism (Lines 58-88)

**Automatic Hide Timer:**
- Default timeout: 5000ms (5 seconds) of inactivity
- Configurable via `options.hideTimeout` parameter
- Timer resets on any mouse movement

**Implementation:**
1. Monitors mouse movement events from X11
2. Shows cursor on any movement
3. Starts countdown timer
4. Hides cursor after timeout expires
5. Repeats cycle on next movement

### API Methods

#### hideCursor() - Line 69-76

```javascript
this.hideCursor = function hideCursor() {
    if (!this.cursorHidden) {
        this._XFixesHideCursor(this._display, this._rootWindow).Val;
        this.cursorHidden = true;
    }
};
```

**Purpose:** Immediately hide the mouse cursor

**Behavior:**
- Calls `XFixesHideCursor()` on X11 root window
- Sets `cursorHidden` flag to prevent duplicate calls
- Idempotent - safe to call multiple times

---

#### showCursor() - Line 77-84

```javascript
this.showCursor = function showCursor() {
    if (this.cursorHidden) {
        this._XFixesShowCursor(this._display, this._rootWindow).Val;
        this.cursorHidden = false;
    }
};
```

**Purpose:** Immediately show the mouse cursor

**Behavior:**
- Calls `XFixesShowCursor()` on X11 root window
- Clears `cursorHidden` flag
- Idempotent - safe to call multiple times

---

#### setCursorHiding(enabled) - Line 85-88

```javascript
this.setCursorHiding = function setCursorHiding(enabled) {
    this.hidingEnabled = enabled;
};
```

**Purpose:** Enable or disable automatic cursor hiding

**Parameters:**
- `enabled` (boolean) - `true` to enable auto-hide, `false` to disable

**Use Case:** Temporarily disable cursor hiding without destroying the cursor manager

### X11 Integration (Lines 28-56)

**Display Connection:**
- Line 52: Opens connection to X11 display server
- Line 53: Retrieves root window handle
- Connection remains open for lifetime of module

**XFixes Extension Initialization:**
- Lines 54-56: Queries XFixes extension version
- Ensures XFixes is available on the X11 server
- Required for cursor show/hide functionality

**Library Loading:**
Lines 28-49 dynamically load X11 libraries and create function bindings:

```javascript
this._marshal = require('_GenericMarshal');
this._X11 = this._marshal.CreateNativeProxy('libX11.so.6');
this._XFixes = this._marshal.CreateNativeProxy('libXfixes.so.3');
```

### Usage Example

```javascript
var cursors = require('linux-cursors');

// Create cursor manager with 3 second timeout
var cursorMgr = new cursors({ hideTimeout: 3000 });

// Cursor will now automatically hide after 3 seconds of inactivity

// Manually hide cursor immediately
cursorMgr.hideCursor();

// Manually show cursor
cursorMgr.showCursor();

// Disable automatic hiding
cursorMgr.setCursorHiding(false);

// Re-enable automatic hiding
cursorMgr.setCursorHiding(true);
```

## Dependencies

### Native Module Dependencies

#### _GenericMarshal (Line 28)

```javascript
this._marshal = require('_GenericMarshal');
```

**Purpose:** Foreign Function Interface (FFI) library for calling native X11 libraries

**Usage:**
- Creates native proxy objects for X11 libraries
- Marshals JavaScript types to C types
- Handles pointer arithmetic and structure packing
- Enables calling C functions from JavaScript

**Source:** `/microscript/ILibDuktape_GenericMarshal.c`

---

#### linux-cursor-theme (Line 11)

```javascript
var cursorTheme = require('linux-cursor-theme');
```

**Purpose:** Linux cursor theme loading and management

**Usage:** Imported but not actively used in the cursor hiding implementation. Likely intended for future cursor theme customization features.

**Status:** Dead code - imported but never referenced

### Platform Binary Dependencies

#### libX11.so.6 (Lines 29-40) - X11 Core Library

**Purpose:** Core X11 window system library

**Functions Used:**
- `XOpenDisplay()` (Line 30) - Opens connection to X11 display server
  - Returns display pointer for all subsequent X11 calls
- `XDefaultRootWindow()` (Line 33) - Retrieves root window handle
  - Root window represents entire screen area
- `XFlush()` (Line 36) - Flushes pending X11 requests
  - Ensures commands are sent to server immediately

**Package:** `libx11-6` (Debian/Ubuntu), `libX11` (Red Hat/Fedora)

---

#### libXfixes.so.3 (Lines 41-49) - X11 Fixes Extension

**Purpose:** X11 extension providing cursor control and other fixes

**Functions Used:**
- `XFixesQueryVersion()` (Line 42) - Query XFixes extension version
  - Verifies XFixes is available and supported
- `XFixesHideCursor()` (Line 45) - Hide cursor on specified window
  - Used in `hideCursor()` method (Line 71)
- `XFixesShowCursor()` (Line 48) - Show cursor on specified window
  - Used in `showCursor()` method (Line 79)

**Package:** `libxfixes3` (Debian/Ubuntu), `libXfixes` (Red Hat/Fedora)

**Version Check:** Lines 54-56 ensure XFixes version 4.0+ is available

### Dependency Chain

```
linux-cursors.js
├─── _GenericMarshal (Line 28) - FFI library
│    └─── Native marshaling layer
├─── linux-cursor-theme (Line 11) - Theme management (unused)
├─── libX11.so.6 (Lines 29-40) - X11 core
│    ├─── XOpenDisplay() - Display connection
│    ├─── XDefaultRootWindow() - Root window handle
│    └─── XFlush() - Request flushing
└─── libXfixes.so.3 (Lines 41-49) - XFixes extension
     ├─── XFixesQueryVersion() - Version check
     ├─── XFixesHideCursor() - Hide cursor
     └─── XFixesShowCursor() - Show cursor
```

### Installation Requirements

**X11 Development Libraries:**
```bash
# Debian/Ubuntu
sudo apt-get install libx11-6 libxfixes3

# Red Hat/Fedora
sudo yum install libX11 libXfixes

# Arch Linux
sudo pacman -S libx11 libxfixes
```

**X11 Server Required:**
- Must have X11 display server running
- Wayland systems may need XWayland compatibility layer
- Won't work in console-only environments

## Technical Notes

### Platform Detection (Lines 17-23)

The module performs a multi-step check before activating:

1. **X11 Display Check** (Line 17):
   ```javascript
   if (process.env['DISPLAY'])
   ```
   - Verifies `DISPLAY` environment variable is set
   - Indicates X11 is available

2. **Module Availability Check** (Line 18):
   ```javascript
   try { require('linux-cursor-theme'); }
   ```
   - Confirms cursor theme module exists
   - Silent failure if not available

3. **XFixes Library Check** (Lines 19-23):
   ```javascript
   require('fs').readdirSync('/usr/lib/x86_64-linux-gnu').filter(function (i) {
       return (i.startsWith('libXfixes') && i.endsWith('.so.3'));
   })
   ```
   - Searches for `libXfixes.so.3` in system library directory
   - Only proceeds if XFixes library found

**Result:** Module only exports functionality if all checks pass

### Timer Management

**Auto-Hide Timer:**
- Implemented using JavaScript `setTimeout()`
- Timer cleared on every mouse movement
- New timer started after showing cursor
- Prevents cursor flicker from rapid movements

**Memory Management:**
- Timer reference stored in `this.timeout`
- Properly cleared before setting new timer
- Prevents timer leaks

### Thread Safety

**X11 Connection:**
- Single X11 display connection shared across calls
- Not thread-safe - assumes single-threaded JavaScript
- X11 calls should not be made concurrently

### Performance Considerations

- Minimal CPU usage - event-driven model
- No polling - reacts to X11 movement events
- Cursor show/hide calls are lightweight X11 operations
- Suitable for long-running applications

### Limitations

- Requires X11 - won't work with Wayland without XWayland
- Assumes standard library paths (`/usr/lib/x86_64-linux-gnu`)
- No multi-display support documented
- Cursor theme loading imported but not implemented

## Summary

The linux-cursors.js module provides automatic cursor hiding for Linux X11 applications through the XFixes extension. It monitors mouse movement and automatically hides the cursor after a configurable timeout period, useful for fullscreen applications, kiosks, and remote desktop scenarios.

**macOS is excluded** because:
- Requires X11 window system and XFixes extension (Lines 17-23, 28-49)
- Depends on Linux-specific shared libraries (`libX11.so.6`, `libXfixes.so.3`)
- macOS uses Quartz/Cocoa with different cursor management APIs (CGDisplayHideCursor/ShowCursor)
- X11 is not the native window system on macOS (XQuartz is optional third-party software)
- Module explicitly checks for X11 environment and Linux library paths

Alternative cursor management would require platform-specific implementation using macOS CoreGraphics framework.
