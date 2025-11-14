# monitor-border.js

Visual indicator module that draws animated borders around monitors/displays. Used to provide user awareness during remote desktop sessions by displaying a distinctive animated border to indicate active remote control.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via GDI
- Linux - Full support via X11 (with Unity special handling)

**Excluded Platforms:**
- macOS (darwin) - Not implemented
- FreeBSD - Not implemented

**Exclusion Reasoning:**

This module is implemented only for **Windows and Linux** platforms. The module is designed to provide visual feedback during remote KVM (remote desktop) sessions.

**Exclusion reasons for macOS and FreeBSD:**

1. **Different Display APIs:** macOS uses Quartz/Cocoa for graphics, which requires completely different implementation from X11 or GDI.

2. **Lower Priority:** macOS and FreeBSD are less commonly used for remote desktop scenarios where visual borders are critical.

3. **Alternative Indicators:** macOS and FreeBSD could implement similar functionality using platform-specific APIs, but this has not been prioritized.

4. **Platform Check:** The module returns empty implementation for unsupported platforms rather than throwing errors.

On unsupported platforms, the module exports stub functions that do nothing, allowing code to remain platform-agnostic without errors.

## Functionality

### Purpose

The monitor-border module provides a visual indicator that remote desktop (KVM) access is active. It serves important purposes:

- **Security Awareness:** Users see when their screen is being remotely viewed/controlled
- **Transparency:** Provides clear indication of remote access
- **Consent Indicator:** Shows that remote session is ongoing
- **Visual Feedback:** Animated border is hard to miss

The animated border:
- Draws around the perimeter of all monitors
- Uses distinctive colors (red and yellow alternating)
- Animates with "marching ants" effect
- Updates continuously while remote session active
- Automatically cleans up on session end

This module is typically used:
- During KVM remote desktop sessions
- When remote administrator is viewing/controlling screen
- To comply with security/consent requirements
- To provide visual feedback for remote access

### Border Animation

**Animation Pattern:**
The border uses a "marching ants" animation with 8 states that cycle continuously:

```
State 0: ████░░░░████░░░░████░░░░
State 1: ░███░░░░░███░░░░░███░░░░
State 2: ░░██░░░░░░██░░░░░░██░░░░
State 3: ░░░█░░░░░░░█░░░░░░░█░░░░
State 4: ░░░░████░░░░████░░░░████
State 5: ░░░░░███░░░░░███░░░░░███
State 6: ░░░░░░██░░░░░░██░░░░░░██
State 7: ░░░░░░░█░░░░░░░█░░░░░░░█
```

**Colors:**
- **Red:** Primary border color
- **Yellow:** Secondary border color
- Alternates between colors for visibility

**Animation Speed:**
- **Windows:** 450ms interval
- **Linux:** 400ms interval

**Border Width:**
- Typically 4-8 pixels wide
- Visible on all monitor edges

### Key Functions/Methods

#### Start()

**Purpose:** Begins border animation around all monitors.

**Platform Implementations:**

**Windows (Lines vary):**
1. Enumerates all displays using user32.dll
2. Gets display dimensions (width, height, position)
3. Creates device context for each monitor
4. Starts animation timer (450ms interval)
5. Draws border using GDI FillRect
6. Updates animation state each cycle

**Linux (Lines vary):**
1. Detects Unity desktop environment
2. **If Unity:** Creates borderless windows instead of direct drawing
   - Unity compositing interferes with direct X11 drawing
   - Workaround uses windows with border appearance
3. **If not Unity:** Direct X11 drawing via Xlib
4. Gets display dimensions from X11
5. Starts animation timer (400ms interval)
6. Updates border each cycle

**Return Value:** None

**Usage:**
```javascript
var monitorBorder = require('monitor-border');

// Start showing border
monitorBorder.Start();

// Border now animates on all monitors
```

**Platform Behavior:**
- **Windows:** GDI FillRect on each monitor's device context
- **Linux (Unity):** Creates borderless windows
- **Linux (non-Unity):** Direct X11 drawing
- **macOS/FreeBSD:** No-op (does nothing)

---

#### Stop()

**Purpose:** Stops border animation and clears borders.

**Process:**
1. Stops animation timer
2. Clears drawn borders
3. Releases graphics resources
4. Closes windows (Linux Unity)
5. Restores display to normal

**Usage:**
```javascript
monitorBorder.Stop();
// Border cleared from all monitors
```

**Platform Behavior:**
- **Windows:** Releases device contexts, stops timer
- **Linux:** Destroys windows or clears X11 drawing, stops timer
- **macOS/FreeBSD:** No-op

---

### Usage

#### Basic Usage

```javascript
var monitorBorder = require('monitor-border');

// Start remote desktop session
function startRemoteSession() {
    // Show border to indicate remote access
    monitorBorder.Start();

    // ... remote desktop logic ...
}

// End remote desktop session
function endRemoteSession() {
    // Hide border
    monitorBorder.Stop();

    // ... cleanup logic ...
}
```

#### Integration with KVM Module

```javascript
// When KVM session starts
kvmSession.on('start', function() {
    monitorBorder.Start();
    console.log('Remote desktop active - border shown');
});

// When KVM session ends
kvmSession.on('end', function() {
    monitorBorder.Stop();
    console.log('Remote desktop ended - border cleared');
});
```

#### Automatic Cleanup

```javascript
// Module automatically cleans up on process exit
process.on('exit', function() {
    // Border automatically cleared
});

// Or manual cleanup in error handler
try {
    // Remote desktop operations
} catch (error) {
    monitorBorder.Stop();  // Ensure border cleared
    throw error;
}
```

---

### Dependencies

#### Node.js Core Modules

- **`events`** - EventEmitter
  - Purpose: Event-driven architecture
  - Platform support: Cross-platform

#### MeshAgent Module Dependencies

- **`monitor-info`** - Display information
  - Purpose: Enumerate monitors and get dimensions
  - Methods: `getInfo()` returns display array
  - Platform support: Windows, Linux, FreeBSD

- **`_GenericMarshal`** - Native bindings
  - Purpose: Access native graphics APIs
  - **Windows:** Binds to user32.dll, gdi32.dll
  - **Linux:** Binds to X11 libraries (libX11.so, libXext.so)
  - Platform support: Windows, Linux

#### Platform Library Dependencies

**Windows:**
- **user32.dll** - Windows User API
  - Functions: EnumDisplayMonitors, GetDC, ReleaseDC
  - Standard Windows component

- **gdi32.dll** - Graphics Device Interface
  - Functions: CreateSolidBrush, FillRect, DeleteObject
  - Standard Windows component

**Linux:**
- **libX11.so** - X11 client library
  - Functions: XOpenDisplay, XCreateWindow, XFillRectangle
  - Install: `apt install libx11-6` or `yum install libX11`

- **libXext.so** - X11 extensions
  - Additional X11 functionality
  - Install: `apt install libxext6` or `yum install libXext`

#### Dependency Summary

| Platform | Core Deps | MeshAgent Deps | System Libraries |
|----------|-----------|----------------|------------------|
| Windows | events | monitor-info, _GenericMarshal | user32.dll, gdi32.dll |
| Linux | events | monitor-info, _GenericMarshal | libX11.so, libXext.so |
| macOS | events | None (stub implementation) | None |
| FreeBSD | events | None (stub implementation) | None |

---

### Technical Notes

**GDI Drawing (Windows):**

Graphics Device Interface (GDI) is Windows' classic 2D graphics API:
- `CreateSolidBrush`: Creates brush with specific color
- `FillRect`: Fills rectangle with brush
- Device contexts (DC) represent drawing surfaces
- One DC per monitor for multi-monitor support

**X11 Drawing (Linux):**

X Window System provides graphics primitives:
- `XOpenDisplay`: Connects to X server
- `XCreateWindow`: Creates drawing surface
- `XFillRectangle`: Draws filled rectangles
- Handles multiple screens/monitors

**Unity Desktop Workaround (Linux):**

Ubuntu's Unity desktop uses compositing that interferes with direct X11 drawing:
- **Problem:** Direct drawing gets composited incorrectly
- **Solution:** Create borderless windows instead
- **Detection:** Checks for Unity window manager process
- **Result:** Borders appear correctly on Unity

**Animation State Machine:**

The border animation is a simple 8-state machine:
```javascript
state = (state + 1) % 8;  // Cycle through states 0-7
```

Each state shifts the pattern, creating "marching" effect.

**Multi-Monitor Support:**

Both Windows and Linux implementations enumerate all monitors:
- **Windows:** `EnumDisplayMonitors` API
- **Linux:** X11 screen enumeration via `monitor-info`

Border drawn on **all** connected displays simultaneously.

**Resource Management:**

Important to clean up graphics resources:
- **Windows:** Release device contexts, delete brushes
- **Linux:** Close windows, disconnect from X server
- Module adds cleanup handler for process termination

**Performance Considerations:**

Border drawing is lightweight:
- Only redraws border area (not full screen)
- Uses hardware acceleration where available
- ~450ms update interval is smooth without overhead
- Minimal CPU usage (~0.1-1%)

**Z-Order (Layering):**

Border must appear on top of all windows:
- **Windows:** Uses topmost window flag
- **Linux:** Sets window stacking order
- Ensures border always visible

**Color Choice Rationale:**

Red and yellow colors chosen for:
- High visibility against most backgrounds
- Universal warning/attention colors
- Easily distinguishable from normal content
- Accessible for color-blind users (brightness contrast)

## Summary

The monitor-border.js module is a **Windows and Linux visual indicator** for remote desktop sessions, drawing animated borders around all monitors to indicate active remote control.

**Key features:**
- Animated "marching ants" border effect
- 8-state animation cycle
- Red and yellow alternating colors
- Multi-monitor support
- Platform-specific implementations (GDI for Windows, X11 for Linux)
- Unity desktop special handling (Linux)
- Automatic cleanup on termination
- 400-450ms animation interval
- Always-on-top layering

**Platform support:**
- **Windows:** Full support via GDI (user32.dll, gdi32.dll)
- **Linux:** Full support via X11 with Unity workaround
- **macOS/FreeBSD:** Stub implementation (no visual border)

The module is used within MeshAgent to provide visual feedback during KVM remote desktop sessions, ensuring users are aware when their screen is being remotely viewed or controlled. This transparency is important for security, consent, and user awareness in remote administration scenarios.
