# notifybar-desktop.js

Visual notification bar component for MeshAgent remote desktop sessions that displays a dismissible banner at the top of the screen to indicate an active remote connection. Provides platform-specific implementations for Windows (sophisticated draggable/pinnable bar), Linux/FreeBSD (X11-based bar), and macOS (message-box fallback).

## Platform

**Supported Platforms:**
- Windows (win32) - Full support with rich UI features (draggable, pinnable, minimizable)
- Linux - Full support with X11 integration
- FreeBSD - Full support with X11 integration
- **macOS (darwin)** - Limited support (fallback to modal message-box dialog)

**Excluded Platforms:**
- None

**Platform-Specific Notes:**

**macOS Implementation:**
- **Degraded/Fallback Support** - macOS uses a simple modal dialog via the `message-box` module instead of a native notification bar (lines 662-672, 686-688)
- **Limited Functionality** - No dragging, pinning, minimizing, multi-monitor support, or custom positioning
- **Modal Behavior** - Dialog blocks user interaction until dismissed (unlike non-modal notification bars on Windows/Linux)
- **Adequate for Purpose** - While less sophisticated, it fulfills the core requirement of notifying users about active remote sessions
- **Technical Reason** - No native Cocoa/AppKit window implementation; would require substantial macOS-specific development

## Functionality

### Purpose

The notifybar-desktop module creates a visual notification bar that appears during remote desktop (KVM) sessions to inform the user that their desktop is being remotely accessed. This serves several critical purposes:

- **User Awareness:** Provides clear visual indication of active remote sessions
- **Security:** Ensures users are aware when someone is viewing/controlling their desktop
- **Transparency:** Meets security compliance requirements for remote access disclosure
- **Session Control:** Allows users to disconnect unwanted remote sessions

This module is invoked automatically by the MeshAgent when:
- A remote KVM (desktop sharing) session is initiated
- An administrator connects to view or control the user's desktop
- Remote assistance is provided to the user

### Platform-Specific Implementations

#### Windows Implementation - Lines 203-467

**Function:** `windows_notifybar_check()` (lines 203-213)
- Detects if running as SYSTEM (tsid 0) or user session
- Routes to appropriate implementation based on session context

**System Mode:** `windows_notifybar_system()` (lines 214-233)
- Used when agent runs as SYSTEM service
- Spawns child process in user's session (specified by tsid)
- Passes configuration via base64-encoded script
- Returns EventEmitter with `close` event and method

**Local Mode:** `windows_notifybar_local()` (lines 235-467)
- Primary implementation for user-space notification bar
- Creates sophisticated draggable, pinnable notification UI

**Key Features:**
1. **Multi-Monitor Support** (lines 261-299)
   - Enumerates all displays using `monitor-info` module
   - Creates separate bar for each monitor
   - Calculates optimal width (30% of screen or 9× DPI, max 45%)
   - Centers bar horizontally on each display
   - Positions at top of screen (y = monitor.top)

2. **Visual Customization** (lines 240-243)
   - Configurable foreground color (default: RGB(200,200,200) light gray)
   - Configurable background color (default: RGB(0,54,105) dark blue)
   - Accepts string format "R,G,B" or numeric RGB values
   - Uses GDI+ for high-quality rendering

3. **Interactive Controls** (lines 313-365)
   - **Close Button** (lines 313-326): X icon at right side, closes session
   - **Pin Button** (lines 327-353): Toggle between pinned/unpinned states
   - **Title Label** (lines 354-365): Displays session title with text ellipsis

4. **Pin/Unpin Behavior** (lines 398-412)
   - **Pinned Mode:** Bar stays fully visible, no auto-hide
   - **Unpinned Mode:** Auto-minimizes after 3 seconds of inactivity
   - Visual feedback via icon change (pin_icon_1 vs pin_icon_2)
   - Default state: Pinned (`module.exports.DefaultPinned = true`)

5. **Auto-Hide Mechanism** (lines 381-387, 448-460)
   - When unpinned, timer starts after 3 seconds
   - Minimizes to thin strip (height × 0.125)
   - Expands on mouse movement
   - Timer resets on each interaction

6. **Drag Functionality** (lines 415-420, 429-446)
   - Click and drag to reposition bar
   - Constrained to monitor boundaries (cannot drag off screen)
   - Locked to Y-axis (top of screen only)
   - Uses WM_NCLBUTTONDOWN for native window dragging

7. **Message Pump Integration** (lines 245-246, 292-462)
   - Uses `win-message-pump` module for window management
   - Processes Windows messages: WM_COMMAND, WM_LBUTTONDOWN, WM_MOUSEMOVE, etc.
   - Handles WM_WINDOWPOSCHANGING to enforce position constraints
   - Manages WM_CTLCOLORSTATIC for custom control colors

**Technical Implementation:**
- Creates popup window with WS_POPUP | WS_BORDER styles
- Uses GDI+ for image scaling (x_icon, pin icons)
- Implements proper resource cleanup on exit
- Synchronizes state across multiple monitors

---

#### Linux/FreeBSD Implementation - Lines 470-660

**Function:** `x_notifybar_check()` (lines 470-554)
- Detects if running as root or user
- Handles session dispatching for multi-user systems

**Dispatch Logic:**
- If running as user OR uid=0: Direct creation via `x_notifybar()`
- If running as root AND console user is logged out: Waits for login, then spawns
- If running as root AND console user exists: Spawns child process in user's X session

**Main Implementation:** `x_notifybar()` (lines 556-660)

**Key Features:**
1. **X11 Integration** (lines 578-601)
   - Creates X11 simple window using XCreateSimpleWindow
   - White background, minimal border
   - Window title set via XStoreName and Xutf8SetWMProperties
   - Proper ICCCM compliance

2. **Multi-Monitor Support** (lines 567-628)
   - Enumerates displays via `monitor-info` module
   - Creates separate window for each monitor
   - Calculates 30% width, 3.5% height of screen
   - Centers horizontally at top of each display

3. **Window Properties** (lines 588-592)
   - Size hints set to make window non-resizable
   - Window icon hidden (hideWindowIcon)
   - Allowed actions: Close only
   - Always on top (setAlwaysOnTop)

4. **Multi-Workspace Support** (lines 636-656)
   - Detects current workspace on startup
   - Listens for workspace changes
   - Automatically creates bars in newly visited workspaces
   - Tracks created workspaces to avoid duplicates

5. **Event Handling** (lines 603-626)
   - Uses DescriptorEvents for X11 connection monitoring
   - Processes ClientMessage events
   - Detects WM_DELETE_WINDOW (close button click)
   - Properly cleans up X resources on close

**Technical Limitations:**
- Simple bar UI (no drag, pin, minimize features)
- White background only (no customization)
- Height fixed at 1 pixel initially (appears as thin line)
- Relies on X11 (no Wayland support indicated)

---

#### macOS Implementation - Lines 662-672, 686-688

**Function:** `macos_messagebox()` (lines 662-672)

**Implementation Details:**
- Uses `message-box` module to create simple dialog
- Title passed as caption, no message text
- Single "Disconnect" button
- Modal behavior (blocks until dismissed)
- Returns EventEmitter with `close` event and method

**Why Different:**
- No native window creation code for macOS
- No Cocoa/AppKit integration
- No multi-monitor support
- No customization options
- No dragging, pinning, or minimizing

**User Experience:**
- User sees modal dialog box instead of notification bar
- Must click "Disconnect" to close (no X button)
- Cannot reposition or minimize
- Blocks other interactions (modal)

---

### Color Handling

**RGB Functions** (lines 134-151):
- `RGB(r, g, b)`: Converts RGB components to Windows COLORREF format
- `string_RGB(s)`: Parses "R,G,B" string format, defaults to RGB(0,54,105)
- `gdip_RGB(r, g, b)`: Converts between Windows and GDI+ color formats (byte order swap)

**Default Colors:**
- Background: RGB(0, 54, 105) - Dark blue, professional appearance
- Foreground: RGB(200, 200, 200) - Light gray, good contrast

---

### Image Scaling (Windows Only)

**Function:** `getScaledImage()` (lines 152-200)

**Purpose:** Scales base64-encoded PNG images for notification bar icons

**Process:**
1. Initialize GDI+ (GdiplusStartup)
2. Decode base64 image to buffer
3. Create memory stream from buffer
4. Load image from stream using GdipCreateBitmapFromStream
5. Create new bitmap with target dimensions
6. Set resolution to match source image DPI
7. Get graphics context from new bitmap
8. Set smoothing mode (SmoothingModeAntiAlias)
9. Set interpolation mode (InterpolationModeBicubic)
10. Draw source image into new bitmap at target size
11. Convert to HBITMAP handle for Windows controls
12. Return handle with GDI+ token for cleanup

**Parameters:**
- `b64`: Base64-encoded PNG image
- `width`: Target width in pixels
- `height`: Target height in pixels
- `options.background`: Background color for transparency (optional)

**Image Assets:**
- `x_icon` (line 116): Close button icon (100×100 PNG)
- `pin_icon_1` (line 117): Pinned state icon (128×128 PNG)
- `pin_icon_2` (line 118): Unpinned state icon (128×128 PNG)

---

### Usage

#### Module Export Structure (Lines 674-689)

```javascript
// Windows
module.exports = windows_notifybar_check;
module.exports.system = windows_notifybar_system;
module.exports.RGB = RGB;
module.exports.DefaultPinned = true;

// Linux/FreeBSD
module.exports = x_notifybar_check;

// macOS
module.exports = macos_messagebox;
```

#### Basic Invocation

```javascript
// Simple notification (uses defaults)
var bar = require('notifybar-desktop')('Remote Assistance Session');
bar.on('close', function() {
    console.log('User closed notification bar');
    // Disconnect remote session
});

// Close programmatically
bar.close();
```

#### Windows-Specific Options

```javascript
// Custom colors and configuration
var bar = require('notifybar-desktop')('IT Support Session', {
    foreground: 'rgb(255,255,255)',  // White text
    background: 'rgb(0,100,200)'     // Blue background
});

// Numeric RGB format
var bar = require('notifybar-desktop')('Admin Session', {
    foreground: require('notifybar-desktop').RGB(255, 255, 0),  // Yellow
    background: require('notifybar-desktop').RGB(128, 0, 0)     // Dark red
});

// Change default pinned state
require('notifybar-desktop').DefaultPinned = false;  // Start unpinned
var bar = require('notifybar-desktop')('Session');
```

#### System Service Context (Windows)

```javascript
// Explicitly spawn in user session from SYSTEM service
var bar = require('notifybar-desktop').system('Remote Session', tsid, options);
// tsid = Terminal Services Session ID (from user-sessions module)
```

#### Multi-User Dispatch (Linux/FreeBSD)

```javascript
// When running as root, automatically dispatches to console user
var bar = require('notifybar-desktop')('Remote Desktop');
// Module handles uid detection and X11 session discovery automatically
```

#### Event Handling

```javascript
var bar = require('notifybar-desktop')('Active Session');

// User closed notification (clicked X button or Disconnect)
bar.on('close', function(code) {
    console.log('Session terminated by user');
    // Cleanup: disconnect KVM tunnel, notify server, etc.
});

// Programmatic cleanup
function disconnectSession() {
    bar.close();  // Removes notification bar
}
```

---

### Dependencies

#### Node.js Core Modules
- `events.EventEmitter` (lines 221, 249, 497, 541, 561, 665) - Event system for close notifications
- `child_process` (lines 225, 512, 545) - Process spawning for session dispatch

#### MeshAgent Module Dependencies

**Windows-Specific:**

- **`_GenericMarshal`** (lines 18, 20, extensive usage)
  - Native C library binding framework
  - Creates native proxies for Windows DLLs (Shlwapi.dll, Gdiplus.dll)
  - Methods: CreateVariable, CreatePointer, CreateNativeProxy
  - Used for all Windows API interactions

- **`win-message-pump`** (line 245)
  - Windows message loop implementation
  - Window creation and management
  - Message processing (WM_* constants)
  - Required for all Windows UI operations

- **`user-sessions`** (lines 205, 225)
  - Session enumeration and management
  - Methods: getProcessOwnerName(), minUid(), Self(), consoleUid()
  - Determines if running as SYSTEM vs. user
  - Provides Terminal Services Session ID (tsid) for spawning

**Linux/FreeBSD-Specific:**

- **`monitor-info`** (lines 246, 511, 535, 558, 578-601, 619)
  - Display enumeration and X11 utilities
  - Methods: getInfo(), getXInfo(), getCurrentWorkspace()
  - X11 functions: XCreateSimpleWindow, XMapWindow, XFlush, etc.
  - Properties: _X11 object with libX11 bindings
  - Workspace change detection
  - **Required for all X11 operations**

- **`user-sessions`** (lines 474-527)
  - Multi-user session detection
  - Methods: minUid(), Self(), consoleUid()
  - Login event monitoring ('changed' event)
  - UID-based session management

- **`DescriptorEvents`** (lines 603, 618)
  - File descriptor monitoring
  - Methods: addDescriptor(), removeDescriptor()
  - Used to monitor X11 connection (XConnectionNumber)
  - Event-driven X event processing

**macOS-Specific:**

- **`message-box`** (line 668)
  - Simple dialog creation
  - Method: create(title, message, timeout, buttons)
  - Returns promise-based interface
  - **Only UI mechanism used on macOS**

**Cross-Platform:**

- **`monitor-info`** (lines 246, 511, 535, 558)
  - Display enumeration (getInfo method)
  - Returns monitor geometry: left, right, top, bottom, dpi
  - Platform-agnostic interface with platform-specific implementations

#### Platform Binary Dependencies

**Windows:**
- **Shlwapi.dll** (line 94) - Shell utility library
  - SHCreateMemStream: Create IStream from memory buffer
- **Gdiplus.dll** (line 97) - GDI+ graphics library
  - Image loading, scaling, rendering
  - Bitmap manipulation
  - Graphics context management
  - Required for icon rendering

**Linux/FreeBSD:**
- **libX11.so** - X Window System library
  - Window creation and management
  - Event processing
  - Atom manipulation
  - Display connection
  - **Required for any X11 operations**
- **X Server** - Running X11 display server
  - Must be accessible via $DISPLAY environment variable
  - Required for window rendering
- **Window Manager** - X11 window manager
  - Handles window positioning, decorations
  - Workspace/virtual desktop support (optional)

**macOS:**
- **osascript** (indirectly via message-box)
  - AppleScript execution
  - Dialog display
  - **Required for macOS implementation**

#### Dependency Summary by Platform

| Platform | Critical Dependencies | Optional |
|----------|----------------------|----------|
| Windows | _GenericMarshal, win-message-pump, Shlwapi.dll, Gdiplus.dll | user-sessions |
| Linux/FreeBSD | monitor-info (with X11), DescriptorEvents, libX11.so | user-sessions |
| macOS | message-box, osascript | None |

#### Why macOS Has Limited Functionality

The dependency analysis reveals why macOS has a simplified implementation:

1. **No Native Window Framework:** The module relies on _GenericMarshal (Windows) or monitor-info._X11 (Linux/FreeBSD) for low-level window creation. macOS would require:
   - Cocoa/AppKit framework bindings (not present)
   - Objective-C or Swift bridge (not implemented)
   - CoreGraphics for window manipulation (not available)

2. **No Multi-Monitor Support:** The monitor-info module on macOS may not provide:
   - Native display enumeration (NSScreen equivalent)
   - Window positioning control
   - Workspace detection (Mission Control integration)

3. **Development Simplification:** Creating a full notification bar on macOS would require:
   - Implementing native Cocoa window creation
   - Handling macOS window server communication
   - Supporting retina displays and DPI scaling
   - Integrating with macOS security (TCC permissions)
   - This represents significant additional development effort

4. **Pragmatic Tradeoff:** The message-box fallback provides:
   - Basic notification functionality
   - Minimal code maintenance
   - Acceptable user experience for rare macOS KVM sessions
   - No complex platform-specific debugging

---

### Code Structure

The module is organized into functional sections:

1. **Lines 1-16:** Copyright and license information (Apache 2.0, Intel Corporation)
2. **Lines 18-114:** Windows API constants and native library initialization
   - Generic Marshal setup
   - Shlwapi.dll and Gdiplus.dll method binding
   - Windows message and style constants
3. **Lines 116-119:** Embedded image assets (base64 PNG icons)
4. **Lines 121-151:** Color manipulation utilities (RGB, string_RGB, gdip_RGB)
5. **Lines 152-200:** Image scaling function for Windows (getScaledImage)
6. **Lines 203-233:** Windows system mode dispatcher (windows_notifybar_system)
7. **Lines 235-467:** Windows local mode implementation (windows_notifybar_local)
   - Multi-monitor bar creation
   - Interactive controls (close, pin, title)
   - Event handling (drag, hover, click)
   - Pin/unpin and auto-hide logic
8. **Lines 470-554:** Linux/FreeBSD dispatcher (x_notifybar_check)
   - Root vs. user detection
   - Session spawning logic
   - Login event handling
9. **Lines 556-660:** Linux/FreeBSD implementation (x_notifybar)
   - X11 window creation
   - Multi-monitor and multi-workspace support
   - X event processing
10. **Lines 662-672:** macOS fallback implementation (macos_messagebox)
11. **Lines 674-689:** Platform-specific exports

---

### Technical Notes

**Windows GDI+ Lifecycle:**
- GdiplusStartup called for each image operation (line 159)
- Token stored in returned handle (_token property, line 196)
- Cleanup should call GdiplusShutdown (not shown in code)
- Memory leaks possible if not properly managed

**X11 Resource Management:**
- X display connections persist across workspace changes
- DescriptorEvents properly removed on close (line 618)
- XCloseDisplay called to free connection (line 619)
- Window handles not explicitly destroyed (implicit on connection close)

**Process Spawning Security:**
- Windows: Spawns child with specific tsid (user session)
- Linux/FreeBSD: Spawns with specific uid and X11 environment
- Scripts passed via base64 encoding (lines 219, 472, 512, 545)
- Child stdout/stderr consumed to prevent blocking (lines 228-229, 515-516, 548-549)

**Color Format Conversions:**
- Windows COLORREF: 0x00BBGGRR (BGR order)
- GDI+ ARGB: 0x00RRGGBB (RGB order)
- gdip_RGB function handles byte swapping (lines 138-151)

**Message Pump Asynchronous Calls:**
- Windows UI operations queued via _addAsyncMethodCall
- Promises used for operation chaining (.then syntax)
- Allows non-blocking window creation and updates

**Multi-Monitor Coordination:**
- Each monitor gets independent window/bar instance
- All monitors share close event (lines 371-380)
- Closing one bar closes all (prevents partial state)

**Workspace Behavior (X11):**
- Initial bar created only in current workspace (line 641)
- Additional workspaces get bars on first visit (lines 648-655)
- Prevents cluttering unused virtual desktops
- Relies on window manager workspace support

---

### Platform Comparison Matrix

| Feature | Windows | Linux/FreeBSD | macOS |
|---------|---------|---------------|-------|
| Notification Type | Draggable bar | Fixed bar | Modal dialog |
| Multi-Monitor | Yes | Yes | No |
| Customizable Colors | Yes | No | No |
| Pin/Unpin | Yes | No | No |
| Auto-Hide | Yes | No | No |
| Draggable | Yes | No | No |
| Window Decoration | Borderless popup | Window manager | System dialog |
| Always On Top | Yes | Yes | No (modal) |
| Multi-Workspace | N/A | Yes | N/A |
| Close Method | X button | Window close | Disconnect button |
| Session Dispatch | Terminal Services | uid + X11 env | Direct |

---

### macOS-Specific Analysis

**What Doesn't Work on macOS:**

1. **Visual Notification Bar** - No native window creation:
   - Would require Cocoa NSWindow or NSPanel
   - Needs NSScreen for monitor enumeration
   - Requires window server permissions

2. **Dragging/Positioning** - No window manipulation:
   - Would need NSWindow setFrame: method
   - Screen bounds checking via NSScreen
   - Mouse event handling via NSEvent

3. **Pin/Unpin Toggle** - No state management:
   - Would need NSButton or custom control
   - State persistence across sessions
   - Timer-based auto-hide mechanism

4. **Multi-Monitor** - No display enumeration:
   - Would need NSScreen screens array
   - Per-screen geometry calculations
   - Display configuration change notifications

5. **Custom Styling** - No color/appearance control:
   - Would need NSColor for foreground/background
   - Possibly NSVisualEffectView for modern appearance
   - Dark mode adaptation

**What Works on macOS:**

1. **Basic Notification** - Message box displays:
   - Uses osascript for native dialog
   - Shows title text
   - Single dismiss button

2. **Close Event** - Emits on dismissal:
   - Promise-based notification
   - Allows cleanup actions
   - Session termination

**Implementation Effort for Full macOS Support:**

To match Windows/Linux functionality would require:

1. Create Cocoa bindings in _GenericMarshal or separate module
2. Implement NSWindow subclass for notification bar
3. Add NSScreen enumeration for multi-monitor
4. Implement mouse event handling for dragging
5. Create custom controls for close/pin buttons
6. Add NSTimer for auto-hide functionality
7. Handle macOS permissions (screen recording, accessibility)
8. Support retina scaling and multiple display DPI
9. Integrate with Mission Control for workspace awareness
10. Test across macOS versions (10.x, 11.x, 12.x+)

**Estimated Development:** 40-80 hours for feature parity

**Alternative Approaches:**

1. **Electron-based UI:** Bundle mini Electron app for consistent cross-platform UI
2. **Web-based overlay:** Use WebKit/WKWebView for HTML/CSS-based notification
3. **Status bar item:** Use NSStatusBar for menubar notification (less intrusive)
4. **Native Swift module:** Develop separate Swift-based module with Node.js bridge

---

## Summary

The notifybar-desktop.js module provides visual notification of active remote desktop sessions across Windows, Linux, FreeBSD, and macOS platforms. The implementation quality and feature set vary significantly by platform:

**Windows** receives the most sophisticated implementation with:
- Rich draggable, pinnable, customizable notification bar
- Multi-monitor support with DPI awareness
- Auto-hide/minimize functionality
- GDI+ powered high-quality graphics

**Linux/FreeBSD** receive functional implementations with:
- X11-integrated notification bars
- Multi-monitor and multi-workspace support
- Proper window manager integration
- Event-driven X event processing

**macOS** receives a minimal fallback implementation:
- Simple modal message box via osascript
- No advanced features (dragging, pinning, multi-monitor)
- Adequate for basic notification purposes
- Significantly degraded user experience

The macOS limitations stem from:
- Lack of Cocoa/AppKit framework integration
- No native window creation mechanisms in module dependencies
- Development resource prioritization for primary Windows/Linux platforms
- Sufficient basic functionality for the MeshAgent's remote desktop notification needs

The module successfully achieves its core security goal—notifying users of active remote sessions—across all platforms, even if the user experience varies. This represents a pragmatic approach to cross-platform development where platform-specific UI polish is balanced against development effort and maintenance burden.
