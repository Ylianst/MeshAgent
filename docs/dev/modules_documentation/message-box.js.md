# message-box.js

Cross-platform dialog box and notification system providing user interaction capabilities including message boxes, notifications, clipboard access, and desktop locking. Implements platform-specific dialog mechanisms with unified API across Windows, Linux, macOS, and FreeBSD.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via Win32 message boxes
- Linux - Full support via Zenity, KDialog, or Xmessage
- macOS (darwin) - Full support via osascript/AppleScript
- FreeBSD - Full support via Zenity, KDialog, or Xmessage

**Excluded Platforms:**
- None - Module is fully cross-platform

**Exclusion Reasoning:**

This module has no platform exclusions. Each platform uses native dialog mechanisms for optimal integration:

- **Windows:** Win32 user32.dll MessageBox API via native bindings
- **Linux/FreeBSD:** Zenity (preferred), KDialog, or Xmessage fallback
- **macOS:** osascript for AppleScript dialogs

All platforms provide equivalent functionality through platform-appropriate implementations, ensuring consistent behavior while respecting platform conventions.

## Functionality

### Purpose

The message-box module provides cross-platform user interaction capabilities for MeshAgent. It serves multiple purposes:

- **Dialog Boxes:** Display message boxes with custom buttons and icons
- **User Notifications:** Toast/notification display (macOS)
- **Clipboard Access:** Get/set clipboard contents (macOS)
- **Desktop Locking:** Lock user desktop/session (macOS)
- **Multi-Button Dialogs:** Support for 1-3 buttons with custom labels
- **Timeout Support:** Auto-close dialogs after specified duration
- **Session-Specific Display:** Target specific user sessions (Linux/FreeBSD)
- **UTF-8 Support:** International character support across platforms

This module is typically used:
- To request user consent for remote operations
- For displaying status messages to logged-in users
- To show error/warning dialogs
- For notification toasts
- When clipboard integration needed (macOS)
- For secure desktop locking (macOS)

### Platform-Specific Implementations

#### Windows Implementation

**Mechanism:** Win32 MessageBox API via user32.dll

**Architecture:**
- IPC-based for privilege separation
- Master process creates named pipe
- Slave child process displays dialog in user session
- Result returned via IPC

**Dialog Features:**
- Native Windows message boxes
- Standard icons (information, warning, error, question)
- Button combinations (OK, OK/Cancel, Yes/No, etc.)
- UTF-8 text support
- Timeout capability

**Process Flow:**
1. Master process creates child-container IPC
2. Spawns slave process in target user session
3. Slave creates MessageBox via user32.dll
4. User interaction captured
5. Result sent back via IPC
6. Master process resolves promise

---

#### Linux/FreeBSD Implementation

**Mechanism:** External dialog tools (Zenity, KDialog, Xmessage)

**Tool Priority:**
1. **Zenity** - Preferred, modern GTK dialogs
2. **KDialog** - KDE dialogs
3. **Xmessage** - Basic X11 fallback

**Detection:**
Module detects available tools at initialization:
```javascript
{
    zenity: '/usr/bin/zenity' || null,
    kdialog: '/usr/bin/kdialog' || null,
    xmessage: '/usr/bin/xmessage' || null
}
```

**Zenity Implementation:**
- GTK-based dialogs
- Supports multiple buttons
- Custom button labels
- Width/height control
- Icon support
- UTF-8 encoding

**KDialog Implementation:**
- Qt/KDE dialogs
- Similar features to Zenity
- Better KDE desktop integration

**Xmessage Fallback:**
- Basic X11 tool
- Limited features
- Always available on X11 systems

**Session Targeting:**
- Uses `monitor-info` to get DISPLAY and XAUTHORITY
- Spawns dialog in specific user's X session
- Handles multiple logged-in users

---

#### macOS Implementation

**Mechanism:** osascript for AppleScript dialogs

**Dialog Features:**
- Native macOS dialogs
- Custom button labels (up to 3)
- Icon support
- Timeout capability
- UTF-8 support

**Additional macOS Features:**

**Clipboard Access:**
- `setClipboard(text)` - Uses `pbcopy` command
- `getClipboard()` - Uses `pbpaste` command

**Desktop Locking:**
- `lock()` - Uses CGSession command
- Locks current user session immediately

**Notification Toasts:**
- `notify(title, caption)` - Displays macOS notification

**IPC Architecture (Root Users):**
When running as root, dialogs must display in user space:
1. Creates LaunchAgent plist
2. Spawns helper process in user context
3. Communicates via Unix socket
4. Helper displays dialog
5. Result returned via socket

---

### Key Functions/Methods

#### create(title, caption, timeout, layout, sid) - Core Function

**Purpose:** Creates and displays a message box dialog.

**Parameters:**
- `title` - String: Dialog window title
- `caption` - String: Dialog message text
- `timeout` - Number: Auto-close timeout in seconds (0 = no timeout)
- `layout` - Array or Number: Button configuration
  - Array: Custom button labels `['OK', 'Cancel']`
  - Number: Standard button layout code
- `sid` - Number: Session ID to target (Windows/Linux only)

**Return Value:**
Promise that resolves with button index (0-based):
```javascript
dialog.then(function(result) {
    // result = 0 (first button), 1 (second button), etc.
    // result = null on timeout or close
});
```

**Button Layouts:**

**Array Format (Custom Labels):**
```javascript
['Yes', 'No', 'Cancel']  // Up to 3 buttons
['Install', 'Skip']
['OK']
```

**Standard Layout Codes:**
- 0: OK
- 1: OK / Cancel
- 2: Yes / No
- 3: Yes / No / Cancel

**Platform-Specific Behavior:**

**Windows:**
```javascript
var dialog = messageBox.create(
    'Confirmation',
    'Install updates?',
    0,  // No timeout
    1   // OK/Cancel
);
```

**Linux:**
```javascript
var dialog = messageBox.create(
    'Warning',
    'This action cannot be undone',
    10,  // 10 second timeout
    ['Proceed', 'Cancel']
);
```

**macOS:**
```javascript
var dialog = messageBox.create(
    'Question',
    'Save changes before closing?',
    0,
    ['Save', 'Don\'t Save', 'Cancel']
);
```

---

#### setClipboard(text) - macOS Only

**Purpose:** Sets clipboard contents.

**Process:**
1. Spawns `pbcopy` process
2. Writes text to stdin
3. Text copied to macOS clipboard

**Usage:**
```javascript
messageBox.setClipboard('Hello, World!');
```

---

#### getClipboard() - macOS Only

**Purpose:** Retrieves clipboard contents.

**Process:**
1. Spawns `pbpaste` process
2. Reads stdout
3. Returns clipboard text as promise

**Return Value:**
Promise resolving to clipboard string

**Usage:**
```javascript
messageBox.getClipboard().then(function(text) {
    console.log('Clipboard:', text);
});
```

---

#### lock() - macOS Only

**Purpose:** Locks the user's desktop session.

**Process:**
1. Executes `/System/Library/CoreServices/Menu\\ Extras/User.menu/Contents/Resources/CGSession`
2. System locks immediately
3. Requires password to unlock

**Usage:**
```javascript
messageBox.lock();  // Desktop locked
```

---

#### notify(title, caption) - macOS Only

**Purpose:** Displays notification toast.

**Process:**
1. Uses osascript with AppleScript
2. Creates macOS notification center notification
3. Non-blocking display

**Usage:**
```javascript
messageBox.notify('Update Available', 'Version 2.0 is ready to install');
```

---

### Usage

#### Basic Dialog (All Platforms)

```javascript
var messageBox = require('message-box');

messageBox.create(
    'Information',
    'Operation completed successfully',
    0,  // No timeout
    ['OK']
).then(function(result) {
    console.log('User clicked OK');
});
```

#### Yes/No Confirmation

```javascript
messageBox.create(
    'Confirmation',
    'Do you want to continue?',
    30,  // 30 second timeout
    ['Yes', 'No']
).then(function(result) {
    if (result === 0) {
        console.log('User clicked Yes');
    } else if (result === 1) {
        console.log('User clicked No');
    } else {
        console.log('Dialog timed out');
    }
});
```

#### Three-Button Dialog

```javascript
messageBox.create(
    'Save Changes',
    'Would you like to save your changes?',
    0,
    ['Save', 'Don\'t Save', 'Cancel']
).then(function(result) {
    switch(result) {
        case 0: console.log('Save'); break;
        case 1: console.log('Don\'t Save'); break;
        case 2: console.log('Cancel'); break;
        default: console.log('Dialog closed');
    }
});
```

#### macOS-Specific Features

```javascript
// Clipboard operations
messageBox.setClipboard('Copied text');

messageBox.getClipboard().then(function(text) {
    console.log('Clipboard contains:', text);
});

// Lock desktop
messageBox.lock();

// Show notification
messageBox.notify('Alert', 'Your attention is required');
```

#### Linux Session-Specific Dialog

```javascript
// Display in specific user session (session ID 42)
messageBox.create(
    'Warning',
    'System will restart in 5 minutes',
    300,  // 5 minute timeout
    ['OK'],
    42  // Session ID
);
```

---

### Dependencies

#### Node.js Core Modules

- **`child_process`** - Execute dialog tools
  - Platform support: Cross-platform

- **`fs`** - File system operations
  - LaunchAgent plist creation (macOS)
  - Platform support: Cross-platform

- **`net`** - Network/IPC
  - Unix socket communication (macOS)
  - Named pipes (Windows)
  - Platform support: Cross-platform

- **`promise`** - Async operations
  - Platform support: Cross-platform

#### MeshAgent Module Dependencies

**Windows:**
- **`_GenericMarshal`** - Native bindings
  - Binds to user32.dll for MessageBox API

- **`child-container`** - IPC framework
  - Master/slave process communication

**Linux/FreeBSD:**
- **`monitor-info`** - X11 session info
  - Gets DISPLAY and XAUTHORITY for target sessions

**macOS:**
- **`service-manager`** - LaunchAgent management
  - Creates/removes LaunchAgent plists for IPC helpers

- **`user-sessions`** - User and session management

#### Platform Binary Dependencies

**Windows:**
- **user32.dll** - Windows User API
  - MessageBox function
  - Standard Windows component

**Linux/FreeBSD:**
- **zenity** (preferred) - `/usr/bin/zenity`
  - GTK dialog tool
  - Install: `apt install zenity` or `yum install zenity`

- **kdialog** (alternative) - `/usr/bin/kdialog`
  - KDE dialog tool
  - Install: `apt install kdialog`

- **xmessage** (fallback) - `/usr/bin/xmessage`
  - X11 basic dialogs
  - Usually pre-installed with X11

**macOS:**
- **osascript** - `/usr/bin/osascript`
  - AppleScript execution
  - Standard on macOS

- **pbcopy** - `/usr/bin/pbcopy`
  - Clipboard write
  - Standard on macOS

- **pbpaste** - `/usr/bin/pbpaste`
  - Clipboard read
  - Standard on macOS

- **CGSession** - `/System/Library/CoreServices/Menu\\ Extras/User.menu/Contents/Resources/CGSession`
  - Desktop locking
  - Standard on macOS

#### Dependency Summary

| Platform | Core Deps | MeshAgent Deps | System Binaries |
|----------|-----------|----------------|-----------------|
| Windows | child_process, net, promise | _GenericMarshal, child-container | user32.dll |
| Linux/FreeBSD | child_process, promise | monitor-info | zenity/kdialog/xmessage |
| macOS | child_process, fs, net, promise | service-manager, user-sessions | osascript, pbcopy, pbpaste, CGSession |

---

### Technical Notes

**IPC Architecture (Windows & macOS Root):**

Both Windows and macOS (when running as root) use IPC to display dialogs in user space:

**Reason:** Security boundaries prevent root/system processes from directly displaying UI in user sessions.

**Solution:** Spawn helper process in user context via IPC.

**Windows Flow:**
1. Master (system service) → Child-container IPC → Slave (user process) → MessageBox

**macOS Flow:**
1. Master (root) → LaunchAgent → Helper (user process) → osascript → Dialog

**UTF-8 Support:**

All platforms support UTF-8 encoding for international characters:
- Windows: Wide character (WCHAR) MessageBox API
- Linux: Zenity/KDialog UTF-8 support
- macOS: osascript UTF-8 encoding

**Timeout Behavior:**

Platform timeout handling varies:
- **Windows:** MessageBox doesn't support native timeout, implemented via timer + close
- **Linux Zenity:** Native `--timeout` parameter
- **macOS osascript:** Native timeout support

**Button Limitations:**

- **Windows:** Standard combinations (OK, OK/Cancel, Yes/No, etc.)
- **Linux Zenity:** Up to 10+ custom buttons
- **macOS:** Up to 3 buttons maximum (AppleScript limitation)

**X11 Session Targeting (Linux/FreeBSD):**

Dialogs must be displayed in correct X session:
1. Query loginctl for active sessions
2. Get DISPLAY (e.g., `:0`) and XAUTHORITY path
3. Set environment variables before spawning dialog
4. Dialog appears on target user's screen

**LaunchAgent Approach (macOS):**

For root users displaying dialogs:
1. Create temporary LaunchAgent plist in `~/Library/LaunchAgents/`
2. LaunchAgent runs in user context
3. Helper process handles IPC and dialog display
4. Cleaned up after use

## Summary

The message-box.js module is a **fully cross-platform dialog and notification system** supporting Windows, Linux, macOS, and FreeBSD with platform-optimized implementations and unified API.

**Key features:**
- Message box dialogs with custom buttons (1-3)
- Platform-native look and feel
- Auto-close timeout support
- UTF-8 international character support
- Session-specific display (Linux/FreeBSD)
- Clipboard access (macOS)
- Desktop locking (macOS)
- Toast notifications (macOS)
- IPC-based privilege separation (Windows, macOS root)
- Multiple dialog tool support (Linux: Zenity/KDialog/Xmessage)

**Platform implementations:**
- **Windows:** Win32 MessageBox via user32.dll with IPC
- **Linux/FreeBSD:** Zenity (preferred), KDialog, or Xmessage
- **macOS:** osascript/AppleScript with LaunchAgent IPC (root users)

The module is used within MeshAgent for user interaction, consent dialogs, notifications, and system integration across all supported platforms. It provides consistent functionality while respecting platform-specific UI conventions and security boundaries.
