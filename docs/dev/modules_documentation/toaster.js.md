# toaster.js

Cross-platform toast notification module for MeshAgent that displays temporary pop-up messages to users in a platform-agnostic manner. Provides unified API for showing notifications on Windows (PowerShell NotifyIcon), Linux/FreeBSD (zenity/kdialog/notify-send), and macOS (osascript via message-box module).

## Platform

**Supported Platforms:**
- Windows (win32) - Full support using PowerShell NotifyIcon API
- Linux - Full support using zenity, kdialog, notify-send, or xmessage
- FreeBSD - Full support using zenity, kdialog, or xmessage
- macOS (darwin) - Full support using message-box.notify() implementation

**Exclusion Reasoning:**

This module is **fully supported on macOS** and is not excluded. The macOS implementation (lines 284-291) delegates to the message-box module's notify() function, which uses native macOS notification mechanisms:

1. **Native macOS Integration** - Uses osascript to trigger Notification Center
2. **System Notification Center** - Displays proper macOS notifications (not dialogs)
3. **Non-Blocking** - Notifications appear without blocking execution
4. **Automatic Dismissal** - System handles timeout and user interaction
5. **Promise-Based** - Returns promise that resolves when dismissed

The macOS implementation is simple, reliable, and leverages the existing message-box module infrastructure.

## Functionality

### Purpose

The toaster module provides a unified cross-platform API for displaying temporary notification messages to logged-in users. It abstracts the differences between platform-specific notification systems:

- **Windows**: PowerShell-based balloon notifications via System.Windows.Forms.NotifyIcon
- **Linux/FreeBSD**: Desktop notification utilities (zenity, kdialog, notify-send, xmessage)
- **macOS**: Notification Center via osascript

This module is typically used to:
- Notify users of agent connection status
- Display remote session consent requests
- Show system maintenance alerts
- Inform users of security events
- Display custom messages from server administrators

The module is called "Toaster" because it creates "toast" notifications - small temporary messages that pop up from the system tray/notification area and automatically dismiss.

### Key Function

#### Toast(title, caption, tsid) - Lines 58-295

**Purpose:** Displays a toast notification with specified title and caption text.

**Parameters:**
- `title` (string) - Notification title/header
- `caption` (string) - Notification message body
- `tsid` (number, optional) - Target session ID (Windows only)

**Returns:** Promise that resolves with 'DISMISSED' when notification is closed.

**Process Flow:**

**Common Pre-Processing (lines 61-64):**
1. If title equals 'MeshCentral', attempts to replace with `require('MeshAgent').displayName`
2. Stores title and caption in promise object for reference
3. Branches to platform-specific implementation

---

**Windows Implementation (lines 68-132):**

**Session Targeting (lines 75-102):**
1. Creates environment with _title and _caption variables (for UTF-8 support)
2. Copies all process.env variables to child environment
3. Determines target user session:
   - If tsid not provided: Gets console session UID
   - If tsid provided: Validates permission to target that session
   - If targeting different session: Uses SpawnTypes.USER for cross-session display
4. Rejects if no user logged in or insufficient permissions

**PowerShell Process Setup (lines 104-129):**
1. Spawns PowerShell with flags: `-noprofile -nologo -command -`
2. Sets up stdio event handlers:
   - stdout: Monitors for `<DISMISSED>` marker to trigger exit
   - stderr: Exits on any error
3. Sends PowerShell commands via stdin:
   ```powershell
   [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
   $objBalloon = New-Object System.Windows.Forms.NotifyIcon
   $objBalloon.Icon = [System.Drawing.SystemIcons]::Information
   $objBalloon.Visible = $True
   Register-ObjectEvent -InputObject $objBalloon -EventName BalloonTipClosed -Action {
       $objBalloon.dispose();
       Write-Host "<DISMISSED>"
   }
   $objBalloon.ShowBalloonTip(10000, $env:_title, $env:_caption, 0)
   ```
4. Sets 10-second timeout for automatic cleanup
5. Attaches 'exit' handler that clears timeout and resolves promise

**Why PowerShell Instead of Native API:**
Line 71 comment explains: "We tried using Shell Notify Icon, but ran into stability issues with it. The Powershell interface for it seemed much more reliable."

**Environment Variable Approach:**
Line 76 comment explains: "We are putting these values into the environment, because Powershell has an issue with passing UTF8 values otherwise." This ensures international characters display correctly.

---

**Linux/FreeBSD Implementation (lines 135-283):**

**Session Information Gathering (lines 137-150):**
1. Gets console UID via `require('user-sessions').consoleUid()`
2. Fetches X11 info: `require('monitor-info').getXInfo(uid)`
   - Returns: { display, xauthority } for targeting correct X session
3. Gets username for su command context switching
4. Rejects if unable to get session information

**Notification Method Selection (lines 152-281):**

The module tries multiple notification methods in order of preference:

**Method 1: Zenity (lines 152-225)**

Conditions checked:
1. Is zenity installed? (`require('message-box').zenity` exists)
2. What mode should be used?

**Zenity Modes:**

**Mode A: Zenity --info (No D-Bus service, lines 154-169):**
- Triggered when: Linux without org.freedesktop.Notifications D-Bus service
- Uses: `zenity --info --title=... --text=... --timeout=5`
- If timeout supported: Uses native --timeout flag
- If timeout not supported: Spawns with manual 5-second kill timeout
- **Descriptor:** 'toaster (zenity/messagebox)'

**Mode B: Zenity --notification (Modern zenity, lines 211-215):**
- Triggered when: Zenity version >= 3.10 and not broken
- Uses: `zenity --notification --title=... --text=... --timeout=5`
- Requires: D-Bus notification service available
- **Descriptor:** 'toaster (zenity/notification)'

**Mode C: notify-send via zenity path (Broken zenity, lines 170-209):**
- Triggered when: Zenity version < 3.10 or broken flag set
- Falls back to notify-send if available
- Root context (lines 176-181):
  ```bash
  su - username -c "export DISPLAY=...; export XDG_RUNTIME_DIR=...; notify-send 'title' 'caption'"
  ```
- User context (lines 183-186):
  ```bash
  notify-send title caption
  ```
- **Descriptor:** 'toaster (notify-send)'

**Mode D: Zenity --info fallback (No notify-send, lines 191-208):**
- Creates message-box with 5-second timeout
- Uses promise chaining to resolve toast promise
- Returns early (lines 198-199)

**Method 2: KDialog (lines 230-247)**

- Triggered when: zenity not available, kdialog found via findPath()
- Requires: XDG_RUNTIME_DIR environment variable
- Uses: `kdialog --title "..." --passivepopup "..." 5`
- Sets uid, DISPLAY, XAUTHORITY, XDG_RUNTIME_DIR for proper session targeting
- **Descriptor:** 'toaster (kdialog)'

**Method 3: notify-send (lines 250-266)**

- Triggered when: zenity and kdialog not available, notify-send available
- Same root/user context switching as zenity mode C
- **Descriptor:** 'toaster (notify-send)'

**Method 4: xmessage (lines 267-276)**

- Last resort fallback
- Uses message-box.create() with 5-second timeout
- Very basic, blocks user interaction
- Only used when no other utilities available

**Method 5: Error (lines 277-279)**

- Rejects with: 'Zenity/KDialog/xmessage not found'
- No notification utilities available on system

**Exit Handler (lines 220-224):**
All methods attach exit handler:
```javascript
child.on('exit', function(code) {
    if (this.timeout) { clearTimeout(this.timeout); }
    this.parent._res('DISMISSED');
});
```

**Descriptor Metadata:**
All spawned processes get `descriptorMetadata` property for debugging/logging (lines 168, 188, 207, 214, 242, 265).

---

**macOS Implementation (lines 284-291):**

**Simple Delegation:**
```javascript
retVal._toast = require('message-box').notify(title, caption);
retVal._toast.parent = retVal;
retVal._toast.then(
    function(v) { this.parent._res(v); },
    function(e) { this.parent._rej(e); }
);
```

**Process:**
1. Calls message-box module's notify() function
2. Passes title and caption unchanged
3. Chains returned promise to toast promise
4. Resolves/rejects based on message-box result

**What message-box.notify() does (implemented elsewhere):**
- Uses osascript to call macOS Notification Center
- Command: `display notification "caption" with title "title"`
- Notifications appear in Notification Center sidebar
- Automatically dismissed after system timeout (~5 seconds)
- Non-blocking, no user interaction required

---

### Platform-Specific Helper Functions

#### findPath(app) - Lines 30-47

**Purpose:** Locates the binary path for a specified application using the whereis utility.

**Platform:** Linux, FreeBSD, macOS (lines 25-48)

**Parameters:**
- `app` (string) - Application name to find (e.g., 'zenity', 'kdialog')

**Process:**

**Linux/FreeBSD (lines 35-37):**
```bash
whereis zenity | awk '{ print $2 }'
```
- whereis output format: `zenity: /usr/bin/zenity /usr/share/man/man1/zenity.1.gz`
- awk extracts second field (binary path)
- Returns: `/usr/bin/zenity`

**macOS (lines 40-41):**
```bash
whereis zenity
```
- macOS whereis output format: `/usr/bin/zenity` (direct path only)
- No awk parsing needed
- Returns: `/usr/bin/zenity`

**FreeBSD Fallback (line 45):**
- If whereis returns empty and /usr/local/bin/[app] exists
- Returns: `/usr/local/bin/[app]`
- Handles FreeBSD's common local installation path

**Returns:** Binary path string or null if not found.

**Usage:** Called line 230 to find kdialog: `util = findPath('kdialog');`

---

### Legacy/Alternative Implementation

#### _containerToast(caption, title) - Lines 301-326

**Purpose:** Old method for displaying Windows toasts using win-console module's SetTrayIcon API.

**Platform:** Windows only (lines 296-326)

**Status:** Deprecated/legacy code, not currently used by Toast() function.

**Process:**
1. Requires win-console module
2. Calls SetTrayIcon with:
   - szInfo: caption
   - szInfoTitle: title
   - balloonOnly: true (no permanent tray icon)
3. Listens for 'ToastDismissed' event to exit
4. Sends message to child-container with PID
5. Sets 7-second timeout for automatic cleanup

**Why Not Used:**
This was the original implementation before switching to PowerShell (line 71 comment explains stability issues with Shell Notify Icon API).

**Kept For:** Possibly backward compatibility or alternative if PowerShell method fails.

---

### Usage Examples

#### Basic Notification

```javascript
var toaster = require('toaster');

toaster.Toast('Connection Status', 'Successfully connected to MeshCentral server')
    .then(function(result) {
        console.log('Toast dismissed: ' + result);  // 'DISMISSED'
    });
```

**Platform Behavior:**
- **Windows**: PowerShell balloon tip appears from system tray
- **Linux**: Notification appears via zenity/notify-send
- **macOS**: Notification appears in Notification Center

---

#### Agent Display Name

```javascript
// If title is 'MeshCentral', automatically uses agent's display name
toaster.Toast('MeshCentral', 'Remote connection established');
// Title becomes: require('MeshAgent').displayName
```

---

#### Windows Session Targeting

```javascript
// Display toast to specific user session (Windows only)
var sessions = require('user-sessions');
var consoleUid = sessions.consoleUid();

toaster.Toast('Alert', 'System maintenance in 5 minutes', consoleUid)
    .then(function() {
        console.log('User notified');
    }, function(err) {
        console.log('Failed: ' + err);
    });
```

---

#### Error Handling

```javascript
toaster.Toast('Test', 'Test message')
    .then(function(result) {
        console.log('Success');
    }, function(error) {
        // Possible errors:
        // - 'Cannot display user notification when a user is not logged in'
        // - 'Insufficient permission to display toast as uid: N'
        // - 'Zenity/KDialog/xmessage not found'
        console.log('Error: ' + error);
    });
```

---

### Dependencies

#### Module Dependencies

**Core Required Modules:**

- **`promise`** (line 23)
  - Custom promise implementation
  - All Toast() calls return promises
  - Not native JavaScript promises

**Platform-Specific Module Dependencies:**

**Windows:**

- **`user-sessions`** (lines 83-84, 176, 179, 186, 253, 256)
  - User session management
  - Methods used:
    - `consoleUid()` - Get active console session ID
    - `getProcessOwnerName(pid)` - Get current process owner info (returns {tsid})
    - `whoami()` - Get current username
    - `findEnv(uid, varname)` - Get environment variable for specific user
  - Required for: Session targeting (Windows), context switching (Linux)

- **`child_process`** (lines 105, 160, 165, 180, 186, 204, 241, 257, 263)
  - Process spawning
  - Methods: `execFile(path, args, options)`
  - Required for: All platforms (PowerShell, zenity, kdialog, notify-send)
  - Special spawn type: `SpawnTypes.USER` for cross-session display (line 95)

**Linux/FreeBSD:**

- **`monitor-info`** (line 143)
  - X11 session information
  - Method: `getXInfo(uid)` - Returns {display, xauthority}
  - Required for: Targeting correct X11 display
  - Used to set DISPLAY and XAUTHORITY environment variables

- **`user-sessions`** (lines 142, 144, 176, 179, 186, 253, 256)
  - Same as Windows usage
  - Additional: Username lookup for su command

- **`message-box`** (lines 152, 157, 170, 173, 193, 196, 250, 267, 272)
  - Dialog and notification utility wrapper
  - Properties checked:
    - `zenity` - Object with zenity info: {path, version, timeout, broken, extra}
    - `zenity.timeout` - Boolean: supports --timeout flag
    - `zenity.broken` - Boolean: notification broken in this version
    - `zenity.version` - Array: [major, minor, patch]
    - `notifysend` - Object: {path} to notify-send binary
    - `kdialog` - Object: {path} to kdialog binary
    - `xmessage` - Object: {path} to xmessage binary
  - Methods: `create(title, caption, timeout, buttons)`
  - Required for: Determining available notification methods

- **`linux-dbus`** (lines 154, 334-344)
  - D-Bus service detection
  - Method: `hasService(name)` - Checks if D-Bus service exists
  - Used line 154: Check for 'org.freedesktop.Notifications'
  - Polyfilled if missing (lines 334-344)

**macOS:**

- **`message-box`** (line 288)
  - Notification display
  - Method: `notify(title, caption)` - Returns promise
  - Implementation: Uses osascript for Notification Center
  - Required for: All macOS notifications

**All Unix Platforms (Linux/FreeBSD/macOS):**

- **`child_process`** (lines 32, 338, 431, 498)
  - Used by findPath() helper
  - Executes whereis via /bin/sh

- **`fs`** (line 45)
  - File system checks
  - Method: `existsSync(path)`
  - Used for: FreeBSD binary path fallback check

#### System Binary Dependencies

**Windows:**
- **powershell.exe** - %windir%\System32\WindowsPowerShell\v1.0\powershell.exe
  - PowerShell interpreter
  - Required for: All Windows toast notifications
  - Version: Any (uses basic .NET System.Windows.Forms)
  - **Critical dependency** - No fallback if missing

**Linux/FreeBSD (in order of preference):**

**Primary Options:**

- **zenity** (preferred if version >= 3.10)
  - GTK+ dialog utility
  - Paths: /usr/bin/zenity, /usr/local/bin/zenity (FreeBSD)
  - Used for: `zenity --notification` or `zenity --info`
  - Best option when D-Bus notifications available

- **notify-send** (fallback for old zenity or primary if no zenity)
  - libnotify notification sender
  - Paths: /usr/bin/notify-send
  - Requires: D-Bus org.freedesktop.Notifications service
  - Used for: `notify-send "title" "caption"`

- **kdialog** (fallback if zenity not available)
  - KDE dialog utility
  - Paths: /usr/bin/kdialog, /usr/local/bin/kdialog
  - Used for: `kdialog --title "..." --passivepopup "..." 5`
  - Requires: KDE runtime environment

**Last Resort:**

- **xmessage** (absolute fallback)
  - X11 message display utility
  - Very basic, blocks user
  - Used via message-box.create()
  - Universally available on X11 systems

**Supporting Utilities:**

- **whereis** (lines 37, 41)
  - Utility to locate binaries
  - Paths: /usr/bin/whereis
  - Required for: findPath() helper
  - Universally available on Unix systems

- **awk** (line 37, Linux/FreeBSD only)
  - Text processing
  - Used to: Parse whereis output
  - Paths: /usr/bin/awk
  - Universally available

- **su** (lines 181, 258)
  - Switch user utility
  - Paths: /bin/su
  - Required when: Running as root and displaying to regular user
  - Used to: Execute notify-send in user's context

**D-Bus Services (Linux):**

- **org.freedesktop.Notifications** (checked line 154)
  - Desktop notification service
  - Required for: zenity --notification and notify-send
  - Provided by: Desktop environments (GNOME, KDE, XFCE, etc.)
  - Checked via: /usr/share/dbus-1/services/*.service files

**macOS:**
- **osascript** (used by message-box.notify())
  - AppleScript interpreter
  - Paths: /usr/bin/osascript
  - Built-in to macOS
  - Used for: `display notification "..." with title "..."`
  - Required for: All macOS notifications

#### Environment Variables Required

**Linux/FreeBSD:**

- **DISPLAY** (lines 160, 165, 181, 204, 213, 235, 241, 258)
  - X11 display identifier (e.g., `:0`)
  - Required for: All X11-based notifications
  - Obtained via: `monitor-info.getXInfo(uid).display`

- **XAUTHORITY** (lines 160, 165, 204, 213, 235, 241)
  - X11 authorization file path
  - Required for: Cross-session X11 access
  - Obtained via: `monitor-info.getXInfo(uid).xauthority`

- **XDG_RUNTIME_DIR** (lines 179, 181, 234, 241, 256, 258)
  - User runtime directory for D-Bus
  - Required for: notify-send, kdialog
  - Obtained via: `user-sessions.findEnv(uid, 'XDG_RUNTIME_DIR')`
  - Example: `/run/user/1000`

**Windows:**

- **_title** (lines 76, 117)
  - Custom environment variable for title
  - Required for: UTF-8 support in PowerShell
  - Set in: child process environment

- **_caption** (lines 76, 117)
  - Custom environment variable for caption
  - Required for: UTF-8 support in PowerShell
  - Set in: child process environment

#### Permission Requirements

**Windows:**
- Root/SYSTEM permissions required if:
  - Displaying toast to different user session (tsid parameter)
  - Current process not running in target session
- Check performed: lines 84-94

**Linux/FreeBSD:**
- Root permissions required if:
  - Displaying notification to user when running as root
  - Must use `su -` to switch context
- Detection: `require('user-sessions').whoami() == 'root'` (lines 176, 253)

**macOS:**
- No special permissions required
- Notifications display in current user's context
- message-box.notify() handles context automatically

### Code Structure

The module is organized into functional sections:

1. **Lines 1-21:** License header and module description comments
2. **Lines 23:** Core module imports (promise)
3. **Lines 25-48:** Unix helper function (findPath)
4. **Lines 50-52:** Toaster constructor function
5. **Lines 54-57:** Toast function JSDoc-style comment
6. **Lines 58-295:** Toast() main function
   - Lines 60-65: Promise setup and title preprocessing
   - Lines 66-132: Windows implementation (PowerShell)
   - Lines 134-283: Linux/FreeBSD implementation (zenity/kdialog/notify-send)
   - Lines 284-291: macOS implementation (message-box delegation)
7. **Lines 296-326:** Legacy _containerToast() function (Windows, unused)
8. **Lines 329:** Module export
9. **Lines 331-344:** linux-dbus.hasService() polyfill

### Technical Notes

#### Promise-Based API

All Toast() calls return custom promise objects:

```javascript
var retVal = new promise(function(res, rej) {
    this._res = res;
    this._rej = rej;
});
retVal.title = title;     // Stores original title
retVal.caption = caption;  // Stores original caption
return retVal;
```

Promises resolve with:
- `'DISMISSED'` - Notification closed by user or timeout

Promises reject with:
- Error strings describing failure reason
- Exception objects from system calls

#### UTF-8 Handling on Windows

PowerShell has issues with UTF-8 strings passed as command-line arguments. Solution (lines 76-80):

```javascript
retVal.options = {
    env: {
        _title: title,      // Environment variables support UTF-8
        _caption: caption   // Better than command-line args
    }
};
// PowerShell accesses via: $env:_title, $env:_caption
```

This ensures international characters (Chinese, Japanese, Arabic, emoji) display correctly in Windows notifications.

#### Zenity Version Detection

The module checks zenity version to determine feature support (line 170):

```javascript
if (require('message-box').zenity.broken ||
    require('message-box').zenity.version[0] < 3 ||
    (require('message-box').zenity.version[0] == 3 &&
     require('message-box').zenity.version[1] < 10))
```

- **Version < 3.10**: Notification support broken or missing
- **Version >= 3.10**: `zenity --notification` fully supported
- **Broken flag**: Manual override if specific version has issues

#### D-Bus Service Detection

Linux desktop notifications require D-Bus service (line 154):

```javascript
if (process.platform == 'linux' &&
    !require('linux-dbus').hasService('org.freedesktop.Notifications'))
```

If D-Bus service missing:
- Cannot use zenity --notification
- Cannot use notify-send
- Falls back to zenity --info (modal dialog)

The hasService() polyfill (lines 334-344) checks:
```bash
cat /usr/share/dbus-1/services/*.service | grep "org.freedesktop.Notifications"
```

#### Descriptor Metadata

All spawned child processes get descriptorMetadata for debugging:

```javascript
retVal.child.descriptorMetadata = 'toaster (zenity/notification)'
```

Possible values:
- `'toaster'` - Windows PowerShell
- `'toaster (zenity/messagebox)'` - Zenity info dialog
- `'toaster (zenity/notification)'` - Zenity notification
- `'toaster (notify-send)'` - notify-send
- `'toaster (kdialog)'` - KDialog

This helps identify which notification method was used in logs/debugging.

#### Automatic Timeout Handling

All platforms implement automatic dismissal:

**Windows (lines 118-123):**
- 10-second setTimeout that writes to PowerShell stdin
- Cleanup: `$objBalloon.dispose();exit\n`

**Linux/FreeBSD (lines 166, 205):**
- 5-second setTimeout that kills child process
- Only for utilities without native timeout support

**Built-in Timeouts:**
- Windows: 10 seconds
- Linux zenity: 5 seconds (--timeout=5)
- Linux kdialog: 5 seconds (passivepopup parameter)
- macOS: ~5 seconds (system default)

#### Context Switching on Linux

When running as root and displaying to regular user (lines 176-181):

```javascript
if (require('user-sessions').whoami() == 'root') {
    var xdg = require('user-sessions').findEnv(retVal.consoleUid, 'XDG_RUNTIME_DIR');
    retVal.child = require('child_process').execFile('/bin/sh', ['sh']);
    retVal.child.stdin.write(
        'su - ' + retVal.username + ' -c "' +
        'export DISPLAY=' + retVal.xinfo.display + '; ' +
        'export XDG_RUNTIME_DIR=' + xdg + '; ' +
        'notify-send \'' + retVal.title + '\' \'' + retVal.caption + '\'"' +
        '\nexit\n'
    );
}
```

This ensures:
1. Notification appears in user's session (not root's)
2. Correct D-Bus session bus accessed
3. Proper X11 display targeted

Without this, root-run notifications wouldn't appear to logged-in user.

#### macOS Notification Center Integration

The message-box.notify() implementation (not shown in this file) uses:

```bash
osascript -e 'display notification "caption" with title "title"'
```

Features:
- Appears in Notification Center sidebar
- System handles timeout and persistence
- User can dismiss manually
- Supports macOS notification preferences
- No blocking or modal behavior

#### Error Handling Philosophy

The module uses a graceful degradation approach:

1. **Try best method** (zenity --notification)
2. **Fall back to alternatives** (notify-send, kdialog)
3. **Use basic method** (zenity --info, xmessage)
4. **Reject only if nothing available**

This ensures notifications work on widest range of systems.

#### Legacy Code Preservation

The _containerToast() function (lines 301-326) is preserved but unused because:
1. Historical reference for original implementation
2. Potential fallback if PowerShell method fails
3. Shows evolution of implementation approach
4. May be useful for debugging/comparison

However, current Toast() implementation never calls it.

## Platform-Specific Analysis

### What Works on macOS

**Fully Functional:**
- ✅ Toast() - Complete implementation via message-box module
- ✅ Native Notification Center integration
- ✅ Automatic timeout and dismissal
- ✅ UTF-8/Unicode support for all languages
- ✅ Non-blocking notifications
- ✅ Promise-based async API
- ✅ User context awareness

**Notification Features on macOS:**
- ✅ Title and caption text
- ✅ System icon (app icon or default)
- ✅ Notification Center persistence
- ✅ User-configurable preferences
- ✅ Do Not Disturb mode respect
- ✅ Banner or alert style (user preference)

**Example macOS Notification:**

```javascript
var toaster = require('toaster');

// Displays in Notification Center
toaster.Toast('MeshAgent', 'Connection established')
    .then(function() {
        console.log('User saw notification');
    });
```

Result:
- Notification slides in from top-right
- Shows "MeshAgent" as title
- Shows "Connection established" as message
- Automatically dismisses after ~5 seconds
- Persists in Notification Center sidebar

### What Doesn't Work on macOS

**Not Supported:**
- ❌ Session targeting (tsid parameter) - macOS implementation ignores this
- ❌ Custom timeout values - System controls dismissal timing
- ❌ Custom icons - Uses default notification icon
- ❌ Action buttons - Simple notifications only

**Limitations:**
- ⚠️ No control over notification persistence in Notification Center
- ⚠️ Cannot detect if user clicked notification (only dismissal)
- ⚠️ Respects system Do Not Disturb mode (notification may not appear)
- ⚠️ Requires osascript (built-in, but could theoretically be disabled)

### Platform Comparison

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| Notification display | ✅ Balloon | ✅ Desktop | ✅ Notification Center |
| Automatic timeout | ✅ 10s | ✅ 5s | ✅ ~5s (system) |
| UTF-8 support | ✅ Via env | ✅ Native | ✅ Native |
| Session targeting | ✅ tsid param | ❌ | ❌ |
| Promise-based | ✅ | ✅ | ✅ |
| Cross-session | ✅ SpawnTypes.USER | ✅ su - | N/A |
| Icon customization | ❌ Info only | ⚠️ Depends | ❌ Default |
| Multiple utilities | ❌ PowerShell | ✅ 4 options | ❌ osascript |
| Blocking dialogs | ❌ | ⚠️ Fallback | ❌ |
| Requires GUI | ✅ | ✅ | ✅ |
| Root context switch | ✅ | ✅ su | N/A |

### macOS Implementation Quality

The macOS implementation is **production-ready** with these characteristics:

**Strengths:**
1. **Simple and reliable** - Delegates to battle-tested message-box module
2. **Native integration** - Uses Notification Center (not dialogs)
3. **Clean code** - Only 8 lines (284-291)
4. **Promise-based** - Consistent with other platforms
5. **No external dependencies** - osascript built into macOS

**Trade-offs:**
1. **Less control** - System manages timeout, icons, persistence
2. **No session targeting** - Always displays to current user
3. **Limited feedback** - Can't detect user interaction (only dismissal)

**Best Practices Followed:**
- Uses official Notification Center API via osascript
- Non-blocking implementation
- Proper promise chaining
- Respects system notification preferences

**Why It's Good Enough:**

For MeshAgent's use case (informing users of agent events), the macOS implementation provides exactly what's needed:
- User sees notifications
- Notifications don't block agent operation
- Works reliably without complex fallback logic
- Integrates with macOS user experience expectations

The limitations (no session targeting, no custom timeouts) don't affect typical usage scenarios.

## Summary

The toaster.js module is a **fully cross-platform** notification solution supporting **Windows, Linux, FreeBSD, and macOS** equally. It provides a unified promise-based API for displaying temporary toast notifications with automatic dismissal.

**macOS is fully supported** with a simple but effective implementation (lines 284-291) that delegates to the message-box module's notify() function. This uses osascript to trigger native Notification Center alerts, providing proper macOS integration without complex fallback logic.

**Platform implementations:**
- **Windows**: PowerShell + System.Windows.Forms.NotifyIcon (10-second balloon tips)
- **Linux/FreeBSD**: Graceful degradation through zenity → notify-send → kdialog → xmessage
- **macOS**: osascript + Notification Center (system-managed timing)

**Key capabilities:**
- **Toast()**: Promise-based notification display
- **UTF-8 support**: International characters on all platforms
- **Automatic timeout**: Platform-appropriate dismissal timing
- **Session awareness**: Windows supports cross-session targeting, Linux switches context via su
- **Graceful degradation**: Linux tries multiple utilities before giving up

The module is production-ready on all four platforms and actively used by MeshAgent for user notifications, consent dialogs, and status alerts. The macOS implementation is particularly elegant, requiring minimal code while providing full functionality through native system APIs.
