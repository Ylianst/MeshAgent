# win-systray.js

Creates system tray icons with context menus for Windows user interface integration. Implements tray icon management with user session context switching, menu item callbacks, and icon lifecycle management through Windows Forms and PowerShell or child process dispatch.

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

**win-systray.js is Windows-only** because:

1. **System Tray** - Windows taskbar notification area feature
2. **Windows Forms** - .NET Windows Forms UI library
3. **User Session Integration** - Session-specific tray icons
4. **PowerShell Dependency** - PowerShell execution context

---

## Functionality

### Core Purpose

win-systray.js manages system tray icons:

1. **Icon Creation** - Create system tray icon with title
2. **Menu Management** - Add context menu items with callbacks
3. **Session Dispatch** - SYSTEM process tray icon in user session
4. **Lifecycle Control** - Remove icon and cleanup

### Main Operations

1. **Tray Creation** - createTrayIcon(trayOptions)
2. **Menu Item Callbacks** - MenuItem click handlers
3. **Icon Removal** - remove() method for cleanup

---

## API Entry Points

### SYSTEM Process (LocalSystem) - Lines 30-79

**Function:** localsystem_createTrayIcon(trayOptions)

**Usage:** When agent runs as SYSTEM, creates tray icon in user session

**Process:**
1. Dispatches to win-dispatcher module (line 39)
2. Creates new process in user session
3. Launches createTrayIcon in child process
4. Child returns thread ID via stdout
5. Handles menu item events from child
6. Provides remove() method to cleanup

**Parameters:**
- user - User session (optional, defaults to console user)

---

### User Process - Lines 81-214

**Function:** createTrayIcon(trayOptions)

**Usage:** When agent runs as user, creates local tray icon

**Parameters - trayOptions object:**
```javascript
{
    title: 'Application Name',
    tsid: null,  // Terminal session ID (optional)
    split: false, // Child process mode
    menuItems: [
        { text: 'Item 1', func: function() { ... } },
        { text: 'Item 2', func: function() { ... } }
    ]
}
```

**Returns:** Promise resolving when tray icon ready

**Process:**
1. Creates child process running PowerShell (line 128)
2. Spawns in user session (line 106)
3. If not split mode:
   - Captures stdout for thread ID (lines 135-150)
   - Monitors for menu clicks
4. If split mode:
   - Splits stdin/stdout streams (lines 155-157)

---

## Menu Item Handling - Lines 41-59, 135-150

**Menu Item Data Flow:**

1. User clicks menu in tray icon
2. PowerShell processes click event
3. Outputs marker to stdout: "<<menuitem:N>>"
4. Parent captures output
5. Calls corresponding menuItem.func()

**Example:**
```javascript
trayOptions.menuItems[i].func.call(trayOptions);
```

---

## PowerShell Tray Icon Implementation - Lines 160-193

**Process:**

1. Loads .NET assemblies:
   - System.Windows.Forms
   - PresentationFramework
   - System.Drawing

2. Creates NotifyIcon (line 171-173):
   - Sets title from environment
   - Sets icon from executable

3. Builds context menu (lines 176-187):
   - Creates MenuItem for each item
   - MenuItem.Add_Click sends marker to stdout

4. Runs message pump (lines 191-192):
   - Keeps PowerShell running until exit

---

## Core Methods

### createTrayIcon(trayOptions) Returns - Line 84

**Return Object Properties:**
- tid - Thread ID of tray icon thread
- connection - IPC connection to tray process
- options - Stored options object
- trayOptions - Stored tray configuration
- remove(tid) - Method to remove icon and cleanup

**Return Promise:**
- Resolves when tray icon displayed
- Rejects if icon creation fails

---

### remove(tid) - Lines 208-212

**Purpose:** Remove tray icon and cleanup

**Parameters:**
- tid - Optional thread ID to post quit message to

**Process:**
1. Posts WM_QUIT message to tray thread (line 203)
2. Removes exit listener (line 211)
3. Cleanup finalized

---

## Constants - Lines 18-21

```javascript
var TH32CS_SNAPTHREAD = 0x00000004;  // Thread snapshot flag
var WM_QUIT = 0x0012;                // Quit window message
var WM_CLOSE = 0x0010;              // Close window message
```

---

## Dispatcher Mode - Lines 39-69

**When SYSTEM Creates Tray for User:**

1. Calls win-dispatcher.dispatch() (line 39)
2. Launches win-systray in child process
3. Child runs as target user (line 39)
4. Returns dispatcher object with:
   - connection - IPC stream
   - Data handler for stdout (lines 44-61)
   - TID detection: "<<TID:N>>"
   - Menu item detection: "<<menuitem:N>>"
5. remove() calls dispatcher.invoke() to cleanup (line 64)

---

## Dependencies

### Module Dependencies - Lines 17-18, 39

**require('promise')**
- Promise constructor for async operations

**require('user-sessions')** - Lines 35, 106, 117
- getUsername() - Get user name for session
- consoleUid() - Get console user session ID
- getProcessOwnerName() - Check current process owner

**require('child_process')** - Line 128
- execFile() - Spawn PowerShell process

**require('win-dispatcher')** - Line 39 (SYSTEM only)
- dispatch() - Create child process IPC

---

## Error Handling

1. **User Not Logged In** (line 123)
   - Throws: 'Cannot set tray icon when a user is not logged in'

2. **Permission Insufficient** (line 115)
   - Throws: 'Insufficient permission to set tray icon'

3. **Icon Creation Failure**
   - Promise rejects with error

---

## Technical Notes

### Thread ID Detection

PowerShell C# code retrieves thread ID:
```powershell
$signature_gctid = "[DllImport(\"kernel32.dll\")]\r\npublic static extern uint GetCurrentThreadId();"
$tid = [MyNameSpace.MyName]::GetCurrentThreadId();
```

### Message Pump

PowerShell's Application.Run() maintains message pump:
- Processes mouse/menu events
- Keeps window responsive
- Exit on WM_QUIT

### Icon Lifecycle

1. Created - NotifyIcon instantiated and visible
2. Running - PowerShell message pump active
3. Removed - WM_QUIT posted to thread
4. Cleanup - Resources released

---

## Usage Examples

### Create Tray Icon

```javascript
var systray = require('win-systray');
var tray = systray.createTrayIcon({
    title: 'My App',
    menuItems: [
        { text: 'Open', func: function() { console.log('Open'); } },
        { text: 'Exit', func: function() { process.exit(0); } }
    ]
});

tray.then(function() {
    console.log('Tray icon created');
});
```

### Remove Icon

```javascript
tray.remove();
```

---

## Summary

win-systray.js provides system tray icon management with sophisticated session handling. The module supports both direct user process creation and SYSTEM process delegation to user sessions. Context menus with callbacks and proper lifecycle management ensure clean integration with Windows user interface.
