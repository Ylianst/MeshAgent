# win-utils.js

Provides Windows utility functions for system configuration management. Implements taskbar settings manipulation through registry access with Windows shell integration.

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

**win-utils.js is Windows-only** because:

1. **Windows Registry** - Uses win-registry module (Windows-specific)
2. **Windows Explorer** - Taskbar functionality tied to explorer.exe
3. **Shell Integration** - Windows-specific shell configuration

---

## Functionality

### Core Purpose

win-utils.js manages Windows system settings:

1. **Taskbar Configuration** - Manage taskbar behavior
2. **User Settings** - Per-user configuration via registry
3. **Shell Integration** - Restart Windows Explorer when needed

### Main Operations

1. **Taskbar Auto-hide** - taskBar.autoHide(tsid, value)

---

## Core Methods

### taskBar.autoHide(tsid, value) - Lines 31-58

**Purpose:** Get or set Windows taskbar auto-hide behavior

**Parameters:**
- `tsid` - Terminal session ID (user session to configure)
- `value` - Optional boolean (undefined = query only)

**Returns:** Boolean - true if auto-hide enabled, false if not

**Query Mode (value undefined):**
1. Gets user key from domain/username (lines 34-35)
2. Queries registry at:
   - HKEY_USERS\{userkey}\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3
   - Value: Settings
3. Returns byte 8 == 3 (auto-hide enabled flag)

**Set Mode (value specified):**
1. Gets current registry value
2. Sets byte 8 to:
   - 3 if value == true (auto-hide)
   - 2 if value == false (always show)
3. Writes updated registry (line 47)
4. Kills explorer.exe to apply changes (line 54)
5. Recursively calls autoHide() to verify and return new state

**Dependencies:**
- require('user-sessions') - getDomain(), getUsername()
- require('win-registry') - HKEY, QueryKey(), WriteKey()
- require('process-manager') - getProcessEx() for explorer

---

## Registry Structure

### Taskbar Settings Location

```
HKEY_USERS\{SID}\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3
```

**Settings Value:**
- REG_BINARY data
- Byte 8 controls auto-hide:
  - 0x02 = Always show
  - 0x03 = Auto-hide

---

## Dependencies

### Module Dependencies - Line 21

**require('win-registry')** - Line 21, 39, 45, 47
- HKEY.Users - Registry hive
- usernameToUserKey() - Convert domain\user to SID
- QueryKey() - Read registry value
- WriteKey() - Write registry value

**require('user-sessions')** - Lines 33, 34
- getDomain(tsid) - Get domain name
- getUsername(tsid) - Get user name

**require('process-manager')** - Line 50
- getProcessEx() - Find process by name

**require('process')** - Line 54
- kill() - Terminate process

---

## Error Handling

- No explicit error handling in autoHide()
- Registry exceptions propagate to caller
- Explorer.exe kill may fail silently (Windows restarts it automatically)

---

## Technical Notes

### Explorer.exe Restart

Windows automatically restarts explorer if killed:
- No explicit restart needed
- Taskbar changes take effect immediately
- Icon/window states preserved

### Per-User Configuration

Registry changes isolated to specific user:
- Different users can have different settings
- Configuration tied to terminal session ID (tsid)
- Multiple sessions supported

---

## Usage Examples

### Query Taskbar State

```javascript
var utils = require('win-utils');
var tsid = 1;  // User session
var isAutoHide = utils.taskBar.autoHide(tsid);
console.log('Auto-hide:', isAutoHide);
```

### Enable Taskbar Auto-hide

```javascript
var utils = require('win-utils');
utils.taskBar.autoHide(tsid, true);
```

### Disable Auto-hide

```javascript
utils.taskBar.autoHide(tsid, false);
```

---

## Summary

win-utils.js provides Windows utility functions for taskbar configuration. The module manages auto-hide settings through registry manipulation with automatic shell restart when needed, enabling per-user taskbar customization across multiple sessions.
