# win-deskutils.js

Provides Windows desktop utilities for managing wallpaper and mouse trail accessibility features. Implements user session dispatching to apply desktop settings to specific user sessions through Windows API SystemParametersInfo calls and child process execution with session switching.

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

**win-deskutils.js is Windows-only** because:

1. **SystemParametersInfoA API** - Windows user32.dll function not available on other platforms
2. **User Session Management** - Windows session ID (tsid) concept specific to Windows
3. **Desktop Context Switching** - Requires Windows user session isolation
4. **User-Sessions Module** - Windows-specific session management

---

## Functionality

### Core Purpose

win-deskutils.js manages Windows user desktop settings:

1. **Wallpaper Management** - Get/set desktop background image path
2. **Mouse Trail Accessibility** - Enable/disable mouse trail feature
3. **User Session Dispatching** - Apply settings to specific logged-in user sessions
4. **SYSTEM Process Handling** - Detect and dispatch from SYSTEM context

### Main Operations

1. **Wallpaper Operations** - background.get(tsid), background.set(path, tsid)
2. **Mouse Trail Operations** - mouse.getTrails(tsid), mouse.setTrails(value, tsid)
3. **Session Dispatch** - dispatch(parent, method, args) for child process operations

---

## Architecture

### Session Dispatching Model

Since SYSTEM process cannot directly access user desktop settings, the module implements process redirection:

1. **Parent Process (SYSTEM or Administrator)** - Calls module functions
2. **Dispatch Detection** - Checks if current process is SYSTEM (tsid == 0)
3. **Child Process Spawning** - Spawns new process in target user session
4. **Session Execution** - Child executes operation in target user context
5. **Result Return** - Returns result via stdout/stderr

---

## Core Methods

### background.get(tsid) - Lines 102-116

**Purpose:** Get current desktop wallpaper path

**Parameters:**
- `tsid` - Target session ID (null = current session, 0 = SYSTEM, >0 = user session)

**Returns:** String path to wallpaper file

**Process:**
1. If tsid not undefined/null, calls sessionDispatch() to execute in target session (line 107)
2. Creates 1024-byte variable for wallpaper path (line 109)
3. Calls SystemParametersInfoA(SPI_GETDESKWALLPAPER) (line 110)
4. Returns String property from result (line 115)

**Error Handling:**
- Throws: 'Error occured trying to fetch wallpaper' if SystemParametersInfoA returns 0

---

### background.set(path, tsid) - Lines 121-135

**Purpose:** Set desktop wallpaper

**Parameters:**
- `path` - Full path to wallpaper image file
- `tsid` - Target session ID (null = current session)

**Returns:** undefined

**Process:**
1. If tsid not undefined/null, calls sessionDispatch() (line 126)
2. Creates variable from path string (line 128)
3. Calls SystemParametersInfoA(SPI_SETDESKWALLPAPER) (line 129)
4. Silently returns on success (line 134)

**Error Handling:**
- Throws: 'Error occured trying to set wallpaper' if SystemParametersInfoA returns 0

---

### mouse.getTrails(tsid) - Lines 176-190

**Purpose:** Get mouse trail accessibility setting

**Parameters:**
- `tsid` - Target session ID

**Returns:** Integer trail count (0 or 1 = disabled, >1 = number of cursors)

**Process:**
1. If tsid not undefined/null, dispatches to target session (line 181)
2. Creates 4-byte variable for result (line 183)
3. Calls SystemParametersInfoA(SPI_GETMOUSETRAILS) (line 184)
4. Reads and returns UInt32LE value (line 189)

---

### mouse.setTrails(value, tsid) - Lines 158-170

**Purpose:** Set mouse trail accessibility feature

**Parameters:**
- `value` - Trail count (0 or 1 = disable, >1 = number of cursors to render)
- `tsid` - Target session ID

**Returns:** undefined

**Process:**
1. If tsid not undefined/null, dispatches to target session (line 163)
2. Calls SystemParametersInfoA(SPI_SETMOUSETRAILS, value) (line 165)
3. Silently returns on success (line 169)

**Error Handling:**
- Throws: 'Error occured trying to fetch wallpaper' (incorrect error message in code)

---

### sessionDispatch(tsid, parent, method, args) - Lines 40-97

**Purpose:** Redirect desktop operation to specific user session

**Parameters:**
- `tsid` - Target session ID (null = use MeshAgent._tsid, 0 = current, >0 = specified)
- `parent` - Object name in module ('background', 'mouse')
- `method` - Method to call ('get', 'set', 'getTrails', 'setTrails')
- `args` - Array of arguments for method

**Returns:** Result from child process or throws exception

**Process:**
1. Detects current process type (line 46):
   - stype = 0 if SYSTEM (tsid == 0)
   - stype = 1 if user process
2. Determines target session (lines 66-77):
   - If stype == 1 (user process running deskutils):
     - Try to use MeshAgent._tsid if available (line 71)
     - Otherwise use provided tsid
3. Spawns child process (line 82):
   - Base64-encodes win-deskutils module
   - Creates program string to call dispatch()
   - Executes in specified user session via execFile()
4. Captures stdout (line 84-85):
   - Accumulates output in child.stdout.str
5. Waits for child completion (line 88)
6. Returns stdout if exit code 0 (line 91):
   - Success case
7. Throws stdout if exit code != 0 (line 95):
   - Error case from child

**Child Process Invocation (line 81):**
```javascript
var prog = "try { addModule('win-deskutils', process.env['win_deskutils']);} catch (x) { }
var x;try{x=require('win-deskutils').dispatch('" + parent + "', '" + method + "', " +
JSON.stringify(args) + ");console.log(x);}catch(z){console.log(z);process.exit(1);}process.exit(0);";
```

---

### dispatch(parent, method, args) - Lines 140-151

**Purpose:** Execute desktop operation (called from child process)

**Parameters:**
- `parent` - Object name ('background', 'mouse')
- `method` - Method name ('get', 'set', 'getTrails', 'setTrails')
- `args` - Arguments array

**Returns:** Result of method call

**Process:**
1. Calls this[parent][method]() with args (line 144)
2. console.log() result for parent capture
3. Error handling (lines 145-150):
   - Catches exceptions and logs them
   - Throws 'Error occured trying to dispatch'

---

## Windows API Constants - Lines 28-31

```javascript
const SPI_GETDESKWALLPAPER = 0x0073;    // Get wallpaper path
const SPI_SETDESKWALLPAPER = 0x0014;    // Set wallpaper path
const SPI_GETMOUSETRAILS = 0x005E;      // Get mouse trail setting
const SPI_SETMOUSETRAILS = 0x005D;      // Set mouse trail setting
```

---

## Dependencies

### Native DLL - Line 34-35

**require('_GenericMarshal')** - Line 33
- CreateNativeProxy('user32.dll') - Load User32 DLL
- CreateMethod('SystemParametersInfoA') - Get wallpaper/mouse settings API
- CreateVariable() - Memory buffer management

### Module Dependencies - Lines 46, 68, 82

**require('user-sessions')** - Lines 46, 68, 82
- getProcessOwnerName(pid) - Get SYSTEM/user context of process
- consoleUid() - Get console user session ID
- getUsername(tsid) - Get username for session

**require('child_process')** - Line 82
- execFile() - Spawn child process in user session

---

## Module Exports - Lines 192-194

```javascript
module.exports = {
    background: { get: background_get, set: background_set },
    mouse: { getTrails: mousetrails_get, setTrails: mousetrails_set },
    dispatch: dispatch
};
```

---

## Technical Notes

### User Session Model

Windows supports multiple user sessions:
- Session 0: System/Services
- Session 1+: Interactive user sessions

Desktop settings are session-specific:
- Each user session has its own wallpaper
- Mouse trail setting is per-session
- SYSTEM cannot directly access user session settings

### Process Type Detection (Line 46)

```javascript
var stype = require('user-sessions').getProcessOwnerName(process.pid).tsid == 0 ? 1 : 0;
```

- tsid == 0 means SYSTEM process → stype = 1 (dispatch to user)
- tsid != 0 means user process → stype = 0 (no dispatch needed)

### Spawn Types (Lines 56-63)

Comments document spawn type enumeration:
- ILibProcessPipe_SpawnTypes_DEFAULT (0) - Default process
- ILibProcessPipe_SpawnTypes_USER (1) - User session (auto-select logged-in user)
- ILibProcessPipe_SpawnTypes_SPECIFIED_USER (5) - Specific user by tsid

### Module Re-loading in Child

Child process includes environment variable with module source:
```javascript
env: { win_deskutils: getJSModule('win-deskutils') }
```

Allows child to load module without file system dependency.

---

## Error Handling

1. **SystemParametersInfoA Failure**
   - Returns 0 on Windows API error
   - Module throws descriptive error

2. **Session Dispatch Failure**
   - Child process exit code != 0
   - stdout contains error message
   - Throws stdout as error message

3. **Dispatch Execution Error**
   - Caught in dispatch() try/catch
   - Logs error and throws generic message

---

## Platform Compatibility

### Wallpaper Paths

- Must be full filesystem path: "C:\\Users\\...\\wallpaper.jpg"
- Supports common formats: .bmp, .jpg, .png
- Empty string disables wallpaper

### Mouse Trail Settings

- 0 or 1: Disabled
- 2-9: Number of cursors rendered
- Platform-dependent valid range

---

## Usage Examples

### Get Current Wallpaper

```javascript
var deskutils = require('win-deskutils');
var path = deskutils.background.get();
console.log('Current wallpaper:', path);
```

### Set Wallpaper for User Session

```javascript
var deskutils = require('win-deskutils');
var userTsid = 1;  // First interactive session
deskutils.background.set('C:\\Windows\\System32\\themes\\light.jpg', userTsid);
```

### Enable Mouse Trails

```javascript
var deskutils = require('win-deskutils');
deskutils.mouse.setTrails(5);  // 5 cursor trail
```

---

## Summary

win-deskutils.js manages Windows desktop settings (wallpaper and mouse trails) with sophisticated session dispatching to apply settings to specific user sessions. The module detects process context and automatically redirects operations to appropriate user sessions when needed, providing a unified interface for desktop customization across SYSTEM and user processes.
