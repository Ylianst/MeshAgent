# desktop-lock.js

Desktop session lock utility that triggers the operating system's native screen lock functionality. Enables remote administrators to secure desktop sessions without logging out the user.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via LockWorkStation API
- Linux - Full support via loginctl lock-sessions
- macOS (darwin) - Full support via message-box.lock()
- Throws error on other platforms

**Excluded Platforms:**
- None - All major platforms supported

## Functionality

### Purpose

Provides desktop screen locking for:
- Remote administration security
- Session security without logout
- Automated security policies
- Terminal/console lock triggers

### Key Functions

#### lock() - Lines 20-43 (Lock Desktop Session)

Invokes platform-specific screen lock mechanism.

**Windows Implementation (Lines 24-27):**
```javascript
var child = require('child_process').execFile(
  process.env['windir'] + '\\system32\\cmd.exe',
  ['/c', 'RunDll32.exe user32.dll,LockWorkStation'],
  { type: require('user-sessions').isRoot() ? 1 : undefined }
);
child.waitExit();
```
- Uses `rundll32.exe` to invoke `user32.dll::LockWorkStation`
- Spawn type 1 if running as root/SYSTEM (session redirection)
- Synchronous via `waitExit()`

**Linux Implementation (Lines 28-35):**
```javascript
var child = require('child_process').execFile('/bin/sh', ['sh']);
child.stdin.write('loginctl lock-sessions\nexit\n');
child.waitExit();
if (child.stderr.str != '') { throw ('Failed'); }
```
- Uses `loginctl lock-sessions` (systemd)
- Locks ALL active user sessions
- Throws if stderr output

**macOS Implementation (Lines 36-38):**
```javascript
return require('message-box').lock();
```
- Delegates to message-box module
- Likely uses `pmset displaysleepnow` or CGSession APIs

### Dependencies

- **child_process** - Process execution
- **user-sessions** (Windows) - Root detection
- **message-box** (macOS) - Native lock implementation

### Usage

```javascript
try {
  require('desktop-lock').lock();
  console.log('Desktop locked');
} catch (e) {
  console.log('Lock failed:', e);
}
```

### Technical Notes

**Platform-Specific Behavior:**

**Windows:**
- Locks current interactive session
- If running as SYSTEM, uses spawn type to target logged-in user
- Immediate effect (no user confirmation)

**Linux:**
- Locks ALL sessions simultaneously
- Requires systemd/loginctl
- May not work on non-systemd distributions
- Throws if loginctl fails

**macOS:**
- Delegates to message-box module
- Implementation details hidden
- Likely uses native screen lock APIs

**Error Handling:**
- Linux: Throws 'Failed' if stderr not empty
- Other platforms: Throws 'Not supported on {platform}'
- Windows: Silent failure (waitExit doesn't check exit code)

## Summary

The desktop-lock.js module is a simple (47-line) utility for triggering native screen lock functionality. It provides cross-platform desktop security for remote administration scenarios.

**macOS support:** Full support via message-box.lock() delegation.

**Note:** No unlock functionality (requires user credentials).
