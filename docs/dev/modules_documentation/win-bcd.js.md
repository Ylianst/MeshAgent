# win-bcd.js

Manages Windows Boot Configuration Data (BCD) to modify safe mode settings and restart behavior. This module provides access to boot configuration parameters and Safe Mode service management through the Windows bcdedit utility and registry modifications.

## Platform

**Supported Platforms:**
- Windows (all versions) - Full support

**Excluded Platforms:**
- **macOS** - Not supported (Windows-only)
- **Linux** - Not supported (Windows-only)
- **FreeBSD** - Not supported (Windows-only)

**Exclusion Reasoning:**

Windows-specific module requiring Windows BCD (Boot Configuration Data) system, bcdedit.exe utility, and Windows registry APIs that are unavailable on other platforms.

**Platform Notes:**

**win-bcd.js is Windows-only** because:

1. **Windows-Specific Boot System** - BCD is exclusive to Windows bootloader configuration and has no equivalent on other platforms
2. **System Utility Dependency** - Requires bcdedit.exe system utility available only on Windows
3. **Registry Dependencies** - Uses win-registry module (Windows-specific) for Safe Mode configuration
4. **SYSTEM Privileges Required** - Needs administrative access to modify boot configuration
5. **32-bit Process Limitation** - BCEdit does not work from 32-bit processes on 64-bit Windows; module detects and disables BCD functions accordingly

**Note on 32-bit Agents on 64-bit Windows:**

When running as a 32-bit agent on 64-bit Windows, the module automatically disables BCD editing functions (getKeys, setKey, deleteKey) because bcdedit.exe cannot be executed from a 32-bit process. Safe Mode service management functions remain available since they use registry APIs instead.

---

## Functionality

### Core Purpose

win-bcd.js manages Windows boot configuration data for:

1. **Boot Mode Configuration** - Query and modify safe mode boot settings
2. **BCD Registry Manipulation** - Read and write boot configuration parameters
3. **Safe Mode Service Management** - Enable/disable services for Safe Mode with Networking
4. **System Restart Control** - Trigger system restart with optional delay

### Main Operations

1. **BCD Key Management**
   - getKeys() - Enumerate all BCD configuration entries for current boot
   - getKey(key) - Query specific boot configuration value
   - setKey(key, value) - Modify boot configuration parameter
   - deleteKey(key) - Remove boot configuration entry

2. **Safe Mode Service Control**
   - enableSafeModeService(serviceName) - Add service to Safe Mode with Networking whitelist
   - disableSafeModeService(serviceName) - Remove service from Safe Mode whitelist
   - isSafeModeService(serviceName) - Check if service is whitelisted for Safe Mode

3. **Boot Mode Querying**
   - bootMode property - Read-only property returning current boot mode: 'NORMAL', 'SAFE_MODE', or 'SAFE_MODE_NETWORK'

4. **System Control**
   - restart(delay) - Trigger immediate (delay=0) or delayed system restart

---

## Core Methods

### getKeys() - Lines 25-47

**Purpose:** Enumerate all BCD configuration entries for current boot session

**Returns:** Object with key/value pairs representing boot parameters

**Process:**
1. Executes bcdedit.exe with /enum {current} flag
2. Parses text output into key/value pairs
3. Skips first two header lines
4. Returns object mapping parameter names to values

**Limitations:**
- Not available on 32-bit agents running on 64-bit Windows
- Requires administrator privileges
- Reads only "{current}" (running boot entry)

---

### getKey(key) - Lines 52-55

**Purpose:** Query single BCD configuration parameter

**Parameters:**
- `key` - Parameter name to retrieve

**Returns:** String value of boot parameter, or undefined if not found

**Example:**
```javascript
var safeBootOption = win_bcd.getKey('safeboot');
```

---

### setKey(key, value) - Lines 60-66

**Purpose:** Modify boot configuration parameter

**Parameters:**
- `key` - Parameter name to modify
- `value` - New value for parameter

**Process:**
1. Executes bcdedit.exe with /set {current} key value
2. Waits for command completion

**Note:** Requires reboot for changes to take effect

---

### deleteKey(key) - Lines 71-77

**Purpose:** Remove boot configuration entry

**Parameters:**
- `key` - Parameter name to delete

**Process:**
1. Executes bcdedit.exe with /deletevalue {current} key
2. Removes parameter from boot configuration

---

### enableSafeModeService(serviceName) - Lines 82-85

**Purpose:** Add service to Safe Mode with Networking whitelist

**Parameters:**
- `serviceName` - Windows service name to enable for Safe Mode

**Implementation:**
- Creates registry key at HKLM\SYSTEM\CurrentControlSet\Control\Safeboot\Network\{serviceName}
- Sets default value to 'Service' (registry value type)
- Uses win-registry module for registry operations

**Example:**
```javascript
win_bcd.enableSafeModeService('SSH');
```

---

### disableSafeModeService(serviceName) - Lines 101-110

**Purpose:** Remove service from Safe Mode whitelist

**Parameters:**
- `serviceName` - Service name to disable for Safe Mode

**Implementation:**
- Deletes registry key from HKLM\SYSTEM\CurrentControlSet\Control\Safeboot\Network\{serviceName}
- Wrapped in try/catch for robust error handling

---

### isSafeModeService(serviceName) - Lines 90-96

**Purpose:** Check if service is currently whitelisted for Safe Mode with Networking

**Parameters:**
- `serviceName` - Service name to check

**Returns:** Boolean - true if service is in Safe Mode whitelist, false otherwise

**Implementation:**
- Queries registry at HKLM\SYSTEM\CurrentControlSet\Control\Safeboot\Network\{serviceName}
- Checks if default value equals 'Service'

---

### bootMode Property - Lines 145-168

**Purpose:** Read-only property returning system's next boot configuration

**Returns:** String - One of:
- 'NORMAL' - Standard boot mode
- 'SAFE_MODE' - Safe Mode without networking
- 'SAFE_MODE_NETWORK' - Safe Mode with networking

**Implementation:**
- Queries OptionValue from HKLM\SYSTEM\CurrentControlSet\Control\Safeboot\Option
- Maps registry value: 2 = SAFE_MODE_NETWORK, other = SAFE_MODE, exception = NORMAL
- Returns 'NORMAL' if registry not found

---

### restart(delay) - Lines 115-121

**Purpose:** Initiate system restart with optional delay

**Parameters:**
- `delay` - Seconds to wait before restart (optional, defaults to 0 for immediate)

**Process:**
1. Executes shutdown.exe /r (restart flag)
2. /t parameter specifies delay in seconds
3. Waits for command completion

**Example:**
```javascript
win_bcd.restart(60);  // Restart after 60 seconds
win_bcd.restart();    // Immediate restart
```

---

## Dependencies

### Windows System Utilities - Lines 28, 62, 73, 117

**bcdedit.exe** - Windows Boot Configuration Editor utility
- Location: %windir%\System32\bcdedit.exe
- Purpose: Enumerate, query, and modify BCD entries
- Requires: Administrator privileges
- Lines 28, 62, 73: spawn three separate child processes

**shutdown.exe** - Windows shutdown control utility
- Location: %windir%\System32\shutdown.exe
- Purpose: Restart system with delay option
- Requires: Administrator privileges
- Line 117: spawns restart command

### Module Dependencies - Lines 84, 92, 105, 152

**require('child_process')** - Line 28, 62, 73, 117
- execFile() method to spawn system utilities
- stdout/stderr event handlers for output capture
- waitExit() for synchronous completion

**require('win-registry')** - Line 84, 92, 105, 151
- HKEY constants for registry paths
- WriteKey() to create Safe Mode service registry entries
- QueryKey() to read boot and Safe Mode configuration
- DeleteKey() to remove service entries

**require('os')** - Line 123
- arch() method to detect 32-bit vs 64-bit process

**require('_GenericMarshal')** - Line 123
- PointerSize property to determine 32-bit (4) vs 64-bit (8) architecture

---

## Platform Compatibility

### Architecture Detection - Lines 123-141

The module includes special handling for 32-bit agents on 64-bit systems:

```javascript
if (require('_GenericMarshal').PointerSize == 4 && require('os').arch() == 'x64')
{
    // 32-bit process on 64-bit Windows
    // BCD functions disabled, Safe Mode functions only
    module.exports = {
        enableSafeModeService, disableSafeModeService,
        restart, isSafeModeService
    };
}
else
{
    // 64-bit process or 32-bit Windows
    // All functions available
    module.exports = {
        getKeys, setKey, deleteKey, enableSafeModeService,
        disableSafeModeService, getKey, restart, isSafeModeService,
        bootMode  // Property only on non-32-bit-on-64-bit systems
    };
}
```

**Reason for Limitation:** bcdedit.exe redirects 32-bit process calls to 32-bit version which cannot properly access 64-bit BCD store. Registry-based functions work fine from 32-bit processes.

---

## Technical Notes

### Registry Paths Used

1. **Boot Configuration:**
   - `HKLM\SYSTEM\CurrentControlSet\Control\Safeboot\Option\OptionValue` - Next boot mode
   - `HKLM\SYSTEM\CurrentControlSet\Control\Safeboot\Network\{serviceName}` - Safe Mode services

2. **System Control Set:**
   - Always uses "CurrentControlSet" not hardcoded set number
   - Dynamically resolves via registry

### Process Synchronization

- All BCD operations use `child.waitExit()` for synchronous execution
- stdout captured in `child.stdout.str` property
- stderr ignored for most operations

### Safe Mode Service Registry Format

- Registry key creates service entry for Safe Mode with Networking
- Default value must be exactly string 'Service'
- Creating key with default 'Service' value registers service for Safe Mode

---

## Usage Examples

### Enabling Service for Safe Mode

```javascript
var win_bcd = require('win-bcd');

// Add SSH service to Safe Mode whitelist
try {
    win_bcd.enableSafeModeService('SSH');
    console.log('SSH enabled for Safe Mode');
} catch(e) {
    console.error('Failed to enable SSH:', e);
}
```

### Checking Boot Mode

```javascript
var win_bcd = require('win-bcd');

// Check current boot configuration
console.log('Next boot mode:', win_bcd.bootMode);

// Possible values:
// - 'NORMAL'
// - 'SAFE_MODE'
// - 'SAFE_MODE_NETWORK'
```

### Managing Service Whitelist

```javascript
var win_bcd = require('win-bcd');

// Check if service is whitelisted
if (win_bcd.isSafeModeService('MyService')) {
    console.log('Service is enabled for Safe Mode');

    // Disable it if needed
    win_bcd.disableSafeModeService('MyService');
}
```

### System Restart with Delay

```javascript
var win_bcd = require('win-bcd');

// Schedule restart in 30 seconds
win_bcd.restart(30);
console.log('System will restart in 30 seconds');
```

---

## Error Handling

### Common Errors

1. **Access Denied (32-bit on 64-bit)**
   - BCD functions unavailable
   - Solution: Use Safe Mode functions or run 64-bit agent

2. **Administrative Privileges Required**
   - Error from bcdedit.exe or shutdown.exe
   - Solution: Run agent with elevated privileges

3. **Registry Key Not Found**
   - Safe Mode function on systems where Safeboot key doesn't exist
   - Solution: Check win_bcd.bootMode property for exception handling

---

## Security Considerations

1. **Administrative Access** - All BCD modifications require SYSTEM or Administrator privileges
2. **Audit Logging** - Registry changes logged in Windows Event Log
3. **Boot Configuration Impact** - Changes affect system boot behavior on next restart
4. **Service Whitelist** - Only affects Safe Mode with Networking boot, not regular Safe Mode

---

## Summary

win-bcd.js provides comprehensive Windows boot configuration management including BCD manipulation and Safe Mode service control. The module intelligently handles 32-bit process limitations on 64-bit Windows while providing full functionality on compatible configurations. Core operations include boot mode detection, service whitelisting for Safe Mode, and system restart scheduling via Windows utilities.
