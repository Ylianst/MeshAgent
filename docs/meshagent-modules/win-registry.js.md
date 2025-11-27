# win-registry.js

Windows Registry access module that provides comprehensive read/write capabilities for the Windows Registry. Enables direct manipulation of registry keys and values across all registry hives with support for multiple data types and advanced features like user SID resolution.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support

**Excluded Platforms:**
- **macOS** - Implicitly excluded (no platform check, module will fail on instantiation)
- **Linux** - Implicitly excluded (no platform check, module will fail on instantiation)
- **FreeBSD** - Implicitly excluded (no platform check, module will fail on instantiation)
- **All non-Windows platforms** - Implicitly excluded

**Exclusion Reasoning:**

The module has **no explicit platform check** but is fundamentally Windows-only. It will fail immediately upon instantiation on non-Windows platforms when attempting to load Windows-specific DLLs:

**Lines 44-58:** Module initialization loads Windows-exclusive DLLs:
```javascript
this._marshal = require('_GenericMarshal');
this._Kernel32 = this._marshal.CreateNativeProxy('Kernel32.dll');
this._AdvApi = this._marshal.CreateNativeProxy('Advapi32.dll');
```

**Why macOS/Linux are excluded:**

1. **Windows Registry Doesn't Exist on Other Platforms**
   - The Windows Registry is a Windows-specific hierarchical database
   - macOS uses plist files, defaults system, and configuration files
   - Linux uses configuration files in /etc, ~/.config, and other directories
   - No equivalent data structure exists on other platforms

2. **Windows-Specific DLL Dependencies**
   - **Advapi32.dll** - Advanced Windows API containing all Registry functions
   - **Kernel32.dll** - Windows core system DLL for time conversion
   - These DLLs only exist on Windows systems

3. **Windows Registry Architecture**
   - Uses Windows-specific hive structure (HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, etc.)
   - Registry key paths use Windows backslash notation
   - Access control via Windows security descriptors
   - Data types are Windows-specific (REG_SZ, REG_DWORD, REG_MULTI_SZ, etc.)

4. **Windows Security Integration**
   - Lines 293-366: `usernameToUserKey()` resolves Windows usernames to registry Security Identifiers (SIDs)
   - Relies on Windows domain/user model
   - Queries Windows SAM (Security Account Manager) database
   - No equivalent on macOS/Linux

**macOS Alternative:** Use `defaults` command, plist manipulation, or NSUserDefaults API

**Linux Alternative:** Direct configuration file parsing, dconf/gsettings, or systemd configuration

## Functionality

### Core Methods

#### QueryKey(hkey, path, key) - Lines 60-168

Queries registry keys and values, supporting both single value retrieval and key enumeration.

**Parameters:**
- `hkey` - Registry hive handle (e.g., `this.HKEY.LocalMachine`)
- `path` - Registry key path (e.g., `'SOFTWARE\\Microsoft\\Windows'`)
- `key` - Optional value name to query (omit to enumerate key)

**Returns:**

When querying a specific value:
- **REG_DWORD**: Returns JavaScript number (32-bit unsigned integer)
- **REG_DWORD_BIG_ENDIAN**: Returns JavaScript number (big-endian 32-bit)
- **REG_SZ**: Returns UTF-8 string
- **REG_EXPAND_SZ**: Returns UTF-8 string (environment variables NOT expanded)
- **REG_BINARY**: Returns Buffer object with `_data` and `_type` properties

When enumerating a key (no `key` parameter):
```javascript
{
    subkeys: ['SubKey1', 'SubKey2', ...],     // Array of subkey names
    values: ['Value1', 'Value2', ...],         // Array of value names
    default: <value>                           // Default value if set
}
```

**Example Usage:**
```javascript
var reg = require('win-registry');

// Read a specific value
var version = reg.QueryKey(reg.HKEY.LocalMachine,
    'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion',
    'CurrentVersion');

// Enumerate a key
var windowsKey = reg.QueryKey(reg.HKEY.LocalMachine,
    'SOFTWARE\\Microsoft\\Windows');
console.log('Subkeys:', windowsKey.subkeys);
console.log('Values:', windowsKey.values);
```

**Error Handling:**
- **Line 75:** Throws exception if key path cannot be opened
- **Line 114:** Throws 'Not Found' if specific value doesn't exist
- **Line 144:** Throws exception if key enumeration fails

---

#### QueryKeyLastModified(hkey, path, key) - Lines 171-212

Retrieves the last modification timestamp of a registry key.

**Parameters:**
- `hkey` - Registry hive handle
- `path` - Registry key path
- `key` - Value name (currently unused in implementation)

**Returns:**
- JavaScript Date object representing last write time

**Implementation Details:**
- **Lines 203-206:** Uses `RegQueryInfoKeyW()` to get `lastWriteTime` (FILETIME format)
- **Line 210:** Converts Windows FILETIME to SYSTEMTIME via `FileTimeToSystemTime()`
- **Line 211:** Converts to JavaScript Date via `fs.convertFileTime()`

**Example Usage:**
```javascript
var lastModified = reg.QueryKeyLastModified(
    reg.HKEY.LocalMachine,
    'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
);
console.log('Last modified:', lastModified.toISOString());
```

---

#### WriteKey(hkey, path, key, value) - Lines 214-263

Creates or updates registry keys and values with automatic type detection.

**Parameters:**
- `hkey` - Registry hive handle
- `path` - Registry key path (created if doesn't exist)
- `key` - Value name (null for default value)
- `value` - Value to write (type auto-detected)

**Automatic Type Mapping:**

| JavaScript Type | Registry Type | Implementation |
|----------------|---------------|----------------|
| `boolean` | REG_DWORD | Lines 235-239: true→1, false→0 |
| `number` | REG_DWORD | Lines 240-244: 32-bit unsigned |
| `string` | REG_SZ | Lines 245-248: Wide character string |
| `Buffer` | REG_BINARY | Lines 249-253: Raw binary data |

**Key Creation:**
- **Line 220:** Uses `RegCreateKeyExW()` which creates key if it doesn't exist
- Opens with `KEY_WRITE (0x20006)` access rights

**Example Usage:**
```javascript
// Write string
reg.WriteKey(reg.HKEY.LocalMachine,
    'SOFTWARE\\MyApp',
    'InstallPath',
    'C:\\Program Files\\MyApp');

// Write number
reg.WriteKey(reg.HKEY.LocalMachine,
    'SOFTWARE\\MyApp',
    'Version',
    100);

// Write boolean
reg.WriteKey(reg.HKEY.LocalMachine,
    'SOFTWARE\\MyApp',
    'Enabled',
    true);

// Write binary data
var buffer = Buffer.from([0x01, 0x02, 0x03, 0x04]);
reg.WriteKey(reg.HKEY.LocalMachine,
    'SOFTWARE\\MyApp',
    'BinaryData',
    buffer);
```

**Error Handling:**
- **Line 220-223:** Throws exception if key cannot be created/opened
- **Line 257-261:** Throws exception if value cannot be written

---

#### DeleteKey(hkey, path, key) - Lines 266-290

Deletes registry keys or values.

**Parameters:**
- `hkey` - Registry hive handle
- `path` - Registry key path
- `key` - Optional value name (omit to delete entire key)

**Behavior:**

**Delete Entire Key** (when `key` is null/undefined):
- **Line 270:** Uses `RegDeleteKeyW()` to delete key and all subkeys
- **WARNING:** Deletes recursively on modern Windows (Vista+)

**Delete Specific Value** (when `key` is provided):
- **Lines 277-288:** Opens key, deletes named value with `RegDeleteValueW()`
- Preserves the key structure, only removes the value

**Example Usage:**
```javascript
// Delete a specific value
reg.DeleteKey(reg.HKEY.LocalMachine,
    'SOFTWARE\\MyApp',
    'OldSetting');

// Delete entire key
reg.DeleteKey(reg.HKEY.LocalMachine,
    'SOFTWARE\\MyApp\\TempData',
    null);
```

**Error Handling:**
- **Line 270-273:** Throws exception if key deletion fails
- **Line 279-282:** Throws exception if key cannot be opened for value deletion
- **Line 283-287:** Throws exception with error code if value deletion fails

---

#### usernameToUserKey(user) - Lines 295-366

Advanced method that resolves Windows usernames to their registry Security Identifier (SID) keys in HKEY_USERS.

**Parameters:**
- `user` - String username OR object `{ user: 'username', domain: 'DOMAIN' }`

**Returns:**
- Registry key path (SID) in HKEY_USERS (e.g., `'S-1-5-21-...-1001'`)

**Algorithm (Multi-Stage Lookup):**

**Stage 1: Domain Resolution** (Lines 306-315)
- Attempts to get current computer domain via WMI
- Query: `Win32_ComputerSystem.Name`
- Falls back if WMI unavailable

**Stage 2: SID Lookup via SAM Database** (Lines 318-337)
- **Line 323:** Queries `HKEY_USERS\SAM\SAM\Domains\Account\Users\Names\<username>`
- Retrieves RID (Relative ID) from default value's type field
- Enumerates `HKEY_USERS` for SID ending with `-<RID>`
- Validates domain matches via `Volatile Environment\USERDOMAIN`

**Stage 3: Brute-Force Enumeration** (Lines 343-364)
- Fallback if SAM lookup fails
- Enumerates all user SIDs in HKEY_USERS
- Filters: SIDs with 5+ components, excludes `*_Classes` keys
- Matches: `Volatile Environment\USERNAME` and `USERDOMAIN`

**Example Usage:**
```javascript
// Simple username
var userKey = reg.usernameToUserKey('JohnDoe');
// Returns: 'S-1-5-21-1234567890-1234567890-1234567890-1001'

// Domain user
var userKey = reg.usernameToUserKey({
    user: 'JohnDoe',
    domain: 'CORPORATE'
});

// Use to access user registry
var userDesktop = reg.QueryKey(reg.HKEY.Users,
    userKey + '\\Control Panel\\Desktop',
    'Wallpaper');
```

**Error Handling:**
- **Line 365:** Throws 'Unable to determine HKEY_USERS key' if user not found
- Silently catches exceptions during lookup stages (tries all methods)

**Use Case:**
- Access per-user registry settings when user is not currently logged in
- Modify user profiles remotely
- Enumerate settings for all users on system

---

### Registry Hive Constants

**Line 58:** Predefined registry hive handles:

```javascript
this.HKEY = {
    Root: 0x80000000,              // HKEY_CLASSES_ROOT
    CurrentUser: 0x80000001,       // HKEY_CURRENT_USER
    LocalMachine: 0x80000002,      // HKEY_LOCAL_MACHINE
    Users: 0x80000003              // HKEY_USERS
}
```

**Standard Windows Hives:**
- **HKEY_CLASSES_ROOT** - File associations and COM registration
- **HKEY_CURRENT_USER** - Current logged-in user settings
- **HKEY_LOCAL_MACHINE** - System-wide configuration
- **HKEY_USERS** - All user profiles

**Note:** HKEY_PERFORMANCE_DATA and HKEY_CURRENT_CONFIG are not exposed

---

### Registry Data Types

**Lines 25-39:** Registry value type constants (Windows standard):

```javascript
var KEY_DATA_TYPES = {
    REG_NONE: 0,                    // No value type
    REG_SZ: 1,                      // String
    REG_EXPAND_SZ: 2,               // Expandable string (with %VAR%)
    REG_BINARY: 3,                  // Binary data
    REG_DWORD: 4,                   // 32-bit number
    REG_DWORD_BIG_ENDIAN: 5,        // 32-bit number (big-endian)
    REG_LINK: 6,                    // Symbolic link
    REG_MULTI_SZ: 7,                // Multiple strings
    REG_RESOURCE_LIST: 8,           // Resource list
    REG_FULL_RESOURCE_DESCRIPTOR: 9,// Full resource descriptor
    REG_RESOURCE_REQUIREMENTS_LIST: 10, // Resource requirements
    REG_QWORD: 11                   // 64-bit number
}
```

**Currently Handled Types:**
- REG_SZ, REG_EXPAND_SZ - Lines 96-98
- REG_DWORD - Line 90-92
- REG_DWORD_BIG_ENDIAN - Line 93-95
- REG_BINARY and others - Lines 100-105 (returned as Buffer)

**Not Yet Implemented:**
- REG_MULTI_SZ parsing (would require null-separator splitting)
- REG_QWORD reading (64-bit integers)
- Environment variable expansion for REG_EXPAND_SZ

## Dependencies

### Native Module Dependencies

#### _GenericMarshal (Line 44)

```javascript
this._marshal = require('_GenericMarshal');
```

**Purpose:** FFI (Foreign Function Interface) library for calling Windows DLLs

**Capabilities:**
- Enables JavaScript to call native Windows DLL functions
- Provides memory marshaling between JavaScript and native code
- Handles pointer arithmetic and buffer management
- Type conversion between JavaScript and C types
- Wide character (UTF-16) string support

**Source:** `/microscript/ILibDuktape_GenericMarshal.c`

---

### Windows System DLL Dependencies

#### Kernel32.dll (Lines 45-46)

```javascript
this._Kernel32 = this._marshal.CreateNativeProxy('Kernel32.dll');
this._Kernel32.CreateMethod('FileTimeToSystemTime');
```

**Methods Used:**
- **FileTimeToSystemTime()** - Line 46
  - **Purpose:** Converts Windows FILETIME structure to SYSTEMTIME
  - **Used by:** `QueryKeyLastModified()` for timestamp conversion
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-filetimetosystemtime

**Purpose:** Core Windows system functions for time conversion

---

#### Advapi32.dll (Lines 47-57) - Advanced Windows Services

```javascript
this._AdvApi = this._marshal.CreateNativeProxy('Advapi32.dll');
```

**All registry operations** are performed through this DLL. Methods used:

**Key Creation and Opening:**
- **RegCreateKeyExW()** - Line 48
  - **Purpose:** Creates or opens registry key (Wide character version)
  - **Used by:** `WriteKey()` - Line 220
  - **Flags:** Creates if doesn't exist, opens if exists
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw

- **RegOpenKeyExW()** - Line 51
  - **Purpose:** Opens existing registry key with specific access rights
  - **Used by:** `QueryKey()` - Line 73, `DeleteKey()` - Line 279
  - **Access Rights:** KEY_QUERY_VALUE (0x0001), KEY_ENUMERATE_SUB_KEYS (0x0008)
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw

**Key Enumeration:**
- **RegEnumKeyExW()** - Line 49
  - **Purpose:** Enumerates subkeys of an open registry key
  - **Used by:** `QueryKey()` - Line 148
  - **Returns:** Subkey name and last write time
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw

- **RegEnumValueW()** - Line 50
  - **Purpose:** Enumerates values within a registry key
  - **Used by:** `QueryKey()` - Line 157
  - **Returns:** Value name
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew

**Value Reading:**
- **RegQueryValueExW()** - Line 53
  - **Purpose:** Retrieves type and data for a registry value
  - **Used by:** `QueryKey()` - Lines 79, 82
  - **Returns:** Value type and data
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw

**Key Information:**
- **RegQueryInfoKeyW()** - Line 52
  - **Purpose:** Retrieves detailed information about a registry key
  - **Used by:** `QueryKey()` - Line 141, `QueryKeyLastModified()` - Line 203
  - **Returns:** Subkey count, value count, last write time, sizes
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw

**Value Writing:**
- **RegSetValueExW()** - Line 57
  - **Purpose:** Sets data and type for a registry value
  - **Used by:** `WriteKey()` - Line 257
  - **Supports:** All registry data types
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw

**Deletion:**
- **RegDeleteKeyW()** - Line 55
  - **Purpose:** Deletes a registry key and all subkeys
  - **Used by:** `DeleteKey()` - Line 270
  - **Warning:** Recursive deletion on Windows Vista+
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletekeyw

- **RegDeleteValueW()** - Line 56
  - **Purpose:** Removes a named value from a registry key
  - **Used by:** `DeleteKey()` - Line 283
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletevaluew

**Resource Cleanup:**
- **RegCloseKey()** - Line 54
  - **Purpose:** Closes an open registry key handle
  - **Used by:** All methods after operations complete
  - **Critical:** Prevents handle leaks
  - **Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey

---

### Conditional Dependencies

#### win-wmi (Line 309)

```javascript
domain = require('win-wmi').query('ROOT\\CIMV2',
    "SELECT * FROM Win32_ComputerSystem",
    ['Name'])[0].Name;
```

**Used by:** `usernameToUserKey()` for domain resolution

**Purpose:** Queries Windows Management Instrumentation to get computer domain name

**Fallback:** Silently continues if WMI unavailable (lines 313-315)

**WMI Query Details:**
- **Namespace:** ROOT\CIMV2 (standard Windows management namespace)
- **Class:** Win32_ComputerSystem
- **Property:** Name (computer/domain name)

---

#### fs (Line 211)

```javascript
require('fs').convertFileTime(lastWriteTime)
```

**Used by:** `QueryKeyLastModified()` for FILETIME to JavaScript Date conversion

**Purpose:** Utility function to convert Windows FILETIME to JavaScript Date object

**Note:** This is a custom extension to the standard Node.js `fs` module, likely provided by the MeshAgent runtime

---

### Windows API Constants Used

**Access Rights (Lines 17-19):**
```javascript
var KEY_QUERY_VALUE = 0x0001;           // Read value data
var KEY_ENUMERATE_SUB_KEYS = 0x0008;    // Enumerate subkeys
var KEY_WRITE = 0x20006;                // Full write access
```

**Registry Documentation:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/25cce700-7fcf-4bb6-a2f3-0f6d08430a55
- https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types

---

### Dependency Chain Summary

```
win-registry.js
├─── _GenericMarshal (Line 44) - FFI library
│    └─── Native marshaling layer
├─── Kernel32.dll (Lines 45-46) - Windows core
│    └─── FileTimeToSystemTime() - Time conversion
├─── Advapi32.dll (Lines 47-57) - Registry API
│    ├─── RegCreateKeyExW() - Create/open keys
│    ├─── RegOpenKeyExW() - Open existing keys
│    ├─── RegEnumKeyExW() - Enumerate subkeys
│    ├─── RegEnumValueW() - Enumerate values
│    ├─── RegQueryValueExW() - Read value data
│    ├─── RegQueryInfoKeyW() - Key metadata
│    ├─── RegSetValueExW() - Write values
│    ├─── RegDeleteKeyW() - Delete keys
│    ├─── RegDeleteValueW() - Delete values
│    └─── RegCloseKey() - Close handles
└─── Optional Dependencies
     ├─── win-wmi (Line 309) - Domain resolution
     └─── fs (Line 211) - Time conversion utility
```

## Technical Implementation Details

### Memory Management

**Buffer Allocation Strategy:**

**Value Reading** (Lines 79-82):
1. First call to `RegQueryValueExW()` with null buffer gets required size
2. Allocate buffer of exact size needed
3. Second call retrieves actual data

**Key Enumeration** (Lines 126-139):
- Pre-allocated buffers:
  - `achClass`: 1024 bytes - Class name
  - `achKey`: 1024 bytes - Subkey names
  - `achValue`: 32768 bytes - Value names (32KB for long paths)
  - Various 4-byte variables for counts and sizes

**Size Limits:**
- Subkey names: Up to 1024 characters
- Value names: Up to 32768 characters
- No explicit limit on value data size (dynamically allocated)

### Wide Character (Unicode) Support

**All W-suffixed APIs** use UTF-16LE (Wide character):
- `RegCreateKeyExW`, `RegOpenKeyExW`, `RegEnumKeyExW`, etc.

**String Conversions:**
- **Line 68:** `this._marshal.CreateVariable(key, { wide: true })` - Convert to UTF-16
- **Line 98:** `data.Wide2UTF8` - Convert UTF-16 registry string to UTF-8
- **Line 151:** `achKey.Wide2UTF8` - Convert enumerated key names
- **Line 159:** `achValue.Wide2UTF8` - Convert enumerated value names

### Data Type Handling

**Reading Values** (Lines 84-106):

Uses `switch` statement on `valType` to handle different registry types:

```javascript
switch (valType.toBuffer().readUInt32LE()) {
    case REG_DWORD:              // Line 90-92
        retVal = data.toBuffer().readUInt32LE();
        break;
    case REG_DWORD_BIG_ENDIAN:   // Line 93-95
        retVal = data.toBuffer().readUInt32BE();
        break;
    case REG_SZ:                 // Line 96-98
    case REG_EXPAND_SZ:
        retVal = data.Wide2UTF8;
        break;
    default:                     // Line 100-105
        retVal = data.toBuffer();
        retVal._data = data;
        retVal._type = valType.toBuffer().readUInt32LE();
        break;
}
```

**Writing Values** (Lines 229-254):

Uses `typeof` to detect JavaScript type and map to registry type:

```javascript
switch(typeof(value)) {
    case 'boolean':      // Convert to REG_DWORD (0 or 1)
    case 'number':       // Write as REG_DWORD
    case 'string':       // Write as REG_SZ (wide character)
    default:             // Assume Buffer, write as REG_BINARY
}
```

### Error Handling

**Immediate Exceptions:**
- Invalid key paths (Line 75)
- Missing values (Line 114)
- Write failures (Lines 222, 260)
- Delete failures (Lines 272, 286)
- User SID not found (Line 365)

**Silent Fallbacks:**
- WMI unavailable during domain lookup (Lines 313-315)
- SAM lookup failure (Line 339)
- Individual enumeration stage failures in `usernameToUserKey()`

**Resource Cleanup:**
- All methods call `RegCloseKey()` before returning or throwing
- Lines 113, 162, 166, 259, 262, 285, 288 - Ensures no handle leaks

### Performance Considerations

**QueryKey() Enumeration:**
- Pre-queries key metadata once (Line 141) to get counts
- Iterates exact number of subkeys/values (no trial-and-error)
- Efficient for large registry keys

**usernameToUserKey() Lookup:**
- Tries fastest method first (SAM database lookup)
- Falls back to slower enumeration only if needed
- Caches domain name from WMI to avoid repeated queries

## Known Usage in Codebase

### Common Registry Access Patterns

**System Information Retrieval:**
```javascript
var reg = require('win-registry');

// Windows version
var winVer = reg.QueryKey(reg.HKEY.LocalMachine,
    'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion',
    'CurrentVersion');

// Installed software enumeration
var software = reg.QueryKey(reg.HKEY.LocalMachine,
    'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall');
```

**User Profile Management:**
```javascript
// Get user's registry key
var userSID = reg.usernameToUserKey('Username');

// Read user settings
var wallpaper = reg.QueryKey(reg.HKEY.Users,
    userSID + '\\Control Panel\\Desktop',
    'Wallpaper');
```

**Service/Application Configuration:**
```javascript
// Write application settings
reg.WriteKey(reg.HKEY.LocalMachine,
    'SOFTWARE\\MeshAgent',
    'InstallPath',
    'C:\\Program Files\\MeshAgent');

// Read back
var path = reg.QueryKey(reg.HKEY.LocalMachine,
    'SOFTWARE\\MeshAgent',
    'InstallPath');
```

## Security Considerations

### Registry Access Rights

**Read Operations:**
- Require `KEY_QUERY_VALUE (0x0001)` access
- May fail on protected keys (SAM, SECURITY hives)

**Write Operations:**
- Require `KEY_WRITE (0x20006)` access
- Require administrator privileges for HKEY_LOCAL_MACHINE
- Standard users can only write to HKEY_CURRENT_USER

### Protected Registry Areas

**SAM Database** (Lines 323-324):
- `HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names`
- Requires SYSTEM or Administrator privileges
- Contains user security information

**User SID Enumeration:**
- `usernameToUserKey()` may fail without proper permissions
- Requires ability to read user profile registry hives

### Best Practices

1. **Error Handling:** Always wrap registry operations in try-catch
2. **Resource Cleanup:** Handled automatically by module
3. **Access Rights:** Verify user has appropriate permissions before registry writes
4. **Data Validation:** Validate data types match expected registry value types
5. **Path Sanitization:** Ensure registry paths don't contain invalid characters

## License

**Apache License 2.0**
Copyright 2018-2022 Intel Corporation

## Summary

win-registry.js is a comprehensive Windows Registry manipulation module providing full read/write/delete capabilities across all registry hives. It offers automatic type detection, advanced user SID resolution, and robust error handling.

**Implicitly excludes all non-Windows platforms** because:
- Relies entirely on Windows-specific DLLs (Advapi32.dll, Kernel32.dll)
- Windows Registry is a Windows-exclusive data structure with no equivalent on other platforms
- Uses Windows-specific Security Identifiers (SIDs) and user/domain model
- No platform check - will fail immediately when trying to load Windows DLLs on macOS/Linux
- Intentionally designed for Windows system configuration management only

The module provides essential functionality for Windows system administration, application configuration storage, and user profile management. Alternative approaches using configuration files, defaults system (macOS), or dconf/gsettings (Linux) would be required for cross-platform configuration management.
