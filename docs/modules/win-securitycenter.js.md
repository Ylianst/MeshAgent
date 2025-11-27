# win-securitycenter.js

Provides access to Windows Security Center for querying antivirus, firewall, and Windows Update status. Implements health monitoring of security providers through Wscapi.dll with event notification support for security status changes.

## Platform

**Supported Platforms:**
- Windows (Desktop only, not Server) - Full support

**Excluded Platforms:**
- **macOS** - Not supported (Windows-only)
- **Linux** - Not supported (Windows-only)
- **FreeBSD** - Not supported (Windows-only)

**Exclusion Reasoning:**

Windows-specific module requiring Windows APIs/DLLs unavailable on other platforms.

**Platform Notes:**

**win-securitycenter.js is Windows-only** because:

1. **Wscapi.dll Dependency** - Windows Security Center API not available on other platforms
2. **Not on Windows Server** - Security Center unavailable on Server SKUs (throws error on initialization)
3. **Health Monitoring** - Windows-specific security provider health model

---

## Functionality

### Core Purpose

win-securitycenter.js monitors system security:

1. **Provider Health Status** - Query firewall, antivirus, update status
2. **Status Notification** - Event fired on status changes
3. **Real-time Monitoring** - Registry-based event notification

### Main Operations

1. **Status Query** - getStatus()
2. **Event Listening** - 'changed' event emission

---

## Initialization - Lines 34-47

**Purpose:** Load Windows Security Center APIs

**Process:**
1. Attempts to load Wscapi.dll (line 40)
2. Creates methods for three security operations (lines 41-43)
3. If fails (line 45-47): Sets seccenter to null (not available on Server)

**Exception Handling:**
- Silently catches failures (allows graceful degradation on Server)

---

## Constants - Lines 24-32

### Security Providers:
```javascript
WSC_SECURITY_PROVIDER_FIREWALL = 0x1
WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS = 0x2
WSC_SECURITY_PROVIDER_ANTIVIRUS = 0x4
WSC_SECURITY_PROVIDER_ANTISPYWARE = 0x8
```

### Health Status:
```javascript
WSC_SECURITY_PROVIDER_HEALTH_GOOD = 0          // Green
WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED = 1  // Yellow
WSC_SECURITY_PROVIDER_HEALTH_POOR = 2          // Red
WSC_SECURITY_PROVIDER_HEALTH_SNOOZE = 3        // Yellow
```

---

## Core Methods

### getStatus() - Lines 71-83

**Purpose:** Query current security provider status

**Returns:** Object with properties:
```javascript
{
    firewall: 'OK'|'WARNING'|'PROBLEM'|'UNKNOWN',
    antiVirus: 'OK'|'WARNING'|'PROBLEM'|'UNKNOWN',
    autoUpdate: 'OK'|'WARNING'|'PROBLEM'|'UNKNOWN'
}
```

**Process:**
1. Checks if seccenter available (line 74)
2. For each provider (firewall, antivirus, autoupdate):
   - Creates 4-byte status variable
   - Calls WscGetSecurityProviderHealth()
   - Maps status value to string via statusString()
3. Returns status object

**Status Mapping (statusString):**
- 0 → 'OK' (green)
- 1 or 3 → 'WARNING' (yellow)
- 2 → 'PROBLEM' (red)
- Other → 'UNKNOWN'

---

## Event Notification - Lines 85-111

**Purpose:** Monitor security status changes

**Setup (lines 85-110):**
1. Creates EventEmitter base object (lines 90-92)
2. Creates event listener (line 94)
3. Registers callback for changes (lines 96-99)
4. On 'changed' event: Emits module 'changed' event
5. Registers cleanup on finalization (lines 101-105)

**Implementation:**
- WscRegisterForChanges() sets up event handler (line 107)
- Callback triggered on security status change
- Module emits 'changed' event
- Application can listen and update status

**Cleanup:**
- On finalization (~): Calls WscUnRegisterChanges()
- Unregisters event handler

---

## Error Handling

1. **Server SKU Unavailable**
   - Silently fails in try/catch (line 45)
   - seccenter remains null
   - getStatus() returns all 'UNKNOWN'
   - Throws: 'win-securitycenter not supported on this platform' (line 115)

---

## Dependencies

### Native DLL - Lines 40-43

**require('_GenericMarshal').CreateNativeProxy('Wscapi.dll')**
- WscGetSecurityProviderHealth() - Get provider status
- WscRegisterForChanges() - Register status change event
- WscUnRegisterChanges() - Unregister event

### Module Dependencies - Lines 91, 94

**require('events').EventEmitter**
- Base for event emission
- createEvent() for 'changed' event

**require('_GenericMarshal')**
- CreateVariable() - Memory buffers
- CreatePointer() - Pointer management
- GetGenericGlobalCallback() - Create callback
- ObjectToPtr() - Object to pointer conversion

---

## Usage Examples

### Query Security Status

```javascript
var sc = require('win-securitycenter');
var status = sc.status();
console.log('Firewall:', status.firewall);
console.log('AV:', status.antiVirus);
console.log('Updates:', status.autoUpdate);
```

### Monitor Security Changes

```javascript
var sc = require('win-securitycenter');
sc.on('changed', function() {
    console.log('Security status changed');
    var status = sc.status();
    // Update UI or take action
});
```

---

## Technical Notes

### Windows Security Center

- Part of Windows Defender Security Center (modern Windows)
- Legacy: Windows Security Center (older versions)
- Not available on Windows Server (no consumer-facing security features)
- Status available for:
  - Firewall protection
  - Antivirus protection
  - Windows Update status

### Health Indicator Colors

- Green: Fully protected
- Yellow: Issues detected or monitoring disabled
- Red: Critical security problem

### Event Notification

Uses COM-based event system through Wscapi.dll:
- WscRegisterForChanges() with callback
- Callback fired on status changes
- Can monitor multiple providers simultaneously

---

## Summary

win-securitycenter.js provides simple security status monitoring on Windows systems (Desktop only). The module queries firewall, antivirus, and update provider health with optional event notification on status changes. Graceful error handling on Server platforms and proper COM event cleanup ensure reliable operation.
