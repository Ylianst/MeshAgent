# linux-acpi.js

Monitors Linux ACPI (Advanced Configuration and Power Interface) events by connecting to the acpid daemon socket to detect power-related hardware events such as power button presses, lid close/open, sleep/wake events, and battery status changes.

## Platform

**Supported Platforms:**
- Linux - Full support

**Excluded Platforms:**
- **macOS** - Not supported
- **Windows** - Not supported
- **FreeBSD** - Not supported

**Exclusion Reasoning:**

**Line 23:** Checks for `/var/run/acpid.socket` - Linux-specific ACPI daemon socket

macOS and other platforms are excluded because:

1. **Linux ACPI Daemon** - The module connects to the `acpid` daemon which is Linux-specific. Line 26 creates a Unix domain socket connection to `/var/run/acpid.socket`, which only exists on Linux systems running the acpid service.

2. **macOS Uses IOKit** - macOS uses its own power management system based on the IOKit framework and IOPMCopySleepServiceWakeTimeDateKey() rather than ACPI. Power events are handled through IORegisterForSystemPower() and related IOKit APIs.

3. **Different Architecture** - While many systems support ACPI at the hardware level, the software interface for accessing ACPI events differs between operating systems. This module specifically interfaces with the Linux acpid daemon.

4. **Socket-Based Communication** - The module expects a Unix domain socket at a Linux-specific path. Windows and macOS don't use this interface for power management events.

## Functionality

### Core Purpose

Provides real-time monitoring of ACPI hardware events on Linux systems, enabling applications to respond to power-related events such as:
- Power button presses
- Lid open/close events
- Sleep/suspend requests
- AC adapter connect/disconnect
- Battery status changes
- Thermal events

### Event Emitter Interface (Line 21)

Creates an EventEmitter that emits 'acpi' events with structured data:

```javascript
{
    name: "button/power",     // Event source
    type: "PBTN",            // Event type
    value: "00000080"        // Event value/data
}
```

### Connection Management (Lines 23-35)

**Daemon Availability Check:**
- Line 23: `require('fs').existsSync('/var/run/acpid.socket')` - Checks if acpid is running
- Only activates if the acpid socket exists
- Silently does nothing if acpid is not available

**Socket Connection:**
- Line 26: Creates Unix domain socket connection to acpid
- Connects to `/var/run/acpid.socket`
- Automatic reconnection not implemented - connection failures are fatal

### Event Parsing (Lines 28-35)

**ACPI Event Format:**

ACPI events are received as text lines in the format:
```
<name> <type> <value> <reserved>
```

**Example Events:**
```
button/power PBTN 00000080 00000000
ac_adapter ACPI 00000001 00000000
battery BAT0 00000080 00000001
```

**Parsing Logic:**
1. Data received from socket is accumulated (Line 29)
2. Split on newlines to process complete events (Line 30)
3. Each line is split on spaces (Line 32)
4. Emits event with `name`, `type`, and `value` properties (Line 33)

### Common ACPI Event Types

| Name | Type | Description |
|------|------|-------------|
| button/power | PBTN | Power button pressed |
| button/sleep | SLPB | Sleep button pressed |
| button/lid | LID | Lid opened/closed |
| ac_adapter | ACPI | AC adapter connected/disconnected |
| battery | BAT0/BAT1 | Battery status change |
| thermal_zone | THRM | Temperature threshold crossed |
| processor | CPU0-N | CPU throttling/frequency change |

### Usage Example

```javascript
var acpi = require('linux-acpi');

acpi.on('acpi', function(event) {
    console.log('ACPI Event:', event.name, event.type, event.value);

    if (event.name === 'button/power') {
        console.log('Power button pressed - initiating shutdown');
        // Handle power button
    }

    if (event.name === 'button/lid') {
        if (event.value === '00000000') {
            console.log('Lid closed - suspending');
        } else {
            console.log('Lid opened - resuming');
        }
    }
});
```

## Dependencies

### Node.js Core Module Dependencies

#### events (Line 21)

```javascript
require('events').EventEmitter.call(this, true);
```

**Purpose:** Provides EventEmitter functionality for emitting ACPI events

**Usage:** Module extends EventEmitter to emit 'acpi' events

---

#### fs (Line 23)

```javascript
require('fs').existsSync('/var/run/acpid.socket')
```

**Purpose:** Check if acpid daemon socket exists

**Usage:** One-time check at module initialization to verify acpid is available

---

#### net (Line 26)

```javascript
require('net').createConnection({ path: '/var/run/acpid.socket' })
```

**Purpose:** Create Unix domain socket connection

**Usage:** Establishes connection to acpid daemon for receiving events

**Type:** Creates Unix domain socket (not TCP socket)

### Platform Binary Dependencies

**acpid (ACPI Daemon)**
- **Service:** Linux ACPI event daemon
- **Socket:** `/var/run/acpid.socket`
- **Package:** Usually `acpid` package on Debian/Ubuntu, `acpid` on Red Hat/Fedora
- **Purpose:** Handles ACPI events from the Linux kernel and exposes them via Unix socket

**Installation:**
```bash
# Debian/Ubuntu
sudo apt-get install acpid
sudo systemctl start acpid

# Red Hat/Fedora
sudo yum install acpid
sudo systemctl start acpid
```

**Kernel Support:**
- Requires ACPI support in Linux kernel
- Typically enabled by default on modern kernels
- Kernel config: `CONFIG_ACPI=y`

### Dependency Chain

```
linux-acpi.js
├─── events (Line 21) - EventEmitter base
├─── fs (Line 23) - Socket existence check
├─── net (Line 26) - Unix socket connection
└─── acpid daemon (Platform binary)
     ├─── /var/run/acpid.socket - Unix domain socket
     └─── Linux kernel ACPI subsystem
```

## Technical Notes

### Module Activation

The module only activates if the acpid socket exists (Line 23). If acpid is not installed or not running:
- No error is thrown
- Module loads successfully but does nothing
- No events will be emitted
- Silent failure mode

### Event Data Format

ACPI events are space-separated text with 4 fields:
1. **Name** - Event source/device path
2. **Type** - Event type identifier
3. **Value** - Event-specific data (usually hex number)
4. **Reserved** - Additional data (often 0, not parsed by this module)

### Security Considerations

- Requires read access to `/var/run/acpid.socket`
- Usually requires root/sudo or membership in appropriate group
- Some distributions allow unprivileged access to acpid socket
- Monitor power events without requiring kernel-level access

### Limitations

- No reconnection logic if acpid restarts
- No error handling for malformed events
- Assumes acpid socket location (some systems may use different paths)
- Does not support acpid configuration or command sending

### Performance

- Minimal CPU usage - event-driven model
- No polling - events pushed from acpid
- Low memory footprint
- Suitable for long-running daemons

## Summary

The linux-acpi.js module provides a simple, lightweight interface for monitoring Linux ACPI events through the acpid daemon. It exposes power-related hardware events as JavaScript events, enabling applications to respond to power buttons, lid switches, battery changes, and thermal events.

**macOS is excluded** because:
- Requires Linux-specific acpid daemon and `/var/run/acpid.socket` socket
- macOS uses IOKit framework for power management, not ACPI daemon
- Different power event architecture between Linux and macOS
- This is a fundamental platform difference in power management interfaces
