# wifi-scanner.js

Cross-platform WiFi network scanner providing unified interface for scanning available wireless networks on Windows and Linux systems. Abstracts platform-specific WiFi APIs through event-based access point discovery.

## Platform

**Supported Platforms:**
- Windows - Full support via native WLAN API
- Linux - Full support via iwlist command-line tool

**Excluded Platforms:**
- macOS - Partially supported (missing implementation)

**Placement in modules_macos_NEVER:**

macOS is excluded because:

1. **Missing macOS Implementation** - The module explicitly handles only Windows and Linux. Lines 51 and 60 show platform-specific branches:
```javascript
if (process.platform == 'win32') {
    // Windows implementation
} else if (process.platform == 'linux') {
    // Linux implementation
}
```

There is no `else` clause for macOS, meaning it would silently do nothing on macOS.

2. **No macOS WiFi APIs Used** - Unlike Windows (wlanapi.dll) and Linux (iwlist command), there is no implementation using macOS CoreWLAN or airport commands.

3. **Wrapper Architecture** - The module is designed to wrap platform-specific scanners (wifi-scanner-windows.js for Windows). No macOS wrapper exists.

4. **No Fallback for Apple Silicon/Intel Macs** - While macOS systems could technically scan WiFi, this module provides no mechanism to do so.

**Code Architecture (Lines 51-117):**
The Scan() method shows complete absence of macOS support:
```javascript
if (process.platform == 'win32') {
    // Windows path (53-58)
} else if (process.platform == 'linux') {
    // Linux path (60-116)
}
// No else for macOS - silently fails
```

## Functionality

### Core Purpose

Provides platform-independent API for scanning and enumerating available WiFi networks. Abstracts Windows native WLAN API and Linux iwlist command behind unified interface.

### Module Export (Line 120)

```javascript
module.exports = WiFiScanner;
```

**Exports constructor** - Create instances with `new WiFiScanner()`.

### Constructor: WiFiScanner() (Lines 33-118)

```javascript
function WiFiScanner() {
    var emitterUtils = require('events').inherits(this);
    emitterUtils.createEvent('accessPoint');
    // ... methods
}
```

**Enables event emission** for access point discovery.

### hasWireless() Method (Lines 38-47)

```javascript
this.hasWireless = function () {
    var retVal = false;
    var interfaces = require('os').networkInterfaces();
    for (var name in interfaces) {
        if (interfaces[name][0].type == 'wireless') { retVal = true; break; }
    }
    return (retVal);
}
```

**Checks for wireless interface availability**

**Logic:**
1. Get all network interfaces via `os.networkInterfaces()`
2. Check if any interface has type 'wireless'
3. Return true if wireless interface found, false otherwise

**Use Case:** Determine if scanning is possible before attempting scan

### Scan Method (Lines 49-117)

#### Windows Implementation (Lines 51-58)

```javascript
if (process.platform == 'win32') {
    this.master = require('ScriptContainer').Create(15, ContainerPermissions.DEFAULT);
    this.master.parent = this;
    this.master.on('data', function (j) {
        this.parent.emit('accessPoint', new AccessPoint(j.ssid, j.bssid, j.lq));
    });

    this.master.addModule('wifi-scanner-windows', getJSModule('wifi-scanner-windows'));
    this.master.ExecuteString(WindowsChildScript);
}
```

**Architecture:**

1. **Create Child Container (Line 53):**
   ```javascript
   this.master = require('ScriptContainer').Create(15, ContainerPermissions.DEFAULT);
   ```
   ScriptContainer isolates the Windows scanning code in separate context.

2. **Register Data Handler (Lines 54-55):**
   ```javascript
   this.master.parent = this;
   this.master.on('data', function (j) {
       this.parent.emit('accessPoint', new AccessPoint(j.ssid, j.bssid, j.lq));
   });
   ```
   Parent reference enables communication back to main scanner.
   Converts received data to AccessPoint events.

3. **Inject Windows Scanner Module (Line 57):**
   ```javascript
   this.master.addModule('wifi-scanner-windows', getJSModule('wifi-scanner-windows'));
   ```
   Makes windows-specific scanner available in child context.

4. **Execute Child Script (Line 58):**
   ```javascript
   this.master.ExecuteString(WindowsChildScript);
   ```
   Runs embedded script in isolated container.

**Windows Child Script (Line 18):**
```javascript
var WindowsChildScript = 'var parent = require("ScriptContainer");var Wireless = require("wifi-scanner-windows");Wireless.on("Scan", function (ap) { parent.send(ap); });Wireless.Scan();';
```

Breakdown:
1. Get ScriptContainer reference (`parent`)
2. Load wifi-scanner-windows module
3. Listen for 'Scan' events from Wireless
4. Send each access point back to parent via `parent.send(ap)`
5. Initiate scan with `Wireless.Scan()`

#### Linux Implementation (Lines 60-116)

```javascript
else if (process.platform == 'linux') {
    var interfaces = require('os').networkInterfaces();
    var wlan = null;
    for (var i in interfaces) {
        if (interfaces[i][0].type == 'wireless') {
            wlan = i;
            break;
        }
    }
    if (wlan != null) {
        this.child = require('child_process').execFile('/sbin/iwlist', ['iwlist', wlan, 'scan']);
        // ... parsing logic
    }
}
```

**Step 1: Find Wireless Interface (Lines 63-71):**
```javascript
var interfaces = require('os').networkInterfaces();
var wlan = null;
for (var i in interfaces) {
    if (interfaces[i][0].type == 'wireless') {
        wlan = i;
        break;
    }
}
```

Searches for interface with type 'wireless' (e.g., 'wlan0').

**Step 2: Execute iwlist Scan (Lines 73-80):**
```javascript
if (wlan != null) {
    this.child = require('child_process').execFile('/sbin/iwlist', ['iwlist', wlan, 'scan']);
    this.child.parent = this;
    this.child.ms = new MemoryStream();
    this.child.ms.parent = this.child;
    this.child.stdout.on('data', function (buffer) {
        this.parent.ms.write(buffer);
    });
    this.child.on('exit', function () { this.ms.end(); });
```

**Execution Flow:**
- Command: `iwlist wlan0 scan`
- Output captured to MemoryStream
- On child process exit, MemoryStream marked complete

**Step 3: Parse iwlist Output (Lines 81-114):**
```javascript
this.child.ms.on('end', function () {
    var str = this.buffer.toString();
    tokens = str.split(' - Address: ');

    for (var block in tokens) {
        if (block == 0) continue;  // Skip header
        var ln = tokens[block].split('\n');
        var _bssid = ln[0];
        var _lq;
        var _ssid;

        for (var lnblock in ln) {
            lnblock = ln[lnblock].trim();
            if (lnblock.startsWith('ESSID:')) {
                _ssid = lnblock.slice(7, lnblock.length - 1);
                if (_ssid == '<hidden>') { _ssid = ''; }
            }
            if (lnblock.startsWith('Signal level=')) {
                _lq = lnblock.slice(13, lnblock.length - 4);
            } else if (lnblock.startsWith('Quality=')) {
                _lq = lnblock.slice(8, 10);
                var scale = lnblock.slice(11, 13);
            }
        }
        this.parent.parent.emit('accessPoint', new AccessPoint(_ssid, _bssid, _lq));
    }
});
```

**Parsing Strategy:**

1. **Split by Address (Line 84):**
   ```javascript
   tokens = str.split(' - Address: ');
   ```
   iwlist output format: `Cell 01 - Address: AA:BB:CC:DD:EE:FF`

2. **Extract BSSID (Line 89):**
   ```javascript
   var _bssid = ln[0];
   ```
   First line after address split is the MAC address.

3. **Extract ESSID (Lines 97-100):**
   ```javascript
   if (lnblock.startsWith('ESSID:')) {
       _ssid = lnblock.slice(7, lnblock.length - 1);
       if (_ssid == '<hidden>') { _ssid = ''; }
   }
   ```
   Format: `ESSID:"NetworkName"`
   Hidden networks show as `<hidden>`, converted to empty string.

4. **Extract Signal Strength (Lines 101-110):**
   ```javascript
   if (lnblock.startsWith('Signal level=')) {
       _lq = lnblock.slice(13, lnblock.length - 4);
   } else if (lnblock.startsWith('Quality=')) {
       _lq = lnblock.slice(8, 10);
       var scale = lnblock.slice(11, 13);
   }
   ```
   iwlist provides either:
   - `Signal level=-50 dBm` format
   - `Quality=75/100 Signal level=-50 dBm` format

5. **Emit Results (Line 112):**
   ```javascript
   this.parent.parent.emit('accessPoint', new AccessPoint(_ssid, _bssid, _lq));
   ```
   Parent.parent chain: this (MemoryStream) → parent (child_process) → parent (WiFiScanner)

### AccessPoint Class (Lines 21-31)

```javascript
function AccessPoint(_ssid, _bssid, _lq) {
    this.ssid = _ssid;
    this.bssid = _bssid;
    this.lq = _lq;
}

AccessPoint.prototype.toString = function () {
    return ("[" + this.bssid + "]: " + this.ssid + " (" + this.lq + ")");
}
```

**Properties:**
- ssid - Network name
- bssid - MAC address
- lq - Link quality

**String Representation:** `"[AA:BB:CC:DD:EE:FF]: NetworkName (75)"`

**Note:** Simpler than wifi-scanner-windows.js version (no RSSI field).

## Dependencies

### MeshAgent Module Dependencies

#### events (Line 35)

```javascript
var emitterUtils = require('events').inherits(this);
emitterUtils.createEvent('accessPoint');
```

**Purpose:** Event emitter for access point discovery

**Methods:**
- `inherits(obj)` - Enable event emitting on object
- `createEvent(name)` - Register event type

#### ScriptContainer (Line 53)

```javascript
this.master = require('ScriptContainer').Create(15, ContainerPermissions.DEFAULT);
this.master.addModule('wifi-scanner-windows', getJSModule('wifi-scanner-windows'));
this.master.ExecuteString(WindowsChildScript);
```

**Purpose (Windows only):** Isolated script execution context

**Methods:**
- `Create(id, permissions)` - Create child container
- `addModule(name, source)` - Inject module
- `ExecuteString(code)` - Run JavaScript
- `.on('data', handler)` - Receive messages from child
- Container's `.send(data)` - Send data to parent

**Functionality:** Sandboxes Windows WiFi scanner in separate context.

#### MemoryStream (Line 17)

```javascript
var MemoryStream = require('MemoryStream');
```

**Purpose (Linux only):** Buffer command output

**Usage:**
```javascript
this.child.ms = new MemoryStream();
this.child.stdout.on('data', function (buffer) {
    this.parent.ms.write(buffer);
});
```

Accumulates iwlist output for parsing.

#### wifi-scanner-windows (Line 57)

```javascript
this.master.addModule('wifi-scanner-windows', getJSModule('wifi-scanner-windows'));
```

**Purpose:** Windows WiFi scanning implementation

**Used in child script:** Provides Wireless object with Scan() and 'Scan' events.

### Node.js Core Module Dependencies

#### os (Lines 41, 63)

```javascript
var interfaces = require('os').networkInterfaces();
```

**Methods:**
- `networkInterfaces()` - Get network interface list with properties

**Purpose:** Detect wireless interfaces by type

#### child_process (Line 75)

```javascript
this.child = require('child_process').execFile('/sbin/iwlist', ['iwlist', wlan, 'scan']);
```

**Methods:**
- `execFile(command, args)` - Execute command with output

**Purpose:** Run `iwlist` command to scan WiFi (Linux only)

### Platform Binary Dependencies

#### iwlist (Linux only, Line 75)

**Linux WiFi Scanning Tool**

**Command:** `iwlist wlan0 scan`

**Output Format Example:**
```
Cell 01 - Address: AA:BB:CC:DD:EE:FF
          ESSID:"NetworkName"
          Frequency:2.412 GHz (Channel 1)
          Quality=75/100  Signal level=-50 dBm
          ...
```

**Availability:** Part of wireless-tools package (Linux)

## Technical Notes

### Platform Abstraction Pattern

**Two-Tier Approach:**

1. **Windows:** ScriptContainer isolation
   - Separates Windows-native code
   - Enables context management
   - Cleaner integration

2. **Linux:** Process execution
   - Shell out to iwlist
   - Parse text output
   - No native API access

### Child Container Messaging (Windows)

**Parent-Child Communication:**

```javascript
// In parent:
this.master.on('data', function (j) {
    this.parent.emit('accessPoint', new AccessPoint(j.ssid, j.bssid, j.lq));
});

// In child script:
Wireless.on("Scan", function (ap) {
    parent.send(ap);  // Send AccessPoint object
});
```

**Serialization:** AccessPoint objects transmitted as JSON through container boundary.

### iwlist Parsing Quirks

**Multiple Format Support (Lines 101-109):**

iwlist can output signal strength in different ways:
- Modern format: `Signal level=-50 dBm`
- Legacy format: `Quality=75/100 Signal level=-50 dBm`

Parser handles both variants.

**Hidden Networks (Lines 99-100):**

```javascript
if (_ssid == '<hidden>') { _ssid = ''; }
```

Networks with SSID broadcast disabled appear as `<hidden>`. Converted to empty string for consistency.

### Interface Type Detection

**String Matching (Line 44):**
```javascript
if (interfaces[name][0].type == 'wireless') { retVal = true; }
```

Linux system reports interface type as 'wireless', 'ethernet', etc.
Windows may not have this property reliably.

### Memory Stream Buffering

**Why MemoryStream? (Line 77):**

```javascript
this.child.ms = new MemoryStream();
this.child.stdout.on('data', function (buffer) {
    this.parent.ms.write(buffer);
});
```

iwlist output comes in chunks (data events). MemoryStream accumulates all chunks before parsing to avoid incomplete records.

### Cross-Platform Event System

**Unified Interface:**

Despite different implementations:
```javascript
// Both emit same event type
scanner.on('accessPoint', function(ap) {
    console.log(ap.ssid, ap.bssid, ap.lq);
});
```

Windows and Linux both emit 'accessPoint' events with same AccessPoint objects.

### getJSModule() Function

**Referenced at Line 57:**
```javascript
getJSModule('wifi-scanner-windows')
```

Function not defined in this module - likely provided by MeshAgent environment to load module source code as string.

## Summary

wifi-scanner.js provides cross-platform WiFi scanning by abstracting Windows WLAN API and Linux iwlist command behind unified event-based interface.

**Placed in modules_macos_NEVER** because:
- No macOS WiFi scanning implementation
- Windows uses ScriptContainer + native WLAN API
- Linux uses iwlist command-line tool
- No CoreWLAN or airport command integration for macOS

**Key Features:**
- Platform-agnostic API
- Event-based access point discovery
- Wireless interface detection
- Hidden network handling
- Windows: Native API via ScriptContainer
- Linux: iwlist command parsing

**Access Point Data:**
- ssid - Network name
- bssid - MAC address
- lq - Link quality/signal strength

**Usage Pattern:**
```javascript
var WiFiScanner = require('wifi-scanner');
var scanner = new WiFiScanner();
scanner.on('accessPoint', function(ap) {
    console.log(ap.toString());
});
scanner.Scan();
```

**Related Modules:**
- wifi-scanner-windows.js - Windows WLAN API implementation
- ScriptContainer - Child process isolation
- MemoryStream - Output buffering
- events - Event emitter functionality
