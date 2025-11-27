# power-monitor.js

A comprehensive power management monitoring module that tracks AC/battery status, battery charge levels, and provides display sleep/wake control across Windows, Linux, and macOS platforms. This module enables MeshAgent to respond to power events and manage display power states for remote management scenarios.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support with Windows-specific APIs
- Linux - Full support with ACPI and sysfs integration
- **macOS (darwin)** - Full support with pmset and caffeinate utilities

**Platform-Specific Implementations:**

This module provides **complete cross-platform support** including macOS, but uses different implementations per platform:

### Windows (Lines 35-40, 179-213, 229-278)
- **Power Monitoring:** Uses Windows message processing via `user-sessions` module
- **Display Control:** Win32 APIs (`SendMessageA` for sleep, `SetThreadExecutionState` for wake)
- **Session Awareness:** Detects LocalSystem context and spawns user-session processes
- **Battery Info:** Real-time events from Windows power management

### Linux (Lines 54-120)
- **Power Monitoring:** ACPI events via `linux-acpi` module
- **Battery Info:** Reads from `/sys/class/power_supply/` sysfs interfaces
- **Polling:** 5-minute intervals for battery level updates (ACPI doesn't provide level events)
- **Display Control:** Not implemented (returns rejection)

### macOS (Lines 121-178, 215-227, 229-278)
- **Power Monitoring:** Polls `pmset -g batt` command output
- **Battery Info:** Parses pmset output with awk for AC/battery status and charge level
- **Polling:** 5-minute intervals for status updates
- **Display Control:**
  - Sleep: `pmset displaysleepnow` command (lines 221)
  - Wake: `caffeinate -u -t 2` command (lines 236-243)
- **Tool Detection:** Discovers caffeinate location at initialization (lines 123-132)

**Why macOS is Fully Supported:**

1. **Standard Unix Tools Available** - macOS includes `pmset` (power management settings) and `caffeinate` (sleep prevention) as standard system utilities.

2. **Shell Command Abstraction** - Using command-line tools (pmset, caffeinate) avoids need for native Objective-C/Swift APIs or macOS-specific frameworks.

3. **Consistent Data Format** - pmset output is structured and parseable with standard text tools (awk), providing reliable AC/battery status.

4. **Promise-Based Architecture** - Async operations use promises, making command execution natural via `child_process.execFile()`.

5. **Essential Feature for Laptops** - MacBooks are popular remote management targets; power monitoring is critical for laptop fleet management.

## Functionality

### Purpose

The power-monitor module provides real-time monitoring and control of system power states for MeshAgent. It enables:

- **Power Status Awareness:** Detecting AC power vs. battery operation for power-sensitive operations
- **Battery Level Monitoring:** Tracking charge percentage to prevent operations that could drain batteries
- **Display Power Management:** Controlling display sleep/wake for security (lock screens) and power saving
- **Event-Driven Architecture:** Emitting events when power conditions change for reactive agent behavior
- **Remote Management Optimization:** Adjusting agent behavior based on power constraints

This module is essential for:
- Laptop fleet management (Windows, Linux, macOS laptops)
- Power-aware remote operations (avoid intensive tasks on battery)
- Privacy/security features (sleep display when session ends)
- Energy efficiency in data centers and edge devices

### Constructor and Initialization - Lines 22-178

**Purpose:** Sets up event emitters, initializes platform-specific power monitoring.

**Event Registration** (lines 25-30):
```javascript
require('events').EventEmitter.call(this, true)
    .createEvent('changed')    // Generic power state change
    .createEvent('sx')         // Sleep/wake state transitions
    .createEvent('batteryLevel') // Battery percentage changes
    .createEvent('acdc')       // AC/battery transition
    .createEvent('display');   // Display power state changes
```

**Initial State** (lines 32-33):
```javascript
this._ACState = 1;          // 1 = AC power, 0 = battery
this._BatteryLevel = -1;    // -1 = unknown/no battery
```

**Windows-Specific Initialization** (lines 35-40):
- Registers event handlers BEFORE newListener hook (critical for state replay)
- Updates internal state on events to support newListener callback

**NewListener Hook** (lines 42-46):
- Immediately calls new listeners with current state
- Enables consumers to get current state without waiting for events
- Example: `on('acdc', callback)` immediately receives 'AC' or 'BATTERY'

**User-Sessions Module Loading** (lines 48-52):
```javascript
this._i = setImmediate(function (self) {
    require('user-sessions'); // Loads Windows message processing
    delete self._i;
}, this);
```
- Deferred loading using `setImmediate` to avoid circular dependencies
- Required for Windows power event message loop

**Platform-Specific Initialization:**

- **Linux:** Lines 54-120 (described in detail below)
- **macOS:** Lines 121-178 (described in detail below)

---

### Linux Implementation - Lines 54-120

**Purpose:** Monitor power state via sysfs and ACPI events.

**AC Adapter Detection** (lines 56-67):
```javascript
var devices = require('fs').readdirSync('/sys/class/power_supply');
for (var i in devices) {
    if (readFileSync('/sys/class/power_supply/' + devices[i] + '/type')
        .toString().trim() == 'Mains') {
        this._ACPath = '/sys/class/power_supply/' + devices[i] + '/';
        break;
    }
}
```
- Scans `/sys/class/power_supply/` for power supply devices
- Identifies AC adapter by type 'Mains'
- Stores path for reading online status

**Battery Detection** (lines 68-74):
```javascript
for (var i in devices) {
    if (readFileSync('/sys/class/power_supply/' + devices[i] + '/type')
        .toString().trim() == 'Battery') {
        this._BatteryPath.push('/sys/class/power_supply/' + devices[i] + '/');
    }
}
```
- Identifies all batteries (multi-battery support)
- Stores array of paths for reading capacity

**Initial AC State** (lines 75-78):
```javascript
if (this._ACPath != null) {
    this._ACState = parseInt(readFileSync(this._ACPath + 'online').toString().trim());
}
```
- Reads `online` file: 1 = connected, 0 = disconnected

**Battery Level Reading Function** (lines 79-92):
```javascript
this._getBatteryLevel = function _getBatteryLevel() {
    var sum = 0;
    for (i in this._BatteryPath) {
        sum += parseInt(readFileSync(this._BatteryPath[i] + 'capacity')
                        .toString().trim());
    }
    sum = Math.floor(sum / this._BatteryPath.length);
    return (sum);
}
```
- Reads `capacity` file from each battery (0-100 percentage)
- Averages across multiple batteries
- Returns integer percentage

**Battery Polling** (lines 93-108):
```javascript
this._BatteryLevelCheck = function _BatteryLevelCheck() {
    var val = this._getBatteryLevel();
    if (val != this._BatteryLevel) {
        this._BatteryLevel = val;
        this.emit('batteryLevel', val);
    }
};
this._BattCheckInterval = setInterval(function (self) {
    self._BatteryLevelCheck.call(self);
}, 300000, this); // 5 minutes
```
- **Why Polling?** ACPI doesn't emit battery level change events reliably
- Checks every 5 minutes (300,000 ms)
- Only emits event if level changed

**ACPI Event Handling** (lines 109-120):
```javascript
this._acpiSink = function _acpiSink(acpiEvent) {
    if (acpiEvent.name == 'ac_adapter') {
        _acpiSink.self._ACState = acpiEvent.value;
        _acpiSink.self.emit('acdc', acpiEvent.value == 1 ? 'AC' : 'BATTERY');
        _acpiSink.self._BatteryLevelCheck();
    }
};
this._acpiSink.self = this;
require('linux-acpi').on('acpi', this._acpiSink);
```
- Listens for ACPI events from kernel via `linux-acpi` module
- Filters for `ac_adapter` events
- Immediately checks battery level on AC change (user may be unplugging)

---

### macOS Implementation - Lines 121-178

**Purpose:** Monitor power state via pmset command parsing.

**Caffeinate Tool Discovery** (lines 123-132):
```javascript
Object.defineProperty(this, "_caffeinate", {
    value: (function () {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = '';
        child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.stdin.write('whereis caffeinate\nexit\n');
        child.waitExit();
        return (child.stdout.str.trim());
    })()
});
```
- Uses `whereis` to locate `caffeinate` binary (typically `/usr/bin/caffeinate`)
- Stores as non-enumerable property
- Used later for waking display

**Battery Level Retrieval Function** (lines 133-152):
```javascript
this._getBatteryLevel = function _getBatteryLevel() {
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write("pmset -g batt | awk 'NR==2 {");
    child.stdin.write('   power=index($0,\"AC\")>0?\"1\":\"0\";');
    child.stdin.write('   for(i=1;i<=NF;i++) { if(index($i,\"%\")>0) { split($i,chg,\";\"); split(chg[1],pct,\"%\"); level=pct[1]; break; } }');
    child.stdin.write('   printf \"{\\\"ac\\\": %s,\\\"level\\\": %s}\",power, (level==\"\"?\"0\":level); ');
    child.stdin.write("}'");
    child.stdin.write("\nexit\n");
    child.waitExit();
    try {
        var info = JSON.parse(child.stdout.str.trim());
        return (info);
    } catch (e) {
        return({ ac: 1, level: 100 }); // Fallback for desktops
    }
}
```

**pmset Output Parsing:**
- `pmset -g batt` output format (line 2 contains battery info):
  ```
  Now drawing from 'Battery Power'
   -InternalBattery-0 (id=12345678)	80%; discharging; 3:45 remaining present: true
  ```
  Or when on AC:
  ```
  Now drawing from 'AC Power'
   -InternalBattery-0 (id=12345678)	100%; charged; 0:00 remaining present: true
  ```

**awk Script Breakdown:**
- Line 139: `power=index($0,"AC")>0?"1":"0"` - Detects "AC" in line (AC=1, Battery=0)
- Line 140: Loop through fields to find one containing '%'
- Line 140: `split($i,chg,";")` - Split "80%;discharging" on semicolon
- Line 140: `split(chg[1],pct,"%")` - Split "80%" to extract number
- Line 141: `printf "{\"ac\": %s,\"level\": %s}"` - Output JSON

**Error Handling** (lines 145-151):
- Catches JSON parse errors
- Returns default values (AC power, 100% charge) for desktop Macs without batteries
- Prevents crashes on systems without power management

**Status Change Detection** (lines 153-166):
```javascript
this._batteryLevelCheck = function _batteryLevelCheck() {
    var newLevel = this._getBatteryLevel();
    if (newLevel.ac != this._ACState) {
        this._ACState = newLevel.ac;
        this.emit('acdc', this._ACState == 1 ? 'AC' : 'BATTERY');
    }
    if (newLevel.level != this._BatteryLevel) {
        this._BatteryLevel = newLevel.level;
        this.emit('batteryLevel', this._BatteryLevel);
    }
};
```
- Compares new values with cached state
- Emits events only on changes
- Handles both AC/DC and battery level changes in single check

**Initial State Retrieval** (lines 167-169):
```javascript
var tmp = this._getBatteryLevel();
this._ACState = tmp.ac;
this._BatteryLevel = tmp.level;
```
- Populates initial state at module load
- Ensures newListener hook can provide current state

**Polling Setup** (lines 171-177):
```javascript
if (this._BatteryLevel >= 0) {
    this._BattCheckInterval = setInterval(function (self) {
        self._batteryLevelCheck.call(self);
    }, 300000, this); // 5 minutes
}
```
- Only starts polling if battery detected (level >= 0)
- Desktop Macs without batteries skip polling
- 5-minute interval balances responsiveness with overhead

---

### sleepDisplay(force) - Lines 179-228

**Purpose:** Puts display to sleep immediately.

**Signature:**
```javascript
powerMonitor.sleepDisplay(force)
```

**Parameters:**
- `force` - Currently unused, reserved for future forced sleep

**Returns:** Promise that resolves when display sleep completes.

**Windows Implementation** (lines 186-214):

**LocalSystem Session Detection** (lines 187-203):
```javascript
if (require('user-sessions').getProcessOwnerName(process.pid).tsid == 0) {
    // Running as LocalSystem service
    var options = {
        launch: { module: 'power-monitor', method: 'sleepDisplay', args: [] }
    };
    try {
        options.user = require('user-sessions').getUsername(require('user-sessions').consoleUid());
    } catch (ee) {
        p._rej('No users logged in');
        return (p);
    }
    p.child = require('child-container').create(options);
    p.child.promise = p;
    p.child.on('exit', function () { this.promise._res(); });
}
```
- **Why?** Display control requires user session context; LocalSystem can't send window messages
- Creates child process in active user's session
- Uses `child-container` to spawn with correct user context
- Fails if no users logged in

**Direct Display Sleep** (lines 204-213):
```javascript
else {
    if (require('child-container').child) { require('win-console').hide(); }
    var GM = require('_GenericMarshal');
    var user32 = GM.CreateNativeProxy('User32.dll');
    user32.CreateMethod('SendMessageA');
    user32.SendMessageA(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
    p._res();
    if (require('child-container').child) { process._exit(); }
}
```
- Calls Win32 API `SendMessageA` with:
  - `HWND_BROADCAST` (0xFFFF) - Send to all top-level windows
  - `WM_SYSCOMMAND` (0x0112) - System command message
  - `SC_MONITORPOWER` (0xF170) - Monitor power control
  - `2` - Low power mode (sleep)
- Hides console window if spawned as child
- Exits child process after sending message

**macOS Implementation** (lines 215-222):
```javascript
case 'darwin':
    p.child = require('child_process').execFile('/bin/sh', ['sh']);
    p.child.promise = p;
    p.child.stderr.on('data', function () { });
    p.child.stdout.on('data', function () { });
    p.child.on('exit', function () { this.promise._res(); });
    p.child.stdin.write('pmset displaysleepnow\nexit\n');
    break;
```
- Spawns shell process
- Executes `pmset displaysleepnow` command
- **Command behavior:** Immediately sleeps display (equivalent to display sleep timer expiring)
- Requires admin/root privileges in some macOS versions
- Resolves promise on command completion

**Linux Implementation** (lines 223-225):
```javascript
default:
    p._rej('Not Supported');
    break;
```
- **Not implemented** on Linux
- Returns rejected promise with 'Not Supported' error
- Could potentially be implemented with:
  - DPMS (Display Power Management Signaling) via xset
  - systemd-logind D-Bus calls
  - Wayland compositor-specific methods

---

### wakeDisplay() - Lines 229-279

**Purpose:** Wakes display from sleep state.

**Signature:**
```javascript
powerMonitor.wakeDisplay()
```

**Returns:** Promise that resolves when display wake completes.

**macOS Implementation** (lines 235-244):
```javascript
case 'darwin':
    if (this._caffeinate) {
        p.child = require('child_process').execFile(this._caffeinate,
                                                     ['caffeinate', '-u', '-t 2']);
        p.child.stdout.on('data', function () { });
        p.child.stderr.on('data', function () { });
        p.child.on('exit', function (code) { this.promise._res(); });
        p.child.promise = p;
    }
    break;
```
- Uses `caffeinate` utility (discovered during initialization)
- **Flags:**
  - `-u` - Create user assertion (wakes display)
  - `-t 2` - Timeout after 2 seconds
- **Behavior:** Simulates user activity to wake display
- Silently succeeds if caffeinate not found

**Windows Implementation** (lines 245-273):

**LocalSystem Session Detection** (lines 246-262):
```javascript
if (require('user-sessions').getProcessOwnerName(process.pid).tsid == 0) {
    var options = {
        launch: { module: 'power-monitor', method: 'wakeDisplay', args: [] }
    };
    try {
        options.user = require('user-sessions').getUsername(require('user-sessions').consoleUid());
    } catch (ee) {
        p._rej('No users logged in');
        return (p);
    }
    p.child = require('child-container').create(options);
    p.child.promise = p;
    p.child.on('exit', function () { this.promise._res(); });
}
```
- Same session handling as sleepDisplay
- Spawns child in user session if running as LocalSystem

**Direct Display Wake** (lines 263-272):
```javascript
else {
    if (require('child-container').child) { require('win-console').hide(); }
    var GM = require('_GenericMarshal');
    var kernel32 = GM.CreateNativeProxy('Kernel32.dll');
    kernel32.CreateMethod('SetThreadExecutionState');
    kernel32.SetThreadExecutionState(ES_DISPLAY_REQUIRED);
    p._res();
    if (require('child-container').child) { process._exit(); }
}
```
- Calls Win32 API `SetThreadExecutionState` with:
  - `ES_DISPLAY_REQUIRED` (0x00000002) - Display required flag
- **Behavior:** Informs system that display is needed, preventing/ending sleep
- Lighter-weight than SendMessage approach

**Linux/Default** (lines 274-276):
```javascript
default:
    p._res();  // Silently succeeds
    break;
```
- No-op implementation for Linux
- Resolves promise without error
- Could be implemented similar to sleepDisplay

---

### Module Export - Line 282

```javascript
module.exports = new powerMonitor();
```

**Design:** Singleton pattern - module exports single instance of powerMonitor class.

**Implications:**
- State shared across all `require('power-monitor')` calls
- Event listeners accumulate across multiple requires
- Initialization happens once at first require

---

### Usage

#### Basic Power Monitoring

```javascript
var power = require('power-monitor');

// Listen for AC/battery transitions
power.on('acdc', function(state) {
    if (state == 'BATTERY') {
        console.log('Switched to battery power - reducing agent activity');
        // Reduce polling frequency, defer non-critical tasks
    } else {
        console.log('Switched to AC power - resuming normal operations');
        // Resume full activity
    }
});

// Monitor battery level
power.on('batteryLevel', function(level) {
    console.log('Battery level: ' + level + '%');
    if (level < 20) {
        console.log('Low battery - suspending intensive operations');
        // Cancel large file transfers, disable desktop streaming, etc.
    }
});

// Get current state immediately (via newListener hook)
power.on('acdc', function(state) {
    console.log('Current power state: ' + state);
});
```

#### Display Power Control

```javascript
var power = require('power-monitor');

// Sleep display when remote session ends
function onSessionEnd() {
    power.sleepDisplay()
        .then(function() {
            console.log('Display put to sleep successfully');
        })
        .catch(function(err) {
            console.log('Failed to sleep display: ' + err);
        });
}

// Wake display when remote session starts
function onSessionStart() {
    power.wakeDisplay()
        .then(function() {
            console.log('Display woken successfully');
        })
        .catch(function(err) {
            console.log('Failed to wake display: ' + err);
        });
}

// Lock screen by sleeping display (security feature)
function lockScreen() {
    return power.sleepDisplay()
        .then(function() {
            // On many systems, display sleep triggers lock screen
            console.log('Screen locked via display sleep');
        });
}
```

#### Power-Aware Agent Operations

```javascript
var power = require('power-monitor');

var agentBehavior = {
    allowIntensiveOps: true,
    pollingInterval: 60000  // 1 minute
};

power.on('acdc', function(state) {
    if (state == 'BATTERY') {
        agentBehavior.allowIntensiveOps = false;
        agentBehavior.pollingInterval = 300000;  // 5 minutes
    } else {
        agentBehavior.allowIntensiveOps = true;
        agentBehavior.pollingInterval = 60000;   // 1 minute
    }
    updateAgentBehavior(agentBehavior);
});

power.on('batteryLevel', function(level) {
    if (level < 15) {
        // Critical battery - minimal operations only
        agentBehavior.allowIntensiveOps = false;
        agentBehavior.pollingInterval = 600000;  // 10 minutes
        pauseBackgroundTasks();
    }
});

function shouldPerformOperation(opType) {
    if (opType == 'intensive') {
        return agentBehavior.allowIntensiveOps;
    }
    return true;
}

// Example: Defer file transfer on battery
if (shouldPerformOperation('intensive')) {
    startLargeFileTransfer();
} else {
    console.log('Deferring file transfer - on battery power');
    queueForLater(startLargeFileTransfer);
}
```

### Dependencies

#### Module Dependencies

**Core Node.js Modules:**
- `events.EventEmitter` (line 25) - Event emitter base class
- `fs` (lines 59, 62, 70, 77, 87) - File system access for sysfs (Linux only)
- `child_process` (lines 126, 135, 216, 238) - Process spawning for commands (macOS)

**Platform-Specific MeshAgent Modules:**

**Windows-Only:**
- `user-sessions` (lines 50, 187, 193, 246, 252) - Windows session management, user detection
- `child-container` (lines 200, 206, 259, 265) - Process spawning in user session context
- `win-console` (lines 206, 265) - Console window hiding
- `_GenericMarshal` (lines 207, 266) - Native Win32 API marshalling

**Linux-Only:**
- `linux-acpi` (line 119) - ACPI event monitoring via kernel netlink

**Cross-Platform:**
- `promise` (line 181) - Custom promise implementation (not Node.js native)

#### System Dependencies

**Linux:**
- `/sys/class/power_supply/` - sysfs power supply interface (kernel 2.6.24+)
- ACPI kernel subsystem - For real-time AC adapter events
- Files:
  - `/sys/class/power_supply/*/type` - Device type (Mains/Battery)
  - `/sys/class/power_supply/*/online` - AC adapter connection status (1/0)
  - `/sys/class/power_supply/*/capacity` - Battery charge percentage (0-100)

**macOS:**
- `/usr/bin/pmset` - Power management settings utility (standard on all macOS)
- `/usr/bin/caffeinate` - Sleep prevention utility (OS X 10.8+)
- `/usr/bin/awk` - Text processing (standard Unix tool)
- `/bin/sh` - Shell interpreter

**Windows:**
- `User32.dll` - Windows user interface API (SendMessageA)
- `Kernel32.dll` - Windows core API (SetThreadExecutionState)
- Windows power management subsystem (broadcasts WM_POWERBROADCAST messages)

#### Binary/Tool Requirements by Platform

| Platform | Required Tools | Optional Tools | Purpose |
|----------|---------------|----------------|---------|
| Windows  | None (APIs only) | None | Native Win32 API calls |
| Linux    | None (sysfs only) | None | Sysfs and ACPI kernel interfaces |
| macOS    | pmset, sh, awk | caffeinate | Power status reading and display control |

#### Why macOS Dependencies Are Reliable

1. **Standard System Tools:** pmset, caffeinate, sh, and awk are part of base macOS installation
2. **Backwards Compatible:** pmset output format has remained consistent across macOS versions
3. **Root Not Required (Usually):** Most pmset operations work without elevation
4. **Fallback Handling:** Graceful degradation if caffeinate not found (wakeDisplay no-ops)

### Code Structure

The module is organized as a single class with platform-specific branches:

1. **Lines 1-16:** Copyright and licensing (Apache 2.0)
2. **Lines 17-20:** Windows API constants
3. **Lines 22-30:** Constructor and event initialization
4. **Lines 32-33:** State variables initialization
5. **Lines 35-40:** Windows event handler setup
6. **Lines 42-46:** newListener hook for state replay
7. **Lines 48-52:** Deferred user-sessions loading (Windows)
8. **Lines 54-120:** Linux implementation (sysfs + ACPI)
9. **Lines 121-178:** macOS implementation (pmset polling)
10. **Lines 179-228:** sleepDisplay() method
11. **Lines 229-279:** wakeDisplay() method
12. **Lines 281-282:** Module export

**Design Patterns:**
- **Singleton:** Single instance exported
- **Event Emitter:** Observer pattern for power state changes
- **Platform Abstraction:** Unified interface, platform-specific implementations
- **Promise-Based Async:** Modern async/await compatible
- **Polling vs. Events:** Uses native events where available (Windows, Linux ACPI), falls back to polling (macOS, Linux battery level)

### Technical Notes

**Event Frequency:**

- **Windows:** Real-time events from OS (instant notifications)
- **Linux ACPI:** Real-time events for AC adapter, polled battery levels (5 min)
- **macOS:** All power state changes polled every 5 minutes

**Performance Implications:**

**Windows:**
- Near-zero overhead when idle (event-driven)
- Message processing integrated with user-sessions module

**Linux:**
- Very low overhead:
  - Sysfs reads are memory-mapped kernel data (fast)
  - ACPI events via netlink socket (efficient kernel notification)
  - Polling timer runs only if battery present

**macOS:**
- Moderate overhead:
  - Spawns shell process every 5 minutes
  - Executes pmset and awk (10-50ms typical)
  - Could be optimized with native IOKit APIs, but command-line approach is simpler

**5-Minute Polling Justification:**

Battery levels change slowly:
- Typical laptop: 1% per 6-12 minutes during use
- 5-minute polling catches changes within 5% granularity
- Balance between responsiveness and system load
- More frequent polling wastes CPU cycles without benefit

**Display Sleep/Wake Security Considerations:**

**Windows:**
- Requires user session context (not available as LocalSystem)
- child-container spawns process in user's security context
- User must be logged in for operation to succeed

**macOS:**
- pmset may require admin privileges in some macOS versions
- caffeinate generally works without elevation
- Screen lock may trigger automatically on display sleep (depends on system preferences)

**Linux:**
- Not implemented, but if it were:
  - DPMS requires X11 connection (DISPLAY environment)
  - Wayland requires compositor-specific protocols
  - May require user session or specific permissions

**Error Handling:**

**Graceful Degradation:**
- macOS without battery: Returns default values, doesn't start polling
- macOS without caffeinate: wakeDisplay silently succeeds
- Linux without batteries: Doesn't start polling
- Windows without logged-in user: Rejects promise with clear error

**Parse Errors:**
- macOS pmset parsing: Falls back to safe defaults (AC, 100%)
- Prevents crashes on unexpected output format

**Multi-Battery Handling:**

**Linux Only:** Averages charge across multiple batteries (line 89)
- Useful for laptops with internal + external batteries
- Returns mean percentage (e.g., 80% + 60% = 70%)

**Windows and macOS:** Report single aggregate battery level
- OS provides unified battery percentage

**newListener Hook Pattern:**

Critical for proper initialization (lines 42-46):
```javascript
this.on('newListener', function (name, callback) {
    if (name == 'acdc') { callback.call(this, this._ACState == 1 ? 'AC' : 'BATTERY'); }
    if (name == 'batteryLevel') { if (this._BatteryLevel >= 0) { callback.call(this, this._BatteryLevel); } }
});
```

**Why?** Allows consumers to get current state immediately rather than waiting for next change event.

**Example:**
```javascript
power.on('acdc', function(state) {
    console.log('Power state: ' + state);  // Called immediately with current state
});
```

Without this hook, code would need separate getCurrentState() method.

**Polling Cleanup:**

Intervals stored in `this._BattCheckInterval` (lines 104, 173) but never explicitly cleared. Could lead to:
- Continued polling after module "unloaded" (though module is singleton)
- Minor memory leak if instance could be recreated

**Best Practice:** Should implement cleanup method:
```javascript
this.stop = function() {
    if (this._BattCheckInterval) {
        clearInterval(this._BattCheckInterval);
        delete this._BattCheckInterval;
    }
};
```

### Platform-Specific Analysis

**What Works on macOS:**

**All Core Functionality:**

1. **Power State Monitoring** - Lines 121-178
   - AC/battery detection via pmset
   - Works on all MacBooks with batteries
   - Desktop Macs report AC power constantly

2. **Battery Level Monitoring** - Lines 133-152, 153-166
   - Accurate percentage from pmset
   - 5-minute polling provides timely updates
   - Graceful fallback for desktop Macs

3. **Display Sleep** - Lines 215-222
   - `pmset displaysleepnow` immediately sleeps display
   - May trigger screen lock if configured
   - Works on all macOS versions with pmset

4. **Display Wake** - Lines 235-244
   - `caffeinate -u` simulates user activity
   - Available on OS X 10.8+
   - Gracefully handles absence of caffeinate

5. **Event System** - Lines 25-30, 42-46
   - Full EventEmitter functionality
   - newListener hook provides instant state
   - All events (acdc, batteryLevel) work correctly

**macOS Advantages:**

1. **Reliable Tooling:** pmset and caffeinate are first-party Apple utilities with stable interfaces
2. **Comprehensive Data:** pmset provides AC/battery status, charge level, charging state, and time remaining in single call
3. **No Privileges Required (Usually):** Most operations work without root
4. **macOS-Specific Features Available:**
   - Could extend to read time remaining (`pmset -g batt` provides this)
   - Could detect charging vs. discharging state
   - Could detect battery health information

**macOS Limitations:**

1. **Polling Delay:** 5-minute intervals mean changes detected with up to 5-minute lag
   - Windows/Linux detect AC changes instantly
   - Not critical for typical use cases (battery drains slowly)

2. **Process Spawning Overhead:** Every poll spawns shell + pmset + awk processes
   - ~10-50ms overhead every 5 minutes
   - Could be eliminated with native IOKit Power Sources API

3. **Display Wake Less Forceful:** caffeinate simulates user activity rather than directly controlling display power
   - May not wake display in all situations
   - Windows SetThreadExecutionState is more direct

**Potential macOS Improvements:**

1. **Native IOKit APIs:** Could use `IOPSCopyPowerSourcesInfo()` for power status
   - Eliminate pmset spawning
   - Enable event-driven monitoring (no polling)
   - Requires native bindings (more complex)

2. **CoreGraphics Display Control:** Could use `CGDisplaySetDisplayMode()` for more control
   - More reliable display wake
   - Requires native Objective-C bindings

3. **Battery Health Metrics:** pmset provides additional data not currently parsed:
   - Cycle count
   - Battery health percentage
   - Designed capacity vs. current capacity

**Comparison Across Platforms:**

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| **Power Monitoring** | Real-time events | ACPI events | 5-min polling |
| **Battery Level** | Real-time events | 5-min polling | 5-min polling |
| **Multi-Battery** | Aggregated | Averaged | Aggregated |
| **Display Sleep** | Win32 API | Not implemented | pmset command |
| **Display Wake** | Win32 API | No-op | caffeinate |
| **Privileges** | User session req | None | None (usually) |
| **Overhead** | Very low | Very low | Low-moderate |
| **Responsiveness** | Instant | Instant (AC), 5-min (battery) | 5-min |

**Production Considerations for macOS:**

1. **MacBook Fleets:** Essential for managing MacBook laptops remotely
2. **Battery Policies:** Can defer intensive operations on battery
3. **Display Control:** Useful for privacy/security (lock screens)
4. **Desktop Macs:** Gracefully handles systems without batteries
5. **Testing:** Should test on both Intel and Apple Silicon Macs

## Summary

The power-monitor.js module provides **comprehensive, production-ready power management monitoring for macOS** alongside Windows and Linux. It implements full functionality for power state monitoring, battery level tracking, and display sleep/wake control.

**Key Characteristics:**

- **Cross-Platform:** Unified interface across Windows, Linux, and macOS
- **Event-Driven:** Observer pattern for reactive agent behavior
- **Platform-Optimized:** Uses native events where available, polling where necessary
- **Promise-Based:** Modern async API for display control
- **Graceful Degradation:** Handles systems without batteries elegantly

**macOS Implementation:**

- **Power Monitoring:** Uses `pmset -g batt` with awk parsing (lines 133-152)
- **Polling:** 5-minute intervals for battery status updates
- **Display Sleep:** `pmset displaysleepnow` command (line 221)
- **Display Wake:** `caffeinate -u -t 2` command (line 238)
- **Reliability:** Standard macOS utilities with stable interfaces
- **Privileges:** Generally works without root access

**Strengths on macOS:**

1. Standard system tools (no native bindings required)
2. Works on all MacBooks with batteries
3. Graceful handling of desktop Macs
4. Full feature parity with other platforms
5. Production-ready and reliable

**Limitations on macOS:**

1. 5-minute polling delay (vs. instant on Windows)
2. Process spawning overhead (could use IOKit for efficiency)
3. Display wake less direct than Windows

**Use Cases:**

- Laptop fleet management (defer operations on battery)
- Power-aware task scheduling (avoid intensive ops on low battery)
- Display control for security (sleep display when session ends)
- Energy efficiency (reduce polling on battery)
- User experience (warn before draining battery)

**macOS Support:** **Fully supported** with complete functionality. While the implementation uses command-line tools rather than native APIs (introducing modest polling overhead), it is reliable, production-ready, and suitable for all macOS-based MeshAgent deployments.
