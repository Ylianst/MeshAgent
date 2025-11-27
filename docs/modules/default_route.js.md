# default_route.js

Network routing utility that identifies the default gateway interface and metric for the system. Used to determine which network interface is actively routing internet traffic for network diagnostics and tunnel configuration.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via GetIpForwardTable API
- Linux - Full support via ip route command
- macOS (darwin) - Full support via netstat -rn
- FreeBSD - Full support via netstat -rn

**Excluded Platforms:**
- None - All platforms supported

## Functionality

### Purpose

Identifies default network route for:
- Tunnel source interface selection
- Network diagnostics
- Connectivity verification
- Multi-homed system routing decisions

### Key Functions

#### windows_defaultRoute() - Lines 17-50 (Windows Implementation)

Uses `Iphlpapi.dll::GetIpForwardTable()` to find default route (0.0.0.0).

**Process:**
1. First call to get buffer size (ERROR_INSUFFICIENT_BUFFER = 122)
2. Allocate buffer and retry
3. Iterate through routing table (56 bytes per entry)
4. Find destination 0.0.0.0
5. Select lowest metric if multiple defaults

**Return:** `{ interface: 12, metric: 25 }` (interface is numeric index)

#### linux_defaultRoute() - Lines 52-60 (Linux Implementation)

Executes: `ip route | grep default | awk '{ if($1=="default" && $4=="dev") { print $5; } }'`

**Return:** `{ interface: "eth0", metric: 1 }` (interface is string name)

#### bsd_defaultRoute() - Lines 62-70 (macOS/FreeBSD Implementation)

Executes: `netstat -rn -f inet | grep default | awk '{ print $NF }'`

**Return:** `{ interface: "en0", metric: 1 }` (interface is string name)

### Dependencies

- **_GenericMarshal** (Windows) - Win32 API access
- **child_process** (Unix) - Shell command execution

### Usage

```javascript
var route = require('default_route')();
if (route) {
  console.log('Default interface:', route.interface);
  console.log('Metric:', route.metric);
}
```

### Technical Notes

**Return Format:**
```javascript
// Windows
{ interface: 12, metric: 25 }  // Numeric index

// Linux/macOS/FreeBSD
{ interface: "eth0", metric: 1 }  // String name

// No route
null
```

**Platform Differences:**

**Windows:**
- Uses MIB_IPFORWARDROW structure
- Interface is numeric adapter index
- Actual metric from routing table
- Handles multiple default routes

**Linux:**
- Uses `ip route` command (modern)
- Interface is string name (eth0, wlan0, ens33)
- Metric hardcoded to 1

**macOS/FreeBSD:**
- Uses `netstat -rn -f inet` (traditional)
- Interface is string name (en0, en1)
- Metric hardcoded to 1
- IPv4 only (`-f inet`)

## Summary

The default_route.js module identifies the default network gateway interface for routing decisions. Windows provides actual metrics via API, while Unix platforms use command-line tools.

**macOS support:** Full support via netstat, returns interface name and metric 1.
