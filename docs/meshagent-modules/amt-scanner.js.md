# amt-scanner.js

Network scanner for discovering Intel AMT-enabled devices on local networks using RMCP (Remote Management Control Protocol) ping packets. Sends UDP broadcast/unicast probes to identify systems with active AMT firmware and retrieves basic AMT configuration information without authentication.

## Platform

**Supported Platforms:**
- Windows (all versions) - Full support
- Linux (all distributions) - Full support

**Excluded Platforms:**
- **macOS** - Excluded (architectural decision)

**Exclusion Reasoning:**

While **technically cross-platform and fully compatible**, this module is excluded from macOS builds because:

1. **Part of Intel AMT Management Stack** - Component of the broader Intel AMT management ecosystem which is not typically deployed on macOS systems in enterprise environments.

2. **Limited Use Case on macOS** - Intel AMT management infrastructure is predominantly deployed on Windows/Linux servers. macOS workstations are rarely used as AMT management platforms in enterprise IT operations.

3. **Architectural Decision** - The entire Intel AMT module suite is excluded from macOS builds to maintain consistent platform targeting, even though this particular scanner module has no technical limitations.

**Technical Capability:**

Despite the exclusion, the module is fully cross-platform because:
- **No Hardware Dependencies** - Scanner performs network operations only, does not require local Intel AMT hardware, HECI interface, or Management Engine
- **Network-Only Protocol** - Uses standard UDP sockets via Node.js `dgram` module (line 29) to send RMCP packets over the network
- **Pure JavaScript** - No binary dependencies or native modules
- **Scans Remote Devices** - Discovers AMT on other computers, not the local system

---

## Functionality

### Core Purpose

AMT Scanner provides unauthenticated discovery of Intel AMT-enabled devices by:

1. **Network Scanning** - Probe IP ranges for AMT presence
2. **Version Detection** - Identify AMT firmware major/minor version
3. **Provisioning State** - Determine if device is pre/in/post provisioning
4. **Port Discovery** - Find open AMT management ports (16992/16993)
5. **Fast Discovery** - Parallel UDP probing for rapid network scanning

### RMCP Protocol

**RMCP (Remote Management Control Protocol):**
- DMTF standard protocol (DSP0136)
- UDP-based, port 623
- Used by IPMI and Intel AMT for discovery
- No authentication required for ping/pong

**RMCP Ping Packet Format - Line 31-35:**
```
Bytes 0-11:  06 00 00 06 00 00 11 BE 80 00 00 00
Byte 9:      Tag (user-defined identifier)
```

**Packet Structure:**
- Byte 0: RMCP version (0x06)
- Bytes 1-2: Reserved (0x00)
- Byte 3: RMCP sequence (0x06)
- Byte 4: Class of message (0x00)
- Bytes 5-7: ASF IANA enterprise number (0x000011BE)
- Byte 8: Message type (0x80 = Presence Pong)
- Byte 9: Message tag
- Bytes 10-11: Reserved (0x0000)

---

### AMTScanner Constructor - Lines 25-107

**Constructor:** `AMTScanner()`

**Purpose:** Creates scanner instance with event-driven result handling

**Events:**
- `found` - Emitted when scan completes with array of discovered devices

**Internal Properties:**
- `dgram` - UDP socket module (line 29)

---

### Methods

#### buildRmcpPing(tag) - Lines 31-35

**Purpose:** Construct RMCP presence ping packet

**Parameters:**
- `tag` - 8-bit identifier to match response (0-255)

**Returns:** 12-byte Buffer containing RMCP ping

**Implementation:**
```javascript
var packet = Buffer.from('06000006000011BE80000000', 'hex');
packet[9] = tag;
return packet;
```

**Usage:** Generate probe packet for AMT discovery

---

#### parseRmcpPacket(server, data, rinfo, func) - Lines 37-55

**Purpose:** Parse RMCP presence pong response

**Parameters:**
- `server` - UDP socket that received packet
- `data` - Response buffer (minimum 20 bytes)
- `rinfo` - Remote info object with `address` property
- `func` - Callback function for valid responses

**Response Validation - Lines 38-40:**
- Minimum 20 bytes required
- Checks specific byte patterns in header
- Validates AMT response bit (byte 21, bit 5)

**Parsed Fields - Lines 41-49:**

```javascript
{
    servertag: data[9],              // Server tag (matches ping tag)
    minorVersion: data[18] & 0x0F,   // AMT minor version (low nibble)
    majorVersion: (data[18] >> 4),   // AMT major version (high nibble)
    provisioningState: data[19] & 0x03,  // 0=PRE, 1=IN, 2=POST
    openPort: (data[16] * 256) + data[17],  // Primary management port
    dualPorts: (data[19] & 0x04) != 0,      // True if both ports active
    address: rinfo.address                   // IP address of AMT device
}
```

**Dual Port Logic - Line 50:**
- If `dualPorts` true: `openPorts = [16992, 16993]`
- If false: `openPorts = [single detected port]`

**AMT Firmware Version:**
- Byte 18 encodes version: `(major << 4) | minor`
- Example: 0x0C = AMT 12.0, 0x66 = AMT 6.6

**Provisioning States:**
- 0 = PRE (not provisioned)
- 1 = IN (provisioning in progress)
- 2 = POST (fully provisioned)

---

#### parseIPv4Range(range) - Lines 57-72

**Purpose:** Convert IP range string to min/max numeric values

**Supported Formats:**

1. **Dash Range:** `"192.168.1.10-192.168.1.50"`
   - Returns: `{ min: 3232235786, max: 3232235826 }`

2. **CIDR Notation:** `"192.168.1.0/24"`
   - Returns: `{ min: 3232235777, max: 3232236030 }`
   - **Note:** Excludes network and broadcast addresses (line 67)
   - Supports /17 to /32 only (line 64)

3. **Single IP:** `"192.168.1.100"`
   - Returns: `{ min: 3232235876, max: 3232235876 }`

**Validation:**
- Returns `null` for invalid formats
- CIDR masks outside 17-32 range rejected

**Implementation Details:**
- Line 67: Adds 1 to min, subtracts 1 from max to exclude network/broadcast
- Prevents scanning .0 (network) and .255 (broadcast) addresses

---

#### parseIpv4Addr(addr) - Lines 75-79

**Purpose:** Convert dotted-decimal IP to 32-bit integer

**Parameters:**
- `addr` - String like "192.168.1.100"

**Returns:** 32-bit integer or `null` if invalid

**Calculation:**
```javascript
(octet1 << 24) + (octet2 << 16) + (octet3 << 8) + octet4
```

**Example:**
- "192.168.1.100" → 3232235876
- "10.0.0.1" → 167772161

---

#### IPv4NumToStr(num) - Lines 82-84

**Purpose:** Convert 32-bit integer to dotted-decimal IP

**Parameters:**
- `num` - 32-bit integer IP address

**Returns:** String like "192.168.1.100"

**Calculation:**
```javascript
((num >> 24) & 0xFF) + '.' +
((num >> 16) & 0xFF) + '.' +
((num >> 8) & 0xFF) + '.' +
(num & 0xFF)
```

---

#### scan(rangestr, timeout, callback) - Lines 86-106

**Purpose:** Perform network scan for AMT devices

**Parameters:**
- `rangestr` - IP range string (dash, CIDR, or single IP)
- `timeout` - Milliseconds to wait for responses
- `callback` - Function called with results array

**Process Flow:**

1. **Parse Range** (line 87)
   - Converts range string to min/max integers

2. **Build Probe** (line 88)
   - Creates RMCP ping with tag 0

3. **Create Socket** (line 89)
   - UDP4 socket for sending/receiving
   - Binds to 0.0.0.0 with ephemeral port (line 96)

4. **Setup Handlers:**
   - **error** (line 92) - Log errors
   - **message** (line 93) - Parse responses, collect results
   - **listening** (line 94) - Send probes to all IPs in range

5. **Send Probes** (lines 94-95)
   - Iterates from `iprange.min` to `iprange.max`
   - Sends RMCP ping to each IP on port 623

6. **Wait for Responses** (line 97)
   - Timeout timer starts
   - Responses collected in `server.scanResults`

7. **Completion** (lines 97-105)
   - Timer expires, closes socket
   - Invokes callback with results array
   - Emits `found` event with results

**Performance:**
- **Parallel Probing:** All IPs probed simultaneously
- **No Rate Limiting:** May generate significant network traffic
- **Response Collection:** All responses within timeout included

**Example Timeline:**
```
Time 0ms:    Scan starts, 100 probes sent instantly
Time 5ms:    First response received
Time 50ms:   20 responses collected
Time 2000ms: Timeout expires, return 23 total results
```

---

## Dependencies

### JavaScript Module Dependencies

#### require('events').inherits() - Line 26
**Type:** Core Node.js module
**Purpose:** Event emitter functionality
**Usage:** Provides `found` event emission
**Cross-Platform:** Yes

#### require('dgram') - Line 29
**Type:** Core Node.js module
**Purpose:** UDP datagram socket operations
**Usage:** Creating UDP sockets for RMCP packet transmission
**Cross-Platform:** Yes (all platforms)

**No Binary Dependencies** - Scanner is pure JavaScript with no native modules

---

## Relationship to Other AMT Modules

### Independence from Hardware Modules

amt-scanner.js is **completely independent** of hardware-dependent AMT modules:

| Module | Dependency | Reason |
|--------|------------|--------|
| **amt-lme.js** | None | Scanner doesn't need local LME/port forwarding |
| **amt-mei.js** | None | Scanner doesn't use PTHI commands |
| **amt_heci.js** | None | Scanner doesn't require HECI hardware |
| **heci** | None | Scanner uses network, not local hardware |

### Complementary to Remote Modules

Scanner works alongside network-based AMT modules:

1. **amt-scanner.js** (this module)
   - **Phase 1:** Discover AMT devices on network
   - **Output:** IP addresses, versions, provisioning states

2. **amt-wsman.js**
   - **Phase 2:** Connect to discovered devices
   - **Input:** IP addresses from scanner
   - **Action:** Perform management operations via WSMAN

3. **amt.js**
   - **Phase 3:** High-level management
   - **Input:** WSMAN connections to scanned devices
   - **Action:** Configuration, control, monitoring

**Typical Workflow:**
```javascript
// 1. Scan network
var scanner = new AMTScanner();
scanner.scan('192.168.1.0/24', 2000, function(devices) {

    // 2. Connect to each device
    devices.forEach(function(device) {
        if (device.provisioningState === 2) {  // POST
            var wsman = require('amt-wsman').create(
                device.address,
                16992,
                'admin',
                'password'
            );

            // 3. Perform management
            wsman.Get('AMT_GeneralSettings', function(obj, response) {
                console.log('Device:', device.address, response);
            });
        }
    });
});
```

---

## Hardware Requirements

### Scanner System Requirements

**Local System (running scanner):**
- **No special hardware required**
- Standard network interface
- UDP port 623 outbound access
- No Intel AMT, vPro, or ME needed

**Target Systems (being scanned):**
- Intel AMT-capable hardware
- AMT firmware enabled in BIOS
- Network connectivity
- Port 623 (UDP) responding
- Optionally ports 16992/16993 (TCP) for management

### Network Requirements

1. **UDP Port 623 Access**
   - Must not be blocked by firewalls
   - Both outbound (scanner) and inbound (AMT devices)

2. **Broadcast/Multicast Support**
   - For CIDR scanning, subnet broadcast may be used
   - Some networks filter broadcast traffic

3. **Network Topology**
   - Works on local subnet (Layer 2)
   - Can scan across routers if routing permits
   - RMCP typically not routed across WAN

---

## Usage Examples

### Basic Network Scan

```javascript
var AMTScanner = require('amt-scanner');
var scanner = new AMTScanner();

// Scan subnet, 5 second timeout
scanner.scan('192.168.1.0/24', 5000, function(devices) {
    console.log('Found', devices.length, 'AMT devices');
    devices.forEach(function(device) {
        console.log('IP:', device.address);
        console.log('  Version:', device.majorVersion + '.' + device.minorVersion);
        console.log('  Provisioning:', ['PRE', 'IN', 'POST'][device.provisioningState]);
        console.log('  Ports:', device.openPorts.join(', '));
    });
});
```

### Event-Driven Scanning

```javascript
var AMTScanner = require('amt-scanner');
var scanner = new AMTScanner();

scanner.on('found', function(devices) {
    console.log('Scan complete:', devices.length, 'devices');
});

scanner.scan('10.0.0.1-10.0.0.254', 3000);
```

### Filtering Results

```javascript
var scanner = new AMTScanner();

scanner.scan('192.168.1.0/24', 2000, function(devices) {
    // Find only provisioned devices
    var provisioned = devices.filter(function(d) {
        return d.provisioningState === 2;  // POST
    });

    // Find AMT 11.0 or newer
    var modern = devices.filter(function(d) {
        return d.majorVersion >= 11;
    });

    // Find devices with HTTPS enabled
    var secure = devices.filter(function(d) {
        return d.openPorts.indexOf(16993) !== -1;
    });

    console.log('Provisioned:', provisioned.length);
    console.log('AMT 11+:', modern.length);
    console.log('HTTPS enabled:', secure.length);
});
```

### Single Device Check

```javascript
var scanner = new AMTScanner();

scanner.scan('192.168.1.100', 1000, function(devices) {
    if (devices.length > 0) {
        console.log('AMT detected:', devices[0]);
    } else {
        console.log('No AMT at this address');
    }
});
```

### Large Network Scan

```javascript
var scanner = new AMTScanner();

// Scan large network (254 addresses)
// Use longer timeout for larger ranges
scanner.scan('10.50.0.0/24', 10000, function(devices) {
    // Save to database, generate report, etc.
    var report = {
        scanned: '10.50.0.0/24',
        timestamp: new Date(),
        found: devices.length,
        devices: devices
    };

    require('fs').writeFileSync(
        'amt-scan-results.json',
        JSON.stringify(report, null, 2)
    );
});
```

---

## Response Structure

### Device Object Format

Each discovered device returns:

```javascript
{
    servertag: 0,              // Echo of ping tag (usually 0)
    minorVersion: 0,           // AMT minor version (0-15)
    majorVersion: 11,          // AMT major version (0-15)
    provisioningState: 2,      // 0=PRE, 1=IN, 2=POST
    openPort: 16992,           // Primary detected port
    openPorts: [16992, 16993], // Array of available ports
    address: '192.168.1.100'   // IP address string
}
```

### AMT Version Examples

| majorVersion | minorVersion | AMT Version |
|--------------|--------------|-------------|
| 6 | 0 | AMT 6.0 |
| 6 | 2 | AMT 6.2 |
| 7 | 0 | AMT 7.0 |
| 8 | 0 | AMT 8.0 |
| 9 | 0 | AMT 9.0 |
| 10 | 0 | AMT 10.0 |
| 11 | 0 | AMT 11.0 |
| 11 | 6 | AMT 11.6 |
| 12 | 0 | AMT 12.0 |

### Port Interpretation

**openPorts Array:**

- **[16992]** - HTTP only (older AMT or HTTP-only config)
- **[16993]** - HTTPS only (security-focused config)
- **[16992, 16993]** - Both HTTP and HTTPS available (typical)

**Port 16992:**
- HTTP-based WSMAN
- Unencrypted management
- Digest authentication
- Legacy compatibility

**Port 16993:**
- HTTPS-based WSMAN
- TLS-encrypted management
- Certificate validation
- Recommended for production

---

## Performance Considerations

### Scan Speed Factors

1. **Network Latency**
   - Local subnet: ~1-5ms response time
   - Routed networks: 10-50ms+ response time
   - Timeout should be 2-3x expected max latency

2. **Target Count**
   - /24 subnet = 254 addresses probed
   - /16 subnet = 65,534 addresses (very slow)
   - Single IP = instant

3. **AMT Response Time**
   - Firmware responsiveness varies
   - Busy devices may respond slowly
   - Some AMT versions respond faster than others

### Recommended Timeouts

| Network Size | Recommended Timeout |
|--------------|---------------------|
| Single IP | 1000ms (1 second) |
| /28 (16 IPs) | 2000ms (2 seconds) |
| /24 (254 IPs) | 3000-5000ms (3-5 seconds) |
| /20 (4096 IPs) | 10000ms+ (10+ seconds) |

### Network Impact

**Bandwidth Usage:**
- Each probe: 12 bytes out + ~28 bytes back = 40 bytes
- /24 scan: 254 × 40 = 10,160 bytes (~10 KB)
- Minimal bandwidth impact

**Packet Rate:**
- All probes sent simultaneously
- Can generate burst of 254+ packets/second
- May trigger IDS/IPS alerts on some networks

**Network Friendliness:**
- UDP probes are lightweight
- No connection state maintained
- Firewalls may drop RMCP packets

---

## Security Considerations

### Scanner Security

1. **No Authentication Required**
   - RMCP ping/pong is unauthenticated
   - Anyone on network can scan for AMT devices
   - Information disclosure risk

2. **Information Leaked by RMCP**
   - Device presence and location
   - AMT version (potential vulnerability identification)
   - Provisioning state (attack surface indication)
   - Open ports (service enumeration)

3. **Scanning Detection**
   - IDS/IPS may log RMCP scans
   - Network monitoring can detect scanner
   - May violate acceptable use policies

### AMT Device Security

1. **RMCP Should Be Filtered**
   - Block UDP 623 at firewall perimeter
   - Limit RMCP to management VLAN
   - Prevent external scanning

2. **Provisioning State Exposure**
   - Pre-provisioned devices visible
   - Unprovision attack vector identification
   - Should provision quickly after deployment

3. **Version Disclosure**
   - Reveals potential vulnerabilities
   - Aids targeted attacks
   - Keep AMT firmware updated

### Best Practices

1. **Authorized Scanning Only**
   - Obtain permission before scanning networks
   - Document scanning activities
   - Use for inventory/audit purposes only

2. **Limit Scan Scope**
   - Scan only managed networks
   - Avoid scanning public/external networks
   - Respect network boundaries

3. **Secure Results**
   - Protect device inventory lists
   - Encrypt stored scan results
   - Limit access to AMT device data

---

## Limitations

### Protocol Limitations

1. **UDP-Based**
   - No delivery guarantee
   - Packets may be lost
   - False negatives possible

2. **Firewall Sensitivity**
   - Blocked by many firewalls
   - May require firewall rules
   - Results depend on network configuration

3. **Limited Information**
   - Only basic AMT details
   - No configuration data
   - No authentication status

### Network Limitations

1. **Subnet Boundary**
   - Works best on local subnet
   - May not cross VLANs
   - Router configuration dependent

2. **Broadcast/Multicast**
   - Some networks filter broadcasts
   - May require unicast scanning
   - Performance varies by network

3. **Port 623 Availability**
   - Must be accessible
   - Often blocked by default
   - Requires network access

### Scanning Limitations

1. **No Parallel Timeouts**
   - Single timeout for entire scan
   - Slow devices delay completion
   - No per-device timeout

2. **No Progress Indication**
   - Callback only at end
   - No incremental results
   - Can't cancel in progress

3. **IPv4 Only**
   - No IPv6 support
   - Limited to IPv4 networks
   - No dual-stack scanning

---

## Troubleshooting

### No Devices Found

**Possible Causes:**

1. **No AMT Devices Present**
   - Verify target systems have AMT hardware
   - Check AMT enabled in BIOS
   - Confirm AMT firmware provisioned

2. **Network Configuration**
   - Firewall blocking UDP 623
   - VLANs preventing communication
   - Routing issues

3. **AMT Configuration**
   - RMCP disabled in AMT settings
   - AMT in sleep mode
   - System powered off

**Solutions:**
- Test with known AMT device first
- Verify network connectivity (ping)
- Check firewall rules
- Increase timeout value
- Try single IP scan

### Incomplete Results

**Possible Causes:**

1. **Timeout Too Short**
   - Slow network responses
   - Distant devices
   - High network latency

2. **Packet Loss**
   - Network congestion
   - Firewall intermittent blocking
   - UDP packet drops

3. **AMT Load**
   - Devices busy with management
   - Firmware slow to respond

**Solutions:**
- Increase timeout (double it)
- Scan smaller ranges
- Retry scan
- Check network quality

### Unexpected Results

**Symptoms:**
- Wrong IP addresses
- Invalid version numbers
- Duplicate entries

**Possible Causes:**
- Network address translation (NAT)
- RMCP proxies or relays
- Non-AMT RMCP responders

**Solutions:**
- Verify target network
- Test individual devices
- Compare with known inventory
- Check for network middleboxes

---

## Platform-Specific Notes

### Windows
- Works on all Windows versions with Node.js
- No special permissions required
- Windows Firewall may prompt for network access
- Use PowerShell or CMD to run

### Linux
- Works on all distributions
- May require `sudo` if binding to privileged ports (not needed for scanner)
- Firewall (iptables/nftables) may block UDP 623
- Check with `netstat -an | grep 623`

### macOS
- **Fully supported** (unlike other AMT modules)
- No special permissions required
- macOS firewall may prompt for network access
- Works on both Intel and Apple Silicon Macs
- Useful for IT admins managing PC fleets from Mac

---

## Advanced Use Cases

### Continuous Monitoring

```javascript
var scanner = new AMTScanner();

function monitorNetwork() {
    scanner.scan('192.168.1.0/24', 3000, function(devices) {
        // Check for new devices
        // Alert on provisioning changes
        // Update inventory database

        // Scan again in 5 minutes
        setTimeout(monitorNetwork, 300000);
    });
}

monitorNetwork();
```

### Integration with Management System

```javascript
var scanner = new AMTScanner();
var database = require('./database');

scanner.scan('10.0.0.0/16', 30000, function(devices) {
    devices.forEach(function(device) {
        database.upsertDevice({
            ip: device.address,
            amtVersion: device.majorVersion + '.' + device.minorVersion,
            provisioned: device.provisioningState === 2,
            ports: device.openPorts,
            lastSeen: new Date()
        });
    });
});
```

### Vulnerability Assessment

```javascript
var scanner = new AMTScanner();

scanner.scan('192.168.1.0/24', 5000, function(devices) {
    var vulnerable = devices.filter(function(d) {
        // AMT versions with known vulnerabilities
        return d.majorVersion < 11 ||
               (d.majorVersion === 11 && d.minorVersion < 8);
    });

    console.log('Vulnerable devices:', vulnerable.length);
    vulnerable.forEach(function(d) {
        console.log('UPDATE REQUIRED:', d.address,
                    'AMT', d.majorVersion + '.' + d.minorVersion);
    });
});
```
