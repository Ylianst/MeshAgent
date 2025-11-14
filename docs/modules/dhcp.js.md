# dhcp.js

Mini DHCP client module for fetching network configuration data from DHCP servers. Provides simple functionality to query DHCP information for specific network interfaces, retrieving details such as subnet masks, routers, DNS servers, domain names, and lease times.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support
- Linux - Full support
- macOS (darwin) - Full support
- FreeBSD - Full support

**Excluded Platforms:**
- None - This module is cross-platform

**Exclusion Reasoning:**

This module has no platform exclusions. It implements the standard DHCP (Dynamic Host Configuration Protocol) which is platform-independent and works identically across all operating systems. The module uses Node.js's built-in `dgram` module for UDP socket communication and the `os` module for network interface enumeration, both of which are cross-platform.

## Functionality

### Purpose

The dhcp module serves as a lightweight DHCP client for querying network configuration information from DHCP servers. It provides functionality to:

- Send DHCP INFORM messages to DHCP servers
- Parse DHCP responses and extract configuration data
- Query DHCP information for specific network interfaces
- Support both interface names and MAC addresses as identifiers

This module is typically used:
- To gather network configuration details without modifying interface settings
- During system information collection
- For network diagnostics and troubleshooting
- To validate DHCP server availability and configuration

### Key Functions/Methods

#### parseDHCP(buffer) - Lines 51-136

**Purpose:** Parses raw DHCP packet data into a structured JavaScript object.

**Process:**
- Extracts DHCP header fields (op code, hardware length, transaction ID)
- Decodes IP addresses (client, your, server, gateway)
- Extracts client hardware address (MAC address)
- Validates magic cookie (bytes 236-239 must be 99, 130, 83, 99)
- Parses DHCP options into a readable format

**Parsed Options:**
- Option 1: Subnet Mask → `ret.options.subnetmask`
- Option 3: Router → `ret.options.router` (array of gateway addresses)
- Option 6: DNS Server → `ret.options.dns`
- Option 15: Domain Name → `ret.options.domainname`
- Option 28: Broadcast Address → `ret.options.broadcastaddr`
- Option 51: Lease Time → `ret.options.lease` (with hours, minutes, seconds breakdown)
- Option 53: Message Type → `ret.options.messageType` (1-8, see MESSAGE_TYPES)
- Option 54: DHCP Server → `ret.options.server`

**Return Value:**
```javascript
{
    op: 'REQ' | 'RES',
    hlen: <hardware_address_length>,
    xid: <transaction_id>,
    ciaddr: '<client_ip>',
    yiaddr: '<your_ip>',
    siaddr: '<server_ip>',
    giaddr: '<gateway_ip>',
    chaddr: '<client_mac_address>',
    magic: true,
    options: {
        subnetmask: '<mask>',
        router: ['<gateway1>', '<gateway2>'],
        dns: '<dns_server>',
        domainname: '<domain>',
        broadcastaddr: '<broadcast>',
        lease: { raw: <seconds>, hours: <h>, minutes: <m>, seconds: <s> },
        messageType: <1-8>,
        server: '<dhcp_server_ip>'
    }
}
```

**Platform Behavior:**
- All platforms supported
- Standard DHCP packet format (RFC 2131)

---

#### createPacket(messageType, data) - Lines 138-209

**Purpose:** Creates a DHCP request packet for sending to DHCP servers.

**Process:**
- Allocates 245-byte buffer
- Sets appropriate headers (op code, hardware type, address length, hops)
- Generates random transaction ID for request tracking
- Sets broadcast flag (0x8000) in flags field
- Includes magic cookie (99, 130, 83, 99) at bytes 236-239
- Adds DHCP message type option (option 53)
- For DHCP INFORM (type 8): Includes client IP address and MAC address

**Parameters:**
- `messageType` - DHCP message type (typically 8 for INFORM)
- `data` - Object containing:
  - `ciaddress` - Client IP address (required for INFORM)
  - `chaddress` - Client hardware (MAC) address (required for INFORM)

**Supported Message Types:**
- **0x08 (8)** - DHCP INFORM - Currently implemented
- Other types (DISCOVER, REQUEST, etc.) throw "NOT SUPPORTED" error

**Platform Behavior:**
- All platforms supported
- Standard DHCP packet construction

---

#### raw(localAddress, port, buffer, handler) - Lines 211-232

**Purpose:** Sends a raw DHCP packet and listens for responses.

**Process:**
- Creates UDP4 socket using `dgram.createSocket()`
- Binds to specified local IP address and port
- Enables broadcast mode for DHCP communication
- Sets multicast interface and TTL
- Registers message handler for incoming responses
- Broadcasts packet to 255.255.255.255 port 67 (DHCP server port)
- Returns promise that resolves when handler processes response

**Parameters:**
- `localAddress` - Local IP address to bind to
- `port` - Local port (null for automatic assignment)
- `buffer` - DHCP packet buffer to send
- `handler` - Callback function to process incoming DHCP responses

**Error Handling:**
- Rejects promise if unable to bind to specified address
- Uses try-catch to handle binding errors

**Platform Behavior:**
- All platforms supported
- Standard UDP broadcast communication

---

#### info(interfaceName, port) - Lines 234-306

**Purpose:** Main function to retrieve DHCP information for a specific network interface.

**Process:**
1. Enumerates network interfaces using `require('os').networkInterfaces()`
2. If `interfaceName` is a MAC address (6 colon-separated hex pairs), converts to interface name
3. Finds IPv4 address for specified interface (skips loopback 00:00:00:00:00:00)
4. Creates DHCP INFORM packet with interface's IP and MAC address
5. Sends packet using `raw()` function
6. Waits for DHCP response matching the MAC address
7. Validates response contains lease information
8. Returns parsed DHCP data or rejects with error

**Parameters:**
- `interfaceName` - Network interface name (e.g., "eth0", "en0") or MAC address (e.g., "00:11:22:33:44:55")
- `port` - Optional local port to bind (null for automatic)

**Timeout:**
- 2-second timeout for DHCP server response (line 286-290)
- Automatically cleans up socket listeners on timeout or success

**Error Conditions:**
- Interface not found
- No IPv4 address on interface
- MAC address is 00:00:00:00:00:00 (loopback)
- DHCP server does not respond within 2 seconds
- Unable to bind to interface IP address

**Platform Behavior:**
- All platforms supported
- Automatically handles interface naming differences across platforms
- MAC address lookup works universally

---

### Usage

#### Programmatic Usage

```javascript
var dhcp = require('dhcp');

// Query DHCP info by interface name
dhcp.client.info('eth0')
    .then(function(result) {
        console.log('IP Address:', result.yiaddr);
        console.log('Subnet Mask:', result.options.subnetmask);
        console.log('Gateway:', result.options.router);
        console.log('DNS Server:', result.options.dns);
        console.log('Domain:', result.options.domainname);
        console.log('DHCP Server:', result.options.server);
        console.log('Lease Time:', result.options.lease.hours + ' hours');
    })
    .catch(function(error) {
        console.log('Error:', error);
    });

// Query DHCP info by MAC address
dhcp.client.info('00:11:22:33:44:55')
    .then(function(result) {
        console.log('Configuration received');
    });

// Access raw DHCP functionality
var packet = dhcp.createPacket(dhcp.MESSAGE_TYPES.INFO, {
    ciaddress: '192.168.1.100',
    chaddress: '00:11:22:33:44:55'
});

dhcp.client.raw('192.168.1.100', 0, packet, function(msg) {
    var response = dhcp.parseDHCP(msg);
    console.log(response);
});
```

#### Available Message Types

The module exports standard DHCP message type constants (lines 311-321):

| Constant | Value | Description |
|----------|-------|-------------|
| DISCOVER | 1 | Client broadcast to locate servers |
| OFFER | 2 | Server response to DISCOVER |
| REQUEST | 3 | Client request for configuration |
| DECLINE | 4 | Client declines offered configuration |
| ACK | 5 | Server acknowledges REQUEST |
| NACK | 6 | Server denies REQUEST |
| RELEASE | 7 | Client releases IP address |
| INFO | 8 | Client requests local configuration |

**Note:** Only INFORM (type 8) is currently implemented in `createPacket()`.

---

### Dependencies

#### Node.js Core Modules

- **`dgram`** (line 214)
  - Purpose: UDP socket creation and communication
  - Usage: Creates UDP4 socket for DHCP broadcast/receive
  - Methods used: `createSocket()`, `bind()`, `setBroadcast()`, `setMulticastInterface()`, `setMulticastTTL()`, `send()`
  - Platform support: Cross-platform

- **`os`** (line 236)
  - Purpose: Network interface enumeration
  - Usage: `networkInterfaces()` to list all network adapters
  - Returns: Object with interface names as keys, array of address objects as values
  - Platform support: Cross-platform

- **`events`** (embedded in promise2 module)
  - Purpose: EventEmitter functionality for promise implementation
  - Usage: Event-driven promise resolution/rejection

#### MeshAgent Module Dependencies

- **`promise2`** (lines 38-39)
  - **Embedded Module:** Lines 38-39 embed the entire promise2 module as a base64-encoded string
  - Purpose: Custom promise implementation for async operations
  - Why embedded: Ensures consistent promise behavior across different JavaScript engines
  - Exports: `Promise` constructor, `Promise.resolve()`, `Promise.reject()`, `Promise.all()`
  - Size: ~8KB when decoded

**Embedded promise2 Module Features:**
- Full Promise/A+ compatible implementation
- Support for `.then()`, `.catch()`, `.finally()` methods
- Promise chaining and error propagation
- `Promise.all()` for parallel promise resolution
- Custom event-driven architecture with 'resolved', 'rejected', 'settled' events
- Automatic cleanup of settled promises
- Uncaught rejection detection and warning

#### Platform Binary Dependencies

**None** - This module has no external binary dependencies. All functionality is implemented using Node.js core modules.

#### Dependency Summary

| Dependency Type | Module | Required | Platform-Specific |
|----------------|--------|----------|-------------------|
| Node.js Core | dgram | Yes | No |
| Node.js Core | os | Yes | No |
| Embedded | promise2 | Yes | No |
| External Binary | None | - | - |

---

### Technical Notes

**Promise Implementation:**

The module embeds a complete promise implementation (promise2) rather than using native JavaScript promises. This embedded module (line 38) is base64-encoded and decoded at runtime. This approach ensures consistent promise behavior across different JavaScript engine versions, particularly important for the MeshAgent environment which may run in Duktape (a lightweight embedded JavaScript engine) rather than V8/Node.js.

**DHCP Protocol Implementation:**

The module implements only the DHCP INFORM message type (message type 8), which is specifically designed to query configuration information from a DHCP server without requesting or modifying IP address assignments. This is a read-only operation that doesn't affect the network interface configuration.

**Magic Cookie Validation:**

DHCP packets must include a "magic cookie" (bytes 99, 130, 83, 99) at offset 236-239 to distinguish DHCP from older BOOTP packets. The parser validates this sequence (line 64) before attempting to parse DHCP options.

**Transaction ID:**

Each DHCP request includes a random transaction ID (lines 167-168) to match responses with requests. The `info()` function validates that responses match the expected MAC address (line 274) to avoid processing responses intended for other clients on the same network.

**Timeout Mechanism:**

The module implements a 2-second timeout (lines 286-290) for DHCP server responses. If no valid response is received within this window, the promise is rejected with a 'timeout' error. The timeout handler also removes message listeners to prevent memory leaks.

**MAC Address Flexibility:**

The `info()` function accepts both interface names (e.g., "eth0", "wlan0", "en0") and MAC addresses (e.g., "00:11:22:33:44:55") as input (lines 237-256). When a MAC address is provided, the function automatically resolves it to the corresponding interface name by enumerating all interfaces and comparing MAC addresses.

**Broadcast Communication:**

DHCP clients communicate with servers via UDP broadcast to 255.255.255.255 on port 67 (line 230). The module enables broadcast mode on the socket (line 225) and sets the multicast TTL to 1 (line 227) to prevent DHCP packets from being routed beyond the local network.

**Memory Management:**

The module uses `setImmediate()` to defer socket cleanup (line 277), working around a bug in older versions of dgram.js where immediate listener removal could cause issues. The `_hide()` function pattern (lines 22-36, 269, 285-291) is used to maintain reference context across async operations.

## Summary

The dhcp.js module is a **cross-platform DHCP client** that provides simple network configuration querying capabilities for all major operating systems (Windows, Linux, macOS, FreeBSD). It implements the DHCP INFORM message type to retrieve configuration data from DHCP servers without modifying interface settings.

**Key features:**
- Lightweight implementation (~324 lines including embedded promise module)
- No external binary dependencies
- 2-second timeout for server responses
- Supports interface name or MAC address lookup
- Parses common DHCP options (subnet mask, gateway, DNS, domain name, lease time)
- Embedded promise2 module for consistent async behavior
- Standard UDP broadcast communication on port 67

The module is used within MeshAgent for network diagnostics and system information gathering. It provides read-only access to DHCP server configuration without requiring elevated privileges or modifying network interface settings.
