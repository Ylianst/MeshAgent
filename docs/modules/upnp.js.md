# upnp.js

Complete UPnP (Universal Plug and Play) implementation providing device discovery via SSDP multicast, service enumeration, action invocation via SOAP, and event subscription capability. Supports full UPnP control point functionality for discovering and controlling network devices like routers, media servers, and IoT devices.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support
- Linux - Full support
- macOS (darwin) - Full support
- FreeBSD - Full support

## Functionality

### Purpose

The upnp module implements a complete UPnP Control Point that enables:

- **Device Discovery** - SSDP multicast search for UPnP devices on local network
- **Service Enumeration** - Parse device descriptions and list available services
- **Action Invocation** - Execute actions on UPnP services via SOAP
- **Event Subscription** - Subscribe to state variable changes
- **Multi-Interface Support** - Searches on all network interfaces simultaneously

This module is used for:
- NAT traversal (port forwarding via IGD/WANIPConnection)
- Media server discovery and control
- Network device management
- IoT device discovery and control

### UPnP Discovery Flow

1. **SSDP Search** - Send M-SEARCH multicast to 239.255.255.250:1900
2. **Device Response** - Devices respond with location URL of description XML
3. **Fetch Description** - Download device description document
4. **Parse Description** - Extract device info, embedded devices, services
5. **Fetch Service Descriptions** - Download SCPD (Service Control Protocol Description) for each service
6. **Ready for Control** - Device object emits 'device' event with full structure

### Key Classes

#### upnpcp (Control Point) - Lines 566-604

**Purpose:** Main control point class that initiates device discovery.

**Constructor:**
```javascript
new upnpcp(search)
```

**Parameters:**
- `search` (string) - Search target, one of:
  - Friendly name (e.g., "Samsung CLX-3300 Series")
  - `ssdp:all` - All devices
  - `upnp:rootdevice` - Root devices only
  - `urn:schemas-upnp-org:device:MediaServer:1` - Specific device type
  - `urn:schemas-upnp-org:service:ContentDirectory:1` - Specific service type
  - `uuid:12345678-1234-1234-1234-123456789ABC` - Specific device UUID

**Process (lines 566-604):**
1. If searching by friendly name, converts to `upnp:rootdevice` (lines 569-573)
2. Constructs M-SEARCH message (line 575)
3. Enumerates all network interfaces via `os.networkInterfaces()` (line 583)
4. For each IPv4 interface with status 'up':
   - Creates UDP socket bound to interface IP (lines 590-593)
   - Sets multicast parameters (TTL=1, loopback=true) (lines 597-598)
   - Sends M-SEARCH to 239.255.255.250:1900 (line 600)
   - Listens for responses on `upnpcp_onSearch` handler (line 594)

**Events:**
- `device` - Emitted when a matching device is fully loaded and ready

**Properties:**
- `deviceTable` - Object mapping USN to device instances
- `searchSockets` - Object mapping interface IPs to UDP sockets
- `searchString` - Original search parameter

**M-SEARCH Message Format (line 575):**
```
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
ST: <search-target>
MAN: "ssdp:discover"
MX: 5
Content-Length: 0
```

---

#### upnpdevice - Lines 25-142

**Purpose:** Represents a UPnP device (root or embedded).

**Constructor:**
```javascript
new upnpdevice(descriptionUrl, usn, cp, localInterface)
```

**Parameters:**
- `descriptionUrl` (string) - URL to device description XML
- `usn` (string) - Unique Service Name (device identifier)
- `cp` (upnpcp) - Control point instance
- `localInterface` (string) - IP address of local interface

**Properties:**
- `locationUrl` - URL to device description
- `BaseURL` - Base URL for relative paths (protocol://host)
- `usn` - Unique service name
- `rootDevice` - Reference to parsed device structure
- `localInterface` - IP of network interface used

**Events:**
- `error` - Device-related errors
- `bye` - Device departure notification
- `alive` - Device presence notification
- `serviceLoaded` - Service SCPD successfully loaded

**Process:**
1. Extracts base URL from description URL (line 28)
2. Fetches device description XML via HTTP (line 39)
3. On successful fetch (statusCode 200):
   - Pipes response to MemoryStream (lines 50-52)
   - On stream end: Parses XML with `upnpdevice_parseXml()` (line 55)
4. Creates `upnpdevice_child` object from XML (line 520)
5. Loads all service descriptions (line 527, 538, 541, 544)
6. Emits 'device' event when all services loaded (line 95)

**Methods:**
- `makeUrl(url)` (lines 64-88) - Converts relative URLs to absolute
- `loadAllServices()` (line 63) - Initiates loading of all service SCPD documents
- `getDevice(udn)` (lines 98-101) - Find device by UDN in tree

---

#### upnpdevice_child - Lines 453-508

**Purpose:** Represents a device in the device tree (root or embedded).

**Constructor:**
```javascript
new upnpdevice_child(rootDevice, xmlDoc)
```

**Properties:**
- `friendlyName` - Human-readable device name
- `deviceType` - URN of device type
- `UDN` - Unique Device Name (UUID)
- `manufacturer` - Device manufacturer
- `services` - Array of upnpservice objects
- `embeddedDevices` - Array of child upnpdevice_child objects

**Parsed from XML (lines 464-467):**
```xml
<device>
  <friendlyName>My Router</friendlyName>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <UDN>uuid:12345678-1234-1234-1234-123456789ABC</UDN>
  <manufacturer>Example Corp</manufacturer>
  <serviceList>...</serviceList>
  <deviceList>...</deviceList>
</device>
```

**Methods:**
- `loadAllServices()` (line 489) - Recursively loads SCPD for all services
- `getDevice(udn)` (lines 490-499) - Recursively search for device by UDN
- `getService(id)` (lines 500-507) - Find service by serviceId

**Services Array Extension (line 456):**
```javascript
Object.defineProperty(this.services, "get", {
    value: function (id) {
        for (var i in this) {
            if (this[i].serviceType == id || this[i].serviceId == id) {
                return (this[i]);
            }
        }
        return (undefined);
    }
});
```

Allows lookup by serviceType OR serviceId.

---

#### upnpservice - Lines 155-233

**Purpose:** Represents a UPnP service offering actions and state variables.

**Constructor:**
```javascript
new upnpservice(parentDevice, xmlDoc)
```

**Properties (parsed from XML lines 162-166):**
- `serviceType` - URN of service type
- `serviceId` - Service identifier
- `controlURL` - URL for SOAP control messages
- `eventSubURL` - URL for event subscriptions
- `SCPDURL` - URL to Service Control Protocol Description

**Parsed from XML:**
```xml
<service>
  <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
  <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
  <controlURL>/ctl/IPConn</controlURL>
  <eventSubURL>/evt/IPConn</eventSubURL>
  <SCPDURL>/WANIPCn.xml</SCPDURL>
</service>
```

**Events:**
- `stateVariableChanged` - State variable value changed

**Methods:**
- `load()` (lines 172-204) - Fetches and parses SCPD
- `getAction(name)` (lines 205-212) - Find action by name
- `subscribe()` (lines 386-421) - Subscribe to service events
- `notify(imsg)` (lines 422-449) - Handle event notifications

**After SCPD Loading:**
- `actions` array populated with upnpaction objects
- `stateVariables` array populated with upnpvariable objects

---

#### upnpaction - Lines 243-337

**Purpose:** Represents an action that can be invoked on a service.

**Properties:**
- `name` - Action name
- `arguments` - Array of upnpargument objects (input/output parameters)
- `service` - Parent service

**Methods:**
- `invoke(args)` (lines 265-336) - Execute action via SOAP

**invoke() Process:**
1. Creates promise for async result (line 267)
2. Validates required input arguments (lines 270-280)
3. Builds SOAP envelope with parameters (lines 283-332):
   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
               s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
     <s:Body>
       <u:ActionName xmlns:u="service-type">
         <param1>value1</param1>
         <param2>value2</param2>
       </u:ActionName>
     </s:Body>
   </s:Envelope>
   ```
4. POSTs SOAP to controlURL with SOAPAction header (lines 286)
5. Parses response XML to extract output parameters (lines 304-318)
6. Resolves promise with output object (line 318)

**Example Usage:**
```javascript
var action = service.getAction('GetExternalIPAddress');
action.invoke({}).then(function(result) {
    console.log('External IP: ' + result.NewExternalIPAddress);
});
```

---

#### upnpargument - Lines 235-241

**Purpose:** Represents an action parameter (input or output).

**Properties:**
- `name` - Argument name
- `direction` - 'in' or 'out'
- `relatedStateVariable` - Associated state variable (type info)

---

#### upnpvariable - Lines 338-351

**Purpose:** Represents a service state variable.

**Properties:**
- `name` - Variable name
- `dataType` - Data type (string, ui4, boolean, etc.)
- `evented` - 'yes' if variable changes trigger events
- `currentValue` - Current value (if evented)

**Events:**
- `changed` - Emitted when evented variable value changes

---

### Helper Functions

#### upnpcp_onSearch(msg, rinfo) - Lines 552-564

**Purpose:** Handles SSDP search responses.

**Process:**
1. Parses HTTP response headers (line 554)
2. Checks for HTTP 200 status
3. Extracts USN from headers (line 556)
4. If device not in deviceTable:
   - Creates new upnpdevice instance (line 560)
   - Stores in deviceTable
   - Attaches error and alive event handlers

---

#### upnpdevice_parseXml(xml) - Lines 510-550

**Purpose:** Parses device description XML and filters by search criteria.

**Process:**
1. Parses XML to DOM (line 513)
2. Finds root `<device>` element (line 517)
3. Creates upnpdevice_child from XML (line 520)
4. Checks search criteria match (lines 521-546):
   - Friendly name match (line 524-528)
   - ssdp:all (no filter)
   - upnp:rootdevice (loads all)
   - uuid:... (loads all)
   - urn:... (loads all)
5. If match: Calls loadAllServices() (line 527, 538, 541, 544)

---

#### upnpservice_parseScpd(scpd) - Lines 352-451

**Purpose:** Parses Service Control Protocol Description (SCPD) XML.

**Process:**
1. Creates stateVariables and actions arrays (lines 354-355)
2. Parses serviceStateTable (lines 357-365):
   - Extracts stateVariable elements
   - Creates upnpvariable for each
3. Parses actionList (lines 367-383):
   - Extracts action elements
   - Creates upnpaction for each (wrapped in try-catch)
4. Attaches subscribe() and notify() methods to service (lines 386-449)
5. Emits 'serviceLoaded' event (line 450)

**SCPD XML Format:**
```xml
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
  <serviceStateTable>
    <stateVariable sendEvents="yes">
      <name>VariableName</name>
      <dataType>string</dataType>
    </stateVariable>
  </serviceStateTable>
  <actionList>
    <action>
      <name>ActionName</name>
      <argumentList>
        <argument>
          <name>ArgName</name>
          <direction>in</direction>
          <relatedStateVariable>VariableName</relatedStateVariable>
        </argument>
      </argumentList>
    </action>
  </actionList>
</scpd>
```

---

### Display Helper Functions

The module includes helper functions for displaying UPnP structures (lines 609-683):

- **display_device(dv, prefix)** (lines 609-627) - Pretty-print device tree
- **display_action(action)** (lines 628-645) - Show action signature
- **display_actionDetail(action)** (lines 647-672) - Detailed action info
- **display_service(svc)** (lines 673-683) - Service details with actions

---

### Module Exports - Lines 685-688

```javascript
module.exports.cp = upnpcp;
module.exports.displayDevice = display_device;
module.exports.displayService = display_service;
module.exports.displayActionDetail = display_actionDetail;
```

**Usage:**
```javascript
var upnp = require('upnp');

// Discover all UPnP devices
var cp = new upnp.cp('upnp:rootdevice');

cp.on('device', function(device) {
    console.log('Found: ' + device.friendlyName);

    // Display device structure
    upnp.displayDevice(device);

    // Get a service
    var service = device.services.get('urn:upnp-org:serviceId:WANIPConn1');

    // Display service details
    upnp.displayService(service);

    // Invoke an action
    var action = service.getAction('GetExternalIPAddress');
    action.invoke({}).then(function(result) {
        console.log('IP: ' + result.NewExternalIPAddress);
    });
});
```

---

### Dependencies

#### Node.js Core Modules
- `http` (lines 19, 39, 106, 175, 224, 393, 594) - HTTP client
- `dgram` (line 20) - UDP sockets for SSDP multicast
- `os` (line 21) - Network interface enumeration
- `net` (line 23) - Network utilities

#### MeshAgent Module Dependencies

- **`promise`** (line 17)
  - Custom promise implementation
  - Used for async action invocation and service loading

- **`parseXml`** (line 18)
  - XML parsing module
  - Methods:
    - `parseXml(string)` - Parse XML to DOM
    - `getElementsByTagNameNS(ns, tag)` - Find elements by namespace
    - `getChildElementsByTagNameNS(ns, tag)` - Find child elements

- **`MemoryStream`** (line 22)
  - In-memory stream buffer
  - Used to accumulate HTTP responses

- **`http-headers`** (line 554)
  - HTTP header parser
  - Used to parse SSDP response headers

### Technical Notes

**SSDP (Simple Service Discovery Protocol):**

SSDP uses HTTP over UDP multicast:
- Multicast address: 239.255.255.250
- Port: 1900
- M-SEARCH request format: HTTP/1.1
- Response: HTTP/1.1 200 OK with Location header

**Multi-Interface Search:**

The module searches on ALL IPv4 interfaces:
```javascript
for(var name in interfaces) {
    for (var i in interfaces[name]) {
        if (interfaces[name][i].family == 'IPv4' && interfaces[name][i].status == 'up') {
            var searchSocket = dgram.createSocket({ type: 'udp4' });
            searchSocket.bind({ port: 0, address: interfaces[name][i].address });
            searchSocket.send(MSEARCH, 1900, '239.255.255.250');
        }
    }
}
```

This ensures discovery works even on multi-homed systems.

**Event Subscription:**

To receive service events:
1. Start event server (HTTP server bound to local interface)
2. Send SUBSCRIBE request to service eventSubURL with CALLBACK header
3. Service sends NOTIFY requests to callback URL when state changes
4. Parse NOTIFY request body for changed variables

**UPnP Device Hierarchy:**

Devices can contain embedded devices:
```
RootDevice
├── EmbeddedDevice1
│   ├── Service1
│   └── Service2
└── EmbeddedDevice2
    └── Service3
```

The module recursively parses this structure.

**Namespace Handling:**

UPnP uses XML namespaces:
- Device schema: `urn:schemas-upnp-org:device-1-0`
- Service schema: `urn:schemas-upnp-org:service-1-0`
- Event schema: `urn:schemas-upnp-org:event-1-0`

The parseXml module's namespace-aware methods handle this.

**SOAP Communication:**

Actions are invoked via SOAP 1.1:
- Envelope namespace: `http://schemas.xmlsoap.org/soap/envelope/`
- Encoding style: `http://schemas.xmlsoap.org/soap/encoding/`
- SOAPAction HTTP header identifies the action

**Promise Chaining:**

Device loading uses promise chains:
1. Fetch device description → Parse XML
2. For each service → Fetch SCPD → Parse SCPD
3. When all services loaded → Emit 'device' event

## Summary

The upnp.js module provides complete UPnP Control Point functionality for **Windows, Linux, macOS, and FreeBSD**. It implements SSDP device discovery, service enumeration, SOAP action invocation, and event subscription following the UPnP Device Architecture specification.

The module discovers devices by sending multicast M-SEARCH requests on all network interfaces, fetches and parses device and service descriptions, and provides an object-oriented API for interacting with UPnP services. It supports embedded device hierarchies, asynchronous action invocation via promises, and real-time event notifications.

Key features include multi-interface discovery for multi-homed systems, friendly name searching, full SOAP support for action invocation, and helper functions for displaying device structures. The module is suitable for NAT traversal (IGD), media server control, and general UPnP device interaction.
