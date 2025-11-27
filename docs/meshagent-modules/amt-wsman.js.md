# amt-wsman.js

WS-Management (WSMAN) protocol stack implementation for Intel Active Management Technology (Intel AMT). Provides complete SOAP/XML-based management protocol supporting Get, Put, Create, Delete, Execute, Enumerate/Pull, and Subscribe/Unsubscribe operations over HTTP/HTTPS. This module serves as the low-level protocol layer for remote AMT device management.

## Platform

**Supported Platforms:**
- Windows (all versions) - Full support
- Linux (all distributions) - Full support

**Excluded Platforms:**
- **macOS** - Excluded (technically compatible, contextually irrelevant)

**Exclusion Reasoning:**

While **technically cross-platform and fully compatible**, this module is excluded from macOS builds because:

1. **Part of Intel AMT Management Stack** - Core component of the Intel AMT WSMAN protocol implementation ecosystem, which is not typically deployed on macOS systems in enterprise environments.

2. **Limited Use Case on macOS** - Intel AMT management infrastructure is predominantly deployed on Windows/Linux servers. macOS workstations are rarely used as AMT management platforms in enterprise IT operations.

3. **Architectural Decision** - The entire Intel AMT module suite is excluded from macOS builds to maintain consistent platform targeting, even though this protocol module has no technical limitations.

**Technical Capability:**

Despite the exclusion, the module is fully cross-platform because:
- **Network-Only Protocol** - WSMAN operates over standard HTTP/HTTPS network connections with no local hardware dependencies, HECI interfaces, or Management Engine required
- **Pure JavaScript Implementation** - All SOAP/XML generation, parsing, and protocol logic implemented in portable JavaScript with no binary dependencies or native modules
- **Remote Management Focus** - Manages Intel AMT devices on other computers via network; the management workstation does not need AMT hardware
- **Transport Abstraction** - Delegates actual HTTP transport to pluggable communication modules (line 34-41), making the stack independent of specific HTTP implementations

**Important:** While this module is cross-platform, it manages **remote Intel AMT devices over the network**. The local system running this module does not need AMT hardware.

---

## Functionality

### Core Purpose

amt-wsman.js implements the WS-Management (WSMAN) protocol as defined by DMTF standard DSP0226, specialized for Intel AMT:

1. **SOAP Envelope Generation** - Create properly formatted WSMAN requests
2. **XML Response Parsing** - Extract data from AMT responses using amt-xml
3. **Resource URI Management** - Handle AMT/CIM/IPS namespace URLs
4. **Message ID Tracking** - Sequence and correlate requests/responses
5. **Selector Management** - Instance identification in AMT object model
6. **Method Execution** - Call AMT object methods with parameters
7. **Enumeration** - Retrieve collections of AMT objects

### WSMAN Protocol Overview

**WS-Management (WSMAN):**
- DMTF standard (DSP0226) for systems management
- SOAP-based messaging over HTTP/HTTPS
- RESTful operations on management objects
- Used by Intel AMT, Windows WinRM, and other platforms

**WSMAN Operations:**
- **Get** - Retrieve single object instance
- **Put** - Update object properties
- **Create** - Create new object instance
- **Delete** - Remove object instance
- **Invoke** - Execute object method
- **Enumerate/Pull** - List collection members
- **Subscribe/Unsubscribe** - Event notifications

---

## Constructor

### WsmanStackCreateService(...) - Lines 24-209

**Purpose:** Create WSMAN protocol stack instance

**Signature Options:**

**Option 1 - Object Parameter (Lines 32-36):**
```javascript
WsmanStackCreateService({
    transport: CreateWsmanComm,  // Transport constructor
    host: '192.168.1.100',       // AMT hostname/IP
    port: 16992,                 // AMT port
    user: 'admin',               // Username
    pass: 'password',            // Password
    tls: false                   // Use HTTPS
})
```

**Option 2 - Multiple Parameters (Lines 38-41):**
```javascript
WsmanStackCreateService(
    CreateWsmanComm,  // Transport constructor
    host,             // Hostname/IP
    port,             // Port number
    user,             // Username
    pass,             // Password
    tls,              // Boolean for HTTPS
    extra             // Additional options
)
```

**Returned Object Properties:**

```javascript
{
    _ObjectID: 'WSMAN',
    NextMessageId: 1,              // Auto-incrementing message ID
    Address: '/wsman',             // WSMAN endpoint path
    xmlParser: require('amt-xml'), // XML parser module
    comm: <transport instance>     // HTTP/HTTPS transport
}
```

---

## Core Methods

### PerformAjax(postdata, callback, tag, pri, namespaces) - Lines 43-50

**Purpose:** Internal method to send WSMAN request and parse response

**Parameters:**
- `postdata` - Partial SOAP body (Action onward)
- `callback` - Function(stack, resourceUri, response, status, tag)
- `tag` - User data passed to callback
- `pri` - Priority (for queued transports)
- `namespaces` - Additional XML namespaces

**Process:**
1. Wraps postdata in complete SOAP envelope (line 45)
2. Sends via `comm.PerformAjax()`
3. Parses XML response with `amt-xml` (line 47)
4. Invokes callback with parsed response or error

**SOAP Envelope Structure:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns:xsd="http://www.w3.org/2001/XMLSchema"
          xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
          xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
          xmlns="http://www.w3.org/2003/05/soap-envelope"
          [additional namespaces]>
  <Header>
    <a:Action>[action URI]</a:Action>
    [postdata continues...]
  </Header>
  <Body>
    [operation-specific content]
  </Body>
</Envelope>
```

**Error Handling:**
- Non-200 status → Callback with HttpError in header (line 46)
- XML parse failure → Error 601 (line 48)

---

### CancelAllQueries(status) - Line 56

**Purpose:** Cancel all pending WSMAN requests

**Parameters:**
- `status` - Status code to return to cancelled callbacks

**Behavior:**
- Delegates to `comm.CancelAllQueries(status)`
- Used for cleanup on disconnect/timeout

---

### GetNameFromUrl(resuri) - Lines 59-62

**Purpose:** Extract class name from resource URI

**Parameters:**
- `resuri` - Full resource URI string

**Returns:** Last component after final '/'

**Example:**
```javascript
GetNameFromUrl('http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings')
// Returns: 'AMT_GeneralSettings'
```

---

## WSMAN Operations

### Subscribe/Unsubscribe Operations

#### ExecSubscribe(resuri, delivery, url, callback, tag, pri, selectors, opaque, user, pass) - Lines 64-72

**Purpose:** Subscribe to AMT event notifications

**Parameters:**
- `resuri` - Event class URI (e.g., `AMT_AlertIndication`)
- `delivery` - Delivery mode: 'Push' or 'PushWithAck'
- `url` - Notification destination URL
- `callback` - Completion callback
- `tag` - User data
- `pri` - Priority
- `selectors` - Instance selectors (optional)
- `opaque` - Reference parameter data (optional)
- `user` - HTTP digest username (optional)
- `pass` - HTTP digest password (optional)

**Delivery Modes:**
- **'Push'** → `http://schemas.xmlsoap.org/ws/2004/08/eventing/DeliveryModes/Push`
- **'PushWithAck'** → `http://schemas.dmtf.org/wbem/wsman/1/wsman/PushWithAck`

**Authentication (Lines 66-67):**
- If user/pass provided: Includes `IssuedTokens` with UsernameToken
- Includes digest auth profile for delivery endpoint

**Example:**
```javascript
stack.ExecSubscribe(
    'AMT_AlertIndication',
    'Push',
    'http://server:8080/amt-events',
    function(stack, uri, response, status) {
        console.log('Subscription ID:', response);
    },
    null, 0, null, null, 'admin', 'password'
);
```

---

#### ExecUnSubscribe(resuri, callback, tag, pri, selectors) - Lines 74-78

**Purpose:** Cancel event subscription

**Parameters:**
- `resuri` - Event class URI
- `callback` - Completion callback
- `tag` - User data
- `pri` - Priority
- `selectors` - Subscription selectors (from subscribe response)

**Example:**
```javascript
stack.ExecUnSubscribe(
    'AMT_AlertIndication',
    function(stack, uri, response, status) {
        console.log('Unsubscribed');
    },
    null, 0, subscriptionSelectors
);
```

---

### Object Manipulation Operations

#### ExecPut(resuri, putobj, callback, tag, pri, selectors) - Lines 80-84

**Purpose:** Update AMT object properties

**Parameters:**
- `resuri` - Resource URI (e.g., `AMT_GeneralSettings`)
- `putobj` - Object with properties to update
- `callback` - Completion callback
- `tag` - User data
- `pri` - Priority
- `selectors` - Instance selectors (for multi-instance classes)

**Example:**
```javascript
stack.ExecPut(
    'AMT_GeneralSettings',
    {
        HostName: 'new-hostname',
        DomainName: 'example.com'
    },
    function(stack, uri, response, status) {
        if (status === 200) {
            console.log('Settings updated');
        }
    }
);
```

**SOAP Body Generated:**
```xml
<Body>
  <r:AMT_GeneralSettings xmlns:r="[resuri]">
    <r:HostName>new-hostname</r:HostName>
    <r:DomainName>example.com</r:DomainName>
  </r:AMT_GeneralSettings>
</Body>
```

---

#### ExecCreate(resuri, putobj, callback, tag, pri, selectors) - Lines 86-92

**Purpose:** Create new AMT object instance

**Parameters:**
- `resuri` - Resource URI of class to instantiate
- `putobj` - Object with initial properties
- `callback` - Completion callback
- `tag` - User data
- `pri` - Priority
- `selectors` - Additional selectors (rare)

**Example:**
```javascript
stack.ExecCreate(
    'AMT_PublicKeyCertificate',
    {
        CertificateBlob: certData,
        InstanceID: 'cert-1'
    },
    function(stack, uri, response, status) {
        console.log('Certificate created');
    }
);
```

**SOAP Body Structure (Lines 89-91):**
```xml
<Body>
  <g:AMT_PublicKeyCertificate xmlns:g="[resuri]">
    <g:CertificateBlob>...</g:CertificateBlob>
    <g:InstanceID>cert-1</g:InstanceID>
  </g:AMT_PublicKeyCertificate>
</Body>
```

---

#### ExecDelete(resuri, putobj, callback, tag, pri) - Lines 94-98

**Purpose:** Delete AMT object instance

**Parameters:**
- `resuri` - Resource URI
- `putobj` - Selectors identifying instance to delete
- `callback` - Completion callback
- `tag` - User data
- `pri` - Priority

**Example:**
```javascript
stack.ExecDelete(
    'AMT_PublicKeyCertificate',
    { InstanceID: 'cert-1' },
    function(stack, uri, response, status) {
        console.log('Certificate deleted');
    }
);
```

**SOAP Structure:**
- Action: `http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete`
- Selectors in header identify instance
- Empty body (line 96)

---

#### ExecGet(resuri, callback, tag, pri) - Lines 100-103

**Purpose:** Retrieve AMT object properties

**Parameters:**
- `resuri` - Resource URI
- `callback` - Function receiving object properties
- `tag` - User data
- `pri` - Priority

**Example:**
```javascript
stack.ExecGet(
    'AMT_GeneralSettings',
    function(stack, uri, response, status) {
        console.log('HostName:', response.Body.HostName);
        console.log('AMT Version:', response.Body.AMTVersion);
    }
);
```

**Response Structure:**
```javascript
{
    Header: {
        Action: '...',
        MessageID: '...',
        ResourceURI: '...'
    },
    Body: {
        HostName: 'amt-device',
        DomainName: 'example.com',
        AMTVersion: '11.0.0',
        // ... all object properties
    }
}
```

---

### Method Execution Operations

#### ExecMethod(resuri, method, args, callback, tag, pri, selectors) - Lines 105-110

**Purpose:** Execute AMT object method with arguments

**Parameters:**
- `resuri` - Resource URI of class
- `method` - Method name (e.g., 'RequestStateChange')
- `args` - Object with method arguments
- `callback` - Completion callback
- `tag` - User data
- `pri` - Priority
- `selectors` - Instance selectors

**Argument Processing (Lines 107-108):**
- Null values skipped
- Arrays expanded to multiple elements
- Scalar values wrapped in tags

**Example:**
```javascript
// Power on system
stack.ExecMethod(
    'CIM_PowerManagementService',
    'RequestPowerStateChange',
    {
        PowerState: 2,             // 2 = power on
        ManagedElement: {          // Reference to system
            Address: 'http://...',
            ReferenceParameters: {...}
        }
    },
    function(stack, uri, response, status) {
        console.log('Return value:', response.Body.ReturnValue);
    }
);
```

**Argument Expansion:**
```javascript
// Array argument
args = { EnabledState: [2, 3, 6] };

// Generates XML:
// <r:EnabledState>2</r:EnabledState>
// <r:EnabledState>3</r:EnabledState>
// <r:EnabledState>6</r:EnabledState>
```

---

#### ExecMethodXml(resuri, method, argsxml, callback, tag, pri, selectors) - Lines 112-115

**Purpose:** Execute method with pre-formatted XML arguments

**Parameters:**
- `resuri` - Resource URI
- `method` - Method name
- `argsxml` - XML string with arguments already formatted
- `callback` - Completion callback
- `tag` - User data
- `pri` - Priority
- `selectors` - Instance selectors

**Use Case:** When you need precise XML control or have complex nested structures

**Example:**
```javascript
var argsxml = '<r:Param1>value1</r:Param1><r:Param2>value2</r:Param2>';
stack.ExecMethodXml(
    'AMT_SetupAndConfigurationService',
    'MethodName',
    argsxml,
    callback
);
```

**SOAP Body Format (Line 114):**
```xml
<Body>
  <r:MethodName_INPUT xmlns:r="[resuri]">
    [argsxml content]
  </r:MethodName_INPUT>
</Body>
```

---

### Enumeration Operations

#### ExecEnum(resuri, callback, tag, pri) - Lines 117-120

**Purpose:** Start enumeration of object collection

**Parameters:**
- `resuri` - Resource URI of collection class
- `callback` - Function receiving enumeration context
- `tag` - User data
- `pri` - Priority

**Returns:** Enumeration context in response, used with ExecPull

**Example:**
```javascript
stack.ExecEnum(
    'AMT_EthernetPortSettings',
    function(stack, uri, response, status) {
        var enumContext = response.Body.EnumerationContext;
        // Use enumContext with ExecPull to get items
    }
);
```

**SOAP Body:**
```xml
<Body>
  <Enumerate xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration" />
</Body>
```

---

#### ExecPull(resuri, enumctx, callback, tag, pri) - Lines 122-125

**Purpose:** Retrieve items from enumeration

**Parameters:**
- `resuri` - Same resource URI from Enum
- `enumctx` - EnumerationContext from ExecEnum response
- `callback` - Function receiving items
- `tag` - User data
- `pri` - Priority

**Example:**
```javascript
stack.ExecPull(
    'AMT_EthernetPortSettings',
    enumContext,
    function(stack, uri, response, status) {
        var items = response.Body.Items;
        items.forEach(function(port) {
            console.log('Port:', port.ElementName);
        });
    }
);
```

**SOAP Body:**
```xml
<Body>
  <Pull xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
    <EnumerationContext>[context string]</EnumerationContext>
    <MaxElements>999</MaxElements>
    <MaxCharacters>99999</MaxCharacters>
  </Pull>
</Body>
```

**Limits (Line 124):**
- MaxElements: 999 items
- MaxCharacters: 99999 characters

---

## XML Generation Helpers

### _PutObjToBodyXml(resuri, putObj) - Lines 127-161

**Purpose:** Convert JavaScript object to WSMAN XML body

**Parameters:**
- `resuri` - Resource URI for namespace
- `putObj` - JavaScript object with properties

**Returns:** XML string for SOAP body

**Property Handling:**

1. **Simple Values (Lines 149-156):**
   ```javascript
   { HostName: 'device1' }
   // → <r:HostName>device1</r:HostName>
   ```

2. **Arrays (Lines 149-152):**
   ```javascript
   { EnabledState: [2, 3, 6] }
   // → <r:EnabledState>2</r:EnabledState>
   //   <r:EnabledState>3</r:EnabledState>
   //   <r:EnabledState>6</r:EnabledState>
   ```

3. **References (Lines 135-146):**
   ```javascript
   {
       ManagedElement: {
           Address: 'http://...',
           ReferenceParameters: {
               ResourceURI: '...',
               SelectorSet: {
                   Selector: { '@Name': 'InstanceID', Value: '...' }
               }
           }
       }
   }
   // → <r:ManagedElement>
   //     <a:Address>...</a:Address>
   //     <a:ReferenceParameters>...</a:ReferenceParameters>
   //   </r:ManagedElement>
   ```

**Skipped Properties (Line 133):**
- Properties starting with `__`
- Properties starting with `@`
- Properties without `hasOwnProperty`
- Null values
- Functions

---

### _ObjectToXmlAttributes(objWithAttributes) - Lines 169-177

**Purpose:** Convert JavaScript object properties to XML attributes

**Format:**
```javascript
{ '@Name': 'InstanceID', '@Type': 'string' }
// → ' Name="InstanceID" Type="string" '
```

**Usage:** Properties starting with '@' become XML attributes

---

### _PutObjToSelectorsXml(selectorSet) - Lines 179-206

**Purpose:** Generate SelectorSet XML for instance identification

**Parameters:**
- `selectorSet` - Object with selector properties or string/null

**Returns:** XML string or empty string

**Formats Supported:**

1. **Null/String (Lines 180-181):**
   ```javascript
   null → ''
   'null' → ''
   '<w:SelectorSet>...</w:SelectorSet>' → passed through
   ```

2. **InstanceID Shorthand (Line 182):**
   ```javascript
   { InstanceID: 'Intel(r) AMT' }
   // → <w:SelectorSet>
   //     <w:Selector Name="InstanceID">Intel(r) AMT</w:Selector>
   //   </w:SelectorSet>
   ```

3. **Multiple Selectors (Lines 184-204):**
   ```javascript
   {
       Name: 'WiFi',
       InstanceID: 'Intel(r) AMT'
   }
   // → <w:SelectorSet>
   //     <w:Selector Name="Name">WiFi</w:Selector>
   //     <w:Selector Name="InstanceID">Intel(r) AMT</w:Selector>
   //   </w:SelectorSet>
   ```

4. **Reference Selectors (Lines 187-198):**
   ```javascript
   {
       Selector1: {
           Address: 'http://...',
           ReferenceParameters: {
               ResourceURI: '...',
               SelectorSet: {
                   Selector: [...]
               }
           }
       }
   }
   // → <w:SelectorSet>
   //     <w:Selector Name="Selector1">
   //       <a:EndpointReference>...</a:EndpointReference>
   //     </w:Selector>
   //   </w:SelectorSet>
   ```

---

## Dependencies

### JavaScript Module Dependencies

#### require('amt-xml') - Line 30
**Type:** JavaScript module
**Purpose:** Parse WSMAN XML responses into JavaScript objects
**Usage:** Convert AMT XML responses to usable data (line 47)
**Platform:** Cross-platform (pure JavaScript)

**No Other Dependencies:**
- No binary modules
- No platform-specific code
- No hardware requirements

### Transport Module Dependency

**Pluggable Transport (Lines 34-41):**

The WSMAN stack requires a transport module implementing:

```javascript
{
    PerformAjax: function(soapXml, callback, tag, pri) {
        // Send HTTP/HTTPS request
        // Call callback(data, status, tag)
    },
    CancelAllQueries: function(status) {
        // Cancel pending requests
    }
}
```

**Common Transports:**
1. **amt-wsman-duk.js** - Duktape HTTP implementation
2. **amt-wsman-comm.js** - Node.js HTTP/HTTPS
3. **Custom** - Any module matching interface

---

## Relationship to Other AMT Modules

### WSMAN in AMT Architecture

```
┌─────────────────────────────────────────┐
│    High-Level Application/Script        │
│    (amt.js, amt-script.js, etc.)        │
└──────────────┬──────────────────────────┘
               │
               │ High-level AMT operations
               ▼
┌─────────────────────────────────────────┐
│       amt-wsman.js (This Module)        │
│    - SOAP envelope generation           │
│    - XML response parsing               │
│    - Resource URI management            │
│    - Selector handling                  │
└──────────────┬──────────────────────────┘
               │
               │ SOAP/XML over HTTP/HTTPS
               ▼
┌─────────────────────────────────────────┐
│       Transport Module                  │
│    (amt-wsman-duk.js, etc.)             │
│    - HTTP/HTTPS connections             │
│    - Digest authentication              │
│    - TLS handling                       │
└──────────────┬──────────────────────────┘
               │
               │ Network (TCP/IP)
               ▼
┌─────────────────────────────────────────┐
│    Intel AMT Device (Remote)            │
│    - WSMAN endpoint                     │
│    - Management objects                 │
└─────────────────────────────────────────┘
```

### Module Relationships

1. **amt.js** - High-level AMT wrapper
   - Uses amt-wsman for all network operations
   - Provides friendly APIs (e.g., `PowerOn()`)
   - amt-wsman provides protocol layer

2. **amt-script.js** - AMT scripting
   - Calls amt-wsman for WSMAN operations
   - Lines 213-243 in amt-script: WSMAN commands
   - amt-wsman provides actual protocol execution

3. **amt-xml** - XML parser
   - amt-wsman uses for response parsing (line 47)
   - Converts XML to JavaScript objects
   - Required dependency

4. **amt-wsman-duk.js / amt-wsman-comm.js** - Transports
   - Provide HTTP/HTTPS connectivity
   - Handle authentication (digest)
   - amt-wsman uses for network I/O

**Independent of Hardware Modules:**
- Does not use amt-lme.js (local port forwarding)
- Does not use amt-mei.js (local HECI commands)
- Does not use heci (hardware interface)
- Network-only, no local AMT hardware needed

---

## Hardware Requirements

### Local System (Running WSMAN Stack)

**No special hardware required:**
- Standard network interface
- TCP/IP connectivity
- No Intel AMT hardware needed
- No vPro chipset required
- Works on any computer

### Remote AMT Device (Target)

**Required:**
1. **Intel vPro Platform**
   - Business-class Intel chipset
   - Intel AMT firmware enabled

2. **Network Connectivity**
   - IP address reachable from management system
   - Ports 16992 (HTTP) and/or 16993 (HTTPS) accessible
   - Firewall rules permit WSMAN traffic

3. **AMT Provisioned**
   - Admin account configured
   - Network stack enabled
   - WSMAN endpoint active

---

## Usage Examples

### Basic Connection

```javascript
var wsman = require('amt-wsman');
var transport = require('amt-wsman-comm');

var stack = wsman({
    transport: transport,
    host: '192.168.1.100',
    port: 16992,
    user: 'admin',
    pass: 'password',
    tls: false
});

// Get general settings
stack.ExecGet('AMT_GeneralSettings', function(ws, uri, response, status) {
    if (status === 200) {
        console.log('Hostname:', response.Body.HostName);
    }
});
```

### Power Control

```javascript
// Get power state
stack.ExecMethod(
    'CIM_PowerManagementService',
    'GetPowerState',
    {},
    function(ws, uri, response, status) {
        console.log('Power state:', response.Body.PowerState);
    }
);

// Power on
stack.ExecMethod(
    'CIM_PowerManagementService',
    'RequestPowerStateChange',
    {
        PowerState: 2,  // 2 = on, 8 = graceful shutdown
        ManagedElement: {
            Address: 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous',
            ReferenceParameters: {
                ResourceURI: 'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ComputerSystem',
                SelectorSet: {
                    Selector: {
                        '@Name': 'Name',
                        Value: 'ManagedSystem'
                    }
                }
            }
        }
    },
    function(ws, uri, response, status) {
        console.log('Power command sent, return:', response.Body.ReturnValue);
    }
);
```

### Enumerate Network Adapters

```javascript
stack.ExecEnum('AMT_EthernetPortSettings', function(ws, uri, response, status) {
    if (status !== 200) {
        console.error('Enum failed:', status);
        return;
    }

    var enumCtx = response.Body.EnumerationContext;

    stack.ExecPull('AMT_EthernetPortSettings', enumCtx, function(ws, uri, response, status) {
        var items = response.Body.Items;
        items.forEach(function(port) {
            console.log('Port:', port.ElementName);
            console.log('  Enabled:', port.LinkControl);
            console.log('  MAC:', port.MACAddress);
        });
    });
});
```

### Update Configuration

```javascript
// Get current settings
stack.ExecGet('AMT_GeneralSettings', function(ws, uri, response, status) {
    var settings = response.Body;

    // Modify settings
    settings.HostName = 'new-hostname';
    settings.DomainName = 'example.com';

    // Write back
    stack.ExecPut('AMT_GeneralSettings', settings, function(ws, uri, response, status) {
        if (status === 200) {
            console.log('Settings updated');
        }
    });
});
```

### Event Subscription

```javascript
stack.ExecSubscribe(
    'AMT_AlertIndication',
    'Push',
    'http://my-server.com:8080/amt-events',
    function(ws, uri, response, status) {
        console.log('Subscribed to alerts');
        console.log('Subscription:', response.Body);
    },
    null,  // tag
    0,     // priority
    null,  // selectors
    null,  // opaque
    'event-user',  // HTTP auth for delivery
    'event-pass'
);
```

---

## WSMAN Message Flow

### Example: Get Operation

**Request (generated by ExecGet):**
```xml
<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"
          xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
          xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
    <a:To>/wsman</a:To>
    <w:ResourceURI>http://intel.com/.../AMT_GeneralSettings</w:ResourceURI>
    <a:MessageID>1</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:OperationTimeout>PT60S</w:OperationTimeout>
  </Header>
  <Body />
</Envelope>
```

**Response (parsed by amt-xml):**
```xml
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Header>
    <Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse</Action>
    <MessageID>uuid:...</MessageID>
    <RelatesTo>1</RelatesTo>
    <ResourceURI>http://intel.com/.../AMT_GeneralSettings</ResourceURI>
  </Header>
  <Body>
    <g:AMT_GeneralSettings xmlns:g="...">
      <g:HostName>amt-device</g:HostName>
      <g:DomainName>example.com</g:DomainName>
      <g:AMTVersion>11.0.0</g:AMTVersion>
      <!-- ... more properties ... -->
    </g:AMT_GeneralSettings>
  </Body>
</Envelope>
```

**JavaScript Callback Receives:**
```javascript
{
    Header: {
        Action: '...GetResponse',
        MessageID: 'uuid:...',
        RelatesTo: '1',
        ResourceURI: 'http://intel.com/.../AMT_GeneralSettings'
    },
    Body: {
        HostName: 'amt-device',
        DomainName: 'example.com',
        AMTVersion: '11.0.0',
        // ...
    }
}
```

---

## AMT Resource URIs

### Common AMT Classes

**AMT Namespace:** `http://intel.com/wbem/wscim/1/amt-schema/1/`

| Class | Purpose |
|-------|---------|
| AMT_GeneralSettings | Hostname, domain, version |
| AMT_SetupAndConfigurationService | Provisioning control |
| AMT_AuthorizationService | User management |
| AMT_BootSettingsData | Boot configuration |
| AMT_EthernetPortSettings | Network settings |
| AMT_PublicKeyCertificate | Certificate management |
| AMT_WiFiPortConfigurationService | WiFi configuration |
| AMT_KVMRedirectionSAP | KVM session control |
| AMT_RedirectionService | Redirection features |

**CIM Namespace:** `http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/`

| Class | Purpose |
|-------|---------|
| CIM_PowerManagementService | Power control |
| CIM_ComputerSystem | System information |
| CIM_BootConfigSetting | Boot order |
| CIM_AssociatedPowerManagementService | Power associations |
| CIM_KVMRedirectionSAP | KVM settings |

**IPS Namespace:** `http://intel.com/wbem/wscim/1/ips-schema/1/`

| Class | Purpose |
|-------|---------|
| IPS_HostBasedSetupService | Host-based provisioning |
| IPS_HTTPProxyService | HTTP proxy configuration |
| IPS_AlarmClockOccurrence | Scheduled power events |

---

## Performance Considerations

### Message ID Tracking

- Auto-incrementing counter (line 28)
- No collision handling
- Assumes sequential processing
- Wraps at JavaScript number limit

### Timeout Handling

**OperationTimeout:** 60 seconds (PT60S)
- Applies to all operations (lines 82, 96, 102, 114, 119, 124)
- AMT firmware enforces timeout
- Network latency not included
- Transport may have separate timeout

### XML Overhead

**SOAP Envelope Size:**
- Minimum ~500 bytes (headers only)
- Body adds data size + markup
- Large enumerations can be 100KB+
- Network bandwidth consideration

### Enumeration Limits

**ExecPull Limits (Line 124):**
- MaxElements: 999 items per pull
- MaxCharacters: 99999 characters
- Multiple pulls may be needed for large collections

---

## Security Considerations

### Transport Security

1. **TLS Recommended** - Use port 16993 (HTTPS) not 16992 (HTTP)
   - Encrypts credentials
   - Prevents eavesdropping
   - Validates server identity

2. **Digest Authentication** - Handled by transport module
   - Username/password not sent in clear
   - Challenge/response protocol
   - Transport responsibility

3. **Certificate Validation** - Important for TLS
   - Verify AMT certificate
   - Prevent man-in-the-middle
   - Error 998 on invalid cert

### Credential Management

1. **Protect Credentials** - Username/password in transport object
   - Never log or display
   - Store securely
   - Rotate regularly

2. **Subscription Authentication** - For event delivery (lines 66-67)
   - Separate credentials for callback endpoint
   - Use digest auth for delivery
   - Validate event sources

### Object Access Control

1. **Authorization** - AMT enforces per-class permissions
   - Admin vs. operator roles
   - Some operations require admin
   - Authentication errors return 401

2. **Audit Logging** - AMT logs all WSMAN operations
   - Review audit logs regularly
   - Detect unauthorized access
   - Track configuration changes

---

## Error Handling

### HTTP Status Codes

| Status | Meaning | Action |
|--------|---------|--------|
| 200 | OK | Success |
| 401 | Unauthorized | Check credentials |
| 408 | Timeout | Increase timeout or check network |
| 500 | Internal Error | Check AMT logs |

### WSMAN Error Codes

| Code | Error | Meaning |
|------|-------|---------|
| 601 | WSMAN Parsing Error | Invalid XML response |
| 602 | HTTP Response Error | Can't parse headers |
| 603 | Enum Response Error | Unexpected enum format |
| 604 | Pull Response Error | Unexpected pull format |
| 998 | TLS Certificate Error | Invalid or untrusted cert |

### Callback Error Pattern

```javascript
function callback(stack, uri, response, status, tag) {
    if (status !== 200) {
        if (response && response.Header && response.Header.HttpError) {
            console.error('HTTP Error:', response.Header.HttpError);
        } else {
            console.error('WSMAN Error:', status);
        }
        return;
    }

    // Process response.Body
}
```

---

## Limitations

1. **No Async/Await** - Callback-based API
   - Sequential operations require nesting
   - Can use Promise wrappers
   - No built-in promise support

2. **No Batch Operations** - One operation per message
   - Multiple updates require multiple puts
   - Enum/pull for collections
   - Performance overhead

3. **Limited Type Checking** - Trusts caller
   - No schema validation
   - No parameter type checks
   - Errors from AMT

4. **No Connection Pooling** - Transport manages connections
   - Stack doesn't handle multiple simultaneous operations
   - Transport implementation detail
   - May serialize requests

5. **MessageID Overflow** - No limit checking
   - Increments indefinitely (line 28)
   - JavaScript number limit (2^53)
   - Rare in practice

---

## Advanced Topics

### Reference Parameters

EPR (Endpoint References) for associations:

```javascript
{
    Address: 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous',
    ReferenceParameters: {
        ResourceURI: 'http://...class-uri...',
        SelectorSet: {
            Selector: [
                { '@Name': 'Name', Value: 'value1' },
                { '@Name': 'ID', Value: 'value2' }
            ]
        }
    }
}
```

### Custom Namespaces

Add namespaces for extensions (line 44):

```javascript
stack.PerformAjax(
    data,
    callback,
    tag,
    priority,
    'xmlns:custom="http://example.com/schema"'
);
```

### Selector Arrays

Multiple selectors for complex identification (lines 191-197):

```javascript
{
    Selector: [
        { '@Name': 'Name', Value: 'value1' },
        { '@Name': 'Type', Value: 'value2' }
    ]
}
```

---

## Troubleshooting

### Connection Failures

**Symptom:** Status 0, no response

**Possible Causes:**
- Network unreachable
- Wrong IP/port
- Firewall blocking
- AMT not provisioned

**Solutions:**
- Ping target IP
- Check port accessibility: `telnet ip 16992`
- Verify AMT provisioned
- Check firewall rules

### Authentication Failures

**Symptom:** Status 401

**Possible Causes:**
- Wrong username/password
- Account disabled
- Wrong authorization realm

**Solutions:**
- Verify credentials
- Check AMT user accounts
- Try admin vs. user credentials
- Reset AMT password if needed

### Parsing Errors

**Symptom:** Status 601

**Possible Causes:**
- AMT returned invalid XML
- Firmware bug
- Incomplete response

**Solutions:**
- Check AMT firmware version
- Update AMT firmware
- Try simpler operations
- Check amt-xml module

### Timeout Issues

**Symptom:** Status 408

**Possible Causes:**
- AMT busy processing
- Network latency high
- Firmware hung

**Solutions:**
- Increase operation timeout (not supported, fixed at 60s)
- Check network latency
- Reboot AMT (via hardware)
- Check AMT system health

This WSMAN stack provides the complete protocol layer for all Intel AMT network-based management operations and can run on any platform to manage remote AMT devices.
