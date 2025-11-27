# CSP.js

Client Service Platform (CSP) command-line interface for Intel AMT management engine interaction. Provides unified access to AMT configuration, activation, certificate management, and device information retrieval with administrative privilege enforcement and error handling.

## Platform

**Supported Platforms:**
- Windows - Full support (requires admin privileges)
- Linux - Not supported (AMT primarily Windows-centric)
- macOS - Not supported (requires admin check and WinCrypto module)
- FreeBSD - Not supported

**Excluded Platforms:**
- macOS - No Intel Management Engine hardware
- Linux - Module requires Windows-specific modules (WinCrypto, windows_registry)
- Non-Intel systems - Requires AMT hardware/firmware

**Placement in modules_macos_NEVER:**

This module is in `modules_macos_NEVER` because:

1. **Explicit Windows Requirement** - Core dependencies are Windows-only:
   - Line 25: `if (!isAdmin())` - Uses Windows privilege API
   - Line 146-150: _GenericMarshal for Advapi32.dll access
   - Line 199: `require('WinCrypto')` - Windows cryptography module
   - Line 299: `require('windows_registry')` - Windows registry access
   - Cannot import or execute on non-Windows platforms

2. **Administrative Privilege Check (Lines 144-165):**
   Queries Windows token membership:
   ```javascript
   var AdvApi = marshal.CreateNativeProxy('Advapi32.dll');
   AdvApi.CreateMethod('AllocateAndInitializeSid');
   AdvApi.CreateMethod('CheckTokenMembership');
   ```
   - Advapi32.dll - Windows security API (not available on macOS)
   - Process exits with ERRORS.Privileges if not admin
   - No equivalent on macOS

3. **Hardware/Firmware Dependencies:**
   - Line 57: `require('amt-mei')` - PTHI interface to Management Engine
   - Line 58: `require('amt-lme')` - LME interface (requires HECI.js)
   - Line 79: `require('amt-wsman-duk')` - WSMAN transport
   - All require Intel MEI hardware (absent on macOS)

4. **Module Stack** - Depends on entire Intel AMT ecosystem:
   - amt-mei.js (Platform to Host Interface)
   - amt-lme.js (Local MEI)
   - amt-wsman-duk.js (WSMAN protocol)
   - amt-wsman.js (Higher-level WSMAN)
   - amt.js (Management API)
   - All excluded from macOS
   - CSP.js cannot initialize without these

5. **Use Case** - Enterprise Windows/Linux management only:
   - CSP = Client Service Platform (Intel terminology)
   - Manages Intel AMT provisioning and configuration
   - Not relevant to macOS system management
   - Requires Windows administrative context

**Technical Note:** While command parsing and some logic could theoretically work on other platforms, the module cannot execute on macOS due to hard dependencies on Windows-specific native modules and the absence of Intel Management Engine hardware.

## Functionality

### Module Initialization and Privileges

**Privilege Check (Lines 25-29):**

```javascript
if (!isAdmin()) {
    process.stdout.write('Error: Could not invoke amtcsp_engine.dll, system privileges are required.\n');
    process.exit(ERRORS.Privileges);
}
```

**isAdmin() Function (Lines 144-165):**

Checks if current process has administrator privileges:
1. Creates NativeProxy to Advapi32.dll (Line 147)
2. Defines three security API methods (Lines 148-150):
   - AllocateAndInitializeSid - Create SID for administrators group
   - CheckTokenMembership - Check if current token is in group
   - FreeSid - Free allocated SID

3. Allocates administrator group SID (Lines 152-154)
4. Checks current token membership (Line 159)
5. Frees SID and returns result (Line 162)

### Command-Line Arguments

**Syntax (Lines 31-36):**
```
CSP [JSON-Value] [-debug]
CSP "{\"Action\": \"GET\", \"ResourceUri\": \"DeviceInfo\"}" -debug
CSP "{\"Action\": \"REPLACE\", \"ResourceUri\": \"Settings/Configuration\"}"
```

**Parameters:**
- First argument: JSON command object
- Optional: -debug flag enables console logging

**Error Exit Codes (Line 22):**
```javascript
ERRORS = {
    JSON: 65535,
    UnknownCommand: 65534,
    UnknownResourceUri: 65533,
    Pthi: 65532,
    Lms: 65531,
    Unknown: 65530,
    ActivState: 65529,
    Wsman: 65528,
    Hbs: 65527,
    Fetch: 65526,
    Privileges: 65525,
    NoParam: 65524,
    NotAuthToken: 65523
}
```

### Module Initialization

**Module Loading (Lines 55-87):**

```javascript
mei = require('amt-mei');
lme = require('amt-lme');
pthi = new mei();
lms = new lme();
transport = require('amt-wsman-duk');
wsman = require('amt-wsman');
amt = require('amt');
```

**Error Handling (Lines 55-87):**
- PTHI connection error → exit ERRORS.Pthi (Line 61)
- LMS binding error check (Line 66):
  - errno 31 (already bound) → continue init()
  - Other errors → exit ERRORS.Lms
- LMS bind event triggers init() (Line 77)

### init() Function - Realm Discovery

**Purpose (Lines 90-142):**

1. **HTTP Request to AMT Device (Line 95):**
   ```javascript
   this.cr = require('http').get('http://127.0.0.1:16992/wsman')
   ```
   Gets 401 response with Digest realm header

2. **Parse WWW-Authenticate Header (Lines 99-105):**
   ```javascript
   var tokens = imsg.headers['WWW-Authenticate'].split(',');
   // Extract realm from header
   realm = token[1].substring(1, realm.length - 1);
   ```

3. **Get Local System Account (Lines 111-135):**
   ```javascript
   pthi.getLocalSystemAccount(function onGetLocalSystemAccount(x) {
       // x.user / x.pass = local OS credentials
   ```

4. **Create WSMAN Stack (Lines 114-130):**
   ```javascript
   if (command.AuthToken && command.Action.toUpperCase() == 'REPLACE' && command.ResourceUri == 'Settings/Activate') {
       pthi.wsstack = new wsman(transport, '127.0.0.1', 16992, x.user, x.pass, false);
   } else if (command.AuthToken) {
       pthi.wsstack = new wsman({ transport: transport, host: '127.0.0.1', port: 16992, tls: false, authToken: command.AuthToken });
   } else {
       pthi.wsstack = new wsman(transport, '127.0.0.1', 16992, x.user, x.pass, false);
   }
   ```

5. **Create AMT Stack (Line 133):**
   ```javascript
   pthi.amtstack = new amt(pthi.wsstack);
   ```

6. **Invoke run() (Line 134):**
   Entry point to command processing

### run() Function - Command Dispatch

**Action Types (Lines 168-492):**

#### GET Actions (Lines 169-401)

**Settings/ActivationState (Lines 171-182):**
```javascript
pthi.getControlMode(function (val) {
    // Returns: { controlMode: 0|1 }
    comObject.dispatch(val.controlMode);
    process.exit(0);
});
```

**Settings/Certificates (Lines 184-192):**
```javascript
EnumerateCertificates(function OnEnumerateCerts(status, certs) { ... });
```
Returns array of certificate objects (Lines 807-839)

**Settings/Configuration (Lines 194-280):**

Batch enumeration of AMT configuration:
```javascript
var wsman_commands = "AMT_WebUIService,CIM_KVMRedirectionSAP,AMT_RedirectionService,...";
pthi.amtstack.BatchEnum(null, wsman_commands, function getConfigurationResponse(...) { ... });
```

**Configuration Data Returned (Lines 200-247):**
```javascript
config = {
    WebUi: { State: 0|1 },
    Redirection: { EnableKvm: 0|1, EnableSol: 0|1, EnableStorage: 0|1 },
    EnvironmentDetection: { DetectionStrings: [...] },
    AlarmClock: [...],
    TLS: { Enabled: 0|1, Sha1Thumbprint: '...' },
    WiFi: { AmtWiFiSync: 0|1 }
}
```

**Settings/ConfigurationHash (Lines 249-280):**

Same as Settings/Configuration but additionally:
```javascript
pthi.amtstack.GetAuditLog(function(...) {
    // Find last provisioning time
    var configHash = require('SHA1Stream').create().syncHash(lastProvisionTime + ':' + JSON.stringify(config));
});
```

**DeviceInfo (Lines 282-396):**

Comprehensive device information:
```javascript
{
    Device: {
        IntelPlatform: true|false,
        UUID: 'uuid-string',
        OSPrimaryDNSSuffix: 'example.com'
    },
    Me: {
        MeFwVersion: 'x.x.x.x',
        MeSku: 0|1|2,
        DriverStatus: 0|1|2,
        DriverVersion: 'x.x.x.x'
    },
    Amt: {
        DigestRealm: 'Digest',
        AmtVersion: 'x.x.x.x',
        CcmEnabled: 0|1,
        NetworkInterfaces: [
            { dnsSuffix: '...', type: 0|1, Status: 0|1, IPv4Address: '...' }
        ]
    }
}
```

**Data Sources (Lines 283-395):**
- smbios (Line 283): Hardware info
- pthi.getVersion (Line 285): BIOS and ME versions
- DeviceManager (Line 319): Check MEI driver status
- windows_registry (Line 299): Get DNS suffix
- pthi.getLanInterfaceSettings (Lines 350-352): Network config

#### DELETE Actions (Lines 404-413)

**Settings/Activate (Line 406-407):**
```javascript
pthi.unprovision(1, function unprovisionResponse(status) {
    process.exit(status);
});
```
Removes AMT provisioning

#### REPLACE Actions (Lines 415-486)

**Settings/Configuration (Lines 418-426):**

Updates multiple configuration settings via NextReplace():
- WiFi synchronization (Lines 510-535)
- WebUI service state (Lines 537-548)
- Redirection settings (Lines 550-566)
- TLS configuration (Lines 568-623)
- Alarm clock settings (Lines 627-652)

**Settings/Activate (Lines 428-481):**

Provisions AMT with CCM (Client Controlled Mode):
1. Validates ActivationState (Lines 429-433)
2. Validates RequestedStateChange (Lines 435-440)
3. Enumerates IPS_HostBasedSetupService (Lines 441-452)
4. Calls Setup with AuthToken (Lines 459-478)
5. Returns status via comObject.dispatch

### Helper Functions

**NextReplace(responses) - Lines 507-652:**

Processes REPLACE command responses and executes updates:

**WiFi Update (Lines 510-535):**
- Enables/disables WiFi synchronization
- Updates AMT_WiFiPortConfigurationService
- Checks device support before attempting

**WebUI Update (Lines 537-548):**
- Enables/disables Web UI service
- Calls AMT_WebUIService_RequestStateChange

**Redirection Update (Lines 550-566):**
- SOL (Serial over LAN) enable/disable
- Storage redirection enable/disable
- KVM enable/disable
- Calls AMT_RedirectionService_RequestStateChange

**TLS Update (Lines 568-623):**
- Enables: IssueSelfSignedCertificate() (Line 622)
- Disables: Certificate_Delete (Lines 599-614)
- Manages credential context (Lines 589-616)
- 2-second delay before delete (Line 597)

**AlarmClock Update (Lines 627-652):**
- Deletes existing alarms
- Creates new alarms from payload
- Calls AMT_AlarmClockService_AddAlarm

**IssueSelfSignedCertificate() - Lines 655-713:**

Generates and installs self-signed TLS certificate:
1. Generates RSA key pair via AMT_PublicKeyManagementService
2. Fetches public key
3. Creates untrusted root certificate
4. Issues certificate signed by root
5. Adds certificate to AMT

**SetupTLS(response) - Lines 715-768:**

Configures TLS after certificate installed

**EnableTLS(AMT_TLSSettingData) - Lines 769-793:**

Enables TLS with settings:
- Enabled: true
- AcceptNonSecureConnections: true
- MutualAuthentication: false

**EnumerateCertificates(callback_func) - Lines 794-847:**

Fetches all certificates and associates with metadata:
```javascript
pthi.amtstack.BatchEnum(null,
    ['AMT_PublicKeyCertificate', 'AMT_TLSCredentialContext', 'AMT_PublicPrivateKeyPair'],
    function(...) { ... }
);
```

Associates:
- Private keys with certificates (Line 821)
- TLS credential contexts with certificates (Line 832)
- Adds Delete method to each certificate (Line 815)

**Certificate_Delete(callback_func) - Lines 922-950:**

Three-step certificate deletion:
1. Delete TLSCredentialContext if exists
2. Delete PublicPrivateKeyPair if exists
3. Delete Certificate

Each step waits for previous completion (Lines 931-944)

**AMT_SupportsWireless(func_callback) - Lines 992-1002:**

Checks if AMT supports wireless:
```javascript
pthi.getLanInterfaceSettings(1, function onAMTSupportsWireless(info, tag) {
    cb.apply(null, tag.unshift(info != null));
});
```

Returns true if interface 1 (wireless) configured

### ComObjectInterop Object

**Purpose (Lines 850-871):**

Bridges process output to COM interface for calling application:

```javascript
var comObject = new ComObjectInterop();
comObject.dispatch({result});
comObject.dispatch({ErrorDescription: '...', ErrorCode: 65535});
```

**Implementation:**
- Attempts to create ExternalDispatchSink method (Line 865)
- Falls back to console output if unavailable (Line 869)
- Disables console by default (Line 856)
- Re-enables with -debug flag (Lines 857-862)

## Dependencies

### Node.js Core Modules

#### http (Line 95)

```javascript
require('http').get('http://127.0.0.1:16992/wsman', callback)
```

**Purpose:** HTTP client for AMT realm discovery

**Methods:**
- get(url, callback) - GET request
- Response headers: 'WWW-Authenticate'

### MeshAgent Module Dependencies

#### amt-mei (Line 57)

```javascript
mei = require('amt-mei');
pthi = new mei();
pthi.getLocalSystemAccount(callback)
pthi.getControlMode(callback)
pthi.getVersion(callback)
pthi.getLanInterfaceSettings(interface, callback)
pthi.unprovision(flag, callback)
```

**Purpose:** Platform to Host Interface (PTHI) access

**Methods:**
- getLocalSystemAccount() - Get default credentials
- getControlMode() - Check activation state
- getVersion() - Get BIOS and ME versions
- getLanInterfaceSettings() - Get network configuration
- unprovision() - Remove AMT provisioning

#### amt-lme (Line 58)

```javascript
lme = require('amt-lme');
lms = new lme();
lms.on('error', callback)
lms.on('bind', callback)
```

**Purpose:** Local MEI interface for port forwarding setup

#### amt-wsman-duk (Line 79)

```javascript
transport = require('amt-wsman-duk');
```

**Purpose:** WSMAN protocol transport (used by amt-wsman)

#### amt-wsman (Line 80)

```javascript
wsman = require('amt-wsman');
var stack = new wsman(transport, host, port, user, pass, tls);
// or
var stack = new wsman({ transport, host, port, tls, authToken });
```

**Purpose:** Higher-level WSMAN protocol implementation

#### amt (Line 81)

```javascript
amt = require('amt');
var amtstack = new amt(wsmanStack);
amtstack.BatchEnum(null, commands, callback)
amtstack.Enum(resource, callback)
amtstack.Put(resource, object, callback)
amtstack.Delete(resource, object, callback)
amtstack.GetAuditLog(callback)
amtstack.IPS_HostBasedSetupService_Setup(mode, token, ...)
// ... and many other AMT CIM methods
```

**Purpose:** High-level AMT management API

**Methods Used:**
- BatchEnum() - Enumerate multiple CIM resources
- Enum() - Enumerate single resource
- Put() - Update resource
- Delete() - Delete resource
- GetAuditLog() - Fetch audit log
- Service-specific methods (IPS_HostBasedSetupService, etc.)

#### smbios (Line 283)

```javascript
this.smbios = require('smbios');
this.smbios.get(function onSMBiosGet(data) { ... });
```

**Purpose:** Hardware information retrieval

**Methods:**
- get(callback) - Retrieve and parse SMBIOS tables
- parse(data) - Parse SMBIOS data
- amtInfo(data) - Extract AMT capabilities
- systemInfo(data) - Extract system information

#### WinCrypto (Line 199)

```javascript
var WinCrypto = require('WinCrypto');
var cert = WinCrypto.loadCert(x509, { encodingType: WinCrypto.X509_ASN_ENCODING });
var info = cert.getInfo();
var root = WinCrypto.makeCert(options);
var child = WinCrypto.MakeCertFromPublicKey({...});
var signed = WinCrypto.SignCertificate(issuer, subject);
```

**Purpose:** Windows cryptography for certificate operations

**Methods:**
- loadCert() - Load X.509 certificate
- makeCert() - Create self-signed certificate
- MakeCertFromPublicKey() - Create cert from public key
- SignCertificate() - Sign certificate

#### windows_registry (Line 299)

```javascript
var registry = require('windows_registry');
registry.QueryKey(registry.HKEY.LocalMachine, 'SYSTEM\\...', 'Domain')
```

**Purpose:** Windows registry access

**Methods:**
- QueryKey(hive, path, valueName) - Read registry value

#### DeviceManager (Line 319)

```javascript
var Devices = require('DeviceManager').getDevices({ manufacturer: 'Intel*', class: 'System' });
```

**Purpose:** Query installed devices

**Methods:**
- getDevices(filter) - List devices matching filter

#### SHA1Stream (Line 265)

```javascript
var configHash = require('SHA1Stream').create().syncHash(data).toString('hex');
```

**Purpose:** SHA1 hashing

**Methods:**
- create() - Create hasher
- syncHash(data) - Hash data synchronously
- toString(encoding) - Get hash as string

### Dependency Chain

```
CSP.js
├─── _GenericMarshal (Advapi32.dll for admin check)
│    └─── Windows privilege API
├─── amt-mei (PTHI interface)
│    └─── HECI layer
├─── amt-lme (LME interface)
│    └─── HECI layer
├─── amt-wsman-duk (WSMAN transport)
│    └─── HTTP/HTTPS
├─── amt-wsman (WSMAN protocol)
│    └─── WSMAN transport
├─── amt (Management API)
│    └─── WSMAN
├─── smbios (Hardware info)
├─── WinCrypto (Certificates)
├─── windows_registry (Registry access)
├─── DeviceManager (Device enumeration)
├─── SHA1Stream (Hashing)
├─── http (HTTP client)
└─── events (EventEmitter)
```

### Platform Binary Dependencies

**Windows-Only:**
- Advapi32.dll - Security/privilege checking
- Kernel32.dll - File and event operations
- SetupAPI.dll - Device enumeration
- Intel MEI driver - Management Engine access
- Kernel32 firmware table API - SMBIOS access
- Windows registry - Configuration access

**Absolute Platform Requirement:**
- Windows operating system
- Administrator/SYSTEM privileges
- Intel Management Engine hardware
- MEI driver installed

## Technical Notes

### Privilege Elevation

CSP.js requires administrative privileges (ERRORS.Privileges = 65525):
- Checked via Windows token membership (Lines 144-165)
- Checks "Administrators" group (SID-512)
- Process exits immediately if not admin
- Required for MEI driver access

### WSMAN Stack Variants

Two initialization patterns:

**Legacy Positional (Lines 116, 128):**
```javascript
new wsman(transport, '127.0.0.1', 16992, user, pass, false)
```

**Modern Object (Line 123):**
```javascript
new wsman({ transport, host, port, tls, authToken })
```

Both are supported, second form preferred.

### Error Handling Pattern

**Try-Catch with Dispatch (Lines 40-50):**
```javascript
try {
    command = JSON.parse(process.argv[1]);
} catch(e) {
    comObject.dispatch({ErrorDescription: 'JSON Error - ' + e, ErrorCode: ERRORS.JSON});
    process.exit(ERRORS.JSON);
}
```

All errors dispatched to COM before exiting.

### HTTP vs HTTPS

Default configuration (Line 123):
- tls: false → HTTP to localhost:16992
- Appropriate for local management engine (no network exposure)
- No certificate validation needed (local device)

### Realm Detection

Realm obtained from 401 response WWW-Authenticate header:
```
WWW-Authenticate: Digest realm="Digest",nonce="..."
```

Required for WSMAN digest authentication setup (Line 100-105).

### Authentication Token Types

**Local Account (Line 128):**
Default OS/Admin credentials
```javascript
pthi.wsstack = new wsman(transport, '127.0.0.1', 16992, user, pass, false);
```

**Custom Token (Line 123):**
User-provided authToken
```javascript
pthi.wsstack = new wsman({ transport, host, port, authToken });
```

**Activation Override (Line 116):**
Special case for activate operation with token
```javascript
if (command.AuthToken && ... 'Settings/Activate')
```

### Configuration Payload

Settings/Configuration REPLACE takes Payload:
```javascript
command.Payload = {
    WebUi: { State: 0|1 },
    Redirection: { EnableKvm, EnableSol, EnableStorage },
    TLS: { Enabled: true|false },
    AlarmClock: [...],
    WiFi: { AmtWiFiSync: 0|1 }
}
```

### Async Callback Chain

Commands use complex nested callbacks for multi-step operations:
1. Init discovers realm (Line 95)
2. Gets credentials (Line 111)
3. Initializes stacks (Lines 116-133)
4. Executes command-specific handlers
5. Dispatches result via comObject
6. Exits with status code

## Summary

The CSP.js module provides a Windows-only command-line interface to Intel AMT management engine functionality. It handles administrative privilege verification, module initialization, command parsing, and dispatch to higher-level AMT APIs for configuration, activation, and device management operations.

**Placed in modules_macos_NEVER** because:
- Explicit Windows requirements (Advapi32.dll, WinCrypto, windows_registry)
- Hard dependency on entire Intel AMT ecosystem (all macOS-excluded modules)
- Requires Intel Management Engine hardware (absent on macOS)
- Administrative privilege API Windows-specific
- Use case (enterprise AMT management) not relevant to macOS

**Core functionality:**
- Administrative privilege enforcement
- PTHI and LME interface initialization
- WSMAN and AMT stack setup
- Command-line argument parsing
- GET/DELETE/REPLACE action dispatch
- Configuration, activation, and certificate management
- Device information and system inventory

Used for enterprise Intel AMT provisioning, configuration, and management on Windows systems with Intel Management Engine.
