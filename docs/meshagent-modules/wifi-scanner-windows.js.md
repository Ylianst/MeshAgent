# wifi-scanner-windows.js

Windows wireless network (WiFi) scanner using native Windows WLAN API through _GenericMarshal for enumerating available access points and detecting network connectivity. Provides low-level WiFi scanning capabilities for Windows systems.

## Platform

**Supported Platforms:**
- Windows - Full support only

**Excluded Platforms:**
- macOS - No support
- Linux - No support
- Other - No support

**Placement in modules_macos_NEVER:**

macOS is excluded because:

1. **Windows WLAN API Exclusive** - Lines 116, 118-122 explicitly load Windows WLAN DLL:
```javascript
this.Native = this.Marshal.CreateNativeProxy("wlanapi.dll");
this.Native.CreateMethod("WlanOpenHandle");
this.Native.CreateMethod("WlanGetNetworkBssList", "GetBSSList");
```

The entire implementation depends on Windows wlanapi.dll (Windows WLAN service). macOS uses completely different WiFi APIs (CoreWLAN framework).

2. **Native DLL Interop** - Line 115 uses _GenericMarshal:
```javascript
this.Marshal = require('_GenericMarshal');
```

This is Windows-specific binary interop mechanism for calling native DLL functions. macOS would require different interop mechanisms for Objective-C frameworks.

3. **WLAN Handle and Interface Enumeration** - Lines 19-25 enumerate WLAN interfaces using Windows-specific structures:
```javascript
this.Native.WlanEnumInterfaces(this.Handle, 0, wlanInterfaces);
var count = wlanInterfaces.Deref().Deref(0, 4).toBuffer().readUInt32LE(0);
```

Windows WLAN interface enumeration has no macOS equivalent.

4. **WiFi Callback Notification** - Lines 130-133 register Windows WLAN notification callback:
```javascript
this._NOTIFY_PROXY_OBJECT = this.Marshal.CreateCallbackProxy(OnNotify, 2);
var result = this.Native.WlanRegisterNotification(this.Handle, 0X0000FFFF, 0, ...);
```

Windows-specific notification mechanism.

## Functionality

### Core Purpose

Enumerates available WiFi networks on Windows systems using native WLAN API. Scans for access points and returns SSID, BSSID (MAC address), signal strength (RSSI), and link quality metrics.

### Module Exports (Line 170)

```javascript
module.exports = new Wireless();
```

**Returns singleton instance** of Wireless object with scan capabilities.

### Wireless Constructor (Lines 111-168)

```javascript
function Wireless() {
    var emitterUtils = require('events').inherits(this);

    this.Marshal = require('_GenericMarshal');
    this.Native = this.Marshal.CreateNativeProxy("wlanapi.dll");
    // ... method definitions and initialization
}
```

**Initialization Steps:**

1. **Enable Event Emitter (Line 113):**
   ```javascript
   var emitterUtils = require('events').inherits(this);
   ```

2. **Load Windows WLAN API (Lines 115-122):**
   ```javascript
   this.Marshal = require('_GenericMarshal');
   this.Native = this.Marshal.CreateNativeProxy("wlanapi.dll");
   this.Native.CreateMethod("WlanOpenHandle");
   this.Native.CreateMethod("WlanGetNetworkBssList", "GetBSSList");
   this.Native.CreateMethod("WlanRegisterNotification");
   this.Native.CreateMethod("WlanEnumInterfaces");
   this.Native.CreateMethod("WlanScan");
   this.Native.CreateMethod("WlanQueryInterface");
   ```

3. **Open WLAN Handle (Lines 124-128):**
   ```javascript
   var negotiated = this.Marshal.CreatePointer();
   var h = this.Marshal.CreatePointer();

   this.Native.WlanOpenHandle(2, 0, negotiated, h);
   this.Handle = h.Deref();
   ```

4. **Register Notification Callback (Lines 130-133):**
   ```javascript
   this._NOTIFY_PROXY_OBJECT = this.Marshal.CreateCallbackProxy(OnNotify, 2);
   this._NOTIFY_PROXY_OBJECT.Parent = this;
   var PrevSource = this.Marshal.CreatePointer();
   var result = this.Native.WlanRegisterNotification(this.Handle, 0X0000FFFF, 0,
       this._NOTIFY_PROXY_OBJECT.Callback, this._NOTIFY_PROXY_OBJECT.State, 0, PrevSource);
   ```

5. **Create Event Emitter Methods (Lines 135-136):**
   ```javascript
   emitterUtils.createEvent('Scan');
   emitterUtils.addMethod('Scan', _Scan);
   ```

### Scan Operation: _Scan() (Lines 17-68)

```javascript
function _Scan() {
    var wlanInterfaces = this.Marshal.CreatePointer();
    this.Native.WlanEnumInterfaces(this.Handle, 0, wlanInterfaces);

    var count = wlanInterfaces.Deref().Deref(0, 4).toBuffer().readUInt32LE(0);
    var info = wlanInterfaces.Deref().Deref(8, 532);
    var iname = info.Deref(16, 512).AnsiString;
    // ...
}
```

**Step 1: Enumerate Interfaces (Lines 19-20):**
```javascript
var wlanInterfaces = this.Marshal.CreatePointer();
this.Native.WlanEnumInterfaces(this.Handle, 0, wlanInterfaces);
```

Call WlanEnumInterfaces to populate interface list.

**Step 2: Parse Interface Count (Lines 22):**
```javascript
var count = wlanInterfaces.Deref().Deref(0, 4).toBuffer().readUInt32LE(0);
```

Read first 4 bytes (uint32) for number of interfaces.

**Step 3: Parse Interface Info (Lines 24-57):**
```javascript
var info = wlanInterfaces.Deref().Deref(8, 532);  // Read 532-byte interface structure
var iname = info.Deref(16, 512).AnsiString;        // Name at offset 16

// Parse interface state (offset 528, 4 bytes)
var istate;
switch (info.Deref(528, 4).toBuffer().readUInt32LE(0)) {
    case 0: istate = "NOT READY"; break;
    case 1: istate = "CONNECTED"; break;
    case 2: istate = "AD-HOC"; break;
    case 3: istate = "DISCONNECTING"; break;
    case 4: istate = "DISCONNECTED"; break;
    case 5: istate = "ASSOCIATING"; break;
    case 6: istate = "DISCOVERING"; break;
    case 7: istate = "AUTHENTICATING"; break;
    default: istate = "UNKNOWN"; break;
}
```

**Interface State Values:**
- 0: NOT READY - Interface not available
- 1: CONNECTED - Connected to network
- 2: AD-HOC - Ad-hoc mode
- 3-7: Connection in progress
- Other: Unknown state

**Step 4: Initiate Scan (Lines 59-67):**
```javascript
var iguid = info.Deref(0, 16);  // Interface GUID (16 bytes at offset 0)
if (this.Native.WlanScan(this.Handle, iguid, 0, 0, 0).Val == 0) {
    return (true);
} else {
    return (false);
}
```

Call WlanScan on interface GUID. Returns true on success, false on failure.

### Notification Callback: OnNotify() (Lines 82-109)

```javascript
function OnNotify(NotificationData) {
    var NotificationSource = NotificationData.Deref(0, 4).toBuffer().readUInt32LE(0);
    var NotificationCode = NotificationData.Deref(4, 4).toBuffer().readUInt32LE(0);
    var dataGuid = NotificationData.Deref(8, 16);

    if ((NotificationSource & 0X00000008) && (NotificationCode == 7)) {
        // Scan complete, retrieve results
    }
}
```

**Notification Structure (Line 84-86):**
- Bytes 0-3: NotificationSource (flags)
- Bytes 4-7: NotificationCode (operation type)
- Bytes 8-23: dataGuid (interface GUID)

**Scan Complete Detection (Line 88):**
```javascript
if ((NotificationSource & 0X00000008) && (NotificationCode == 7))
```
- Checks for notification source flag 0x00000008
- Checks for notification code 7 (scan complete)

**Step 1: Get BSS List (Lines 90-91):**
```javascript
var bss = this.Parent.Marshal.CreatePointer();
var result = this.Parent.Native.GetBSSList(this.Parent.Handle, dataGuid, 0, 3, 0, 0, bss).Val;
```

Call GetBSSList to retrieve scanned access points.

**Step 2: Parse BSS Count (Lines 94-95):**
```javascript
var totalSize = bss.Deref().Deref(0, 4).toBuffer().readUInt32LE(0);
var numItems = bss.Deref().Deref(4, 4).toBuffer().readUInt32LE(0);
```

**Step 3: Parse Access Points (Lines 96-105):**
```javascript
for (i = 0; i < numItems; ++i) {
    var item = bss.Deref().Deref(8 + (360 * i), 360);  // 360-byte BSS entry
    var ssid = item.Deref(4, 32).String.trim();        // SSID at offset 4, 32 bytes
    var bssid = item.Deref(40, 6).HexString2;          // BSSID at offset 40, 6 bytes (MAC)
    var rssi = item.Deref(56, 4).toBuffer().readUInt32LE(0);    // RSSI (signal strength)
    var lq = item.Deref(60, 4).toBuffer().readUInt32LE(0);      // Link quality

    this.Parent.emit('Scan', new AccessPoint(ssid, bssid, rssi, lq));
}
```

**BSS Structure (360 bytes per entry):**
- Offset 4: SSID (32 bytes, string)
- Offset 40: BSSID (6 bytes, MAC address)
- Offset 56: RSSI (4 bytes, uint32, signal strength in dBm)
- Offset 60: Link Quality (4 bytes, uint32, 0-100%)

### AccessPoint Class (Lines 70-80)

```javascript
function AccessPoint(_ssid, _bssid, _rssi, _lq) {
    this.ssid = _ssid;
    this.bssid = _bssid;
    this.rssi = _rssi;
    this.lq = _lq;
}

AccessPoint.prototype.toString = function() {
    return (this.ssid + " [" + this.bssid + "]: " + this.lq);
}
```

**Properties:**
- ssid - Network name (string)
- bssid - MAC address (hex string)
- rssi - Received Signal Strength Indicator (dBm)
- lq - Link Quality (percentage 0-100)

**String Representation:** `"NetworkName [AA:BB:CC:DD:EE:FF]: 75"`

### GetConnectedNetwork() (Lines 138-164)

```javascript
this.GetConnectedNetwork = function () {
    var interfaces = this.Marshal.CreatePointer();
    console.log('Success = ' + this.Native.WlanEnumInterfaces(this.Handle, 0, interfaces).Val);

    var count = interfaces.Deref().Deref(0, 4).toBuffer().readUInt32LE(0);
    var info = interfaces.Deref().Deref(8, 532);
    var istate = info.Deref(528, 4).toBuffer().readUInt32LE(0);

    if(info.Deref(528, 4).toBuffer().readUInt32LE(0) == 1) { // CONNECTED
        var dataSize = this.Marshal.CreatePointer();
        var pData = this.Marshal.CreatePointer();
        var valueType = this.Marshal.CreatePointer();
        var iguid = info.Deref(0, 16);

        var retVal = this.Native.WlanQueryInterface(this.Handle, iguid, 7, 0,
            dataSize, pData, valueType).Val;

        if (retVal == 0) {
            var associatedSSID = pData.Deref().Deref(524, 32).String;
            var bssid = pData.Deref().Deref(560, 6).HexString;
            var lq = pData.Deref().Deref(576, 4).toBuffer().readUInt32LE(0);

            return (new AccessPoint(associatedSSID, bssid, 0, lq));
        }
    }
    throw ("GetConnectedNetworks: FAILED (not associated to a network)");
}
```

**Returns currently connected network information** via WlanQueryInterface.

**Query Data Offsets (if connected):**
- Offset 524: Associated SSID (32 bytes)
- Offset 560: BSSID (6 bytes)
- Offset 576: Link Quality (4 bytes)

## Dependencies

### MeshAgent Module Dependencies

#### _GenericMarshal (Lines 115, 124-125, 130, 140, 149-151, 156-157)

```javascript
this.Marshal = require('_GenericMarshal');
this.Native = this.Marshal.CreateNativeProxy("wlanapi.dll");
```

**Purpose:** Windows native DLL interop mechanism

**Methods Used:**
- `CreateNativeProxy(dllName)` - Load DLL
- `CreateMethod(methodName, [aliasName])` - Define method signature
- `CreatePointer()` - Create pointer for output parameters
- `CreateCallbackProxy(function, paramCount)` - Create callback function pointer
- `Deref(offset, size)` - Dereference pointer at offset
- `.toBuffer()` - Convert to Buffer
- `.AnsiString`, `.String`, `.HexString2` - String conversions

#### events (Line 113)

```javascript
var emitterUtils = require('events').inherits(this);
emitterUtils.createEvent('Scan');
emitterUtils.addMethod('Scan', _Scan);
```

**Purpose:** Event emitter for scan notifications

**Methods:**
- `createEvent(name)` - Register event type
- `addMethod(name, function)` - Add event-triggering method

### Platform Binary Dependencies

#### wlanapi.dll (Line 116)

**Windows Native Library - WLAN Service API**

**Functions Called:**
- `WlanOpenHandle(dwClientVersion, reserved, pdwNegotiatedVersion, phClientHandle)` - Open WLAN service connection
- `WlanEnumInterfaces(hClientHandle, reserved, ppInterfaceList)` - List WLAN interfaces
- `WlanScan(hClientHandle, pInterfaceGuid, pSsid, pIeData, pReserved)` - Initiate WiFi scan
- `WlanRegisterNotification(hClientHandle, dwNotifSource, bIgnoreDuplicate, funcCallback, pCallbackContext, pReserved, pdwPrevNotifSource)` - Register for scan completion notifications
- `WlanGetNetworkBssList(hClientHandle, pInterfaceGuid, pSsid, dot11BssType, bSecurityEnabled, pReserved, ppWlanBssList)` - Get list of access points found
- `WlanQueryInterface(hClientHandle, pInterfaceGuid, opCode, pData, pdwDataSize, ppInterfaceInfo, pWlanOpcodeValueType)` - Query current connection info

**Availability:** All Windows versions with wireless support (XP SP3+, Vista, 7, 8, 10, 11)

## Technical Notes

### Windows WLAN API Architecture

**Three-Phase Scanning:**

1. **Initiation** - Call WlanScan()
2. **Notification** - Receive OnNotify callback when complete
3. **Retrieval** - Call WlanGetNetworkBssList() to get results

This asynchronous model allows multiple scan requests without blocking.

### Interface GUID

**16-byte Identifier (Line 59):**
```javascript
var iguid = info.Deref(0, 16);
```

Each WiFi interface has unique 128-bit GUID. Must specify which interface to scan.

### RSSI (Received Signal Strength Indicator)

**Value:** Typically -30 to -90 dBm
- -30 dBm: Very strong signal
- -50 dBm: Good signal
- -70 dBm: Weak signal
- -90 dBm: Very weak signal

**Interpretation:** Higher values (closer to 0) = stronger signal

### Link Quality

**Value:** 0-100 percentage
- 100: Excellent
- 75-99: Good
- 50-74: Fair
- 25-49: Weak
- 0-24: Very Weak

### Event Emission

**Scan Event (Line 104):**
```javascript
this.Parent.emit('Scan', new AccessPoint(ssid, bssid, rssi, lq));
```

Emits 'Scan' event for each access point found.

### Structure Memory Layout

**Interface Structure (532 bytes):**
- Offset 0-15: Interface GUID
- Offset 16-527: Interface name and info
- Offset 528-531: Interface state

**BSS Entry (360 bytes):**
- Offset 4-35: SSID
- Offset 40-45: BSSID (MAC)
- Offset 56-59: RSSI
- Offset 60-63: Link Quality

### Pointer Dereferencing

**Chain Dereferencing (Line 22):**
```javascript
var count = wlanInterfaces.Deref().Deref(0, 4).toBuffer().readUInt32LE(0);
```

1. `wlanInterfaces.Deref()` - Dereference pointer
2. `.Deref(0, 4)` - Read 4 bytes at offset 0
3. `.toBuffer()` - Convert to Buffer object
4. `.readUInt32LE(0)` - Read as 32-bit little-endian integer

### Notification Bitmask

**NotificationSource Flags (Line 88):**
```javascript
if ((NotificationSource & 0X00000008) && (NotificationCode == 7))
```

- 0x00000008: Mask for specific notification source
- 7: Scan complete notification code

Both conditions must be true to process results.

## Summary

wifi-scanner-windows.js provides Windows WiFi scanning using native WLAN API via _GenericMarshal interop. Enumerates available networks with SSID, BSSID, signal strength, and link quality.

**Placed in modules_macos_NEVER** because:
- Exclusively uses Windows wlanapi.dll (no macOS equivalent)
- Relies on _GenericMarshal Windows DLL interop
- Implements Windows WLAN interface enumeration
- Uses Windows notification callback mechanism
- No fallback for non-Windows platforms

**Key Features:**
- Asynchronous WiFi scanning via notifications
- Access point enumeration with signal metrics
- Current network connection query
- Interface enumeration and state detection

**Data Per Access Point:**
- SSID (network name)
- BSSID (MAC address)
- RSSI (signal strength in dBm)
- Link Quality (0-100%)

**Related Modules:**
- wifi-scanner.js - Cross-platform wrapper
- _GenericMarshal - Windows DLL interop
