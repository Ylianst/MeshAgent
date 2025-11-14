# win-firewall.js

Manages Windows Firewall rules through COM interface to Windows Firewall API. Provides comprehensive firewall configuration including rule enumeration, creation, modification, and enable/disable operations via INetFwPolicy2 COM interface with support for filtering and async operations.

## Platform

**Supported Platforms:**
- Windows (all versions with Windows Firewall) - Full support

**Excluded Platforms:**
- **macOS** - Not supported (Windows-only)
- **Linux** - Not supported (Windows-only)
- **FreeBSD** - Not supported (Windows-only)

**Exclusion Reasoning:**

Windows-specific module requiring Windows APIs/DLLs unavailable on other platforms.

**Platform Notes:**

**win-firewall.js is Windows-only** because:

1. **Windows Firewall COM API** - INetFwPolicy2 interface specific to Windows
2. **OleAut32.dll Dependency** - Windows OLE Automation library
3. **COM Infrastructure** - Uses win-com module for COM operations
4. **VARIANT Structures** - Windows-specific OLE variant handling

---

## Functionality

### Core Purpose

win-firewall.js manages Windows Firewall operations:

1. **Rule Enumeration** - Get all firewall rules with filtering
2. **Rule Manipulation** - Add, remove, enable, disable rules
3. **Async Operations** - Promise-based async rule retrieval with progress
4. **Profile Management** - Support for Domain, Private, Public profiles
5. **Direction Control** - Inbound/outbound rule management

### Main Operations

1. **Rule Queries** - getFirewallRules(options), getRulesCount(), getRulesCount2()
2. **Async Rules** - getFirewallRulesAsync(options) with progress events
3. **Rule Management** - addFirewallRule(rule), removeFirewallRule(rule), enableFirewallRules(), disableFirewallRules()

---

## Constants and Configuration - Lines 18-276

### CLSID/IID Constants:

**Firewall Classes:**
- CLSID_NetFwPolicy2: {E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}
- CLSID_NetFwRule: {2C5BC43E-3369-4C33-AB0C-BE9469677AF4}

**Interface IDs:**
- IID_INetFwPolicy2: {98325047-C671-4174-8D81-DEFCD3F03186}
- IID_INetFwRule: {AF230D27-BABA-4E42-ACED-F524F22CFCE2}
- IID_IEnumVARIANT: {00020404-0000-0000-C000-000000000046}

### Protocol Numbers Array (Lines 130-276)

Complete array of IP protocol names indexed by protocol number:
- Index 0: HOPOPT
- Index 6: TCP
- Index 17: UDP
- Index 58: IPv6-ICMP
- And 270+ other protocol types

### Profile Constants:

```javascript
DOMAIN = 0x1          // Domain profile
PRIVATE = 0x2         // Private (internal) profile
PUBLIC = 0x4          // Public profile
```

---

## Core Functions

### getFirewallRules(options) - Lines 459-557

**Purpose:** Synchronously retrieve firewall rules

**Parameters - options object (optional):**
```javascript
{
    program: 'C:\\path\\to\\app.exe',  // Filter by executable path
    minimal: false,                     // Minimal output (name, program only)
    count: true                         // Return count only
}
```

**Returns:**
- Integer if count: true
- Array of rule objects if count: false/undefined

**Rule Object Properties:**
- Program - Application path
- DisplayName - Rule name
- Description - Rule description
- LocalPorts - Comma-separated port list
- RemotePorts - Remote port list
- LocalAddresses - Local address filter
- RemoteAddresses - Remote address filter
- InterfaceTypes - Interface types
- Enabled - Boolean enabled state
- Direction - 'inbound' or 'outbound'
- Protocol - Protocol name (from protocol array)
- EdgeTraversalPolicy - 'Allow' or 'Block'
- Profile - Profile mask string (e.g., "DOMAIN, PRIVATE")

**Process:**
1. Creates INetFwPolicy2 COM instance (line 475)
2. Marshals firewall functions (line 476)
3. Gets rule collection (line 478)
4. Gets rule count if count requested (lines 481-490)
5. Enumerates all rules using IEnumVARIANT (lines 492-553)
6. Filters by program if specified (lines 510-511)
7. Extracts properties for each rule (lines 513-549)
8. Releases COM object (line 555)

---

### getFirewallRulesAsync(options) - Lines 420-458

**Purpose:** Asynchronously retrieve firewall rules with progress events

**Parameters:**
- Same as getFirewallRules()

**Returns:** Promise object with events

**Promise Events:**
- 'progress' - Fired every 5% progress (value: "XX%")
- 'rule' - Fired for each rule found
- resolve(array) - Array of rules on completion
- reject(error) - Error code on failure

**Process:**
- Similar to synchronous version
- Uses setImmediate() for async iteration
- Emits progress events every 5%
- Maintains counter for progress calculation

---

### getRulesCount() - Lines 287-290

**Purpose:** Get total firewall rule count

**Returns:** Integer count of rules

**Implementation:** Calls getFirewallRules({count: true})

---

### getRulesCount2(options) - Lines 382-418

**Purpose:** Async rule count retrieval with threading

**Returns:** Promise resolving to rule count

**Process:**
- Uses async COM method call with threading
- Returns count without enumerating all rules
- More efficient than getFirewallRulesAsync() for count only

---

### addFirewallRule(rule) - Lines 631-685

**Purpose:** Create new firewall rule

**Parameters - rule object:**
```javascript
{
    DisplayName: 'Rule Name',              // Required
    Program: 'C:\\path\\to\\app.exe',      // Required
    Protocol: 6,                           // Required (TCP=6, UDP=17, etc.)
    direction: 'inbound' or 'outbound',    // Required
    Profile: 'DOMAIN, PRIVATE',            // Required (comma-separated)
    Description: 'Rule description',       // Optional
    LocalPort: '80,443',                   // Optional
    RemotePort: '*',                       // Optional
    EdgeTraversalPolicy: true/false,       // Optional
    Enabled: true/false                    // Optional
}
```

**Process:**
1. Validates required parameters (line 633)
2. Validates direction and protocol (lines 637-639)
3. Creates new INetFwRule instance (line 660)
4. Sets rule properties via COM (lines 663-671):
   - Name, Direction, ApplicationName
   - Protocol, LocalPorts, RemotePorts
   - Description, EdgeTraversal, Enabled
5. Converts Profile string to bitmask (lines 644-659)
6. Gets rule collection from policy (line 678)
7. Adds rule to collection (line 681)

**Profile Conversion (lines 644-659):**
- Splits by comma
- Converts 'private' → 0x2
- Converts 'public' → 0x4
- Converts 'domain' → 0x1

---

### removeFirewallRule(arg) - Lines 589-630

**Purpose:** Delete firewall rule by name or rule array

**Parameters:**
- arg - String rule name, rule object array, or object with DisplayName

**Returns:** Boolean - true if removed, false if not found

**Process:**
1. If array: Recursively removes each rule
2. If string: Gets rule count before/after removal
3. Calls Rules.Remove() with rule name (line 612)
4. Compares count to verify removal (line 618)

---

### enableFirewallRules(arg) / disableFirewallRules(arg) - Lines 574-588

**Purpose:** Enable/disable existing rules

**Parameters:**
- arg - Rule array or query options object

**Process:**
1. If not array: Gets rules via getFirewallRules(arg)
2. For each rule: Calls put_Enabled(-1 for enable, 0 for disable)
3. Validates no errors occurred

---

## Profile Mask to String - Lines 278-285

```javascript
function ProfileMaskToString(mask)
{
    var val = [];
    if((mask & 0x1)==0x1) { val.push('DOMAIN');}
    if((mask & 0x2)==0x2) { val.push('PRIVATE');}
    if((mask & 0x4)==0x4) { val.push('PUBLIC');}
    return (val.join(', '));
}
```

Converts numeric profile bitmask to readable string.

---

## COM Function Declarations

### FirewallFunctions Array (Lines 30-60)

INetFwPolicy2 methods:
- get_CurrentProfileTypes - Get active profiles
- get_FirewallEnabled - Check if firewall enabled
- put_FirewallEnabled - Enable/disable firewall
- get_Rules - Get rule collection
- get_DefaultInboundAction / get_DefaultOutboundAction
- Many other policy management methods

### RulesFunctions, RuleFunctions, etc. (Lines 61-127)

Complete vtable definitions for:
- INetFwRules (rule collection)
- INetFwRule (individual rule)
- IEnumVARIANT (enumeration)
- IIdleSettings (idle properties)

---

## Dependencies

### Native DLLs - Lines 18-19

**require('_GenericMarshal')** - Line 18
- CreateNativeProxy('OleAut32.dll') - OLE Automation
- CreateVariable() - Memory buffers
- CreatePointer() - Pointer operations
- PointerSize - Architecture detection

### Module Dependencies - Lines 322, 404, 426, 475, 606, 660, 675

**require('win-com')** - Multiple locations
- createInstance() - Create COM objects
- marshalFunctions() - Create callable interfaces
- CLSIDFromString() - Convert CLSID strings
- IID_IUnknown - Base interface

**require('promise')** - Lines 385, 425
- Promise constructor for async operations

**require('events').EventEmitter** - Line 399
- Event handling for progress/rule events

---

## Error Handling

### Validation Errors

1. **Missing Required Parameters** - Throws 'Invalid Arguments'
2. **Invalid Direction** - Throws 'Invalid Direction'
3. **Invalid Protocol** - Throws 'Invalid Protocol'
4. **COM Operation Errors** - Throws 'Error...' with COM details

### Query Errors

- Silent failures in property retrieval
- Val field checked for success/failure
- Errors logged to console.info1() for debugging

---

## Technical Notes

### Direction Constants

- INBOUND (1): Inbound traffic rules
- OUTBOUND (2): Outbound traffic rules

### Protocol Handling

Protocols can be specified as:
- Integer (protocol number)
- String (protocol name from array)
- Validation checks valid range/name

### Reference Implementation

- Line 688: Module marks netsecurityExists = false
- Placeholder for future security center integration

---

## Usage Examples

### Get All Firewall Rules

```javascript
var fw = require('win-firewall');
var rules = fw.getFirewallRules();
rules.forEach(function(rule) {
    console.log(rule.DisplayName, rule.direction);
});
```

### Filter Rules by Application

```javascript
var fw = require('win-firewall');
var appRules = fw.getFirewallRules({
    program: 'C:\\Program Files\\App\\app.exe',
    minimal: true
});
```

### Add Firewall Rule

```javascript
var fw = require('win-firewall');
fw.addFirewallRule({
    DisplayName: 'Allow SSH',
    Program: 'C:\\Windows\\System32\\OpenSSH\\ssh.exe',
    Protocol: 6,        // TCP
    direction: 'inbound',
    Profile: 'DOMAIN, PRIVATE',
    LocalPort: '22',
    Enabled: true
});
```

### Disable Rules

```javascript
var fw = require('win-firewall');
var rules = fw.getFirewallRules({ program: 'C:\\badapp.exe' });
fw.disableFirewallRules(rules);
```

### Async Rule Retrieval

```javascript
var fw = require('win-firewall');
fw.getFirewallRulesAsync()
    .on('progress', function(pct) { console.log(pct); })
    .on('rule', function(rule) { console.log(rule.DisplayName); })
    .then(function(allRules) {
        console.log('Total rules:', allRules.length);
    });
```

---

## Summary

win-firewall.js provides comprehensive Windows Firewall rule management through COM interface. The module supports synchronous and asynchronous rule enumeration, filtering by application, rule creation/modification, and enable/disable operations. Complete profile support (Domain, Private, Public) and protocol handling enable flexible firewall configuration management.
