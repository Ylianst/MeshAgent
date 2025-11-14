# win-wmi.js

Provides Windows Management Instrumentation (WMI) query interface for system information retrieval. Implements COM-based WMI access with support for both synchronous and asynchronous queries with proper COM object lifetime management.

## Platform

**Supported Platforms:**
- Windows (all versions with WMI) - Full support

**Excluded Platforms:**
- **macOS** - Not supported (Windows-only)
- **Linux** - Not supported (Windows-only)
- **FreeBSD** - Not supported (Windows-only)

**Exclusion Reasoning:**

Windows-specific module requiring Windows APIs/DLLs unavailable on other platforms.

**Platform Notes:**

**win-wmi.js is Windows-only** because:

1. **Windows WMI Infrastructure** - Windows-only system management interface
2. **COM Architecture** - WMI accessed through COM interfaces
3. **WbemLocator Interface** - Windows-specific WMI class locator
4. **OleAut32.dll Dependency** - Windows OLE Automation

---

## Functionality

### Core Purpose

win-wmi.js enables WMI queries:

1. **Query Execution** - Execute WQL (WMI Query Language) queries
2. **Result Enumeration** - Retrieve and parse results
3. **Property Extraction** - Get object properties
4. **Type Conversion** - Convert COM VARIANT types to JavaScript
5. **Async Operations** - Non-blocking query execution

### Main Operations

1. **Query Execution** - query(namespace, queryString, options)
2. **Async Queries** - queryAsync(namespace, queryString, options)
3. **Object Enumeration** - Iterate results with property extraction

---

## Constants and Setup - Lines 17-82

### COM Constants:

```javascript
CLSID_WbemAdministrativeLocator = '{CB8555CC-9128-11D1-AD9B-00C04FD8FDFF}'
IID_WbemLocator = '{dc12a687-737f-11cf-884d-00aa004b2e24}'
WBEM_FLAG_BIDIRECTIONAL = 0
WBEM_INFINITE = -1
WBEM_FLAG_ALWAYS = 0
E_NOINTERFACE = 0x80004002
```

### COM Interfaces:

- **IWbemLocator** - Connect to WMI services
- **IWbemServices** - Execute WMI queries
- **IEnumWbemClassObject** - Enumerate results
- **IWbemClassObject** - Individual WMI object
- **IWbemObjectSink** - Async query callback

---

## Core Functions

### enumerateProperties(j, fields) - Lines 223-317

**Purpose:** Extract properties from WMI object

**Parameters:**
- `j` - WMI class object pointer
- `fields` - Optional field name array (undefined = all fields)

**Returns:** JavaScript object with property values

**Process:**
1. Marshals COM functions on object
2. If fields specified, uses provided list
3. Otherwise, calls GetNames() to enumerate all properties
4. For each property:
   - Calls Get() to retrieve value
   - Converts VARIANT type to JavaScript type (lines 267-312):
     - VT_NULL/VT_EMPTY → null
     - VT_I2, VT_I4 → integer
     - VT_BOOL → boolean
     - VT_BSTR → string
     - VT_R8 → floating point
     - VT_UI1, VT_UI2, VT_UI4 → unsigned integer
     - Arrays handled separately
5. Returns object mapping property names to values

### Type Mapping (lines 267-312)

```javascript
0x0000, 0x0001  // VT_EMPTY, VT_NULL → null
0x0002, 0x0003  // VT_I2, VT_I4 → integer
0x000B          // VT_BOOL → boolean
0x000E          // VT_DECIMAL → special handling
0x0010-0x0013   // VT_I1, VT_UI1, VT_UI2, VT_UI4
0x0008          // VT_BSTR → string (Wide2UTF8)
0x000C          // VT_VARIANT → recursive
0x4000-0x4010   // Array variants (VT_ARRAY)
```

---

## Async Query Handler - Lines 118-220

### QueryAsyncHandler Methods (lines 118-220)

Implements IWbemObjectSink interface:

1. **QueryInterface(j, riid, ppv)** - Line 121
   - Handles IUnknown and IWmiObjectSink queries
   - Returns E_NOINTERFACE for unsupported interfaces

2. **AddRef()** - Line 149
   - Increments reference count

3. **Release()** - Line 157
   - Decrements reference count
   - Cleans up when refcount reaches 0

4. **Indicate(j, count, arr)** - Line 185
   - Called for each batch of results
   - Enumerates objects in array
   - Calls enumerateProperties() for each
   - Pushes to results array

5. **SetStatus(j, lFlags, hResult, strParam, pObjParam)** - Line 202
   - Called when query completes
   - Resolves or rejects promise based on hResult

---

## Query Functions

### query(namespace, queryString, fields) - Synchronous Query

**Purpose:** Synchronously execute WMI query

**Parameters:**
- `namespace` - WMI namespace (e.g., "ROOT\\CIMV2")
- `queryString` - WQL query string
- `fields` - Optional array of specific fields to retrieve

**Returns:** Array of result objects

**Process:**
1. Creates WbemLocator COM object
2. Connects to specified namespace
3. Executes ExecQuery()
4. Enumerates results using IEnumWbemClassObject
5. For each result, extracts properties
6. Returns array of objects

---

### queryAsync(namespace, queryString, fields) - Asynchronous Query

**Purpose:** Asynchronously execute WMI query with events

**Parameters:** Same as query()

**Returns:** Promise with events

**Events:**
- 'result' - Fired for each result object
- resolve(array) - All results on completion
- reject(error) - Error code on failure

**Advantage:** Non-blocking for large result sets

---

## Dependencies

### Native DLLs - Line 18, 25

**require('_GenericMarshal')**
- CreateNativeProxy('OleAut32.dll') - Line 25
- CreateVariable() - Memory buffers
- CreatePointer() - Pointer management
- PointerSize - Architecture detection
- SafeArrayAccessData() - Access array data

### Module Dependencies

**require('win-com')** - Multiple locations
- createInstance() - Create COM objects
- marshalFunctions() - Create callable interfaces
- CLSIDFromString() - Convert CLSID strings
- IID_IUnknown - Base interface

**require('promise')** - Async query returns

**require('events').EventEmitter** - Event emission

---

## WQL (WMI Query Language)

### Query Examples

```sql
-- Get all volumes
SELECT * FROM Win32_Volume

-- Get running processes
SELECT Name, ProcessId FROM Win32_Process WHERE Status='OK'

-- Get specific properties
SELECT DeviceID, Capacity FROM Win32_LogicalDisk

-- Filter with WHERE clause
SELECT * FROM Win32_Service WHERE State='Running'
```

---

## COM Lifetime Management

### Object Cleanup

- Each COM object properly released
- Services.Release() called after query
- Handler cleanup via Release() method
- Memory leaks prevented through proper ref counting

---

## Error Handling

### Query Errors

- HRESULT checked for success (S_OK = 0)
- Errors logged to console.info1()
- Async queries reject promise on error

### Type Conversion

- Array handling deferred (marked as TODO)
- Unknown types silently ignored
- VARIANT_BOOL properly converted

---

## Usage Examples

### Query Disk Volumes

```javascript
var wmi = require('win-wmi');
var volumes = wmi.query('ROOT\\CIMV2', 'SELECT * FROM Win32_Volume');
volumes.forEach(function(vol) {
    console.log(vol.DeviceID, vol.Capacity);
});
```

### Query Running Processes

```javascript
var processes = wmi.query('ROOT\\CIMV2',
    'SELECT Name, ProcessId FROM Win32_Process');
processes.forEach(function(proc) {
    console.log(proc.Name, proc.ProcessId);
});
```

### Async Network Query

```javascript
var wmi = require('win-wmi');
wmi.queryAsync('ROOT\\CIMV2', 'SELECT * FROM Win32_NetworkAdapter')
    .on('result', function(obj) {
        console.log('Found:', obj.Name);
    })
    .then(function(allResults) {
        console.log('Total adapters:', allResults.length);
    });
```

---

## Technical Notes

### WMI Namespaces

Common namespaces:
- ROOT\CIMV2 - Standard system information
- ROOT\DEFAULT - Default classes
- ROOT\CIMV2\Security - Security-related classes
- ROOT\WMI - Windows Management Instrumentation

### VARIANT Structures

WMI returns VARIANT structures:
- First 2 bytes: Type identifier (VT_*)
- Remaining bytes: Value or pointer to value
- Type-specific handling required

### Reference Counting

COM reference counting model:
- CreateInstance() implicit AddRef
- Must call Release() when done
- Cleanup handlers ensure Release() called

---

## Summary

win-wmi.js provides comprehensive WMI query interface with both synchronous and asynchronous execution. The module properly handles COM objects, VARIANT type conversion, and result enumeration. Support for custom field selection and async event emission enables flexible system information queries from Windows.
