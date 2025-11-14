# win-com.js

Provides COM (Component Object Model) interface for Windows component instantiation and manipulation. Enables JavaScript interaction with Windows COM objects through native DLL binding and virtual table marshaling, supporting both standard COM operations and custom interface implementations.

## Platform

**Supported Platforms:**
- Windows (all versions) - Full support

**Excluded Platforms:**
- **macOS** - Not supported (Windows-only)
- **Linux** - Not supported (Windows-only)
- **FreeBSD** - Not supported (Windows-only)

**Exclusion Reasoning:**

Windows-specific module requiring Windows APIs/DLLs unavailable on other platforms.

**Platform Notes:**

**win-com.js is Windows-only** because:

1. **COM Architecture** - Component Object Model is Windows-exclusive system architecture
2. **ole32.dll Dependency** - Windows COM library only available on Windows
3. **CLSID/IID Systems** - Windows Globally Unique Identifiers and interface definitions
4. **Virtual Table Marshaling** - Requires native C++ vtable manipulation
5. **Direct DLL Access** - Uses _GenericMarshal for low-level Windows API calls

---

## Functionality

### Core Purpose

win-com.js enables JavaScript code to:

1. **COM Object Creation** - Instantiate Windows COM classes by CLSID
2. **Interface Querying** - Marshal COM interfaces with proper function signatures
3. **Method Invocation** - Call COM object methods with proper calling conventions
4. **Custom Interface Implementation** - Create JavaScript-implemented COM interfaces

### Main Operations

1. **COM Instantiation** - createInstance(CLSID, IID, options)
2. **Interface Marshaling** - marshalFunctions(vptr, functionList)
3. **Interface Creation** - marshalInterface(functionArray)
4. **CLSID/IID Conversion** - CLSIDFromString(), IIDFromString()

---

## Constructor and Initialization - Lines 27-49

**Module-level Initialization:**

ole32.dll methods created (lines 29-37):
- CLSIDFromString() - Convert string GUID to binary CLSID
- CoCreateInstance() - Create COM object instance
- CoInitializeSecurity() - Set COM security parameters
- CoInitialize() - Initialize COM for thread
- CoInitializeEx() - Initialize COM with options
- CoUninitialize() - Cleanup COM for thread
- IIDFromString() - Convert string GUID to binary IID
- StringFromCLSID() - Convert CLSID to string
- StringFromIID() - Convert IID to string

**Constants:**
- CLSCTX_INPROC_SERVER (1) - In-process server
- CLSCTX_LOCAL_SERVER (4) - Local server
- EOAC_NONE (0) - No additional COM authentication
- RPC_C_AUTHN_LEVEL_DEFAULT (0) - Default authentication level
- RPC_C_IMP_LEVEL_IMPERSONATE (3) - Impersonation level
- COINIT_MULTITHREADED (0) - Multithreaded initialization
- IUnknownMethods - Base COM methods: QueryInterface, AddRef, Release

---

## Core Methods

### createInstance(CLSID, IID, options) - Lines 45-69

**Purpose:** Create and initialize Windows COM object instance

**Parameters:**
- `CLSID` - Binary CLSID (use CLSIDFromString() to convert from string)
- `IID` - Binary interface ID (use IIDFromString() for interface pointer type)
- `options` - Optional configuration (currently unused)

**Returns:** COM interface pointer

**Process:**
1. Initializes COM library for thread (line 48-49):
   - CoInitializeEx() with COINIT_MULTITHREADED flag
2. Sets COM security (line 52):
   - CoInitializeSecurity() with default parameters
3. Creates COM instance (line 57):
   - CoCreateInstance() with CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER
   - Creates interface of specified IID
4. Attaches cleanup handler (line 60):
   - Once('~') listener triggers createInstance_finalizer()
5. Returns interface pointer (line 61)

**Cleanup:**
- createInstance_finalizer() calls CoUninitialize() on finalization (line 43)

**Error Handling:**
- Throws: 'Error calling CoCreateInstance(hr)' if CoCreateInstance fails (line 68)

**Example:**
```javascript
var com = require('win-com');
var clsid = com.CLSIDFromString('{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}');
var iid = com.IIDFromString('{98325047-C671-4174-8D81-DEFCD3F03186}');
var instance = com.createInstance(clsid, iid);
```

---

### marshalFunctions(vptr, functionList) - Lines 104-107

**Purpose:** Create JavaScript-callable interface from COM virtual table

**Parameters:**
- `vptr` - Dereferenced interface pointer (usually vptr.Deref())
- `functionList` - Array of function names in vtable order

**Returns:** Object with callable function properties

**Process:**
1. Calls GM.MarshalFunctions() with vptr and function names (line 106)
2. Returns object mapping function names to callable methods
3. Methods handle native calling conventions automatically

**Example:**
```javascript
var com = require('win-com');
var functions = ['QueryInterface', 'AddRef', 'Release', 'SomeMethod'];
var obj = com.marshalFunctions(instance.Deref(), functions);
obj.SomeMethod(param1, param2);
```

---

### marshalInterface(functionArray) - Lines 110-165

**Purpose:** Create JavaScript-implemented COM interface for passing to Windows code

**Parameters:**
- `functionArray` - Array of function definitions with:
  - `name` - Function name
  - `parms` - Parameter count
  - `func` - JavaScript function implementation
  - `cx` - Custom handler (32-bit only) if needed

**Returns:** COM interface pointer (vtable)

**Process:**
1. Validates 32-bit requirements (lines 112-122):
   - Checks if 32-bit: custom handlers must be provided
   - Throws error if cx missing on 32-bit
2. Creates virtual table buffer (line 123):
   - Allocates ptr array * function count
3. Creates interface pointer (line 124):
   - Derefs vtable buffer to interface ptr
4. Registers callback handlers (lines 142-162):
   - Creates global callback for each function
   - Stores in obj._gcallbacks array
   - Copies function pointer to vtable
5. Sets up callback dispatcher (lines 149-161):
   - Listens for 'GlobalCallback' events
   - Routes to corresponding JavaScript function
   - Passes all arguments through
6. Registers cleanup handler (lines 129-138)

**Cleanup:**
- cleanup() method removes all global callbacks
- Prevents memory leaks from callbacks

**Example:**
```javascript
var com = require('win-com');
var functions = [
    { name: 'QueryInterface', parms: 3, func: function(j, riid, ppv) { ... } },
    { name: 'AddRef', parms: 1, func: function() { return 1; } },
    { name: 'Release', parms: 1, func: function() { return 0; } }
];
var iface = com.marshalInterface(functions);
```

---

### CLSIDFromString(CLSIDString) - Lines 72-85

**Purpose:** Convert GUID string to binary CLSID structure

**Parameters:**
- `CLSIDString` - String format GUID (e.g., "{12345678-1234-1234-1234-123456789012}")

**Returns:** 16-byte binary CLSID structure

**Process:**
1. Creates wide-character string from GUID (line 74)
2. Creates 16-byte buffer for CLSID (line 75)
3. Calls CLSIDFromString() ole32 API (line 77)
4. Returns binary CLSID (line 79)

**Error Handling:**
- Throws: 'Error Converting CLSIDString' if conversion fails

---

### IIDFromString(IIDString) - Lines 88-101

**Purpose:** Convert GUID string to binary IID structure

**Parameters:**
- `IIDString` - String format GUID for interface identifier

**Returns:** 16-byte binary IID structure

**Process:**
- Same as CLSIDFromString but for interface IDs
- Uses IIDFromString() ole32 API

**Error Handling:**
- Throws: 'Error Converting IIDString' if conversion fails

---

## Exported Constants and Functions

### IID_IUnknown - Line 166

**Value:** {00000000-0000-0000-C000-000000000046}

**Purpose:** Base COM interface identifier (IUnknown vtable)

**Usage:**
```javascript
var com = require('win-com');
var clsid = com.CLSIDFromString(someCLSID);
var instance = com.createInstance(clsid, com.IID_IUnknown);
```

### Module Exports - Line 166

```javascript
module.exports = {
    createInstance: createInstance,
    marshalFunctions: marshalFunctions,
    marshalInterface: marshalInterface,
    CLSIDFromString: CLSIDFromString,
    IIDFromString: IIDFromString,
    IID_IUnknown: IIDFromString('{00000000-0000-0000-C000-000000000046}')
};
```

---

## Dependencies

### Native DLL - Lines 27-37

**require('_GenericMarshal')** - Line 27
- CreateNativeProxy('ole32.dll') - Load COM library
- CreateMethod() - Define exported ole32 functions
- CreateVariable() - Memory buffer management
- CreatePointer() - Pointer operations
- PointerSize - Detect 32-bit vs 64-bit (for custom handlers)
- MarshalFunctions() - Create callable interface wrappers
- GetGenericGlobalCallbackEx() - Create global callbacks for custom interfaces
- ObjectToPtr() - Convert JavaScript objects to pointers
- PutGenericGlobalCallbackEx() - Release global callbacks

---

## Architecture Notes

### COM Threading Model

- CoInitializeEx() with COINIT_MULTITHREADED allows multithreaded access
- CoInitializeSecurity() sets per-thread security context
- Each createInstance call initializes/cleans up COM for that operation

### 32-bit vs 64-bit Considerations

- Custom handler functions require `cx` parameter on 32-bit (ellipsis support)
- 64-bit doesn't need custom handlers (line 112-119)
- Vtable pointer size adjusted automatically

### Virtual Table Structure

- Standard COM vtable: array of function pointers
- First three functions always: QueryInterface, AddRef, Release
- Function signatures must match Windows calling conventions

---

## Error Handling

1. **CLSID/IID Conversion**
   - Throws: 'Error Converting CLSIDString/IIDString'

2. **COM Initialization**
   - Throws: 'Error calling CoCreateInstance(hr)'
   - hr contains HRESULT error code

3. **Interface Marshaling**
   - Throws: 'Not supported on 32bit platforms' if custom handler missing

---

## Security Considerations

1. **COM Security** - CoInitializeSecurity() provides authentication/authorization
2. **Object Identity** - IUnknown::QueryInterface maintains object identity
3. **Reference Counting** - AddRef/Release manage object lifetime
4. **Impersonation** - Uses RPC_C_IMP_LEVEL_IMPERSONATE for caller impersonation

---

## Summary

win-com.js provides comprehensive COM object manipulation from JavaScript. The module handles COM initialization, interface marshaling, object instantiation, and custom interface implementation. Support for both consuming Windows COM objects and implementing COM-compatible interfaces enables bidirectional Windows component integration on Windows platforms only.
