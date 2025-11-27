# amt-xml.js

Lightweight XML parser and generator specifically designed for WSMAN (Web Services for Management) SOAP messages used in Intel AMT communication. Provides bidirectional conversion between XML and JavaScript objects without requiring external XML parser dependencies.

## Platform

**Supported Platforms:**
- Windows - Full support
- Linux - Full support
- FreeBSD - Full support
- **Cross-platform** - Pure JavaScript, no platform-specific code

**Excluded Platforms:**
- **macOS** - Excluded (technically compatible, contextually irrelevant)

**Exclusion Reasoning:**

This module is **technically compatible** with macOS (100% portable JavaScript with zero dependencies) but is **excluded for architectural reasons**:

1. **Intel AMT Context** - Exclusively used for parsing WSMAN SOAP messages in Intel AMT communication. Intel AMT management is rarely performed from macOS systems.

2. **Part of AMT Stack** - Component of the larger Intel AMT management infrastructure (used by amt.js, amt-wsman.js, amt-wsman-duk.js). The entire stack is excluded from macOS builds due to limited use case.

3. **Enterprise Management Tool** - AMT management typically runs on Windows/Linux servers in enterprise environments, not on macOS workstations.

4. **Contextually Irrelevant** - While the code would work identically on macOS, the Intel AMT management use case doesn't apply to typical macOS deployments where AMT hardware doesn't exist and AMT management servers are not deployed.

## Functionality

### Core Purpose

Provides specialized XML parsing and generation for WSMAN protocol messages without requiring heavy XML parsing libraries. Key capabilities:

- Parse WSMAN SOAP responses into JavaScript objects
- Generate WSMAN SOAP request bodies from JavaScript objects
- Handle XML namespaces (xmlns)
- Convert XML types to JavaScript types (boolean, integer)
- Support for XML attributes
- Lightweight implementation (189 lines, no dependencies)

### Why Custom XML Parser?

**Instead of using standard XML parsers because:**

1. **Embedded Environment** - MeshAgent runs in Duktape, a lightweight JavaScript engine. Standard DOM parsers may not be available.

2. **Minimal Dependencies** - Avoids external dependencies on libxml2, expat, or other XML libraries.

3. **WSMAN-Specific** - Tailored for WSMAN SOAP structure, not general XML processing.

4. **Size Constraints** - Smaller footprint than general-purpose XML parsers.

### ParseWsman(xml) - Line 21

**Purpose:** Parse WSMAN SOAP XML response into structured JavaScript object

**Input:** XML string or XML DOM object

**Output:** JavaScript object with Header and Body properties

**Example:**

```javascript
var xml = '<s:Envelope xmlns:s="..." xmlns:wsman="...">' +
          '  <s:Header>' +
          '    <wsman:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings</wsman:ResourceURI>' +
          '    <wsa:MessageID>uuid:12345</wsa:MessageID>' +
          '  </s:Header>' +
          '  <s:Body>' +
          '    <r:AMT_GeneralSettings_OUTPUT>' +
          '      <r:NetworkInterfaceEnabled>true</r:NetworkInterfaceEnabled>' +
          '      <r:DDNSUpdateEnabled>false</r:DDNSUpdateEnabled>' +
          '      <r:IdleWakeTimeout>65535</r:IdleWakeTimeout>' +
          '    </r:AMT_GeneralSettings_OUTPUT>' +
          '  </s:Body>' +
          '</s:Envelope>';

var result = require('amt-xml').ParseWsman(xml);

// Result structure:
{
    Header: {
        ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings",
        MessageID: "uuid:12345"
    },
    Body: {
        NetworkInterfaceEnabled: true,      // Converted from "true" string
        DDNSUpdateEnabled: false,            // Converted from "false" string
        IdleWakeTimeout: 65535               // Converted from "65535" string to int
    }
}
```

**Type Conversions (Lines 54-56):**

```javascript
if (data == 'true') data = true;                           // String "true" → boolean true
if (data == 'false') data = false;                         // String "false" → boolean false
if ((parseInt(data) + '') === data) data = parseInt(data); // "123" → number 123
```

**Attribute Handling (Lines 59-64):**

XML attributes are converted to properties prefixed with `@`:

```xml
<r:Property Name="Value1" Type="string">Test</r:Property>
```

Becomes:

```javascript
{
    Property: {
        Value: "Test",
        "@Name": "Value1",
        "@Type": "string"
    }
}
```

**Array Handling (Lines 66-68):**

Multiple elements with same name become JavaScript arrays:

```xml
<r:Items>
    <r:Item>First</r:Item>
    <r:Item>Second</r:Item>
    <r:Item>Third</r:Item>
</r:Items>
```

Becomes:

```javascript
{
    Items: {
        Item: ["First", "Second", "Third"]
    }
}
```

### _ParseWsmanRec(node) - Line 49

**Purpose:** Recursive helper for parsing XML node tree

**Behavior:**
- Recursively traverses XML child nodes
- Converts leaf nodes to text content
- Converts branch nodes to nested objects
- Handles attributes, arrays, type conversion

**Private Method:** Not exposed in module.exports

### _PutObjToBodyXml(resuri, putObj) - Line 73

**Purpose:** Convert JavaScript object to WSMAN SOAP XML body

**Parameters:**
- `resuri` (string) - Resource URI (determines XML namespace and root element)
- `putObj` (object) - JavaScript object to convert

**Output:** XML string for WSMAN SOAP Body

**Example:**

```javascript
var obj = {
    NetworkInterfaceEnabled: true,
    DDNSUpdateEnabled: false,
    IdleWakeTimeout: 65535
};

var xml = _PutObjToBodyXml(
    'http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings',
    obj
);

// Result:
// <r:AMT_GeneralSettings xmlns:r="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings">
//   <r:NetworkInterfaceEnabled>true</r:NetworkInterfaceEnabled>
//   <r:DDNSUpdateEnabled>false</r:DDNSUpdateEnabled>
//   <r:IdleWakeTimeout>65535</r:IdleWakeTimeout>
// </r:AMT_GeneralSettings>
```

**Special Handling:**

1. **Property Filtering (Lines 79-80):**
   - Skips properties starting with `__` (internal)
   - Skips properties starting with `@` (attributes)
   - Skips null values and functions

2. **Reference Parameters (Lines 81-93):**
   - Special handling for WS-Addressing reference objects
   - Includes Address and SelectorSet elements
   - Used for referencing other WSMAN objects

3. **Array Properties (Lines 95-98):**
   - Arrays converted to repeated XML elements
   - Each array item gets its own element with same name

### _turnToXml(text) - Line 118

**Purpose:** Parse XML string into DOM-like JavaScript object

**Input:** XML text string

**Output:** DOM-like object with:
- `childNodes` - Array of child elements
- `getElementsByTagName(name)` - Find elements by tag name
- `getElementsByTagNameNS(ns, name)` - Find elements by namespace and name
- `getChildElementsByTagName(name)` - Find direct children by tag name

**Implementation:** Custom lightweight XML parser (Lines 124-189)

**Why Custom Parser:**
- No dependency on platform-specific XML libraries
- Works in constrained JavaScript environments (Duktape)
- Sufficient for WSMAN SOAP structure
- Smaller and faster than full DOM parser

### _turnToXmlRec(text) - Line 124

**Purpose:** Recursive XML parsing implementation

**Features:**

1. **Namespace Support (Lines 166-171):**
   ```javascript
   if (attrName == 'xmlns') {
       elementStack.addNamespace('*', attrValue);  // Default namespace
   } else if (attrName.startsWith('xmlns:')) {
       elementStack.addNamespace(attrName.substring(6), attrValue);  // Prefixed namespace
   }
   ```

2. **Attribute Parsing (Lines 160-178):**
   - Extracts name="value" pairs
   - Handles namespaced attributes
   - Stores in attributes array

3. **Self-Closing Tags (Lines 152-159):**
   - Detects `<Element />` syntax
   - Sets empty textContent
   - Pops from stack immediately

4. **Text Content (Line 183):**
   - Extracts text between opening and closing tags
   - Stored in `textContent` property

### _treeBuilder() - Line 110

**Purpose:** Stack-based helper for building XML tree during parsing

**Methods:**
- `push(element)` - Add element to stack
- `pop()` - Remove element from stack and add to parent
- `peek()` - Look at top of stack without removing
- `addNamespace(prefix, namespace)` - Register namespace
- `getNamespace(prefix)` - Resolve namespace URI from prefix

**Why Stack-Based:**
- Tracks current position in nested XML structure
- Manages namespace scope (namespaces inherit from parents)
- Efficient for recursive descent parsing

### Array.prototype.peek() - Line 17

**Utility Extension:**

```javascript
Object.defineProperty(Array.prototype, "peek", {
    value: function () {
        return (this.length > 0 ? this[this.length - 1] : undefined);
    }
});
```

**Purpose:** Add `peek()` method to all arrays for getting last element without removing

**Usage:** `stack.peek()` instead of `stack[stack.length - 1]`

## Dependencies

### Node.js Core Module Dependencies

**None** - This module has zero dependencies. It's pure JavaScript with no require() statements.

### MeshAgent Module Dependencies

**None** - Completely standalone module

### Platform Binary Dependencies

**None** - No native code, no system libraries, no external tools

### Dependency Chain

```
amt-xml.js
└─── No dependencies (pure JavaScript)
```

**Upstream Modules (modules that use amt-xml.js):**
- **amt-wsman.js** - Uses ParseWsman() to parse SOAP responses
- **amt.js** - Indirectly uses through amt-wsman.js
- **amt-wsman-duk.js** - May use for parsing in Duktape environment

## Technical Notes

### WSMAN SOAP Structure

**Typical WSMAN Response:**

```xml
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse</wsa:Action>
    <wsa:MessageID>uuid:00000000-8086-8086-8086-000000000001</wsa:MessageID>
    <wsa:RelatesTo>uuid:12345</wsa:RelatesTo>
    <wsman:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings</wsman:ResourceURI>
  </s:Header>
  <s:Body>
    <r:AMT_GeneralSettings_OUTPUT xmlns:r="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings">
      <r:NetworkInterfaceEnabled>true</r:NetworkInterfaceEnabled>
      <r:DDNSUpdateEnabled>false</r:DDNSUpdateEnabled>
    </r:AMT_GeneralSettings_OUTPUT>
  </s:Body>
</s:Envelope>
```

**Parsed Result:**

```javascript
{
    Header: {
        Action: "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse",
        MessageID: "uuid:00000000-8086-8086-8086-000000000001",
        RelatesTo: "uuid:12345",
        ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings",
        Method: "AMT_GeneralSettings"  // Derived from body element name
    },
    Body: {
        NetworkInterfaceEnabled: true,
        DDNSUpdateEnabled: false
    }
}
```

### Method Name Extraction (Lines 35-38)

```javascript
t = body.childNodes[0].localName;           // e.g., "AMT_GeneralSettings_OUTPUT"
var x = t.indexOf('_OUTPUT');
if ((x != -1) && (x == (t.length - 7))) {
    t = t.substring(0, t.length - 7);       // Remove "_OUTPUT" suffix
}
r.Header['Method'] = t;                     // Result: "AMT_GeneralSettings"
```

**Purpose:** Extract method name for easier identification in calling code

### Namespace Handling

**WSMAN uses multiple namespaces:**
- `s:` or `soap:` - SOAP envelope namespace
- `wsa:` - WS-Addressing namespace
- `wsman:` - WS-Management namespace
- `r:` - Resource-specific namespace (varies by resource)

**Parser Behavior:**
- `localName` property contains tag name without prefix
- `namespace` property contains full namespace URI
- Namespace inheritance through element tree

### Error Handling

**ParseWsman (Lines 42-45):**

```javascript
try {
    // Parsing logic
} catch (e) {
    console.error("Unable to parse XML: " + xml, e);
    return null;
}
```

**Behavior:** Returns `null` on any parsing error, logs error to console

**_turnToXmlRec (Line 187):**

```javascript
try {
    // Parsing logic
} catch (ex) {
    return null;
}
```

**Behavior:** Returns `null` on parsing error, silent failure

### Performance Characteristics

**Parsing Speed:**
- String-based parsing (split on `<` and `>`)
- No regex for main parsing (faster)
- Linear time complexity O(n) for document size
- Suitable for WSMAN messages (typically < 100KB)

**Memory Usage:**
- Builds full DOM-like structure in memory
- Not suitable for huge XML documents (100MB+)
- Perfect for WSMAN messages (few KB to few hundred KB)

### Limitations

1. **No Validation** - Doesn't validate XML structure or check for malformed XML
2. **No Entity Resolution** - Doesn't handle `&lt;`, `&gt;`, `&amp;` entities
3. **No CDATA Support** - Doesn't handle `<![CDATA[...]]>` sections
4. **No Processing Instructions** - Ignores `<?xml ... ?>` declarations
5. **No Comments** - Doesn't preserve `<!-- ... -->` comments
6. **WSMAN-Focused** - Optimized for WSMAN SOAP, may not handle all XML

**Acceptable Because:** WSMAN messages don't typically use these features

### Alternative Implementations

**If Full XML Support Needed:**
- **Node.js:** `xml2js`, `fast-xml-parser` packages
- **Browser:** Native `DOMParser` API
- **Duktape:** Could integrate libxml2 via C binding

**This Module's Advantage:** Zero dependencies, small size, sufficient for WSMAN

## Summary

The amt-xml.js module is a lightweight, dependency-free XML parser and generator specifically designed for WSMAN SOAP messages used in Intel AMT communication. It provides bidirectional conversion between XML and JavaScript objects with support for namespaces, attributes, type conversion, and arrays.

**Placed in modules_macos_NEVER** because:
- Part of Intel AMT management stack (rarely relevant on macOS)
- Used exclusively for WSMAN protocol in AMT context
- AMT management typically performed from Windows/Linux servers
- Enterprise management tool not commonly deployed on macOS

**Technical capability:** The module is 100% portable JavaScript with zero dependencies and no platform-specific code. It would work identically on macOS, but the AMT management use case doesn't typically apply to macOS deployments.

The module represents a practical tradeoff: limited XML capabilities in exchange for zero dependencies and minimal code size, perfectly suited for the constrained use case of parsing WSMAN SOAP messages in embedded MeshAgent environments.
