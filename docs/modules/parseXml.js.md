# parseXml.js

A lightweight, dependency-free XML parser and DOM (Document Object Model) implementation designed as a drop-in replacement for traditional XML parsing libraries. This module provides XML parsing, namespace support, and DOM traversal functionality without requiring external XML parser dependencies.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support
- Linux - Full support
- FreeBSD - Full support
- **macOS (darwin)** - Full support

**Platform-Universal Design:**

This module is **fully cross-platform** with no platform-specific code. It works identically across all platforms including macOS because:

1. **Pure JavaScript Implementation** - All functionality implemented in pure JavaScript without native bindings (lines 1-216).

2. **No External Dependencies** - The module has no `require()` statements except for a single Array prototype extension (line 17), making it completely self-contained.

3. **String-Based Processing** - XML parsing is performed entirely through JavaScript string manipulation and regular expressions, which work identically across all platforms.

4. **No File System Access** - The module operates on in-memory strings, not files, avoiding platform-specific I/O differences.

5. **Universal XML Standard** - XML is a platform-independent standard; parsing rules are identical regardless of operating system.

## Functionality

### Purpose

The parseXml.js module provides XML parsing and DOM manipulation capabilities for MeshAgent without requiring heavyweight XML parser dependencies. It is specifically designed for:

- Parsing XML responses from Intel AMT (Active Management Technology) WSMAN (Web Services Management) interfaces
- Handling SOAP envelopes and XML-based management protocols
- Providing DOM-like query methods for XML document traversal
- Supporting XML namespaces for complex multi-namespace documents
- Enabling lightweight XML processing in resource-constrained environments

This module serves as the XML processing foundation for MeshAgent's hardware management and remote administration features.

### Key Components

#### Array.prototype.peek Extension - Line 17

**Purpose:** Adds a `peek()` method to all arrays for accessing the last element without removal.

**Implementation:**
```javascript
Object.defineProperty(Array.prototype, "peek", {
    value: function () {
        return (this.length > 0 ? this[this.length - 1] : undefined);
    }
});
```

**Usage:**
```javascript
var stack = [1, 2, 3];
stack.peek();  // Returns: 3 (without removing it)
stack.length;  // Still: 3
```

**Error Handling:** Returns `undefined` for empty arrays instead of throwing error.

**Platform Behavior:** Cross-platform JavaScript prototype extension.

---

#### _treeBuilder Class - Lines 21-76

**Purpose:** Stack-based data structure for building XML DOM tree during parsing.

**Properties:**
- `tree` (line 23) - Internal array storing element stack

**Methods:**

**push(element)** - Lines 25-28
- Adds new element to top of stack
- Used when opening tag encountered

**pop()** - Lines 29-37
- Removes top element from stack
- Automatically adds popped element to parent's childNodes (line 34)
- Returns the popped element
- Used when closing tag encountered

**peek()** - Lines 38-41
- Returns current top element without removing
- Used to access current context during parsing

**addNamespace(prefix, namespace)** - Lines 42-64
- Registers namespace declaration for current element
- Parameters:
  - `prefix` - Namespace prefix (or '*' for default namespace)
  - `namespace` - Namespace URI
- Updates namespace table for current element (line 44)
- Retroactively applies namespace to attributes (lines 45-62)
- Special handling for default namespace (`prefix == '*'`) vs. prefixed namespaces

**getNamespace(prefix)** - Lines 65-75
- Retrieves namespace URI for given prefix
- Searches up element stack to find inherited namespaces (lines 67-73)
- Returns 'undefined' (as string) if prefix not found
- Implements namespace inheritance from parent elements

**Design Pattern:** Stack-based builder pattern with automatic parent-child relationship management.

---

#### _turnToXml(text) - Lines 79-84

**Purpose:** Main entry point for XML parsing.

**Signature:**
```javascript
function _turnToXml(text)
```

**Parameters:**
- `text` - String containing XML document

**Returns:**
- Object with:
  - `childNodes` - Array containing root element(s)
  - `getElementsByTagName` - Query method for finding elements by tag name
  - `getChildElementsByTagName` - Query method for direct children only
  - `getElementsByTagNameNS` - Query method with namespace awareness

**Process:**
- Returns null for null input (line 82)
- Creates wrapper object with parsed root element (line 83)
- Attaches query methods to returned object

**Usage Example:**
```javascript
var doc = require('parseXml')('<root><child>text</child></root>');
var children = doc.getElementsByTagName('child');
console.log(children[0].textContent);  // Outputs: "text"
```

**Platform Behavior:** Cross-platform.

---

#### DOM Query Methods

**getElementsByTagNameNS(ns, name)** - Lines 86-92

**Purpose:** Finds all elements with specified local name and namespace URI.

**Parameters:**
- `ns` - Namespace URI (or '*' for any namespace)
- `name` - Local element name

**Process:**
- Recursively traverses all child nodes using `_xmlTraverseAllRec()` (line 88)
- Matches elements where `localName` equals `name` (line 90)
- Matches namespace exactly or accepts wildcard '*' (line 90)
- Returns array of matching elements

**Usage Example:**
```javascript
var elements = doc.getElementsByTagNameNS('http://www.w3.org/2001/XMLSchema', 'element');
```

---

**getElementsByTagName(name)** - Lines 93-99

**Purpose:** Finds all elements with specified local name (namespace-agnostic).

**Parameters:**
- `name` - Local element name

**Process:**
- Recursively traverses entire document tree (line 95)
- Matches only on `localName` property (line 97)
- Ignores namespaces
- Returns array of matching elements

**Usage Example:**
```javascript
var allChildren = doc.getElementsByTagName('child');
```

---

**getChildElementsByTagName(name)** - Lines 100-110

**Purpose:** Finds direct child elements with specified name (non-recursive).

**Parameters:**
- `name` - Local element name

**Process:**
- Iterates only immediate childNodes (line 105)
- No recursive traversal
- Checks localName match (line 106)
- Returns array of matching direct children

**Usage Example:**
```javascript
var rootElement = doc.childNodes[0];
var directChildren = rootElement.getChildElementsByTagName('item');
```

---

**getChildElementsByTagNameNS(ns, name)** - Lines 111-122

**Purpose:** Finds direct child elements with specified name and namespace (non-recursive).

**Parameters:**
- `ns` - Namespace URI (or '*' for any)
- `name` - Local element name

**Process:**
- Iterates only immediate childNodes (line 116)
- Matches both localName and namespace (line 118)
- Supports wildcard namespace matching (line 118)
- Returns array of matching children

---

#### _xmlTraverseAllRec(nodes, func) - Line 124

**Purpose:** Recursive helper for traversing entire XML tree.

**Parameters:**
- `nodes` - Array of nodes to traverse
- `func` - Callback function to invoke for each node

**Process:**
- Iterates through provided nodes (line 124)
- Invokes callback for current node
- Recursively processes child nodes if present

**Implementation:** Single-line compact recursive traversal using conditional recursion.

---

#### _turnToXmlRec(text) - Lines 125-214

**Purpose:** Core recursive XML parsing implementation.

**Signature:**
```javascript
function _turnToXmlRec(text)
```

**Parameters:**
- `text` - XML string to parse

**Returns:**
- Element node object with properties:
  - `name` - Full qualified name (prefix:localName)
  - `localName` - Local element name without prefix
  - `namespace` - Namespace URI
  - `attributes` - Array of attribute objects
  - `childNodes` - Array of child elements
  - `textContent` - Text content of element
  - `nsTable` - Namespace prefix mapping table
  - Query methods (getElementsByTagName, etc.)

**Parsing Algorithm:**

**1. Initialization** (lines 127-130):
```javascript
var elementStack = new _treeBuilder();
var lastElement = null;
var x1 = text.split('<');
```

**2. Element Processing Loop** (lines 131-212):
- Split on '<' to separate tags from content (line 130)
- For each segment:

**3. Tag Parsing** (line 133):
```javascript
var x2 = x1[i].split('>');           // Separate tag from content after '>'
var x3 = x2[0].split(' ');           // Split tag into name and attributes
var elementName = x3[0];             // First token is element name
```

**4. Opening Tag Processing** (lines 136-206):
- Skip XML declarations starting with '?' (line 134)
- Determine if opening or closing tag (line 136)
- Extract local name from qualified name (lines 138-139):
  ```javascript
  var localname2 = elementName.split(':');
  var localName = (localname2.length > 1) ? localname2[1] : localname2[0];
  ```

**5. Attribute Array Setup** (lines 140-158):
- Creates attributes array with custom `get()` method
- `get(name)` - Retrieve by attribute name only (lines 145-148)
- `get(namespace, name)` - Retrieve by namespace and name (lines 149-152)
- Wildcard namespace support with '*' (line 151)

**6. Element Creation** (line 161):
```javascript
elementStack.push({
    name: elementName,
    localName: localName,
    attributes: attributes,
    childNodes: [],
    nsTable: {},
    // Query methods attached
});
```

**7. Attribute Parsing** (lines 164-203):
- Skip if no attributes (x3.length <= 1)
- Loop through attribute tokens (line 167)

**Empty Element Detection** (lines 169-177):
```javascript
if (x3[j] == '/') {
    // Self-closing tag like <element/>
    elementStack.peek().namespace = /* resolve namespace */;
    elementStack.peek().textContent = '';
    lastElement = elementStack.pop();
    skip = true;
    break;
}
```

**Attribute Value Extraction** (lines 178-182):
```javascript
var k = x3[j].indexOf('=');
var attrName = x3[j].substring(0, k);               // "name" or "prefix:name"
var attrValue = x3[j].substring(k + 2, length - 1); // Remove =" and trailing "
```

**Namespace Declaration Handling** (lines 185-193):
```javascript
if (attrName == 'xmlns') {
    // Default namespace: xmlns="http://..."
    elementStack.addNamespace('*', attrValue);
}
else if (attrName.startsWith('xmlns:')) {
    // Prefixed namespace: xmlns:prefix="http://..."
    elementStack.addNamespace(attrName.substring(6), attrValue);
}
```

**Regular Attribute Processing** (lines 194-200):
```javascript
var ax = attrName.split(':');
if (ax.length == 2) {
    attrName = ax[1];                      // Use local name
    attrNS = elementStack.getNamespace(ax[0]); // Resolve prefix
}
elementStack.peek().attributes.push({
    name: attrName,
    value: attrValue,
    namespace: attrNS
});
```

**8. Namespace Resolution** (line 204):
```javascript
elementStack.peek().namespace =
    elementStack.peek().name == elementStack.peek().localName
        ? elementStack.getNamespace('*')         // No prefix = default namespace
        : elementStack.getNamespace(prefix);     // Extract and resolve prefix
```

**9. Text Content Assignment** (line 205):
```javascript
if (x2[1]) { elementStack.peek().textContent = x2[1]; }
```

**10. Closing Tag Processing** (lines 207-210):
```javascript
else {
    lastElement = elementStack.pop();  // Pop completed element
}
```

**11. Return** (line 213):
```javascript
return lastElement;  // Root element
```

**Error Handling:** Minimal; malformed XML may produce incorrect structures rather than throwing exceptions.

**Platform Behavior:** Cross-platform string parsing.

---

### Usage

#### Basic XML Parsing

```javascript
var parseXml = require('parseXml');

var xmlString = `
<root xmlns="http://example.com/ns">
    <person id="1">
        <name>John Doe</name>
        <age>30</age>
    </person>
    <person id="2">
        <name>Jane Smith</name>
        <age>25</age>
    </person>
</root>`;

var doc = parseXml(xmlString);

// Access root element
var root = doc.childNodes[0];
console.log(root.localName);        // Outputs: "root"
console.log(root.namespace);        // Outputs: "http://example.com/ns"

// Find all person elements
var people = doc.getElementsByTagName('person');
console.log(people.length);         // Outputs: 2

// Access attributes
console.log(people[0].attributes.get('id').value);  // Outputs: "1"

// Access child elements
var names = doc.getElementsByTagName('name');
console.log(names[0].textContent);  // Outputs: "John Doe"
```

#### Namespace-Aware Parsing

```javascript
var soapXml = `
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
    <soap:Header>
        <wsman:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings</wsman:ResourceURI>
    </soap:Header>
    <soap:Body>
        <wsman:Response>
            <NetworkName>Corporate Network</NetworkName>
        </wsman:Response>
    </soap:Body>
</soap:Envelope>`;

var doc = parseXml(soapXml);

// Query with namespace awareness
var headers = doc.getElementsByTagNameNS('http://www.w3.org/2003/05/soap-envelope', 'Header');
var resourceURI = doc.getElementsByTagNameNS('http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd', 'ResourceURI');

console.log(resourceURI[0].textContent);  // Outputs: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings"

// Wildcard namespace matching
var allResponses = doc.getElementsByTagNameNS('*', 'Response');
```

#### Attribute Access with Namespaces

```javascript
var xmlWithNsAttrs = `
<config xmlns:custom="http://example.com/custom">
    <setting custom:type="string" name="hostname">server1</setting>
</config>`;

var doc = parseXml(xmlWithNsAttrs);
var setting = doc.getElementsByTagName('setting')[0];

// Access attribute by name only
var nameAttr = setting.attributes.get('name');
console.log(nameAttr.value);  // Outputs: "hostname"

// Access attribute by namespace and name
var typeAttr = setting.attributes.get('http://example.com/custom', 'type');
console.log(typeAttr.value);  // Outputs: "string"
```

#### Intel AMT WSMAN Response Parsing

```javascript
// Typical use case in MeshAgent for AMT management
var amtResponse = `
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
    <s:Body>
        <amt:AMT_GeneralSettings xmlns:amt="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings">
            <amt:ElementName>Intel(r) AMT: General Settings</amt:ElementName>
            <amt:NetworkInterfaceEnabled>true</amt:NetworkInterfaceEnabled>
            <amt:DHCPEnabled>true</amt:DHCPEnabled>
        </amt:AMT_GeneralSettings>
    </s:Body>
</s:Envelope>`;

var doc = parseXml(amtResponse);

// Extract AMT settings
var body = doc.getElementsByTagNameNS('http://www.w3.org/2003/05/soap-envelope', 'Body')[0];
var settings = body.childNodes[0];  // First child of Body

var dhcpEnabled = settings.getChildElementsByTagName('DHCPEnabled')[0];
console.log(dhcpEnabled.textContent);  // Outputs: "true"
```

### Dependencies

#### Module Dependencies

**None** - This module has no `require()` statements for external modules.

**Array Prototype Extension** (line 17):
- Modifies global `Array.prototype` to add `peek()` method
- Uses `Object.defineProperty()` with try-catch for environments where prototype modification is restricted
- Non-enumerable property to avoid interference with for-in loops

#### System Dependencies

**None** - No platform-specific APIs, file system access, or native bindings.

#### Runtime Requirements

**JavaScript Engine:**
- ES5+ features required:
  - `Object.defineProperty()` (line 17, 141)
  - Array methods (split, join, push, pop, indexOf, etc.)
  - String methods (split, substring, startsWith, endsWith, toLowerCase, trim)
  - Regular string operations

**Memory:**
- Loads entire XML document into memory as string
- Builds complete DOM tree in memory
- Not suitable for extremely large XML documents (multi-megabyte)
- No streaming or SAX-style parsing

### Code Structure

The module is organized in distinct functional sections:

1. **Lines 1-16:** Copyright header and licensing (Apache 2.0)
2. **Line 17:** Array.prototype.peek extension
3. **Lines 21-76:** _treeBuilder class (stack-based tree builder)
4. **Lines 79-84:** _turnToXml() main entry point
5. **Lines 86-92:** getElementsByTagNameNS() namespace-aware query
6. **Lines 93-99:** getElementsByTagName() simple query
7. **Lines 100-110:** getChildElementsByTagName() direct children query
8. **Lines 111-122:** getChildElementsByTagNameNS() direct children with namespace query
9. **Line 124:** _xmlTraverseAllRec() recursive traversal helper
10. **Lines 125-214:** _turnToXmlRec() core parsing implementation

**Module Export** (line 216):
```javascript
module.exports = _turnToXml;
```

**Design Patterns:**

- **Builder Pattern:** _treeBuilder constructs DOM tree incrementally
- **Recursive Descent:** _turnToXmlRec recursively processes nested elements
- **Visitor Pattern:** _xmlTraverseAllRec accepts callback for node processing
- **Fluent Interface:** Query methods return arrays for further processing

### Technical Notes

**Parsing Strategy:**

This is a **simple string-splitting parser**, not a formal XML parser:

1. Splits on '<' to find tags (line 130)
2. Splits on '>' to separate tag from content (line 133)
3. Splits on ' ' to separate element name from attributes (line 133)
4. Extracts attributes by finding '=' characters (line 178)

**Limitations of String-Splitting Approach:**

1. **No CDATA Support** - `<![CDATA[...]]>` sections not handled; may parse incorrectly
2. **No Entity References** - `&lt;`, `&gt;`, `&amp;`, `&quot;`, `&apos;` not decoded
3. **No DTD Support** - Document Type Definitions ignored
4. **No Processing Instructions** - `<?xml-stylesheet ...?>` skipped (line 134 skips '?')
5. **No Comments** - `<!-- ... -->` may cause parsing errors
6. **Fragile Whitespace Handling** - Assumes attributes separated by single spaces
7. **No XML Declaration Parsing** - `<?xml version="1.0"?>` attributes not extracted
8. **Attribute Quoting Assumptions** - Assumes double quotes, not single quotes or unquoted

**Advantages:**

- **No External Dependencies** - Works without libxml2, expat, or other parsers
- **Small Code Size** - ~200 lines vs. thousands for full XML parsers
- **Fast for Simple XML** - String splitting is fast for well-formed, simple documents
- **Embedded-Friendly** - Suitable for resource-constrained environments

**Security Considerations:**

**No XML External Entity (XXE) Vulnerability** - Since external entities aren't supported, XXE attacks are prevented by design.

**No Billion Laughs Attack Protection** - Deeply nested entities could still cause memory exhaustion, but entities aren't expanded so risk is minimal.

**Input Validation** - No validation that XML is well-formed; malformed input may produce incorrect output rather than errors.

**Namespace Handling:**

- **Inheritance:** Child elements inherit parent namespaces (lines 67-73)
- **Default Namespace:** `xmlns="..."` sets namespace for unprefixed elements (line 186)
- **Prefixed Namespace:** `xmlns:prefix="..."` sets namespace for prefixed elements (line 190)
- **Attribute Namespaces:** Attributes without prefixes belong to element's namespace (line 183)

**Performance Characteristics:**

- **Time Complexity:** O(n) where n is number of characters in XML string
- **Space Complexity:** O(m) where m is number of elements (entire tree stored in memory)
- **Query Performance:**
  - `getElementsByTagName()` - O(m) traverses entire tree
  - `getChildElementsByTagName()` - O(k) where k is number of direct children

**Text Content Handling:**

- **textContent Property** - Contains text between opening and closing tags (line 205)
- **No Mixed Content Support** - Text mixed with elements may be lost
- **Example:**
  ```xml
  <p>This is <b>bold</b> text</p>
  ```
  The "This is " and " text" portions may not be properly preserved.

**Attribute Value Parsing:**

The attribute value extraction (line 182) assumes format: `name="value"` with double quotes. This means:

```javascript
var attrValue = x3[j].substring(k + 2, x3[j].length - 1);
//                               ^^^^ Skips '="'
//                                            ^^^ Removes trailing '"'
```

This breaks for:
- Single quotes: `name='value'`
- Unquoted: `name=value`
- Spaces in values: `name="multi word value"` (would be split incorrectly)

**Actual Behavior for Spaced Attributes:**

Multi-word attribute values would fail because the initial split on ' ' (line 133) would separate them incorrectly:
```xml
<tag attr="value with spaces"/>
```
Would be split into: `["tag", 'attr="value', "with", "spaces"/>"]`

This is a **significant limitation** for real-world XML.

### Platform-Specific Analysis

**What Works on All Platforms (Including macOS):**

**Everything** - All functionality is platform-universal:

1. **XML Parsing** - String manipulation works identically across all platforms
2. **Namespace Handling** - Pure JavaScript logic, no platform dependencies
3. **DOM Traversal** - Query methods use standard JavaScript array operations
4. **Attribute Access** - Custom attribute array methods work universally
5. **Memory Management** - JavaScript garbage collection handles cleanup on all platforms

**Platform Differences:**

**None at module level** - Since this is pure JavaScript with no system calls:

- No file system access
- No network operations
- No native library dependencies
- No process spawning
- No platform-specific APIs

**Potential Differences in Calling Context:**

While the module itself is platform-agnostic, how it's **used** may vary:

1. **XML Source:**
   - Windows: May parse XML from Windows APIs (WMI, COM objects)
   - Linux: May parse XML from system tools (udev, systemd)
   - macOS: May parse XML from plists or system_profiler output

2. **Character Encoding:**
   - JavaScript strings are UTF-16 internally on all platforms
   - If XML is loaded from files, encoding detection is platform-specific
   - Module assumes string input is already properly decoded

3. **Memory Limits:**
   - Different platforms may have different JavaScript heap size limits
   - Very large XML documents may hit memory limits differently

**Intel AMT Usage (Primary Use Case):**

This module is primarily used for parsing Intel AMT WSMAN responses. AMT support is:
- **Windows/Linux:** Available on Intel-based systems with AMT-enabled chipsets
- **macOS:** **Not available** - Mac hardware doesn't support Intel AMT

However, the **module itself** works fine on macOS; it just won't be used for AMT purposes. It could still be used for:
- Parsing configuration files
- Processing other XML-based protocols
- General-purpose XML handling

**Testing Considerations:**

Since parsing is purely algorithmic, test results should be **byte-identical** across platforms:
- Same input XML produces same output DOM structure
- Same queries return same results
- Same attribute values extracted

Any platform differences would indicate bugs in the JavaScript engine itself, not this module.

## Summary

The parseXml.js module provides a **lightweight, platform-universal XML parser** implemented in pure JavaScript without external dependencies. It works identically on **Windows, Linux, FreeBSD, and macOS** as it contains no platform-specific code.

**Key Characteristics:**

- **Pure JavaScript** - No native bindings or platform APIs
- **Self-Contained** - No module dependencies (except Array.prototype extension)
- **Namespace-Aware** - Full support for XML namespaces and prefix resolution
- **DOM-Like Interface** - Provides familiar query methods (getElementsByTagName, etc.)
- **Simple Parser** - String-splitting approach rather than formal XML grammar
- **Lightweight** - ~200 lines of code suitable for embedded environments

**Strengths:**

- Cross-platform compatibility
- No external parser library dependencies (libxml2, expat, etc.)
- Fast for well-formed, simple XML documents
- Namespace support for complex multi-namespace documents
- Attribute namespace resolution
- Immune to XXE (XML External Entity) attacks by design

**Limitations:**

- No CDATA section support
- No entity reference decoding (&lt;, &gt;, etc.)
- No DTD or schema validation
- No comment preservation
- Fragile attribute parsing (breaks with spaces in values)
- No mixed content support
- Assumes double-quoted attributes
- Entire document loaded into memory (not streaming)

**Primary Use Cases:**

- Parsing Intel AMT WSMAN SOAP responses (despite AMT not being available on macOS hardware, the parser works fine)
- Processing configuration files in XML format
- Handling simple XML-based protocols
- Lightweight XML processing in embedded MeshAgent environments

**macOS Support:** **Fully supported** with identical functionality to all other platforms. No limitations or platform-specific concerns. While Intel AMT (the primary use case) is not available on macOS hardware, the XML parser itself works perfectly and can be used for any XML parsing needs.
