# pac.js

A lightweight Proxy Auto-Configuration (PAC) file parser and evaluator that implements standard PAC helper functions for determining proxy settings based on URLs and hostnames. This module provides the runtime environment for executing PAC scripts that control web proxy routing decisions.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support
- Linux - Full support
- FreeBSD - Full support
- **macOS (darwin)** - Full support

**Platform-Universal Design:**

This module is **fully cross-platform** with no platform-specific code. It works identically across all platforms including macOS because:

1. **Pure JavaScript Implementation** - All functionality is implemented in pure JavaScript without any native bindings or platform-specific APIs (lines 1-111).

2. **No External Dependencies** - The module has no `require()` statements and depends only on JavaScript string manipulation and array methods, making it completely self-contained.

3. **Standard PAC Functions** - Implements the de facto standard set of PAC helper functions defined by Netscape's original PAC specification, which are platform-agnostic by design.

4. **Network Protocol Agnostic** - PAC files evaluate at the application layer (HTTP/HTTPS), not requiring platform-specific networking APIs.

5. **DNS Resolution Abstraction** - While DNS resolution is platform-specific, this module expects a `resolve()` function to be provided by the calling context, abstracting away platform differences.

## Functionality

### Purpose

The pac.js module provides a JavaScript runtime environment for evaluating Proxy Auto-Configuration (PAC) files. PAC files are used by web browsers and HTTP clients to automatically determine the appropriate proxy server for a given URL based on hostname, domain, IP address, and other factors.

This module serves as:
- A PAC function library for MeshAgent's proxy detection system
- A runtime environment for executing PAC scripts downloaded from network configurations
- A helper for implementing automatic proxy configuration (WPAD/Web Proxy Auto-Discovery Protocol)
- A compatibility layer ensuring PAC files work consistently across platforms

### Key Functions

#### dnsDomainIs() - Lines 21-28

**Purpose:** Evaluates whether a target hostname matches or belongs to a specified domain.

**Signature:**
```javascript
function dnsDomainIs(target, host)
```

**Process:**
- Normalizes host parameter by prepending '.' if not already present (lines 23-26)
- Performs case-insensitive comparison using `endsWith()` (line 27)
- Returns true if target hostname ends with the domain string

**Usage Examples:**
```javascript
dnsDomainIs("www.example.com", "example.com")     // Returns: true
dnsDomainIs("www.example.com", ".example.com")    // Returns: true
dnsDomainIs("www.example.com", "www.example.com") // Returns: true
dnsDomainIs("example.com", "www.example.com")     // Returns: false
```

**Platform Behavior:** Cross-platform, no platform-specific logic.

---

#### shExpMatch() - Lines 30-38

**Purpose:** Matches a hostname or URL against a shell-style wildcard expression.

**Signature:**
```javascript
function shExpMatch(host, exp)
```

**Process:**
- Converts shell wildcard pattern to regular expression (lines 33-36):
  - Escapes literal dots: `.` → `\.`
  - Converts single-char wildcards: `?` → `.`
  - Converts multi-char wildcards: `*` → `.*`
- Anchors pattern with `^` and `$` for full-string matching (line 36)
- Uses regex search to test match (line 37)

**Usage Examples:**
```javascript
shExpMatch("www.example.com", "*.example.com")      // Returns: true
shExpMatch("www.example.com", "www.*.com")          // Returns: true
shExpMatch("www.example.com", "???.example.com")    // Returns: true
shExpMatch("www.example.com", "*.example.org")      // Returns: false
```

**Platform Behavior:** Cross-platform, uses JavaScript regex engine.

---

#### isInNet() - Lines 40-53

**Purpose:** Evaluates whether a target hostname resolves to an IP address within a specified subnet.

**Signature:**
```javascript
function isInNet(target, address, mask)
```

**Process:**
- Resolves target hostname to IP address using external `resolve()` function (line 45)
- Resolves subnet mask to integer representation (line 46)
- Performs bitwise AND operation to check subnet membership (line 47)
- Compares result against provided network address (line 47)
- Returns false on any error (lines 49-52)

**Usage Examples:**
```javascript
isInNet("proxy.example.com", "192.168.1.0", "255.255.255.0")  // Returns: true if proxy.example.com is 192.168.1.x
isInNet("10.0.0.50", "10.0.0.0", "255.255.0.0")               // Returns: true
isInNet("8.8.8.8", "192.168.0.0", "255.255.255.0")            // Returns: false
```

**Dependencies:** Requires external `resolve()` and `_ipv4From()` functions to be defined in calling context.

**Platform Behavior:** Cross-platform, but DNS resolution behavior depends on system resolver.

---

#### dnsResolve() - Lines 55-67

**Purpose:** Resolves a hostname to its IP address.

**Signature:**
```javascript
function dnsResolve(host)
```

**Process:**
- Calls external `resolve()` function to perform DNS lookup (line 58)
- Returns empty string if no results (lines 59-62)
- Returns first resolved address (lines 63-66)

**Usage Examples:**
```javascript
dnsResolve("www.google.com")    // Returns: "142.250.185.46" (example)
dnsResolve("localhost")          // Returns: "127.0.0.1"
dnsResolve("nonexistent.local")  // Returns: ""
```

**Dependencies:** Requires external `resolve()` function.

**Platform Behavior:** Cross-platform, DNS results vary by system configuration.

---

#### isPlainHostName() - Lines 69-73

**Purpose:** Determines if a hostname is a plain hostname (no domain components).

**Signature:**
```javascript
function isPlainHostName(host)
```

**Process:**
- Searches for presence of '.' character (line 72)
- Returns true if no dots found, false otherwise

**Usage Examples:**
```javascript
isPlainHostName("localhost")           // Returns: true
isPlainHostName("myserver")            // Returns: true
isPlainHostName("www.example.com")     // Returns: false
```

**Platform Behavior:** Cross-platform, simple string operation.

---

#### localHostOrDomainIs() - Lines 75-79

**Purpose:** Evaluates whether a target hostname exactly matches a specified host after DNS resolution.

**Signature:**
```javascript
function localHostOrDomainIs(target, host)
```

**Process:**
- Resolves target hostname to IP address (line 78)
- Performs exact string comparison with provided host
- Returns true only on exact match

**Usage Examples:**
```javascript
localHostOrDomainIs("www.example.com", "192.168.1.1")  // Returns: true if www.example.com resolves to 192.168.1.1
```

**Dependencies:** Requires `dnsResolve()` function (line 78).

**Platform Behavior:** Cross-platform.

---

#### isResolvable() - Lines 81-85

**Purpose:** Tests whether a hostname can be successfully resolved via DNS.

**Signature:**
```javascript
function isResolvable(host)
```

**Process:**
- Attempts DNS resolution using `resolve()` function (line 84)
- Returns true if any addresses are returned (length > 0)
- Returns false if resolution fails or returns empty array

**Usage Examples:**
```javascript
isResolvable("www.google.com")    // Returns: true
isResolvable("localhost")          // Returns: true
isResolvable("invalid.local")      // Returns: false
```

**Dependencies:** Requires external `resolve()` function.

**Platform Behavior:** Cross-platform, depends on DNS configuration.

---

#### dnsDomainLevels() - Lines 87-91

**Purpose:** Returns the number of DNS domain levels (dots) in a hostname.

**Signature:**
```javascript
function dnsDomainLevels(host)
```

**Process:**
- Splits hostname on '.' delimiter (line 90)
- Returns array length minus 1 (number of separators)

**Usage Examples:**
```javascript
dnsDomainLevels("www.example.com")     // Returns: 2
dnsDomainLevels("example.com")         // Returns: 1
dnsDomainLevels("localhost")           // Returns: 0
dnsDomainLevels("sub.domain.example.com") // Returns: 3
```

**Platform Behavior:** Cross-platform, simple string operation.

---

#### Stub Functions - Lines 94-110

**Purpose:** Placeholder implementations for time/date-based PAC functions.

**Functions:**
- `weekdayRange(start, end)` - Lines 94-97
- `dateRange(start, end)` - Lines 98-101
- `timeRange(start, end)` - Lines 102-105
- `alert(msg)` - Lines 107-110

**Implementation Status:** All are currently empty stubs with no functionality.

**Intended Purpose (from PAC specification):**
- `weekdayRange()` - Should return true if current day falls within specified weekday range
- `dateRange()` - Should return true if current date falls within specified date range
- `timeRange()` - Should return true if current time falls within specified time range
- `alert()` - Should display debugging message (typically logged rather than shown to user)

**Platform Behavior:** Cross-platform stubs.

---

### Usage

#### Typical PAC File Evaluation Context

```javascript
var pac = require('pac');

// PAC files typically export a FindProxyForURL function
function FindProxyForURL(url, host) {
    // Example PAC logic using helper functions

    // Direct connection for plain hostnames
    if (isPlainHostName(host)) {
        return "DIRECT";
    }

    // Direct connection for local networks
    if (isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "10.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }

    // Use corporate proxy for internal domains
    if (dnsDomainIs(host, ".company.com") ||
        dnsDomainIs(host, ".corp.local")) {
        return "PROXY proxy.company.com:8080";
    }

    // Wildcard matching for specific patterns
    if (shExpMatch(host, "*.example.com") ||
        shExpMatch(url, "http://www.*.com/*")) {
        return "PROXY web-proxy.example.com:3128";
    }

    // Default to direct connection
    return "DIRECT";
}
```

#### Integration with MeshAgent

The pac.js module is typically used by MeshAgent's proxy configuration system:

```javascript
// Load PAC file content
var pacContent = downloadPACFile("http://wpad.company.com/wpad.dat");

// Evaluate PAC file in context with helper functions
var proxyResult = evaluatePAC(pacContent, targetURL, targetHost);

// Parse result (format: "PROXY host:port" or "DIRECT")
var proxyConfig = parseProxyResult(proxyResult);
```

### Dependencies

#### External Function Requirements

The pac.js module **expects** the following functions to be defined in the calling context:

**resolve(hostname)** - DNS resolution function
- **Purpose:** Resolves hostname to array of IP addresses
- **Expected Return:** Array-like object with:
  - `_integers` property containing integer representations of IPs
  - `length` property for checking if resolution succeeded
  - Array elements as string representations (e.g., `["192.168.1.1"]`)
- **Used By:** `isInNet()`, `dnsResolve()`, `isResolvable()`
- **Platform Implementation:** Typically provided by calling module using platform-specific DNS APIs

**_ipv4From(integer)** - IPv4 address formatting function
- **Purpose:** Converts integer representation back to dotted-decimal notation
- **Expected Return:** String in format "xxx.xxx.xxx.xxx"
- **Used By:** `isInNet()`
- **Platform Implementation:** Typically simple bit manipulation and formatting

#### Module Dependencies

**None** - This module has no `require()` statements and is completely self-contained.

#### System Dependencies

**None** - No platform-specific system calls, binaries, or libraries required.

### Code Structure

The module is organized as a collection of standalone helper functions:

1. **Lines 1-16:** Copyright header and licensing information (Apache 2.0)
2. **Lines 20-28:** Domain matching function (`dnsDomainIs`)
3. **Lines 30-38:** Shell expression matching function (`shExpMatch`)
4. **Lines 40-53:** Subnet matching function (`isInNet`)
5. **Lines 55-67:** DNS resolution function (`dnsResolve`)
6. **Lines 69-73:** Plain hostname detection (`isPlainHostName`)
7. **Lines 75-79:** Exact hostname matching (`localHostOrDomainIs`)
8. **Lines 81-85:** DNS resolvability test (`isResolvable`)
9. **Lines 87-91:** Domain level counting (`dnsDomainLevels`)
10. **Lines 94-110:** Stub implementations for time/date functions

**Design Pattern:** Collection of independent utility functions without object-oriented structure. Functions are defined in global scope for use by PAC scripts.

### Technical Notes

**PAC Specification Compliance:**

This module implements a subset of the original Netscape PAC specification from 1996, which became the de facto standard for proxy auto-configuration. The specification defines these exact function names and behaviors for compatibility across all PAC-aware applications.

**Reference:** Original Netscape documentation "Navigator Proxy Auto-Config File Format" defined these functions.

**Missing/Incomplete Functionality:**

1. **Time-Based Functions Not Implemented** - `weekdayRange()`, `dateRange()`, and `timeRange()` are stubs. These would require:
   - Current system time/date retrieval
   - Timezone handling
   - Date range parsing and comparison
   - Not commonly used in most PAC files

2. **Alert Function Stub** - `alert()` is typically used for debugging PAC files. In browser contexts, this would log to console. In MeshAgent context, it could log to agent logs.

3. **Missing Extended Functions** - Some PAC implementations include additional functions not present here:
   - `myIpAddress()` - Returns client's local IP address
   - `myIpAddressEx()` - Returns multiple IPs for multi-homed systems
   - `dnsResolveEx()` - Returns all resolved IPs, not just first
   - `isInNetEx()` - IPv6-aware subnet matching

**Error Handling:**

- **isInNet()** - Uses try-catch to handle resolution failures gracefully (lines 43-52)
- **Other Functions** - Most functions don't explicitly handle errors, relying on JavaScript's loose typing and error propagation

**Performance Considerations:**

- DNS resolution functions (`dnsResolve`, `isInNet`, `isResolvable`) can be slow due to network lookups
- PAC files should minimize DNS resolution calls
- Many PAC implementations cache DNS results to avoid repeated lookups
- String operations (`dnsDomainIs`, `shExpMatch`) are fast and suitable for frequent calls

**Case Sensitivity:**

- **dnsDomainIs()** - Case-insensitive (line 27: `toLowerCase()`)
- **shExpMatch()** - Case-sensitive (no case conversion)
- **Other functions** - Generally case-sensitive unless DNS resolution normalizes

**Regular Expression Security:**

The `shExpMatch()` function converts shell wildcards to regex. While generally safe, extremely complex patterns could cause catastrophic backtracking in regex engine. Production systems may want to add pattern complexity limits.

### Platform-Specific Analysis

**What Works on All Platforms (Including macOS):**

**Everything** - All functions in this module work identically across platforms:

1. **String Manipulation Functions** - `dnsDomainIs()`, `isPlainHostName()`, `dnsDomainLevels()`
   - Pure JavaScript string operations
   - No platform dependencies

2. **Pattern Matching** - `shExpMatch()`
   - JavaScript regex engine
   - Consistent across all platforms

3. **DNS-Dependent Functions** - `isInNet()`, `dnsResolve()`, `isResolvable()`, `localHostOrDomainIs()`
   - Behavior consistent across platforms
   - Results may vary based on network/DNS configuration, not OS
   - Calling code provides platform-specific `resolve()` implementation

4. **Stub Functions** - `weekdayRange()`, `dateRange()`, `timeRange()`, `alert()`
   - Empty implementations work (do nothing) on all platforms

**Platform Differences in Practice:**

While the pac.js module itself is platform-universal, the **calling context** may have platform-specific behavior:

**DNS Resolution:**
- **Windows:** Uses Windows DNS resolver (respects system DNS settings, WINS, etc.)
- **Linux/FreeBSD:** Uses libc resolver (respects /etc/resolv.conf, /etc/hosts, nsswitch.conf)
- **macOS:** Uses mDNSResponder (respects system DNS, Bonjour, /etc/hosts)

**Network Configuration:**
- Different platforms may have different methods for obtaining PAC file URLs (DHCP option 252, DNS SRV records, WPAD well-known URLs)
- Registry (Windows) vs. config files (Unix-like) for storing proxy settings

**Character Encoding:**
- JavaScript string handling is UTF-16 internally
- All platforms handle Unicode hostnames consistently
- International Domain Names (IDN) should be punycode-encoded before passing to PAC functions

**IPv6 Considerations:**

This implementation is **IPv4-centric**:
- `isInNet()` uses `_integers[0]` assuming single 32-bit integer (line 45-46)
- IPv6 addresses would require different bitwise operations (128-bit)
- No IPv6-specific functions implemented

Modern PAC implementations often add IPv6-aware functions, but they're not in the original spec.

## Summary

The pac.js module provides a lightweight, **fully cross-platform** implementation of Proxy Auto-Configuration helper functions. It works identically on **Windows, Linux, FreeBSD, and macOS** because it's written in pure JavaScript with no platform-specific code or dependencies.

**Key Characteristics:**

- **Pure JavaScript** - No native bindings or platform APIs
- **Self-Contained** - No module dependencies
- **Standards-Compliant** - Implements Netscape's original PAC specification
- **Minimal Implementation** - Provides core hostname/domain/subnet matching functions
- **Stub Extensions** - Time/date functions present but not implemented
- **DNS Abstraction** - Delegates DNS resolution to calling context

**Limitations:**

- Time-based functions not implemented (weekdayRange, dateRange, timeRange)
- No IPv6 support
- No extended PAC functions (myIpAddress, dnsResolveEx, etc.)
- No built-in DNS caching (performance optimization left to caller)

**Primary Use Case:**

Provides the JavaScript runtime environment for MeshAgent's automatic proxy detection system, allowing PAC files downloaded from WPAD or DHCP to execute and determine appropriate proxy settings for server communication.

**macOS Support:** **Fully supported** with no limitations or platform-specific concerns.
