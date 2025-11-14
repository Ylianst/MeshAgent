# lib-finder.js

Library and binary locator utility for FreeBSD and Linux systems that provides programmatic discovery of shared libraries and executable binaries. This module enables runtime detection of system dependencies by querying package managers and filesystem utilities, supporting both FreeBSD's pkg system and Linux's package management tools.

## Platform

**Supported Platforms:**
- FreeBSD - Full support using pkg info commands
- Linux - Full support using monitor-info module

**Excluded Platforms:**
- **macOS (darwin)** - Not supported
- **Windows (win32)** - Not supported

**Exclusion Reasoning:**

macOS and Windows are excluded from this utility for several technical reasons:

1. **Different Package Management Systems** - The module is designed for FreeBSD's `pkg` system and Linux package managers. macOS uses different approaches:
   - **macOS:** Homebrew (`brew`), MacPorts (`port`), or native `.dylib` libraries without package metadata
   - **Windows:** No native package manager, uses DLLs in System32/SysWOW64
   - The pkg/dpkg/rpm query patterns don't apply to these systems

2. **Shared Library Naming Conventions** - Library naming differs across platforms:
   - **Unix-like (FreeBSD/Linux):** `libname.so.version` (ELF shared objects)
   - **macOS:** `libname.dylib` or `libname.so` (Mach-O dynamic libraries)
   - **Windows:** `name.dll` (PE dynamic-link libraries)

3. **Library Discovery Methods** - Each platform uses different mechanisms:
   - **FreeBSD:** `pkg info -l <package>` lists files installed by package
   - **Linux:** `monitor-info.getLibInfo()` queries package database
   - **macOS:** `otool -L` for dependency analysis, `dyld` for runtime linking
   - **Windows:** Registry, SxS (Side-by-Side), DLL search path

4. **Binary Location Tools** - The `whereis` command used for binary location:
   - **FreeBSD/Linux:** Standard utility in base system
   - **macOS:** Has `whereis` but with different behavior (mainly for man pages)
   - **Windows:** No `whereis` equivalent, uses `where` command

5. **Use Case Specificity** - This module addresses FreeBSD/Linux-specific scenarios:
   - Verifying shared library availability for native modules
   - Locating system binaries before execution
   - Supporting dependency detection in package-managed environments
   - macOS and Windows have different dependency management paradigms

6. **monitor-info Module Dependency** - Linux implementation relies on `monitor-info.getLibInfo()`, which is Linux-specific and not implemented for macOS/Windows.

## Functionality

### Purpose

The lib-finder module provides programmatic discovery of shared libraries and executable binaries on FreeBSD and Linux systems. It enables MeshAgent to:

1. **Library Discovery:**
   - Find shared library files (.so) provided by installed packages
   - Determine exact filesystem paths of library files
   - Verify library availability before loading native modules
   - Support dependency checking for optional features

2. **Binary Discovery:**
   - Locate executable binaries in system PATH
   - Check for binary existence without executing
   - Find full paths to system utilities
   - Enable conditional feature activation based on tool availability

This module is used throughout MeshAgent to:
- Detect system capabilities before using platform-specific features
- Locate required utilities dynamically
- Verify dependencies for optional modules
- Provide graceful fallbacks when tools are unavailable

### Use Cases

**Typical scenarios where this module is used:**

1. **Native Module Loading:**
   ```javascript
   var libFinder = require('lib-finder');
   var libs = libFinder('libssl');
   if (libs.length > 0) {
       // OpenSSL available, enable SSL features
       var ssl = require('openssl');
   } else {
       // Fallback to alternative crypto
   }
   ```

2. **System Utility Detection:**
   ```javascript
   var libFinder = require('lib-finder');
   if (libFinder.hasBinary('zenity')) {
       // Use zenity for GUI dialogs
   } else if (libFinder.hasBinary('kdialog')) {
       // Use kdialog instead
   } else {
       // Use console-based prompts
   }
   ```

3. **Feature Availability Checking:**
   ```javascript
   var libFinder = require('lib-finder');
   var xclipPath = libFinder.findBinary('xclip');
   if (xclipPath) {
       // Enable clipboard features using xclip at specific path
       initClipboard(xclipPath);
   }
   ```

### Key Functions

#### find(name) - Lines 17-47

**Purpose:** Locates shared library files (.so) provided by a named package.

**Parameters:**
- `name` (string) - Package name to search for

**Return Value:**
- **FreeBSD:** Array of objects with `{name: string, location: string}` structure
- **Linux:** Array returned by `monitor-info.getLibInfo(name)`
- **Other platforms:** `undefined` (no return statement)

**FreeBSD Implementation** (lines 21-42):

**Process:**

1. **Query shared libraries provided by package** (line 26):
   ```javascript
   child.stdin.write("pkg info " + name + " | tr '\\n' '\\|' | awk ' { a=split($0, t, \"Shared Libs provided:\"); if(a==2) { split(t[2], lib, \":\"); print lib[1]; } }' | tr '\\|' '\\n' | awk '{ if(split($1, res, \".so\")>1) { print $1; } }'\nexit\n");
   ```

   **Command breakdown:**
   - `pkg info <name>` - Get package information
   - `tr '\n' '|'` - Replace newlines with pipes (single line)
   - `awk` - Extract "Shared Libs provided:" section
   - `split(t[2], lib, ":")` - Split library list by colons
   - `tr '|' '\n'` - Restore newlines
   - `awk` - Filter for .so files only
   - Result: List of .so filenames provided by package

   **Example output:**
   ```
   libssl.so.111
   libcrypto.so.111
   ```

2. **Filter libraries matching package name** (lines 29-31):
   ```javascript
   for(var i in res) {
       if(!res[i].startsWith(name + '.so')) { continue; }
       // Process matching library
   }
   ```
   - Only process libraries named `<package>.so*`
   - Skips dependencies or differently-named libraries

3. **Find filesystem location for each library** (lines 32-38):
   ```javascript
   child.stdin.write('pkg info -l ' + name + ' | grep ' + v.name + ' | awk \'{ a=split($1, tok, "/"); if(tok[a]=="' + v.name + '") { print $1; } }\'\nexit\n');
   ```

   **Command breakdown:**
   - `pkg info -l <name>` - List all files installed by package
   - `grep <libname>` - Filter for specific library file
   - `awk` - Extract only exact filename matches
   - Ensures `/usr/local/lib/libssl.so.111` matches, not `/usr/local/lib/libssl.so.111.debug`

   **Example output:**
   ```
   /usr/local/lib/libssl.so.111
   ```

4. **Build result object** (lines 32, 38-39):
   ```javascript
   var v = {name: res[i]};
   // ... find location ...
   v.location = child.stdout.str.trim();
   ret.push(v);
   ```

   **Result structure:**
   ```javascript
   [
       {name: "libssl.so.111", location: "/usr/local/lib/libssl.so.111"},
       {name: "libssl.so", location: "/usr/local/lib/libssl.so"}
   ]
   ```

**Linux Implementation** (lines 43-45):

```javascript
case 'linux':
    return (require('monitor-info').getLibInfo(name));
    break;
```

- Delegates to `monitor-info` module's `getLibInfo()` function
- Likely queries dpkg, rpm, or other package databases
- Returns similar structure (implementation in monitor-info module)

**Platform Behavior:**
- **FreeBSD:** Full implementation using pkg commands
- **Linux:** Delegates to monitor-info module
- **macOS/Windows:** Returns `undefined` (no case, no return)

---

#### hasBinary(bin) - Lines 49-60

**Purpose:** Checks if an executable binary exists in the system PATH.

**Parameters:**
- `bin` (string) - Binary name to search for (e.g., "zenity", "git", "xclip")

**Return Value:**
- `true` - Binary found in PATH
- `false` - Binary not found or unsupported platform

**Implementation:**

```javascript
if (process.platform != 'linux' && process.platform != 'freebsd') { return (false); }
var child = require('child_process').execFile('/bin/sh', ['sh']);
child.stdout.str = '';
child.stdout.on('data', function (c) { this.str += c.toString(); });
child.stdin.write("whereis " + bin + " | awk '{ print $2 }'\nexit\n");
child.waitExit();
var ret = child.stdout.str.trim() != '';
child = null;
return (ret);
```

**Process:**

1. **Platform check** (line 51):
   - Returns `false` immediately on non-Linux/FreeBSD platforms
   - Prevents execution on unsupported systems

2. **Execute whereis command** (line 55):
   ```bash
   whereis zenity | awk '{ print $2 }'
   ```

   **whereis output format:**
   ```
   zenity: /usr/bin/zenity /usr/share/man/man1/zenity.1.gz
   ```

   **awk processing:**
   - `$1` = "zenity:" (binary name with colon)
   - `$2` = "/usr/bin/zenity" (first path, the binary)
   - Subsequent fields are man pages, source, etc.

3. **Check if result is non-empty** (line 57):
   ```javascript
   var ret = child.stdout.str.trim() != '';
   ```
   - If `whereis` found the binary, `$2` contains path
   - If not found, `whereis` outputs only "zenity:" and `$2` is empty
   - Returns `true` if path exists, `false` if empty

**Example behavior:**

```javascript
hasBinary('zenity')  // true (if /usr/bin/zenity exists)
hasBinary('xclip')   // true (if /usr/bin/xclip exists)
hasBinary('fakebin') // false (not in PATH)
```

**Platform Behavior:**
- **Linux/FreeBSD:** Full implementation
- **macOS/Windows:** Always returns `false`

---

#### findBinary(bin) - Lines 61-72

**Purpose:** Finds the full filesystem path to an executable binary.

**Parameters:**
- `bin` (string) - Binary name to locate

**Return Value:**
- **Found:** String containing full path (e.g., "/usr/bin/zenity")
- **Not found:** `null`
- **Unsupported platform:** `null`

**Implementation:**

```javascript
if (process.platform != 'linux' && process.platform != 'freebsd') { return (null); }
var child = require('child_process').execFile('/bin/sh', ['sh']);
child.stdout.str = '';
child.stdout.on('data', function (c) { this.str += c.toString(); });
child.stdin.write("whereis " + bin + " | awk '{ print $2 }'\nexit\n");
child.waitExit();
var ret = child.stdout.str.trim() != "" ? child.stdout.str.trim() : null;
child = null;
return (ret);
```

**Process:**

1. **Platform check** (line 63):
   - Returns `null` immediately on non-Linux/FreeBSD platforms

2. **Execute whereis command** (line 67):
   - Same command as `hasBinary()`
   - Extracts second field (binary path)

3. **Return path or null** (line 69):
   ```javascript
   var ret = child.stdout.str.trim() != "" ? child.stdout.str.trim() : null;
   ```
   - If path found, returns the path string
   - If empty, returns `null`
   - Ternary operator for clean null handling

**Difference from hasBinary():**
- `hasBinary()` returns boolean (true/false)
- `findBinary()` returns string path or null
- Use `hasBinary()` for existence checks
- Use `findBinary()` when you need the actual path

**Example behavior:**

```javascript
findBinary('zenity')  // "/usr/bin/zenity"
findBinary('git')     // "/usr/bin/git"
findBinary('fakebin') // null
```

**Platform Behavior:**
- **Linux/FreeBSD:** Full implementation
- **macOS/Windows:** Always returns `null`

---

### Module Exports Structure

**Line 74-76:**
```javascript
module.exports = find;
module.exports.hasBinary = hasBinary;
module.exports.findBinary = findBinary;
```

**Export pattern:**
- Default export: `find()` function
- Named exports: `hasBinary()` and `findBinary()` as properties

**Usage:**
```javascript
// Require module
var libFinder = require('lib-finder');

// Use default export (find function)
var libs = libFinder('libssl');

// Use named exports
var hasZenity = libFinder.hasBinary('zenity');
var gitPath = libFinder.findBinary('git');
```

### Dependencies

#### Node.js Core Modules

- **`child_process`** (lines 23, 52, 64)
  - Method: `execFile('/bin/sh', ['sh'])` - Spawn shell process
  - Used for executing system commands
  - Platform: All (but only used on Linux/FreeBSD in this module)

#### MeshAgent Module Dependencies

**Required Modules:**

- **`monitor-info`** (line 44) - **Linux only**
  - Method: `getLibInfo(name)` - Query package database for library information
  - Platform-specific implementation for Linux package managers
  - Likely interfaces with:
    - dpkg (Debian/Ubuntu)
    - rpm (RedHat/CentOS/Fedora)
    - pacman (Arch)
  - Returns library information in consistent format
  - **Not available on macOS/Windows**

**Conditional Dependencies:**
The module only requires `monitor-info` on Linux. FreeBSD implementation uses only child_process and shell commands.

#### Platform Binary Dependencies

**FreeBSD:**
- **`pkg`** (lines 26, 36)
  - Path: `/usr/sbin/pkg` or `/usr/local/sbin/pkg`
  - Package manager for FreeBSD
  - Commands used:
    - `pkg info <name>` - Show package information
    - `pkg info -l <name>` - List files in package
  - Standard on FreeBSD 10+

- **`awk`** (lines 26, 36, 55, 67)
  - Path: `/usr/bin/awk`
  - Text processing utility
  - Standard on all Unix-like systems

- **`grep`** (line 36)
  - Path: `/usr/bin/grep`
  - Text search utility
  - Standard on all Unix-like systems

- **`tr`** (line 26)
  - Path: `/usr/bin/tr`
  - Character translation utility
  - Standard on all Unix-like systems

- **`whereis`** (lines 55, 67)
  - Path: `/usr/bin/whereis`
  - Binary/man page locator
  - Standard on FreeBSD base system

**Linux:**
- **`whereis`** (lines 55, 67)
  - Path: `/usr/bin/whereis` or `/bin/whereis`
  - Binary locator utility
  - Part of util-linux package
  - Standard on all Linux distributions

- **`awk`** (lines 55, 67)
  - Path: `/usr/bin/awk` or `/bin/awk`
  - Usually GNU AWK (gawk)
  - Standard on all Linux distributions

**Linux (indirect, via monitor-info):**
- **`dpkg-query`** (Debian/Ubuntu) - Package database queries
- **`rpm`** (RedHat/CentOS/Fedora) - RPM package queries
- **`pacman`** (Arch) - Pacman database queries
- Specific tool depends on distribution

**macOS (not supported, but for reference):**
- Would need:
  - **`brew`** - Homebrew package manager
  - **`port`** - MacPorts package manager
  - **`otool`** - Mach-O dependency analyzer
  - **`dyld`** - Dynamic linker info
  - **`which`** - Binary locator (not whereis)

**Windows (not supported):**
- Would need:
  - **`where.exe`** - Binary locator
  - Registry queries for DLL locations
  - WMI queries for software detection

### Technical Notes

**Shell Command Execution Pattern:**

The module uses a consistent pattern for shell execution:

```javascript
var child = require('child_process').execFile('/bin/sh', ['sh']);
child.stdout.str = '';
child.stdout.on('data', function (c) { this.str += c.toString(); });
child.stdin.write("command here\nexit\n");
child.waitExit();
var result = child.stdout.str.trim();
```

**Pattern breakdown:**
1. Spawn interactive shell (`/bin/sh`)
2. Create string accumulator on stdout
3. Attach data event handler to accumulate output
4. Write command to stdin
5. Write `exit` to terminate shell
6. Wait for process exit
7. Parse accumulated output

**Why this pattern instead of exec():**
- Allows complex multi-command pipelines
- Provides better control over stdin/stdout
- Consistent with patterns used elsewhere in MeshAgent
- Enables interactive shell features

**waitExit() Method:**

```javascript
child.waitExit();
```

This is a MeshAgent-specific extension to child_process:
- Blocks execution until child process exits
- Synchronous operation (unusual for Node.js)
- Simplifies sequential command execution
- Part of MeshAgent's child_process modifications

**FreeBSD pkg info Output Format:**

```
pkg info libssl
libssl-1.1.1l
Name           : libssl
Version        : 1.1.1l
Installed on   : Tue Nov 12 10:30:00 2024 UTC
Origin         : security/openssl
Architecture   : FreeBSD:13:amd64
Prefix         : /usr/local
Shared Libs provided:
        libssl.so.111
        libcrypto.so.111
Shared Libs required:
        libc.so.7
...
```

The AWK script extracts only the "Shared Libs provided:" section.

**whereis Output Format:**

```bash
$ whereis zenity
zenity: /usr/bin/zenity /usr/share/man/man1/zenity.1.gz

$ whereis git
git: /usr/bin/git /usr/local/bin/git /usr/share/man/man1/git.1.gz

$ whereis nonexistent
nonexistent:
```

**Field extraction:**
- `$1` - Binary name with colon (e.g., "zenity:")
- `$2` - First path (usually the binary in /usr/bin or /bin)
- `$3+` - Additional paths (man pages, source, alternate locations)

The module uses `$2` to get the primary binary location.

**Security Considerations:**

**Command Injection Risk:**
```javascript
child.stdin.write("whereis " + bin + " | awk '{ print $2 }'\nexit\n");
```

The `bin` and `name` parameters are concatenated directly into shell commands without sanitization. This could allow command injection if untrusted input is passed:

```javascript
// DANGEROUS - DO NOT DO THIS
var userInput = "; rm -rf / #";
libFinder.hasBinary(userInput);
// Executes: whereis ; rm -rf / # | awk '{ print $2 }'
```

**Mitigation in practice:**
- Module is intended for internal use with trusted input
- Callers should validate input before calling
- Typically used with hardcoded binary names ("zenity", "git", etc.)
- Not exposed to user input in normal operation

**Proper usage:**
```javascript
// Safe - hardcoded trusted values
var hasZenity = libFinder.hasBinary('zenity');

// Safe - validated against whitelist
var allowedBinaries = ['zenity', 'kdialog', 'xclip'];
if (allowedBinaries.includes(userBinary)) {
    var hasBin = libFinder.hasBinary(userBinary);
}
```

**Memory Management:**

```javascript
child = null;  // Lines 58, 70
```

Explicitly setting `child` to `null` after use helps garbage collection:
- Releases reference to child process object
- Cleans up event handlers
- Frees memory from stdout accumulator
- Good practice for preventing memory leaks

**Synchronous vs Asynchronous:**

This module uses **synchronous** execution:
- `waitExit()` blocks until command completes
- No callbacks or promises
- Simple, sequential code flow
- Suitable for initialization/setup code
- Not suitable for high-frequency calls in event loops

**Platform Detection:**

```javascript
if (process.platform != 'linux' && process.platform != 'freebsd') {
    return (false); // or null
}
```

All functions check platform before execution:
- Early return for unsupported platforms
- Prevents errors from missing commands
- Clean failure mode (false/null)
- No exceptions thrown

### macOS-Specific Analysis

**Why macOS is Not Supported:**

1. **Package Manager Differences:**
   - FreeBSD uses `pkg` (ports collection)
   - Linux uses dpkg/rpm/pacman
   - **macOS options:**
     - **Homebrew** (`brew`) - Third-party, most popular
     - **MacPorts** (`port`) - Third-party, ports-based
     - **No native package manager** - Apps are bundles, not packages
     - **System libraries** - In `/usr/lib` without package metadata

2. **Shared Library Discovery on macOS:**

   **Current approach (FreeBSD/Linux):**
   - Query package database for .so files
   - Get installation path from package manager

   **macOS equivalent:**
   ```bash
   # Homebrew approach
   brew list libssl --verbose
   # Output: Lists all files in formula

   # MacPorts approach
   port contents libssl
   # Output: Lists installed files

   # Native library detection
   otool -L /usr/bin/some_binary
   # Output: Lists dynamic library dependencies

   # Find dylib files
   find /usr/local/lib -name "libssl*.dylib"
   ```

3. **Library Naming Conventions:**
   - **FreeBSD/Linux:** `libssl.so.1.1`, `libssl.so`
   - **macOS:** `libssl.1.1.dylib`, `libssl.dylib`
   - Different extension: `.dylib` vs `.so`
   - Different versioning schemes

4. **Binary Location on macOS:**
   - `whereis` exists but has different behavior:
     ```bash
     # Linux/FreeBSD whereis
     $ whereis git
     git: /usr/bin/git /usr/share/man/man1/git.1.gz

     # macOS whereis (mainly for man pages)
     $ whereis git
     /usr/share/man/man1/git.1
     ```

   - **macOS alternative:** `which` command:
     ```bash
     $ which git
     /usr/bin/git
     ```

5. **System Integrity Protection (SIP):**
   - macOS restricts access to system libraries
   - `/usr/lib` is protected
   - Third-party libraries in `/usr/local/lib` (Homebrew) or `/opt/local/lib` (MacPorts)
   - Dynamic linker behavior differs from Linux

**macOS Implementation Challenges:**

To support macOS, the module would need:

1. **Detect package manager:**
   ```javascript
   var hasBrew = hasBinary('brew');
   var hasPort = hasBinary('port');
   ```

2. **Query appropriate package manager:**
   ```javascript
   // Homebrew
   brew list libssl --verbose | grep dylib

   // MacPorts
   port contents libssl | grep dylib
   ```

3. **Handle .dylib instead of .so:**
   ```javascript
   if (process.platform == 'darwin') {
       // Look for .dylib files
   }
   ```

4. **Use which instead of whereis:**
   ```javascript
   case 'darwin':
       child.stdin.write("which " + bin + "\nexit\n");
   ```

5. **Handle system vs. Homebrew binaries:**
   ```javascript
   // which might return /usr/bin/git (system)
   // or /usr/local/bin/git (Homebrew)
   // or /opt/local/bin/git (MacPorts)
   ```

**Theoretical macOS Implementation:**

```javascript
case 'darwin':
    var ret = [];
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = '';
    child.stdout.on('data', function (c) { this.str += c.toString(); });

    // Try Homebrew first
    child.stdin.write("which brew > /dev/null 2>&1 && brew list " + name + " --verbose | grep '\\.dylib$'\nexit\n");
    child.waitExit();

    if (child.stdout.str.trim() != '') {
        // Parse Homebrew output
        var libs = child.stdout.str.trim().split('\n');
        for (var i in libs) {
            ret.push({
                name: libs[i].split('/').pop(),
                location: libs[i].trim()
            });
        }
    }
    return ret;
    break;
```

**Why It Hasn't Been Implemented:**

1. **Limited Use Case** - macOS MeshAgent deployment is less common than Linux
2. **Package Manager Fragmentation** - Supporting Homebrew, MacPorts, and native libs is complex
3. **Dynamic Library Detection Alternatives** - macOS has other mechanisms (dyld, otool)
4. **Development Tool** - This is primarily for dependency checking, not core functionality
5. **MeshAgent Modules Likely Bundled** - Native modules may be statically linked or bundled
6. **Effort vs. Benefit** - Implementation effort doesn't justify limited macOS usage

**What Would Work on macOS:**

If the module were modified:
- `hasBinary()` could use `which` instead of `whereis`
- `findBinary()` could return results from `which`
- Basic binary detection would work with minimal changes

**What Wouldn't Work:**

- `find()` function - Completely different implementation needed
- Package-based library discovery - No native macOS support
- .so file detection - macOS uses .dylib

### Comparison to Platform-Specific Alternatives

**FreeBSD (current implementation):**
```javascript
var libs = libFinder('libssl');
// Uses: pkg info, pkg info -l, grep, awk
// Returns: [{name: "libssl.so.111", location: "/usr/local/lib/libssl.so.111"}]
```

**Linux (current implementation):**
```javascript
var libs = libFinder('libssl');
// Uses: monitor-info.getLibInfo() -> dpkg/rpm queries
// Returns: Similar structure to FreeBSD
```

**macOS (hypothetical):**
```javascript
var libs = libFinder('openssl');
// Would use: brew list, port contents, or find
// Would return: [{name: "libssl.1.1.dylib", location: "/usr/local/lib/libssl.1.1.dylib"}]
```

**Windows (hypothetical):**
```javascript
var libs = libFinder('openssl');
// Would use: Registry queries, directory search
// Would return: [{name: "libssl-1_1-x64.dll", location: "C:\\Windows\\System32\\libssl-1_1-x64.dll"}]
```

## Summary

The lib-finder.js module is a library and binary discovery utility specifically designed for **FreeBSD and Linux** systems. It provides three main functions: `find()` for locating shared libraries via package managers, `hasBinary()` for checking binary existence, and `findBinary()` for retrieving full binary paths.

**macOS and Windows are not supported** because:
- Package management systems differ fundamentally (pkg/dpkg/rpm vs. Homebrew/MacPorts vs. no native PM)
- Shared library naming conventions are platform-specific (.so vs .dylib vs .dll)
- Library discovery mechanisms are incompatible (package databases vs. otool vs. Registry)
- The `whereis` command behaves differently on macOS (man page focus vs. binary location)
- Implementation would require complete rewrites for each platform with limited benefit
- This is a dependency checking tool, not core functionality - MeshAgent operates without it

The FreeBSD implementation uses `pkg info` commands with AWK parsing to extract library information, while the Linux implementation delegates to the `monitor-info` module's package database queries. Binary detection uses `whereis` combined with AWK to extract the primary binary path from system PATH.

For macOS support, the module would need to detect and query Homebrew/MacPorts, handle .dylib extensions instead of .so files, use `which` instead of `whereis`, and implement significantly different library discovery logic. Given the limited deployment of MeshAgent on macOS and the availability of alternative dependency detection methods, implementing macOS support has not been prioritized.
