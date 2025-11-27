# mac_plist_utils.c

Secure CoreFoundation-based parsing utilities for macOS LaunchDaemon plist files. Provides functions to extract meshagent configuration information (service labels, program paths, command-line arguments) from plist files during upgrade and service discovery operations.

## Description

Property list (plist) parsing utilities specifically designed for safely extracting meshagent configuration from LaunchDaemon plist files without shell injection vulnerabilities. Uses CoreFoundation APIs exclusively for robust, type-safe plist parsing.

## Platform

**Supported Platforms:**
- macOS (darwin) - Exclusive

**Excluded Platforms:**
- Windows (win32) - Uses XML/registry, not plists
- Linux - Uses systemd service files, not plists
- FreeBSD - Uses rc.d scripts, not plists

**Platform Requirements:**
- **Minimum Version:** macOS 10.7+ (CoreFoundation property list APIs)
- **Architecture:** arm64, x86_64, universal binaries
- **Reason:** macOS-specific plist format and CoreFoundation framework

**Exclusion Reasoning:**

This module is **macOS only** due to:

1. **Plist Format:** Apple's property list file format (XML/binary) unique to macOS/iOS
2. **CoreFoundation APIs:** CFPropertyList, CFDictionary, CFArray APIs (macOS-only)
3. **LaunchDaemon Structure:** Specific to macOS launchd system service management
4. **Service Discovery:** Parses `/Library/LaunchDaemons/*.plist` files (macOS path convention)

Other platforms use different service configuration formats:
- **Windows:** Registry keys, XML service configs
- **Linux:** systemd unit files (.service), init.d scripts
- **FreeBSD:** rc.d scripts

## Functionality

### Purpose

Enables MeshAgent to discover and upgrade existing installations by parsing LaunchDaemon plist files to extract:
- **Service Label:** Unique launchd service identifier (e.g., `meshagent.tacticalmesh`)
- **Program Path:** Location of meshagent binary (bundle or standalone)
- **Arguments:** Command-line flags like `--disableUpdate=1`
- **Modification Time:** When plist was last modified (for conflict resolution)

### Critical Use Cases

**1. Upgrade Detection:**
- Scan `/Library/LaunchDaemons/` for existing meshagent plists
- Extract service label and program path
- Upgrade in-place without changing service name

**2. Multi-Installation Discovery:**
- Identify all installed meshagent services on system
- Distinguish between different service variants (tactical, standard, custom)
- Prevent installation conflicts

**3. Configuration Migration:**
- Read arguments from old plist during upgrade
- Preserve `--disableUpdate=1` flag across upgrades
- Maintain service configuration consistency

**4. Service Verification:**
- Verify plist contains valid meshagent configuration
- Detect corrupted or malformed plist files
- Skip non-meshagent LaunchDaemons during scans

### Security Design

**Why CoreFoundation Instead of Shell Commands?**

❌ **Unsafe (shell injection risk):**
```c
// NEVER DO THIS
char cmd[1024];
sprintf(cmd, "/usr/libexec/PlistBuddy -c 'Print :Label' '%s'", plistPath);
FILE* f = popen(cmd, "r");  // Shell injection if plistPath contains '; rm -rf /'
```

✅ **Safe (CoreFoundation):**
```c
// This code uses CoreFoundation (no shell)
CFDictionaryRef dict = load_plist_from_file(plistPath);
CFStringRef label = CFDictionaryGetValue(dict, CFSTR("Label"));
```

**Benefits:**
- No shell execution (no injection attacks)
- Type-safe API (detects malformed plists)
- Handles binary and XML plists identically
- Proper Unicode/UTF-8 handling

### Integration Points

- **macOSHelpers.js:** JavaScript wrapper calls these functions for service discovery
- **agent-installer.js:** Uses plist parsing during upgrade operations
- **service-manager.js:** Reads service configuration from plists

## Dependencies

### System Headers
- `<CoreFoundation/CoreFoundation.h>` - CF* property list APIs (Line 9)
- `<stdio.h>` - Not actively used, legacy include (Line 10)
- `<string.h>` - memset, strncpy, strcmp, strstr (Line 11)
- `<sys/stat.h>` - stat() for file modification time (Line 12)
- `<stdlib.h>` - malloc, free for dynamic allocations (Line 13)

### MeshAgent Headers
- `mac_plist_utils.h` - MeshPlistInfo structure and function declarations (Line 8)

### System Frameworks
- **CoreFoundation.framework** - Required for compilation

### External Libraries
- None

## Key Data Structures

### MeshPlistInfo - Lines 16-22 (header)

**Purpose:** Container structure for parsed plist information

**Definition:**
```c
typedef struct {
    char plistPath[1024];           // Path to the plist file
    char label[256];                 // Label from plist
    char programPath[1024];          // First path in ProgramArguments
    int hasDisableUpdate;            // 1 if --disableUpdate=1 found
    time_t modTime;                  // Modification time of plist file
} MeshPlistInfo;
```

**Fields:**
- `plistPath` - Full path to plist file (e.g., `/Library/LaunchDaemons/meshagent.plist`)
- `label` - LaunchDaemon Label value (e.g., `meshagent.tacticalmesh`)
- `programPath` - Path to meshagent binary from first ProgramArguments entry
- `hasDisableUpdate` - Boolean flag (1=true, 0=false) indicating `--disableUpdate=1` present
- `modTime` - Unix timestamp of plist file modification (for choosing newest)

**Memory Management:**
- Stack-allocated by caller
- No dynamic allocations within structure
- Fixed-size buffers prevent overflow (truncation at max size)

## Key Functions

### load_plist_from_file() - Lines 20-66 (static helper)

**Purpose:** Load and parse a plist file into a CFDictionaryRef using CoreFoundation

**Signature:**
```c
static CFDictionaryRef load_plist_from_file(const char* plistPath);
```

**Parameters:**
- `plistPath` (const char*): File system path to plist file

**Return Value:**
- `CFDictionaryRef` - Parsed plist dictionary (caller must CFRelease)
- `NULL` - If file doesn't exist, is malformed, or is not a dictionary

**Implementation:**
1. **Create File URL** (Lines 26-36):
   - Convert C string path to CFString
   - Create CFURL from path (POSIX style)
   - Release temporary CFString
2. **Open Stream** (Lines 38-42):
   - Create read stream from file URL
   - Open stream (returns false if file doesn't exist)
3. **Parse Plist** (Lines 44-50):
   - Use `CFPropertyListCreateWithStream()` for secure parsing
   - Check for errors (malformed plist)
   - Handles both XML and binary plist formats automatically
4. **Type Check** (Lines 52-55):
   - Verify plist is a dictionary (not array/string/number)
   - Retain dictionary for return
5. **Cleanup** (Lines 57-65):
   - Close and release stream
   - Release all temporary CoreFoundation objects
   - Uses goto cleanup pattern for consistent cleanup

**Thread Safety:** Thread-safe (no shared state, file I/O is kernel-serialized)

**Memory Management:**
- **Caller must CFRelease** returned dictionary
- All intermediate objects properly released
- Null checks prevent crashes on invalid paths

**Notes:**
- **Binary/XML Agnostic:** Parses both plist formats identically
- **Error Handling:** Graceful failure (returns NULL, no crashes)
- **goto cleanup Pattern:** Ensures consistent resource cleanup (acceptable C idiom)

---

### cfstring_to_cstring() - Lines 73-88 (static helper)

**Purpose:** Convert CoreFoundation CFString to dynamically allocated C string

**Signature:**
```c
static char* cfstring_to_cstring(CFStringRef cfString);
```

**Parameters:**
- `cfString` (CFStringRef): CoreFoundation string object

**Return Value:**
- `char*` - Dynamically allocated C string (caller must free())
- `NULL` - If cfString is NULL, wrong type, or conversion fails

**Implementation:**
1. **Type Check** (Lines 74-76): Verify cfString is actually a CFString
2. **Calculate Buffer Size** (Lines 78-79):
   - Get string length
   - Calculate maximum UTF-8 size (handles multi-byte characters)
   - Add 1 for null terminator
3. **Allocate and Convert** (Lines 80-84):
   - malloc() buffer
   - Convert CFString to C string (UTF-8 encoding)
   - Return on success
4. **Cleanup on Failure** (Lines 86-87):
   - Free buffer if conversion failed
   - Return NULL

**Thread Safety:** Thread-safe

**Memory Management:**
- **Caller must free()** returned string
- Properly sized buffer prevents overflow
- Frees buffer on failure (no leaks)

**Notes:**
- **UTF-8 Encoding:** Supports international characters in plist values
- **Dynamic Sizing:** Handles strings of any length
- **Null Safety:** Returns NULL on any error (safe to check)

---

### mesh_plist_get_label() - Lines 93-104

**Purpose:** Extract the Label value from a plist file

**Signature:**
```c
char* mesh_plist_get_label(const char* plistPath);
```

**Parameters:**
- `plistPath` (const char*): Path to plist file

**Return Value:**
- `char*` - Dynamically allocated string with label (caller must free())
- `NULL` - If file doesn't exist, is malformed, or has no Label key

**Implementation:**
1. Load plist dictionary
2. Get "Label" value from dictionary
3. Convert CFString to C string
4. Release dictionary
5. Return result (NULL if any step fails)

**Thread Safety:** Thread-safe

**Memory Management:** Caller must free() returned string

**Example:**
```c
char* label = mesh_plist_get_label("/Library/LaunchDaemons/meshagent.tactical.plist");
if (label) {
    printf("Service label: %s\n", label);  // "meshagent.tactical"
    free(label);
}
```

---

### mesh_plist_get_program_path() - Lines 109-128

**Purpose:** Extract the first ProgramArguments path from a plist file

**Signature:**
```c
char* mesh_plist_get_program_path(const char* plistPath);
```

**Parameters:**
- `plistPath` (const char*): Path to plist file

**Return Value:**
- `char*` - Dynamically allocated string with program path (caller must free())
- `NULL` - If no ProgramArguments or array is empty

**Implementation:**
1. Load plist dictionary
2. Get "ProgramArguments" array from dictionary
3. Type-check array
4. Get first element (index 0)
5. Convert CFString to C string
6. Release dictionary
7. Return result

**Thread Safety:** Thread-safe

**Memory Management:** Caller must free() returned string

**LaunchDaemon ProgramArguments Format:**
```xml
<key>ProgramArguments</key>
<array>
    <string>/Applications/MeshAgent.app/Contents/MacOS/meshagent</string>  <!-- index 0 -->
    <string>-foreground</string>                                           <!-- index 1 -->
    <string>--disableUpdate=1</string>                                     <!-- index 2 -->
</array>
```

**Example:**
```c
char* path = mesh_plist_get_program_path("/Library/LaunchDaemons/meshagent.plist");
if (path) {
    printf("Binary location: %s\n", path);
    free(path);
}
```

---

### mesh_plist_has_argument() - Lines 133-162

**Purpose:** Check if ProgramArguments array contains a specific argument

**Signature:**
```c
int mesh_plist_has_argument(const char* plistPath, const char* argument);
```

**Parameters:**
- `plistPath` (const char*): Path to plist file
- `argument` (const char*): Argument to search for (e.g., "--disableUpdate=1")

**Return Value:**
- `1` - Argument found in ProgramArguments array
- `0` - Argument not found, or plist invalid

**Implementation:**
1. Load plist dictionary
2. Get "ProgramArguments" array
3. Create CFString from search argument
4. **Iterate** through array (Lines 147-155):
   - Get each element
   - Type-check as CFString
   - Compare with target using `CFStringCompare()`
   - Break on first match
5. Release all objects
6. Return found flag

**Thread Safety:** Thread-safe

**Memory Management:** All objects properly released, no leaks

**Example:**
```c
if (mesh_plist_has_argument("/Library/LaunchDaemons/meshagent.plist", "--disableUpdate=1")) {
    printf("Auto-updates are disabled\n");
}
```

---

### mesh_parse_launchdaemon_plist() - Lines 167-227

**Purpose:** Parse a LaunchDaemon plist file and extract all meshagent information

**Signature:**
```c
int mesh_parse_launchdaemon_plist(const char* plistPath, MeshPlistInfo* info);
```

**Parameters:**
- `plistPath` (const char*): Path to plist file
- `info` (MeshPlistInfo*): Pointer to structure to populate

**Return Value:**
- `1` - Successfully parsed and contains meshagent info
- `0` - Invalid path/info pointer, file error, or not a meshagent plist

**Implementation:**

**Initialization** (Lines 168-179):
- Validate parameters (null checks)
- Zero out info structure (`memset`)
- Copy plistPath into structure
- Load plist dictionary

**Extract Label** (Lines 183-187):
- Get "Label" value from dictionary
- Type-check as CFString
- Copy directly to info->label buffer (max 256 chars)

**Extract ProgramArguments** (Lines 189-216):
- Get "ProgramArguments" array
- Type-check as CFArray
- **Iterate through all elements:**
  - Copy each to temporary buffer (max 1024 chars)
  - **Find meshagent binary** (Lines 205-209):
    - Check if argument contains substring "meshagent"
    - First match becomes `info->programPath`
    - Sets `foundMeshagent` flag (return value)
  - **Find --disableUpdate flag** (Lines 211-214):
    - Check for exact match `"--disableUpdate=1"`
    - Sets `info->hasDisableUpdate = 1` if found

**Get Modification Time** (Lines 220-224):
- Call `stat()` on plist file
- Store `st_mtime` in `info->modTime`
- Used for choosing newest plist during conflicts

**Return Value** (Line 226):
- Returns `foundMeshagent` flag
- Only returns 1 if plist actually contains meshagent reference

**Thread Safety:** Thread-safe

**Memory Management:**
- All CoreFoundation objects properly released
- Fixed-size buffers in MeshPlistInfo (no dynamic allocations)
- Info structure zeroed before use (prevents stale data)

**Example:**
```c
MeshPlistInfo info;
if (mesh_parse_launchdaemon_plist("/Library/LaunchDaemons/meshagent.tactical.plist", &info)) {
    printf("Label: %s\n", info.label);
    printf("Binary: %s\n", info.programPath);
    printf("Disable updates: %s\n", info.hasDisableUpdate ? "yes" : "no");
    printf("Modified: %s", ctime(&info.modTime));
}
```

## macOS-Specific Implementation Details

### CoreFoundation Property List APIs

**CFPropertyListCreateWithStream():**
- Parses both XML and binary plist formats
- Type-safe (returns CFPropertyListRef, must cast after type check)
- Error reporting via CFErrorRef
- Immutable flag prevents modification (security)

**CFDictionary vs NSDictionary:**
- CFDictionary is C API (works in pure C code)
- NSDictionary is Objective-C (requires ARC/MRC)
- CFDictionary used here for C compatibility

**CFArray Iteration:**
- Use `CFArrayGetCount()` for length
- Use `CFArrayGetValueAtIndex()` for elements
- No subscript syntax (C, not Objective-C)

### LaunchDaemon Plist Structure

**Typical meshagent LaunchDaemon plist:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" ...>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>meshagent.tacticalmesh</string>

    <key>ProgramArguments</key>
    <array>
        <string>/opt/tacticalmesh/meshagent</string>
        <string>-foreground</string>
        <string>--disableUpdate=1</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

**Keys Parsed by This Code:**
- `Label` - Service identifier (required by launchd)
- `ProgramArguments` - Array of command + arguments (required)

**Keys Ignored:**
- `RunAtLoad`, `KeepAlive`, `WorkingDirectory`, etc. (not needed for discovery)

### File System Paths

**LaunchDaemon Locations:**
- `/Library/LaunchDaemons/` - User-installed services (writable by root)
- `/System/Library/LaunchDaemons/` - Apple services (read-only)

**Typical meshagent plist paths:**
- `/Library/LaunchDaemons/meshagent.plist` - Default installation
- `/Library/LaunchDaemons/meshagent.tactical.plist` - Tactical RMM
- `/Library/LaunchDaemons/meshagent.company.service.plist` - Custom ServiceID

### Plist File Permissions
- Must be owned by root:wheel
- Permissions: 644 (readable by all, writable by root)
- launchd ignores plists with incorrect permissions

## Usage Examples

### Example 1: Discover All MeshAgent Installations

```c
#include "mac_plist_utils.h"
#include <dirent.h>

void find_all_meshagent_services(void) {
    DIR* dir = opendir("/Library/LaunchDaemons");
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL) {
        // Skip non-plist files
        if (!strstr(entry->d_name, ".plist")) continue;

        char path[1024];
        snprintf(path, sizeof(path), "/Library/LaunchDaemons/%s", entry->d_name);

        MeshPlistInfo info;
        if (mesh_parse_launchdaemon_plist(path, &info)) {
            printf("Found meshagent service:\n");
            printf("  Label: %s\n", info.label);
            printf("  Binary: %s\n", info.programPath);
            printf("  Updates: %s\n", info.hasDisableUpdate ? "disabled" : "enabled");
        }
    }

    closedir(dir);
}
```

### Example 2: Upgrade Detection

```c
#include "mac_plist_utils.h"

int detect_existing_installation(char* outPath, size_t pathSize) {
    const char* possiblePaths[] = {
        "/Library/LaunchDaemons/meshagent.plist",
        "/Library/LaunchDaemons/meshagent.tactical.plist",
        "/Library/LaunchDaemons/meshagent.tacticalmesh.plist",
        NULL
    };

    for (int i = 0; possiblePaths[i] != NULL; i++) {
        char* path = mesh_plist_get_program_path(possiblePaths[i]);
        if (path) {
            strncpy(outPath, path, pathSize - 1);
            free(path);
            return 1;  // Found existing installation
        }
    }

    return 0;  // No existing installation
}
```

### Example 3: Preserve Configuration During Upgrade

```c
#include "mac_plist_utils.h"

void upgrade_meshagent(const char* oldPlistPath, const char* newBinaryPath) {
    MeshPlistInfo oldInfo;

    if (!mesh_parse_launchdaemon_plist(oldPlistPath, &oldInfo)) {
        fprintf(stderr, "Cannot parse old plist\n");
        return;
    }

    // Create new plist with same configuration
    printf("Upgrading %s\n", oldInfo.label);
    printf("Old binary: %s\n", oldInfo.programPath);
    printf("New binary: %s\n", newBinaryPath);

    if (oldInfo.hasDisableUpdate) {
        printf("Preserving --disableUpdate=1 flag\n");
    }

    // Generate new plist with updated binary path but same arguments
    // ... (plist generation code)
}
```

### Example 4: Find Newest Installation (Conflict Resolution)

```c
#include "mac_plist_utils.h"
#include <dirent.h>

char* find_newest_meshagent_plist(void) {
    DIR* dir = opendir("/Library/LaunchDaemons");
    struct dirent* entry;

    time_t newestTime = 0;
    char newestPath[1024] = {0};

    while ((entry = readdir(dir)) != NULL) {
        if (!strstr(entry->d_name, "meshagent") || !strstr(entry->d_name, ".plist")) {
            continue;
        }

        char path[1024];
        snprintf(path, sizeof(path), "/Library/LaunchDaemons/%s", entry->d_name);

        MeshPlistInfo info;
        if (mesh_parse_launchdaemon_plist(path, &info)) {
            if (info.modTime > newestTime) {
                newestTime = info.modTime;
                strncpy(newestPath, path, sizeof(newestPath) - 1);
            }
        }
    }

    closedir(dir);

    return newestTime > 0 ? strdup(newestPath) : NULL;
}
```

## Technical Notes

### Architecture Decisions

**Why CoreFoundation Instead of libplist or XML Parser?**
- **Native API:** Part of macOS, no external dependencies
- **Type Safety:** CF APIs enforce type checking
- **Format Agnostic:** Handles XML and binary plists identically
- **Security:** Well-tested, maintained by Apple
- **Performance:** Optimized for macOS

**Why Static Helpers?**
- `load_plist_from_file()` and `cfstring_to_cstring()` are implementation details
- Not part of public API (not in header)
- Reduces symbol namespace pollution
- Encourages use of higher-level functions

**Why Fixed-Size Buffers in MeshPlistInfo?**
- **Simplicity:** No malloc/free needed by caller
- **Safety:** Bounds checking prevents overflow
- **Stack Allocation:** Efficient, automatic cleanup
- **Limits:** 1024 bytes sufficient for all realistic paths

### Performance Characteristics

- **File I/O:** Dominant cost (~1-5ms per plist on SSD)
- **Parsing:** Negligible (<0.1ms for typical plist)
- **Memory:** Temporary allocations during parsing (freed on return)
- **Scalability:** Suitable for scanning 10-100 plists (typical LaunchDaemons directory)

### Security Considerations

**Shell Injection Prevention:**
- **Never calls shell commands** (no popen, system, etc.)
- Immune to path injection attacks
- Safe even with malicious plist paths

**Buffer Overflow Prevention:**
- Fixed-size buffers with explicit size limits
- `strncpy()` with size-1 prevents overflow
- `CFStringGetCString()` with maxSize prevents overflow

**Type Confusion Prevention:**
- Explicit `CFGetTypeID()` checks before casting
- Fails gracefully on wrong types (returns NULL/0)

**Malformed Plist Handling:**
- CoreFoundation handles malformed XML/binary safely
- Returns NULL on parse errors (no crashes)

**Privilege Handling:**
- Runs at current process privileges (no elevation)
- Safe for root and user processes

### Platform Quirks

**Binary vs XML Plists:**
- macOS uses binary format by default (more compact)
- CoreFoundation handles both transparently
- Can convert: `plutil -convert xml1 file.plist`

**CFString Encoding:**
- UTF-8 encoding supports international characters
- Service labels often contain non-ASCII (company names)
- Proper encoding prevents data loss

**stat() Limitations:**
- `st_mtime` has 1-second resolution on HFS+
- APFS has nanosecond resolution (not used here)
- Sufficient for upgrade conflict resolution

**Path Length Limits:**
- macOS PATH_MAX is 1024
- Buffers sized accordingly
- Truncation handled gracefully (strncpy)

## Cross-References

### Related C Files
- [`bundle_detection.c`](bundle_detection.md) - Bundle path resolution used in plist ProgramArguments
- [`mac_logging_utils.c`](mac_logging_utils.md) - Could be used for plist parsing errors (not currently used)

### Related Modules
- [`macOSHelpers.js`](../meshagent-modules/macOSHelpers.js.md) - JavaScript wrapper for plist utilities
- [`service-manager.js`](../meshagent-modules/service-manager.js.md) - Uses plist parsing for service discovery
- [`agent-installer.js`](../meshagent-modules/agent-installer.js.md) - Upgrade operations use plist parsing

### Documentation
- [macOS ServiceID System](../macOS-ServiceID-System.md) - Service naming reflected in plist Label
- [macOS Install Assistant](../macos-install-assistant.md) - Uses plist parsing for upgrade detection

## Testing

### Unit Tests
Location: No dedicated unit tests (tested via integration)

### Integration Tests
- Parse valid meshagent plist, verify all fields extracted
- Parse invalid plist (malformed XML), verify graceful failure
- Parse non-meshagent plist, verify returns 0
- Test with binary and XML plist formats
- Test UTF-8 characters in service names

### Manual Testing

**Test Valid Plist:**
```bash
# Create test plist
cat > /tmp/test-meshagent.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>meshagent.test</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/test/meshagent</string>
        <string>-foreground</string>
        <string>--disableUpdate=1</string>
    </array>
</dict>
</plist>
EOF

# Test with code
gcc -o test_plist test_plist.c mac_plist_utils.c -framework CoreFoundation
./test_plist /tmp/test-meshagent.plist
# Should print: Label: meshagent.test, Path: /opt/test/meshagent, DisableUpdate: 1
```

**Test Malformed Plist:**
```bash
echo "not a plist" > /tmp/bad.plist
./test_plist /tmp/bad.plist
# Should return gracefully (no crash)
```

**Test Binary Plist:**
```bash
# Convert to binary format
plutil -convert binary1 /tmp/test-meshagent.plist
./test_plist /tmp/test-meshagent.plist
# Should work identically to XML format
```

## Summary

mac_plist_utils.c provides secure, CoreFoundation-based plist parsing specifically designed for discovering and upgrading meshagent installations on macOS. By using native Apple APIs instead of shell commands, it eliminates shell injection vulnerabilities while providing robust parsing of both XML and binary plist formats. The utility functions extract service labels, program paths, and command-line arguments from LaunchDaemon plists, enabling safe in-place upgrades that preserve service configuration across installations.

---

**Last Updated:** 2025-11-28
**Documented By:** Peet McKinney
**Source File:** `meshcore/MacOS/mac_plist_utils.c`
**Lines of Code:** 228
**Public API:** 5 functions (mesh_parse_launchdaemon_plist, mesh_plist_get_label, mesh_plist_get_program_path, mesh_plist_has_argument), 1 structure (MeshPlistInfo)
**Security:** Shell injection immune, type-safe, buffer overflow protected
