# mac_bundle_detection.c

macOS application bundle detection and working directory management for MeshAgent. Provides runtime detection of bundle vs standalone execution mode and automatic working directory adjustment to ensure file operations work correctly in both deployment modes.

## Platform

**Supported Platforms:**
- macOS (darwin) - Exclusive

**Excluded Platforms:**
- Windows (win32) - Not supported
- Linux - Not supported
- FreeBSD - Not supported

**Platform Requirements:**
- **Minimum Version:** macOS 10.7+ (CoreFoundation availability)
- **Architecture:** arm64, x86_64, universal binaries
- **Reason:** Uses macOS-specific CoreFoundation APIs (CFBundle*) and .app bundle structure

**Exclusion Reasoning:**

This module is **macOS only** and relies exclusively on macOS application bundle concepts:

1. **CFBundle APIs:** CoreFoundation framework's CFBundleGetMainBundle(), CFBundleCopyBundleURL()
2. **.app Bundle Structure:** Detects macOS application bundles with .app extension
3. **Bundle Path Conventions:** Contents/MacOS/ hierarchy unique to macOS
4. **Dual Deployment Modes:** macOS agents can run as .app bundles OR standalone binaries

For cross-platform deployment detection, other platforms use different mechanisms:
- Windows: Service detection, registry keys
- Linux: Systemd service detection, file paths

The `#ifdef __APPLE__` guards ensure this code only compiles on macOS.

## Functionality

### Purpose

Bundle detection enables MeshAgent to automatically adapt to two deployment modes on macOS:

**Mode 1: Application Bundle (.app)**
- Agent packaged as `MeshAgent.app/Contents/MacOS/meshagent`
- Requires working directory adjustment to bundle parent directory
- Enables Install UI, permissions UI, and macOS-native user experience
- Used for installations from .pkg installer or manual .app deployment

**Mode 2: Standalone Binary**
- Agent runs as bare binary `/opt/acmemesh/meshagent`
- Working directory remains current directory
- Traditional Unix daemon behavior
- Used for scripted deployments and legacy installations

### Critical Use Cases

1. **File Path Resolution:** Configuration files (.msh), databases (.db), and runtime sockets must be found relative to working directory
2. **Installation Detection:** Determines if Installation UI should be shown
3. **Upgrade Operations:** Detects existing bundle installations for service discovery
4. **Logging Context:** Provides execution mode information for debugging

### Integration Points

- **agentcore.c:** Calls `adjust_working_directory_for_bundle()` in main() startup
- **macOSHelpers.js:** JavaScript wrapper uses bundle detection for service management
- **Installation Assistant:** Checks bundle status to show/hide UI options
- **Logger Module:** Logs deployment mode for troubleshooting

## Dependencies

### System Headers
- `<CoreFoundation/CoreFoundation.h>` - CFBundle APIs for bundle detection (Lines 21)
- `<unistd.h>` - chdir() for working directory changes (Line 22)
- `<string.h>` - String manipulation (strcmp, strlen, strrchr) (Line 23)
- `<stdio.h>` - Not currently used, legacy include (Line 24)
- `<stdlib.h>` - malloc, free for dynamic memory (Line 25)
- `<limits.h>` - PATH_MAX constant (Line 26)
- `<dirent.h>` - Not currently used, legacy include (Line 27)

### MeshAgent Headers
- `bundle_detection.h` - Function declarations and API documentation (Line 19)
- `MacOS/mac_logging_utils.h` - mesh_log_message() macro for logging (Line 20)

### System Frameworks
- **CoreFoundation.framework** - Required for compilation, provides CFBundle APIs

### External Libraries
- None (uses only system frameworks)

## Key Functions

### is_running_from_bundle() - Lines 29-62

**Purpose:** Detect if the current process is running from a macOS application bundle (.app)

**Signature:**
```c
int is_running_from_bundle(void);
```

**Parameters:**
- None

**Return Value:**
- `1` - Binary is running from a .app bundle
- `0` - Binary is running as standalone executable

**Implementation:**
1. **Get Main Bundle** (Lines 33-37): Call `CFBundleGetMainBundle()` to get bundle reference
   - Returns NULL for binaries with no Info.plist
   - Returns non-NULL even for standalone binaries with embedded Info.plist (requires path check)
2. **Get Bundle URL** (Lines 39-43): Convert bundle reference to file system URL
3. **Extract Path** (Lines 45-57): Convert URL to POSIX path string
4. **Check .app Extension** (Lines 53-56): Verify path ends with ".app" to distinguish true bundles
5. **Cleanup** (Lines 57-61): Release CoreFoundation objects to prevent memory leaks

**Thread Safety:** Thread-safe (no shared state, pure function)

**Memory Management:**
- All CoreFoundation objects are released before return
- No dynamic allocations
- Returns simple integer, no cleanup needed by caller

**Notes:**
- **Critical Path Check:** CFBundleGetMainBundle() returns non-NULL for standalone binaries with embedded Info.plist, so the .app extension check is essential
- **Path Suffix Matching:** Uses simple string suffix comparison (`strcmp(path + len - 4, ".app")`)
- **Null Safety:** Guards against NULL at every CoreFoundation call

---

### get_bundle_path() - Lines 64-103

**Purpose:** Retrieve the full file system path to the application bundle root directory

**Signature:**
```c
char* get_bundle_path(void);
```

**Parameters:**
- None

**Return Value:**
- `char*` - Dynamically allocated string containing bundle path (e.g., "/Applications/MeshAgent.app")
- `NULL` - If not running from bundle or error occurred

**Implementation:**
1. **Get Main Bundle** (Lines 66-70): Call `CFBundleGetMainBundle()`, return NULL if none
2. **Get Bundle URL** (Lines 72-76): Convert bundle to URL, return NULL on failure
3. **Convert to Path String** (Lines 78-98):
   - Calculate maximum buffer size needed for UTF-8 encoding
   - Allocate buffer dynamically
   - Convert CFString to C string
   - Free and return NULL if conversion fails
4. **Cleanup** (Lines 98-102): Release all CoreFoundation objects

**Thread Safety:** Thread-safe (no shared state)

**Memory Management:**
- **Caller Responsibility:** MUST call `free()` on returned string
- **Null Return:** Safe to ignore (no cleanup needed)
- **Size Calculation:** Uses `CFStringGetMaximumSizeForEncoding()` to prevent buffer overflows

**Notes:**
- **Dynamic Allocation:** Required because bundle path length is unknown at compile time
- **UTF-8 Encoding:** Handles international characters in bundle paths
- **Failure Modes:** Returns NULL if:
  - Not running from bundle
  - Memory allocation fails
  - String conversion fails (rare)

---

### adjust_working_directory_for_bundle() - Lines 105-150

**Purpose:** Adjust process working directory based on bundle deployment mode

**Signature:**
```c
int adjust_working_directory_for_bundle(void);
```

**Parameters:**
- None

**Return Value:**
- `0` - Success (working directory adjusted or already correct)
- `-1` - Fatal error (could not get bundle path or change directory)

**Implementation:**

**Bundle Mode (Lines 109-142):**
1. **Detect Bundle** (Line 109): Call `is_running_from_bundle()`
2. **Get Bundle Path** (Lines 111-116): Retrieve bundle root path, fail if NULL
3. **Find Parent Directory** (Lines 120-126):
   - Use `strrchr()` to find last '/' separator
   - Validate path structure
   - Temporarily null-terminate to create parent path
4. **Change Directory** (Lines 130-136):
   - Call `chdir()` to parent directory (install location)
   - Log fatal error and return -1 if fails
5. **Restore Path** (Lines 138-141): Restore '/' character for logging
6. **Cleanup** (Line 141): Free allocated bundle path

**Standalone Mode (Lines 143-147):**
- No action needed
- Working directory remains as set by system/parent process
- Logging handled by JavaScript layer

**Thread Safety:** Not thread-safe (modifies global process working directory)

**Memory Management:**
- Frees bundle_path before return in all code paths
- No memory leaks on error paths

**Notes:**
- **Critical Timing:** MUST be called early in main() before any file I/O operations
- **Relative Paths:** After this call, relative paths like "mesh.msh" and "MeshAgent.db" work correctly in both modes
- **Parent Directory Logic:** Bundle at `/Applications/MeshAgent.app` → working directory becomes `/Applications/`
- **Logging Migration:** Previously logged from C, now handled by JavaScript logger module
- **Error Handling:** Caller should exit if returns -1, as continuing will cause file operation failures

## macOS-Specific Implementation Details

### CoreFoundation Bundle APIs

**CFBundleGetMainBundle():**
- Returns bundle object for current process
- Always succeeds (even for non-bundled apps) if Info.plist exists
- Requires .app path verification to distinguish true bundles

**CFBundleCopyBundleURL():**
- Returns file:// URL pointing to bundle root
- Must be released with CFRelease()

**CFURLCopyFileSystemPath():**
- Converts URL to POSIX path string
- Uses kCFURLPOSIXPathStyle for Unix-style paths
- Returns CFStringRef that must be released

**CFStringGetCString():**
- Converts CFString to C string buffer
- Uses UTF-8 encoding for international characters
- Returns false if buffer too small (shouldn't happen with proper sizing)

### Application Bundle Structure

```
MeshAgent.app/              ← Bundle root (get_bundle_path returns this)
├── Contents/
│   ├── Info.plist          ← Bundle metadata
│   ├── MacOS/
│   │   └── meshagent       ← Executable binary (runs from here)
│   └── Resources/
└── [parent directory]      ← Working directory after adjustment
    ├── mesh.msh            ← Config files now accessible via relative paths
    └── MeshAgent.db        ← Database files
```

### Working Directory Behavior

| Deployment Mode | Execution Path | Initial Working Dir | After Adjustment |
|-----------------|----------------|---------------------|------------------|
| Bundle | `/Applications/MeshAgent.app/Contents/MacOS/meshagent` | `Contents/MacOS/` | `/Applications/` |
| Standalone | `/opt/acmemesh/meshagent` | `/opt/acmemesh/` | `/opt/acmemesh/` (unchanged) |

This ensures config files live alongside the bundle/binary in both modes.

### Code Signing Considerations

- No special entitlements required for bundle detection
- CoreFoundation APIs work in both signed and unsigned bundles
- Bundle detection works before any TCC permission checks

## Usage Examples

### Example 1: Startup Sequence (agentcore.c)

```c
#include "MacOS/mac_bundle_detection.h"

int main(int argc, char* argv[]) {
    // CRITICAL: Call this first, before any file I/O
    if (adjust_working_directory_for_bundle() != 0) {
        fprintf(stderr, "FATAL: Could not adjust working directory\n");
        return 1;
    }

    // Now relative paths work correctly in both bundle and standalone modes
    FILE* config = fopen("mesh.msh", "r");  // Works in both modes!

    // Rest of initialization...
    return 0;
}
```

### Example 2: Detecting Bundle Mode

```c
#include "MacOS/mac_bundle_detection.h"
#include <stdio.h>

void configure_ui_mode(void) {
    if (is_running_from_bundle()) {
        printf("Bundle mode: Enable Installation Assistant UI\n");
        // Show GUI elements
        enable_install_ui();
    } else {
        printf("Standalone mode: Headless operation\n");
        // Suppress all GUI
    }
}
```

### Example 3: Getting Bundle Path for Logging

```c
#include "MacOS/mac_bundle_detection.h"
#include <stdio.h>
#include <stdlib.h>

void log_deployment_info(void) {
    char* bundle_path = get_bundle_path();

    if (bundle_path) {
        printf("Deployed as bundle: %s\n", bundle_path);
        free(bundle_path);  // MUST free!
    } else {
        printf("Deployed as standalone binary\n");
    }
}
```

### Example 4: Error Handling

```c
#include "MacOS/mac_bundle_detection.h"
#include <stdio.h>
#include <stdlib.h>

int safe_bundle_detection(void) {
    if (!is_running_from_bundle()) {
        return 0;  // Standalone mode, no bundle path needed
    }

    char* path = get_bundle_path();
    if (!path) {
        fprintf(stderr, "ERROR: Running from bundle but cannot get path\n");
        return -1;
    }

    printf("Bundle path: %s\n", path);
    free(path);
    return 0;
}
```

## Technical Notes

### Architecture Decisions

**Why Dual Deployment Modes?**
- **User-Friendly Bundles:** .app bundles provide macOS-native experience (double-click, Finder integration, Install UI)
- **Automation-Friendly Standalone:** Bare binaries work better for RMM tools (ACME RMM) that copy binaries directly
- **Backward Compatibility:** Legacy installations use standalone binaries

**Why Adjust Working Directory?**
- **Path Consistency:** Config files (.msh, .db) live alongside bundle/binary in both modes
- **Relative Path Safety:** Code can use relative paths without mode detection everywhere
- **Simplicity:** One-time adjustment at startup vs. path logic scattered throughout codebase

**Why .app Extension Check?**
- `CFBundleGetMainBundle()` returns non-NULL for standalone binaries with embedded Info.plist
- Checking path suffix ensures we only detect true application bundles
- Alternative approaches (checking Contents/MacOS structure) are more complex

### Performance Characteristics

- **Negligible Overhead:** Called once at startup, takes <1ms
- **Memory Usage:** Minimal (temporary allocations, immediately freed)
- **No Runtime Impact:** Working directory set once, no ongoing cost

### Security Considerations

**Path Traversal Prevention:**
- Uses CoreFoundation APIs (not user input) for all path operations
- No string concatenation of untrusted data
- `chdir()` validates path existence before changing

**Memory Safety:**
- All CoreFoundation objects explicitly released
- Checks NULL at every allocation
- No buffer overflows (dynamic sizing based on actual string length)

**Privilege Handling:**
- No privilege escalation
- Works at current process privileges
- No TOCTOU vulnerabilities (path not used for security decisions)

### Platform Quirks

**macOS Version Differences:**
- CoreFoundation APIs stable since macOS 10.7
- No version-specific workarounds needed
- Works identically on arm64 and x86_64

**Bundle Path Locations:**
- `/Applications/MeshAgent.app` - User installations
- `/Library/Application Support/ACMEAgent/MeshAgent.app` - RMM installations
- Any custom path - Bundle detection works regardless of location

**Symlink Handling:**
- `CFBundleCopyBundleURL()` resolves symlinks automatically
- Bundle path is always canonical (no symlinks in path)

**Known Issues:**
- None currently

## Cross-References

### Related C Files
- [`mac_logging_utils.c`](mac_logging_utils.md) - Provides mesh_log_message() used for fatal errors
- [`agentcore.c`](../agentcore.md) - Calls adjust_working_directory_for_bundle() at startup

### Related Modules
- [`macOSHelpers.js`](../meshagent-modules/macOSHelpers.js.md) - JavaScript wrapper for bundle detection
- [`logger.js`](../meshagent-modules/logger.js.md) - Logs deployment mode information
- [`security-permissions.js`](../meshagent-modules/security-permissions.js.md) - Uses bundle detection for UI decisions

### Documentation
- [macOS ServiceID System](../macOS-ServiceID-System.md) - Service naming in bundle vs standalone modes
- [macOS Install Assistant](../macos-install-assistant.md) - UI only shown in bundle mode

## Testing

### Unit Tests
Location: No dedicated unit tests (tested via integration)

### Integration Tests
- Build agent as bundle, verify `is_running_from_bundle()` returns 1
- Build agent as standalone, verify returns 0
- Verify working directory changes correctly in bundle mode
- Verify relative file paths work in both modes

### Manual Testing

**Test Bundle Mode:**
1. Build: `make ARCHID=29`
2. Create bundle: `build/tools/macos_build/macos-build_sign_notarize.sh --skip-sign --skip-notary`
3. Run: `build/output/osx-universal-64-app/MeshAgent.app/Contents/MacOS/meshagent -show-install-ui`
4. Verify console shows: "Running from bundle: /path/to/MeshAgent.app"
5. Verify working directory is bundle parent: `pwd` should show bundle directory

**Test Standalone Mode:**
1. Build: `make ARCHID=29`
2. Run: `build/output/meshagent_osx-universal-64`
3. Verify console shows: "Running as standalone binary"
4. Verify working directory unchanged: `pwd` shows current directory

**Test Working Directory:**
```bash
# Bundle mode
cd /tmp
./MeshAgent.app/Contents/MacOS/meshagent -test
# Working directory should be /tmp (bundle parent), not /tmp/MeshAgent.app/Contents/MacOS

# Standalone mode
cd /opt/mesh
./meshagent -test
# Working directory should be /opt/mesh (unchanged)
```

## Summary

bundle_detection.c provides essential runtime detection of macOS deployment modes, enabling MeshAgent to seamlessly support both user-friendly .app bundles and automation-friendly standalone binaries. The automatic working directory adjustment ensures configuration files are found via relative paths in both modes, simplifying file I/O logic throughout the codebase. This dual-mode support is critical for supporting both user installations (with Installation Assistant UI) and RMM tool deployments (headless operation).

---

**Last Updated:** 2025-11-28
**Documented By:** Peet McKinney
**Source File:** `meshcore/MacOS/mac_bundle_detection.c`
**Lines of Code:** 153
**Public API:** 3 functions (is_running_from_bundle, get_bundle_path, adjust_working_directory_for_bundle)
