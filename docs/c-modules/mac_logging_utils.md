# mac_logging_utils.c

Centralized logging utility for macOS C components, providing dual-output logging (stderr + file) for debugging installation, upgrade, and TCC permission issues. Ensures real-time console visibility while maintaining persistent log files for post-mortem troubleshooting.

## Platform

**Supported Platforms:**
- macOS (darwin) - Exclusive

**Excluded Platforms:**
- Windows (win32) - Not supported (uses platform-specific macOS logging paths)
- Linux - Not supported
- FreeBSD - Not supported

**Platform Requirements:**
- **Minimum Version:** macOS 10.7+ (standard C library)
- **Architecture:** arm64, x86_64, universal binaries
- **Reason:** macOS-specific logging path (`/tmp/`) and designed for macOS C components

**Exclusion Reasoning:**

This utility is designed specifically for **macOS C logging** in the MeshAgent codebase:

1. **Hardcoded macOS Paths:** Logs to `/tmp/meshagent-install-ui.log` (macOS temp directory convention)
2. **macOS Component Integration:** Used by bundle_detection.c, TCC UI, Install UI (all macOS-only)
3. **Debugging macOS Issues:** Tailored for troubleshooting macOS-specific problems (TCC, bundles, LaunchDaemons)

For cross-platform logging:
- **JavaScript:** Use `logger.js` module (works on all platforms)
- **Windows/Linux C:** Use platform-specific logging mechanisms

This is a simple utility wrapper, not intended for cross-platform use.

## Functionality

### Purpose

Provides a **printf-style logging function** for macOS C code that simultaneously:
- Writes to **stderr** for real-time console output
- Appends to **/tmp/meshagent-install-ui.log** for persistent debugging

### Critical Use Cases

1. **Installation Debugging:** Track Installation Assistant UI steps and failures
2. **Permission Issues:** Log TCC permission checks and FDA/Screen Recording status
3. **Bundle Detection:** Record bundle vs standalone mode detection
4. **Crash Investigation:** Persistent logs survive crashes (flushed immediately)
5. **Upgrade Troubleshooting:** Debug service discovery and LaunchDaemon issues

### Why Dual Output?

**stderr (Real-Time):**
- Visible in Terminal.app when running agent manually
- Captured by Xcode console during development
- Useful for interactive troubleshooting

**File (Persistent):**
- Survives process crashes
- Available for remote debugging (RMM tools can retrieve file)
- Historical record of installation/upgrade attempts
- Explicit flush ensures data written before crashes

### Integration Points

- **bundle_detection.c:** Logs fatal bundle path errors
- **Install UI:** Logs user interactions and authorization events
- **TCC UI:** Logs permission detection results
- **Upgrade operations:** Logs service discovery steps

## Dependencies

### System Headers
- `<stdio.h>` - FILE*, fprintf, vfprintf, fopen, fclose, fflush (Lines 9)
- `<stdarg.h>` - va_list, va_start, va_copy, va_end for variadic functions (Line 10)

### MeshAgent Headers
- `mac_logging_utils.h` - Function declaration and MESH_LOG_FILE constant (Line 8)

### System Frameworks
- None (uses only standard C library)

### External Libraries
- None

## Key Functions

### mesh_log_message() - Lines 19-36

**Purpose:** Log a printf-style formatted message to both stderr and a log file

**Signature:**
```c
void mesh_log_message(const char* format, ...);
```

**Parameters:**
- `format` (const char*): printf-style format string (e.g., "Error: %s at line %d\n")
- `...`: Variable arguments matching format specifiers

**Return Value:**
- None (void function)

**Implementation:**
1. **Initialize va_list** (Lines 20-22):
   - `va_start(args1, format)` - Start variadic argument processing
   - `va_copy(args2, args1)` - Create copy for second vfprintf call (required!)
2. **Write to stderr** (Lines 24-26):
   - `vfprintf(stderr, format, args1)` - Immediate console output
   - `va_end(args1)` - Clean up first argument list
3. **Write to File** (Lines 28-35):
   - Open `/tmp/meshagent-install-ui.log` in append mode ("a")
   - `vfprintf(logFile, format, args2)` - Write formatted output
   - `fflush(logFile)` - **CRITICAL:** Force immediate disk write (crash safety)
   - `fclose(logFile)` - Close file (automatic flush)
   - Silently ignores file open failures (logs still go to stderr)
4. **Cleanup** (Line 35):
   - `va_end(args2)` - Clean up second argument list

**Thread Safety:**
- **Not thread-safe** - Multiple threads calling simultaneously may interleave output
- File operations not protected by mutex
- Acceptable for single-threaded macOS C components (Install UI, TCC UI)

**Memory Management:**
- No dynamic allocations
- va_list automatically cleaned up
- No memory leaks possible

**Notes:**
- **va_copy Required:** Cannot reuse va_list for second vfprintf (undefined behavior)
- **Immediate Flush:** `fflush()` ensures log written before potential crash
- **Silent Failure:** File open errors ignored (stderr output still works)
- **Append Mode:** Multiple processes can safely append to same log file
- **Temporary Location:** `/tmp/` may be cleared on reboot (intentional for transient debugging)

## Constants

### MESH_LOG_FILE - Line 11 (header)

**Definition:**
```c
#define MESH_LOG_FILE "/tmp/meshagent-install-ui.log"
```

**Purpose:** Centralized log file path for all macOS C components

**Location Rationale:**
- **/tmp/** - Standard macOS temporary directory
- **Permissions:** World-writable (root and user processes can both log)
- **Cleanup:** Automatically cleared on reboot (prevents unbounded growth)
- **Visibility:** Easy to find for users troubleshooting issues

**Usage Pattern:**
```c
FILE* logFile = fopen(MESH_LOG_FILE, "a");  // Open in append mode
```

**Alternative Locations Considered:**
- `~/Library/Logs/` - Requires home directory access (doesn't work for root LaunchDaemons)
- `/Library/Logs/` - Requires root privileges to write
- `/var/log/` - Not accessible to user processes
- **/tmp/** - ✅ Works for all privilege levels

## macOS-Specific Implementation Details

### File Permissions
- `/tmp/` directory is world-writable (permissions: 1777, sticky bit set)
- First process to call mesh_log_message() creates log file with process owner
- Subsequent processes can append if file is world-writable (664 or 666 permissions)

### Process Privilege Contexts

| Context | Can Write to stderr? | Can Write to /tmp/? | Use Case |
|---------|---------------------|---------------------|----------|
| Root LaunchDaemon | ✅ (invisible) | ✅ | Service startup logging |
| User GUI Process | ✅ (Terminal) | ✅ | Installation Assistant UI |
| sudo Process | ✅ (Terminal) | ✅ | Manual debugging |
| User LaunchAgent | ✅ (Console.app) | ✅ | KVM permission logging |

### Console.app Integration
- stderr output from LaunchDaemons/LaunchAgents appears in Console.app
- Filter: Search for "meshagent" in Console.app to find logs
- Log file provides superset of Console.app output

### Crash Safety
**Why fflush() is Critical:**
```c
mesh_log_message("[BUNDLE] Attempting to change directory...\n");
chdir(path);  // ← Potential crash here (invalid path)
mesh_log_message("[BUNDLE] Success\n");  // Never reached if crash
```

Without `fflush()`, first message might be buffered and lost on crash. With `fflush()`, first message is guaranteed on disk.

### Performance Implications
- **File Open/Close Per Call:** Intentional trade-off for crash safety
- **Performance Cost:** ~1-2ms per log call (acceptable for infrequent logging)
- **Alternative Considered:** Keep file open (faster but loses logs on crash)

## Usage Examples

### Example 1: Basic Logging (bundle_detection.c)

```c
#include "MacOS/mac_logging_utils.h"

void detect_bundle(void) {
    mesh_log_message("[BUNDLE] Starting bundle detection\n");

    if (is_running_from_bundle()) {
        mesh_log_message("[BUNDLE] Detected application bundle mode\n");
    } else {
        mesh_log_message("[BUNDLE] Detected standalone binary mode\n");
    }
}
```

**Output (stderr + file):**
```
[BUNDLE] Starting bundle detection
[BUNDLE] Detected application bundle mode
```

### Example 2: Error Logging with Details

```c
#include "MacOS/mac_logging_utils.h"

int load_config(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        mesh_log_message("[CONFIG] ERROR: Cannot open %s: %s\n",
                        path, strerror(errno));
        return -1;
    }

    mesh_log_message("[CONFIG] Successfully loaded %s\n", path);
    fclose(f);
    return 0;
}
```

**Output (on error):**
```
[CONFIG] ERROR: Cannot open /etc/mesh.conf: No such file or directory
```

### Example 3: Installation Progress Tracking

```c
#include "MacOS/mac_logging_utils.h"

void install_agent(void) {
    mesh_log_message("[INSTALL] Step 1: Checking permissions\n");
    check_permissions();

    mesh_log_message("[INSTALL] Step 2: Copying bundle to /Applications\n");
    copy_bundle();

    mesh_log_message("[INSTALL] Step 3: Creating LaunchDaemon plist\n");
    create_plist();

    mesh_log_message("[INSTALL] Installation complete\n");
}
```

**Output (shows progress even if process crashes mid-install):**
```
[INSTALL] Step 1: Checking permissions
[INSTALL] Step 2: Copying bundle to /Applications
[INSTALL] Step 3: Creating LaunchDaemon plist
```

### Example 4: Conditional Debug Logging

```c
#include "MacOS/mac_logging_utils.h"

#ifdef DEBUG_BUILD
#define DEBUG_LOG(...) mesh_log_message(__VA_ARGS__)
#else
#define DEBUG_LOG(...) // No-op in release builds
#endif

void complex_operation(void) {
    DEBUG_LOG("[DEBUG] Entering complex_operation\n");
    DEBUG_LOG("[DEBUG] Variable state: x=%d, y=%d\n", x, y);
    // ... implementation ...
    DEBUG_LOG("[DEBUG] Exiting complex_operation\n");
}
```

### Example 5: Viewing Log File

```bash
# Real-time tail (watch log as it's written)
tail -f /tmp/meshagent-install-ui.log

# Full log contents
cat /tmp/meshagent-install-ui.log

# Clear log file
> /tmp/meshagent-install-ui.log  # Truncate to 0 bytes

# Search for errors
grep ERROR /tmp/meshagent-install-ui.log
```

## Technical Notes

### Architecture Decisions

**Why Not Use macOS Unified Logging (os_log)?**
- os_log requires macOS 10.12+ (this code targets 10.7+)
- os_log output harder to retrieve remotely (requires special tools)
- Simple text files easier for users to locate and send
- C stdio more portable across macOS versions

**Why Not Use syslog()?**
- syslog output scattered across system logs (harder to find)
- /tmp/ file is single, obvious location
- syslog may be disabled on some systems
- File approach works identically for root and user processes

**Why Append Mode ("a")?**
- Multiple installation attempts append to same file (full history)
- No need to manage file rotation (cleared on reboot)
- Safe for concurrent access (kernel serializes appends)

### Performance Characteristics

- **Overhead per call:** 1-2ms (file open + write + flush + close)
- **Acceptable use:** Infrequent logging (startup, errors, milestones)
- **Not acceptable for:** High-frequency logging (inner loops, per-frame logging)
- **Disk usage:** Typically <100KB per installation (logs cleared on reboot)

### Security Considerations

**Information Disclosure:**
- Log file may contain file paths (not sensitive)
- Does NOT log credentials, tokens, or user data
- World-readable by design (intended for troubleshooting)

**Denial of Service:**
- No rate limiting (could be abused to fill /tmp/)
- Acceptable risk (requires code execution, /tmp/ typically large)
- Cleared on reboot (no persistent DoS)

**Privilege Escalation:**
- No setuid/setgid operations
- Runs at current process privileges
- No elevation risks

### Platform Quirks

**macOS /tmp/ Directory:**
- Actually a symlink to `/private/tmp/`
- Cleared on reboot (not on logout)
- Sticky bit (1777) prevents non-owners from deleting files

**File Descriptor Limits:**
- Opens and closes file on every call (no fd leak risk)
- Acceptable because logging is infrequent

**Disk Full Scenarios:**
- fopen() fails silently if disk full
- Logs still go to stderr (user sees output)
- No crash risk

**Internationalization:**
- Format strings should be English (diagnostic output)
- Supports UTF-8 in format strings if needed

## Cross-References

### Related C Files
- [`bundle_detection.c`](bundle_detection.md) - Uses mesh_log_message() for fatal bundle errors
- [`mac_tcc_detection.c`](mac_tcc_detection.md) - Logs TCC permission status
- [`mac_authorized_install.m`](mac_authorized_install.md) - Install UI logs installation steps

### Related Modules
- [`logger.js`](../meshagent-modules/logger.js.md) - JavaScript logging module (cross-platform)

### Documentation
- None (simple utility, no architectural docs needed)

## Testing

### Unit Tests
Location: No dedicated unit tests (simple utility, tested via integration)

### Integration Tests
- Verify log file created at `/tmp/meshagent-install-ui.log`
- Verify messages appear in both stderr and file
- Verify fflush() ensures data written immediately

### Manual Testing

**Test Basic Logging:**
```bash
# Build test program
cat > test_logging.c <<EOF
#include "MacOS/mac_logging_utils.h"
int main() {
    mesh_log_message("[TEST] Message 1\n");
    mesh_log_message("[TEST] Message 2 with number: %d\n", 42);
    return 0;
}
EOF

gcc -o test_logging test_logging.c mac_logging_utils.c
./test_logging

# Verify stderr output (should see both messages)
# Verify file output
cat /tmp/meshagent-install-ui.log
# Should contain both messages
```

**Test Crash Safety:**
```bash
# Verify logs survive crashes
cat > test_crash.c <<EOF
#include "MacOS/mac_logging_utils.h"
#include <signal.h>

int main() {
    mesh_log_message("[TEST] About to crash\n");
    raise(SIGSEGV);  // Simulate crash
    mesh_log_message("[TEST] This should NOT appear\n");
    return 0;
}
EOF

gcc -o test_crash test_crash.c mac_logging_utils.c
./test_crash

# Check log file
cat /tmp/meshagent-install-ui.log
# Should contain "About to crash", NOT "This should NOT appear"
```

**Test Concurrent Access:**
```bash
# Run multiple processes simultaneously
for i in {1..5}; do
    (
        build/output/meshagent_osx-universal-64 --some-operation &
    )
done
wait

# Verify log file contains all messages (no corruption)
cat /tmp/meshagent-install-ui.log | wc -l
# Should have messages from all 5 processes
```

## Summary

mac_logging_utils.c provides a simple, reliable dual-output logging mechanism for macOS C components. The combination of real-time stderr output and crash-safe file logging makes it ideal for debugging installation, upgrade, and TCC permission issues where crashes are common and persistent logs are essential. Its simplicity (37 lines) and immediate flush behavior ensure logged data survives process crashes, making it invaluable for post-mortem debugging of macOS agent issues.

---

**Last Updated:** 2025-11-28
**Documented By:** Peet McKinney
**Source File:** `meshcore/MacOS/mac_logging_utils.c`
**Lines of Code:** 37
**Public API:** 1 function (mesh_log_message), 1 constant (MESH_LOG_FILE)
