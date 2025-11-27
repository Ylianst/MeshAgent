# mac_tcc_detection.c

Real-time TCC (Transparency, Consent, and Control) permission detection for macOS. Provides functions to check Full Disk Access, Accessibility, and Screen Recording permissions without requiring app restart, enabling MeshAgent to guide users through permission grant workflows.

## Description

TCC permission detection utilities that enable MeshAgent's KVM and remote management features to verify and request necessary macOS privacy permissions. Uses native Apple APIs for real-time permission status checks that update immediately when users grant permissions in System Settings.

## Platform

**Supported Platforms:**
- macOS (darwin) - Exclusive
- **Minimum Version:** macOS 10.14+ (Mojave) for FDA, 10.15+ (Catalina) for Screen Recording

**Excluded Platforms:**
- Windows (win32) - No TCC framework
- Linux - No TCC framework
- FreeBSD - No TCC framework

**Platform Requirements:**
- **Reason:** macOS-specific TCC (Transparency, Consent, and Control) privacy framework introduced in macOS 10.14

**Exclusion Reasoning:**

This module is **macOS only** (10.14+) due to:

1. **TCC Framework:** Apple's privacy permission system unique to macOS/iOS
2. **System Settings Integration:** Checks permissions granted in Privacy & Security
3. **CoreGraphics/ApplicationServices:** macOS-specific frameworks for screen access
4. **TCC Database:** `/Library/Application Support/com.apple.TCC/TCC.db` (macOS-only path)

## Functionality

### Purpose

Enables MeshAgent to:
1. **Detect Permission Status:** Check FDA, Accessibility, Screen Recording in real-time
2. **Guide Users:** Show permission UI when permissions missing
3. **Enable KVM:** Screen Recording required for screen capture
4. **Enable Input Control:** Accessibility required for mouse/keyboard input
5. **Enable File Access:** FDA required for accessing user files remotely

### Three TCC Permissions

| Permission | Required For | System Location |
|------------|--------------|-----------------|
| **Full Disk Access** | Access TCC.db, user files | Privacy & Security → Full Disk Access |
| **Accessibility** | Mouse/keyboard control | Privacy & Security → Accessibility |
| **Screen Recording** | Screen capture for KVM | Privacy & Security → Screen & System Audio Recording |

### Real-Time Detection

**Critical Feature:** All checks update **immediately** when user grants permission in System Settings (no app restart required). This enables:
- Live UI updates (permission checkmarks turn green instantly)
- Automatic workflow progression (installation continues after grant)
- Better user experience (no confusing "restart required" messages)

### Integration Points

- **TCC UI (mac_permissions_window.m):** Polls every 3 seconds to update permission display
- **Install UI (mac_authorized_install.m):** Checks permissions before installation
- **KVM (mac_kvm.c):** Verifies Screen Recording before capturing screen
- **security-permissions.js:** JavaScript wrapper for permission checks

## Dependencies

### System Headers
- `<sqlite3.h>` - TCC database access for FDA check (Line 2)
- `<ApplicationServices/ApplicationServices.h>` - AXIsProcessTrusted() for Accessibility (Line 3)
- `<CoreGraphics/CoreGraphics.h>` - CGWindowListCopyWindowInfo() for Screen Recording (Line 4)
- `<stdio.h>` - Not actively used (Line 5)
- `<unistd.h>` - getpid() for process ID (Line 6)

### MeshAgent Headers
- `mac_tcc_detection.h` - Enum definitions and function declarations (Line 1)

### System Frameworks
- **ApplicationServices.framework** - Accessibility APIs
- **CoreGraphics.framework** - Screen capture APIs
- **libsqlite3.dylib** - SQLite3 library (system-provided)

### External Libraries
- None (all system frameworks)

## Key Enums and Structures

### TCC_PermissionStatus - Lines 13-19 (header)

**Purpose:** Represents permission grant status

**Definition:**
```c
typedef enum {
    TCC_PERMISSION_DENIED = 0,           // Explicitly denied by user
    TCC_PERMISSION_GRANTED_USER = 1,     // Granted in System Settings
    TCC_PERMISSION_GRANTED_MDM = 2,      // Granted via MDM profile
    TCC_PERMISSION_NOT_DETERMINED = 3,   // Never requested
    TCC_PERMISSION_ERROR = -1            // Error checking status
} TCC_PermissionStatus;
```

**Values:**
- `DENIED (0)` - User clicked "Don't Allow" or removed permission
- `GRANTED_USER (1)` - User enabled in Privacy & Security settings
- `GRANTED_MDM (2)` - IT admin deployed MDMOverrides.plist (not detected by current code)
- `NOT_DETERMINED (3)` - Permission never requested (not detected by current code)
- `ERROR (-1)` - System error during check (not used by current code)

**Notes:**
- Current implementation only returns `GRANTED_USER` or `DENIED`
- MDM and NOT_DETERMINED detection not implemented (future enhancement)

### TCC_AllPermissions - Lines 26-30 (header)

**Purpose:** Container for all three permission statuses

**Definition:**
```c
typedef struct {
    TCC_PermissionStatus fda;               // Full Disk Access
    TCC_PermissionStatus accessibility;     // Accessibility
    TCC_PermissionStatus screen_recording;  // Screen & System Audio Recording
} TCC_AllPermissions;
```

## Key Functions

### check_fda_permission() - Lines 17-37

**Purpose:** Check Full Disk Access by attempting to open TCC.db

**Signature:**
```c
TCC_PermissionStatus check_fda_permission(void);
```

**Return Value:**
- `TCC_PERMISSION_GRANTED_USER` - FDA granted (TCC.db accessible)
- `TCC_PERMISSION_DENIED` - FDA denied (TCC.db inaccessible)

**Implementation:**
1. **Attempt Open** (Line 23): `sqlite3_open_v2(TCC_DB_PATH, &db, SQLITE_OPEN_READONLY, NULL)`
2. **Check Success** (Lines 25-27): If `SQLITE_OK` and `db != NULL`, permission granted
3. **Always Close** (Lines 32-34): Close database even on failure (critical for polling)

**Why This Works:**
- TCC.db requires Full Disk Access to open
- Attempting to open read-only is harmless
- Success = FDA granted, failure = FDA denied

**Thread Safety:** Thread-safe (no shared state)

**Memory Management:**
- CRITICAL: Always calls `sqlite3_close()` even on open failure
- Some SQLite versions allocate structures on failed opens
- This function called every 3 seconds by TCC UI (must not leak handles)

**Performance:** ~0.5-1ms per call (acceptable for 3-second polling)

---

### check_accessibility_permission() - Lines 45-48

**Purpose:** Check Accessibility permission using native API

**Signature:**
```c
TCC_PermissionStatus check_accessibility_permission(void);
```

**Return Value:**
- `TCC_PERMISSION_GRANTED_USER` - Accessibility granted
- `TCC_PERMISSION_DENIED` - Accessibility denied

**Implementation:**
- Single line: `AXIsProcessTrusted()` returns Boolean
- Converts Boolean to TCC_PermissionStatus

**Why This Works:**
- `AXIsProcessTrusted()` is Apple's official API for Accessibility check
- Updates immediately when user grants permission
- No caching issues

**Thread Safety:** Thread-safe

**Performance:** Negligible (<0.1ms)

---

### check_screen_recording_permission() - Lines 64-133

**Purpose:** Check Screen Recording permission by testing window name visibility

**Signature:**
```c
TCC_PermissionStatus check_screen_recording_permission(void);
```

**Return Value:**
- `TCC_PERMISSION_GRANTED_USER` - Screen Recording granted (can see window names)
- `TCC_PERMISSION_DENIED` - Screen Recording denied (window names hidden)

**Implementation:**

**Step 1: Get Window List** (Line 68):
- `CGWindowListCopyWindowInfo()` retrieves all on-screen windows
- Returns array of dictionaries with window metadata

**Step 2: Iterate Windows** (Lines 80-115):
- Get window owner PID (Lines 84-88)
- Skip our own windows (Lines 90-91)
- Skip Dock/WindowServer (Lines 98-102) - these always show names
- Check if window has visible name (Lines 108-114)
- **Break immediately on first success** (Line 113) - optimization

**Step 3: Determine Status** (Lines 119-130):
- If checked windows but no names visible → DENIED
- If no valid windows to check → use `CGPreflightScreenCaptureAccess()` fallback
- Otherwise → GRANTED

**Why This Method?**

❌ **Don't use CGRequestScreenCaptureAccess():**
- Returns cached value (doesn't update until app restart)
- Poor user experience (restart required)

✅ **Use window name visibility test:**
- Updates in real-time (immediately after user grants permission)
- No restart required
- Industry standard (Splashtop, TeamViewer, AnyDesk use this)

**Thread Safety:** Thread-safe

**Performance:** ~1-3ms (acceptable for 3-second polling)

**macOS Version Requirements:**
- Window list API: macOS 10.5+
- `CGPreflightScreenCaptureAccess()`: macOS 10.15+

---

### check_all_permissions() - Lines 140-146

**Purpose:** Convenience function to check all three permissions at once

**Signature:**
```c
TCC_AllPermissions check_all_permissions(void);
```

**Return Value:**
- `TCC_AllPermissions` struct with all three statuses

**Implementation:**
- Calls each individual check function
- Populates and returns structure

**Thread Safety:** Thread-safe

## Constants

### TCC_DB_PATH - Line 9

**Definition:**
```c
#define TCC_DB_PATH "/Library/Application Support/com.apple.TCC/TCC.db"
```

**Purpose:** Path to system TCC database

**Access Requirements:**
- Requires Full Disk Access permission to open
- Root processes can access without FDA (not applicable to MeshAgent bundle apps)

## macOS-Specific Implementation Details

### TCC (Transparency, Consent, and Control) Framework

**History:**
- **macOS 10.14 (Mojave):** FDA introduced
- **macOS 10.15 (Catalina):** Screen Recording introduced
- **macOS 11+ (Big Sur):** Additional permissions added

**Permission Storage:**
- `/Library/Application Support/com.apple.TCC/TCC.db` - System database
- `~/Library/Application Support/com.apple.TCC/TCC.db` - User database (deprecated)

**MDM Overrides:**
- `/Library/Application Support/com.apple.TCC/MDMOverrides.plist` - Enterprise deployments
- Allows IT admins to pre-grant permissions
- Not detected by current code (future enhancement)

### System Settings Paths

**macOS 13+ (Ventura):**
- Settings → Privacy & Security → Full Disk Access
- Settings → Privacy & Security → Accessibility
- Settings → Privacy & Security → Screen & System Audio Recording

**macOS 12 and earlier:**
- System Preferences → Security & Privacy → Privacy tab

### Screen Recording Detection Method

**Why Window Name Visibility?**

When Screen Recording is **denied:**
- `CGWindowListCopyWindowInfo()` returns window dictionaries
- `kCGWindowName` key is present but value is **NULL or empty**
- Cannot see titles of other apps' windows

When Screen Recording is **granted:**
- `kCGWindowName` key contains actual window title
- Can see "Safari - Google.com", "Terminal - bash", etc.

**Special Cases:**
- **Dock/WindowServer:** Always show names (even without permission) - must skip
- **Own process windows:** Always show names - must skip
- **No other windows open:** Use `CGPreflightScreenCaptureAccess()` fallback

### Performance Optimization

**Polling Frequency:**
- TCC UI polls every **3 seconds**
- Fast checks essential to avoid UI lag
- Optimizations:
  - FDA check: Open TCC.db (0.5-1ms)
  - Accessibility: Single API call (<0.1ms)
  - Screen Recording: Break on first window with name (1-3ms)

**Memory Management:**
- All CoreFoundation objects released immediately
- SQLite handles closed in all code paths
- No leaks during continuous polling

## Usage Examples

### Example 1: Check All Permissions

```c
#include "mac_tcc_detection.h"
#include <stdio.h>

void display_permission_status(void) {
    TCC_AllPermissions perms = check_all_permissions();

    printf("Full Disk Access: %s\n",
           perms.fda == TCC_PERMISSION_GRANTED_USER ? "✓ Granted" : "✗ Denied");
    printf("Accessibility: %s\n",
           perms.accessibility == TCC_PERMISSION_GRANTED_USER ? "✓ Granted" : "✗ Denied");
    printf("Screen Recording: %s\n",
           perms.screen_recording == TCC_PERMISSION_GRANTED_USER ? "✓ Granted" : "✗ Denied");
}
```

### Example 2: Poll for Permission Changes (TCC UI)

```c
#include "mac_tcc_detection.h"
#include <unistd.h>

void monitor_permissions_loop(void) {
    while (1) {
        TCC_AllPermissions perms = check_all_permissions();

        // Update UI with current status
        update_fda_checkbox(perms.fda == TCC_PERMISSION_GRANTED_USER);
        update_accessibility_checkbox(perms.accessibility == TCC_PERMISSION_GRANTED_USER);
        update_screen_recording_checkbox(perms.screen_recording == TCC_PERMISSION_GRANTED_USER);

        sleep(3);  // Poll every 3 seconds
    }
}
```

### Example 3: Gate KVM on Screen Recording

```c
#include "mac_tcc_detection.h"

int start_screen_capture(void) {
    if (check_screen_recording_permission() != TCC_PERMISSION_GRANTED_USER) {
        fprintf(stderr, "Screen Recording permission required for KVM\n");
        return -1;
    }

    // Permission granted, proceed with screen capture
    return capture_screen();
}
```

### Example 4: Installation Pre-Check

```c
#include "mac_tcc_detection.h"

int verify_permissions_for_install(void) {
    TCC_AllPermissions perms = check_all_permissions();
    int missing = 0;

    if (perms.fda != TCC_PERMISSION_GRANTED_USER) {
        printf("Missing: Full Disk Access\n");
        missing++;
    }
    if (perms.accessibility != TCC_PERMISSION_GRANTED_USER) {
        printf("Missing: Accessibility\n");
        missing++;
    }
    if (perms.screen_recording != TCC_PERMISSION_GRANTED_USER) {
        printf("Missing: Screen Recording\n");
        missing++;
    }

    if (missing > 0) {
        printf("\nGrant permissions in Privacy & Security, then try again.\n");
        return -1;
    }

    return 0;  // All permissions granted
}
```

## Technical Notes

### Architecture Decisions

**Why Three Separate Check Functions?**
- Different permissions required at different times
- FDA needed for installation, Screen Recording only for KVM
- Allows UI to show individual permission status

**Why Real-Time Updates?**
- Better UX (no restart required)
- Guides users through permission grant workflow
- Enables automated installation scripts

**Why SQLite for FDA Check?**
- TCC.db is **the** file that defines FDA requirement
- Most reliable method (no false positives/negatives)
- Attempting read-only open is harmless

### Performance Characteristics

**Polling Overhead:**
- Called every 3 seconds by TCC UI
- ~2-5ms total per check cycle
- Negligible CPU/battery impact

**Memory Usage:**
- Temporary CoreFoundation allocations (released immediately)
- SQLite handle (closed immediately)
- No persistent memory usage

### Security Considerations

**FDA Check Safety:**
- Read-only open (no modifications to TCC.db)
- Graceful failure if FDA denied
- No privilege escalation

**Screen Recording Privacy:**
- Only checks if window **names** are visible
- Does not capture actual screen content
- Does not examine window image data

**No User Prompts:**
- Check functions never trigger system permission dialogs
- Only passive detection (no prompt spam)

### Platform Quirks

**macOS Version Differences:**
- Screen Recording permission added in 10.15 (returns DENIED on 10.14)
- `CGPreflightScreenCaptureAccess()` only available 10.15+
- FDA existed in 10.14 but was less restrictive

**Bundle vs Standalone:**
- FDA check works for both .app bundles and standalone binaries
- Permission granted per bundle identifier or binary path
- Changing bundle location may lose permission grant

**M1/M2 (Apple Silicon):**
- APIs work identically on arm64 and x86_64
- No Rosetta-specific issues

**Known Issues:**
- MDM-granted permissions not detected (only user-granted)
- NOT_DETERMINED status not detected (only GRANTED/DENIED)

## Cross-References

### Related C Files
- [`mac_permissions_window.m`](mac_permissions_window.md) - TCC UI that polls these functions
- [`mac_authorized_install.m`](mac_authorized_install.md) - Installation UI uses permission checks
- [`mac_kvm.c`](mac_kvm.md) - KVM verifies Screen Recording before capture

### Related Modules
- [`security-permissions.js`](../meshagent-modules/security-permissions.js.md) - JavaScript wrapper

### Documentation
- None specific to TCC detection

## Testing

### Manual Testing

**Test FDA Detection:**
```bash
# Without FDA:
./meshagent --check-permissions
# Should show: FDA: ✗ Denied

# Grant FDA:
# 1. Open System Settings
# 2. Privacy & Security → Full Disk Access
# 3. Enable MeshAgent

./meshagent --check-permissions
# Should show: FDA: ✓ Granted (no restart required!)
```

**Test Accessibility Detection:**
```bash
# Without Accessibility:
./meshagent --check-permissions
# Should show: Accessibility: ✗ Denied

# Grant in Privacy & Security → Accessibility
./meshagent --check-permissions
# Should show: Accessibility: ✓ Granted (immediate update)
```

**Test Screen Recording Detection:**
```bash
# Without Screen Recording:
./meshagent --check-permissions
# Should show: Screen Recording: ✗ Denied

# Grant in Privacy & Security → Screen & System Audio Recording
./meshagent --check-permissions
# Should show: Screen Recording: ✓ Granted (immediate update)
```

**Test Polling (TCC UI):**
1. Launch TCC UI without any permissions
2. Observe all three checkboxes are unchecked
3. Grant FDA in System Settings while UI is open
4. Within 3 seconds, FDA checkbox should turn green ✓
5. Repeat for other two permissions

## Summary

mac_tcc_detection.c provides real-time detection of macOS TCC (Transparency, Consent, and Control) permissions required for MeshAgent's KVM and file access features. Using native Apple APIs, it checks Full Disk Access, Accessibility, and Screen Recording permissions with immediate updates when users grant permissions in System Settings (no restart required). The optimized detection methods enable responsive permission UI that guides users through the grant workflow with live feedback.

---

**Last Updated:** 2025-11-28
**Documented By:** Peet McKinney
**Source File:** `meshcore/MacOS/mac_tcc_detection.c`
**Lines of Code:** 147
**Public API:** 4 functions, 2 types (enum, struct)
**macOS Version:** 10.14+ (FDA), 10.15+ (Screen Recording)
