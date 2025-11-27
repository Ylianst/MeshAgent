#include "mac_tcc_detection.h"
#include <sqlite3.h>
#include <ApplicationServices/ApplicationServices.h>
#include <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <unistd.h>

// TCC Database Path
#define TCC_DB_PATH "/Library/Application Support/com.apple.TCC/TCC.db"

/**
 * Check Full Disk Access permission
 *
 * Attempts to open TCC.db. If successful, the calling process has FDA.
 * This is the most reliable FDA check since TCC.db requires FDA to access.
 */
TCC_PermissionStatus check_fda_permission(void) {
    sqlite3 *db = NULL;

    // Try to open TCC.db read-only
    // If this succeeds, we have Full Disk Access
    int rc = sqlite3_open_v2(TCC_DB_PATH, &db, SQLITE_OPEN_READONLY, NULL);

    if (rc == SQLITE_OK) {
        sqlite3_close(db);
        return TCC_PERMISSION_GRANTED_USER;
    }

    // Cannot open TCC.db - no FDA permission
    return TCC_PERMISSION_DENIED;
}

/**
 * Check Accessibility permission
 *
 * Uses the native Accessibility API to check if the calling process
 * has been granted Accessibility permission.
 */
TCC_PermissionStatus check_accessibility_permission(void) {
    Boolean isTrusted = AXIsProcessTrusted();
    return isTrusted ? TCC_PERMISSION_GRANTED_USER : TCC_PERMISSION_DENIED;
}

/**
 * Check Screen Recording permission
 *
 * Uses CGWindowListCopyWindowInfo to check if we can see window names
 * from other processes. This method updates in REAL-TIME without requiring
 * app restart (unlike CGRequestScreenCaptureAccess which returns cached values).
 *
 * OPTIMIZED: Samples only 3 windows to minimize CPU load during polling.
 * If ANY of the 3 sampled windows has a visible name → GRANTED
 * If all 3 are NULL → DENIED
 *
 * This is the industry-standard approach used by Splashtop, TeamViewer, etc.
 * Requires macOS 10.15+
 */
TCC_PermissionStatus check_screen_recording_permission(void) {
    pid_t currentPID = getpid();

    // Get list of all on-screen windows
    CFArrayRef windowList = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID);
    if (!windowList) {
        return TCC_PERMISSION_DENIED;
    }

    CFIndex totalWindows = CFArrayGetCount(windowList);
    int checkedWindows = 0;
    int foundWithName = 0;
    Boolean hasPermission = false;

    // Sample up to 3 windows (skip our own PID, Dock, WindowServer)
    for (CFIndex i = 0; i < totalWindows && checkedWindows < 3; i++) {
        CFDictionaryRef window = (CFDictionaryRef)CFArrayGetValueAtIndex(windowList, i);

        // Get window owner PID
        CFNumberRef pidRef = (CFNumberRef)CFDictionaryGetValue(window, kCGWindowOwnerPID);
        if (!pidRef) continue;

        pid_t windowPID;
        CFNumberGetValue(pidRef, kCFNumberIntType, &windowPID);

        // Skip our own windows
        if (windowPID == currentPID) continue;

        // Get window owner name
        CFStringRef ownerName = (CFStringRef)CFDictionaryGetValue(window, kCGWindowOwnerName);
        if (!ownerName) continue;

        // Skip Dock and WindowServer (they always show window names)
        if (CFStringCompare(ownerName, CFSTR("Dock"), 0) == kCFCompareEqualTo ||
            CFStringCompare(ownerName, CFSTR("WindowServer"), 0) == kCFCompareEqualTo ||
            CFStringCompare(ownerName, CFSTR("Window Server"), 0) == kCFCompareEqualTo) {
            continue;
        }

        // This is a valid window to check
        checkedWindows++;

        // Get window name
        CFStringRef windowName = (CFStringRef)CFDictionaryGetValue(window, kCGWindowName);
        if (windowName && CFStringGetLength(windowName) > 0) {
            // Found a window with visible name - we have permission!
            foundWithName++;
            hasPermission = true;
            break; // Exit immediately on first success
        }
    }

    CFRelease(windowList);

    // If we checked windows but none had visible names → no permission
    if (checkedWindows > 0 && foundWithName == 0) {
        hasPermission = false;
    } else if (checkedWindows == 0) {
        // No valid windows to check (only our own, Dock, WindowServer)
        // Return DENIED but note that we couldn't verify
        hasPermission = false;
    }

    return hasPermission ? TCC_PERMISSION_GRANTED_USER : TCC_PERMISSION_DENIED;
}

/**
 * Check all TCC permissions
 *
 * Convenience function to check all three permissions at once.
 */
TCC_AllPermissions check_all_permissions(void) {
    TCC_AllPermissions result;
    result.fda = check_fda_permission();
    result.accessibility = check_accessibility_permission();
    result.screen_recording = check_screen_recording_permission();
    return result;
}
