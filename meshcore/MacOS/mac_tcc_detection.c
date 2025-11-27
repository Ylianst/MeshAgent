#include "mac_tcc_detection.h"
#include <sqlite3.h>
#include <ApplicationServices/ApplicationServices.h>
#include <CoreGraphics/CoreGraphics.h>
#include <stdio.h>

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

    printf("[TCC-API] check_fda_permission: Attempting to open TCC.db at: %s\n", TCC_DB_PATH);
    // Try to open TCC.db read-only
    // If this succeeds, we have Full Disk Access
    int rc = sqlite3_open_v2(TCC_DB_PATH, &db, SQLITE_OPEN_READONLY, NULL);

    printf("[TCC-API] check_fda_permission: sqlite3_open_v2 returned: %d (SQLITE_OK=%d)\n", rc, SQLITE_OK);

    if (rc == SQLITE_OK) {
        sqlite3_close(db);
        printf("[TCC-API] check_fda_permission: GRANTED (TCC_PERMISSION_GRANTED_USER=%d)\n", TCC_PERMISSION_GRANTED_USER);
        return TCC_PERMISSION_GRANTED_USER;
    }

    // Cannot open TCC.db - no FDA permission
    printf("[TCC-API] check_fda_permission: DENIED (TCC_PERMISSION_DENIED=%d)\n", TCC_PERMISSION_DENIED);
    return TCC_PERMISSION_DENIED;
}

/**
 * Check Accessibility permission
 *
 * Uses the native Accessibility API to check if the calling process
 * has been granted Accessibility permission.
 */
TCC_PermissionStatus check_accessibility_permission(void) {
    printf("[TCC-API] check_accessibility_permission: Calling AXIsProcessTrusted()\n");
    Boolean isTrusted = AXIsProcessTrusted();
    printf("[TCC-API] check_accessibility_permission: AXIsProcessTrusted returned: %d\n", isTrusted);

    TCC_PermissionStatus result = isTrusted ? TCC_PERMISSION_GRANTED_USER : TCC_PERMISSION_DENIED;
    printf("[TCC-API] check_accessibility_permission: Returning %d (%s)\n",
           result, isTrusted ? "GRANTED" : "DENIED");
    return result;
}

/**
 * Check Screen Recording permission
 *
 * Uses the CoreGraphics API to check if the calling process
 * has been granted Screen Recording permission.
 * Requires macOS 10.15+
 */
TCC_PermissionStatus check_screen_recording_permission(void) {
    printf("[TCC-API] check_screen_recording_permission: Calling CGRequestScreenCaptureAccess()\n");
    Boolean hasAccess = CGRequestScreenCaptureAccess();
    printf("[TCC-API] check_screen_recording_permission: CGRequestScreenCaptureAccess returned: %d\n", hasAccess);

    TCC_PermissionStatus result = hasAccess ? TCC_PERMISSION_GRANTED_USER : TCC_PERMISSION_DENIED;
    printf("[TCC-API] check_screen_recording_permission: Returning %d (%s)\n",
           result, hasAccess ? "GRANTED" : "DENIED");
    return result;
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
