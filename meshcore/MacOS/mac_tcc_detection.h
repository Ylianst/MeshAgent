#ifndef MAC_TCC_DETECTION_H
#define MAC_TCC_DETECTION_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * TCC Permission Status
 *
 * Represents the current status of a TCC permission for the application.
 */
typedef enum {
    TCC_PERMISSION_DENIED = 0,           // Permission explicitly denied
    TCC_PERMISSION_GRANTED_USER = 1,     // Permission granted by user via System Settings
    TCC_PERMISSION_GRANTED_MDM = 2,      // Permission granted by MDM via MDMOverrides.plist
    TCC_PERMISSION_NOT_DETERMINED = 3,   // Permission not yet requested or determined
    TCC_PERMISSION_ERROR = -1            // Error checking permission status
} TCC_PermissionStatus;

/**
 * All TCC Permissions Status
 *
 * Contains the status of all three required TCC permissions.
 */
typedef struct {
    TCC_PermissionStatus fda;               // Full Disk Access
    TCC_PermissionStatus accessibility;     // Accessibility
    TCC_PermissionStatus screen_recording;  // Screen & System Audio Recording
} TCC_AllPermissions;

/**
 * Check Full Disk Access permission
 *
 * Attempts to open TCC.db to verify Full Disk Access for the calling process.
 * If TCC.db can be opened, the calling process has FDA.
 *
 * @return TCC_PERMISSION_GRANTED_USER if FDA is granted, TCC_PERMISSION_DENIED otherwise
 */
TCC_PermissionStatus check_fda_permission(void);

/**
 * Check Accessibility permission
 *
 * Uses AXIsProcessTrusted() to check if the calling process has Accessibility permission.
 *
 * @return TCC_PERMISSION_GRANTED_USER if granted, TCC_PERMISSION_DENIED otherwise
 */
TCC_PermissionStatus check_accessibility_permission(void);

/**
 * Check Screen Recording permission
 *
 * Uses CGPreflightScreenCaptureAccess() to check if the calling process has Screen Recording permission.
 *
 * @return TCC_PERMISSION_GRANTED_USER if granted, TCC_PERMISSION_DENIED otherwise
 */
TCC_PermissionStatus check_screen_recording_permission(void);

/**
 * Check all TCC permissions
 *
 * Convenience function to check all three required TCC permissions at once for the calling process.
 *
 * @return TCC_AllPermissions struct containing status of all permissions
 */
TCC_AllPermissions check_all_permissions(void);

#ifdef __cplusplus
}
#endif

#endif // MAC_TCC_DETECTION_H
