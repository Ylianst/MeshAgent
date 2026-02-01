#ifndef MAC_PERMISSIONS_WINDOW_H
#define MAC_PERMISSIONS_WINDOW_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Display the TCC permissions window
 *
 * Shows a modal window with the required TCC permissions:
 * - Accessibility
 * - Full Disk Access
 * - Screen & System Audio Recording
 *
 * Parameters:
 *   show_reminder_checkbox - If 1, show "Do not remind me again" checkbox
 *                            If 0, hide the checkbox (for explicit SHIFT+click)
 *   exe_path               - Path to meshagent executable (for spawning permission requests)
 *   uid                    - Console user ID (for spawning permission requests as user)
 *
 * Returns:
 *   0 if user clicked "Finish"
 *   1 if user wants "Do not remind me again" (only if checkbox was shown)
 */
int show_tcc_permissions_window(int show_reminder_checkbox, const char* exe_path, int uid);

/**
 * Display the TCC permissions window asynchronously (non-blocking)
 *
 * Spawns a child process with "-check-tcc" flag to show the permissions UI.
 * Uses fire-and-forget spawning via launchctl asuser - no pipe monitoring.
 * The child process reads/writes the "Do not remind me again" preference
 * directly from/to meshagent.db.
 *
 * Uses posix_spawn() to launch: launchctl asuser <uid> <exe_path> -check-tcc
 * This ensures the process runs with:
 *   - euid=0 (root) for database access
 *   - auid=<uid> (user) for TCC permission attribution
 *   - Proper GUI session registration
 *
 * Parameters:
 *   exe_path     - Path to the meshagent executable (for re-execing self)
 *   pipeManager  - Unused (kept for API compatibility)
 *   uid          - User ID to register the process in (for TCC attribution)
 *
 * Returns:
 *   Always -1 (fire-and-forget, no pipe to monitor)
 */
int show_tcc_permissions_window_async(const char* exe_path, void* pipeManager, int uid);

/**
 * Request Accessibility permission (called by -request-accessibility flag)
 *
 * Calls AXIsProcessTrustedWithOptions with kAXTrustedCheckOptionPrompt to
 * trigger the macOS system dialog:
 * "MeshAgent.app would like to control this computer using accessibility features"
 *
 * This function should be called from a process running as the console user
 * (spawned via posix_spawn with setuid).
 *
 * Returns:
 *   0 on success
 */
int request_accessibility_permission(void);

/**
 * Request Screen Recording permission (called by -request-screenrecording flag)
 *
 * Checks if Screen Recording permission is already granted via CGPreflightScreenCaptureAccess.
 * If not granted, calls CGRequestScreenCaptureAccess to trigger the macOS system dialog.
 *
 * This function should be called from a process running as the console user
 * (spawned via posix_spawn with setuid).
 *
 * Returns:
 *   0 on success
 */
int request_screen_recording_permission(void);

#ifdef __cplusplus
}
#endif

#endif // MAC_PERMISSIONS_WINDOW_H
