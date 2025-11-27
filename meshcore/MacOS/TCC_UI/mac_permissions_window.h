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
 *
 * Returns:
 *   0 if user clicked "Finish"
 *   1 if user wants "Do not remind me again" (only if checkbox was shown)
 */
int show_tcc_permissions_window(int show_reminder_checkbox);

/**
 * Display the TCC permissions window asynchronously (non-blocking)
 *
 * Spawns a child process with "-tccCheck" flag to show the permissions UI.
 * Returns immediately (non-blocking). The child process will write the
 * "Do not remind me again" preference (0 or 1) to stdout when the window is closed.
 *
 * Uses ILibProcessPipe_Manager_SpawnProcessEx3 to spawn the child process
 * as the specified user (same approach as old -kvm0 implementation).
 *
 * Parameters:
 *   exe_path     - Path to the meshagent executable (for re-execing self)
 *   pipeManager  - ILibProcessPipe manager for spawning child process
 *   uid          - User ID to run the child process as (0 = keep as root)
 *
 * Returns:
 *   File descriptor for reading result from child (stdout pipe read end)
 *   -1 on error (e.g., spawn failed, TCC UI already running)
 */
int show_tcc_permissions_window_async(const char* exe_path, void* pipeManager, int uid);

#ifdef __cplusplus
}
#endif

#endif // MAC_PERMISSIONS_WINDOW_H
