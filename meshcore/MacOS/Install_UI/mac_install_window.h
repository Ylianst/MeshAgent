#ifndef MAC_INSTALL_WINDOW_H
#define MAC_INSTALL_WINDOW_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Installation mode selection
 */
typedef enum {
    INSTALL_MODE_UPGRADE = 0,
    INSTALL_MODE_NEW = 1,
    INSTALL_MODE_UNINSTALL = 2
} InstallMode;

/**
 * Installation result structure
 */
typedef struct {
    InstallMode mode;
    char installPath[1024];
    char mshFilePath[1024];
    int disableUpdate;    // 1 to disable updates, 0 to enable
    int disableTccCheck;  // 1 to disable TCC check UI, 0 to enable
    int verboseLogging;   // 1 to enable --log=3, 0 to disable
    int meshAgentLogging; // 1 to enable --meshAgentLogging=1, 0 to disable
    int fullUninstall;    // 1 for full uninstall (-funinstall), 0 for standard (-uninstall)
    int cancelled;  // 1 if user cancelled, 0 if user clicked Install
} InstallResult;

/**
 * Display the MeshAgent Installation Assistant
 *
 * Shows a modal window allowing the user to choose between:
 * - Upgrade existing installation (browse for existing meshagent location)
 * - New installation (browse for install folder + .msh file)
 *
 * Returns:
 *   InstallResult structure with user's selections
 *   cancelled=1 if user clicked Cancel
 *   cancelled=0 if user clicked Install/Upgrade
 */
InstallResult show_install_assistant_window(void);

#ifdef __cplusplus
}
#endif

#endif // MAC_INSTALL_WINDOW_H
