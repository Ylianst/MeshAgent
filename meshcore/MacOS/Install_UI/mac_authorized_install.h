#ifndef MAC_AUTHORIZED_INSTALL_H
#define MAC_AUTHORIZED_INSTALL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callback function type for progress updates
 * @param line The output line from the install/upgrade process
 */
typedef void (^ProgressCallback)(const char* line);

/**
 * Set the progress callback block
 * @param callback Block to call with each output line (or NULL to disable)
 */
void set_progress_callback(ProgressCallback callback);

/**
 * Request admin authorization from the user (shows system auth dialog).
 * Must be called on the main thread before install/upgrade.
 *
 * @return 0 on success (user authorized), -1 on failure or user cancelled
 */
int acquire_admin_authorization(void);

/**
 * Release previously acquired admin authorization.
 * Safe to call even if no authorization was acquired.
 */
void release_admin_authorization(void);

/**
 * Execute meshagent install command
 *
 * Executes: meshagent -install --installPath="<installPath>" --mshPath="<mshFilePath>" --disableUpdate=<0|1> --disableTccCheck=<0|1> [--log=3] [--meshAgentLogging=1]
 *
 * @param installPath The directory where MeshAgent should be installed
 * @param mshFilePath The path to the .msh configuration file
 * @param disableUpdate 1 to disable updates, 0 to enable
 * @param disableTccCheck 1 to disable TCC check UI, 0 to enable
 * @param verboseLogging 1 to enable --log=3, 0 to disable
 * @param meshAgentLogging 1 to enable --meshAgentLogging=1, 0 to disable
 * @return 0 on success, non-zero on failure
 */
int execute_meshagent_install(const char* installPath, const char* mshFilePath, int disableUpdate, int disableTccCheck, int verboseLogging, int meshAgentLogging);

/**
 * Execute meshagent upgrade command
 *
 * Executes: meshagent -upgrade --installPath="<installPath>" --disableUpdate=<0|1> --disableTccCheck=<0|1> [--log=3] [--meshAgentLogging=1]
 *
 * @param installPath The directory where the existing MeshAgent is installed
 * @param disableUpdate 1 to disable updates, 0 to enable
 * @param disableTccCheck 1 to disable TCC check UI, 0 to enable
 * @param verboseLogging 1 to enable --log=3, 0 to disable
 * @param meshAgentLogging 1 to enable --meshAgentLogging=1, 0 to disable
 * @return 0 on success, non-zero on failure
 */
int execute_meshagent_upgrade(const char* installPath, int disableUpdate, int disableTccCheck, int verboseLogging, int meshAgentLogging);

/**
 * Execute meshagent uninstall command
 *
 * Executes: meshagent -uninstall --installPath="<installPath>" [--log=3]
 * or:       meshagent -funinstall --installPath="<installPath>" [--log=3]
 *
 * @param installPath The directory where the existing MeshAgent is installed
 * @param fullUninstall 1 for full uninstall (-funinstall), 0 for standard (-uninstall)
 * @param verboseLogging 1 to enable --log=3, 0 to disable
 * @return 0 on success, non-zero on failure
 */
int execute_meshagent_uninstall(const char* installPath, int fullUninstall, int verboseLogging);

/**
 * Read the current disableUpdate setting from an existing installation
 *
 * Checks in priority order: 1. .msh file  2. meshagent.db  3. Default to enabled
 *
 * @param installPath The directory where MeshAgent is installed (must end with /)
 * @return 1 if updates should be enabled, 0 if disabled, -1 on error
 */
int read_existing_update_setting(const char* installPath);

/**
 * Read the current disableTccCheck setting from an existing installation
 *
 * Checks in priority order: 1. .msh file  2. meshagent.db  3. Default to enabled
 *
 * @param installPath The directory where MeshAgent is installed (must end with /)
 * @return 1 if TCC check should be enabled, 0 if disabled, -1 on error
 */
int read_existing_tcc_check_setting(const char* installPath);

#ifdef __cplusplus
}
#endif

#endif // MAC_AUTHORIZED_INSTALL_H
