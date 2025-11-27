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
 * Ensure the process is running as root. If not, relaunch with admin privileges.
 * This function will not return if elevation is needed - it relaunches and exits.
 *
 * @return 0 if already root, negative on error, does not return if elevation succeeds
 */
int ensure_running_as_root(void);

/**
 * Execute meshagent install command with admin privileges
 *
 * Uses macOS Authorization Services to show native authentication dialog
 * and execute: meshagent -install --installPath="<installPath>" --mshPath="<mshFilePath>" --disableUpdate=<0|1> --disableTccCheck=<0|1>
 *
 * @param installPath The directory where MeshAgent should be installed
 * @param mshFilePath The path to the .msh configuration file
 * @param disableUpdate 1 to disable updates, 0 to enable
 * @param disableTccCheck 1 to disable TCC check UI, 0 to enable
 * @return 0 on success, non-zero on failure
 */
int execute_meshagent_install(const char* installPath, const char* mshFilePath, int disableUpdate, int disableTccCheck);

/**
 * Execute meshagent upgrade command with admin privileges
 *
 * Uses macOS Authorization Services to show native authentication dialog
 * and execute: meshagent -upgrade --installPath="<installPath>" --disableUpdate=<0|1> --disableTccCheck=<0|1>
 *
 * @param installPath The directory where the existing MeshAgent is installed
 * @param disableUpdate 1 to disable updates, 0 to enable
 * @param disableTccCheck 1 to disable TCC check UI, 0 to enable
 * @return 0 on success, non-zero on failure
 */
int execute_meshagent_upgrade(const char* installPath, int disableUpdate, int disableTccCheck);

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
