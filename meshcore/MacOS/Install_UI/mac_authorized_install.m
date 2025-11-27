#include "mac_authorized_install.h"
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include "../../../microstack/ILibSimpleDataStore.h"
#include "../mac_logging_utils.h"  // Shared logging utility
#include "../mac_plist_utils.h"    // Shared plist parsing utility

// Global progress callback
static ProgressCallback g_progressCallback = NULL;

// Cleanup function called when library/executable unloads
__attribute__((destructor))
static void cleanup_progress_callback(void) {
    if (g_progressCallback) {
        Block_release(g_progressCallback);
        g_progressCallback = NULL;
    }
}

void set_progress_callback(ProgressCallback callback) {
    if (g_progressCallback) {
        Block_release(g_progressCallback);
        g_progressCallback = NULL;
    }
    if (callback) {
        g_progressCallback = Block_copy(callback);
    }
}

/**
 * Get the path to the current executable
 */
static char* get_executable_path(void) {
    char exePath[1024];
    uint32_t size = sizeof(exePath);

    if (_NSGetExecutablePath(exePath, &size) != 0) {
        mesh_log_message("[AUTH-INSTALL] Error: Failed to get executable path\n");
        return NULL;
    }

    return strdup(exePath);
}

/**
 * Execute a command with admin privileges using Authorization Services
 */
static int execute_with_authorization(const char* executable, char* const argv[]) {
    OSStatus status;
    AuthorizationRef authRef;

    // Create authorization reference
    status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
                                  kAuthorizationFlagDefaults, &authRef);
    if (status != errAuthorizationSuccess) {
        mesh_log_message("[AUTH-INSTALL] Error: Failed to create authorization reference (status: %d)\n", status);
        return -1;
    }

    // Request admin rights
    AuthorizationItem items = {kAuthorizationRightExecute, 0, NULL, 0};
    AuthorizationRights rights = {1, &items};
    AuthorizationFlags flags = kAuthorizationFlagDefaults |
                               kAuthorizationFlagInteractionAllowed |
                               kAuthorizationFlagPreAuthorize |
                               kAuthorizationFlagExtendRights;

    status = AuthorizationCopyRights(authRef, &rights, NULL, flags, NULL);
    if (status != errAuthorizationSuccess) {
        mesh_log_message("[AUTH-INSTALL] Error: Failed to obtain authorization (status: %d)\n", status);
        if (status == errAuthorizationCanceled) {
            mesh_log_message("[AUTH-INSTALL] User cancelled authentication\n");
        }
        AuthorizationFree(authRef, kAuthorizationFlagDefaults);
        return -2;
    }

    // Execute the command with privileges
    mesh_log_message("[AUTH-INSTALL] Executing: %s", executable);
    for (int i = 0; argv[i] != NULL; i++) {
        mesh_log_message(" %s", argv[i]);
    }
    mesh_log_message("\n");

    FILE* pipe = NULL;
    status = AuthorizationExecuteWithPrivileges(authRef, executable,
                                                 kAuthorizationFlagDefaults,
                                                 argv, &pipe);

    if (status != errAuthorizationSuccess) {
        mesh_log_message("[AUTH-INSTALL] Error: Failed to execute command (status: %d)\n", status);
        AuthorizationFree(authRef, kAuthorizationFlagDefaults);
        return -3;
    }

    // Wait for process and read output simultaneously
    mesh_log_message("[AUTH-INSTALL] [%ld] Starting upgrade process...\n", time(NULL));

    // Set pipe to non-blocking mode if we have one
    int fd = -1;
    if (pipe) {
        fd = fileno(pipe);
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    int waitStatus;
    time_t startWait = time(NULL);
    int waitTimeoutSeconds = 120;  // 2 minute timeout total
    pid_t result;
    char buffer[256];

    // Read from pipe and wait for process simultaneously
    while (difftime(time(NULL), startWait) < waitTimeoutSeconds) {
        // Try to read from pipe if available
        if (pipe) {
            while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
                // Send to progress callback if set
                if (g_progressCallback) {
                    g_progressCallback(buffer);
                }
            }
        }

        // Check if process has exited
        result = waitpid(-1, &waitStatus, WNOHANG);

        if (result > 0) {
            // Process exited - read any remaining output
            mesh_log_message("[AUTH-INSTALL] [%ld] Process exited (PID=%d), reading remaining output...\n", time(NULL), result);
            if (pipe) {
                while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
                    if (g_progressCallback) {
                        g_progressCallback(buffer);
                    }
                }
                fclose(pipe);
            }
            break;
        } else if (result < 0) {
            // Error or no child processes
            mesh_log_message("[AUTH-INSTALL] [%ld] ✗ No child process found (errno=%d)\n", time(NULL), errno);
            if (pipe) fclose(pipe);
            break;
        }

        // result == 0 means child is still running
        usleep(100000);  // Sleep 100ms before next check
    }

    // Handle timeout case
    if (result == 0) {
        mesh_log_message("[AUTH-INSTALL] [%ld] ⏱ Process timed out after %d seconds\n", time(NULL), waitTimeoutSeconds);
        if (pipe) fclose(pipe);
    }

    // Clean up
    AuthorizationFree(authRef, kAuthorizationFlagDefaults);

    mesh_log_message("[AUTH-INSTALL] [%ld] Wait loop exited: result=%d, WIFEXITED=%d\n",
            time(NULL), result, result > 0 ? WIFEXITED(waitStatus) : 0);

    if (result > 0 && WIFEXITED(waitStatus)) {
        int exitCode = WEXITSTATUS(waitStatus);
        mesh_log_message("[AUTH-INSTALL] [%ld] ✓ Command completed with exit code: %d\n", time(NULL), exitCode);
        return exitCode;
    } else if (result > 0 && WIFSIGNALED(waitStatus)) {
        // Process was killed by a signal
        int signal = WTERMSIG(waitStatus);
        mesh_log_message("[AUTH-INSTALL] [%ld] ✗ Command was killed by signal %d\n", time(NULL), signal);
        return -4;
    } else if (result == 0) {
        // Timeout - process is still running
        mesh_log_message("[AUTH-INSTALL] [%ld] ⏱ Command timed out but may be running in background\n", time(NULL));
        return 0;  // Return success - the command was launched
    } else {
        mesh_log_message("[AUTH-INSTALL] [%ld] ✗ Command did not exit normally (result=%d)\n", time(NULL), result);
        return -4;
    }
}

int execute_meshagent_install(const char* installPath, const char* mshFilePath, int enableDisableUpdate) {
    if (!installPath || !mshFilePath) {
        mesh_log_message("[AUTH-INSTALL] Error: Invalid parameters\n");
        return -1;
    }

    // Get path to current executable
    char* exePath = get_executable_path();
    if (!exePath) {
        return -1;
    }

    mesh_log_message("[AUTH-INSTALL] Installing MeshAgent to: %s\n", installPath);
    mesh_log_message("[AUTH-INSTALL] Using config file: %s\n", mshFilePath);
    mesh_log_message("[AUTH-INSTALL] Automatic updates: %s\n", enableDisableUpdate ? "enabled" : "disabled");

    // Build command arguments
    char installPathArg[2048];
    char mshFileArg[2048];
    char updateArg[64];
    snprintf(installPathArg, sizeof(installPathArg), "--installPath=%s", installPath);
    snprintf(mshFileArg, sizeof(mshFileArg), "--mshPath=%s", mshFilePath);
    snprintf(updateArg, sizeof(updateArg), "--enableDisableUpdate=%d", enableDisableUpdate);

    char* argv[] = {
        "-install",
        installPathArg,
        mshFileArg,
        updateArg,
        NULL
    };

    int result = execute_with_authorization(exePath, argv);
    free(exePath);

    return result;
}

int execute_meshagent_upgrade(const char* installPath, int enableDisableUpdate) {
    if (!installPath) {
        mesh_log_message("[AUTH-INSTALL] Error: Invalid parameter\n");
        return -1;
    }

    // Get path to current executable
    char* exePath = get_executable_path();
    if (!exePath) {
        return -1;
    }

    mesh_log_message("[AUTH-INSTALL] Upgrading MeshAgent at: %s\n", installPath);
    mesh_log_message("[AUTH-INSTALL] Automatic updates: %s\n", enableDisableUpdate ? "enabled" : "disabled");

    // Build command arguments
    char installPathArg[2048];
    char updateArg[64];
    snprintf(installPathArg, sizeof(installPathArg), "--installPath=%s", installPath);
    snprintf(updateArg, sizeof(updateArg), "--enableDisableUpdate=%d", enableDisableUpdate);

    char* argv[] = {
        "-upgrade",
        installPathArg,
        updateArg,
        NULL
    };

    int result = execute_with_authorization(exePath, argv);
    free(exePath);

    return result;
}

/**
 * Helper to scan LaunchDaemons and find disableUpdate setting in plist
 * Returns: 1 if found and should enable updates, 0 if found and should disable, -1 if not found
 */
static int read_update_setting_from_launchdaemon(const char* installPath) {
    DIR* dir = opendir("/Library/LaunchDaemons");
    if (!dir) return -1;

    MeshPlistInfo plists[100];
    int plistCount = 0;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL && plistCount < 100) {
        if (strstr(entry->d_name, ".plist") == NULL) continue;

        char plistPath[1024];
        snprintf(plistPath, sizeof(plistPath), "/Library/LaunchDaemons/%s", entry->d_name);

        MeshPlistInfo info;
        if (mesh_parse_launchdaemon_plist(plistPath, &info)) {
            // Check if this plist contains a path matching our install path
            if (strstr(info.programPath, installPath) != NULL) {
                plists[plistCount++] = info;
            }
        }
    }
    closedir(dir);

    if (plistCount == 0) return -1;

    // Find newest plist
    int newestIndex = 0;
    for (int i = 1; i < plistCount; i++) {
        if (plists[i].modTime > plists[newestIndex].modTime) {
            newestIndex = i;
        }
    }

    mesh_log_message("[READ-SETTING] Found LaunchDaemon plist: %s\n", plists[newestIndex].plistPath);
    mesh_log_message("[READ-SETTING] Has --disableUpdate=1: %s\n", plists[newestIndex].hasDisableUpdate ? "yes" : "no");

    // Return: 0 if updates disabled (checkbox checked), 1 if enabled (checkbox unchecked)
    return plists[newestIndex].hasDisableUpdate ? 0 : 1;
}

/**
 * Read the current disableUpdate setting from an existing installation
 * Priority: 1. LaunchDaemon plist  2. .msh file  3. meshagent.db  4. Default to enabled (return 1)
 *
 * @param installPath Path to the installation directory (must end with /)
 * @return 1 if updates should be enabled (checkbox unchecked), 0 if disabled (checkbox checked), -1 on error
 */
int read_existing_update_setting(const char* installPath) {
    char mshPath[2048];
    char dbPath[2048];
    char buffer[256];
    int result = 1;  // Default to updates enabled
    FILE* mshFile = NULL;
    ILibSimpleDataStore db = NULL;

    // Construct paths
    snprintf(mshPath, sizeof(mshPath), "%smeshagent.msh", installPath);
    snprintf(dbPath, sizeof(dbPath), "%smeshagent.db", installPath);

    mesh_log_message("[READ-SETTING] Checking for update settings in: %s\n", installPath);

    // FIRST: Check LaunchDaemon plist (highest priority)
    int plistResult = read_update_setting_from_launchdaemon(installPath);
    if (plistResult >= 0) {
        mesh_log_message("[READ-SETTING] Using setting from LaunchDaemon plist\n");
        return plistResult;
    }

    // SECOND: Try to read from .msh file
    mshFile = fopen(mshPath, "r");
    if (mshFile != NULL) {
        char line[512];
        while (fgets(line, sizeof(line), mshFile)) {
            // Remove newline
            line[strcspn(line, "\r\n")] = 0;

            // Check if this line is disableUpdate=...
            if (strncmp(line, "disableUpdate=", 14) == 0) {
                char* value = line + 14;
                mesh_log_message("[READ-SETTING] Found disableUpdate in .msh: %s\n", value);

                // If value is "1" or non-empty, updates are disabled
                if (value[0] != '\0' && strcmp(value, "0") != 0) {
                    result = 0;  // Checkbox should be checked (disable updates)
                } else {
                    result = 1;  // Checkbox should be unchecked (enable updates)
                }
                fclose(mshFile);
                return result;
            }
        }
        fclose(mshFile);
        mesh_log_message("[READ-SETTING] No disableUpdate found in .msh file\n");
    } else {
        mesh_log_message("[READ-SETTING] No .msh file found\n");
    }

    // THIRD: Try to read from meshagent.db
    db = ILibSimpleDataStore_Create(dbPath);
    if (db != NULL) {
        int len = ILibSimpleDataStore_Get(db, "disableUpdate", buffer, sizeof(buffer));
        if (len > 0) {
            buffer[len] = '\0';
            mesh_log_message("[READ-SETTING] Found disableUpdate in database: %s\n", buffer);

            // If value is "1" or non-empty, updates are disabled
            if (strcmp(buffer, "1") == 0) {
                result = 0;  // Checkbox should be checked (disable updates)
            } else {
                result = 1;  // Checkbox should be unchecked (enable updates)
            }
        } else {
            mesh_log_message("[READ-SETTING] No disableUpdate found in database\n");
        }
        ILibSimpleDataStore_Close(db);
    } else {
        mesh_log_message("[READ-SETTING] Could not open meshagent.db\n");
    }

    mesh_log_message("[READ-SETTING] Final result: %d (1=enable updates, 0=disable updates)\n", result);
    return result;
}
