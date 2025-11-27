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
#include <pthread.h>
#include "../../../microstack/ILibSimpleDataStore.h"
#include "../mac_logging_utils.h"  // Shared logging utility
#include "../mac_plist_utils.h"    // Shared plist parsing utility

// Global progress callback with thread safety
static ProgressCallback g_progressCallback = NULL;
static pthread_mutex_t g_progressCallback_mutex = PTHREAD_MUTEX_INITIALIZER;

// Cleanup function called when library/executable unloads
__attribute__((destructor))
static void cleanup_progress_callback(void) {
    pthread_mutex_lock(&g_progressCallback_mutex);
    if (g_progressCallback) {
        Block_release(g_progressCallback);
        g_progressCallback = NULL;
    }
    pthread_mutex_unlock(&g_progressCallback_mutex);
    pthread_mutex_destroy(&g_progressCallback_mutex);
}

void set_progress_callback(ProgressCallback callback) {
    pthread_mutex_lock(&g_progressCallback_mutex);

    if (g_progressCallback) {
        Block_release(g_progressCallback);
        g_progressCallback = NULL;
    }
    if (callback) {
        g_progressCallback = Block_copy(callback);
    }

    pthread_mutex_unlock(&g_progressCallback_mutex);
}

/**
 * Validates an installation path to prevent command injection and path traversal attacks.
 *
 * @param path The path to validate
 * @param errorBuf Buffer to store error message if validation fails
 * @param errorBufSize Size of error buffer
 * @return 1 if path is valid, 0 if invalid
 */
static int validate_installation_path(const char* path, char* errorBuf, size_t errorBufSize) {
    if (path == NULL || path[0] == '\0') {
        snprintf(errorBuf, errorBufSize, "Path is empty");
        return 0;
    }

    // Check path length
    size_t pathLen = strlen(path);
    if (pathLen >= 1024) {
        snprintf(errorBuf, errorBufSize, "Path too long (max 1023 characters)");
        return 0;
    }

    // Check for dangerous characters that could enable command injection
    const char* dangerousChars = ";\n\r`$|&<>(){}[]'\"\\";
    for (const char* p = path; *p != '\0'; p++) {
        if (strchr(dangerousChars, *p)) {
            snprintf(errorBuf, errorBufSize, "Path contains invalid character: '%c'", *p);
            return 0;
        }
    }

    // Check for directory traversal sequences
    if (strstr(path, "..") != NULL) {
        snprintf(errorBuf, errorBufSize, "Path contains directory traversal sequence (..)");
        return 0;
    }

    // Canonicalize path using realpath (resolves symlinks and relative paths)
    char resolved[1024];
    char* canonical = realpath(path, resolved);

    // If realpath fails, path doesn't exist yet - walk up directory tree to find existing ancestor
    if (canonical == NULL) {
        char parentPath[1024];
        snprintf(parentPath, sizeof(parentPath), "%s", path);

        // Walk up the directory tree until we find an existing directory
        while (canonical == NULL) {
            char* lastSlash = strrchr(parentPath, '/');
            if (lastSlash == NULL || lastSlash == parentPath) {
                // Reached root without finding existing directory
                snprintf(errorBuf, errorBufSize, "Cannot validate path - no existing ancestor found");
                return 0;
            }
            *lastSlash = '\0';

            // Try to resolve this parent directory
            canonical = realpath(parentPath, resolved);
        }
    }

    // Verify canonical path is in an allowed location
    // Allow /Applications/, /opt/, /usr/local/, /Library/
    if (strncmp(canonical, "/Applications", 13) != 0 &&
        strncmp(canonical, "/opt", 4) != 0 &&
        strncmp(canonical, "/usr/local", 10) != 0 &&
        strncmp(canonical, "/Library", 8) != 0) {
        mesh_log_message("[AUTH-INSTALL] [WARN] Installation path outside typical locations: %s\n", canonical);
        // Don't reject, just warn - user might have valid reason
    }

    mesh_log_message("[AUTH-INSTALL] Path validation passed: %s -> %s\n", path, canonical);
    return 1;
}

/**
 * Ensure the process is running as root. If not, relaunch with admin privileges.
 * This function will not return if elevation is needed - it relaunches and exits.
 *
 * @return 0 if already root, does not return if elevation needed
 */
int ensure_running_as_root(void) {
    // Already running as root?
    if (getuid() == 0) {
        mesh_log_message("[AUTH-ELEVATE] Already running as root\n");
        return 0;
    }

    mesh_log_message("[AUTH-ELEVATE] Not running as root (uid=%d), requesting elevation\n", getuid());

    // Get path to current executable
    char exePath[1024];
    uint32_t size = sizeof(exePath);
    if (_NSGetExecutablePath(exePath, &size) != 0) {
        mesh_log_message("[AUTH-ELEVATE] Error: Failed to get executable path\n");
        return -1;
    }

    // Create authorization reference
    OSStatus status;
    AuthorizationRef authRef;

    status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
                                  kAuthorizationFlagDefaults, &authRef);
    if (status != errAuthorizationSuccess) {
        mesh_log_message("[AUTH-ELEVATE] Error: Failed to create authorization reference (status: %d)\n", status);
        return -1;
    }

    // Request admin rights - this shows the password dialog
    AuthorizationItem items = {kAuthorizationRightExecute, 0, NULL, 0};
    AuthorizationRights rights = {1, &items};
    AuthorizationFlags flags = kAuthorizationFlagDefaults |
                               kAuthorizationFlagInteractionAllowed |
                               kAuthorizationFlagPreAuthorize |
                               kAuthorizationFlagExtendRights;

    status = AuthorizationCopyRights(authRef, &rights, NULL, flags, NULL);
    if (status != errAuthorizationSuccess) {
        mesh_log_message("[AUTH-ELEVATE] Error: Failed to obtain authorization (status: %d)\n", status);
        if (status == errAuthorizationCanceled) {
            mesh_log_message("[AUTH-ELEVATE] User cancelled authentication\n");
        }
        AuthorizationFree(authRef, kAuthorizationFlagDefaults);
        return -2;  // User cancelled or auth failed
    }

    // Relaunch ourselves with privileges
    // Pass --show-install-ui flag so elevated process knows to show the Install UI
    // (it won't have LAUNCHED_FROM_FINDER env var or detect CMD key)
    char* argv[] = { "--show-install-ui", NULL };

    mesh_log_message("[AUTH-ELEVATE] Relaunching as root: %s\n", exePath);

    FILE* pipe = NULL;
    status = AuthorizationExecuteWithPrivileges(authRef, exePath,
                                                 kAuthorizationFlagDefaults,
                                                 argv, &pipe);

    if (status != errAuthorizationSuccess) {
        mesh_log_message("[AUTH-ELEVATE] Error: Failed to relaunch with privileges (status: %d)\n", status);
        AuthorizationFree(authRef, kAuthorizationFlagDefaults);
        return -3;
    }

    // Close pipe if we got one
    if (pipe) {
        fclose(pipe);
    }

    AuthorizationFree(authRef, kAuthorizationFlagDefaults);

    mesh_log_message("[AUTH-ELEVATE] Elevated process launched, exiting parent\n");

    // Exit this (non-elevated) process - the elevated one will take over
    exit(0);

    // Never reached
    return 0;
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

    char* result = strdup(exePath);
    if (result == NULL) {
        mesh_log_message("[AUTH-INSTALL] Error: Memory allocation failed for executable path\n");
    }
    return result;
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
                // Send to progress callback if set (thread-safe)
                pthread_mutex_lock(&g_progressCallback_mutex);
                ProgressCallback callback = g_progressCallback;
                pthread_mutex_unlock(&g_progressCallback_mutex);

                if (callback) {
                    callback(buffer);
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
                    // Send to progress callback if set (thread-safe)
                    pthread_mutex_lock(&g_progressCallback_mutex);
                    ProgressCallback callback = g_progressCallback;
                    pthread_mutex_unlock(&g_progressCallback_mutex);

                    if (callback) {
                        callback(buffer);
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

int execute_meshagent_install(const char* installPath, const char* mshFilePath, int disableUpdate, int disableTccCheck) {
    if (!installPath || !mshFilePath) {
        mesh_log_message("[AUTH-INSTALL] Error: Invalid parameters\n");
        return -1;
    }

    // Validate paths to prevent command injection and path traversal attacks
    char errorBuf[256];
    if (!validate_installation_path(installPath, errorBuf, sizeof(errorBuf))) {
        mesh_log_message("[AUTH-INSTALL] ERROR: Invalid install path: %s\n", errorBuf);
        return -1;
    }
    if (!validate_installation_path(mshFilePath, errorBuf, sizeof(errorBuf))) {
        mesh_log_message("[AUTH-INSTALL] ERROR: Invalid .msh file path: %s\n", errorBuf);
        return -1;
    }

    // Get path to current executable
    char* exePath = get_executable_path();
    if (!exePath) {
        return -1;
    }

    mesh_log_message("[AUTH-INSTALL] Installing MeshAgent to: %s\n", installPath);
    mesh_log_message("[AUTH-INSTALL] Using config file: %s\n", mshFilePath);
    mesh_log_message("[AUTH-INSTALL] Automatic updates: %s\n", disableUpdate ? "disabled" : "enabled");
    mesh_log_message("[AUTH-INSTALL] TCC Check UI: %s\n", disableTccCheck ? "disabled" : "enabled");

    // Build command arguments
    char installPathArg[2048];
    char mshFileArg[2048];
    char updateArg[64];
    char tccCheckArg[64];
    snprintf(installPathArg, sizeof(installPathArg), "--installPath=%s", installPath);
    snprintf(mshFileArg, sizeof(mshFileArg), "--mshPath=%s", mshFilePath);
    snprintf(updateArg, sizeof(updateArg), "--disableUpdate=%d", disableUpdate);
    snprintf(tccCheckArg, sizeof(tccCheckArg), "--disableTccCheck=%d", disableTccCheck);

    char* argv[] = {
        "-install",
        installPathArg,
        mshFileArg,
        updateArg,
        tccCheckArg,
        NULL
    };

    int result = execute_with_authorization(exePath, argv);
    free(exePath);

    return result;
}

int execute_meshagent_upgrade(const char* installPath, int disableUpdate, int disableTccCheck) {
    if (!installPath) {
        mesh_log_message("[AUTH-INSTALL] Error: Invalid parameter\n");
        return -1;
    }

    // Validate path to prevent command injection and path traversal attacks
    char errorBuf[256];
    if (!validate_installation_path(installPath, errorBuf, sizeof(errorBuf))) {
        mesh_log_message("[AUTH-INSTALL] ERROR: Invalid install path: %s\n", errorBuf);
        return -1;
    }

    // Get path to current executable
    char* exePath = get_executable_path();
    if (!exePath) {
        return -1;
    }

    mesh_log_message("[AUTH-INSTALL] Upgrading MeshAgent at: %s\n", installPath);
    mesh_log_message("[AUTH-INSTALL] Automatic updates: %s\n", disableUpdate ? "disabled" : "enabled");
    mesh_log_message("[AUTH-INSTALL] TCC Check UI: %s\n", disableTccCheck ? "disabled" : "enabled");

    // Build command arguments
    char installPathArg[2048];
    char updateArg[64];
    char tccCheckArg[64];
    snprintf(installPathArg, sizeof(installPathArg), "--installPath=%s", installPath);
    snprintf(updateArg, sizeof(updateArg), "--disableUpdate=%d", disableUpdate);
    snprintf(tccCheckArg, sizeof(tccCheckArg), "--disableTccCheck=%d", disableTccCheck);

    char* argv[] = {
        "-upgrade",
        installPathArg,
        updateArg,
        tccCheckArg,
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
 * Priority: 1. .msh file  2. meshagent.db  3. Default to enabled (return 1)
 *
 * Note: We no longer check LaunchDaemon plist since disableUpdate is now stored
 * in the .msh file rather than as a command-line argument.
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

    // FIRST: Try to read from .msh file
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

    // SECOND: Try to read from meshagent.db
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

/**
 * Read the current disableTccCheck setting from an existing installation
 * Priority: 1. .msh file  2. meshagent.db  3. Default to enabled (return 1)
 *
 * @param installPath Path to the installation directory (must end with /)
 * @return 1 if TCC check should be enabled (checkbox unchecked), 0 if disabled (checkbox checked), -1 on error
 */
int read_existing_tcc_check_setting(const char* installPath) {
    char mshPath[2048];
    char dbPath[2048];
    char buffer[256];
    int result = 1;  // Default to TCC check enabled
    FILE* mshFile = NULL;
    ILibSimpleDataStore db = NULL;

    // Construct paths
    snprintf(mshPath, sizeof(mshPath), "%smeshagent.msh", installPath);
    snprintf(dbPath, sizeof(dbPath), "%smeshagent.db", installPath);

    mesh_log_message("[READ-SETTING] Checking for TCC check settings in: %s\n", installPath);

    // FIRST: Try to read from .msh file
    mshFile = fopen(mshPath, "r");
    if (mshFile != NULL) {
        char line[512];
        while (fgets(line, sizeof(line), mshFile)) {
            // Remove newline
            line[strcspn(line, "\r\n")] = 0;

            // Check if this line is disableTccCheck=...
            if (strncmp(line, "disableTccCheck=", 16) == 0) {
                char* value = line + 16;
                mesh_log_message("[READ-SETTING] Found disableTccCheck in .msh: %s\n", value);

                // If value is "1" or non-empty, TCC check is disabled
                if (value[0] != '\0' && strcmp(value, "0") != 0) {
                    result = 0;  // Checkbox should be checked (disable TCC check)
                } else {
                    result = 1;  // Checkbox should be unchecked (enable TCC check)
                }
                fclose(mshFile);
                return result;
            }
        }
        fclose(mshFile);
        mesh_log_message("[READ-SETTING] No disableTccCheck found in .msh file\n");
    } else {
        mesh_log_message("[READ-SETTING] No .msh file found\n");
    }

    // SECOND: Try to read from meshagent.db
    db = ILibSimpleDataStore_Create(dbPath);
    if (db != NULL) {
        int len = ILibSimpleDataStore_Get(db, "disableTccCheck", buffer, sizeof(buffer));
        if (len > 0) {
            buffer[len] = '\0';
            mesh_log_message("[READ-SETTING] Found disableTccCheck in database: %s\n", buffer);

            // If value is "1", TCC check is disabled
            if (strcmp(buffer, "1") == 0) {
                result = 0;  // Checkbox should be checked (disable TCC check)
            } else {
                result = 1;  // Checkbox should be unchecked (enable TCC check)
            }
        } else {
            mesh_log_message("[READ-SETTING] No disableTccCheck found in database\n");
        }
        ILibSimpleDataStore_Close(db);
    } else {
        mesh_log_message("[READ-SETTING] Could not open meshagent.db\n");
    }

    mesh_log_message("[READ-SETTING] Final TCC check result: %d (1=enable TCC check, 0=disable TCC check)\n", result);
    return result;
}
