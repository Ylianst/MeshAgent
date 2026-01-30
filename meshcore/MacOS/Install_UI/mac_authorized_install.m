#include "mac_authorized_install.h"
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <Block.h>
#include <Security/Authorization.h>
#include "../../../microstack/ILibSimpleDataStore.h"
#include "../mac_logging_utils.h"  // Shared logging utility
#include "../mac_plist_utils.h"    // Shared plist parsing utility

extern char **environ;

// Global authorization reference (acquired on main thread, used by execute functions)
static AuthorizationRef g_authRef = NULL;
static pthread_mutex_t g_authRef_mutex = PTHREAD_MUTEX_INITIALIZER;

// Global progress callback with thread safety
static ProgressCallback g_progressCallback = NULL;
static pthread_mutex_t g_progressCallback_mutex = PTHREAD_MUTEX_INITIALIZER;

// Get base filename from executable path for dynamic .msh/.db naming
static void getAgentBaseName(char *baseName, size_t baseNameSize) {
    char execPath[PATH_MAX];
    uint32_t size = sizeof(execPath);

    if (_NSGetExecutablePath(execPath, &size) != 0) {
        baseName[0] = '\0';  // Empty on failure - caller must handle
        return;
    }

    char *lastSlash = strrchr(execPath, '/');
    const char *filename = lastSlash ? lastSlash + 1 : execPath;

    strncpy(baseName, filename, baseNameSize - 1);
    baseName[baseNameSize - 1] = '\0';

    char *dot = strrchr(baseName, '.');
    if (dot) *dot = '\0';
}

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

int acquire_admin_authorization(void) {
    pthread_mutex_lock(&g_authRef_mutex);

    // Release any existing ref
    if (g_authRef != NULL) {
        AuthorizationFree(g_authRef, kAuthorizationFlagDefaults);
        g_authRef = NULL;
    }

    OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
                                          kAuthorizationFlagDefaults, &g_authRef);
    if (status != errAuthorizationSuccess) {
        mesh_log_message("[AUTH-INSTALL] Error: Failed to create authorization reference (status=%d)\n", status);
        g_authRef = NULL;
        pthread_mutex_unlock(&g_authRef_mutex);
        return -1;
    }

    AuthorizationItem right = { "system.privilege.admin", 0, NULL, 0 };
    AuthorizationRights rights = { 1, &right };
    AuthorizationFlags flags = kAuthorizationFlagDefaults |
                               kAuthorizationFlagInteractionAllowed |
                               kAuthorizationFlagPreAuthorize |
                               kAuthorizationFlagExtendRights;

    status = AuthorizationCopyRights(g_authRef, &rights, NULL, flags, NULL);
    if (status != errAuthorizationSuccess) {
        mesh_log_message("[AUTH-INSTALL] Admin authorization denied or failed (status=%d)\n", status);
        AuthorizationFree(g_authRef, kAuthorizationFlagDefaults);
        g_authRef = NULL;
        pthread_mutex_unlock(&g_authRef_mutex);
        return -1;
    }

    mesh_log_message("[AUTH-INSTALL] Admin authorization acquired\n");
    pthread_mutex_unlock(&g_authRef_mutex);
    return 0;
}

void release_admin_authorization(void) {
    pthread_mutex_lock(&g_authRef_mutex);
    if (g_authRef != NULL) {
        AuthorizationFree(g_authRef, kAuthorizationFlagDefaults);
        g_authRef = NULL;
        mesh_log_message("[AUTH-INSTALL] Admin authorization released\n");
    }
    pthread_mutex_unlock(&g_authRef_mutex);
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
 * Execute a command with admin privileges using the previously acquired authorization.
 * Uses AuthorizationExecuteWithPrivileges to run as root.
 * Reads stdout via the FILE* returned by the API and sends lines to the progress callback.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static int execute_command(const char* executable, char* const argv[]) {
    // Build full command string for logging
    char cmdLine[4096];
    int cmdLen = snprintf(cmdLine, sizeof(cmdLine), "%s", executable);
    int hasVerbose = 0;
    for (int i = 0; argv[i] != NULL; i++) {
        if (cmdLen < (int)sizeof(cmdLine) - 1) {
            cmdLen += snprintf(cmdLine + cmdLen, sizeof(cmdLine) - cmdLen, " %s", argv[i]);
        }
        if (strcmp(argv[i], "--log=3") == 0) hasVerbose = 1;
    }

    mesh_log_message("[AUTH-INSTALL] Executing: %s\n", cmdLine);

    // When verbose logging is enabled, send full command to progress UI
    if (hasVerbose) {
        pthread_mutex_lock(&g_progressCallback_mutex);
        ProgressCallback cb = g_progressCallback;
        pthread_mutex_unlock(&g_progressCallback_mutex);
        if (cb) {
            char cbLine[4200];
            snprintf(cbLine, sizeof(cbLine), "Command: %s\n\n", cmdLine);
            cb(cbLine);
        }
    }

    pthread_mutex_lock(&g_authRef_mutex);
    AuthorizationRef authRef = g_authRef;
    pthread_mutex_unlock(&g_authRef_mutex);

    if (authRef == NULL) {
        mesh_log_message("[AUTH-INSTALL] Error: No admin authorization available. Call acquire_admin_authorization() first.\n");
        return -1;
    }

    // Strip LAUNCHED_FROM_FINDER so the child process doesn't try to show
    // the install UI instead of processing command-line arguments
    char* savedLFF = NULL;
    const char* lffVal = getenv("LAUNCHED_FROM_FINDER");
    if (lffVal != NULL) {
        savedLFF = strdup(lffVal);
        unsetenv("LAUNCHED_FROM_FINDER");
    }

    FILE* pipeFile = NULL;
    OSStatus status = AuthorizationExecuteWithPrivileges(
        authRef,
        executable,
        kAuthorizationFlagDefaults,
        argv,
        &pipeFile
    );

    // Restore LAUNCHED_FROM_FINDER (child already spawned)
    if (savedLFF != NULL) {
        setenv("LAUNCHED_FROM_FINDER", savedLFF, 1);
        free(savedLFF);
        savedLFF = NULL;
    }

    if (status != errAuthorizationSuccess) {
        mesh_log_message("[AUTH-INSTALL] Error: AuthorizationExecuteWithPrivileges failed (status=%d)\n", status);
        return -3;
    }

    mesh_log_message("[AUTH-INSTALL] [%ld] Privileged process launched\n", time(NULL));

    // Read output from pipe
    if (pipeFile != NULL) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipeFile) != NULL) {
            pthread_mutex_lock(&g_progressCallback_mutex);
            ProgressCallback callback = g_progressCallback;
            pthread_mutex_unlock(&g_progressCallback_mutex);

            if (callback) {
                callback(buffer);
            }
        }
        fclose(pipeFile);
    }

    // AuthorizationExecuteWithPrivileges doesn't give us the child PID directly,
    // so we wait for any child to collect the exit status
    int waitStatus;
    pid_t childPid = wait(&waitStatus);

    if (childPid > 0 && WIFEXITED(waitStatus)) {
        int exitCode = WEXITSTATUS(waitStatus);
        mesh_log_message("[AUTH-INSTALL] [%ld] Command completed with exit code: %d\n", time(NULL), exitCode);
        return exitCode;
    } else if (childPid > 0 && WIFSIGNALED(waitStatus)) {
        int sig = WTERMSIG(waitStatus);
        mesh_log_message("[AUTH-INSTALL] [%ld] Command was killed by signal %d\n", time(NULL), sig);
        return -4;
    } else {
        mesh_log_message("[AUTH-INSTALL] [%ld] Command did not exit normally (childPid=%d, errno=%d)\n", time(NULL), childPid, errno);
        return -4;
    }
}
#pragma clang diagnostic pop

int execute_meshagent_install(const char* installPath, const char* mshFilePath, int disableUpdate, int disableTccCheck, int verboseLogging, int meshAgentLogging) {
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
    mesh_log_message("[AUTH-INSTALL] Verbose logging: %s\n", verboseLogging ? "enabled" : "disabled");
    mesh_log_message("[AUTH-INSTALL] MeshAgent logging: %s\n", meshAgentLogging ? "enabled" : "disabled");

    // Build command arguments
    char installPathArg[2048];
    char mshFileArg[2048];
    char updateArg[64];
    char tccCheckArg[64];
    char logArg[64];
    char meshAgentLogArg[64];
    snprintf(installPathArg, sizeof(installPathArg), "--installPath=%s", installPath);
    snprintf(mshFileArg, sizeof(mshFileArg), "--mshPath=%s", mshFilePath);
    snprintf(updateArg, sizeof(updateArg), "--disableUpdate=%d", disableUpdate);
    snprintf(tccCheckArg, sizeof(tccCheckArg), "--disableTccCheck=%d", disableTccCheck);
    snprintf(logArg, sizeof(logArg), "--log=3");
    snprintf(meshAgentLogArg, sizeof(meshAgentLogArg), "--meshAgentLogging=1");

    char* argv[9]; // max: command + path + msh + update + tcc + log + meshlog + NULL
    int argc = 0;
    argv[argc++] = "-install";
    argv[argc++] = installPathArg;
    argv[argc++] = mshFileArg;
    argv[argc++] = updateArg;
    argv[argc++] = tccCheckArg;
    if (verboseLogging) { argv[argc++] = logArg; }
    if (meshAgentLogging) { argv[argc++] = meshAgentLogArg; }
    argv[argc] = NULL;

    int result = execute_command(exePath, argv);
    free(exePath);

    return result;
}

int execute_meshagent_upgrade(const char* installPath, int disableUpdate, int disableTccCheck, int verboseLogging, int meshAgentLogging) {
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
    mesh_log_message("[AUTH-INSTALL] Verbose logging: %s\n", verboseLogging ? "enabled" : "disabled");
    mesh_log_message("[AUTH-INSTALL] MeshAgent logging: %s\n", meshAgentLogging ? "enabled" : "disabled");

    // Build command arguments
    char installPathArg[2048];
    char updateArg[64];
    char tccCheckArg[64];
    char logArg[64];
    char meshAgentLogArg[64];
    snprintf(installPathArg, sizeof(installPathArg), "--installPath=%s", installPath);
    snprintf(updateArg, sizeof(updateArg), "--disableUpdate=%d", disableUpdate);
    snprintf(tccCheckArg, sizeof(tccCheckArg), "--disableTccCheck=%d", disableTccCheck);
    snprintf(logArg, sizeof(logArg), "--log=3");
    snprintf(meshAgentLogArg, sizeof(meshAgentLogArg), "--meshAgentLogging=1");

    char* argv[8]; // max: command + path + update + tcc + log + meshlog + NULL
    int argc = 0;
    argv[argc++] = "-upgrade";
    argv[argc++] = installPathArg;
    argv[argc++] = updateArg;
    argv[argc++] = tccCheckArg;
    if (verboseLogging) { argv[argc++] = logArg; }
    if (meshAgentLogging) { argv[argc++] = meshAgentLogArg; }
    argv[argc] = NULL;

    int result = execute_command(exePath, argv);
    free(exePath);

    return result;
}

int execute_meshagent_uninstall(const char* installPath, int fullUninstall, int verboseLogging) {
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

    mesh_log_message("[AUTH-INSTALL] %s MeshAgent at: %s\n",
                     fullUninstall ? "Fully uninstalling" : "Uninstalling", installPath);
    mesh_log_message("[AUTH-INSTALL] Verbose logging: %s\n", verboseLogging ? "enabled" : "disabled");

    // Build command arguments
    char installPathArg[2048];
    char logArg[64];
    snprintf(installPathArg, sizeof(installPathArg), "--installPath=%s", installPath);
    snprintf(logArg, sizeof(logArg), "--log=3");

    char* argv[5]; // max: command + path + log + NULL
    int argc = 0;
    argv[argc++] = fullUninstall ? "-funinstall" : "-uninstall";
    argv[argc++] = installPathArg;
    if (verboseLogging) { argv[argc++] = logArg; }
    argv[argc] = NULL;

    int result = execute_command(exePath, argv);
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

    // Derive agent base name from current executable
    char exePath[1024];
    uint32_t exeSize = sizeof(exePath);
    const char* baseName = "meshagent";
    if (_NSGetExecutablePath(exePath, &exeSize) == 0) {
        const char* slash = strrchr(exePath, '/');
        if (slash) baseName = slash + 1;
    }

    MeshPlistInfo plists[100];
    int plistCount = 0;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL && plistCount < 100) {
        if (strstr(entry->d_name, ".plist") == NULL) continue;

        char plistPath[1024];
        snprintf(plistPath, sizeof(plistPath), "/Library/LaunchDaemons/%s", entry->d_name);

        MeshPlistInfo info;
        if (mesh_parse_launchdaemon_plist(plistPath, &info, baseName)) {
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

    // Get agent base name for dynamic file naming
    char agentBaseName[256];
    getAgentBaseName(agentBaseName, sizeof(agentBaseName));
    if (agentBaseName[0] == '\0') {
        mesh_log_message("[READ-SETTING] ERROR: Failed to get agent base name\n");
        return -1;
    }

    // Construct paths using dynamic base name
    snprintf(mshPath, sizeof(mshPath), "%s%s.msh", installPath, agentBaseName);
    snprintf(dbPath, sizeof(dbPath), "%s%s.db", installPath, agentBaseName);

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

    // Get agent base name for dynamic file naming
    char agentBaseName[256];
    getAgentBaseName(agentBaseName, sizeof(agentBaseName));
    if (agentBaseName[0] == '\0') {
        mesh_log_message("[READ-SETTING] ERROR: Failed to get agent base name\n");
        return -1;
    }

    // Construct paths using dynamic base name
    snprintf(mshPath, sizeof(mshPath), "%s%s.msh", installPath, agentBaseName);
    snprintf(dbPath, sizeof(dbPath), "%s%s.db", installPath, agentBaseName);

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
