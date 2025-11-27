#ifndef MAC_PLIST_UTILS_H
#define MAC_PLIST_UTILS_H

#include <time.h>

/**
 * Shared plist parsing utilities for macOS
 *
 * Provides secure, CoreFoundation-based parsing of LaunchDaemon plists
 * to extract meshagent configuration information.
 */

/**
 * Structure to hold parsed plist information
 */
typedef struct {
    char plistPath[1024];           // Path to the plist file
    char label[256];                 // Label from plist
    char programPath[1024];          // First path in ProgramArguments
    int hasDisableUpdate;            // 1 if --disableUpdate=1 found in ProgramArguments
    time_t modTime;                  // Modification time of plist file
} MeshPlistInfo;

/**
 * Parse a LaunchDaemon plist file and extract meshagent information
 *
 * Uses CoreFoundation APIs for secure, proper plist parsing (no shell injection)
 *
 * @param plistPath Path to the plist file to parse
 * @param info Pointer to MeshPlistInfo structure to fill
 * @return 1 if successfully parsed and contains meshagent info, 0 otherwise
 */
int mesh_parse_launchdaemon_plist(const char* plistPath, MeshPlistInfo* info);

/**
 * Extract the Label value from a plist file
 *
 * @param plistPath Path to the plist file
 * @return Dynamically allocated string containing the label, or NULL on failure
 *         Caller must free() the returned string
 */
char* mesh_plist_get_label(const char* plistPath);

/**
 * Extract the first ProgramArguments path from a plist file
 *
 * @param plistPath Path to the plist file
 * @return Dynamically allocated string containing the program path, or NULL on failure
 *         Caller must free() the returned string
 */
char* mesh_plist_get_program_path(const char* plistPath);

/**
 * Check if ProgramArguments contains a specific argument
 *
 * @param plistPath Path to the plist file
 * @param argument Argument to search for (e.g., "--disableUpdate=1")
 * @return 1 if argument found, 0 otherwise
 */
int mesh_plist_has_argument(const char* plistPath, const char* argument);

#endif // MAC_PLIST_UTILS_H
