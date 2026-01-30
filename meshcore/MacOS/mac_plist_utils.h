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
 * Parse a LaunchDaemon plist file and extract agent information
 *
 * Uses CoreFoundation APIs for secure, proper plist parsing (no shell injection)
 *
 * @param plistPath Path to the plist file to parse
 * @param info Pointer to MeshPlistInfo structure to fill
 * @param agentName Agent binary base name to match in ProgramArguments (e.g., "acmemesh").
 *                  If NULL, defaults to "meshagent" for backward compatibility.
 * @return 1 if successfully parsed and contains matching agent info, 0 otherwise
 */
int mesh_parse_launchdaemon_plist(const char* plistPath, MeshPlistInfo* info, const char* agentName);

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

/**
 * Find the serviceId (plist Label) by scanning a directory for a plist whose
 * ProgramArguments[0] matches the given binary path.
 *
 * @param directory Directory to scan (e.g., "/Library/LaunchDaemons" or "/Library/LaunchAgents")
 * @param binaryPath Absolute path of the binary to match against ProgramArguments[0]
 * @return Dynamically allocated string containing the Label, or NULL if not found
 *         Caller must free() the returned string
 */
char* mesh_plist_find_service_id(const char* directory, const char* binaryPath);

#endif // MAC_PLIST_UTILS_H
