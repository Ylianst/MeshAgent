#ifndef MAC_LOGGING_UTILS_H
#define MAC_LOGGING_UTILS_H

/**
 * Shared logging utility for macOS components
 *
 * Logs messages to both stderr and a log file for troubleshooting
 * installation and upgrade issues.
 */

#define MESH_LOG_FILE "/tmp/meshagent-install-ui.log"

/**
 * Log a message to both stderr and the log file
 *
 * @param format printf-style format string
 * @param ... variable arguments for format string
 */
void mesh_log_message(const char* format, ...);

#endif // MAC_LOGGING_UTILS_H
