/*
Shared logging utility for macOS components

Provides centralized logging to both stderr and a file for troubleshooting
installation, upgrade, and TCC permission issues.
*/

#include "mac_logging_utils.h"
#include <stdio.h>
#include <stdarg.h>

/**
 * Log a message to both stderr and the log file
 *
 * This function duplicates the output to both destinations to ensure:
 * 1. Real-time visibility in console/terminal (stderr)
 * 2. Persistent record for post-mortem debugging (log file)
 */
void mesh_log_message(const char* format, ...) {
    va_list args1, args2;
    va_start(args1, format);
    va_copy(args2, args1);

    // Log to stderr for real-time monitoring
    vfprintf(stderr, format, args1);
    va_end(args1);

    // Log to file for persistent troubleshooting
    FILE* logFile = fopen(MESH_LOG_FILE, "a");
    if (logFile) {
        vfprintf(logFile, format, args2);
        fflush(logFile);  // Ensure immediate write (important for crash debugging)
        fclose(logFile);
    }
    va_end(args2);
}
