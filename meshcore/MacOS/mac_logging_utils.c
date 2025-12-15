/*
Shared logging utility for macOS components

Routes log messages to stdout or stderr based on severity level.
*/

#include "mac_logging_utils.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/**
 * Log a message to stdout or stderr based on severity
 *
 * Auto-detects severity from message content:
 * - ERROR/WARN/FATAL/CRITICAL → stderr
 * - Everything else → stdout
 */
void mesh_log_message(const char* format, ...) {
    va_list args;
    va_start(args, format);

    // Determine output stream based on message content
    FILE* output = stdout;  // Default to stdout

    // Check if message contains error/warning keywords
    if (strstr(format, "ERROR") != NULL ||
        strstr(format, "WARN") != NULL ||
        strstr(format, "FATAL") != NULL ||
        strstr(format, "CRITICAL") != NULL) {
        output = stderr;
    }

    // Write to appropriate stream
    vfprintf(output, format, args);
    fflush(output);  // Ensure immediate output

    va_end(args);
}
