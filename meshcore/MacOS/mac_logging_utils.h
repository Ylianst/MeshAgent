#ifndef MAC_LOGGING_UTILS_H
#define MAC_LOGGING_UTILS_H

/**
 * Shared logging utility for macOS components
 *
 * Routes log messages to stdout or stderr based on severity:
 * - ERROR/WARN/FATAL/CRITICAL messages → stderr
 * - All other messages → stdout
 */

/**
 * Log a message to stdout or stderr based on content
 *
 * Auto-detects log level from message content:
 * - If message contains "ERROR", "WARN", "FATAL", or "CRITICAL" → stderr
 * - Otherwise → stdout
 *
 * @param format printf-style format string
 * @param ... variable arguments for format string
 */
void mesh_log_message(const char* format, ...);

#endif // MAC_LOGGING_UTILS_H
