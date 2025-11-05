/*
OpenFrame File Logger - Duplicates printf to both console and file
Usage: Call enable_file_logging() at the start of main()
*/

#ifndef OPENFRAME_FILE_LOGGER_H
#define OPENFRAME_FILE_LOGGER_H

/* Feature test macros for POSIX functions */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_POSIX) || defined(__APPLE__) || defined(__linux__) || defined(__unix__)
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#endif

#ifdef WIN32
#include <Windows.h>
#include <process.h>
#include <io.h>
#include <fcntl.h>
#endif

/* Macro to ignore return values */
#ifndef ignore_result
#define ignore_result(x) do { if(x) {} } while(0)
#endif

/* Constants */
#define LOG_BUFFER_SIZE 4096
#define LOG_PATH_SIZE 512

/* Global file handle for logging */
static FILE* g_log_file = NULL;

#ifdef WIN32
static int g_original_stdout_fd = -1;
static HANDLE g_tee_thread = INVALID_HANDLE_VALUE;
static int g_pipe_fds[2] = {-1, -1};
static volatile int g_logging_active = 0;
static int g_daemon_mode = 0;  /* Flag to detect daemon mode */

/* Thread function to duplicate output to both console and file */
static DWORD WINAPI tee_thread_func(LPVOID lpParam) {
    char buffer[LOG_BUFFER_SIZE];
    int bytes_read;
    
    (void)lpParam; /* Unused parameter */
    
    while (g_logging_active && (bytes_read = _read(g_pipe_fds[0], buffer, sizeof(buffer))) > 0) {
        /* Write to original stdout (console) - but skip if daemon mode */
        if (!g_daemon_mode && g_original_stdout_fd >= 0) {
            int result = _write(g_original_stdout_fd, buffer, bytes_read);
            if (result < 0) {
                /* If write fails, we're probably in daemon mode */
                g_daemon_mode = 1;
            }
        }
        
        /* Write to log file */
        if (g_log_file != NULL) {
            fwrite(buffer, 1, bytes_read, g_log_file);
            fflush(g_log_file);
        }
    }
    
    return 0;
}
#endif

#if defined(_POSIX) || defined(__APPLE__) || defined(__linux__) || defined(__unix__)
static int g_original_stdout_fd = -1;
static pthread_t g_tee_thread;
static int g_pipe_fds[2] = {-1, -1};
static volatile int g_logging_active = 0;
static int g_daemon_mode = 0;  /* Flag to detect daemon mode */

/* Thread function to duplicate output to both console and file */
static void* tee_thread_func(void* arg) {
    char buffer[LOG_BUFFER_SIZE];
    ssize_t bytes_read;
    
    (void)arg; /* Unused parameter */
    
    while (g_logging_active && (bytes_read = read(g_pipe_fds[0], buffer, sizeof(buffer))) > 0) {
        /* Write to original stdout (console) - but skip if daemon mode */
        if (!g_daemon_mode && g_original_stdout_fd >= 0) {
            ssize_t result = write(g_original_stdout_fd, buffer, bytes_read);
            if (result < 0) {
                /* If write fails, we're probably in daemon mode */
                g_daemon_mode = 1;
            }
        }
        
        /* Write to log file */
        if (g_log_file != NULL) {
            fwrite(buffer, 1, bytes_read, g_log_file);
            fflush(g_log_file);
        }
    }
    
    return NULL;
}
#endif

/*
 * Enable file logging - duplicates stdout and stderr to file AND console
 * All existing printf() calls will write to BOTH destinations
 * 
 * Returns: 1 on success, 0 on failure
 */
static inline int enable_file_logging(const char* log_directory, const char* log_prefix)
{
    char logfile_path[LOG_PATH_SIZE];
    int pid;
    
    /* Check if logging is already enabled */
    if (g_log_file != NULL) {
        printf("WARNING: File logging is already enabled\n");
        return 1;
    }
    
#ifdef WIN32
    pid = _getpid();
#else
    pid = getpid();
#endif

    /* Generate log filename with timestamp */
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    
    if (log_directory != NULL && strlen(log_directory) > 0) {
        snprintf(logfile_path, sizeof(logfile_path), 
                "%s/%s_%04d%02d%02d_%02d%02d%02d_pid%d.log",
                log_directory,
                log_prefix ? log_prefix : "meshagent",
                tm_info->tm_year + 1900,
                tm_info->tm_mon + 1,
                tm_info->tm_mday,
                tm_info->tm_hour,
                tm_info->tm_min,
                tm_info->tm_sec,
                pid);
    } else {
        snprintf(logfile_path, sizeof(logfile_path), 
                "%s_%04d%02d%02d_%02d%02d%02d_pid%d.log",
                log_prefix ? log_prefix : "meshagent",
                tm_info->tm_year + 1900,
                tm_info->tm_mon + 1,
                tm_info->tm_mday,
                tm_info->tm_hour,
                tm_info->tm_min,
                tm_info->tm_sec,
                pid);
    }

    /* Open log file */
    g_log_file = fopen(logfile_path, "a");
    if (g_log_file == NULL) {
        fprintf(stderr, "WARNING: Failed to open log file: %s\n", logfile_path);
        return 0;
    }
    setvbuf(g_log_file, NULL, _IONBF, 0);

    /* Print header to log file */
    fprintf(g_log_file, "========================================\n");
    fprintf(g_log_file, "MeshAgent Log Started\n");
    fprintf(g_log_file, "Time: %04d-%02d-%02d %02d:%02d:%02d\n",
            tm_info->tm_year + 1900,
            tm_info->tm_mon + 1,
            tm_info->tm_mday,
            tm_info->tm_hour,
            tm_info->tm_min,
            tm_info->tm_sec);
    fprintf(g_log_file, "PID: %d\n", pid);
    fprintf(g_log_file, "Log file: %s\n", logfile_path);
    fprintf(g_log_file, "========================================\n\n");
    fflush(g_log_file);

#ifdef WIN32
    /* Create pipe for tee functionality */
    if (_pipe(g_pipe_fds, LOG_BUFFER_SIZE, _O_BINARY) != 0) {
        fprintf(stderr, "WARNING: Failed to create pipe for logging\n");
        fclose(g_log_file);
        g_log_file = NULL;
        return 0;
    }

    /* Save original stdout and check if we're running as service */
    g_original_stdout_fd = _dup(1); /* 1 is stdout */
    if (g_original_stdout_fd < 0) {
        fprintf(g_log_file, "WARNING: Failed to duplicate stdout - running as service\n");
        fflush(g_log_file);
        g_daemon_mode = 1;
    } else {
        /* Check if stdout is redirected (common in service mode) */
        if (!_isatty(g_original_stdout_fd)) {
            /* stdout is not a console - likely service mode */
            g_daemon_mode = 1;
            fprintf(g_log_file, "INFO: Detected service mode - console output disabled\n");
            fflush(g_log_file);
        } else {
            fprintf(g_log_file, "INFO: Console mode detected - output will go to both console and file\n");
            fflush(g_log_file);
        }
    }

    /* Start tee thread */
    g_logging_active = 1;
    g_tee_thread = CreateThread(NULL, 0, tee_thread_func, NULL, 0, NULL);
    if (g_tee_thread == NULL) {
        fprintf(g_log_file, "WARNING: Failed to create logging thread\n");
        fflush(g_log_file);
        if (g_original_stdout_fd >= 0) _close(g_original_stdout_fd);
        _close(g_pipe_fds[0]);
        _close(g_pipe_fds[1]);
        fclose(g_log_file);
        g_log_file = NULL;
        g_logging_active = 0;
        return 0;
    }

    /* Redirect stdout to pipe */
    if (_dup2(g_pipe_fds[1], 1) < 0) { /* 1 is stdout */
        fprintf(g_log_file, "WARNING: Failed to redirect stdout\n");
        fflush(g_log_file);
        g_logging_active = 0;
        _close(g_pipe_fds[1]); /* Close write end to signal thread to exit */
        WaitForSingleObject(g_tee_thread, 1000);
        CloseHandle(g_tee_thread);
        if (g_original_stdout_fd >= 0) _close(g_original_stdout_fd);
        _close(g_pipe_fds[0]);
        fclose(g_log_file);
        g_log_file = NULL;
        return 0;
    }
    
    if (_dup2(g_pipe_fds[1], 2) < 0) { /* 2 is stderr */
        fprintf(g_log_file, "WARNING: Failed to redirect stderr\n");
        fflush(g_log_file);
        if (g_original_stdout_fd >= 0) _dup2(g_original_stdout_fd, 1);
        g_logging_active = 0;
        _close(g_pipe_fds[1]); /* Close write end to signal thread to exit */
        WaitForSingleObject(g_tee_thread, 1000);
        CloseHandle(g_tee_thread);
        if (g_original_stdout_fd >= 0) _close(g_original_stdout_fd);
        _close(g_pipe_fds[0]);
        fclose(g_log_file);
        g_log_file = NULL;
        return 0;
    }
    
    _close(g_pipe_fds[1]);
    
    /* Disable buffering */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
#endif

#if defined(_POSIX) || defined(__APPLE__) || defined(__linux__) || defined(__unix__)
    /* Create pipe for tee functionality */
    if (pipe(g_pipe_fds) != 0) {
        fprintf(stderr, "WARNING: Failed to create pipe for logging\n");
        fclose(g_log_file);
        g_log_file = NULL;
        return 0;
    }

    /* Save original stdout and check if we're running as daemon */
    g_original_stdout_fd = dup(STDOUT_FILENO);
    if (g_original_stdout_fd < 0) {
        fprintf(g_log_file, "WARNING: Failed to duplicate stdout - running in daemon mode\n");
        fflush(g_log_file);
        g_daemon_mode = 1;
    } else {
        /* Check if stdout is redirected (common in daemon mode) */
        struct stat stat_buf;
        if (fstat(g_original_stdout_fd, &stat_buf) == 0) {
            if (!isatty(g_original_stdout_fd)) {
                /* stdout is not a terminal - likely daemon mode */
                g_daemon_mode = 1;
                fprintf(g_log_file, "INFO: Detected daemon mode - console output disabled\n");
                fflush(g_log_file);
            } else {
                fprintf(g_log_file, "INFO: Console mode detected - output will go to both console and file\n");
                fflush(g_log_file);
            }
        }
    }

    /* Start tee thread */
    g_logging_active = 1;
    if (pthread_create(&g_tee_thread, NULL, tee_thread_func, NULL) != 0) {
        fprintf(g_log_file, "WARNING: Failed to create logging thread\n");
        fflush(g_log_file);
        if (g_original_stdout_fd >= 0) close(g_original_stdout_fd);
        close(g_pipe_fds[0]);
        close(g_pipe_fds[1]);
        fclose(g_log_file);
        g_log_file = NULL;
        g_logging_active = 0;
        return 0;
    }

    /* Redirect stdout to pipe */
    dup2(g_pipe_fds[1], STDOUT_FILENO);
    dup2(g_pipe_fds[1], STDERR_FILENO);
    close(g_pipe_fds[1]);
    
    /* Disable buffering */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
#endif

    printf("File logging enabled: %s\n", logfile_path);
    
    /* Force immediate flush to ensure message appears */
    fflush(stdout);
    fflush(stderr);

    return 1;
}

/*
 * Simpler version - auto-generates filename in current directory
 */
static inline int enable_file_logging_simple(void)
{
    return enable_file_logging(NULL, "meshagent");
}

/*
 * Thread-safe, error-resilient printf replacement
 * Never crashes the application due to disk errors
 */

#ifdef WIN32
static CRITICAL_SECTION g_log_mutex;
static int g_log_mutex_initialized = 0;
#else
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static volatile int g_disk_error_count = 0;
static volatile int g_disk_available = 1;

static inline void init_log_mutex(void) {
#ifdef WIN32
    if (!g_log_mutex_initialized) {
        InitializeCriticalSection(&g_log_mutex);
        g_log_mutex_initialized = 1;
    }
#endif
}

static inline void lock_log(void) {
#ifdef WIN32
    EnterCriticalSection(&g_log_mutex);
#else
    pthread_mutex_lock(&g_log_mutex);
#endif
}

static inline void unlock_log(void) {
#ifdef WIN32
    LeaveCriticalSection(&g_log_mutex);
#else
    pthread_mutex_unlock(&g_log_mutex);
#endif
}

static inline int openframe_printf(const char *format, ...)
{
    va_list args;
    char buffer[4096];
    int len;
    int success = 0;
    
    va_start(args, format);
    len = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    if (len <= 0) return len;
    
    init_log_mutex();
    lock_log();
    
    /* Try to write to log file with error handling */
    if (g_log_file != NULL && g_disk_available) {
        size_t written = fwrite(buffer, 1, len, g_log_file);
        
        if (written == (size_t)len) {
            /* Successful write - try to flush */
            if (fflush(g_log_file) == 0) {
                success = 1;
                g_disk_error_count = 0; /* Reset error counter */
            } else {
                /* Flush failed - disk might be full */
                g_disk_error_count++;
                if (g_disk_error_count >= 5) {
                    g_disk_available = 0; /* Disable disk writes temporarily */
                }
            }
        } else {
            /* Write failed - handle gracefully */
            g_disk_error_count++;
            if (g_disk_error_count >= 3) {
                /* Too many failures - might be disk full or disconnected */
                g_disk_available = 0;
                
                /* Try to write error message if possible */
                if (g_log_file != NULL) {
                    fprintf(g_log_file, "\n*** LOG ERROR: Disk write failures detected, switching to stdout-only mode ***\n");
                    fflush(g_log_file);
                }
            }
        }
    }
    
    unlock_log();
    
    /* ALWAYS write to stdout - this is our backup */
#ifdef WIN32
    DWORD written_stdout;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buffer, len, &written_stdout, NULL);
#else
    ignore_result(write(STDOUT_FILENO, buffer, len));
#endif
    
    /* Periodically try to re-enable disk writes */
    if (!g_disk_available && (g_disk_error_count % 50 == 0)) {
        lock_log();
        g_disk_available = 1; /* Try again */
        unlock_log();
    }
    
    return len;
}

/* 
 * Override printf with reliable version when file logging is active
 * This ensures printf works correctly in both console and daemon modes
 */
#define OPENFRAME_PRINTF_OVERRIDE 1
#if OPENFRAME_PRINTF_OVERRIDE
#define printf(...) openframe_printf(__VA_ARGS__)
#endif

/*
 * Disable file logging and clean up resources
 */
static inline void disable_file_logging(void)
{
    if (g_log_file == NULL) {
        return; /* Logging not active */
    }

#ifdef WIN32
    if (g_logging_active) {
        g_logging_active = 0;
        
        /* Restore original stdout/stderr */
        if (g_original_stdout_fd >= 0) {
            _dup2(g_original_stdout_fd, 1);
            _dup2(g_original_stdout_fd, 2);
            _close(g_original_stdout_fd);
            g_original_stdout_fd = -1;
        }
        
        /* Wait for thread to finish and clean up */
        if (g_tee_thread != INVALID_HANDLE_VALUE) {
            WaitForSingleObject(g_tee_thread, 1000); /* Wait up to 1 second */
            CloseHandle(g_tee_thread);
            g_tee_thread = INVALID_HANDLE_VALUE;
        }
        
        /* Close pipe */
        if (g_pipe_fds[0] >= 0) {
            _close(g_pipe_fds[0]);
            g_pipe_fds[0] = -1;
        }
        g_pipe_fds[1] = -1;
    }
#endif

#if defined(_POSIX) || defined(__APPLE__) || defined(__linux__) || defined(__unix__)
    if (g_logging_active) {
        g_logging_active = 0;
        
        /* Restore original stdout/stderr */
        if (g_original_stdout_fd >= 0) {
            dup2(g_original_stdout_fd, STDOUT_FILENO);
            dup2(g_original_stdout_fd, STDERR_FILENO);
            close(g_original_stdout_fd);
            g_original_stdout_fd = -1;
        }
        
        /* Wait for thread to finish and clean up */
        pthread_join(g_tee_thread, NULL);
        
        /* Close pipe */
        if (g_pipe_fds[0] >= 0) {
            close(g_pipe_fds[0]);
            g_pipe_fds[0] = -1;
        }
        g_pipe_fds[1] = -1;
    }
#endif

    /* Close log file */
    if (g_log_file != NULL) {
        fprintf(g_log_file, "\n========================================\n");
        fprintf(g_log_file, "MeshAgent Log Ended\n");
        fprintf(g_log_file, "========================================\n");
        fclose(g_log_file);
        g_log_file = NULL;
    }
    
    /* Reset daemon mode flag and cleanup */
    g_daemon_mode = 0;
    g_disk_available = 1;
    g_disk_error_count = 0;
    
#ifdef WIN32
    if (g_log_mutex_initialized) {
        DeleteCriticalSection(&g_log_mutex);
        g_log_mutex_initialized = 0;
    }
#endif
    
    printf("File logging disabled.\n");
}

#endif // OPENFRAME_FILE_LOGGER_H

