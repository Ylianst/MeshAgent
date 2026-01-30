/*
Shared plist parsing utilities for macOS

Provides secure, CoreFoundation-based parsing of LaunchDaemon plists
to extract meshagent configuration information.
*/

#include "mac_plist_utils.h"
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>

/**
 * Helper to load plist from file path
 * Returns CFDictionaryRef on success, NULL on failure
 * Caller must CFRelease the returned dictionary
 */
static CFDictionaryRef load_plist_from_file(const char* plistPath) {
    CFURLRef fileURL = NULL;
    CFReadStreamRef stream = NULL;
    CFPropertyListRef plist = NULL;
    CFDictionaryRef dict = NULL;

    // Create URL from file path
    CFStringRef pathString = CFStringCreateWithCString(NULL, plistPath, kCFStringEncodingUTF8);
    if (!pathString) {
        goto cleanup;
    }

    fileURL = CFURLCreateWithFileSystemPath(NULL, pathString, kCFURLPOSIXPathStyle, false);
    CFRelease(pathString);
    if (!fileURL) {
        goto cleanup;
    }

    // Open file stream
    stream = CFReadStreamCreateWithFile(NULL, fileURL);
    if (!stream || !CFReadStreamOpen(stream)) {
        goto cleanup;
    }

    // Parse plist
    CFErrorRef error = NULL;
    plist = CFPropertyListCreateWithStream(NULL, stream, 0, kCFPropertyListImmutable, NULL, &error);
    if (error) {
        CFRelease(error);
        goto cleanup;
    }

    // Verify it's a dictionary
    if (plist && CFGetTypeID(plist) == CFDictionaryGetTypeID()) {
        dict = (CFDictionaryRef)CFRetain(plist);
    }

cleanup:
    if (stream) {
        CFReadStreamClose(stream);
        CFRelease(stream);
    }
    if (fileURL) CFRelease(fileURL);
    if (plist) CFRelease(plist);

    return dict;
}

/**
 * Helper to convert CFString to C string
 * Returns dynamically allocated string or NULL
 * Caller must free() the returned string
 */
static char* cfstring_to_cstring(CFStringRef cfString) {
    if (!cfString || CFGetTypeID(cfString) != CFStringGetTypeID()) {
        return NULL;
    }

    CFIndex length = CFStringGetLength(cfString);
    CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
    char* cString = (char*)malloc(maxSize);

    if (cString && CFStringGetCString(cfString, cString, maxSize, kCFStringEncodingUTF8)) {
        return cString;
    }

    free(cString);
    return NULL;
}

/**
 * Extract the Label value from a plist file
 */
char* mesh_plist_get_label(const char* plistPath) {
    CFDictionaryRef dict = load_plist_from_file(plistPath);
    if (!dict) {
        return NULL;
    }

    CFStringRef label = CFDictionaryGetValue(dict, CFSTR("Label"));
    char* result = cfstring_to_cstring(label);

    CFRelease(dict);
    return result;
}

/**
 * Extract the first ProgramArguments path from a plist file
 */
char* mesh_plist_get_program_path(const char* plistPath) {
    CFDictionaryRef dict = load_plist_from_file(plistPath);
    if (!dict) {
        return NULL;
    }

    char* result = NULL;
    CFArrayRef programArgs = CFDictionaryGetValue(dict, CFSTR("ProgramArguments"));

    if (programArgs && CFGetTypeID(programArgs) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(programArgs);
        if (count > 0) {
            CFStringRef firstArg = CFArrayGetValueAtIndex(programArgs, 0);
            result = cfstring_to_cstring(firstArg);
        }
    }

    CFRelease(dict);
    return result;
}

/**
 * Check if ProgramArguments contains a specific argument
 */
int mesh_plist_has_argument(const char* plistPath, const char* argument) {
    CFDictionaryRef dict = load_plist_from_file(plistPath);
    if (!dict) {
        return 0;
    }

    int found = 0;
    CFArrayRef programArgs = CFDictionaryGetValue(dict, CFSTR("ProgramArguments"));

    if (programArgs && CFGetTypeID(programArgs) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(programArgs);
        CFStringRef targetArg = CFStringCreateWithCString(NULL, argument, kCFStringEncodingUTF8);

        if (targetArg) {
            for (CFIndex i = 0; i < count; i++) {
                CFStringRef arg = CFArrayGetValueAtIndex(programArgs, i);
                if (arg && CFGetTypeID(arg) == CFStringGetTypeID()) {
                    if (CFStringCompare(arg, targetArg, 0) == kCFCompareEqualTo) {
                        found = 1;
                        break;
                    }
                }
            }
            CFRelease(targetArg);
        }
    }

    CFRelease(dict);
    return found;
}

/**
 * Find the serviceId (plist Label) by scanning a directory for a plist whose
 * ProgramArguments[0] matches the given binary path.
 */
char* mesh_plist_find_service_id(const char* directory, const char* binaryPath) {
    DIR *dir;
    struct dirent *entry;

    if (directory == NULL || binaryPath == NULL || strlen(binaryPath) == 0) {
        return NULL;
    }

    dir = opendir(directory);
    if (dir == NULL) {
        return NULL;
    }

    char *serviceId = NULL;
    char plistPath[1024];

    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".plist") == NULL) continue;

        snprintf(plistPath, sizeof(plistPath), "%s/%s", directory, entry->d_name);

        char *programPath = mesh_plist_get_program_path(plistPath);
        if (programPath != NULL) {
            if (strcmp(programPath, binaryPath) == 0) {
                serviceId = mesh_plist_get_label(plistPath);
                free(programPath);
                break;
            }
            free(programPath);
        }
    }

    closedir(dir);
    return serviceId;
}

/**
 * Parse a LaunchDaemon plist file and extract meshagent information
 */
int mesh_parse_launchdaemon_plist(const char* plistPath, MeshPlistInfo* info, const char* agentName) {
    if (!plistPath || !info) {
        return 0;
    }

    // Default to "meshagent" if no agent name specified
    if (!agentName || agentName[0] == '\0') {
        agentName = "meshagent";
    }

    // Initialize info structure
    memset(info, 0, sizeof(MeshPlistInfo));
    strncpy(info->plistPath, plistPath, sizeof(info->plistPath) - 1);

    CFDictionaryRef dict = load_plist_from_file(plistPath);
    if (!dict) {
        return 0;
    }

    int foundMeshagent = 0;

    // Extract Label
    CFStringRef label = CFDictionaryGetValue(dict, CFSTR("Label"));
    if (label && CFGetTypeID(label) == CFStringGetTypeID()) {
        CFStringGetCString(label, info->label, sizeof(info->label), kCFStringEncodingUTF8);
    }

    // Extract ProgramArguments
    CFArrayRef programArgs = CFDictionaryGetValue(dict, CFSTR("ProgramArguments"));
    if (programArgs && CFGetTypeID(programArgs) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(programArgs);

        for (CFIndex i = 0; i < count; i++) {
            CFStringRef arg = CFArrayGetValueAtIndex(programArgs, i);
            if (!arg || CFGetTypeID(arg) != CFStringGetTypeID()) {
                continue;
            }

            char argStr[1024];
            if (!CFStringGetCString(arg, argStr, sizeof(argStr), kCFStringEncodingUTF8)) {
                continue;
            }

            // Check if this is the agent path (first argument containing the agent name)
            if (!foundMeshagent && strstr(argStr, agentName) != NULL) {
                strncpy(info->programPath, argStr, sizeof(info->programPath) - 1);
                foundMeshagent = 1;
            }

            // Check for --disableUpdate=1
            if (strcmp(argStr, "--disableUpdate=1") == 0) {
                info->hasDisableUpdate = 1;
            }
        }
    }

    CFRelease(dict);

    // Get modification time
    struct stat st;
    if (stat(plistPath, &st) == 0) {
        info->modTime = st.st_mtime;
    }

    return foundMeshagent;
}
