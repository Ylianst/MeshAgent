/*
Copyright 2025

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifdef __APPLE__

#include "bundle_detection.h"
#include <CoreFoundation/CoreFoundation.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>

int is_running_from_bundle(void)
{
    // CFBundleGetMainBundle() returns non-NULL even for standalone binaries
    // if they have embedded Info.plist, so we must check the actual path
    CFBundleRef mainBundle = CFBundleGetMainBundle();
    if (!mainBundle)
    {
        return 0; // No bundle found - standalone
    }

    CFURLRef bundleURL = CFBundleCopyBundleURL(mainBundle);
    if (!bundleURL)
    {
        return 0;
    }

    CFStringRef bundlePath = CFURLCopyFileSystemPath(bundleURL, kCFURLPOSIXPathStyle);

    int is_bundle = 0;
    if (bundlePath)
    {
        char path[PATH_MAX];
        if (CFStringGetCString(bundlePath, path, PATH_MAX, kCFStringEncodingUTF8))
        {
            // Check if path ends with .app
            size_t len = strlen(path);
            is_bundle = (len > 4 && strcmp(path + len - 4, ".app") == 0);
        }
        CFRelease(bundlePath);
    }

    CFRelease(bundleURL);
    return is_bundle;
}

char* get_bundle_path(void)
{
    CFBundleRef mainBundle = CFBundleGetMainBundle();
    if (!mainBundle)
    {
        return NULL;
    }

    CFURLRef bundleURL = CFBundleCopyBundleURL(mainBundle);
    if (!bundleURL)
    {
        return NULL;
    }

    CFStringRef bundlePath = CFURLCopyFileSystemPath(bundleURL, kCFURLPOSIXPathStyle);

    char* result = NULL;
    if (bundlePath)
    {
        // Get the maximum length needed for the string
        CFIndex maxSize = CFStringGetMaximumSizeForEncoding(
            CFStringGetLength(bundlePath),
            kCFStringEncodingUTF8
        ) + 1;

        result = (char*)malloc(maxSize);
        if (result)
        {
            if (!CFStringGetCString(bundlePath, result, maxSize, kCFStringEncodingUTF8))
            {
                free(result);
                result = NULL;
            }
        }
        CFRelease(bundlePath);
    }

    CFRelease(bundleURL);
    return result;
}

int adjust_working_directory_for_bundle(void)
{
    // CRITICAL: Call this early in main() before any file operations
    // Returns 0 on success, -1 on error
    if (is_running_from_bundle())
    {
        char* bundleRoot = get_bundle_path();
        if (!bundleRoot)
        {
            fprintf(stderr, "MeshAgent: FATAL: Could not get bundle path\n");
            return -1;
        }

        // For bundle installations, change to the parent directory (install path)
        // This allows .msh and .db files to be found in the same location as standalone
        char* lastSlash = strrchr(bundleRoot, '/');
        if (!lastSlash || lastSlash == bundleRoot)
        {
            fprintf(stderr, "MeshAgent: FATAL: Invalid bundle path: %s\n", bundleRoot);
            free(bundleRoot);
            return -1;
        }

        *lastSlash = '\0';  // Truncate to get parent directory

        if (chdir(bundleRoot) != 0)
        {
            *lastSlash = '/';  // Restore for error message
            fprintf(stderr, "MeshAgent: FATAL: Could not change to install directory: %s\n", bundleRoot);
            free(bundleRoot);
            return -1;
        }

        // Restore slash
        *lastSlash = '/';
        // Note: Bundle detection message is now logged from JavaScript using logger.info()
        free(bundleRoot);
    }
    else
    {
        // Standalone mode - working directory already correct
        // Note: Standalone detection message is now logged from JavaScript using logger.info()
    }

    return 0;
}

#endif /* __APPLE__ */
