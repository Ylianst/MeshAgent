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

#ifndef MACOS_BUNDLE_DETECTION_H
#define MACOS_BUNDLE_DETECTION_H

#ifdef __APPLE__

/**
 * Detect if the binary is running from a macOS application bundle (.app)
 *
 * Uses CoreFoundation to reliably detect bundle execution by checking if the
 * bundle path ends with ".app". This distinguishes between:
 * - Standalone binaries with embedded Info.plist (returns 0)
 * - Actual application bundles (returns 1)
 *
 * @return 1 if running from a .app bundle, 0 if standalone binary
 */
int is_running_from_bundle(void);

/**
 * Get the application bundle root directory path
 *
 * Returns the full path to the .app directory (e.g., "/Applications/MeshAgent.app")
 *
 * @return Dynamically allocated string containing bundle path, or NULL on failure
 *         Caller must free() the returned string when done
 */
char* get_bundle_path(void);

/**
 * Adjust working directory based on bundle status
 *
 * If running from a bundle:
 *   - Changes working directory to the bundle's parent directory (install path)
 *   - Prints "MeshAgent: Running from bundle: <path>"
 *   - Returns -1 if unable to determine bundle path or change directory
 *
 * If running as standalone binary:
 *   - Leaves working directory unchanged
 *   - Prints "MeshAgent: Running as standalone binary from: <cwd>"
 *
 * This should be called early in main() before any file I/O operations that
 * depend on relative paths. The caller should check the return value and exit
 * if non-zero, as continuing with the wrong working directory will cause file
 * operations to fail.
 *
 * @return 0 on success, -1 on error (only possible when running from bundle)
 */
int adjust_working_directory_for_bundle(void);

#endif /* __APPLE__ */

#endif /* MACOS_BUNDLE_DETECTION_H */
