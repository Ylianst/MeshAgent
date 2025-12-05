#ifndef VERSION_INFO_H
#define VERSION_INFO_H

#ifdef __APPLE__

// Helper function to extract CFBundleShortVersionString from embedded Info.plist
// Returns dynamically allocated string that must be freed by caller, or NULL on failure
// Format: YY.MM.DD (e.g., "25.12.10")
char* get_embedded_version(void);

// Helper function to extract CFBundleVersion from embedded Info.plist
// Returns dynamically allocated string that must be freed by caller, or NULL on failure
// Format: HH.MM.SS (e.g., "12.48.22")
char* get_embedded_build_version(void);

// Helper function to get full version string (CFBundleShortVersionString + CFBundleVersion)
// Returns dynamically allocated string that must be freed by caller, or NULL on failure
// Format: "YY.MM.DD HH.MM.SS" (e.g., "25.12.10 12.48.22")
char* get_embedded_full_version(void);

#endif // __APPLE__

#endif // VERSION_INFO_H
