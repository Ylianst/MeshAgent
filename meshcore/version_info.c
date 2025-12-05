#include "version_info.h"

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#include <string.h>
#include <stdlib.h>

// Helper function to extract CFBundleShortVersionString from embedded Info.plist
// Returns dynamically allocated string that must be freed by caller, or NULL on failure
char* get_embedded_version(void)
{
	unsigned long plist_size = 0;
	char *version_string = NULL;

	// Get pointer to embedded __info_plist section
	const uint8_t *plist_data = getsectiondata(&_mh_execute_header, "__TEXT", "__info_plist", &plist_size);

	if (plist_data == NULL || plist_size == 0)
	{
		return NULL;  // No embedded plist found
	}

	// Create CFData from the plist bytes
	CFDataRef data = CFDataCreate(kCFAllocatorDefault, plist_data, plist_size);
	if (data == NULL)
	{
		return NULL;
	}

	// Parse the plist
	CFErrorRef error = NULL;
	CFPropertyListRef plist = CFPropertyListCreateWithData(
		kCFAllocatorDefault,
		data,
		kCFPropertyListImmutable,
		NULL,
		&error
	);

	CFRelease(data);

	if (plist == NULL || error != NULL)
	{
		if (error) CFRelease(error);
		return NULL;
	}

	// Get CFBundleShortVersionString value
	if (CFGetTypeID(plist) == CFDictionaryGetTypeID())
	{
		CFStringRef version_key = CFStringCreateWithCString(kCFAllocatorDefault, "CFBundleShortVersionString", kCFStringEncodingUTF8);
		CFStringRef version_value = (CFStringRef)CFDictionaryGetValue((CFDictionaryRef)plist, version_key);

		if (version_value != NULL && CFGetTypeID(version_value) == CFStringGetTypeID())
		{
			// Convert CFString to C string
			CFIndex length = CFStringGetLength(version_value);
			CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
			version_string = (char*)malloc(maxSize);

			if (version_string != NULL)
			{
				if (!CFStringGetCString(version_value, version_string, maxSize, kCFStringEncodingUTF8))
				{
					free(version_string);
					version_string = NULL;
				}
			}
		}

		CFRelease(version_key);
	}

	CFRelease(plist);
	return version_string;
}

// Helper function to extract CFBundleVersion from embedded Info.plist
// Returns dynamically allocated string that must be freed by caller, or NULL on failure
char* get_embedded_build_version(void)
{
	unsigned long plist_size = 0;
	char *build_string = NULL;

	// Get pointer to embedded __info_plist section
	const uint8_t *plist_data = getsectiondata(&_mh_execute_header, "__TEXT", "__info_plist", &plist_size);

	if (plist_data == NULL || plist_size == 0)
	{
		return NULL;  // No embedded plist found
	}

	// Create CFData from the plist bytes
	CFDataRef data = CFDataCreate(kCFAllocatorDefault, plist_data, plist_size);
	if (data == NULL)
	{
		return NULL;
	}

	// Parse the plist
	CFErrorRef error = NULL;
	CFPropertyListRef plist = CFPropertyListCreateWithData(
		kCFAllocatorDefault,
		data,
		kCFPropertyListImmutable,
		NULL,
		&error
	);

	CFRelease(data);

	if (plist == NULL || error != NULL)
	{
		if (error) CFRelease(error);
		return NULL;
	}

	// Get CFBundleVersion value
	if (CFGetTypeID(plist) == CFDictionaryGetTypeID())
	{
		CFStringRef build_key = CFStringCreateWithCString(kCFAllocatorDefault, "CFBundleVersion", kCFStringEncodingUTF8);
		CFStringRef build_value = (CFStringRef)CFDictionaryGetValue((CFDictionaryRef)plist, build_key);

		if (build_value != NULL && CFGetTypeID(build_value) == CFStringGetTypeID())
		{
			// Convert CFString to C string
			CFIndex length = CFStringGetLength(build_value);
			CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
			build_string = (char*)malloc(maxSize);

			if (build_string != NULL)
			{
				if (!CFStringGetCString(build_value, build_string, maxSize, kCFStringEncodingUTF8))
				{
					free(build_string);
					build_string = NULL;
				}
			}
		}

		CFRelease(build_key);
	}

	CFRelease(plist);
	return build_string;
}

// Helper function to get full version string (CFBundleShortVersionString + CFBundleVersion)
// Returns dynamically allocated string that must be freed by caller, or NULL on failure
char* get_embedded_full_version(void)
{
	char *version = get_embedded_version();
	char *build = get_embedded_build_version();
	char *full_version = NULL;

	if (version != NULL && build != NULL)
	{
		// Allocate space for "version build" + null terminator
		size_t len = strlen(version) + strlen(build) + 2;
		full_version = (char*)malloc(len);
		if (full_version != NULL)
		{
			snprintf(full_version, len, "%s %s", version, build);
		}
	}
	else if (version != NULL)
	{
		// Only version available
		full_version = strdup(version);
	}
	else if (build != NULL)
	{
		// Only build available
		full_version = strdup(build);
	}

	if (version) free(version);
	if (build) free(build);

	return full_version;
}

#endif // __APPLE__
