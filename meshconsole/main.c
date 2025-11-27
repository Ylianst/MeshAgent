/*
Copyright 2006 - 2022 Intel Corporation

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

#ifdef WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#include <Windows.h>
#endif

#include "meshcore/agentcore.h"

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "microscript/ILibDuktape_ScriptContainer.h"
#include "microstack/ILibCrypto.h"
#include "microscript/ILibDuktape_Commit.h"

#if defined(__APPLE__) && defined(_LINKVM)
#include <dirent.h>
#include <limits.h>
#include <libgen.h>
#include <string.h>
#endif

#ifdef __APPLE__
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#include <CoreFoundation/CoreFoundation.h>
#include "meshcore/MacOS/bundle_detection.h"
#include "meshcore/MacOS/mac_tcc_detection.h"
#include "meshcore/MacOS/TCC_UI/mac_permissions_window.h"
#include "microstack/ILibSimpleDataStore.h"
#endif

MeshAgentHostContainer *agentHost = NULL;
#ifdef _OPENBSD
#include <stdlib.h>
char __agentExecPath[1024] = { 0 };
#endif


#ifdef WIN32
BOOL CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	{
		if (agentHost != NULL) { MeshAgent_Stop(agentHost); }
		return TRUE;
	}
	default:
		return FALSE;
	}
}
#endif


#if defined(_POSIX)
void BreakSink(int s)
{
	UNREFERENCED_PARAMETER(s);

	signal(SIGINT, SIG_IGN);	// To ignore any more ctrl c interrupts
	if (agentHost != NULL) { MeshAgent_Stop(agentHost); }
}
#endif

#if defined(_LINKVM) && defined(__APPLE__)
extern void* kvm_server_mainloop(void *parm, char *serviceID);
extern void senddebug(int val);
ILibTransport_DoneState kvm_serviceWriteSink(char *buffer, int bufferLen, void *reserved)
{
	ignore_result(write(STDOUT_FILENO, (void*)buffer, bufferLen));
	return ILibTransport_DoneState_COMPLETE;
}

// Helper function to extract Label from a plist file
char* extract_plist_label(const char* plistPath)
{
	FILE *fp;
	char cmd[1024];
	char *result = NULL;
	char buffer[512];

	// Use awk to extract Label value from plist
	snprintf(cmd, sizeof(cmd),
		"cat '%s' | tr '\\n' '.' | awk '{ split($0, a, \"<key>Label</key>\"); "
		"split(a[2], b, \"</string>\"); split(b[1], c, \"<string>\"); print c[2]; }'",
		plistPath);

	fp = popen(cmd, "r");
	if (fp != NULL)
	{
		if (fgets(buffer, sizeof(buffer), fp) != NULL)
		{
			// Remove trailing newline
			size_t len = strlen(buffer);
			if (len > 0 && buffer[len-1] == '\n') buffer[len-1] = '\0';
			if (strlen(buffer) > 0)
			{
				result = strdup(buffer);
			}
		}
		pclose(fp);
	}

	return result;
}

// Helper function to extract first ProgramArguments path from plist
char* extract_plist_program_path(const char* plistPath)
{
	FILE *fp;
	char cmd[1024];
	char *result = NULL;
	char buffer[512];

	// Use awk to extract first ProgramArguments string (the binary path)
	snprintf(cmd, sizeof(cmd),
		"cat '%s' | tr '\\n' '.' | awk '{ split($0, a, \"<key>ProgramArguments</key>\"); "
		"split(a[2], b, \"</array>\"); split(b[1], c, \"<string>\"); "
		"split(c[2], d, \"</string>\"); print d[1]; }'",
		plistPath);

	fp = popen(cmd, "r");
	if (fp != NULL)
	{
		if (fgets(buffer, sizeof(buffer), fp) != NULL)
		{
			// Remove trailing newline
			size_t len = strlen(buffer);
			if (len > 0 && buffer[len-1] == '\n') buffer[len-1] = '\0';
			if (strlen(buffer) > 0)
			{
				result = strdup(buffer);
			}
		}
		pclose(fp);
	}

	return result;
}

// Discover serviceId by finding which LaunchAgent plist references our binary
char* discover_service_id_from_plist(const char* binaryPath)
{
	DIR *dir;
	struct dirent *entry;
	char *serviceId = NULL;
	const char *launchAgentDir = "/Library/LaunchAgents";

	dir = opendir(launchAgentDir);
	if (dir == NULL)
	{
		return NULL;
	}

	while ((entry = readdir(dir)) != NULL)
	{
		// Look for .plist files
		if (strstr(entry->d_name, ".plist") == NULL)
			continue;

		// Build full plist path
		char plistPath[PATH_MAX];
		snprintf(plistPath, sizeof(plistPath), "%s/%s", launchAgentDir, entry->d_name);

		// Extract ProgramArguments path
		char *programPath = extract_plist_program_path(plistPath);
		if (programPath != NULL)
		{
			// Check if it matches our binary path
			if (strcmp(programPath, binaryPath) == 0)
			{
				// Found it! Extract the Label
				serviceId = extract_plist_label(plistPath);
				free(programPath);
				break;
			}
			free(programPath);
		}
	}

	closedir(dir);
	return serviceId;
}

// Parse serviceId to extract serviceName and companyName
// Format: meshagent.{serviceName}.{companyName}-agent or {serviceName}-agent
void parse_service_id(const char* serviceId, char** serviceName, char** companyName)
{
	if (serviceId == NULL)
	{
		*serviceName = strdup("meshagent");
		*companyName = NULL;
		return;
	}

	// Make a working copy
	char workingCopy[512];
	strncpy(workingCopy, serviceId, sizeof(workingCopy) - 1);
	workingCopy[sizeof(workingCopy) - 1] = '\0';

	// Strip -agent suffix if present
	char *agentSuffix = strstr(workingCopy, "-agent");
	if (agentSuffix != NULL)
	{
		*agentSuffix = '\0';  // Terminate string before -agent
	}

	// Check if format is meshagent.{serviceName}.{companyName}
	if (strncmp(workingCopy, "meshagent.", 10) == 0)
	{
		// Skip "meshagent." prefix
		char *remainder = workingCopy + 10;

		// Find the next dot to separate serviceName and companyName
		char *dot = strchr(remainder, '.');
		if (dot != NULL)
		{
			*dot = '\0';  // Split at dot
			*serviceName = strdup(remainder);
			*companyName = strdup(dot + 1);
		}
		else
		{
			// Only serviceName, no companyName
			*serviceName = strdup(remainder);
			*companyName = NULL;
		}
	}
	else
	{
		// Simple format - just serviceName
		*serviceName = strdup(workingCopy);
		*companyName = NULL;
	}
}
#endif

#ifdef __APPLE__
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
#endif

#ifdef WIN32
#define wmain_free(argv) for(argvi=0;argvi<(int)(ILibMemory_Size(argv)/sizeof(void*));++argvi){ILibMemory_Free(argv[argvi]);}ILibMemory_Free(argv);
int wmain(int argc, char **wargv)
#else
int main(int argc, char **argv)
#endif
{
#ifdef _OPENBSD
	realpath(argv[0], __agentExecPath);
#endif

	// Check if .JS file is integrated with executable
	char *integratedJavaScript = NULL;
	int integratedJavaScriptLen = 0;
	int retCode = 0;
	int capabilities = 0;

#ifdef WIN32
	int argvi, argvsz;
	char **argv = (char**)ILibMemory_SmartAllocate(argc * sizeof(void*));
	for (argvi = 0; argvi < argc; ++argvi)
	{
		argvsz = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wargv[argvi], -1, NULL, 0, NULL, NULL);
		argv[argvi] = (char*)ILibMemory_SmartAllocate(argvsz);
		WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wargv[argvi], -1, argv[argvi], argvsz, NULL, NULL);
	}
#endif

#if defined (_POSIX)
#ifndef _NOILIBSTACKDEBUG
char* crashMemory = ILib_POSIX_InstallCrashHandler(argv[0]);
#endif
#endif

#ifdef __APPLE__
	// Adjust working directory if running from application bundle
	if (adjust_working_directory_for_bundle() != 0)
	{
		fprintf(stderr, "MeshAgent: Failed to set working directory for bundle. Exiting.\n");
		return -1;
	}
#endif

	ILibDuktape_ScriptContainer_CheckEmbedded(&integratedJavaScript, &integratedJavaScriptLen);

	if (integratedJavaScriptLen != 0 && integratedJavaScript != NULL && argc > 1)
	{
		int i;
		for (i = 1; i < argc; ++i)
		{
			if (strcmp(argv[i], "--no-embedded=1") == 0 || strcmp(argv[i], "--no-embedded=\"1\"") == 0)
			{
				free(integratedJavaScript);
				integratedJavaScript = NULL;
				integratedJavaScriptLen = 0;
				break;
			}
		}
	}

	if (argc > 1 && strcmp(argv[1], "-export") == 0 && integratedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy("require('code-utils').expand({embedded: true});process.exit();",0);
		integratedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	}

	if (argc > 1 && strcmp(argv[1], "-import") == 0 && integratedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy("require('code-utils').shrink();process.exit();",0);
		integratedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	}

	if (argc > 2 && strcmp(argv[1], "-exec") == 0 && integratedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy(argv[2], 0);
		integratedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	} 
	if (argc > 2 && strcmp(argv[1], "-b64exec") == 0)
	{
		integratedJavaScript = NULL;
		integratedJavaScriptLen = ILibBase64Decode((unsigned char *)argv[2], (const int)strnlen_s(argv[2], sizeof(ILibScratchPad2)), (unsigned char**)&integratedJavaScript);
	}
	if (argc > 1 && strcasecmp(argv[1], "-nodeid") == 0 && integratedJavaScriptLen == 0)
	{
		char script[] = "console.log(require('_agentNodeId')());process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-name") == 0 && integratedJavaScriptLen == 0)
	{
		char script[] = "console.log(require('_agentNodeId').serviceName());process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-agentHash") == 0 && integratedJavaScriptLen == 0)
	{
		char script[] = "console.log(getSHA384FileHash(process.execPath).toString('hex').substring(0,16));process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-agentFullHash") == 0 && integratedJavaScriptLen == 0)
	{
		char script[] = "console.log(getSHA384FileHash(process.execPath).toString('hex'));process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcmp(argv[1], "-daemon") == 0 && integratedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy("require('daemon').agent();", 0);
		integratedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	}
	if (argc > 1 && strcasecmp(argv[1], "-licenses") == 0)
	{
		printf("========================================================================================\n");
		printf(" MeshCentral MeshAgent: Copyright 2006 - 2022 Intel Corporation\n");
		printf("                        https://github.com/Ylianst/MeshAgent \n");
		printf("----------------------------------------------------------------------------------------\n");
		printf("   Licensed under the Apache License, Version 2.0 (the \"License\");\n");
		printf("   you may not use this file except in compliance with the License.\n");
		printf("   You may obtain a copy of the License at\n");
		printf("   \n");
		printf("   http://www.apache.org/licenses/LICENSE-2.0\n");
		printf("   \n");
		printf("   Unless required by applicable law or agreed to in writing, software\n");
		printf("   distributed under the License is distributed on an \"AS IS\" BASIS,\n");
		printf("   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n");
		printf("   See the License for the specific language governing permissions and\n");
		printf("   limitations under the License.\n\n");
		printf("========================================================================================\n");
		printf(" Duktape Javascript Engine: Copyright (c) 2013-2019 by Duktape authors (see AUTHORS.rst)\n");
		printf("                        https://github.com/svaarala/duktape \n");
		printf("                        http://opensource.org/licenses/MIT \n");
		printf("----------------------------------------------------------------------------------------\n");
		printf("   Permission is hereby granted, free of charge, to any person obtaining a copy\n");
		printf("   of this software and associated documentation files(the \"Software\"), to deal\n");
		printf("   in the Software without restriction, including without limitation the rights\n");
		printf("   to use, copy, modify, merge, publish, distribute, sublicense, and / or sell\n");
		printf("   copies of the Software, and to permit persons to whom the Software is\n");
		printf("   furnished to do so, subject to the following conditions :\n");
		printf("   \n");
		printf("   The above copyright notice and this permission notice shall be included in\n");
		printf("   all copies or substantial portions of the Software.\n");
		printf("   \n");
		printf("   THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n");
		printf("   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n");
		printf("   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE\n");
		printf("   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n");
		printf("   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n");
		printf("   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN\n");
		printf("   THE SOFTWARE.\n");
		printf("========================================================================================\n");
		printf("ZLIB Data Compression Library: Copyright (c) 1995-2017 Jean-loup Gailly and Mark Adler\n");
		printf("                               http://www.zlib.net \n");
		printf("----------------------------------------------------------------------------------------\n");
		printf("   This software is provided 'as-is', without any express or implied\n");
		printf("   warranty.In no event will the authors be held liable for any damages\n");
		printf("   arising from the use of this software.\n");
		printf("\n");
		printf("   Permission is granted to anyone to use this software for any purpose,\n");
		printf("   including commercial applications, and to alter it and redistribute it\n");
		printf("   freely, subject to the following restrictions :\n");
		printf("\n");
		printf("   1. The origin of this software must not be misrepresented; you must not\n");
		printf("      claim that you wrote the original software.If you use this software\n");
		printf("      in a product, an acknowledgment in the product documentation would be\n");
		printf("      appreciated but is not required.\n");
		printf("   2. Altered source versions must be plainly marked as such, and must not be\n");
		printf("      misrepresented as being the original software.\n");
		printf("   3. This notice may not be removed or altered from any source distribution.\n");
		printf("\n");
		printf("   Jean - loup Gailly        Mark Adler\n");
		printf("   jloup@gzip.org            madler@alumni.caltech.edu\n");


#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}
	if (argc > 1 && strcasecmp(argv[1], "-info") == 0)
	{
		printf("Compiled on: %s, %s\n", __TIME__, __DATE__);
		if (SOURCE_COMMIT_HASH != NULL && SOURCE_COMMIT_DATE != NULL) 
		{ 
			printf("   Commit Hash: %s\n", SOURCE_COMMIT_HASH); 
			printf("   Commit Date: %s\n", SOURCE_COMMIT_DATE); 
		}
#ifndef MICROSTACK_NOTLS
		printf("Using %s\n", SSLeay_version(SSLEAY_VERSION));
#endif

		printf("Agent ARCHID: %d\n", MESH_AGENTID);
		char script[] = "var _tmp = 'Detected OS: ' + require('os').Name; try{_tmp += (' - ' + require('os').arch());}catch(x){}console.log(_tmp);if(process.platform=='win32'){ _tmp=require('win-authenticode-opus')(process.execPath); if(_tmp!=null && _tmp.url!=null){ _tmp=require('win-authenticode-opus').locked(_tmp.url); if(_tmp!=null) { console.log('LOCKED to: ' + _tmp.dns); console.log(' => ' + _tmp.id); } } } process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-updaterversion") == 0)
	{
#ifdef WIN32
		DWORD dummy;
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "1\n", 2, &dummy, NULL);
#else
		ignore_result(write(STDOUT_FILENO, "1\n", 2));
#endif
#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}
	if (argc > 1 && strcasecmp(argv[1], "-version") == 0)
	{
#ifdef __APPLE__
		char *version = get_embedded_version();
		if (version != NULL)
		{
			printf("%s\n", version);
			free(version);
		}
		else
		{
			printf("Version information not available\n");
		}
#else
		printf("-version flag is only supported on macOS builds\n");
#endif
#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}
#if defined(_LINKVM) && defined(__APPLE__)
	// -kvm0 DISABLED: macOS now uses REVERSED ARCHITECTURE with -kvm1
	//
	// Historical context:
	// - -kvm0: Original process-spawning architecture (stdin/stdout I/O)
	// - -kvm1: Apple-required architecture using QueueDirectories + domain sockets
	//
	// The -kvm1 REVERSED ARCHITECTURE was required to work within Apple's
	// LaunchAgent/LaunchDaemon framework and bootstrap namespace restrictions.
	// -kvm0 is kept commented here for function/feature comparison purposes.
	//
	// See commit 8772b02 (Oct 29, 2025) for removal of -kvm0 spawning code.
	/*
	if (argc > 1 && strcasecmp(argv[1], "-kvm0") == 0)
	{
		kvm_server_mainloop(NULL);
		return 0;
	}
	else
	*/

	if (argc > 1 && strcasecmp(argv[1], "-kvm1") == 0)
	{
		char *serviceId = NULL;

		// Parse command-line arguments for --serviceId parameter
		for (int i = 2; i < argc; i++)
		{
			if (strncmp(argv[i], "--serviceId=", 12) == 0)
			{
				serviceId = strdup(argv[i] + 12);
				printf("KVM: Using serviceID from parameter: %s\n", serviceId);
				break;
			}
		}

		// Discover serviceId by parsing LaunchAgent plist
		if (serviceId == NULL)
		{
			char binaryPath[PATH_MAX];

			printf("KVM: No --serviceId parameter provided, discovering from LaunchAgent plist\n");

			// Get absolute path of our binary
			if (realpath(argv[0], binaryPath) != NULL)
			{
				printf("KVM: Binary path: %s\n", binaryPath);
				printf("KVM: Scanning /Library/LaunchAgents/ for matching plist...\n");

				// Find which LaunchAgent plist references this binary
				serviceId = discover_service_id_from_plist(binaryPath);

				if (serviceId != NULL)
				{
					printf("KVM: Discovered serviceId from LaunchAgent plist: %s\n", serviceId);
				}
				else
				{
					printf("KVM: Warning - Could not find LaunchAgent plist for %s\n", binaryPath);
					printf("KVM: Using default serviceId\n");
					serviceId = strdup("meshagent");
				}
			}
			else
			{
				printf("KVM: Warning - Could not determine binary path (argv[0]=%s)\n", argv[0]);
				printf("KVM: Using default serviceId\n");
				serviceId = strdup("meshagent");
			}
		}

		kvm_server_mainloop((void*)(uint64_t)getpid(), serviceId);

		// Cleanup
		if (serviceId != NULL) free(serviceId);

		return 0;
	}

	// -tccCheck: Check TCC permissions and show UI if needed
	if (argc > 1 && strcasecmp(argv[1], "-tccCheck") == 0)
	{
		printf("[TCC-CHILD] -tccCheck process started (PID: %d)\n", getpid());

		char* db_path = NULL;
		if (argc > 2) {
			db_path = argv[2]; // Database path passed as second argument
			printf("[TCC-CHILD] Database path: %s\n", db_path);
		} else {
			printf("[TCC-CHILD] WARNING: No database path provided\n");
		}

		// Check "do not remind" flag first
		if (db_path != NULL) {
			void* db = ILibSimpleDataStore_Create(db_path);
			if (db != NULL) {
				int disabledLen = ILibSimpleDataStore_Get(db, "tccPermissionsUIDisabled", NULL, 0);
				printf("[TCC-CHILD] Checking tccPermissionsUIDisabled in child, result length: %d\n", disabledLen);

				if (disabledLen != 0) {
					// User doesn't want to be reminded - exit silently
					printf("[TCC-CHILD] tccPermissionsUIDisabled IS set - exiting without UI\n");
					ILibSimpleDataStore_Close(db);
					return 0;
				} else {
					printf("[TCC-CHILD] tccPermissionsUIDisabled NOT set - continuing to check permissions\n");
				}
				ILibSimpleDataStore_Close(db);
			} else {
				printf("[TCC-CHILD] WARNING: Failed to open database\n");
			}
		}

		// Check all three permissions (fresh check in this new process!)
		printf("[TCC-CHILD] Calling check_accessibility_permission()...\n");
		TCC_PermissionStatus accessibility = check_accessibility_permission();
		printf("[TCC-CHILD] Accessibility result: %d\n", accessibility);

		printf("[TCC-CHILD] Calling check_fda_permission()...\n");
		TCC_PermissionStatus fda = check_fda_permission();
		printf("[TCC-CHILD] FDA result: %d\n", fda);

		printf("[TCC-CHILD] Calling check_screen_recording_permission()...\n");
		TCC_PermissionStatus screen_recording = check_screen_recording_permission();
		printf("[TCC-CHILD] Screen Recording result: %d\n", screen_recording);

		// If ALL are granted, exit without showing UI
		int all_granted = (accessibility == TCC_PERMISSION_GRANTED_USER || accessibility == TCC_PERMISSION_GRANTED_MDM) &&
		                  (fda == TCC_PERMISSION_GRANTED_USER || fda == TCC_PERMISSION_GRANTED_MDM) &&
		                  (screen_recording == TCC_PERMISSION_GRANTED_USER || screen_recording == TCC_PERMISSION_GRANTED_MDM);

		printf("[TCC-CHILD] All granted check: %d (Accessibility: %d, FDA: %d, Screen Recording: %d)\n",
		       all_granted, accessibility, fda, screen_recording);

		if (all_granted) {
			printf("[TCC-CHILD] All permissions granted - exiting without UI\n");
			return 0; // All permissions granted - no UI needed
		}

		// At least one permission missing - show UI
		printf("[TCC-CHILD] At least one permission missing - showing UI\n");
		int result = show_tcc_permissions_window();
		printf("[TCC-CHILD] UI closed with result: %d (1 = do not remind, 0 = remind again)\n", result);

		// If user clicked "Do not remind me again", save to database
		if (result == 1 && db_path != NULL) {
			printf("[TCC-CHILD] Saving tccPermissionsUIDisabled = 1 to database\n");
			void* db = ILibSimpleDataStore_Create(db_path);
			if (db != NULL) {
				ILibSimpleDataStore_Put(db, "tccPermissionsUIDisabled", "1");
				ILibSimpleDataStore_Close(db);
				printf("[TCC-CHILD] Successfully saved preference\n");
			} else {
				printf("[TCC-CHILD] WARNING: Failed to save preference - couldn't open database\n");
			}
		}

		printf("[TCC-CHILD] -tccCheck process exiting\n");
		return 0;
	}
#endif

#if defined(__APPLE__) && defined(_LINKVM)
	// TODO: Clean up stale KVM session files from previous crash/unclean shutdown
	// Now that paths are dynamic based on companyName.meshServiceName, we need to either:
	// 1. Read companyName/meshServiceName early to build correct paths for cleanup
	// 2. Use glob patterns to clean up all matching files (/tmp/*-kvm.sock, /var/run/*/session-active)
	// 3. Move cleanup to after database is loaded in MeshAgent_Start
	// For now, skipping cleanup - each serviceId has its own paths and won't conflict
	/*
	unlink("/tmp/meshagent-kvm.sock");
	unlink("/var/run/meshagent/session-active");

	// Clear all contents from /var/run/meshagent but keep the directory itself
	// This avoids QueueDirectories weirdness while cleaning up stale files
	DIR *dir = opendir("/var/run/meshagent");
	if (dir != NULL)
	{
		struct dirent *entry;
		char filepath[PATH_MAX];
		
		while ((entry = readdir(dir)) != NULL)
		{
			// Skip . and .. entries
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;
				
			snprintf(filepath, sizeof(filepath), "/var/run/meshagent/%s", entry->d_name);
			
			if (entry->d_type == DT_DIR)
			{
				// Recursively remove subdirectory - this shouldn't happen but handle it
				char rm_cmd[PATH_MAX + 20];
				snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf \"%s\"", filepath);
				system(rm_cmd);
			}
			else
			{
				// Remove regular file
				unlink(filepath);
			}
		}
		closedir(dir);
	}
	// Errors are ignored - files might not exist and that's fine
	*/
#endif

	if (argc > 2 && strcasecmp(argv[1], "-faddr") == 0)
	{
#if !defined(WIN32)
		uint64_t addrOffset = 0;
		sscanf(argv[2] + 2, "%016"PRIx64, &addrOffset);
#elif defined(WIN64)
		uint64_t addrOffset = 0;
		sscanf_s(argv[2] + 2, "%016llx", &addrOffset);
#else
		uint32_t addrOffset = 0;
		sscanf_s(argv[2] + 2, "%x", &addrOffset);
#endif

		ILibChain_DebugOffset(ILibScratchPad, sizeof(ILibScratchPad), (uint64_t)addrOffset);
		printf("%s", ILibScratchPad);
#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}

	if (argc > 2 && strcasecmp(argv[1], "-fdelta") == 0)
	{
		uint64_t delta = 0;
#ifdef WIN32
		sscanf_s(argv[2], "%lld", &delta);
#else
		sscanf(argv[2], "%"PRIu64, &delta);
#endif
		ILibChain_DebugDelta(ILibScratchPad, sizeof(ILibScratchPad), delta);
		printf("%s", ILibScratchPad);
#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}

	if (argc > 1 && strcasecmp(argv[1], "connect") == 0) { capabilities = MeshCommand_AuthInfo_CapabilitiesMask_TEMPORARY; }

	if (integratedJavaScriptLen == 0)
	{
		if (argc >= 2 && strnlen_s(argv[1], 9) >= 8 && strncmp(argv[1], "-update:", 8) == 0)
		{
			ILibMemory_AllocateRaw(integratedJavaScript, 1024);
			if (argv[1][8] == '*')
			{
				// New Style
				integratedJavaScriptLen = sprintf_s(integratedJavaScript, 1024, "require('agent-installer').update(false, '%s');", argc > 2 ? argv[2] : "null");
			}
			else
			{
				// Legacy
				integratedJavaScriptLen = sprintf_s(integratedJavaScript, 1024, "require('agent-installer').update(false, ['%s']);", argc > 2 ? argv[2] : "");
			}
		}
	}
#ifdef WIN32
	_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE); // Set SIGNAL on windows to listen for Ctrl-C
	ILib_DumpEnabledContext winExceptionContext;
#elif defined(_POSIX)
	signal(SIGPIPE, SIG_IGN); // Set a SIGNAL on Linux to listen for Ctrl-C						  
	signal(SIGINT, BreakSink);// Shutdown on Ctrl + C
	{	
		struct sigaction act;
		act.sa_handler = SIG_IGN;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;
		sigaction(SIGPIPE, &act, NULL);
	}
#endif

#ifdef WIN32
	__try
	{
		agentHost = MeshAgent_Create(capabilities);
		agentHost->meshCoreCtx_embeddedScript = integratedJavaScript;
		agentHost->meshCoreCtx_embeddedScriptLen = integratedJavaScriptLen;
		while (MeshAgent_Start(agentHost, argc, argv) != 0);
		retCode = agentHost->exitCode;
		MeshAgent_Destroy(agentHost);
		agentHost = NULL;
	}
	__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winExceptionContext))
	{
		ILib_WindowsExceptionDebugEx(&winExceptionContext);
	}
	wmain_free(argv);
	_CrtDumpMemoryLeaks();
#else
	agentHost = MeshAgent_Create(capabilities);
	agentHost->meshCoreCtx_embeddedScript = integratedJavaScript;
	agentHost->meshCoreCtx_embeddedScriptLen = integratedJavaScriptLen;

	// Note: KVM socket is now created on-demand when session starts (not at startup)
	// QueueDirectories triggers -kvm1 only when /var/run/meshagent/ contains session file

	while (MeshAgent_Start(agentHost, argc, argv) != 0);
	retCode = agentHost->exitCode;
	MeshAgent_Destroy(agentHost);
	agentHost = NULL;
#ifndef _NOILIBSTACKDEBUG
	if (crashMemory != NULL) { free(crashMemory); }
#endif
#endif
	return retCode;
}

extern void* gILibChain;
void _fdsnap()
{
	char val[] = "require('ChainViewer').getSnapshot().then(function(c) { console.log(c); console.log(require('ChainViewer').getTimerInfo()); });";
	duk_eval_string_noresult(agentHost->meshCoreCtx, val);
}
void _fdsnap2()
{
	char val[] = "console.setDestination(console.Destinations.LOGFILE);require('ChainViewer').getSnapshot().then(function(c) { console.log(c); console.log(require('ChainViewer').getTimerInfo()); });";
	duk_eval_string_noresult(agentHost->meshCoreCtx, val);
}
void _timerinfo()
{
	char *s = ILibChain_GetMetadataForTimers(gILibChain);
	printf("%s\n", s);
	ILibMemory_Free(s);
}