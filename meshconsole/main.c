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
#include "meshcore/version_info.h"

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
#import <ApplicationServices/ApplicationServices.h>
#import <CoreGraphics/CoreGraphics.h>
#endif

#ifdef __APPLE__
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <stdarg.h>
#include <fcntl.h>
#include <CoreFoundation/CoreFoundation.h>
#include "meshcore/MacOS/mac_bundle_detection.h"
#include "meshcore/MacOS/mac_tcc_detection.h"
#include "meshcore/MacOS/TCC_UI/mac_permissions_window.h"
#include "meshcore/MacOS/Install_UI/mac_install_window.h"
#include "meshcore/MacOS/Install_UI/mac_authorized_install.h"
#include "meshcore/MacOS/mac_logging_utils.h"  // Shared logging utility
#include "meshcore/MacOS/mac_plist_utils.h"    // Shared plist parsing utility
#include <CoreGraphics/CoreGraphics.h>  // For CGEventSourceFlagsState()

#endif

MeshAgentHostContainer *agentHost = NULL;
#ifdef _OPENBSD
#include <stdlib.h>
char __agentExecPath[1024] = { 0 };
#endif

#ifdef __APPLE__
#include <stdbool.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <libkern/OSByteOrder.h>

char __agentExecPath[1024] = { 0 };

// Check if the binary at the given path is a universal (FAT) binary
static bool is_universal_binary_at_path(const char *path, uint32_t *out_nfat)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return false;

	uint32_t magic;
	ssize_t n = read(fd, &magic, sizeof(magic));
	if (n != sizeof(magic))
	{
		close(fd);
		return false;
	}

	// Check for any of the FAT magic values
	bool is_fat =
		(magic == FAT_MAGIC)     ||
		(magic == FAT_CIGAM)     ||
		(magic == FAT_MAGIC_64)  ||
		(magic == FAT_CIGAM_64);

	if (!is_fat)
	{
		close(fd);
		return false; // thin Mach-O, not universal
	}

	struct fat_header fh;
	lseek(fd, 0, SEEK_SET);
	if (read(fd, &fh, sizeof(fh)) != sizeof(fh))
	{
		close(fd);
		return false;
	}
	close(fd);

	// fat_header fields are big-endian
	uint32_t nfat = OSSwapBigToHostInt32(fh.nfat_arch);
	if (out_nfat) *out_nfat = nfat;

	// "Universal" usually means >1 slices
	return nfat > 1;
}

// Check if the current executable is a universal binary
// Returns 10005 for universal binaries, otherwise returns MESH_AGENTID
static int GetEffectiveARCHID()
{
	char exePath[PATH_MAX];
	uint32_t len = sizeof(exePath);
	uint32_t nfat = 0;

	// Get the executable path
	if (_NSGetExecutablePath(exePath, &len) != 0)
	{
		return MESH_AGENTID; // Fallback to compile-time ARCHID
	}

	// Check if it's a universal binary with multiple slices
	if (is_universal_binary_at_path(exePath, &nfat))
	{
		return 10005; // Universal binary ARCHID
	}

	return MESH_AGENTID; // Single-arch binary
}

// Get the console user UID for spawning TCC permission requests
static uid_t get_console_user_uid() {
	uid_t uid = 0;
	SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("MeshAgent"), NULL, NULL);
	if (store) {
		CFStringRef userName = SCDynamicStoreCopyConsoleUser(store, &uid, NULL);
		if (userName) {
			CFRelease(userName);
		}
		CFRelease(store);
	}
	return uid;
}
#endif

//
// ╔════════════════════════════════════════════════════════════════════════════╗
// ║                    MASTER ARGUMENT LIST                                    ║
// ║                  (Single Source of Truth)                                  ║
// ╚════════════════════════════════════════════════════════════════════════════╝
//
// This is the AUTHORITATIVE list of ALL command-line arguments supported by
// MeshAgent across ALL platforms. When adding new arguments:
//
// 1. Add to appropriate section below (ALL PLATFORMS or platform-specific)
// 2. Update modules/agent-installer.js if JavaScript needs to parse it
// 3. Update help text in print_help() function (line 650+)
// 4. Update documentation in docs/ if user-facing
//
// VALIDATION STATUS:
// - macOS: ACTIVE (enforced via validate_argument())
// - Other platforms: DOCUMENTATION ONLY (validation disabled)
//
// To enable validation on other platforms:
// - Change ENABLE_ARGUMENT_VALIDATION macro for that platform
// - Test thoroughly to ensure no legitimate use cases are blocked
//

// Control validation per platform
// NOTE: The allow lists below include arguments for ALL platforms (Windows, Linux,
// macOS, BSD), not just macOS. Validation is currently only enforced on macOS, but
// the lists are maintained as a complete cross-platform reference. Arguments for
// other platforms are included but have not been tested on those platforms.
#if defined(__APPLE__)
	#define ENABLE_ARGUMENT_VALIDATION 1
#else
	#define ENABLE_ARGUMENT_VALIDATION 0
#endif

// ═══════════════════════════════════════════════════════════════════════
// ARGUMENT ARRAYS - Shared by validate_argument() and detect_argument_platform()
// ═══════════════════════════════════════════════════════════════════════

// ┌─────────────────────────────────────────────────────────────────────┐
// │ ALL PLATFORMS - Arguments used on Windows, Linux, macOS, BSD        │
// └─────────────────────────────────────────────────────────────────────┘

// Simple flags (exact match, no value)
static const char* ALL_PLATFORMS_simple_flags[] = {
		// Help & Information
		"-help", "--help", "-h", "--all",
		"-version",           // Print version number (YY.MM.DD format)
		"-buildver",          // Print build version (HH.MM.SS format)
		"-buildversion",      // Alias for -buildver
		"-fullversion",       // Print full version (YY.MM.DD HH.MM.SS)
		"-info",              // Print agent information
		"-licenses",          // Print license information
		"-nodeid",            // Print node ID
		"-name",              // Print agent name
		"-agentHash",         // Print agent executable hash (SHA384, truncated)
		"-agentFullHash",     // Print agent executable hash (SHA384, full)
		"-updaterversion",    // Print updater version
		"-state",             // Fetch and display agent state

		// Installation & Service Management
		"-install",           // Install as service (simple mode)
		"-finstall",          // Full install with all options
		"-fullinstall",       // Alias for -finstall
		"-uninstall",         // Uninstall service
		"-funinstall",        // Full uninstall (remove data)
		"-fulluninstall",     // Alias for -funinstall
		"-upgrade",           // Upgrade existing installation

		// Connection & Network
		"connect",            // Connect to server (interactive mode)
		"--slave",            // Run as slave agent
		"--netinfo",          // Display network information

		// Execution & Scripting
		"-exec",              // Execute JavaScript code
		"-b64exec",           // Execute base64-encoded JavaScript
		"-faddr",             // Force address
		"-fdelta",            // Force delta

		// Backup Control
		"--backup",           // Create backup during install/upgrade (flag format)

		// Development & Testing
		"-export",            // Export configuration
		"-import",            // Import configuration

		// Service Control (non-macOS)
		"run",                // Run as console agent (foreground)
		"start",              // Start as daemon/service
		"stop",               // Stop daemon/service

		// Interactive Mode
		"-mesh",              // Print mesh configuration info
		"-translations",      // Print translation strings
		"-connect",           // Connect to server (dash form)
		"-update",            // Update/install (interactive mode)

		NULL
	};

// Prefix flags (starts with these, value follows)
static const char* ALL_PLATFORMS_prefix_flags[] = {
		// Installation Paths & Files
		"--installPath=",     // Installation directory path
		"--mshPath=",         // Path to .msh configuration file
		"--target=",          // Target binary path
		"--fileName=",        // Binary file name

		// Service Configuration
		"--meshServiceName=", // Service name (primary)
		"--serviceName=",     // Service name (backward compat alias)
		"--companyName=",     // Company name for service identification
		"--displayName=",     // Service display name
		"--description=",     // Service description
		"--serviceId=",       // Unique service identifier (for multiple instances)

		// Feature Control
		"--disableUpdate=",   // Disable auto-updates (0=enable, 1=disable)
		"--allowNoMsh=",      // Allow operation without .msh file

		// Logging & Output Control
		"--verbose=",         // Verbose logging level
		"--info=",            // Info logging level
		"--quiet=",           // Quiet mode (minimal output)
		"--silent=",          // Silent mode (no output)
		"--log=",             // Log level (0-3)
		"--readonly=",        // Read-only filesystem mode

		// Backup Control (value format)
		"--backup=",          // Create backup during install/upgrade (value format)

		// Advanced Options
		"--script-db",        // Script database path
		"--script-flags",     // Script execution flags
		"--script-timeout",   // Script timeout
		"--script-connect",   // Script connection mode
		"--no-embedded=",     // Disable embedded resources
		"--expandedPath=",    // Expanded path
		"--filePath=",        // File path
		"--modulesPath=",     // Modules path
		"--resetnodeid",      // Reset node ID

		// KVM Options
		"--allowedUIDs=",     // Allowed user IDs for KVM sessions
		"--virtualDM=",       // Virtual display manager mode

		// Proxy
		"--autoproxy=",       // Auto-proxy configuration domain

		// Localization
		"--lang=",            // Language selection

		// Self-Test & Diagnostics
		"--debugMode=",       // Enable debug mode (self-test)
		"--dumpOnly=",        // Dump-only mode (self-test)
		"--cycleCount=",      // Cycle count (self-test)
		"--showCoreInfo=",    // Show core info (self-test)
		"--smbios=",          // Show SMBIOS information (self-test)

		// Testing
		"--fakeUpdate=",      // Simulate update (testing)

		NULL
	};

// ┌─────────────────────────────────────────────────────────────────────┐
// │ WINDOWS ONLY                                                         │
// └─────────────────────────────────────────────────────────────────────┘

static const char* WINDOWS_simple_flags[] = {
		"-nocertstore",       // Don't use Windows Certificate Store
		"-recovery",          // Windows recovery mode
		"-kvm0",              // Windows KVM mode 0
		"-kvm1",              // Windows KVM mode 1
		"-coredump",          // Enable core dump (with -kvm0/-kvm1)
		"-remotecursor",      // Enable remote cursor (with -kvm0/-kvm1)
		"-lang",              // Show current language (simple flag)
		"exstate",            // Extended service state
		"state",              // Service state (without dash)
		"-start",             // Start service
		"-stop",              // Stop service
		"restart",            // Restart service
		"-restart",           // Restart service (dash form)
		"-resetnodeid",       // Reset node ID
		"-setfirewall",       // Set Windows firewall rules
		"-clearfirewall",     // Clear Windows firewall rules
		"-checkfirewall",     // Check Windows firewall rules
		"meshcmd",            // MeshCmd mode
		"-netinfo",           // Network information (single-dash form)
		NULL
	};

static const char* WINDOWS_prefix_flags[] = {
	"--installedByUser=", // Windows: User registry key who installed
	"-update:",           // Windows: Update path
	"--hideConsole=",     // Hide console window
	"--exitPID=",         // Exit when PID dies
	NULL
};

// ┌─────────────────────────────────────────────────────────────────────┐
// │ LINUX ONLY                                                           │
// └─────────────────────────────────────────────────────────────────────┘

static const char* LINUX_simple_flags[] = {
	"-daemon",            // Run as daemon (Linux daemon mode)
	"-d",                 // Start as daemon (alias for start)
	"-s",                 // Stop daemon (alias for stop)
	NULL
};

static const char* LINUX_prefix_flags[] = {
	"--installedByUser=", // Linux: UID of user who installed
	NULL
};

// ┌─────────────────────────────────────────────────────────────────────┐
// │ macOS ONLY                                                           │
// └─────────────────────────────────────────────────────────────────────┘

static const char* MACOS_simple_flags[] = {
	"-tccCheck",          // Check TCC (Transparency Consent Control) permissions
	"-show-install-ui",   // Show installation UI
	"-show-tcc-ui",       // Show TCC permissions window (standalone, same as SHIFT+double-click)
	"-check-tcc",         // Check TCC permissions, show UI if needed (no pipe, fire-and-forget)
	"-request-accessibility",   // Request Accessibility permission (spawned as user)
	"-request-screenrecording", // Request Screen Recording permission (spawned as user)
	"-kvm1",              // macOS KVM mode (LaunchAgent via QueueDirectories)
	"-config",            // Configure/update launchd scripts for existing installation
	NULL
};

static const char* MACOS_prefix_flags[] = {
	"--disableTccCheck=", // Disable TCC check (0=check, 1=skip)
	"--copy-msh=",        // Copy .msh file during install (0=no, 1=yes)
	"--meshAgentLogging=",// Configure meshagent launchd logging to /tmp (0=no, 1=yes)
	"--setServiceID=",    // Set service identifier for fresh install (e.g., com.company.service)
	"--appBundle=",       // macOS app bundle path
	"--installedByUser=", // macOS: UID of user who installed
	NULL
};

// ┌─────────────────────────────────────────────────────────────────────┐
// │ BSD ONLY                                                             │
// └─────────────────────────────────────────────────────────────────────┘

static const char* BSD_simple_flags[] = {
	"-daemon",            // Run as daemon (BSD daemon mode - shared with Linux)
	"-d",                 // Start as daemon (alias for start)
	"-s",                 // Stop daemon (alias for stop)
	NULL
};

static const char* BSD_prefix_flags[] = {
	// TODO: Audit BSD-specific arguments if any
	NULL
};

// ═══════════════════════════════════════════════════════════════════════
// VALIDATION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

// Validate command-line arguments against known flags
// Uses case-insensitive matching to match the processing code (strcasecmp)
// Returns 1 if valid, 0 if unknown flag detected
int validate_argument(const char* arg)
{
	size_t len = strlen(arg);

	// Check ALL PLATFORMS simple flags
	for (int i = 0; ALL_PLATFORMS_simple_flags[i] != NULL; i++) {
		if (strcasecmp(arg, ALL_PLATFORMS_simple_flags[i]) == 0) return 1;
	}

	// Check ALL PLATFORMS prefix flags
	for (int i = 0; ALL_PLATFORMS_prefix_flags[i] != NULL; i++) {
		size_t prefix_len = strlen(ALL_PLATFORMS_prefix_flags[i]);
		if (len >= prefix_len && strncasecmp(arg, ALL_PLATFORMS_prefix_flags[i], prefix_len) == 0) {
			return 1;
		}
	}

	// Check PLATFORM-SPECIFIC flags
#ifdef _WIN32
	// Windows-specific
	for (int i = 0; WINDOWS_simple_flags[i] != NULL; i++) {
		if (strcasecmp(arg, WINDOWS_simple_flags[i]) == 0) return 1;
	}
	for (int i = 0; WINDOWS_prefix_flags[i] != NULL; i++) {
		size_t prefix_len = strlen(WINDOWS_prefix_flags[i]);
		if (len >= prefix_len && strncasecmp(arg, WINDOWS_prefix_flags[i], prefix_len) == 0) {
			return 1;
		}
	}
#endif

#ifdef __linux__
	// Linux-specific
	for (int i = 0; LINUX_simple_flags[i] != NULL; i++) {
		if (strcasecmp(arg, LINUX_simple_flags[i]) == 0) return 1;
	}
	for (int i = 0; LINUX_prefix_flags[i] != NULL; i++) {
		size_t prefix_len = strlen(LINUX_prefix_flags[i]);
		if (len >= prefix_len && strncasecmp(arg, LINUX_prefix_flags[i], prefix_len) == 0) {
			return 1;
		}
	}
#endif

#ifdef __APPLE__
	// macOS-specific
	for (int i = 0; MACOS_simple_flags[i] != NULL; i++) {
		if (strcasecmp(arg, MACOS_simple_flags[i]) == 0) return 1;
	}
	for (int i = 0; MACOS_prefix_flags[i] != NULL; i++) {
		size_t prefix_len = strlen(MACOS_prefix_flags[i]);
		if (len >= prefix_len && strncasecmp(arg, MACOS_prefix_flags[i], prefix_len) == 0) {
			return 1;
		}
	}
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	// BSD-specific
	for (int i = 0; BSD_simple_flags[i] != NULL; i++) {
		if (strcasecmp(arg, BSD_simple_flags[i]) == 0) return 1;
	}
	for (int i = 0; BSD_prefix_flags[i] != NULL; i++) {
		size_t prefix_len = strlen(BSD_prefix_flags[i]);
		if (len >= prefix_len && strncasecmp(arg, BSD_prefix_flags[i], prefix_len) == 0) {
			return 1;
		}
	}
#endif

	// Check .js file extension (script execution)
	if (len >= 3 && strcasecmp(arg + len - 3, ".js") == 0) return 1;

	// Allow positional arguments (don't start with -)
	// These are values for flags like -exec <code>
	// But reject KEY=VALUE patterns without -- prefix (likely typos like LOG=3 instead of --log=3)
	if (arg[0] != '-') {
		// If it contains '=' it's probably a malformed flag
		if (strchr(arg, '=') != NULL) return 0;
		return 1;
	}

	return 0; // Unknown flag
}

// Helper function to detect which platform(s) an argument belongs to
// Uses case-insensitive matching to match validate_argument() and processing code
// Returns platform name string, or NULL if not found anywhere
const char* detect_argument_platform(const char* arg)
{
	size_t len = strlen(arg);

	// Check Windows
	for (int i = 0; WINDOWS_simple_flags[i] != NULL; i++) {
		if (strcasecmp(arg, WINDOWS_simple_flags[i]) == 0) return "Windows";
	}
	for (int i = 0; WINDOWS_prefix_flags[i] != NULL; i++) {
		size_t prefix_len = strlen(WINDOWS_prefix_flags[i]);
		if (len >= prefix_len && strncasecmp(arg, WINDOWS_prefix_flags[i], prefix_len) == 0) {
			return "Windows";
		}
	}

	// Check Linux
	for (int i = 0; LINUX_simple_flags[i] != NULL; i++) {
		if (strcasecmp(arg, LINUX_simple_flags[i]) == 0) return "Linux";
	}
	for (int i = 0; LINUX_prefix_flags[i] != NULL; i++) {
		size_t prefix_len = strlen(LINUX_prefix_flags[i]);
		if (len >= prefix_len && strncasecmp(arg, LINUX_prefix_flags[i], prefix_len) == 0) {
			return "Linux";
		}
	}

	// Check macOS
	for (int i = 0; MACOS_simple_flags[i] != NULL; i++) {
		if (strcasecmp(arg, MACOS_simple_flags[i]) == 0) return "macOS";
	}
	for (int i = 0; MACOS_prefix_flags[i] != NULL; i++) {
		size_t prefix_len = strlen(MACOS_prefix_flags[i]);
		if (len >= prefix_len && strncasecmp(arg, MACOS_prefix_flags[i], prefix_len) == 0) {
			return "macOS";
		}
	}

	// Check BSD
	for (int i = 0; BSD_simple_flags[i] != NULL; i++) {
		if (strcasecmp(arg, BSD_simple_flags[i]) == 0) return "BSD";
	}
	for (int i = 0; BSD_prefix_flags[i] != NULL; i++) {
		size_t prefix_len = strlen(BSD_prefix_flags[i]);
		if (len >= prefix_len && strncasecmp(arg, BSD_prefix_flags[i], prefix_len) == 0) {
			return "BSD";
		}
	}

	return NULL; // Not found in any platform list
}

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

// Removed: discover_service_id_from_plist() — now using shared mesh_plist_find_service_id()
// Removed: parse_service_id() — dead code, never called
#endif

// Version info functions moved to meshcore/version_info.c for DRY compliance
// Include meshcore/version_info.h to use get_embedded_version(), get_embedded_build_version(), get_embedded_full_version()

#ifdef WIN32
#define wmain_free(argv) for(argvi=0;argvi<(int)(ILibMemory_Size(argv)/sizeof(void*));++argvi){ILibMemory_Free(argv[argvi]);}ILibMemory_Free(argv);
int wmain(int argc, char **wargv)
#else
int main(int argc, char **argv)
#endif
{
#if defined(_OPENBSD) || defined(__APPLE__)
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

	// Check if launched from Finder (via Info.plist LSEnvironment variable)
	// This check MUST happen early, before any command processing that might trigger TCC permission prompts
	// IMPORTANT: Skip this check if running with install/upgrade/uninstall flags
	int has_forbidden_flag = 0;
	const char* forbidden_flags[] = {
		"-upgrade", "-install", "-fullinstall",
		"-uninstall", "-fulluninstall", "-update"
	};
	for (int i = 1; i < argc; i++) {
		for (int j = 0; j < 6; j++) {
			if (strcmp(argv[i], forbidden_flags[j]) == 0) {
				has_forbidden_flag = 1;
				break;
			}
		}
		if (has_forbidden_flag) break;
	}

	// Check for -show-install-ui flag (direct launch of Installation Assistant)
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-show-install-ui") == 0) {
			mesh_log_message("[MAIN] [%ld] MeshAgent launched with -show-install-ui\n", time(NULL));

			InstallResult result = show_install_assistant_window();
			mesh_log_message("[MAIN] [%ld] Installation Assistant returned (cancelled=%d, mode=%d)\n",
			        time(NULL), result.cancelled, result.mode);
			mesh_log_message("[MAIN] [%ld] Installation Assistant closed, exiting\n", time(NULL));
			exit(0);
		}
	}

	// Check for -show-tcc-ui flag (standalone TCC permissions window)
	// This allows end-users to manually check TCC permissions from command line
	// Functions identically to SHIFT+double-click on app bundle
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-show-tcc-ui") == 0) {
			fprintf(stderr, "[MAIN] MeshAgent launched with -show-tcc-ui - showing TCC permissions window\n");
			uid_t consoleUID = get_console_user_uid();
			int result = show_tcc_permissions_window(0, __agentExecPath, consoleUID); // 0 = hide "Do not remind me again" checkbox
			fprintf(stderr, "[MAIN] TCC permissions window closed (do not remind again: %d)\n", result);
			return 0;
		}
	}

	if (!has_forbidden_flag && getenv("LAUNCHED_FROM_FINDER") != NULL)
	{
		// Check which modifier keys are being held
		CGEventFlags flags = CGEventSourceFlagsState(kCGEventSourceStateCombinedSessionState);
		int cmdKeyHeld = (flags & kCGEventFlagMaskCommand) != 0;
		int shiftKeyHeld = (flags & kCGEventFlagMaskShift) != 0;

		if (cmdKeyHeld)
		{
			// CMD + double-click -> show Installation Assistant
			{
				char debugPath[1024];
				uint32_t debugPathSize = sizeof(debugPath);
				_NSGetExecutablePath(debugPath, &debugPathSize);
				fprintf(stderr, "[DEBUG] Binary path: %s\n", debugPath);
				fprintf(stderr, "[DEBUG] PID: %d, UID: %d, EUID: %d\n", getpid(), getuid(), geteuid());
			}
			mesh_log_message("[MAIN] [%ld] MeshAgent launched from Finder with CMD key - showing Installation Assistant\n", time(NULL));

			// UI launches unprivileged; install/upgrade runs via execute_command() in mac_authorized_install.m
			InstallResult result = show_install_assistant_window();
			mesh_log_message("[MAIN] [%ld] Installation Assistant returned (cancelled=%d, mode=%d)\n",
			        time(NULL), result.cancelled, result.mode);

			// Note: The Installation Assistant window handles upgrade/install execution internally
			// with progress UI, so we don't need to execute anything here. Just exit.
			mesh_log_message("[MAIN] [%ld] Installation Assistant closed, exiting\n", time(NULL));
			exit(0);
		}
		else if (shiftKeyHeld)
		{
			// SHIFT + double-click -> ALWAYS show TCC permissions UI (regardless of current status)
			fprintf(stderr, "MeshAgent launched from Finder with SHIFT key - showing TCC permissions window\n");
			uid_t consoleUID = get_console_user_uid();
			int result = show_tcc_permissions_window(0, __agentExecPath, consoleUID); // 0 = hide "Do not remind me again" checkbox
			fprintf(stderr, "TCC permissions window closed (do not remind again: %d)\n", result);
			return 0;
		}
		else
		{
			// Normal double-click (no modifier keys) -> Exit without showing any UI
			fprintf(stderr, "MeshAgent launched from Finder without modifier keys - exiting\n");
			return 0;
		}
	}
#endif

	// Validate all command-line arguments before processing
#if ENABLE_ARGUMENT_VALIDATION
	for (int i = 1; i < argc; i++)
	{
		// Skip validation of arguments that follow flags expecting arbitrary values
		// -exec and -b64exec take JavaScript code as the next argument
		// -faddr and -fdelta take memory address/delta values
		// --script-db, --script-flags, --script-timeout take space-separated values
		if (i > 1 && (strcasecmp(argv[i-1], "-exec") == 0 || strcasecmp(argv[i-1], "-b64exec") == 0 ||
		              strcasecmp(argv[i-1], "-faddr") == 0 || strcasecmp(argv[i-1], "-fdelta") == 0 ||
		              strcasecmp(argv[i-1], "--script-db") == 0 || strcasecmp(argv[i-1], "--script-flags") == 0 ||
		              strcasecmp(argv[i-1], "--script-timeout") == 0))
		{
			continue; // Skip validation - next argument is a value, not a flag
		}

		if (!validate_argument(argv[i]))
		{
			// Check if this is a platform-specific argument
			const char* platform = detect_argument_platform(argv[i]);

			if (platform != NULL)
			{
				// Argument exists but is for a different platform
				fprintf(stderr, "ERROR: Platform-specific argument at position %d: '%s'\n", i, argv[i]);
#ifdef __APPLE__
				fprintf(stderr, "This is a %s-only argument and cannot be used on macOS.\n", platform);
#elif defined(_WIN32)
				fprintf(stderr, "This is a %s-only argument and cannot be used on Windows.\n", platform);
#elif defined(__linux__)
				fprintf(stderr, "This is a %s-only argument and cannot be used on Linux.\n", platform);
#else
				fprintf(stderr, "This is a %s-only argument and cannot be used on this platform.\n", platform);
#endif
			}
			else
			{
				// Argument not found in any platform list - truly unknown
				fprintf(stderr, "ERROR: Unknown argument at position %d: '%s'\n", i, argv[i]);
			}

			fprintf(stderr, "Use -help for available options\n");
			fprintf(stderr, "\n");
#ifdef __APPLE__
			fprintf(stderr, "Note: Argument validation is ACTIVE on this platform (macOS).\n");
#else
			fprintf(stderr, "Note: Argument validation is ACTIVE on this platform.\n");
#endif
			fprintf(stderr, "For more info, see the master argument list in meshconsole/main.c (line ~145)\n");
#ifdef WIN32
			wmain_free(argv);
#endif
			return 1;
		}
	}
#else
	// Validation disabled on this platform - arguments pass through without checking
	// (Master argument list in main.c still serves as documentation reference)
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

#ifdef __APPLE__
		printf("Agent ARCHID: %d\n", GetEffectiveARCHID());
#else
		printf("Agent ARCHID: %d\n", MESH_AGENTID);
#endif
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
	if (argc > 1 && (strcmp(argv[1], "-help") == 0 ||
	                 strcmp(argv[1], "--help") == 0 ||
	                 strcmp(argv[1], "-h") == 0))
	{
		// Check for --all flag to show full help
		int showAll = 0;
		for (int j = 2; j < argc; j++)
		{
			if (strcmp(argv[j], "--all") == 0) { showAll = 1; break; }
		}

		printf("MeshAgent - MeshCentral remote management agent\n\n");
		printf("Usage: meshagent [options] [script.js]\n\n");
		printf("Information:\n");
		printf("  -help, --help, -h     Show this help message\n");
		printf("  -help --all           Show all arguments (including platform-specific)\n");
		printf("  -version              Show version\n");
		printf("  -fullversion          Show complete version (version + build)\n");
		printf("  -info                 Show detailed agent information\n");
		printf("  -licenses             Show open source licenses\n");
		printf("  -nodeid               Show agent's unique node ID\n");
		printf("  -name                 Show agent's service name\n");
		printf("  -agentHash            Show agent hash (short)\n");
		printf("  -agentFullHash        Show agent hash (full)\n\n");
		printf("Installation:\n");
		printf("  -install              Install agent as system service\n");
		printf("  -finstall             Full install (with recovery)\n");
		printf("  -upgrade              Upgrade existing installation\n");
		printf("  -uninstall            Uninstall agent service\n");
		printf("  -funinstall           Full uninstall (remove all data)\n\n");
		printf("Installation Options:\n");
		printf("  --installPath=PATH    Installation directory\n");
		printf("  --mshPath=PATH        Path to .msh configuration file\n");
		printf("  --meshServiceName=N   Service name component\n");
		printf("  --companyName=NAME    Company name component\n");
		printf("  --serviceId=ID        Unique service identifier (for multiple instances)\n");
		printf("  --copy-msh=1          Copy .msh file to install location\n");
		printf("  --disableUpdate=1     Disable automatic updates\n");
		printf("  --backup=1            Create backup during install/upgrade\n\n");
		printf("Service Control:\n");
		printf("  run                   Run as console agent (foreground)\n");
		printf("  start, -d             Start as background daemon\n");
		printf("  stop, -s              Stop background daemon\n");
		printf("  -daemon               Run in foreground daemon mode\n");
		printf("  -state                Show agent state\n\n");
		printf("Script Execution:\n");
		printf("  script.js             Execute JavaScript file\n");
		printf("  -exec CODE            Execute JavaScript code string\n");
		printf("  -b64exec CODE         Execute base64-encoded JavaScript\n\n");
		printf("Module Management:\n");
		printf("  -export               Export embedded JavaScript modules\n");
		printf("  -import               Import modules from filesystem\n\n");
		printf("Update:\n");
		printf("  -update:URL           Self-update from URL\n\n");

		if (showAll)
		{
			printf("─── Extended Reference (all platforms) ─────────────────────────────\n\n");
			printf("Information (additional):\n");
			printf("  -buildver             Show build version\n");
			printf("  -buildversion         Alias for -buildver\n");
			printf("  -updaterversion       Show updater version\n\n");
			printf("Installation (aliases):\n");
			printf("  -fullinstall          Alias for -finstall\n");
			printf("  -fulluninstall        Alias for -funinstall\n\n");
			printf("Installation Options (additional):\n");
			printf("  --serviceName=NAME    Alias for --meshServiceName\n");
			printf("  --displayName=NAME    Service display name\n");
			printf("  --description=TEXT    Service description\n");
			printf("  --setServiceID=ID     Set service identifier during fresh install (macOS)\n");
			printf("  --fileName=NAME       Binary file name\n");
			printf("  --target=PATH         Target binary path\n");
			printf("  --allowNoMsh=1        Allow operation without .msh file\n");
			printf("  --backup              Create backup (flag form, same as --backup=1)\n");
			printf("  --installedByUser=UID User who performed the installation\n\n");
			printf("Interactive Mode:\n");
			printf("  -mesh                 Print mesh configuration info\n");
			printf("  -translations         Print translation strings\n");
			printf("  -connect              Connect to server (interactive mode)\n");
			printf("  -update               Update/install (interactive mode)\n");
			printf("  --lang=CODE           Set language (e.g., --lang=en)\n\n");
			printf("Script Execution (additional):\n");
			printf("  --script-db PATH      Database path for script mode\n");
			printf("  --script-flags FLAGS  Script execution flags\n");
			printf("  --script-timeout SEC  Watchdog timeout (0=unlimited)\n");
			printf("  --script-connect      Enable MeshCentral connection\n\n");
			printf("Module Management (additional):\n");
			printf("  --no-embedded=1       Disable embedded JavaScript resources\n");
			printf("  --expandedPath=PATH   Expanded path for module export\n");
			printf("  --filePath=PATH       File path for polyfills output\n");
			printf("  --modulesPath=PATH    Modules directory path\n\n");
			printf("KVM Options:\n");
			printf("  --allowedUIDs=LIST    Allowed user IDs for KVM sessions\n");
			printf("  --virtualDM=1         Enable virtual display manager mode\n\n");
			printf("Network & Proxy:\n");
			printf("  --slave               Run as slave agent\n");
			printf("  --netinfo             Display network information\n");
			printf("  connect               Development mode connection\n");
			printf("  --autoproxy=DOMAIN    Auto-proxy configuration domain\n\n");
			printf("Advanced:\n");
			printf("  --readonly=1          Read-only database mode\n");
			printf("  --resetnodeid         Reset node ID\n");
			printf("  --verbose=LEVEL       Verbose logging level\n");
			printf("  --info=LEVEL          Info logging level\n");
			printf("  --quiet=1             Quiet mode (minimal output)\n");
			printf("  --silent=1            Silent mode (no output)\n");
			printf("  --log=LEVEL           Log level (0-3)\n\n");
			printf("Self-Test & Diagnostics:\n");
			printf("  --debugMode=1         Enable debug mode (self-test)\n");
			printf("  --dumpOnly=1          Dump-only mode (self-test)\n");
			printf("  --cycleCount=N        Cycle count (self-test)\n");
			printf("  --showCoreInfo=1      Show core info (self-test)\n");
			printf("  --smbios=1            Show SMBIOS information (self-test)\n");
			printf("  --fakeUpdate=1        Simulate update (testing)\n\n");
			printf("Debug:\n");
			printf("  -faddr ADDR           Memory address debug tool\n");
			printf("  -fdelta DELTA         Memory delta debug tool\n\n");
			printf("─── macOS Specific ─────────────────────────────────────────────────\n\n");
			printf("  -kvm1                 KVM remote desktop subprocess mode\n");
			printf("  -config               Update launchd scripts for existing install\n");
			printf("  -tccCheck             TCC permissions check subprocess (with pipe)\n");
			printf("  -check-tcc            Check TCC permissions, show UI if needed\n");
			printf("  -show-install-ui      Launch Installation Assistant GUI\n");
			printf("                        Note: Also auto-launches with CMD+double-click on .app\n");
			printf("  -show-tcc-ui          Show TCC permissions window\n");
			printf("                        Note: Also auto-launches with SHIFT+double-click on .app\n");
			printf("  -request-accessibility        Request Accessibility permission\n");
			printf("  -request-screenrecording      Request Screen Recording permission\n");
			printf("                        WARNING: -request-* flags request permissions for the\n");
			printf("                        calling process. From a terminal, that means the terminal\n");
			printf("                        app, not MeshAgent. These are spawned by the TCC UI.\n");
			printf("  --appBundle=1         Running from app bundle\n");
			printf("  --disableTccCheck=1   Disable TCC permission check UI\n");
			printf("  --meshAgentLogging=1  Enable launchd logging to /tmp\n");
			printf("  --setServiceID=ID     Set service identifier during fresh install\n\n");
			printf("─── Windows Specific ───────────────────────────────────────────────\n\n");
			printf("  -kvm0                 KVM mode 0\n");
			printf("  -kvm1                 KVM mode 1\n");
			printf("  -coredump             Enable core dump (with -kvm0/-kvm1)\n");
			printf("  -remotecursor         Enable remote cursor (with -kvm0/-kvm1)\n");
			printf("  -nocertstore          Disable Windows Certificate Store\n");
			printf("  -recovery             Set recovery capabilities\n");
			printf("  -resetnodeid          Reset agent node ID\n");
			printf("  -lang                 Show current language\n");
			printf("  --hideConsole=1       Hide console window\n");
			printf("  --exitPID=PID         Exit when specified PID terminates\n");
			printf("  start, -start         Start Windows service\n");
			printf("  stop, -stop           Stop Windows service\n");
			printf("  restart, -restart     Restart Windows service\n");
			printf("  state, exstate        Show service state / extended state\n");
			printf("  -setfirewall          Set Windows firewall rules\n");
			printf("  -clearfirewall        Clear Windows firewall rules\n");
			printf("  -checkfirewall        Check Windows firewall rules\n");
			printf("  meshcmd               Enter MeshCmd mode\n");
			printf("  -netinfo              Display network information\n\n");
			printf("─── Linux/BSD Specific ─────────────────────────────────────────────\n\n");
			printf("  -daemon               Run as foreground daemon\n");
			printf("  -d                    Start daemon (alias for start)\n");
			printf("  -s                    Stop daemon (alias for stop)\n");
		}
		else
		{
			printf("Use -help --all for the full argument reference including\n");
			printf("platform-specific, advanced, and diagnostic options.\n");
		}
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
	if (argc > 1 && (strcasecmp(argv[1], "-buildver") == 0 || strcasecmp(argv[1], "-buildversion") == 0))
	{
#ifdef __APPLE__
		char *build = get_embedded_build_version();
		if (build != NULL)
		{
			printf("%s\n", build);
			free(build);
		}
		else
		{
			printf("Build version information not available\n");
		}
#else
		printf("-buildver flag is only supported on macOS builds\n");
#endif
#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}
	if (argc > 1 && strcasecmp(argv[1], "-fullversion") == 0)
	{
#ifdef __APPLE__
		char *full_version = get_embedded_full_version();
		if (full_version != NULL)
		{
			printf("%s\n", full_version);
			free(full_version);
		}
		else
		{
			printf("Full version information not available\n");
		}
#else
		printf("-fullversion flag is only supported on macOS builds\n");
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
				serviceId = mesh_plist_find_service_id("/Library/LaunchAgents", binaryPath);

				if (serviceId != NULL)
				{
					printf("KVM: Discovered serviceId from LaunchAgent plist: %s\n", serviceId);
				}
				else
				{
					printf("KVM: Warning - Could not find LaunchAgent plist for %s\n", binaryPath);
					printf("KVM: Using default serviceId\n");
					serviceId = strdup("unknown-agent");
				}
			}
			else
			{
				printf("KVM: Warning - Could not determine binary path (argv[0]=%s)\n", argv[0]);
				printf("KVM: Using default serviceId\n");
				serviceId = strdup("unknown-agent");
			}
		}

		// Strip -agent suffix if present (LaunchAgent label is {serviceId}-agent, paths use base serviceId)
		if (serviceId != NULL)
		{
			size_t len = strlen(serviceId);
			if (len > 6 && strcmp(serviceId + len - 6, "-agent") == 0)
			{
				serviceId[len - 6] = '\0';
			}
		}

		kvm_server_mainloop((void*)(uint64_t)getpid(), serviceId);

		// Cleanup
		if (serviceId != NULL) free(serviceId);

		return 0;
	}

	// -check-tcc: Check TCC permissions and show UI if needed (fire-and-forget, no pipe)
	// Reads/writes disableTccCheck directly from/to meshagent.db
	if (argc > 1 && strcasecmp(argv[1], "-check-tcc") == 0)
	{

		// Get executable path and build bundle-aware database path
		char exePath[PATH_MAX];
		char dbPath[PATH_MAX];
		char mshPath[PATH_MAX];
		uint32_t len = sizeof(exePath);

		if (_NSGetExecutablePath(exePath, &len) != 0) {
			return 1;
		}

		// Check if running from bundle and adjust paths accordingly
		if (is_running_from_bundle()) {
			char* bundlePath = get_bundle_path();
			if (bundlePath == NULL) {
				return 1;
			}

			// get_bundle_path() returns the .app path, e.g. /opt/meshagent/MeshAgent.app
			// We need the parent directory (/opt/meshagent/) and the exe name (meshagent)

			// Extract exe name from exePath (already resolved above)
			char* exeSlash = strrchr(exePath, '/');
			char exeNameCopy[256];
			if (exeSlash != NULL) {
				strncpy(exeNameCopy, exeSlash + 1, sizeof(exeNameCopy) - 1);
				exeNameCopy[sizeof(exeNameCopy) - 1] = '\0';
			} else {
				strncpy(exeNameCopy, "meshagent", sizeof(exeNameCopy) - 1);
				exeNameCopy[sizeof(exeNameCopy) - 1] = '\0';
			}

			// Strip .app bundle name to get parent directory
			char* lastSlash = strrchr(bundlePath, '/');
			if (lastSlash != NULL && lastSlash != bundlePath) {
				*lastSlash = '\0'; // /opt/meshagent/MeshAgent.app -> /opt/meshagent
			}

			snprintf(dbPath, sizeof(dbPath), "%s/%s.db", bundlePath, exeNameCopy);
			snprintf(mshPath, sizeof(mshPath), "%s/%s.msh", bundlePath, exeNameCopy);
			free(bundlePath);
		} else {
			// Standalone binary - database is next to executable
			snprintf(dbPath, sizeof(dbPath), "%s.db", exePath);
			snprintf(mshPath, sizeof(mshPath), "%s.msh", exePath);
		}

		// Open database READ-ONLY (no exclusive lock - allows concurrent access with daemon)
		ILibSimpleDataStore db = ILibSimpleDataStore_CreateEx2(dbPath, 0, 1); // 1 = readonly
		if (db == NULL) {
			return 1;
		}

		// Check if TCC check is disabled in database
		char buffer[32];
		int dbLen = ILibSimpleDataStore_Get(db, "disableTccCheck", buffer, sizeof(buffer));
		if (dbLen > 0) {
			buffer[dbLen] = '\0';
			if (strcmp(buffer, "1") == 0) {
				ILibSimpleDataStore_Close(db);
				return 0;
			}
		} else {
		}

		// Check all three permissions (fresh check in this new process!)
		uid_t consoleUID = get_console_user_uid();

		TCC_PermissionStatus accessibility = check_accessibility_permission();
		TCC_PermissionStatus fda = check_fda_permission();
		TCC_PermissionStatus screen_recording = check_screen_recording_permission();

		// If ALL are granted, exit without showing UI
		int all_granted = (accessibility == TCC_PERMISSION_GRANTED_USER || accessibility == TCC_PERMISSION_GRANTED_MDM) &&
		                  (fda == TCC_PERMISSION_GRANTED_USER || fda == TCC_PERMISSION_GRANTED_MDM) &&
		                  (screen_recording == TCC_PERMISSION_GRANTED_USER || screen_recording == TCC_PERMISSION_GRANTED_MDM);

		if (all_granted) {
			ILibSimpleDataStore_Close(db);
			return 0;
		}


		// At least one permission missing - show UI
		int result = show_tcc_permissions_window(1, __agentExecPath, consoleUID); // 1 = show "Do not remind me again" checkbox

		// If user clicked "Do not remind me again", write to .msh file
		if (result == 1) {
			// Append disableTccCheck=1 to .msh file
			FILE* mshFile = fopen(mshPath, "a");
			if (mshFile != NULL) {
				fprintf(mshFile, "\ndisableTccCheck=1\n");
				fclose(mshFile);

				// Get serviceId from database to build launchctl command
				char serviceId[256] = "meshagent"; // default
				int serviceIdLen = ILibSimpleDataStore_Get(db, "ServiceID", serviceId, sizeof(serviceId));
				if (serviceIdLen > 0) {
					serviceId[serviceIdLen] = '\0';
				}

				// Trigger daemon restart using launchctl kickstart
				// This will cause daemon to re-import .msh file on restart
				char kickstartCmd[512];
				snprintf(kickstartCmd, sizeof(kickstartCmd), "launchctl kickstart -k system/%s", serviceId);
				system(kickstartCmd);
			}
		}

		// Close database
		ILibSimpleDataStore_Close(db);
		return 0;
	}

	// -request-accessibility: Request Accessibility permission (spawned as console user)
	if (argc > 1 && strcasecmp(argv[1], "-request-accessibility") == 0)
	{
		// If running as root, drop privileges to the actual user
		// (needed if spawned via launchctl asuser instead of su)
		if (geteuid() == 0 && getuid() != 0) {
			uid_t uid = getuid();
			gid_t gid = getgid();

			if (setgid(gid) != 0) {
				return 1;
			}

			if (setuid(uid) != 0) {
				return 1;
			}
		}

		return request_accessibility_permission();
	}

	// -request-screenrecording: Request Screen Recording permission (spawned as console user)
	if (argc > 1 && strcasecmp(argv[1], "-request-screenrecording") == 0)
	{
		return request_screen_recording_permission();
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

#if defined(__APPLE__)
	// Detect if running in macOS app bundle mode
	char exePath[PATH_MAX];
	uint32_t len = sizeof(exePath);
	if (_NSGetExecutablePath(exePath, &len) == 0) {
		if (strstr(exePath, ".app/Contents/MacOS/") != NULL) {
			capabilities |= MeshCommand_AuthInfo_CapabilitiesMask_APPBUNDLE;
		}
	}
#endif

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