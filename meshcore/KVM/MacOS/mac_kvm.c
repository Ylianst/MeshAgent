/*
Copyright 2010 - 2018 Intel Corporation

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

/*
 * REVERSED ARCHITECTURE for macOS KVM (-kvm1)
 *
 * Unlike Windows/Linux where the main daemon spawns a child KVM process,
 * macOS uses a REVERSED pattern where:
 *
 * 1. Main daemon creates a listening socket at /tmp/meshagent-kvm.sock
 * 2. Main daemon creates a signal file at /var/run/meshagent/session-active
 * 3. LaunchAgent (/Library/LaunchAgents/meshagent-kvm1.plist) monitors directory via QueueDirectories
 * 4. When signal file appears, LaunchAgent starts -kvm1 process
 * 5. -kvm1 process CONNECTS to the daemon socket (not spawned by daemon)
 * 6. When signal file removed, LaunchAgent exits -kvm1 process
 *
 * This design works around Apple's bootstrap namespace restrictions and
 * ensures -kvm1 runs in the correct user context (LoginWindow or Aqua).
 *
 * See commit 8772b02 (Oct 29, 2025) for removal of old spawning architecture.
 */

#include "mac_kvm.h"
#include "mac_kvm_auth.h"
#include "../../meshdefines.h"
#include "../../meshinfo.h"
#include "../../../microstack/ILibParsers.h"
#include "../../../microstack/ILibAsyncSocket.h"
#include "../../../microstack/ILibAsyncServerSocket.h"
// DEPRECATED: Process pipe header - no longer used in socket architecture
// #include "../../../microstack/ILibProcessPipe.h"
#include <IOKit/IOKitLib.h>
#include <IOKit/hidsystem/IOHIDLib.h>
#include <IOKit/hidsystem/IOHIDParameter.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreServices/CoreServices.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <string.h>
#include <pwd.h>
#include <dirent.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <removefile.h>
#include "../../MacOS/mac_plist_utils.h"
#include "../../MacOS/mac_logging_utils.h"

static int KVM_Daemon_Listener_FD = -1;  // Main daemon's listener socket

// Dynamic paths built from companyName and meshServiceName at runtime
static char *KVM_Listener_Path = NULL;
static char *KVM_Queue_Directory = NULL;
static char *KVM_Session_Signal_File = NULL;
#if defined(_TLSLOG)
#define TLSLOG1 printf
#else
#define TLSLOG1(...) ;
#endif

// Screen capture tile dimensions (optimized for JPEG compression blocks)
#define KVM_TILE_WIDTH 32
#define KVM_TILE_HEIGHT 32

// JPEG compression quality (1-100, higher = better quality but larger)
#define KVM_DEFAULT_COMPRESSION 50

// Frame capture interval in milliseconds
#define KVM_DEFAULT_FRAME_INTERVAL_MS 100


int KVM_AGENT_FD = -1;
int KVM_SEND(char *buffer, int bufferLen)
{
	int retVal = -1;
	retVal = write(KVM_AGENT_FD == -1 ? STDOUT_FILENO : KVM_AGENT_FD, buffer, bufferLen);
	if (KVM_AGENT_FD == -1) { fsync(STDOUT_FILENO); }
	else
	{
		if (retVal < 0)
		{
			char tmp[255];
			int tmpLen = sprintf_s(tmp, sizeof(tmp), "Write Error: %d on %d\n", errno, KVM_AGENT_FD);
			write(STDOUT_FILENO, tmp, tmpLen);
			fsync(STDOUT_FILENO);
		}
	}
	return(retVal);
}

// Helper to open IOHIDSystem connection (DRY: extracted from set_kbd_state/get_kbd_state)
// Returns 0 on success, -1 on failure
static int open_iohid_connection(io_connect_t* ioc_out)
{
	kern_return_t kr;
	io_service_t ios;
	CFMutableDictionaryRef mdict;

	mdict = IOServiceMatching(kIOHIDSystemClass);
	ios = IOServiceGetMatchingService(kIOMasterPortDefault, (CFDictionaryRef)mdict);
	if (!ios)
	{
		if (mdict)
		{
			CFRelease(mdict);
		}
		ILIBLOGMESSAGEX("IOServiceGetMatchingService() failed\n");
		return -1;
	}

	kr = IOServiceOpen(ios, mach_task_self(), kIOHIDParamConnectType, ioc_out);
	IOObjectRelease(ios);
	if (kr != KERN_SUCCESS)
	{
		ILIBLOGMESSAGEX("IOServiceOpen() failed: %x\n", kr);
		return -1;
	}

	return 0;
}

CGDirectDisplayID SCREEN_NUM = 0;
int SH_HANDLE = 0;
int SCREEN_WIDTH = 0;
int SCREEN_HEIGHT = 0;
int SCREEN_SCALE = 1;
int SCREEN_SCALE_SET = 0;
int SCREEN_DEPTH = 0;
int TILE_WIDTH = 0;
int TILE_HEIGHT = 0;
int TILE_WIDTH_COUNT = 0;
int TILE_HEIGHT_COUNT = 0;
int COMPRESSION_RATIO = 0;
int FRAME_RATE_TIMER = 0;
struct tileInfo_t **g_tileInfo = NULL;
int g_remotepause = 0;           // Remote pause signal from daemon
int g_pause = 0;                 // Local pause state
int g_shutdown = 0;              // Shutdown signal
int g_resetipc = 0;              // Signal to reconnect to daemon socket (not restart process)
int kvm_clientProcessId = 0;     // Client process ID (unused in REVERSED ARCHITECTURE, kept for compatibility)
int g_restartcount = 0;          // Socket reconnection attempt counter (not process restart)
int g_totalRestartCount = 0;     // Total socket reconnection attempts
int restartKvm = 0;              // Flag to trigger socket reconnect (not process restart)
extern void* tilebuffer;
// DEPRECATED: Process spawning variables - no longer used in socket architecture
// OLD ARCHITECTURE: Main daemon spawned -kvm1 as a child process (pid_t g_slavekvm = 0)
// CURRENT REVERSED ARCHITECTURE: -kvm1 is an independent LaunchAgent that connects to daemon socket
// pid_t g_slavekvm = 0;
pthread_t kvmthread = (pthread_t)NULL;
// ILibProcessPipe_Process gChildProcess;
ILibQueue g_messageQ;

//int logenabled = 1;
//FILE *logfile = NULL;
//#define MASTERLOGFILE "/dev/null"
//#define SLAVELOGFILE "/dev/null"
//#define LOGFILE "/dev/null"


#define KvmDebugLog(...) ;
//#define KvmDebugLog(...) printf(__VA_ARGS__); fflush(stdout);
//#define KvmDebugLog(x) if (logenabled) printf(x);
// DEPRECATED: Old debug line used "slave" terminology (incorrect for REVERSED ARCHITECTURE)
//#define KvmDebugLog(x) if (logenabled) fprintf(logfile, "Processing KVM data in domain socket handler\n");

void senddebug(int val)
{
	char *buffer = (char*)ILibMemory_SmartAllocate(8);

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_DEBUG);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);			// Write the size
	((int*)buffer)[1] = val;

	ILibQueue_Lock(g_messageQ);
	ILibQueue_EnQueue(g_messageQ, buffer);
	ILibQueue_UnLock(g_messageQ);
}



void kvm_send_resolution()
{
	char *buffer = ILibMemory_SmartAllocate(8);

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SCREEN);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
	((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)SCREEN_WIDTH);		// X position
	((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)SCREEN_HEIGHT);	// Y position

	// Write the reply to the pipe.
	ILibQueue_Lock(g_messageQ);
	ILibQueue_EnQueue(g_messageQ, buffer);
	ILibQueue_UnLock(g_messageQ);
}

#define BUFSIZE 65535

int set_kbd_state(int input_state)
{
	int ret = 0;
	kern_return_t kr;
	io_connect_t ioc;
	bool state;

	// Use helper function to open IOHIDSystem connection
	if (open_iohid_connection(&ioc) != 0)
	{
		return 0;
	}

	// Set CAPSLOCK
	kr = IOHIDSetModifierLockState(ioc, kIOHIDCapsLockState, (input_state & 4) == 4);
	if (kr != KERN_SUCCESS)
	{
		IOServiceClose(ioc);
		ILIBLOGMESSAGEX("IOHIDSetModifierLockState() failed: %x\n", kr);
		return 0;
	}

	// Set NUMLOCK
	kr = IOHIDSetModifierLockState(ioc, kIOHIDNumLockState, (input_state & 1) == 1);
	if (kr != KERN_SUCCESS)
	{
		IOServiceClose(ioc);
		ILIBLOGMESSAGEX("IOHIDSetModifierLockState() failed: %x\n", kr);
		return 0;
	}

	// CAPSLOCK_QUERY
	kr = IOHIDGetModifierLockState(ioc, kIOHIDCapsLockState, &state);
	if (kr != KERN_SUCCESS)
	{
		IOServiceClose(ioc);
		ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
		return 0;
	}
	ret |= (state << 2);

	// NUMLOCK_QUERY
	kr = IOHIDGetModifierLockState(ioc, kIOHIDNumLockState, &state);
	if (kr != KERN_SUCCESS)
	{
		IOServiceClose(ioc);
		ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
		return 0;
	}
	ret |= state;

	IOServiceClose(ioc);
	return(ret);
}
int get_kbd_state()
{
	int ret = 0;
	kern_return_t kr;
	io_connect_t ioc;
	bool state;

	// Use helper function to open IOHIDSystem connection
	if (open_iohid_connection(&ioc) != 0)
	{
		return 0;
	}

	// CAPSLOCK_QUERY
	kr = IOHIDGetModifierLockState(ioc, kIOHIDCapsLockState, &state);
	if (kr != KERN_SUCCESS)
	{
		IOServiceClose(ioc);
		ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
		return 0;
	}
	ret |= (state << 2);

	// NUMLOCK_QUERY
	kr = IOHIDGetModifierLockState(ioc, kIOHIDNumLockState, &state);
	if (kr != KERN_SUCCESS)
	{
		IOServiceClose(ioc);
		ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
		return 0;
	}
	ret |= state;

	IOServiceClose(ioc);
	return(ret);
}


int kvm_init()
{
	ILibCriticalLogFilename = "KVMAgent.log";  // -kvm1 is a LaunchAgent, not a slave process
	int old_height_count = TILE_HEIGHT_COUNT;

	SCREEN_NUM = CGMainDisplayID();

	if (SCREEN_WIDTH > 0)
	{
		CGDisplayModeRef mode = CGDisplayCopyDisplayMode(SCREEN_NUM);
		SCREEN_SCALE = (int) CGDisplayModeGetPixelWidth(mode) / SCREEN_WIDTH;
		CGDisplayModeRelease(mode);
	}

	SCREEN_HEIGHT = CGDisplayPixelsHigh(SCREEN_NUM) * SCREEN_SCALE;
	SCREEN_WIDTH = CGDisplayPixelsWide(SCREEN_NUM) * SCREEN_SCALE;

	// Initialize capture parameters with defaults
	TILE_WIDTH = KVM_TILE_WIDTH;
	TILE_HEIGHT = KVM_TILE_HEIGHT;
	COMPRESSION_RATIO = KVM_DEFAULT_COMPRESSION;
	FRAME_RATE_TIMER = KVM_DEFAULT_FRAME_INTERVAL_MS;

	TILE_HEIGHT_COUNT = SCREEN_HEIGHT / TILE_HEIGHT;
	TILE_WIDTH_COUNT = SCREEN_WIDTH / TILE_WIDTH;
	if (SCREEN_WIDTH % TILE_WIDTH) { TILE_WIDTH_COUNT++; }
	if (SCREEN_HEIGHT % TILE_HEIGHT) { TILE_HEIGHT_COUNT++; }

	kvm_send_resolution();
	reset_tile_info(old_height_count);

	unsigned char *buffer = ILibMemory_SmartAllocate(5);
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_KEYSTATE);		// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);					// Write the size
	buffer[4] = (unsigned char)get_kbd_state();

	// Write the reply to the pipe.
	ILibQueue_Lock(g_messageQ);
	ILibQueue_EnQueue(g_messageQ, buffer);
	ILibQueue_UnLock(g_messageQ);

	return 0;
}

// void CheckDesktopSwitch(int checkres) { return; }

int kvm_server_inputdata(char* block, int blocklen)
{
	unsigned short type, size;
	//CheckDesktopSwitch(0);
	
	//senddebug(100+blocklen);

	// Decode the block header
	if (blocklen < 4) return 0;
	type = ntohs(((unsigned short*)(block))[0]);
	size = ntohs(((unsigned short*)(block))[1]);

	if (size > blocklen) return 0;

	switch (type)
	{
		case MNG_KVM_KEY_UNICODE: // Unicode Key
			if (size != 7) break;
			KeyActionUnicode(((((unsigned char)block[5]) << 8) + ((unsigned char)block[6])), block[4]);
			break;
		case MNG_KVM_KEY: // Key
		{
			if (size != 6) { break; }
			KeyAction(block[5], block[4]);
			break;
		}
		case MNG_KVM_MOUSE: // Mouse
		{
			int x, y;
			short w = 0;
			if (size == 10 || size == 12)
			{
				x = ((int)ntohs(((unsigned short*)(block))[3])) / SCREEN_SCALE;
				y = ((int)ntohs(((unsigned short*)(block))[4])) / SCREEN_SCALE;
				
				if (size == 12) w = ((short)ntohs(((short*)(block))[5]));
				
				//printf("x:%d, y:%d, b:%d, w:%d\n", x, y, block[5], w);
				MouseAction(x, y, (int)(unsigned char)(block[5]), w);
			}
			break;
		}
		case MNG_KVM_COMPRESSION: // Compression
		{
			if (size != 6) break;
			set_tile_compression((int)block[4], (int)block[5]);
			COMPRESSION_RATIO = 100;
			break;
		}
		case MNG_KVM_REFRESH: // Refresh
		{
			// FIX: Send resolution IMMEDIATELY, not via queue, to ensure it arrives before any tile data
			// This fixes the race condition where tiles were sent before resolution, causing wrong canvas size
			char resolution_buffer[8];
			((unsigned short*)resolution_buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SCREEN);
			((unsigned short*)resolution_buffer)[1] = (unsigned short)htons((unsigned short)8);
			((unsigned short*)resolution_buffer)[2] = (unsigned short)htons((unsigned short)SCREEN_WIDTH);
			((unsigned short*)resolution_buffer)[3] = (unsigned short)htons((unsigned short)SCREEN_HEIGHT);

			KVM_SEND(resolution_buffer, 8);

			int row, col;
			if (size != 4) break;
			if (g_tileInfo == NULL) {
				if ((g_tileInfo = (struct tileInfo_t **) malloc(TILE_HEIGHT_COUNT * sizeof(struct tileInfo_t *))) == NULL) ILIBCRITICALEXIT(254);
				for (row = 0; row < TILE_HEIGHT_COUNT; row++) {
					if ((g_tileInfo[row] = (struct tileInfo_t *) malloc(TILE_WIDTH_COUNT * sizeof(struct tileInfo_t))) == NULL) ILIBCRITICALEXIT(254);
				}
			}
			for (row = 0; row < TILE_HEIGHT_COUNT; row++) {
				for (col = 0; col < TILE_WIDTH_COUNT; col++) {
					g_tileInfo[row][col].crc = 0xFF;
					g_tileInfo[row][col].flag = 0;
				}
			}

			break;
		}
		case MNG_KVM_PAUSE: // Pause
		{
			if (size != 5) break;
			g_remotepause = block[4];
			break;
		}
		case MNG_KVM_FRAME_RATE_TIMER:
		{
			//int fr = ((int)ntohs(((unsigned short*)(block))[2]));
			//if (fr > 20 && fr < 2000) FRAME_RATE_TIMER = fr;
			break;
		}
	}

	return size;
}

// Set the KVM pause state
void kvm_pause(int pause)
{
	g_pause = pause;
}

// Sanitize identifier string to match JavaScript sanitizeIdentifier() behavior
// Replaces spaces with hyphens, removes all non-alphanumeric except hyphens/underscores
static void sanitize_identifier(char *dest, size_t destSize, const char *src)
{
	size_t i, j = 0;

	if (src == NULL || dest == NULL || destSize == 0) {
		if (dest != NULL && destSize > 0) dest[0] = '\0';
		return;
	}

	for (i = 0; src[i] != '\0' && j < destSize - 1; i++) {
		if (src[i] == ' ') {
			// Replace spaces with hyphens
			dest[j++] = '-';
		} else if ((src[i] >= 'a' && src[i] <= 'z') ||
		           (src[i] >= 'A' && src[i] <= 'Z') ||
		           (src[i] >= '0' && src[i] <= '9') ||
		           src[i] == '-' || src[i] == '_') {
			// Keep alphanumeric, hyphens, and underscores
			dest[j++] = src[i];
		}
		// Skip all other characters
	}
	dest[j] = '\0';
}

// Read serviceID from LaunchDaemon plist Label field
// Scans /Library/LaunchDaemons/*.plist files to find the one with matching ProgramArguments:0
// Returns strdup() of Label field, or NULL if not found (caller must free)
//
// SECURITY FIX: Replaced popen() with secure CoreFoundation-based plist parsing
// Previous implementation was vulnerable to command injection via malicious filenames
static char* kvm_read_serviceid_from_plist(const char *exePath)
{
	DIR *dir;
	struct dirent *entry;
	char plistPath[PATH_MAX];

	if (exePath == NULL || strlen(exePath) == 0)
	{
		return NULL;
	}

	// Open LaunchDaemons directory
	dir = opendir("/Library/LaunchDaemons");
	if (dir == NULL)
	{
		return NULL;
	}

	// Scan for .plist files
	while ((entry = readdir(dir)) != NULL)
	{
		// Skip non-plist files
		if (!strstr(entry->d_name, ".plist")) continue;

		snprintf(plistPath, sizeof(plistPath), "/Library/LaunchDaemons/%s", entry->d_name);

		// Use SECURE CoreFoundation-based plist parser (no shell execution)
		char* binPath = mesh_plist_get_program_path(plistPath);
		if (binPath != NULL)
		{
			// Check if this matches our binary path
			if (strcmp(binPath, exePath) == 0)
			{
				free(binPath);

				// Found matching plist! Extract Label using secure API
				char* label = mesh_plist_get_label(plistPath);
				closedir(dir);
				return label;  // Caller must free
			}
			free(binPath);
		}
	}

	closedir(dir);
	return NULL;
}

// Build dynamic KVM paths using serviceID
// Priority 1: Database serviceID (from .msh file)
// Priority 2: LaunchDaemon plist Label (when database unavailable)
// Priority 3: Default "meshagent-agent"
static void kvm_build_dynamic_paths(char *companyName, char *meshServiceName, char *serviceID, char *exePath)
{
	char serviceId[512];

	UNREFERENCED_PARAMETER(companyName);
	UNREFERENCED_PARAMETER(meshServiceName);

	// Free any previously allocated paths
	if (KVM_Listener_Path != NULL) { free(KVM_Listener_Path); KVM_Listener_Path = NULL; }
	if (KVM_Queue_Directory != NULL) { free(KVM_Queue_Directory); KVM_Queue_Directory = NULL; }
	if (KVM_Session_Signal_File != NULL) { free(KVM_Session_Signal_File); KVM_Session_Signal_File = NULL; }

	// Priority 1: Use pre-computed serviceID from database
	if (serviceID != NULL && strlen(serviceID) > 0)
	{
		strncpy(serviceId, serviceID, sizeof(serviceId) - 1);
		serviceId[sizeof(serviceId) - 1] = '\0';
	}
	// Priority 2: Read from LaunchDaemon plist Label
	else if (exePath != NULL && strlen(exePath) > 0)
	{
		char *plistServiceId = kvm_read_serviceid_from_plist(exePath);
		if (plistServiceId != NULL)
		{
			strncpy(serviceId, plistServiceId, sizeof(serviceId) - 1);
			serviceId[sizeof(serviceId) - 1] = '\0';
			free(plistServiceId);
		}
		else
		{
			// Priority 3: Default to "meshagent-agent"
			strncpy(serviceId, "meshagent-agent", sizeof(serviceId) - 1);
			serviceId[sizeof(serviceId) - 1] = '\0';
		}
	}
	else
	{
		// Priority 3: Default to "meshagent-agent" (no exePath available)
		strncpy(serviceId, "meshagent-agent", sizeof(serviceId) - 1);
		serviceId[sizeof(serviceId) - 1] = '\0';
	}

	// Build dynamic paths
	KVM_Listener_Path = (char*)malloc(PATH_MAX);
	KVM_Queue_Directory = (char*)malloc(PATH_MAX);
	KVM_Session_Signal_File = (char*)malloc(PATH_MAX);

	snprintf(KVM_Listener_Path, PATH_MAX, "/tmp/%s.sock", serviceId);
	snprintf(KVM_Queue_Directory, PATH_MAX, "/var/run/%s", serviceId);
	snprintf(KVM_Session_Signal_File, PATH_MAX, "/var/run/%s/session-active", serviceId);
}

void* kvm_mainloopinput(void* param)
{
	int ptr = 0;
	int ptr2 = 0;
	int len = 0;
	char* pchRequest2[30000];
	int cbBytesRead = 0;

	char tmp[255];
	int tmpLen;

	if (KVM_AGENT_FD == -1)
	{
		int flags;
		flags = fcntl(STDIN_FILENO, F_GETFL, 0);
		if (fcntl(STDIN_FILENO, F_SETFL, (O_NONBLOCK | flags) ^ O_NONBLOCK) == -1) { senddebug(-999); }
	}

	while (!g_shutdown)
	{
		cbBytesRead = read(KVM_AGENT_FD == -1 ? STDIN_FILENO: KVM_AGENT_FD, pchRequest2 + len, 30000 - len);

		if (cbBytesRead == -1 || cbBytesRead == 0)
		{
			if (KVM_AGENT_FD == -1)
			{
				g_shutdown = 1;
			}
			else
			{
				g_resetipc = 1;
			}
			break;
		}
		len += cbBytesRead;
		ptr2 = 0;

		while ((ptr2 = kvm_server_inputdata((char*)pchRequest2 + ptr, cbBytesRead - ptr)) != 0) { ptr += ptr2; }

		if (ptr == len) { len = 0; ptr = 0; }
		// TODO: else move the reminder.
	}

	return 0;
}
void ExitSink(int s)
{
	UNREFERENCED_PARAMETER(s);

	signal(SIGTERM, SIG_IGN);

	g_shutdown = 1;
}
void* kvm_server_mainloop(void* param, char *serviceID)
{
	int x, y, height, width, r, c = 0;
	long long desktopsize = 0;
	long long tilesize = 0;
	void *desktop = NULL;
	void *buf = NULL;
	int screen_height, screen_width, screen_num;
	int written = 0;
	struct sockaddr_un serveraddr;

	if (param == NULL)
	{
		// This is doing I/O via StdIn/StdOut

		int flags;
		flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
		if (fcntl(STDOUT_FILENO, F_SETFL, (O_NONBLOCK | flags) ^ O_NONBLOCK) == -1) {}
	}
	else
	{
		// REVERSED ARCHITECTURE: -kvm1 now CONNECTS to main agent's listener socket
		// This fixes the bootstrap namespace issue and null data problem

		// Build dynamic paths using serviceID (passed from command-line parameter)
		if (KVM_Listener_Path == NULL)
		{
			// -kvm1 child process: Get binary path for fallback (backward compatibility)
			char kvmExePath[1024];
			uint32_t pathSize = sizeof(kvmExePath);
			char *exePathToUse = NULL;

			#ifdef __APPLE__
			if (_NSGetExecutablePath(kvmExePath, &pathSize) == 0)
			{
				exePathToUse = kvmExePath;
			}
			#endif

			// -kvm1 child process receives serviceID from --serviceId parameter
			// companyName/meshServiceName no longer needed for -kvm1
			kvm_build_dynamic_paths(NULL, NULL, serviceID, exePathToUse);
		}

		written = write(STDOUT_FILENO, "KVM: Connecting to daemon socket...\n", 37);
		fsync(STDOUT_FILENO);

		// Create socket
		if ((KVM_AGENT_FD = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		{
			char tmp[255];
			int tmplen = sprintf_s(tmp, sizeof(tmp), "KVM: Failed to create socket (errno=%d)\n", errno);
			written = write(STDOUT_FILENO, tmp, tmplen);
			fsync(STDOUT_FILENO);
			return(NULL);
		}

		// Set up address to connect to
		memset(&serveraddr, 0, sizeof(serveraddr));
		serveraddr.sun_family = AF_UNIX;
		strcpy(serveraddr.sun_path, KVM_Listener_Path);

		// Print socket path we're connecting to
		char tmp_path[512];
		int tmp_path_len = sprintf_s(tmp_path, sizeof(tmp_path), "KVM: -kvm1 connecting to socket: %s\n", KVM_Listener_Path);
		written = write(STDOUT_FILENO, tmp_path, tmp_path_len);
		fsync(STDOUT_FILENO);

		// Connect to main agent's listener socket
		// Retry logic for robustness (daemon might not be ready yet)
		int retry_count = 0;
		while (retry_count < 30)
		{
			if (connect(KVM_AGENT_FD, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr)) == 0)
			{
				// Success!
				char tmp[255];
				int tmpLen = sprintf_s(tmp, sizeof(tmp), "KVM: Connected (fd=%d)\n", KVM_AGENT_FD);
				written = write(STDOUT_FILENO, tmp, tmpLen);
				fsync(STDOUT_FILENO);
				break;
			}

			// Connection failed
			if (retry_count == 0)
			{
				char tmp[255];
				int tmplen = sprintf_s(tmp, sizeof(tmp), "KVM: Connect failed (errno=%d), retrying...\n", errno);
				written = write(STDOUT_FILENO, tmp, tmplen);
				fsync(STDOUT_FILENO);
			}

			retry_count++;
			sleep(1);  // Wait 1 second before retry
		}

		if (retry_count >= 30)
		{
			written = write(STDOUT_FILENO, "KVM: Connect failed after 30 retries\n", 38);
			fsync(STDOUT_FILENO);
			close(KVM_AGENT_FD);
			return(NULL);
		}

		signal(SIGTERM, ExitSink);
	}
	// Init the kvm
	g_messageQ = ILibQueue_Create();
	if (kvm_init() != 0) { return (void*)-1; }


	g_shutdown = 0;
	pthread_create(&kvmthread, NULL, kvm_mainloopinput, param);

	while (!g_shutdown) 
	{
		if (g_resetipc != 0)
		{
			g_resetipc = 0;
			close(KVM_AGENT_FD);

			SCREEN_HEIGHT = SCREEN_WIDTH = 0;

			written = write(STDOUT_FILENO, "KVM: Reconnecting to daemon socket...\n", 39);
			fsync(STDOUT_FILENO);

			// REVERSED: Reconnect to daemon socket
			if ((KVM_AGENT_FD = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			{
				g_shutdown = 1;
				written = write(STDOUT_FILENO, "KVM: Socket error on reconnect\n", 32);
				fsync(STDOUT_FILENO);
				break;
			}

			if (connect(KVM_AGENT_FD, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr)) < 0)
			{
				g_shutdown = 1;
				char tmp[255];
				int tmplen = sprintf_s(tmp, sizeof(tmp), "KVM: Reconnect failed (errno=%d)\n", errno);
				written = write(STDOUT_FILENO, tmp, tmplen);
				fsync(STDOUT_FILENO);
				close(KVM_AGENT_FD);
				break;
			}
			else
			{
				char tmp[255];
				int tmpLen = sprintf_s(tmp, sizeof(tmp), "KVM: Reconnected (fd=%d)\n", KVM_AGENT_FD);
				written = write(STDOUT_FILENO, tmp, tmpLen);
				fsync(STDOUT_FILENO);
				pthread_create(&kvmthread, NULL, kvm_mainloopinput, param);
			}
		}
		
		// Check if there are pending messages to be sent
		ILibQueue_Lock(g_messageQ);
		while (ILibQueue_IsEmpty(g_messageQ) == 0)
		{
			if ((buf = (char*)ILibQueue_DeQueue(g_messageQ)) != NULL)
			{
				int msg_size = (int)ILibMemory_Size(buf);
				KVM_SEND(buf, msg_size);
				ILibMemory_Free(buf);
			}
		}
		ILibQueue_UnLock(g_messageQ);


		for (r = 0; r < TILE_HEIGHT_COUNT; r++) 
		{
			for (c = 0; c < TILE_WIDTH_COUNT; c++) 
			{
				g_tileInfo[r][c].flag = TILE_TODO;
#ifdef KVM_ALL_TILES
				g_tileInfo[r][c].crc = 0xFF;
#endif
			}
		}

		screen_num = CGMainDisplayID();

		if (screen_num == 0) { g_shutdown = 1; senddebug(-2); break; }
		
		if (SCREEN_SCALE_SET == 0)
		{
			CGDisplayModeRef mode = CGDisplayCopyDisplayMode(screen_num);
			if (SCREEN_WIDTH > 0 && SCREEN_SCALE < (int) CGDisplayModeGetPixelWidth(mode) / SCREEN_WIDTH)
			{
				SCREEN_SCALE = (int) CGDisplayModeGetPixelWidth(mode) / SCREEN_WIDTH;
				SCREEN_SCALE_SET = 1;
			}			 
			CGDisplayModeRelease(mode);
		}
		
		screen_height = CGDisplayPixelsHigh(screen_num) * SCREEN_SCALE;
		screen_width = CGDisplayPixelsWide(screen_num) * SCREEN_SCALE;
		
		if ((SCREEN_HEIGHT != screen_height || (SCREEN_WIDTH != screen_width) || SCREEN_NUM != screen_num)) 
		{
			kvm_init();
			continue;
		}

		//senddebug(screen_num);
		CGImageRef image = CGDisplayCreateImage(screen_num);
		//senddebug(99);
		if (image == NULL) 
		{
			g_shutdown = 1;
			senddebug(0);
		}
		else {
			//senddebug(100);
			getScreenBuffer((unsigned char **)&desktop, &desktopsize, image);

			for (y = 0; y < TILE_HEIGHT_COUNT; y++)
			{
				for (x = 0; x < TILE_WIDTH_COUNT; x++) {
					height = TILE_HEIGHT * y;
					width = TILE_WIDTH * x;
					if (!g_shutdown && (g_pause)) { usleep(100000); g_pause = 0; } //HACK: Change this

					if (g_shutdown) { x = TILE_WIDTH_COUNT; y = TILE_HEIGHT_COUNT; break; }

					if (g_tileInfo[y][x].flag == TILE_SENT) continue;
					if (g_tileInfo[y][x].flag == TILE_DONT_SEND) continue;

					getTileAt(width, height, &buf, &tilesize, desktop, desktopsize, y, x);

					if (buf && !g_shutdown)
					{
						// Write the reply to the pipe.
						written = KVM_SEND(buf, tilesize);
						if (written == -1)
						{
							/*ILIBMESSAGE("KVMBREAK-K2\r\n");*/
							if(KVM_AGENT_FD == -1)
							{
								// This is a User Session, so if the connection fails, we exit out... We can be spawned again later
								g_shutdown = 1; height = SCREEN_HEIGHT; width = SCREEN_WIDTH; break;
							}
						}
						free(buf);
					}
				}
			}

		}
		CGImageRelease(image);

	}
	
	pthread_join(kvmthread, NULL);
	kvmthread = (pthread_t)NULL;

	if (g_tileInfo != NULL) { for (r = 0; r < TILE_HEIGHT_COUNT; r++) { free(g_tileInfo[r]); } }
	g_tileInfo = NULL;
	if(tilebuffer != NULL) {
		free(tilebuffer);
		tilebuffer = NULL;
	}

	if (KVM_AGENT_FD != -1)
	{
		written = write(STDOUT_FILENO, "KVM: Exiting\n", 13);
		fsync(STDOUT_FILENO);
	}
	ILibQueue_Destroy(g_messageQ);
	return (void*)0;
}

// DEPRECATED: Process pipe exit handler - no longer used in socket architecture
// OLD ARCHITECTURE: This handled child process exits and respawned -kvm1
// CURRENT REVERSED ARCHITECTURE: -kvm1 is LaunchAgent managed by QueueDirectories, not spawned by daemon
/*
void kvm_relay_ExitHandler(ILibProcessPipe_Process sender, int exitCode, void* user)
{
	//ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)user)[0];
	//void *reserved = ((void**)user)[1];
	//void *pipeMgr = ((void**)user)[2];
	//char *exePath = (char*)((void**)user)[3];
	UNREFERENCED_PARAMETER(sender);
	UNREFERENCED_PARAMETER(exitCode);
	UNREFERENCED_PARAMETER(user);
}
*/
// DEPRECATED: Process pipe stdout handler - no longer used in socket architecture
/*
void kvm_relay_StdOutHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)
{
	unsigned short size = 0;
	UNREFERENCED_PARAMETER(sender);
	ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)user)[0];
	void *reserved = ((void**)user)[1];

	if (bufferLen > 4)
	{
		if (ntohs(((unsigned short*)(buffer))[0]) == (unsigned short)MNG_JUMBO)
		{
			if (bufferLen > 8)
			{
				if (bufferLen >= (8 + (int)ntohl(((unsigned int*)(buffer))[1])))
				{
					*bytesConsumed = 8 + (int)ntohl(((unsigned int*)(buffer))[1]);
					TLSLOG1("<< KVM/WRITE: %d bytes\n", *bytesConsumed);
					writeHandler(buffer, *bytesConsumed, reserved);

					//printf("JUMBO PACKET: %d\n", *bytesConsumed);
					return;
				}
			}
		}
		else
		{
			size = ntohs(((unsigned short*)(buffer))[1]);
			if (size <= bufferLen)
			{
				*bytesConsumed = size;
				writeHandler(buffer, size, reserved);
				//printf("Normal PACKET: %d\n", *bytesConsumed);
				return;
			}
		}
	}
	*bytesConsumed = 0;
}
*/
// DEPRECATED: Process pipe stderr handler - no longer used in socket architecture
/*
void kvm_relay_StdErrHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)
{
	//KVMDebugLog *log = (KVMDebugLog*)buffer;

	//UNREFERENCED_PARAMETER(sender);
	//UNREFERENCED_PARAMETER(user);

	//if (bufferLen < sizeof(KVMDebugLog) || bufferLen < log->length) { *bytesConsumed = 0;  return; }
	//*bytesConsumed = log->length;
	////ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), (ILibRemoteLogging_Modules)log->logType, (ILibRemoteLogging_Flags)log->logFlags, "%s", log->logData);
	//ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Microstack_Generic, (ILibRemoteLogging_Flags)log->logFlags, "%s", log->logData);
	*bytesConsumed = bufferLen;
}
*/


// Setup the KVM session. Return 1 if ok, 0 if it could not be setup.
// Create KVM session: directory + signal file + socket
// This triggers QueueDirectories to start -kvm1 LaunchAgent
// Only called when user clicks "Connect" in MeshCentral
int kvm_create_session(char *companyName, char *meshServiceName, char *serviceID, char *exePath)
{
	struct sockaddr_un serveraddr;
	mode_t old_umask;
	int signal_fd;

	// Build dynamic paths based on companyName and meshServiceName
	// This must be called before checking if session is already active
	// because paths might not have been built yet
	if (KVM_Listener_Path == NULL)
	{
		kvm_build_dynamic_paths(companyName, meshServiceName, serviceID, exePath);
	}

	// Check if session already active
	if (KVM_Daemon_Listener_FD != -1)
	{
		return 0;  // Already initialized
	}

	// 1. Create domain socket FIRST (before directory/signal file)
	// This prevents race condition where -kvm1 starts before socket is ready
	if ((KVM_Daemon_Listener_FD = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		mesh_log_message("[KVM] ERROR: Failed to create listener socket: %s\n", strerror(errno));
		return -1;
	}

	// Set socket to allow world-writable (code signature verification provides security)
	old_umask = umask(0000);

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sun_family = AF_UNIX;
	strcpy(serveraddr.sun_path, KVM_Listener_Path);

	// Remove old socket file if exists
	unlink(KVM_Listener_Path);

	if (bind(KVM_Daemon_Listener_FD, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr)) < 0)
	{
		mesh_log_message("[KVM] ERROR: Failed to bind listener socket: %s\n", strerror(errno));
		close(KVM_Daemon_Listener_FD);
		KVM_Daemon_Listener_FD = -1;
		umask(old_umask);
		return -1;
	}

	umask(old_umask);

	// Explicitly set permissions (defense in depth)
	chmod(KVM_Listener_Path, 0777);

	// Listen with backlog of 2 (handles fast-user-switching edge case)
	if (listen(KVM_Daemon_Listener_FD, 2) < 0)
	{
		mesh_log_message("[KVM] ERROR: Failed to listen on socket: %s\n", strerror(errno));
		close(KVM_Daemon_Listener_FD);
		KVM_Daemon_Listener_FD = -1;
		unlink(KVM_Listener_Path);
		return -1;
	}

	// 2. NOW create queue directory for LaunchAgent QueueDirectories monitoring
	// Socket is guaranteed ready before -kvm1 can start
	if (mkdir(KVM_Queue_Directory, 0755) < 0 && errno != EEXIST)
	{
		mesh_log_message("[KVM] ERROR: Failed to create queue directory %s: %s\n", KVM_Queue_Directory, strerror(errno));
		close(KVM_Daemon_Listener_FD);
		KVM_Daemon_Listener_FD = -1;
		unlink(KVM_Listener_Path);
		return -1;
	}

	// 3. Create signal file to trigger QueueDirectories (directory not empty)
	signal_fd = open(KVM_Session_Signal_File, O_CREAT | O_WRONLY, 0644);
	if (signal_fd < 0)
	{
		mesh_log_message("[KVM] ERROR: Failed to create session signal file: %s\n", strerror(errno));
		close(KVM_Daemon_Listener_FD);
		KVM_Daemon_Listener_FD = -1;
		unlink(KVM_Listener_Path);
		rmdir(KVM_Queue_Directory);
		return -1;
	}
	write(signal_fd, "1", 1);  // Write something so file is not empty
	close(signal_fd);

	return 0;
}

// Cleanup KVM session: remove socket, signal file, and clear directory contents
// This causes -kvm1 to exit (directory empty, avoiding QueueDirectories weirdness)
void kvm_cleanup_session(void)
{
	// Close and remove socket
	if (KVM_Daemon_Listener_FD != -1)
	{
		close(KVM_Daemon_Listener_FD);
		KVM_Daemon_Listener_FD = -1;
	}
	unlink(KVM_Listener_Path);

	// Remove signal file (makes directory empty)
	unlink(KVM_Session_Signal_File);

	// Clear all contents from directory (CRITICAL: Must be completely empty to stop -kvm1)
	// Keep the directory itself to avoid QueueDirectories weirdness with folder deletion
	// Any remaining files will cause LaunchAgent to continuously spawn -kvm1
	DIR *dir = opendir(KVM_Queue_Directory);
	if (dir != NULL)
	{
		struct dirent *entry;
		char filepath[PATH_MAX];

		while ((entry = readdir(dir)) != NULL)
		{
			// Skip . and .. entries
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;

			snprintf(filepath, sizeof(filepath), "%s/%s", KVM_Queue_Directory, entry->d_name);

			if (entry->d_type == DT_DIR)
			{
				// Recursively remove subdirectory - this shouldn't happen but handle it
				// Use removefile() instead of system() to prevent command injection
				if (removefile(filepath, NULL, REMOVEFILE_RECURSIVE) != 0) {
					// First attempt failed - try with force flag
					if (removefile(filepath, NULL, REMOVEFILE_RECURSIVE | REMOVEFILE_KEEP_PARENT) != 0) {
						mesh_log_message("[KVM] CRITICAL: Failed to remove directory %s: %s\n",
						        filepath, strerror(errno));
						mesh_log_message("[KVM] CRITICAL: LaunchAgent may continue spawning -kvm1!\n");
					}
				}
			}
			else
			{
				// Remove regular file with retry
				if (unlink(filepath) != 0) {
					// Retry with chmod in case of permission issues
					chmod(filepath, 0644);
					if (unlink(filepath) != 0) {
						mesh_log_message("[KVM] CRITICAL: Failed to remove file %s: %s\n",
						        filepath, strerror(errno));
						mesh_log_message("[KVM] CRITICAL: LaunchAgent may continue spawning -kvm1!\n");
					}
				}
			}
		}
		closedir(dir);

		// VERIFICATION PASS: Ensure directory is actually empty
		dir = opendir(KVM_Queue_Directory);
		if (dir != NULL)
		{
			int remaining_files = 0;
			while ((entry = readdir(dir)) != NULL)
			{
				if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
					continue;
				remaining_files++;
				mesh_log_message("[KVM] CRITICAL: Stray file remains: %s/%s\n",
				        KVM_Queue_Directory, entry->d_name);
			}
			closedir(dir);

			if (remaining_files > 0) {
				mesh_log_message("[KVM] CRITICAL: %d stray file(s) in queue directory!\n", remaining_files);
				mesh_log_message("[KVM] CRITICAL: LaunchAgent will continue spawning -kvm1 until directory is empty!\n");
			}
		}
	}
	else if (errno != ENOENT)
	{
		mesh_log_message("[KVM] WARN: Failed to open queue directory: %s\n", strerror(errno));
	}
}

void* kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int uid, char *companyName, char *meshServiceName, char *serviceID)
{
	// REVERSED ARCHITECTURE: Always use on-demand session with QueueDirectories
	// The uid parameter is ignored - LaunchAgent runs in correct user context via LimitLoadToSessionType
	// No child process spawning - -kvm1 LaunchAgent connects to us

	UNREFERENCED_PARAMETER(processPipeMgr);
	UNREFERENCED_PARAMETER(writeHandler);
	UNREFERENCED_PARAMETER(reserved);
	UNREFERENCED_PARAMETER(uid);

	int client_fd;

	// Create KVM session (directory + signal file + socket)
	// This triggers QueueDirectories to start -kvm1
	if (kvm_create_session(companyName, meshServiceName, serviceID, exePath) < 0)
	{
		mesh_log_message("[KVM] ERROR: Failed to create session\n");
		return NULL;
	}

	// Accept connection from -kvm1 LaunchAgent (triggered by QueueDirectories)
	client_fd = accept(KVM_Daemon_Listener_FD, NULL, NULL);

	if (client_fd < 0)
	{
		mesh_log_message("[KVM] ERROR: Failed to accept connection: %s\n", strerror(errno));
		kvm_cleanup_session();  // Clean up on failure
		return NULL;
	}

	// Verify connecting process is legitimate meshagent binary
	if (!verify_peer_codesign(client_fd))
	{
		mesh_log_message("[KVM] ERROR: Peer verification FAILED - rejecting connection\n");
		close(client_fd);
		kvm_cleanup_session();  // Clean up on failure
		return NULL;
	}

	// Return FD cast as void* for use with ILibAsyncSocket
	return (void*)(intptr_t)client_fd;
}

// Force a KVM reset & refresh
void kvm_relay_reset(void *reserved)
{
	if (reserved == NULL)
	{
		return;
	}

	// Create MNG_KVM_REFRESH message
	char buffer[4];
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_REFRESH);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)4);				// Write the size

	// Get RemoteDesktop_Ptrs from reserved parameter (same structure as Windows)
	// On macOS, we need to forward this via ILibAsyncSocket to the -kvm1 domain socket
	// The reserved pointer is RemoteDesktop_Ptrs*, which contains kvmDomainSocketModule

	// We need to include the agentcore header to access RemoteDesktop_Ptrs structure
	// For now, just cast to void** and access kvmDomainSocketModule at the correct offset
	// Structure: ctx, object, MeshAgentObject, kvmPipe, kvmDomainSocket, kvmDomainSocketModule, stream
	// On 64-bit: 0, 8, 16, 24, 32, 40, 48
	void **ptrs = (void**)reserved;
	void *kvmDomainSocketModule = ptrs[5];  // kvmDomainSocketModule is at offset 5 (after ctx, object, MeshAgentObject, kvmPipe, kvmDomainSocket)

	if (kvmDomainSocketModule != NULL)
	{
		// Send to -kvm1 via domain socket (same as ILibDuktape_MeshAgent_RemoteDesktop_WriteSink)
		ILibAsyncSocket_Send(kvmDomainSocketModule, buffer, 4, ILibAsyncSocket_MemoryOwnership_USER);
	}
}

// Clean up the KVM session.
void kvm_cleanup()
{
	KvmDebugLog("kvm_cleanup\n");
	g_shutdown = 1;
	// DEPRECATED: Process pipe cleanup - no longer used in socket architecture
	/*
	if (gChildProcess != NULL)
	{
		ILibProcessPipe_Process_SoftKill(gChildProcess);
		gChildProcess = NULL;
	}
	*/

	// Cleanup session resources (directory, signal file, socket)
	// This triggers -kvm1 to exit (QueueDirectories detects empty directory)
	kvm_cleanup_session();
}


typedef enum {
    MPAuthorizationStatusNotDetermined,
    MPAuthorizationStatusAuthorized,
    MPAuthorizationStatusDenied
} MPAuthorizationStatus;




MPAuthorizationStatus _checkFDAUsingFile(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd != -1)
    {
        close(fd);
        return MPAuthorizationStatusAuthorized;
    }

    if (errno == EPERM || errno == EACCES)
    {
        return MPAuthorizationStatusDenied;
    }

    return MPAuthorizationStatusNotDetermined;
}

MPAuthorizationStatus _fullDiskAuthorizationStatus() {
    char *userHomeFolderPath = getenv("HOME");
    if (userHomeFolderPath == NULL) {
        struct passwd *pw = getpwuid(getuid());
        if (pw == NULL) {
            return MPAuthorizationStatusNotDetermined;
        }
        userHomeFolderPath = pw->pw_dir;
    }

    // SECURITY FIX: Use stack allocation instead of malloc to prevent memory leak
    // Previous implementation leaked 60 bytes per call (30 bytes × 2 paths)
    char safariCloudTabsPath[PATH_MAX];
    char safariBookmarksPath[PATH_MAX];

    snprintf(safariCloudTabsPath, sizeof(safariCloudTabsPath),
             "%s/Library/Safari/CloudTabs.db", userHomeFolderPath);
    snprintf(safariBookmarksPath, sizeof(safariBookmarksPath),
             "%s/Library/Safari/Bookmarks.plist", userHomeFolderPath);

    const char *testFiles[] = {
        safariCloudTabsPath,
        safariBookmarksPath,
        "/Library/Application Support/com.apple.TCC/TCC.db",
        "/Library/Preferences/com.apple.TimeMachine.plist",
    };

    MPAuthorizationStatus resultStatus = MPAuthorizationStatusNotDetermined;
    for (int i = 0; i < 4; i++) {
        MPAuthorizationStatus status = _checkFDAUsingFile(testFiles[i]);
        if (status == MPAuthorizationStatusAuthorized) {
            resultStatus = MPAuthorizationStatusAuthorized;
            break;
        }
        if (status == MPAuthorizationStatusDenied) {
            resultStatus = MPAuthorizationStatusDenied;
        }
    }

    return resultStatus;
}


void kvm_check_permission()
{

    //Request screen recording access
    if(__builtin_available(macOS 10.15, *)){
        if(!CGPreflightScreenCaptureAccess()) {
            CGRequestScreenCaptureAccess();
        }
    }


    // Request accessibility access
    if(__builtin_available(macOS 10.9, *)){
        const void * keys[] = { kAXTrustedCheckOptionPrompt };
        const void * values[] = { kCFBooleanTrue };

        CFDictionaryRef options = CFDictionaryCreate(
            kCFAllocatorDefault,
            keys,
            values,
            sizeof(keys) / sizeof(*keys),
            &kCFCopyStringDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);

        AXIsProcessTrustedWithOptions(options);
    }

    // Check full disk access status
    // Note: If not granted, do nothing here. This will be addressed later with a GUI
    // permission helper that users can launch on-demand to review and grant permissions.
    if(__builtin_available(macOS 10.14, *)) {
        if(_fullDiskAuthorizationStatus() != MPAuthorizationStatusAuthorized) {
            // TODO: Launch permission helper GUI (when implemented)
            // For now, silently continue - don't auto-open System Settings
        }
    }
}