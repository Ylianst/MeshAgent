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

#include "mac_kvm.h"
#include "mac_cursor.h"
#include "mac_inputlock.h"
#include "mac_sck.h"
#include "../../meshdefines.h"
#include "../../meshinfo.h"
#include "../../../microstack/ILibParsers.h"
#include "../../../microstack/ILibAsyncSocket.h"
#include "../../../microstack/ILibAsyncServerSocket.h"
#include "../../../microstack/ILibProcessPipe.h"
#include <IOKit/IOKitLib.h>
#include <IOKit/hidsystem/IOHIDLib.h>
#include <IOKit/hidsystem/IOHIDParameter.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreServices/CoreServices.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/event.h>

#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <membership.h>
#include <libproc.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <spawn.h>
#include <sys/wait.h>
#include <mach-o/dyld.h>
#include <notify.h>

extern char **environ;

// Some macOS SDKs (notably older Xcode / SDK 10.x) did not export
// LOCAL_PEERPID in <sys/un.h> even though the kernel supports it.
// Define it here as a fallback so we can always query the connected
// peer's pid via getsockopt(). This is the macOS-specific way to
// validate that the daemon's IPC peer really is the user-LaunchAgent
// meshagent process (and not, e.g., a stale socket file from a
// crashed helper that was re-bound by an unrelated process). See
// issue #359: stale KVM socket files of the uid used to
// cause the daemon to wrap a phantom socket in ILibProcessPipe_Pipe
// and then crash on the first .write() with "of undefined".
#ifndef LOCAL_PEERPID
#define LOCAL_PEERPID 0x102
#endif

int KVM_Listener_FD = -1;
// Socket path used when kvm_server_mainloop runs in socket-listener
// mode. Default is the system-owned path used by the legacy -kvm1
// mode (root daemon spawn case). The new user-LaunchAgent flow
// (-kvmagent) overrides this via kvm_set_listener_path() before
// entering the loop, since the user agent can't bind under
// /usr/local/mesh_services/.
static char kvm_listener_path[256] = "/usr/local/mesh_services/meshagent/kvm";

void kvm_set_listener_path(const char *path)
{
	if (path == NULL || *path == '\0') return;
	size_t len = strlen(path);
	if (len >= sizeof(kvm_listener_path)) return;
	memcpy(kvm_listener_path, path, len);
	kvm_listener_path[len] = '\0';
}

// The launchd job label of this process, or NULL when launchd did not start it. A process started from Terminal has "0".
static const char* kvm_service_label(void)
{
	const char *label = getenv("XPC_SERVICE_NAME");
	return((label != NULL && label[0] != 0 && strcmp(label, "0") != 0) ? label : NULL);
}

// Two agent services on one Mac shared /tmp/meshagent-kvm-<uid>.sock, so the LaunchAgent started last got the desktop of every service's daemon.
// launchd sets XPC_SERVICE_NAME to the job label, "<service>" for the daemon and "<service>-launchagent" for the LaunchAgent, so both sides name the socket after the service.
// Without a label or with legacy set, it writes the shared path.
void kvm_socket_path(char *buf, size_t bufLen, unsigned int uid, int legacy)
{
	static const char suffix[] = "-launchagent";
	const char *label = legacy ? NULL : kvm_service_label();
	size_t len = label != NULL ? strlen(label) : 0;
	size_t maxLen = bufLen < sizeof(((struct sockaddr_un*)0)->sun_path) ? bufLen : sizeof(((struct sockaddr_un*)0)->sun_path);
	int written;

	if (len > sizeof(suffix) - 1 && strcmp(label + len - (sizeof(suffix) - 1), suffix) == 0) { len -= sizeof(suffix) - 1; }
	if (len > 0 && memchr(label, '/', len) == NULL)
	{
		written = snprintf(buf, bufLen, "/tmp/meshagent-kvm-%.*s-%u.sock", (int)len, label, uid);
		if (written > 0 && (size_t)written < maxLen) { return; }
	}
	snprintf(buf, bufLen, "/tmp/meshagent-kvm-%u.sock", uid);
}

// Writes the socket the daemon should connect to for the uid: the service socket, or the shared one a LaunchAgent started before the update still listens on.
// Returns 1 when a socket owned by the uid is there. Anybody can bind a name in /tmp while the agent is not listening, so another owner is not the agent.
static int kvm_find_socket(char *buf, size_t bufLen, unsigned int uid)
{
	struct stat s;
	int legacy;
	for (legacy = 0; legacy < 2; ++legacy)
	{
		kvm_socket_path(buf, bufLen, uid, legacy);
		if (stat(buf, &s) == 0 && S_ISSOCK(s.st_mode) && s.st_uid == uid) { return(1); }
	}
	return(0);
}
#if defined(_TLSLOG)
#define TLSLOG1 printf
#else
#define TLSLOG1(...) ;
#endif


int KVM_AGENT_FD = -1;
int KVM_STDOUT_IS_LOG = 0;
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



CGDirectDisplayID SCREEN_NUM = 0;
int SH_HANDLE = 0;
int SCREEN_WIDTH = 0;
int SCREEN_HEIGHT = 0;
int SCREEN_SCALE = 1;
int SCREEN_DEPTH = 0;
int TILE_WIDTH = 0;
int TILE_HEIGHT = 0;
int TILE_WIDTH_COUNT = 0;
int TILE_HEIGHT_COUNT = 0;
int COMPRESSION_RATIO = 0;
int FRAME_RATE_TIMER = 0;
volatile int g_viewerFrameTimer = 0; // The viewer's frame timer, kept apart because kvm_init() sets FRAME_RATE_TIMER back to 100 after every display change
struct tileInfo_t **g_tileInfo = NULL;
int g_remotepause = 0;
int g_pause = 0;
int g_shutdown = 0;
int g_resetipc = 0;
int kvm_clientProcessId = 0;
int g_restartcount = 0;
int g_totalRestartCount = 0;
int restartKvm = 0;
extern void* tilebuffer;
pid_t g_slavekvm = 0;
pthread_t kvmthread = (pthread_t)NULL;
ILibProcessPipe_Process gChildProcess;
ILibQueue g_messageQ;

// #define KVMDEBUGENABLED 1
#ifdef KVMDEBUGENABLED
static void KvmDebugLog(const char *format, ...)
{
	char tmp[255];
	int len;
	va_list args;

	if (KVM_STDOUT_IS_LOG == 0) { return; }
	va_start(args, format);
	len = vsnprintf(tmp, sizeof(tmp), format, args);
	va_end(args);
	if (len <= 0) { return; }
	if (len > (int)sizeof(tmp) - 1) { len = (int)sizeof(tmp) - 1; }
	write(STDOUT_FILENO, tmp, len);
	fsync(STDOUT_FILENO);
}
#else
#define KvmDebugLog(...)
#endif

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
	io_service_t ios;
	io_connect_t ioc;
	CFMutableDictionaryRef mdict;

	while (1)
	{
		mdict = IOServiceMatching(kIOHIDSystemClass);
		ios = IOServiceGetMatchingService(kIOMasterPortDefault, (CFDictionaryRef)mdict);
		if (!ios)
		{
			if (mdict)
			{
				CFRelease(mdict);
			}
			ILIBLOGMESSAGEX("IOServiceGetMatchingService() failed\n");
			break;
		}

		kr = IOServiceOpen(ios, mach_task_self(), kIOHIDParamConnectType, &ioc);
		IOObjectRelease(ios);
		if (kr != KERN_SUCCESS)
		{
			ILIBLOGMESSAGEX("IOServiceOpen() failed: %x\n", kr);
			break;
		}

		// Set CAPSLOCK
		kr = IOHIDSetModifierLockState(ioc, kIOHIDCapsLockState, (input_state & 4) == 4);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}

		// Set NUMLOCK
		kr = IOHIDSetModifierLockState(ioc, kIOHIDNumLockState, (input_state & 1) == 1);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}

		// CAPSLOCK_QUERY
		bool state;
		kr = IOHIDGetModifierLockState(ioc, kIOHIDCapsLockState, &state);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}
		ret |= (state << 2);

		// NUMLOCK_QUERY
		kr = IOHIDGetModifierLockState(ioc, kIOHIDNumLockState, &state);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}
		ret |= state;

		IOServiceClose(ioc);
		break;
	}
	return(ret);
}
int get_kbd_state()
{
	int ret = 0;
	kern_return_t kr;
	io_service_t ios;
	io_connect_t ioc;
	CFMutableDictionaryRef mdict;

	while (1)
	{
		mdict = IOServiceMatching(kIOHIDSystemClass);
		ios = IOServiceGetMatchingService(kIOMasterPortDefault, (CFDictionaryRef)mdict);
		if (!ios)
		{
			if (mdict)
			{
				CFRelease(mdict);
			}
			ILIBLOGMESSAGEX("IOServiceGetMatchingService() failed\n");
			break;
		}

		kr = IOServiceOpen(ios, mach_task_self(), kIOHIDParamConnectType, &ioc);
		IOObjectRelease(ios);
		if (kr != KERN_SUCCESS)
		{
			ILIBLOGMESSAGEX("IOServiceOpen() failed: %x\n", kr);
			break;
		}

		// CAPSLOCK_QUERY
		bool state;
		kr = IOHIDGetModifierLockState(ioc, kIOHIDCapsLockState, &state);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}
		ret |= (state << 2);

		// NUMLOCK_QUERY
		kr = IOHIDGetModifierLockState(ioc, kIOHIDNumLockState, &state);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}
		ret |= state;

		IOServiceClose(ioc);
		break;
	}
	return(ret);
}


// Sets the screen to "width" by "height" pixels, then the tiles and the viewer's resolution.
// The scale for the mouse is the ratio of pixels to the display's points, 2 on a Retina display. It was kept from earlier sizes and only ever grew, so after a display mode change it could stay wrong.
static int kvm_init_size(int width, int height)
{
	ILibCriticalLogFilename = "KVMSlave.log";
	int points = (int)CGDisplayPixelsWide(SCREEN_NUM);

	SCREEN_WIDTH = width;
	SCREEN_HEIGHT = height;
	SCREEN_SCALE = (points > 0 && width >= points) ? (width + points / 2) / points : 1;
	// Some magic numbers.
	TILE_WIDTH = 32;
	TILE_HEIGHT = 32;
	COMPRESSION_RATIO = 50;
	FRAME_RATE_TIMER = 100;
	
	TILE_HEIGHT_COUNT = SCREEN_HEIGHT / TILE_HEIGHT;
	TILE_WIDTH_COUNT = SCREEN_WIDTH / TILE_WIDTH;
	if (SCREEN_WIDTH % TILE_WIDTH) { TILE_WIDTH_COUNT++; }
	if (SCREEN_HEIGHT % TILE_HEIGHT) { TILE_HEIGHT_COUNT++; }
	
	kvm_send_resolution();
	tile_info_alloc();
	
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

// The display mode's pixel size is a first guess, the main loop corrects it from the first captured image when they differ
int kvm_init()
{
	CGDisplayModeRef mode;
	int width, height;

	SCREEN_NUM = CGMainDisplayID();
	if ((mode = CGDisplayCopyDisplayMode(SCREEN_NUM)) != NULL)
	{
		width = (int)CGDisplayModeGetPixelWidth(mode);
		height = (int)CGDisplayModeGetPixelHeight(mode);
		CGDisplayModeRelease(mode);
	}
	else
	{
		width = (int)CGDisplayPixelsWide(SCREEN_NUM);
		height = (int)CGDisplayPixelsHigh(SCREEN_NUM);
	}
	return(kvm_init_size(width, height));
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
		case MNG_KVM_INPUT_LOCK:
		{
			// 0 unlocks, 1 locks, 2 only asks, and the reply carries the state now in force, as on Windows
			unsigned char *buffer;
			if (size != 5 || (unsigned char)block[4] > 2) { break; }
			if (block[4] != 2) { kvm_inputlock_set(block[4]); }
			buffer = ILibMemory_SmartAllocate(5);
			((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_INPUT_LOCK);
			((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);
			buffer[4] = (unsigned char)kvm_inputlock_get();
			ILibQueue_Lock(g_messageQ);
			ILibQueue_EnQueue(g_messageQ, buffer);
			ILibQueue_UnLock(g_messageQ);
			break;
		}
		case MNG_KVM_KEY: // Key
		{
			// Removed `KVM_AGENT_FD != -1` skip — in our user-LaunchAgent
			// architecture (-kvmagent) the agent IS the process that
			// should handle keystrokes locally via KeyAction, since it's
			// the one in the user's GUI session with TCC permission to
			// post CGEvents.
			if (size != 6) { break; }
			KeyAction(block[5], block[4]);
			break;
		}
		case MNG_KVM_MOUSE: // Mouse
		{
			double x, y;
			short w = 0;
			// Same as above — process mouse locally in -kvmagent mode.
			if (size == 10 || size == 12)
			{
				x = ((int)ntohs(((unsigned short*)(block))[3])) / (double)SCREEN_SCALE;
				y = ((int)ntohs(((unsigned short*)(block))[4])) / (double)SCREEN_SCALE;
				
				if (size == 12) w = ((short)ntohs(((short*)(block))[5]));
				
				//printf("x:%d, y:%d, b:%d, w:%d\n", x, y, block[5], w);
				MouseAction(x, y, (int)(unsigned char)(block[5]), w);
				kvm_cursor_moved();
			}
			break;
		}
		case MNG_KVM_COMPRESSION: // Compression
		{
			// The server sends 10 bytes, with the scaling at offset 6, which is not used here, and the frame timer at offset 8
			if (size >= 10) { int fr = ((int)ntohs(ILibUnaligned_Read16(block + 8))); if (fr >= 20 && fr <= 5000) g_viewerFrameTimer = fr; }
			if (size >= 6) { set_tile_compression((int)block[4], (int)block[5]); }
			COMPRESSION_RATIO = 100;
			break;
		}
		case MNG_KVM_REFRESH: // Refresh
		{
			kvm_send_resolution();

			if (size != 4) break;
			tile_request_refresh();
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
			if (size >= 6) { int fr = ((int)ntohs(ILibUnaligned_Read16(block + 4))); if (fr >= 20 && fr <= 5000) g_viewerFrameTimer = fr; }
			break;
		}
	}

	return size;
}


// Socket-mode (user-LaunchAgent) state. When the daemon successfully
// connects to the KVM socket of the uid at session-init time,
// kvm_relay_setup() leaves these populated and the write/read paths
// fall through to the socket pipe instead of the legacy fork-exec
// helper's stdio.
static ILibProcessPipe_Pipe g_kvmSocketPipe = NULL;
static int                   g_kvmSocketFD   = -1;
static ILibKVM_WriteHandler  g_kvmSocketWriteHandler = NULL;
static void                 *g_kvmSocketReserved     = NULL;

static void kvm_relay_socket_ResetState(int closePipe)
{
	if (closePipe != 0 && g_kvmSocketPipe != NULL)
	{
		ILibProcessPipe_Pipe_SetBrokenPipeHandler(g_kvmSocketPipe, NULL);
		ILibProcessPipe_FreePipe(g_kvmSocketPipe);
	}
	else if (closePipe != 0 && g_kvmSocketFD != -1)
	{
		close(g_kvmSocketFD);
	}

	g_kvmSocketPipe = NULL;
	g_kvmSocketFD = -1;
	g_kvmSocketWriteHandler = NULL;
	g_kvmSocketReserved = NULL;
}

int kvm_relay_feeddata(char* buf, int len)
{
	if (g_kvmSocketPipe != NULL)
	{
		// Socket-mode: forward bytes to the user-context LaunchAgent
		// over the connected Unix domain socket. Same TLV protocol
		// that flowed over the helper's stdin in fork-exec mode.
		ILibProcessPipe_Pipe_Write(g_kvmSocketPipe, buf, len, ILibTransport_MemoryOwnership_USER);
		return(len);
	}
	if (gChildProcess != NULL)
	{
		ILibProcessPipe_Process_WriteStdIn(gChildProcess, buf, len, ILibTransport_MemoryOwnership_USER);
	}
	return(len);
}

// Set the KVM pause state
void kvm_pause(int pause)
{
	g_pause = pause;
}


// Before login the window server refuses this process the connection that posting events needs, and CGEventCreateKeyboardEvent() then blocked the thread on the first key packet.
// So the login window instance drops mouse and keyboard packets, the picture keeps working and the input thread keeps reading. Posting from the main thread blocked that thread too.
static int kvm_input_packet(char *block, int blocklen)
{
	unsigned short type, size;

	if (getuid() != 0 || blocklen < 4) { return(kvm_server_inputdata(block, blocklen)); }
	type = ntohs(((unsigned short*)(block))[0]);
	size = ntohs(((unsigned short*)(block))[1]);
	if (size == 0 || size > blocklen) { return(0); }
	if (type == MNG_KVM_KEY || type == MNG_KVM_KEY_UNICODE || type == MNG_KVM_MOUSE) { return(size); }
	return(kvm_server_inputdata(block, blocklen));
}

void* kvm_mainloopinput(void* param)
{
	int ptr = 0;
	int ptr2 = 0;
	int len = 0;
	char* pchRequest2[30000];
	int cbBytesRead = 0;

	if (KVM_AGENT_FD == -1)
	{
		int flags;
		flags = fcntl(STDIN_FILENO, F_GETFL, 0);
		if (fcntl(STDIN_FILENO, F_SETFL, (O_NONBLOCK | flags) ^ O_NONBLOCK) == -1) { senddebug(-999); }
	}
	kvm_inputlock_watch(1);

	while (!g_shutdown)
	{
		KvmDebugLog("About to read from IPC Socket\n");
		cbBytesRead = read(KVM_AGENT_FD == -1 ? STDIN_FILENO: KVM_AGENT_FD, pchRequest2 + len, 30000 - len);
		KvmDebugLog("Read %d bytes from IPC Socket\n", cbBytesRead);

		if (cbBytesRead == -1 || cbBytesRead == 0) 
		{ 
			/*ILIBMESSAGE("KVMBREAK-K1\r\n"); g_shutdown = 1; printf("shutdown\n");*/ 
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
		
		KvmDebugLog("enter while\n");
		while ((ptr2 = kvm_input_packet((char*)pchRequest2 + ptr, cbBytesRead - ptr)) != 0) { ptr += ptr2; }
		KvmDebugLog("exited while\n");

		if (ptr == len) { len = 0; ptr = 0; }
		// TODO: else move the reminder.
	}

	// The viewer is gone, so the local user gets the keyboard and mouse back
	kvm_inputlock_set(0);
	kvm_inputlock_watch(0);
	return 0;
}
static void kvm_permission_watch_start(void);
static volatile int g_exiting = 0;

void ExitSink(int s)
{
	UNREFERENCED_PARAMETER(s);
	g_exiting = 1;

	signal(SIGTERM, SIG_IGN);	
	
	if (KVM_Listener_FD > 0) 
	{
		write(STDOUT_FILENO, "EXITING\n", 8);
		fsync(STDOUT_FILENO);
		close(KVM_Listener_FD); 
	}
	g_shutdown = 1;
}

static int kvm_session_on_console(void);

// 1 when this session is not on the screen, read at most once a second
static int kvm_session_left_console(void)
{
	static uint64_t lastCheck = 0;
	uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1000000;

	if (now - lastCheck < 1000) { return(0); }
	lastCheck = now;
	return(!kvm_session_on_console());
}

// Encodes and sends the tiles that changed in the frame
static void kvm_send_tiles(void *desktop, long long desktopsize)
{
	int x, y;
	long long tilesize = 0;
	void *buf = NULL;
	int written;

	KvmDebugLog("...Enter for loop\n");
	tile_start_pass((const unsigned char *)desktop, desktopsize);

	for (y = 0; y < TILE_HEIGHT_COUNT; y++)
	{
		for (x = 0; x < TILE_WIDTH_COUNT; x++)
		{
			if (!g_shutdown && (g_pause)) { usleep(100000); g_pause = 0; } //HACK: Change this
			if (g_shutdown) { return; }
			if (g_tileInfo[y][x].flag != TILE_CHANGED) { continue; }

			getTileAt(TILE_WIDTH * x, TILE_HEIGHT * y, &buf, &tilesize, desktop, desktopsize, y, x);
			if (buf == NULL) { continue; }

			written = g_shutdown ? 0 : KVM_SEND(buf, tilesize);
			free(buf);
			if (written == -1)
			{
				// The rest of the frame is not encoded for a connection that is gone. A user session exits and can be spawned again.
				// A -kvmagent waits for its next connection, and sends the whole screen should this one still be there.
				if (KVM_AGENT_FD == -1) { g_shutdown = 1; } else { tile_request_refresh(); }
				return;
			}
		}
	}

	KvmDebugLog("...exit for loop\n");
}

// 1 when the display mode's pixel size is no longer the size the stream was started with, read at most once a second.
// A size of 0 is read at once, because a new session sets it to 0 to get the size sent again.
static int kvm_display_size_changed(CGDirectDisplayID display)
{
	static uint64_t lastCheck = 0;
	uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1000000;
	CGDisplayModeRef mode;
	int changed = 0;

	if (SCREEN_WIDTH != 0 && now - lastCheck < 1000) { return(0); }
	lastCheck = now;

	if ((mode = CGDisplayCopyDisplayMode(display)) != NULL)
	{
		changed = (int)CGDisplayModeGetPixelWidth(mode) != SCREEN_WIDTH || (int)CGDisplayModeGetPixelHeight(mode) != SCREEN_HEIGHT;
		CGDisplayModeRelease(mode);
	}
	return(changed);
}

// A sleeping display gives the stream no frames, so a new session wakes it like a key press does
static void kvm_wake_display(void)
{
	static IOPMAssertionID activity = kIOPMNullAssertionID;
	IOPMAssertionDeclareUserActivity(CFSTR("MeshAgent remote desktop"), kIOPMUserActiveLocal, &activity);
}

static uint64_t g_sckRetryAtMs = 0;
static int g_sckRetryWaitS = 0;

// Sets when the stream is tried again and returns the state "failed", so CGDisplayCreateImage() captures until then.
// After 5 s at first, then twice as long each time up to 60 s, because a start that fails can hold the frame loop for 4 s.
static int kvm_sck_failed(const char *what)
{
	g_sckRetryWaitS = (g_sckRetryWaitS == 0) ? 5 : (g_sckRetryWaitS >= 30 ? 60 : g_sckRetryWaitS * 2);
	g_sckRetryAtMs = clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1000000 + (uint64_t)g_sckRetryWaitS * 1000;
	ILIBLOGMESSAGEX("KVM: the ScreenCaptureKit stream %s, capturing with CGDisplayCreateImage(), next try in %d s\n", what, g_sckRetryWaitS);
	return(-1);
}

void* kvm_server_mainloop(void* param)
{
	uint64_t frameStartMs = 0;
	int frameTimerQueue = -1;
	int sckState = 0; // 0 not started, 1 the stream runs, -1 it failed, so CGDisplayCreateImage() is used until the next try, -2 this macOS has no stream
	int sckIntervalMs = 0;
	long long desktopsize = 0;
	void *desktop = NULL;
	void *buf = NULL;
	int screen_num;
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
		// this is doing I/O via a Unix Domain Socket
		KVM_STDOUT_IS_LOG = 1;
		if ((KVM_Listener_FD = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		{
			char tmp[255];
			int tmplen = sprintf_s(tmp, sizeof(tmp), "ERROR CREATING DOMAIN SOCKET: %d\n", errno);
			// Error creating domain socket
			write(STDOUT_FILENO, tmp, tmplen);
			fsync(STDOUT_FILENO);
			return(NULL);
		}

		int flags;
		flags = fcntl(KVM_Listener_FD, F_GETFL, 0);
		if (fcntl(KVM_Listener_FD, F_SETFL, (O_NONBLOCK | flags) ^ O_NONBLOCK) == -1) { }

		KvmDebugLog("Set FCNTL2\n");

		memset(&serveraddr, 0, sizeof(serveraddr));
		serveraddr.sun_family = AF_UNIX;
		strcpy(serveraddr.sun_path, kvm_listener_path);
		remove(kvm_listener_path);
		if (bind(KVM_Listener_FD, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr)) < 0)
		{
			char tmp[255];
			int tmplen = sprintf_s(tmp, sizeof(tmp), "BIND ERROR on DOMAIN SOCKET: %d\n", errno);
			// Error creating domain socket
			write(STDOUT_FILENO, tmp, tmplen);
			fsync(STDOUT_FILENO);
			return(NULL);
		}

		if (listen(KVM_Listener_FD, 1) < 0)
		{
			write(STDOUT_FILENO, "LISTEN ERROR ON DOMAIN SOCKET", 29);
			fsync(STDOUT_FILENO);
			return(NULL);
		}

		write(STDOUT_FILENO, "LISTENING ON DOMAIN SOCKET\n", 27);
		fsync(STDOUT_FILENO);

		signal(SIGTERM, ExitSink);

		if ((KVM_AGENT_FD = accept(KVM_Listener_FD, NULL, NULL)) < 0)
		{
			write(STDOUT_FILENO, "ACCEPT ERROR ON DOMAIN SOCKET", 29);
			fsync(STDOUT_FILENO);
			return(NULL);
		}
		else
		{
			char tmp[255];
			int tmpLen = sprintf_s(tmp, sizeof(tmp), "ACCEPTed new connection %d on Domain Socket\n", KVM_AGENT_FD);
			write(STDOUT_FILENO, tmp, tmpLen);
			fsync(STDOUT_FILENO);

		}
	}
	// Init the kvm
	g_messageQ = ILibQueue_Create();
	if (kvm_init() != 0) { return (void*)-1; }
	frameTimerQueue = kqueue();


	g_shutdown = 0;
	kvm_wake_display();
	kvm_permission_watch_start();
	pthread_create(&kvmthread, NULL, kvm_mainloopinput, param);


	KvmDebugLog("Starting Loop [] TILE_HEIGHT_COUNT=%d, TILE_WIDTH_COUNT=%d\n", TILE_HEIGHT_COUNT, TILE_WIDTH_COUNT);

kvm_next_session:
	while (!g_shutdown)
	{
		if (g_resetipc != 0)
		{
			g_resetipc = 0;
			kvm_cursor_reset();
			if (sckState == 1) { kvm_sck_stop(); }
			sckState = 0;
			close(KVM_AGENT_FD);

			SCREEN_HEIGHT = SCREEN_WIDTH = 0;

			char stmp[255];
			int stmpLen = sprintf_s(stmp, sizeof(stmp), "Waiting for NEXT DomainSocket, TILE_HEIGHT_COUNT=%d, TILE_WIDTH_COUNT=%d\n", TILE_HEIGHT_COUNT, TILE_WIDTH_COUNT);
			write(STDOUT_FILENO, stmp, stmpLen);
			fsync(STDOUT_FILENO);

			if ((KVM_AGENT_FD = accept(KVM_Listener_FD, NULL, NULL)) < 0)
			{
				g_shutdown = 1;
				write(STDOUT_FILENO, "ACCEPT ERROR ON DOMAIN SOCKET", 29);
				fsync(STDOUT_FILENO);
				break;
			}
			else
			{
				char tmp[255];
				int tmpLen = sprintf_s(tmp, sizeof(tmp), "ACCEPTed new connection %d on Domain Socket\n", KVM_AGENT_FD);
				write(STDOUT_FILENO, tmp, tmpLen);
				fsync(STDOUT_FILENO);
				kvm_wake_display();
				kvm_permission_watch_start();
				pthread_create(&kvmthread, NULL, kvm_mainloopinput, param);
			}
		}

		// After a fast user switch the capture of this session no longer fits, so the session ends and the next connect reaches the user now at the screen.
		// For the -kvmagent the closed socket ends the input thread's read, which sets g_resetipc, and the block above then waits for the next connection.
		if (kvm_session_left_console())
		{
			if (KVM_AGENT_FD == -1) { g_shutdown = 1; break; }
			shutdown(KVM_AGENT_FD, SHUT_RDWR);
			while (!g_resetipc && !g_shutdown) { usleep(50000); }
			continue;
		}

		// Check if there are pending messages to be sent
		ILibQueue_Lock(g_messageQ);
		while (ILibQueue_IsEmpty(g_messageQ) == 0)
		{
			if ((buf = (char*)ILibQueue_DeQueue(g_messageQ)) != NULL)
			{
				KVM_SEND(buf, (int)ILibMemory_Size(buf));
				ILibMemory_Free(buf);
			}
		}
		ILibQueue_UnLock(g_messageQ);
		kvm_cursor_check(g_messageQ);


		// The frame timer is the time from one frame start to the next. Without this wait the loop captured again as soon as the tiles were sent.
		// Waits in steps of 50 ms at most, so a new timer value, a shutdown or a new connection is noticed, and not at all while a running stream paces the frames.
		// A kqueue timer with NOTE_CRITICAL because under launchd usleep(20000) took 66 to 95 ms and usleep(50000) 102 to 125 ms (macOS 15.8 and 26.7), this one 20.0 and 50.1 ms.
		while (sckState != 1 && !g_shutdown && g_resetipc == 0)
		{
			uint64_t nowMs = clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1000000;
			uint64_t timerMs = (uint64_t)(g_viewerFrameTimer > 0 ? g_viewerFrameTimer : FRAME_RATE_TIMER);
			uint64_t waitMs;
			struct kevent timerEvent, firedEvent;

			if (frameStartMs == 0 || nowMs - frameStartMs >= timerMs) { break; }
			waitMs = timerMs - (nowMs - frameStartMs);
			if (waitMs > 50) { waitMs = 50; }
			EV_SET(&timerEvent, 1, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_USECONDS | NOTE_CRITICAL, (intptr_t)(waitMs * 1000), NULL);
			if (frameTimerQueue < 0 || kevent(frameTimerQueue, &timerEvent, 1, &firedEvent, 1, NULL) < 0) { usleep((useconds_t)(waitMs * 1000)); }
		}
		if (g_shutdown) { break; }
		if (g_resetipc != 0) { continue; }
		frameStartMs = clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1000000;

		screen_num = CGMainDisplayID();

		if (screen_num == 0) { g_shutdown = 1; senddebug(-2); break; }
		
		// Before macOS 12.3 there is no ScreenCaptureKit, so CGDisplayCreateImage() captures every frame as before
		if (sckState == 0 && !kvm_sck_available()) { sckState = -2; }

		// The size is checked before the stream starts, and not during the fallback, which takes it from the captured image
		if (SCREEN_NUM != screen_num || (sckState >= 0 && kvm_display_size_changed(screen_num)))
		{
			if (sckState == 1) { kvm_sck_stop(); sckState = 0; }
			kvm_init();
			continue;
		}

		// The stream paces the frames and delivers only changed ones, so a still screen costs no capture and no tile check
		if (sckState == -1 && frameStartMs >= g_sckRetryAtMs) { sckState = 0; }
		if (sckState == 0)
		{
			sckIntervalMs = g_viewerFrameTimer > 0 ? g_viewerFrameTimer : FRAME_RATE_TIMER;
			if (kvm_sck_start(screen_num, SCREEN_WIDTH, SCREEN_HEIGHT, sckIntervalMs) != 0) { sckState = kvm_sck_failed("did not start"); }
			else
			{
				if (g_sckRetryWaitS != 0) { ILIBLOGMESSAGEX("KVM: the ScreenCaptureKit stream runs again\n"); }
				g_sckRetryWaitS = 0;
				sckState = 1;
			}
		}
		if (sckState == 1)
		{
			int got;

			// A new timer from the viewer changes the running stream's interval, and the stream starts again only when that fails
			int timer = g_viewerFrameTimer;
			if (timer > 0 && timer != sckIntervalMs)
			{
				if (kvm_sck_set_interval(timer) != 0) { kvm_sck_stop(); sckState = 0; continue; }
				sckIntervalMs = timer;
			}

			// A short wait, so the message queue and the pointer check above still run on a still screen
			got = kvm_sck_take_frame((unsigned char **)&desktop, &desktopsize, 50);
			if (got < 0) { kvm_sck_stop(); sckState = kvm_sck_failed("stopped"); continue; }
			// A still screen gives no new frame, so a viewer's refresh and tiles whose encode failed are sent from the last one
			if (got == 0 && tile_pass_pending()) { got = 1; }
			if (got > 0) { kvm_send_tiles(desktop, desktopsize); }
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
			// The captured image is the screen as it is now, also during a fast user switch or after a display mode change, so a new size comes from it
			if ((int)CGImageGetWidth(image) != SCREEN_WIDTH || (int)CGImageGetHeight(image) != SCREEN_HEIGHT)
			{
				kvm_init_size((int)CGImageGetWidth(image), (int)CGImageGetHeight(image));
				CGImageRelease(image);
				continue;
			}
			//senddebug(100);
			if (getScreenBuffer((unsigned char **)&desktop, &desktopsize, image) != 0)
			{
				// The image did not fit the buffer, so the size is read again as after a display change, after a short pause in case it stays so
				CGImageRelease(image);
				usleep(100000);
				kvm_init();
				continue;
			}

			kvm_send_tiles(desktop, desktopsize);

		}
		CGImageRelease(image);
	}

	// A capture fails once the session left the screen (NULL image or display 0), which ended the whole -kvmagent with exit 0 and kept the socket open, so the viewer froze.
	// Unless SIGTERM ended it, a -kvmagent closes only the session, waits for its input thread and takes the next connection.
	if (sckState == 1) { kvm_sck_stop(); }
	sckState = 0;
	if (KVM_AGENT_FD != -1 && !g_exiting)
	{
		shutdown(KVM_AGENT_FD, SHUT_RDWR);
		pthread_join(kvmthread, NULL);
		g_shutdown = 0;
		g_resetipc = 1;
		goto kvm_next_session;
	}

	pthread_join(kvmthread, NULL);
	kvmthread = (pthread_t)NULL;

	if (frameTimerQueue >= 0) { close(frameTimerQueue); }
	tile_info_free();
	if(tilebuffer != NULL) {
		free(tilebuffer);
		tilebuffer = NULL;
	}

	KvmDebugLog("Exiting...\n");
	ILibQueue_Destroy(g_messageQ);
	return (void*)0;
}

// ProcessPipe frees the child and its pipes right after this, so the session has to let go of them here.
// A child that kvm_cleanup() already let go of is skipped, because its session data may be freed by now.
void kvm_relay_ExitHandler(ILibProcessPipe_Process sender, int exitCode, void* user)
{
	UNREFERENCED_PARAMETER(exitCode);
	if (sender == gChildProcess)
	{
		gChildProcess = NULL;
		ILibDuktape_MeshAgent_RemoteDesktop_KVM_Exited(((void**)user)[1]);
	}
	ILibMemory_Free(user);
}
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


// macOS Tahoe: socket-mode read handler. Same TLV-frame parser as
// kvm_relay_StdOutHandler but with the (sender, buf, len, consumed)
// signature ILibProcessPipe_Pipe_AddPipeReadHandler expects (no user
// arg). User context is fetched from g_kvmSocket* statics, set in
// kvm_relay_setup.
static void kvm_relay_socket_ReadHandler(ILibProcessPipe_Pipe sender, char *buffer, size_t bufferLen, size_t* bytesConsumed)
{
	unsigned short size = 0;
	UNREFERENCED_PARAMETER(sender);
	ILibKVM_WriteHandler writeHandler = g_kvmSocketWriteHandler;
	void *reserved = g_kvmSocketReserved;
	if (writeHandler == NULL) { *bytesConsumed = bufferLen; return; }

	if (bufferLen > 4)
	{
		if (ntohs(((unsigned short*)(buffer))[0]) == (unsigned short)MNG_JUMBO)
		{
			if (bufferLen > 8)
			{
				if (bufferLen >= (8 + (int)ntohl(((unsigned int*)(buffer))[1])))
				{
					*bytesConsumed = 8 + (int)ntohl(((unsigned int*)(buffer))[1]);
					writeHandler(buffer, *bytesConsumed, reserved);
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
				return;
			}
		}
	}
	*bytesConsumed = 0;
}

// macOS Tahoe: socket-mode broken-pipe handler. Clears state so
// kvm_relay_feeddata() falls through cleanly and a future Desktop
// session re-runs kvm_relay_setup() (which reconnects).
static void kvm_relay_socket_BrokenHandler(ILibProcessPipe_Pipe sender)
{
	void *reserved = g_kvmSocketReserved;
	UNREFERENCED_PARAMETER(sender);
	kvm_relay_socket_ResetState(0);
	// ProcessPipe frees this pipe right after the handler, and the session kept pausing and freeing it, while the viewer waited on a stream that sent nothing.
	// The LaunchAgent ends the socket when its user leaves the screen or it restarts after a grant, so the session ends as for an exited -kvm0 child.
	if (reserved != NULL) { ILibDuktape_MeshAgent_RemoteDesktop_KVM_Exited(reserved); }
}

// Validate that the connected peer of an AF_UNIX socket really is the
// meshagent LaunchAgent we expect (i.e. an agent running as the same
// uid we were asked to connect to, and owned by the current user, not
// a stale socket file from a crashed helper or a symlink to something
// else).
//
// Returns 1 if the peer credentials look right, 0 otherwise. On
// platforms / builds that lack getpeereid() (extremely rare on
// macOS — it's been there since 10.4) we conservatively return 1
// rather than blocking the socket path. The crash-class of #359
// happens AFTER a connect() that returns 0, so the validation only
// fires for sockets that would otherwise be accepted; we are not
// adding a new failure mode.
static int kvm_relay_socket_validate_peer(int fd, int expectedUid, const char *socketPath)
{
#if defined(__APPLE__)
	uid_t peerUid = (uid_t)-1;
	gid_t peerGid = (gid_t)-1;
	if (getpeereid(fd, &peerUid, &peerGid) != 0)
	{
		fprintf(stderr, "meshagent: kvm-relay: getpeereid() failed on %s: %s (errno=%d) — treating as untrusted peer\n",
			socketPath, strerror(errno), errno);
		return(0);
	}
	if ((int)peerUid != expectedUid)
	{
		fprintf(stderr, "meshagent: kvm-relay: peer uid=%d on %s does not match expected uid=%d — refusing to attach\n",
			(int)peerUid, socketPath, expectedUid);
		return(0);
	}
	// Also ask the kernel for the peer's pid (Apple-specific
	// LOCAL_PEERPID option). If the peer exists but reports an
	// unplausible pid (0, -1) we treat that as a hint the peer
	// is a phantom and bail out.
	pid_t peerPid = -1;
	socklen_t plen = sizeof(peerPid);
	if (getsockopt(fd, 0, LOCAL_PEERPID, &peerPid, &plen) == 0 && peerPid <= 0)
	{
		fprintf(stderr, "meshagent: kvm-relay: peer pid=%d on %s is unplausible — refusing to attach\n",
			(int)peerPid, socketPath);
		return(0);
	}
	return(1);
#else
	UNREFERENCED_PARAMETER(fd);
	UNREFERENCED_PARAMETER(expectedUid);
	UNREFERENCED_PARAMETER(socketPath);
	return(1);
#endif
}
// Setup the KVM session. Return 1 if ok, 0 if it could not be setup.
void* kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int uid)
{
	char * parms0[] = { "meshagent_osx64", "-kvm0", NULL };
	void **user = (void**)ILibMemory_Allocate(4 * sizeof(void*), 0, NULL, NULL);
	user[0] = writeHandler;
	user[1] = reserved;
	user[2] = processPipeMgr;
	user[3] = exePath;

	// Ensure stale socket-mode state from a prior Desktop session is gone
	// before attempting a new connection.
	kvm_relay_socket_ResetState(1);

	if (uid != 0)
	{
		// macOS Tahoe path: prefer the user-LaunchAgent socket. Agent
		// registers in gui/<uid> natively → com.apple.replayd reachable
		// → ScreenCaptureKit works without audit_session_join. Daemon
		// just proxies bytes here.
		//
		// Fallback policy: only fall through to the legacy fork-exec
		// helper if the LaunchAgent is genuinely NOT installed (no
		// socket file on disk). If the socket exists but connect()
		// transiently fails — e.g. agent is between sessions and
		// hasn't re-accept()ed yet — we retry briefly with backoff
		// rather than firing the broken fork-exec path that lands
		// the helper in the wrong audit session and produces black
		// frames.
		char socketPath[128];
		int agentInstalled = kvm_find_socket(socketPath, sizeof(socketPath), (unsigned int)uid);

		if (agentInstalled)
		{
			int fd = -1;
			int attempt;
			const int maxRetries = 8;
			// Per-attempt backoff in microseconds. Capped at 800ms so
			// that even at the high end we stay well under one second
			// per attempt; the previous `50000 << attempt` would have
			// shifted into the millions on a 32-bit int and silently
			// wrapped to a very small sleep once attempt >= 4.
			static const int backoffUs[8] = {
				50000, 100000, 200000, 400000, 800000, 800000, 800000, 800000
			};
			int lastConnectErrno = 0;
			for (attempt = 0; attempt < maxRetries; attempt++)
			{
				fd = socket(AF_UNIX, SOCK_STREAM, 0);
				if (fd < 0)
				{
					lastConnectErrno = errno;
					fprintf(stderr, "meshagent: kvm-relay: socket() failed on attempt %d: %s (errno=%d)\n",
						attempt, strerror(errno), errno);
					break;
				}
				struct sockaddr_un addr;
				memset(&addr, 0, sizeof(addr));
				addr.sun_family = AF_UNIX;
				strncpy(addr.sun_path, socketPath, sizeof(addr.sun_path) - 1);
				if (connect(fd, (struct sockaddr*)&addr, SUN_LEN(&addr)) == 0)
				{
					// Connected. Before wrapping the fd in a Pipe, confirm
					// the peer is actually the user-LaunchAgent we expect.
					// This blocks a whole class of crashes where a stale
					// KVM socket of the uid (left behind by a
					// crashed helper) gets re-bound by an unrelated
					// process, the daemon connects, and the very first
					// .write() through ILibProcessPipe_Pipe becomes a
					// "cannot read property 'write' of undefined" that
					// promotes to ILIBCRITICALEXITMSG(254). See #359.
					if (!kvm_relay_socket_validate_peer(fd, uid, socketPath))
					{
						fprintf(stderr, "meshagent: kvm-relay: peer validation failed on %s (attempt %d) — closing and retrying\n",
							socketPath, attempt);
						close(fd);
						fd = -1;
						// Treat the bad peer as transient; the agent
						// may rebind the socket correctly on the next
						// pass. We still want to fall back to fork-exec
						// if it never recovers.
						lastConnectErrno = ECONNREFUSED;
						usleep((useconds_t)backoffUs[attempt]);
						continue;
					}
					g_kvmSocketFD            = fd;
					g_kvmSocketWriteHandler  = writeHandler;
					g_kvmSocketReserved      = reserved;
					g_kvmSocketPipe          = ILibProcessPipe_Pipe_CreateFromExisting((ILibProcessPipe_Manager)processPipeMgr, fd);
					if (g_kvmSocketPipe == NULL)
					{
						// CreateFromExisting can fail if the fd is in a
						// weird state, the manager is full, or memory is
						// exhausted. Don't leak the fd or return a half-
						// initialized pipe — close it and retry, just
						// like a transient connect() failure.
						fprintf(stderr, "meshagent: kvm-relay: Pipe_CreateFromExisting returned NULL on %s (attempt %d) — closing and retrying\n",
							socketPath, attempt);
						close(fd);
						g_kvmSocketFD = -1;
						fd = -1;
						lastConnectErrno = ECONNREFUSED;
						usleep((useconds_t)backoffUs[attempt]);
						continue;
					}
					ILibProcessPipe_Pipe_AddPipeReadHandler(g_kvmSocketPipe, 65535, &kvm_relay_socket_ReadHandler);
					ILibProcessPipe_Pipe_SetBrokenPipeHandler(g_kvmSocketPipe, &kvm_relay_socket_BrokenHandler);
					ILibProcessPipe_Pipe_ResetMetadata(g_kvmSocketPipe, "KVM user-LaunchAgent socket");
					g_shutdown = 0;
					ILibMemory_Free(user); // not used in socket mode
					return(g_kvmSocketPipe);
				}
				lastConnectErrno = errno;
				close(fd);
				fd = -1;
				// Transient failure (ECONNREFUSED on agent re-accept,
				// or similar). Back off briefly. Capped table above;
				// total budget across 8 attempts is ~3.65s.
				usleep((useconds_t)backoffUs[attempt]);
			}
			// Socket exists but unreachable after retries. Don't fall
			// back to fork-exec — that path is broken on Tahoe and
			// would produce black-screen / dead-input. Return NULL
			// to let the caller surface the error to MeshCentral.
			fprintf(stderr, "meshagent: kvm-relay: giving up on %s after %d attempts (last errno=%d: %s)\n",
				socketPath, maxRetries, lastConnectErrno, strerror(lastConnectErrno));
			ILibMemory_Free(user);
			return(NULL);
		}

		// Agent not installed (no socket file) — legacy fork-exec
		// helper. Still subject to the audit-session-isolation
		// problem on Tahoe; install the LaunchAgent (-fullinstall
		// in agent-installer.js) to upgrade to the working path.
		gChildProcess = ILibProcessPipe_Manager_SpawnProcessEx3(processPipeMgr, exePath, parms0, ILibProcessPipe_SpawnTypes_DEFAULT, (void*)(uint64_t)uid, 0);
		g_slavekvm = ILibProcessPipe_Process_GetPID(gChildProcess);

		char tmp[255];
		sprintf_s(tmp, sizeof(tmp), "Child KVM (pid: %d)", g_slavekvm);
		ILibProcessPipe_Process_ResetMetadata(gChildProcess, tmp);

		ILibProcessPipe_Process_AddHandlers(gChildProcess, 65535, &kvm_relay_ExitHandler, &kvm_relay_StdOutHandler, &kvm_relay_StdErrHandler, NULL, user);

		// Run the relay
		g_shutdown = 0;
		return(ILibProcessPipe_Process_GetStdOut(gChildProcess));
	}
	else
	{
		// No users are logged in. This is a special case for MacOS
		//int fd = socket(AF_UNIX, SOCK_STREAM, 0);
		//if (!fd < 0)
		//{
		//	struct sockaddr_un serveraddr;
		//	memset(&serveraddr, 0, sizeof(serveraddr));
		//	serveraddr.sun_family = AF_UNIX;
		//	strcpy(serveraddr.sun_path, kvm_listener_path);
		//	if (!connect(fd, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr)) < 0)
		//	{
		//		return((void*)(uint64_t)fd);
		//	}
		//}
		// The login window instance of the launch agent runs -kvmagent as root, so it listens on the uid 0 socket and not on kvm_listener_path
		// Without a root owned socket it returns kvm_listener_path, which no user can create, so the caller's connect just fails.
		static char loginWindowPath[128];
		ILibMemory_Free(user);
		return((void*)(kvm_find_socket(loginWindowPath, sizeof(loginWindowPath), 0) ? loginWindowPath : kvm_listener_path));
	}
}

// Force a KVM reset & refresh
void kvm_relay_reset()
{
	char buffer[4];
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_REFRESH);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)4);				// Write the size
	kvm_relay_feeddata(buffer, 4);
}

// Clean up the KVM session.
void kvm_cleanup()
{
	KvmDebugLog("kvm_cleanup\n");
	g_shutdown = 1;
	kvm_relay_socket_ResetState(1);
	if (gChildProcess != NULL)
	{
		ILibProcessPipe_Process_SoftKill(gChildProcess);
		gChildProcess = NULL;
	}
}


#define KVM_PERM_SCREEN 1
#define KVM_PERM_INPUT 2

int kvm_permissions(void)
{
	int ret = AXIsProcessTrusted() ? KVM_PERM_INPUT : 0;
	if (CGPreflightScreenCaptureAccess()) { ret |= KVM_PERM_SCREEN; }
	return(ret);
}

// Screen Recording access is only read once per process, so a new child is asked what is granted now
static int kvm_permissions_fresh(void)
{
	char path[PATH_MAX];
	uint32_t len = sizeof(path);
	char *args[] = { path, "-kvmpermcheck", NULL };
	pid_t pid;
	int status;

	if (_NSGetExecutablePath(path, &len) != 0) { return(-1); }
	if (posix_spawn(&pid, path, NULL, NULL, args, environ) != 0) { return(-1); }
	while (waitpid(pid, &status, 0) < 0) { if (errno != EINTR) { return(-1); } }
	return(WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

// The prompt flags are one name per line in "<executable>.kvmprefs", shared by every user of this install, because the Screen Recording and Accessibility grants are machine-wide too.
// The uninstall deletes it with the other "<executable>.*" files, so a new install asks again.
static int kvm_flags_path(char *buf, size_t bufLen)
{
	uint32_t len = (uint32_t)bufLen;
	if (_NSGetExecutablePath(buf, &len) != 0) { return(0); }
	return(strlcat(buf, ".kvmprefs", bufLen) < bufLen);
}

// The user's processes cannot create files in the install folder, so the root daemon creates the file at start, writable by the staff group
void kvm_flags_prepare(void)
{
	char path[PATH_MAX];
	struct group *staff;
	int fd;

	if (getuid() != 0 || kvm_service_label() == NULL || !kvm_flags_path(path, sizeof(path))) { return; }
	if ((fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0664)) < 0) { return; }
	if ((staff = getgrnam("staff")) != NULL) { fchown(fd, 0, staff->gr_gid); }
	fchmod(fd, 0664);
	close(fd);
}

// Reads a flag and adds it when "set" is not 0. Returns the value it had.
// Any login user can write the file, so it is only searched for whole lines and nothing else is taken from it.
static int kvm_pref_flag(const char *name, int set)
{
	char path[PATH_MAX], data[512];
	char line[64];
	struct stat st;
	ssize_t got = 0;
	int fd, lineLen, was = 0;

	lineLen = snprintf(line, sizeof(line), "\n%s\n", name);
	if (lineLen <= 0 || lineLen >= (int)sizeof(line) || !kvm_flags_path(path, sizeof(path))) { return(0); }
	if ((fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) >= 0)
	{
		if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode))
		{
			data[0] = '\n';
			got = read(fd, data + 1, sizeof(data) - 3);
			if (got < 0) { got = 0; }
			if (got > 0 && data[got] != '\n') { data[++got] = '\n'; }
			data[got + 1] = 0;
			was = strstr(data, line) != NULL;
		}
		close(fd);
	}
	if (set && !was && (fd = open(path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC)) >= 0)
	{
		if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) { write(fd, line + 1, lineLen - 1); }
		close(fd);
	}
	return(was);
}

// System Settings lists the file name, and the -kvm0 child is started with argv[0] "meshagent_osx64" instead
static const char* kvm_program_name(void)
{
	static char name[PATH_MAX];
	char path[PATH_MAX];
	uint32_t len = sizeof(path);
	const char *slash;

	if (name[0] == 0)
	{
		slash = _NSGetExecutablePath(path, &len) == 0 ? strrchr(path, '/') : NULL;
		strlcpy(name, slash != NULL ? slash + 1 : getprogname(), sizeof(name));
	}
	return(name);
}

static void kvm_open_pane(const char *url)
{
	CFURLRef ref = CFURLCreateWithBytes(NULL, (const UInt8*)url, strlen(url), kCFStringEncodingASCII, NULL);
	if (ref != NULL) { LSOpenCFURLRef(ref, NULL); CFRelease(ref); }
}

// Restart through launchd, because a new Screen Recording grant only works in a new process.
// kickstart -k kills this process, so reaching _exit(3) means it failed and KeepAlive has to restart it.
static void kvm_restart_self(void)
{
	char target[160];
	char *args[] = { "/bin/launchctl", "kickstart", "-k", target, NULL };
	const char *label = kvm_service_label();
	pid_t pid;
	int status;

	if (label != NULL)
	{
		snprintf(target, sizeof(target), "gui/%u/%s", (unsigned int)getuid(), label);
		if (posix_spawn(&pid, args[0], NULL, NULL, args, environ) == 0)
		{
			while (waitpid(pid, &status, 0) < 0 && errno == EINTR) { }
		}
	}
	_exit(3);
}

static int g_permissionOnGrant = 0;
static volatile int g_permissionWatching = 0;
static volatile int g_permissionGranted = 0;

// The Screen Recording grant is machine-wide but only works in a process started after it, so the process that sees it tells the -kvmagent of every other user.
// The name is per service, for the LaunchAgent and the -kvm0 child alike, the same way kvm_socket_path() names the socket.
static int kvm_grant_name(char *buf, size_t bufLen)
{
	static const char suffix[] = "-launchagent";
	const char *label = kvm_service_label();
	size_t len = label != NULL ? strlen(label) : 0;
	int written;

	if (len > sizeof(suffix) - 1 && strcmp(label + len - (sizeof(suffix) - 1), suffix) == 0) { len -= sizeof(suffix) - 1; }
	written = len > 0 ? snprintf(buf, bufLen, "meshagent.kvm.%.*s.screen", (int)len, label) : snprintf(buf, bufLen, "meshagent.kvm.screen");
	return(written > 0 && (size_t)written < bufLen);
}

// The prompt, the silent check and the notification can all see the grant, and only the first may restart, or a second kickstart hits the new process
static void kvm_permission_granted(int onGrant)
{
	char name[200];

	if (!__sync_bool_compare_and_swap(&g_permissionGranted, 0, 1)) { return; }
	if (kvm_grant_name(name, sizeof(name))) { notify_post(name); }
	if (onGrant == KVM_PROMPT_RESTART) { kvm_restart_self(); }
	_exit(3);
}

static void* kvm_grant_listen_thread(void *arg)
{
	int fd = (int)(intptr_t)arg, token, now;
	time_t last = 0;

	while (read(fd, &token, sizeof(token)) == sizeof(token))
	{
		// Any process can post the name, so a post only starts a check, at most one every 5 s
		if (time(NULL) - last < 5) { continue; }
		last = time(NULL);
		if ((now = kvm_permissions_fresh()) >= 0 && (now & KVM_PERM_SCREEN)) { kvm_permission_granted(g_permissionOnGrant); }
	}
	return(NULL);
}

// Also runs after "Not now" and "Don't ask again", because that user's process needs the restart just as well
static void kvm_grant_listen_start(void)
{
	char name[200];
	int fd, token;
	pthread_t t;

	if (g_permissionOnGrant == 0 || (kvm_permissions() & KVM_PERM_SCREEN) || !kvm_grant_name(name, sizeof(name))) { return; }
	if (notify_register_file_descriptor(name, &fd, 0, &token) != NOTIFY_STATUS_OK) { return; }
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (pthread_create(&t, NULL, kvm_grant_listen_thread, (void*)(intptr_t)fd) == 0) { pthread_detach(t); }
	else { notify_cancel(token); }
}

// Checks every 5 s, at most "rounds" times, whether the grant is on
static int kvm_permission_poll(int bit, int rounds)
{
	int i, now;
	for (i = 0; i < rounds; ++i)
	{
		if ((now = kvm_permissions_fresh()) >= 0 && (now & bit)) { return(1); }
		sleep(5);
	}
	return(0);
}

// macOS shows its own Screen Recording and Accessibility requests in windows of this process, measured on macOS 15.8 and 26.7
#define KVM_REQUEST_OWNER CFSTR("universalAccessAuthWarn")
#define KVM_WINDOW_REQUEST 1
#define KVM_WINDOW_SETTINGS 2
#define KVM_WINDOW_MAX 16

static int kvm_path_ends_with(const char *path, const char *tail)
{
	size_t len = strlen(path), tailLen = strlen(tail);
	return(len >= tailLen && strcmp(path + len - tailLen, tail) == 0);
}

static int kvm_settings_path(const char *path)
{
	return(kvm_path_ends_with(path, "/System Settings.app/Contents/MacOS/System Settings"));
}

// Returns 1 when System Settings of this user started at or after "since", which is how macOS's request opens it
static int kvm_settings_started(time_t since)
{
	char path[PROC_PIDPATHINFO_MAXSIZE];
	struct proc_bsdinfo info;
	pid_t *pids;
	int i, count, found = 0;

	if ((count = proc_listallpids(NULL, 0)) <= 0 || (pids = (pid_t*)calloc((size_t)count + 16, sizeof(pid_t))) == NULL) { return(0); }
	count = proc_listallpids(pids, (int)((count + 16) * sizeof(pid_t)));
	for (i = 0; i < count && !found; ++i)
	{
		if (proc_pidpath(pids[i], path, sizeof(path)) <= 0 || !kvm_settings_path(path)) { continue; }
		found = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &info, sizeof(info)) == (int)sizeof(info) && info.pbi_uid == getuid() && (time_t)info.pbi_start_tvsec >= since;
	}
	free(pids);
	return(found);
}

static int kvm_window_is(CFDictionaryRef w, int kind)
{
	char path[PROC_PIDPATHINFO_MAXSIZE];
	CFStringRef owner;
	CFNumberRef pid;
	int p = 0;

	if (kind == KVM_WINDOW_REQUEST)
	{
		owner = (CFStringRef)CFDictionaryGetValue(w, kCGWindowOwnerName);
		return(owner != NULL && CFStringCompare(owner, KVM_REQUEST_OWNER, 0) == kCFCompareEqualTo);
	}

	// The owner name of Settings is translated, the path of its executable is not
	pid = (CFNumberRef)CFDictionaryGetValue(w, kCGWindowOwnerPID);
	if (pid == NULL || !CFNumberGetValue(pid, kCFNumberIntType, &p) || proc_pidpath(p, path, sizeof(path)) <= 0) { return(0); }
	return(kvm_settings_path(path));
}

// Writes the numbers of the windows of that kind on screen now and returns how many there are
static int kvm_windows(int kind, CGWindowID *ids, int max)
{
	CFArrayRef list = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements, kCGNullWindowID);
	CFIndex i;
	int count = 0;

	if (list == NULL) { return(0); }
	for (i = 0; i < CFArrayGetCount(list) && count < max; ++i)
	{
		CFDictionaryRef w = (CFDictionaryRef)CFArrayGetValueAtIndex(list, i);
		CFNumberRef number = (CFNumberRef)CFDictionaryGetValue(w, kCGWindowNumber);
		if (number != NULL && kvm_window_is(w, kind) && CFNumberGetValue(number, kCFNumberSInt32Type, &ids[count])) { ++count; }
	}
	CFRelease(list);
	return(count);
}

// Returns 1 when a window of that kind is on screen that is not in "before"
static int kvm_window_new(int kind, const CGWindowID *before, int beforeCount)
{
	CGWindowID now[KVM_WINDOW_MAX];
	int i, j, count = kvm_windows(kind, now, KVM_WINDOW_MAX);

	for (i = 0; i < count; ++i)
	{
		for (j = 0; j < beforeCount && before[j] != now[i]; ++j) { }
		if (j == beforeCount) { return(1); }
	}
	return(0);
}

// Looks for a window of that kind for appearChecks times 250 ms, then waits while it is open, at most 5 minutes. Returns 1 as soon as the grant is on.
// Only a request window that was not there before counts, because a Screen Recording request stays open after the grant until the asking process exits.
static int kvm_window_wait(int kind, int bit, const CGWindowID *before, int beforeCount, int appearChecks)
{
	int i, now, open = 0;

	for (i = 0; i < appearChecks && !open; ++i) { usleep(250000); open = kvm_window_new(kind, before, beforeCount); }
	for (i = 0; open && i < 600; ++i)
	{
		if (i % 10 == 0 && (now = kvm_permissions_fresh()) >= 0 && (now & bit)) { return(1); }
		usleep(500000);
		open = kvm_window_new(kind, before, beforeCount);
	}
	return((now = kvm_permissions_fresh()) >= 0 && (now & bit));
}

static int kvm_permission_wait(int bit, const char *name, const char *paneUrl, int admin);

// One permission: macOS's own request first, then a window of the agent only when macOS showed none or it was closed without the grant.
// After "Open System Settings" in macOS's request the agent's window would only repeat it, so it waits without a window while Settings is open.
// The agent's window stays on top of every other window, which is why it closes by itself after 15 s, followed by 5 minutes of checks.
// Returns 1 when granted, 0 after Skip or when the time is up.
static int kvm_permission_step(int bit, const char *name, const char *paneUrl, int admin)
{
	const void *axKeys[] = { kAXTrustedCheckOptionPrompt };
	const void *axValues[] = { kCFBooleanTrue };
	CFDictionaryRef axOptions;
	CGWindowID before[KVM_WINDOW_MAX];
	int beforeCount = kvm_windows(KVM_WINDOW_REQUEST, before, KVM_WINDOW_MAX);
	time_t started = time(NULL);

	if (bit == KVM_PERM_SCREEN)
	{
		CGRequestScreenCaptureAccess();
	}
	else if ((axOptions = CFDictionaryCreate(NULL, axKeys, axValues, 1, &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks)) != NULL)
	{
		AXIsProcessTrustedWithOptions(axOptions);
		CFRelease(axOptions);
	}
	// macOS needs a moment to show its request, and Settings a moment to open
	if (kvm_window_wait(KVM_WINDOW_REQUEST, bit, before, beforeCount, 8)) { return(1); }
	// Settings that the request just started gets 10 s instead of 3 s, because on a 2013 MacBook Air with macOS 15.8 its window was not there 4 s after the process started
	if (kvm_window_wait(KVM_WINDOW_SETTINGS, bit, NULL, 0, kvm_settings_started(started) ? 40 : 12)) { return(1); }
	return(kvm_permission_wait(bit, name, paneUrl, admin));
}

// The window of the agent for one permission, see kvm_permission_step()
static int kvm_permission_wait(int bit, const char *name, const char *paneUrl, int admin)
{
	CFStringRef header = CFStringCreateWithFormat(NULL, NULL, CFSTR("Turn on %s"), name);
	CFStringRef text = CFStringCreateWithFormat(NULL, NULL, CFSTR("In System Settings, Privacy & Security, %s, turn on \"%s\".%s This window closes after a few seconds, the agent notices the switch by itself.\n\n"
		      "If it is already on, remove it with the - button and add it again with +. A switch from an older version of the agent stays on in Settings but no longer counts."), name, kvm_program_name(),
		admin ? "" : " macOS then asks for an administrator's name and password.");
	const void *keys[] = { kCFUserNotificationAlertHeaderKey, kCFUserNotificationAlertMessageKey, kCFUserNotificationDefaultButtonTitleKey, kCFUserNotificationAlternateButtonTitleKey };
	const void *values[] = { header, text, CFSTR("Skip"), CFSTR("Open Settings") };
	CFDictionaryRef dict = (header != NULL && text != NULL) ? CFDictionaryCreate(NULL, keys, values, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) : NULL;
	CFUserNotificationRef note = NULL;
	CFOptionFlags response = 0;
	int i, now, answered = 0, skipped;
	int granted = 0;

	if (dict != NULL) { note = CFUserNotificationCreate(NULL, 0, kCFUserNotificationNoteAlertLevel, NULL, dict); }
	for (i = 0; i < 3 && note != NULL && !granted && !answered; ++i)
	{
		if ((now = kvm_permissions_fresh()) >= 0 && (now & bit)) { granted = 1; }
		else { answered = (CFUserNotificationReceiveResponse(note, 5, &response) == 0); }
	}
	if (note != NULL)
	{
		if (!answered) { CFUserNotificationCancel(note); }
		CFRelease(note);
	}
	if (dict != NULL) { CFRelease(dict); }
	if (text != NULL) { CFRelease(text); }
	if (header != NULL) { CFRelease(header); }

	skipped = answered && (response & 0x3) != kCFUserNotificationAlternateResponse;
	if (answered && !skipped) { kvm_open_pane(paneUrl); }
	if (!granted && !skipped) { granted = kvm_permission_poll(bit, 60); }
	return(granted);
}

// The grants are machine-wide, so a standard user can only turn the switches on with an administrator's name and password.
// When the membership cannot be read, the user counts as an administrator, which is how the prompt behaved before.
static int kvm_user_is_admin(void)
{
	struct group entry, *admin = NULL;
	char buf[4096];
	uuid_t user, group;
	int member = 0;

	if (getgrnam_r("admin", &entry, buf, sizeof(buf), &admin) != 0 || admin == NULL) { return(1); }
	if (mbr_uid_to_uuid(getuid(), user) != 0 || mbr_gid_to_uuid(admin->gr_gid, group) != 0) { return(1); }
	if (mbr_check_membership(user, group, &member) != 0) { return(1); }
	return(member != 0);
}

// The restart after the Screen Recording grant leaves this marker in the user's temporary folder, so the new process goes on with Accessibility without the first dialog
static int kvm_resume_path(char *buf, size_t bufLen)
{
	const char *label = kvm_service_label();
	size_t len = confstr(_CS_DARWIN_USER_TEMP_DIR, buf, bufLen);
	if (len == 0 || len > bufLen) { return(0); }
	return(strlcat(buf, "meshagent-kvm-", bufLen) < bufLen && strlcat(buf, label != NULL && strchr(label, '/') == NULL ? label : "default", bufLen) < bufLen && strlcat(buf, ".resume", bufLen) < bufLen);
}

static void kvm_resume_mark(void)
{
	char path[PATH_MAX];
	int fd;
	if (kvm_resume_path(path, sizeof(path)) && (fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600)) >= 0) { close(fd); }
}

// Removes the marker and returns 1 when it was left less than 2 minutes ago
static int kvm_resume_take(void)
{
	char path[PATH_MAX];
	struct stat st;
	int fresh;
	if (!kvm_resume_path(path, sizeof(path)) || lstat(path, &st) != 0) { return(0); }
	fresh = S_ISREG(st.st_mode) && st.st_uid == getuid() && time(NULL) - st.st_mtime < 120;
	unlink(path);
	return(fresh);
}

// The first dialog. Returns 1 after Continue.
static int kvm_permission_intro(int admin)
{
	CFOptionFlags response = kCFUserNotificationCancelResponse;
	CFStringRef message = CFStringCreateWithFormat(NULL, NULL,
		CFSTR("To show this screen and use mouse and keyboard in a remote session, macOS needs you to allow \"%s\" under Screen Recording and Accessibility.\n\n"
		      "%sAfter Continue, macOS asks for each permission in turn, and the agent restarts once after Screen Recording. If macOS does not ask, a window shows which switch to turn on."),
		kvm_program_name(), admin ? "" : "Turning these on needs an administrator's name and password. ");
	if (message == NULL) { return(0); }

	// "Don't ask again" holds for every user, so a standard user, who cannot grant anything, does not get it
	CFUserNotificationDisplayAlert(300, kCFUserNotificationNoteAlertLevel, NULL, NULL, NULL,
		CFSTR("Remote desktop needs your permission"), message,
		CFSTR("Continue"), CFSTR("Not now"), admin ? CFSTR("Don't ask again") : NULL, &response);
	CFRelease(message);
	response &= 0x3;

	if (response == kCFUserNotificationOtherResponse) { kvm_pref_flag("noPermissionPrompt", 1); }
	return(response == kCFUserNotificationDefaultResponse);
}

// Returns 0 while another user's session is on the screen, and 1 without a window server session, as before
static int kvm_session_on_console(void)
{
	CFDictionaryRef session = CGSessionCopyCurrentDictionary();
	CFTypeRef onConsole;
	int ret = 1;

	if (session == NULL) { return(1); }
	onConsole = CFDictionaryGetValue(session, kCGSessionOnConsoleKey);
	if (onConsole != NULL && CFGetTypeID(onConsole) == CFBooleanGetTypeID()) { ret = CFBooleanGetValue((CFBooleanRef)onConsole); }
	CFRelease(session);
	return(ret);
}

static void* kvm_permission_thread(void *arg)
{
	int onGrant = (int)(intptr_t)arg;
	int had = kvm_permissions();
	int now, have = had;
	int admin, resume = kvm_resume_take();

	if (had == (KVM_PERM_SCREEN | KVM_PERM_INPUT) || kvm_pref_flag("noPermissionPrompt", 0)) { return(NULL); }
	admin = kvm_user_is_admin();
	if (!resume)
	{
		// A user who is logged in behind another one would find the dialog later, often after the user at the screen turned both switches on, so it waits for this session to be on the screen.
		// The grants are machine-wide, so they are read again after the wait. A Screen Recording grant made meanwhile needs the restart.
		while (!kvm_session_on_console()) { sleep(2); }
		if ((now = kvm_permissions_fresh()) >= 0)
		{
			if ((now & KVM_PERM_SCREEN) && !(had & KVM_PERM_SCREEN)) { kvm_permission_granted(onGrant); return(NULL); }
			if (now == (KVM_PERM_SCREEN | KVM_PERM_INPUT)) { return(NULL); }
			have = now;
		}
		if (kvm_pref_flag("noPermissionPrompt", 0) || !kvm_permission_intro(admin)) { return(NULL); }
	}

	// One permission at a time, so macOS's own request and the window of the agent never pile up.
	// A new Screen Recording grant only works in a new process, and the restart also closes macOS's request, which stays open until this process exits.
	if (!(had & KVM_PERM_SCREEN) && kvm_permission_step(KVM_PERM_SCREEN, "Screen Recording", "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture", admin))
	{
		if ((now = kvm_permissions_fresh()) >= 0 && !(now & KVM_PERM_INPUT)) { kvm_resume_mark(); }
		kvm_permission_granted(onGrant);
		return(NULL);
	}
	if ((now = kvm_permissions_fresh()) >= 0) { have = now; }
	if (!(have & KVM_PERM_INPUT))
	{
		kvm_permission_step(KVM_PERM_INPUT, "Accessibility", "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility", admin);
	}

	// Screen Recording can also be turned on during the Accessibility step
	if (!(had & KVM_PERM_SCREEN) && (now = kvm_permissions_fresh()) >= 0 && (now & KVM_PERM_SCREEN)) { kvm_permission_granted(onGrant); }
	return(NULL);
}

void kvm_permission_prompt_start(int onGrant)
{
	pthread_t t;
	g_permissionOnGrant = onGrant;
	kvm_grant_listen_start();
	if (pthread_create(&t, NULL, kvm_permission_thread, (void*)(intptr_t)onGrant) == 0) { pthread_detach(t); }
}

static void* kvm_permission_watch_thread(void *arg)
{
	if (kvm_permission_poll(KVM_PERM_SCREEN, 60)) { kvm_permission_granted((int)(intptr_t)arg); }
	__sync_lock_release(&g_permissionWatching);
	return(NULL);
}

// A session's capture can make macOS ask for Screen Recording by itself, also after "Not now" or "Don't ask again".
// That grant needs a new process as well, so a session without Screen Recording checks for it for 5 minutes, without any window.
static void kvm_permission_watch_start(void)
{
	pthread_t t;
	if (g_permissionOnGrant == 0 || (kvm_permissions() & KVM_PERM_SCREEN)) { return; }
	if (!__sync_bool_compare_and_swap(&g_permissionWatching, 0, 1)) { return; }
	if (pthread_create(&t, NULL, kvm_permission_watch_thread, (void*)(intptr_t)g_permissionOnGrant) == 0) { pthread_detach(t); }
	else { __sync_lock_release(&g_permissionWatching); }
}
