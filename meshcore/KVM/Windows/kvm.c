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

#if defined(_LINKVM)
#pragma warning(disable: 4996)

#include <stdio.h>
#include "kvm.h"
#include "tile.h"
#include <signal.h>
#include "input.h"
#include <Winuser.h>

#include "meshcore/meshdefines.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibAsyncSocket.h"
#include "microstack/ILibProcessPipe.h"
#include "microstack/ILibRemoteLogging.h"
#include <sas.h>

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

extern void KVM_WriteLog(ILibKVM_WriteHandler writeHandler, void *user, char *format, ...);

//#define KVMDEBUGENABLED 1
ILibProcessPipe_SpawnTypes gProcessSpawnType = ILibProcessPipe_SpawnTypes_USER;
int gProcessTSID = -1;
extern int gRemoteMouseRenderDefault;
int gRemoteMouseMoved = 0;
extern int gCurrentCursor;

#pragma pack(push, 1)
typedef struct KVMDebugLog
{
	unsigned short length;
	unsigned short logType;
	unsigned short logFlags;
	char logData[];
}KVMDebugLog;
#pragma pack(pop)


#ifdef KVMDEBUGENABLED
void KvmCriticalLog(const char* msg, const char* file, int line, int user1, int user2)
{
	int len;
	HANDLE h;
	int DontDestroy = 0;
	h = OpenMutex(MUTEX_ALL_ACCESS, FALSE, TEXT("MeshAgentKvmLogLock"));
	if (h == NULL)
	{
		if (GetLastError() != ERROR_FILE_NOT_FOUND) return;
		if ((h = CreateMutex(NULL, TRUE, TEXT("MeshAgentKvmLogLock"))) == NULL) return;
		DontDestroy = 1;
	}
	else
	{
		WaitForSingleObject(h, INFINITE);
	}
	len = sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "\r\n%s:%d (%d,%d) %s", file, line, user1, user2, msg);
	if (len > 0 && len < (int)sizeof(ILibScratchPad)) ILibAppendStringToDiskEx("C:\\Temp\\MeshAgentKvm.log", ILibScratchPad, len);
	ReleaseMutex(h);
	if (DontDestroy == 0) CloseHandle(h);
}
#define KVMDEBUG(m,u) { KvmCriticalLog(m, __FILE__, __LINE__, u, GetLastError()); printf("KVMMSG: %s (%d,%d).\r\n", m, (int)u, (int)GetLastError()); }
#define KVMDEBUG2 ILIBLOGMESSAGEX
#else
#define KVMDEBUG(m, u)
#define KVMDEBUG2(...) 
#endif

int TILE_WIDTH = 0;
int TILE_HEIGHT = 0;
int SCREEN_COUNT = -1;			// Total number of displays
int SCREEN_SEL = 0;				// Currently selected display (0 = all)
int SCREEN_SEL_TARGET = 0;		// Desired selected display (0 = all)
int SCREEN_SEL_PROCESS = 0;		// In process of changing displays (0 = all)
int SCREEN_X = 0;				// Left most of current screen
int SCREEN_Y = 0;				// Top most of current screen
int SCREEN_WIDTH = 0;			// Width of current screen
int SCREEN_HEIGHT = 0;			// Height of current screen
int VSCREEN_X = 0;				// Left most of virtual screen
int VSCREEN_Y = 0;				// Top most of virtual screen
int VSCREEN_WIDTH = 0;			// Width of virtual screen
int VSCREEN_HEIGHT = 0;			// Height of virtual screen
int SCALED_WIDTH = 0;
int SCALED_HEIGHT = 0;
int PIXEL_SIZE = 0;
int TILE_WIDTH_COUNT = 0;
int TILE_HEIGHT_COUNT = 0;
int COMPRESSION_RATIO = 0;
int SCALING_FACTOR = 1024;		// Scaling factor, 1024 = 100%
int SCALING_FACTOR_NEW = 1024;	// Desired scaling factor, 1024 = 100%
int FRAME_RATE_TIMER = 0;
HANDLE kvmthread = NULL;
int g_shutdown = 999;
int g_desktop_switch_pending = 0;
int g_pause = 0;
int g_remotepause = 1;
int g_restartcount = 0;
struct tileInfo_t **tileInfo = NULL;
int g_slavekvm = 0;
static ILibProcessPipe_Process gChildProcess;
int kvm_relay_restart(int paused, void *pipeMgr, char *exePath, ILibKVM_WriteHandler writeHandler, void *reserved);

HANDLE hStdOut = INVALID_HANDLE_VALUE;
HANDLE hStdIn = INVALID_HANDLE_VALUE;
int ThreadRunning = 0;
int kvmConsoleMode = 0;

ILibQueue gPendingPackets = NULL;

ILibRemoteLogging gKVMRemoteLogging = NULL;
#ifdef _WINSERVICE
void kvm_slave_OnRawForwardLog(ILibRemoteLogging sender, ILibRemoteLogging_Modules module, ILibRemoteLogging_Flags flags, char *buffer, int bufferLen)
{
	if (flags <= ILibRemoteLogging_Flags_VerbosityLevel_1)
	{
		KVMDebugLog *log = (KVMDebugLog*)buffer;
		log->length = bufferLen + 1;
		log->logType = (unsigned short)module;
		log->logFlags = (unsigned short)flags;
		buffer[bufferLen] = 0;

		WriteFile(GetStdHandle(STD_ERROR_HANDLE), buffer, log->length, &bufferLen, NULL);
	}
}
#endif

void kvm_setupSasPermissions()
{
	DWORD dw = 3;
	HKEY key = NULL;

	KVMDEBUG("kvm_setupSasPermissions", 0);

    // SoftwareSASGeneration
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_ALL_ACCESS, &key) == ERROR_SUCCESS)
	{
		RegSetValueEx(key, "SoftwareSASGeneration", 0, REG_DWORD, (BYTE*)&dw, 4);
		RegCloseKey(key);
	}
}

// Emulate the CTRL-ALT-DEL (Should work on WinXP, not on Vista & Win7)
DWORD WINAPI kvm_ctrlaltdel(LPVOID Param)
{
	UNREFERENCED_PARAMETER( Param );
	KVMDEBUG("kvm_ctrlaltdel", (int)(uintptr_t)Param);
	typedef VOID(WINAPI *SendSas)(BOOL asUser);
	SendSas sas;

	// Perform new method (Vista & Win7)
	HMODULE m = LoadLibraryExA("sas.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);

	// We need to dynamically load this, becuase it doesn't exist on Windows Core.
	// However, LOAD_LIBRARY_SEARCH_SYSTEM32 does not exist on Windows 7 SP1 / Windows Server 2008 R2 without a MSFT Patch,
	// but this patch is no longer available from MSFT, so this fallback case will only affect insecure versions of Windows 7 SP1 / Server 2008 R2
	if (m == NULL && GetLastError() == ERROR_INVALID_PARAMETER) { m = LoadLibraryA("sas.dll"); }	
	if (m != NULL)
	{
		sas = (SendSas)GetProcAddress(m, "SendSAS");
		if (sas != NULL)
		{
			kvm_setupSasPermissions();
			sas(FALSE);
		}
		FreeLibrary(m);
	}
	return 0;
}

BOOL CALLBACK DisplayInfoEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData)
{
	int w, h, deviceid = 0;
    MONITORINFOEX mi;
	DWORD *selection = (DWORD*)dwData;
	UNREFERENCED_PARAMETER( hdcMonitor );
	UNREFERENCED_PARAMETER( lprcMonitor );

	ZeroMemory(&mi, sizeof(mi));
    mi.cbSize = sizeof(mi);

	// Get the display information
    if (!GetMonitorInfo(hMonitor, (LPMONITORINFO)&mi)) return TRUE;
	if (sscanf_s(mi.szDevice, "\\\\.\\DISPLAY%d", &deviceid) != 1) return TRUE;
	if (--selection[0] > 0) { return TRUE; }
	
	// See if anything changed
	w = abs(mi.rcMonitor.left - mi.rcMonitor.right);
	h = abs(mi.rcMonitor.top - mi.rcMonitor.bottom);
	if (SCREEN_X != mi.rcMonitor.left || SCREEN_Y !=  mi.rcMonitor.top || SCREEN_WIDTH != w || SCREEN_HEIGHT != h || SCALING_FACTOR != SCALING_FACTOR_NEW)
	{
		SCREEN_X = mi.rcMonitor.left;
		SCREEN_Y = mi.rcMonitor.top;
		SCREEN_WIDTH = w;
		SCREEN_HEIGHT = h;
		SCREEN_SEL_PROCESS |= 1;	// Force the new resolution to be sent to the client.
	}

	if (SCREEN_SEL != SCREEN_SEL_TARGET)
	{
		SCREEN_SEL = SCREEN_SEL_TARGET;
		SCREEN_SEL_PROCESS |= 2;	// Force the display list to be sent to the client, includes the new display selection
	}
   
    return TRUE;
}

BOOL CALLBACK DisplayInfoEnumProc_Info(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData)
{
	unsigned short* buffer = (unsigned short*)dwData;
	MONITORINFOEX mi;
	UNREFERENCED_PARAMETER(hdcMonitor);
	UNREFERENCED_PARAMETER(lprcMonitor);

	ZeroMemory(&mi, sizeof(mi));
	mi.cbSize = sizeof(mi);

	// Get the display information
	if (!GetMonitorInfo(hMonitor, (LPMONITORINFO)&mi)) return TRUE;
	int w = abs(mi.rcMonitor.left - mi.rcMonitor.right);
	int h = abs(mi.rcMonitor.top - mi.rcMonitor.bottom);

	int i = (int)(buffer[0]++);
	int offset = (5 * i) + 4;

	if ((((i + 1) * 10) + 4) > buffer[1]) { return(FALSE); }

	buffer[offset] = (unsigned short)htons((unsigned short)(i+1));						// ID
	buffer[offset+1] = (unsigned short)htons((unsigned short)(mi.rcMonitor.left));		// X
	buffer[offset+2] = (unsigned short)htons((unsigned short)(mi.rcMonitor.top));		// Y
	buffer[offset+3] = (unsigned short)htons((unsigned short)(w));						// WIDTH
	buffer[offset+4] = (unsigned short)htons((unsigned short)(h));						// HEIGHT
	return(TRUE);
}
void kvm_send_display_list(ILibKVM_WriteHandler writeHandler, void *reserved)
{
	int i;
	char dwData[4096];
	((unsigned short*)dwData)[0] = (unsigned short)0;
	((unsigned short*)dwData)[1] = (unsigned short)sizeof(dwData);
	((unsigned short*)dwData)[2] = (unsigned short)htons((unsigned short)MNG_KVM_DISPLAY_INFO);			// Write the type
	if (EnumDisplayMonitors(NULL, NULL, DisplayInfoEnumProc_Info, (LPARAM)dwData))
	{
		((unsigned short*)dwData)[3] = (unsigned short)htons((((unsigned short*)dwData)[0]) * 10 + 4);	// Length
		writeHandler(dwData+4, (((unsigned short*)dwData)[0]) * 10 + 4, reserved);
	}

	// Not looked at the number of screens yet
	if (SCREEN_COUNT == -1) return;
	char *buffer = ILibMemory_AllocateA((5 + SCREEN_COUNT) * 2);
	memset(buffer, 0xFF, ILibMemory_AllocateA_Size(buffer));
	// Send the list of possible displays to remote
	if (SCREEN_COUNT == 0 || SCREEN_COUNT == 1)
	{
		// Only one display, send empty
		((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_GET_DISPLAYS);		// Write the type
		((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)(8));						// Write the size
		((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)(0));						// Screen Count
		((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)(0));						// Selected Screen

		writeHandler(buffer, 8, reserved);
	}
	else
	{
		// Many displays
		((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_GET_DISPLAYS);		// Write the type
		((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)(10 + (2 * SCREEN_COUNT)));	// Write the size
		((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)(SCREEN_COUNT + 1));			// Screen Count
		((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)(-1));						// Possible Screen (ALL)
		for (i = 0; i < SCREEN_COUNT; i++) {
			((unsigned short*)buffer)[4 + i] = (unsigned short)htons((unsigned short)(i + 1));				// Possible Screen
		}
		if (SCREEN_SEL == 0) {
			((unsigned short*)buffer)[4 + i] = (unsigned short)htons((unsigned short)(-1));				// Selected Screen (All)
		} else {
			((unsigned short*)buffer)[4 + i] = (unsigned short)htons((unsigned short)(SCREEN_SEL));		// Selected Screen
		}

		writeHandler(buffer, (10 + (2 * SCREEN_COUNT)), reserved);
	}
}

void kvm_server_SetResolution();
int kvm_server_currentDesktopname = 0;
void CheckDesktopSwitch(int checkres, ILibKVM_WriteHandler writeHandler, void *reserved)
{
	int x, y, w, h;
	HDESK desktop;
	HDESK desktop2;
	char name[64];

	// KVMDEBUG("CheckDesktopSwitch", checkres);

	// Check desktop switch
	if ((desktop2 = GetThreadDesktop(GetCurrentThreadId())) == NULL) { KVMDEBUG("GetThreadDesktop Error", 0); } // CloseDesktop() is not needed
	if ((desktop = OpenInputDesktop(0, TRUE,
                        DESKTOP_CREATEMENU |
                        DESKTOP_CREATEWINDOW |
                        DESKTOP_ENUMERATE |
                        DESKTOP_HOOKCONTROL |
                        DESKTOP_WRITEOBJECTS |
                        DESKTOP_READOBJECTS |
                        DESKTOP_SWITCHDESKTOP |
                        GENERIC_WRITE)) == NULL) { KVMDEBUG("OpenInputDesktop Error", 0); }

	if (SetThreadDesktop(desktop) == 0)
	{
		if (CloseDesktop(desktop) == 0) { KVMDEBUG("CloseDesktop1 Error", 0); }
		desktop = desktop2;
	} else {
		CloseDesktop(desktop2);
	}

	// Check desktop name switch
	if (GetUserObjectInformationA(desktop, UOI_NAME, name, 63, 0))
	{
		//ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: name = %s", name);

		// KVMDEBUG(name, 0);
		if (kvm_server_currentDesktopname == 0)
		{
			// This is the first time we come here.
			kvm_server_currentDesktopname = ((int*)name)[0];
		}
		else
		{
			// If the desktop name has changed, shutdown.
			if (kvm_server_currentDesktopname != ((int*)name)[0])
			{
				KVMDEBUG("DESKTOP NAME CHANGE DETECTED, triggering shutdown", 0);
				ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: kvm_server_currentDesktop: NAME CHANGE DETECTED...");
				g_desktop_switch_pending = 1;
			}
		}
	}
	else
	{
		KVMDEBUG("GetUserObjectInformation Error", 0);
	}

	// See if the number of displays has changed
	x = GetSystemMetrics(SM_CMONITORS);
	if (SCREEN_COUNT != x) { SCREEN_COUNT = x; kvm_send_display_list(writeHandler, reserved); }

	// Check resolution change
	if (checkres != 0 && g_shutdown == 0)
	{
		VSCREEN_X = GetSystemMetrics(SM_XVIRTUALSCREEN);
		VSCREEN_Y = GetSystemMetrics(SM_YVIRTUALSCREEN);
		VSCREEN_WIDTH = GetSystemMetrics(SM_CXVIRTUALSCREEN);
		VSCREEN_HEIGHT = GetSystemMetrics(SM_CYVIRTUALSCREEN);

		if (SCREEN_SEL_TARGET == 0)
		{
			if (VSCREEN_WIDTH == 0)
			{
				// Old style, one display only. Added this just in case VIRTUALSCREEN does not work.
				x = 0;
				y = 0;
				w = GetSystemMetrics(SM_CXSCREEN);
				h = GetSystemMetrics(SM_CYSCREEN);
			} else {
				// New style, entire virtual desktop
				x = VSCREEN_X;
				y = VSCREEN_Y;
				w = VSCREEN_WIDTH;
				h = VSCREEN_HEIGHT;
			}

			if (SCREEN_X != x || SCREEN_Y != y || SCREEN_WIDTH != w || SCREEN_HEIGHT != h || SCALING_FACTOR != SCALING_FACTOR_NEW)
			{
				//printf("RESOLUTION CHANGED! (supposedly)\n");
				SCREEN_X = x;
				SCREEN_Y = y;
				SCREEN_WIDTH = w;
				SCREEN_HEIGHT = h;
				kvm_server_SetResolution(writeHandler, reserved);
			}

			if (SCREEN_SEL_TARGET != SCREEN_SEL) { SCREEN_SEL = SCREEN_SEL_TARGET; kvm_send_display_list(writeHandler, reserved); }
		}
		else
		{
			// Get the list of monitors
			if (SCREEN_SEL_PROCESS == 0)
			{
				DWORD selection = SCREEN_SEL_TARGET;
				if (EnumDisplayMonitors(NULL, NULL, DisplayInfoEnumProc, (LPARAM)&selection))
				{
					// Set the resolution
					if (SCREEN_SEL_PROCESS & 1) kvm_server_SetResolution(writeHandler, reserved);
					if (SCREEN_SEL_PROCESS & 2) kvm_send_display_list(writeHandler, reserved);
				}
				SCREEN_SEL_PROCESS = 0;
			}
		}
	}
}

unsigned char g_blockinput = 0;

// Feed network data into the KVM. Return the number of bytes consumed.
// This method consumes a single command.
int kvm_server_inputdata(char* block, int blocklen, ILibKVM_WriteHandler writeHandler, void *reserved)
{
	unsigned short type, size;

	// Decode the block header
	if (blocklen < 4) return 0;

	ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_2, "KVM [SLAVE]: Handle Input [Len = %d]", blocklen);
	// KVMDEBUG("kvm_server_inputdata", blocklen);
	CheckDesktopSwitch(0, writeHandler, reserved);

	type = ntohs(((unsigned short*)(block))[0]);
	size = ntohs(((unsigned short*)(block))[1]);

	ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_2, "KVM [SLAVE]: Handle Input [Len = %d, type = %u, size = %u]", blocklen, type, size);

	if (size > blocklen) return 0;

	//printf("INPUT: %d, %d\r\n", type, size);

	switch (type)
	{
	case MNG_KVM_INPUT_LOCK:
		// 0 = unlock
		// 1 = lock
		// 2 = query
		if (size == 5)
		{
			switch (block[4])
			{
				case 0:
					g_blockinput = 0;
					BlockInput(0);
					break;
				case 1:
					g_blockinput = 1;
					BlockInput(1);
					break;
				case 2:
					break;
				default:
					return(size);
					break;
			}

			unsigned char buffer[5];
			((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_INPUT_LOCK);	// Write the type
			((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);					// Write the size
			buffer[4] = g_blockinput;																	// status

			writeHandler((char*)buffer, 5, reserved);
		}
		
		break;
	case MNG_KVM_KEY: // Key
		{
			if (size != 6) break;
			//KVM_WriteLog(writeHandler, reserved, "Key[%u] UP: %d", (unsigned char)(block[5]), block[4]);
			KeyAction(block[5], block[4]);
			break;
		}
	case MNG_KVM_KEY_UNICODE: // Unicode key
		{
			if (size != 7) break;
			//KVM_WriteLog(writeHandler, reserved, "UnicodeKey[%u] UP: %d", ((((unsigned char)block[5]) << 8) + ((unsigned char)block[6])), block[4]);
			KeyActionUnicode(((((unsigned char)block[5]) << 8) + ((unsigned char)block[6])), block[4]);
			break;
		}
	case MNG_KVM_MOUSE: // Mouse
		{
			double x, y;
			short w = 0;
			KVM_MouseCursors curcursor = KVM_MouseCursor_NOCHANGE;

			if (size == 10 || size == 12)
			{
				gRemoteMouseMoved = 1;

				// Get positions and scale correctly
				x = (double)ntohs(((short*)(block))[3]) * 1024 / SCALING_FACTOR;
				y = (double)ntohs(((short*)(block))[4]) * 1024 / SCALING_FACTOR;

				// Add relative display position
				x += fabs((double)(SCREEN_X - VSCREEN_X));
				y += fabs((double)(SCREEN_Y - VSCREEN_Y));

				// Scale back to the virtual screen
				x = (x * ((double)SCREEN_WIDTH / (double)VSCREEN_WIDTH)) * (double)65535;
				y = (y * ((double)SCREEN_HEIGHT / (double)VSCREEN_HEIGHT)) * (double)65535;

				// Perform the mouse movement
				if (size == 12) w = ((short)ntohs(((short*)(block))[5]));
				MouseAction((((double)x / (double)SCREEN_WIDTH)), (((double)y / (double)SCREEN_HEIGHT)), (int)(unsigned char)(block[5]), w);				
			}
			break;
		}
	case MNG_KVM_COMPRESSION: // Compression
		{
			if (size >= 10) { int fr = ((int)ntohs(((unsigned short*)(block + 8))[0])); if (fr >= 20 && fr <= 5000) FRAME_RATE_TIMER = fr; }
			if (size >=  8) { int ns = ((int)ntohs(((unsigned short*)(block + 6))[0])); if (ns >= 64 && ns <= 4096) SCALING_FACTOR_NEW = ns; }
			if (size >=  6) { set_tile_compression((int)block[4], (int)block[5]); }
			COMPRESSION_RATIO = 100;
			break;
		}
	case MNG_KVM_REFRESH: // Refresh
		{
			int row, col;
			char buffer[8];
			if (size != 4) break;

			((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SCREEN);	// Write the type
			((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
			((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)SCALED_WIDTH);		// X position
			((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)SCALED_HEIGHT);	// Y position

			writeHandler((char*)buffer, 8, reserved);

			// Send the list of available displays
			kvm_send_display_list(writeHandler, reserved);

			// Reset all tile information
			if (tileInfo == NULL) {
				if ((tileInfo = (struct tileInfo_t **) malloc(TILE_HEIGHT_COUNT * sizeof(struct tileInfo_t *))) == NULL) ILIBCRITICALEXIT(254);
				for (row = 0; row < TILE_HEIGHT_COUNT; row++) { if ((tileInfo[row] = (struct tileInfo_t *)malloc(TILE_WIDTH_COUNT * sizeof(struct tileInfo_t))) == NULL) ILIBCRITICALEXIT(254); }
			}
			for (row = 0; row < TILE_HEIGHT_COUNT; row++) { for (col = 0; col < TILE_WIDTH_COUNT; col++) { tileInfo[row][col].crc = 0xFF; tileInfo[row][col].flags = 0; } }

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
			int fr = ((int)ntohs(((unsigned short*)(block))[2]));
			if (fr >= 20 && fr <= 5000) FRAME_RATE_TIMER = fr;
			break;
		}
	case MNG_KVM_INIT_TOUCH:
		{
			// Attempt to initialized touch support
			char buffer[6];
			unsigned short r = (unsigned short)TouchInit();
			((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_INIT_TOUCH);	// Write the type
			((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)6);					// Write the size
			((unsigned short*)buffer)[2] = (unsigned short)htons(r);									// Write the return code

			writeHandler((char*)buffer, 6, reserved);
			break;
		}
	case MNG_KVM_TOUCH:
		{
			int r = 0;

			if (block[4] == 1) // Version 1 touch structure (Very simple)
			{
				unsigned int flags = (unsigned int)ntohl(((unsigned int*)(block + 6))[0]);

				// Get positions and scale correctly
				unsigned short x = (unsigned short)(ntohs(((unsigned short*)(block + 10))[0])) * 1024 / (unsigned short)SCALING_FACTOR;
				unsigned short y = (unsigned short)(ntohs(((unsigned short*)(block + 12))[0])) * 1024 / (unsigned short)SCALING_FACTOR;

				// Add relative display position
				x += (unsigned short)fabs((double)(SCREEN_X - VSCREEN_X));
				y += (unsigned short)fabs((double)(SCREEN_Y - VSCREEN_Y));

				// Scale back to the virtual screen
				x = (unsigned short)(((double)x * ((double)SCREEN_WIDTH / (double)VSCREEN_WIDTH)) * (double)65535);
				y = (unsigned short)(((double)y * ((double)SCREEN_HEIGHT / (double)VSCREEN_HEIGHT)) * (double)65535);

				r = TouchAction1(block[5], flags, x, y);
			}
			else if (block[4] == 2) // Version 2 touch structure array
			{
				r = TouchAction2(block + 5, size - 5, SCALING_FACTOR);
			}

			if (r == 1) {
				// Reset touch
				char buffer[4];
				((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_TOUCH); // Write the type
				((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)4);			 // Write the size

				writeHandler((char*)buffer, 4, reserved);
			}
			break;
		}
	case MNG_KVM_GET_DISPLAYS:
		{
			kvm_send_display_list(writeHandler, reserved);
			break;
		}
	case MNG_KVM_SET_DISPLAY:
		{
			// Set the display
			int x = 0;
			if (size < 6) break;
			x = (unsigned short)ntohs(((unsigned short*)(block + 4))[0]);
			if (x == 65535) SCREEN_SEL_TARGET = 0; else SCREEN_SEL_TARGET = x;
			break;
		}
	}
	return size;
}

typedef struct kvm_data_handler
{
	ILibKVM_WriteHandler handler;
	void *reserved;
	int len;
	char buffer[];
}kvm_data_handler;



// Feed network data into the KVM. Return the number of bytes consumed.
// This method consumes as many input commands as it can.
int kvm_relay_feeddata(char* buf, int len, ILibKVM_WriteHandler writeHandler, void *reserved)
{
	if (gChildProcess != NULL)
	{
		if (len >= 2 && ntohs(((unsigned short*)buf)[0]) == MNG_CTRLALTDEL)
		{
			HANDLE ht = CreateThread(NULL, 0, kvm_ctrlaltdel, 0, 0, 0);
			if (ht != NULL) CloseHandle(ht);
		}
		ILibProcessPipe_Process_WriteStdIn(gChildProcess, buf, len, ILibTransport_MemoryOwnership_USER);
		ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_2, "KVM [Master]: Write Input [Type = %u]", ntohs(((unsigned short*)buf)[0]));
		return len;
	}
	else
	{
		int len2 = 0;
		int ptr = 0;
		//while ((len2 = kvm_server_inputdata(buf + ptr, len - ptr, kvm_relay_feeddata_ex, (void*[]) {writeHandler, reserved})) != 0) { ptr += len2; }
		while ((len2 = kvm_server_inputdata(buf + ptr, len - ptr, writeHandler, reserved)) != 0) { ptr += len2; }
		return ptr;
	}
}

// Set the KVM pause state
void kvm_pause(int pause)
{
	// KVMDEBUG("kvm_pause", pause);
	if (gChildProcess == NULL)
	{
		g_pause = pause;
	}
	else
	{
		if (pause == 0)
		{
			KVMDEBUG2("RESUME: KVM");
			ILibProcessPipe_Pipe_Resume(ILibProcessPipe_Process_GetStdOut(gChildProcess));
		}
		else
		{
			KVMDEBUG2("PAUSE: KVM");
			ILibProcessPipe_Pipe_Pause(ILibProcessPipe_Process_GetStdOut(gChildProcess));
		}
	}
}

void kvm_server_SetResolution(ILibKVM_WriteHandler writeHandler, void *reserved)
{
	char buffer[8];
	int row, col;

	KVMDEBUG("kvm_server_SetResolution", 0);

	// Free the tileInfo before you manipulate the TILE_HEIGHT_COUNT
	if (tileInfo != NULL) { for (row = 0; row < TILE_HEIGHT_COUNT; row++) { free(tileInfo[row]); } free(tileInfo); tileInfo = NULL; }

	// Setup scaling
	SCALING_FACTOR = SCALING_FACTOR_NEW;
	SCALED_WIDTH = (SCREEN_WIDTH * SCALING_FACTOR) / 1024;
	SCALED_HEIGHT = (SCREEN_HEIGHT * SCALING_FACTOR) / 1024;

	// Compute the tile count
	TILE_WIDTH_COUNT = SCALED_WIDTH / TILE_WIDTH;
	TILE_HEIGHT_COUNT = SCALED_HEIGHT / TILE_HEIGHT;
	if (SCALED_WIDTH % TILE_WIDTH) TILE_WIDTH_COUNT++;
	if (SCALED_HEIGHT % TILE_HEIGHT) TILE_HEIGHT_COUNT++;

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SCREEN);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
	((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)SCALED_WIDTH);		// X position
	((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)SCALED_HEIGHT);	// Y position

	writeHandler((char*)buffer, 8, reserved);

	if ((tileInfo = (struct tileInfo_t **)malloc(TILE_HEIGHT_COUNT * sizeof(struct tileInfo_t *))) == NULL) ILIBCRITICALEXIT(254);
	for (row = 0; row < TILE_HEIGHT_COUNT; row++) {
		if ((tileInfo[row] = (struct tileInfo_t *)malloc(TILE_WIDTH_COUNT * sizeof(struct tileInfo_t))) == NULL) ILIBCRITICALEXIT(254);
	}
	for (row = 0; row < TILE_HEIGHT_COUNT; row++) { for (col = 0; col < TILE_WIDTH_COUNT; col++) { tileInfo[row][col].crc = 0xFF; tileInfo[row][col].flags = 0; } }
}

#define BUFSIZE 65535
#ifdef _WINSERVICE
DWORD WINAPI kvm_mainloopinput_ex(LPVOID Param)
{
	int ptr = 0;
	int ptr2 = 0;
	int len = 0;
	char pchRequest2[30000];
	BOOL fSuccess = FALSE;
	DWORD cbBytesRead = 0;
	ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)Param)[0];
	void *reserved = ((void**)Param)[1];

	KVMDEBUG("kvm_mainloopinput / start", (int)GetCurrentThreadId());

	ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: (mainloopinput) Starting...");


	while (!g_shutdown)
	{
		fSuccess = ReadFile(hStdIn, pchRequest2 + len, 30000 - len, &cbBytesRead, NULL);
		if (!fSuccess || cbBytesRead == 0 || g_shutdown) 
		{ 
			ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: fSuccess/%d  cbBytesRead/%d  g_shutdown/%d", fSuccess, cbBytesRead, g_shutdown);
			KVMDEBUG("ReadFile() failed", 0); /*ILIBMESSAGE("KVMBREAK-K1\r\n");*/ g_shutdown = 1; break; 
		}
		len += cbBytesRead;
		ptr2 = 0;
		while ((ptr2 = kvm_server_inputdata((char*)pchRequest2 + ptr, len - ptr, writeHandler, reserved)) != 0) { ptr += ptr2; }
		if (ptr == len) { len = 0; ptr = 0; }
		// TODO: else move the reminder.
	}
	ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: (mainloopinput) Exiting...");
	ILibRemoteLogging_Destroy(gKVMRemoteLogging);
	gKVMRemoteLogging = NULL;

	KVMDEBUG("kvm_mainloopinput / end", (int)GetCurrentThreadId());

	return 0;
}

DWORD WINAPI kvm_mainloopinput(LPVOID Param)
{
	DWORD ret = 0;
	if (((int*)&(((void**)Param)[3]))[0] == 1)
	{
		ILib_DumpEnabledContext winException;
		__try
		{
			ret = kvm_mainloopinput_ex(Param);
		}
		__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winException))
		{
			ILib_WindowsExceptionDebugEx(&winException);
		}
	}
	else
	{
		ret = kvm_mainloopinput_ex(Param);
	}
	return(ret);
}
#endif


// This is the main KVM pooling loop. It will look at the display and see if any changes occur. [Runs as daemon if Windows Service]
DWORD WINAPI kvm_server_mainloop_ex(LPVOID parm)
{
	//long cur_timestamp = 0;
	//long prev_timestamp = 0;
	//long time_diff = 50;
	long long tilesize;
	int width, height = 0;
	void *buf, *desktop;
	long long desktopsize;
	BITMAPINFO bmpInfo;
	int row, col;
	ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)parm)[0];
	void *reserved = ((void**)parm)[1];
	char *tmoBuffer;
	long mouseMove[3] = { 0,0,0 };
	int sentHideCursor = 0;

	gPendingPackets = ILibQueue_Create();
	KVM_InitMouseCursors(gPendingPackets);

#ifdef _WINSERVICE
	if (!kvmConsoleMode)
	{
		gKVMRemoteLogging = ILibRemoteLogging_Create(NULL);
		ILibRemoteLogging_SetRawForward(gKVMRemoteLogging, sizeof(KVMDebugLog), kvm_slave_OnRawForwardLog);
		ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: Child Processing Running...");
	}
#endif

	// This basic lock will prevent 2 thread from running at the same time. Gives time for the first one to fully exit.
	while (ThreadRunning != 0 && height < 200) { height++; Sleep(50); }
	if (height >= 200 && ThreadRunning != 0) return 0;
	ThreadRunning = 1;
	g_shutdown = 0;

	g_pause = 0;
	g_remotepause = ((int*)&(((void**)parm)[2]))[0];

	KVMDEBUG("kvm_server_mainloop / start1", (int)GetCurrentThreadId());

#ifdef _WINSERVICE
	if (!kvmConsoleMode)
	{
		hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		hStdIn = GetStdHandle(STD_INPUT_HANDLE);
	}
#endif

	KVMDEBUG("kvm_server_mainloop / start2", (int)GetCurrentThreadId());

#ifdef _WINSERVICE
	if (!kvmConsoleMode)
	{
		g_shutdown = 0;
		kvmthread = CreateThread(NULL, 0, kvm_mainloopinput, parm, 0, 0);
		CloseHandle(kvmthread);
	}
#endif

	do {
		g_desktop_switch_pending = 0;
		g_shutdown = 0;

	if (!initialize_gdiplus())
	{
#ifdef _WINSERVICE
		if (!kvmConsoleMode)
		{
			ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: initialize_gdiplus() failed");
		}
#endif
		KVMDEBUG("kvm_server_mainloop / initialize_gdiplus failed", (int)GetCurrentThreadId()); return 0;
	}
#ifdef _WINSERVICE
	if (!kvmConsoleMode)
	{
		ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: initialize_gdiplus() SUCCESS");
	}
#endif
	kvm_server_SetResolution(writeHandler, reserved);

	// Set all CRCs to 0xFF
	for (row = 0; row < TILE_HEIGHT_COUNT; row++) {
		for (col = 0; col < TILE_WIDTH_COUNT; col++) {
			tileInfo[row][col].crc = 0xFF;
		}
	}

	// Send the list of displays
	kvm_send_display_list(writeHandler, reserved);

	Sleep(100); // Pausing here seems to fix connection issues, especially with WebRTC. TODO: Investigate why.
	KVMDEBUG("kvm_server_mainloop / start3", (int)GetCurrentThreadId());

	// Loop and send only when a tile changes.
	while (!g_shutdown && !g_desktop_switch_pending)
	{
		KVMDEBUG("kvm_server_mainloop / loop1", (int)GetCurrentThreadId());

		// Reset all the flags to TILE_TODO
		for (row = 0; row < TILE_HEIGHT_COUNT; row++) 
		{
			for (col = 0; col < TILE_WIDTH_COUNT; col++) 
			{
				tileInfo[row][col].flags = (char)TILE_TODO;
#ifdef KVM_ALL_TILES
				tileInfo[row][col].crc = 0xFF;
#endif
			}
		}
		CheckDesktopSwitch(1, writeHandler, reserved);
		if (g_shutdown) break;


		// Enter Alertable State, so we can dispatch any packets if necessary.
		// We are doing it here, in case we need to merge any data with the bitmaps
		SleepEx(0, TRUE);
		mouseMove[0] = 0;
		while ((tmoBuffer = ILibQueue_DeQueue(gPendingPackets)) != NULL)
		{
			if (ntohs(((unsigned short*)tmoBuffer)[0]) == MNG_KVM_MOUSE_MOVE)
			{
				if (SCREEN_SEL_TARGET == 0)
				{
					mouseMove[0] = 1;
					mouseMove[1] = ((long*)tmoBuffer)[1] - VSCREEN_X;
					mouseMove[2] = ((long*)tmoBuffer)[2] - VSCREEN_Y;
				}
				else
				{
					if (((long*)tmoBuffer)[1] >= SCREEN_X && ((long*)tmoBuffer)[1] <= (SCREEN_X + SCREEN_WIDTH) &&
						((long*)tmoBuffer)[2] >= SCREEN_Y && ((long*)tmoBuffer)[2] <= (SCREEN_Y + SCREEN_HEIGHT))
					{
						mouseMove[0] = 1;
						mouseMove[1] = ((long*)tmoBuffer)[1] - SCREEN_X;
						mouseMove[2] = ((long*)tmoBuffer)[2] - SCREEN_Y;
					}
				}
			}
			else
			{
				if (ntohs(((unsigned short*)tmoBuffer)[0]) != MNG_KVM_MOUSE_CURSOR || sentHideCursor==0)
				{
					writeHandler(tmoBuffer, (int)ILibMemory_Size(tmoBuffer), reserved);
				}
			}
			ILibMemory_Free(tmoBuffer);
		}
		if (mouseMove[0] == 0 && (gRemoteMouseRenderDefault != 0 || gRemoteMouseMoved == 0))
		{
			mouseMove[0] = 1;
			CURSORINFO info = { 0 };
			info.cbSize = sizeof(info);
			GetCursorInfo(&info);

			if (SCREEN_SEL_TARGET == 0)
			{
				mouseMove[1] = info.ptScreenPos.x - VSCREEN_X;
				mouseMove[2] = info.ptScreenPos.y - VSCREEN_Y;
			}
			else
			{
				mouseMove[1] = info.ptScreenPos.x - SCREEN_X;
				mouseMove[2] = info.ptScreenPos.y - SCREEN_Y;
			}
		}
		if (mouseMove[0] != 0)
		{
			if (sentHideCursor == 0)
			{
				sentHideCursor = 1;
				char tmpBuffer[5];
				((unsigned short*)tmpBuffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_MOUSE_CURSOR);	// Write the type
				((unsigned short*)tmpBuffer)[1] = (unsigned short)htons((unsigned short)5);						// Write the size
				tmpBuffer[4] = (char)KVM_MouseCursor_NONE;														// Cursor Type
				writeHandler(tmpBuffer, 5, reserved);
			}
		}
		else
		{
			if (sentHideCursor != 0)
			{
				sentHideCursor = 0;
				char tmpBuffer[5];
				((unsigned short*)tmpBuffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_MOUSE_CURSOR);	// Write the type
				((unsigned short*)tmpBuffer)[1] = (unsigned short)htons((unsigned short)5);						// Write the size
				tmpBuffer[4] = (char)gCurrentCursor;															// Cursor Type
				writeHandler(tmpBuffer, 5, reserved);
			}
		}

		// Scan the desktop
		if (get_desktop_buffer(&desktop, &desktopsize, mouseMove) == 1 || desktop == NULL)
		{
#ifdef _WINSERVICE
			if (!kvmConsoleMode)
			{
				ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: get_desktop_buffer() failed");
			}
#endif
			KVMDEBUG("get_desktop_buffer() failed, restarting...", (int)GetCurrentThreadId());
			g_desktop_switch_pending = 1;
		}
		else 
		{
			bmpInfo = get_bmp_info(TILE_WIDTH, TILE_HEIGHT);
			for (row = 0; row < TILE_HEIGHT_COUNT; row++) {
				for (col = 0; col < TILE_WIDTH_COUNT; col++) {
					height = TILE_HEIGHT * row;
					width = TILE_WIDTH * col;

					while (!g_shutdown && (g_pause)) { Sleep(50); /*printf(".");*/ } // If the socket is in pause state, wait here. //ToDo: YLIAN!!!!

					if (g_shutdown || SCALING_FACTOR != SCALING_FACTOR_NEW) { height = SCALED_HEIGHT; width = SCALED_WIDTH; break; }
					
					// Skip the tile if it has already been sent or if the CRC is same as before
					if (tileInfo[row][col].flags == (char)TILE_SENT || tileInfo[row][col].flags == (char)TILE_DONT_SEND) { continue; }

					if (get_tile_at(width, height, &buf, &tilesize, desktop, row, col) == 1)
					{
						// GetTileAt failed, lets not send the tile
						continue;
					}
					if (buf && !g_shutdown)
					{
						KVMDEBUG2("Writing JPEG: %llu bytes", tilesize);
						switch (writeHandler((char*)buf, (int)tilesize, reserved))
						{
							case ILibTransport_DoneState_INCOMPLETE:
								g_pause = 1;
								ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_2, "Agent KVM: KVM PAUSE");
								KVMDEBUG2("JPEG WRITE resulted in PAUSE");
								break;
							case ILibTransport_DoneState_ERROR:
								g_shutdown = 1; 
								height = SCALED_HEIGHT; 
								width = SCALED_WIDTH; 
								KVMDEBUG2("JPEG WRITE resulted in ERROR");
								break;
						}
						free(buf);
					}
				}
			}
			
			KVMDEBUG("kvm_server_mainloop / loop2", (int)GetCurrentThreadId());

			if (desktop) free(desktop);
			desktop = NULL;
			desktopsize = 0;
		}

		KVMDEBUG("kvm_server_mainloop / loop3", (int)GetCurrentThreadId());

		// We can't go full speed here, we need to slow this down.
		height = FRAME_RATE_TIMER;
		while (!g_shutdown && height > 0) { if (height > 50) { height -= 50; Sleep(50); } else { Sleep(height); height = 0; } SleepEx(0, TRUE); }
	}

	KVMDEBUG("kvm_server_mainloop / end3", (int)GetCurrentThreadId());
	KVMDEBUG("kvm_server_mainloop / end2", (int)GetCurrentThreadId());

	if (tileInfo != NULL) {
		for (row = 0; row < TILE_HEIGHT_COUNT; row++) free(tileInfo[row]);
		free(tileInfo);
		tileInfo = NULL;
	}
	KVMDEBUG("kvm_server_mainloop / end1", (int)GetCurrentThreadId());
	teardown_gdiplus();

	if (g_desktop_switch_pending) {
		Sleep(500);
	}
	} while (g_desktop_switch_pending && !g_shutdown);

	KVMDEBUG("kvm_server_mainloop / end", (int)GetCurrentThreadId());

	KVM_UnInitMouseCursors();

	while ((tmoBuffer = ILibQueue_DeQueue(gPendingPackets)) != NULL)
	{
		ILibMemory_Free(tmoBuffer);
	}
	ILibQueue_Destroy(gPendingPackets);


	ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: Process Exiting...");

	ThreadRunning = 0;
	free(parm);
	return 0;
}

DWORD WINAPI kvm_server_mainloop(LPVOID parm)
{
	DWORD ret = 0;
	if (((int*)&(((void**)parm)[3]))[0] == 1)
	{
		// Enable Core Dump in KVM Child
		ILib_DumpEnabledContext winException;
		WCHAR str[_MAX_PATH];
		DWORD strLen;
		if ((strLen = GetModuleFileNameW(NULL, str, _MAX_PATH)) > 5)
		{
			str[strLen - 4] = 0;	// We're going to convert .exe to _kvm.dmp
			g_ILibCrashDump_path = ILibMemory_Allocate((strLen * 2) + 10, 0, NULL, NULL); // Add enough space to add '.dmp' to the end of the path
			swprintf_s((wchar_t*)g_ILibCrashDump_path, strLen + 5, L"%s_kvm.dmp", str);
			ILibCriticalLogFilename = "KVMSlave.log";
		}

		__try
		{
			ret = kvm_server_mainloop_ex(parm);
		}
		__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winException))
		{
			ILib_WindowsExceptionDebugEx(&winException);
		}
	}
	else
	{
		// Core Dump not enabled in KVM Child
		ret = kvm_server_mainloop_ex(parm);
	}
	return(ret);
}

#ifdef _WINSERVICE
void kvm_relay_ExitHandler(ILibProcessPipe_Process sender, int exitCode, void* user)
{
	ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)user)[0];
	void *reserved = ((void**)user)[1];
	void *pipeMgr = ((void**)user)[2];
	char *exePath = (char*)((void**)user)[3];

	ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "Agent KVM: KVM Child Process(%d) [EXITED]", g_slavekvm);
	UNREFERENCED_PARAMETER(exitCode);
	UNREFERENCED_PARAMETER(sender);

	if (g_restartcount < 4 && g_shutdown == 0)
	{
		kvm_relay_restart(1, pipeMgr, exePath, writeHandler, reserved);
	}
	else
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "Agent KVM: g_restartcount = %d, aborting", g_restartcount);
		writeHandler(NULL, 0, reserved);
	}
}

void kvm_relay_StdOutHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)
{
	unsigned short size = 0;
	UNREFERENCED_PARAMETER(sender);
	ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)user)[0];
	void *reserved = ((void**)user)[1];

	if (bufferLen > 4)
	{
		if (ntohs(((unsigned short*)(buffer))[0]) > 1000)
		{
			KVMDEBUG2("Invalid KVM Command received: %u", ntohs(((unsigned short*)(buffer))[0]));
		}
		if (ntohs(((unsigned short*)(buffer))[0]) == (unsigned short)MNG_JUMBO)
		{
			if (bufferLen > 8)
			{
				if (bufferLen >= (size_t)(8 + (int)ntohl(((unsigned int*)(buffer))[1])))
				{
					*bytesConsumed = 8 + (int)ntohl(((unsigned int*)(buffer))[1]);
					KVMDEBUG2("Jumbo Packet received of size: %llu (bufferLen=%llu)", *bytesConsumed, bufferLen);

					writeHandler(buffer, (int)*bytesConsumed, reserved);
					return;
				}
			}
			KVMDEBUG2("Accumulate => JUMBO: [%llu bytes] bufferLen=%llu ", (size_t)(8 + (int)ntohl(((unsigned int*)(buffer))[1])), bufferLen);
		}
		else
		{
			size = ntohs(((unsigned short*)(buffer))[1]);
			if (size <= bufferLen)
			{
				KVMDEBUG2("KVM Command: [%u: %llu bytes]", ntohs(((unsigned short*)(buffer))[0]), size);
				*bytesConsumed = size;
				writeHandler(buffer, size, reserved);
				return;
			}
			KVMDEBUG2("Accumulate => KVM Command: [%u: %d bytes] bufferLen=%llu ", ntohs(((unsigned short*)(buffer))[0]), bufferLen);
		}
	}
	*bytesConsumed = 0;
}
void kvm_relay_StdErrHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)
{
	KVMDebugLog *log = (KVMDebugLog*)buffer;

	UNREFERENCED_PARAMETER(sender);
	UNREFERENCED_PARAMETER(user);

	if (bufferLen < sizeof(KVMDebugLog) || bufferLen < log->length) { *bytesConsumed = 0;  return; }
	*bytesConsumed = log->length;
	//ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), (ILibRemoteLogging_Modules)log->logType, (ILibRemoteLogging_Flags)log->logFlags, "%s", log->logData);
	ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Microstack_Generic, (ILibRemoteLogging_Flags)log->logFlags, "%s", log->logData);

}

int kvm_relay_restart(int paused, void *pipeMgr, char *exePath, ILibKVM_WriteHandler writeHandler, void *reserved)
{
	char * parms0[] = { " -kvm0", g_ILibCrashDump_path != NULL ? "-coredump" : NULL, NULL, NULL };
	char * parms1[] = { " -kvm1", g_ILibCrashDump_path != NULL ? "-coredump" : NULL, NULL, NULL };
	void **user = (void**)ILibMemory_Allocate(4 * sizeof(void*), 0, NULL, NULL);

	if (parms0[1] == NULL)
	{
		parms0[1] = (gRemoteMouseRenderDefault != 0 ? "-remotecursor" : NULL);
		parms1[1] = (gRemoteMouseRenderDefault != 0 ? "-remotecursor" : NULL);
	}
	else
	{
		parms0[2] = (gRemoteMouseRenderDefault != 0 ? "-remotecursor" : NULL);
		parms1[2] = (gRemoteMouseRenderDefault != 0 ? "-remotecursor" : NULL);
	}

	user[0] = writeHandler;
	user[1] = reserved;
	user[2] = pipeMgr;
	user[3] = exePath;
	
	KVMDEBUG("kvm_relay_restart / start", paused);

	// If we are re-launching the child process, wait a bit. The computer may be switching desktop, etc.
	if (paused == 0) Sleep(500);
	if (gProcessSpawnType == ILibProcessPipe_SpawnTypes_SPECIFIED_USER && gProcessTSID < 0) { gProcessSpawnType = ILibProcessPipe_SpawnTypes_USER; }

	ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [Master]: Spawning Slave as %s", gProcessSpawnType == ILibProcessPipe_SpawnTypes_USER ? "USER":"WIN_LOGON");
	gChildProcess = ILibProcessPipe_Manager_SpawnProcessEx3(pipeMgr, exePath, paused == 0 ? parms0 : parms1, gProcessSpawnType, (void*)(ULONG_PTR)gProcessTSID, 0);
	gProcessSpawnType = (gProcessSpawnType == ILibProcessPipe_SpawnTypes_SPECIFIED_USER || gProcessSpawnType == ILibProcessPipe_SpawnTypes_USER) ? ILibProcessPipe_SpawnTypes_WINLOGON : (gProcessTSID < 0 ? ILibProcessPipe_SpawnTypes_USER : ILibProcessPipe_SpawnTypes_SPECIFIED_USER);

	g_slavekvm = ILibProcessPipe_Process_GetPID(gChildProcess);
	char tmp[255];
	sprintf_s(tmp, sizeof(tmp), "Child KVM (pid: %d)", g_slavekvm);
	ILibProcessPipe_Process_ResetMetadata(gChildProcess, tmp);

	ILibProcessPipe_Process_AddHandlers(gChildProcess, 65535, &kvm_relay_ExitHandler, &kvm_relay_StdOutHandler, &kvm_relay_StdErrHandler, NULL, user);

	KVMDEBUG("kvm_relay_restart() launched child process", g_slavekvm);

	// Run the relay
	g_shutdown = 0;
	KVMDEBUG("kvm_relay_restart / end", (int)(uintptr_t)kvmthread);

	return 1;
}
#endif

// Setup the KVM session. Return 1 if ok, 0 if it could not be setup.
int kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int tsid)
{
	if (processPipeMgr != NULL)
	{
#ifdef _WINSERVICE
		if (ThreadRunning == 1 && g_shutdown == 0) { KVMDEBUG("kvm_relay_setup() session already exists", 0); return 0; }
		g_restartcount = 0;
		gProcessSpawnType = ILibProcessPipe_SpawnTypes_SPECIFIED_USER;
		gProcessTSID = tsid;
		KVMDEBUG("kvm_relay_setup() session starting", 0);
		return kvm_relay_restart(1, processPipeMgr, exePath, writeHandler, reserved);
#else
		return(0);
#endif
	}
	else
	{
		// if (kvmthread != NULL && g_shutdown == 0) return 0;
		void **parms = (void**)ILibMemory_Allocate((2 * sizeof(void*)) + sizeof(int), 0, NULL, NULL);
		parms[0] = writeHandler;
		parms[1] = reserved;
		((int*)(&parms[2]))[0] = 1;
		kvmConsoleMode = 1;

		if (ThreadRunning == 1 && g_shutdown == 0) { KVMDEBUG("kvm_relay_setup() session already exists", 0); free(parms); return 0; }
		kvmthread = CreateThread(NULL, 0, kvm_server_mainloop, (void*)parms, 0, 0);
		if (kvmthread != 0) { CloseHandle(kvmthread); }
		return 1;
	}
}

// Force a KVM reset & refresh
void kvm_relay_reset(ILibKVM_WriteHandler writeHandler, void *reserved)
{
	char buffer[4];
	KVMDEBUG("kvm_relay_reset", 0);
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_REFRESH);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)4);				// Write the size
	kvm_relay_feeddata(buffer, 4, writeHandler, reserved);
}

// Clean up the KVM session.
void kvm_cleanup()
{
	//ILIBMESSAGE("KVMBREAK-CLEAN\r\n");
	KVMDEBUG("kvm_cleanup", 0);
	g_shutdown = 1;
	if (gChildProcess != NULL) 
	{ 
		ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM.c/kvm_cleanup: Attempting to kill child process");
		ILibProcessPipe_Process_SoftKill(gChildProcess);
		gChildProcess = NULL;
	}
	else
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM.c/kvm_cleanup: gChildProcess = NULL");
	}
}


////
//// Desktop Duplication API KVM
////
//#include <d3d11.h>
//#include <dxgi1_2.h>
//
//typedef struct D3D11_Functions
//{
//	HRESULT(*D3D11CreateDevice)(
//		IDXGIAdapter            *pAdapter,
//		D3D_DRIVER_TYPE         DriverType,
//		HMODULE                 Software,
//		UINT                    Flags,
//		const D3D_FEATURE_LEVEL *pFeatureLevels,
//		UINT                    FeatureLevels,
//		UINT                    SDKVersion,
//		ID3D11Device            **ppDevice,
//		D3D_FEATURE_LEVEL       *pFeatureLevel,
//		ID3D11DeviceContext     **ppImmediateContext
//		);
//}D3D11_Functions;


//void DD_Init()
//{
	//int i;
	//HRESULT hr;
	//ID3D11Device* m_Device;
	//ID3D11DeviceContext* m_DeviceContext;
	//IDXGIFactory2* m_Factory;
	//DWORD m_OcclusionCookie;
	//DXGI_OUTDUPL_DESC lOutputDuplDesc;
	//ID3D11Texture2D *lGDIImage;
	//ID3D11Texture2D *desktopImage;
	//ID3D11Texture2D *destinationImage;

	//DXGI_OUTDUPL_FRAME_INFO lFrameInfo;
	//IDXGIResource *lDesktopResource;

	//D3D11_Functions funcs;

	//HMODULE _D3D = NULL;
	//if ((_D3D = LoadLibraryExA((LPCSTR)"D3D11.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32)) != NULL)
	//{
	//	(FARPROC)funcs.D3D11CreateDevice = GetProcAddress(_D3D, "D3D11CreateDevice");
	//}

	//D3D_DRIVER_TYPE DriverTypes[] =
	//{
	//	D3D_DRIVER_TYPE_HARDWARE,
	//	D3D_DRIVER_TYPE_WARP,
	//	D3D_DRIVER_TYPE_REFERENCE,
	//};
	//UINT NumDriverTypes = ARRAYSIZE(DriverTypes);

	//// Feature levels supported
	//D3D_FEATURE_LEVEL FeatureLevels[] =
	//{
	//	D3D_FEATURE_LEVEL_11_0,
	//	D3D_FEATURE_LEVEL_10_1,
	//	D3D_FEATURE_LEVEL_10_0,
	//	D3D_FEATURE_LEVEL_9_1
	//};
	//UINT NumFeatureLevels = ARRAYSIZE(FeatureLevels);
	//D3D_FEATURE_LEVEL FeatureLevel;

	//// Create device
	//for (UINT DriverTypeIndex = 0; DriverTypeIndex < NumDriverTypes; ++DriverTypeIndex)
	//{
	//	hr = funcs.D3D11CreateDevice(NULL, DriverTypes[DriverTypeIndex], NULL, 0, FeatureLevels, NumFeatureLevels, D3D11_SDK_VERSION, &m_Device, &FeatureLevel, &m_DeviceContext);
	//	if (SUCCEEDED(hr))
	//	{
	//		// Device creation succeeded, no need to loop anymore
	//		break;
	//	}
	//}
	//if (FAILED(hr))
	//{
	//	DebugBreak();
	//}

	//// Get DXGI factory
	//IDXGIDevice* DxgiDevice = NULL;
	//hr = m_Device->lpVtbl->QueryInterface(m_Device, &IID_IDXGIDevice, (void**)&DxgiDevice);
	//if (FAILED(hr))
	//{
	//	DebugBreak();
	//}

	//IDXGIAdapter* DxgiAdapter = NULL;
	//hr = DxgiDevice->lpVtbl->GetParent(DxgiDevice, &IID_IDXGIAdapter, (void**)&DxgiAdapter);
	//DxgiDevice->lpVtbl->Release(DxgiDevice);
	//DxgiDevice = NULL;
	//if (FAILED(hr))
	//{
	//	DebugBreak();
	//}

	//hr = DxgiAdapter->lpVtbl->GetParent(DxgiAdapter, &IID_IDXGIFactory2, (void**)&m_Factory);
	//DxgiAdapter->lpVtbl->Release(DxgiAdapter);
	//DxgiAdapter = NULL;
	//if (FAILED(hr))
	//{
	//	DebugBreak();
	//	//return ProcessFailure(m_Device, L"Failed to get parent DXGI Factory", L"Error", hr, SystemTransitionsExpectedErrors);
	//}

	//IDXGIOutput1 *DxgiOutput1;
	//hr = m_Device->lpVtbl->QueryInterface(m_Device, &IID_IDXGIOutput, (void**)&DxgiOutput1);
	//if (FAILED(hr))
	//{
	//	DebugBreak();
	//}

	//IDXGIOutputDuplication *dupl = NULL;
	//DxgiOutput1->lpVtbl->DuplicateOutput(DxgiOutput1, m_Device, &dupl);

	//// Create GUI drawing texture
	//dupl->lpVtbl->GetDesc(dupl, &lOutputDuplDesc);

	//D3D11_TEXTURE2D_DESC desc;
	//desc.Width = lOutputDuplDesc.ModeDesc.Width;
	//desc.Height = lOutputDuplDesc.ModeDesc.Height;
	//desc.Format = lOutputDuplDesc.ModeDesc.Format;
	//desc.ArraySize = 1;
	//desc.BindFlags = D3D11_BIND_RENDER_TARGET;
	//desc.MiscFlags = D3D11_RESOURCE_MISC_GDI_COMPATIBLE;
	//desc.SampleDesc.Count = 1;
	//desc.SampleDesc.Quality = 0;
	//desc.MipLevels = 1;
	//desc.CPUAccessFlags = 0;
	//desc.Usage = D3D11_USAGE_DEFAULT;

	//hr = m_Device->lpVtbl->CreateTexture2D(m_Device, &desc, NULL, &lGDIImage);
	//hr = m_Device->lpVtbl->CreateTexture2D(m_Device, &desc, NULL, &destinationImage);

	//if (FAILED(hr))
	//{
	//	DebugBreak();
	//}

	//// Get new frame
	//for (i = 0; i < 5; ++i)
	//{
	//	hr = dupl->lpVtbl->AcquireNextFrame(dupl, 250, &lFrameInfo, &lDesktopResource);
	//	if (hr != DXGI_ERROR_WAIT_TIMEOUT) { break; }
	//	Sleep(100);
	//}
	//
	//hr = lDesktopResource->lpVtbl->QueryInterface(lDesktopResource, &IID_ID3D11Texture2D, &desktopImage);

	//// Copy image into GDI drawing texture
	//m_DeviceContext->lpVtbl->CopyResource(m_DeviceContext, lGDIImage, desktopImage);

	//// Draw cursor image into GDI drawing texture
	//IDXGISurface1 *surface;
	//hr = lGDIImage->lpVtbl->QueryInterface(lGDIImage, &IID_IDXGISurface1, &surface);


	//// Copy from CPU access texture to bitmap buffer

	//D3D11_MAPPED_SUBRESOURCE resource;
	//UINT subresource = D3D11CalcSubresource(0, 0, 0);
	//m_DeviceContext->lpVtbl->Map(m_DeviceContext, destinationImage, subresource, D3D11_MAP_READ_WRITE, 0, &resource);

	//BITMAPINFO	lBmpInfo;

	//// BMP 32 bpp

	//ZeroMemory(&lBmpInfo, sizeof(BITMAPINFO));
	//lBmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	//lBmpInfo.bmiHeader.biBitCount = 32;
	//lBmpInfo.bmiHeader.biCompression = BI_RGB;
	//lBmpInfo.bmiHeader.biWidth = lOutputDuplDesc.ModeDesc.Width;
	//lBmpInfo.bmiHeader.biHeight = lOutputDuplDesc.ModeDesc.Height;
	//lBmpInfo.bmiHeader.biPlanes = 1;
	//lBmpInfo.bmiHeader.biSizeImage = lOutputDuplDesc.ModeDesc.Width * lOutputDuplDesc.ModeDesc.Height * 4;


	//BYTE* pBuf = (BYTE*)ILibMemory_SmartAllocate(lBmpInfo.bmiHeader.biSizeImage);
	//UINT lBmpRowPitch = lOutputDuplDesc.ModeDesc.Width * 4;
	//BYTE* sptr = (BYTE*)resource.pData;
	//BYTE* dptr = pBuf + lBmpInfo.bmiHeader.biSizeImage - lBmpRowPitch;
	//UINT lRowPitch = min(lBmpRowPitch, resource.RowPitch);
	//size_t h;

	//for (h = 0; h < lOutputDuplDesc.ModeDesc.Height; ++h)
	//{
	//	memcpy_s(dptr, lBmpRowPitch, sptr, lRowPitch);
	//	sptr += resource.RowPitch;
	//	dptr -= lBmpRowPitch;
	//}
//}


#endif
