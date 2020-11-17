/*   
Copyright 2006 - 2018 Intel Corporation

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

// #define KVMDEBUGENABLED 1
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
#else
#define KVMDEBUG(m, u)
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
	KVMDEBUG("kvm_ctrlaltdel", (int)Param);
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

void kvm_send_display_list(ILibKVM_WriteHandler writeHandler, void *reserved)
{
	int i;

	// Not looked at the number of screens yet
	if (SCREEN_COUNT == -1) return;
	char *buffer = ILibMemory_AllocateA((5 + SCREEN_COUNT) * 2);
	memset(buffer, 0xFF, ILibMemory_AllocateA_Size(buffer));
	// Send the list of possible displays to remote
	if (SCREEN_COUNT == 0 || SCREEN_COUNT == 1)
	{
		// Only one display, send empty
		((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_GET_DISPLAYS);		// Write the type
		((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)(8));					// Write the size
		((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)(0));							// Screen Count
		((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)(0));							// Selected Screen

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
				g_shutdown = 1;
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

// Push keyboard events to the default input desktop
// Used for remote messaging keyboard input
void kvm_keyboardInput(char* block, int blocklen)
{
	int i;

	KVMDEBUG("kvm_keyboardInput", blocklen);

	/*
	HWINSTA ws1, ws2;
	HDESK desktop, desktop2;

	ws2 = GetProcessWindowStation();
	ws1 = OpenWindowStation(_T("winsta0"), FALSE,
					WINSTA_ACCESSCLIPBOARD    |
					WINSTA_ACCESSGLOBALATOMS  |
					WINSTA_CREATEDESKTOP      |
					WINSTA_ENUMDESKTOPS       |
					WINSTA_ENUMERATE          |
					WINSTA_EXITWINDOWS        |
					WINSTA_READATTRIBUTES     |
					WINSTA_READSCREEN         |
					WINSTA_WRITEATTRIBUTES);
	if (ws1 != NULL) SetProcessWindowStation(ws1);

	// Check desktop switch
	desktop2 = GetThreadDesktop(GetCurrentThreadId());
	desktop = OpenInputDesktop(0, TRUE,
                        DESKTOP_CREATEMENU    |
                        DESKTOP_CREATEWINDOW  |
                        DESKTOP_ENUMERATE     |
                        DESKTOP_HOOKCONTROL   |
                        DESKTOP_WRITEOBJECTS  |
                        DESKTOP_READOBJECTS   |
                        DESKTOP_SWITCHDESKTOP |
                        GENERIC_WRITE);
	SetThreadDesktop(desktop);
	*/

	for (i = 1; i < blocklen; i += 2) KeyAction(block[i], block[i - 1]);

	/*
	if (ws1 != NULL) { SetProcessWindowStation(ws2); CloseWindowStation(ws1); }
	SetThreadDesktop(desktop2);
	CloseDesktop(desktop);
	*/
}

char *kvm_getKeyboardLayoutCode(char *layout, size_t layoutLength)
{
	char *val = layout;
	char *ret = NULL;
	if (layoutLength < 16) { return(NULL); }

	switch (((int64_t*)val)[0])
	{
	case 280568361569: // ar-SA
		ret = "00000401";
		break;
	case 306052949858: // bg-BG
		ret = "00000402";
		break;
	case 357642887523: // ca-ES
		ret = "00000403";
		break;
	case 375074416762: // zh-TW
		ret = "00000404";
		break;
	case 387674108771: // cs-CZ
		ret = "00000405";
		break;
	case 323266371940: // da-DK
		ret = "00000406";
		break;
	case 297496569188: // de-DE
		ret = "00000407";
		break;
	case 353381477477: // el-GR
		ret = "00000408";
		break;
	case 357911326309: // en-US
		ret = "00000409";
		break;
	case 314709993830: // fi-FI
		ret = "0000040B";
		break;
	case 353364701798: // fr-FR
		ret = "0000040C";
		break;
	case 327645226344: // he-IL
		ret = "0000040D";
		break;
	case 366283158888: // hu-HU
		ret = "0000040E";
		break;
	case 357710001001: // is-IS
		ret = "0000040F";
		break;
	case 362004968553: // it-IT
		ret = "00000410";
		break;
	case 344841871722: // ja-JP
		ret = "00000411";
		break;
	case 353448587115: // ko-KR
		ret = "00000412";
		break;
	case 327729114222: // nl-NL
		ret = "00000413";
		break;
	case 340614013550: // nb-NO
		ret = "00000414";
		break;
	case 327762668656: // pl-PL
		ret = "00000415";
		break;
	case 353297593456: // pt-BR
		ret = "00000416";
		break;
	case 310364695922: // rm-CH
		ret = "00000417";
		break;
	case 340681125746: // ro-RO
		ret = "00000418";
		break;
	case 366450931058: // ru-RU
		ret = "00000419";
		break;
	case 353398256232: // hr-HR
		ret = "0000041A";
		break;
	case 323518032755: // sk-SK
		ret = "0000041B";
		break;
	case 327511011699: // sq-AL
		ret = "0000041C";
		break;
	case 297748231795: // sv-SE
		ret = "0000041D";
		break;
	case 310649907316: // th-TH
		ret = "0000041E";
		break;
	case 353599582836: // tr-TR
		ret = "0000041F";
		break;
	case 323467702901: // ur-PK
		ret = "00000420";
		break;
	case 293285487721: // id-ID
		ret = "00000421";
		break;
	case 280601914229: // uk-UA
		ret = "00000422";
		break;
	case 383362360674: // be-BY
		ret = "00000423";
		break;
	case 314928098419: // sl-SI
		ret = "00000424";
		break;
	case 297513350245: // et-EE
		ret = "00000425";
		break;
	case 370645235308: // lv-LV
		ret = "00000426";
		break;
	case 362055300204: // lt-LT
		ret = "00000427";
		break;
	case 353415029094: // fa-IR
		ret = "00000429";
		break;
	case 336453265782: // vi-VN
		ret = "0000042A";
		break;
	case 331805981032: // hy-AM
		ret = "0000042B";
		break;
	case 357642892645: // eu-ES
		ret = "0000042D";
		break;
	case 76159121519464: // hsb-DE
		ret = "0000042E";
		break;
	case 323417369453: // mk-MK
		ret = "0000042F";
		break;
	case 280685802611: // st-ZA
		ret = "00000430";
		break;
	case 280685802356: // ts-ZA
		ret = "00000431";
		break;
	case 280685801076: // tn-ZA
		ret = "00000432";
		break;
	case 280685798774: // ve-ZA
		ret = "00000433";
		break;
	case 280685799544: // xh-ZA
		ret = "00000434";
		break;
	case 280685802874: // zu-ZA
		ret = "00000435";
		break;
	case 280685799009: // af-ZA
		ret = "00000436";
		break;
	case 297546899819: // ka-GE
		ret = "00000437";
		break;
	case 340479799142: // fo-FO
		ret = "00000438";
		break;
	case 336235161960: // hi-IN
		ret = "00000439";
		break;
	case 362072077421: // mt-MT
		ret = "0000043A";
		break;
	case 340614014323: // se-NO
		ret = "0000043B";
		break;
	case 32196334487169401: // yi-Hebr
		ret = "0000043D";
		break;
	case 383546913645: // ms-MY
		ret = "0000043E";
		break;
	case 387808324459: // kk-KZ
		ret = "0000043F";
		break;
	case 306203949419: // ky-KG
		ret = "00000440";
		break;
	case 297614014323: // sw-KE
		ret = "00000441";
		break;
	case 332124744564: // tk-TM
		ret = "00000442";
		break;
	case 366450930804: // tt-RU
		ret = "00000444";
		break;
	case 336235163234: // bn-IN
		ret = "00000445";
		break;
	case 336235159920: // pa-IN
		ret = "00000446";
		break;
	case 336235165031: // gu-IN
		ret = "00000447";
		break;
	case 336235164271: // or-IN
		ret = "00000448";
		break;
	case 336235159924: // ta-IN
		ret = "00000449";
		break;
	case 336235160948: // te-IN
		ret = "0000044A";
		break;
	case 336235163243: // kn-IN
		ret = "0000044B";
		break;
	case 336235162733: // ml-IN
		ret = "0000044C";
		break;
	case 336235164513: // as-IN
		ret = "0000044D";
		break;
	case 336235164269: // mr-IN
		ret = "0000044E";
		break;
	case 336235159923: // sa-IN
		ret = "0000044F";
		break;
	case 336302272109: // mn-MN
		ret = "00000450";
		break;
	case 336134500194: // bo-CN
		ret = "00000451";
		break;
	case 284662004067: // cy-GB
		ret = "00000452";
		break;
	case 310498913643: // km-KH
		ret = "00000453";
		break;
	case 280450920300: // lo-LA
		ret = "00000454";
		break;
	case 332007307629: // my-MM
		ret = "00000455";
		break;
	case 357642890343: // gl-ES
		ret = "00000456";
		break;
	case 86076201594731: // kok-IN
		ret = "00000457";
		break;
	case 86076201463405: // mni-IN
		ret = "00000458";
		break;
	case 98213779634547: // syr-SY
		ret = "0000045A";
		break;
	case 323400591731: // si-LK
		ret = "0000045B";
		break;
	case 361937857889: // am-ET
		ret = "0000045E";
		break;
	case 27691691065308011: // ks-Arab
		ret = "00000460";
		break;
	case 344908981614: // ne-NP
		ret = "00000461";
		break;
	case 327729117542: // fy-NL
		ret = "00000462";
		break;
	case 301741208432: // ps-AF
		ret = "00000463";
		break;
	case 79509196663142: // fil-PH
		ret = "00000464";
		break;
	case 370662012516: // dv-MV
		ret = "00000465";
		break;
	case 78401095231842: // bin-NG
		ret = "00000466";
		break;
	case 78401095759206: // fuv-NG
		ret = "00000467";
		break;
	case 78401094443625: // ibb-NG
		ret = "00000469";
		break;
	case 306254278521: // yo-NG
		ret = "0000046A";
		break;
	case 87145649436017: // quz-BO
		ret = "0000046B";
		break;
	case 71855565140846: // nso-ZA
		ret = "0000046C";
		break;
	case 366450925922: // ba-RU
		ret = "0000046D";
		break;
	case 366350262892: // lb-LU
		ret = "0000046E";
		break;
	case 327611673707: // kl-GL
		ret = "0000046F";
		break;
	case 306254276457: // ig-NG
		ret = "00000470";
		break;
	case 306254279275: // kr-NG
		ret = "00000471";
		break;
	case 361937857903: // om-ET
		ret = "00000472";
		break;
	case 361937856884: // ti-ET
		ret = "00000473";
		break;
	case 383597244007: // gn-PY
		ret = "00000474";
		break;
	case 91625300124008: // haw-US
		ret = "00000475";
		break;
	case 31090208676864364: // la-Latn
		ret = "00000476";
		break;
	case 340697902963: // so-SO
		ret = "00000477";
		break;
	case 336134498665: // ii-CN
		ret = "00000478";
		break;
	case 16099256174666096: // pap-029
		ret = "00000479";
		break;
	case 83851408732769: // arn-CL
		ret = "0000047A";
		break;
	case 71756780433261: // moh-CA
		ret = "0000047C";
		break;
	case 353364701794: // br-FR
		ret = "0000047E";
		break;
	case 336134498165: // ug-CN
		ret = "00000480";
		break;
	case 387858655597: // mi-NZ
		ret = "00000481";
		break;
	case 353364697967: // oc-FR
		ret = "00000482";
		break;
	case 353364701027: // co-FR
		ret = "00000483";
		break;
	case 90461363991399: // gsw-FR
		ret = "00000484";
		break;
	case 93811437494643: // sah-RU
		ret = "00000485";
		break;
	case 92664682018161: // qut-GT
		ret = "00000486";
		break;
	case 375040866162: // rw-RW
		ret = "00000487";
		break;
	case 336402935671: // wo-SN
		ret = "00000488";
		break;
	case 77245749359216: // prs-AF
		ret = "0000048C";
		break;
	case 78396800658544: // plt-MG
		ret = "0000048D";
		break;
	case 284661998695: // gd-GB
		ret = "00000491";
		break;
	case 87149942895985: // quc-CO
		ret = "00000493";
		break;
	case 349120066145: // ar-IQ
		ret = "00000801";
		break;
	case 336134498426: // zh-CN
		ret = "00000804";
		break;
	case 310364693860: // de-CH
		ret = "00000807";
		break;
	case 284662001253: // en-GB
		ret = "00000809";
		break;
	case 379251946341: // es-MX
		ret = "0000080A";
		break;
	case 297463018086: // fr-BE
		ret = "0000080C";
		break;
	case 310364697705: // it-CH
		ret = "00000810";
		break;
	case 297463016558: // nl-BE
		ret = "00000813";
		break;
	case 340614016622: // nn-NO
		ret = "00000814";
		break;
	case 362122409072: // pt-PT
		ret = "00000816";
		break;
	case 293352599410: // ro-MD
		ret = "00000818";
		break;
	case 293352600946: // ru-MD
		ret = "00000819";
		break;
	case 314709997171: // sv-FI
		ret = "0000081D";
		break;
	case 336235164277: // ur-IN
		ret = "00000820";
		break;
	case 76159121519460: // dsb-DE
		ret = "0000082E";
		break;
	case 374772428404: // tn-BW
		ret = "00000832";
		break;
	case 297748227443: // se-SE
		ret = "0000083B";
		break;
	case 297580454247: // ga-IE
		ret = "0000083C";
		break;
	case 336117724013: // ms-BN
		ret = "0000083E";
		break;
	case 293168049762: // bn-BD
		ret = "00000845";
		break;
	case 323400589684: // ta-LK
		ret = "00000849";
		break;
	case 361887526754: // bo-BT
		ret = "00000851";
		break;
	case 27433250048537451: // ks-Deva
		ret = "00000860";
		break;
	case 336235160942: // ne-IN
		ret = "00000861";
		break;
	case 73964394804593: // quz-EC
		ret = "0000086B";
		break;
	case 353347922292: // ti-ER
		ret = "00000873";
		break;
	case 306103284321: // ar-EG
		ret = "00000C01";
		break;
	case 323333482618: // zh-HK
		ret = "00000C04";
		break;
	case 361870746980: // de-AT
		ret = "00000C07";
		break;
	case 366165716581: // en-AU
		ret = "00000C09";
		break;
	case 357642892133: // es-ES
		ret = "00000C0A";
		break;
	case 280299926118: // fr-CA
		ret = "00000C0C";
		break;
	case 314709992819: // se-FI
		ret = "00000C3B";
		break;
	case 361887529572: // dz-BT
		ret = "00000C51";
		break;
	case 71799731285364: // tmz-MA
		ret = "00000C5F";
		break;
	case 76210662700401: // quz-PE
		ret = "00000C6b";
		break;
	case 383530136161: // ar-LY
		ret = "00001001";
		break;
	case 306338162810: // zh-SG
		ret = "00001004";
		break;
	case 366350263652: // de-LU
		ret = "00001007";
		break;
	case 280299925093: // en-CA
		ret = "00001009";
		break;
	case 361971413861: // es-GT
		ret = "0000100A";
		break;
	case 310364697190: // fr-CH
		ret = "0000100C";
		break;
	case 280283148904: // hr-BA
		ret = "0000101A";
		break;
	case 87197187992947: // smj-NO
		ret = "0000103B";
		break;
	case 387690885729: // ar-DZ
		ret = "00001401";
		break;
	case 340597237882: // zh-MO
		ret = "00001404";
		break;
	case 314810656100: // de-LI
		ret = "00001407";
		break;
	case 387858656869: // en-NZ
		ret = "00001409";
		break;
	case 353314370405: // es-CR
		ret = "0000140A";
		break;
	case 366350266982: // fr-LU
		ret = "0000140C";
		break;
	case 76223546551667: // smj-SE
		ret = "0000143B";
		break;
	case 280467698273: // ar-MA
		ret = "00001801";
		break;
	case 297580457573: // en-IE
		ret = "00001809";
		break;
	case 280518030181: // es-PA
		ret = "0000180A";
		break;
	case 289057632870: // fr-MC
		ret = "0000180C";
		break;
	case 87197187403123: // sma-NO
		ret = "0000183B";
		break;
	case 336419713633: // ar-TN
		ret = "00001C01";
		break;
	case 280685801061: // en-ZA
		ret = "00001C09";
		break;
	case 340446245733: // es-DO
		ret = "00001C0A";
		break;
	case 76223545961843: // sma-SE
		ret = "00001C3B";
		break;
	case 332040860257: // ar-OM
		ret = "00002001";
		break;
	case 331956973157: // en-JM
		ret = "00002009";
		break;
	case 297798562661: // es-VE
		ret = "0000200A";
		break;
	case 297731453542: // fr-RE
		ret = "0000200C";
		break;
	case 80565759077747: // sms-FI
		ret = "0000203B";
		break;
	case 297848894049: // ar-YE
		ret = "00002401";
		break;
	case 62887719431781: // en-029
		ret = "00002409";
		break;
	case 340429468517: // es-CO
		ret = "0000240A";
		break;
	case 293184828006: // fr-CD
		ret = "0000240C";
		break;
	case 80565758750067: // smn-FI
		ret = "0000243B";
		break;
	case 383647576673: // ar-SY
		ret = "00002801";
		break;
	case 387657330277: // en-BZ
		ret = "00002809";
		break;
	case 297697899365: // es-PE
		ret = "0000280A";
		break;
	case 336402936422: // fr-SN
		ret = "0000280C";
		break;
	case 340546908769: // ar-JO
		ret = "00002C01";
		break;
	case 362189516389: // en-TT
		ret = "00002C09";
		break;
	case 353280815973: // es-AR
		ret = "00002C0A";
		break;
	case 331839533670: // fr-CM
		ret = "00002C0C";
		break;
	case 284745888353: // ar-LB
		ret = "00003001";
		break;
	case 375175081573: // en-ZW
		ret = "00003009";
		break;
	case 288923415397: // es-EC
		ret = "0000300A";
		break;
	case 314659664486: // fr-CI
		ret = "0000300C";
		break;
	case 374923424353: // ar-KW
		ret = "00003401";
		break;
	case 310582799973: // en-PH
		ret = "00003409";
		break;
	case 327544566629: // es-CL
		ret = "0000340A";
		break;
	case 327712338534: // fr-ML
		ret = "0000340C";
		break;
	case 297446240865: // ar-AE
		ret = "00003801";
		break;
	case 293285490277: // en-ID
		ret = "00003809";
		break;
	case 383681131365: // es-UY
		ret = "0000380A";
		break;
	case 280467698278: // fr-MA
		ret = "0000380C";
		break;
	case 310347919969: // ar-BH
		ret = "00003c01";
		break;
	case 323333484133: // en-HK
		ret = "00003c09";
		break;
	case 383597245285: // es-PY
		ret = "00003c0A";
		break;
	case 361988190822: // fr-HT
		ret = "00003c0C";
		break;
	case 280534807137: // ar-QA
		ret = "00004001";
		break;
	case 336235163237: // en-IN
		ret = "00004009";
		break;
	case 340412691301: // es-BO
		ret = "0000400A";
		break;
	case 383546912357: // en-MY
		ret = "00004409";
		break;
	case 370762675045: // es-SV
		ret = "0000440A";
		break;
	case 58498279633505: // ar-145
		ret = "00004801";
		break;
	case 306338164325: // en-SG
		ret = "00004809";
		break;
	case 336218387301: // es-HN
		ret = "0000480A";
		break;
	case 297446239845: // en-AE
		ret = "00004C09";
		break;
	case 314844214117: // es-NI
		ret = "00004C0A";
		break;
	case 310347918949: // en-BH
		ret = "00005009";
		break;
	case 353532474213: // es-PR
		ret = "0000500A";
		break;
	case 306103283301: // en-EG
		ret = "00005409";
		break;
	case 357911327589: // es-US
		ret = "0000540A";
		break;
	case 340546907749: // en-JO
		ret = "00005809";
		break;
	case 62883491574629: // es-419
		ret = "0000580A";
		break;
	case 374923423333: // en-KW
		ret = "00005C09";
		break;
	case 366199272293: // es-CU
		ret = "00005C0A";
		break;
	case 353599581797: // en-TR
		ret = "00006009";
		break;
	case 297848893029: // en-YE
		ret = "00006409";
		break;
	case 30525162628412258: // bs-Cyrl
		ret = "0000641A";
		break;
	case 31090208676868962: // bs-Latn
		ret = "0000681A";
		break;
	case 30525162628412019: // sr-Cyrl
		ret = "00006C1A";
		break;
	case 31090208676868723: // sr-Latn
		ret = "0000701A";
		break;
	case 7236979: // smn
		ret = "0000703B";
		break;
	case 30525162628414049: // az-Cyrl
		ret = "0000742C";
		break;
	case 7564659: // sms
		ret = "0000743B";
		break;
	case 26746: // zh
		ret = "00007804";
		break;
	case 28270: // nn
		ret = "00007814";
		break;
	case 29538: // bs
		ret = "0000781A";
		break;
	case 31090208676870753: // az-Latn
		ret = "0000782C";
		break;
	case 6385011: // sma
		ret = "0000783B";
		break;
	case 30525162628414069: // uz-Cyrl
		ret = "00007843";
		break;
	case 30525162628410989: // mn-Cyrl
		ret = "00007850";
		break;
	case 32490986339661161: // iu-Cans
		ret = "0000785D";
		break;
	case 32772461400254586: // zh-Hant
		ret = "00007C04";
		break;
	case 25198: // nb
		ret = "00007C14";
		break;
	case 29299: // sr
		ret = "00007C1A";
		break;
	case 30525162628409204: // tg-Cyrl
		ret = "00007C28";
		break;
	case 6452068: // dsb
		ret = "00007C2E";
		break;
	case 6974835: // smj
		ret = "00007C3B";
		break;
	case 31090208676870773: // uz-Latn
		ret = "00007C43";
		break;
	case 27691691065303408: // pa-Arab
		ret = "00007C46";
		break;
	case 29113346916445805: // mn-Mong
		ret = "00007C50";
		break;
	case 27691691065304179: // sd-Arab
		ret = "00007C59";
		break;
	case 31090208676869481: // iu-Latn
		ret = "00007C5D";
		break;
	case 31090208676865638: // ff-Latn
		ret = "00007C67";
		break;
	case 31090208676864360: // ha-Latn
		ret = "00007C68";
		break;
	case 8247321628869751653: // es-ES_tradnl
		ret = "0000040A";
		break;
	case 3273116894335166324: // tg-Cyrl-TJ
		ret = "00000428";
		break;
	case 3273681940383627873: // az-Latn-AZ
		ret = "0000042C";
		break;
	case 3273681940383627893: // uz-Latn-UZ
		ret = "00000443";
		break;
	case 3270024981755290739: // sd-Deva-IN
		ret = "00000459";
		break;
	case 8243109330706131043:
		switch (((int64_t*)val)[1])
		{
		case 0:     // chr-Cher
			ret = "00007C5C";
			break;
		case 5461293:     // chr-Cher-US
			ret = "0000045C";
			break;
		}
		break;
	case 3275082718046418281: // iu-Cans-CA
		ret = "0000045D";
		break;
	case 7089072912718461556: // tzm-Arab-MA
		ret = "0000045F";
		break;
	case 3273681940383621480: // ha-Latn-NG
		ret = "00000468";
		break;
	case 5200924699901388922: // zh-yue-HK
		ret = "0000048E";
		break;
	case 7308323309482173556: // tdd-Tale-CN
		ret = "0000048F";
		break;
	case 8461244814088890475: // khb-Talu-CN
		ret = "00000490";
		break;
	case 3270283422772065643: // ku-Arab-IQ
		ret = "00000492";
		break;
	case 7165064761224425585:
		switch (((int64_t*)val)[1])
		{
		case 109:     // qps-plocm
			ret = "000009FF";
			break;
		case 97:     // qps-ploca
			ret = "000005FE";
			break;
		case 0:     // qps-ploc
			ret = "00000501";
			break;
		}
		break;
	case 7022850504597004643: // ca-ES-valencia
		ret = "00000803";
		break;
	case 3270580265393414506: // ja-Ploc-JP
		ret = "00000811";
		break;
	case 3273681940383625843:
		switch (((int64_t*)val)[1])
		{
		case 17741:     // sr-Latn-ME
			ret = "00002C1A";
			break;
		case 21330:     // sr-Latn-RS
			ret = "0000241A";
			break;
		case 16706:     // sr-Latn-BA
			ret = "0000181A";
			break;
		case 21315:     // sr-Latn-CS
			ret = "0000081A";
			break;
		}
		break;
	case 3273116894335171169: // az-Cyrl-AZ
		ret = "0000082C";
		break;
	case 3273116894335171189: // uz-Cyrl-UZ
		ret = "00000843";
		break;
	case 3270283422772060528: // pa-Arab-PK
		ret = "00000846";
		break;
	case 3271705078623202925:
		switch (((int64_t*)val)[1])
		{
		case 20045:     // mn-Mong-MN
			ret = "00000C50";
			break;
		case 20035:     // mn-Mong-CN
			ret = "00000850";
			break;
		}
		break;
	case 3270283422772061299: // sd-Arab-PK
		ret = "00000859";
		break;
	case 3273681940383626601: // iu-Latn-CA
		ret = "0000085D";
		break;
	case 7959093421278067316:
		switch (((int64_t*)val)[1])
		{
		case 0:     // tzm-Latn
			ret = "00007C5F";
			break;
		case 5915693:     // tzm-Latn-DZ
			ret = "0000085F";
			break;
		}
		break;
	case 3273681940383622758: // ff-Latn-SN
		ret = "00000867";
		break;
	case 3273116894335169139:
		switch (((int64_t*)val)[1])
		{
		case 17741:     // sr-Cyrl-ME
			ret = "0000301A";
			break;
		case 21330:     // sr-Cyrl-RS
			ret = "0000281A";
			break;
		case 16706:     // sr-Cyrl-BA
			ret = "00001C1A";
			break;
		case 21315:     // sr-Cyrl-CS
			ret = "00000C1A";
			break;
		}
		break;
	case 7453006945070185076:
		switch (((int64_t*)val)[1])
		{
		case 0:     // tzm-Tfng
			ret = "0000785F";
			break;
		case 4279597:     // tzm-Tfng-MA
			ret = "0000105F";
			break;
		}
		break;
	case 3273681940383626082: // bs-Latn-BA
		ret = "0000141A";
		break;
	case 3273116894335169378: // bs-Cyrl-BA
		ret = "0000201A";
		break;
	case 3270580265393418849: // ar-Ploc-SA
		ret = "00004401";
		break;
	}



	return(ret);
}


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
	case MNG_KVM_KEY_WITHLAYOUT:
		if (size != 22) { break; }
		char *klayout = kvm_getKeyboardLayoutCode(block + 6, 22);
		if (klayout != NULL)
		{
			char current[KL_NAMELENGTH + 1];
			if (GetKeyboardLayoutNameA(current) != 0 && strcmp(current, klayout) == 0)
			{
				// Current keyboard layour matches the intended layout
				KeyAction(block[5], block[4]);
			}
			else
			{
				HKL kb = LoadKeyboardLayoutA(klayout, KLF_ACTIVATE | KLF_REORDER);
				if (kb != NULL)
				{
					KeyActionEx(block[5], block[4], kb);
					UnloadKeyboardLayout(kb);
				}
			}
		}
		break;
	case MNG_KVM_KEY: // Key
		{
			if (size != 6) break;
			KeyAction(block[5], block[4]);
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

//void __stdcall kvm_relay_feeddata_ex_APC(ULONG_PTR data)
//{
//	kvm_data_handler *k = (kvm_data_handler*)data;
//
//	k->handler(k->buffer, k->len, k->reserved);
//	free((void*)data);
//}
//ILibTransport_DoneState kvm_relay_feeddata_ex(char *buf, int len, void *reserved)
//{
//	kvm_data_handler *data = (kvm_data_handler*)ILibMemory_Allocate(sizeof(kvm_data_handler) + len, 0, NULL, NULL);
//	data->handler = (ILibKVM_WriteHandler)((void**)reserved)[0];
//	data->reserved = ((void**)reserved)[1];
//	data->len = len;
//	memcpy_s(data->buffer, len, buf, len);
//
//	QueueUserAPC((PAPCFUNC)kvm_relay_feeddata_ex_APC, kvmthread, (ULONG_PTR)data);
//}

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
			ILibProcessPipe_Pipe_Resume(ILibProcessPipe_Process_GetStdOut(gChildProcess));
		}
		else
		{
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


#ifdef _WINSERVICE
	if (!kvmConsoleMode)
	{
		g_shutdown = 0;
		kvmthread = CreateThread(NULL, 0, kvm_mainloopinput, parm, 0, 0);
	}
#endif

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
	while (!g_shutdown)
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
			KVMDEBUG("get_desktop_buffer() failed, shutting down", (int)GetCurrentThreadId());
			g_shutdown = 1;
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
						switch (writeHandler((char*)buf, (int)tilesize, reserved))
						{
							case ILibTransport_DoneState_INCOMPLETE:
								g_pause = 1;
								ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_2, "Agent KVM: KVM PAUSE");
								break;
							case ILibTransport_DoneState_ERROR:
								g_shutdown = 1; 
								height = SCALED_HEIGHT; 
								width = SCALED_WIDTH; 
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

	// if (kvmthread != NULL) { CloseHandle(kvmthread); kvmthread = NULL; }
	if (tileInfo != NULL) {
		for (row = 0; row < TILE_HEIGHT_COUNT; row++) free(tileInfo[row]);
		free(tileInfo);
		tileInfo = NULL;
	}
	KVMDEBUG("kvm_server_mainloop / end1", (int)GetCurrentThreadId());
	teardown_gdiplus();

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
		if (ntohs(((unsigned short*)(buffer))[0]) == (unsigned short)MNG_JUMBO)
		{
			if (bufferLen > 8)
			{
				if (bufferLen >= (size_t)(8 + (int)ntohl(((unsigned int*)(buffer))[1])))
				{
					*bytesConsumed = 8 + (int)ntohl(((unsigned int*)(buffer))[1]);
					writeHandler(buffer, (int)*bytesConsumed, reserved);
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
	KVMDEBUG("kvm_relay_restart / end", (int)kvmthread);

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
