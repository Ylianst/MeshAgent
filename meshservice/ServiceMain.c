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

#if defined(WINSOCK2)
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(WINSOCK1)
#include <winsock.h>
#include <wininet.h>
#endif

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include "resource.h"
#include "meshcore/signcheck.h"
#include "meshcore/meshdefines.h"
#include "meshcore/meshinfo.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibCrypto.h"
#include "meshcore/agentcore.h"
#include "microscript/ILibDuktape_ScriptContainer.h"
#include "microscript/ILibDuktape_Commit.h"
#include <shellscalingapi.h>

#if defined(WIN32) && defined (_DEBUG) && !defined(_MINCORE)
#include <crtdbg.h>
#define _CRTDBG_MAP_ALLOC
#endif

#include <WtsApi32.h>

TCHAR* serviceFile = TEXT("Mesh Agent");
TCHAR* serviceName = TEXT("Mesh Agent background service");

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle = 0;
INT_PTR CALLBACK DialogHandler(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK DialogHandler2(HWND, UINT, WPARAM, LPARAM);

MeshAgentHostContainer *agent = NULL;
DWORD g_serviceArgc;
char **g_serviceArgv;
extern int gRemoteMouseRenderDefault;
char *DIALOG_LANG = NULL;

HBRUSH DialogBackgroundBrush = NULL;
duk_context *g_dialogCtx = NULL;
char *g_dialogLanguage = NULL;
void *g_dialogTranslationObject = NULL;
char image_b64[] = "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";

/*
extern int g_TrustedHashSet;
extern char g_TrustedHash[32];
extern char NullNodeId[32];
extern struct PolicyInfoBlock* g_TrustedPolicy;
extern char g_selfid[UTIL_HASHSIZE];
extern struct sockaddr_in6 g_ServiceProxy;
extern char* g_ServiceProxyHost;
extern int g_ServiceConnectFlags;
*/


#if defined(_LINKVM)
extern DWORD WINAPI kvm_server_mainloop(LPVOID Param);
#endif

#include <Shlwapi.h>
#define SmoothingModeAntiAlias 5
#define InterpolationModeBicubic 8


HMODULE _gdip = NULL;
HMODULE _shm = NULL;
typedef int(__stdcall *_GdipCreateBitmapFromStream)(void *stream, void **bitmap);
typedef int(__stdcall *_GdiplusStartup)(void **token, void *input, void *obj);
typedef int(__stdcall *_GdiplusShutdown)(void *token);
typedef IStream*(__stdcall *_SHCreateMemStream)(void *buffer, uint32_t bufferLen);
typedef int(__stdcall *_GdipCreateHBITMAPFromBitmap)(void *bitmap, HBITMAP *hbReturn, int background);
typedef int(__stdcall *_GdipGetImagePixelFormat)(void *image, int *format);
typedef int(__stdcall *_GdipCreateBitmapFromScan0)(int width, int height, int stride, int format, BYTE* scan0, void** bitmap);
typedef int(__stdcall *_GdipGetImageHorizontalResolution)(void *image, float *resolution);
typedef int(__stdcall *_GdipGetImageVerticalResolution)(void *image, float *resolution);
typedef int(__stdcall *_GdipBitmapSetResolution)(void* bitmap, float xdpi, float ydpi);
typedef int(__stdcall *_GdipGetImageGraphicsContext)(void *image, void **graphics);
typedef int(__stdcall *_GdipSetSmoothingMode)(void *graphics, int smoothingMode);
typedef int(__stdcall *_GdipSetInterpolationMode)(void *graphics, int interpolationMode);
typedef int(__stdcall *_GdipDrawImageRectI)(void *graphics, void *image, int x, int y, int width, int height);
typedef int(__stdcall *_GdipDisposeImage)(void *image);
typedef HRESULT(__stdcall *DpiAwarenessFunc)(PROCESS_DPI_AWARENESS);

_GdipCreateBitmapFromStream __GdipCreateBitmapFromStream;
_GdipCreateHBITMAPFromBitmap __GdipCreateHBITMAPFromBitmap;
_GdipGetImagePixelFormat __GdipGetImagePixelFormat;
_GdipCreateBitmapFromScan0 __GdipCreateBitmapFromScan0;
_GdipGetImageHorizontalResolution __GdipGetImageHorizontalResolution;
_GdipGetImageVerticalResolution __GdipGetImageVerticalResolution;
_GdipBitmapSetResolution __GdipBitmapSetResolution;
_GdipGetImageGraphicsContext __GdipGetImageGraphicsContext;
_GdipSetSmoothingMode __GdipSetSmoothingMode;
_GdipSetInterpolationMode __GdipSetInterpolationMode;
_GdipDrawImageRectI __GdipDrawImageRectI;
_GdipDisposeImage __GdipDisposeImage;
_GdiplusShutdown __GdiplusShutdown;

_GdiplusStartup __GdiplusStartup;
_SHCreateMemStream __SHCreateMemStream2;
void *GdiPlusToken = NULL;

#if defined _M_IX86
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

void GdiPlusFlat_Init()
{
	INITCOMMONCONTROLSEX icex;		// declare an INITCOMMONCONTROLSEX Structure
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_BAR_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_PROGRESS_CLASS;   // This is needed for tooltips  									
	BOOL _ok = InitCommonControlsEx(&icex);

	char input[24] = { 0 };
	_gdip = LoadLibraryExW(L"Gdiplus.dll", NULL, LOAD_LIBRARY_SEARCH_USER_DIRS);
	if (_gdip == NULL) { _gdip = LoadLibraryExW(L"Gdiplus.dll", NULL, 0); }
	if (_gdip == NULL) { return; }
	_shm = LoadLibraryExW(L"Shlwapi.dll", NULL, LOAD_LIBRARY_SEARCH_USER_DIRS);
	if (_shm == NULL) { _gdip = LoadLibraryExW(L"Shlwapi.dll", NULL, 0); }
	if (_shm == NULL) { FreeLibrary(_gdip); _gdip = NULL; return; }

	__GdipCreateBitmapFromStream = (_GdipCreateBitmapFromStream)GetProcAddress(_gdip, (LPCSTR)"GdipCreateBitmapFromStream");
	__GdiplusStartup = (_GdiplusStartup)GetProcAddress(_gdip, (LPCSTR)"GdiplusStartup");
	__SHCreateMemStream2 = (_SHCreateMemStream)GetProcAddress(_shm, (LPCSTR)"SHCreateMemStream");
	__GdipCreateHBITMAPFromBitmap = (_GdipCreateHBITMAPFromBitmap)GetProcAddress(_gdip, (LPCSTR)"GdipCreateHBITMAPFromBitmap");
	__GdipGetImagePixelFormat = (_GdipGetImagePixelFormat)GetProcAddress(_gdip, (LPCSTR)"GdipGetImagePixelFormat");
	__GdipCreateBitmapFromScan0 = (_GdipCreateBitmapFromScan0)GetProcAddress(_gdip, (LPCSTR)"GdipCreateBitmapFromScan0");
	__GdipGetImageHorizontalResolution = (_GdipGetImageHorizontalResolution)GetProcAddress(_gdip, (LPCSTR)"GdipGetImageHorizontalResolution");
	__GdipGetImageVerticalResolution = (_GdipGetImageVerticalResolution)GetProcAddress(_gdip, (LPCSTR)"GdipGetImageVerticalResolution");
	__GdipBitmapSetResolution = (_GdipBitmapSetResolution)GetProcAddress(_gdip, (LPCSTR)"GdipBitmapSetResolution");
	__GdipGetImageGraphicsContext = (_GdipGetImageGraphicsContext)GetProcAddress(_gdip, (LPCSTR)"GdipGetImageGraphicsContext");
	__GdipSetSmoothingMode = (_GdipSetSmoothingMode)GetProcAddress(_gdip, (LPCSTR)"GdipSetSmoothingMode");
	__GdipSetInterpolationMode = (_GdipSetInterpolationMode)GetProcAddress(_gdip, (LPCSTR)"GdipSetInterpolationMode");
	__GdipDrawImageRectI = (_GdipDrawImageRectI)GetProcAddress(_gdip, (LPCSTR)"GdipDrawImageRectI");
	__GdipDisposeImage = (_GdipDisposeImage)GetProcAddress(_gdip, (LPCSTR)"GdipDisposeImage");
	__GdiplusShutdown = (_GdiplusShutdown)GetProcAddress(_gdip, (LPCSTR)"GdiplusShutdown");

	((uint32_t*)input)[0] = 1;
	__GdiplusStartup(&GdiPlusToken, input, NULL);
}
void GdiPlusFlat_Release()
{
	if (GdiPlusToken != NULL) { __GdiplusShutdown(GdiPlusToken); GdiPlusToken = NULL; }
	if (_gdip != NULL) { FreeLibrary(_gdip); _gdip = NULL; }
	if (_shm != NULL) { FreeLibrary(_shm); _shm = NULL; }
}

BOOL IsAdmin()
{
	BOOL admin = 0;
	PSID AdministratorsGroup;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

	if ((admin = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) != 0)
	{
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &admin)) admin = FALSE;
		FreeSid(AdministratorsGroup);
	}
	return admin;
}

BOOL RunAsAdmin(char* args, int isAdmin)
{
	WCHAR szPath[_MAX_PATH + 100];
	if (GetModuleFileNameW(NULL, szPath, sizeof(szPath) / 2))
	{
		SHELLEXECUTEINFOW sei = { sizeof(sei) };
		sei.hwnd = NULL;
		sei.nShow = SW_NORMAL;
		sei.lpVerb = isAdmin ? L"open" : L"runas";
		sei.lpFile = szPath;
		sei.lpParameters = ILibUTF8ToWide(args, -1);
		return ShellExecuteExW(&sei);
	}
	return FALSE;
}

DWORD WINAPI ServiceControlHandler(DWORD controlCode, DWORD eventType, void *eventData, void* eventContext)
{
	switch (controlCode)
	{
	case SERVICE_CONTROL_INTERROGATE:
		break;
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
		if (agent != NULL) { MeshAgent_Stop(agent); }
		return(0);
	case SERVICE_CONTROL_POWEREVENT:
		switch (eventType)
		{
		case PBT_APMPOWERSTATUSCHANGE:	// Power status has changed.
			break;
		case PBT_APMRESUMEAUTOMATIC:	// Operation is resuming automatically from a low - power state.This message is sent every time the system resumes.
			break;
		case PBT_APMRESUMESUSPEND:		// Operation is resuming from a low - power state.This message is sent after PBT_APMRESUMEAUTOMATIC if the resume is triggered by user input, such as pressing a key.
			break;
		case PBT_APMSUSPEND:			// System is suspending operation.
			break;
		case PBT_POWERSETTINGCHANGE:	// Power setting change event has been received.
			break;
		}
		break;
	case SERVICE_CONTROL_SESSIONCHANGE:
		if (agent == NULL)
		{
			break; // If there isn't an agent, no point in doing anything, cuz nobody will hear us
		}

		switch (eventType)
		{
		case WTS_CONSOLE_CONNECT:		// The session identified by lParam was connected to the console terminal or RemoteFX session.
			break;
		case WTS_CONSOLE_DISCONNECT:	// The session identified by lParam was disconnected from the console terminal or RemoteFX session.
			break;
		case WTS_REMOTE_CONNECT:		// The session identified by lParam was connected to the remote terminal.
			break;
		case WTS_REMOTE_DISCONNECT:		// The session identified by lParam was disconnected from the remote terminal.
			break;
		case WTS_SESSION_LOGON:			// A user has logged on to the session identified by lParam.
		case WTS_SESSION_LOGOFF:		// A user has logged off the session identified by lParam.					
			break;
		case WTS_SESSION_LOCK:			// The session identified by lParam has been locked.
			break;
		case WTS_SESSION_UNLOCK:		// The session identified by lParam has been unlocked.
			break;
		case WTS_SESSION_REMOTE_CONTROL:// The session identified by lParam has changed its remote controlled status.To determine the status, call GetSystemMetrics and check the SM_REMOTECONTROL metric.
			break;
		case WTS_SESSION_CREATE:		// Reserved for future use.
		case WTS_SESSION_TERMINATE:		// Reserved for future use.
			break;
		}
		break;
	default:
		break;
	}

	SetServiceStatus(serviceStatusHandle, &serviceStatus);
	return(0);
}


void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	ILib_DumpEnabledContext winException;
	size_t len = 0;
	WCHAR str[_MAX_PATH];


	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	// Initialise service status
	serviceStatus.dwServiceType = SERVICE_WIN32;
	serviceStatus.dwCurrentState = SERVICE_STOPPED;
	serviceStatus.dwControlsAccepted = 0;
	serviceStatus.dwWin32ExitCode = NO_ERROR;
	serviceStatus.dwServiceSpecificExitCode = NO_ERROR;
	serviceStatus.dwCheckPoint = 0;
	serviceStatus.dwWaitHint = 0;
	serviceStatusHandle = RegisterServiceCtrlHandlerExA(serviceName, (LPHANDLER_FUNCTION_EX)ServiceControlHandler, NULL);

	if (serviceStatusHandle)
	{
		// Service is starting
		serviceStatus.dwCurrentState = SERVICE_START_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);

		// Service running
		serviceStatus.dwControlsAccepted |= (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE);
		serviceStatus.dwCurrentState = SERVICE_RUNNING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);

		// Get our own executable name
		GetModuleFileNameW(NULL, str, _MAX_PATH);


		// Run the mesh agent
		CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

		__try
		{
			agent = MeshAgent_Create(0);
			agent->serviceReserved = 1;
			MeshAgent_Start(agent, g_serviceArgc, g_serviceArgv);
			agent = NULL;
		}
		__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winException))
		{
			ILib_WindowsExceptionDebugEx(&winException);
		}
		CoUninitialize();

		// Service was stopped
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);

		// Service is now stopped
		serviceStatus.dwControlsAccepted &= ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
	}
}

int RunService(int argc, char* argv[])
{
	SERVICE_TABLE_ENTRY serviceTable[2];
	serviceTable[0].lpServiceName = serviceName;
	serviceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
	serviceTable[1].lpServiceName = NULL;
	serviceTable[1].lpServiceProc = NULL;
	g_serviceArgc = argc;
	g_serviceArgv = argv;

	return StartServiceCtrlDispatcher(serviceTable);
}

// SERVICE_STOPPED				  1    The service is not running.
// SERVICE_START_PENDING		  2    The service is starting.
// SERVICE_STOP_PENDING			  3    The service is stopping.
// SERVICE_RUNNING				  4    The service is running.
// SERVICE_CONTINUE_PENDING		  5    The service continue is pending.
// SERVICE_PAUSE_PENDING		  6    The service pause is pending.
// SERVICE_PAUSED				  7    The service is paused.
// SERVICE_NOT_INSTALLED		100    The service is not installed.
int GetServiceState(LPCSTR servicename)
{
	int r = 0;
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService(serviceControlManager, servicename, SERVICE_QUERY_STATUS);
		if (service)
		{
			SERVICE_STATUS serviceStatusEx;
			if (QueryServiceStatus(service, &serviceStatusEx))
			{
				r = serviceStatusEx.dwCurrentState;
			}
			CloseServiceHandle(service);
		}
		else
		{
			r = 100;
		}
		CloseServiceHandle(serviceControlManager);
	}
	return r;
}


/*
int APIENTRY _tWinMain(HINSTANCE hInstance,
					 HINSTANCE hPrevInstance,
					 LPTSTR    lpCmdLine,
					 int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	return _tmain( 0, NULL );
}
*/


ILibTransport_DoneState kvm_serviceWriteSink(char *buffer, int bufferLen, void *reserved)
{
	DWORD len;
	WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buffer, bufferLen, &len, NULL);
	return ILibTransport_DoneState_COMPLETE;
}
BOOL CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	{
		if (agent != NULL) { MeshAgent_Stop(agent); }
		return TRUE;
	}
	default:
		return FALSE;
	}
}

#define wmain_free(argv) for(argvi=0;argvi<(int)(ILibMemory_Size(argv)/sizeof(void*));++argvi){ILibMemory_Free(argv[argvi]);}ILibMemory_Free(argv);

void need_stop_chain(duk_context *ctx, void *user)
{
	void *chain = duk_ctx_chain(ctx);
	ILibStopChain(chain);
}

duk_ret_t _start(duk_context *ctx)
{
	duk_push_global_object(ctx);
	if (Duktape_GetBooleanProperty(ctx, -1, "_OK", 0))
	{
		duk_get_prop_string(ctx, -1, "_start_data");
		FreeConsole();
		GdiPlusFlat_Init();
		DialogBoxW(NULL, MAKEINTRESOURCEW(IDD_INSTALLDIALOG), NULL, DialogHandler);
		GdiPlusFlat_Release();
	}
	duk_eval_string_noresult(ctx, "process._exit();");

	return(0);
}

int wmain(int argc, char* wargv[])
{
	size_t str2len = 0;// , proxylen = 0, taglen = 0;
	ILib_DumpEnabledContext winException;
	int retCode = 0;

	int argvi, argvsz;
	char **argv = (char**)ILibMemory_SmartAllocate((argc + 1) * sizeof(void*));
	for (argvi = 0; argvi < argc; ++argvi)
	{
		argvsz = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wargv[argvi], -1, NULL, 0, NULL, NULL);
		argv[argvi] = (char*)ILibMemory_SmartAllocate(argvsz);
		WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wargv[argvi], -1, argv[argvi], argvsz, NULL, NULL);
	}

	if (argc > 1 && (strcasecmp(argv[1], "-finstall") == 0 || strcasecmp(argv[1], "-funinstall") == 0 ||
		strcasecmp(argv[1], "-fulluninstall") == 0 || strcasecmp(argv[1], "-fullinstall") == 0 ||
		strcasecmp(argv[1], "-install") == 0 || strcasecmp(argv[1], "-uninstall") == 0 ||
		strcasecmp(argv[1], "-state") == 0))
	{
		argv[argc] = argv[1];
		argv[1] = (char*)ILibMemory_SmartAllocate(4);
		sprintf_s(argv[1], ILibMemory_Size(argv[1]), "run");
		argc += 1;
	}

	/*
#ifndef NOMESHCMD
	// Check if this is a Mesh command operation
	if (argc >= 1 && strlen(argv[0]) >= 7 && strcasecmp(argv[0] + strlen(argv[0]) - 7, "meshcmd") == 0) return MeshCmd_ProcessCommand(argc, argv, 1);
	if (argc >= 2 && strcasecmp(argv[1], "meshcmd") == 0) return MeshCmd_ProcessCommand(argc, argv, 2);
#endif
	*/

	//CoInitializeEx(NULL, COINIT_MULTITHREADED);
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
	char *integratedJavaScript = NULL;
	int integragedJavaScriptLen = 0;

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
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}

	if (argc > 2 && strcasecmp(argv[1], "-faddr") == 0)
	{
#ifdef WIN64
		uint64_t addrOffset = 0;
		sscanf_s(argv[2] + 2, "%016llx", &addrOffset);
#else
		uint32_t addrOffset = 0;
		sscanf_s(argv[2] + 2, "%x", &addrOffset);
#endif
		ILibChain_DebugOffset(ILibScratchPad, sizeof(ILibScratchPad), (uint64_t)addrOffset);
		printf("%s", ILibScratchPad);
		wmain_free(argv);
		return(0);
	}

	if (argc > 2 && strcasecmp(argv[1], "-fdelta") == 0)
	{
		uint64_t delta = 0;
		sscanf_s(argv[2], "%lld", &delta);
		ILibChain_DebugDelta(ILibScratchPad, sizeof(ILibScratchPad), delta);
		printf("%s", ILibScratchPad);
		wmain_free(argv);
		return(0);
	}

	if (integratedJavaScript == NULL || integragedJavaScriptLen == 0)
	{
		ILibDuktape_ScriptContainer_CheckEmbedded(&integratedJavaScript, &integragedJavaScriptLen);
	}

	if (argc > 1 && strcmp(argv[1], "-export") == 0 && integragedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy("require('code-utils').expand({embedded: true});process.exit();", 0);
		integragedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	}
	if (argc > 1 && strcmp(argv[1], "-import") == 0 && integragedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy("require('code-utils').shrink();process.exit();", 0);
		integragedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	}

	if (argc > 2 && strcmp(argv[1], "-exec") == 0 && integragedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy(argv[2], 0);
		integragedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	}
	if (argc > 2 && strcmp(argv[1], "-b64exec") == 0 && integragedJavaScriptLen == 0)
	{
		integragedJavaScriptLen = ILibBase64Decode((unsigned char *)argv[2], (const int)strnlen_s(argv[2], sizeof(ILibScratchPad2)), (unsigned char**)&integratedJavaScript);
	}
	if (argc > 1 && strcasecmp(argv[1], "-nodeid") == 0)
	{
		char script[] = "console.log(require('_agentNodeId')());process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-name") == 0)
	{
		char script[] = "console.log(require('_agentNodeId').serviceName());process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && (strcasecmp(argv[1], "exstate") == 0))
	{
		char script[] = "var r={rawState: -1, state: 'NOT INSTALLED'};try{r=require('service-manager').manager.getService(require('_agentNodeId').serviceName()).status;}catch(z){};console.log(r.state);process.exit(r.rawState);";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && (strcasecmp(argv[1], "state") == 0))
	{
		char script[] = "try{console.log(require('service-manager').manager.getService(require('_agentNodeId').serviceName()).status.state);}catch(z){console.log('NOT INSTALLED');};process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && (strcasecmp(argv[1], "start") == 0 || strcasecmp(argv[1], "-start") == 0))
	{
		char script[] = "try{require('service-manager').manager.getService(require('_agentNodeId').serviceName()).start();console.log('Service Started');}catch(z){console.log('Failed to start service');}process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && (strcasecmp(argv[1], "stop") == 0 || strcasecmp(argv[1], "-stop") == 0))
	{
		char script[] = "try{require('service-manager').manager.getService(require('_agentNodeId').serviceName()).stop().then(function(m){console.log('Service Stopped');process.exit();}, function(m){console.log(m);process.exit();});}catch(z){console.log('Failed to stop service');process.exit();}";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && (strcasecmp(argv[1], "restart") == 0 || strcasecmp(argv[1], "-restart") == 0))
	{
		char script[] = "try{require('service-manager').manager.getService(require('_agentNodeId').serviceName()).restart().then(function(m){console.log('Service Restarted');process.exit();}, function(m){console.log(m);process.exit();});}catch(z){console.log('Failed to restart service');process.exit();}";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}

	if (argc > 1 && strcasecmp(argv[1], "-agentHash") == 0 && integragedJavaScriptLen == 0)
	{
		char script[] = "console.log(getSHA384FileHash(process.execPath).toString('hex').substring(0,16));process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-agentFullHash") == 0 && integragedJavaScriptLen == 0)
	{
		char script[] = "console.log(getSHA384FileHash(process.execPath).toString('hex'));process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc == 2 && (strcasecmp(argv[1], "-resetnodeid") == 0))
	{
		// Set "resetnodeid" in registry
		char script[] = "try{require('_agentNodeId').resetNodeId();}catch(z){console.log('This command requires admin.');}process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && (strcasecmp(argv[1], "-setfirewall") == 0))
	{
		// Reset the firewall rules
		char script[] = "require('agent-installer').setfirewall();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && (strcasecmp(argv[1], "-clearfirewall") == 0))
	{
		// Clear the firewall rules
		char script[] = "require('agent-installer').clearfirewall();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && (strcasecmp(argv[1], "-checkfirewall") == 0))
	{
		// Clear the firewall rules
		char script[] = "require('agent-installer').checkfirewall();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (argc > 1 && strcasecmp(argv[1], "-updaterversion") == 0)
	{
		DWORD dummy;
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "1\n", 2, &dummy, NULL);
		wmain_free(argv);
		return(0);
	}
#if defined(_LINKVM)
	if (argc > 1 && strcasecmp(argv[1], "-kvm0") == 0)
	{
		void **parm = (void**)ILibMemory_Allocate(4 * sizeof(void*), 0, 0, NULL);
		parm[0] = kvm_serviceWriteSink;
		((int*)&(parm[2]))[0] = 0;
		((int*)&(parm[3]))[0] = (argc > 2 && strcasecmp(argv[2], "-coredump") == 0) ? 1 : 0;
		if ((argc > 2 && strcasecmp(argv[2], "-remotecursor") == 0) ||
			(argc > 3 && strcasecmp(argv[3], "-remotecursor") == 0))
		{
			gRemoteMouseRenderDefault = 1;
		}

		// This is only supported on Windows 8 / Windows Server 2012 R2 and newer
		HMODULE shCORE = LoadLibraryExA((LPCSTR)"Shcore.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
		DpiAwarenessFunc dpiAwareness = NULL;
		if (shCORE != NULL)
		{
			if ((dpiAwareness = (DpiAwarenessFunc)GetProcAddress(shCORE, (LPCSTR)"SetProcessDpiAwareness")) == NULL)
			{
				FreeLibrary(shCORE);
				shCORE = NULL;
			}
		}
		if (dpiAwareness != NULL)
		{
			dpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);
			FreeLibrary(shCORE);
			shCORE = NULL;
		}
		else
		{
			SetProcessDPIAware();
		}

		kvm_server_mainloop((void*)parm);
		wmain_free(argv);
		return 0;
	}
	else if (argc > 1 && strcasecmp(argv[1], "-kvm1") == 0)
	{
		void **parm = (void**)ILibMemory_Allocate(4 * sizeof(void*), 0, 0, NULL);
		parm[0] = kvm_serviceWriteSink;
		((int*)&(parm[2]))[0] = 1;
		((int*)&(parm[3]))[0] = (argc > 2 && strcasecmp(argv[2], "-coredump") == 0) ? 1 : 0;
		if ((argc > 2 && strcasecmp(argv[2], "-remotecursor") == 0) ||
			(argc > 3 && strcasecmp(argv[3], "-remotecursor") == 0))
		{
			gRemoteMouseRenderDefault = 1;
		}

		// This is only supported on Windows 8 / Windows Server 2012 R2 and newer
		HMODULE shCORE = LoadLibraryExA((LPCSTR)"Shcore.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
		DpiAwarenessFunc dpiAwareness = NULL;
		if (shCORE != NULL)
		{
			if ((dpiAwareness = (DpiAwarenessFunc)GetProcAddress(shCORE, (LPCSTR)"SetProcessDpiAwareness")) == NULL)
			{
				FreeLibrary(shCORE);
				shCORE = NULL;
			}
		}
		if (dpiAwareness != NULL)
		{
			dpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);
			FreeLibrary(shCORE);
			shCORE = NULL;
		}
		else
		{
			SetProcessDPIAware();
		}


		kvm_server_mainloop((void*)parm);
		wmain_free(argv);
		return 0;
	}
#endif	
	if (integratedJavaScript != NULL || (argc > 0 && strcasecmp(argv[0], "--slave") == 0) || (argc > 1 && ((strcasecmp(argv[1], "run") == 0) || (strcasecmp(argv[1], "connect") == 0) || (strcasecmp(argv[1], "--slave") == 0))))
	{
		// Run the mesh agent in console mode, since the agent is compiled for windows service, the KVM will not work right. This is only good for testing.
		SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE); // Set SIGNAL on windows to listen for Ctrl-C

		__try
		{
			int capabilities = 0;
			if (argc > 1 && ((strcasecmp(argv[1], "connect") == 0))) { capabilities = MeshCommand_AuthInfo_CapabilitiesMask_TEMPORARY; }
			agent = MeshAgent_Create(capabilities);
			agent->meshCoreCtx_embeddedScript = integratedJavaScript;
			agent->meshCoreCtx_embeddedScriptLen = integragedJavaScriptLen;
			if (integratedJavaScript != NULL || (argc > 1 && (strcasecmp(argv[1], "run") == 0 || strcasecmp(argv[1], "connect") == 0))) { agent->runningAsConsole = 1; }
			MeshAgent_Start(agent, argc, argv);
			retCode = agent->exitCode;
			MeshAgent_Destroy(agent);
			agent = NULL;
		}
		__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winException))
		{
			ILib_WindowsExceptionDebugEx(&winException);
		}
		wmain_free(argv);
		return(retCode);
	}
	else if (argc > 1 && memcmp(argv[1], "-update:", 8) == 0)
	{
		char *update = ILibMemory_Allocate(1024, 0, NULL, NULL);
		int updateLen;

		if (argv[1][8] == '*')
		{
			// New Style
			updateLen = sprintf_s(update, 1024, "require('agent-installer').update(%s, '%s');", argv[1][9] == 'S' ? "true" : "false", argc > 2 ? argv[2] : "null");
		}
		else
		{
			// Legacy
			if (argc > 2 && (strcmp(argv[2], "run") == 0 || strcmp(argv[2], "connect") == 0))
			{
				// Console Mode
				updateLen = sprintf_s(update, 1024, "require('agent-installer').update(false, ['%s']);", argv[2]);
			}
			else
			{
				// Service
				updateLen = sprintf_s(update, 1024, "require('agent-installer').update(true);");
			}
		}

		__try
		{
			agent = MeshAgent_Create(0);
			agent->meshCoreCtx_embeddedScript = update;
			agent->meshCoreCtx_embeddedScriptLen = updateLen;
			MeshAgent_Start(agent, argc, argv);
			retCode = agent->exitCode;
			MeshAgent_Destroy(agent);
			agent = NULL;
		}
		__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winException))
		{
			ILib_WindowsExceptionDebugEx(&winException);
		}
		wmain_free(argv);
		return(retCode);
	}
#ifndef _MINCORE
	else if (argc > 1 && (strcasecmp(argv[1], "-netinfo") == 0))
	{
		char* data;
		int len = MeshInfo_GetSystemInformation(&data);
		if (len > 0) { printf_s(data); }
	}
#endif
	else
	{
		int skip = 0;

		// See if we are running as a service
		if (RunService(argc, argv) == 0 && GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
		{
			// Not running as service, so check if we need to run as a script engine
			if (argc >= 2 && (ILibString_EndsWith(argv[1], -1, ".js", 3) != 0 || ILibString_EndsWith(argv[1], -1, ".zip", 4) != 0))
			{
				SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE); // Set SIGNAL on windows to listen for Ctrl-C

				__try
				{
					agent = MeshAgent_Create(0);
					agent->runningAsConsole = 1;
					MeshAgent_Start(agent, argc, argv);
					MeshAgent_Destroy(agent);
					agent = NULL;
				}
				__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winException))
				{
					ILib_WindowsExceptionDebugEx(&winException);
				}
			}
			else
			{
				if (argc == 2 && strcmp(argv[1], "-lang") == 0)
				{
					char *lang = NULL;
					char selfexe[_MAX_PATH];
					WCHAR wselfexe[MAX_PATH];
					GetModuleFileNameW(NULL, wselfexe, sizeof(wselfexe) / 2);
					ILibWideToUTF8Ex(wselfexe, -1, selfexe, (int)sizeof(selfexe));


					void *dialogchain = ILibCreateChain();
					ILibChain_PartialStart(dialogchain);
					duk_context *ctx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(0, 0, dialogchain, NULL, NULL, selfexe, NULL, NULL, dialogchain);
					if (duk_peval_string(ctx, "require('util-language').current.toUpperCase().split('-').join('_');") == 0)
					{
						lang = (char*)duk_safe_to_string(ctx, -1);
						printf("Current Language: %s\n", lang);
					}

					Duktape_SafeDestroyHeap(ctx);
					ILibStopChain(dialogchain);
					ILibStartChain(dialogchain);
					argc = 1;
					skip = 1;
				}
				if (argc == 2 && strlen(argv[1]) > 6 && strncmp(argv[1], "-lang=", 6) == 0)
				{
					DIALOG_LANG = argv[1] + 1 + ILibString_IndexOf(argv[1], strlen(argv[1]), "=", 1);
					argc = 1;
				}

				if (argc != 1)
				{
					printf("Mesh Agent available switches:\r\n");
					printf("  run               Start as a console agent.\r\n");
					printf("  connect           Start as a temporary console agent.\r\n");
					printf("  start             Start the service.\r\n");
					printf("  restart           Restart the service.\r\n");
					printf("  stop              Stop the service.\r\n");
					printf("  state             Display the running state of the service.\r\n");
					printf("  -signcheck        Perform self - check.\r\n");
					printf("  -install          Install the service from this location.\r\n");
					printf("  -uninstall        Remove the service from this location.\r\n");
					printf("  -nodeid           Return the current agent identifier.\r\n");
					printf("  -info             Return agent version information.\r\n");
					printf("  -resetnodeid      Reset the NodeID next time the service is started.\r\n");
					printf("  -fulluninstall    Stop agent and clean up the program files location.\r\n");
					printf("  -fullinstall      Copy agent into program files, install and launch.\r\n");
					printf("\r\n");
					printf("                    The following switches can be specified after -fullinstall:\r\n");
					printf("\r\n");
					printf("     --WebProxy=\"http://proxyhost:port\"      Specify an HTTPS proxy.\r\n");
					printf("     --agentName=\"alternate name\"            Specify an alternate name to be provided by the agent.\r\n");
				}
				else if (skip == 0)
				{
					// This is only supported on Windows 8 / Windows Server 2012 R2 and newer
					char selfexe[_MAX_PATH];
					char *lang = NULL;

					// Get current executable path
					WCHAR wselfexe[MAX_PATH];
					GetModuleFileNameW(NULL, wselfexe, sizeof(wselfexe) / 2);
					ILibWideToUTF8Ex(wselfexe, -1, selfexe, (int)sizeof(selfexe));

					void *dialogchain = ILibCreateChain();
					ILibChain_PartialStart(dialogchain);
					duk_context *ctx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(0, 0, dialogchain, NULL, NULL, selfexe, NULL, need_stop_chain, dialogchain);
					if (duk_peval_string(ctx, "require('win-authenticode-opus').checkMSH();") == 0)
					{
						if (duk_peval_string(ctx, "require('util-language').current.toLowerCase().split('_').join('-');") == 0) { lang = (char*)duk_safe_to_string(ctx, -1); }
						if (duk_peval_string(ctx, "(function foo(){return(JSON.parse(_MSH().translation));})()") != 0 || !duk_has_prop_string(ctx, -1, "en"))
						{
							duk_push_object(ctx);															// [translation][en]
							duk_push_string(ctx, "Install"); duk_put_prop_string(ctx, -2, "install");
							duk_push_string(ctx, "Uninstall"); duk_put_prop_string(ctx, -2, "uninstall");
							duk_push_string(ctx, "Connect"); duk_put_prop_string(ctx, -2, "connect");
							duk_push_string(ctx, "Disconnect"); duk_put_prop_string(ctx, -2, "disconnect");
							duk_push_string(ctx, "Update"); duk_put_prop_string(ctx, -2, "update");
							duk_push_array(ctx);
							duk_push_string(ctx, "NOT INSTALLED"); duk_array_push(ctx, -2);
							duk_push_string(ctx, "RUNNING"); duk_array_push(ctx, -2);
							duk_push_string(ctx, "NOT RUNNING"); duk_array_push(ctx, -2);
							duk_put_prop_string(ctx, -2, "status");
							duk_put_prop_string(ctx, -2, "en");												// [translation]
						}
						if (DIALOG_LANG != NULL) { lang = DIALOG_LANG; }
						if (!duk_has_prop_string(ctx, -1, lang))
						{
							duk_push_string(ctx, lang);					// [obj][string]
							duk_string_split(ctx, -1, "-");				// [obj][string][array]
							duk_array_shift(ctx, -1);					// [obj][string][array][string]
							lang = (char*)duk_safe_to_string(ctx, -1);
							duk_dup(ctx, -4);							// [obj][string][array][string][obj]
						}
						if (!duk_has_prop_string(ctx, -1, lang))
						{
							lang = "en";
						}

						if (strcmp("en", lang) != 0)
						{
							// Not English, so check the minimum set is present
							duk_get_prop_string(ctx, -1, "en");				// [en]
							duk_get_prop_string(ctx, -2, lang);				// [en][lang]
							duk_enum(ctx, -2, DUK_ENUM_OWN_PROPERTIES_ONLY);// [en][lang][enum]
							while (duk_next(ctx, -1, 1))					// [en][lang][enum][key][val]
							{
								if (!duk_has_prop_string(ctx, -4, duk_get_string(ctx, -2)))
								{
									duk_put_prop(ctx, -4);					// [en][lang][enum]
								}
								else
								{
									duk_pop_2(ctx);							// [en][lang][enum]
								}
							}
							duk_pop_3(ctx);									// ...
						}
						g_dialogTranslationObject = duk_get_heapptr(ctx, -1);
						g_dialogCtx = ctx;
						g_dialogLanguage = lang;

						duk_push_global_object(ctx);
						duk_dup(ctx, -2); duk_put_prop_string(ctx, -2, "_start_data");
						duk_push_c_function(ctx, _start, 0);
						duk_put_prop_string(ctx, -2, "_start");

						duk_eval_string(ctx, "global.__msh = _MSH()");
						if (duk_has_prop_string(ctx, -1, "ack"))
						{
							duk_pop(ctx);
							duk_eval_string_noresult(ctx, "global.ack=JSON.parse(global.__msh.ack)");
							duk_eval_string_noresult(ctx, "global.bcolor=global.__msh.background");
							duk_eval_string_noresult(ctx, "global.fcolor=global.__msh.foreground");
							duk_eval_string_noresult(ctx, "global.bimage=global.__msh.image?global.__msh.image:'default2';");
							duk_push_sprintf(ctx, "global.ackTitle = global.ack.captions['%s']?global.ack.captions['%s'].title:global.ack.captions['en'].title;", lang, lang);
							duk_eval_noresult(ctx);
							duk_push_sprintf(ctx, "global.ackText = global.ack.captions['%s']?global.ack.captions['%s'].caption:global.ack.captions['en'].caption;", lang, lang);
							duk_eval_noresult(ctx);
							duk_push_sprintf(ctx, "global.ackLink = { text: global.ack.captions['%s'].linkText, url: global.ack.captions['%s'].linkUrl };if(global.ackLink.text==null || global.ackLink.url==null){delete global.ackLink;}", lang, lang);
							duk_eval_noresult(ctx);
							duk_eval_string_noresult(ctx, "var x = require('win-userconsent').create(global.ackTitle, global.ackText, '', {noCheck: true, background: global.bcolor, foreground: global.fcolor, b64Image: global.bimage, linkText: global.ackLink});x.then(function () { global._OK = true; }); x.pump.on('exit', function () { _start(); });");
						}
						else
						{
							duk_pop(ctx);
							duk_eval_string_noresult(ctx, "global._OK=true; _start();");
						}
						ILibStartChain(dialogchain);
					}
					else
					{
						printf("Error: %s", duk_safe_to_string(ctx, -1));
						Duktape_SafeDestroyHeap(ctx);
						ILibStartChain(dialogchain);
					}
				}
			}
		}
	}

	CoUninitialize();
	wmain_free(argv);
	return 0;
}


int autoproxy_checked = 0;
char *configured_autoproxy_value = NULL;

#ifndef _MINCORE
COLORREF gBKCOLOR = RGB(0, 0, 0);
COLORREF gFGCOLOR = RGB(0, 0, 0);
COLORREF GDIP_RGB(COLORREF c)
{
	unsigned char _r = (c & 0xFF);
	unsigned char _g = ((c >> 8) & 0xFF);
	unsigned char _b = ((c >> 16) & 0xFF);
	return (RGB(_b, _g, _r));
}


uint32_t ColorFromMSH(char *c)
{
	uint32_t ret = RGB(0, 54, 105);
	if (c != NULL)
	{
		size_t len = strnlen_s(c, 14);
		if (c[len] == 0)
		{
			parser_result *pr = ILibParseString(c, 0, len, ",", 1);
			if (pr->NumResults == 3)
			{				
				if (atoi(pr->FirstResult->data) >= 0 && atoi(pr->FirstResult->data) <= UINT8_MAX 
					&& atoi(pr->FirstResult->NextResult->data) >= 0 && atoi(pr->FirstResult->NextResult->data) <= UINT8_MAX
					&& atoi(pr->LastResult->data) >= 0 && atoi(pr->LastResult->data) <= UINT8_MAX)
				{
					ret = RGB(atoi(pr->FirstResult->data), atoi(pr->FirstResult->NextResult->data), atoi(pr->LastResult->data));
				}
			}
			ILibDestructParserResults(pr);
		}
	}
	return(ret);
}

WCHAR *Dialog_GetTranslationEx(void *ctx, char *utf8)
{
	WCHAR *ret = NULL;
	if (utf8 != NULL)
	{
		int wlen = ILibUTF8ToWideCount(utf8);
		ret = (WCHAR*)Duktape_PushBuffer(ctx, sizeof(WCHAR)*wlen + 1);
		duk_swap_top(ctx, -2);
		ILibUTF8ToWideEx(utf8, -1, ret, wlen);
	}
	return(ret);
}
WCHAR *Dialog_GetTranslation(void *ctx, char *property)
{
	WCHAR *ret = NULL;
	char *utf8 = Duktape_GetStringPropertyValue(ctx, -1, property, NULL);
	if (utf8 != NULL)
	{
		int wlen = ILibUTF8ToWideCount(utf8);
		ret = (WCHAR*)Duktape_PushBuffer(ctx, sizeof(WCHAR)*wlen + 1);
		duk_swap_top(ctx, -2);
		ILibUTF8ToWideEx(utf8, -1, ret, wlen);
	}
	return(ret);
}

WCHAR closeButtonText[255] = { 0 };
int closeButtonTextSet = 0;

HBITMAP GetScaledImage(char *raw, size_t rawLen, int w, int h)
{
	size_t newLen = ILibBase64DecodeLength(rawLen);
	char *decoded = (char*)ILibMemory_SmartAllocate(newLen);
	newLen = ILibBase64Decode(raw, (int)rawLen, (unsigned char**)&decoded);

	IStream *instream = __SHCreateMemStream2(decoded, (uint32_t)newLen);
	void *bm = NULL;
	void *g = NULL;
	void *nb = NULL;
	HBITMAP hbm;
	int format;
	float REAL_w, REAL_h;
	int s = __GdipCreateBitmapFromStream((void*)instream, &bm);
	s = __GdipGetImagePixelFormat(bm, &format);
	s = __GdipCreateBitmapFromScan0(w, h, 0, format, NULL, &nb);
	s = __GdipGetImageHorizontalResolution(bm, &REAL_w);
	s = __GdipGetImageVerticalResolution(bm, &REAL_h);
	s = __GdipBitmapSetResolution(nb, REAL_w, REAL_h);
	s = __GdipGetImageGraphicsContext(nb, &g);
	s = __GdipSetSmoothingMode(g, SmoothingModeAntiAlias);
	s = __GdipSetInterpolationMode(g, InterpolationModeBicubic);
	s = __GdipDrawImageRectI(g, bm, 0, 0, w, h);
	s = __GdipCreateHBITMAPFromBitmap(nb, &hbm, GDIP_RGB(gBKCOLOR));
	s = __GdipDisposeImage(bm);
	ILibMemory_Free(decoded);
	return(hbm);
}

// Message handler for dialog box.
INT_PTR CALLBACK DialogHandler(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	char *fileName = NULL, *meshname = NULL, *meshid = NULL, *serverid = NULL, *serverurl = NULL, *installFlags = NULL, *mshfile = NULL;
	char *displayName = NULL, *meshServiceName = NULL;
	int hiddenButtons = 0; // Flags: 1 if "Connect" is hidden, 2 if "Uninstall" is hidden, 4 is "Install is hidden"

	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_CTLCOLORDLG: {
		// Set the background of the dialog box to blue
		if (DialogBackgroundBrush == NULL) {
			DialogBackgroundBrush = CreateSolidBrush(gBKCOLOR);
		}
		return (INT_PTR)DialogBackgroundBrush;
	}
	case WM_CTLCOLORSTATIC: {
		// Set the left text to white over transparent
		if ((HWND)lParam == GetDlgItem(hDlg, IDC_STATIC_LEFTTEXT))
		{
			SetBkMode((HDC)wParam, TRANSPARENT);
			SetTextColor((HDC)wParam, gFGCOLOR);
			return (INT_PTR)GetStockObject(NULL_BRUSH);
		}
		if ((HWND)lParam == GetDlgItem(hDlg, IDC_IMAGE))
		{
			// Set the background mode to transparent for the customized bitmap
			SetBkMode((HDC)wParam, TRANSPARENT);
			return (INT_PTR)GetStockObject(NULL_BRUSH);
		}
		break;
	}
	case WM_PAINT:
	{
		break;
	}
	case WM_INITDIALOG:
	{
		WCHAR *agentstatus = NULL;
		WCHAR *agentversion = NULL;
		WCHAR *serverlocation = NULL;
		WCHAR *meshname = NULL;
		WCHAR *meshidentitifer = NULL;
		WCHAR *serveridentifier = NULL;
		WCHAR *dialogdescription = NULL;
		WCHAR *install_buttontext = NULL;
		WCHAR *update_buttontext = NULL;
		WCHAR *uninstall_buttontext = NULL;
		WCHAR *connect_buttontext = NULL;
		WCHAR *close_buttontext = NULL;
		WCHAR *disconnect_buttontext = NULL;
		WCHAR *state_notinstalled = NULL;
		WCHAR *state_running = NULL;
		WCHAR *state_notrunning = NULL;
		WCHAR *connectiondetailsbutton = NULL;
		WCHAR *closetext = NULL;
		duk_context *ctx = g_dialogCtx;
		char *lang = g_dialogLanguage;


		if (duk_has_prop_string(ctx, -1, lang))
		{
			duk_get_prop_string(ctx, -1, lang);

			agentstatus = Dialog_GetTranslation(ctx, "statusDescription");
			if (agentstatus != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_AGENTSTATUS_TEXT), agentstatus); }
			agentversion = Dialog_GetTranslation(ctx, "agentVersion");
			if (agentversion != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_AGENT_VERSION), agentversion); }
			serverlocation = Dialog_GetTranslation(ctx, "url");
			if (serverlocation != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_SERVER_LOCATION), serverlocation); }
			meshname = Dialog_GetTranslation(ctx, "meshName");
			if (meshname != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_MESH_NAME), meshname); }
			meshidentitifer = Dialog_GetTranslation(ctx, "meshId");
			if (meshidentitifer != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_MESH_IDENTIFIER), meshidentitifer); }
			serveridentifier = Dialog_GetTranslation(ctx, "serverId");
			if (serveridentifier != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_SERVER_IDENTIFIER), serveridentifier); }
			dialogdescription = Dialog_GetTranslation(ctx, "description");
			if (dialogdescription != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_STATIC_LEFTTEXT), dialogdescription); }
			connectiondetailsbutton = Dialog_GetTranslation(ctx, "connectionDetailsButton");
			if (connectiondetailsbutton != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_DETAILSBUTTON), connectiondetailsbutton); }
			closetext = Dialog_GetTranslation(ctx, "close");
			if (closetext != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDCLOSE), closetext); }

			install_buttontext = Dialog_GetTranslation(ctx, "install");
			update_buttontext = Dialog_GetTranslation(ctx, "update");
			uninstall_buttontext = Dialog_GetTranslation(ctx, "uninstall");
			close_buttontext = Dialog_GetTranslation(ctx, "close");
			disconnect_buttontext = Dialog_GetTranslation(ctx, "disconnect");
			if (disconnect_buttontext != NULL)
			{
				wcscpy_s(closeButtonText, sizeof(closeButtonText) / 2, disconnect_buttontext);
				closeButtonTextSet = 1;
			}

			if (uninstall_buttontext != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), uninstall_buttontext); }
			connect_buttontext = Dialog_GetTranslation(ctx, "connect");
			if (connect_buttontext != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_CONNECTBUTTON), connect_buttontext); }
			if (close_buttontext != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDCLOSE), close_buttontext); }

			duk_get_prop_string(ctx, -1, "status");	// [Array]
			state_notinstalled = Dialog_GetTranslationEx(ctx, Duktape_GetStringPropertyIndexValue(ctx, -1, 0, NULL));
			state_running = Dialog_GetTranslationEx(ctx, Duktape_GetStringPropertyIndexValue(ctx, -1, 1, NULL));
			state_notrunning = Dialog_GetTranslationEx(ctx, Duktape_GetStringPropertyIndexValue(ctx, -1, 2, NULL));
		}

		if (duk_peval_string(ctx, "_MSH();") == 0)
		{
			int installFlagsInt = 0;
			WINDOWPLACEMENT lpwndpl;
			RECT r;
			GetWindowRect(GetDlgItem(hDlg, IDC_IMAGE), &r);

			char *bkcolor = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "background", "0,54,105");
			char *fgcolor = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "foreground", "255,255,255");
			gBKCOLOR = ColorFromMSH(bkcolor);
			gFGCOLOR = ColorFromMSH(fgcolor);

			duk_size_t rawLen;
			char *imageraw = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "image", NULL);
			if (imageraw != NULL)
			{
				duk_push_sprintf(g_dialogCtx, "('%s').split(',').pop()", imageraw);					// [msh][str]
				duk_eval(g_dialogCtx);																// [msh][str]
				duk_swap_top(g_dialogCtx, -2);														// [str][msh]
				imageraw = (char*)duk_get_lstring(g_dialogCtx, -2, &rawLen);
				HBITMAP scaled = GetScaledImage(imageraw, rawLen, 162, 162);
				SendMessageW(GetDlgItem(hDlg, IDC_IMAGE), STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)scaled);
			}
			else
			{
				HBITMAP scaled = GetScaledImage(image_b64, sizeof(image_b64) - 1, 162, 162);
				SendMessageW(GetDlgItem(hDlg, IDC_IMAGE), STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)scaled);
			}
			installFlags = Duktape_GetStringPropertyValue(ctx, -1, "InstallFlags", NULL);
			meshname = (WCHAR*)Duktape_GetStringPropertyValue(ctx, -1, "MeshName", NULL);
			meshid = Duktape_GetStringPropertyValue(ctx, -1, "MeshID", NULL);
			serverid = Duktape_GetStringPropertyValue(ctx, -1, "ServerID", NULL);
			serverurl = Duktape_GetStringPropertyValue(ctx, -1, "MeshServer", NULL);
			displayName = Duktape_GetStringPropertyValue(ctx, -1, "displayName", NULL);
			meshServiceName = Duktape_GetStringPropertyValue(ctx, -1, "meshServiceName", NULL);

			configured_autoproxy_value = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "autoproxy", NULL);
			autoproxy_checked = configured_autoproxy_value != NULL;

			// Set text in the dialog box
			if (installFlags != NULL) { installFlagsInt = ILib_atoi2_int32(installFlags, 255); }
			if (strnlen_s(meshid, 255) > 50) { meshid += 2; meshid[42] = 0; }
			if (strnlen_s(serverid, 255) > 50) { serverid[42] = 0; }
			if (displayName != NULL) { SetWindowTextW(hDlg, ILibUTF8ToWide(displayName, -1)); }
			SetWindowTextW(GetDlgItem(hDlg, IDC_POLICYTEXT), ILibUTF8ToWide((meshname != NULL) ? (char*)meshname : "(None)", -1));
			SetWindowTextA(GetDlgItem(hDlg, IDC_HASHTEXT), (meshid != NULL) ? meshid : "(None)");
			SetWindowTextW(GetDlgItem(hDlg, IDC_SERVERLOCATION), ILibUTF8ToWide((serverurl != NULL) ? serverurl : "(None)", -1));
			SetWindowTextA(GetDlgItem(hDlg, IDC_SERVERID), (serverid != NULL) ? serverid : "(None)");
			if (meshid == NULL) { EnableWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), FALSE); }
			if ((installFlagsInt & 3) == 1) {
				// Temporary Agent Only
				hiddenButtons |= 6; // Both install and uninstall buttons are hidden
				ShowWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), SW_HIDE);
				ShowWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), SW_HIDE);
				GetWindowPlacement(GetDlgItem(hDlg, IDC_INSTALLBUTTON), &lpwndpl);
				SetWindowPlacement(GetDlgItem(hDlg, IDC_CONNECTBUTTON), &lpwndpl);
			}
			else if ((installFlagsInt & 3) == 2) {
				// Background Only
				hiddenButtons |= 1; // Connect button is hidden hidden
				ShowWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), SW_HIDE);
			}
			else if ((installFlagsInt & 3) == 3) {
				// Uninstall only
				GetWindowPlacement(GetDlgItem(hDlg, IDC_INSTALLBUTTON), &lpwndpl);
				SetWindowPlacement(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), &lpwndpl);
				hiddenButtons |= 5; // Both install and connect buttons are hidden
				ShowWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), SW_HIDE);
				ShowWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), SW_HIDE);
			}
		}
		else
		{
			EnableWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), FALSE);
			HBITMAP scaled = GetScaledImage(image_b64, sizeof(image_b64) - 1, 162, 162);
			SendMessageW(GetDlgItem(hDlg, IDC_IMAGE), STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)scaled);
		}

		// Get the current service running state
		int r = GetServiceState(meshServiceName != NULL ? meshServiceName : serviceFile);
		SetWindowTextW(GetDlgItem(hDlg, IDC_INSTALLBUTTON), update_buttontext);

		switch (r)
		{
		case SERVICE_RUNNING:
			SetWindowTextW(GetDlgItem(hDlg, IDC_STATUSTEXT), state_running);
			break;
		case 0:
		case 100: // Not installed
			SetWindowTextW(GetDlgItem(hDlg, IDC_STATUSTEXT), state_notinstalled);
			SetWindowTextW(GetDlgItem(hDlg, IDC_INSTALLBUTTON), install_buttontext);
			hiddenButtons |= 2; // Uninstall buttons is hidden
			ShowWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), SW_HIDE);
			break;
		default: // Not running
			SetWindowTextW(GetDlgItem(hDlg, IDC_STATUSTEXT), state_notrunning);
			break;
		}

		// Correct the placement of buttons, push them to the left side if some of them are hidden.
		if (hiddenButtons == 2) { // Uninstall button is the only one hidden. Place connect button at uninstall position
			WINDOWPLACEMENT lpwndpl;
			GetWindowPlacement(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), &lpwndpl);
			SetWindowPlacement(GetDlgItem(hDlg, IDC_CONNECTBUTTON), &lpwndpl);
		}
		else if (hiddenButtons == 6) { // Only connect button is showing, place it in the install button location
			WINDOWPLACEMENT lpwndpl;
			GetWindowPlacement(GetDlgItem(hDlg, IDC_INSTALLBUTTON), &lpwndpl);
			SetWindowPlacement(GetDlgItem(hDlg, IDC_CONNECTBUTTON), &lpwndpl);
		}

		if (mshfile != NULL) { free(mshfile); }
		return (INT_PTR)TRUE;
	}
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCLOSE || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));

#ifdef _DEBUG
			_CrtCheckMemory();
			_CrtDumpMemoryLeaks();
#endif

			return (INT_PTR)TRUE;
		}
		else if (LOWORD(wParam) == IDC_DETAILSBUTTON) 
		{
			DialogBoxW(NULL, MAKEINTRESOURCEW(IDD_DETAILSDIALOG), hDlg, DialogHandler2);
			return (INT_PTR)TRUE;
		}
		else if (LOWORD(wParam) == IDC_INSTALLBUTTON || LOWORD(wParam) == IDC_UNINSTALLBUTTON)
		{
			BOOL result = FALSE;

			EnableWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDCLOSE), FALSE);

			sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "-full%s %s%s", LOWORD(wParam) == IDC_INSTALLBUTTON ? "install" : "uninstall", autoproxy_checked != 0 ? "--autoproxy=" : "", autoproxy_checked != 0 ? (configured_autoproxy_value != NULL ? configured_autoproxy_value : "1") : "");
			result = RunAsAdmin(ILibScratchPad, IsAdmin() == TRUE);

			if (result)
			{
				EndDialog(hDlg, LOWORD(wParam));
			}
			else
			{
				EnableWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), TRUE);
				EnableWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), TRUE);
				EnableWindow(GetDlgItem(hDlg, IDCLOSE), TRUE);
			}

#ifdef _DEBUG
			_CrtCheckMemory();
			_CrtDumpMemoryLeaks();
#endif

			return (INT_PTR)TRUE;
		}
		else if (LOWORD(wParam) == IDC_CONNECTBUTTON)
		{
			//
			// Temporary Agent
			//
			EnableWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), FALSE);
			SetWindowTextA(GetDlgItem(hDlg, IDC_STATUSTEXT), "Running as temporary agent");

			DWORD pid = GetCurrentProcessId();
			sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "connect --disableUpdate=1 --hideConsole=1 --exitPID=%u %s%s", pid, autoproxy_checked != 0 ? "--autoproxy=" : "", autoproxy_checked != 0 ? (configured_autoproxy_value != NULL ? configured_autoproxy_value : "1") : "");
			if (RunAsAdmin(ILibScratchPad, IsAdmin() == TRUE) == 0) { RunAsAdmin(ILibScratchPad, 1); }

			if (closeButtonTextSet != 0) { SetWindowTextW(GetDlgItem(hDlg, IDCLOSE), closeButtonText); }
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

#endif


// Message handler for details dialog box.
INT_PTR CALLBACK DialogHandler2(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	char *fileName = NULL, *meshname = NULL, *meshid = NULL, *serverid = NULL, *serverurl = NULL, *installFlags = NULL, *mshfile = NULL, *autoproxy = NULL;
	char *displayName = NULL, *meshServiceName = NULL;
	int hiddenButtons = 0; // Flags: 1 if "Connect" is hidden, 2 if "Uninstall" is hidden, 4 is "Install is hidden"
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
		case WM_CLOSE:
			autoproxy_checked = IsDlgButtonChecked(hDlg, IDC_AUTOPROXY_CHECK);
			break;
	case WM_CTLCOLORDLG: {
		// Set the background of the dialog box to blue
		if (DialogBackgroundBrush == NULL) {
			DialogBackgroundBrush = CreateSolidBrush(gBKCOLOR);
		}
		return (INT_PTR)DialogBackgroundBrush;
	}
	case WM_CTLCOLORSTATIC: 
	{
		if (GetDlgCtrlID((HWND)lParam) == IDC_AUTOPROXY_CHECK)
		{
			HBRUSH h=CreateSolidBrush(gBKCOLOR);
			SetBkColor((HDC)wParam, gBKCOLOR);
			SetTextColor((HDC)wParam, gFGCOLOR);
			return((INT_PTR)h);
		}
		// Set the left text to white over transparent
		SetBkMode((HDC)wParam, TRANSPARENT);
		SetTextColor((HDC)wParam, gFGCOLOR);
		return (INT_PTR)GetStockObject(NULL_BRUSH);
		break;
	}
	case WM_CTLCOLORBTN:
	{
		DWORD ID = GetDlgCtrlID((HWND)lParam);
		if(ID == IDC_AUTOPROXY_CHECK)
		{
			SetBkMode((HDC)wParam, TRANSPARENT);
			SetTextColor((HDC)wParam, gFGCOLOR);
			return (INT_PTR)GetStockObject(NULL_BRUSH);
		}
		break;
	}
	case WM_INITDIALOG:
	{
		if (duk_peval_string(g_dialogCtx, "_MSH();") == 0)
		{
			WCHAR *state_notinstalled = NULL;
			WCHAR *state_running = NULL;
			WCHAR *state_notrunning = NULL;
			WCHAR *agentstatus = NULL;
			WCHAR *agentversion = NULL;
			WCHAR *serverlocation = NULL;
			WCHAR *serveridentifier = NULL;
			WCHAR *groupname = NULL;
			WCHAR *meshidentitifer = NULL;
			WCHAR *oktext = NULL;
			WCHAR *dialogtitle = NULL;
			WCHAR *osname = NULL;
			meshname = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "MeshName", NULL);
			meshid = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "MeshID", NULL);
			serverid = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "ServerID", NULL);
			serverurl = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "MeshServer", NULL);
			displayName = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "displayName", NULL);
			meshServiceName = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "meshServiceName", "Mesh Agent");
			autoproxy = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "autoproxy", NULL);
			char *bkcolor = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "bkcolor", "0,0,0");

			if (autoproxy != NULL || autoproxy_checked != 0)
			{
				CheckDlgButton(hDlg, IDC_AUTOPROXY_CHECK, BST_CHECKED);
			}

			// Set text in the dialog box
			if (strnlen_s(meshid, 255) > 50) { meshid += 2; meshid[42] = 0; }
			if (strnlen_s(serverid, 255) > 50) { serverid[42] = 0; }
			if (displayName != NULL) { SetWindowTextW(hDlg, ILibUTF8ToWide(displayName, -1)); }
			SetWindowTextA(GetDlgItem(hDlg, IDC_HASHTEXT), (meshid != NULL) ? meshid : "(None)");
			SetWindowTextW(GetDlgItem(hDlg, IDC_SERVERLOCATION), ILibUTF8ToWide((serverurl != NULL) ? serverurl : "(None)", -1));
			SetWindowTextA(GetDlgItem(hDlg, IDC_SERVERID), (serverid != NULL) ? serverid : "(None)");
			SetWindowTextW(GetDlgItem(hDlg, IDC_SERVERLOCATION), ILibUTF8ToWide((serverurl != NULL) ? serverurl : "(None)", -1));
			SetWindowTextW(GetDlgItem(hDlg, IDC_POLICYTEXT), ILibUTF8ToWide((meshname != NULL) ? meshname : "(None)", -1));
			SetWindowTextW(GetDlgItem(hDlg, IDC_VERSIONTEXT), ILibUTF8ToWide(SOURCE_COMMIT_DATE, -1));

			// Set Tooltip for ServerLocation
			HWND hServerLocationHWND = GetDlgItem(hDlg, IDC_SERVERLOCATION);
			HWND hToolTip = CreateWindowExW(0, TOOLTIPS_CLASSW, NULL, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hDlg, NULL, GetModuleHandle(NULL), NULL);
			DWORD _e = GetLastError();
			if (hToolTip != NULL && hServerLocationHWND != NULL)
			{
				// Associate the tooltip
				TOOLINFOW toolInfo = { 0 };
				toolInfo.cbSize = sizeof(TOOLINFOW);
				toolInfo.hwnd = hDlg;
				toolInfo.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
				toolInfo.uId = (UINT_PTR)hServerLocationHWND;
				toolInfo.lpszText = ILibUTF8ToWide((serverurl != NULL) ? serverurl : "(None)", -1);
				toolInfo.hinst = GetModuleHandle(NULL);

				SendMessageW(hToolTip, TTM_ADDTOOLW, 0, (LPARAM)&toolInfo);
			}


			duk_push_heapptr(g_dialogCtx, g_dialogTranslationObject); // [obj]
			if (duk_has_prop_string(g_dialogCtx, -1, g_dialogLanguage))
			{
				duk_get_prop_string(g_dialogCtx, -1, g_dialogLanguage);
				agentstatus = Dialog_GetTranslation(g_dialogCtx, "statusDescription");
				if (agentstatus != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_AGENTSTATUS_TEXT), agentstatus); }
				agentversion = Dialog_GetTranslation(g_dialogCtx, "agentVersion");
				if (agentversion != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_AGENT_VERSION), agentversion); }
				serverlocation = Dialog_GetTranslation(g_dialogCtx, "url");
				if (serverlocation != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_SERVER_LOCATION), serverlocation); }
				serveridentifier = Dialog_GetTranslation(g_dialogCtx, "serverId");
				if (serveridentifier != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_SERVER_IDENTIFIER), serveridentifier); }
				groupname = Dialog_GetTranslation(g_dialogCtx, "meshName");
				if (groupname != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_MESH_NAME), groupname); }
				meshidentitifer = Dialog_GetTranslation(g_dialogCtx, "meshId");
				if (meshidentitifer != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_MESH_IDENTIFIER), meshidentitifer); }
				oktext = Dialog_GetTranslation(g_dialogCtx, "ok");
				if (oktext != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDOK), oktext); }
				dialogtitle = Dialog_GetTranslation(g_dialogCtx, "connectionDetailsTitle");
				if (dialogtitle != NULL) { SetWindowTextW(hDlg, dialogtitle); }

				duk_get_prop_string(g_dialogCtx, -1, "status");	// [Array]
				state_notinstalled = Dialog_GetTranslationEx(g_dialogCtx, Duktape_GetStringPropertyIndexValue(g_dialogCtx, -1, 0, NULL));
				state_running = Dialog_GetTranslationEx(g_dialogCtx, Duktape_GetStringPropertyIndexValue(g_dialogCtx, -1, 1, NULL));
				state_notrunning = Dialog_GetTranslationEx(g_dialogCtx, Duktape_GetStringPropertyIndexValue(g_dialogCtx, -1, 2, NULL));

				// Get the current service running state
				int r = GetServiceState(meshServiceName);
				switch (r)
				{
				case SERVICE_RUNNING:
					SetWindowTextW(GetDlgItem(hDlg, IDC_STATUSTEXT), state_running);
					break;
				case 0:
				case 100: // Not installed
					SetWindowTextW(GetDlgItem(hDlg, IDC_STATUSTEXT), state_notinstalled);
					break;
				default: // Not running
					SetWindowTextW(GetDlgItem(hDlg, IDC_STATUSTEXT), state_notrunning);
					break;
				}
				char osnametmp[255];
				#ifdef WIN32
					// This is only supported on Windows 8 and above
					HMODULE wsCORE = LoadLibraryExA((LPCSTR)"Ws2_32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
					GetHostNameWFunc ghnw = NULL;
					if (wsCORE != NULL)
					{
						if ((ghnw = (GetHostNameWFunc)GetProcAddress(wsCORE, (LPCSTR)"GetHostNameW")) == NULL)
						{
							FreeLibrary(wsCORE);
							wsCORE = NULL;
						}
					}
					if (ghnw != NULL)
					{
						WCHAR whostname[MAX_PATH];
						if (ghnw(whostname, MAX_PATH) == 0)
						{
							WideCharToMultiByte(CP_UTF8, 0, whostname, -1, osnametmp, (int)sizeof(osnametmp), NULL, NULL);
						}
					}
					else
					{
						gethostname(osnametmp, (int)sizeof(osnametmp));
					}
					if (wsCORE != NULL)
					{
						FreeLibrary(wsCORE);
						wsCORE = NULL;
					}
				#else
					gethostname(osnametmp, (int)sizeof(osnametmp));
				#endif
				osname = Dialog_GetTranslationEx(g_dialogCtx, osnametmp);
				SetWindowTextW(GetDlgItem(hDlg, IDC_OSNAME), osname);
			}
		}
		break;
	}
	case WM_COMMAND: 
	{
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCLOSE || LOWORD(wParam) == IDCANCEL)
		{
			autoproxy_checked = IsDlgButtonChecked(hDlg, IDC_AUTOPROXY_CHECK);

			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
	}
	}
	return (INT_PTR)FALSE;
}


#ifdef _MINCORE
BOOL WINAPI AreFileApisANSI(void) { return FALSE; }
VOID WINAPI FatalAppExitA(_In_ UINT uAction, _In_ LPCSTR lpMessageText) {}
HANDLE WINAPI CreateSemaphoreW(_In_opt_  LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, _In_ LONG lInitialCount, _In_ LONG lMaximumCount, _In_opt_ LPCWSTR lpName)
{
	return 0;
}
#endif
