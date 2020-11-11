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

#ifndef _MINCORE
// #include "../kvm/kvm.h"
int SetupWindowsFirewall(wchar_t* processname);
int ClearWindowsFirewall(wchar_t* processname);
#endif

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

MeshAgentHostContainer *agent = NULL;
DWORD g_serviceArgc;
char **g_serviceArgv;
extern int gRemoteMouseRenderDefault;


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

BOOL IsAdmin()
{
	BOOL admin;
	PSID AdministratorsGroup; 
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

	if ((admin = AllocateAndInitializeSid( &NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) != 0)
	{
		if (!CheckTokenMembership( NULL, AdministratorsGroup, &admin)) admin = FALSE;
		FreeSid(AdministratorsGroup);
	}
	return admin;
}

BOOL RunAsAdmin(char* args, int isAdmin)
{
	WCHAR szPath[_MAX_PATH + 100];
	if (GetModuleFileNameW(NULL, szPath, sizeof(szPath)/2))
	{
		SHELLEXECUTEINFOW sei = { sizeof(sei) };
		sei.hwnd = NULL;
		sei.nShow = SW_NORMAL;
		sei.lpVerb = isAdmin?L"open":L"runas";
		sei.lpFile = szPath;
		sei.lpParameters = ILibUTF8ToWide(args, -1);
		return ShellExecuteExW(&sei);
	}
	return FALSE;
}

DWORD WINAPI ServiceControlHandler( DWORD controlCode, DWORD eventType, void *eventData, void* eventContext )
{
	switch (controlCode)
	{
		case SERVICE_CONTROL_INTERROGATE:
			break;
		case SERVICE_CONTROL_SHUTDOWN:
		case SERVICE_CONTROL_STOP:
			serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
			SetServiceStatus( serviceStatusHandle, &serviceStatus );
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

	SetServiceStatus( serviceStatusHandle, &serviceStatus );
	return(0);
}


void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	ILib_DumpEnabledContext winException;
	size_t len = 0;
	WCHAR str[_MAX_PATH];


	UNREFERENCED_PARAMETER( argc );
	UNREFERENCED_PARAMETER( argv );

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
		SetServiceStatus( serviceStatusHandle, &serviceStatus);

		// Get our own executable name
		GetModuleFileNameW(NULL, str, _MAX_PATH);

#ifndef _MINCORE
		// Setup firewall
		SetupWindowsFirewall(str);
#endif

		// Run the mesh agent
		CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

		__try
		{
			agent = MeshAgent_Create(0);
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

	return StartServiceCtrlDispatcher( serviceTable );
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
		SC_HANDLE service = OpenService( serviceControlManager, servicename, SERVICE_QUERY_STATUS );
		if (service)
		{
			SERVICE_STATUS serviceStatusEx;
			if ( QueryServiceStatus( service, &serviceStatusEx) )
			{
				r = serviceStatusEx.dwCurrentState;
			}
			CloseServiceHandle( service );
		}
		else
		{
			r = 100;
		}
		CloseServiceHandle( serviceControlManager );
	}
	return r;
}


int LaunchService(LPCSTR servicename)
{
	int r = 0;
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SERVICE_QUERY_STATUS | SERVICE_START);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService( serviceControlManager, servicename, SERVICE_QUERY_STATUS | SERVICE_START );
		if (service)
		{
			SERVICE_STATUS serviceStatusEx;
			if ( QueryServiceStatus( service, &serviceStatusEx) )
			{
				if (serviceStatusEx.dwCurrentState == SERVICE_STOPPED ) { if (StartService(service, 0, NULL) == TRUE) { r = 1; } } else { r = 2; }
			}
			CloseServiceHandle( service );
		}
		CloseServiceHandle( serviceControlManager );
	}
	return r;
}

int StopService(LPCSTR servicename)
{
	int r = 0;
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SERVICE_QUERY_STATUS | SERVICE_STOP);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService( serviceControlManager, servicename, SERVICE_QUERY_STATUS | SERVICE_STOP );
		if (service)
		{
			SERVICE_STATUS serviceStatusEx;
			if ( QueryServiceStatus( service, &serviceStatusEx) )
			{
				if (serviceStatusEx.dwCurrentState != SERVICE_STOPPED )
				{
					if (ControlService(service, SERVICE_CONTROL_STOP, &serviceStatusEx) == FALSE)
					{
						// TODO: Unable to stop service
						#ifdef _DEBUG
						ILIBMESSAGE("Unable to stop service");
						#endif
					}
					else
					{
						Sleep(3000);
						r = 1;
					}
				}
			}
			CloseServiceHandle( service );
		}
		CloseServiceHandle( serviceControlManager );
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
int wmain(int argc, char* wargv[])
{
	int i;
	size_t str2len = 0;// , proxylen = 0, taglen = 0;
	wchar_t str[_MAX_PATH];
	ILib_DumpEnabledContext winException;
	int retCode = 0;

	int argvi, argvsz;
	char **argv = (char**)ILibMemory_SmartAllocate((argc+1) * sizeof(void*));
	for (argvi = 0; argvi < argc; ++argvi)
	{
		argvsz = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wargv[argvi], -1, NULL, 0, NULL, NULL);
		argv[argvi] = (char*)ILibMemory_SmartAllocate(argvsz);
		WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wargv[argvi], -1, argv[argvi], argvsz, NULL, NULL);
	}

	if (argc > 1 && (strcasecmp(argv[1], "-finstall") == 0 || strcasecmp(argv[1], "-funinstall") == 0 || 
		strcasecmp(argv[1], "-fulluninstall") == 0 || strcasecmp(argv[1], "-fullinstall") == 0 ||
		strcasecmp(argv[1], "-install")==0 || strcasecmp(argv[1], "-uninstall") == 0 ||
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
		printf(" MeshCentral MeshAgent: Copyright 2006 - 2020 Intel Corporation\n");
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
		wmain_free(argv);
		return(0);
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

	char *integratedJavaScript;
	int integragedJavaScriptLen;
	ILibDuktape_ScriptContainer_CheckEmbedded(&integratedJavaScript, &integragedJavaScriptLen);
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


	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
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
	else if (argc > 1 && (strcasecmp(argv[1], "state") == 0))
	{
		// SERVICE_STOPPED				  1    The service is not running.
		// SERVICE_START_PENDING		  2    The service is starting.
		// SERVICE_STOP_PENDING			  3    The service is stopping.
		// SERVICE_RUNNING				  4    The service is running.
		// SERVICE_CONTINUE_PENDING		  5    The service continue is pending.
		// SERVICE_PAUSE_PENDING		  6    The service pause is pending.
		// SERVICE_PAUSED				  7    The service is paused.
		// SERVICE_NOT_INSTALLED		100    The service is not installed.
		int serviceState = GetServiceState(serviceFile);
		if (serviceState == 1) { printf("Stopped"); }
		else if (serviceState == 2) { printf("Start Pending"); }
		else if (serviceState == 3) { printf("Stop Pending"); }
		else if (serviceState == 4) { printf("Running"); }
		else if (serviceState == 5) { printf("Continue Pending"); }
		else if (serviceState == 6) { printf("Pause Pending"); }
		else if (serviceState == 7) { printf("Paused"); }
		else if (serviceState == 100) { printf("Not installed"); }
		wmain_free(argv);
		return serviceState;
	}
	else if (argc > 1 && (strcasecmp(argv[1], "start") == 0 || strcasecmp(argv[1], "-start") == 0))
	{
		// Ask the service manager to launch the service
		int r = LaunchService(serviceFile);
		if (r == 0) { printf("Failed to start mesh agent"); }
		else if (r == 1) { printf("Started the mesh agent"); }
		else if (r == 2) { printf("Mesh agent already running"); }
	}
	else if (argc > 1 && (strcasecmp(argv[1], "stop") == 0 || strcasecmp(argv[1], "-stop") == 0))
	{
		// Ask the service manager to stop the service
		if (StopService(serviceFile) == 1) { printf("Stopped mesh agent"); } else { printf("Failed to stop mesh agent"); }
	}
	else if (argc > 1 && (strcasecmp(argv[1], "restart") == 0 || strcasecmp(argv[1], "-restart") == 0))
	{
		// Ask the service manager to stop and start the service
		StopService(serviceFile);
		{
			int r = LaunchService(serviceFile);
			if (r == 0) { printf("Failed to restart mesh agent"); }
			else if (r == 1) { printf("Restarted the mesh agent"); }
			else if (r == 2) { printf("Mesh agent failed to stop"); }
		}
	}
	else if (argc > 1 && memcmp(argv[1], "-update:", 8) == 0)
	{		
		char *update = ILibMemory_Allocate(1024, 0, NULL, NULL);
		int updateLen;

		if (argv[1][8] == '*')
		{
			// New Style
			updateLen = sprintf_s(update, 1024, "require('agent-installer').update(%s, '%s');", argv[1][9] == 'S' ? "true" : "false", argc > 1 ? argv[2] : "null");
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
	else if (argc > 1 && (strcasecmp(argv[1], "-setfirewall") == 0))
	{
		// Reset the firewall rules
		GetModuleFileNameW(NULL, str, _MAX_PATH);
		if (IsAdmin() == FALSE) { printf("Must run as administrator"); } else { ClearWindowsFirewall(str); SetupWindowsFirewall(str); printf("Done"); }
	}
	else if (argc > 1 && (strcasecmp(argv[1], "-clearfirewall") == 0))
	{
		// Clear the firewall rules
		GetModuleFileNameW(NULL, str, _MAX_PATH);
		if (IsAdmin() == FALSE) { printf("Must run as administrator"); } else { ClearWindowsFirewall(str); printf("Done"); }
	}
#endif
	else if (argc == 2 && (strcasecmp(argv[1], "-nodeidhex") == 0))
	{
		// Get the NodeID from the registry
		HKEY hKey;
		DWORD len = 0;
		char* strEx = NULL;
#ifndef _WIN64
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent2", 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS )
#else
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent2", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS )
#endif
		{
			if (RegQueryValueExA(hKey, "NodeId", NULL, NULL, NULL, &len ) == ERROR_SUCCESS && len > 0)
			{
				if ((strEx = (char*)malloc(len)) == NULL) ILIBCRITICALEXIT(254);
				if (RegQueryValueExA(hKey, "NodeId", NULL, NULL, (LPBYTE)strEx, &len ) != ERROR_SUCCESS || len == 0) { free(strEx); strEx = NULL; len = 0;}
			}
			RegCloseKey(hKey);
		}
		if (strEx != NULL) printf_s("%s", strEx); else printf("Not defined, start the mesh service to create a nodeid.");
		wmain_free(argv);
		return 0;
	}
	else if (argc == 2 && (strcasecmp(argv[1], "-info") == 0))
	{
		// Display agent information from the registry
		HKEY hKey;
		DWORD len = 0;
		char* strEx = NULL;
#ifndef _WIN64
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent2", 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS)
#else
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent2", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
#endif
		{
			// Display NodeId
			len = sizeof(ILibScratchPad2);
			if (RegQueryValueExA(hKey, "NodeId", NULL, NULL, (LPBYTE)ILibScratchPad2, &len) != ERROR_SUCCESS) { len = 0; }
			if (len == 0) printf("NodeId:    (none)"); else printf("NodeId:    %s", ILibScratchPad2);

			// Display MeshId
			len = sizeof(ILibScratchPad2);
			if (RegQueryValueExA(hKey, "MeshId", NULL, NULL, (LPBYTE)ILibScratchPad2, &len) != ERROR_SUCCESS) { len = 0; }
			if (len > 0) printf("\r\nMeshId:    %s", ILibScratchPad2);

			// Display AgentHash
			len = sizeof(ILibScratchPad2);
			if (RegQueryValueExA(hKey, "AgentHash", NULL, NULL, (LPBYTE)ILibScratchPad2, &len) != ERROR_SUCCESS) { len = 0; }
			if (len > 0) printf("\r\nAgentHash: %s", ILibScratchPad2);

			// Display MeshServerId
			len = sizeof(ILibScratchPad2);
			if (RegQueryValueExA(hKey, "MeshServerId", NULL, NULL, (LPBYTE)ILibScratchPad2, &len) != ERROR_SUCCESS) { len = 0; }
			if (len > 0) printf("\r\nServerId:  %s", ILibScratchPad2);

			// Display MeshServerUrl
			len = sizeof(ILibScratchPad2);
			if (RegQueryValueExA(hKey, "MeshServerUrl", NULL, NULL, (LPBYTE)ILibScratchPad2, &len) != ERROR_SUCCESS) { len = 0; }
			if (len > 0) printf("\r\nServerUrl: %s", ILibScratchPad2);

			// Display Proxy
			len = sizeof(ILibScratchPad2);
			if (RegQueryValueExA(hKey, "Proxy", NULL, NULL, (LPBYTE)ILibScratchPad2, &len) != ERROR_SUCCESS) { len = 0; }
			if (len > 0) printf("\r\nProxy:     %s", ILibScratchPad2);

			// Display Tag
			len = sizeof(ILibScratchPad2);
			if (RegQueryValueExA(hKey, "Tag", NULL, NULL, (LPBYTE)ILibScratchPad2, &len) != ERROR_SUCCESS) { len = 0; }
			if (len > 0) printf("\r\nTag:       %s", ILibScratchPad2);

			RegCloseKey(hKey);
		}
		wmain_free(argv);
		return 0;
	}
	else if (argc == 2 && (strcasecmp(argv[1], "-resetnodeid") == 0))
	{
		// Set "resetnodeid" in registry
		HKEY hKey;
#ifndef _WIN64
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent2", 0, KEY_WRITE | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS )
#else
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent2", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS )
#endif
		{
			i = 1;
			DWORD err = RegSetValueEx(hKey, "ResetNodeId", 0, REG_DWORD, (BYTE*)&i, (DWORD)4);
			if (err == ERROR_SUCCESS) { printf("NodeID will be reset next time the Mesh Agent service is started."); }
			RegCloseKey(hKey);
		}
		else
		{
			printf("Error writing to registry, try running as administrator.");
		}
		wmain_free(argv);
		return 0;
	}
	else
	{
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
					printf("  -nodeidhex        Return the current agent identifier.\r\n");
					printf("  -resetnodeid      Reset the NodeID next time the service is started.\r\n");
					printf("  -fulluninstall    Stop agent and clean up the program files location.\r\n");
					printf("  -fullinstall      Copy agent into program files, install and launch.\r\n");
					printf("\r\n");
					printf("                    The following switches can be specified after -fullinstall:\r\n");
					printf("\r\n");
					printf("     --WebProxy=\"http://proxyhost:port\"      Specify an HTTPS proxy.\r\n");
					printf("     --agentName=\"alternate name\"            Specify an alternate name to be provided by the agent.\r\n");
				}
				else
				{
					FreeConsole();
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

					DialogBox(NULL, MAKEINTRESOURCE(IDD_INSTALLDIALOG), NULL, DialogHandler);
				}
			}
		}
	}

	CoUninitialize();
	wmain_free(argv);
	return 0;
}

char* getMshSettings(char* fileName, char* selfexe, char** meshname, char** meshid, char** serverid, char** serverurl, char** installFlags)
{
	char* importFile;
	int eq, importFileLen;
	parser_result *pr;
	parser_result_field *f;

	*meshname = *meshid = *serverid = *serverurl = *installFlags = NULL;
	importFileLen = ILibReadFileFromDiskEx(&importFile, fileName);
	if (importFile == NULL) {
		// Could not find the .msh file, see if there is one inside our own executable.
		FILE *tmpFile = NULL;
		char exeMeshPolicyGuid[] = { 0xB9, 0x96, 0x01, 0x58, 0x80, 0x54, 0x4A, 0x19, 0xB7, 0xF7, 0xE9, 0xBE, 0x44, 0x91, 0x4C, 0x19 };
		char tmpHash[16];

		_wfopen_s(&tmpFile, ILibUTF8ToWide(selfexe, -1), L"rb");
		if (tmpFile == NULL) { return NULL; } // Could not open our own executable

		fseek(tmpFile, -16, SEEK_END);
		ignore_result(fread(tmpHash, 1, 16, tmpFile)); // Read the GUID
		if (memcmp(tmpHash, exeMeshPolicyGuid, 16) == 0) { // If this is the Mesh policy file guid, we found a MSH file
														   // Found embedded MSH File
			fseek(tmpFile, -20, SEEK_CUR);
			if (fread((void*)&importFileLen, 1, 4, tmpFile) == 4) { // Read the length of the MSH file
				importFileLen = ntohl(importFileLen);
				if ((importFileLen >= 20000) || (importFileLen < 1)) { fclose(tmpFile); return NULL; }
				fseek(tmpFile, -4 - importFileLen, SEEK_CUR);
				if ((importFile = malloc(importFileLen + 1)) == NULL) { fclose(tmpFile); return NULL; }
				if (fread(importFile, 1, importFileLen, tmpFile) != importFileLen) { fclose(tmpFile); free(importFile); return NULL; }
				importFile[importFileLen] = 0;
			}
		}
		else {
			fclose(tmpFile);
			return NULL;
		}
		fclose(tmpFile);
	}

	pr = ILibParseString(importFile, 0, importFileLen, "\n", 1);
	f = pr->FirstResult;
	while (f != NULL) {
		f->datalength = ILibTrimString(&(f->data), f->datalength);
		if (f->data[0] != 35) { // Checking to see if this line is commented out
			eq = ILibString_IndexOf(f->data, f->datalength, "=", 1);
			if (eq > 0) {
				char *key, *val;
				size_t keyLen, valLen;

				key = f->data;
				keyLen = eq;
				key[keyLen] = 0;
				val = key + keyLen + 1;
				valLen = f->datalength - keyLen - 1;
				if (val[valLen - 1] == 13) { --valLen; }
				valLen = ILibTrimString(&val, valLen);
				val[valLen] = 0;

				if (keyLen == 8 && memcmp("MeshName", key, keyLen) == 0) { *meshname = val; }
				if (keyLen == 6 && memcmp("MeshID", key, keyLen) == 0) { *meshid = val; }
				if (keyLen == 8 && memcmp("ServerID", key, keyLen) == 0) { *serverid = val; }
				if (keyLen == 10 && memcmp("MeshServer", key, keyLen) == 0) { *serverurl = val; }
				if (keyLen == 12 && memcmp("InstallFlags", key, keyLen) == 0) { *installFlags = val; }
			}
		}
		f = f->NextResult;
	}
	ILibDestructParserResults(pr);
	return importFile;
}


#ifndef _MINCORE

// Message handler for dialog box.
INT_PTR CALLBACK DialogHandler(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	char *fileName = NULL, *meshname = NULL, *meshid = NULL, *serverid = NULL, *serverurl = NULL, *installFlags = NULL, *mshfile = NULL;

	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		{
			// Get the current service running state
			int r = GetServiceState(serviceFile);
			char* txt = "";
			char selfexe[_MAX_PATH];

			switch (r)
			{
			case 0:
				txt = "Error";
				break;
			case SERVICE_STOPPED: 
				txt = "Stopped";
				break;
			case SERVICE_START_PENDING: 
				txt = "Start Pending";
				break;
			case SERVICE_STOP_PENDING: 
				txt = "Stop Pending";
				break;
			case SERVICE_RUNNING: 
				txt = "Running";
				break;
			case SERVICE_CONTINUE_PENDING: 
				txt = "Continue Pending";
				break;
			case SERVICE_PAUSE_PENDING: 
				txt = "Pause Pending";
				break;
			case SERVICE_PAUSED: 
				txt = "Paused";
				break;
			case 100: 
				txt = "Not Installed";
				break;
			}
			SetWindowTextA( GetDlgItem( hDlg, IDC_STATUSTEXT ), txt);

			// Get current executable path
			WCHAR wselfexe[MAX_PATH];
			GetModuleFileNameW(NULL, wselfexe, sizeof(wselfexe) / 2);
			ILibWideToUTF8Ex(wselfexe, -1, selfexe, (int)sizeof(selfexe));
			fileName = MeshAgent_MakeAbsolutePath(selfexe, ".msh");
			{
				DWORD               dwSize = 0;
				BYTE                *pVersionInfo = NULL;
				VS_FIXEDFILEINFO    *pFileInfo = NULL;
				UINT                pLenFileInfo = 0;
				int major, minor, hotfix, other;

				if ((dwSize = GetFileVersionInfoSizeW(wselfexe, NULL)))
				{					
					if ((pVersionInfo = malloc(dwSize)) == NULL) { ILIBCRITICALEXIT(254); }
					if (GetFileVersionInfoW(wselfexe, 0, dwSize, pVersionInfo))
					{
						if (VerQueryValue(pVersionInfo, TEXT("\\"), (LPVOID*)&pFileInfo, &pLenFileInfo))
						{
							// Display the version of this software
							major = (pFileInfo->dwFileVersionMS >> 16) & 0xffff;
							minor = (pFileInfo->dwFileVersionMS) & 0xffff;
							hotfix = (pFileInfo->dwFileVersionLS >> 16) & 0xffff;
							other = (pFileInfo->dwFileVersionLS) & 0xffff;
#ifdef _WIN64
							sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "v%d.%d.%d, 64bit", major, minor, hotfix);
#else
							sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "v%d.%d.%d", major, minor, hotfix);
#endif
							SetWindowTextA(GetDlgItem(hDlg, IDC_VERSIONTEXT), ILibScratchPad);
						}
					}
					free(pVersionInfo);
				}
			}

			if ((mshfile = getMshSettings(fileName, selfexe, &meshname, &meshid, &serverid, &serverurl, &installFlags)) != NULL)
			{
				// Set text in the dialog box
				int installFlagsInt = 0;
				WINDOWPLACEMENT lpwndpl;
				if (installFlags != NULL) { installFlagsInt = ILib_atoi2_int32(installFlags, 255); }
				if (strnlen_s(meshid, 255) > 50) { meshid += 2; meshid[42] = 0; }
				if (strnlen_s(serverid, 255) > 50) { serverid[42] = 0; }
				SetWindowTextA(GetDlgItem(hDlg, IDC_POLICYTEXT), (meshid != NULL) ? meshname : "(None)");
				SetWindowTextA(GetDlgItem(hDlg, IDC_HASHTEXT), (meshid != NULL) ? meshid : "(None)");
				SetWindowTextA(GetDlgItem(hDlg, IDC_SERVERLOCATION), (serverurl != NULL) ? serverurl : "(None)");
				SetWindowTextA(GetDlgItem(hDlg, IDC_SERVERID), (serverid != NULL) ? serverid : "(None)");
				free(mshfile);
				if (meshid == NULL) { EnableWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), FALSE); }
				if ((installFlagsInt & 3) == 1) {
					// Temporary Agent Only
					ShowWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), SW_HIDE);
					ShowWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), SW_HIDE);
					GetWindowPlacement(GetDlgItem(hDlg, IDC_INSTALLBUTTON), &lpwndpl);
					SetWindowPlacement(GetDlgItem(hDlg, IDC_CONNECTBUTTON), &lpwndpl);
				}  else if ((installFlagsInt & 3) == 2) {
					// Background Only
					ShowWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), SW_HIDE);
				} else if ((installFlagsInt & 3) == 3) {
					// Uninstall only
					GetWindowPlacement(GetDlgItem(hDlg, IDC_INSTALLBUTTON), &lpwndpl);
					SetWindowPlacement(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), &lpwndpl);
					ShowWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), SW_HIDE);
					ShowWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), SW_HIDE);
				}
			}
			else
			{
				EnableWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), FALSE);
			}

			return (INT_PTR)TRUE;
		}
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));

#ifdef _DEBUG
			_CrtCheckMemory();
			_CrtDumpMemoryLeaks();
#endif

			return (INT_PTR)TRUE;
		}
		else if (LOWORD(wParam) == IDC_INSTALLBUTTON || LOWORD(wParam) == IDC_UNINSTALLBUTTON)
		{
			BOOL result = FALSE;

			EnableWindow( GetDlgItem( hDlg, IDC_INSTALLBUTTON ), FALSE );
			EnableWindow( GetDlgItem( hDlg, IDC_UNINSTALLBUTTON ), FALSE );
			EnableWindow( GetDlgItem( hDlg, IDCANCEL ), FALSE );

			if (LOWORD(wParam) == IDC_INSTALLBUTTON)
			{
				result = RunAsAdmin("-fullinstall", IsAdmin() == TRUE);
			}
			else
			{
				result = RunAsAdmin("-fulluninstall", IsAdmin() == TRUE);
			}

			if (result)
			{
				EndDialog(hDlg, LOWORD(wParam));
			}
			else
			{
				EnableWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), TRUE);
				EnableWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), TRUE);
				EnableWindow(GetDlgItem(hDlg, IDCANCEL), TRUE);
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
			sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "connect --disableUpdate=1 --hideConsole=1 --exitPID=%u", pid);
			if (RunAsAdmin(ILibScratchPad, IsAdmin() == TRUE) == 0) { RunAsAdmin(ILibScratchPad, 1); }
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

#endif

#ifdef _MINCORE
BOOL WINAPI AreFileApisANSI(void) { return FALSE; }
VOID WINAPI FatalAppExitA(_In_ UINT uAction, _In_ LPCSTR lpMessageText) {}
HANDLE WINAPI CreateSemaphoreW(_In_opt_  LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, _In_ LONG lInitialCount, _In_ LONG lMaximumCount, _In_opt_ LPCWSTR lpName)
{
	return 0;
}
#endif
