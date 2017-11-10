/*
Copyright (c) 2016, Intel Corporation
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
* Neither the name of Intel Corporation nor the names of its contributors
may be used to endorse or promote products derived from this software
without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.
*/

#if defined(WINSOCK2)
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(WINSOCK1)
#include <winsock.h>
#include <wininet.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <windows.h>
#include "resource.h"
#include "../../microstack/ILibParsers.h"
#include "../lms/ILibLMS.h"

#if defined(WIN32) && defined (_DEBUG) && !defined(_MINCORE)
#include <crtdbg.h>
#define _CRTDBG_MAP_ALLOC
#endif

void *Chain = NULL;
struct ILibLMS_StateModule *MicroLMS = NULL;

#define VERSION "0.4.4" // Remember to change in the resources as well

int serviceId = 0; // 0 = MicroLMS, 1 = IntelLMS
TCHAR* serviceFile[2] = { TEXT("MicroLMS"), TEXT("LMS") };
TCHAR* serviceName[2] = { TEXT("MicroLMS Service for Intel(R) AMT"), TEXT("Intel(R) Management and Security Application Local Management Service") };
TCHAR* serviceDesc[2] = { TEXT("Provides Intel(R) Active Management Technology (Intel AMT) with local network connectivity and services."), TEXT("Intel(R) Management and Security Application Local Management Service - Provides OS-related Intel(R) ME functionality.") };
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle = 0;

void BreakSink(int s)
{
	UNREFERENCED_PARAMETER(s);
	signal(SIGINT, SIG_IGN);	// To ignore any more ctrl-c interrupts
	ILibStopChain(Chain);
}

BOOL IsAdmin()
{
	BOOL admin;
	PSID AdministratorsGroup;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

	if ((admin = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) != 0)
	{
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &admin)) admin = FALSE;
		FreeSid(AdministratorsGroup);
	}
	return admin;
}

void WINAPI ServiceControlHandler(DWORD controlCode)
{
	switch (controlCode)
	{
	case SERVICE_CONTROL_INTERROGATE:
		break;
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
		if (Chain != NULL) ILibStopChain(Chain);
		Chain = NULL;
		return;
	default:
		break;
	}

	SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	char selfexe[_MAX_PATH];
	size_t selfexelen = 0;

	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	// Find directory of our own executable 
	selfexelen = GetModuleFileNameA(NULL, selfexe, _MAX_PATH);

	// Initialise service status
	serviceStatus.dwServiceType = SERVICE_WIN32;
	serviceStatus.dwCurrentState = SERVICE_STOPPED;
	serviceStatus.dwControlsAccepted = 0;
	serviceStatus.dwWin32ExitCode = NO_ERROR;
	serviceStatus.dwServiceSpecificExitCode = NO_ERROR;
	serviceStatus.dwCheckPoint = 0;
	serviceStatus.dwWaitHint = 0;
	serviceStatusHandle = RegisterServiceCtrlHandler(serviceName[serviceId], ServiceControlHandler);

	if (serviceStatusHandle)
	{
		// Service is starting
		serviceStatus.dwCurrentState = SERVICE_START_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);

		// Service running
		serviceStatus.dwControlsAccepted |= (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
		serviceStatus.dwCurrentState = SERVICE_RUNNING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);

		// Run the MicroLMS Service
		CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
		Chain = ILibCreateChain();
		MicroLMS = ILibLMS_Create(Chain, selfexe, NULL);
		if (MicroLMS != NULL)
		{
			printf("Starting MicroLMS.\r\n");
			ILibStartChain(Chain);
			printf("Stopping MicroLMS.\r\n");
		}
		else
		{
			printf("Unable to launch MicroLMS. Check that Intel ME is present, MEI driver installed and run this executable as administrator.\r\n");
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

int RunService()
{
	SERVICE_TABLE_ENTRY serviceTable[2];
	serviceTable[0].lpServiceName = serviceName[serviceId];
	serviceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
	serviceTable[1].lpServiceName = NULL;
	serviceTable[1].lpServiceProc = NULL;
	return StartServiceCtrlDispatcher(serviceTable);
}

BOOL InstallService()
{
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
	SERVICE_DESCRIPTION sd;
	SERVICE_DELAYED_AUTO_START_INFO as;
	SERVICE_FAILURE_ACTIONS fa;
	SC_ACTION failactions[3];
	BOOL r = FALSE;

	if (serviceControlManager)
	{
		char path[1024];
		if (GetModuleFileName(0, (LPTSTR)path, 1024) > 0)
		{
			// Install the service
			SC_HANDLE service = CreateService(
				serviceControlManager,
				serviceFile[serviceId],
				serviceName[serviceId],
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
				SERVICE_AUTO_START,
				SERVICE_ERROR_IGNORE,
				(LPCTSTR)path,
				0, 0, 0, 0, 0);

			if (service)
			{
				// Update the service description
				sd.lpDescription = serviceDesc[serviceId];
				ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &sd);

				// Update the service auto-start
				as.fDelayedAutostart = FALSE;
				ChangeServiceConfig2(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &as);

				// Update the faliure action
				failactions[0].Type = SC_ACTION_RESTART;
				failactions[0].Delay = 120000;				// Wait 2 minutes before faliure restart (milliseconds)
				failactions[1].Type = SC_ACTION_RESTART;
				failactions[1].Delay = 120000;				// Wait 2 minutes before faliure restart (milliseconds)
				failactions[2].Type = SC_ACTION_NONE;
				failactions[2].Delay = 120000;
				memset(&fa, 0, sizeof(SERVICE_FAILURE_ACTIONS));
				fa.dwResetPeriod = 86400;					// After 1 days, reset the faliure counters (seconds)
				fa.cActions = 3;
				fa.lpsaActions = failactions;
				r = ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

				// Cleanup
				CloseServiceHandle(service);
#ifdef _DEBUG
				//ILIBMESSAGE("MicroLMS service installed successfully");
#endif
			}
			else
			{
#ifdef _DEBUG
				if (GetLastError() == ERROR_SERVICE_EXISTS)
				{
					ILIBMESSAGE("MicroLMS service already exists.");
				}
				else
				{
					ILIBMESSAGE2("MicroLMS service was not installed successfully.", (int)GetLastError());
				}
#endif
			}
		}

		CloseServiceHandle(serviceControlManager);
	}
	return r;
}

int UninstallService()
{
	int r = 0;
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService(serviceControlManager, serviceFile[serviceId], SERVICE_QUERY_STATUS | DELETE);
		if (service)
		{
			SERVICE_STATUS serviceStatus;
			if (QueryServiceStatus(service, &serviceStatus))
			{
				if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
				{
					if (DeleteService(service))
					{
#ifdef _DEBUG
						//ILIBMESSAGE("MicroLMS service removed successfully");
#endif
						r = 1;
					}
					else
					{
#ifdef _DEBUG
						DWORD dwError = GetLastError();
						if (dwError == ERROR_ACCESS_DENIED) {
							ILIBMESSAGE("Access denied while trying to remove MicroLMS service");
						}
						else if (dwError == ERROR_INVALID_HANDLE) {
							ILIBMESSAGE("Handle invalid while trying to remove MicroLMS service");
						}
						else if (dwError == ERROR_SERVICE_MARKED_FOR_DELETE) {
							ILIBMESSAGE("MicroLMS service already marked for deletion");
						}
#endif
					}
				}
				else
				{
					r = 2;
#ifdef _DEBUG
					ILIBMESSAGE("MicroLMS service is still running");
#endif
				}
			}
			CloseServiceHandle(service);
		}
		CloseServiceHandle(serviceControlManager);
	}
	return r;
}

int GetServiceState(LPCWSTR servicename)
{
	int r = 0;
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService(serviceControlManager, servicename, SERVICE_QUERY_STATUS | DELETE);
		if (service)
		{
			SERVICE_STATUS serviceStatus;
			if (QueryServiceStatus(service, &serviceStatus))
			{
				r = serviceStatus.dwCurrentState;
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

int LaunchService(LPCWSTR servicename)
{
	int r = 0;
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SERVICE_QUERY_STATUS | SERVICE_START);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService(serviceControlManager, servicename, SERVICE_QUERY_STATUS | SERVICE_START);
		if (service)
		{
			SERVICE_STATUS serviceStatus;
			if (QueryServiceStatus(service, &serviceStatus))
			{
				if (serviceStatus.dwCurrentState == SERVICE_STOPPED) { if (StartService(service, 0, NULL) == TRUE) { r = 1; } }
				else { r = 2; }
			}
			CloseServiceHandle(service);
		}
		CloseServiceHandle(serviceControlManager);
	}
	return r;
}

int StopService(LPCWSTR servicename)
{
	int r = 0;
	SERVICE_STATUS ServiceStatus;
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SERVICE_QUERY_STATUS | SERVICE_STOP);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService(serviceControlManager, servicename, SERVICE_QUERY_STATUS | SERVICE_STOP);
		if (service)
		{
			SERVICE_STATUS serviceStatus;
			if (QueryServiceStatus(service, &serviceStatus))
			{
				if (serviceStatus.dwCurrentState != SERVICE_STOPPED)
				{
					if (ControlService(service, SERVICE_CONTROL_STOP, &ServiceStatus) == FALSE)
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
			CloseServiceHandle(service);
		}
		CloseServiceHandle(serviceControlManager);
	}
	return r;
}

int RunProcess(char* exe)
{
	BOOL r;
	int count = 50;
	DWORD exitcode;
	STARTUPINFOA info = { sizeof(info) };
	PROCESS_INFORMATION processInfo;
	if (CreateProcessA(NULL, exe, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &info, &processInfo) == 0) return 0;
	do
	{
		Sleep(100);
		r = GetExitCodeProcess(processInfo.hProcess, &exitcode);
		if (exitcode == STILL_ACTIVE) r = 0;
	} while (r == 0 && count-- > 0);
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
	return r;
}

#ifdef EXCLUSESERVICE
char *helpString = "MicroLMS v" VERSION " available switches : \r\n  -run                 Run LMS as a console application.\r\n  -json                Output Intel AMT information in JSON format.\r\n  -install             Install the service from this location.\r\n  -uninstall           Remove the service from this location.\r\n  start                Start the service.\r\n  stop                 Stop the service.\r\n  auth [user] [pass]   Set LMS authentication.\r\n  clearauth            Clear LMS authentication.\r\n  version              Display Intel(R) AMT version.\r\n  check                Check if Intel(R) AMT requires a firmware update.\r\n";
#else
char *helpString = "MicroLMS v" VERSION " available switches : \r\n  -run                 Run LMS as a console application.\r\n  version              Display Intel(R) AMT version.\r\n  check                Check if Intel(R) AMT requires a firmware update.\r\n";
#endif
char *lmsStartStrings[3] = { "Failed to start MicroLMS", "Started MicroLMS", "MicroLMS already running" };
char *lmsUninstallStrings[3] = { "Failed to uninstall MicroLMS", "MicroLMS uninstalled", "MicroLMS still running" };

int main(int argc, char* argv[])
{
	int returnCode = 0;
	char selfexe[_MAX_PATH];
	size_t selfexelen = 0;

	//CoInitializeEx(NULL, COINIT_MULTITHREADED);
	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	// Find directory of our own executable 
	selfexelen = GetModuleFileNameA(NULL, selfexe, _MAX_PATH);

	if (argc == 2 && ((strcasecmp(argv[1], "-?") == 0) || (strcasecmp(argv[1], "/?") == 0)))
	{
		printf(helpString);
		return 0;
	}
#ifdef EXCLUSESERVICE
	else if (argc > 1 && (strcasecmp(argv[1], "start") == 0 || strcasecmp(argv[1], "-start") == 0))
	{
		// Ask the service manager to launch the service
		printf(lmsStartStrings[LaunchService(serviceFile[serviceId])]);
	}
	else if (argc > 1 && (strcasecmp(argv[1], "stop") == 0 || strcasecmp(argv[1], "-stop") == 0))
	{
		// Ask the service manager to stop the service
		if (StopService(serviceFile[serviceId]) == 1) { printf("Stopped MicroLMS"); }
		else { printf("Failed to stop MicroLMS"); }
	}
	else if (argc > 1 && strcasecmp(argv[1], "-install") == 0)
	{
		// Setup the service
		StopService(serviceFile[serviceId]);
		UninstallService();
		if (InstallService() == TRUE)
		{
			printf("MicroLMS installed\r\n");
			printf(lmsStartStrings[LaunchService(serviceFile[serviceId])]); // Ask the service manager to launch the service
		}
		else
		{
			printf("Failed to install MicroLMS");
		}
	}
	else if (argc > 1 && ((strcasecmp(argv[1], "-remove") == 0) || (strcasecmp(argv[1], "-uninstall") == 0)))
	{
		// Ask the service manager to stop the service
		StopService(serviceFile[serviceId]);

		// Remove the service
		printf(lmsUninstallStrings[UninstallService()]);
	}
	else if (argc > 1 && (strcasecmp(argv[1], "intelstart") == 0 || strcasecmp(argv[1], "-intelstart") == 0))
	{
		// Ask the service manager to launch the service
		serviceId = 1; // Set to Intel
		printf(lmsStartStrings[LaunchService(serviceFile[serviceId])]);
	}
	else if (argc > 1 && (strcasecmp(argv[1], "intelstop") == 0 || strcasecmp(argv[1], "-intelstop") == 0))
	{
		// Ask the service manager to stop the service
		serviceId = 1; // Set to Intel
		if (StopService(serviceFile[serviceId]) == 1) { printf("Stopped MicroLMS"); }
		else { printf("Failed to stop MicroLMS"); }
	}
	else if (argc > 1 && strcasecmp(argv[1], "-intelinstall") == 0)
	{
		// Setup the service
		serviceId = 1; // Set to Intel
		StopService(serviceFile[serviceId]);
		UninstallService();
		if (InstallService() == TRUE)
		{
			printf("MicroLMS installed\r\n");
			printf(lmsStartStrings[LaunchService(serviceFile[serviceId])]); // Ask the service manager to launch the service
		}
		else
		{
			printf("Failed to install MicroLMS");
		}
	}
	else if (argc > 1 && ((strcasecmp(argv[1], "-intelremove") == 0) || (strcasecmp(argv[1], "-inteluninstall") == 0)))
	{
		// Ask the service manager to stop the service
		serviceId = 1; // Set to Intel
		StopService(serviceFile[serviceId]);

		// Remove the service
		printf(lmsUninstallStrings[UninstallService()]);
	}
	else if (argc == 4 && ((strcasecmp(argv[1], "auth") == 0) || (strcasecmp(argv[1], "-auth") == 0)))
	{
		// Set authentication user/pass
		ILibLMS_setregistryA("username", argv[2]);
		ILibLMS_setregistryA("password", argv[3]);
		printf("Credentials set");
	}
	else if (argc == 2 && strcasecmp(argv[1], "clearauth") == 0)
	{
		// Remote authentication user/pass
		ILibLMS_deleteregistryA("username");
		ILibLMS_deleteregistryA("password");
		printf("Credentials cleared");
	}
	else if (argc > 1 && ((strcasecmp(argv[1], "json") == 0) || (strcasecmp(argv[1], "-json") == 0)))
	{
		// Ask the service manager to stop the service
		char* data;
		int len = info_GetMeInformation(&data, 0);
		if (len == 2)
		{
			printf("Unable to launch MicroLMS. Check that Intel ME is present, MEI driver installed and running as administrator.\r\n");
			returnCode = 1;
		}
		else
		{
			printf(data + 2);
		}
		free(data);
	}
#endif
	else if (argc > 1 && ((strcasecmp(argv[1], "version") == 0) || (strcasecmp(argv[1], "-version") == 0)))
	{
		// Check to see what version of Intel AMT is present and if it needs to be updates
		int version = info_GetAmtVersion();
		if (version == 0)
		{
			printf("Unable to launch MicroLMS. Check that Intel ME is present, MEI driver installed and running as administrator.\r\n");
			returnCode = 1;
		}
		else
		{
			printf("Intel(R) AMT version %d.%d.%d\r\n", (version >> 16), ((version >> 8) & 0xFF), (version & 0xFF));
		}
	}
	else if (argc > 1 && ((strcasecmp(argv[1], "check") == 0) || (strcasecmp(argv[1], "-check") == 0)))
	{
		// Check to see what version of Intel AMT is present and if it needs to be updates
		int version = info_GetAmtVersion();
		if (version == 0)
		{
			printf("Unable to launch MicroLMS. Check that Intel ME is present, MEI driver installed and running as administrator.\r\n");
			returnCode = 1;
		}
		else
		{
			// Check if this is a correct version of Intel AMT
			int v1 = (version >> 16), v2 = (version >> 8) & 0xFF, v3 = version & 0xFF, vx = ((v2 * 1000) + v3), ok = 0;
			printf("Intel(R) AMT version %d.%d.%d\r\n", v1, v2, v3);
			if ((v1 <= 5) || (v1 >= 12)) { ok = 1; } // Intel AMT less then v5 and v12 and beyond, all ok.
			else if ((v1 == 6) && (vx >= 2061)) { ok = 1; } // 1st Gen Core
			else if ((v1 == 7) && (vx >= 1091)) { ok = 1; } // 2st Gen Core
			else if ((v1 == 8) && (vx >= 1071)) { ok = 1; } // 3st Gen Core
			else if ((v1 == 9)) { if ((v2 < 5) && (vx >= 1041)) { ok = 1; } else if (vx >= 5061) { ok = 1; } } // 4st Gen Core
			else if ((v1 == 10) && (vx >= 55)) { ok = 1; } // 5st Gen Core
			else if (v1 == 11) {
				if ((v2 < 5) && (vx >= 25)) { ok = 1; } // 6st Gen Core
				else if (vx >= 6027) { ok = 1; } // 7st Gen Core
			}
			if (ok == 0) {
				printf("This computer requires a firmware update.\r\nPlease check: https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&languageid=en-fr\r\nExit code 2\r\n");
				returnCode = 2;
			}
		}
	}
	else if (argc > 1 && (strcasecmp(argv[1], "run") == 0 || strcasecmp(argv[1], "-run") == 0))
	{
		// Run as an command line application
		Chain = ILibCreateChain();
		MicroLMS = ILibLMS_Create(Chain, selfexe, NULL);
		if (MicroLMS != NULL)
		{
#ifdef NOCOMMANDER
			printf("Starting MicroLMS-lite v" VERSION ", CTRL-C to stop.\r\n");
#elif
			printf("Starting MicroLMS v" VERSION ", CTRL-C to stop.\r\nWeb Application at http://127.0.0.1:16994.\r\n");
#endif
			ILibStartChain(Chain);
			printf("Stopping MicroLMS.\r\n");
		}
		else
		{
			printf("Unable to launch MicroLMS. Check that Intel ME is present, MEI driver installed and running as administrator.\r\n");
			returnCode = 1;
		}
	}
#ifdef EXCLUSESERVICE
	else
	{
		if (RunService() == 0 && GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
		{
			// Shutdown on Ctrl + C
			signal(SIGINT, BreakSink);

			printf(helpString);
			return 0;
		}
	}
#else
	else
	{
		printf(helpString);
	}
#endif

	CoUninitialize();
	return returnCode;
}

