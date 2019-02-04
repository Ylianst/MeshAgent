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
TCHAR* serviceFileOld = TEXT("Mesh Agent v2");
TCHAR* serviceName = TEXT("Mesh Agent background service");
TCHAR* serviceDesc = TEXT("Remote monitoring and management service.");

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle = 0;
INT_PTR CALLBACK DialogHandler(HWND, UINT, WPARAM, LPARAM);

MeshAgentHostContainer *agent = NULL;

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

BOOL RunAsAdmin(char* args) {
	char szPath[_MAX_PATH + 100];
	if (GetModuleFileNameA(NULL, szPath, _MAX_PATH))
	{
		SHELLEXECUTEINFO sei = { sizeof(sei) };
		sei.hwnd = NULL;
		sei.nShow = SW_NORMAL;
		sei.lpVerb = "runas";
		sei.lpFile = szPath;
		sei.lpParameters = args;
		return ShellExecuteExA(&sei);
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


// Add the uninstallation icon in the Windows Control Panel.
void WINAPI AddUninstallIcon()
{
	/*
	[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MeshAgent]
	"DisplayName"="Mesh Agent Service - Remote Control Software"
	"Publisher"="MeshCentral"
	"MajorVersion"="2"
	"MinorVersion"="13"
	"InstallLocation"="C:\\Program Files\\Mesh Agent"
	"UninstallString"="C:\\Program Files\\Mesh Agent\\meshuninstaller.bat"
	"DisplayIcon"="C:\\Program Files\\Mesh Agent\\MeshAgent.exe"
	"DisplayVersion"="2.1.3"
	"URLInfoAbout"="http://www.meshcentral.com/"
	"VersionMajor"=dword:00000002
	"VersionMinor"=dword:00000013
	"EstimatedSize"=dword:00208000
	"NoModify"=dword:00000001
	"NoRepair"=dword:00000001
	*/

	int i;
	HKEY hKey;
	if (RegCreateKey(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MeshCentralAgent", &hKey) == ERROR_SUCCESS)
	{
		LPCTSTR str;
		char targetexe[_MAX_PATH + 40];
		size_t targetexelen = 0;

		str = "MeshCentral Agent - Remote Control Software\0";
		RegSetValueEx(hKey, "DisplayName", 0, REG_SZ, (LPBYTE)str, (DWORD)strlen(str)+1);

		str = "Open Source\0";
		RegSetValueEx(hKey, "Publisher", 0, REG_SZ, (LPBYTE)str, (DWORD)strlen(str) + 1);

		str = "1\0";
		RegSetValueEx(hKey, "MajorVersion", 0, REG_SZ, (LPBYTE)str, (DWORD)strlen(str) + 1);

		str = "0\0";
		RegSetValueEx(hKey, "MinorVersion", 0, REG_SZ, (LPBYTE)str, (DWORD)strlen(str) + 1);

		// Install location
		if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, targetexe) != S_FALSE) {
			targetexelen = strnlen_s(targetexe, _MAX_PATH + 40);
			if (targetexelen <= MAX_PATH) {
				memcpy_s(targetexe + targetexelen, _MAX_PATH + 40 - targetexelen, "\\Mesh Agent\\\0", 13);
				RegSetValueEx(hKey, "InstallLocation", 0, REG_SZ, (LPBYTE)targetexe, (DWORD)strlen(targetexe) + 1);
			}
		}

		// Uninstall command
		if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, targetexe) != S_FALSE) {
			targetexelen = strnlen_s(targetexe, _MAX_PATH + 40);
			if (targetexelen <= MAX_PATH) {
				memcpy_s(targetexe + targetexelen, _MAX_PATH + 40 - targetexelen, "\\Mesh Agent\\MeshAgent.exe -fulluninstall\0", 41);
				RegSetValueEx(hKey, "UninstallString", 0, REG_SZ, (LPBYTE)targetexe, (DWORD)strlen(targetexe) + 1);
			}
		}

		// Display icon
		if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, targetexe) != S_FALSE) {
			targetexelen = strnlen_s(targetexe, _MAX_PATH + 40);
			if (targetexelen <= MAX_PATH) {
				memcpy_s(targetexe + targetexelen, _MAX_PATH + 40 - targetexelen, "\\Mesh Agent\\MeshAgent.exe\0", 26);
				RegSetValueEx(hKey, "DisplayIcon", 0, REG_SZ, (LPBYTE)targetexe, (DWORD)strlen(targetexe) + 1);
			}
		}

		str = "1.0.0\0";
		RegSetValueEx(hKey, "DisplayVersion", 0, REG_SZ, (LPBYTE)str, (DWORD)strlen(str) + 1);

		str = "http://www.meshcentral.com/\0"; // TODO - Change this to .msg content
		RegSetValueEx(hKey, "URLInfoAbout", 0, REG_SZ, (LPBYTE)str, (DWORD)strlen(str) + 1);

		i = 2;
		RegSetValueEx(hKey, "VersionMajor", 0, REG_DWORD, (BYTE*)&i, (DWORD)4);

		i = 13;
		RegSetValueEx(hKey, "VersionMinor", 0, REG_DWORD, (BYTE*)&i, (DWORD)4);

		i = 0x00208000;
		RegSetValueEx(hKey, "EstimatedSize", 0, REG_DWORD, (BYTE*)&i, (DWORD)4);

		i = 1;
		RegSetValueEx(hKey, "NoModify", 0, REG_DWORD, (BYTE*)&i, (DWORD)4);
		RegSetValueEx(hKey, "NoRepair", 0, REG_DWORD, (BYTE*)&i, (DWORD)4);

		RegCloseKey(hKey);
	}
	else
	{
		printf("Error writing to registry, try running as administrator.");
	}

}


void WINAPI RemoveUninstallIcon()
{
	RegDeleteKey(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MeshCentralAgent");
}


void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	CONTEXT winException;
	size_t len = 0;
	WCHAR str[_MAX_PATH];
	char selfexe[_MAX_PATH];
	char *selfexe_ptr[] = { selfexe };

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
		if (GetModuleFileNameW(NULL, str, _MAX_PATH) > 5)
		{
			wcstombs_s(&len, selfexe, _MAX_PATH, str, _MAX_PATH);
		}

#ifndef _MINCORE
		// Setup firewall
		SetupWindowsFirewall(str);
#endif

		// Run the mesh agent
		CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

		__try
		{
			agent = MeshAgent_Create(0);
			MeshAgent_Start(agent, 1, selfexe_ptr);
			agent = NULL;
		}
		__except (ILib_WindowsExceptionFilter(GetExceptionCode(), GetExceptionInformation(), &winException))
		{
			ILib_WindowsExceptionDebug(&winException);
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
	serviceTable[0].lpServiceName = serviceName;
	serviceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
	serviceTable[1].lpServiceName = NULL;
	serviceTable[1].lpServiceProc = NULL;

	return StartServiceCtrlDispatcher( serviceTable );
}

BOOL InstallService()
{
	SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SC_MANAGER_CREATE_SERVICE );
	SERVICE_DESCRIPTION sd;
	SERVICE_DELAYED_AUTO_START_INFO as;
	SERVICE_FAILURE_ACTIONS fa;
	SC_ACTION failactions[3];
	BOOL r = FALSE;

	if ( serviceControlManager )
	{
		char path[1024];
		if (GetModuleFileName( 0, (LPTSTR)path, 1024) > 0)
		{
			// Install the service
			SC_HANDLE service = CreateService( 
				serviceControlManager,
				serviceFile,
				serviceName,
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
				SERVICE_AUTO_START,
				SERVICE_ERROR_IGNORE,
				(LPCTSTR)path,
				0, 0, 0, 0, 0 );

			if (service)
			{
				// Update the service description
				sd.lpDescription = serviceDesc;
				ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &sd);

				// Update the service auto-start
				as.fDelayedAutostart = FALSE;
				ChangeServiceConfig2(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &as);

				// Update the faliure action
				failactions[0].Type = SC_ACTION_RESTART;
				failactions[0].Delay = 60000;                          // Wait 1 minutes before faliure restart (milliseconds)
				failactions[1].Type = SC_ACTION_RESTART;
				failactions[1].Delay = 60000;                          // Wait 1 minutes before faliure restart (milliseconds)
				failactions[2].Type = SC_ACTION_RESTART;
				failactions[2].Delay = 60000;
				memset(&fa, 0, sizeof(SERVICE_FAILURE_ACTIONS));
				fa.dwResetPeriod = 86400;					// After 1 days, reset the faliure counters (seconds)
				fa.cActions = 3;
				fa.lpsaActions = failactions;
				r = ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

				// Cleanup
				CloseServiceHandle( service );
				#ifdef _DEBUG
				//ILIBMESSAGE("Mesh service installed successfully");
				#endif
			}
			else
			{
				#ifdef _DEBUG
				if(GetLastError() == ERROR_SERVICE_EXISTS)
				{
					ILIBMESSAGE("Mesh service already exists.");
				}
				else
				{
					ILIBMESSAGE("Mesh service was not Installed Successfully.");
				}
				#endif
			}
		}

		CloseServiceHandle( serviceControlManager );
	}
	return r;
}

int UninstallService(TCHAR* serviceName)
{
	int r = 0;
	SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SC_MANAGER_CONNECT);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService( serviceControlManager, serviceName, SERVICE_QUERY_STATUS | DELETE );
		if (service)
		{
			SERVICE_STATUS serviceStatusEx;
			if ( QueryServiceStatus( service, &serviceStatusEx ) )
			{
				if ( serviceStatusEx.dwCurrentState == SERVICE_STOPPED )
				{
					if (DeleteService(service))
					{
						#ifdef _DEBUG
						//ILIBMESSAGE("Mesh service removed successfully");
						#endif
						r = 1;
					}
					else
					{
						#ifdef _DEBUG
						DWORD dwError = GetLastError();
						if(dwError == ERROR_ACCESS_DENIED) {
							ILIBMESSAGE("Access denied while trying to remove mesh service");
						}
						else if(dwError == ERROR_INVALID_HANDLE) {
							ILIBMESSAGE("Handle invalid while trying to remove mesh service");
						}
						else if(dwError == ERROR_SERVICE_MARKED_FOR_DELETE) {
							ILIBMESSAGE("Mesh service already marked for deletion");
						}
						#endif
					}
				}
				else
				{
					r = 2;
					#ifdef _DEBUG
					ILIBMESSAGE("Mesh service is still running");
					#endif
				}
			}
			CloseServiceHandle( service );
		}
		CloseServiceHandle( serviceControlManager );
	}
	return r;
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
		SC_HANDLE service = OpenService( serviceControlManager, servicename, SERVICE_QUERY_STATUS | DELETE );
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

int RunProcess(char* exe, int waitForExit)
{
	BOOL r = TRUE;
	int count = 50;
	DWORD exitcode;
	STARTUPINFOA info = {sizeof(info)};
	PROCESS_INFORMATION processInfo;
	if (CreateProcessA(NULL, exe, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &info, &processInfo) == 0) return 0;
	if (waitForExit != 0) {
		do
		{
			Sleep(100);
			r = GetExitCodeProcess(processInfo.hProcess, &exitcode);
			if (exitcode == STILL_ACTIVE) r = 0;
		} while (r == 0 && count-- > 0);
	}
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
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

#ifndef _MINCORE
void fullinstall(int uninstallonly, char* proxy, int proxylen, char* tag, int taglen)
{
	int r = 0;
	int loops = 0;
	char targetexe2[_MAX_PATH + 40];
	char *targetexe = targetexe2 + 1;
	size_t targetexelen = 0;
	char selfexe[_MAX_PATH];
	size_t selfexelen = 0;
	char setup1[_MAX_PATH];
	char setup2[_MAX_PATH];
	int setup1len;
	int setup2len;

	if (IsAdmin() == FALSE) { printf("Requires administrator permissions.\r\n"); return; }
	if (uninstallonly != 0) { printf("Performing uninstall...\r\n"); } else { printf("Performing install...\r\n"); }

	// Stop and remove the service
	StopService(serviceFile);

	// Wait for the service to stop
	int serviceStateLoopCount = 0;;
	int serviceState;
	do {
		serviceStateLoopCount++;
		Sleep(100);
		serviceState = GetServiceState(serviceFile);
	} while ((serviceState == 3) && (serviceStateLoopCount < 400));
	UninstallService(serviceFile);
	UninstallService(serviceFileOld);

	// Get our own executable
	selfexelen = GetModuleFileNameA(NULL, selfexe, _MAX_PATH);

	// Get the target executable
	if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, targetexe) != S_FALSE)
	{
		targetexe2[0] = '\"';
		targetexelen = strnlen_s(targetexe, _MAX_PATH + 40);
		if (targetexelen <= MAX_PATH) memcpy_s(targetexe + targetexelen, _MAX_PATH + 40 - targetexelen, "\\Mesh Agent\\MeshAgent.exe\" -uninstall", 38);
		targetexelen += 25;
	}

	// Check if we are uninstalling ourself
	if ((uninstallonly != 0) && (targetexelen == selfexelen) && (memcmp(selfexe, targetexe, targetexelen) == 0)) {
		// Copy ourself to a temp folder and run full uninstall.
		char tempPath[_MAX_PATH + 40];
		int tempPathLen = GetTempPathA(_MAX_PATH, tempPath);
		memcpy_s(tempPath + tempPathLen, _MAX_PATH + 40 - tempPathLen, "MeshAgent.exe\0", 15);
		remove(tempPath);
		util_CopyFile(selfexe, tempPath, FALSE);
		memcpy_s(tempPath + tempPathLen, _MAX_PATH + 40 - tempPathLen, "MeshAgent.exe -fulluninstall\0", 30);
		RunProcess(tempPath, 0); // Don't wait for the process to terminate since we want to self-delete.
		return;
	}

	// Call uninstall, this will remove the firewall rules.
	RunProcess(targetexe2, 1);

#ifdef _MINCORE
	// Remove the MeshAgent registry keys
	RegDeleteKeyEx(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent2", KEY_WOW64_32KEY, 0);
	RegDeleteKeyEx(HKEY_CURRENT_USER, "Software\\Open Source\\MeshAgent2", KEY_WOW64_32KEY, 0);
#else
	// Remove the MeshAgent registry keys
	RegDeleteKey(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent2");
	RegDeleteKey(HKEY_CURRENT_USER, "Software\\Open Source\\MeshAgent2");
#endif

	// Remove the uninstall icon from the control panel if present
	RemoveUninstallIcon();

	// Check if selfexe is already located at the target, if so, skip to copy steps.
	if ((uninstallonly != 0) || (targetexelen != selfexelen) || (memcmp(selfexe, targetexe, targetexelen) != 0))
	{
		// Remove the target executable, wait if needed
		int selfExeDelLoopCount = 0;;
		int selfExeDel;
		targetexe[targetexelen] = 0;
		do {
			Sleep(100);
			selfExeDelLoopCount++;
			selfExeDel = remove(targetexe);
		} while ((selfExeDel != 0) && (selfExeDel != -1) && (selfExeDelLoopCount < 400));

		// Remove "[Executable].msh" file
		if ((setup2len = (int)strnlen_s(targetexe, _MAX_PATH + 40)) < 4 || setup2len > 259) return;
		memcpy_s(setup2, sizeof(setup2), targetexe, setup2len);
		memcpy_s(setup2 + (setup2len - 3), sizeof(setup2) - setup2len - 3, "msh", 4);
		setup2[setup2len] = 0;
		remove(setup2);

		// Remove "[Executable].mshx" file
		if ((setup2len = (int)strnlen_s(targetexe, _MAX_PATH + 40)) < 4 || setup2len > 259) return;
		memcpy_s(setup2, sizeof(setup2), targetexe, setup2len);
		memcpy_s(setup2 + (setup2len - 3), sizeof(setup2) - setup2len - 3, "mshx", 5);
		setup2[setup2len + 1] = 0;
		remove(setup2);


		// Remove "[Executable].proxy" file
		if ((setup2len = (int)strnlen_s(targetexe, _MAX_PATH + 40)) < 4 || setup2len > 257) return;
		memcpy_s(setup2, sizeof(setup2), targetexe, setup2len);
		memcpy_s(setup2 + (setup2len - 3), sizeof(setup2) - setup2len - 3, "proxy", 6);
		setup2[setup2len + 2] = 0;
		remove(setup2);

		if (uninstallonly != 0) {
			// Remove "[Executable].tag" file
			if ((setup2len = (int)strnlen_s(targetexe, _MAX_PATH + 40)) < 4 || setup2len > 259) return;
			memcpy_s(setup2, sizeof(setup2), targetexe, setup2len);
			memcpy_s(setup2 + (setup2len - 3), sizeof(setup2) - setup2len - 3, "tag", 4);
			setup2[setup2len] = 0;
			remove(setup2);

			// Remove "[Executable].log" file
			if ((setup2len = (int)strnlen_s(targetexe, _MAX_PATH + 40)) < 4 || setup2len > 259) return;
			memcpy_s(setup2, sizeof(setup2), targetexe, setup2len);
			memcpy_s(setup2 + (setup2len - 3), sizeof(setup2) - setup2len - 3, "log", 4);
			setup2[setup2len] = 0;
			remove(setup2);

			// Remove "[Executable].db" file
			if ((setup2len = (int)strnlen_s(targetexe, _MAX_PATH + 40)) < 4 || setup2len > 256) return;
			memcpy_s(setup2, sizeof(setup2), targetexe, setup2len);
			memcpy_s(setup2 + (setup2len - 3), sizeof(setup2) - setup2len - 3, "db", 3);
			setup2[setup2len] = 0;
			remove(setup2);
		}

		// Remove the folder.
		targetexe[targetexelen - 14] = 0;
		RemoveDirectoryA(targetexe);

		if (uninstallonly != 0) return;

		// Get the target executable, create folders if needed
		if (!CreateDirectoryA(targetexe, NULL) && GetLastError() == ERROR_ACCESS_DENIED) { ILIBMESSAGE("Access denied (1)"); return; }
		targetexe[targetexelen - 14] = '\\';

		// Attempt to copy our own exe over the original exe
		loops = 0;
		while (!util_CopyFile(selfexe, targetexe, TRUE))
		{
			if (GetLastError() == ERROR_ACCESS_DENIED) { ILIBMESSAGE("Access denied (2)"); return; }
			if (loops++ > 5) { ILIBMESSAGE("Error copying executable file"); return; }
			Sleep(5000);
		}

		// Try to copy "[Executable].msh" file to target directory
		if ((setup1len = (int)strnlen_s(selfexe, sizeof(selfexe))) < 4) return;
		memcpy_s(setup1, sizeof(setup1), selfexe, setup1len);
		memcpy_s(setup1 + (setup1len - 3), sizeof(setup1) - setup1len - 3, "msh", 4);
		if ((setup2len = (int)strnlen_s(targetexe, _MAX_PATH + 40)) < 4 || setup2len > 259) return;
		memcpy_s(setup2, sizeof(setup2), targetexe, setup2len);
		memcpy_s(setup2 + (setup2len - 3), sizeof(setup2) - setup2len - 3, "msh", 4);
		util_CopyFile(setup1, setup2, TRUE);

		// Write the tag if one was passed
		if (tag != NULL)
		{
			FILE *SourceFile = NULL;
			if ((setup2len = (int)strnlen_s(targetexe, _MAX_PATH + 40)) < 4 || setup2len > 259) return;
			memcpy_s(setup2, sizeof(setup2), targetexe, setup2len);
			memcpy_s(setup2 + (setup2len - 3), sizeof(setup2) - setup2len - 3, "tag", 4);
			if (taglen > 0) {
				fopen_s(&SourceFile, setup2, "wb");
				if (SourceFile != NULL)
				{
					if (fwrite(tag, sizeof(char), taglen, SourceFile)) {}
					fclose(SourceFile);
				}
			}
			else
			{
				remove(setup2);
			}
		}

		// Setup proxy filenames
		if ((setup1len = (int)strnlen_s(selfexe, sizeof(selfexe))) < 4) return;
		memcpy_s(setup1, sizeof(setup1), selfexe, setup1len);
		memcpy_s(setup1 + (setup1len - 3), sizeof(setup1) - setup1len - 3, "proxy", 6);
		if ((setup2len = (int)strnlen_s(targetexe, _MAX_PATH + 40)) < 4 || setup2len > 259) return;
		memcpy_s(setup2, sizeof(setup2), targetexe, setup2len);
		memcpy_s(setup2 + (setup2len - 3), sizeof(setup2) - setup2len - 3, "proxy", 6);

		if (proxy != NULL && proxylen > 0)
		{
			// Use the specified proxy in the command line switch
			FILE *SourceFile = NULL;
			fopen_s(&SourceFile, setup2, "wb");
			if (SourceFile != NULL)
			{
				if (fwrite(proxy, sizeof(char), proxylen, SourceFile)) {}
				fclose(SourceFile);
			}
		}
		else
		{
			// Try to copy "[Executable].proxy" file to target directory
			if (util_CopyFile(setup1, setup2, TRUE) == FALSE)
			{
				// Failed to copy proxy file, lets try to create one.
				WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyEx;
				if (WinHttpGetIEProxyConfigForCurrentUser(&proxyEx))
				{
					if (proxyEx.lpszProxy != NULL)
					{
						FILE *SourceFile = NULL;
						size_t len;
						if (wcstombs_s(&len, ILibScratchPad, 4095, proxyEx.lpszProxy, 2000) == 0)
						{
							char* ptr = strstr(ILibScratchPad, "https=");
							if (ptr != NULL) {
								char* ptr2 = strstr(ptr, ";");
								ptr += 6;
								if (ptr2 != NULL) ptr2[0] = 0;
							} else {
								ptr = ILibScratchPad;
							}
							fopen_s(&SourceFile, setup2, "wb");
							if (SourceFile != NULL)
							{
								if (fwrite(ptr, sizeof(char), strnlen_s(ptr, sizeof(ILibScratchPad)), SourceFile)) {}
								fclose(SourceFile);
							}
						}
						GlobalFree(proxyEx.lpszProxy);
					}

					// Release the rest of the proxy settings
					if (proxyEx.lpszAutoConfigUrl != NULL) GlobalFree(proxyEx.lpszAutoConfigUrl);
					if (proxyEx.lpszProxyBypass != NULL) GlobalFree(proxyEx.lpszProxyBypass);
				}
			}
		}
	}

	// Add the uninstall icon in the control panel
	AddUninstallIcon();

	/*
#if defined(_LINKVM)
	// Setup the SendSAS permission
	kvm_setupSasPermissions();
#endif
	*/

	// Attempt to start the updated service up again
	memcpy(targetexe + targetexelen, "\" -install", 11);
	r = RunProcess(targetexe2, 1);
	memcpy(targetexe + targetexelen, "\" -start", 9);
	r = RunProcess(targetexe2, 1);
}
#endif


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
int main(int argc, char* argv[])
{
	int i;
	size_t str2len = 0;// , proxylen = 0, taglen = 0;
	wchar_t str[_MAX_PATH];
	char str2[_MAX_PATH];
	char* proxyarg = NULL;
	char* tagarg = NULL;
	CONTEXT winException;
	int retCode = 0;

	/*
#ifndef NOMESHCMD
	// Check if this is a Mesh command operation
	if (argc >= 1 && strlen(argv[0]) >= 7 && strcasecmp(argv[0] + strlen(argv[0]) - 7, "meshcmd") == 0) return MeshCmd_ProcessCommand(argc, argv, 1);
	if (argc >= 2 && strcasecmp(argv[1], "meshcmd") == 0) return MeshCmd_ProcessCommand(argc, argv, 2);
#endif
	*/

	//CoInitializeEx(NULL, COINIT_MULTITHREADED);

	if (argc > 1 && strcasecmp(argv[1], "-info") == 0)
	{
		printf("Compiled on: %s, %s\n", __TIME__, __DATE__);
#ifndef MICROSTACK_NOTLS
		printf("Using %s\n", SSLeay_version(SSLEAY_VERSION));
#endif
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
		return(0);
	}

	if (argc > 2 && strcasecmp(argv[1], "-fdelta") == 0)
	{
		uint64_t delta = 0;
		sscanf_s(argv[2], "%lld", &delta);
		ILibChain_DebugDelta(ILibScratchPad, sizeof(ILibScratchPad), delta);
		printf("%s", ILibScratchPad);
		return(0);
	}

	char *integratedJavaScript;
	int integragedJavaScriptLen;
	ILibDuktape_ScriptContainer_CheckEmbedded(&integratedJavaScript, &integragedJavaScriptLen);

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	// Process extra switches
	for (i = 0; i < argc; i++)
	{
		str2len = strnlen_s(argv[i], _MAX_PATH - 1);
		if (str2len > 7 && memcmp(argv[i], "-proxy:", 7) == 0) { proxyarg = argv[i] + 7; } // Set the HTTPS proxy
		else if (str2len >= 5 && memcmp(argv[i], "-tag:", 5) == 0) { tagarg = argv[i] + 5; } // Set the TAG
	}

	/*
	#ifdef _MINCORE
	if (argc == 2 && ((strcasecmp(argv[1], "-?") == 0) || (strcasecmp(argv[1], "/?") == 0)))
	{
		printf("Mesh Agent v%d available switches:\r\n  start             Start the service.\r\n  restart           Restart the service.\r\n  stop              Stop the service.\r\n  -signcheck        Perform self-check.\r\n  -install          Install the service from this location.\r\n  -uninstall        Remove the service from this location.\r\n  -nodeidhex        Return the current agent identifier.\r\n  -proxy:host:port  Specifiy an HTTPS proxy (after -fullinstall only).\r\n  -tag:xxx          Specifiy a agent tag  (after -fullinstall only).\r\n\r\n  -resetnodeid      Reset the NodeID next time the service is started.", MESH_AGENT_VERSION);
		return 0;
	}
	#else
	if (argc == 2 && ((strcasecmp(argv[1], "-?") == 0) || (strcasecmp(argv[1], "/?") == 0)))
	{
		//printf("Mesh Agent v%d available switches:\r\n  start             Start the service.\r\n  restart           Restart the service.\r\n  stop              Stop the service.\r\n  -proxy:host:port  Specifiy an HTTPS proxy.\r\n  -leader           Force the agent to always be a leader.\r\n  -signcheck        Perform self-check.\r\n  -install          Install the service from this location.\r\n  -uninstall        Remove the service from this location.\r\n  -nodeidhex        Return the current agent identifier.\r\n  -fullinstall      Copy agent into program files, install and launch.\r\n  -fulluninstall    Stop agent and clean up the program files location.\r\n  -loadcert:c.pem   Load a pem cert as node certificate.\r\n", MESH_AGENT_VERSION);
		printf("Mesh Agent v%d available switches:\r\n  start             Start the service.\r\n  restart           Restart the service.\r\n  stop              Stop the service.\r\n  -signcheck        Perform self-check.\r\n  -install          Install the service from this location.\r\n  -uninstall        Remove the service from this location.\r\n  -nodeidhex        Return the current agent identifier.\r\n  -fullinstall      Copy agent into program files, install and launch.\r\n  -fulluninstall    Stop agent and clean up the program files location.\r\n  -proxy:host:port  Specifiy an HTTPS proxy (after -fullinstall only).\r\n  -tag:xxx          Specifiy a agent tag  (after -fullinstall only).\r\n  -resetnodeid      Reset the NodeID next time the service is started.", MESH_AGENT_VERSION);
		return 0;
	}
	#endif
	*/
	
	#if defined(_LINKVM)
	if (argc > 1 && strcasecmp(argv[1], "-kvm0") == 0)
	{
		void **parm = (void**)ILibMemory_Allocate(3 * sizeof(void*), 0, 0, NULL);
		parm[0] = kvm_serviceWriteSink;
		((int*)&(parm[2]))[0] = 0;
		kvm_server_mainloop((void*)parm);
		return 0;
	}
	else if (argc > 1 && strcasecmp(argv[1], "-kvm1") == 0)
	{
		void **parm = (void**)ILibMemory_Allocate(3 * sizeof(void*), 0, 0, NULL);
		parm[0] = kvm_serviceWriteSink;
		((int*)&(parm[2]))[0] = 1;
		kvm_server_mainloop((void*)parm);
		return 0;
	}
	#endif

#ifdef _MINCORE
	if (argc > 1 && strcasecmp(argv[1], "-signcheck") == 0)
	{
		// Check the signature of out own executable
		util_openssl_init();
		printf("%d", signcheck_verifysign(argv[0], 0));
		util_openssl_uninit();
		return 0;
	}
#else
	
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
		__except (ILib_WindowsExceptionFilter(GetExceptionCode(), GetExceptionInformation(), &winException))
		{
			ILib_WindowsExceptionDebug(&winException);
		}
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
		return serviceState;
	}
	else if (argc > 1 && strcasecmp(argv[1], "-signcheck") == 0 && GetModuleFileNameA(NULL, str2, _MAX_PATH) > 5)
	{
		// Check the signature of out own executable
#ifndef MICROSTACK_NOTLS
		util_openssl_init();
		printf("%d", signcheck_verifysign(str2, 0));
		util_openssl_uninit();
#else
		printf("Cannot verify without OpenSSL support");
#endif
		return 0;
	}
#endif
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
	else if (argc > 1 && strcasecmp(argv[1], "-install") == 0)
	{
		// Setup the service
		StopService(serviceFile);
		UninstallService(serviceFile);
		UninstallService(serviceFileOld);
		if (InstallService() == TRUE) { printf("Mesh agent installed"); } else { printf("Failed to install mesh agent"); }

#ifndef _MINCORE
		// Setup the Windows firewall
		if (GetModuleFileNameW(NULL, str, _MAX_PATH) > 5)
		{
			ClearWindowsFirewall(str);
			if (SetupWindowsFirewall(str) != 0)
			{
				#ifdef _DEBUG
				ILIBMESSAGE("Firewall rules added successfully");
				#endif
			}
			else
			{
				#ifdef _DEBUG
				ILIBMESSAGE("Unable to add firewall rules");
				#endif
			}
		}
#endif
	}
	else if (argc > 1 && ((strcasecmp(argv[1], "-remove") == 0) || (strcasecmp(argv[1], "-uninstall") == 0)))
	{
		// Ask the service manager to stop the service
		StopService(serviceFile);

		// Remove the service
		UninstallService(serviceFileOld);
		i = UninstallService(serviceFile);
		if (i == 0) { printf("Failed to uninstall mesh agent"); }
		else if (i == 1) { printf("Mesh agent uninstalled"); }
		else if (i == 2) { printf("Mesh agent still running"); }

#ifndef _MINCORE
		// Remove the MeshAgent registry keys
		RegDeleteKey(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent2");
		RegDeleteKey(HKEY_CURRENT_USER, "Software\\Open Source\\MeshAgent2");

		// Cleanup the firewall rules
		if (GetModuleFileNameW( NULL, str, _MAX_PATH ) > 5)
		{
			if (ClearWindowsFirewall(str) != 0)
			{
				#ifdef _DEBUG
				ILIBMESSAGE("Firewall rules removed successfully");
				#endif
			}
			else
			{
				#ifdef _DEBUG
				ILIBMESSAGE("Unable to remove firewall rules");
				#endif
			}
		}
#endif
	}
#ifdef _MINCORE
	else if (argc > 1 && memcmp(argv[1], "-update:", 8) == 0)
	{
		// Attempt to copy our own exe over the original exe
		while (util_CopyFile(argv[0], argv[1] + 8, FALSE) == FALSE) { Sleep(5000); }

		// Attempt to start the updated service up again
		LaunchService();
	}
#endif
#ifndef _MINCORE
	else if (argc > 1 && memcmp(argv[1], "-update:", 8) == 0)
	{
		// Attempt to copy our own exe over the original exe
		while (util_CopyFile(argv[0], argv[1] + 8, FALSE) == FALSE) Sleep(5000);

		// Attempt to start the updated service up again
		LaunchService(serviceFile);
	}
	else if (argc > 1 && (strcasecmp(argv[1], "-netinfo") == 0))
	{
		char* data;
		int len = MeshInfo_GetSystemInformation(&data);
		if (len > 0) { printf(data); }
	}
	else if (argc > 1 && (strcasecmp(argv[1], "-fullinstall") == 0))
	{
		fullinstall( 0, proxyarg, (int)strnlen_s(proxyarg, _MAX_PATH), tagarg, (int)strnlen_s(tagarg, _MAX_PATH));
	}
	else if (argc > 1 && (strcasecmp(argv[1], "-fulluninstall") == 0))
	{
		fullinstall(1, NULL, 0, NULL, 0);
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
		if (strEx != NULL) printf(strEx); else printf("Not defined, start the mesh service to create a nodeid.");
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
		return 0;
	}
	else
	{
		UninstallService(serviceFileOld);
		if (argc > 1)
		{
			// See if we need to run as a script engine
			if (argc >= 2 && ILibString_EndsWith(argv[1], -1, ".js", 3) != 0)
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
				__except (ILib_WindowsExceptionFilter(GetExceptionCode(), GetExceptionInformation(), &winException))
				{
					ILib_WindowsExceptionDebug(&winException);
				}
			}
			else
			{
#ifdef _MINCORE
				printf("Mesh Agent available switches:\r\n  run               Start as a console agent.\r\n  connect           Start as a temporary console agent.\r\n  restart           Restart the service.\r\n  stop              Stop the service.\r\n  state             Display the running state of the service.\r\n  -signcheck        Perform self-check.\r\n  -install          Install the service from this location.\r\n  -uninstall        Remove the service from this location.\r\n  -nodeidhex        Return the current agent identifier.\r\n  -proxy:host:port  Specifiy an HTTPS proxy (after -fullinstall only).\r\n  -tag:xxx          Specifiy a agent tag  (after -fullinstall only).\r\n\r\n  -resetnodeid      Reset the NodeID next time the service is started.");
#else
				printf("Mesh Agent available switches:\r\n  run               Start as a console agent.\r\n  connect           Start as a temporary console agent.\r\n  start             Start the service.\r\n  restart           Restart the service.\r\n  stop              Stop the service.\r\n  state             Display the running state of the service.\r\n  -signcheck        Perform self-check.\r\n  -install          Install the service from this location.\r\n  -uninstall        Remove the service from this location.\r\n  -nodeidhex        Return the current agent identifier.\r\n  -fullinstall      Copy agent into program files, install and launch.\r\n  -fulluninstall    Stop agent and clean up the program files location.\r\n  -proxy:host:port  Specifiy an HTTPS proxy (after -fullinstall only).\r\n  -tag:xxx          Specifiy a agent tag  (after -fullinstall only).\r\n  -resetnodeid      Reset the NodeID next time the service is started.");
#endif
			}
		}
		else
		{
#ifndef _MINCORE
			if (RunService() == 0 && GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
			{
				FreeConsole();

				/*
				if (IsAdmin() == FALSE)
				{
					MessageBox(NULL, TEXT("Must run as administrator"), TEXT("Mesh Agent"), MB_OK | MB_ICONERROR);
				}
				else
				{
					DialogBox(NULL, MAKEINTRESOURCE(IDD_INSTALLDIALOG), NULL, DialogHandler);
				}
				*/
				DialogBox(NULL, MAKEINTRESOURCE(IDD_INSTALLDIALOG), NULL, DialogHandler);
			}
		}
#else
		RunService();
#endif
	}

	CoUninitialize();

	return 0;
}

char* getMshSettings(char* fileName, char* selfexe, char** meshname, char** meshid, char** serverid, char** serverurl)
{
	char* importFile;
	int eq, importFileLen;
	parser_result *pr;
	parser_result_field *f;

	*meshname = *meshid = *serverid = *serverurl = NULL;
	importFileLen = ILibReadFileFromDiskEx(&importFile, fileName);
	if (importFile == NULL) {
		// Could not find the .msh file, see if there is one inside our own executable.
		FILE *tmpFile = NULL;
		char exeMeshPolicyGuid[] = { 0xB9, 0x96, 0x01, 0x58, 0x80, 0x54, 0x4A, 0x19, 0xB7, 0xF7, 0xE9, 0xBE, 0x44, 0x91, 0x4C, 0x19 };
		char tmpHash[16];

		fopen_s(&tmpFile, selfexe, "rb");
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
				int keyLen, valLen;

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
			}
		}
		f = f->NextResult;
	}
	ILibDestructParserResults(pr);
	return importFile;
}


#ifndef _MINCORE

// Start as a temporary mesh agent.
DWORD WINAPI StartTempAgent(_In_ LPVOID lpParameter)
{
	CONTEXT winException;
	char selfexe[_MAX_PATH];
	char *selfexe_ptr[] = { selfexe };
	WCHAR str[_MAX_PATH];
	size_t len;
	char *integratedJavaScript;
	int integragedJavaScriptLen;
	char setup1[_MAX_PATH];
	int setup1len;

	ILibDuktape_ScriptContainer_CheckEmbedded(&integratedJavaScript, &integragedJavaScriptLen);

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	// Get our own executable name
	if (GetModuleFileNameW(NULL, str, _MAX_PATH) > 5) { wcstombs_s(&len, selfexe, _MAX_PATH, str, _MAX_PATH); }

	// Setup proxy filenames
	if ((setup1len = (int)strnlen_s(selfexe, sizeof(selfexe))) >= 4) {
		memcpy_s(setup1, sizeof(setup1), selfexe, setup1len);
		memcpy_s(setup1 + (setup1len - 3), sizeof(setup1) - setup1len - 3, "proxy", 6);

		// Try to setup the proxy file
		WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyEx;
		if (WinHttpGetIEProxyConfigForCurrentUser(&proxyEx))
		{
			if (proxyEx.lpszProxy != NULL)
			{
				FILE *SourceFile = NULL;
				size_t len;
				if (wcstombs_s(&len, ILibScratchPad, 4095, proxyEx.lpszProxy, 2000) == 0)
				{
					char* ptr = strstr(ILibScratchPad, "https=");
					if (ptr != NULL)
					{
						char* ptr2 = strstr(ptr, ";");
						ptr += 6;
						if (ptr2 != NULL) ptr2[0] = 0;
					}
					else
					{
						ptr = ILibScratchPad;
					}
					fopen_s(&SourceFile, setup1, "wb");
					if (SourceFile != NULL)
					{
						if (fwrite(ptr, sizeof(char), strnlen_s(ptr, sizeof(ILibScratchPad)), SourceFile)) {}
						fclose(SourceFile);
					}
				}
				GlobalFree(proxyEx.lpszProxy);
			}

			// Release the rest of the proxy settings
			if (proxyEx.lpszAutoConfigUrl != NULL) GlobalFree(proxyEx.lpszAutoConfigUrl);
			if (proxyEx.lpszProxyBypass != NULL) GlobalFree(proxyEx.lpszProxyBypass);
		}
	}

	// Launch the temporary agent
	__try
	{
		agent = MeshAgent_Create(MeshCommand_AuthInfo_CapabilitiesMask_TEMPORARY);
		agent->meshCoreCtx_embeddedScript = integratedJavaScript;
		agent->meshCoreCtx_embeddedScriptLen = integragedJavaScriptLen;
		agent->runningAsConsole = 1;
		MeshAgent_Start(agent, 1, selfexe_ptr);
		//retCode = agent->exitCode;
		MeshAgent_Destroy(agent);
		agent = NULL;
	}
	__except (ILib_WindowsExceptionFilter(GetExceptionCode(), GetExceptionInformation(), &winException))
	{
		ILib_WindowsExceptionDebug(&winException);
	}

	CoUninitialize();
	return(0);
}

// Message handler for dialog box.
INT_PTR CALLBACK DialogHandler(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	char *fileName = NULL, *meshname = NULL, *meshid = NULL, *serverid = NULL, *serverurl = NULL, *mshfile = NULL;

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
			GetModuleFileNameA(NULL, selfexe, MAX_PATH);
			fileName = MeshAgent_MakeAbsolutePath(selfexe, ".msh");

			{
				DWORD               dwSize = 0;
				BYTE                *pVersionInfo = NULL;
				VS_FIXEDFILEINFO    *pFileInfo = NULL;
				UINT                pLenFileInfo = 0;
				int major, minor, hotfix, other;

				if ((dwSize = GetFileVersionInfoSize(selfexe, NULL)))
				{					
					if ((pVersionInfo = malloc(dwSize)) == NULL) { ILIBCRITICALEXIT(254); }
					if (GetFileVersionInfo(selfexe, 0, dwSize, pVersionInfo))
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

			if ((mshfile = getMshSettings(fileName, selfexe, &meshname, &meshid, &serverid, &serverurl)) != NULL)
			{
				// Set text in the dialog box
				if (strnlen_s(meshid, 255) > 50) { meshid += 2; meshid[42] = 0; }
				if (strnlen_s(serverid, 255) > 50) { serverid[42] = 0; }
				SetWindowTextA(GetDlgItem(hDlg, IDC_POLICYTEXT), (meshid != NULL) ? meshname : "(None)");
				SetWindowTextA(GetDlgItem(hDlg, IDC_HASHTEXT), (meshid != NULL) ? meshid : "(None)");
				SetWindowTextA(GetDlgItem(hDlg, IDC_SERVERLOCATION), (serverurl != NULL) ? serverurl : "(None)");
				SetWindowTextA(GetDlgItem(hDlg, IDC_SERVERID), (serverid != NULL) ? serverid : "(None)");
				free(mshfile);
				if (meshid == NULL) { EnableWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), FALSE); }
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

			if (IsAdmin() == TRUE)
			{
				// We are already administrator, just install/uninstall now.
				if (LOWORD(wParam) == IDC_INSTALLBUTTON) { fullinstall(0, NULL, 0, NULL, 0); } else { fullinstall(1, NULL, 0, NULL, 0); }
				result = TRUE;
			}
			else
			{
				// We need to request admin escalation
				if (LOWORD(wParam) == IDC_INSTALLBUTTON) { result = RunAsAdmin("-fullinstall"); } else { result = RunAsAdmin("-fulluninstall"); }
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
		else if (LOWORD(wParam) == IDC_CONNECTBUTTON) {
			EnableWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), FALSE);
			SetWindowTextA(GetDlgItem(hDlg, IDC_STATUSTEXT), "Running as temporary agent");
			CreateThread(NULL, 0, &StartTempAgent, NULL, 0, NULL);
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
