/*   
Copyright 2018 Intel Corporation

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

#if defined(WIN32) || defined (_WIN32_WCE)
#ifndef MICROSTACK_NO_STDAFX
#include "stdafx.h"
#endif
#endif

#if defined(WIN32)
#define _CRTDBG_MAP_ALLOC
#ifdef _DEBUG
#define DEBUG_NEW new(_NORMAL_BLOCK, __FILE__, __LINE__)
#define new DEBUG_NEW
#endif
#endif

#if defined(WINSOCK2)
	#include <winsock2.h>
	#include <ws2tcpip.h>
#elif defined(WINSOCK1)
	#include <winsock.h>
	#include <wininet.h>
#endif

#include <io.h>
#include <conio.h>
#include <stdio.h>  
#include <stdlib.h>  
#include <windows.h>
#include <process.h>
#include <Tlhelp32.h>
#include <winbase.h>
#include <string.h>
#include <signal.h>
#include <shlobj.h>
#include "..\microstack\ILibParsers.h"
#include "..\microstack\ILibSimpleDataStore.h"

#if defined(WIN32) & !defined(_CONSOLE)
#include "resource.h"
#endif

#if defined(WIN32) && defined (_DEBUG)
#include <crtdbg.h>
#endif

// The following macros set and clear, respectively, given bits
// of the C runtime library debug flag, as specified by a bitmask.
#ifdef   _DEBUG
#define  SET_CRT_DEBUG_FIELD(a) \
	_CrtSetDbgFlag((a) | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG))
#define  CLEAR_CRT_DEBUG_FIELD(a) \
	_CrtSetDbgFlag(~(a) & _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG))
#else
#define  SET_CRT_DEBUG_FIELD(a)   ((void) 0)
#define  CLEAR_CRT_DEBUG_FIELD(a) ((void) 0)
#endif

#ifdef MEMORY_CHECK
#ifdef WIN32
// This routine place comments at the head of a section of debug output
void OutputHeading( const char * explanation )
{
	_RPT1( _CRT_WARN, "\n\n%s:\n**************************************************************************\n", explanation );
}
#endif
#endif

void BreakSink(int s)
{
	UNREFERENCED_PARAMETER( s );
	signal(SIGINT, SIG_IGN);	// To ignore any more ctrl-c interrupts
	// TODO
}

// Return 1 if the file exists
int isFileExists(char *filePath)
{
#ifdef WIN32
	return(_access(filePath, 0) == 0 ? 1 : 0);
#else
	return(access(filePath, 0) == 0 ? 1 : 0);
#endif
}

// Find a process by name and kill it.
void killProcess(char *name)
{
	PROCESSENTRY32 pEntry;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes) {
		if (strcmp(pEntry.szExeFile, name) == 0) {
			HANDLE hProc = OpenProcess(PROCESS_TERMINATE, 0, (DWORD)pEntry.th32ProcessID);
			if (hProc != NULL) {
				printf("Terminating process %p.\r\n", hProc);
				TerminateProcess(hProc, 9);
				CloseHandle(hProc);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}

// Find a process by name and kill it.
void killProcess2(char *name)
{
	snprintf(ILibScratchPad2, sizeof(ILibScratchPad2), "taskkill /F /T /IM %s", name);
	system(ILibScratchPad2);
}

// Find a process by name and kill it.
void killService(char *servicename)
{
	snprintf(ILibScratchPad2, sizeof(ILibScratchPad2), "taskkill /F /FI \"SERVICES eq %s\"", servicename);
	system(ILibScratchPad2);
}


// Uninstall a service
int UninstallService(TCHAR* serviceName)
{
	int r = 0;
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService(serviceControlManager, serviceName, SERVICE_QUERY_STATUS | DELETE);
		if (service)
		{
			SERVICE_STATUS serviceStatusEx;
			if (QueryServiceStatus(service, &serviceStatusEx))
			{
				if (serviceStatusEx.dwCurrentState == SERVICE_STOPPED)
				{
					if (DeleteService(service))
					{
						printf("Mesh service removed successfully.\r\n");
						r = 1;
					}
					else
					{
						DWORD dwError = GetLastError();
						if (dwError == ERROR_ACCESS_DENIED) {
							printf("Access denied while trying to remove mesh service.\r\n");
						}
						else if (dwError == ERROR_INVALID_HANDLE) {
							printf("Handle invalid while trying to remove mesh service.\r\n");
						}
						else if (dwError == ERROR_SERVICE_MARKED_FOR_DELETE) {
							printf("Mesh service already marked for deletion.\r\n");
						}
					}
				}
				else
				{
					r = 2;
					printf("Mesh service is still running.\r\n");
				}
			}
			CloseServiceHandle(service);
		}
		CloseServiceHandle(serviceControlManager);
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
		SC_HANDLE service = OpenService(serviceControlManager, servicename, SERVICE_QUERY_STATUS | DELETE);
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

// Start a Windows service
int LaunchService(LPCSTR servicename)
{
	int r = 0;
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SERVICE_QUERY_STATUS | SERVICE_START);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService(serviceControlManager, servicename, SERVICE_QUERY_STATUS | SERVICE_START);
		if (service)
		{
			SERVICE_STATUS serviceStatusEx;
			if (QueryServiceStatus(service, &serviceStatusEx))
			{
				if (serviceStatusEx.dwCurrentState == SERVICE_STOPPED) { if (StartService(service, 0, NULL) == TRUE) { r = 1; printf("Started service.\r\n"); } }
				else { r = 2; }
			}
			CloseServiceHandle(service);
		}
		CloseServiceHandle(serviceControlManager);
	}
	return r;
}

// Stop a Windows service
int StopService(LPCSTR servicename)
{
	int r = 0;
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SERVICE_QUERY_STATUS | SERVICE_STOP);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService(serviceControlManager, servicename, SERVICE_QUERY_STATUS | SERVICE_STOP);
		if (service)
		{
			SERVICE_STATUS serviceStatusEx;
			if (QueryServiceStatus(service, &serviceStatusEx))
			{
				if (serviceStatusEx.dwCurrentState != SERVICE_STOPPED)
				{
					if (ControlService(service, SERVICE_CONTROL_STOP, &serviceStatusEx) == FALSE)
					{
						// TODO: Unable to stop service
						printf("Unable to stop service.\r\n");
					}
					else
					{
						printf("Stopped service.\r\n");
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

void removeDir(char* dir)
{
	SHFILEOPSTRUCT file_op = {
		NULL,
		FO_DELETE,
		dir,
		"",
		FOF_NOCONFIRMATION |
		FOF_NOERRORUI |
		FOF_SILENT,
		FALSE,
		0,
		"" };
	int r = SHFileOperation(&file_op);
	if (r == 0) {
		printf("Removed folder: %s.\r\n", dir);
	} else {
		if (r != 124) { printf("Unable to remove folder (%d): %s.\r\n", r, dir); }
	}
}

// Remove CoreModule from the .db file
void removeMeshCore(char* file) {
	if (ILibSimpleDataStore_Exists(file) != 1) return;
	void* ILibSimpleDataStore = ILibSimpleDataStore_Create(file);
	if (ILibSimpleDataStore == NULL) return;
	printf("Checking %s...\r\n", file);

	if (ILibSimpleDataStore_Get(ILibSimpleDataStore, "CoreModule", NULL, 0) != 0) {
		if (ILibSimpleDataStore_Delete(ILibSimpleDataStore, "CoreModule") == 1) {
			printf("Removed CoreModule.\r\n");
			ILibSimpleDataStore_Compact(ILibSimpleDataStore); // While we are at it, compact the .db file.
		}
	}
	
	ILibSimpleDataStore_Close(ILibSimpleDataStore);
}

int main(int argc, char **argv)
{
	// Shutdown on Ctrl + C
	signal(SIGINT, BreakSink);

#ifdef _POSIX
	signal(SIGPIPE, SIG_IGN);
#ifdef _DEBUG
	//mtrace();
#endif
#endif

#ifdef MEMORY_CHECK
#ifdef WIN32
	//SET_CRT_DEBUG_FIELD( _CRTDBG_DELAY_FREE_MEM_DF );
	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF);
#endif
#endif

	if ((argc == 2) && (strcasecmp(argv[1], "reset") == 0)) {
		int i;
		char targetexe[_MAX_PATH + 40];
		size_t targetexelen = 0;

		// Reset the mesh agent & clear the core
		printf("Attempting MeshAgent Reset...\r\n");

		// Kill the agent 3 different ways.
		killProcess("meshagent.exe");
		killProcess2("meshagent.exe");
		killService("Mesh Agent");
		Sleep(1000);

		// Stop the service
		i = GetServiceState("Mesh Agent");
		if (i == 100) { printf("Mesh Agent is not installed.\r\n"); return; }
		if (i != 1) { StopService("Mesh Agent"); }

		// Remove the core from the .db file
		if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, targetexe) != S_FALSE) {
			targetexelen = strnlen_s(targetexe, _MAX_PATH + 40);
			memcpy_s(targetexe + targetexelen, _MAX_PATH + 40 - targetexelen, "\\Mesh Agent\\MeshAgent.db\0", 25);
			removeMeshCore(targetexe);
		} else {
			removeMeshCore("C:\\Program Files\\Mesh Agent\\MeshAgent.db");
		}

		// Remove the core from the .db file
		if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILESX86 | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, targetexe) != S_FALSE) {
			targetexelen = strnlen_s(targetexe, _MAX_PATH + 40);
			memcpy_s(targetexe + targetexelen, _MAX_PATH + 40 - targetexelen, "\\Mesh Agent\\MeshAgent.db\0", 25);
			removeMeshCore(targetexe);
		} else {
			removeMeshCore("C:\\Program Files (x86)\\Mesh Agent\\MeshAgent.db");
		}

		// Start the agent again
		LaunchService("Mesh Agent");
		printf("Done.\r\n");
	} else if ((argc == 2) && (strcasecmp(argv[1], "remove") == 0)) {
		int i;

		printf("Attempting MeshAgent Removal...\r\n");

		// Kill the agent 3 different ways.
		killProcess("meshagent.exe");
		killProcess2("meshagent.exe");
		killService("Mesh Agent");
		Sleep(1000);

		// Stop & remove the service
		i = GetServiceState("Mesh Agent");
		if (i != 100) {
			if (i != 1) { StopService("Mesh Agent"); }
			UninstallService("Mesh Agent");
		}
		i = GetServiceState("Mesh Agent v2");
		if (i != 100) {
			if (i != 1) { StopService("Mesh Agent v2"); }
			UninstallService("Mesh Agent v2");
		}

		// Remove the MeshAgent v1 registry keys if present
		if (RegDeleteKeyEx(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent", KEY_WOW64_32KEY, 0) == ERROR_SUCCESS) { printf("Removed WOW64 registry key: LOCALMACHINE\\Software\\Open Source\\MeshAgent.\r\n"); }
		if (RegDeleteKeyEx(HKEY_CURRENT_USER, "Software\\Open Source\\MeshAgent", KEY_WOW64_32KEY, 0) == ERROR_SUCCESS) { printf("Removed WOW64 registry key: CURRENTUSER\\Software\\Open Source\\MeshAgent.\r\n"); }
		if (RegDeleteKey(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent") == ERROR_SUCCESS) { printf("Removed registry key: LOCALMACHINE\\Software\\Open Source\\MeshAgent.\r\n"); }
		if (RegDeleteKey(HKEY_CURRENT_USER, "Software\\Open Source\\MeshAgent") == ERROR_SUCCESS) { printf("Removed registry key: CURRENTUSER\\Software\\Open Source\\MeshAgent.\r\n"); }

		// Remove the MeshAgent v2 registry keys if present
		if (RegDeleteKeyEx(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent2", KEY_WOW64_32KEY, 0) == ERROR_SUCCESS) { printf("Removed WOW64 registry key: LOCALMACHINE\\Software\\Open Source\\MeshAgent2.\r\n"); }
		if (RegDeleteKeyEx(HKEY_CURRENT_USER, "Software\\Open Source\\MeshAgent2", KEY_WOW64_32KEY, 0) == ERROR_SUCCESS) { printf("Removed WOW64 registry key: CURRENTUSER\\Software\\Open Source\\MeshAgent2.\r\n"); }
		if (RegDeleteKey(HKEY_LOCAL_MACHINE, "Software\\Open Source\\MeshAgent2") == ERROR_SUCCESS) { printf("Removed registry key: LOCALMACHINE\\Software\\Open Source\\MeshAgent2.\r\n"); }
		if (RegDeleteKey(HKEY_CURRENT_USER, "Software\\Open Source\\MeshAgent2") == ERROR_SUCCESS) { printf("Removed registry key: CURRENTUSER\\Software\\Open Source\\MeshAgent2.\r\n"); }

		// Remove windows service keys
		if (RegDeleteKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Mesh Agent", KEY_WOW64_32KEY, 0) == ERROR_SUCCESS) { printf("Removed service keys.\r\n"); }
		if (RegDeleteKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Mesh Agent") == ERROR_SUCCESS) { printf("Removed service keys.\r\n"); }

		// Remove uninstall icon if present
		if (RegDeleteKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MeshCentralAgent", KEY_WOW64_32KEY, 0) == ERROR_SUCCESS) { printf("Removed WOW64 uninstall icon.\r\n"); }
		if (RegDeleteKey(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MeshCentralAgent") == ERROR_SUCCESS) { printf("Removed uninstall icon.\r\n"); }

		// Remote mesh agent folder
		removeDir("C:\\Program Files\\Mesh Agent\\");
		removeDir("C:\\Program Files (x86)\\Mesh Agent\\");
	} else {
		// Display help
		printf("MeshCentral Agent Reset & Removal Tool v1. Usage:\r\n\r\n");
		printf("  MeshReset [RESET|REMOVE]\r\n");
		printf("\r\nThis tool should run with administrator privilages.\r\n");
	}

#ifdef MEMORY_CHECK
#ifdef WIN32
	OutputHeading("Generating the final memory leak report\r\n");
	_CrtCheckMemory();
	_CrtDumpMemoryLeaks();
#endif
#endif

#ifdef _POSIX
#ifdef _DEBUG
    //muntrace();
#endif
#endif

#ifdef _POSIX
	exit(EXIT_SUCCESS);
#else
	return 0;
#endif
}

