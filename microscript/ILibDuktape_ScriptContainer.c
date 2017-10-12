/*
Copyright 2006 - 2017 Intel Corporation

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
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <IPHlpApi.h>
#include <Windows.h>
#include <WinBase.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#endif

#include "duktape.h"

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "ILibDuktape_ScriptContainer.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktape_Helpers.h"
#include "../microstack/ILibParsers.h"
#include "../microstack/ILibProcessPipe.h"
#include "../microstack/ILibRemoteLogging.h"
#include "../microstack/ILibCrypto.h"

#include "ILibDuktape_net.h"
#include "ILibDuktape_http.h"
#include "ILibDuktape_WebRTC.h"
#include "ILibDuktape_Dgram.h"
#include "ILibDuktape_GenericMarshal.h"
#include "ILibDuktape_ProcessPipe.h"
#include "ILibDuktape_fs.h"
#include "ILibDuktape_Polyfills.h"
#include "ILibDuktape_SimpleDataStore.h"
#include "ILibDuktape_NetworkMonitor.h"

#include "ILibDuktape_SHA256.h"
#include "ILibDuktape_EncryptionStream.h"

#define SCRIPT_ENGINE_PIPE_BUFFER_SIZE 65535
#define ILibDuktape_ScriptContainer_MasterPtr		"\xFF_ScriptContainer_MasterPtr"
#define ILibDuktape_ScriptContainer_SlavePtr		"\xFF_ScriptContainer_SlavePtr"
#define ILibDuktape_ScriptContainer_ExePath			"\xFF_ScriptContainer_ExePath"
#define ILibDuktape_ScriptContainer_PipeManager		"\xFF_ScriptContainer_PipeManager"
#define ILibDuktape_ScriptContainer_PtrTable		"\xFF_ScriptContainer_PtrTable"
#define ILibDuktape_ScriptContainer_PtrTable_Idx	"\xFF_ScriptContainer_PtrTableIdx"


#define ILibDuktape_ScriptContainer_Command_Execute_Status		"ScriptContainer_Command_Execute_Status"
#define ILibDuktape_ScriptContainer_Command_Log					"ScriptContainer_Command_Log"
#define ILibDuktape_ScriptContainer_Settings_ExecutionTimeout	"\xFF_ScriptContainerSettings_ExecutionTimeout"
#define ILibDuktape_ScriptContainer_Settings_SecurityFlags		"\xFF_ScriptContainerSettings_SecurityFlags"
#define ILibDuktape_ScriptContainer_Settings_DB					"\xFF_ScriptContainerSettings_DB"
#define ILibDuktape_ScriptContainer_Settings_ExitHandler		"\xFF_ScriptContainerSettings_ExitHandler"
#define ILibDuktape_ScriptContainer_Settings_ExitUser			"\xFF_ScriptContainerSettings_ExitUser"
#define ILibDuktape_ScriptContainer_Process_ArgArray			"\xFF_argArray"
#define ILibDuktape_ScriptContainer_Process_Restart				"\xFF_ScriptContainer_Process_Restart"

#define ILibDuktape_ScriptContainer_ExitCode					"\xFF_ExitCode"
#define ILibDuktape_ScriptContainer_Exitting					"\xFF_Exiting"

#ifdef MESH_AGENTID
	char *ARCHNAME[] =
	{
		NULL,
		"x86",	// ARCHID = 1					# Windows Console x86 32 bit
		"x64",	// ARCHID = 2					# Windows Console x86 64 bit
		"x86",	// ARCHID = 3					# Windows Service x86 32 bit
		"x64",	// ARCHID = 4					# Windows Service x86 64 bit
		"x86",	// ARCHID = 5					# Linux x86 32 bit
		"x64",	// ARCHID = 6					# Linux x86 64 bit
		"mips",	// ARCHID = 7					# Linux MIPS
		NULL,
		"arm",	// ARCHID = 9					# Linux ARM 32 bit
		NULL,NULL,NULL,
		"arm",	// ARCHID = 13					# Linux ARM 32 bit PogoPlug							
		NULL,
		"x86",	// ARCHID = 15					# Linux x86 32 bit POKY								
		NULL, NULL,
		"x64",	// ARCHARCHID = 18				# Linux x86 64 bit POKY								
		"x86",	// ARCHARCHID = 19				# Linux x86 32 bit NOKVM							
		"x64",	// ARCHARCHID = 20				# Linux x86 64 bit NOKVM
		NULL, NULL, NULL, NULL,
		"arm"	// ARCHARCHID = 25 				# Linux ARM 32 bit HardFloat
	};
#endif

extern void ILibDuktape_MemoryStream_Init(duk_context *ctx);
extern void ILibDuktape_NetworkMonitor_Init(duk_context *ctx);

typedef enum SCRIPT_ENGINE_COMMAND
{
	SCRIPT_ENGINE_COMMAND_UNKNOWN = 0x00,
	SCRIPT_ENGINE_COMMAND_INIT = 0x01,
	SCRIPT_ENGINE_COMMAND_EXEC = 0x02,
	SCRIPT_ENGINE_COMMAND_ADD_MODULE = 0x04,
	SCRIPT_ENGINE_COMMAND_SEND_JSON = 0x10,
	SCRIPT_ENGINE_COMMAND_QUERY = 0x20,
	SCRIPT_ENGINE_COMMAND_SET = 0x21,
	SCRIPT_ENGINE_COMMAND_LOG = 0xFF
}SCRIPT_ENGINE_COMMAND;


typedef struct ILibDuktape_ScriptContainer_Master
{
	duk_context *ctx;
	ILibDuktape_EventEmitter *emitter;

	ILibProcessPipe_Process child;
	void *chain;
	void *OnExit, *OnError, *OnJSON;
}ILibDuktape_ScriptContainer_Master;

typedef struct ILibDuktape_ScriptContainer_Slave
{
	duk_context *ctx;
	ILibDuktape_EventEmitter *emitter;

	void *OnData;
	void *chain;
	int exitCode;
}ILibDuktape_ScriptContainer_Slave;

#ifdef _REMOTELOGGING
void ILibDuktape_ScriptContainer_Slave_LogForwarder(ILibRemoteLogging sender, ILibRemoteLogging_Modules module, ILibRemoteLogging_Flags flags, char *buffer, int bufferLen)
{
	char tmp[4096];
	int len;

	buffer[bufferLen] = 0;
	len = sprintf_s(tmp + 4, sizeof(tmp) - 4, "{\"command\":255,\"module\":%d,\"flags\":%d,\"message\":\"%s\"}", module, flags, buffer);
	((int*)tmp)[0] = 4 + len;
#ifdef WIN32
	DWORD arg;
	WriteFile(GetStdHandle(STD_ERROR_HANDLE), (void*)tmp, 4 + len, &arg, NULL);
#else
	ignore_result(write(STDERR_FILENO, (void*)tmp, 4 + len));
#endif
}
#endif

void ILibDuktape_ScriptContainer_PUSH_MASTER(duk_context *ctx, void *chain);
void ILibDuktape_ScriptContainer_PUSH_SLAVE(duk_context *ctx, void *chain);

void ILibDuktape_ScriptContainer_Slave_SendJSON(duk_context *ctx)
{
	char *json = (char*)duk_json_encode(ctx, -1);
	int len = 4 + sprintf_s(ILibScratchPad2 + 4, sizeof(ILibScratchPad2) - 4, "%s", json);
	((int*)ILibScratchPad2)[0] = len;

#ifdef WIN32
	DWORD tmpLen;
	WriteFile(GetStdHandle(STD_ERROR_HANDLE), ILibScratchPad2, len, &tmpLen, NULL);
#else
	ignore_result(write(STDERR_FILENO, ILibScratchPad2, len));
#endif	
	duk_pop(ctx);
}

void ILibDuktape_ScriptContainer_Slave_OnBrokenPipe(ILibProcessPipe_Pipe sender)
{
	ILibStopChain(((ILibDuktape_ScriptContainer_Slave*)((void**)ILibMemory_GetExtraMemory(sender, ILibMemory_ILibProcessPipe_Pipe_CONTAINERSIZE))[0])->chain);
}

// Polyfill process object: 
void ILibDuktape_ScriptContainer_Process_ExitCallback(void *obj)
{
	duk_context *ctx = ((void**)obj)[0];

	free(obj);
	duk_destroy_heap(ctx);
}
duk_ret_t ILibDuktape_ScriptContainer_Process_Exit(duk_context *ctx)
{
	void **tmp;
	int nargs = duk_get_top(ctx);

	duk_push_this(ctx);															// [process]
	if (nargs == 1)
	{
		duk_push_int(ctx, duk_require_int(ctx, 0));								// [process][code]
		duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_ExitCode);		// [process]
	}
	if (duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Exitting)) { return(ILibDuktape_Error(ctx, "Process.exit(): Cannot call exit again, already Exiting...")); }
	duk_push_int(ctx, 1);
	duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_Exitting);			// [process]


	// Execute this later, so that this stack can unwind first, before we destroy the heap
	tmp = (void**)ILibMemory_Allocate(sizeof(void*), 0, NULL, NULL);
	tmp[0] = ctx;
	ILibLifeTime_Add(ILibGetBaseTimer(Duktape_GetChain(ctx)), tmp, 0, ILibDuktape_ScriptContainer_Process_ExitCallback, NULL);

	return 0;
}


// Polyfill process object: 
duk_ret_t ILibDuktape_ScriptContainer_Process_Argv0(duk_context *ctx)
{
	duk_push_this(ctx);																	// [process]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_ArgArray))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_ArgArray);		// [process][array]
		duk_get_prop_index(ctx, -1, 0);													// [process][array][val]
	}
	else
	{
		duk_push_string(ctx, "");														// [process][array][val]
	}
	return 1;
}

// Polyfill process object: 
duk_ret_t ILibDuktape_ScriptContainer_Process_Argv(duk_context *ctx)
{
	duk_push_this(ctx);																	// [process]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_ArgArray))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_ArgArray);		// [process][array]
		duk_dup(ctx, -1);																// [process][array][array]
	}
	else
	{
		duk_push_array(ctx);															// [process][array]
	}
	return 1;
}

void ILibDuktape_ScriptContainer_Process_Init(duk_context *ctx, char **argList)
{
	int i = 0;
	ILibDuktape_EventEmitter *emitter;

	duk_push_global_object(ctx);														// [g]
	duk_push_object(ctx);																// [g][process]
#if defined(WIN32)																		// [g][process][platform]
	duk_push_string(ctx, "win32");
#elif defined(__APPLE__)
	duk_push_string(ctx, "darwin");
#else
	duk_push_string(ctx, "linux");
#endif
	duk_put_prop_string(ctx, -2, "platform");											// [g][process]

	if (argList != NULL)
	{
		duk_push_array(ctx);															// [g][process][array]
		while (argList[i] != NULL)
		{
			duk_push_string(ctx, argList[i]);											// [g][process][array][val]
			duk_put_prop_index(ctx, -2, i);												// [g][process][array]
			++i;
		}
		duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_Process_ArgArray);		// [g][process]
	}

	if (duk_peval_string(ctx, "require('os').arch();") == 0)							// [g][process][arch]
	{
		ILibDuktape_CreateReadonlyProperty(ctx, "arch");								// [g][process]
	}
	else
	{																				   // [g][process]
		duk_pop(ctx);
	}

	emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "exit");
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "exit", ILibDuktape_ScriptContainer_Process_Exit, DUK_VARARGS);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "uncaughtException");

	ILibDuktape_CreateEventWithGetter(ctx, "argv0", ILibDuktape_ScriptContainer_Process_Argv0);
	ILibDuktape_CreateEventWithGetter(ctx, "argv", ILibDuktape_ScriptContainer_Process_Argv);

	duk_put_prop_string(ctx, -2, "process");											// [g]
	duk_pop(ctx);																		// ...
}
void ILibDuktape_ScriptContainer_ExecTimeout_Finalizer(duk_context *ctx, void *timeoutKey)
{
	if (ILibIsChainBeingDestroyed((Duktape_GetChain(ctx))) == 0)
	{
		ILibLifeTime_Remove(ILibGetBaseTimer(Duktape_GetChain(ctx)), timeoutKey);
	}
	free(timeoutKey);
}
// Called when the executation timeout occurs
void ILibDuktape_ScriptContainer_ExecTimeout(void *obj)
{
	duk_context *ctx = (duk_context*)((void**)obj)[0];
	ILibRemoteLogging_printf(ILibChainGetLogger(Duktape_GetChain(ctx)), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "Script Container Execution Timeout Elapsed");

	duk_push_global_object(ctx);																			// [g]
	duk_get_prop_string(ctx, -1, "process");																// [g][process]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Exitting)) { duk_pop_2(ctx); return; }
	duk_push_int(ctx, 5);
	duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_ExitCode);										// [g][process]
	duk_pop_2(ctx);																							// ...

	duk_destroy_heap(ctx);
}
SCRIPT_ENGINE_SETTINGS *ILibDuktape_ScriptContainer_GetSettings(duk_context *ctx)
{
	SCRIPT_ENGINE_SETTINGS *retVal = (SCRIPT_ENGINE_SETTINGS*)ILibScratchPad;
	memset(retVal, 0, sizeof(SCRIPT_ENGINE_SETTINGS));
	
	retVal->chain = Duktape_GetChain(ctx);
	duk_push_heap_stash(ctx);																															// [s]
	retVal->securityFlags = (SCRIPT_ENGINE_SECURITY_FLAGS)Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_ScriptContainer_Settings_SecurityFlags, 0);	// [s]
	retVal->executionTimeout = (unsigned int)Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_ScriptContainer_Settings_ExecutionTimeout, 0);			// [s]
	retVal->exitHandler = (ILibDuktape_HelperEvent)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_ScriptContainer_Settings_ExitHandler);				// [s]
	retVal->exitUserObject = Duktape_GetPointerProperty(ctx, -1, ILibDuktape_ScriptContainer_Settings_ExitUser);										// [s]
	retVal->db = (ILibSimpleDataStore)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_ScriptContainer_Settings_DB);										// [s]
	retVal->exePath = Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_ScriptContainer_ExePath, NULL);												// [s]
	retVal->pipeManager = (ILibProcessPipe_Manager)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_ScriptContainer_PipeManager);						// [s]
	duk_pop(ctx);																																		// ...

	duk_push_global_object(ctx);													// [g]
	duk_get_prop_string(ctx, -1, "process");										// [g][process]
	duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_ArgArray);		// [g][process][array]

	int i, count = duk_get_length(ctx, -1);
	for (i = 0; i < count; ++i)
	{
		duk_get_prop_index(ctx, -1, i);												// [g][process][array][index]
		retVal->argList[i] = (char*)duk_get_string(ctx, -1);
		duk_pop(ctx);																// [g][process][array]
	}
	retVal->argList[i] = NULL;
	duk_pop(ctx);																	// [g][process]

	if (duk_has_prop_string(ctx, -1, ILibDuktape_NativeUncaughtExceptionPtr))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_NativeUncaughtExceptionPtr);		// [g][process][handler]
		duk_get_prop_string(ctx, -2, ILibDuktape_NativeUncaughtExceptionUserPtr);	// [g][process][handler][user]
		retVal->nExeptionHandler = (ILibDuktape_NativeUncaughtExceptionHandler)duk_get_pointer(ctx, -2);
		retVal->nExceptionUserObject = duk_get_pointer(ctx, -1);
		duk_pop_2(ctx);																// [g][process]
	}
	duk_pop_2(ctx);																	// ...


	return(retVal);
}
duk_context *ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx2(SCRIPT_ENGINE_SETTINGS *settings)
{
	return(ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(settings->securityFlags, settings->executionTimeout, settings->chain, settings->argList, settings->db, settings->exePath, settings->pipeManager, settings->exitHandler, settings->exitUserObject));
}

void *ILibDuktape_ScriptContainer_Engine_malloc(void *udata, duk_size_t size)
{
	return(ILibMemory_Allocate(size, 0, NULL, NULL));
}
void *ILibDuktape_ScriptContainer_Engine_realloc(void *udata, void *ptr, duk_size_t size)
{
	if (size == 0)
	{ 
		return(ptr);
	}
	if ((ptr = realloc(ptr, size)) == NULL) 
	{ 
		ILIBCRITICALEXITMSG(255, "REALLOC FAILURE");
	}
	return(ptr);
}
void ILibDuktape_ScriptContainer_Engine_free(void *udata, void *ptr)
{
	free(ptr);
}
void ILibDuktape_ScriptContainer_Engine_fatal(duk_context *ctx, duk_errcode_t code, const char *msg)
{
	ILIBCRITICALEXITMSG(code, msg);
}
duk_ret_t ILibDuktape_ScriptContainer_OS_arch(duk_context *ctx)
{
#ifdef MESH_AGENTID
	duk_push_string(ctx, ARCHNAME[MESH_AGENTID]);
#else
	return(ILibDuktape_Error(ctx, "Result for arch() cannot be determined"));
#endif
	return 1;
}
duk_ret_t ILibDuktape_ScriptContainer_OS_platform(duk_context *ctx)
{
#ifdef WIN32
	duk_push_string(ctx, "win32");
#else
#ifdef __APPLE__
	duk_push_string(ctx, "darwin");
#else
	duk_push_string(ctx, "linux");
#endif
#endif
	return 1;
}
#ifndef WIN32
int ILibDuktape_ScriptContainer_os_isWirelessInterface(char *interfaceName)
{
	int s, retVal = 0;
	char data[4096];

	memset(&data, 0, sizeof(data));
	strncpy(data, interfaceName, IFNAMSIZ);

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0 && (s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)) < 0)
	{
		return(0);
	}
	if (ioctl(s, 0x8B01, &data) != -1)
	{
		retVal = 1;
	}
	close(s);
	return(retVal);
}
#endif

duk_ret_t ILibDuktape_ScriptContainer_OS_networkInterfaces(duk_context *ctx)
{
	duk_push_object(ctx);

#ifdef WIN32
	int i = 0;
	size_t converted;
	char tmpBuffer[32768];
	DWORD tmpBufferSize = sizeof(tmpBuffer);
	IP_ADAPTER_ADDRESSES *padapters = (IP_ADAPTER_ADDRESSES*)tmpBuffer;
	unsigned long mask;
	if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_ANYCAST, NULL, (PIP_ADAPTER_ADDRESSES)tmpBuffer, &tmpBufferSize) != NO_ERROR) { return(ILibDuktape_Error(ctx, "os.networkInterfaces(): Internal Error")); }
	while (padapters != NULL)
	{

		IP_ADAPTER_UNICAST_ADDRESS *addr = padapters->FirstUnicastAddress;
		i = 0;

		duk_push_array(ctx);
		while (addr != NULL)
		{
			duk_push_object(ctx);
			duk_push_string(ctx, ILibRemoteLogging_ConvertAddress((struct sockaddr*)addr->Address.lpSockaddr));
			duk_put_prop_string(ctx, -2, "address");

			duk_push_string(ctx, ((struct sockaddr_in*)addr->Address.lpSockaddr)->sin_family == AF_INET6 ? "IPv6" : "IPv4");
			duk_put_prop_string(ctx, -2, "family");

			if (((struct sockaddr_in*)addr->Address.lpSockaddr)->sin_family == AF_INET)
			{
				if (ConvertLengthToIpv4Mask(addr->OnLinkPrefixLength, &mask) == NO_ERROR)
				{
					struct sockaddr_in tmpAddr;
					memset(&tmpAddr, 0, sizeof(struct sockaddr_in));
					tmpAddr.sin_family = AF_INET;
					tmpAddr.sin_addr.s_addr = mask;
					duk_push_string(ctx, ILibRemoteLogging_ConvertAddress((struct sockaddr*)&tmpAddr));
					duk_put_prop_string(ctx, -2, "netmask");
				}
			}

			duk_push_string(ctx, padapters->PhysicalAddressLength>0 ? util_tohex2(padapters->PhysicalAddress, padapters->PhysicalAddressLength, ILibScratchPad) : "00:00:00:00:00:00");
			duk_put_prop_string(ctx, -2, "mac");

			duk_push_string(ctx, padapters->OperStatus == IfOperStatusUp ? "up" : "down");
			duk_put_prop_string(ctx, -2, "status");

			switch (padapters->IfType)
			{
			case IF_TYPE_ETHERNET_CSMACD:
				duk_push_string(ctx, "ethernet");
				break;
			case IF_TYPE_IEEE80211:
				duk_push_string(ctx, "wireless");
				break;
			case IF_TYPE_TUNNEL:
				duk_push_string(ctx, "tunnel");
				break;
			case IF_TYPE_SOFTWARE_LOOPBACK:
				duk_push_string(ctx, "loopback");
				break;
			default:
				duk_push_string(ctx, "other");
				break;
			}
			duk_put_prop_string(ctx, -2, "type");

			duk_put_prop_index(ctx, -2, i++);
			addr = addr->Next;
		}
		wcstombs_s(&converted, ILibScratchPad, sizeof(ILibScratchPad), padapters->FriendlyName, sizeof(ILibScratchPad));
		duk_put_prop_string(ctx, -2, ILibScratchPad);

		padapters = padapters->Next;
	}
#else
	struct ifaddrs *addrlist;
	struct ifaddrs *current;
	if (getifaddrs(&addrlist) == 0)
	{
		current = addrlist;
		while (current != NULL)
		{
			if (current->ifa_addr != NULL)
			{
				if (((struct sockaddr_in*)current->ifa_addr)->sin_family == AF_PACKET)
				{
					struct sockaddr_ll *pk = (struct sockaddr_ll*)current->ifa_addr;
					char *mac = "00:00:00:00:00:00";
					int isWireless = ILibDuktape_ScriptContainer_os_isWirelessInterface(current->ifa_name);

					if (pk->sll_halen > 0)
					{
						util_tohex2((char*)pk->sll_addr, pk->sll_halen, ILibScratchPad);
						mac = ILibScratchPad;
					}

					if (!duk_has_prop_string(ctx, -1, current->ifa_name))
					{
						duk_push_array(ctx);								// [array]
						duk_push_string(ctx, mac);
						duk_put_prop_string(ctx, -2, "\xFF_mac");
						if (isWireless != 0) duk_push_string(ctx, "wireless"); else duk_push_string(ctx, "ethernet");
						duk_put_prop_string(ctx, -2, "\xFF_type");

						duk_put_prop_string(ctx, -2, current->ifa_name);	// ...
					}
					else
					{
						int i, alen;
						duk_get_prop_string(ctx, -1, current->ifa_name);	// [array]
						duk_push_string(ctx, mac);
						duk_put_prop_string(ctx, -2, "\xFF_mac");
						if (isWireless != 0) duk_push_string(ctx, "wireless"); else duk_push_string(ctx, "ethernet");
						duk_put_prop_string(ctx, -2, "\xFF_type");

						alen = duk_get_length(ctx, -1);
						for (i = 0; i < alen; ++i)
						{
							duk_get_prop_index(ctx, -1, i);
							duk_push_string(ctx, mac);
							duk_put_prop_string(ctx, -2, "mac");
							if (isWireless != 0) duk_push_string(ctx, "wireless"); else duk_push_string(ctx, "ethernet");
							duk_put_prop_string(ctx, -2, "type");
							duk_pop(ctx);
						}
						duk_pop(ctx);										// ...
					}
				}
				if (((struct sockaddr_in*)current->ifa_addr)->sin_family == AF_INET || ((struct sockaddr_in*)current->ifa_addr)->sin_family == AF_INET6)
				{
					if (duk_has_prop_string(ctx, -1, current->ifa_name))
					{
						duk_get_prop_string(ctx, -1, current->ifa_name);
					}
					else
					{
						duk_push_array(ctx);
					}

					duk_push_object(ctx);

					if (duk_has_prop_string(ctx, -2, "\xFF_mac"))
					{
						duk_get_prop_string(ctx, -2, "\xFF_mac");
						duk_put_prop_string(ctx, -2, "mac");
					}
					if (duk_has_prop_string(ctx, -2, "\xFF_type"))
					{
						duk_get_prop_string(ctx, -2, "\xFF_type");
						duk_put_prop_string(ctx, -2, "type");
					}

					duk_push_string(ctx, "up");
					duk_put_prop_string(ctx, -2, "status");

					duk_push_string(ctx, ILibRemoteLogging_ConvertAddress(current->ifa_addr));
					duk_put_prop_string(ctx, -2, "address");

					duk_push_string(ctx, ((struct sockaddr_in*)current->ifa_addr)->sin_family == AF_INET ? "IPv4" : "IPv6");
					duk_put_prop_string(ctx, -2, "family");

					duk_push_string(ctx, ILibRemoteLogging_ConvertAddress(current->ifa_netmask));
					duk_put_prop_string(ctx, -2, "netmask");

					duk_put_prop_index(ctx, -2, duk_get_length(ctx, -2));
					duk_put_prop_string(ctx, -2, current->ifa_name);
				}
			}
			current = current->ifa_next;
		}
		freeifaddrs(addrlist);
	}

	duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);
	while (duk_next(ctx, -1, 1))
	{
		if (duk_get_length(ctx, -1) == 0)
		{
			duk_push_object(ctx);
			duk_get_prop_string(ctx, -2, "\xFF_mac");
			duk_put_prop_string(ctx, -2, "mac");
			duk_get_prop_string(ctx, -2, "\xFF_type");
			duk_put_prop_string(ctx, -2, "type");
			duk_push_string(ctx, "up");
			duk_put_prop_string(ctx, -2, "status");
			duk_put_prop_index(ctx, -2, duk_get_length(ctx, -2));
		}
		duk_pop_2(ctx);
	}
	duk_pop(ctx);
#endif

	return(1);
}
void ILibDuktape_ScriptContainer_OS_Push(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);							// [os]

#ifdef WIN32
	duk_push_string(ctx, "\r\n");
#else
	duk_push_string(ctx, "\n");
#endif
	ILibDuktape_CreateReadonlyProperty(ctx, "EOL");

	ILibDuktape_CreateInstanceMethod(ctx, "arch", ILibDuktape_ScriptContainer_OS_arch, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "platform", ILibDuktape_ScriptContainer_OS_platform, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "networkInterfaces", ILibDuktape_ScriptContainer_OS_networkInterfaces, 0);
}
void ILibDuktape_ScriptContainer_OS_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "os", ILibDuktape_ScriptContainer_OS_Push);
}

duk_context *ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(SCRIPT_ENGINE_SECURITY_FLAGS securityFlags, unsigned int executionTimeout, void *chain, char **argList, ILibSimpleDataStore *db, char *exePath, ILibProcessPipe_Manager pipeManager, ILibDuktape_HelperEvent exitHandler, void *exitUser)
{
	duk_context *ctx = duk_create_heap(ILibDuktape_ScriptContainer_Engine_malloc, ILibDuktape_ScriptContainer_Engine_realloc, ILibDuktape_ScriptContainer_Engine_free, NULL, ILibDuktape_ScriptContainer_Engine_fatal);
	//duk_context *ctx = duk_create_heap_default();
	void **timeoutKey = executionTimeout > 0 ? (void**)ILibMemory_Allocate(sizeof(void*), 0, NULL, NULL) : NULL;

	duk_push_heap_stash(ctx);															// [s]
	duk_push_pointer(ctx, chain);														// [s][chain]
	duk_put_prop_string(ctx, -2, ILibDuktape_Context_Chain);							// [s]
	duk_push_int(ctx, (int)securityFlags);												// [s][flags]
	duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_Settings_SecurityFlags);	// [s]
	duk_push_int(ctx, (int)executionTimeout);											// [s][timeout]
	duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_Settings_ExecutionTimeout);// [s]
	duk_push_pointer(ctx, db);															// [s][db]
	duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_Settings_DB);				// [s]
	duk_push_pointer(ctx, exitHandler);													// [s][exitHandler]
	duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_Settings_ExitHandler);		// [s]
	duk_push_pointer(ctx, exitUser);													// [s][exitUser]
	duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_Settings_ExitUser);		// [s]
	if (exePath != NULL)
	{
		duk_push_string(ctx, exePath);
		duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_ExePath);
	}
	if (pipeManager != NULL)
	{
		duk_push_pointer(ctx, pipeManager);
		duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_PipeManager);
	}
	duk_pop(ctx);																		// ...

	if (exitHandler != NULL) { ILibDuktape_Helper_AddHeapFinalizer(ctx, exitHandler, exitUser); }

	// Setup the permissions on this engine. JavaScript will only be allowed to access the libraries it has access to.
	if ((securityFlags & SCRIPT_ENGINE_NO_NETWORK_ACCESS) == 0)
	{
		ILibDuktape_WebRTC_Init(ctx);						// WebRTC library (browser api)
		ILibDuktape_http_init(ctx, chain);					// HTTP library (node api)
		ILibDuktape_net_init(ctx, chain);					// Network library (node api)
		ILibDuktape_DGram_Init(ctx);						// Datagram Sockets
	}
	if ((securityFlags & SCRIPT_ENGINE_NO_GENERIC_MARSHAL_ACCESS) == 0) { ILibDuktape_GenericMarshal_init(ctx); }
	if ((securityFlags & SCRIPT_ENGINE_NO_PROCESS_SPAWNING) == 0) { ILibDuktape_ProcessPipe_Init(ctx, chain); }
	if ((securityFlags & SCRIPT_ENGINE_NO_FILE_SYSTEM_ACCESS) == 0) { ILibDuktape_fs_init(ctx); }


	ILibDuktape_SHA256_Init(ctx);					// SHA256 as node writable stream
	ILibDuktape_EncryptionStream_init(ctx);
	ILibDuktape_EventEmitter_Init(ctx);				// event emitter
	ILibDuktape_Polyfills_Init(ctx);				// Various Polyfills
	ILibDuktape_MemoryStream_Init(ctx);				// Add MemoryStream support
	ILibDuktape_NetworkMonitor_Init(ctx);

	Duktape_CreateEnum(ctx, "ContainerPermissions", (char*[]) { "DEFAULT", "NO_AGENT", "NO_MARSHAL", "NO_PROCESS_SPAWNING", "NO_FILE_SYSTEM_ACCESS", "NO_NETWORK_ACCESS" }, (int[]) { 0x00, 0x10000000, 0x08000000, 0x04000000, 0x00000001, 0x00000002 }, 6);
#ifdef WIN32
	Duktape_CreateEnum(ctx, "ContainerUserTypes", (char*[]) { "DEFAULT", "USER", "TERMINAL", "WINLOGON" }, (int[]) { ILibProcessPipe_SpawnTypes_DEFAULT, ILibProcessPipe_SpawnTypes_USER, ILibProcessPipe_SpawnTypes_TERM, ILibProcessPipe_SpawnTypes_WINLOGON }, 4);
#else
	Duktape_CreateEnum(ctx, "ContainerUserTypes", (char*[]) { "DEFAULT", "USER", "TERMINAL" }, (int[]) { ILibProcessPipe_SpawnTypes_DEFAULT, ILibProcessPipe_SpawnTypes_USER, ILibProcessPipe_SpawnTypes_TERM }, 3);
#endif

	if (exePath != NULL && pipeManager != NULL)
	{
		ILibDuktape_ModSearch_AddHandler(ctx, "ScriptContainer", ILibDuktape_ScriptContainer_PUSH_MASTER);
	}
	else
	{
		ILibDuktape_ModSearch_AddHandler(ctx, "ScriptContainer", ILibDuktape_ScriptContainer_PUSH_SLAVE);
	}
																															

	// Setup Module Search and Database
	ILibDuktape_ModSearch_Init(ctx, chain, db);
	ILibDuktape_SimpleDataStore_init(ctx, db);

	// Polyfill os functions
	ILibDuktape_ScriptContainer_OS_Init(ctx);

	// Polyfill process functions
	ILibDuktape_ScriptContainer_Process_Init(ctx, argList);
														
	// Setup execution timeout
	if (timeoutKey != NULL)
	{
		timeoutKey[0] = ctx;
		ILibDuktape_Helper_AddHeapFinalizer(ctx, ILibDuktape_ScriptContainer_ExecTimeout_Finalizer, timeoutKey);
		ILibLifeTime_Add(ILibGetBaseTimer(Duktape_GetChain(ctx)), timeoutKey, executionTimeout, ILibDuktape_ScriptContainer_ExecTimeout, NULL);
	}

	return ctx;
}

void ILibDuktape_ScriptContainer_Slave_HeapDestroyed(duk_context *ctx, void *user)
{
	ILibDuktape_ScriptContainer_Slave *slave = (ILibDuktape_ScriptContainer_Slave*)user;
	void *p = ILibDuktape_GetProcessObject(ctx);
	if (p != NULL)
	{
		duk_push_heapptr(ctx, p);					// [process]
		if (!duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_Restart))
		{
			slave->exitCode = Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_ScriptContainer_ExitCode, 0);
			ILibStopChain(slave->chain);
		}
		duk_pop(ctx);								// ...
	}
}

// Compiles the JavaScript to bytecode
int ILibDuktape_ScriptContainer_CompileJavaScript_FromFile(duk_context *ctx, char *path, int pathLen)
{
	if (ctx == NULL)
	{
		return 1;	// Error, but we can't put an error object on top of stack, because we don't have a valid heap ptr (ctx)
	}

	if (path == NULL || pathLen == 0)
	{
		duk_push_error_object(ctx, DUK_ERR_API_ERROR, "Invalid Path specified");
		return(1);
	}
	else
	{
		return(duk_pcompile_lstring_filename(ctx, 0, path, pathLen));
	}
}
// Compiles the JavaScript to bytecode
int ILibDuktape_ScriptContainer_CompileJavaScript(duk_context *ctx, char *payload, int payloadLen)
{
	if (ctx == NULL) 
	{ 
		return 1;	// Error, but we can't put an error object on top of stack, because we don't have a valid heap ptr (ctx)
	}

	if((payloadLen > 0 ? duk_pcompile_lstring(ctx, 0, payload, payloadLen) : duk_pcompile_string(ctx, 0, payload)) != 0)
	{	
		return 1;	// Error.... Error Object is on top of stack
	}
	else
	{
		return 0;	// SUCCESS
	}
}
// Executes the bytecode. If JavaScript is written correctly, this should not block.
int ILibDuktape_ScriptContainer_ExecuteByteCode(duk_context *ctx)
{
	if (duk_pcall(ctx, 0) == 0)
	{
		// SUCCESS					
		return(0);
	}
	else
	{
		// FAILURE					
		return(1);
	}
}

// Slave process, process commmands from the master using stdin.
void ILibDuktape_ScriptContainer_Slave_ProcessCommands(ILibDuktape_ScriptContainer_Slave *slave, char *buffer, ILibProcessPipe_Pipe sender)
{
	SCRIPT_ENGINE_COMMAND cmd = SCRIPT_ENGINE_COMMAND_UNKNOWN;
	duk_context *codec = NULL;

	if (slave->ctx == NULL)
	{
		codec = duk_create_heap_default();
	}
	else
	{
		codec = slave->ctx;
	}
	

	duk_push_lstring(codec, buffer + 4, ((int*)buffer)[0] - 4);
	duk_json_decode(codec, -1);
	cmd = (SCRIPT_ENGINE_COMMAND)Duktape_GetIntPropertyValue(codec, -1, "command", SCRIPT_ENGINE_COMMAND_UNKNOWN);

	ILibRemoteLogging_printf(ILibChainGetLogger(slave->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshAgent_Slave: Command: %u", (unsigned int)cmd);

	switch (cmd)
	{
		case SCRIPT_ENGINE_COMMAND_ADD_MODULE:
		{
			duk_size_t moduleLen;
			char *moduleName = Duktape_GetStringPropertyValue(slave->ctx, -1, "name", NULL);
			char *module = Duktape_GetStringPropertyValueEx(slave->ctx, -1, "module", NULL, &moduleLen);

			ILibDuktape_ModSearch_AddModule(slave->ctx, moduleName, module, moduleLen);
			ILibRemoteLogging_printf(ILibChainGetLogger(slave->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshAgent_Slave: Added module %s", moduleName);

			break;
		}
		case SCRIPT_ENGINE_COMMAND_INIT:
		{
			SCRIPT_ENGINE_SECURITY_FLAGS securityFlags = (SCRIPT_ENGINE_SECURITY_FLAGS)Duktape_GetIntPropertyValue(codec, -1, "securityFlags", 0);
			unsigned int executionTimeout = (unsigned int)Duktape_GetIntPropertyValue(codec, -1, "executionTimeout", 0);
			void **argList = NULL;
			if (duk_has_prop_string(codec, -1, "argv"))
			{
				duk_get_prop_string(codec, -1, "argv");							// [json][argv]
				int i, argLen = duk_get_length(codec, -1);
				if (argLen > 0)
				{
					if ((argLen + 1) * sizeof(void*) > sizeof(ILibScratchPad))
					{
						duk_push_object(codec);
						duk_push_int(codec, (int)SCRIPT_ENGINE_COMMAND_INIT);
						duk_put_prop_string(codec, -2, "command");
						duk_push_string(codec, "argv list was invalid");
						duk_put_prop_string(codec, -2, "error");
						ILibDuktape_ScriptContainer_Slave_SendJSON(codec);

						duk_pop(codec);											// [json]
						break;
					}
					else
					{
						argList = (void**)ILibScratchPad;
						for (i = 0; i < argLen; ++i)
						{
							duk_get_prop_index(codec, -1, i);						// [json][argv][val]
							argList[i] = (char*)duk_get_string(codec, -1);
							duk_pop(codec);											// [json][argv]
						}
						argList[i] = NULL;
						duk_pop(codec);												// [json]
					}
				}
			}

			if (slave->ctx != NULL) { duk_destroy_heap(slave->ctx); slave->ctx = codec = NULL; }
			slave->ctx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngine(securityFlags, executionTimeout, slave->chain, (char**)argList, NULL, ILibDuktape_ScriptContainer_Slave_HeapDestroyed, slave);
			
			duk_push_heap_stash(slave->ctx);											// [s]
			duk_push_pointer(slave->ctx, slave);										// [s][slave]
			duk_put_prop_string(slave->ctx, -2, ILibDuktape_ScriptContainer_SlavePtr);	// [s]
			duk_pop(slave->ctx);														// ...

			ILibRemoteLogging_printf(ILibChainGetLogger(slave->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshAgent_Slave: Created Java Script Engine: %p", (void*)slave->ctx);

			duk_push_object(slave->ctx);
			duk_push_int(slave->ctx, (int)SCRIPT_ENGINE_COMMAND_INIT);
			duk_put_prop_string(slave->ctx, -2, "command");
			ILibDuktape_ScriptContainer_Slave_SendJSON(slave->ctx);
		}
		break;
		case SCRIPT_ENGINE_COMMAND_EXEC:
		{
			int seq = Duktape_GetIntPropertyValue(slave->ctx, -1, "sequence", -1);			// [json]
			char *execData;
			duk_size_t execDataLen;
			if (slave->ctx == NULL)
			{
				// Cannot call execute without first calling INIT
				duk_push_object(codec);														// [json][retJSON]
				duk_push_int(codec, (int)SCRIPT_ENGINE_COMMAND_EXEC);						// [json][retJSON][command
				duk_put_prop_string(codec, -2, "command");									// [json][retJSON]
				if (seq >= 0)
				{
					duk_push_int(codec, seq);													// [json][retJSON][sequence]
					duk_put_prop_string(codec, -2, "sequence");									// [json][retJSON]
				}
				duk_push_string(codec, "Cannot call execute without first calling INIT");	// [json][retJSON][errMsg]
				duk_put_prop_string(codec, -2, "error");									// [json][retJSON]
				ILibDuktape_ScriptContainer_Slave_SendJSON(codec);							// [json]
			}
			else
			{
				if (duk_has_prop_string(slave->ctx, -1, "string"))
				{
					// Execute String
					execData = (char*)Duktape_GetStringPropertyValueEx(slave->ctx, -1, "string", NULL, &execDataLen);
					if (ILibDuktape_ScriptContainer_CompileJavaScript(slave->ctx, execData, execDataLen) == 0 && ILibDuktape_ScriptContainer_ExecuteByteCode(slave->ctx) == 0)
					{
						// Success
						duk_push_object(slave->ctx);										// [json][retJSON]
						duk_push_int(slave->ctx, (int)SCRIPT_ENGINE_COMMAND_EXEC);			// [json][retJSON][command
						duk_put_prop_string(slave->ctx, -2, "command");						// [json][retJSON]
						if (seq >= 0)
						{
							duk_push_int(slave->ctx, seq);										// [json][retJSON][sequence]
							duk_put_prop_string(slave->ctx, -2, "sequence");					// [json][retJSON]
						}
						if (!duk_is_undefined(slave->ctx, -2))
						{
							duk_dup(slave->ctx, -2);										// [json][retJSON][retVal]
							duk_json_encode(slave->ctx, -1);								// [json][retJSON][retValJSON]
							duk_put_prop_string(slave->ctx, -2, "result");					// [json][retJSON]
						}
					}
					else
					{
						// Failure															// [json][error]
						char *errMsg = (char*)duk_safe_to_string(slave->ctx, -1);
						duk_push_string(slave->ctx, errMsg);								// [json][error][errMsg]
						duk_swap_top(slave->ctx, -2);										// [json][errMsg][error]
						duk_pop(slave->ctx);												// [json][errMsg]
						duk_push_object(slave->ctx);										// [json][errMsg][retJSON]
						duk_push_int(slave->ctx, (int)SCRIPT_ENGINE_COMMAND_EXEC);			// [json][errMsg][retJSON][command
						duk_put_prop_string(slave->ctx, -2, "command");						// [json][errMsg][retJSON]
						if (seq >= 0)
						{
							duk_push_int(slave->ctx, seq);										// [json][errMsg][retJSON][sequence]
							duk_put_prop_string(slave->ctx, -2, "sequence");					// [json][errMsg][retJSON]
						}
						duk_swap_top(slave->ctx, -2);										// [json][retJSON][errMsg]
						duk_put_prop_string(slave->ctx, -2, "error");						// [json][retJSON]
					}
					ILibDuktape_ScriptContainer_Slave_SendJSON(slave->ctx);					// [json]
				}
				else if (duk_has_prop_string(slave->ctx, -1, "path"))
				{
					// Execute Path
					execData = (char*)Duktape_GetStringPropertyValueEx(slave->ctx, -1, "path", NULL, &execDataLen);
					if (ILibDuktape_ScriptContainer_CompileJavaScript_FromFile(slave->ctx, execData, execDataLen) == 0 && ILibDuktape_ScriptContainer_ExecuteByteCode(slave->ctx))
					{
						// SUCCESS
						duk_push_object(slave->ctx);										// [json][retJSON]
						duk_push_int(slave->ctx, (int)SCRIPT_ENGINE_COMMAND_EXEC);			// [json][retJSON][command
						duk_put_prop_string(slave->ctx, -2, "command");						// [json][retJSON]
						if (seq >= 0)
						{
							duk_push_int(slave->ctx, seq);										// [json][retJSON][sequence]
							duk_put_prop_string(slave->ctx, -2, "sequence");					// [json][retJSON]
						}
						if (!duk_is_undefined(slave->ctx, -2))
						{
							duk_dup(slave->ctx, -2);										// [json][retJSON][retVal]
							duk_json_encode(slave->ctx, -1);								// [json][retJSON][retValJSON]
							duk_put_prop_string(slave->ctx, -2, "result");					// [json][retJSON]
						}
					}
					else
					{
						// ERROR
						char *errMsg = (char*)duk_safe_to_string(slave->ctx, -1);
						duk_push_string(slave->ctx, errMsg);								// [json][error][errMsg]
						duk_swap_top(slave->ctx, -2);										// [json][errMsg][error]
						duk_pop(slave->ctx);												// [json][errMsg]
						duk_push_object(slave->ctx);										// [json][errMsg][retJSON]
						duk_push_int(slave->ctx, (int)SCRIPT_ENGINE_COMMAND_EXEC);			// [json][errMsg][retJSON][command
						duk_put_prop_string(slave->ctx, -2, "command");						// [json][errMsg][retJSON]
						if (seq >= 0)
						{
							duk_push_int(slave->ctx, seq);										// [json][errMsg][retJSON][sequence]
							duk_put_prop_string(slave->ctx, -2, "sequence");					// [json][errMsg][retJSON]
						}
						duk_swap_top(slave->ctx, -2);										// [json][retJSON][errMsg]
						duk_put_prop_string(slave->ctx, -2, "error");						// [json][retJSON]
					}
					ILibDuktape_ScriptContainer_Slave_SendJSON(slave->ctx);					// [json]
				}
				else
				{
					// Error
					duk_push_object(slave->ctx);										// [json][retJSON]
					duk_push_int(slave->ctx, (int)SCRIPT_ENGINE_COMMAND_EXEC);			// [json][retJSON][command
					duk_put_prop_string(slave->ctx, -2, "command");						// [json][retJSON]
					if (seq >= 0)
					{
						duk_push_int(slave->ctx, seq);										// [json][retJSON][sequence]
						duk_put_prop_string(slave->ctx, -2, "sequence");					// [json][retJSON]
					}
					duk_push_string(slave->ctx, "Malformed Command");					// [json][retJSON][errmsg]
					duk_put_prop_string(slave->ctx, -2, "error");						// [json][retJSON]
					ILibDuktape_ScriptContainer_Slave_SendJSON(slave->ctx);				// [json]
				}
			}
			break;
		}
		break;
		case SCRIPT_ENGINE_COMMAND_SEND_JSON:
		{
			if (slave->OnData != NULL)
			{
				char *json = Duktape_GetStringPropertyValue(slave->ctx, -1, "json", NULL);
				if (json != NULL)
				{
					duk_push_heapptr(slave->ctx, slave->OnData);									// [func]
					duk_push_heapptr(slave->ctx, slave->emitter->object);							// [func][this]
					duk_push_string(slave->ctx, json);												// [func][this][json]
					duk_json_decode(slave->ctx, -1);												// [func][this][object]
					if (duk_pcall_method(slave->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(slave->ctx, "ScriptContainer.OnData(): "); }
					duk_pop(slave->ctx);															// ...
				}
			}
			break;
		}
		default:
			break;

	}

	if (codec != NULL && slave->ctx == NULL)
	{
		duk_destroy_heap(codec);
	}
}


#ifdef WIN32
void ILibDuktape_ScriptContainer_Slave_OnReadStdInEx(void *chain, void *data)
{
	ILibDuktape_ScriptContainer_Slave *slave = (ILibDuktape_ScriptContainer_Slave*)((void**)ILibMemory_GetExtraMemory(data, ILibMemory_ILibProcessPipe_Pipe_CONTAINERSIZE))[0];
	char *buffer = (char*)((void**)ILibMemory_GetExtraMemory(data, ILibMemory_ILibProcessPipe_Pipe_CONTAINERSIZE))[1];

	ILibDuktape_ScriptContainer_Slave_ProcessCommands(slave, buffer, (ILibProcessPipe_Pipe)data);
	ILibProcessPipe_Pipe_Resume((ILibProcessPipe_Pipe)data);
}
#endif
void ILibDuktape_ScriptContainer_Slave_OnReadStdIn(ILibProcessPipe_Pipe sender, char *buffer, int bufferLen, int* bytesConsumed)
{
	ILibDuktape_ScriptContainer_Slave *slave = (ILibDuktape_ScriptContainer_Slave*)((void**)ILibMemory_GetExtraMemory(sender, ILibMemory_ILibProcessPipe_Pipe_CONTAINERSIZE))[0];
	if (bufferLen < 4 || bufferLen < ((int*)buffer)[0]) { return; }
	ILibRemoteLogging_printf(ILibChainGetLogger(slave->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "Slave read: %d bytes", bufferLen);

#ifdef WIN32
	// Windows dispatches on a non-microstack thread, so we need to context switch to microstack/duktape thread
	((void**)ILibMemory_GetExtraMemory(sender, ILibMemory_ILibProcessPipe_Pipe_CONTAINERSIZE))[1] = buffer;

	ILibProcessPipe_Pipe_Pause(sender);
	ILibChain_RunOnMicrostackThread(slave->chain, ILibDuktape_ScriptContainer_Slave_OnReadStdInEx, sender);
#else
	ILibDuktape_ScriptContainer_Slave_ProcessCommands(slave, buffer, sender);
#endif
	
	*bytesConsumed = ((int*)buffer)[0];
}

int ILibDuktape_ScriptContainer_StartSlave(void *chain, ILibProcessPipe_Manager manager)
{
	// We are just a slave container
	ILibProcessPipe_Pipe mStdIn = NULL;
	ILibDuktape_ScriptContainer_Slave slaveObject;

#ifdef _REMOTELOGGING
	ILibRemoteLogging logger = ILibRemoteLogging_Create(NULL);
	ILibRemoteLogging_SetRawForward(logger, 0, ILibDuktape_ScriptContainer_Slave_LogForwarder);
	ILibChainSetLogger(chain, logger);
#endif

#ifndef MICROSTACK_NOTLS
	util_openssl_init();
#endif

	memset(&slaveObject, 0, sizeof(ILibDuktape_ScriptContainer_Slave));
	slaveObject.chain = chain;

	ILibRemoteLogging_printf(logger, ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "Starting Slave Process");

	// We must attach StdIn to fetch parameters
#ifdef WIN32
	mStdIn = ILibProcessPipe_Pipe_CreateFromExistingWithExtraMemory(manager, GetStdHandle(STD_INPUT_HANDLE), ILibProcessPipe_Pipe_ReaderHandleType_NotOverLapped, 2 * sizeof(void*));
#else
	mStdIn = ILibProcessPipe_Pipe_CreateFromExistingWithExtraMemory(manager, STDIN_FILENO, sizeof(void*));
#endif
	((void**)ILibMemory_GetExtraMemory(mStdIn, ILibMemory_ILibProcessPipe_Pipe_CONTAINERSIZE))[0] = &slaveObject;

	ILibProcessPipe_Pipe_SetBrokenPipeHandler(mStdIn, ILibDuktape_ScriptContainer_Slave_OnBrokenPipe);
	ILibProcessPipe_Pipe_AddPipeReadHandler(mStdIn, SCRIPT_ENGINE_PIPE_BUFFER_SIZE, ILibDuktape_ScriptContainer_Slave_OnReadStdIn);

	ILibStartChain(chain);

#ifndef MICROSTACK_NOTLS
	util_openssl_uninit();
#endif

	return(slaveObject.exitCode);
}


int ILibDuktape_ScriptContainer_DecodeJSON(duk_context *ctx, char *json, int jsonLen)
{
	int retVal = 0;
	duk_push_global_object(ctx);								// [g]
	duk_get_prop_string(ctx, -1, "JSON");						// [g][JSON]
	duk_get_prop_string(ctx, -1, "parse");						// [g][JSON][func]
	duk_swap_top(ctx, -3);										// [func][JSON][g]
	duk_pop_2(ctx);												// [func]
	duk_push_lstring(ctx, json, jsonLen);						// [func][str]
	if (duk_pcall(ctx, 1) != 0) { retVal = 1; duk_pop(ctx); }
	return(retVal);
}

int ILibDuktape_ScriptContainer_AddVoidPtr(duk_context *ctx, void *heapptr, void *ptr)
{
	int i;
	duk_push_heapptr(ctx, heapptr);															// [master]
	if (!duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_PtrTable))
	{
		duk_push_object(ctx);																// [master][obj]
		duk_dup(ctx, -1);																	// [master][obj][obj]
		duk_put_prop_string(ctx, -3, ILibDuktape_ScriptContainer_PtrTable);					// [master][obj]
	}

	i = 1 + Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_ScriptContainer_PtrTable_Idx, 0);
	duk_push_int(ctx, i);
	duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_PtrTable_Idx);					// [master][obj]
	duk_push_pointer(ctx, ptr);
	duk_put_prop_index(ctx, -2, i);
	duk_pop_2(ctx);																			// ...
	return(i);
}
void* ILibDuktape_ScriptContainer_RemoveVoidPtr(duk_context *ctx, void *heapptr, int idx)
{
	int i;
	void *retVal = NULL;
	duk_push_heapptr(ctx, heapptr);																			// [master]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_PtrTable))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_PtrTable);									// [master][obj]
		i = Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_ScriptContainer_PtrTable_Idx, 0);
		if (duk_has_prop_index(ctx, -1, i))
		{
			duk_get_prop_index(ctx, -1, i);																	// [master][obj][ptr]
			retVal = duk_get_pointer(ctx, -1);
			duk_pop(ctx);																					// [master][obj]
			duk_del_prop_index(ctx, -1, i);
		}
		duk_pop(ctx);																						// [master]
	}
	duk_pop(ctx);																							// ...
	return(retVal);
}


duk_ret_t ILibDuktape_ScriptContainer_Exit(duk_context *ctx)
{
	ILibDuktape_ScriptContainer_Master *master;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_MasterPtr);
	master = (ILibDuktape_ScriptContainer_Master*)Duktape_GetBuffer(ctx, -1, NULL);

	if (ILibIsChainBeingDestroyed(Duktape_GetChain(ctx)) == 0)
	{
		if (master->child != NULL) { ILibProcessPipe_Process_SoftKill(master->child); }
	}
	return 0;
}
duk_ret_t ILibDuktape_ScriptContainer_ExecuteScript(duk_context *ctx)
{
	return 0;
}
duk_ret_t ILibDuktape_ScriptContainer_ExecuteString(duk_context *ctx)
{
	ILibDuktape_ScriptContainer_Master *master;
	void *ptr = duk_get_top(ctx) > 1 ? duk_require_heapptr(ctx, 1) : NULL;
	int seq = -1;
	duk_size_t bufferLen;
	char *buffer;
	char header[4];

	duk_require_string(ctx, 0);
	duk_push_this(ctx);																	// [container]
	duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_MasterPtr);				// [container][buffer]
	master = (ILibDuktape_ScriptContainer_Master*)Duktape_GetBuffer(ctx, -1, NULL);		// [container][buffer]

	if (ptr != NULL) { seq = ILibDuktape_ScriptContainer_AddVoidPtr(ctx, duk_get_heapptr(ctx, -2), ptr); }

	duk_push_object(ctx);																// [container][buffer][obj]
	duk_push_int(ctx, (int)SCRIPT_ENGINE_COMMAND_EXEC);									// [container][buffer][obj][command]
	duk_put_prop_string(ctx, -2, "command");											// [container][buffer][obj]
	duk_dup(ctx, 0);																	// [container][buffer][obj][string]
	duk_put_prop_string(ctx, -2, "string");												// [container][buffer][obj]
	if (ptr != NULL)
	{
		duk_push_int(ctx, seq);															// [container][buffer][obj][seq]
		duk_put_prop_string(ctx, -2, "sequence");										// [container][buffer][obj]
	}
	
	duk_json_encode(ctx, -1);										
	buffer = (char*)duk_get_lstring(ctx, -1, &bufferLen);

	((int*)header)[0] = bufferLen + 4;

	ILibProcessPipe_Process_WriteStdIn(master->child, header, 4, ILibTransport_MemoryOwnership_USER);
	ILibProcessPipe_Process_WriteStdIn(master->child, buffer, bufferLen, ILibTransport_MemoryOwnership_USER);

	return(0);
}
void ILibDuktape_ScriptContainer_ExitSink(ILibProcessPipe_Process sender, int exitCode, void* user)
{
	ILibDuktape_ScriptContainer_Master *master = (ILibDuktape_ScriptContainer_Master*)user;
	
	if (master->OnExit != NULL)
	{
		duk_push_heapptr(master->ctx, master->OnExit);			// [func]
		duk_push_heapptr(master->ctx, master->emitter->object);	// [func][this]
		duk_push_int(master->ctx, exitCode);					// [func][this][code]
		if (duk_pcall_method(master->ctx, 1) != 0)				// [retVal]
		{
			ILibDuktape_Process_UncaughtException(master->ctx);
		}
		duk_pop(master->ctx);									// ...
	}

	master->child = NULL;
}
void ILibDuktape_ScriptContainer_StdOutSink(ILibProcessPipe_Process sender, char *buffer, int bufferLen, int* bytesConsumed, void* user)
{
	buffer[bufferLen] = 0;
	printf("StdOut: %s", buffer);
	*bytesConsumed = bufferLen;
}
void ILibDuktape_ScriptContainer_SendOkSink(ILibProcessPipe_Process sender, void* user)
{
}
void ILibDuktape_ScriptContainer_StdErrSink_MicrostackThread(void *chain, void *user)
{
	ILibDuktape_ScriptContainer_Master *master = (ILibDuktape_ScriptContainer_Master*)((void**)user)[0];
	char *buffer = (char*)((void**)user)[1];
	int bufferLen = ((int*)buffer)[0];
	void *ptr;
	int i;

	if (ILibDuktape_ScriptContainer_DecodeJSON(master->ctx, buffer+4, bufferLen-4) == 0)
	{
		switch ((SCRIPT_ENGINE_COMMAND)Duktape_GetIntPropertyValue(master->ctx, -1, "command", (int)SCRIPT_ENGINE_COMMAND_UNKNOWN))
		{
			case SCRIPT_ENGINE_COMMAND_SEND_JSON:
			{
				if (master->OnJSON != NULL)
				{
					char *json = Duktape_GetStringPropertyValue(master->ctx, -1, "json", NULL);
					if (json != NULL)
					{
						duk_push_heapptr(master->ctx, master->OnJSON);
						duk_push_heapptr(master->ctx, master->emitter->object);
						duk_push_string(master->ctx, json);
						duk_json_decode(master->ctx, -1);
						if (duk_pcall_method(master->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(master->ctx, "ScriptContainer.OnData(): "); }
						duk_pop(master->ctx);
					}
				}
				break;
			}
			case SCRIPT_ENGINE_COMMAND_LOG:
				{
					ILibRemoteLogging_printf(ILibChainGetLogger(Duktape_GetChain(master->ctx)), (ILibRemoteLogging_Modules)Duktape_GetIntPropertyValue(master->ctx, -1, "module", (int)ILibRemoteLogging_Modules_ConsolePrint), (ILibRemoteLogging_Flags)Duktape_GetIntPropertyValue(master->ctx, -1, "flags", (int)ILibRemoteLogging_Flags_NONE), "%s", Duktape_GetStringPropertyValue(master->ctx, -1, "message", ""));
					break;
				}
			case SCRIPT_ENGINE_COMMAND_EXEC:
			{
				if (duk_has_prop_string(master->ctx, -1, "error"))
				{
					// ERROR
					if ((i = Duktape_GetIntPropertyValue(master->ctx, -1, "sequence", -1)) < 0)
					{
						// No callback was specified
						if (master->OnError != NULL)
						{
							duk_push_heapptr(master->ctx, master->OnError);									// [func]
							duk_push_heapptr(master->ctx, master->emitter->object);							// [func][this]
							duk_get_prop_string(master->ctx, -3, "error");									// [func][this][error]
							if (duk_pcall_method(master->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(master->ctx, "ScriptContainer_OnError_Dispatch(): "); }
							duk_pop(master->ctx);															// ...
						}
					}
					else
					{
						if ((ptr = ILibDuktape_ScriptContainer_RemoveVoidPtr(master->ctx, master->emitter->object, i)) != NULL)
						{
							// Callback was provided
							duk_push_heapptr(master->ctx, ptr);												// [func]
							duk_push_heapptr(master->ctx, master->emitter->object);							// [func][this]
							duk_push_false(master->ctx);													// [func][this][false]
							duk_get_prop_string(master->ctx, -4, "error");									// [func][this][false][error]
							if (duk_pcall_method(master->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(master->ctx, "ScriptContainer_OnError_Dispatch(): "); }
							duk_pop(master->ctx);															// ...
						}
					}
				}
				else
				{
					// SUCCESS
					if ((i = Duktape_GetIntPropertyValue(master->ctx, -1, "sequence", -1)) >= 0 && (ptr = ILibDuktape_ScriptContainer_RemoveVoidPtr(master->ctx, master->emitter->object, i)) != NULL)
					{
						duk_push_heapptr(master->ctx, ptr);												// [func]
						duk_push_heapptr(master->ctx, master->emitter->object);							// [func][this]
						duk_push_true(master->ctx);														// [func][this][true]
						if (duk_has_prop_string(master->ctx, -4, "result"))
						{
							duk_get_prop_string(master->ctx, -4, "result");
							duk_json_decode(master->ctx, -1);											// [func][this][true][result]
						}
						else
						{
							duk_push_undefined(master->ctx);											// [func][this][true][undefined]
						}
						if (duk_pcall_method(master->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(master->ctx, "ScriptContainer_OnExec_Dispatch(): "); }
						duk_pop(master->ctx);															// ...
					}
				}
				break;
			}
			default:
				break;
		}
		duk_pop(master->ctx);		// ...
	}

#ifdef WIN32
	ILibProcessPipe_Pipe_Resume(ILibProcessPipe_Process_GetStdErr(master->child));
#endif
}
void ILibDuktape_ScriptContainer_StdErrSink(ILibProcessPipe_Process sender, char *buffer, int bufferLen, int* bytesConsumed, void* user)
{
	ILibDuktape_ScriptContainer_Master* master = (ILibDuktape_ScriptContainer_Master*)user;
	
	if (bufferLen < 4 || bufferLen < ((int*)buffer)[0]) { return; }
	
	*bytesConsumed = ((int*)buffer)[0];
#ifdef WIN32
	void **ptr = (void**)ILibMemory_GetExtraMemory(ILibProcessPipe_Process_GetStdErr(sender), ILibMemory_ILibProcessPipe_Pipe_CONTAINERSIZE);
	ptr[0] = master;
	ptr[1] = buffer;
	ILibProcessPipe_Pipe_Pause(ILibProcessPipe_Process_GetStdErr(sender));
	ILibChain_RunOnMicrostackThread(master->chain, ILibDuktape_ScriptContainer_StdErrSink_MicrostackThread, ptr);
#else
	void *ptr[2] = { master, buffer };
	ILibDuktape_ScriptContainer_StdErrSink_MicrostackThread(master->chain, ptr);
#endif


}

duk_ret_t ILibDuktape_ScriptContainer_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, ILibDuktape_ScriptContainer_MasterPtr);
	ILibDuktape_ScriptContainer_Master *master = (ILibDuktape_ScriptContainer_Master*)Duktape_GetBuffer(ctx, -1, NULL);
	if (master->child != NULL)
	{
		ILibProcessPipe_Process_KillEx(master->child);
	}

	return(0);
}
duk_ret_t ILibDuktape_ScriptContainer_SendToSlave(duk_context *ctx)
{
	ILibDuktape_ScriptContainer_Master *master;
	int len;

	duk_push_this(ctx);																	// [container]
	duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_MasterPtr);				// [container][master]
	master = (ILibDuktape_ScriptContainer_Master*)Duktape_GetBuffer(ctx, -1, NULL);

	duk_push_object(ctx);																// [container][master][obj]
	duk_push_int(ctx, (int)SCRIPT_ENGINE_COMMAND_SEND_JSON);							// [container][master][obj][command]
	duk_put_prop_string(ctx, -2, "command");											// [container][master][obj]
	duk_dup(ctx, 0);																	// [container][master][obj][value]
	duk_json_encode(ctx, -1);															// [container][master][obj][json]
	duk_put_prop_string(ctx, -2, "json");												// [container][master][obj]

	duk_json_encode(ctx, -1);															// [container][master][json]
	len = sprintf_s(ILibScratchPad2 + 4, sizeof(ILibScratchPad2) - 4, "%s", duk_get_string(ctx, -1));
	((int*)ILibScratchPad2)[0] = len + 4;

	ILibProcessPipe_Process_WriteStdIn(master->child, ILibScratchPad2, len + 4, ILibTransport_MemoryOwnership_USER);
	return(0);
}
duk_ret_t ILibDuktape_ScriptContainer_Master_AddModule(duk_context *ctx)
{
	ILibDuktape_ScriptContainer_Master *master;
	int len;

	duk_push_this(ctx);																	// [container]
	duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_MasterPtr);				// [container][master]
	master = (ILibDuktape_ScriptContainer_Master*)Duktape_GetBuffer(ctx, -1, NULL);

	duk_push_object(ctx);
	duk_push_int(ctx, (int)SCRIPT_ENGINE_COMMAND_ADD_MODULE);
	duk_put_prop_string(ctx, -2, "command");
	duk_dup(ctx, 0);
	duk_put_prop_string(ctx, -2, "name");
	duk_dup(ctx, 1);
	duk_put_prop_string(ctx, -2, "module");
	duk_json_encode(ctx, -1);

	len = sprintf_s(ILibScratchPad2 + 4, sizeof(ILibScratchPad2) - 4, "%s", duk_get_string(ctx, -1));
	((int*)ILibScratchPad2)[0] = len + 4;

	ILibProcessPipe_Process_WriteStdIn(master->child, ILibScratchPad2, len+4, ILibTransport_MemoryOwnership_USER);
	return(0);
}
duk_ret_t ILibDuktape_ScriptContainer_Create(duk_context *ctx)
{
	char *exePath;
	ILibProcessPipe_Manager manager;
	ILibDuktape_ScriptContainer_Master *master;
	char *param[] = { (char*)"--slave", NULL };
	duk_size_t bufferLen;
	char *buffer;
	char header[4];
	ILibProcessPipe_SpawnTypes spawnType = (duk_get_top(ctx) > 2 && duk_is_number(ctx, 2)) ? (ILibProcessPipe_SpawnTypes)duk_require_int(ctx, 2) : ILibProcessPipe_SpawnTypes_DEFAULT;

	duk_push_heap_stash(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_ExePath);
	duk_get_prop_string(ctx, -2, ILibDuktape_ScriptContainer_PipeManager);

	exePath = (char*)duk_get_string(ctx, -2);
	manager = (ILibProcessPipe_Manager)duk_get_pointer(ctx, -1);

	duk_push_object(ctx);														// [container]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_ScriptContainer_Master));		// [container][buffer]
	master = (ILibDuktape_ScriptContainer_Master*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_MasterPtr);		// [container]

	memset(master, 0, sizeof(ILibDuktape_ScriptContainer_Master));
	master->ctx = ctx;
	master->emitter = ILibDuktape_EventEmitter_Create(ctx);
	master->chain = Duktape_GetChain(ctx);
	ILibDuktape_EventEmitter_CreateEvent(master->emitter, "exit", &(master->OnExit));
	ILibDuktape_EventEmitter_CreateEvent(master->emitter, "error", &(master->OnError));
	ILibDuktape_EventEmitter_CreateEvent(master->emitter, "data", &(master->OnJSON));
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "exit", ILibDuktape_ScriptContainer_Exit, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(master->ctx, "ExecuteScript", ILibDuktape_ScriptContainer_ExecuteScript, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(master->ctx, "ExecuteString", ILibDuktape_ScriptContainer_ExecuteString, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(master->ctx, "send", ILibDuktape_ScriptContainer_SendToSlave, 1);
	ILibDuktape_CreateInstanceMethod(master->ctx, "addModule", ILibDuktape_ScriptContainer_Master_AddModule, 2);
	ILibDuktape_CreateFinalizer(master->ctx, ILibDuktape_ScriptContainer_Finalizer);

	unsigned int executionTimeout = (unsigned int)duk_require_int(ctx, 0);
	unsigned int securityFlags = (unsigned int)duk_require_int(ctx, 1) | SCRIPT_ENGINE_NO_MESH_AGENT_ACCESS;

	master->child = ILibProcessPipe_Manager_SpawnProcessEx2(manager, exePath, (char * const*)param, spawnType, 2 * sizeof(void*));
	if (master->child == NULL) { return(ILibDuktape_Error(ctx, "ScriptContainer.Create(): Error spawning child process, using [%s]", exePath)); }

	duk_push_object(ctx);										// [container][obj]
	duk_push_int(ctx, (int)SCRIPT_ENGINE_COMMAND_INIT);
	duk_put_prop_string(ctx, -2, "command");
	duk_push_int(ctx, (int)executionTimeout);
	duk_put_prop_string(ctx, -2, "executionTimeout");
	duk_push_int(ctx, (int)securityFlags);
	duk_put_prop_string(ctx, -2, "securityFlags");
	duk_json_encode(ctx, -1);
	buffer = (char*)Duktape_GetBuffer(ctx, -1, &bufferLen);

	duk_swap_top(ctx, -2);										// [json][container]

	((int*)header)[0] = bufferLen + 4;
	ILibProcessPipe_Process_AddHandlers(master->child, SCRIPT_ENGINE_PIPE_BUFFER_SIZE, ILibDuktape_ScriptContainer_ExitSink, ILibDuktape_ScriptContainer_StdOutSink, ILibDuktape_ScriptContainer_StdErrSink, ILibDuktape_ScriptContainer_SendOkSink, master);
	ILibProcessPipe_Process_WriteStdIn(master->child, header, sizeof(header), ILibTransport_MemoryOwnership_USER);
	ILibProcessPipe_Process_WriteStdIn(master->child, buffer, (int)bufferLen, ILibTransport_MemoryOwnership_USER);
	return 1;
}
void ILibDuktape_ScriptContainer_PUSH_MASTER(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);				
	ILibDuktape_CreateInstanceMethod(ctx, "Create", ILibDuktape_ScriptContainer_Create, DUK_VARARGS);
}
duk_ret_t ILibDuktape_ScriptContainer_Slave_SendToMaster(duk_context *ctx)
{
	duk_push_object(ctx);										// [obj]
	duk_push_int(ctx, (int)SCRIPT_ENGINE_COMMAND_SEND_JSON);	// [obj][cmd]
	duk_put_prop_string(ctx, -2, "command");					// [obj]
	duk_dup(ctx, 0);											// [obj][value]
	duk_json_encode(ctx, -1);									// [obj][json]
	duk_put_prop_string(ctx, -2, "json");						// [obj]

	ILibDuktape_ScriptContainer_Slave_SendJSON(ctx);
	return(0);
}
void ILibDuktape_ScriptContainer_PUSH_SLAVE(duk_context *ctx, void *chain)
{
	ILibDuktape_ScriptContainer_Slave *slave;

	duk_push_heap_stash(ctx);												// [s]
	duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_SlavePtr);		// [s][ptr]
	slave = (ILibDuktape_ScriptContainer_Slave*)duk_get_pointer(ctx, -1);
	duk_pop(ctx);															// ...

	duk_push_object(ctx);
	slave->emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEvent(slave->emitter, "data", &(slave->OnData));
	ILibDuktape_CreateInstanceMethod(ctx, "send", ILibDuktape_ScriptContainer_Slave_SendToMaster, 1);
}

#ifdef __DOXY__
/*!
\brief The os module provides a number of operating system-related utility methods. <b>Note:</b> To use, must <b>require('os')</b>
*/
class os
{
public:
	/*!
	\brief Constant defining the operating system specific end-of-line marker (<b>'\\r'</b> or <b>'\\r\\n'</b>)
	*/
	String EOL;
	/*!
	\brief returns a String identifying the operating system platform (<b>'darwin'</b>, <b>'win32'</b>, or <b>'linux'</b>)
	\return \<String\>
	*/
	String platform();
	/*!
	\brief Returns a String identifying the operating system CPU architecture (ie: <b>'x86'</b>, <b>'x64'</b>, etc) <b>Note:</b> Same as process.arch
	\return \<String\>
	*/
	String arch();
	/*!
	\brief Returns an object containing the current network interfaces
	*
	Each key on the returned object identifies a network interfaces. The associated value is an array of objects that each describe an assigned network address.\n
	\par The properties available on the network address object include:\n
	<b>address</b> \<String\> The assigned IPv4 or IPv6 address\n
	<b>netmask</b> \<String\> The IPv4 of IPv6 network mask\n
	<b>family</b> \<String\> Either <b>'IPv4'</b> or <b>'IPv6'</b>\n
	<b>mac</b> \<String\> The MAC address of the network interface\n
	<b>status</b> \<String\> Either <b>'up'</b> or <b>'down'</b>\n
	<b>type</b> \<String\> One of <b>'ethernet'</b>, <b>'wireless'</b>, <b>'tunnel'</b>, <b>'loopback'</b>, or <b>'other'</b>\n
	\return <Object>
	*/
	Object networkInterfaces();
};
/*!
\implements EventEmitter
\brief The process object is a global that provides information about, and control over, the current process
*/
class process
{
public:
	/*!
	\brief Property String identifying the operating system platform on which the JavaScript engine is running. (<b>'darwin'</b>, <b>'linux'</b>, or <b>'win32'</b>)
	*/
	String platform;
	/*!
	\brief Event is emitted when the process is about to exit, either as a result of a call to exit(), or the event loop no longer having any work to perform.
	\param code <integer> Intended exit code
	*/
	void exit;
	/*!
	\brief Terminate the process with the specified exit status
	\param code <integer> Optional. Exit Status to use. <b>Default:</b> 0
	*/
	void exit([code]);
	/*!
	\brief Event is emitted when an uncaught JavaScript exception bubbles all the way back to the event loop
	\param err <Error>
	*/
	void uncaughtException;

	/*!
	\brief Property stores a read-only copy of the original value of argv[0]
	*/
	String argv0;
	/*!
	\brief An array containing the command line arguments
	*/
	Array<String> argv;
	/*!
	\brief Property returns a String identifying the processor architecture. (ie: <b>'x86'</b>, <b>'x64'</b>, etc)
	*/
	String arch;
	ILibDuktape_CreateEventWithGetter(ctx, "argv0", ILibDuktape_ScriptContainer_Process_Argv0);
	ILibDuktape_CreateEventWithGetter(ctx, "argv", ILibDuktape_ScriptContainer_Process_Argv);


};
#endif