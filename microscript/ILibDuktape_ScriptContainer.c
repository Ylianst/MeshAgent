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

#ifdef WIN32
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <IPHlpApi.h>
#include <Windows.h>
#include <WinBase.h>
#include <signal.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#ifndef NO_IFADDR
	#include <ifaddrs.h>
#endif
#ifndef __APPLE__
#include <netpacket/packet.h>
#else
#include <mach-o/dyld.h>
#endif
#include <sys/utsname.h>
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
#include "../microstack/ILibRemoteLogging.h"
#include "../microstack/ILibCrypto.h"

#include "ILibDuktape_net.h"
#include "ILibDuktape_WebRTC.h"
#include "ILibDuktape_Dgram.h"
#include "ILibDuktape_GenericMarshal.h"
#include "ILibDuktape_fs.h"
#include "ILibDuktape_Polyfills.h"
#include "ILibDuktape_SimpleDataStore.h"
#include "ILibDuktape_NetworkMonitor.h"
#include "ILibDuktape_ReadableStream.h"
#include "ILibDuktape_WritableStream.h"

#include "ILibDuktape_SHA256.h"
#include "ILibDuktape_EncryptionStream.h"
#include "ILibDuktape_ChildProcess.h"
#include "ILibDuktape_HECI.h"
#include "ILibDuktape_Debugger.h"
#include "ILibDuktape_Commit.h"

#ifdef _POSIX
extern char **environ;
int SignalDescriptors[2] = { 0, 0 };
#endif

#define SCRIPT_ENGINE_PIPE_BUFFER_SIZE 65535

char exeJavaScriptGuid[] = "B996015880544A19B7F7E9BE44914C18";
#define ILibDuktape_ScriptContainer_MasterPtr		"\xFF_ScriptContainer_MasterPtr"
#define ILibDuktape_ScriptContainer_SlavePtr		"\xFF_ScriptContainer_SlavePtr"
#define ILibDuktape_ScriptContainer_ExePath			"\xFF_ScriptContainer_ExePath"
#define ILibDuktape_ScriptContainer_PipeManager		"\xFF_ScriptContainer_PipeManager"
#define ILibDuktape_ScriptContainer_PtrTable		"\xFF_ScriptContainer_PtrTable"
#define ILibDuktape_ScriptContainer_PtrTable_Idx	"\xFF_ScriptContainer_PtrTableIdx"
#define ILibDuktape_ScriptContainer_ProcessIsolated	"\xFF_ScriptContainer_ProcessIsolated"
#define ILibDuktape_ScriptContainer_PeerThread		"\xFF_ScriptContainer_PeerThread"

#define ILibDuktape_ScriptContainer_Command_Execute_Status		"ScriptContainer_Command_Execute_Status"
#define ILibDuktape_ScriptContainer_Command_Log					"ScriptContainer_Command_Log"
#define ILibDuktape_ScriptContainer_Settings_ExecutionTimeout	"\xFF_ScriptContainerSettings_ExecutionTimeout"
#define ILibDuktape_ScriptContainer_Settings_SecurityFlags		"\xFF_ScriptContainerSettings_SecurityFlags"
#define ILibDuktape_ScriptContainer_Settings_DB					"\xFF_ScriptContainerSettings_DB"
#define ILibDuktape_ScriptContainer_Settings_ExitHandler		"\xFF_ScriptContainerSettings_ExitHandler"
#define ILibDuktape_ScriptContainer_Settings_ExitUser			"\xFF_ScriptContainerSettings_ExitUser"
#define ILibDuktape_ScriptContainer_Process_ArgArray			"\xFF_argArray"
#define ILibDuktape_ScriptContainer_Process_Restart				"\xFF_ScriptContainer_Process_Restart"
#define ILibDuktape_ScriptContainer_Process_stdin				"\xFF_stdin"
#define ILibDuktape_ScriptContainer_Process_stdout				"\xFF_stdout"
#define ILibDuktape_ScriptContainer_Process_stderr				"\xFF_stderr"
#define ILibDuktape_ScriptContainer_Signal_ListenerPtr				"\xFF_signalListener"

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
extern int GenerateSHA384FileHash(char *filePath, char *fileHash);
char g_AgentCrashID[280];

typedef enum SCRIPT_ENGINE_COMMAND
{
	SCRIPT_ENGINE_COMMAND_UNKNOWN = 0x00,
	SCRIPT_ENGINE_COMMAND_INIT = 0x01,
	SCRIPT_ENGINE_COMMAND_EXEC = 0x02,
	SCRIPT_ENGINE_COMMAND_ADD_MODULE = 0x04,
	SCRIPT_ENGINE_COMMAND_SEND_JSON = 0x10,
	SCRIPT_ENGINE_COMMAND_QUERY = 0x20,
	SCRIPT_ENGINE_COMMAND_SET = 0x21,
	SCRIPT_ENGINE_COMMAND_ERROR = 0x40,
	SCRIPT_ENGINE_COMMAND_EXIT = 0x80,
	SCRIPT_ENGINE_COMMAND_LOG = 0xFF
}SCRIPT_ENGINE_COMMAND;


typedef struct ILibDuktape_ScriptContainer_Master
{
	duk_context *ctx;
	ILibDuktape_EventEmitter *emitter;

	ILibProcessPipe_Process child;
	void *chain;
	void *PeerThread, *PeerChain;
	unsigned int ChildSecurityFlags;
}ILibDuktape_ScriptContainer_Master;

typedef struct ILibDuktape_ScriptContainer_Slave
{
	duk_context *ctx;
	ILibDuktape_EventEmitter *emitter;

	void *chain;
	int exitCode;
	int noRespond;
}ILibDuktape_ScriptContainer_Slave;


typedef struct ILibDuktape_ScriptContainer_NonIsolated_Command
{
	union { ILibDuktape_ScriptContainer_Master * master; ILibDuktape_ScriptContainer_Slave *slave; }container;
	char json[];
}ILibDuktape_ScriptContainer_NonIsolated_Command;

void ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsSlave(void *chain, void *user);
void ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsMaster(void *chain, void *user);

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
	duk_size_t jsonLen;
	char *json = (char*)duk_json_encode(ctx, -1);
	duk_get_lstring(ctx, -1, &jsonLen);

	duk_push_heap_stash(ctx);
	ILibDuktape_ScriptContainer_Master *master = (ILibDuktape_ScriptContainer_Master*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_ScriptContainer_MasterPtr);
	duk_pop(ctx);

	if (master != NULL)
	{
		ILibDuktape_ScriptContainer_NonIsolated_Command* cmd = (ILibDuktape_ScriptContainer_NonIsolated_Command*)ILibMemory_Allocate(1+(int)jsonLen + sizeof(ILibDuktape_ScriptContainer_NonIsolated_Command), 0, NULL, NULL);
		cmd->container.master = master;
		memcpy_s(cmd->json, jsonLen, json, jsonLen);
		cmd->json[jsonLen] = 0;
		ILibChain_RunOnMicrostackThread2(master->chain, ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsMaster, cmd, 1);
		return;
	}

	char *scratch = ILibMemory_Allocate((int)jsonLen + 4, 0, NULL, NULL);
	((int*)scratch)[0] = (int)jsonLen+4;
	memcpy_s(scratch + 4, jsonLen, json, jsonLen);

#ifdef WIN32
	DWORD tmpLen;
	WriteFile(GetStdHandle(STD_ERROR_HANDLE), scratch, 4+(DWORD)jsonLen, &tmpLen, NULL);
#else
	ignore_result(write(STDERR_FILENO, scratch, 4 + jsonLen));
#endif	
	duk_pop(ctx);
	free(scratch);
}

void ILibDuktape_ScriptContainer_Slave_OnBrokenPipe(ILibProcessPipe_Pipe sender)
{
	if (ILibMemory_CanaryOK(sender))
	{
		ILibStopChain(((ILibDuktape_ScriptContainer_Slave*)((void**)ILibMemory_Extra(sender))[0])->chain);
	}
}


#if defined(WIN32) && defined(MeshLibInterface)
void ILibDuktape_ScriptContainer_GetEmbeddedJS_Raw(char *exePath, char **script, int *scriptLen)
{
	char *integratedJavaScript = NULL;
	int integratedJavaScriptLen = 0;
	FILE* tmpFile = NULL;

	fopen_s(&tmpFile, exePath, "rb");
	if (tmpFile != NULL)
	{
		// Read the PE Headers, to determine where to look for the Embedded JS
		char *optHeader = NULL;
		fseek(tmpFile, 0, SEEK_SET);
		ignore_result(fread(ILibScratchPad, 1, 2, tmpFile));
		if (ntohs(((unsigned int*)ILibScratchPad)[0]) == 19802) // 5A4D
		{
			fseek(tmpFile, 60, SEEK_SET);
			ignore_result(fread(ILibScratchPad, 1, 4, tmpFile));
			fseek(tmpFile, ((unsigned *)ILibScratchPad)[0], SEEK_SET);
			ignore_result(fread(ILibScratchPad, 1, 24, tmpFile));
			if (((unsigned int*)ILibScratchPad)[0] == 17744)
			{
				// PE Image
				optHeader = ILibMemory_AllocateA(((unsigned short*)ILibScratchPad)[10]);
				ignore_result(fread(optHeader, 1, ILibMemory_AllocateA_Size(optHeader), tmpFile));
				switch (((unsigned short*)optHeader)[0])
				{
				case 0x10B:
					if (((unsigned int*)(optHeader + 128))[0] != 0)
					{
						fseek(tmpFile, ((unsigned int*)(optHeader + 128))[0] - 16, SEEK_SET);
					}
					else
					{
						fseek(tmpFile, -16, SEEK_END);
					}
					break;
				case 0x20B:
					if (((unsigned int*)(optHeader + 144))[0] != 0)
					{
						fseek(tmpFile, ((unsigned int*)(optHeader + 144))[0] - 16, SEEK_SET);
					}
					else
					{
						fseek(tmpFile, -16, SEEK_END);
					}
					break;
				default:
					fclose(tmpFile);
					return;
				}
				ignore_result(fread(ILibScratchPad, 1, 16, tmpFile));
				util_hexToBuf(exeJavaScriptGuid, 32, ILibScratchPad2);
				if (memcmp(ILibScratchPad, ILibScratchPad2, 16) == 0)
				{
					// Found an Embedded JS
					fseek(tmpFile, -20, SEEK_CUR);
					ignore_result(fread((void*)&integratedJavaScriptLen, 1, 4, tmpFile));
					integratedJavaScriptLen = (int)ntohl(integratedJavaScriptLen);
					fseek(tmpFile, -4 - integratedJavaScriptLen, SEEK_CUR);
					integratedJavaScript = ILibMemory_Allocate(integratedJavaScriptLen + 1, 0, NULL, NULL);
					ignore_result(fread(integratedJavaScript, 1, integratedJavaScriptLen, tmpFile));
					integratedJavaScript[integratedJavaScriptLen] = 0;
				}
			}
		}
		fclose(tmpFile);
	}
	*script = integratedJavaScript;
	*scriptLen = integratedJavaScriptLen;
}
#endif
void ILibDuktape_ScriptContainer_CheckEmbeddedEx(char *exePath, char **script, int *scriptLen)
{
	int i;
	FILE *tmpFile;
	char *integratedJavaScript = NULL;
	int integratedJavaScriptLen = 0;


#ifdef WIN32
	if (ILibString_EndsWith(exePath, -1, ".exe", 4) == 0)
	{
		i = sprintf_s(g_AgentCrashID, sizeof(g_AgentCrashID), "%s_", exePath);
		sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "%s.exe", exePath);
		fopen_s(&tmpFile, ILibScratchPad, "rb");
	}
	else
	{
		i = ILibString_LastIndexOf(exePath, -1, "\\", 1);
		if (i > 0)
		{
			i = sprintf_s(g_AgentCrashID, sizeof(g_AgentCrashID), "%s", exePath + i + 1);
			g_AgentCrashID[i - 4] = '_';
			i -= 3;
		}
		else
		{
			i = sprintf_s(g_AgentCrashID, sizeof(g_AgentCrashID), "%s", exePath);
			g_AgentCrashID[i - 4] = '_';
			i -= 3;
		}
	}
#else
	i = sprintf_s(g_AgentCrashID, sizeof(g_AgentCrashID), "%s_", exePath);
#endif

	char hashValue[1 + UTIL_SHA384_HASHSIZE];
	if (GenerateSHA384FileHash(exePath, hashValue) == 0)
	{
		util_tohex(hashValue, UTIL_SHA384_HASHSIZE, g_AgentCrashID + i);

#ifdef WIN32
		memcpy_s(g_AgentCrashID + i + 16, 5, ".exe", 5);
#else
		g_AgentCrashID[i + 16] = 0;
#endif
	}

#ifdef WIN32
	fopen_s(&tmpFile, exePath, "rb");
#else
	tmpFile = fopen(exePath, "rb");
#endif

	if (tmpFile != NULL)
	{
		g_ILibCrashID = g_AgentCrashID;

#ifdef WIN32
		// Read the PE Headers, to determine where to look for the Embedded JS
		char *optHeader = NULL;
		fseek(tmpFile, 0, SEEK_SET);
		ignore_result(fread(ILibScratchPad, 1, 2, tmpFile));
		if (ntohs(((unsigned int*)ILibScratchPad)[0]) == 19802) // 5A4D
		{
			fseek(tmpFile, 60, SEEK_SET);
			ignore_result(fread(ILibScratchPad, 1, 4, tmpFile));
			fseek(tmpFile, ((unsigned *)ILibScratchPad)[0], SEEK_SET);
			ignore_result(fread(ILibScratchPad, 1, 24, tmpFile));
			if (((unsigned int*)ILibScratchPad)[0] == 17744)
			{
				// PE Image
				optHeader = ILibMemory_AllocateA(((unsigned short*)ILibScratchPad)[10]);
				ignore_result(fread(optHeader, 1, ILibMemory_AllocateA_Size(optHeader), tmpFile));
				switch (((unsigned short*)optHeader)[0])
				{
				case 0x10B:
					if (((unsigned int*)(optHeader + 128))[0] != 0)
					{
						fseek(tmpFile, ((unsigned int*)(optHeader + 128))[0] - 16, SEEK_SET);
					}
					else
					{
						fseek(tmpFile, -16, SEEK_END);
					}
					break;
				case 0x20B:
					if (((unsigned int*)(optHeader + 144))[0] != 0)
					{
						fseek(tmpFile, ((unsigned int*)(optHeader + 144))[0] - 16, SEEK_SET);
					}
					else
					{
						fseek(tmpFile, -16, SEEK_END);
					}
					break;
				default:
					fclose(tmpFile);
					return;
				}
				ignore_result(fread(ILibScratchPad, 1, 16, tmpFile));
				util_hexToBuf(exeJavaScriptGuid, 32, ILibScratchPad2);
				if (memcmp(ILibScratchPad, ILibScratchPad2, 16) == 0)
				{
					// Found an Embedded JS
					fseek(tmpFile, -20, SEEK_CUR);
					ignore_result(fread((void*)&integratedJavaScriptLen, 1, 4, tmpFile));
					integratedJavaScriptLen = (int)ntohl(integratedJavaScriptLen);
					fseek(tmpFile, -4 - integratedJavaScriptLen, SEEK_CUR);
					integratedJavaScript = ILibMemory_Allocate(integratedJavaScriptLen + 1, 0, NULL, NULL);
					ignore_result(fread(integratedJavaScript, 1, integratedJavaScriptLen, tmpFile));
					integratedJavaScript[integratedJavaScriptLen] = 0;
				}
			}
		}
#else
		fseek(tmpFile, -16, SEEK_END);
		ignore_result(fread(ILibScratchPad, 1, 16, tmpFile));
		util_hexToBuf(exeJavaScriptGuid, 32, ILibScratchPad2);
		if (memcmp(ILibScratchPad, ILibScratchPad2, 16) == 0)
		{
			// Found an Embedded JS
			fseek(tmpFile, -20, SEEK_CUR);
			ignore_result(fread((void*)&integratedJavaScriptLen, 1, 4, tmpFile));
			integratedJavaScriptLen = (int)ntohl(integratedJavaScriptLen);
			fseek(tmpFile, -4 - integratedJavaScriptLen, SEEK_CUR);
			integratedJavaScript = ILibMemory_Allocate(integratedJavaScriptLen + 1, 0, NULL, NULL);
			ignore_result(fread(integratedJavaScript, 1, integratedJavaScriptLen, tmpFile));
			integratedJavaScript[integratedJavaScriptLen] = 0;
		}
#endif
		fclose(tmpFile);
	}
	*script = integratedJavaScript;
	*scriptLen = integratedJavaScriptLen;
}
void ILibDuktape_ScriptContainer_CheckEmbedded(char **script, int *scriptLen)
{
	// Check if .JS file is integrated with executable

#ifndef __APPLE__
	char exePath[_MAX_PATH];
#else
	char exePath[PATH_MAX+1];
#endif

#ifdef WIN32
	GetModuleFileName(NULL, exePath, sizeof(exePath));
#elif defined(__APPLE__)
	uint32_t len = sizeof(exePath);
	if (_NSGetExecutablePath(exePath, &len) != 0) ILIBCRITICALEXIT(247);
	exePath[len] = 0;
#elif defined(NACL)
#else
	int x = readlink("/proc/self/exe", exePath, sizeof(exePath));
	if (x < 0 || x >= sizeof(exePath)) ILIBCRITICALEXIT(246);
	exePath[x] = 0;
#endif

	ILibDuktape_ScriptContainer_CheckEmbeddedEx(exePath, script, scriptLen);
}


// Polyfill process object: 
void ILibDuktape_ScriptContainer_Process_ExitCallback(void *obj)
{
	if (ILibMemory_CanaryOK(obj))
	{
		duk_context *ctx = ((void**)obj)[0];
		duk_destroy_heap(ctx);
	}
}
duk_ret_t ILibDuktape_ScriptContainer_Process_Exit(duk_context *ctx)
{
	void **tmp;
	int nargs = duk_get_top(ctx);

	if (duk_peval_string(ctx, "require('MeshAgent').agentMode") == 0 && duk_get_boolean(ctx, -1))
	{
		// Running in Agent Mode, so exiting process is not allowed
		return(ILibDuktape_Error(ctx, "Process.exit() not allowed when running in Agent Mode"));
	}
	else
	{
		duk_push_this(ctx);															// [process]
		if (nargs == 1)
		{
			duk_push_int(ctx, duk_require_int(ctx, 0));								// [process][code]
			duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_ExitCode);		// [process]
		}
		if (duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Exitting)) { return(ILibDuktape_Error(ctx, "Process.exit() forced script termination")); }
		duk_push_int(ctx, 1);
		duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_Exitting);			// [process]


		// Execute this later, so that this stack can unwind first, before we destroy the heap
		tmp = (void**)Duktape_PushBuffer(ctx, sizeof(void*));						// [process][buffer]
		duk_put_prop_string(ctx, -2, "\xFF_JUNK");									// [process]
		tmp[0] = ctx;
		ILibLifeTime_Add(ILibGetBaseTimer(Duktape_GetChain(ctx)), tmp, 0, ILibDuktape_ScriptContainer_Process_ExitCallback, NULL);
	}
	return(ILibDuktape_Error(ctx, "Process.exit() forced script termination"));
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
	duk_push_current_function(ctx);
	int readOnly = Duktape_GetIntPropertyValue(ctx, -1, "readOnly", 0);

	duk_push_this(ctx);																	// [process]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_ArgArray))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_ArgArray);		// [process][array]
		if (readOnly != 0) { duk_dup(ctx, -1); }										// [process][array][array]
	}
	else
	{
		duk_push_array(ctx);															// [process][array]
		if (readOnly == 0)
		{
			duk_dup(ctx, -1);															// [process][array][array]
			duk_put_prop_string(ctx, -3, ILibDuktape_ScriptContainer_Process_ArgArray);	// [process][array]
		}
	}
	return 1;
}

duk_ret_t ILibDuktape_ScriptContainer_Process_env(duk_context *ctx)
{
	duk_push_object(ctx);																// [env]

#ifdef WIN32
	int i;
	char *envStrings = GetEnvironmentStringsA();
	int envStringsLen = ILibString_IndexOf(envStrings, INT_MAX, "\0\0", 2);
	if (envStringsLen > 0)
	{
		parser_result *r = ILibParseString(envStrings, 0, envStringsLen, "\0", 1);
		parser_result_field *f = r->FirstResult;
		while (f != NULL)
		{
			i = ILibString_IndexOf(f->data, f->datalength, "=", 1);
			if (i > 0)
			{																			// [env]
				duk_push_lstring(ctx, f->data, i);										// [env][key]
				duk_push_string(ctx, f->data + i + 1);									// [env][key][val]
				duk_put_prop(ctx, -3);													// [env]
			}
			f = f->NextResult;
		}
		ILibDestructParserResults(r);
	}
	FreeEnvironmentStringsA(envStrings);
#elif defined(_POSIX)
	for (char **env = environ; *env; ++env)
	{
		int envLen = (int)strnlen_s(*env, INT_MAX);
		int i = ILibString_IndexOf(*env, envLen, "=", 1);
		if (i > 0)
		{
			duk_push_lstring(ctx, *env, i);
			duk_push_string(ctx, *env + i + 1);
			duk_put_prop(ctx, -3);
		}
	}
#endif

	return(1);
}

duk_ret_t ILibDuktape_ScriptContainer_Process_Finalizer(duk_context *ctx)
{
	// We need to dispatch the 'exit' event
	int exitCode = 0;
	duk_push_this(ctx);											// [process]
	ILibChain_Link *link = (ILibChain_Link*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_ScriptContainer_Signal_ListenerPtr);

	if (duk_has_prop_string(ctx, -1, "\xFF_ExitCode"))
	{
		duk_get_prop_string(ctx, -1, "\xFF_ExitCode");			// [process][exitCode]
		exitCode = duk_get_int(ctx, -1);
		duk_pop(ctx);											// [process]
	}
	ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, -1), "exit");	// [emit][this]['exit']
	duk_push_int(ctx, exitCode);												// [emit][this]['exit'][exitCode]
	duk_call_method(ctx, 2);

	if (link != NULL)
	{
		((void**)link->ExtraMemoryPtr)[0] = NULL;
		((void**)link->ExtraMemoryPtr)[1] = NULL;
		ILibChain_SafeRemove(Duktape_GetChain(ctx), link);
	}

	return(0);
}


typedef struct ILibDuktape_Process_StdIn_Data
{
	ILibDuktape_readableStream *rs;
#ifdef WIN32
	HANDLE workerThread;
	HANDLE resumeEvent;
	int exit;
#endif
	int wasUnshifted;
	int endPointer;
	int bufferSize;
	char buffer[];
}ILibDuktape_Process_StdIn_Data;

#ifdef WIN32
void __stdcall ILibDuktape_Process_stdin_readSink(ULONG_PTR obj)
{
	ILibDuktape_Process_StdIn_Data *data = (ILibDuktape_Process_StdIn_Data*)obj;
	int endPointer;
	do
	{
		endPointer = data->endPointer;
		data->wasUnshifted = 0;
		ILibDuktape_readableStream_WriteData(data->rs, data->buffer, data->endPointer);
	} while (!data->rs->paused && data->wasUnshifted > 0 && data->wasUnshifted != endPointer);

	data->endPointer = data->wasUnshifted;
	if (!data->rs->paused) { SetEvent(data->resumeEvent); }
}
#endif
void ILibDuktape_Process_stdin_pauseSink(struct ILibDuktape_readableStream *sender, void *user)
{
	UNREFERENCED_PARAMETER(sender);
	UNREFERENCED_PARAMETER(user);

	// NO-OP, because stream state flag will be paused, which will cause the processing loop to exit
}
void ILibDuktape_Process_stdin_resumeSink(struct ILibDuktape_readableStream *sender, void *user)
{
#ifdef WIN32
	ILibDuktape_Process_StdIn_Data *data = (ILibDuktape_Process_StdIn_Data*)user;
	SetEvent(data->resumeEvent);
#endif
}
int ILibDuktape_Process_stdin_unshiftSink(struct ILibDuktape_readableStream *sender, int unshiftBytes, void *user)
{
	ILibDuktape_Process_StdIn_Data *data = (ILibDuktape_Process_StdIn_Data*)user;
	data->wasUnshifted = unshiftBytes <= data->endPointer ? unshiftBytes : data->endPointer;

	if (unshiftBytes > 0 && unshiftBytes < data->endPointer)
	{
		memmove_s(data->buffer, data->bufferSize, data->buffer + (data->endPointer - unshiftBytes), unshiftBytes);
		data->endPointer = unshiftBytes;
	}
	return(data->wasUnshifted);
}
#ifdef WIN32
void ILibDuktape_Process_stdin_WindowsRunLoop(void *arg)
{
	ILibDuktape_Process_StdIn_Data *data = (ILibDuktape_Process_StdIn_Data*)arg;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	DWORD bytesRead, waitResult;

	while (((waitResult = WaitForSingleObjectEx(data->resumeEvent, INFINITE, TRUE)) == WAIT_OBJECT_0 || waitResult == WAIT_IO_COMPLETION) && !data->exit)
	{
		if (!ReadFile(h, data->buffer + data->endPointer, data->bufferSize - data->endPointer, &bytesRead, NULL))
		{
			break;
		}
		else
		{
			ResetEvent(data->resumeEvent);		// Reset, becuase we'll need to pause and context switch to Duktape thread
			data->endPointer += (int)bytesRead;
			QueueUserAPC((PAPCFUNC)ILibDuktape_Process_stdin_readSink, ILibChain_GetMicrostackThreadHandle(data->rs->chain), (ULONG_PTR)data);
		}
	}
}
#endif
duk_ret_t ILibDuktape_Process_stdin_finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, ILibDuktape_readableStream_RSPTRS);
	ILibDuktape_readableStream *rs = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);
	ILibDuktape_Process_StdIn_Data *data = (ILibDuktape_Process_StdIn_Data*)rs->user;

#ifdef WIN32
	data->exit = 1;
	SetEvent(data->resumeEvent);
	CancelSynchronousIo(data->workerThread);
	WaitForSingleObject(data->workerThread, 10000);

	CloseHandle(data->resumeEvent);
#endif

	free(data);
	return(0);
}
duk_ret_t ILibDuktape_Process_stdin_get(duk_context *ctx)
{
	duk_push_this(ctx);																// [process]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_stdin))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_stdin);
		return(1);
	}

	duk_push_object(ctx);															// [process][stdin]
	duk_dup(ctx, -1);																// [process][stdin][dup]
	duk_put_prop_string(ctx, -3, ILibDuktape_ScriptContainer_Process_stdin);		// [process][stdin]
	ILibDuktape_WriteID(ctx, "process.stdin");
	ILibDuktape_readableStream *rs = ILibDuktape_ReadableStream_InitEx(ctx, ILibDuktape_Process_stdin_pauseSink, ILibDuktape_Process_stdin_resumeSink, ILibDuktape_Process_stdin_unshiftSink, NULL);
	rs->user = ILibMemory_Allocate(sizeof(ILibDuktape_Process_StdIn_Data) + 4096, 0, NULL, NULL);
	((ILibDuktape_Process_StdIn_Data*)rs->user)->rs = rs;
	((ILibDuktape_Process_StdIn_Data*)rs->user)->bufferSize = 4096;

#ifdef WIN32
	((ILibDuktape_Process_StdIn_Data*)rs->user)->resumeEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
	((ILibDuktape_Process_StdIn_Data*)rs->user)->workerThread = ILibSpawnNormalThread(ILibDuktape_Process_stdin_WindowsRunLoop, rs->user);
#endif
	
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "~", ILibDuktape_Process_stdin_finalizer);
	return(1);
}
ILibTransport_DoneState ILibDuktape_Process_stdout_WriteSink(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
#ifdef WIN32
	DWORD writeLen;
	WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), (void*)buffer, bufferLen, &writeLen, NULL);
#else
	ignore_result(write(STDOUT_FILENO, buffer, bufferLen));
#endif
	return(ILibTransport_DoneState_COMPLETE);
}
void ILibDuktape_Process_stdout_EndSink(struct ILibDuktape_WritableStream *stream, void *user)
{
	UNREFERENCED_PARAMETER(stream);
	UNREFERENCED_PARAMETER(user);
}

duk_ret_t ILibDuktape_Process_stdout_get(duk_context *ctx)
{
	duk_push_this(ctx);																// [process]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_stdout))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_stdout);
		return(1);
	}

	duk_push_object(ctx);															// [process][stdout]
	duk_dup(ctx, -1);																// [process][stdout][dup]
	duk_put_prop_string(ctx, -3, ILibDuktape_ScriptContainer_Process_stdout);		// [process][stdout]
	ILibDuktape_WriteID(ctx, "process.stdout");
	ILibDuktape_WritableStream_Init(ctx, ILibDuktape_Process_stdout_WriteSink, ILibDuktape_Process_stdout_EndSink, NULL);
	return(1);
}
ILibTransport_DoneState ILibDuktape_Process_stderr_WriteSink(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
#ifdef WIN32
	DWORD writeLen;
	WriteFile(GetStdHandle(STD_ERROR_HANDLE), (void*)buffer, bufferLen, &writeLen, NULL);
#else
	ignore_result(write(STDERR_FILENO, buffer, bufferLen));
#endif
	return(ILibTransport_DoneState_COMPLETE);
}
duk_ret_t ILibDuktape_Process_stderr_get(duk_context *ctx)
{
	duk_push_this(ctx);																// [process]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_stderr))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_Process_stderr);
		return(1);
	}

	duk_push_object(ctx);															// [process][stderr]
	duk_dup(ctx, -1);																// [process][stderr][dup]
	duk_put_prop_string(ctx, -3, ILibDuktape_ScriptContainer_Process_stderr);		// [process][stderr]
	ILibDuktape_WriteID(ctx, "process.stderr");
	ILibDuktape_WritableStream_Init(ctx, ILibDuktape_Process_stderr_WriteSink, ILibDuktape_Process_stdout_EndSink, NULL);
	return(1);
}
duk_ret_t ILibDuktape_ScriptContainer_Process_Kill(duk_context *ctx)
{
	int pid = duk_require_int(ctx, 0);

#ifdef WIN32
	int len = sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "require('child_process').execFile(process.env['windir'] + '\\x5Csystem32\\x5Ccmd.exe', ['/C', 'taskkill /F /PID %d']);", pid);
	if (len > 0)
	{
		duk_eval_string(ctx, ILibScratchPad);	// [child_process]
	}
#else
	kill((pid_t)pid, SIGKILL);
#endif
	return(0);
}
duk_ret_t ILibDuktape_Process_cwd(duk_context *ctx)
{
#ifdef WIN32
	GetCurrentDirectoryA((DWORD)sizeof(ILibScratchPad), ILibScratchPad);
	duk_push_string(ctx, ILibScratchPad);
	return(1);
#elif defined(_POSIX)
	getcwd(ILibScratchPad, sizeof(ILibScratchPad));
	duk_push_string(ctx, ILibScratchPad);				
	return(1);
#else
	return(ILibDuktape_Error(ctx, "Error"));
#endif
}

#ifdef _POSIX
void ILibDuktape_ScriptContainer_Process_SignalListener_PreSelect(void* object, fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime)
{
	if (SignalDescriptors[0] != 0)
	{
		FD_SET(SignalDescriptors[0], readset);
	}
}
void ILibDuktape_ScriptContainer_Process_SignalListener_PostSelect(void* object, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	int stype = 0, bytesRead = 0;
	ILibChain_Link *link = (ILibChain_Link*)object;
	duk_context *ctx = (duk_context*)((void**)link->ExtraMemoryPtr)[0];
	void *h = ((void**)link->ExtraMemoryPtr)[1];

	if (FD_ISSET(SignalDescriptors[0], readset))
	{
		bytesRead = read(SignalDescriptors[0], (char*)&stype, sizeof(stype));
		if (bytesRead == 4)
		{
			switch (stype)
			{
				case SIGTERM:
					ILibDuktape_EventEmitter_SetupEmit(ctx, h, "SIGTERM");
					if (duk_pcall_method(ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "Error Emitting SIGTERM: "); }
					duk_pop(ctx);
					break;
				default:
					break;
			}
		}
		else if(bytesRead == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
		{
			close(SignalDescriptors[0]);
			close(SignalDescriptors[1]);
			if (pipe(SignalDescriptors) == 0)
			{
				fcntl(SignalDescriptors[0], F_SETFL, O_NONBLOCK);
				fcntl(SignalDescriptors[1], F_SETFL, O_NONBLOCK);
			}
		}
	}
}
void ILibDuktape_ScriptContainer_Process_SignalListener(int signum)
{
	if (SignalDescriptors[1] != 0)
	{
		ignore_result(write(SignalDescriptors[1], &signum, sizeof(signum)));
	}
}
void ILibDuktape_ScriptContainer_Process_SignalListener_Destroy(void *object)
{
	if (SignalDescriptors[0] != 0)
	{
		close(SignalDescriptors[0]);
	}
	if (SignalDescriptors[1] != 0)
	{
		close(SignalDescriptors[1]);
	}
	SignalDescriptors[0] = SignalDescriptors[1] = 0;
}
#endif

void ILibDuktape_ScriptContainer_Process_SIGTERM_Hook(ILibDuktape_EventEmitter *sender, char *eventName, void *hookedCallback)
{
	int listenerCount = ILibDuktape_EventEmitter_HasListeners2(sender, "SIGTERM", 0);
	if (listenerCount == 0)
	{
		// We are the first
#ifdef _POSIX
		signal(SIGTERM, ILibDuktape_ScriptContainer_Process_SignalListener);
#else
		UNREFERENCED_PARAMETER(eventName);
		UNREFERENCED_PARAMETER(hookedCallback);
#endif
	}

}
duk_ret_t ILibDuktape_Process_setenv(duk_context *ctx)
{
	char *name = (char*)duk_require_string(ctx, 0);
	char *value = Duktape_GetBuffer(ctx, 1, NULL);

#ifdef WIN32
	SetEnvironmentVariableA((LPCSTR)name, (LPCTSTR)value);
#else
	if (value != NULL)
	{
		setenv(name, value, 1);
	}
	else
	{
		unsetenv(name);
	}
#endif

	return(0);
}
void ILibDuktape_ScriptContainer_Process_Init(duk_context *ctx, char **argList)
{
	int i = 0;
	ILibDuktape_EventEmitter *emitter;
	char *sslv = (char*)SSLeay_version(SSLEAY_VERSION);
	char *sslvS = strstr(sslv, " ") + 1;


	duk_push_global_object(ctx);														// [g]
	duk_push_object(ctx);																// [g][process]
	ILibDuktape_WriteID(ctx, "process");
	ILibDuktape_CreateEventWithGetter(ctx, "env", ILibDuktape_ScriptContainer_Process_env);
	ILibDuktape_CreateInstanceMethod(ctx, "cwd", ILibDuktape_Process_cwd, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "setenv", ILibDuktape_Process_setenv, 2);
	
	duk_push_object(ctx);
	if (sslvS != ((char*)NULL + 1))
	{
		char *tmp = strstr(sslvS, " ");
		if (tmp != NULL)
		{
			duk_push_lstring(ctx, sslvS, (duk_size_t)(tmp - sslvS));
			duk_put_prop_string(ctx, -2, "openssl");
		}
	}
	duk_push_string(ctx, DUK_GIT_DESCRIBE); duk_put_prop_string(ctx, -2, "duktape");
	if (SOURCE_COMMIT_DATE != NULL)
	{
		duk_eval_string(ctx,
			"(function translateDate(COMMIT_DATE)\
		{\
			var MONTH_TRANSLATE =\
			{\
				'Jan' : '01',\
				'Feb' : '02',\
				'Mar' : '03',\
				'Apr' : '04',\
				'May' : '05',\
				'Jun' : '06',\
				'Jul' : '07',\
				'Aug' : '08',\
				'Sep' : '09',\
				'Oct' : '10',\
				'Nov' : '11',\
				'Dec' : '12'\
			};\
			var tz = COMMIT_DATE.substring(COMMIT_DATE.length-2);\
			COMMIT_DATE = COMMIT_DATE.substring(0, COMMIT_DATE.length-2) + ':' + tz;\
			var tmp = COMMIT_DATE.split('-');\
			tmp[1] = MONTH_TRANSLATE[tmp[1]];\
			var day = tmp[2];\
			var day2 = day.split(' ');\
			day2[0] = day2[0].padStart(2, '0');\
			tmp[2] = day2.join(' ');\
			return (new Date(tmp.join('-')));\
		})");										// [func]
		duk_push_string(ctx, SOURCE_COMMIT_DATE);	// [func][date]
		if (duk_pcall(ctx, 1) == 0)
		{
			if (SOURCE_COMMIT_HASH != NULL)
			{
				duk_push_string(ctx, SOURCE_COMMIT_HASH); duk_put_prop_string(ctx, -2, "commitHash");
			}
			duk_put_prop_string(ctx, -2, "meshAgent");
		}
		else
		{
			duk_pop(ctx);
		}
	}
	ILibDuktape_CreateReadonlyProperty(ctx, "versions");

#if defined(WIN32)																		// [g][process][platform]
	duk_push_string(ctx, "win32");
#elif defined(__APPLE__)
	duk_push_string(ctx, "darwin");
#else
	duk_push_string(ctx, "linux");
#endif
	duk_put_prop_string(ctx, -2, "platform");											// [g][process]

	duk_push_heap_stash(ctx);															// [g][process][stash]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_ExePath))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_ExePath);				// [g][process][stash][path]
		duk_swap_top(ctx, -2);															// [g][process][path][stash]
		duk_pop(ctx);																	// [g][process][path]
		ILibDuktape_CreateReadonlyProperty(ctx, "execPath");							// [g][process]
	}
	else
	{
		duk_pop(ctx);																	// [g][process]
	}

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
	
#ifdef _POSIX
	duk_push_int(ctx, (duk_int_t)getpid());
	ILibDuktape_CreateReadonlyProperty(ctx, "pid");								
#endif

	emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "exit");
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "exit", ILibDuktape_ScriptContainer_Process_Exit, DUK_VARARGS);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "uncaughtException");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "SIGTERM");
	ILibDuktape_EventEmitter_AddHook(emitter, "SIGTERM", ILibDuktape_ScriptContainer_Process_SIGTERM_Hook);

	ILibDuktape_CreateEventWithGetter(ctx, "argv0", ILibDuktape_ScriptContainer_Process_Argv0);
	duk_push_int(ctx, 1);
	ILibDuktape_CreateEventWithGetterAndCustomProperty(ctx, "readOnly", "argv", ILibDuktape_ScriptContainer_Process_Argv);
	duk_push_int(ctx, 0);
	ILibDuktape_CreateEventWithGetterAndCustomProperty(ctx, "readOnly", "_argv", ILibDuktape_ScriptContainer_Process_Argv);

	duk_push_heap_stash(ctx);															// [g][process][stash]
	if (!duk_has_prop_string(ctx, -1, ILibDuktape_ScriptContainer_SlavePtr))
	{
		duk_pop(ctx);																	// [g][process]
		ILibDuktape_CreateEventWithGetter(ctx, "stdin", ILibDuktape_Process_stdin_get);
		ILibDuktape_CreateEventWithGetter(ctx, "stdout", ILibDuktape_Process_stdout_get);
		ILibDuktape_CreateEventWithGetter(ctx, "stderr", ILibDuktape_Process_stderr_get);
	}
	else
	{
		duk_pop(ctx);																	// [g][process]
	}
	ILibDuktape_CreateInstanceMethod(ctx, "kill", ILibDuktape_ScriptContainer_Process_Kill, DUK_VARARGS);
	duk_put_prop_string(ctx, -2, "process");											// [g]
	duk_pop(ctx);																		// ...

	ILibDuktape_EventEmitter_AddOnceEx(emitter, "~", ILibDuktape_ScriptContainer_Process_Finalizer, 1);

#ifdef _POSIX
	if (SignalDescriptors[0] == 0 && SignalDescriptors[1] == 0)
	{
		if (pipe(SignalDescriptors) == 0)
		{
			fcntl(SignalDescriptors[0], F_SETFL, O_NONBLOCK);
			fcntl(SignalDescriptors[1], F_SETFL, O_NONBLOCK);

			void *chain = Duktape_GetChain(ctx);
			ILibChain_Link *k = ILibChain_Link_Allocate(sizeof(ILibChain_Link), 2 * sizeof(void*));
			((void**)k->ExtraMemoryPtr)[0] = ctx;
			((void**)k->ExtraMemoryPtr)[1] = emitter->object;
			k->MetaData = "Signal_Listener";
			k->PreSelectHandler = ILibDuktape_ScriptContainer_Process_SignalListener_PreSelect;
			k->PostSelectHandler = ILibDuktape_ScriptContainer_Process_SignalListener_PostSelect;
			k->DestroyHandler = ILibDuktape_ScriptContainer_Process_SignalListener_Destroy;
			ILibAddToChain(chain, k);

			duk_push_heapptr(ctx, emitter->object);											// [process]
			duk_push_pointer(ctx, k);														// [process][ptr]
			duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_Signal_ListenerPtr);	// [process]
			duk_pop(ctx);																	// ...
		}
	}
#endif

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
	ILibRemoteLogging_printf(ILibChainGetLogger(Duktape_GetChain(ctx)), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "Script Container Execution Timeout Elapsed");

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

	int i, count = (int)duk_get_length(ctx, -1);
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

size_t ILibDuktape_ScriptContainer_TotalAllocations = 0;
void *ILibDuktape_ScriptContainer_Engine_malloc(void *udata, duk_size_t size)
{
	ILibDuktape_ScriptContainer_TotalAllocations += size;
	return(ILibMemory_SmartAllocate(size));
}
void *ILibDuktape_ScriptContainer_Engine_realloc(void *udata, void *ptr, duk_size_t size)
{
	size_t difference = 0;

	if (ptr != NULL) 
	{ 
		ptr = ILibMemory_RawPtr(ptr);
		if ((ptr = realloc(ptr, size + sizeof(ILibMemory_Header))) == NULL)
		{
			ILIBCRITICALEXITMSG(255, "REALLOC FAILURE");
		}
		ptr = ILibMemory_FromRaw(ptr);
		if (ILibMemory_Size(ptr) > size)
		{
			// Memory Shrink
			difference = ILibMemory_Size(ptr) - size;
			ILibDuktape_ScriptContainer_TotalAllocations -= difference;
		}
		else
		{
			difference = size - ILibMemory_Size(ptr);
			ILibDuktape_ScriptContainer_TotalAllocations += difference;
		}
		ILibMemory_Size(ptr) = size;
	}
	else
	{
		if (size > 0)
		{
			ptr = ILibMemory_SmartAllocate(size);
			ILibDuktape_ScriptContainer_TotalAllocations += size;
		}
	}

	return(ptr);
}
void ILibDuktape_ScriptContainer_Engine_free(void *udata, void *ptr)
{
	if (ptr != NULL) 
	{
		size_t sz = ILibMemory_Size(ptr);
		ILibDuktape_ScriptContainer_TotalAllocations -= ILibMemory_Size(ptr);
		memset(ptr, 0xDEADBEEF, sz);
		ILibMemory_Free(ptr); 
	}
}
void ILibDuktape_ScriptContainer_Engine_fatal(void *udata, const char *msg)
{
	ILIBCRITICALEXITMSG(254, msg);
}
duk_ret_t ILibDuktape_ScriptContainer_OS_arch(duk_context *ctx)
{
#ifdef WIN32
	if (sizeof(void*) == 8)
	{
		// We are 64 bit App, so we must be on 64 bit Windows
		duk_push_string(ctx, "x64");
	}
	else
	{
		HMODULE hm = LoadLibraryA("Kernel32.dll");
		void *func = (void*)GetProcAddress(hm, "IsWow64Process");
		BOOL isWow = FALSE;

		if (func != NULL)
		{
			BOOL isWow = FALSE;
			BOOL result = ((BOOL(__stdcall *)(HANDLE, BOOL*))func)(GetCurrentProcess(), &isWow);
			if (result)
			{
				// We are 32 bit App running on 64 bit Windows
				duk_push_string(ctx, "x64");
			}
			else
			{
				// We are 32 bit App running on 32 bit Windows
				duk_push_string(ctx, "ia32");
			}
		}
		else
		{
			// We are 32 bit App running on 32 bit Windows
			duk_push_string(ctx, "ia32");
		}
		FreeLibrary(hm);
	}
	return(1);
#else
	struct utsname u;
	if (uname(&u) != 0) { return(ILibDuktape_Error(ctx, "Could not determine architecture")); }
	if (u.machine[0] == 'i')
	{
		duk_push_string(ctx, "ia32");
	}
	else
	{
		if (strcmp(u.machine, "x86_64") == 0)
		{
			duk_push_string(ctx, "x64");
		}
		else
		{
			int mlen = strlen(u.machine);
			if (mlen > 4 && strncmp(u.machine, "armv", 4) == 0)
			{
				if (atoi(u.machine + 4) > 7)
				{
					duk_push_string(ctx, "arm64");
				}
				else
				{
					duk_push_string(ctx, "arm");
				}				
			}
			else
			{
				return(ILibDuktape_Error(ctx, "Could not determine architecture"));
			}
		}
	}

	return(1);
#endif
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
#ifndef __APPLE__
duk_ret_t ILibDuktape_ScriptContainer_OS_networkInterfaces(duk_context *ctx)
{
#if !defined(WIN32)
	duk_eval_string(ctx, "require('os').getDefaultGateways();");
	void *gwTable = duk_get_heapptr(ctx, -1);
#endif

	duk_push_object(ctx);			// [retVal]

#ifdef WIN32
	duk_push_object(ctx);			// [retVal][indexTable]
	void *indexTable = duk_get_heapptr(ctx, -1);
	ILibDuktape_CreateReadonlyProperty(ctx, "interfaceIndexes");

	char fqdn[4096];
	size_t fqdnLen;
	int i = 0;
	size_t converted;
	char tmpBuffer[32768];
	DWORD tmpBufferSize = sizeof(tmpBuffer);
	IP_ADAPTER_ADDRESSES *padapters = (IP_ADAPTER_ADDRESSES*)tmpBuffer;
	unsigned long mask;
	if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_ANYCAST, NULL, (PIP_ADAPTER_ADDRESSES)tmpBuffer, &tmpBufferSize) != NO_ERROR) { return(ILibDuktape_Error(ctx, "os.networkInterfaces(): Internal Error")); }
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

			if (padapters->FirstGatewayAddress != NULL && ((struct sockaddr*)padapters->FirstGatewayAddress->Address.lpSockaddr)->sa_family == ((struct sockaddr*)addr->Address.lpSockaddr)->sa_family)
			{
				duk_push_string(ctx, ILibRemoteLogging_ConvertAddress((struct sockaddr*)padapters->FirstGatewayAddress->Address.lpSockaddr));
				duk_put_prop_string(ctx, -2, "gateway");
			}

			wcstombs_s(&fqdnLen, fqdn, sizeof(fqdn), (const wchar_t*)padapters->DnsSuffix, wcsnlen_s(padapters->DnsSuffix, sizeof(fqdn)));
			duk_push_string(ctx, fqdn);
			duk_put_prop_string(ctx, -2, "fqdn");

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

		duk_push_heapptr(ctx, indexTable);				// [table]
		duk_push_int(ctx, (int)padapters->IfIndex);		// [table][index]
		duk_push_string(ctx, ILibScratchPad);			// [table][index][name]
		duk_put_prop(ctx, -3);							// [table]
		duk_pop(ctx);									// ...

		padapters = padapters->Next;
	}
#else
#ifndef NO_IFADDR
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

					if (((struct sockaddr_in*)current->ifa_addr)->sin_family == AF_INET)
					{
						duk_push_heapptr(ctx, gwTable);							// [table]
						if (duk_has_prop_string(ctx, -1, current->ifa_name))
						{
							duk_get_prop_string(ctx, -1, current->ifa_name);	// [table][gwAddress]
							duk_remove(ctx, -2);								// [gwAddress]
							duk_put_prop_string(ctx, -2, "gateway");			// ...
						}
						else
						{
							duk_pop(ctx);
						}
					}

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
#endif
	return(1);
}
#endif
duk_ret_t ILibDuktape_ScriptContainer_OS_hostname(duk_context *ctx)
{
	char name[1024];
	int len = gethostname(name, (int)sizeof(name));
	duk_push_lstring(ctx, name, len);
	return(1);
}
void ILibDuktape_ScriptContainer_OS_Push(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);							// [os]
	ILibDuktape_WriteID(ctx, "os");

#ifdef WIN32
	duk_push_string(ctx, "\r\n");
#else
	duk_push_string(ctx, "\n");
#endif
	ILibDuktape_CreateReadonlyProperty(ctx, "EOL");


	ILibDuktape_CreateInstanceMethod(ctx, "arch", ILibDuktape_ScriptContainer_OS_arch, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "platform", ILibDuktape_ScriptContainer_OS_platform, 0);
#ifndef __APPLE__
	ILibDuktape_CreateInstanceMethod(ctx, "networkInterfaces", ILibDuktape_ScriptContainer_OS_networkInterfaces, 0);
#endif
	ILibDuktape_CreateInstanceMethod(ctx, "hostname", ILibDuktape_ScriptContainer_OS_hostname, 0);

	char jsExtras[] = "exports.getPrimaryDnsSuffix = function getPrimaryDnsSuffix()\
	{\
		if (process.platform == 'win32')\
		{\
			var DsRolePrimaryDomainInfoBasic = 1;\
			var marshal = require('_GenericMarshal');\
			var netapi32 = marshal.CreateNativeProxy('netapi32.dll');\
			netapi32.CreateMethod('DsRoleGetPrimaryDomainInformation');\
			netapi32.CreateMethod('DsRoleFreeMemory');\
			var kernel32 = marshal.CreateNativeProxy('kernel32.dll');\
			kernel32.CreateMethod('GetLastError');\
			var info = marshal.CreatePointer();\
			if (netapi32.DsRoleGetPrimaryDomainInformation(0, DsRolePrimaryDomainInfoBasic, info).Val != 0) \
			{\
				throw ('Error[' = kernel32.GetLastError().Val + '] when trying to call DsRoleGetPrimaryDomainInformation');\
			}\
			var suffix = info.Deref().Deref(marshal.PointerSize == 4 ? 12 : 16, marshal.PointerSize).Deref().AnsiString;\
			var flat = info.Deref().Deref(8, marshal.PointerSize).Deref().AnsiString;\
			netapi32.DsRoleFreeMemory(info.Deref());\
			return (suffix.length > 0 ? suffix : flat);\
		}\
		else\
		{\
			var resolv = require('fs').readFileSync('/etc/resolv.conf');\
			var lines = resolv.toString().split('\\n');\
			for (var i in lines)\
			{\
				var tokens = lines[i].split(' ');\
				if (tokens[0] == 'domain')\
				{\
					return (tokens[1]);\
				}\
			}\
			return ('');\
		}\
	};\
	exports.getArpCache = function getArpCache()\
	{\
		if(process.platform == 'darwin')\
		{\
			var promise = require('promise');\
			var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });\
			var child_process = require('child_process');\
			ret._child = child_process.execFile('/bin/sh', ['sh']);\
			ret._child.promise = ret;\
			ret._child.stdout._lines = '';\
			ret._child.stdout.on('data', function (chunk) { this._lines += chunk.toString(); });\
			ret._child.stdin.write('arp -a\\nexit\\n');\
			ret._child.on('exit', function (code)\
			{\
				var lines = this.stdout._lines.split('\\n');\
				var tokens, hw;\
				var cache = {};\
				for (var i in lines)\
				{\
					if (lines[i].length > 0)\
					{\
						tokens = lines[i].split(' ');\
						if (tokens[3] != '(incomplete)')\
						{\
							if (!cache[tokens[5]]) { cache[tokens[5]] = {}; }\
							var hwtokens = tokens[3].split(':');\
							for (var hwi in hwtokens)\
							{\
								if (hwtokens[hwi].length == 1) { hwtokens[hwi] = '0' + hwtokens[hwi]; }\
								hwtokens[hwi] = hwtokens[hwi].toUpperCase();\
							}\
							cache[tokens[5]][tokens[1].slice(1, tokens[1].length - 1)] = hwtokens.join(':');\
						}\
					}\
				}\
				Object.defineProperty(cache, 'flat',\
				{\
					value: function flat() {\
						var r = {};\
						for (var adapter in this) {\
							for (var addr in this[adapter]) {\
								r[addr] = this[adapter][addr];\
							}\
						}\
						return (r);\
					}\
				});\
				this.promise._res(cache);\
			});\
			return (ret);\
		}\
		var retVal = {};\
		Object.defineProperty(retVal, 'flat',\
		{\
			value: function flat() {\
				var r = {};\
				for (var adapter in this) {\
					for (var addr in this[adapter]) {\
						r[addr] = this[adapter][addr];\
					}\
				}\
				return (r);\
			}\
		});\
		if (process.platform == 'win32')\
		{\
			var marshal = require('_GenericMarshal');\
			var IpHlpApi = marshal.CreateNativeProxy('Iphlpapi.dll');\
			var RESULTS = { ERROR_INSUFFICIENT_BUFFER: 122, ERROR_NO_DATA : 232, NO_ERROR : 0 };\
			IpHlpApi.CreateMethod('GetIpNetTable');\
			var sz = marshal.CreateVariable(4);\
			sz.toBuffer().writeUInt32LE(0);\
			switch (IpHlpApi.GetIpNetTable(0, sz, 0).Val) {\
			case RESULTS.ERROR_NO_DATA:\
				/*No OP, will return empty set*/ \
				break;\
			case RESULTS.ERROR_INSUFFICIENT_BUFFER:\
				var arpTable = marshal.CreateVariable(sz.toBuffer().readUInt32LE());\
				if (IpHlpApi.GetIpNetTable(arpTable, sz, 0).Val == RESULTS.NO_ERROR) {\
					var adapters = require('os').networkInterfaces();\
					var numEntries = arpTable.toBuffer().readUInt32LE(0);\
					var buffer = arpTable.toBuffer().slice(4);\
					for (var i = 0; i < numEntries; ++i) {\
						var row = buffer.slice(i * 24, (i * 24) + 24);\
						var addr = row.readUInt32BE(16);\
						var address = ((addr >> 24) & 255) + '.' + ((addr >> 16) & 255) + '.' + ((addr >> 8) & 255) + '.' + (addr & 255);\
						var index = row.readUInt32LE(0);\
						var mac = row.slice(8, 14).toString('hex:');\
						if (!retVal[adapters.interfaceIndexes[index]]) { retVal[adapters.interfaceIndexes[index]] = {}; }\
						retVal[adapters.interfaceIndexes[index]][address] = mac;\
					}\
				}\
				break;\
			default:\
				throw ('Error accessing ARP/CACHE');\
				break;\
			}\
		}\
		else\
		{\
			var arpCache = require('fs').readFileSync('/proc/net/arp');\
			var dataLines = arpCache.toString().split('\\x0A');\
			var headers = {};\
			var tokens = dataLines[0].split('  ');\
			var key = 0;\
			for (var i in tokens)\
			{\
				if (tokens[i].length > 0) { headers[key++] = tokens[i].trim(); }\
			}\
			for (var i = 1; i < dataLines.length; ++i)\
			{\
				var val = {};\
				var k = 0;\
				tokens = dataLines[i].split(' ');\
				for (var x in tokens)\
				{\
					if (tokens[x].length > 0)\
					{\
						val[headers[k++]] = tokens[x].trim();\
					}\
				}\
				if (tokens.length > 1)\
				{\
					if (!retVal[val['Device']]) { retVal[val['Device']] = {}; }\
					retVal[val['Device']][val['IP address']] = val['HW address'].toUpperCase();\
				}\
			}\
		}\
		return (retVal);\
	};\
	if(process.platform == 'linux')\
	{\
		exports.getDefaultGateways = function getDefaultGateways()\
		{\
			var defaultGateways = {};\
			var routingtable = require('fs').readFileSync('/proc/net/route');\
			var lines = routingtable.toString().split('\\n');\
			var headers = {};\
			var tokens = lines[0].split('\\t');\
			for (var i in tokens)\
			{\
				if (tokens[i].length > 0) { headers[tokens[i].trim()] = i; }\
			}\
			for (var i = 1; i < lines.length; ++i)\
			{\
				tokens = lines[i].split('\\t');\
				if (tokens[headers['Mask']] == '00000000')\
				{\
					var gw = Buffer.from(tokens[headers['Gateway']], 'hex').readUInt32LE();\
					var gwAddr = ((gw >> 24) & 255) + '.' + ((gw >> 16) & 255) + '.' + ((gw >> 8) & 255) + '.' + (gw & 255);\
					defaultGateways[tokens[headers['Iface']]] = gwAddr;\
				}\
			}\
			return(defaultGateways);\
		}\
	}\
	if(process.platform == 'darwin')\
	{\
		exports.networkInterfaces = function()\
		{\
		var child_process = require('child_process');\
		var child = child_process.execFile('/bin/sh', ['sh']);\
		child.stdout._lines = '';\
		child.stdout.on('data', function (chunk) { this._lines += chunk.toString(); });\
		child.stdin.write('ifconfig\\nexit\\n');\
		child.waitExit();\
		var adapters = [];\
		var adapter;\
		var lines = child.stdout._lines.split('\\n');\
		var tokens;\
		for (var i in lines)\
		{\
			if (lines[i].length > 0 && lines[i][0] != '\\t')\
			{\
				if (adapters.length > 0 && adapters[adapters.length - 1].inet === undefined && adapters[adapters.length - 1].inet6 === undefined) { adapters.pop(); }\
				adapters.push({ device: lines[i].split(':')[0] });\
			}\
			if (lines[i][0] == '\\t')\
			{\
				adapter = adapters[adapters.length - 1];\
				tokens = lines[i].split(' ');\
				tokens[0] = tokens[0].trim();\
				switch (tokens[0])\
				{\
				case 'inet':\
					adapter.inet = tokens[1];\
					var tst = Buffer.from(tokens[3].substring(2), 'hex');\
					adapter.netmask = tst[0].toString() + '.' + tst[1].toString() + '.' + tst[2].toString() + '.' + tst[3].toString();\
					break;\
				case 'inet6':\
					if (adapter.inet6 === undefined) { adapter.inet6 = []; }\
					var i6 = {};\
					i6.address = tokens[1].toUpperCase().split('%')[0];\
					if (tokens[tokens.length - 3] == 'scopeid')\
					{\
						i6.scope = tokens[tokens.length - 2].substring(2);\
						if (i6.scope.length == 1) { i6.scope = '0' + i6.scope; }\
						i6.scope = Buffer.from(i6.scope, 'hex')[0].toString();\
					}\
					adapter.inet6.push(i6);\
					break;\
				case 'ether':\
					var ether = tokens[1].split(':');\
					for (var x in ether)\
					{\
						if (ether[x].length == 1) { ether[x] = '0' + ether[x]; }\
						ether[x] = ether[x].toUpperCase();\
					}\
					adapter.mac = ether.join(':');\
					break;\
				}\
			}\
		}\
		if (adapters.length > 0 && adapters[adapters.length - 1].inet === undefined && adapters[adapters.length - 1].inet6 === undefined) { adapters.pop(); }\
		var retval = {};\
		while (adapters.length > 0)\
		{\
			adapter = adapters.pop();\
			retval[adapter.device] = [];\
			if (adapter.inet)\
			{\
				retval[adapter.device].push({ address: adapter.inet, netmask : adapter.netmask, mac : adapter.mac, family : 'IPv4' });\
			}\
			if (adapter.inet6)\
			{\
				while (adapter.inet6.length > 0)\
				{\
					var i6 = adapter.inet6.pop();\
					retval[adapter.device].push({ address: i6.address, mac : adapter.mac, family : 'IPv6', scope : i6.scope });\
				}\
			}\
		}\
		child = child_process.execFile('/bin/sh', ['sh']);\
		child.stdout._lines = '';\
		child.stdout.on('data', function(chunk) { this._lines += chunk.toString(); });\
		child.stdin.write('networksetup -listallhardwareports\\nexit\\n');\
		child.waitExit();\
		lines = child.stdout._lines.split('\\n');\
		for (var i = 0; i<lines.length; ++i)\
		{\
			if (lines[i].split('Hardware Port:').length > 1)\
			{\
				if (lines[i].split(':')[1].split('802.11').length > 1)\
				{\
					var dv = lines[i + 1].split(':')[1].trim();\
					if (retval[dv])\
					{\
						for (var x in retval[dv])\
						{\
							retval[dv][x].type = 'wireless';\
						}\
					}\
					else\
					{\
						retval[dv] = [{type: 'wireless', mac: lines[i + 2].split('Ethernet Address:')[1].trim().toUpperCase()}];\
					}\
				}\
				else if (lines[i].split(':')[1].trim() == 'Ethernet')\
				{\
					var dv = lines[i + 1].split(':')[1].trim();\
					if (retval[dv])\
					{\
						for (var x in retval[dv])\
						{\
							retval[dv][x].type = 'ethernet';\
						}\
					}\
					else\
					{\
						retval[dv] = [{type: 'ethernet', mac: lines[i + 2].split('Ethernet Address:')[1].trim().toUpperCase()}];\
					}\
				}\
			}\
		}\
		return(retval);\
		};\
	}\
	exports.name = function name()\
	{\
		var promise = require('promise');\
		var p = new promise(function(acc, rej) { this._acc = acc; this._rej = rej; });\
		switch (process.platform)\
		{\
			case 'linux':\
			case 'darwin':\
				p.child = require('child_process').execFile('/bin/sh', ['sh'], { type: require('child_process').SpawnTypes.TERM });\
				break;\
			case 'win32':\
				p.child = require('child_process').execFile('%windir%\\\\system32\\\\cmd.exe');\
				break;\
		}\
		p.child.promise = p;\
		p.child.stdout.str = '';\
		p.child.stdout.on('data', function(chunk) { this.str += chunk.toString(); });\
		p.child.on('exit', function(code)\
		{\
			var lines;\
			var tokens;\
			var i, j;\
			switch (process.platform)\
			{\
				case 'win32':\
					this.promise._acc(this.stdout.str.split('\\r\\n')[0]);\
					break;\
				case 'linux':\
					lines = this.stdout.str.split('\\n');\
					for (i in lines)\
					{\
						tokens = lines[i].split('=');\
						if (tokens[0] == 'PRETTY_NAME')\
						{\
							this.promise._acc(tokens[1].substring(1, tokens[1].length - 2));\
							break;\
						}\
					}\
					break;\
				case 'darwin':\
					var OSNAME = '';\
					var OSVERSION = '';\
					lines = this.stdout.str.split('\\n');\
					for (i in lines)\
					{\
						tokens = lines[i].split(':');\
						if (tokens[0] == 'ProductName') { OSNAME = tokens[1].trim(); }\
						if (tokens[0] == 'ProductVersion') { OSVERSION = tokens[1].trim(); }\
					}\
					this.promise._acc(OSNAME + ' ' + OSVERSION);\
					break;\
			}\
		});\
		switch (process.platform)\
		{\
			case 'linux':\
				p.child.stdin.write('cat /etc/*release\\nexit\\n');\
				break;\
			case 'darwin':\
				p.child.stdin.write('sw_vers\\nexit\\n');\
				break;\
			case 'win32':\
				p.child.stdin.write('exit\\r\\n');\
				break;\
		}\
		return (p);\
	}";

	ILibDuktape_ModSearch_AddHandler_AlsoIncludeJS(ctx, jsExtras, sizeof(jsExtras) - 1);
}
void ILibDuktape_ScriptContainer_OS_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "os", ILibDuktape_ScriptContainer_OS_Push);
}
extern void ILibDuktape_HttpStream_Init(duk_context *ctx);
duk_context *ILibDuktape_ScriptContainer_InitializeJavaScriptEngine_minimal()
{
	duk_context *ctx = duk_create_heap(ILibDuktape_ScriptContainer_Engine_malloc, ILibDuktape_ScriptContainer_Engine_realloc, ILibDuktape_ScriptContainer_Engine_free, NULL, ILibDuktape_ScriptContainer_Engine_fatal);
	if (ctx == NULL) { ILIBCRITICALEXIT(254); }
	return(ctx);
}
int ILibDuktape_ScriptContainer_DebuggingOK(duk_context *ctx)
{
	int retVal = 0;
	duk_push_heap_stash(ctx);
	retVal = (Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_ScriptContainer_Settings_SecurityFlags, 0) & SCRIPT_ENGINE_NO_DEBUGGER) == SCRIPT_ENGINE_NO_DEBUGGER ? 0 : 1;
	duk_pop(ctx);
	return(retVal);
}
duk_context *ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx3(duk_context *ctx, SCRIPT_ENGINE_SECURITY_FLAGS securityFlags, unsigned int executionTimeout, void *chain, char **argList, ILibSimpleDataStore *db, char *exePath, ILibProcessPipe_Manager pipeManager, ILibDuktape_HelperEvent exitHandler, void *exitUser)
{
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
		ILibDuktape_net_init(ctx, chain);					// Network library (node api)
		ILibDuktape_DGram_Init(ctx);						// Datagram Sockets
		ILibDuktape_HttpStream_Init(ctx);					// HTTP Library (node api)
	}
	if ((securityFlags & SCRIPT_ENGINE_NO_GENERIC_MARSHAL_ACCESS) == 0) { ILibDuktape_GenericMarshal_init(ctx); }
	if ((securityFlags & SCRIPT_ENGINE_NO_PROCESS_SPAWNING) == 0) 
	{ 
		ILibDuktape_ChildProcess_Init(ctx); 
#ifndef _NOHECI
		ILibDuktape_HECI_Init(ctx); 
#endif
	}
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

	ILibDuktape_Polyfills_JS_Init(ctx);

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
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Invalid Path specified");
		return(1);
	}
	else
	{
		return(duk_pcompile_lstring_filename(ctx, 0, path, pathLen));
	}
}
// Compiles the JavaScript to bytecode
int ILibDuktape_ScriptContainer_CompileJavaScriptEx(duk_context *ctx, char *payload, int payloadLen, char *filename, int filenameLen)
{
	if (ctx == NULL) 
	{ 
		return 1;	// Error, but we can't put an error object on top of stack, because we don't have a valid heap ptr (ctx)
	}

	ILibDuktape_Debugger_SetScript(payload, payloadLen, filename, filenameLen);

	if (filename == NULL)
	{
		if ((payloadLen > 0 ? duk_pcompile_lstring(ctx, 0, payload, payloadLen) : duk_pcompile_string(ctx, 0, payload)) != 0)
		{
			return 1;	// Error.... Error Object is on top of stack
		}
		else
		{
			return 0;	// SUCCESS
		}
	}
	else
	{
		if (filenameLen > 0) 
		{ 
			duk_push_lstring(ctx, filename, filenameLen); 
		}
		else
		{
			duk_push_string(ctx, filename);
		}
		if ((payloadLen > 0 ? duk_pcompile_lstring_filename(ctx, 0, payload, payloadLen) : duk_pcompile_string_filename(ctx, 0, payload)) != 0)
		{
			return 1;	// Error.... Error Object is on top of stack
		}
		else
		{
			return 0;	// SUCCESS
		}
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
		if ((codec = duk_create_heap_default()) == NULL) { ILIBCRITICALEXIT(254); }
	}
	else
	{
		codec = slave->ctx;
	}
	

	duk_push_lstring(codec, buffer + 4, ((int*)buffer)[0] - 4);
	duk_json_decode(codec, -1);
	cmd = (SCRIPT_ENGINE_COMMAND)Duktape_GetIntPropertyValue(codec, -1, "command", SCRIPT_ENGINE_COMMAND_UNKNOWN);

	ILibRemoteLogging_printf(ILibChainGetLogger(slave->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshAgent_Slave: Command: %u", (unsigned int)cmd);

	switch (cmd)
	{
		case SCRIPT_ENGINE_COMMAND_ADD_MODULE:
		{
			duk_size_t moduleLen;
			char *moduleName = Duktape_GetStringPropertyValue(slave->ctx, -1, "name", NULL);
			char *module = Duktape_GetStringPropertyValueEx(slave->ctx, -1, "module", NULL, &moduleLen);

			ILibDuktape_ModSearch_AddModule(slave->ctx, moduleName, module, (int)moduleLen);
			ILibRemoteLogging_printf(ILibChainGetLogger(slave->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshAgent_Slave: Added module %s", moduleName);

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
				int i, argLen = (int)duk_get_length(codec, -1);
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

			ILibRemoteLogging_printf(ILibChainGetLogger(slave->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshAgent_Slave: Created Java Script Engine: %p", (void*)slave->ctx);

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
					if (ILibDuktape_ScriptContainer_CompileJavaScript(slave->ctx, execData, (int)execDataLen) == 0 && ILibDuktape_ScriptContainer_ExecuteByteCode(slave->ctx) == 0)
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
							if (duk_peval_string(slave->ctx, "JSON.stringify") == 0)		// [json][retJSON][stringify]
							{
								duk_dup(slave->ctx, -3);									// [json][retJSON][stringify][retVal]
								if (duk_pcall(slave->ctx, 1) == 0)							// [json][retJSON][retValJSON]
								{
									duk_put_prop_string(slave->ctx, -2, "result");			// [json][retJSON]
								}
								else
								{
									duk_pop(slave->ctx);									// [json][retJSON]
								}
							}
							else
							{
								duk_pop(slave->ctx);										// [json][retJSON]
							}
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
					if (ILibDuktape_ScriptContainer_CompileJavaScript_FromFile(slave->ctx, execData, (int)execDataLen) == 0 && ILibDuktape_ScriptContainer_ExecuteByteCode(slave->ctx))
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
			if (ILibDuktape_EventEmitter_HasListeners(slave->emitter, "data")!=0)
			{
				char *json = Duktape_GetStringPropertyValue(slave->ctx, -1, "json", NULL);
				if (json != NULL)
				{
					ILibDuktape_EventEmitter_SetupEmit(slave->ctx, slave->emitter->object, "data");	// [emit][this][data]
					duk_push_string(slave->ctx, json);												// [emit][this][data][json]
					duk_json_decode(slave->ctx, -1);												// [emit][this][data][object]
					if (duk_pcall_method(slave->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(slave->ctx, "ScriptContainer.OnData(): "); }
					duk_pop(slave->ctx);															// ...
				}
			}
			break;
		}
		case SCRIPT_ENGINE_COMMAND_EXIT:
			if (slave->ctx != NULL) { duk_destroy_heap(slave->ctx); }
			break;
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
	if (!ILibMemory_CanaryOK(data)) { return; }

	ILibDuktape_ScriptContainer_Slave *slave = (ILibDuktape_ScriptContainer_Slave*)((void**)ILibMemory_Extra(data))[0];
	char *buffer = (char*)((void**)ILibMemory_Extra(data))[1];

	ILibDuktape_ScriptContainer_Slave_ProcessCommands(slave, buffer, (ILibProcessPipe_Pipe)data);
	ILibProcessPipe_Pipe_Resume((ILibProcessPipe_Pipe)data);
}
#endif
void ILibDuktape_ScriptContainer_Slave_OnReadStdIn(ILibProcessPipe_Pipe sender, char *buffer, int bufferLen, int* bytesConsumed)
{
	if (!ILibMemory_CanaryOK(sender)) { return; }

	ILibDuktape_ScriptContainer_Slave *slave = (ILibDuktape_ScriptContainer_Slave*)((void**)ILibMemory_Extra(sender))[0];
	if (bufferLen < 4 || bufferLen < ((int*)buffer)[0]) { return; }
	ILibRemoteLogging_printf(ILibChainGetLogger(slave->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "Slave read: %d bytes", bufferLen);

#ifdef WIN32
	// Windows dispatches on a non-microstack thread, so we need to context switch to microstack/duktape thread
	((void**)ILibMemory_Extra(sender))[1] = buffer;

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

#if defined(_POSIX) && !defined(__APPLE__)
	ILibCriticalLogFilename = "/var/tmp/agentSlave";
#endif

#ifndef MICROSTACK_NOTLS
	util_openssl_init();
#endif

	memset(&slaveObject, 0, sizeof(ILibDuktape_ScriptContainer_Slave));
	slaveObject.chain = chain;

	ILibRemoteLogging_printf(logger, ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "Starting Slave Process");

	// We must attach StdIn to fetch parameters
#ifdef WIN32
	mStdIn = ILibProcessPipe_Pipe_CreateFromExistingWithExtraMemory(manager, GetStdHandle(STD_INPUT_HANDLE), ILibProcessPipe_Pipe_ReaderHandleType_NotOverLapped, 2 * sizeof(void*));
#else
	mStdIn = ILibProcessPipe_Pipe_CreateFromExistingWithExtraMemory(manager, STDIN_FILENO, sizeof(void*));
#endif
	((void**)ILibMemory_Extra(mStdIn))[0] = &slaveObject;

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
	if (master->PeerChain != NULL)
	{
		char json[] = "{\"command\": \"128\"}";
		ILibDuktape_ScriptContainer_NonIsolated_Command *cmd = ILibMemory_Allocate(sizeof(json) + sizeof(ILibDuktape_ScriptContainer_NonIsolated_Command), 0, NULL, NULL);
		cmd->container.slave = ((void**)ILibMemory_GetExtraMemory(master->PeerChain, ILibMemory_CHAIN_CONTAINERSIZE))[1];
		memcpy_s(cmd->json, sizeof(json), json, sizeof(json));
		ILibChain_RunOnMicrostackThread2(master->PeerChain, ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsSlave, cmd, 1);
		return(0);
	}

	if (ILibIsChainBeingDestroyed(Duktape_GetChain(ctx)) == 0)
	{
		char *buffer;
		char header[4];
		duk_size_t bufferLen;

		duk_push_object(ctx);																// [obj]
		duk_push_int(ctx, (int)SCRIPT_ENGINE_COMMAND_EXIT);									// [obj][command]
		duk_put_prop_string(ctx, -2, "command");											// [obj]

		duk_json_encode(ctx, -1);
		buffer = (char*)duk_get_lstring(ctx, -1, &bufferLen);

		((int*)header)[0] = (int)bufferLen + 4;
		ILibProcessPipe_Process_WriteStdIn(master->child, header, 4, ILibTransport_MemoryOwnership_USER);
		ILibProcessPipe_Process_WriteStdIn(master->child, buffer, (int)bufferLen, ILibTransport_MemoryOwnership_USER);
		//if (master->child != NULL) { ILibProcessPipe_Process_SoftKill(master->child); }
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


	if (master->PeerChain != NULL)
	{
		char json[] = "{\"command\": \"2\", \"base64\": \"\"}";
		char *payload;
		duk_size_t payloadLen;
		payload = (char*)duk_get_lstring(ctx, 0, &payloadLen);
		int encodedPayloadLen = ILibBase64EncodeLength((int)payloadLen);
		ILibDuktape_ScriptContainer_NonIsolated_Command *cmd = (ILibDuktape_ScriptContainer_NonIsolated_Command*)ILibMemory_Allocate(sizeof(ILibDuktape_ScriptContainer_NonIsolated_Command) + encodedPayloadLen + sizeof(json), 0, NULL, NULL);

		cmd->container.slave = (ILibDuktape_ScriptContainer_Slave*)((void**)ILibMemory_GetExtraMemory(master->PeerChain, ILibMemory_CHAIN_CONTAINERSIZE))[1];
		int i = sprintf_s(cmd->json, sizeof(json) + encodedPayloadLen, json);
		char *output = cmd->json + i -2;
		i += ILibBase64Encode((unsigned char*)payload, (int)payloadLen, (unsigned char**)&output);
		sprintf_s(cmd->json + i - 2, 3, "\"}");
		
		ILibChain_RunOnMicrostackThread2(master->PeerChain, ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsSlave, cmd, 1);
		return(0);
	}


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

	((int*)header)[0] = (int)bufferLen + 4;


	ILibProcessPipe_Process_WriteStdIn(master->child, header, 4, ILibTransport_MemoryOwnership_USER);
	ILibProcessPipe_Process_WriteStdIn(master->child, buffer, (int)bufferLen, ILibTransport_MemoryOwnership_USER);

	return(0);
}
void ILibDuktape_ScriptContainer_ExitSink(ILibProcessPipe_Process sender, int exitCode, void* user)
{
	ILibDuktape_ScriptContainer_Master *master = (ILibDuktape_ScriptContainer_Master*)user;
	if (ILibMemory_CanaryOK(master))
	{
		duk_context *ctx = master->ctx;

		ILibDuktape_EventEmitter_SetupEmit(master->ctx, master->emitter->object, "exit");			// [emit][this][exit]
		duk_push_int(master->ctx, exitCode);														// [emit][this][exit][code]
		if (duk_pcall_method(master->ctx, 2) != 0)
		{
			ILibDuktape_Process_UncaughtException(master->ctx);
		}

		duk_pop(ctx);

		if (ILibMemory_CanaryOK(master)) { master->child = NULL; }
	}
}
void ILibDuktape_ScriptContainer_StdOutSink_Chain(void *chain, void *user)
{
	ILibDuktape_ScriptContainer_Master *master = (ILibDuktape_ScriptContainer_Master*)((void**)user)[0];
	if (ILibMemory_CanaryOK(master))
	{
		char *buffer = ILibMemory_Extra(user);
		duk_push_global_object(master->ctx);								// [g]
		duk_get_prop_string(master->ctx, -1, "console");					// [g][console]
		duk_get_prop_string(master->ctx, -1, "log");						// [g][console][log]
		duk_swap_top(master->ctx, -2);										// [g][log][this]
		duk_push_string(master->ctx, "Child/StdOut");						// [g][log][this][s1]
		duk_push_lstring(master->ctx, buffer, ILibMemory_ExtraSize(user));	// [g][log][this][s1][str]
		duk_pcall_method(master->ctx, 2); duk_pop(master->ctx);				// [g]
		duk_pop(master->ctx);												// ...
	}
	ILibMemory_Free(user);
}
void ILibDuktape_ScriptContainer_StdOutSink(ILibProcessPipe_Process sender, char *buffer, int bufferLen, int* bytesConsumed, void* user)
{
	buffer[bufferLen] = 0;

	ILibDuktape_ScriptContainer_Master *master = (ILibDuktape_ScriptContainer_Master*)user;
	if (ILibMemory_CanaryOK(master))
	{
		void *tmp = ILibMemory_SmartAllocateEx(sizeof(void*), bufferLen + 1);
		((void**)tmp)[0] = master;
		memcpy_s(ILibMemory_Extra(tmp), ILibMemory_ExtraSize(tmp), buffer, bufferLen);
		ILibChain_RunOnMicrostackThread(master->chain, ILibDuktape_ScriptContainer_StdOutSink_Chain, tmp);
	}

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
				if(ILibDuktape_EventEmitter_HasListeners(master->emitter, "data")!=0)
				{ 
					char *json = Duktape_GetStringPropertyValue(master->ctx, -1, "json", NULL);
					if (json != NULL)
					{
						ILibDuktape_EventEmitter_SetupEmit(master->ctx, master->emitter->object, "data");	// [emit][this][data]
						duk_push_string(master->ctx, json);													// [emit][this][data][str]
						duk_json_decode(master->ctx, -1);													// [emit][this][data][json]
						if (duk_pcall_method(master->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(master->ctx, "ScriptContainer.OnData(): "); }
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
						ILibDuktape_EventEmitter_SetupEmit(master->ctx, master->emitter->object, "error");	// [emit][this][error]
						duk_get_prop_string(master->ctx, -4, "error");										// [emit][this][error][errorObj]
						if (duk_pcall_method(master->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(master->ctx, "ScriptContainer_OnError_Dispatch(): "); }
						duk_pop(master->ctx);																// ...
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
	if (ILibMemory_CanaryOK(sender))
	{
		void **ptr = (void**)ILibMemory_Extra(ILibProcessPipe_Process_GetStdErr(sender));
		ptr[0] = master;
		ptr[1] = buffer;
		ILibProcessPipe_Pipe_Pause(ILibProcessPipe_Process_GetStdErr(sender));
		ILibChain_RunOnMicrostackThread(master->chain, ILibDuktape_ScriptContainer_StdErrSink_MicrostackThread, ptr);
	}
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
		ILibProcessPipe_Process_SoftKill(master->child);
	}
	else if (master->PeerChain != NULL)
	{
		char json[] = "{\"command\": \"128\", \"noResponse\": \"1\"}";
		ILibDuktape_ScriptContainer_NonIsolated_Command *cmd = ILibMemory_Allocate(sizeof(json) + sizeof(ILibDuktape_ScriptContainer_NonIsolated_Command), 0, NULL, NULL);
		cmd->container.slave = ((void**)ILibMemory_GetExtraMemory(master->PeerChain, ILibMemory_CHAIN_CONTAINERSIZE))[1];
		memcpy_s(cmd->json, sizeof(json), json, sizeof(json));
		ILibChain_RunOnMicrostackThread2(master->PeerChain, ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsSlave, cmd, 1);
#ifdef WIN32
		WaitForSingleObject(master->PeerThread, INFINITE);
#endif
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

	if (master->child != NULL)
	{
		len = sprintf_s(ILibScratchPad2 + 4, sizeof(ILibScratchPad2) - 4, "%s", duk_get_string(ctx, -1));
		((int*)ILibScratchPad2)[0] = len + 4;

		ILibProcessPipe_Process_WriteStdIn(master->child, ILibScratchPad2, len + 4, ILibTransport_MemoryOwnership_USER);
	}
	else if(master->PeerChain != NULL)
	{
		duk_size_t payloadLen;
		char *payload = (char*)duk_get_lstring(ctx, -1, &payloadLen);
		ILibDuktape_ScriptContainer_NonIsolated_Command *cmd = ILibMemory_Allocate(sizeof(ILibDuktape_ScriptContainer_NonIsolated_Command) + (int)payloadLen + 1, 0, NULL, NULL);
		cmd->container.slave = (ILibDuktape_ScriptContainer_Slave*)((void**)ILibMemory_GetExtraMemory(master->PeerChain, ILibMemory_CHAIN_CONTAINERSIZE))[1];
		memcpy_s(cmd->json, payloadLen + 1, payload, payloadLen + 1);
		ILibChain_RunOnMicrostackThread2(master->PeerChain, ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsSlave, cmd, 1);
	}
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


void ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsMaster(void *chain, void *user)
{
	ILibDuktape_ScriptContainer_NonIsolated_Command *cmd = (ILibDuktape_ScriptContainer_NonIsolated_Command*)user;
	ILibDuktape_ScriptContainer_Master *master = cmd->container.master;
	ILibDuktape_ScriptContainer_Slave *slave = master->PeerChain == NULL ? NULL : (ILibDuktape_ScriptContainer_Slave*)((void**)ILibMemory_GetExtraMemory(master->PeerChain, ILibMemory_CHAIN_CONTAINERSIZE))[1];
	if (master->ctx == NULL) { return; }

	int id;
	duk_push_string(master->ctx, cmd->json);		// [string]
	duk_json_decode(master->ctx, -1);				// [json]
	free(cmd);

	switch ((id = Duktape_GetIntPropertyValue(master->ctx, -1, "command", -1)))
	{
		case 0:																// Ready
		{
			// Call INIT first
			char json[] = "{\"command\": \"1\"}";
			ILibDuktape_ScriptContainer_NonIsolated_Command* initCmd = (ILibDuktape_ScriptContainer_NonIsolated_Command*)ILibMemory_Allocate(sizeof(json) + sizeof(ILibDuktape_ScriptContainer_NonIsolated_Command), 0, NULL, NULL);
			initCmd->container.slave = slave;
			memcpy_s(initCmd->json, sizeof(json), json, sizeof(json));
			ILibChain_RunOnMicrostackThread2(master->PeerChain, ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsSlave, initCmd, 1);
			break;
		}
		case 1:
		{
			// Emit Ready Event
			duk_push_heapptr(master->ctx, master->emitter->object);		// [json][container]
			duk_get_prop_string(master->ctx, -1, "emit");				// [json][container][emit]
			duk_swap_top(master->ctx, -2);								// [json][emit][this]
			duk_push_string(master->ctx, "ready");						// [json][emit][this][ready]
			if (duk_pcall_method(master->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(master->ctx, "Error Dispatching 'ready' event to Master Script Container"); }
			duk_pop(master->ctx);										// [json]

			break;
		}
		case SCRIPT_ENGINE_COMMAND_ERROR:
			duk_push_heapptr(master->ctx, master->emitter->object);			// [json][container]
			duk_get_prop_string(master->ctx, -1, "emit");					// [json][container][emit]
			duk_swap_top(master->ctx, -2);									// [json][emit][this]
			duk_push_string(master->ctx, "error");							// [json][emit][this][error]
			duk_get_prop_string(master->ctx, -4, "message");				// [json][emit][this][error][msg]
			if (duk_pcall_method(master->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(master->ctx, "Error Emitting ScriptContainer Error Message: "); }
			duk_pop(master->ctx);											// [json]
			break;
		case SCRIPT_ENGINE_COMMAND_EXIT:
			duk_push_heapptr(master->ctx, master->emitter->object);			// [json][container]
			duk_get_prop_string(master->ctx, -1, "emit");					// [json][container][emit]
			duk_swap_top(master->ctx, -2);									// [json][emit][this]
			duk_push_string(master->ctx, "exit");							// [json][emit][this][exit]
			duk_get_prop_string(master->ctx, -4, "exitCode");				// [json][emit][this][exit][msg]
			if (duk_pcall_method(master->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(master->ctx, "Error Emitting ScriptContainer Exit: "); }
			duk_pop(master->ctx);											// [json]
			master->PeerChain = NULL;
			break;
		case SCRIPT_ENGINE_COMMAND_SEND_JSON:
			ILibDuktape_EventEmitter_SetupEmit(master->ctx, master->emitter->object, "data");	// [json][emit][this][data]
			duk_get_prop_string(master->ctx, -4, "json");										// [json][emit][this][data][str]
			duk_json_decode(master->ctx, -1);													// [json][emit][this][data][value]
			if (duk_pcall_method(master->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(master->ctx, "Error Emitting ScriptContainer Data: "); }
			duk_pop(master->ctx);																// [json]
			break;
		default:
			ILibDuktape_Process_UncaughtExceptionEx(master->ctx, "Unknown Command [%d] Received from Slave Container ", id);
			break;
	}

	duk_pop(master->ctx);							// ...

}

void ILibDuktape_ScriptContainer_NonIsolatedWorker_ExceptionSink(duk_context *ctx, char *msg, void *user)
{
	duk_push_object(ctx);									// [obj]
	duk_push_int(ctx, (int)SCRIPT_ENGINE_COMMAND_ERROR);
	duk_put_prop_string(ctx, -2, "command");
	duk_push_string(ctx, msg);
	duk_put_prop_string(ctx, -2, "message");
	duk_json_encode(ctx, -1);								// [json]

	duk_size_t payloadLen;
	char *payload = (char*)duk_get_lstring(ctx, -1, &payloadLen);

	ILibDuktape_ScriptContainer_NonIsolated_Command *cmd = (ILibDuktape_ScriptContainer_NonIsolated_Command*)ILibMemory_Allocate((int)(sizeof(ILibDuktape_ScriptContainer_NonIsolated_Command) + payloadLen + 1), 0, NULL, NULL);
	cmd->container.master = ((void**)ILibMemory_GetExtraMemory(Duktape_GetChain(ctx), ILibMemory_CHAIN_CONTAINERSIZE))[0];
	memcpy_s(cmd->json, payloadLen + 1, payload, payloadLen + 1);

	duk_pop(ctx);											// ...

	ILibChain_RunOnMicrostackThread2(cmd->container.master->chain, ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsMaster, cmd, 1);
}
void ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsSlave(void *chain, void *user)
{
	ILibDuktape_ScriptContainer_NonIsolated_Command *cmd = (ILibDuktape_ScriptContainer_NonIsolated_Command*)user;
	ILibDuktape_ScriptContainer_Slave *slave = cmd->container.slave;
	ILibDuktape_ScriptContainer_Master *master = (ILibDuktape_ScriptContainer_Master*)((void**)ILibMemory_GetExtraMemory(slave->chain, ILibMemory_CHAIN_CONTAINERSIZE))[0];

	int id;
	duk_push_string(slave->ctx, cmd->json);		// [string]
	duk_json_decode(slave->ctx, -1);			// [json]
	free(cmd);

	switch ((id = Duktape_GetIntPropertyValue(slave->ctx, -1, "command", -1)))
	{
		case SCRIPT_ENGINE_COMMAND_INIT:
			ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx3(slave->ctx, (SCRIPT_ENGINE_SECURITY_FLAGS)master->ChildSecurityFlags, 0, slave->chain, NULL, NULL, NULL, NULL, ILibDuktape_ScriptContainer_Slave_HeapDestroyed, slave);
			ILibDuktape_SetNativeUncaughtExceptionHandler(slave->ctx, ILibDuktape_ScriptContainer_NonIsolatedWorker_ExceptionSink, master);
			
			char json[] = "{\"command\": \"1\"}";
			ILibDuktape_ScriptContainer_NonIsolated_Command* cmd = (ILibDuktape_ScriptContainer_NonIsolated_Command*)ILibMemory_Allocate(sizeof(json) + sizeof(ILibDuktape_ScriptContainer_NonIsolated_Command), 0, NULL, NULL);
			cmd->container.master = master;
			memcpy_s(cmd->json, sizeof(json), json, sizeof(json));
			ILibChain_RunOnMicrostackThread2(master->chain, ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsMaster, cmd, 1);
			break;
		case SCRIPT_ENGINE_COMMAND_EXEC:
			{
				char *payload;
				duk_size_t payloadLen;

				payload = (char*)Duktape_GetStringPropertyValueEx(slave->ctx, -1, "base64", NULL, &payloadLen);
				payloadLen = ILibBase64Decode((unsigned char*)payload, (int)payloadLen, (unsigned char**)&payload);

				if (ILibDuktape_ScriptContainer_CompileJavaScript(slave->ctx, payload, (int)payloadLen) == 0 && ILibDuktape_ScriptContainer_ExecuteByteCode(slave->ctx) == 0)
				{
					// SUCCESS
					duk_pop(slave->ctx);
				}
				else
				{
					// ERROR
					ILibDuktape_Process_UncaughtExceptionEx(slave->ctx, "ScriptContainer Error: ");
					duk_pop(slave->ctx);
				}
			}
			break;
		case SCRIPT_ENGINE_COMMAND_SEND_JSON:
			{
				if (slave->emitter != NULL)
				{
					duk_get_prop_string(slave->ctx, -1, "json");			// [cmd][string]
					duk_json_decode(slave->ctx, -1);						// [cmd][obj]
					duk_push_heapptr(slave->ctx, slave->emitter->object);	// [cmd][obj][container]
					duk_get_prop_string(slave->ctx, -1, "emit");			// [cmd][obj][container][emit]
					duk_swap_top(slave->ctx, -2);							// [cmd][obj][emit][this]
					duk_push_string(slave->ctx, "data");					// [cmd][obj][emit][this][data]
					duk_dup(slave->ctx, -4);								// [cmd][obj][emit][this][data][obj]
					if (duk_pcall_method(slave->ctx, 2) != 0) { ILibDuktape_Process_UncaughtException(slave->ctx); }
					duk_pop_2(slave->ctx);									// [cmd]
				}
			}
			break;
		case SCRIPT_ENGINE_COMMAND_EXIT:
			slave->noRespond = Duktape_GetIntPropertyValue(slave->ctx, -1, "noResponse", 0);
			duk_pop(slave->ctx);
			duk_destroy_heap(slave->ctx);
			return;
	}
	duk_pop(slave->ctx);						// ...
}

void ILibDuktape_ScriptContainer_NonIsolatedWorker(void *arg)
{
	ILibDuktape_ScriptContainer_Master *master = (ILibDuktape_ScriptContainer_Master*)arg;
	ILibDuktape_ScriptContainer_Slave *slave = ILibMemory_AllocateA(sizeof(ILibDuktape_ScriptContainer_Slave));
	char json[] = "{\"command\": \"0\"}";

	slave->chain = ILibCreateChainEx(2 * sizeof(void*));
	((void**)ILibMemory_GetExtraMemory(slave->chain, ILibMemory_CHAIN_CONTAINERSIZE))[0] = master;
	((void**)ILibMemory_GetExtraMemory(slave->chain, ILibMemory_CHAIN_CONTAINERSIZE))[1] = slave;
	master->PeerChain = slave->chain;
	slave->ctx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngine_minimal();

	duk_push_heap_stash(slave->ctx);
	duk_push_pointer(slave->ctx, slave);
	duk_put_prop_string(slave->ctx, -2, ILibDuktape_ScriptContainer_SlavePtr);
	duk_push_pointer(slave->ctx, master);
	duk_put_prop_string(slave->ctx, -2, ILibDuktape_ScriptContainer_MasterPtr);
	duk_pop(slave->ctx);

	ILibDuktape_ScriptContainer_NonIsolated_Command* cmd = (ILibDuktape_ScriptContainer_NonIsolated_Command*)ILibMemory_Allocate(sizeof(json) + sizeof(ILibDuktape_ScriptContainer_NonIsolated_Command), 0, NULL, NULL);
	cmd->container.master = master;
	memcpy_s(cmd->json, sizeof(json), json, sizeof(json));
	ILibChain_RunOnMicrostackThread2(master->chain, ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsMaster, cmd, 1);
	ILibChain_DisableWatchDog(slave->chain);
	ILibStartChain(slave->chain);

	if (slave->noRespond == 0)
	{
		cmd = (ILibDuktape_ScriptContainer_NonIsolated_Command*)ILibMemory_Allocate(64 + sizeof(ILibDuktape_ScriptContainer_NonIsolated_Command), 0, NULL, NULL);
		cmd->container.master = master;
		sprintf_s(cmd->json, 64, "{\"command\": \"128\", \"exitCode\": \"%d\"}", slave->exitCode);
		ILibChain_RunOnMicrostackThread2(master->chain, ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsMaster, cmd, 1);
	}
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
	int processIsolation = 1;
	int sessionIdSpecified = 0;
	void *sessionId = NULL;

	if (duk_get_top(ctx) > 0 && duk_is_object(ctx, 0))
	{
		processIsolation = Duktape_GetIntPropertyValue(ctx, 0, "processIsolation", 1);
		if (duk_has_prop_string(ctx, 0, "sessionId"))
		{
			sessionIdSpecified = 1;
			sessionId = (void*)(ILibPtrCAST)(uint64_t)Duktape_GetIntPropertyValue(ctx, 0, "sessionId", 0);
		}
	}

#if defined(MeshLibInterface)
	if (processIsolation != 0) { return(ILibDuktape_Error(ctx, "Process Isolation is not supported with this runtime")); }
#endif

	duk_push_heap_stash(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_ScriptContainer_ExePath);
	duk_get_prop_string(ctx, -2, ILibDuktape_ScriptContainer_PipeManager);

	exePath = (char*)duk_get_string(ctx, -2);
	manager = (ILibProcessPipe_Manager)duk_get_pointer(ctx, -1);

	duk_push_object(ctx);														// [container]
	ILibDuktape_WriteID(ctx, "ScriptContainer.master");
	master = (ILibDuktape_ScriptContainer_Master*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_ScriptContainer_Master));
	duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_MasterPtr);		// [container]

	master->ctx = ctx;
	master->emitter = ILibDuktape_EventEmitter_Create(ctx);
	master->chain = Duktape_GetChain(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(master->emitter, "exit");
	ILibDuktape_EventEmitter_CreateEventEx(master->emitter, "error");
	ILibDuktape_EventEmitter_CreateEventEx(master->emitter, "data");
	ILibDuktape_EventEmitter_CreateEventEx(master->emitter, "ready");
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "exit", ILibDuktape_ScriptContainer_Exit, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(master->ctx, "ExecuteScript", ILibDuktape_ScriptContainer_ExecuteScript, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(master->ctx, "ExecuteString", ILibDuktape_ScriptContainer_ExecuteString, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(master->ctx, "send", ILibDuktape_ScriptContainer_SendToSlave, 1);
	ILibDuktape_CreateInstanceMethod(master->ctx, "addModule", ILibDuktape_ScriptContainer_Master_AddModule, 2);
	ILibDuktape_CreateFinalizer(master->ctx, ILibDuktape_ScriptContainer_Finalizer);

	if (processIsolation)
	{
		// We're going to spawn a child process to run this ScriptContainer
		unsigned int executionTimeout = duk_is_object(ctx, 0)?Duktape_GetIntPropertyValue(ctx, 0, "executionTimeout", 0): (unsigned int)duk_require_int(ctx, 0);
		master->ChildSecurityFlags = (duk_is_object(ctx, 0) ? Duktape_GetIntPropertyValue(ctx, 0, "childSecurityFlags", 0): (unsigned int)duk_require_int(ctx, 1)) | SCRIPT_ENGINE_NO_MESH_AGENT_ACCESS;

		if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "env"))
		{
			char tmp[32768];	
			size_t v = 0;
#ifdef WIN32
			char *key, *value;
			duk_size_t keyLen, valueLen;
#else
			char **envvars = (char**)tmp;
#endif


			duk_get_prop_string(ctx, 0, "env");				// [env]
			duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);// [env][enum]
			while (duk_next(ctx, -1, 1))					// [env][enum][key][val]
			{
#ifdef WIN32
				key = (char*)duk_to_lstring(ctx, -2, &keyLen);
				value = (char*)duk_to_lstring(ctx, -1, &valueLen);
				if (keyLen + valueLen + 3 + v > sizeof(tmp)) { return(ILibDuktape_Error(ctx, "Environment Variables too Large")); }
				v += sprintf_s(tmp + v, sizeof(tmp) - v, "%s=%s", key, value);
				(tmp + v)[0] = 0; ++v;
#else
				v += (2 * sizeof(char*));
				if (v < sizeof(tmp))
				{
					envvars[0] = (char*)duk_to_string(ctx, -2);
					envvars[1] = (char*)duk_to_string(ctx, -1);
					envvars = (char**)((char*)envvars + 2 * sizeof(char*));
				}
#endif
				duk_pop_2(ctx);								// [env][enum]
			}
			duk_pop_2(ctx);									// ...
#ifdef WIN32
			(tmp + v)[0] = 0; ++v;
#else
			v += sizeof(char*);
			if (v < sizeof(tmp))
			{
				envvars[0] = NULL;
			}
			else
			{
				return(ILibDuktape_Error(ctx, "Environment Variables are too large"));
			}
#endif
			master->child = ILibProcessPipe_Manager_SpawnProcessEx4(manager, exePath, (char * const*)param, sessionIdSpecified!=0?ILibProcessPipe_SpawnTypes_SPECIFIED_USER:spawnType, sessionId, (void*)tmp, 2 * sizeof(void*));
		}
		else
		{
			master->child = ILibProcessPipe_Manager_SpawnProcessEx3(manager, exePath, (char * const*)param, sessionIdSpecified!=0?ILibProcessPipe_SpawnTypes_SPECIFIED_USER:spawnType, sessionId, 2 * sizeof(void*));
		}


		if (master->child == NULL) { return(ILibDuktape_Error(ctx, "ScriptContainer.Create(): Error spawning child process, using [%s]", exePath)); }
		
		duk_push_true(ctx);
		duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_ProcessIsolated);
		duk_push_object(ctx);										// [container][obj]
		duk_push_int(ctx, (int)SCRIPT_ENGINE_COMMAND_INIT);
		duk_put_prop_string(ctx, -2, "command");
		duk_push_int(ctx, (int)executionTimeout);
		duk_put_prop_string(ctx, -2, "executionTimeout");
		duk_push_int(ctx, (int)master->ChildSecurityFlags);
		duk_put_prop_string(ctx, -2, "securityFlags");
		duk_json_encode(ctx, -1);
		buffer = (char*)Duktape_GetBuffer(ctx, -1, &bufferLen);

		duk_swap_top(ctx, -2);										// [json][container]

		((int*)header)[0] = (int)bufferLen + 4;
		ILibProcessPipe_Process_AddHandlers(master->child, SCRIPT_ENGINE_PIPE_BUFFER_SIZE, ILibDuktape_ScriptContainer_ExitSink, ILibDuktape_ScriptContainer_StdOutSink, ILibDuktape_ScriptContainer_StdErrSink, ILibDuktape_ScriptContainer_SendOkSink, master);
		ILibProcessPipe_Process_WriteStdIn(master->child, header, sizeof(header), ILibTransport_MemoryOwnership_USER);
		ILibProcessPipe_Process_WriteStdIn(master->child, buffer, (int)bufferLen, ILibTransport_MemoryOwnership_USER);
	}
	else
	{
		// We're going to spawn a thread to host this Script Container
		duk_push_false(ctx);
		duk_put_prop_string(ctx, -2, ILibDuktape_ScriptContainer_ProcessIsolated);
		ILibDuktape_EventEmitter_CreateEventEx(master->emitter, "ready");
		master->PeerThread = ILibSpawnNormalThread(ILibDuktape_ScriptContainer_NonIsolatedWorker, master);
		master->ChildSecurityFlags = Duktape_GetIntPropertyValue(ctx, 0, "permissions", 0);
		
		duk_push_fixed_buffer(ctx, sizeof(void*));									// [container][buffer]
		((void**)Duktape_GetBuffer(ctx, -1, NULL))[0] = master->PeerThread;
		duk_dup(ctx, -1);															// [container][buffer][buffer]
		duk_put_prop_string(ctx, -3, "\xFF_PointerBuffer");							// [container][buffer]
		duk_push_buffer_object(ctx, -1, 0, sizeof(void*), DUK_BUFOBJ_NODEJS_BUFFER);// [container][buffer][NodeBuffer]
		duk_remove(ctx, -2);														// [container][NodeBuffer]
		ILibDuktape_CreateReadonlyProperty(ctx, "_PeerThread");						// [container]
#ifdef WIN32
		duk_push_int(ctx, (int)GetThreadId(master->PeerThread));
		ILibDuktape_CreateReadonlyProperty(ctx, "_PeerThreadID");					// [container]
#endif
	}
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
	ILibDuktape_WriteID(ctx, "ScriptContainer.slave");
	slave->emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(slave->emitter, "data");
	ILibDuktape_CreateInstanceMethod(ctx, "send", ILibDuktape_ScriptContainer_Slave_SendToMaster, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "Create", ILibDuktape_ScriptContainer_Create, DUK_VARARGS);
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
