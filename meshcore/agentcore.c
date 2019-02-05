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
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <WinBase.h>
#include "wincrypto.h"
#endif

#include "agentcore.h"
#include "signcheck.h"
#include "meshdefines.h"
#include "meshinfo.h"
#include "microscript/ILibDuktape_Polyfills.h"
#include "microscript/ILibDuktape_Helpers.h"
#include "microscript/ILibDuktape_SHA256.h"
#include "microscript/ILibDuktape_EncryptionStream.h"
#include "microscript/ILibDuktape_DuplexStream.h"
#include "microscript/ILibDuktape_EventEmitter.h"
#include "microscript/ILibDuktape_net.h"
#include "microscript/ILibDuktape_Dgram.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibAsyncUDPSocket.h"
#include "microstack/ILibMulticastSocket.h"
#include "microscript/ILibDuktape_ScriptContainer.h"
#include "../microstack/ILibIPAddressMonitor.h"

#ifdef _POSIX
#include <sys/stat.h>
#include <sys/wait.h>
#endif

#ifdef _LINKVM
	#ifdef WIN32
		#include "KVM/Windows/kvm.h"
	#endif
	#ifdef _POSIX
		#ifndef __APPLE__
			#include "KVM/Linux/linux_kvm.h"
		#else
			#include "KVM/MacOS/mac_kvm.h"
		#endif
	#endif
#endif

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#define HEX_IDENTIFIER (unsigned short)12408
#define EXE_IDENTIFIER (unsigned int)778401893
#define MSH_IDENTIFIER (unsigned int)778924904
#define SCRIPT_ENGINE_PIPE_BUFFER_SIZE 65535

#define MESH_AGENT_PORT 16990					 //!< Default Mesh Agent Port
#define MESH_MCASTv4_GROUP "239.255.255.235"
#define MESH_MCASTv6_GROUP "FF02:0:0:0:0:0:0:FE"

char exeMeshPolicyGuid[] = { 0xB9, 0x96, 0x01, 0x58, 0x80, 0x54, 0x4A, 0x19, 0xB7, 0xF7, 0xE9, 0xBE, 0x44, 0x91, 0x4C, 0x19 };
#define MESH_SCRIPTCONTAINER_ID	"\xFF_ScriptContainer_ID"
#define MESH_AGENT_SINGLETON	"\xFF_MeshAgentObject_Singleton"
#define SEQ_TABLE_KEY			"\xFF_seqTable"
#define CONTAINER_PTR			"\xFF_ptr"
#define MESH_AGENT_PTR			"\xFFMeshAgentPtr"
#define CTX_PTR					"\xFF_Heap"
#define CONTEXT_GUID_PTR		"_CONTEXT_GUID_PTR"
#define REMOTE_DESKTOP_STREAM	"\xFF_RemoteDesktopStream"
#define REMOTE_DESKTOP_ptrs		"\xFF_RemoteDesktopPTRS"
#define DEFAULT_IDLE_TIMEOUT	120

#define KVM_IPC_SOCKET			"\xFF_KVM_IPC_SOCKET"

#ifdef _POSIX
	extern char **environ;
#endif

char* MeshAgentHost_BatteryInfo_STRINGS[] = { "UNKNOWN", "HIGH_CHARGE", "LOW_CHARGE", "NO_BATTERY", "CRITICAL_CHARGE", "", "", "", "CHARGING" };
JS_ENGINE_CONTEXT MeshAgent_JavaCore_ContextGuid = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

typedef struct RemoteDesktop_Ptrs
{
	duk_context *ctx;
	void *object;
	void *MeshAgentObject;
#ifdef _POSIX
	void *kvmPipe;
#ifdef __APPLE__
	int kvmDomainSocket;
#endif
#endif
	ILibDuktape_DuplexStream *stream;
}RemoteDesktop_Ptrs;


typedef struct ScriptContainerSettings
{
	SCRIPT_ENGINE_SECURITY_FLAGS permissions;
	unsigned int executionTimeout;
	int usingMasterDb;
	ILibDuktape_NativeUncaughtExceptionHandler nUncaughtExceptionHandler;
	void *nUncaughtExceptionUser;
	char ContextGuid[sizeof(JS_ENGINE_CONTEXT) + 1];
}ScriptContainerSettings;

#pragma pack(push, 1)
typedef struct MeshCommand_BinaryPacket_ServerId
{
	unsigned short command;
	char serverId[UTIL_SHA384_HASHSIZE];
}MeshCommand_BinaryPacket_ServerId;
typedef struct MeshCommand_BinaryPacket_AuthRequest
{
	unsigned short command;
	char serverHash[UTIL_SHA384_HASHSIZE];
	char serverNonce[UTIL_SHA384_HASHSIZE];
}MeshCommand_BinaryPacket_AuthRequest;
typedef struct MeshCommand_BinaryPacket_AuthVerify_Header
{
	unsigned short command;
	unsigned short certLen;
	char data[];
}MeshCommand_BinaryPacket_AuthVerify_Header;
typedef struct MeshCommand_BinaryPacket_AuthVerify
{
	char *cert;
	unsigned short certLen;
	char *signature;
	unsigned short signatureLen;
}MeshCommand_BinaryPacket_AuthVerify;
typedef enum MeshCommand_AuthInfo_PlatformType
{
	MeshCommand_AuthInfo_PlatformType_DESKTOP	     = 1,
	MeshCommand_AuthInfo_PlatformType_LAPTOP	     = 2,
	MeshCommand_AuthInfo_PlatformType_MOBILE	     = 3,
	MeshCommand_AuthInfo_PlatformType_SERVER	     = 4,
	MeshCommand_AuthInfo_PlatformType_DISK		     = 5,
	MeshCommand_AuthInfo_PlatformType_ROUTER	     = 6
}MeshCommand_BinaryPacket_AuthInfo_PlatformType;
typedef struct MeshCommand_BinaryPacket_AuthInfo
{
	unsigned short command;
	unsigned int infoVersion;
	unsigned int agentId;
	unsigned int agentVersion;
	unsigned int platformType;
	char MeshID[UTIL_SHA384_HASHSIZE];
	unsigned int capabilities;
	unsigned short hostnameLen;
	char hostname[];
}MeshCommand_BinaryPacket_AuthInfo;
typedef struct MeshCommand_BinaryPacket_CoreModule
{
	unsigned short command;
	unsigned short request;
	char coreModuleHash[UTIL_SHA384_HASHSIZE];
	char coreModule[];
}MeshCommand_BinaryPacket_CoreModule;
#pragma pack(pop)


#define ScriptContainerSettingsKey			"\xFF_ScriptContainerSettings"

ScriptContainerSettings* ScriptEngine_GetSettings(duk_context *ctx)
{
	ScriptContainerSettings *retVal = NULL;
	duk_push_heap_stash(ctx);									// [stash]
	if (duk_has_prop_string(ctx, -1, ScriptContainerSettingsKey))
	{
		duk_get_prop_string(ctx, -1, ScriptContainerSettingsKey);	// [stash][buffer]
		retVal = (ScriptContainerSettings*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop_2(ctx);												// ...
		return retVal;
	}
	else
	{
		duk_pop(ctx);											// ...
		return NULL;
	}
}

typedef struct SCRIPT_ENGINE_ISOLATION
{
	unsigned int reserved;
	MeshAgentHostContainer *agent;
	ILibProcessPipe_Process process;
	duk_context *ctx;
	ILibDuktape_EventEmitter *emitter;
	void *ScriptContainer;
	void *OnExit;
	void *OnError;
	unsigned int seq;
	char *containerID;
	duk_size_t containerIDLen;
#ifdef WIN32
	char* buffer;
	int bufferLen;
#endif
}SCRIPT_ENGINE_ISOLATION;

typedef enum SCRIPT_ENGINE_COMMAND
{
	SCRIPT_ENGINE_COMMAND_INIT			= 0x01,
	SCRIPT_ENGINE_COMMAND_EXEC_PATH		= 0x02,
	SCRIPT_ENGINE_COMMAND_EXEC_STR		= 0x03,
	SCRIPT_ENGINE_COMMAND_EXEC_OK		= 0x04,
	SCRIPT_ENGINE_COMMAND_EXEC_ERR		= 0xFE,
	SCRIPT_ENGINE_COMMAND_QUERY			= 0x20,
	SCRIPT_ENGINE_COMMAND_SET			= 0x21,
	SCRIPT_ENGINE_COMMAND_DB_GET		= 0x10,
	SCRIPT_ENGINE_COMMAND_DB_PUT		= 0x11,
	SCRIPT_ENGINE_COMMAND_LOG					= 0xFF
}SCRIPT_ENGINE_COMMAND;

#pragma pack(push, 1)
typedef struct SCRIPT_ENGINE_COMMAND_HEADER
{
	unsigned short length;
	unsigned short cmdType;
	char data[];
}SCRIPT_ENGINE_COMMAND_HEADER;
typedef struct SCRIPT_ENGINE_COMMAND_INIT_DATA
{
	JS_ENGINE_CONTEXT contextGuid;
	unsigned int securityFlags;
	unsigned int executionTimeout;
}SCRIPT_ENGINE_COMMAND_INIT_DATA;
typedef struct SCRIPT_ENGINE_COMMAND_LOG_DATA
{
	ILibRemoteLogging_Modules module;
	ILibRemoteLogging_Flags flags;
	char msg[];
}SCRIPT_ENGINE_COMMAND_LOG_DATA;
typedef struct SCRIPT_ENGINE_COMMAND_EXEC_ERR_DATA
{
	JS_ENGINE_CONTEXT contextGuid;
	int seq;
	char errorMessage[];
}SCRIPT_ENGINE_COMMAND_EXEC_ERR_DATA;
typedef struct SCRIPT_ENGINE_COMMAND_EXEC_OK_DATA
{
	JS_ENGINE_CONTEXT contextGuid;
	int seq;
	char retVal_JSON[];
}SCRIPT_ENGINE_COMMAND_EXEC_OK_DATA;
typedef struct SCRIPT_ENGINE_COMMAND_EXEC_STR_DATA
{
	JS_ENGINE_CONTEXT contextGuid;
	int seq;
	char script[];
}SCRIPT_ENGINE_COMMAND_EXEC_STR_DATA;
typedef struct SCRIPT_ENGINE_COMMAND_DB_GET_DATA
{
	JS_ENGINE_CONTEXT contextGuid;
	char key[];
}SCRIPT_ENGINE_COMMAND_DB_GET_DATA;
typedef struct SCRIPT_ENGINE_COMMAND_DB_PUT_DATA
{
	JS_ENGINE_CONTEXT contextGuid;
	int valueOffset;
	char data[];
}SCRIPT_ENGINE_COMMAND_DB_PUT_DATA;
#pragma pack(pop)

const char* AgentID_String[24] =
{
	"UNKNOWN", "Windows Console/x86", "Windows Console/x64", "Windows Service/x86", "Windows Service/x64",
	"Linux/x86", "Linux/x64", "MIPS", "XEN/x86", "Android/ARM", "Linux/ARM", "MAC OS/x86", "Android/x86", "PogoPlug/ARM",
	"Android (Google Play)", "Linux(Poky)/x86", "MAC OS/x64", "ChromeOS", "Linux(Poky)/x64", "Linux (NoKVM)/x86",
	"Linux (NoKVM)/x64", "Windows Console (MIN)", "Windows Service (MIN)", "NodeJS"
};

typedef enum AGENT_RECORD_TYPE
{
	AGENT_RECORD_TYPE_INIT = 0x00000001,
	AGENT_RECORD_TYPE_SHARED_DB = 0x00000003,
	AGENT_RECORD_TYPE_JAVASCRIPT_PAYLOAD = 0x00000004,
	AGENT_RECORD_TYPE_DATA_SET = 0x00000006,
	AGENT_RECORD_TYPE_DATA_QUERY = 0x00000008
}AGENT_RECORD_TYPE;

typedef struct AGENT_RECORD_HEADER
{
	unsigned int RecordLength;
	AGENT_RECORD_TYPE RecordType;
	JS_ENGINE_CONTEXT Context;
	char Payload[];
}AGENT_RECORD_HEADER;

//
// Piped Data Layout:
//
// 4 Bytes: Record Length
// 4 Bytes: Record Type
// 16 Bytes: Context GUID
// Variable: Payload

// Payloads ==>

// Init Record Payload 
// 4 Bytes:		Security Flags
// 4 Bytes:		Execution Timeout

// Javascript Payload
// JS Payload

// Shared DB Payload
// DB Path

// Environment Payload 
// 2 Bytes: VarLen
// 2 Bytes: VarValueLen
// Variable: VarName
// Variable: VarValue

// Data Query
// 2 Bytes: QueryLen
// Variable: Query

void MeshServer_Connect(MeshAgentHostContainer *agent);
void MeshServer_ProcessCommand(ILibWebClient_StateObject wcdo, MeshAgentHostContainer *agent, char *buffer, int bufferLen);
char ContainerContextGUID[sizeof(JS_ENGINE_CONTEXT) + 1];
void MeshServer_ConnectEx(MeshAgentHostContainer *agent);
int agent_VerifyMeshCertificates(MeshAgentHostContainer *agent);

void MeshAgent_sendConsoleText(duk_context *ctx, char *txt)
{
	if (ctx != NULL && txt != NULL)
	{
		if (duk_peval_string(ctx, "require('MeshAgent');") == 0)
		{
			duk_get_prop_string(ctx, -1, "SendCommand");			// [agent][SendCommand]
			duk_swap_top(ctx, -2);									// [SendCommand][this]
			duk_push_object(ctx);									// [SendCommand][this][var]
			duk_push_string(ctx, "msg"); duk_put_prop_string(ctx, -2, "action");
			duk_push_string(ctx, "console"); duk_put_prop_string(ctx, -2, "type");
			duk_push_string(ctx, txt); duk_put_prop_string(ctx, -2, "value");
			if (duk_pcall_method(ctx, 1) != 0) {}
		}
		duk_pop(ctx);												// ...
	}
}


int MeshAgent_GetSystemProxy(MeshAgentHostContainer *agent, char *buffer, size_t bufferSize)
{
#ifndef __APPLE__
	int retVal = 0;
#endif

#ifdef _POSIX
	#ifndef __APPLE__
		for (char **env = environ; *env; ++env)
		{
			int envLen = (int)strnlen_s(*env, INT_MAX);
			int i = ILibString_IndexOf(*env, envLen, "=", 1);
			if (i > 0)
			{
				if (i == 11 && strncmp(*env, "https_proxy", 11) == 0)
				{
					if (ILibString_StartsWith(*env + i + 1, envLen - i - 1, "http://", 7) != 0)
					{
						strcpy_s(buffer, bufferSize, *env + i + 8);
						retVal = envLen - i - 8;
					}
					else if(ILibString_StartsWith(*env + i + 1, envLen - i - 1, "https://", 8) != 0)
					{
						strcpy_s(buffer, bufferSize, *env + i + 9);
						retVal = envLen - i - 9;
					}
					else
					{
						strcpy_s(buffer, bufferSize, *env + i + 1);
						retVal = envLen - i - 1;
					}
					break;
				}
			}
		}
		return(retVal);
	#else
	char getProxyies[] = "(function getProxies(){\
		var ret = {};\
		var child = require('child_process').execFile('/bin/sh', ['sh']);\
		child.stdout.str = '';\
		child.stdout.on('data', function(chunk) { this.str += chunk.toString(); });\
		child.stdin.write('system_profiler SPNetworkDataType | grep \"Proxy\" \\nexit\\n');\
		child.waitExit();\
		var lines = child.stdout.str.split('\\n');\
		for (var i in lines)\
		{\
			if (lines[i])\
			{\
				var val = lines[i].split(':')[1].trim().toLowerCase();\
				var tokens = lines[i].split(':')[0].trim().split(' ');\
				var key = tokens[0].toLowerCase();\
				var t = tokens[2].toLowerCase();\
				if (!ret[key]) { ret[key] = {}; }\
				ret[key][t] = val;\
			}\
		}\
		return(ret);\
	})();";
	if (duk_peval_string(agent->meshCoreCtx, getProxyies) == 0)
	{
		if (duk_has_prop_string(agent->meshCoreCtx, -1, "http"))
		{
			duk_get_prop_string(agent->meshCoreCtx, -1, "http");
		}
		else if (duk_has_prop_string(agent->meshCoreCtx, -1, "https"))
		{
			duk_get_prop_string(agent->meshCoreCtx, -1, "https");
		}
		else
		{
			duk_pop(agent->meshCoreCtx);
			return(0); // No Proxies detected
		}

		if (strcmp(Duktape_GetStringPropertyValue(agent->meshCoreCtx, -1, "enabled", "no"), "yes") == 0)
		{
			char *proxyserver, *proxyport;
			duk_size_t proxyserverLen, proxyportLen;

			proxyserver = (char*)Duktape_GetStringPropertyValueEx(agent->meshCoreCtx, -1, "server", NULL, &proxyserverLen);
			proxyport = (char*)Duktape_GetStringPropertyValueEx(agent->meshCoreCtx, -1, "port", "8080", &proxyportLen);

			strncpy_s(buffer, bufferSize, proxyserver, proxyserverLen);
			strncpy_s(buffer + proxyserverLen, bufferSize - proxyserverLen, ":", 1);
			strncpy_s(buffer + proxyserverLen + 1, bufferSize - proxyserverLen - 1, proxyport, proxyportLen);
			duk_pop(agent->meshCoreCtx);
			return(proxyserverLen + 1 + proxyportLen);
		}
		else
		{
			// Proxy is disabled
			duk_pop(agent->meshCoreCtx);
			return(0);
		}
	}
	else
	{
		return(0);
	}
	#endif
#else
	char getProxy[] = "(function () {\
		var isroot = false;\
		var servers = [];\
		/* First we need to see if we are running as admin */\
		var GM = require('_GenericMarshal');\
		var advapi = GM.CreateNativeProxy('Advapi32.dll');\
		advapi.CreateMethod('AllocateAndInitializeSid');\
		advapi.CreateMethod('CheckTokenMembership');\
		advapi.CreateMethod('FreeSid');\
		var NTAuthority = GM.CreateVariable(6);\
		NTAuthority.toBuffer().writeInt8(5, 5);\
		var AdministratorsGroup = GM.CreatePointer();\
		if (advapi.AllocateAndInitializeSid(NTAuthority, 2, 32, 544, 0, 0, 0, 0, 0, 0, AdministratorsGroup).Val != 0)\
		{\
			var member = GM.CreateInteger();\
			if (advapi.CheckTokenMembership(0, AdministratorsGroup.Deref(), member).Val != 0)\
			{\
				if (member.toBuffer().readUInt32LE() != 0) { isroot = true; }\
			}\
			advapi.FreeSid(AdministratorsGroup.Deref());\
		}\
		var reg = require('win-registry');\
		if (isroot)\
		{\
			/* If running as admin, enumerate the users to find proxy settings */\
			var users = reg.QueryKey(reg.HKEY.Users);\
			var keys;\
			for (var i in users.subkeys)\
			{\
				try\
				{\
					value = reg.QueryKey(reg.HKEY.Users, users.subkeys[i] + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 'ProxyEnable');\
					if (value == 1)\
					{\
						value = reg.QueryKey(reg.HKEY.Users, users.subkeys[i] + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 'ProxyServer');\
						servers.push(value);\
					}\
				}\
				catch (e)\
				{\
				}\
			}\
			return (servers);\
		}\
		else\
		{\
			/* We're not admin, so we can only check HKEY_LOCAL_USERS for proxy settings */\
			try\
			{\
				if (reg.QueryKey(reg.HKEY.CurrentUser, 'Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings', 'ProxyEnable') == 1)\
				{\
					servers.push(reg.QueryKey(reg.HKEY.CurrentUser, 'Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings', 'ProxyServer'));\
				}\
			}\
			catch (e)\
			{\
			}\
			return (servers);\
		}\
	})();";

	if (duk_peval_string(agent->meshCoreCtx, getProxy) == 0)
	{
		if (duk_get_length(agent->meshCoreCtx, -1) > 0)		// [array]
		{
			duk_get_prop_index(agent->meshCoreCtx, -1, 0);	// [array][0];
			char *tmp;
			duk_size_t tmpLen;

			tmp = (char*)duk_get_lstring(agent->meshCoreCtx, -1, &tmpLen);
			strncpy_s(buffer, bufferSize, tmp, tmpLen);
			duk_pop(agent->meshCoreCtx);					// [array]
			retVal = (int)tmpLen;
		}
	}
	duk_pop(agent->meshCoreCtx);							// ...

	return(retVal);
#endif
}
#ifdef _POSIX
typedef enum MeshAgent_Posix_PlatformTypes
{
	MeshAgent_Posix_PlatformTypes_UNKNOWN	= 0,
	MeshAgent_Posix_PlatformTypes_SYSTEMD	= 1,
	MeshAgent_Posix_PlatformTypes_INITD		= 2,
	MeshAgent_Posix_PlatformTypes_LAUNCHD	= 3,
}MeshAgent_Posix_PlatformTypes;

size_t MeshAgent_Linux_ReadMemFile(char *path, char **buffer)
{
	size_t i = 0, r, sz = 4096;
	*buffer = NULL;
	FILE *f = fopen(path, "rb");
	if (f != NULL)
	{
		if ((*buffer = malloc(sz)) == NULL) { ILIBCRITICALEXIT(254); }
		while ((r = fread(*buffer + i, 1, sz - i, f)) > 0)
		{
			i += r;
			if (i == sz)
			{
				if ((*buffer = realloc(*buffer, sz + 4096)) == NULL) { ILIBCRITICALEXIT(254); }
				sz += 4096;
			}
		}
		(*buffer)[i] = 0;
		fclose(f);
	}
	return(i);
}
MeshAgent_Posix_PlatformTypes MeshAgent_Posix_GetPlatformType()
{
#ifdef __APPLE__
	return(MeshAgent_Posix_PlatformTypes_LAUNCHD);
#else
	MeshAgent_Posix_PlatformTypes retVal = MeshAgent_Posix_PlatformTypes_UNKNOWN, fini = 0;
	char *status;
	size_t statusLen = MeshAgent_Linux_ReadMemFile("/proc/1/status", &status);
	if (statusLen > 0)
	{
		parser_result *result = ILibParseString(status, 0, (int)statusLen, "\n", 1), *tokens;
		parser_result_field *rf = result->FirstResult;
		while (rf != NULL && fini == 0)
		{
			tokens = ILibParseString(rf->data, 0, rf->datalength, ":", 1);
			if (tokens->NumResults == 2)
			{
				if (tokens->FirstResult->datalength == 4 && strncasecmp(tokens->FirstResult->data, "name", 4) == 0)
				{
					int tlen = tokens->LastResult->datalength;
					char *tstr = tokens->LastResult->data;
					tlen = ILibTrimString(&tstr, tlen);
					if (tlen == 7 && strncasecmp(tstr, "systemd", 5) == 0)
					{
						retVal = MeshAgent_Posix_PlatformTypes_SYSTEMD;
					}
					else if (tlen == 4 && strncasecmp(tstr, "init", 4) == 0)
					{
						retVal = MeshAgent_Posix_PlatformTypes_INITD;
					}
					fini = 1;
				}
			}
			ILibDestructParserResults(tokens);
			rf = rf->NextResult;
		}
		ILibDestructParserResults(result);
		free(status);
	}
	return(retVal);
#endif
}
int MeshAgent_Helper_CommandLine(char **commands, char **result, int *resultLen)
{
	int bytesRead, x;
	size_t sz;
	int inputPipe[2], outputPipe[2];
	pid_t pid;

	if (commands == NULL || result == NULL || resultLen == NULL) { return(-2); }

	ignore_result(pipe(inputPipe));
	ignore_result(pipe(outputPipe));

	pid = vfork();
	if (pid < 0)
	{
		// error;
		close(inputPipe[0]); close(inputPipe[1]);
		close(outputPipe[0]); close(outputPipe[1]);
		return(-1);
	}

	if (pid == 0)
	{
		// child
		close(inputPipe[1]);	// Close Write End of StdIn
		close(outputPipe[0]);	// Close Read End of StdOut
		dup2(inputPipe[0], STDIN_FILENO);
		dup2(outputPipe[1], STDOUT_FILENO);
		dup2(outputPipe[1], STDERR_FILENO);
		close(inputPipe[0]);
		close(outputPipe[1]);

		execv("/bin/sh", (char*[]) {"sh", NULL});
		exit(1);
	}

	// parent
	close(inputPipe[0]);	// Close Read End of StdIn
	close(outputPipe[1]);	// Close Write End of StdOut

	for (int i = 0; commands[i] != NULL; ++i)
	{
		ignore_result(write(inputPipe[1], commands[i], strlen(commands[i])));
	}
	
	x = 0;
	sz = 4096;
	if ((*result = (char*)malloc(sz)) == NULL) { ILIBCRITICALEXIT(254); }
	while ((bytesRead = read(outputPipe[0], *result + x, sz - x)) > 0)
	{
		x += bytesRead;
		if (x == sz)
		{
			if ((*result = realloc(*result, sz + 4096)) == NULL) { ILIBCRITICALEXIT(254); }
			sz += 4096;
		}
	}
	(*result)[x] = 0;
	*resultLen = x;
	waitpid(pid, &bytesRead, 0);
	return(0);
}
int MeshAgent_Helper_IsService()
{
	char *result = NULL;
	int resultLen = 0;
	char pidStr[255];
	int pidStrLen = sprintf_s(pidStr, sizeof(pidStr), "%d", (int)getpid());
	int retVal = 0;

	switch (MeshAgent_Posix_GetPlatformType())
	{
		case MeshAgent_Posix_PlatformTypes_SYSTEMD: // Linux Systemd			
			if (MeshAgent_Helper_CommandLine((char*[]) { "systemctl status meshagent | grep 'Main PID:'\n", "exit\n", NULL }, &result, &resultLen) == 0)
			{
				ILibAppendStringToDiskEx("/tmp/meshagent.log", result, resultLen);
				parser_result *pr = ILibParseString(result, 0, resultLen, "\r\n", 2);
				parser_result_field *f = pr->FirstResult;
				while (f != NULL)
				{
					if (ILibString_StartsWith(f->data, f->datalength, " Main PID:", 10) != 0)
					{
						int sx = ILibString_IndexOf(f->data, f->datalength, ":", 1) + 1;
						int ex = ILibString_IndexOf(f->data, f->datalength, "(", 1) - 1;

						char *syspid = f->data + sx;
						int syspidLen = ILibTrimString(&syspid, ex - sx);
						syspid[syspidLen] = 0;

						if (syspidLen == pidStrLen && strncmp(syspid, pidStr, syspidLen) == 0)
						{
							retVal = 1;
							break;
						}
					}
					f = f->NextResult;
				}
				ILibDestructParserResults(pr);
			}
			break;
		case MeshAgent_Posix_PlatformTypes_LAUNCHD: // MacOS Launchd
			if (MeshAgent_Helper_CommandLine((char*[]) { "launchctl list\n", "exit\n", NULL }, &result, &resultLen) == 0)
			{
				parser_result *pr = ILibParseString(result, 0, resultLen, "\n", 1), *p2;
				parser_result_field *f = pr->FirstResult;
				while (f != NULL)
				{
					if (f->datalength > 0)
					{
						p2 = ILibParseString(f->data, 0, f->datalength, "\t", 1);
						if (p2->NumResults > 1 && p2->FirstResult->datalength == pidStrLen && strncmp(p2->FirstResult->data, pidStr, pidStrLen) == 0)
						{
							retVal = 1;
							ILibDestructParserResults(p2);
							break;
						}
						ILibDestructParserResults(p2);
					}
					f = f->NextResult;
				}
				ILibDestructParserResults(pr);
			}
			break;
		default: // Generic
			// Just check to see if the pid file matches the current pid
			{
				char *diskpid;
				int diskpidLen;
		
				if ((diskpidLen = ILibReadFileFromDiskEx(&diskpid, "/var/run/meshagent.pid")) == 0) { diskpidLen = ILibReadFileFromDiskEx(&diskpid, ".meshagent.pid"); }
				if (diskpidLen != 0 && atoi(diskpid) == atoi(pidStr))
				{
					retVal = 1;
				}
			}
			
			break;
	}
	return(retVal);
}
#endif

#ifdef _REMOTELOGGING
void MeshAgent_Slave_LogForward(ILibRemoteLogging sender, ILibRemoteLogging_Modules module, ILibRemoteLogging_Flags flags, char *buffer, int bufferLen)
{
	SCRIPT_ENGINE_COMMAND_HEADER* header = (SCRIPT_ENGINE_COMMAND_HEADER*)buffer;

	buffer[bufferLen] = 0;
	header->cmdType = SCRIPT_ENGINE_COMMAND_LOG;
	header->length = bufferLen+1;
	((SCRIPT_ENGINE_COMMAND_LOG_DATA*)header->data)->module = module;
	((SCRIPT_ENGINE_COMMAND_LOG_DATA*)header->data)->flags = flags;
#ifdef WIN32
	WriteFile(GetStdHandle(STD_ERROR_HANDLE), (void*)buffer, ((SCRIPT_ENGINE_COMMAND_HEADER*)buffer)->length, &bufferLen, NULL);
#else
	ignore_result(write(STDERR_FILENO, buffer, ((SCRIPT_ENGINE_COMMAND_HEADER*)buffer)->length));
#endif
}
#endif

ILibDuktape_EventEmitter* MeshAgent_GetEventEmitter_FromCTX(duk_context *ctx)
{
	ILibDuktape_EventEmitter* retVal = NULL;
	duk_push_heap_stash(ctx);									// [stash]
	if (duk_has_prop_string(ctx, -1, MESH_AGENT_SINGLETON))
	{
		duk_get_prop_string(ctx, -1, MESH_AGENT_SINGLETON);		// [stash][MeshAgent]
		retVal = ILibDuktape_EventEmitter_GetEmitter(ctx, -1);
		duk_pop_2(ctx);											// ...
	}
	else
	{
		duk_pop(ctx);											// ...
	}
	return retVal;
}

void MeshAgent_Slave_SendCommand(MeshAgentHostContainer *agent, char *buffer, int bufferLen)
{
	if (agent->slaveMode != 0) 
	{
#ifdef WIN32
		int writeLen;
		WriteFile(GetStdHandle(STD_ERROR_HANDLE), (void*)buffer, bufferLen, &writeLen, NULL);
#else
		ignore_result(write(STDERR_FILENO, buffer, bufferLen));
#endif
	}
}

// This is used in windows console mode to detect if Intel LMS is running
#ifdef WIN32
#ifndef _WINSERVICE
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
#else
extern int GetServiceState(LPCSTR servicename);
#endif
#endif

/* ------------------------------
Begin Mesh Agent Multicast Support
This is used only when "MeshServer=local" in .msh policy file
--------------------------------*/

// Called when a UDP packet is received
void UDPSocket_OnData(ILibAsyncUDPSocket_SocketModule socketModule, char* buffer, int bufferLength, struct sockaddr_in6 *remoteInterface, void *user, void *user2, int *PAUSE)
{
	//int isLoopback;
	MeshAgentHostContainer *agentHost = (MeshAgentHostContainer*)user;

	UNREFERENCED_PARAMETER(socketModule);
	UNREFERENCED_PARAMETER(user);
	UNREFERENCED_PARAMETER(user2);
	UNREFERENCED_PARAMETER(PAUSE);

	// Perform basic checks before processing this packet
	if (remoteInterface->sin6_family != AF_INET && remoteInterface->sin6_family != AF_INET6) return;
	//isLoopback = ILibIsLoopback((struct sockaddr*)remoteInterface);

	// Check if this is a Mesh Server discovery packet and it is for our server
	// It will have this form: "MeshCentral2|f5a50091028fe2c122434cbcbd2709a7ec10369295e5a0e43db8853a413d89df|wss://~:443/agent.ashx"
	if ((bufferLength > 78) && (memcmp(buffer, "MeshCentral2|", 13) == 0) && ((ILibSimpleDataStore_Get(agentHost->masterDb, "ServerID", ILibScratchPad, sizeof(ILibScratchPad))) == 97) && (memcmp(ILibScratchPad, buffer + 13, 96) == 0)) {
		// We have a match, set the server URL correctly.
		if (agentHost->multicastServerUrl != NULL) { free(agentHost->multicastServerUrl); agentHost->multicastServerUrl = NULL; }
		if ((agentHost->multicastServerUrl = (char*)malloc(bufferLength - 78 + 128)) == NULL) { ILIBCRITICALEXIT(254); }

		buffer[bufferLength] = 0;
		ILibInet_ntop2((struct sockaddr*)remoteInterface, (char*)ILibScratchPad2, sizeof(ILibScratchPad));
		sprintf_s(agentHost->multicastServerUrl, bufferLength - 78 + 128, buffer + 78 + 32, ILibScratchPad2);

		//printf("FoundServer: %s\r\n", agentHost->multicastServerUrl);
		if (agentHost->serverConnectionState == 0) { MeshServer_ConnectEx(agentHost); }
	}
}

/*
// Called with a 5 second lag time when an interface changes
void IPAddressMonitorUpdate(void *data)
{
	UNREFERENCED_PARAMETER(data);

	// Setup the multicast timer
	//MSG("IPAddressMonitorUpdate.\r\n");


#ifdef WIN32
	// In Windows, just reset the broadcast timer to 15 seconds
	ILibLifeTime_Remove(Mesh.Timer, (void*)2);
	ILibLifeTime_Add(Mesh.Timer, (void*)2, 15, &TimerTriggered, &TimerDestroyed);
#else
	// In Linux, we need to check to see if the push block has changed
	ctrl_GetCurrentSignedNodeInfoBlock(NULL);
	if (Mesh.LastMulticastPushSerial != g_serial)
	{
		Mesh.LastMulticastPushSerial = g_serial;
		ILibLifeTime_Remove(Mesh.Timer, (void*)2);
		ILibLifeTime_Add(Mesh.Timer, (void*)2, 30, &TimerTriggered, &TimerDestroyed);
	}
#endif

	// If the service is not connected, reduce the time to the next attempt to 5 seconds
	if (g_ServiceConnected == 0) {
		ILibLifeTime_Remove(Mesh.Timer, (void*)4);
		ILibLifeTime_Add(Mesh.Timer, (void*)4, 5, &TimerTriggered, &TimerDestroyed);
	}
}

// Method gets periodically executed on the microstack thread to update the list of known IP addresses.
#ifdef WINSOCK2
void CALLBACK IPAddressMonitor
(
	IN DWORD dwError,
	IN DWORD cbTransferred,
	IN LPWSAOVERLAPPED lpOverlapped,
	IN DWORD dwFlags
)
#else
void IPAddressMonitor(void *data)
#endif
{
#ifdef WINSOCK2
	UNREFERENCED_PARAMETER(dwError);
	UNREFERENCED_PARAMETER(cbTransferred);
	UNREFERENCED_PARAMETER(lpOverlapped);
	UNREFERENCED_PARAMETER(dwFlags);
#endif

	// We are in the process of cleaning up, lets exit now
	if (Mesh.MulticastSocket == NULL) return;

#ifdef WINSOCK2
	// Call the interface update with a lag timer. The short lag allows interfaces to stabilize.
	ILibLifeTime_Remove(Mesh.Timer, ILibScratchPad);									// Here we use "ILibScratchPad" as a dummy global identifier, memory not actualy used
	ILibLifeTime_Add(Mesh.Timer, ILibScratchPad, 6, &IPAddressMonitorUpdate, NULL);		// Here we use "ILibScratchPad" as a dummy global identifier, memory not actualy used
	WSAIoctl(NetworkMonitorSocket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &UpnpMonitorSocketReserved, &UpnpMonitorSocketStateObject, &IPAddressMonitor);
#else
	// Call the interface update directly. TODO: This is very innefficient, we need to fix this.
	IPAddressMonitorUpdate(NULL);
	ILibLifeTime_Add(Mesh.Timer, NULL, 20, &IPAddressMonitor, NULL);
#endif
}
*/

/* ------------------------------
Begin Mesh Agent Duktape Abstraction
--------------------------------*/

duk_ret_t ILibDuktape_MeshAgent_AddCommandHandler(duk_context *ctx)
{
	duk_push_this(ctx);							// [agent]
	duk_get_prop_string(ctx, -1, "on");			// [agent][on]
	duk_swap_top(ctx, -2);						// [on][this]
	duk_push_string(ctx, "Command");			// [on][this][Command]
	duk_dup(ctx, 0);							// [on][this][Command][listener]
	duk_call_method(ctx, 2);
	return 0;
}
duk_ret_t ILibDuktape_MeshAgent_AddConnectHandler(duk_context *ctx)
{
	duk_push_this(ctx);							// [agent]
	duk_get_prop_string(ctx, -1, "on");			// [agent][on]
	duk_swap_top(ctx, -2);						// [on][this]
	duk_push_string(ctx, "Connected");			// [on][this][connected]
	duk_dup(ctx, 0);							// [on][this][connected][listener]
	duk_call_method(ctx, 2);
	return 0;
}
duk_ret_t ILibDuktape_MeshAgent_Finalizer(duk_context *ctx)
{
	return 0;
}

duk_ret_t ILibDuktape_MeshAgent_GenerateCertificate(duk_context *ctx)
{
#ifdef MICROSTACK_NOTLS
	return ILibDuktape_Error(ctx, "MeshAgent.generateCertificate(): Error, OpenSSL Support Disabled");
#else
	char *passphrase = (char*)duk_require_string(ctx, 0);
	int len;
	struct util_cert cert;
	char *data;
#ifdef _REMOTELOGGING
	MeshAgentHostContainer *agent;
	duk_push_this(ctx);												// [agent]
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);					// [agent][ptr]
	agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);

	// Generate a new TLS certificate
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Generating JS TLS Certificate");
#endif
	SSL_TRACE1("ILibDuktape_MeshAgent_GenerateCertificate()");
	len = util_mkCert(NULL, &(cert), 3072, 10000, "localhost", CERTIFICATE_TLS_CLIENT, NULL);
	len = util_to_p12(cert, passphrase, &data);

	duk_push_fixed_buffer(ctx, len);
	memcpy_s((void*)Duktape_GetBuffer(ctx, -1, NULL), len, data, len);

	util_free(data);
	util_freecert(&cert);
	SSL_TRACE2("ILibDuktape_MeshAgent_GenerateCertificate()");
	return 1;
#endif
}

// Javascript SendCommand(obj), send some data to the MeshCentral server
// This method can handle buffers, string or objects as input.
duk_ret_t ILibDuktape_MeshAgent_SendCommand(duk_context *ctx)
{
	MeshAgentHostContainer *agent;
	char *buffer;
	duk_size_t bufferLen;

	// Get the pointer to the agent object
	duk_push_this(ctx);									// [MeshAgent]
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);		// [MeshAgent][Ptr]
	agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);
	
	if (agent->controlChannel == NULL)
	{
		duk_push_int(ctx, (int)ILibTransport_DoneState_ERROR); // Agent not connected
	}
#ifndef MICROSTACK_NOTLS
	else if (agent->serverAuthState != 3) {
		// Server connection is not authenticated, SendCommand is not allowed.
		duk_push_int(ctx, (int)ILibTransport_DoneState_ERROR);
	}
#endif
	else if (duk_is_buffer(ctx, 0) || duk_is_buffer_data(ctx, 0))
	{
		// We are trying to send a buffer
		buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
		if (bufferLen > 0) { duk_push_int(ctx, (int)ILibWebClient_WebSocket_Send(agent->controlChannel, buffer[0] == '{' ? ILibWebClient_WebSocket_DataType_TEXT : ILibWebClient_WebSocket_DataType_BINARY, buffer, (int)bufferLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete)); }
		else { duk_push_int(ctx, (int)ILibTransport_DoneState_ERROR); }
	}
	else if (duk_is_string(ctx, 0))
	{
		// We are trying to send a string
		buffer = (char*)duk_get_lstring(ctx, 0, &bufferLen);
		duk_push_int(ctx, (int)ILibWebClient_WebSocket_Send(agent->controlChannel, ILibWebClient_WebSocket_DataType_TEXT, buffer, (int)bufferLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete));
	}
	else
	{
		// We are trying to send an object, perform JSON serialization first
		duk_dup(ctx, 0);							// [object]
		duk_json_encode(ctx, -1);					// [json]
		buffer = (char*)duk_get_lstring(ctx, -1, &bufferLen);
		duk_push_int(ctx, (int)ILibWebClient_WebSocket_Send(agent->controlChannel, ILibWebClient_WebSocket_DataType_TEXT, buffer, (int)bufferLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete));
	}
	return 1;
}

void ILibDuktape_MeshAgent_Ready(ILibDuktape_EventEmitter *sender, char *eventName, void *hookedCallback)
{
	MeshAgentHostContainer *agent;
	duk_push_heapptr(sender->ctx, sender->object);						// [agent]
	duk_get_prop_string(sender->ctx, -1, MESH_AGENT_PTR);				// [MeshAgent][ptr]
	agent = (MeshAgentHostContainer*)duk_get_pointer(sender->ctx, -1);
	duk_pop(sender->ctx);												// [MeshAgent]

	if (agent->controlChannel != NULL)
	{
		// MeshAgent is already 'Ready'
		duk_push_heapptr(sender->ctx, hookedCallback);					// [MeshAgent][callback]
		duk_swap_top(sender->ctx, -2);									// [callback][this]
		if (duk_pcall_method(sender->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(sender->ctx, "Error: MeshAgent_OnReady"); }
	}
	duk_pop(sender->ctx);												// ...
}
#ifdef _LINKVM
ILibTransport_DoneState ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink(char *buffer, int bufferLen, void *reserved)
{
	RemoteDesktop_Ptrs *ptrs = (RemoteDesktop_Ptrs*)reserved;
	if (ptrs->stream != NULL)
	{
		if (ILibDuktape_DuplexStream_WriteData(ptrs->stream, buffer, bufferLen) != ILibTransport_DoneState_ERROR)
		{
			return ILibTransport_DoneState_COMPLETE;		// Always returning complete, because we'll let the stream object handle flow control
		}
		else
		{
			return ILibTransport_DoneState_ERROR;
		}
	}
	return ILibTransport_DoneState_ERROR;
}
ILibTransport_DoneState ILibDuktape_MeshAgent_RemoteDesktop_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
#ifdef _LINKVM
#ifdef WIN32
	kvm_relay_feeddata(buffer, bufferLen, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, user);
#else
#ifdef __APPLE__
	if (((RemoteDesktop_Ptrs*)user)->kvmPipe == NULL)
	{
		// Write to AF_UNIX Domain Socket
		duk_push_external_buffer(stream->writableStream->ctx);														// [ext]
		duk_config_buffer(stream->writableStream->ctx, -1, buffer, (duk_size_t)bufferLen);
		duk_push_heapptr(stream->writableStream->ctx, stream->writableStream->obj);									// [ext][rd]
		duk_get_prop_string(stream->writableStream->ctx, -1, KVM_IPC_SOCKET);										// [ext][rd][IPC]
		duk_get_prop_string(stream->writableStream->ctx, -1, "write");												// [ext][rd][IPC][write]
		duk_swap_top(stream->writableStream->ctx, -2);																// [ext][rd][write][this]
		duk_push_buffer_object(stream->writableStream->ctx, -4, 0, (duk_size_t)bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);// [ext][rd][write][this][buffer]
		if (duk_pcall_method(stream->writableStream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->writableStream->ctx, "Error Writing Data"); }
																													// [ext][rd][ret]
		duk_pop_n(stream->writableStream->ctx, 3);																	// ...
	}
	else
#endif
	{
		kvm_relay_feeddata(buffer, bufferLen);
	}
#endif
#endif
	return ILibTransport_DoneState_COMPLETE;
}
void ILibDuktape_MeshAgent_RemoteDesktop_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	// Peer disconnected the data channel
	RemoteDesktop_Ptrs *ptrs = (RemoteDesktop_Ptrs*)user;
	if (ptrs->ctx != NULL)
	{
		duk_push_heapptr(ptrs->ctx, ptrs->MeshAgentObject);			// [MeshAgent]
		duk_get_prop_string(ptrs->ctx, -1, REMOTE_DESKTOP_STREAM);	// [MeshAgent][RD]
		if (duk_has_prop_string(ptrs->ctx, -1, KVM_IPC_SOCKET))
		{
			duk_get_prop_string(ptrs->ctx, -1, KVM_IPC_SOCKET);		// [MeshAgent][RD][IPC]
			duk_get_prop_string(ptrs->ctx, -1, "end");				// [MeshAgent][RD][IPC][end]
			duk_swap_top(ptrs->ctx, -2);							// [MeshAgent][RD][end][this]
			duk_pcall_method(ptrs->ctx, 0); duk_pop(ptrs->ctx);		// [MeshAgent][RD]

			duk_peval_string(ptrs->ctx, "require('MeshAgent').SendCommand({ 'action': 'msg', 'type' : 'console', 'value' : 'Closing IPC Socket' });"); duk_pop(ptrs->ctx);
		}
		duk_pop(ptrs->ctx);											// [MeshAgent]
		
		duk_del_prop_string(ptrs->ctx, -1, REMOTE_DESKTOP_STREAM);
		duk_pop(ptrs->ctx);											// ...
		memset(ptrs, 0, sizeof(RemoteDesktop_Ptrs));
	}
	kvm_cleanup();
}

void ILibDuktape_MeshAgent_RemoteDesktop_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
	//printf("KVM/PAUSE\n");
#ifdef _POSIX
	if (((RemoteDesktop_Ptrs*)user)->kvmPipe != NULL) { ILibProcessPipe_Pipe_Pause(((RemoteDesktop_Ptrs*)user)->kvmPipe); }
#ifdef __APPLE__
	else
	{
		duk_push_heapptr(sender->writableStream->ctx, sender->writableStream->obj);									// [rd]
		duk_get_prop_string(sender->writableStream->ctx, -1, KVM_IPC_SOCKET);										// [rd][IPC]
		duk_get_prop_string(sender->writableStream->ctx, -1, "pause");												// [rd][IPC][pause]
		duk_swap_top(sender->writableStream->ctx, -2);																// [rd][pause][this]
		duk_pcall_method(sender->writableStream->ctx, 0);															// [rd][ret]
		duk_pop_2(sender->writableStream->ctx);																		// ...
	}
#endif
#else
	kvm_pause(1);
#endif
}
void ILibDuktape_MeshAgent_RemoteDesktop_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	//printf("KVM/RESUME\n");

#ifdef _POSIX
	if (((RemoteDesktop_Ptrs*)user)->kvmPipe != NULL) { ILibProcessPipe_Pipe_Resume(((RemoteDesktop_Ptrs*)user)->kvmPipe); }
#ifdef __APPLE__
	else
	{
		duk_push_heapptr(sender->writableStream->ctx, sender->writableStream->obj);									// [rd]
		duk_get_prop_string(sender->writableStream->ctx, -1, KVM_IPC_SOCKET);										// [rd][IPC]
		duk_get_prop_string(sender->writableStream->ctx, -1, "resume");												// [rd][IPC][resume]
		duk_swap_top(sender->writableStream->ctx, -2);																// [rd][resume][this]
		duk_pcall_method(sender->writableStream->ctx, 0);															// [rd][ret]
		duk_pop_2(sender->writableStream->ctx);																		// ...
	}
#endif
#else
	kvm_pause(0);
#endif
}
duk_ret_t ILibDuktape_MeshAgent_RemoteDesktop_Finalizer(duk_context *ctx)
{
	RemoteDesktop_Ptrs *ptrs;

	duk_get_prop_string(ctx, 0, REMOTE_DESKTOP_ptrs);
	ptrs = (RemoteDesktop_Ptrs*)Duktape_GetBuffer(ctx, -1, NULL);

	if (ptrs->ctx != NULL)
	{
		duk_push_heapptr(ptrs->ctx, ptrs->MeshAgentObject);			// [MeshAgent]
		duk_del_prop_string(ptrs->ctx, -1, REMOTE_DESKTOP_STREAM);
		duk_pop(ptrs->ctx);											// ...
#ifdef _LINKVM
		kvm_cleanup();
#endif
	}
	return 0;
}
void ILibDuktape_MeshAgent_RemoteDesktop_PipeHook(ILibDuktape_readableStream *stream, void *wstream, void *user)
{
#ifdef _LINKVM
#ifdef WIN32
	ILibDuktape_DuplexStream *ds = (ILibDuktape_DuplexStream*)user;
	kvm_relay_reset(ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ds->user);
#else
	kvm_relay_reset();
#endif
#else
	UNREFERENCED_PARAMETER(stream);
	UNREFERENCED_PARAMETER(user);
#endif
}
#endif

int ILibDuktape_MeshAgent_remoteDesktop_unshiftSink(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user)
{
	return(0);
}

#ifdef __APPLE__
duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_EndSink(duk_context *ctx)
{
	MeshAgent_sendConsoleText(ctx, "IPC Connection Closed...");

	duk_push_this(ctx);
	RemoteDesktop_Ptrs *ptrs = (RemoteDesktop_Ptrs*)Duktape_GetPointerProperty(ctx, -1, KVM_IPC_SOCKET);

	// Check to see if there is a user logged in
	if (duk_peval_string(ctx, "require('user-sessions').consoleUid()") == 0)
	{
		int console_uid = duk_get_int(ctx, -1);
		char tmp[255];
		sprintf_s(tmp, sizeof(tmp), "User id: %d has logged in", console_uid);
		MeshAgent_sendConsoleText(ctx, tmp);

		duk_push_heapptr(ctx, ptrs->MeshAgentObject);
		duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);
		MeshAgentHostContainer *agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);

		if (ptrs != NULL && ptrs->ctx != NULL && ptrs->stream != NULL)
		{
			ptrs->kvmPipe = kvm_relay_setup(agent->exePath, agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, console_uid);
		}
	}
	else
	{
		if (ptrs != NULL && ptrs->ctx != NULL && ptrs->stream != NULL)
		{
			ILibDuktape_DuplexStream_WriteEnd(ptrs->stream);
		}
	}


	return(0);
}
duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_DataSink(duk_context *ctx)
{
	duk_push_this(ctx);
	RemoteDesktop_Ptrs *ptrs = (RemoteDesktop_Ptrs*)Duktape_GetPointerProperty(ctx, -1, KVM_IPC_SOCKET);
	char *buffer;
	duk_size_t bufferLen, consumed = 0;
	unsigned short size;

	buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);
	
	// We need to properly frame the data before we propagate it up
	if (bufferLen > 4)
	{
		size = ntohs(((unsigned short*)(buffer))[1]);
		if (size <= bufferLen)
		{
			// We have all the data, to be able to frame it
			consumed = size;
			ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink(buffer, (int)size, ptrs);
		}
	}

	if ((bufferLen - consumed) > 0)
	{
		// We need to unshift() the remainder to continue processing
		duk_push_external_buffer(ctx);														// [ext]
		duk_config_buffer(ctx, -1, buffer, bufferLen - consumed);
		duk_push_this(ctx);																	// [ext][IPC]
		duk_get_prop_string(ctx, -1, "unshift");											// [ext][IPC][unshift]
		duk_swap_top(ctx, -2);																// [ext][unshift][this]
		duk_push_buffer_object(ctx, -3, 0, bufferLen - consumed, DUK_BUFOBJ_NODEJS_BUFFER);	// [ext][unshift][this][buffer]
		duk_call_method(ctx, 1);															// [ext][ret]
	}

	return(0);
}
duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_Sink(duk_context *ctx)
{
	// This is called when we successfully attach an IPC Domain Socket to the Windows Server, running in the LoginWindow context
	RemoteDesktop_Ptrs *ptrs;

	MeshAgent_sendConsoleText(ctx, "IPC Connection Established...");

	duk_push_current_function(ctx);
	ptrs = (RemoteDesktop_Ptrs*)Duktape_GetPointerProperty(ctx, -1, "ptrs");

	duk_push_this(ctx);
	duk_push_pointer(ctx, ptrs); duk_put_prop_string(ctx, -2, KVM_IPC_SOCKET);
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "data", ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_DataSink);
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "end", ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_EndSink);

	return(0);
}
#endif

#if defined(_LINKVM) && defined(_POSIX) && !defined(__APPLE__)
void ILibDuktape_MeshAgent_RemoteDesktop_SendError(RemoteDesktop_Ptrs* ptrs, char *msg)
{
	int msgLen = strnlen_s(msg, 255);
	char buffer[512];

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_ERROR);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)(msgLen + 4));	// Write the size
	memcpy_s(buffer + 4, 512 - 4, msg, msgLen);
	ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink(buffer, msgLen + 4, ptrs);
}
#endif

duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop(duk_context *ctx)
{
#ifndef _LINKVM
	duk_push_null(ctx);
	return 1;
#else
	RemoteDesktop_Ptrs *ptrs;
	MeshAgentHostContainer *agent;

#if !defined(WIN32) && !defined(__APPLE__)
	if (duk_peval_string(ctx, "require('monitor-info')") == 0)
	{
		char *libx11 = Duktape_GetStringPropertyValue(ctx, -1, "Location_X11LIB", NULL);
		char *libx11tst = Duktape_GetStringPropertyValue(ctx, -1, "Location_X11TST", NULL);
		char *libx11ext = Duktape_GetStringPropertyValue(ctx, -1, "Location_X11EXT", NULL);
		kvm_set_x11_locations(libx11, libx11tst, libx11ext);
	}
#endif


	duk_push_this(ctx);											// [MeshAgent]
	if (duk_has_prop_string(ctx, -1, REMOTE_DESKTOP_STREAM))
	{
		duk_get_prop_string(ctx, -1, REMOTE_DESKTOP_STREAM);	// [MeshAgent][RemoteDesktop]
		duk_get_prop_string(ctx, -1, REMOTE_DESKTOP_ptrs);
		ptrs = (RemoteDesktop_Ptrs*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop(ctx);
		return 1;
	}
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);
	agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);
	duk_pop(ctx);

	duk_push_object(ctx);										// [MeshAgent][RemoteDesktop]
	ILibDuktape_WriteID(ctx, "MeshAgent.kvmSession");
	duk_dup(ctx, -1);											// [MeshAgent][RemoteDesktop][RemoteDesktop]
	duk_put_prop_string(ctx, -3, REMOTE_DESKTOP_STREAM);		// [MeshAgent][RemoteDesktop]
	duk_push_fixed_buffer(ctx, sizeof(RemoteDesktop_Ptrs));		// [MeshAgent][RemoteDesktop][buffer]
	ptrs = (RemoteDesktop_Ptrs*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, REMOTE_DESKTOP_ptrs);			// [MeshAgent][RemoteDesktop]
	memset(ptrs, 0, sizeof(RemoteDesktop_Ptrs));
	ptrs->MeshAgentObject = duk_get_heapptr(ctx, -2);
	ptrs->ctx = ctx;
	ptrs->object = duk_get_heapptr(ctx, -1);
	ptrs->stream = ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_MeshAgent_RemoteDesktop_WriteSink, ILibDuktape_MeshAgent_RemoteDesktop_EndSink, ILibDuktape_MeshAgent_RemoteDesktop_PauseSink, ILibDuktape_MeshAgent_RemoteDesktop_ResumeSink, ILibDuktape_MeshAgent_remoteDesktop_unshiftSink, ptrs);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_MeshAgent_RemoteDesktop_Finalizer);
	ptrs->stream->readableStream->PipeHookHandler = ILibDuktape_MeshAgent_RemoteDesktop_PipeHook;
	// Setup Remote Desktop
#ifdef WIN32
	#ifdef _WINSERVICE
		kvm_relay_setup(agent->exePath, agent->runningAsConsole ? NULL : agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs);
	#else
		kvm_relay_setup(agent->exePath, NULL, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs);
	#endif	
#else
	int console_uid = 0;
	if (duk_peval_string(ctx, "require('user-sessions').consoleUid();") == 0) { console_uid = duk_get_int(ctx, -1); }
	duk_pop(ctx);

	#ifdef __APPLE__
		// MacOS
		if (console_uid == 0)
		{
			MeshAgent_sendConsoleText(ctx, "Establishing IPC-x-Connection to LoginWindow for KVM");
			char *ipc = (char*)kvm_relay_setup(agent->exePath, agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, console_uid);
			duk_eval_string(ctx, "require('net');");														// [rd][net]
			duk_get_prop_string(ctx, -1, "createConnection");												// [rd][net][createConnection]
			duk_swap_top(ctx, -2);																			// [rd][createConnection][this]
			duk_push_object(ctx);																			// [rd][createConnection][this][options]
			duk_push_string(ctx, ipc); duk_put_prop_string(ctx, -2, "path");								// [rd][createConnection][this][options]
			duk_push_c_function(ctx, ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_Sink, DUK_VARARGS);	// [rd][createConnection][this][options][callback]
			duk_push_pointer(ctx, ptrs); duk_put_prop_string(ctx, -2, "ptrs");
			duk_call_method(ctx, 2);																		// [rd][icpSocket]
			duk_put_prop_string(ctx, -2, KVM_IPC_SOCKET);													// [rd]
			//ptrs->kvmDomainSocket = (int)(uint64_t)kvm_relay_setup(agent->exePath, agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, console_uid);
		}
		else
		{
			MeshAgent_sendConsoleText(ctx, "Spawning User Process for KVM");
			ptrs->kvmPipe = kvm_relay_setup(agent->exePath, agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, console_uid);
		}
	#else
		// For Linux, we need to determine where the XAUTHORITY is:
		char *updateXAuth = NULL;
		int needPop = 0;
		if (getenv("XAUTHORITY") == NULL)
		{
			if (duk_peval_string(ctx, "(function getAuthToken()\
			{\
				var child = require('child_process').execFile('/bin/sh', ['sh']);\
				child.stdout.str = '';\
				child.stdin.write('ps -e -o user -o command | awk {\\'printf \"%s,\",$1;$1=\"\";printf \"%s\\\\n\", $0\\'} | grep X\\nexit\\n');\
				child.stdout.on('data', function(chunk) { this.str += chunk.toString(); });\
				child.waitExit();\
				var lines = child.stdout.str.split('\\n');\
				for (var i in lines) {\
					var tokens = lines[i].split(',');\
					if (tokens[0]) {\
						var items = tokens[1].split(' ');\
						for (var x = 0; x < items.length; ++x) {\
							if (items[x] == '-auth' && items.length >(x + 1)) {\
								return (items[x + 1]);\
							}\
						}\
					}\
				}\
				return (null);\
			})();") == 0)
			{
				updateXAuth = (char*)duk_get_string(ctx, -1);
				if (console_uid != 0 && updateXAuth == NULL)
				{
					ILibDuktape_MeshAgent_RemoteDesktop_SendError(ptrs, "Xauthority not found! Is your DM configured to use X?");
					duk_pop(ctx);
					return(1);
				}
			}
			needPop = 1;
		}
		ptrs->kvmPipe = kvm_relay_setup(agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, console_uid, updateXAuth);
		if (needPop!= 0) {duk_pop(ctx); }
	#endif
#endif
	return 1;
#endif
}
duk_ret_t ILibDuktape_MeshAgent_ConnectedServer(duk_context *ctx)
{
	int len;
	MeshAgentHostContainer *agent;
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);
	agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);
#ifndef MICROSTACK_NOTLS
	if (agent->controlChannel != NULL && agent->serverAuthState == 3)
#else
	if (agent->controlChannel != NULL)
#endif
	{
		len = ILibSimpleDataStore_Get(agent->masterDb, "MeshServer", ILibScratchPad2, sizeof(ILibScratchPad2));
		if (len == 0) { duk_push_null(ctx); return 1; }

		parser_result *rs = ILibParseString(ILibScratchPad2, 0, len, ",", 1);
		parser_result_field *f = ILibParseString_GetResultIndex(rs, agent->serverIndex);
		f->datalength = ILibTrimString(&(f->data), f->datalength);
		f->data[f->datalength] = 0;

		duk_push_lstring(ctx, f->data, f->datalength);
		ILibDestructParserResults(rs);
	}
	else
	{
		duk_push_null(ctx);
	}
	return 1;
}

duk_ret_t ILibDuktape_MeshAgent_NetInfo(duk_context *ctx)
{
#ifdef __APPLE__
	duk_push_null(ctx);
	return(1);
#else
	char *data;
	int len = MeshInfo_GetSystemInformation(&data);
	if (len > 0)
	{
		duk_push_lstring(ctx, data, len);
		duk_json_decode(ctx, -1);
		free(data);
	}
	else
	{
		duk_push_null(ctx);
	}
	return 1;
#endif
}

// Javascript ExecPowerState(int), executes power state command on the computer (Sleep, Hibernate...)
duk_ret_t ILibDuktape_MeshAgent_ExecPowerState(duk_context *ctx)
{
#ifdef __APPLE__
	duk_push_null(ctx);
#else
	int force = 0;
	int numArgs = (int)duk_get_top(ctx);
	duk_push_this(ctx);	// [MeshAgent]

	if (numArgs == 2 && duk_is_number(ctx, 1)) { force = duk_get_int(ctx, 1); }
	if (duk_is_number(ctx, 0))
	{
		duk_push_int(ctx, MeshInfo_PowerState((AgentPowerStateActions)duk_get_int(ctx, 0), force));
	}
	else
	{
		duk_push_null(ctx);
	}
#endif
	return 1;
}

duk_ret_t ILibDuktape_MeshAgent_ServerUrl(duk_context *ctx)
{
	duk_push_this(ctx);											// [MeshAgent]
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);				// [MeshAgent][ptr]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);

	duk_push_string(ctx, agent->serveruri);						// [MeshAgent][ptr][uri]
	return(1);
}
duk_ret_t ILibDuktape_MeshAgent_isControlChannelConnected(duk_context *ctx)
{
	duk_push_this(ctx);								// [agent]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);

	if (agent != NULL)
	{
		duk_push_boolean(ctx, agent->serverAuthState == 3 ? 1 : 0);
		return(1);
	}
	else
	{
		return(0);
	}
}
duk_ret_t ILibDuktape_MeshAgent_eval(duk_context *ctx)
{
	duk_size_t evalStrLen;
	char *evalStr = (char*)duk_get_lstring(ctx, 0, &evalStrLen);

	printf("eval(): %s\n", evalStr);
	duk_eval_string(ctx, evalStr);
	return(1);
}
duk_context* ScriptEngine_Stop(MeshAgentHostContainer *agent, char *contextGUID);

void ILibDuktape_MeshAgent_dumpCoreModuleEx(void *chain, void *user)
{
	MeshAgentHostContainer* agentHost = (MeshAgentHostContainer*)user;
	char *CoreModule;

	ScriptEngine_Stop((MeshAgentHostContainer*)user, MeshAgent_JavaCore_ContextGuid);
	printf("CoreModule was manually dumped, restarting!\n");

	int CoreModuleLen = ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", NULL, 0);
	if (CoreModuleLen > 0)
	{
		// There is a core module, launch it now.
		CoreModule = (char*)ILibMemory_Allocate(CoreModuleLen, 0, NULL, NULL);
		ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", CoreModule, CoreModuleLen);

		if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(agentHost->meshCoreCtx, CoreModule + 4, CoreModuleLen - 4, "CoreModule.js", 13) != 0 ||
			ILibDuktape_ScriptContainer_ExecuteByteCode(agentHost->meshCoreCtx) != 0)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
				ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: %s", duk_safe_to_string(agentHost->meshCoreCtx, -1));
			duk_pop(agentHost->meshCoreCtx);
		}
		free(CoreModule);
	}
	agentHost->localScript = 1;
}
duk_ret_t ILibDuktape_MeshAgent_dumpCoreModule(duk_context *ctx)
{
	duk_push_this(ctx);								// [agent]
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);	// [agent][ptr]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);

	agent->localScript = 0;
	ILibChain_RunOnMicrostackThreadEx(agent->chain, ILibDuktape_MeshAgent_dumpCoreModuleEx, agent);
	return(0);
}
void ILibDuktape_MeshAgent_ConnectedHook(ILibDuktape_EventEmitter *sender, char *eventName, void *hookedCallback)
{
	int top = duk_get_top(sender->ctx);
	duk_push_heapptr(sender->ctx, hookedCallback);			// [cb]
	duk_push_heapptr(sender->ctx, sender->object);			// [cb][this]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(sender->ctx, -1, MESH_AGENT_PTR);
	if (agent->serverAuthState == 3)
	{
		duk_push_int(sender->ctx, 1);						// [cb][this][1]
		duk_pcall_method(sender->ctx, 1);
	}
	duk_set_top(sender->ctx, top);
}
void ILibDuktape_MeshAgent_PUSH(duk_context *ctx, void *chain)
{
	MeshAgentHostContainer *agent;
	ILibDuktape_EventEmitter *emitter;

	duk_push_heap_stash(ctx);									// [stash]
	if (duk_has_prop_string(ctx, -1, MESH_AGENT_SINGLETON))
	{
		duk_get_prop_string(ctx, -1, MESH_AGENT_SINGLETON);		// [stash][MeshAgent]
		duk_swap_top(ctx, -2);									// [MeshAgent][stash]
		duk_pop(ctx);											// [MeshAgent]
		return;
	}

	duk_get_prop_string(ctx, -1, "MeshAgentPtr");				// [stash][agentPtr]
	agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);

	duk_pop_2(ctx);												// ...
	duk_push_object(ctx);										// [MeshAgent]
	ILibDuktape_WriteID(ctx, "MeshAgent");
	duk_push_pointer(ctx, agent);								// [MeshAgent][ptr]
	duk_put_prop_string(ctx, -2, MESH_AGENT_PTR);				// [MeshAgent]

	duk_push_heap_stash(ctx);									// [MeshAgent][stash]
	duk_dup(ctx, -2);											// [MeshAgent][stash][MeshAgent]
	duk_put_prop_string(ctx, -2, MESH_AGENT_SINGLETON);			// [MeshAgent][stash]
	duk_pop(ctx);												// [MeshAgent]

	emitter = ILibDuktape_EventEmitter_Create(ctx);

	if (agent->slaveMode == 0)
	{
#ifndef MICROSTACK_NOTLS
		if (agent->selftlscert.x509 != NULL) {
			// We have a TLS certificate, use it for WebRTC
			duk_push_pointer(ctx, &agent->selftlscert);
			duk_put_prop_string(ctx, -2, ILibDuktape_MeshAgent_Cert_Server);
		} else {
			// We don't have a TLS certificate, use the root cert for WebRTC
			duk_push_pointer(ctx, &agent->selfcert);
			duk_put_prop_string(ctx, -2, ILibDuktape_MeshAgent_Cert_Server);
		}
		// Always use the root cert for agent authentication
		duk_push_pointer(ctx, &agent->selfcert);
		duk_put_prop_string(ctx, -2, ILibDuktape_MeshAgent_Cert_NonLeaf);
#endif

		ILibDuktape_EventEmitter_CreateEventEx(emitter, "Ready");
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "Connected");
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "Command");
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "DesktopSessionChanged");
		ILibDuktape_EventEmitter_AddHook(emitter, "Connected", ILibDuktape_MeshAgent_ConnectedHook);


		ILibDuktape_CreateEventWithGetter(ctx, "isControlChannelConnected", ILibDuktape_MeshAgent_isControlChannelConnected);
		ILibDuktape_EventEmitter_AddHook(emitter, "Ready", ILibDuktape_MeshAgent_Ready);
		ILibDuktape_CreateEventWithGetter(ctx, "ConnectedServer", ILibDuktape_MeshAgent_ConnectedServer);
		ILibDuktape_CreateEventWithGetter(ctx, "ServerUrl", ILibDuktape_MeshAgent_ServerUrl);
		ILibDuktape_CreateInstanceMethod(ctx, "getRemoteDesktopStream", ILibDuktape_MeshAgent_getRemoteDesktop, 0);
		ILibDuktape_CreateInstanceMethod(ctx, "AddCommandHandler", ILibDuktape_MeshAgent_AddCommandHandler, 1);
		ILibDuktape_CreateInstanceMethod(ctx, "AddConnectHandler", ILibDuktape_MeshAgent_AddConnectHandler, 1);
		ILibDuktape_CreateInstanceMethod(ctx, "SendCommand", ILibDuktape_MeshAgent_SendCommand, 1);
		ILibDuktape_CreateFinalizer(ctx, ILibDuktape_MeshAgent_Finalizer);
		ILibDuktape_CreateReadonlyProperty_int(ctx, "activeMicroLMS", (agent->microLMS != NULL ? 1 : 0));
		ILibDuktape_CreateInstanceMethod(ctx, "restartCore", ILibDuktape_MeshAgent_dumpCoreModule, 0);
#ifdef _LINKVM 
		ILibDuktape_CreateReadonlyProperty_int(ctx, "hasKVM", 1);
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "kvmConnected");
#else
		ILibDuktape_CreateReadonlyProperty_int(ctx, "hasKVM", 0);
#endif

		ILibDuktape_CreateEventWithGetter(ctx, "NetInfo", ILibDuktape_MeshAgent_NetInfo);
		ILibDuktape_CreateInstanceMethod(ctx, "ExecPowerState", ILibDuktape_MeshAgent_ExecPowerState, DUK_VARARGS);
		ILibDuktape_CreateInstanceMethod(ctx, "eval", ILibDuktape_MeshAgent_eval, 1);

		Duktape_CreateEnum(ctx, "ContainerPermissions", (char*[]) { "DEFAULT", "NO_AGENT", "NO_MARSHAL", "NO_PROCESS_SPAWNING", "NO_FILE_SYSTEM_ACCESS", "NO_NETWORK_ACCESS" }, (int[]) { 0x00, 0x10000000, 0x08000000, 0x04000000, 0x00000001, 0x00000002 }, 6);
	}

	ILibDuktape_CreateInstanceMethod(ctx, "GenerateCertificate", ILibDuktape_MeshAgent_GenerateCertificate, 1);
	duk_push_pointer(ctx, agent->masterDb); duk_put_prop_string(ctx, -2, "\xFF_MasterDB");

	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "Acquired MeshAgent");
}
void ILibDuktape_MeshAgent_Init(duk_context* ctx, void *chain, MeshAgentHostContainer *agent)
{
	duk_push_heap_stash(ctx);						// [stash]
	duk_push_pointer(ctx, agent);					// [stash][agentPtr]
	duk_put_prop_string(ctx, -2, "MeshAgentPtr");	// [stash]
	duk_pop(ctx);									// ...
	ILibDuktape_ModSearch_AddHandler(ctx, "MeshAgent", ILibDuktape_MeshAgent_PUSH);
}

/* ------------------------------ 

End Mesh Agent Duktape Abstraction
	
--------------------------------*/

// !!!WARNING!!!: The result of this method is stored in ILibScratchPad2
char* MeshAgent_MakeAbsolutePath(char *basePath, char *localPath)
{
	size_t localPathLen = strnlen_s(localPath, sizeof(ILibScratchPad2));
	size_t basePathLen = strnlen_s(basePath, sizeof(ILibScratchPad2));
	int i, sz;
	if (localPath[0] == '.')
	{
		// Use Same executable Name, but different extension
		sz = (int)basePathLen;
		if (sz>=4 && ntohl(((unsigned int*)(basePath + sz - 4))[0]) == EXE_IDENTIFIER)
		{
			// BasePath ends with .exe
			memcpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), basePath, sz - 4);
			memcpy_s(ILibScratchPad2 + sz - 4, sizeof(ILibScratchPad2) - sz - 4, localPath, localPathLen);
			sz = sz - 4 + (int)localPathLen;
		}
		else
		{
			// BasePath does not end with .exe
			memcpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), basePath, sz);
			memcpy_s(ILibScratchPad2 + sz, sizeof(ILibScratchPad2) - sz, localPath, localPathLen);
			sz += (int)localPathLen;
		}
		ILibScratchPad2[sz] = 0;
	}
	else
	{
		if ((i = ILibString_LastIndexOf(basePath, (int)basePathLen, "\\", 1)) < 0) { i = ILibString_LastIndexOf(basePath, (int)basePathLen, "/", 1); }
		
		i += 1;
		sz = i + (int)localPathLen;
		memcpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), basePath, i);
		memcpy_s(ILibScratchPad2 + i, sizeof(ILibScratchPad2) - i, localPath, localPathLen);
		ILibScratchPad2[sz] = 0;
	}
	return ILibScratchPad2;
}

#ifndef MICROSTACK_NOTLS
int agent_GenerateCertificates(MeshAgentHostContainer *agent, char* certfile)
{
	int len = -1;
	char* str;

	// Clear the certs in the database.
	ILibSimpleDataStore_Delete(agent->masterDb, "SelfNodeCert");
	ILibSimpleDataStore_Delete(agent->masterDb, "SelfNodeTlsCert");
	util_freecert(&(agent->selfcert));
	util_freecert(&(agent->selftlscert));

	if (certfile == NULL)
	{
#if defined(WIN32)
		if (wincrypto_open(TRUE) == 0) // Force certificate re-generation
		{
			int l;
			do {
				// Finish off work with our own certificate
				l = wincrypto_getcert(&str);
				if (l > 0)
				{
					util_from_cer(str, l, &(agent->selfcert));
					util_keyhash(agent->selfcert, agent->g_selfid);
					if (((int*)agent->g_selfid)[0] == 0) { wincrypto_close(); wincrypto_open(1); }
				}
			} while (l != 0 && ((int*)agent->g_selfid)[0] == 0); // This removes any chance that the self_id starts with 32 bits of zeros.

			if (l > 0)
			{
				// Generate a new TLS certificate & save it.
				l = wincrypto_mkCert(L"CN=localhost", CERTIFICATE_TLS_SERVER, L"hidden", &str);
				util_from_p12(str, l, "hidden", &(agent->selftlscert));
				ILibSimpleDataStore_PutEx(agent->masterDb, "SelfNodeTlsCert", 15, str, l);
				util_free(str);
				return 0;
			}
		} else {
#endif
			// Generate a new self-signed root certificate for this node using OpenSSL
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Generating new Node Certificate");
			printf("Generating Certificate...\r\n");
			do
			{
				SSL_TRACE1("agent_GenerateCertificates()");
				if (util_mkCert(NULL, &(agent->selfcert), 3072, 10000, "MeshNodeCertificate", CERTIFICATE_ROOT, NULL) == 0)
				{
					SSL_TRACE2("agent_GenerateCertificates()");
					return -1;
				}
				util_keyhash(agent->selfcert, agent->g_selfid);
				SSL_TRACE2("agent_GenerateCertificates()");
			} while (((int*)agent->g_selfid)[0] == 0); // This removes any chance that the self_id starts with 32 bits of zeros.
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...g_selfid = %s", ILibRemoteLogging_ConvertToHex(agent->g_selfid, (int)sizeof(agent->g_selfid)));
#if defined(WIN32)
			wincrypto_setregistry(L"KeyStore", L"None");
		}
#endif
	}
	else
	{
		// Load a node certificate from a PEM file
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Loading Node Cert from PEM file");
		SSL_TRACE1("ILibDuktape_MeshAgent_GenerateCertificate_FromFile()");

		if (util_from_pem(certfile, &(agent->selfcert)) == -1)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "......*ERROR*");
			SSL_TRACE2("ILibDuktape_MeshAgent_GenerateCertificate_FromFile([ERROR])");
			return -1;
		}
		util_keyhash(agent->selfcert, agent->g_selfid);
		if (((int*)agent->g_selfid)[0] == 0)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "......g_selfid = *ERROR*");
			SSL_TRACE2("ILibDuktape_MeshAgent_GenerateCertificate_FromFile([ERROR])");
			return -1; // This removes any chance that the self_id starts with 32 bits of zeros.
		}
		SSL_TRACE2("ILibDuktape_MeshAgent_GenerateCertificate_FromFile()");
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...g_selfid = %s", ILibRemoteLogging_ConvertToHex(agent->g_selfid, (int)sizeof(agent->g_selfid)));
	}

	SSL_TRACE1("ILibDuktape_MeshAgent_GenerateCertificate(SelfNodeCert)");
	len = util_to_p12(agent->selfcert, "hidden", &str);
	ILibSimpleDataStore_PutEx(agent->masterDb, "SelfNodeCert", 12, str, len);
	util_free(str);
	SSL_TRACE2("ILibDuktape_MeshAgent_GenerateCertificate(SelfNodeCert)");

	/*
	// If the root certificate is generated in the TPM, generate a new TLS certificate
	SSL_TRACE1("ILibDuktape_MeshAgent_GenerateCertificate(SelfNodeTlsCert)");
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Generating TLS Certificate");
	len = util_mkCert(&(agent->selfcert), &(agent->selftlscert), 3072, 10000, "localhost", CERTIFICATE_TLS_SERVER, NULL);
	len = util_to_p12(agent->selftlscert, "hidden", &str);
	ILibSimpleDataStore_PutEx(agent->masterDb, "SelfNodeTlsCert", 15, str, len);
	util_free(str);
	SSL_TRACE2("ILibDuktape_MeshAgent_GenerateCertificate(SelfNodeTlsCert)");
	*/

	// If we don't use TPM, we can skip generating the TLS cert.
	agent->selftlscert.flags = 0;
	agent->selftlscert.x509 = NULL;
	agent->selftlscert.pkey = NULL;

	MSG("Certificates ready.\r\n");
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...READY");
	return 0;
}
int agent_LoadCertificates(MeshAgentHostContainer *agent)
{
	int len;

	SSL_TRACE1("agent_LoadCertificates()");

	//printf("Loading Certificates...\r\n");

	// First, look to see if we have a certificate in the .db file, if we do, use that.
	len = ILibSimpleDataStore_Get(agent->masterDb, "SelfNodeCert", ILibScratchPad2, sizeof(ILibScratchPad2));
	if (len == 0 || util_from_p12(ILibScratchPad2, len, "hidden", &(agent->selfcert)) == 0)
	{
#if defined(WIN32)
		// No cert in this .db file. Try to load or generate a root certificate from a Windows crypto provider. This can be TPM backed which is great.
		if (wincrypto_open(FALSE) == 0)
		{
			char* str = NULL;
			int l;
			
			do {
				// Finish off work with our own certificate
				l = wincrypto_getcert(&str);
				if (l > 0)
				{
					util_from_cer(str, l, &(agent->selfcert));
					util_keyhash(agent->selfcert, agent->g_selfid);
					if (((int*)agent->g_selfid)[0] == 0) { wincrypto_open(TRUE); } // Force generation of a new certificate.
				}
			} while (l != 0 && ((int*)agent->g_selfid)[0] == 0); // This removes any chance that the self_id starts with 32 bits of zeros.

			if (l > 0)
			{
				// Load the TLS certificate from the database. If not present, generate one.
				len = ILibSimpleDataStore_Get(agent->masterDb, "SelfNodeTlsCert", ILibScratchPad2, sizeof(ILibScratchPad2));
				if ((len != 0) && (util_from_p12(ILibScratchPad2, len, "hidden", &(agent->selftlscert)) == 0)) { len = 0; } // Unable to decode this certificate
				if (agent_VerifyMeshCertificates(agent) != 0) { len = 0; } // Check that the load TLS cert is signed by our root.
				if (len == 0) {
					// Generate a new TLS certificate & save it.
					util_freecert(&(agent->selftlscert));
					l = wincrypto_mkCert(L"CN=localhost", CERTIFICATE_TLS_SERVER, L"hidden", &str);
					if (l > 0) {
						util_from_p12(str, l, "hidden", &(agent->selftlscert));
						ILibSimpleDataStore_PutEx(agent->masterDb, "SelfNodeTlsCert", 15, str, l);
					}
					util_free(str);
					if (l <= 0) { return 1; } // Problem generating the TLS cert, reset everything.
				}
				return 0; // All good. We loaded or generated a root agent cert and TLS cert.
			}
		}
#endif

		// No certificate in the database. Return 1 here so we can generate one.
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Failed to load Node Certificate from Database");
		SSL_TRACE2("agent_LoadCertificates([ERROR: SelfNodeCert])");
		return 1;
	}

	// Try to load the TLS certificate
	len = ILibSimpleDataStore_Get(agent->masterDb, "SelfNodeTlsCert", ILibScratchPad2, sizeof(ILibScratchPad2));
	if (len != 0)
	{
		// If the TLS certificate is in the database, load it. If not, it's ok to skip this.
		if (util_from_p12(ILibScratchPad2, len, "hidden", &(agent->selftlscert)) == 0) {
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Failed to load TLS Certificate from Database");
			util_freecert(&(agent->selfcert));
			SSL_TRACE2("agent_LoadCertificates([ERROR: SelfNodeTlsCert])");
			return 1;
		}
	}

	// Compute this agent's nodeid.
	util_keyhash(agent->selfcert, agent->g_selfid);
	SSL_TRACE2("agent_LoadCertificates()");

	return 0;
}

int agent_VerifyMeshCertificates(MeshAgentHostContainer *agent)
{
	X509_STORE *store;
	X509_STORE_CTX *ctx;
	int i = 0;

	SSL_TRACE1("agent_VerifyMeshCertificates()");
	if (agent->selftlscert.x509 == NULL) { return 0; } // There is no TLS certificate, no verification needed.

	// Check that the TLS certificate and TLS client certificate are correctly signed by our Mesh Agent certificate
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Verifying TLS Certificates are signed by Mesh Agent Certificate");
	store = X509_STORE_new();
	X509_STORE_add_cert(store, agent->selfcert.x509);

	ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, agent->selftlscert.x509, NULL);
	i = X509_verify_cert(ctx);
	X509_STORE_CTX_free(ctx);

	X509_STORE_free(store);

	// If the certificate chain is not correct, re-create all the certificates.
	if (i != 1)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "......INVALID TLS Server Certificate");
	}
	SSL_TRACE2("agent_VerifyMeshCertificates()");

	if (i != 1) { return 1; } // Bad certificates
	return 0;
}
#endif



void WritePipeResponse(AGENT_RECORD_TYPE recordType, JS_ENGINE_CONTEXT engineContext, char *payload, int payloadLength)
{
#ifdef WIN32
	int tmpLen;
#endif
	AGENT_RECORD_HEADER *header = (AGENT_RECORD_HEADER*)ILibScratchPad2;
	header->RecordType = recordType;
	header->RecordLength = sizeof(AGENT_RECORD_HEADER) + payloadLength;
	memcpy_s(header->Context, sizeof(JS_ENGINE_CONTEXT), engineContext, sizeof(JS_ENGINE_CONTEXT));
	if (payloadLength > 0)
	{
		memcpy_s(header->Payload, sizeof(ILibScratchPad2) - sizeof(AGENT_RECORD_HEADER), payload, payloadLength);
	}

#ifdef WIN32
	WriteFile(GetStdHandle(STD_ERROR_HANDLE), header, header->RecordLength, &tmpLen, NULL);
#else
	ignore_result(write(STDERR_FILENO, header, header->RecordLength));
#endif
}




void ScriptEngine_Exit(MeshAgentHostContainer *agent, char *contextGUID, int exitCode)
{
	duk_context *ctx = agent->meshCoreCtx;
	if (ctx != NULL)
	{
		void *procObj = ILibDuktape_GetProcessObject(ctx);
		duk_push_heapptr(ctx, procObj);				// [process]
		duk_get_prop_string(ctx, -1, "exit");		// [process][exitFunc]
		duk_swap_top(ctx, -2);						// [exitFunc][this/process]
		duk_push_int(ctx, exitCode);				// [exitFunc][this/process][exitCode]
		duk_pcall_method(ctx, 1);					// [retVal]
		duk_pop(ctx);								// ...
	}
}

duk_context* ScriptEngine_Stop(MeshAgentHostContainer *agent, char *contextGUID)
{
	duk_context *oldCtx = agent->meshCoreCtx;
	agent->meshCoreCtx = NULL;
	SCRIPT_ENGINE_SETTINGS *settings = ILibDuktape_ScriptContainer_GetSettings(oldCtx);
	duk_context *newCtx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx2(settings);
	ILibDuktape_MeshAgent_Init(newCtx, agent->chain, agent);

	ILibDuktape_SetNativeUncaughtExceptionHandler(newCtx, settings->nExeptionHandler, settings->nExceptionUserObject);
	if (g_displayFinalizerMessages) { printf("\n\n==> Stopping JavaScript Engine\n"); }
	duk_destroy_heap(oldCtx);
	agent->meshCoreCtx = newCtx;
	if (agent->proxyServer != NULL)
	{
		memcpy_s(&(ILibDuktape_GetNewGlobalTunnel(agent->meshCoreCtx)->proxyServer), sizeof(struct sockaddr_in6), agent->proxyServer, sizeof(struct sockaddr_in6));
	}

	return(newCtx);
}
char* ScriptEngine_Restart(MeshAgentHostContainer *agent, char *contextGUID, char *buffer, int bufferLen)
{
	duk_context *ctx = ScriptEngine_Stop(agent, contextGUID);
	
	if (ctx != NULL) 
	{ 
		if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(ctx, buffer, bufferLen, "CoreModule.js", 13) != 0 || ILibDuktape_ScriptContainer_ExecuteByteCode(ctx) != 0)
		{
			sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "%s", (char*)duk_safe_to_string(ctx, -1));
			duk_pop(ctx);
			return(ILibScratchPad);
		}
		return(NULL);
	}
	else
	{
		return "Restart Failed, because Script Engine Stop failed";
	}
}

void MeshAgent_Slave_HeapWasDestroyed(duk_context *ctx, void *user)
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user;
	agent->exitCode = ILibDuktape_Process_GetExitCode(ctx);
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshAgent_Slave: Engine has exited");
	ILibStopChain(agent->chain);
}


// Called when we can now send more data to MeshCentral
void MeshServer_OnSendOK(ILibWebClient_StateObject sender, void *user1, void *user2)
{
	// TODO: Inform JavaScript core module that we are in underflow situation
}


int GenerateSHA384FileHash(char *filePath, char *fileHash)
{
	FILE *tmpFile = NULL;
	unsigned int endIndex = 0;
	unsigned int bytesLeft = 0;
	size_t bytesRead;
	unsigned int checkSumIndex = 0;
	unsigned int tableIndex = 0;

#ifdef WIN32
	int retVal = 1;
	fopen_s(&tmpFile, filePath, "rb");
#else
	tmpFile = fopen(filePath, "rb");
#endif
	if (tmpFile == NULL) { return(1); }

#ifdef WIN32
	// We need to check if this is a signed binary
	// Read the PE Headers, to determine where to look for the Embedded JS
	char *optHeader = NULL;
	unsigned int NTHeaderIndex = 0;
	fseek(tmpFile, 0, SEEK_SET);
	ignore_result(fread(ILibScratchPad, 1, 2, tmpFile));
	if (ntohs(((unsigned int*)ILibScratchPad)[0]) == 19802) // 5A4D
	{
		fseek(tmpFile, 60, SEEK_SET);
		ignore_result(fread((void*)&NTHeaderIndex, 1, 4, tmpFile));
		fseek(tmpFile, NTHeaderIndex, SEEK_SET);					// NT HEADER
		checkSumIndex = NTHeaderIndex + 24 + 64;

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
					endIndex = ((unsigned int*)(optHeader + 128))[0];
				}
				tableIndex = NTHeaderIndex + 24 + 128;
				retVal = 0;
				break;
			case 0x20B:
				if (((unsigned int*)(optHeader + 144))[0] != 0)
				{
					endIndex = ((unsigned int*)(optHeader + 144))[0];
				}
				tableIndex = NTHeaderIndex + 24 + 144;
				retVal = 0;
				break;
			default:
				break;
			}
		}
	}
	if (retVal != 0)
	{
		fclose(tmpFile);
		return(1);
	}
#endif

	if (endIndex == 0)
	{
		// We just need to check for Embedded MSH file
		int mshLen = 0;
		fseek(tmpFile, -16, SEEK_END);
		ignore_result(fread(ILibScratchPad, 1, 16, tmpFile));
		if (memcmp(ILibScratchPad, exeMeshPolicyGuid, 16) == 0)
		{
			fseek(tmpFile, -20, SEEK_CUR);
			ignore_result(fread((void*)&mshLen, 1, 4, tmpFile));
			mshLen = ntohl(mshLen);
			endIndex = (unsigned int)ftell(tmpFile) - 4 - mshLen;
		}
		else
		{
			endIndex = (unsigned int)ftell(tmpFile);
		}
	}

	SHA512_CTX ctx;
	SHA384_Init(&ctx);
	bytesLeft = endIndex;
	fseek(tmpFile, 0, SEEK_SET);
	if (checkSumIndex != 0)
	{
		bytesRead = fread(ILibScratchPad, 1, checkSumIndex + 4, tmpFile);
		((unsigned int*)(ILibScratchPad + checkSumIndex))[0] = 0;
		SHA384_Update(&ctx, ILibScratchPad, bytesRead);
		if (endIndex > 0) { bytesLeft -= (unsigned int)bytesRead; }

		bytesRead = fread(ILibScratchPad, 1, tableIndex + 8 - (checkSumIndex + 4), tmpFile);
		((unsigned int*)(ILibScratchPad + bytesRead - 8))[0] = 0;
		((unsigned int*)(ILibScratchPad + bytesRead - 8))[1] = 0;
		SHA384_Update(&ctx, ILibScratchPad, bytesRead);
		if (endIndex > 0) { bytesLeft -= (unsigned int)bytesRead; }
	}

	while ((bytesRead = fread(ILibScratchPad, 1, endIndex == 0 ? sizeof(ILibScratchPad) : (bytesLeft > sizeof(ILibScratchPad) ? sizeof(ILibScratchPad) : bytesLeft), tmpFile)) > 0)
	{
		SHA384_Update(&ctx, ILibScratchPad, bytesRead);
		if (endIndex > 0) 
		{ 
			bytesLeft -= (unsigned int)bytesRead; 
			if (bytesLeft == 0) { break; }
		}
	}
	SHA384_Final((unsigned char*)fileHash, &ctx);
	fclose(tmpFile);

	return(0);
}

// Called when the connection of the mesh server is fully authenticated
void MeshServer_ServerAuthenticated(ILibWebClient_StateObject WebStateObject, MeshAgentHostContainer *agent) {
	int len = 0;

	// Send the mesh agent tag to the server
	// We send the tag information independently of the meshcore because we could use this to select what meshcore to use on the server.
	((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_AgentTag); // MeshCommand_AgentTag (15), agent tag information
	len = ILibSimpleDataStore_GetEx(agent->masterDb, "Tag", 3, ILibScratchPad2 + 2, sizeof(ILibScratchPad2) - 2);
	ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, 2 + len, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

	// Inform JavaScript core module of the connection
	// TODO: Verify with Bryan that only the core module will get this. No other modules should.
	if (agent->serverAuthState == 3) 
	{
		ILibDuktape_MeshAgent_PUSH(agent->meshCoreCtx, agent->chain);				// [agent]
		duk_get_prop_string(agent->meshCoreCtx, -1, "emit");						// [agent][emit]
		duk_swap_top(agent->meshCoreCtx, -2);										// [emit][this]
		duk_push_string(agent->meshCoreCtx, "Connected");							// [emit][this][Connected]
		duk_push_int(agent->meshCoreCtx, 1);										// [emit][this][Connected][1]
		if (duk_pcall_method(agent->meshCoreCtx, 2) != 0) { ILibDuktape_Process_UncaughtException(agent->meshCoreCtx); }
		duk_pop(agent->meshCoreCtx);												// ...

		if (agent->logUpdate != 0) 
		{
			sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "Connection Established [%p]...", WebStateObject);
			ILIBLOGMESSSAGE(ILibScratchPad);
		}

	}
}

void MeshServer_SendAgentInfo(MeshAgentHostContainer* agent, ILibWebClient_StateObject WebStateObject) {
	int hostnamelen = (int)strnlen_s(agent->hostname, sizeof(agent->hostname));

	// Send to the server information about this agent
	MeshCommand_BinaryPacket_AuthInfo *info = (MeshCommand_BinaryPacket_AuthInfo*)ILibScratchPad2;
	memset(info, 0, sizeof(MeshCommand_BinaryPacket_AuthInfo)); // Required because if hash are SHA384, they will not fully fill the struct.
	info->command = htons(MeshCommand_AuthInfo);
	info->infoVersion = htonl(1);
	info->agentId = htonl(MESH_AGENTID);
	info->agentVersion = htonl(agent->version);
	info->platformType = htonl(((agent->batteryState != MeshAgentHost_BatteryInfo_NONE) && (agent->batteryState != MeshAgentHost_BatteryInfo_UNKNOWN)) ? MeshCommand_AuthInfo_PlatformType_LAPTOP : MeshCommand_AuthInfo_PlatformType_DESKTOP);
	memcpy_s(info->MeshID, sizeof(info->MeshID), agent->meshId, sizeof(agent->meshId));
	info->capabilities = htonl(agent->capabilities);
	info->hostnameLen = htons(hostnamelen);
	memcpy_s(info->hostname, sizeof(ILibScratchPad2) - sizeof(MeshCommand_BinaryPacket_AuthInfo), agent->hostname, hostnamelen);

	// Send mesh agent information to the server
	ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)info, sizeof(MeshCommand_BinaryPacket_AuthInfo) + hostnamelen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
	agent->retryTime = 0;
	printf("Connected.\n");
	if (agent->serverAuthState == 3) { MeshServer_ServerAuthenticated(WebStateObject, agent); }
}

// Process MeshCentral server commands. 
void MeshServer_ProcessCommand(ILibWebClient_StateObject WebStateObject, MeshAgentHostContainer *agent, char *cmd, int cmdLen)
{
	unsigned short command = ntohs(((unsigned short*)cmd)[0]);
	unsigned short requestid;

#ifndef MICROSTACK_NOTLS
	// If we are not authenticated with the mesh server, we only support auth commands.
	if (agent->serverAuthState != 3)
	{
		X509* peer = ILibWebClient_SslGetCert(WebStateObject);

		switch (command)
		{
		case MeshCommand_AuthRequest: // This is basic authentication information from the server, we need to sign this and return the signature.
			if (cmdLen == sizeof(MeshCommand_BinaryPacket_AuthRequest))
			{
				MeshCommand_BinaryPacket_AuthRequest *AuthRequest = (MeshCommand_BinaryPacket_AuthRequest*)cmd;
				int signLen;
				SHA512_CTX c;
				EVP_PKEY *evp_prikey;
				RSA *rsa_prikey;

				// Hash the server's web certificate and check if it matches the one in the auth request
				util_certhash2(peer, ILibScratchPad2); // Hash the server certificate
				if (memcmp(ILibScratchPad2, AuthRequest->serverHash, sizeof(AuthRequest->serverHash)) != 0) { 
					util_keyhash2(peer, ILibScratchPad2); // Hash the server certificate public key (this is the old way)
					if (memcmp(ILibScratchPad2, AuthRequest->serverHash, sizeof(AuthRequest->serverHash)) != 0) {
						printf("Bad server certificate hash\r\n"); // TODO: Disconnect
						break;
					}
				}
				memcpy_s(agent->serverNonce, sizeof(agent->serverNonce), AuthRequest->serverNonce, sizeof(AuthRequest->serverNonce));

				// Place our certificate in the response
				MeshCommand_BinaryPacket_AuthVerify_Header *rav = (MeshCommand_BinaryPacket_AuthVerify_Header*)ILibScratchPad2;
				rav->command = htons(MeshCommand_AuthVerify);										// MeshCommand_AuthVerify (2), agent certificate in ASN1 format
				char *certDer = (char*)rav->data;
				short certLen = i2d_X509(agent->selfcert.x509, (unsigned char **)&certDer); // Place the agent root certificate in DER form
				rav->certLen = htons(certLen);

#ifdef WIN32
				if (agent->selfcert.pkey != NULL) {
#endif
					// Use our agent root private key to sign HASH(ServerWebHash + ServerNonce + AgentNonce)
					SHA384_Init(&c);
					SHA384_Update(&c, AuthRequest->serverHash, UTIL_SHA384_HASHSIZE); // Server web hash
					SHA384_Update(&c, agent->serverNonce, UTIL_SHA384_HASHSIZE); // Server nonce
					SHA384_Update(&c, agent->agentNonce, UTIL_SHA384_HASHSIZE); // Agent nonce
					SHA384_Final((unsigned char*)ILibScratchPad, &c);

					// Create a RSA signature using OpenSSL & send it
					evp_prikey = agent->selfcert.pkey;
					rsa_prikey = EVP_PKEY_get1_RSA(evp_prikey);
					signLen = sizeof(ILibScratchPad2) - sizeof(MeshCommand_BinaryPacket_AuthVerify_Header) - certLen;
					if (RSA_sign(NID_sha384, (unsigned char*)ILibScratchPad, UTIL_SHA384_HASHSIZE, (unsigned char*)(rav->data + certLen), (unsigned int*)&signLen, rsa_prikey) == 1)
					{
						// Signature succesful, send the result to the server
						ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rav, sizeof(MeshCommand_BinaryPacket_AuthVerify_Header) + certLen + signLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
					}
					RSA_free(rsa_prikey);
#ifdef WIN32
				} else {
					// Use our agent root private key to sign: ServerWebHash + ServerNonce + AgentNonce
					memcpy_s(ILibScratchPad, sizeof(ILibScratchPad), AuthRequest->serverHash, UTIL_SHA384_HASHSIZE);
					memcpy_s(ILibScratchPad + UTIL_SHA384_HASHSIZE, sizeof(ILibScratchPad) - UTIL_SHA384_HASHSIZE, agent->serverNonce, UTIL_SHA384_HASHSIZE);
					memcpy_s(ILibScratchPad + UTIL_SHA384_HASHSIZE + UTIL_SHA384_HASHSIZE, sizeof(ILibScratchPad) - UTIL_SHA384_HASHSIZE - UTIL_SHA384_HASHSIZE, agent->agentNonce, UTIL_SHA384_HASHSIZE);

					// Create a PKCS7 signature using Windows crypto & send it
					char* signature = NULL;
					signLen = wincrypto_sign((unsigned char*)ILibScratchPad, sizeof(AuthRequest->serverHash) + UTIL_SHA384_HASHSIZE + UTIL_SHA384_HASHSIZE, &signature);
					if (signLen > 0) {
						// Signature succesful, send the result to the server
						memcpy_s((unsigned char*)(rav->data + certLen), sizeof(ILibScratchPad2) - sizeof(MeshCommand_BinaryPacket_AuthVerify_Header) - certLen, signature, signLen);
						ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rav, sizeof(MeshCommand_BinaryPacket_AuthVerify_Header) + certLen + signLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
						free(signature);
					}
				}
#endif
			}
			break;
		case MeshCommand_AuthVerify: // This is the signature from the server. We need to check everything is ok.
			if (cmdLen > 8)
			{
				MeshCommand_BinaryPacket_AuthVerify_Header *avh = (MeshCommand_BinaryPacket_AuthVerify_Header*)cmd;
#ifdef WIN32
				MeshCommand_BinaryPacket_AuthVerify *AuthVerify = (MeshCommand_BinaryPacket_AuthVerify*)_alloca(sizeof(MeshCommand_BinaryPacket_AuthVerify));
#else
				MeshCommand_BinaryPacket_AuthVerify *AuthVerify = (MeshCommand_BinaryPacket_AuthVerify*)alloca(sizeof(MeshCommand_BinaryPacket_AuthVerify));
#endif
				AuthVerify->cert = avh->data;
				AuthVerify->certLen = ntohs(avh->certLen);
				AuthVerify->signature = avh->data + AuthVerify->certLen;
				AuthVerify->signatureLen = (unsigned short)(cmdLen - (int)(sizeof(MeshCommand_BinaryPacket_AuthVerify_Header) + AuthVerify->certLen));

				if (cmdLen > (int)(sizeof(MeshCommand_BinaryPacket_AuthVerify_Header) + AuthVerify->certLen))
				{
					int hashlen = UTIL_SHA384_HASHSIZE;
					SHA512_CTX c;
					X509* serverCert = NULL;
					EVP_PKEY *evp_pubkey;
					RSA *rsa_pubkey;

					// Get the server certificate
					if (!d2i_X509(&serverCert, (const unsigned char**)&AuthVerify->cert, AuthVerify->certLen)) { printf("Invalid server certificate\r\n"); break; } // TODO: Disconnect

					// Check if this certificate public key hash matches what we want
					X509_pubkey_digest(serverCert, EVP_sha384(), (unsigned char*)ILibScratchPad, (unsigned int*)&hashlen); // OpenSSL 1.1, SHA384
					if (memcmp(ILibScratchPad, agent->serverHash, UTIL_SHA384_HASHSIZE) != 0) {
						X509_pubkey_digest(serverCert, EVP_sha256(), (unsigned char*)ILibScratchPad, (unsigned int*)&hashlen); // OpenSSL 1.1, SHA256 (For older .mshx policy file)
						if (memcmp(ILibScratchPad, agent->serverHash, UTIL_SHA256_HASHSIZE) != 0) {
							printf("Server certificate mismatch\r\n"); break; // TODO: Disconnect
						}
					}

					// Compute the authentication hash
					SHA384_Init(&c);
					util_certhash2(peer, ILibScratchPad2);
					SHA384_Update(&c, ILibScratchPad2, UTIL_SHA384_HASHSIZE);
					SHA384_Update(&c, agent->agentNonce, UTIL_SHA384_HASHSIZE);
					SHA384_Update(&c, agent->serverNonce, UTIL_SHA384_HASHSIZE);
					SHA384_Final((unsigned char*)ILibScratchPad, &c);

					// Verify the hash signature using the server certificate
					evp_pubkey = X509_get_pubkey(serverCert);
					rsa_pubkey = EVP_PKEY_get1_RSA(evp_pubkey);
					if (RSA_verify(NID_sha384, (unsigned char*)ILibScratchPad, UTIL_SHA384_HASHSIZE, (unsigned char*)AuthVerify->signature, AuthVerify->signatureLen, rsa_pubkey) == 1)
					{
						// Server signature verified, we are good to go.
						agent->serverAuthState += 1;

						// Store the server's TLS cert hash so in the future, we can skip server auth.
						ILibSimpleDataStore_PutEx(agent->masterDb, "ServerTlsCertHash", 17, ILibScratchPad2, UTIL_SHA384_HASHSIZE);

						// Send our agent information to the server
						MeshServer_SendAgentInfo(agent, WebStateObject);
					} else {
						printf("Invalid server signature\r\n");
						// TODO: Disconnect
					}

					RSA_free(rsa_pubkey);
					EVP_PKEY_free(evp_pubkey);
					X509_free(serverCert);
				}
				break;
			case MeshCommand_AuthConfirm: // Server indicates that we are authenticated, we can now send data.
				{
					// We have to wait for the server to indicate that it authenticated the agent (us) before sending any data to the server.
					// Node authentication requires the server make database calls, so we need to delay.
					agent->serverAuthState += 2;
					if (agent->serverAuthState == 3) { MeshServer_ServerAuthenticated(WebStateObject, agent); }
				}
				break;
			}
		}
		if (peer != NULL) { X509_free(peer); peer = NULL; }
		return;
	}
#endif

	// If we get a authentication command after authentication is completed, ignore it. Commands 0 to 9 are reserved for authentication.
	if (command < 10) return;

	// If the command is JSON or binary over 1000, send it directly to the JavaScript code module
	// TODO: Verify with Bryan that only the core module will get this. No other modules should.
	if (cmd[0] == '{' || command >= 1000)
	{
		int popCount = 0;
		// if (cmd[0] == '{') { cmd[cmdLen] = 0; printf("%s\r\n", cmd); } // DEBUG: Print JSON command

		ILibDuktape_MeshAgent_PUSH(agent->meshCoreCtx, agent->chain);			// [agent]
		duk_get_prop_string(agent->meshCoreCtx, -1, "emit");					// [agent][emit]
		duk_swap_top(agent->meshCoreCtx, -2);									// [emit][this]
		duk_push_string(agent->meshCoreCtx, "Command");							// [emit][this][Command]
		if (cmd[0] == '{')
		{
			// JSON
			duk_push_global_object(agent->meshCoreCtx);											// [emit][this][Command][g]
			duk_get_prop_string(agent->meshCoreCtx, -1, "JSON");								// [emit][this][Command][g][JSON]
			duk_get_prop_string(agent->meshCoreCtx, -1, "parse");								// [emit][this][Command][g][JSON][func]
			duk_swap_top(agent->meshCoreCtx, -3);												// [emit][this][Command][func][JSON][g]
			duk_pop_2(agent->meshCoreCtx);														// [emit][this][Command][func]
			duk_push_lstring(agent->meshCoreCtx, cmd, cmdLen);									// [emit][this][Command][func][str]
			if (duk_pcall(agent->meshCoreCtx, 1) != 0)											// [emit][this][Command][JSON]
			{
				duk_pop(agent->meshCoreCtx);													// [emit][this][Command]
				duk_push_lstring(agent->meshCoreCtx, cmd, cmdLen);								// [emit][this][Command][str]
			}
			popCount = 1;
		}
		else
		{
			// BINARY
			duk_push_external_buffer(agent->meshCoreCtx);										// [emit][this][Command][extBuffer]
			duk_insert(agent->meshCoreCtx, -4);													// [extBuffer][emit][this][Command]
			duk_config_buffer(agent->meshCoreCtx, -4, cmd, cmdLen);
			duk_push_buffer_object(agent->meshCoreCtx, -4, 0, cmdLen, DUK_BUFOBJ_NODEJS_BUFFER);// [extBuffer][emit][this][Command][buffer]
			popCount = 2;
		}

		if (duk_pcall_method(agent->meshCoreCtx, 2) != 0) { ILibDuktape_Process_UncaughtException(agent->meshCoreCtx); }
		duk_pop_n(agent->meshCoreCtx, popCount);												// ...
		return;
	}

	// All these commands must have both a commandid and a requestid
	if (cmdLen < 4) return;
	requestid = ntohs(((unsigned short*)cmd)[1]);

	// Process Core Module Commands here, but only if we aren't running a local script
	switch (command)
	{
		case MeshCommand_CoreModule:        // New core modules to be used instead of the old one, if empty, remove the core module
		{
			char *coreException = NULL;
			MeshCommand_BinaryPacket_CoreModule *cm = (MeshCommand_BinaryPacket_CoreModule*)cmd;

			// If the agent is running with a local core, ignore this command
			if (agent->localScript != 0) break;

			if (cmdLen > sizeof(MeshCommand_BinaryPacket_CoreModule)) // Setup a new mesh core. 
			{
				char *hashref = ILibSimpleDataStore_GetHash(agent->masterDb, "CoreModule"); // Get the reference to the SHA384 hash for the currently running code
				if (hashref == NULL || memcmp(hashref, cm->coreModuleHash, sizeof(cm->coreModuleHash)) != 0) 
				{					
					agent->coreTimeout = NULL; // Setting this to null becuase we're going to stop the core. If we stop the core, this timeout will cleanup by itself.

					// If server sends us the same core, just do nothing.
					// Server sent us a new core, start by storing it in the data store
					ILibSimpleDataStore_PutEx(agent->masterDb, "CoreModule", 10, cm->coreModule, cmdLen - sizeof(MeshCommand_BinaryPacket_CoreModule));	// Store the JavaScript in the data store
					hashref = ILibSimpleDataStore_GetHash(agent->masterDb, "CoreModule");					// Get the reference to the SHA384 hash
					if (memcmp(hashref, cm->coreModuleHash, sizeof(cm->coreModuleHash)) != 0) 
					{																						// Check the hash for sanity
																											// Something went wrong, clear the data store
						ILibSimpleDataStore_Delete(agent->masterDb, "CoreModule");

						// Stop the currently running core if present
						ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
							ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: Stop");
						ScriptEngine_Stop(agent, MeshAgent_JavaCore_ContextGuid);

						// Tell the server we are no longer running a core module
						MeshCommand_BinaryPacket_CoreModule *rcm = (MeshCommand_BinaryPacket_CoreModule*)ILibScratchPad2;
						rcm->command = htons(MeshCommand_CoreModuleHash);									// MeshCommand_CoreModuleHash (11), SHA384 hash of the code module
						rcm->request = htons(requestid);													// Request id
						ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rcm, 4, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
						break;
					}

					// Stop the current JavaScript core if present and launch the new one.
					// JavaScript located at (cmd + 36) of length (cmdLen - 36)
					//printf("CORE: Restart\r\n");
					ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
						ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: Restart");
					if ((coreException = ScriptEngine_Restart(agent, MeshAgent_JavaCore_ContextGuid, cm->coreModule + 4, cmdLen - sizeof(MeshCommand_BinaryPacket_CoreModule) - 4)) != NULL)
					{
						ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
							ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: Error: %s", coreException);
						// TODO: Ylian: New Java Core threw an exception... Exception String is stored in 'coreException'
					}

					// Since we did a big write to the data store, good time to compact the store
					ILibSimpleDataStore_Compact(agent->masterDb);
				}

				// Create the server confirmation message that we are running the new core
				MeshCommand_BinaryPacket_CoreModule *rcm = (MeshCommand_BinaryPacket_CoreModule*)ILibScratchPad2;
				((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_CoreModuleHash);					// MeshCommand_CoreModuleHash (11), SHA384 hash of the code module
				((unsigned short*)ILibScratchPad2)[1] = htons(requestid);									// Request id
				memcpy_s(ILibScratchPad2 + 4, sizeof(ILibScratchPad2) - 4, hashref, UTIL_SHA384_HASHSIZE);			// SHA384 hash

				// Send the confirmation to the server
				ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rcm, sizeof(MeshCommand_BinaryPacket_CoreModule), ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
			}
			else if (cmdLen == 4)
			{
				// Server is telling us to stop running a core
				ILibSimpleDataStore_Delete(agent->masterDb, "CoreModule"); // Clear the core from datastore
																		  
				// Stop the current JavaScript core if present and launch the new one.
				ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
					ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: Stop");
				ScriptEngine_Stop(agent, MeshAgent_JavaCore_ContextGuid);

				// Confirm to the server that we are not running any core
				MeshCommand_BinaryPacket_CoreModule *rcm = (MeshCommand_BinaryPacket_CoreModule*)ILibScratchPad2;
				rcm->command = htons(MeshCommand_CoreModuleHash);											// MeshCommand_CoreModuleHash (11), SHA384 hash of the code module
				rcm->request = htons(requestid);															// Request id
				ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rcm, 4, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
			}
			break;
		}
		case MeshCommand_CoreModuleHash: // Request/return the SHA384 hash of the core module
		{
			// Tell the server what core module we are running
			char *hashref = ILibSimpleDataStore_GetHash(agent->masterDb, "CoreModule");						// Get the reference to the SHA384 hash
			int len = 4;

			// If the agent is running with a local core, ignore this command
			if (agent->localScript != 0) break;

			// Confirm to the server what core we are running
			MeshCommand_BinaryPacket_CoreModule *rcm = (MeshCommand_BinaryPacket_CoreModule*)ILibScratchPad2;
			rcm->command = htons(MeshCommand_CoreModuleHash);										// MeshCommand_CoreModuleHash (11), SHA384 hash of the code module
			rcm->request = htons(requestid);														// Request id
			if (hashref != NULL) { memcpy_s(rcm->coreModuleHash, sizeof(rcm->coreModuleHash), hashref, UTIL_SHA384_HASHSIZE); len = sizeof(MeshCommand_BinaryPacket_CoreModule); }

			// Send the confirmation to the server
			ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rcm, len, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

			break;
		}
		case MeshCommand_CoreOk: // Message from the server indicating our meshcore is ok. No update needed.
		{
			printf("Server verified meshcore...");
			if (agent->coreTimeout != NULL)
			{
				// Cancel the timeout
				duk_push_global_object(agent->meshCoreCtx);					// [g]
				duk_get_prop_string(agent->meshCoreCtx, -1, "clearTimeout");// [g][clearTimeout]
				duk_swap_top(agent->meshCoreCtx, -2);						// [clearTimeout][this]
				duk_push_heapptr(agent->meshCoreCtx, agent->coreTimeout);	// [clearTimeout][this][timeout]
				duk_pcall_method(agent->meshCoreCtx, 1); duk_pop(agent->meshCoreCtx);
				agent->coreTimeout = NULL;

				int CoreModuleLen = ILibSimpleDataStore_Get(agent->masterDb, "CoreModule", NULL, 0);
				if (CoreModuleLen <= 0)
				{
					printf(" meshcore not found...\n");
				}
				else
				{
					printf(" Launching meshcore...\n");
					char *CoreModule = (char*)ILibMemory_Allocate(CoreModuleLen, 0, NULL, NULL);
					ILibSimpleDataStore_Get(agent->masterDb, "CoreModule", CoreModule, CoreModuleLen);

					if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(agent->meshCoreCtx, CoreModule + 4, CoreModuleLen - 4, "CoreModule.js", 13) != 0 ||
						ILibDuktape_ScriptContainer_ExecuteByteCode(agent->meshCoreCtx) != 0)
					{
						ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
							ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: %s", duk_safe_to_string(agent->meshCoreCtx, -1));
						duk_pop(agent->meshCoreCtx);
					}
					free(CoreModule);
				}
			}
			else
			{
				// There's no timeout, probably because the core is already running
				printf(" meshcore already running...\n");
			}
			break;
		}
		case MeshCommand_AgentHash:
		{
			// This is a request for the hash of the agent binary
			// Built the response that includes our self hash
			MeshCommand_BinaryPacket_CoreModule *rcm = (MeshCommand_BinaryPacket_CoreModule*)ILibScratchPad2;
			rcm->command = htons(MeshCommand_AgentHash);						// MeshCommand_AgentHash (12), SHA384 hash of the agent executable
			rcm->request = htons(requestid);									// Request id
			if (agent->disableUpdate != 0)
			{
				// Never update
				memset(rcm->coreModuleHash, 0, UTIL_SHA384_HASHSIZE);
			}
			else if (agent->forceUpdate != 0)
			{
				// Always Update
				memset(rcm->coreModuleHash, 0xFFFF, UTIL_SHA384_HASHSIZE);
				if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Forcing Update..."); }
			}
			else
			{
				// Update when necessary
				memcpy_s(rcm->coreModuleHash, sizeof(rcm->coreModuleHash), agent->agentHash, UTIL_SHA384_HASHSIZE);// SHA384 hash of the agent executable
			}

			// Send the self hash back to the server
			ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rcm, sizeof(MeshCommand_BinaryPacket_CoreModule), ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

			break;
		}
		case MeshCommand_AgentUpdate:
		{
#ifdef WIN32
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agent->exePath, ".update.exe");
#else
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agent->exePath, ".update");
#endif
			char updateFileHash[UTIL_SHA384_HASHSIZE];
			MeshCommand_BinaryPacket_CoreModule *cm = (MeshCommand_BinaryPacket_CoreModule*)cmd;

			if (cmdLen == 4) 
			{
				// Indicates the start of the agent update transfer
				if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Starting download..."); }
				util_deletefile(updateFilePath);
			} else if (cmdLen == sizeof(MeshCommand_BinaryPacket_CoreModule)) 
			{
				// Indicates the end of the agent update transfer
				// Check the SHA384 hash of the received file against the file we got.
				if ((GenerateSHA384FileHash(updateFilePath, updateFileHash) == 0) && (memcmp(updateFileHash, cm->coreModuleHash, sizeof(cm->coreModuleHash)) == 0))
				{
					//printf("UPDATE: End OK\r\n");
					if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Download Complete... Hash verified"); }
					if (agent->fakeUpdate != 0)
					{
						int fsz;
						char *fsc;
						fsz = ILibReadFileFromDiskEx(&fsc, agent->exePath);
						ILibWriteStringToDiskEx(updateFilePath, fsc, fsz);
						if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Overriding update with same version..."); }
					}
					if (agent->fakeUpdate != 0 || agent->forceUpdate != 0)
					{
						ILibSimpleDataStore_Put(agent->masterDb, "disableUpdate", "1");
						if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Disabling future updates..."); }
					}
#ifdef WIN32
					agent->performSelfUpdate = 1;
#else
					// Set performSelfUpdate to the startupType, on Linux is this important: 1 = systemd, 2 = upstart, 3 = sysv-init
					int len = ILibSimpleDataStore_Get(agent->masterDb, "StartupType", ILibScratchPad, sizeof(ILibScratchPad));
					if (len > 0) { agent->performSelfUpdate = atoi(ILibScratchPad); }
					if (agent->performSelfUpdate == 0) { agent->performSelfUpdate = 999; } // Never allow this value to be zero.
#endif
					// Everything looks good, lets perform the update
					if (agent->logUpdate != 0) 
					{
						char tmp[255];
						sprintf_s(tmp, sizeof(tmp), "SelfUpdate -> Stopping Chain (%d)", agent->performSelfUpdate);
						ILIBLOGMESSSAGE(tmp);
					}
					ILibStopChain(agent->chain);
				} else 
				{
					// Hash check failed, delete the file and do nothing. On next server reconnect, we will try again.
					if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Download Complete... Hash FAILED, aborting update..."); }
					util_deletefile(updateFilePath);
				}
			}

			break;
		}
		case MeshCommand_AgentUpdateBlock:
		{
			// Write the mesh agent block to file
#ifdef WIN32
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agent->exePath, ".update.exe");
#else
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agent->exePath, ".update");
#endif

			// We have to try to write until it works, fopen sometimes fails
			while (util_appendfile(updateFilePath, cmd + 4, cmdLen - 4) == 0) 
			{ 
#ifdef WIN32
				Sleep(100); 
#else
				sleep(100);
#endif
			}

			// Confirm we got a mesh agent update block
			((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_AgentUpdateBlock);             // MeshCommand_AgentHash (14), SHA384 hash of the agent executable
			((unsigned short*)ILibScratchPad2)[1] = htons(requestid);                                // Request id
			ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, 4, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

			break;
		}
	}
}
void MeshServer_ControlChannel_IdleTimeout(ILibWebClient_StateObject WebStateObject, void *user)
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user;
	ILibWebClient_WebSocket_Ping(WebStateObject);
	ILibWebClient_SetTimeout(WebStateObject, agent->controlChannel_idleTimeout_seconds, MeshServer_ControlChannel_IdleTimeout, user);
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost , ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore/MeshServer_ControlChannel_IdleTimeout(): Sending Ping");
}
ILibWebClient_WebSocket_PingResponse MeshServer_ControlChannel_PingSink(ILibWebClient_StateObject WebStateObject, void *user)
{
	return ILibWebClient_WebSocket_PingResponse_Respond;
}
void MeshServer_ControlChannel_PongSink(ILibWebClient_StateObject WebStateObject, void *user)
{
#ifdef _REMOTELOGGING
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user;
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost , ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore/MeshServer_ControlChannel_IdleTimeout(): Received Pong");
#endif
}
void MeshServer_OnResponse(ILibWebClient_StateObject WebStateObject, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, ILibWebClient_ReceiveStatus recvStatus, void *user1, void *user2, int *PAUSE)
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user1;

	// Look at the various connection states and handle data if needed
	switch (recvStatus)
	{
		case ILibWebClient_ReceiveStatus_Partial:
		case ILibWebClient_ReceiveStatus_LastPartial:
			*beginPointer = endPointer; // ToDo: Buffer this data and send it up
			break;
		case ILibWebClient_ReceiveStatus_Connection_Established: // New connection established.
		{
#ifndef MICROSTACK_NOTLS
			int len;
#endif
			int idleLen;
			if ((idleLen = ILibSimpleDataStore_Get(agent->masterDb, "controlChannelIdleTimeout", NULL, 0)) != 0)
			{
				if (idleLen > 15)
				{
					agent->controlChannel_idleTimeout_seconds = DEFAULT_IDLE_TIMEOUT;
				}
				else
				{
					char idleBuffer[16];
					idleBuffer[ILibSimpleDataStore_Get(agent->masterDb, "controlChannelIdleTimeout", idleBuffer, sizeof(idleBuffer))] = 0;
					agent->controlChannel_idleTimeout_seconds = atoi(idleBuffer);
				}
			}
			else
			{
				agent->controlChannel_idleTimeout_seconds = DEFAULT_IDLE_TIMEOUT;
			}

			agent->controlChannel = WebStateObject; // Set the agent MeshCentral server control channel
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "Control Channel Idle Timeout = %d seconds", agent->controlChannel_idleTimeout_seconds);
			ILibWebClient_SetTimeout(WebStateObject, agent->controlChannel_idleTimeout_seconds, MeshServer_ControlChannel_IdleTimeout, agent);
			ILibWebClient_WebSocket_SetPingPongHandler(WebStateObject, MeshServer_ControlChannel_PingSink, MeshServer_ControlChannel_PongSink, agent);

#ifndef MICROSTACK_NOTLS
			X509* peer = ILibWebClient_SslGetCert(WebStateObject);
			agent->serverAuthState = 0; // We are not authenticated. Bitmask: 1 = Server Auth, 2 = Agent Auth.
			agent->serverConnectionState = 2;

			// Send the ServerID to the server, this is useful for the server to use the correct certificate to authenticate.
			MeshCommand_BinaryPacket_ServerId *serveridcmd = (MeshCommand_BinaryPacket_ServerId*)ILibScratchPad2;
			serveridcmd->command = htons(MeshCommand_ServerId);
			memcpy_s(serveridcmd->serverId, sizeof(serveridcmd->serverId), agent->serverHash, sizeof(agent->serverHash)); // Place our mesh agent nonce
			ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)serveridcmd, sizeof(MeshCommand_BinaryPacket_ServerId), ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

			// Check to see if we already have a validated TLS cert hash
			{
				MeshCommand_BinaryPacket_AuthRequest *ar = (MeshCommand_BinaryPacket_AuthRequest*)ILibScratchPad2;
				util_certhash2(peer, ar->serverHash); // Hash the server certificate public key and place it

				len = ILibSimpleDataStore_GetEx(agent->masterDb, "ServerTlsCertHash", 17, ILibScratchPad, sizeof(ILibScratchPad));
				if ((len == UTIL_SHA384_HASHSIZE) && (memcmp(ILibScratchPad, ar->serverHash, UTIL_SHA384_HASHSIZE) == 0)) {
					// The TLS certificate of this server is correct, no need to authenticate further.
					unsigned short response = htons(MeshCommand_AuthConfirm); // Send indication to the server that it's already authenticated
					agent->serverAuthState = 1;
					ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)&response, 2, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
				}

				// Start authentication by sending a auth nonce & server TLS cert hash - If we indicated AuthConfirm already, the server will use this data but not respond to it.
				// Send 384 bits SHA384 hash of TLS cert public key + 384 bits nonce
				util_random(sizeof(agent->agentNonce), agent->agentNonce);		// Generate a new mesh agent connection nonce
				ar->command = htons(MeshCommand_AuthRequest);					// MeshCommand_AuthRequest (1), server hash + nonce
				if (peer != NULL) { X509_free(peer); }
				memcpy_s(ar->serverNonce, sizeof(ar->serverNonce), agent->agentNonce, sizeof(agent->agentNonce)); // Place our mesh agent nonce
				ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)ar, sizeof(MeshCommand_BinaryPacket_AuthRequest), ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

				// If we know this is a good server, send our agent information right now.
				if (agent->serverAuthState == 1) { MeshServer_SendAgentInfo(agent, WebStateObject); }
			}
#endif
			break;
		}
		case ILibWebClient_ReceiveStatus_Complete: // Disconnection
			// If the channel had been authenticates, inform JavaScript core module that we are not disconnected
#ifndef MICROSTACK_NOTLS
			if (agent->serverAuthState == 3)
#endif
			{
				if (agent->meshCoreCtx != NULL)
				{
					ILibDuktape_MeshAgent_PUSH(agent->meshCoreCtx, agent->chain);			// [agent]
					duk_get_prop_string(agent->meshCoreCtx, -1, "emit");					// [agent][emit]
					duk_swap_top(agent->meshCoreCtx, -2);									// [emit][this]
					duk_push_string(agent->meshCoreCtx, "Connected");						// [emit][this][Connected]
					duk_push_int(agent->meshCoreCtx, 0);									// [emit][this][Connected][0] (0 means disconnected)
					if (duk_pcall_method(agent->meshCoreCtx, 2) != 0) { ILibDuktape_Process_UncaughtException(agent->meshCoreCtx); }
					duk_pop(agent->meshCoreCtx);
				}
			}
			agent->controlChannel = NULL; // Set the agent MeshCentral server control channel
			agent->serverConnectionState = 0;
			break;
		case ILibWebClient_ReceiveStatus_MoreDataToBeReceived:	// Data received			
			if (header->StatusCode == 101)
			{
				// Process Mesh Agent commands
				MeshServer_ProcessCommand(WebStateObject, agent, bodyBuffer, endPointer);
			}
			else
			{
				printf("Protocol Error encountered...\n");
			}
			break;
	}

	// If there are no headers, this is a connection error. Log it and try again...
	if (header == NULL)
	{
		if (ILibIsChainBeingDestroyed(agent->chain)) { return; }
		ILibRemoteLogging_printf(ILibChainGetLogger(ILibWebClient_GetChainFromWebStateObject(WebStateObject)), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "Agent Host Container: Mesh Server Connection Error, trying again later.");
		printf("Mesh Server Connection Error\n");

		if (agent->logUpdate != 0) 
		{
			sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "Connection Error [%p, %d]...\n", WebStateObject, InterruptFlag);
			ILIBLOGMESSSAGE(ILibScratchPad); 
		}


		if (agent->multicastServerUrl != NULL) { free(agent->multicastServerUrl); agent->multicastServerUrl = NULL; }
		MeshServer_Connect(agent);
		return;
	}

	if (recvStatus != ILibWebClient_ReceiveStatus_Partial) { *beginPointer = endPointer; } // TODO: Confirm with Bryan that this is how partial data works
}
#ifdef MICROSTACK_PROXY
void MeshServer_ConnectEx_Enumerate_Contexts(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user;
	if (Key1 == NULL && ((SCRIPT_ENGINE_ISOLATION*)Data)->reserved != 0)
	{
		// This is a regular Duktape Context
		duk_context *ctx = (duk_context*)Data;
		ScriptContainerSettings *settings = ScriptEngine_GetSettings(ctx);
		if (settings != NULL && (settings->permissions & SCRIPT_ENGINE_NO_MESH_AGENT_ACCESS) == 0)
		{
			memcpy_s(&(ILibDuktape_GetNewGlobalTunnel(ctx)->proxyServer), sizeof(struct sockaddr_in6), agent->proxyServer, sizeof(struct sockaddr_in6));
		}
	}
}
#endif
void MeshServer_ConnectEx(MeshAgentHostContainer *agent)
{
	int len, serverUrlLen;
	char *path;
	char *host;
	char *serverUrl;
	unsigned short port;
	struct sockaddr_in6 meshServer;
	ILibHTTPPacket *req;
	ILibWebClient_RequestToken reqToken;
	parser_result *rs;
	parser_result_field *f;

	// If this is called while we are in any connection state, just leave now.
	if (agent->serverConnectionState != 0) return;

	if (ILibIsChainBeingDestroyed(agent->chain) != 0) { return; }

	len = ILibSimpleDataStore_Get(agent->masterDb, "MeshServer", ILibScratchPad2, sizeof(ILibScratchPad2));
	if (len == 0) { printf("No MeshCentral settings found, place .msh file with this executable and restart.\r\n"); ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "agentcore: MeshServer URI not found"); return; }

	rs = ILibParseString(ILibScratchPad2, 0, len, ",", 1);
	if (agent->serverIndex == 0)
	{
		int rval;
		util_random(4, (char*)&rval);
		agent->serverIndex = (rval % rs->NumResults) + 1;
	}
	else
	{
#ifdef MICROSTACK_PROXY
		if (agent->triedNoProxy_Index == agent->serverIndex)
#endif
		{
			agent->serverIndex = (agent->serverIndex % rs->NumResults) + 1;
			agent->triedNoProxy_Index = agent->serverIndex - 1;
		}
	}

	f = ILibParseString_GetResultIndex(rs, agent->serverIndex);
	f->datalength = ILibTrimString(&(f->data), f->datalength);
	f->data[f->datalength] = 0;
	serverUrl = f->data;
	serverUrlLen = f->datalength;
	if (f->datalength > 5 && memcmp(f->data, "local", 5) == 0)
	{
		if (agent->multicastServerUrl != NULL) {
			serverUrl = agent->multicastServerUrl;
			serverUrlLen = (int)strlen(serverUrl);
		} else {
			// Multicast discovery packet to try to find our server
			if ((agent->multicastDiscovery2 != NULL) && (ILibSimpleDataStore_Get(agent->masterDb, "ServerID", ILibScratchPad2, sizeof(ILibScratchPad2)) == 97)) { ILibMulticastSocket_Broadcast(agent->multicastDiscovery2, ILibScratchPad2, 96, 1); }
			ILibDestructParserResults(rs);
			MeshServer_Connect(agent);
			return;
		}
	}

	if (serverUrlLen < sizeof(agent->serveruri))
	{
		strcpy_s(agent->serveruri, sizeof(agent->serveruri), serverUrl);
	}
	else
	{
		agent->serveruri[0] = 0;
	}

#ifndef MICROSTACK_NOTLS
	ILibParseUriResult result = ILibParseUri(serverUrl, &host, &port, &path, &meshServer);
#else
	ILibParseUri(serverUrl, &host, &port, &path, &meshServer);
#endif



	if (meshServer.sin6_family == AF_UNSPEC)
	{
		// Could not resolve host name
		if (ILibSimpleDataStore_GetEx(agent->masterDb, serverUrl, serverUrlLen, (char*)&meshServer, sizeof(struct sockaddr_in6)) == 0)
		{
			meshServer.sin6_family = AF_UNSPEC;
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "agentcore: Could not resolve: %s", ILibScratchPad);
			printf("agentcore: Could not resolve: %s\n", host);
		}
	}
	else
	{
		// Successfully resolved host name
		struct sockaddr_in6 tempAddr;
		len = ILibSimpleDataStore_GetEx(agent->masterDb, serverUrl, serverUrlLen, (char*)&tempAddr, sizeof(struct sockaddr_in6));
		if (len == 0)
		{
			// No entry in DB, so update the value
			ILibSimpleDataStore_PutEx(agent->masterDb, serverUrl, serverUrlLen, (char*)&meshServer, ILibInet_StructSize(&meshServer));
		}
		else
		{
			// Entry exists, lets see if we need to update
			if (tempAddr.sin6_family != meshServer.sin6_family || memcmp(&tempAddr, &meshServer, ILibInet_StructSize(&meshServer)) != 0)
			{
				// Entry was different, so we need to update it
				ILibSimpleDataStore_PutEx(agent->masterDb, serverUrl, serverUrlLen, (char*)&meshServer, ILibInet_StructSize(&meshServer));
			}
		}
	}

	printf("Connecting to: %s\n", serverUrl);
	if (agent->logUpdate != 0) { ILIBLOGMESSSAGE(serverUrl); }

	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore: Attempting connection to: %s", serverUrl);
	ILibDestructParserResults(rs);

	if ((len = ILibSimpleDataStore_Get(agent->masterDb, "ServerID", ILibScratchPad2, sizeof(ILibScratchPad2))) == 0) { printf("ServerID entry not found in Db!\n"); free(host); free(path); return; }
	rs = ILibParseString(ILibScratchPad2, 0, len, ",", 1);
	f = ILibParseString_GetResultIndex(rs, agent->serverIndex);
	if (f == NULL)
	{
		// Invalid Server ID Count
		printf("ServerID Count Mismatch\r\n");
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore: ServerID Count Mismatch. Hash Count = %d, Server Index = %d", rs->NumResults, agent->serverIndex);
		ILibDestructParserResults(rs);
		free(host); free(path);
		return;
	}
	f->datalength = ILibTrimString(&(f->data), f->datalength);
	if (f->datalength / 2 > sizeof(agent->serverHash))
	{
		printf("ServerID too big\r\n");
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore: ServerID too big. Was %d bytes, but expected %d bytes", f->datalength / 2, sizeof(agent->serverHash) - 1);
		ILibDestructParserResults(rs);
		free(host); free(path);
		return;
	}

	memset(agent->serverHash, 0, sizeof(agent->serverHash));
	util_hexToBuf(f->data, f->datalength, agent->serverHash);
	ILibDestructParserResults(rs);
	
	len = ILibSimpleDataStore_Get(agent->masterDb, "MeshID", ILibScratchPad, sizeof(ILibScratchPad));
	if ((len != 32) && (len != 48)) { printf("MeshID entry not found in db or bad size.\n"); return; } // Make sure MeshID is both present and SHA256 or SHA384.
	memset(agent->meshId, 0, sizeof(agent->meshId)); // Clear the meshid first in case we copy SHA256
	memcpy_s(agent->meshId, sizeof(agent->meshId), ILibScratchPad, len); // Copy the correct length

#ifndef MICROSTACK_NOTLS
	util_keyhash(agent->selfcert, agent->g_selfid); // Compute our own identifier using our certificate
#endif

	req = ILibCreateEmptyPacket();
	ILibSetVersion(req, "1.1", 3);
	ILibSetDirective(req, "GET", 3, path, (int)strnlen_s(path, serverUrlLen));
	ILibAddHeaderLine(req, "Host", 4, host, (int)strnlen_s(host, serverUrlLen));

	free(path);

	if (meshServer.sin6_family != AF_UNSPEC)
	{
		ILibWebClient_AddWebSocketRequestHeaders(req, 65535, MeshServer_OnSendOK);
		reqToken = ILibWebClient_PipelineRequest(agent->httpClientManager, (struct sockaddr*)&meshServer, req, MeshServer_OnResponse, agent, NULL);
#ifndef MICROSTACK_NOTLS
		ILibWebClient_Request_SetHTTPS(reqToken, result == ILibParseUriResult_TLS ? ILibWebClient_RequestToken_USE_HTTPS : ILibWebClient_RequestToken_USE_HTTP);
		ILibWebClient_Request_SetSNI(reqToken, host, (int)strnlen_s(host, serverUrlLen));
#endif
		if ((ILibSimpleDataStore_GetEx(agent->masterDb, "ignoreProxyFile", 15, ILibScratchPad, sizeof(ILibScratchPad)) == 0) && ((len = ILibSimpleDataStore_Get(agent->masterDb, "WebProxy", ILibScratchPad, sizeof(ILibScratchPad))) != 0 || (len = MeshAgent_GetSystemProxy(agent, ILibScratchPad, sizeof(ILibScratchPad))) != 0))
		{
#ifdef MICROSTACK_PROXY
			unsigned short proxyPort = 80;
			int delimiter = ILibString_LastIndexOf(ILibScratchPad, len, ":", 1);
			
			if (agent->triedNoProxy_Index < agent->serverIndex && agent->proxyServer != NULL)
			{
				printf("Disabling Proxy: %s\n", ILibScratchPad);
				agent->triedNoProxy_Index++;
				agent->proxyServer = ILibWebClient_SetProxy(reqToken, NULL, 0, NULL, NULL);;

				if (duk_peval_string(agent->meshCoreCtx, "require('global-tunnel');") == 0)
				{
					duk_get_prop_string(agent->meshCoreCtx, -1, "end");						// [tunnel][end]
					duk_swap_top(agent->meshCoreCtx, -2);									// [end][this]
					duk_pcall_method(agent->meshCoreCtx, 0); 								// [undefined]
				}
				duk_pop(agent->meshCoreCtx);												// ...
			}
			else
			{
				printf("Using proxy: %s\n", ILibScratchPad);
				if (delimiter > 0)
				{
					ILibScratchPad[delimiter] = 0;
					ILibScratchPad[len] = 0;
					proxyPort = atoi(ILibScratchPad + delimiter + 1);
				}
				agent->proxyServer = ILibWebClient_SetProxy(reqToken, ILibScratchPad, proxyPort, NULL, NULL);
				if (agent->proxyServer != NULL)
				{
					memcpy_s(&(ILibDuktape_GetNewGlobalTunnel(agent->meshCoreCtx)->proxyServer), sizeof(struct sockaddr_in6), agent->proxyServer, sizeof(struct sockaddr_in6));
				}
				if (agent->logUpdate != 0) { ILibScratchPad[delimiter] = ':';  ILIBLOGMESSSAGE(ILibScratchPad); }
			}
#else
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore.MeshServer_ConnectEx(): Proxy Specified, but support was not enabled in this build");
#endif
		}
		else
		{
			// No Proxy was specified
			agent->triedNoProxy_Index++;
		}
		agent->serverConnectionState = 1; // We are trying to connect
	}
	else
	{
		ILibDestructPacket(req);
	}
	free(host);
}
void MeshServer_Connect(MeshAgentHostContainer *agent)
{
	unsigned int timeout;

	// If this is called while we are in any connection state, just leave now.
	if (agent->serverConnectionState != 0) return;

	util_random(sizeof(int), (char*)&timeout);
	agent->disableUpdate = ILibSimpleDataStore_Get(agent->masterDb, "disableUpdate", NULL, 0);
	agent->forceUpdate = ILibSimpleDataStore_Get(agent->masterDb, "forceUpdate", NULL, 0);
	agent->logUpdate = ILibSimpleDataStore_Get(agent->masterDb, "logUpdate", NULL, 0);
	agent->fakeUpdate = ILibSimpleDataStore_Get(agent->masterDb, "fakeUpdate", NULL, 0);


	if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("Attempting to connect to Server..."); }

	if (agent->retryTime == 0)
	{
		agent->retryTime = (timeout % 1500) + 500;		// Random value between 500 and 2000
		MeshServer_ConnectEx(agent);
	}
	else
	{
		int delay;
		if (agent->retryTime >= 240000)
		{
			// Cap at around 4 minutes
			delay = agent->retryTime + (timeout % 120000);					// Random value between 4 and 6 minutes
		}
		else
		{
			delay = agent->retryTime + (timeout % agent->retryTime);		// Random value between current value and double the current value
		}
		printf("AutoRetry Connect in %d milliseconds\n", delay);
		ILibLifeTime_AddEx(ILibGetBaseTimer(agent->chain), agent, delay, (ILibLifeTime_OnCallback)MeshServer_ConnectEx, NULL);
		agent->retryTime = delay;
	}
}

#ifndef MICROSTACK_NOTLS
int ValidateMeshServer(ILibWebClient_RequestToken sender, int preverify_ok, STACK_OF(X509) *certs, struct sockaddr_in6 *address)
{
	// Server validation is always true here. We will do a second round within the websocket to see if the server is really valid or not.
	return 1;
}
#endif


void checkForEmbeddedMSH(MeshAgentHostContainer *agent)
{
	FILE *tmpFile = NULL;
	int mshLen;

#ifdef WIN32
	fopen_s(&tmpFile, agent->exePath, "rb");
#else
	tmpFile = fopen(agent->exePath, "rb");
#endif
	if (tmpFile == NULL) { return; }

	fseek(tmpFile, -16, SEEK_END);
	ignore_result(fread(ILibScratchPad, 1, 16, tmpFile));
	if (memcmp(ILibScratchPad, exeMeshPolicyGuid, 16) == 0)
	{
		// Found Embedded MSH File
		fseek(tmpFile, -20, SEEK_CUR);
		if (fread((void*)&mshLen, 1, 4, tmpFile) == 4)
		{
			mshLen = ntohl(mshLen);
			fseek(tmpFile, -4 - mshLen, SEEK_CUR);
			char *eMSH = ILibMemory_AllocateA(mshLen);
			if (fread(eMSH, 1, mshLen, tmpFile) == mshLen)
			{
				FILE *msh = NULL;
#ifdef WIN32
				fopen_s(&msh, MeshAgent_MakeAbsolutePath(agent->exePath, ".msh"), "wb");
#else
				msh = fopen(MeshAgent_MakeAbsolutePath(agent->exePath, ".msh"), "wb");
#endif
				if (msh != NULL)
				{
					ignore_result(fwrite(eMSH, 1, mshLen, msh));
					fclose(msh);
				}
			}
			
		}
	}
	fclose(tmpFile);
}
int importSettings(MeshAgentHostContainer *agent, char* fileName)
{
	int eq;
	char* importFile;
	int importFileLen;
	parser_result *pr;
	parser_result_field *f;

	importFileLen = ILibReadFileFromDiskEx(&importFile, fileName);
	if (importFileLen == 0) { return(0); }
	//printf("Importing settings file: %s\n", fileName);

	pr = ILibParseString(importFile, 0, importFileLen, "\n", 1);
	f = pr->FirstResult;
	while (f != NULL)
	{
		f->datalength = ILibTrimString(&(f->data), f->datalength);
		if (f->data[0] != 35)	// Checking to see if this line is commented out
		{
			eq = ILibString_IndexOf(f->data, f->datalength, "=", 1);
			if (eq > 0)
			{
				char *key, *val;
				int keyLen, valLen;

				key = f->data;
				keyLen = eq;
				key[keyLen] = 0;
				val = key + keyLen + 1;
				valLen = f->datalength - keyLen - 1;
				if (val[valLen - 1] == 13) { --valLen; }
				valLen = ILibTrimString(&val, valLen);

				if (!(keyLen == 10 && strncmp("CoreModule", key, 10) == 0))
				{
					if (valLen == 0) 
					{
						// Empty key, remove the value completely.
						ILibSimpleDataStore_DeleteEx(agent->masterDb, key, keyLen);
					}
					else
					{
						if (ntohs(((unsigned short*)val)[0]) == HEX_IDENTIFIER)
						{
							// HEX value
							ILibSimpleDataStore_PutEx(agent->masterDb, key, keyLen, ILibScratchPad2, util_hexToBuf(val + 2, valLen - 2, ILibScratchPad2));
						}
						else
						{
							// STRING value
							val[valLen] = 0;
							ILibSimpleDataStore_PutEx(agent->masterDb, key, keyLen, val, valLen + 1);
						}
					}
					//printf("...Imported: %s\n", key);
				}
			}
		}
		f = f->NextResult;
	}
	ILibDestructParserResults(pr);
	free(importFile);

	return(importFileLen);
}

void agentDumpKeysSink(ILibSimpleDataStore sender, char* Key, int KeyLen, void *user)
{
	if (KeyLen < sizeof(ILibScratchPad2))
	{
		memcpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), Key, KeyLen);
		ILibScratchPad2[KeyLen] = 0;
		printf("--> %s\n", ILibScratchPad2);
	}
}

MeshAgentHostContainer* MeshAgent_Create(MeshCommand_AuthInfo_CapabilitiesMask capabilities)
{
	MeshAgentHostContainer* retVal = (MeshAgentHostContainer*)ILibMemory_Allocate(sizeof(MeshAgentHostContainer), 0, NULL, NULL);
#ifdef WIN32
	SYSTEM_POWER_STATUS stats;
#endif

	retVal->agentID = (AgentIdentifiers)MESH_AGENTID;
	retVal->chain = ILibCreateChainEx(3 * sizeof(void*));
	retVal->pipeManager = ILibProcessPipe_Manager_Create(retVal->chain);
	retVal->capabilities = capabilities | MeshCommand_AuthInfo_CapabilitiesMask_CONSOLE | MeshCommand_AuthInfo_CapabilitiesMask_JAVASCRIPT;
	gethostname(retVal->hostname, (int)sizeof(retVal->hostname));

#ifdef WIN32
	GetSystemPowerStatus(&stats);
	switch (stats.BatteryFlag)
	{
		case 128:
			retVal->batteryState = MeshAgentHost_BatteryInfo_NONE;
			break;
		case 255:
			retVal->batteryState = MeshAgentHost_BatteryInfo_UNKNOWN;
			break;
		default:
			retVal->batteryState = (MeshAgentHost_BatteryInfo)stats.BatteryFlag;
			break;
	}
#endif

	((void**)ILibMemory_GetExtraMemory(retVal->chain, ILibMemory_CHAIN_CONTAINERSIZE))[2] = retVal;
	return retVal;
}

void MeshAgent_Slave(MeshAgentHostContainer *agentHost)
{
	// We are just a slave container
	agentHost->exitCode = ILibDuktape_ScriptContainer_StartSlave(agentHost->chain, agentHost->pipeManager);
	agentHost->chain = NULL;
}


void MeshAgent_ChainEnd(void *chain, void *user)
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user;
	if (agent->meshCoreCtx != NULL) 
	{
		if (g_displayFinalizerMessages) { printf("\n\n==> Stopping JavaScript Engine\n"); }
		duk_destroy_heap(agent->meshCoreCtx); 
	}
	agent->meshCoreCtx = NULL;
}

void MeshAgent_RunScriptOnly_Finalizer(duk_context *ctx, void *user)
{
	MeshAgentHostContainer *agentHost = (MeshAgentHostContainer*)user;
	agentHost->exitCode = ILibDuktape_Process_GetExitCode(ctx);

	agentHost->meshCoreCtx = NULL;
	if (ILibIsChainBeingDestroyed(agentHost->chain) == 0)
	{
		MeshAgent_Stop(agentHost);
	}
}
void MeshAgent_CoreModule_UncaughtException(duk_context *ctx, char *msg, void *user)
{
	printf("JavaCore UncaughtException: %s\n", msg);
}
void MeshAgent_AgentMode_IPAddressChanged_Handler(ILibIPAddressMonitor sender, void *user)
{
	MeshAgentHostContainer *agentHost = (MeshAgentHostContainer*)user;

	if (agentHost->serverConnectionState == 0)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "Network State Change detected... Resetting connection timeout");
		ILibLifeTime_Remove(ILibGetBaseTimer(agentHost->chain), agentHost);

		agentHost->retryTime = 3000;
		ILibLifeTime_AddEx(ILibGetBaseTimer(agentHost->chain), agentHost, agentHost->retryTime, (ILibLifeTime_OnCallback)MeshServer_ConnectEx, NULL);
	}
}

int MeshAgent_AgentMode(MeshAgentHostContainer *agentHost, int paramLen, char **param, int parseCommands);
void MeshAgent_AgentMost_dbRetryCallback(void *object)
{
	MeshAgentHostContainer *agentHost = (MeshAgentHostContainer*)((void**)object)[0];
	int paramLen = ((int*)&((void**)object)[1])[0];
	char **param = (char**)((void**)object)[2];
	int parseCommands = ((int*)&((void**)object)[3])[0];

	if (MeshAgent_AgentMode(agentHost, paramLen, param, parseCommands) == 0)
	{
		ILibStopChain(agentHost->chain);
	}
}

void MeshAgent_AgentMode_Core_ServerTimeout(duk_context *ctx, void ** args, int argsLen)
{
	MeshAgentHostContainer *agentHost = (MeshAgentHostContainer*)args[0];
	int CoreModuleLen = ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", NULL, 0);
	char *CoreModule;

	duk_push_this(ctx);			// [timeout]
	duk_push_heap_stash(ctx);	// [timeout][stash]
	duk_del_prop_string(ctx, -1, Duktape_GetStashKey(duk_get_heapptr(ctx, -2)));
	agentHost->coreTimeout = NULL;

	printf("Timeout waiting for Server, launching cached meshcore...\n");
	if (CoreModuleLen <= 0)
	{
		printf("   No meshcore found in db...\n");
	}
	else
	{
		CoreModule = (char*)ILibMemory_Allocate(CoreModuleLen, 0, NULL, NULL);
		ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", CoreModule, CoreModuleLen);

		if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(agentHost->meshCoreCtx, CoreModule + 4, CoreModuleLen - 4, "CoreModule.js", 13) != 0 ||
			ILibDuktape_ScriptContainer_ExecuteByteCode(agentHost->meshCoreCtx) != 0)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
				ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: %s", duk_safe_to_string(agentHost->meshCoreCtx, -1));
			duk_pop(agentHost->meshCoreCtx);
		}
		free(CoreModule);
	}
}

int MeshAgent_AgentMode(MeshAgentHostContainer *agentHost, int paramLen, char **param, int parseCommands)
{
	int resetNodeId = 0;
#ifdef WIN32
	int pLen;
#endif
#ifdef _POSIX
#ifndef __APPLE__
	int options = 0;
#endif
	if (paramLen >= 2)
	{
		if ((strcmp(param[1], "stop") == 0 || strcmp(param[1], "-s") == 0))
		{
			// Stop
			FILE *fd = NULL;
			char str[15];
			pid_t pid = 0;
			size_t len;

#ifdef _ANDROID
			fd = fopen("/data/usr/tmp/meshagent.pid", "r");
#else
			fd = fopen("/var/run/meshagent.pid", "r");
#endif
			if (fd == NULL) fd = fopen(".meshagent.pid", "r");
			if (fd != NULL)
			{
				len = fread(str, sizeof(char), 15, fd);
				if (len > 0)
				{
					sscanf(str, "%d\r\n", &pid);
					if (pid > 0 && kill(pid, SIGKILL) == 0) printf("Mesh agent stopped.\r\n"); else printf("Mesh agent not running.\r\n");
#ifdef _ANDROID
					remove("/data/usr/tmp/meshagent.pid");
#else
					remove("/var/run/meshagent.pid");
					remove(".meshagent.pid");
#endif
				}
				fclose(fd);
				exit(EXIT_SUCCESS); 
			}
			else
			{
				printf("Unable to find process id file.\r\n");
				exit(EXIT_FAILURE); 
			}
		}
	}

#endif

	// We are a Mesh Agent
	if (agentHost->masterDb == NULL) { agentHost->masterDb = ILibSimpleDataStore_Create(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db")); }
	if (agentHost->masterDb == NULL) 
	{ 
		void **data = (void**)ILibScratchPad;
		data[0] = agentHost;
		((int*)&(data[1]))[0] = paramLen;
		data[2] = param;
		((int*)&(data[3]))[0] = parseCommands;

		switch (agentHost->dbRetryCount)
		{
		case 10:
			printf("Unable to open database.\r\n");
			return 0;
		default:
			printf("Unable to open database (%d/10)...\r\n", agentHost->dbRetryCount + 1);
			agentHost->dbRetryCount++;
			ILibLifeTime_AddEx(ILibGetBaseTimer(agentHost->chain), data, 2000, MeshAgent_AgentMost_dbRetryCallback, NULL);
			return 1;
		}
	}

	agentHost->httpClientManager = ILibCreateWebClient(3, agentHost->chain);

	ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "agentcore: argv[0] = %s", param[0]);

#if defined(_WINSERVICE)
	// If running as a windows services, check the "ResetNodeId" key.
	{
		HKEY hKey;
		DWORD len = 0;
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Open Source\\MeshAgent2"), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
		{
			if (RegQueryValueExA(hKey, TEXT("ResetNodeId"), NULL, NULL, NULL, &len) == ERROR_SUCCESS && len > 0)
			{
				if (RegDeleteValue(hKey, TEXT("ResetNodeId")) == ERROR_SUCCESS) { resetNodeId = 1; } // Force certificate reset
			}
			RegCloseKey(hKey);
		}
	}
#else
	// If running in console mode, check the --resetnodeid command switch
	if (parseCommands != 0)
	{
		int i;
		// Parse command-line arguments
		for (i = 0; i < paramLen; ++i) {
			if (strcmp(param[i], "--resetnodeid") == 0) { resetNodeId = 1; }
		}
	}
#endif
#ifndef MICROSTACK_NOTLS
	// Check the local MacAddresses, to see if we need to reset our NodeId
	duk_context *tmpCtx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(0, 0, agentHost->chain, NULL, NULL, agentHost->exePath, NULL, NULL, NULL);
	if (duk_peval_string(tmpCtx, "(function _getMac() { var ret = ''; var ni = require('os').networkInterfaces(); for (var f in ni) { for (var i in ni[f]) { if(ni[f][i].type == 'ethernet' || ni[f][i].type == 'wireless') {ret += ('[' + ni[f][i].mac + ']');} } } return(ret); })();") == 0)
	{
		int len;
		duk_size_t macLen;
		char *mac = (char*)duk_get_lstring(tmpCtx, -1, &macLen);

		if (macLen >= 19) // Only continue if we have at least 1 MAC Address
		{
			if ((len = ILibSimpleDataStore_Get(agentHost->masterDb, "LocalMacAddresses", NULL, 0)) == 0)
			{
				// We didn't have any MAC addresses in the db, so put them there, and return
				ILibSimpleDataStore_PutEx(agentHost->masterDb, "LocalMacAddresses", 17, mac, (int)macLen);
			}
			else
			{
				// We have MAC addresses in the db, so before we compare them, lets check that we have MAC addresses on the
				// system that aren't just zeros. So lets count how many we have
				int i = 0;
				while (i < (int)macLen)
				{
					if (strncmp(mac + i, "[00:00:00:00:00:00]", 19) != 0) { break; }
					i += 19;
				}
				if (i < (int)macLen)
				{
					// We have at least one valid MAC address, so we can continue with the checks

					i = 0;
					char *curr = ILibMemory_AllocateA(len);
					ILibSimpleDataStore_Get(agentHost->masterDb, "LocalMacAddresses", curr, len);

					while (i < len)
					{
						if (strncmp(curr + i, "[00:00:00:00:00:00]", 19) != 0)
						{
							if (ILibString_IndexOf(mac, (int)macLen, curr + i, 19) >= 0) { break; }
						}
						i += 19;
					}
					if (i >= len) { resetNodeId = 1; ILibSimpleDataStore_PutEx(agentHost->masterDb, "LocalMacAddresses", 17, mac, (int)macLen); }
				}
			}
		}
	}
	duk_destroy_heap(tmpCtx);

	// Load the mesh agent certificates
	if ((resetNodeId == 1 || agent_LoadCertificates(agentHost) != 0) && agent_GenerateCertificates(agentHost, NULL) != 0) { printf("Certificate error\r\n"); }
	if (agent_VerifyMeshCertificates(agentHost) != 0) { printf("Certificate validation error\r\n"); }
#else
	printf("TLS support disabled\n");
#endif

	// Read the .tag file if present and push it into the database
	{
		char* str = NULL;
		int len = (int)util_readfile(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".tag"), &str, 1024);
		if (str != NULL) { ILibSimpleDataStore_PutEx(agentHost->masterDb, "Tag", 3, str, len); free(str); } else { ILibSimpleDataStore_DeleteEx(agentHost->masterDb, "Tag", 3); }
	}

	// Read the .proxy file if present and push it into the database
	{
		char tmp[255];
		if (ILibSimpleDataStore_GetEx(agentHost->masterDb, "ignoreProxyFile", 15, tmp, sizeof(tmp)) == 0)
		{
			char* str = NULL;
			int len = (int)util_readfile(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".proxy"), &str, 1024);
			if (str != NULL) { ILibSimpleDataStore_PutEx(agentHost->masterDb, "WebProxy", 8, str, len); free(str); }
			else { ILibSimpleDataStore_DeleteEx(agentHost->masterDb, "WebProxy", 8); }
		}
	}

	// Check to see if we need to import a settings file
	if (importSettings(agentHost, MeshAgent_MakeAbsolutePath(agentHost->exePath, ".mshx")) == 0) 
	{
		if (importSettings(agentHost, MeshAgent_MakeAbsolutePath(agentHost->exePath, ".msh")) == 0)
		{
			if ((importSettings(agentHost, "mesh_linumshx") == 0) && (importSettings(agentHost, "mesh_limshx") == 0)) // Do this because the old agent would generate this bad file name on linux.
			{
				// Let's check to see if an .msh was embedded into our binary
				checkForEmbeddedMSH(agentHost);
				importSettings(agentHost, MeshAgent_MakeAbsolutePath(agentHost->exePath, ".msh"));
			}
		}
	}

	// Check to see if any capabilities are specified in the db
	{
		int dbCapabilities = 0;
		if (ILibSimpleDataStore_Get(agentHost->masterDb, "AgentCapabilities", NULL, 0) == 4)
		{
			ILibSimpleDataStore_Get(agentHost->masterDb, "AgentCapabilities",(char*) &dbCapabilities, 4);
			dbCapabilities = (int)ntohl(dbCapabilities);
			agentHost->capabilities |= dbCapabilities;
		}
	}


#ifdef WIN32
	// If running as a Windows service, set basic values to the registry, this allows other applications to know what the mesh agent is doing.
	{
		HKEY hKey;

#if defined(_WINSERVICE)
		// If running as a Windows Service, save the key in LOCAL_MACHINE
		if (RegCreateKey(HKEY_LOCAL_MACHINE, TEXT("Software\\Open Source\\MeshAgent2"), &hKey) == ERROR_SUCCESS)
#else
		// If running in Console mode, save the key in CURRENT_USER
		if (RegCreateKey(HKEY_CURRENT_USER, TEXT("Software\\Open Source\\MeshAgent2"), &hKey) == ERROR_SUCCESS)
#endif
		{
			int i, len;
			char* tmp = NULL;

			// Save the NodeId
			len = ILibBase64Encode(agentHost->g_selfid, UTIL_SHA384_HASHSIZE, &tmp);
			if ((len > 0) && (tmp != NULL)) {
				for (i = 0; i < len; i++) { if (tmp[i] == '+') { tmp[i] = '@'; } else if (tmp[i] == '/') { tmp[i] = '$'; } } // Replace + --> @ and / --> $
				RegSetValueExA(hKey, "NodeId", 0, REG_SZ, tmp, len);
				free(tmp);
				tmp = NULL;
			}
			else { RegDeleteKeyA(hKey, "NodeId"); }

			// Save the AgentHash
			util_tohex(agentHost->agentHash, UTIL_SHA384_HASHSIZE, ILibScratchPad);
			RegSetValueExA(hKey, "AgentHash", 0, REG_SZ, ILibScratchPad, (int)strlen(ILibScratchPad));

			// Save the MeshId
			if (ILibSimpleDataStore_Get(agentHost->masterDb, "MeshID", NULL, 0) == 0) { RegDeleteKeyA(hKey, "MeshId"); } else {
				len = ILibSimpleDataStore_Get(agentHost->masterDb, "MeshID", ILibScratchPad2, (int)sizeof(ILibScratchPad2));
				if (len > 0) {
					len = ILibBase64Encode(ILibScratchPad2, len, &tmp);
					if ((len > 0) && (tmp != NULL)) {
						for (i = 0; i < len; i++) { if (tmp[i] == '+') { tmp[i] = '@'; } else if (tmp[i] == '/') { tmp[i] = '$'; } } // Replace + --> @ and / --> $
						RegSetValueExA(hKey, "MeshId", 0, REG_SZ, tmp, len);
						free(tmp);
						tmp = NULL;
					}
					else { RegDeleteKeyA(hKey, "MeshId"); }
				}
				else { RegDeleteKeyA(hKey, "MeshId"); }
			}

			// Save a bunch of values in the registry
			if ((pLen = ILibSimpleDataStore_Get(agentHost->masterDb, "MeshServer", ILibScratchPad2, (int)sizeof(ILibScratchPad2))) == 0) { RegDeleteKeyA(hKey, "MeshServerUrl"); } else { RegSetValueExA(hKey, "MeshServerUrl", 0, REG_SZ, (BYTE*)ILibScratchPad2, (int)strlen(ILibScratchPad2)); } // Save the mesh server URL
			if ((pLen = ILibSimpleDataStore_Get(agentHost->masterDb, "ServerID", ILibScratchPad2, (int)sizeof(ILibScratchPad2))) == 0) { RegDeleteKeyA(hKey, "MeshServerId"); } else { RegSetValueExA(hKey, "MeshServerId", 0, REG_SZ, (BYTE*)ILibScratchPad2, (int)strlen(ILibScratchPad2)); } // Save the mesh server id
			if ((pLen = ILibSimpleDataStore_Get(agentHost->masterDb, "WebProxy", ILibScratchPad2, (int)sizeof(ILibScratchPad2))) == 0) { RegDeleteKeyA(hKey, "Proxy"); }  else { RegSetValueExA(hKey, "Proxy", 0, REG_SZ, (BYTE*)ILibScratchPad2, (int)strlen(ILibScratchPad2)); } // Save the proxy
			if ((pLen = ILibSimpleDataStore_Get(agentHost->masterDb, "Tag", ILibScratchPad2, (int)sizeof(ILibScratchPad2))) == 0) { RegDeleteKeyA(hKey, "Tag"); } else { RegSetValueExA(hKey, "Tag", 0, REG_SZ, (BYTE*)ILibScratchPad2, (int)strlen(ILibScratchPad2)); } // Save the tag

			// Close the registry key
			RegCloseKey(hKey);
		}
	}
#endif

#ifndef MICROSTACK_NOTLS
	if (agentHost->selftlscert.x509 == NULL) {
		// We don't have a TLS certificate, so setup the client without one.
		ILibWebClient_EnableHTTPS(agentHost->httpClientManager, NULL, NULL, ValidateMeshServer);
	} else {
		// We have a TLS certificate, use it for HTTPS client side auth (not super useful).
		ILibWebClient_EnableHTTPS(agentHost->httpClientManager, &(agentHost->selftlscert), agentHost->selfcert.x509, ValidateMeshServer);
	}
#endif

#if defined(_POSIX) && !defined(__APPLE__) // Excluding MacOS, becuase I found fork() doesn't work as expected on MacOS Sierra. Should be using launchctl on MacOS anyways
	if (paramLen >= 2)
	{
		if ((strcmp(param[1], "start") == 0 || strcmp(param[1], "-d") == 0)) options = 1;
		else if ((strcmp(param[1], "stop") == 0 || strcmp(param[1], "-s") == 0)) options = 2;
	}

	// Start
	if (options & 1)
	{
		FILE *fd = NULL;
		char str[15];
		pid_t pid, sid;
		size_t len;

		ILibSimpleDataStore_Close(agentHost->masterDb);
		agentHost->masterDb = NULL;
		pid = fork();
		if (pid < 0) { exit(EXIT_FAILURE); }
		else if (pid > 0)
		{
			len = snprintf(str, 15, "%d\r\n", pid);

#ifdef _ANDROID
			fd = fopen("/data/usr/tmp/meshagent.pid", "w");
#else
			fd = fopen("/var/run/meshagent.pid", "w");
#endif
			if (fd == NULL) fd = fopen(".meshagent.pid", "w");
			if (fd != NULL)
			{
				if (fwrite(str, sizeof(char), len, fd)) {}
				fclose(fd);
			}
			printf("Mesh agent started.\r\n");
			exit(EXIT_SUCCESS);
		}
		sid = setsid();
		if (sid < 0) { exit(EXIT_FAILURE); }
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		parseCommands = 0;
		agentHost->masterDb = ILibSimpleDataStore_Create(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db"));
	}
	else if (options) { exit(EXIT_SUCCESS); }
#endif

	if (parseCommands == 0 || paramLen == 1 || ((paramLen == 2) && (strcmp(param[1], "run") == 0 || strcmp(param[1], "connect") == 0)))
	{
#ifdef WIN32
		char* filePath = MeshAgent_MakeAbsolutePath(agentHost->exePath, ".update.exe");
#else
		char* filePath = MeshAgent_MakeAbsolutePath(agentHost->exePath, ".update");
#endif

		// Delete the mesh agent update file if there is one
		util_deletefile(filePath);

		// If there is a ".corereset" file, delete the core and remove the file.
		filePath = MeshAgent_MakeAbsolutePath(agentHost->exePath, ".corereset");
		if (ILibSimpleDataStore_Exists(filePath)) {
			ILibSimpleDataStore_Delete(agentHost->masterDb, "CoreModule"); // Clear the core from datastore
			util_deletefile(filePath);
		}

		// Check if there is a CoreModule in the db
		char *CoreModule;
		int CoreModuleLen = agentHost->localScript == 0 ? ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", NULL, 0) : 0;
		
		if (agentHost->meshCoreCtx != NULL)
		{
			ILibDuktape_MeshAgent_PUSH(agentHost->meshCoreCtx, agentHost->chain);								// [agent]
			duk_get_prop_string(agentHost->meshCoreCtx, -1, "emit");											// [agent][emit]
			duk_swap_top(agentHost->meshCoreCtx, -2);															// [emit][this]
			duk_push_string(agentHost->meshCoreCtx, "Ready");													// [emit][this][Ready]
			if (duk_pcall_method(agentHost->meshCoreCtx, 1) != 0) { ILibDuktape_Process_UncaughtException(agentHost->meshCoreCtx); }	
			duk_pop(agentHost->meshCoreCtx);																	// ...
		}

		if (agentHost->localScript == 0)
		{
			// Create the context for the Local CoreModule, regardless if we have one yet
			agentHost->meshCoreCtx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(0, 0, agentHost->chain, NULL, agentHost->masterDb, agentHost->exePath, agentHost->pipeManager, NULL, NULL);
			ILibDuktape_MeshAgent_Init(agentHost->meshCoreCtx, agentHost->chain, agentHost);

			ILibDuktape_SetNativeUncaughtExceptionHandler(agentHost->meshCoreCtx, MeshAgent_CoreModule_UncaughtException, agentHost);

			if (CoreModuleLen > 0)
			{
				if (ILibSimpleDataStore_Get(agentHost->masterDb, "noUpdateCoreModule", NULL, 0) != 0) 
				{ 
					// CoreModule Updates are disabled
					agentHost->localScript = 1; printf("** CoreModule: Update Disabled**\n"); 

					// If updates are disabled, then we should launch the core now
					CoreModule = (char*)ILibMemory_Allocate(CoreModuleLen, 0, NULL, NULL);
					ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", CoreModule, CoreModuleLen);

					if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(agentHost->meshCoreCtx, CoreModule + 4, CoreModuleLen - 4, "CoreModule.js", 13) != 0 ||
						ILibDuktape_ScriptContainer_ExecuteByteCode(agentHost->meshCoreCtx) != 0)
					{
						ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
							ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: %s", duk_safe_to_string(agentHost->meshCoreCtx, -1));
						duk_pop(agentHost->meshCoreCtx);
					}

					free(CoreModule);
				}
				else
				{
					// There's a CoreModule, but we should try to wait for the Server to verify the CoreModule before we run it.
					// Otherwise, we run the risk that if the module is bad and causes a crash, the server will have no way to
					// update/remedy the situation. We'll set a timeout, so if the server is unavailable, we'll run the core anyways.

					agentHost->coreTimeout = ILibDuktape_Timeout(agentHost->meshCoreCtx, (void**)(void*[]) { agentHost }, 1, 60000, MeshAgent_AgentMode_Core_ServerTimeout);
					duk_push_heap_stash(agentHost->meshCoreCtx);													// [stash]
					duk_push_heapptr(agentHost->meshCoreCtx, agentHost->coreTimeout);								// [stash][timeout]
					duk_put_prop_string(agentHost->meshCoreCtx, -2, Duktape_GetStashKey(agentHost->coreTimeout));	// [stash]
					duk_pop(agentHost->meshCoreCtx);																// ...
				}
			}
		}

		ILibIPAddressMonitor_Create(agentHost->chain, MeshAgent_AgentMode_IPAddressChanged_Handler, agentHost);
		
		MeshServer_Connect(agentHost);


		// We are acting as a mesh agent
		if (((ILibSimpleDataStore_Get(agentHost->masterDb, "MeshServer", ILibScratchPad, sizeof(ILibScratchPad))) > 5) && (memcmp(ILibScratchPad, "local", 5) == 0))
		{
			// Mesh agent is in local mode, start the multicast server discovery
			struct sockaddr_in multicastAddr4;
			struct sockaddr_in6 multicastAddr6;

			// Cleanup all addresses
			memset(&multicastAddr4, 0, sizeof(struct sockaddr_in));
			memset(&multicastAddr6, 0, sizeof(struct sockaddr_in6));

			// Setup addresses
			if (ILibDetectIPv6Support())
			{
				// IPv6 support
				multicastAddr6.sin6_family = AF_INET6;
				multicastAddr6.sin6_port = htons(16989);
				ILibInet_pton(AF_INET6, MESH_MCASTv6_GROUP, &(multicastAddr6.sin6_addr));
			}

			// Setup multicastAddr4
			multicastAddr4.sin_family = AF_INET;
			multicastAddr4.sin_port = htons(16989);
			ILibInet_pton(AF_INET, MESH_MCASTv4_GROUP, &(multicastAddr4.sin_addr));

			// Multicast socket on fixed port, will receive multicast from the server.
			agentHost->multicastDiscovery = ILibMulticastSocket_Create(agentHost->chain, 1024, MESH_AGENT_PORT, &multicastAddr4, &multicastAddr6, UDPSocket_OnData, agentHost, 1);
			if (agentHost->multicastDiscovery == NULL) { ILIBMARKPOSITION(219); return 1; }

			// Multicast socket on a random port, used to multicast to the server and receive server unicast responses.
			agentHost->multicastDiscovery2 = ILibMulticastSocket_Create(agentHost->chain, 1024, 0, &multicastAddr4, &multicastAddr6, UDPSocket_OnData, agentHost, 1);
			if (agentHost->multicastDiscovery2 == NULL) { ILIBMARKPOSITION(219); return 1; }
		}

		return 1;
	}
	return 0;
}

void MeshAgent_ScriptMode_UncaughtExceptionSink(duk_context *ctx, char *msg, void *user)
{
	printf("*** UNCAUGHT EXCEPTION: %s ***\n", msg);
	//ScriptEngine_Exit((MeshAgentHostContainer*)user, MeshAgent_JavaCore_ContextGuid, 254);
}

void MeshAgent_ScriptMode_MeshDesktop_PUSH(duk_context *ctx, void *chain)
{
	duk_push_heap_stash(ctx);									// [stash]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, "\xFF_MeshDesktop_AgentPtr");
	duk_pop(ctx);

	duk_push_object(ctx);
	ILibDuktape_WriteID(ctx, "MeshDesktop");
	if (agent != NULL)
	{
		duk_push_pointer(ctx, agent);
		duk_put_prop_string(ctx, -2, MESH_AGENT_PTR);

		ILibDuktape_CreateInstanceMethod(ctx, "getRemoteDesktopStream", ILibDuktape_MeshAgent_getRemoteDesktop, 0);
	}
}

void MeshAgent_ScriptMode(MeshAgentHostContainer *agentHost, int argc, char **argv)
{
	char *jsFile;
	int jsFileLen;
	int i;
	unsigned int execTimeout = 0;
	unsigned int secFlags = 0;
	char **scriptArgs = NULL;
	char *jsPath;
	int sx = 1;
	int connectAgent = 0;
	int pathLen = 0;

	if (agentHost->meshCoreCtx_embeddedScript == NULL)
	{
		// Get the full path name of the JavaScript file
#ifdef WIN32
		pathLen = GetFullPathName(argv[1], sizeof(ILibScratchPad2), ILibScratchPad2, NULL);
#else
		if (realpath(argv[1], ILibScratchPad2) != NULL) { pathLen = strnlen_s(ILibScratchPad2, PATH_MAX); }
#endif

		// Try to load the JavaScript file from disk, if fail, return
		jsFileLen = ILibReadFileFromDiskEx(&jsFile, ILibScratchPad2);
		if (jsFileLen == 0) { printf("ERROR loading %s\n", ILibScratchPad2); return; }

		// We need to pass the JavaScript full path to the JavaScript runtime as the first argument. Set the up here.
		scriptArgs = (char**)ILibMemory_Allocate((1 + argc) * sizeof(char*), 1 + pathLen, NULL, (void**)&jsPath);		// KLOCWORK is being dumb, becuase ILibScratchpad2 is gauranteed to be NULL terminated
		strncpy_s(jsPath, ILibMemory_GetExtraMemorySize(jsPath), ILibScratchPad2, ILibMemory_GetExtraMemorySize(jsPath));
		scriptArgs[0] = jsPath;

#ifdef WIN32
		i = ILibString_LastIndexOf(ILibScratchPad2, pathLen, "\\", 1);
#else
		i = ILibString_LastIndexOf(ILibScratchPad2, pathLen, "/", 1);
#endif
		ILibScratchPad2[i] = 0;
#ifdef WIN32
		SetCurrentDirectory(ILibScratchPad2);
#else
		ignore_result(chdir(ILibScratchPad2));
#endif

		// Parse arguments. Handle the ones we can, others will be passed to the JavaScript engine. 
		for (i = 2; i < argc; ++i)
		{
			if (agentHost->masterDb == NULL && strncmp(argv[i], "--script-db", 11) == 0 && ((i + 1) < argc))
			{
				// Specify DB file path
				agentHost->masterDb = ILibSimpleDataStore_Create(MeshAgent_MakeAbsolutePath(agentHost->exePath, argv[i + 1]));
				++i;
			}
			else if (strncmp(argv[i], "--script-flags", 14) == 0 && ((i + 1) < argc))
			{
				// JS Permissions (see .h for values)
				if (ntohs(((unsigned short*)argv[i + 1])[0]) == HEX_IDENTIFIER)
				{
					int xlen = (int)strnlen_s(argv[i + 1], 32);
					if (xlen <= 10)
					{
						util_hexToBuf(argv[i + 1] + 2, xlen - 2, (char*)&secFlags);
						secFlags = ntohl(secFlags);
					}
					++i;
				}
			}
			else if (strncmp(argv[i], "--script-timeout", 16) == 0 && ((i + 1) < argc))
			{
				// Seconds before watchdog termination, 0 for unlimited
				execTimeout = (unsigned int)atoi(argv[i + 1]);
				++i;
			}
			else if (strncmp(argv[i], "--script-connect", 16) == 0)
			{
				// Connect to MeshCentral
				connectAgent = 1;
				if (agentHost->masterDb == NULL)
				{
					agentHost->masterDb = ILibSimpleDataStore_Create(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db"));
				}
			}
			else
			{
				// Unhandled arguments, passed to JavaScript
				scriptArgs[sx++] = argv[i];
			}
		}
	}
	else
	{
		// Embedded JavaScript
		jsFile = agentHost->meshCoreCtx_embeddedScript;
		jsFileLen = agentHost->meshCoreCtx_embeddedScriptLen;
		scriptArgs = (char**)ILibMemory_Allocate((1 + argc) * sizeof(char*), 0, NULL, NULL);
		for (i = 1; i < argc; ++i)
		{
			scriptArgs[i] = argv[i];
		}
		scriptArgs[i] = NULL;
		scriptArgs[0] = agentHost->exePath;
	}

	// Start the JavaScript engine, run the loaded .js file
	agentHost->localScript = 1;

	agentHost->meshCoreCtx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(secFlags, execTimeout, agentHost->chain, scriptArgs, connectAgent != 0 ? agentHost->masterDb : NULL, agentHost->exePath, agentHost->pipeManager, connectAgent == 0 ? MeshAgent_RunScriptOnly_Finalizer : NULL, agentHost);
	ILibDuktape_SetNativeUncaughtExceptionHandler(agentHost->meshCoreCtx, MeshAgent_ScriptMode_UncaughtExceptionSink, agentHost);
	if (connectAgent != 0) 
	{ 
		ILibDuktape_MeshAgent_Init(agentHost->meshCoreCtx, agentHost->chain, agentHost); 
	}
	else
	{
		duk_push_heap_stash(agentHost->meshCoreCtx);									// [stash]
		duk_push_pointer(agentHost->meshCoreCtx, agentHost);							// [stash][ptr]
		duk_put_prop_string(agentHost->meshCoreCtx, -2, "\xFF_MeshDesktop_AgentPtr");	// [stash]
		duk_pop(agentHost->meshCoreCtx);												// ...
		ILibDuktape_ModSearch_AddHandler(agentHost->meshCoreCtx, "meshDesktop", MeshAgent_ScriptMode_MeshDesktop_PUSH);
	}

	if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(agentHost->meshCoreCtx, jsFile, jsFileLen, agentHost->meshCoreCtx_embeddedScript == NULL ? scriptArgs[0] : "[embedded].js", 0) != 0 || ILibDuktape_ScriptContainer_ExecuteByteCode(agentHost->meshCoreCtx) != 0)
	{
		if (strcmp(duk_safe_to_string(agentHost->meshCoreCtx, -1), "Process.exit() forced script termination") != 0)
		{
			// Error
			ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "Script Error: %s", duk_safe_to_string(agentHost->meshCoreCtx, -1));
		}
		duk_pop(agentHost->meshCoreCtx);
	}

	// JavaScript copies this, we do not need this anymore.
	free(jsFile);
	free(scriptArgs);

	// If in agent mode, setup the chain to be a mesh agent
	if (connectAgent != 0) 
	{
		printf("MeshCentral2 Agent\r\n"); // MESH_AGENT_VERSION
		if (MeshAgent_AgentMode(agentHost, argc, argv, 0) == 0) 
		{
			ILibStopChain(agentHost->chain); // Agent Error, stop the chain
		}
	}
}

void MeshAgent_ScriptMode_Dispatched(void *chain, void *user)
{
	MeshAgent_ScriptMode((MeshAgentHostContainer*)((void**)user)[0], ((int*)((void**)user)[1])[0], (char**)((void**)user)[2]);
}
void MeshAgent_AgentMode_Dispatched(void *chain, void *user)
{
	printf("MeshCentral2 Agent\r\n"); // MESH_AGENT_VERSION
	if (MeshAgent_AgentMode((MeshAgentHostContainer*)((void**)user)[0], ((int*)((void**)user)[1])[0], (char**)((void**)user)[2], 1) == 0)
	{
		ILibStopChain(((MeshAgentHostContainer*)((void**)user)[0])->chain);
	}
}


#ifdef _POSIX
int MeshAgent_System(char *cmd)
{
	//int status = -1;
	pid_t pid = fork();

	if(pid == 0)
	{
		// Child
		execv("/bin/sh", (char**)(char*[]) { "sh", "-c", cmd, (char*)0 });
		_exit(1);
	}
	else if (pid > 0)
	{
		// Parent
		//waitpid(pid, &status, 0);
	}
	return(0);
}

#endif

int MeshAgent_Start(MeshAgentHostContainer *agentHost, int paramLen, char **param)
{
	char exePath[1024];
#ifdef WIN32
	int x;
#elif defined(__APPLE__)
	uint32_t len = 1024;
#elif defined(NACL)
	// Do nothing
#else
	int x;
#endif

#if defined(WIN32) && defined(_LINKVM) && !defined(WINSERVICE)
	SetProcessDPIAware();
#endif

	if ((paramLen == 1 && strcmp(param[0], "--slave") == 0) || (paramLen == 2 && strcmp(param[1], "--slave") == 0)) { MeshAgent_Slave(agentHost); return 0; }
#ifndef __APPLE__
	if (paramLen == 2 && strcmp(param[1], "--netinfo") == 0) { char* data; int len = MeshInfo_GetSystemInformation(&data); if (len > 0) { printf("%s\r\n", data); free(data); } return 0; }
#endif

	if (agentHost->exePath == NULL)
	{
		agentHost->exePath = exePath;
		exePath[0] = 0;

#ifdef WIN32
		GetModuleFileName(NULL, exePath, sizeof(exePath));
#elif defined(__APPLE__)
		if (_NSGetExecutablePath(exePath, &len) != 0) ILIBCRITICALEXIT(247);
		exePath[(int)len] = 0;
		agentHost->exePath = exePath;
#elif defined(NACL)
#else
		x = readlink("/proc/self/exe", exePath, 1024);
		if (x < 0 || x >= 1024) ILIBCRITICALEXIT(246);
		exePath[x] = 0;
#endif
	}

	// Perform a self SHA384 Hash
	GenerateSHA384FileHash(agentHost->exePath, agentHost->agentHash);

#ifdef _REMOTELOGGINGSERVER
	{
		int len;
		if (agentHost->masterDb == NULL && ILibSimpleDataStore_Exists(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db")) != 0)
		{
			agentHost->masterDb = ILibSimpleDataStore_Create(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db"));
			if (agentHost->masterDb != NULL)
			{
				if ((len = ILibSimpleDataStore_Get(agentHost->masterDb, "enableILibRemoteLogging", ILibScratchPad, sizeof(ILibScratchPad))) != 0)
				{
					ILibScratchPad[len] = 0;
					ILibStartDefaultLoggerEx(agentHost->chain, (unsigned short)atoi(ILibScratchPad), MeshAgent_MakeAbsolutePath(agentHost->exePath, ".wlg"));
				}
				ILibSimpleDataStore_Close(agentHost->masterDb);
				agentHost->masterDb = NULL;
			}
		}
	}
#endif
	ILibCriticalLogFilename = ILibString_Copy(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".log"), -1);
#ifndef MICROSTACK_NOTLS
	util_openssl_init();
#endif

	ILibChain_OnDestroyEvent_AddHandler(agentHost->chain, MeshAgent_ChainEnd, agentHost);

#ifdef WIN32
	x = ILibString_LastIndexOf(param[0], -1, "\\", 1);
	if (x > 0)
	{
		strncpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), param[0], x);
		ILibScratchPad2[x] = 0;
		SetCurrentDirectory(ILibScratchPad2);
	}
#endif

	void *reserved[] = { agentHost, &paramLen, param };

	// Check to see if we are running as just a JavaScript Engine
	if (agentHost->meshCoreCtx_embeddedScript != NULL || (paramLen >= 2 && ILibString_EndsWith(param[1], -1, ".js", 3) != 0))
	{ 
		// We are acting as a scripting engine
		ILibChain_RunOnMicrostackThreadEx(agentHost->chain, MeshAgent_ScriptMode_Dispatched, reserved);
		ILibStartChain(agentHost->chain);
		agentHost->chain = NULL; 
	}
	else
	{
		// We are acting as an Agent
		ILibChain_RunOnMicrostackThreadEx(agentHost->chain, MeshAgent_AgentMode_Dispatched, reserved);
		ILibStartChain(agentHost->chain);
		agentHost->chain = NULL; // Mesh agent has exited, set the chain to NULL

		// Close the database
		if (agentHost->masterDb != NULL) {
			ILibSimpleDataStore_Close(agentHost->masterDb);
			agentHost->masterDb = NULL;
		}

		// Check if we need to perform self-update (performSelfUpdate should indicate startup type on Liunx: 1 = systemd, 2 = upstart, 3 = sysv-init)
		if (agentHost->performSelfUpdate != 0)
		{
			int i, ptr = 0;
#ifdef WIN32
			STARTUPINFOA info = { sizeof(info) };
			PROCESS_INFORMATION processInfo;
#endif
			// Get the update executable path
#ifdef WIN32
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agentHost->exePath, ".update.exe"); // uses ILibScratchPad2
#else
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agentHost->exePath, ".update"); // uses ILibScratchPad2
#endif
			char str[4096];				

			if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Updating..."); }

			// Build the argument list
			str[0] = 0;
			for (i = 1; i < paramLen && ptr >= 0; i++) ptr += sprintf_s(str + ptr, 4096 - ptr, " %s", param[i]);

#ifdef WIN32
			// Windows version
			sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "%s -update:\"%s\"%s", updateFilePath, agentHost->exePath, str);
			if (!CreateProcessA(NULL, ILibScratchPad, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &info, &processInfo))
			{
				// We tried to execute a bad executable... not good. Lets try to recover.
				if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> FAILED..."); }
				if (updateFilePath != NULL && agentHost->exePath != NULL)
				{
					while (util_CopyFile(agentHost->exePath, updateFilePath, FALSE) == FALSE) Sleep(5000);
					if (CreateProcessA(NULL, ILibScratchPad, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &info, &processInfo))
					{
						CloseHandle(processInfo.hProcess);
						CloseHandle(processInfo.hThread);
					}
				}
			}
			else
			{
				CloseHandle(processInfo.hProcess);
				CloseHandle(processInfo.hThread);
			}
#else
			if (MeshAgent_Helper_IsService() != 0)
			{
				// We were started as a service
				if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Service Check... [YES]"); }

				MeshAgent_Posix_PlatformTypes pt = MeshAgent_Posix_GetPlatformType();
				if (pt != MeshAgent_Posix_PlatformTypes_UNKNOWN)
				{
					struct stat results;
					stat(agentHost->exePath, &results); // This the mode of the current executable
					chmod(updateFilePath, results.st_mode); // Set the new executable to the same mode as the current one.

					sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "mv \"%s\" \"%s\"", updateFilePath, agentHost->exePath); // Move the update over our own executable
					if (system(ILibScratchPad)) {}

					switch (pt)
					{
#ifdef __APPLE__
						case MeshAgent_Posix_PlatformTypes_LAUNCHD:
							if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Complete... [LAUNCHD should auto restart]"); }
							write(STDOUT_FILENO, "Finishing update...\n", 20);
							fsync(STDOUT_FILENO);
							exit(1); // We're exiting here, to restart via KeepAlive (LaunchD doesn't support an explicit 'restart')
							break;
#endif
						case MeshAgent_Posix_PlatformTypes_SYSTEMD:
							if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Complete... Issuing SYSTEMD restart"); }
							sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "systemctl restart meshagent"); // Restart the service
							ignore_result(MeshAgent_System(ILibScratchPad));
							break;
						case MeshAgent_Posix_PlatformTypes_INITD:
							if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Complete... Calling Service Start (INITD)"); }
							sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "service meshagent start");	// Restart the service
							ignore_result(MeshAgent_System(ILibScratchPad));
							break;
						default:
							break;
					}
				}
			}
			else
			{
				if (agentHost->logUpdate != 0) 
				{
					ILIBLOGMESSSAGE("SelfUpdate -> Service Check... [NO]");
					ILIBLOGMESSSAGE("SelfUpdate -> Manual Mode (COMPLETE)");
				}

				// Generic update process, call our own update with arguments.
				struct stat results;
				stat(agentHost->exePath, &results); // This the mode of the current executable
				chmod(updateFilePath, results.st_mode); // Set the new executable to the same mode as the current one.
				sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "\"%s\" -update:\"%s\"%s &", updateFilePath, agentHost->exePath, str); // Launch the new executable for update.
				if (system(ILibScratchPad)) {}
			}
#endif
		}
	}

	
#ifndef MICROSTACK_NOTLS
	util_openssl_uninit();
#endif
	if (ILibCriticalLogFilename != NULL) free(ILibCriticalLogFilename);
	return 0;
}


void MeshAgent_Destroy(MeshAgentHostContainer* agent)
{
#ifndef MICROSTACK_NOTLS
	util_freecert(&agent->selftlscert);
	util_freecert(&agent->selfcert);
#endif

	if (agent->masterDb != NULL) { ILibSimpleDataStore_Close(agent->masterDb); agent->masterDb = NULL; }
	if (agent->chain != NULL) { ILibChain_DestroyEx(agent->chain); agent->chain = NULL; }
	free(agent);
}
void MeshAgent_Stop(MeshAgentHostContainer *agent)
{
	ILibStopChain(agent->chain);
}



#ifdef WIN32
// Perform self-update (Windows console/tray version)
void MeshAgent_PerformSelfUpdate(char* selfpath, char* exepath, int argc, char **argv)
{
	int i, ptr = 0;
	STARTUPINFOA info = { sizeof(info) };
	PROCESS_INFORMATION processInfo;

	// Sleep for 5 seconds, this will give some time for the calling process to get going.
	Sleep(5000);

	// Built the argument list
	ILibScratchPad[0] = 0;
	for (i = 2; i < argc; i++) ptr += sprintf_s(ILibScratchPad + ptr, 4096 - ptr, " %s", argv[i]);
	sprintf_s(ILibScratchPad2, 60000, "%s%s", exepath, ILibScratchPad);

	// Attempt to copy our own exe over the original exe
	while (util_CopyFile(selfpath, exepath, FALSE) == FALSE) Sleep(5000);

	// Now run the process
	if (!CreateProcessA(NULL, ILibScratchPad2, NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
	{
		// TODO: Failed to run update.
	}
	else
	{
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
	}
}
/*
#elif defined(__APPLE__) && defined(_DAEMON)
// Perform self-update (Apple Daemon)
void MeshAgent_PerformSelfUpdate(char* selfpath, char* exepath, int argc, char **argv)
{
int i;

// First, we wait a little to give time for the calling process to exit
sleep(5);

// Attempt to copy our own exe over the
remove(exepath);
snprintf(ILibScratchPad2, 6000, "cp %s %s", selfpath, exepath);
while (system(ILibScratchPad2) != 0)
{
sleep(5);
remove(exepath);
}

// Now run the updated process
i = system("/sbin/SystemStarter restart \"MeshAgent\"");
UNREFERENCED_PARAMETER(i);
}
*/
#elif ANDROID
// no self update
#elif NACL
// no self update
#else
// Perform self-update (Linux version)
void MeshAgent_PerformSelfUpdate(char* selfpath, char* exepath, int argc, char **argv)
{
	int i, ptr = 0;

	// First, we wait a little to give time for the calling process to exit
	sleep(5);

	// Attempt to copy our own exe over 
	remove(exepath);
	sprintf_s(ILibScratchPad2, 6000, "cp \"%s\" \"%s\"", selfpath, exepath);
	while (system(ILibScratchPad2) != 0)
	{
		sleep(5);
		remove(exepath);
	}

	// Built the argument list
	ILibScratchPad[0] = 0;
	for (i = 2; i < argc && ptr >= 0; i++) ptr += sprintf_s(ILibScratchPad + ptr, 4096 - ptr, " %s", argv[i]);
	sprintf_s(ILibScratchPad2, 60000, "%s%s &", exepath, ILibScratchPad);

	// Now run the updated process
	i = system(ILibScratchPad2);
	UNREFERENCED_PARAMETER(i);
}
#endif


#ifdef __DOXY__
/*!
\implements EventEmitter
\brief JavaScript object interface for native Mesh Agent
*/
class MeshAgent
{
public:
	/*!
	\brief Event emitted when the MeshAgent is initialized and ready to connect
	*/
	void Ready;
	/*!
	\brief Event emitted when the MeshAgent has established an authenticated control channel with the server
	*/
	void Connected;
	void kvmConnected;
	/*!
	\brief Event emitted when an LMS notification is received
	\param notification <Object> Notification object in the format:\n
	<b>messageId</b> \<String\> 
	<b>indicationTime</b> \<String\> 
	<b>messageArguments</b> \<String\> 
	<b>rawXML</b> \<String\> 
	*/
	void lmsNotification;
	/*!
	\brief The Mesh Server the agent is connected to. If LAN Mode, will be 'local'
	*/
	String ConnectedServer;
	/*!
	\brief The fully qualified network uri that the agent is connected to (ie: <b>wss://www.meshcentral.com:443/agent.ashx</b>)
	*/
	String ServerUrl;
	/*!
	\brief Returns a DuplexStream KVM session, that can be piped to a data channel. 
	*/
	DuplexStream getRemoteDesktopStream();

	/*!
	\brief Add a function callback to be added to the list of Command listeners, which gets dispatched whenever a command is received from the server.
	\param handler <func>
	*/
	void AddCommandHandler(handler);
	/*!
	\brief Add a function callback that will get dispatched when the MeshAgent successfully establishes an authenticated control channel with the server
	\param handler <func>
	*/
	void AddConnectHandler(handler);
	/*!
	\brief Send a command to the server
	\param cmd \<Buffer\|String\|Object\> Command to send
	\return <bool> False if the calling code should wait for the 'drain' event before sending more commands
	*/
	bool SendCommand(cmd);
	/*!
	\brief Property indicating if MicroLMS is active
	*/
	Integer activeMicroLMS;
	/*!
	\brief Property indicating if KVM Support is present
	*/
	Integer hasKVM;
	/*!
	\brief Property indicating if HECI support is present
	*/
	Integer hasHECI;
	/*!
	\brief Property containing MEInfo
	*/
	Object MEInfo;
	/*!
	\brief Property containing NetInfo
	*/
	Object NetInfo;

	/*!
	\brief Executes power state command on the computer (ie: Sleep, Hibernate...)
	\param powerState <Integer> 
	\param force <Integer> Optional
	\return <Integer> status
	*/
	Integer ExecPowerState(powerState[, force]);

	/*!
	\brief Generates a new self signed certificate
	\param passphrase \<String\> passphrase for private key
	\return \<Buffer\> PKS encoded certificate
	*/
	Buffer GenerateCertificate(passphrase);
};
#endif
