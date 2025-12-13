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

#ifndef __AGENTCORE__
#define __AGENTCORE__


typedef char JS_ENGINE_CONTEXT[16];

#ifdef WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#include <Windows.h>
#include <WinBase.h>
#endif

#include "microstack/ILibParsers.h"
#include "microstack/ILibWebServer.h"
#include "microstack/ILibWebClient.h"
#include "microstack/ILibSimpleDataStore.h"
#include "microstack/ILibRemoteLogging.h"
#include "microstack/ILibProcessPipe.h"
#include "microscript/duktape.h"
#include "microscript/ILibDuktape_WebRTC.h"
#include "microscript/ILibDuktape_net.h"
#include "microscript/ILibDuktapeModSearch.h"
#include "microscript/ILibDuktape_GenericMarshal.h"
#include "microscript/ILibDuktape_SimpleDataStore.h"
#include "microscript/ILibDuktape_fs.h"
#include "microstack/ILibProcessPipe.h"
#include "microstack/ILibCrypto.h"

#define ILibDuktape_MeshAgent_LoggedOnUsers	"\xFF_MeshAgent_LoggedOnUsers"

typedef enum MeshAgent_Posix_PlatformTypes
{
	MeshAgent_Posix_PlatformTypes_UNKNOWN = 0,
	MeshAgent_Posix_PlatformTypes_SYSTEMD = 1,
	MeshAgent_Posix_PlatformTypes_INITD = 2,
	MeshAgent_Posix_PlatformTypes_INIT_UPSTART = 4,
	MeshAgent_Posix_PlatformTypes_LAUNCHD = 3,
	MeshAgent_Posix_PlatformTypes_BSD = 5,
	MeshAgent_Posix_PlatformTypes_WINDOWS = 10,
	MeshAgent_Posix_PlatformTypes_PROCD = 7
}MeshAgent_Posix_PlatformTypes;

typedef enum MeshCommand_AuthInfo_CapabilitiesMask
{
	MeshCommand_AuthInfo_CapabilitiesMask_DESKTOP = 0x01,
	MeshCommand_AuthInfo_CapabilitiesMask_TERMINAL = 0x02,
	MeshCommand_AuthInfo_CapabilitiesMask_FILES = 0x04,
	MeshCommand_AuthInfo_CapabilitiesMask_CONSOLE = 0x08,
	MeshCommand_AuthInfo_CapabilitiesMask_JAVASCRIPT = 0x10,
	MeshCommand_AuthInfo_CapabilitiesMask_TEMPORARY = 0x20,
	MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY = 0x40,
	MeshCommand_AuthInfo_CapabilitiesMask_RESERVED = 0x80,
	MeshCommand_AuthInfo_CapabilitiesMask_COMPRESSION = 0x100
}MeshCommand_AuthInfo_CapabilitiesMask;

typedef enum AgentIdentifiers
{
	AGENTID_UNKNOWN = 0,  //!< Self-update not supported
	AGENTID_WIN32_CONSOLE = 1,  //!< Windows x86 console app
	AGENTID_WIN64_CONSOLE = 2,  //!< Windows x86-64 console app
	AGENTID_WIN32_SERVICE = 3,  //!< Windows x86 service
	AGENTID_WIN64_SERVICE = 4,  //!< Windows x86-64 service
	AGENTID_LINUX32 = 5,  //!< Linux x86
	AGENTID_LINUX64 = 6,  //!< Linux x64
	AGENTID_MIPS = 7,  //!< MIPS (used for home routers)
	AGENTID_XEN_x86 = 8,  //!< XEN Virtualization
	AGENTID_ANDROID_ARM = 9,  //!< Android ARM devices
	AGENTID_LINUX_ARM = 10, //!< Linux/ARM, used for PlugPC
	AGENTID_MAC_OSX = 11, //!< Apple MAC OS X
	AGENTID_ANDROID_x86 = 12, //!< Android/x86
	AGENTID_POGOPLUG_ARM = 13, //!< PogoPlug/ARM
	AGENTID_ANDROID_APK = 14, //!< Android Market
	AGENTID_LINUX_POKY_X86 = 15, //!< Intel Galileo
	AGENTID_MAC_OSX64 = 16, //!< Apple MAC OSX (64 bit)
	AGENTID_CHROMEOS = 17, //!< ChromeOS
	AGENTID_LINUXPOKY64 = 18, //!< Linux Poky (64 bit)
	AGENTID_LINUX_NOKVM_X86 = 19, //!< Linux NOKVM (32 bit)
	AGENTID_LINUX_NOKVM_X64 = 20, //!< Linux NOKVM (64 bit)
	AGENTID_WIN32_MIN_CONSOLE = 21, //!< Windows MinCore Console (32 bit)
	AGENTID_WIN32_MIN_SERVICE = 22,				//!< Windows MinCore Service (32 bit)
	AGENTID_NODEJS = 23							//!< NodeJS agent
}AgentIdentifiers;

// MeshServer to/from MeshAgent commands.
// Commands 0 to 9 are reserved for client/server authentication, once authenticated they can't be used and must not be processed.
// Commands 10 and above must only be processed if the server is authenticated. All these commands have 2 bytes commandid + 2 bytes requestid.
// Commands with an id that starts with '{' (123, 0x7B) are reserved for JSON commands, that is commands 31488 (0x7B00) to 31743 (0x7BFF)
typedef enum MeshCommands_Binary
{
	MeshCommand_AuthRequest				= 1,    // Server web certificate public key sha384 hash + agent or server nonce
	MeshCommand_AuthVerify				= 2,    // Agent or server signature
	MeshCommand_AuthInfo				= 3,	// Agent information
	MeshCommand_AuthConfirm             = 4,	// Server confirm to the agent that is it authenticated
	MeshCommand_ServerId				= 5,	// Optional, agent sends the expected serverid to the server. Useful if the server has many server certificates.
	MeshCommand_CoreModule				= 10,	// New core modules to be used instead of the old one, if empty, remove the core module
	MeshCommand_CompressedCoreModule	= 20,
	MeshCommand_CoreModuleHash			= 11,	// Request/return the SHA384 hash of the core module
	MeshCommand_AgentCommitDate			= 30,	// Commit Date that the agent was built with
	MeshCommand_AgentHash				= 12,	// Request/return the SHA384 hash of the agent executable
	MeshCommand_AgentUpdate				= 13,   // Indicate the start and end of the mesh agent binary transfer
	MeshCommand_AgentUpdateBlock		= 14,   // Part of the mesh agent sent from the server to the agent, confirmation/flowcontrol from agent to server
	MeshCommand_AgentTag				= 15,	// Send the mesh agent tag to the server
	MeshCommand_CoreOk					= 16,	// Sent by the server to indicate the meshcore is ok
	MeshCommand_HostInfo				= 31,	// Host OS and CPU Architecture

} MeshCommands_Binary;

#pragma pack(push,1)
typedef struct MeshAgent_Commands_SCRIPT_CreateContext
{
	unsigned short CommandType;
	JS_ENGINE_CONTEXT ContextGUID;
	unsigned int SecurityFlags;
	unsigned int ExecutionTimeout;
}MeshAgent_Commands_SCRIPT_CreateContext;
typedef struct MeshAgent_Commands_SCRIPT_DeleteContext
{
	unsigned short CommandType;
	JS_ENGINE_CONTEXT ContextGUID;
}MeshAgent_Commands_SCRIPT_DeleteContext;
typedef struct MeshAgent_Commands_SCRIPT_ExecuteString
{
	unsigned short CommandType;
	JS_ENGINE_CONTEXT ContextGUID;
	char script[];
}MeshAgent_Commands_SCRIPT_ExecuteString;
#pragma pack(pop)

typedef enum MeshAgentHost_BatteryInfo
{
	MeshAgentHost_BatteryInfo_HIGH			= 1,
	MeshAgentHost_BatteryInfo_LOW			= 2,
	MeshAgentHost_BatteryInfo_CRITICAL		= 4,
	MeshAgentHost_BatteryInfo_CHARGING		= 8,
	MeshAgentHost_BatteryInfo_NONE			= 3,
	MeshAgentHost_BatteryInfo_UNKNOWN		= 0,
}MeshAgentHost_BatteryInfo;

extern char* MeshAgentHost_BatteryInfo_STRINGS[];

#ifdef WIN32
typedef HRESULT (__stdcall *DpiAwarenessFunc)(PROCESS_DPI_AWARENESS);
typedef int (WSAAPI *GetHostNameWFunc)(PWSTR name, int namelen);
#endif

typedef struct MeshAgentHostContainer
{
	void* chain;
	int slaveMode;

	duk_context *meshCoreCtx;
	duk_context *bootstrapCoreCtx;
	char *meshCoreCtx_embeddedScript;
	int meshCoreCtx_embeddedScriptLen;
	ILibProcessPipe_Manager *pipeManager;

	char* exePath;
	ILibWebClient_RequestManager httpClientManager;
	ILibSimpleDataStore masterDb;
	int configPathUsesCWD;
	ILibWebClient_StateObject controlChannel;
	struct sockaddr_in6* proxyServer;
	int proxyFailed;
	void *controlChannelRequest;

#ifdef WIN32
	void *shCore;
	DpiAwarenessFunc dpiAwareness;
	char DNS_LOCK[255];
	char ID_LOCK[255];
#endif

	int showModuleNames;
	int localScript;
	int agentMode;
	int version;
	int capabilities; // Extra agent capabilities indicated to the server from MeshCommand_AuthInfo_CapabilitiesMask
	char hostname[255];
	char serveruri[1024];
	char serverip[1024];
	AgentIdentifiers agentID;
	int serverIndex;
	int triedNoProxy_Index;
	int retryTime;
	MeshAgentHost_BatteryInfo batteryState;
	char meshId[UTIL_SHA384_HASHSIZE];
	int performSelfUpdate;
	int disableUpdate;
	int forceUpdate;
	int logUpdate;
	int fakeUpdate;
	int controlChannelDebug;
	void *coreTimeout;
	int jsDebugPort;
	int coreDumpEnabled;
	int localConsentMask;
	int localdebugmode;

	char agentHash[UTIL_SHA384_HASHSIZE];
	char serverHash[UTIL_SHA384_HASHSIZE];
#ifndef MICROSTACK_NOTLS
#ifdef WIN32
	int noCertStore;
	void* certObject;
#endif
	struct util_cert selfcert;
	struct util_cert selftlscert;
	char serverWebHash[UTIL_SHA384_HASHSIZE];
#endif

	char serverNonce[UTIL_SHA384_HASHSIZE];
	char agentNonce[UTIL_SHA384_HASHSIZE];
	int serverAuthState;

	int timerLogging;
	int retryTimerSet;
	int controlChannel_idleTimeout_seconds;
	int controlChannel_idleTimeout_dataMode;
	char g_selfid[UTIL_SHA384_HASHSIZE];
	void* microLMS;
	void* multicastDiscovery;
	void* multicastDiscovery2;
	void* multicastDiscoveryKey;
	char* multicastServerUrl;
	int serverConnectionState;
	int exitCode;
	int dbRetryCount;
	MeshAgent_Posix_PlatformTypes platformType;
	int JSRunningAsService;
	int JSRunningWithAdmin;
	int updaterVersion;
	char **execparams;
	char *meshServiceName;
	char *displayName;
	int serviceReserved;
	long consoleText_timeStamp;
	int consoleText_counter;
	int consoleText_maxRate;
	int autoproxy_status;
#if defined(_WINSERVICE)
	int runningAsConsole;
#endif
}MeshAgentHostContainer;

MeshAgentHostContainer* MeshAgent_Create(MeshCommand_AuthInfo_CapabilitiesMask capabilities);
void MeshAgent_Destroy(MeshAgentHostContainer* agent);

int MeshAgent_Start(MeshAgentHostContainer *agent, int argc, char **argv);
void MeshAgent_Stop(MeshAgentHostContainer *agent);
void MeshAgent_PerformSelfUpdate(char* selfpath, char* exepath, int argc, char **argv);
char* MeshAgent_MakeAbsolutePathEx(char *basePath, char *localPath, int escapeBackSlash);
#define MeshAgent_MakeAbsolutePath(basePath, localPath) MeshAgent_MakeAbsolutePathEx(basePath, localPath, 0)



/* List of DB Keys that can be set, to alter behavior of the Mesh Agent
*
*
AgentCapabilities:			Integer Mask, specifying supported Agent Capabilities	
agentName					If set, this will be sent to the server instead of the hostname
compactDirtyMinimum			Minimum dirty bytes threshold for db.compact() operation
consoleTextMaxRate:			Sets rate limit for sendConsoleText. Default is 10 messages per second.
controlChannelDebug:		If set, will log/display controlChannel messages (Except for JSON messages)
controlChannelIdleTimeout:  Integer value specifying the idle timeout in seconds, to send Ping/Pong to server, to keep connection alive
coreDumpEnabled:			If set, a dump file will be written when the agent crashes
disableUpdate:				If set, will prevent the agent from self-updating
noUpdateCoreModule:			If set, will prevent the agent from taking a new meshcore from the server
enableILibRemoteLogging:	Integer value specifying the port number to enable Web Logging. Disabled otherwise
fakeUpdate:					If set, when the agent self-updates, it will update to the same version. Will set disableUpdate upon completion
forceUpdate:				If set, will cause the agent to perform a self-update on next start.
ignoreProxyFile:			If set, will cause the agent to ignore any proxy settings
logUpdate:					If set, will cause the agent to log self-update status
jsDebugPort:				Specify a JS Debugger Port
maxLogSize:					Specifies the maximum size of the error log file. 
nocertstore:				If set on Windows, will force the Agent to use OpenSSL instead of WinCrypto for cert generation/storage.
readonly:					If set, forces the agent to open the database in readonly mode
readmsh:					If set while db is in readonly mode, it will cache the local msh file in the readonly db
remoteMouseRender:			If set, will always render the remote mouse cursor for KVM
showModuleNames:			If set, will display the name of modules when they are loaded for the first time
skipmaccheck:				If set, the agent will not change NodeID on local mac address changes.
slaveKvmLog:				[Linux] If set, will enable logging inside the Child KVM Process.
WebProxy:					Manually specify proxy configuration
*
*
*/

#endif
