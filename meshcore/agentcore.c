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

#include <winsock2.h>
#include <ws2tcpip.h>

#include <Windows.h>
#include <WinBase.h>
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


#ifndef _NOHECI
#include "microlms/lms/ILibLMS.h"
#endif

#ifdef _POSIX
#include <sys/stat.h>
#endif

#ifdef _LINKVM
	#ifdef WIN32
	#include "KVM/Windows/kvm.h"
	#endif
	#ifdef _POSIX
	#include "KVM/Linux/linux_kvm.h"
	#endif
#endif

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#define HEX_IDENTIFIER (unsigned short)12408
#define EXE_IDENTIFIER (unsigned int)778401893
#define MSH_IDENTIFIER (unsigned int)778924904
#define SCRIPT_ENGINE_PIPE_BUFFER_SIZE 65535

#define MESH_AGENT_PORT 16990					 //!< Default Mesh Agent Port
#define MESH_MCASTv4_GROUP "239.255.255.235"
#define MESH_MCASTv6_GROUP "FF02:0:0:0:0:0:0:FE"

#define MESH_SCRIPTCONTAINER_ID	"\xFF_ScriptContainer_ID"
#define MESH_AGENT_SINGLETON	"\xFF_MeshAgentObject_Singleton"
#define SEQ_TABLE_KEY			"\xFF_seqTable"
#define CONTAINER_PTR			"\xFF_ptr"
#define MESH_AGENT_PTR			"\xFFMeshAgentPtr"
#define MESH_AGENT_DUKPTRS		"\xFFptrs"
#define CTX_PTR					"\xFF_Heap"
#define CONTEXT_GUID_PTR		"_CONTEXT_GUID_PTR"
#define REMOTE_DESKTOP_STREAM	"\xFF_RemoteDesktopStream"
#define REMOTE_DESKTOP_ptrs		"\xFF_RemoteDesktopPTRS"
#define DEFAULT_IDLE_TIMEOUT	120

char* MeshAgentHost_BatteryInfo_STRINGS[] = { "UNKNOWN", "HIGH_CHARGE", "LOW_CHARGE", "NO_BATTERY", "CRITICAL_CHARGE", "", "", "", "CHARGING" };
JS_ENGINE_CONTEXT MeshAgent_JavaCore_ContextGuid = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

typedef struct RemoteDesktop_Ptrs
{
	duk_context *ctx;
	void *object;
	void *MeshAgentObject;
#ifdef _POSIX
	void *kvmPipe;
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
	if ((bufferLength > 78) && (memcmp(buffer, "MeshCentral2|", 13) == 0) && ((ILibSimpleDataStore_Get(agentHost->masterDb, "ServerID", ILibScratchPad, sizeof(ILibScratchPad))) == 65) && (memcmp(ILibScratchPad, buffer + 13, 64) == 0)) {
		// We have a match, set the server URL correctly.
		if (agentHost->multicastServerUrl != NULL) { free(agentHost->multicastServerUrl); agentHost->multicastServerUrl = NULL; }
		if ((agentHost->multicastServerUrl = (char*)malloc(bufferLength - 78 + 128)) == NULL) { ILIBCRITICALEXIT(254); }

		buffer[bufferLength] = 0;
		ILibInet_ntop2((struct sockaddr*)remoteInterface, (char*)ILibScratchPad2, sizeof(ILibScratchPad));
		sprintf_s(agentHost->multicastServerUrl, bufferLength - 78 + 128, buffer + 78, ILibScratchPad2);

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

MeshAgentDuktapePtrs* ILibDuktape_MeshAgent_GetMeshAgentPtrs(duk_context *ctx) 
{
	MeshAgentDuktapePtrs *ptrs = NULL;
	MeshAgentHostContainer *agent = NULL;

	duk_push_this(ctx);												// [MeshAgent]
	if (duk_has_prop_string(ctx, -1, MESH_AGENT_DUKPTRS))
	{
		// We already created a binding earlier
		duk_get_prop_string(ctx, -1, MESH_AGENT_DUKPTRS);			// [MeshAgent][ptrs]
		ptrs = (MeshAgentDuktapePtrs*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop(ctx);												// [MeshAgent]
	}
	else
	{
		// Create a new binding
		duk_push_fixed_buffer(ctx, sizeof(MeshAgentDuktapePtrs));	// [MeshAgent][buffer]
		ptrs = (MeshAgentDuktapePtrs*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_put_prop_string(ctx, -2, MESH_AGENT_DUKPTRS);			// [MeshAgent]

		memset(ptrs, 0, sizeof(MeshAgentDuktapePtrs));
		ptrs->ctx = ctx;
		ptrs->MeshAgentObject = duk_get_heapptr(ctx, -1);

		duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);				// [MeshAgent][Host]
		agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);
		duk_pop(ctx);												// [MeshAgent]
		ptrs->Next = agent->DuktapeMeshBindings;
		agent->DuktapeMeshBindings = ptrs;
	}
	duk_pop(ctx);													// ...
	return ptrs;
}
duk_ret_t ILibDuktape_MeshAgent_AddCommandHandler(duk_context *ctx)
{
	MeshAgentDuktapePtrs *ptrs;
	void *OnCommand = duk_require_heapptr(ctx, 0);

	ptrs = ILibDuktape_MeshAgent_GetMeshAgentPtrs(ctx);
	ptrs->OnCommand = OnCommand;
	return 0;
}
duk_ret_t ILibDuktape_MeshAgent_AddConnectHandler(duk_context *ctx)
{
	MeshAgentDuktapePtrs *ptrs;
	void *OnConnect = duk_require_heapptr(ctx, 0);

	ptrs = ILibDuktape_MeshAgent_GetMeshAgentPtrs(ctx);
	ptrs->OnConnect = OnConnect;
	return 0;
}
duk_ret_t ILibDuktape_MeshAgent_Finalizer(duk_context *ctx)
{
	MeshAgentDuktapePtrs *ptrs = NULL, *binding = NULL;
	MeshAgentHostContainer *agent = NULL;

	duk_dup(ctx, 0);									// [MeshAgent]
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);		// [MeshAgent][MeshAgentPtr]
	agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);

	if (duk_has_prop_string(ctx, -2, MESH_AGENT_DUKPTRS))
	{
		duk_get_prop_string(ctx, -2, MESH_AGENT_DUKPTRS);		// [MeshAgent][MeshAgentPtr][ptrs]
		ptrs = (MeshAgentDuktapePtrs*)Duktape_GetBuffer(ctx, -1, NULL);

		if (agent->DuktapeMeshBindings == ptrs)
		{
			agent->DuktapeMeshBindings = ptrs->Next;
		}
		else
		{
			binding = agent->DuktapeMeshBindings;
			while (binding->Next != NULL)
			{
				if (binding->Next == ptrs) { binding->Next = ptrs->Next; break; }
				binding = binding->Next;
			}
		}
	}
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

	len = util_mkCert(NULL, &(cert), 2048, 10000, "localhost", CERTIFICATE_TLS_CLIENT, NULL);
	len = util_to_p12(cert, passphrase, &data);

	duk_push_fixed_buffer(ctx, len);
	memcpy_s((void*)Duktape_GetBuffer(ctx, -1, NULL), len, data, len);

	util_free(data);
	util_freecert(&cert);
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
	kvm_relay_feeddata(buffer, bufferLen);
#endif
#endif
	return ILibTransport_DoneState_COMPLETE;
}
void ILibDuktape_MeshAgent_RemoteDesktop_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	// Peer disconnected the data channel
	RemoteDesktop_Ptrs *ptrs = (RemoteDesktop_Ptrs*)user;
	duk_push_heapptr(ptrs->ctx, ptrs->MeshAgentObject);			// [MeshAgent]
	duk_del_prop_string(ptrs->ctx, -1, REMOTE_DESKTOP_STREAM);
	duk_pop(ptrs->ctx);											// ...

	memset(ptrs, 0, sizeof(RemoteDesktop_Ptrs));
	kvm_cleanup();
}

void ILibDuktape_MeshAgent_RemoteDesktop_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
#ifdef _POSIX
	ILibProcessPipe_Pipe_Pause(((RemoteDesktop_Ptrs*)user)->kvmPipe);
#else
	kvm_pause(1);
#endif
}
void ILibDuktape_MeshAgent_RemoteDesktop_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
#ifdef _POSIX
	ILibProcessPipe_Pipe_Resume(((RemoteDesktop_Ptrs*)user)->kvmPipe);
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
void ILibDuktape_MeshAgent_RemoteDesktop_PipeHook(ILibDuktape_readableStream *stream, void *user)
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

duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop(duk_context *ctx)
{
#ifndef _LINKVM
	duk_push_null(ctx);
	return 1;
#else
	RemoteDesktop_Ptrs *ptrs;
	MeshAgentHostContainer *agent;

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
	duk_dup(ctx, -1);											// [MeshAgent][RemoteDesktop][RemoteDesktop]
	duk_put_prop_string(ctx, -3, REMOTE_DESKTOP_STREAM);		// [MeshAgent][RemoteDesktop]
	duk_push_fixed_buffer(ctx, sizeof(RemoteDesktop_Ptrs));		// [MeshAgent][RemoteDesktop][buffer]
	ptrs = (RemoteDesktop_Ptrs*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, REMOTE_DESKTOP_ptrs);			// [MeshAgent][RemoteDesktop]
	memset(ptrs, 0, sizeof(RemoteDesktop_Ptrs));
	ptrs->MeshAgentObject = duk_get_heapptr(ctx, -2);
	ptrs->ctx = ctx;
	ptrs->object = duk_get_heapptr(ctx, -1);
	ptrs->stream = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_MeshAgent_RemoteDesktop_WriteSink, ILibDuktape_MeshAgent_RemoteDesktop_EndSink, ILibDuktape_MeshAgent_RemoteDesktop_PauseSink, ILibDuktape_MeshAgent_RemoteDesktop_ResumeSink, ptrs);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_MeshAgent_RemoteDesktop_Finalizer);
	ptrs->stream->readableStream->PipeHookHandler = ILibDuktape_MeshAgent_RemoteDesktop_PipeHook;

	// Setup Remote Desktop
#ifdef WIN32
	kvm_relay_setup(agent->exePath, agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs);
#else
	ptrs->kvmPipe = kvm_relay_setup(agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs);
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
#ifndef _NOHECI
duk_ret_t ILibDuktape_MeshAgent_MEInfo(duk_context *ctx)
{
	char *data;
	int len = ILibLMS_GetMeInformation(&data, 0);
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
}
#endif
duk_ret_t ILibDuktape_MeshAgent_NetInfo(duk_context *ctx)
{
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
}

// Javascript ExecPowerState(int), executes power state command on the computer (Sleep, Hibernate...)
duk_ret_t ILibDuktape_MeshAgent_ExecPowerState(duk_context *ctx)
{
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
		duk_push_pointer(ctx, &agent->selftlscert);
		duk_put_prop_string(ctx, -2, ILibDuktape_MeshAgent_Cert_Server);
		duk_push_pointer(ctx, &agent->selftlsclientcert);
		duk_put_prop_string(ctx, -2, ILibDuktape_MeshAgent_Cert_Client);
		duk_push_pointer(ctx, &agent->selfcert);
		duk_put_prop_string(ctx, -2, ILibDuktape_MeshAgent_Cert_NonLeaf);
#endif
		duk_push_fixed_buffer(ctx, sizeof(MeshAgentDuktapePtrs));	// [MeshAgent][buffer]
		MeshAgentDuktapePtrs *ptrs  = (MeshAgentDuktapePtrs*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_put_prop_string(ctx, -2, MESH_AGENT_DUKPTRS);			// [MeshAgent]

		memset(ptrs, 0, sizeof(MeshAgentDuktapePtrs));
		ptrs->ctx = ctx;
		ptrs->MeshAgentObject = duk_get_heapptr(ctx, -1);
		ptrs->Next = agent->DuktapeMeshBindings;
		agent->DuktapeMeshBindings = ptrs;

		ILibDuktape_EventEmitter_CreateEvent(emitter, "Ready", &(ptrs->OnReady));
		ILibDuktape_EventEmitter_CreateEvent(emitter, "Connected", &(ptrs->OnConnect));

		ILibDuktape_EventEmitter_AddHook(emitter, "Ready", ILibDuktape_MeshAgent_Ready);
		ILibDuktape_CreateEventWithGetter(ctx, "ConnectedServer", ILibDuktape_MeshAgent_ConnectedServer);
		ILibDuktape_CreateEventWithGetter(ctx, "ServerUrl", ILibDuktape_MeshAgent_ServerUrl);
		ILibDuktape_CreateInstanceMethod(ctx, "getRemoteDesktopStream", ILibDuktape_MeshAgent_getRemoteDesktop, 0);
		ILibDuktape_CreateInstanceMethod(ctx, "AddCommandHandler", ILibDuktape_MeshAgent_AddCommandHandler, 1);
		ILibDuktape_CreateInstanceMethod(ctx, "AddConnectHandler", ILibDuktape_MeshAgent_AddConnectHandler, 1);
		ILibDuktape_CreateInstanceMethod(ctx, "SendCommand", ILibDuktape_MeshAgent_SendCommand, 1);
		ILibDuktape_CreateFinalizer(ctx, ILibDuktape_MeshAgent_Finalizer);
		ILibDuktape_CreateReadonlyProperty_int(ctx, "activeMicroLMS", (agent->microLMS != NULL ? 1 : 0));
#ifdef _LINKVM 
		ILibDuktape_CreateReadonlyProperty_int(ctx, "hasKVM", 1);
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "kvmConnected");
#else
		ILibDuktape_CreateReadonlyProperty_int(ctx, "hasKVM", 0);
#endif

#ifdef _NOHECI
		ILibDuktape_CreateReadonlyProperty_int(ctx, "hasHECI", 0);
#else
		ILibDuktape_CreateReadonlyProperty_int(ctx, "hasHECI", 1);
		ILibDuktape_CreateEventWithGetter(ctx, "MEInfo", ILibDuktape_MeshAgent_MEInfo);
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "lmsNotification");
#endif
		ILibDuktape_CreateEventWithGetter(ctx, "NetInfo", ILibDuktape_MeshAgent_NetInfo);
		ILibDuktape_CreateInstanceMethod(ctx, "ExecPowerState", ILibDuktape_MeshAgent_ExecPowerState, DUK_VARARGS);

		Duktape_CreateEnum(ctx, "ContainerPermissions", (char*[]) { "DEFAULT", "NO_AGENT", "NO_MARSHAL", "NO_PROCESS_SPAWNING", "NO_FILE_SYSTEM_ACCESS", "NO_NETWORK_ACCESS" }, (int[]) { 0x00, 0x10000000, 0x08000000, 0x04000000, 0x00000001, 0x00000002 }, 6);
	}

	ILibDuktape_CreateInstanceMethod(ctx, "GenerateCertificate", ILibDuktape_MeshAgent_GenerateCertificate, 1);
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
		if (ntohl(((unsigned int*)(basePath + sz - 4))[0]) == EXE_IDENTIFIER)
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

	printf("Generating Certificates...\r\n");

	ILibSimpleDataStore_Delete(agent->masterDb, "SelfNodeCert");
	ILibSimpleDataStore_Delete(agent->masterDb, "SelfNodeTlsCert");
	ILibSimpleDataStore_Delete(agent->masterDb, "SelfNodeTlsClientCert");

	// Make sure the certs and database are clean
	util_freecert(&(agent->selfcert));
	util_freecert(&(agent->selftlscert));
	util_freecert(&(agent->selftlsclientcert));

	if (certfile == NULL)
	{
		// Generate a new random node certificate
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Generating new Node Certificate");

		do
		{
			if (util_mkCert(NULL, &(agent->selfcert), 2048, 10000, "MeshNodeCertificate", CERTIFICATE_ROOT, NULL) == 0) return -1;
			util_keyhash(agent->selfcert, agent->g_selfid);

		} while (((int*)agent->g_selfid)[0] == 0); // This removes any chance that the self_id starts with 32 bits of zeros.
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...g_selfid = %s", ILibRemoteLogging_ConvertToHex(agent->g_selfid, (int)sizeof(agent->g_selfid)));
	}
	else
	{
		// Load a node certificate from a PEM file
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Loading Node Cert from PEM file");
		if (util_from_pem(certfile, &(agent->selfcert)) == -1)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "......*ERROR*");
			return -1;
		}
		util_keyhash(agent->selfcert, agent->g_selfid);
		if (((int*)agent->g_selfid)[0] == 0)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "......g_selfid = *ERROR*");
			return -1; // This removes any chance that the self_id starts with 32 bits of zeros.
		}
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...g_selfid = %s", ILibRemoteLogging_ConvertToHex(agent->g_selfid, (int)sizeof(agent->g_selfid)));
	}

	len = util_to_p12(agent->selfcert, "hidden", &str);
	ILibSimpleDataStore_PutEx(agent->masterDb, "SelfNodeCert", 12, str, len);
	util_free(str);

	// Generate a new TLS certificate
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Generating TLS Certificate");
	len = util_mkCert(&(agent->selfcert), &(agent->selftlscert), 2048, 10000, "localhost", CERTIFICATE_TLS_SERVER, NULL);
	len = util_to_p12(agent->selftlscert, "hidden", &str);
	ILibSimpleDataStore_PutEx(agent->masterDb, "SelfNodeTlsCert", 15, str, len);
	util_free(str);

	// Generate a new TLS client certificate
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Generating TLS Client Certificate");
	len = util_mkCert(&(agent->selfcert), &(agent->selftlsclientcert), 2048, 10000, "localhost", CERTIFICATE_TLS_CLIENT, NULL);
	len = util_to_p12(agent->selftlsclientcert, "hidden", &str);
	ILibSimpleDataStore_PutEx(agent->masterDb, "SelfNodeTlsClientCert", 21, str, len);
	util_free(str);

	MSG("Certificates ready.\r\n");
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...READY");
	return 0;
}
int agent_LoadCertificates(MeshAgentHostContainer *agent)
{
	char *buffer = ILibScratchPad2;
	int len;

	//printf("Loading Certificates...\r\n");
	len = ILibSimpleDataStore_Get(agent->masterDb, "SelfNodeCert", buffer, sizeof(ILibScratchPad2));
	if (len == 0 || util_from_p12(buffer, len, "hidden", &(agent->selfcert)) == 0)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Failed to load Node Certificate from Database");
		return 1;
	}

	len = ILibSimpleDataStore_Get(agent->masterDb, "SelfNodeTlsCert", buffer, sizeof(ILibScratchPad2));
	if (len == 0 || util_from_p12(buffer, len, "hidden", &(agent->selftlscert)) == 0)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Failed to load TLS Certificate from Database");
		util_freecert(&(agent->selfcert));
		return 1;
	}

	len = ILibSimpleDataStore_Get(agent->masterDb, "SelfNodeTlsClientCert", buffer, sizeof(ILibScratchPad2));
	if (len == 0 || util_from_p12(buffer, len, "hidden", &(agent->selftlsclientcert)) == 0)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Failed to load TLS Client Certificate from Database");
		util_freecert(&(agent->selfcert));
		util_freecert(&(agent->selftlscert));
		return 1;
	}

	util_keyhash(agent->selfcert, agent->g_selfid);
	return 0;
}

int agent_VerifyMeshCertificates(MeshAgentHostContainer *agent)
{
	X509_STORE *store;
	X509_STORE_CTX *ctx;
	int i, j;

	// Check that the TLS certificate and TLS client certificate are correctly signed by our Mesh Agent certificate
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Verifying TLS Certificates are signed by Mesh Agent Certificate");
	store = X509_STORE_new();
	X509_STORE_add_cert(store, agent->selfcert.x509);

	// Check the TLS certificate
	ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, agent->selftlscert.x509, NULL);
	i = X509_verify_cert(ctx);
	X509_STORE_CTX_free(ctx);

	// Check the TLS client certificate
	ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, agent->selftlsclientcert.x509, NULL);
	j = X509_verify_cert(ctx);
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);

	// If the certificate chain is not correct, re-create all the certificates.
	if (i != 1)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "......INVALID TLS Server Certificate");
	}
	if (j != 1)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "......INVALID TLS Client Certificate");
	}

	if (i != 1 || j != 1) { return 1; } // Bad certificates
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

	duk_destroy_heap(oldCtx);
	agent->meshCoreCtx = newCtx;

	return(newCtx);
}
char* ScriptEngine_Restart(MeshAgentHostContainer *agent, char *contextGUID, char *buffer, int bufferLen)
{
	duk_context *ctx = ScriptEngine_Stop(agent, contextGUID);
	
	if (ctx != NULL) 
	{ 
		if (ILibDuktape_ScriptContainer_CompileJavaScript(ctx, buffer, bufferLen) != 0 || ILibDuktape_ScriptContainer_ExecuteByteCode(ctx) != 0)
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


void OnBrokenPipe_StdIn(ILibProcessPipe_Pipe sender)
{
	ILibStopChain(((MeshAgentHostContainer*)((void**)ILibMemory_GetExtraMemory(sender, ILibMemory_ILibProcessPipe_Pipe_CONTAINERSIZE))[0])->chain);
}

// Called when we can now send more data to MeshCentral
void MeshServer_OnSendOK(ILibWebClient_StateObject sender, void *user1, void *user2)
{
	// TODO: Inform JavaScript core module that we are in underflow situation
}

// Called when the connection of the mesh server is fully authenticated
void MeshServer_ServerAuthenticated(ILibWebClient_StateObject WebStateObject, MeshAgentHostContainer *agent) {
	int len = 0;
	MeshAgentDuktapePtrs *meshBindings;

	// Send the mesh agent tag to the server
	// We send the tag information independently of the meshcore because we could use this to select what meshcore to use on the server.
	((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_AgentTag); // MeshCommand_AgentTag (15), agent tag information
	len = ILibSimpleDataStore_GetEx(agent->masterDb, "Tag", 3, ILibScratchPad2 + 2, sizeof(ILibScratchPad2) - 2);
	ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, 2 + len, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

	// Inform JavaScript core module of the connection
	// TODO: Verify with Bryan that only the core module will get this. No other modules should.
	if (agent->serverAuthState == 3) {
		meshBindings = agent->DuktapeMeshBindings;
		while (meshBindings != NULL)
		{
			if (meshBindings->OnConnect != NULL)
			{
				duk_push_heapptr(meshBindings->ctx, meshBindings->OnConnect);
				duk_push_heapptr(meshBindings->ctx, meshBindings->MeshAgentObject);
				duk_push_int(meshBindings->ctx, 1); // Argument 1 here indicates connection
				if (duk_pcall_method(meshBindings->ctx, 1) != 0) { ILibDuktape_Process_UncaughtException(meshBindings->ctx); }
				duk_pop(meshBindings->ctx);
			}
			meshBindings = meshBindings->Next;
		}
	}
}

// Process MeshCentral server commands. 
void MeshServer_ProcessCommand(ILibWebClient_StateObject WebStateObject, MeshAgentHostContainer *agent, char *cmd, int cmdLen)
{
	unsigned short command = ntohs(((unsigned short*)cmd)[0]);
	unsigned short requestid;
	MeshAgentDuktapePtrs *meshBindings;

#ifndef MICROSTACK_NOTLS
	// If we are not authenticated with the mesh server, we only support auth commands.
	if (agent->serverAuthState != 3)
	{
		X509* peer = ILibWebClient_SslGetCert(WebStateObject);

		switch (command)
		{
		case MeshCommand_AuthRequest: // This is basic authentication information from the server, we need to sign this and return the signature.
			if (cmdLen == 66) {
				int signLen, certlen;
				SHA256_CTX c;
				EVP_PKEY *evp_prikey;
				RSA *rsa_prikey;
				char *certDer = ILibScratchPad2 + 4;

				// Hash the server's web certificate and check if it matches the one in the auth request
				util_keyhash2(peer, ILibScratchPad2); // Hash the server certificate public key and place it

				if (memcmp(ILibScratchPad2, cmd + 2, UTIL_HASHSIZE) != 0) { printf("Bad server certificate hash\r\n"); break; } // TODO: Disconnect
				memcpy_s(agent->serverNonce, sizeof(agent->serverNonce), cmd + 34, UTIL_HASHSIZE);

				// Place our certificate in the response
				((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_AuthVerify); // MeshCommand_AuthVerify (2), agent certificate in ASN1 format
				certlen = i2d_X509(agent->selfcert.x509, (unsigned char **)&certDer); // Place the agent root certificate in DER form
				((unsigned short*)ILibScratchPad2)[1] = htons(certlen); // Place the size of the certificate

				// Use our agent root private key to sign the ServerWebHash + ServerNonce + AgentNonce
				SHA256_Init(&c);
				util_keyhash2(peer, ILibScratchPad);
				SHA256_Update(&c, cmd + 2, UTIL_HASHSIZE); // Server web hash
				SHA256_Update(&c, agent->serverNonce, UTIL_HASHSIZE); // Server nonce
				SHA256_Update(&c, agent->agentNonce, UTIL_HASHSIZE); // Agent nonce
				SHA256_Final((unsigned char*)ILibScratchPad, &c);

				// Place the signature & send
				evp_prikey = agent->selfcert.pkey;
				rsa_prikey = EVP_PKEY_get1_RSA(evp_prikey);
				signLen = 65535 - (4 + certlen);
				if (RSA_sign(NID_sha256, (unsigned char*)ILibScratchPad, UTIL_HASHSIZE, (unsigned char*)(ILibScratchPad2 + 4 + certlen), (unsigned int*)&signLen, rsa_prikey) == 1) 
				{
					// Signature succesful, send the result to the server
					ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, 4 + certlen + signLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
				}
				RSA_free(rsa_prikey);
				
			}
			break;
		case MeshCommand_AuthVerify: // This is the signature from the server. We need to check everything is ok.
			if (cmdLen > 8)
			{
				unsigned short certlen = ntohs(((unsigned short*)cmd)[1]);
				if (cmdLen > (4 + certlen)) {
					int platformType = 1, hashlen = UTIL_HASHSIZE;
					SHA256_CTX c;
					X509* serverCert = NULL;
					EVP_PKEY *evp_pubkey;
					RSA *rsa_pubkey;
					char* ptr = cmd + 4;

					// Get the server certificate
					if (!d2i_X509(&serverCert, (const unsigned char**)&ptr, certlen)) { printf("Invalid server certificate\r\n"); break; } // TODO: Disconnect

					// Check if this certificate public key hash matches what we want
					// util_sha256((char*)(serverCert->cert_info->key->public_key->data), serverCert->cert_info->key->public_key->length, ILibScratchPad); // OpenSSL 1.0
					X509_pubkey_digest(serverCert, EVP_sha256(), (unsigned char*)ILibScratchPad, (unsigned int*)&hashlen); // OpenSSL 1.1
					if (memcmp(ILibScratchPad, agent->serverHash, UTIL_HASHSIZE) != 0) { printf("Server certificate mismatch\r\n"); break; } // TODO: Disconnect

					// Compute the authentication hash
					SHA256_Init(&c);
					util_keyhash2(peer, ILibScratchPad);
					SHA256_Update(&c, ILibScratchPad, UTIL_HASHSIZE);
					SHA256_Update(&c, agent->agentNonce, UTIL_HASHSIZE);
					SHA256_Update(&c, agent->serverNonce, UTIL_HASHSIZE);
					SHA256_Final((unsigned char*)ILibScratchPad, &c);

					// Verify the hash signature using the server certificate
					evp_pubkey = X509_get_pubkey(serverCert);
					rsa_pubkey = EVP_PKEY_get1_RSA(evp_pubkey);
					if (RSA_verify(NID_sha256, (unsigned char*)ILibScratchPad, UTIL_HASHSIZE, (unsigned char*)(cmd + 4 + certlen), cmdLen - (4 + certlen), rsa_pubkey) == 1) 
					{
						int hostnamelen = (int)strnlen_s(agent->hostname, sizeof(agent->hostname));
						// Server signature verified, we are good to go.
						agent->serverAuthState += 1;

						// Send to the server information about this agent (TODO: Replace this with a struct)
						if ((agent->batteryState != MeshAgentHost_BatteryInfo_NONE) && (agent->batteryState != MeshAgentHost_BatteryInfo_UNKNOWN)) { platformType = 2; } // If a battery is present, select laptop icon
						((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_AuthInfo);		// MeshCommand_AuthInfo (3), agent information
						((unsigned int*)(ILibScratchPad2 + 2))[0] = htonl(1);						// Agent information version
						((unsigned int*)(ILibScratchPad2 + 6))[0] = htonl(MESH_AGENTID);			// Agent Identifier
						((unsigned int*)(ILibScratchPad2 + 10))[0] = htonl(agent->version);			// Agent Version
						((unsigned int*)(ILibScratchPad2 + 14))[0] = htonl(platformType);			// Platfrom Type: This is the icon: 1 = Desktop, 2 = Laptop, 3 = Mobile, 4 = Server, 5 = Disk, 6 = Router
						memcpy_s(ILibScratchPad2 + 18, sizeof(ILibScratchPad2) - 18, agent->meshId, UTIL_HASHSIZE);					// MeshId, taken from the agent settings
						((unsigned int*)(ILibScratchPad2 + 50))[0] = htonl(8 + 16);					// Capabilities of the agent(bitmask) : 1 = Desktop, 2 = Terminal, 4 = Files, 8 = Console, 16 = JavaScript
						((unsigned short*)ILibScratchPad2 + 54)[0] = htons(hostnamelen);			// Hostname length
						memcpy_s(ILibScratchPad2 + 56, sizeof(ILibScratchPad2) - 56, agent->hostname, hostnamelen);					// Hostname
						
						// Send mesh agent information to the server
						ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, 56 + hostnamelen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
						agent->retryTime = 0;
						printf("Connected.\n");
						if (agent->serverAuthState == 3) { MeshServer_ServerAuthenticated(WebStateObject, agent); }
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
		int processed = 0;
		// if (cmd[0] == '{') { cmd[cmdLen] = 0; printf("%s\r\n", cmd); } // DEBUG: Print JSON command
		meshBindings = agent->DuktapeMeshBindings;
		while (processed == 0 && meshBindings != NULL)
		{
			if (meshBindings->OnCommand != NULL)
			{
				duk_push_heapptr(meshBindings->ctx, meshBindings->OnCommand);														// [func] 
				duk_push_heapptr(meshBindings->ctx, meshBindings->MeshAgentObject);													// [func][this]
				if (cmd[0] == '{')
				{
					// JSON
					duk_push_global_object(meshBindings->ctx);				// [g]
					duk_get_prop_string(meshBindings->ctx, -1, "JSON");		// [g][JSON]
					duk_get_prop_string(meshBindings->ctx, -1, "parse");	// [g][JSON][func]
					duk_swap_top(meshBindings->ctx, -3);					// [func][JSON][g]
					duk_pop_2(meshBindings->ctx);							// [func]
					duk_push_lstring(meshBindings->ctx, cmd, cmdLen);		// [func][str]
					if (duk_pcall(meshBindings->ctx, 1) != 0)
					{
						duk_pop(meshBindings->ctx);							
						duk_push_lstring(meshBindings->ctx, cmd, cmdLen);
					}
				}
				else
				{
					// BINARY
					duk_push_external_buffer(meshBindings->ctx);														// [func][this][buffer]
					duk_config_buffer(meshBindings->ctx, -1, cmd, cmdLen);
				}

				if (duk_pcall_method(meshBindings->ctx, 1) == 0)														// [retVal]
				{
					if (duk_is_number(meshBindings->ctx, -1)) { processed = duk_get_int(meshBindings->ctx, -1); }		// Get the return value
				}
				else
				{
					ILibDuktape_Process_UncaughtException(meshBindings->ctx);
				}
				duk_pop(meshBindings->ctx);																				// ...
			}
			meshBindings = meshBindings->Next;
		}
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

			// If the agent is running with a local core, ignore this command
			if (agent->localScript != 0) break;

			if (cmdLen > 36) // Setup a new mesh core. Command is: cmdid + requestid + sha256hash + javascript
			{
				char *hashref = ILibSimpleDataStore_GetHash(agent->masterDb, "CoreModule"); // Get the reference to the SHA256 hash for the currently running code
				if (hashref == NULL || memcmp(hashref, cmd + 4, 32) != 0) 
				{														
					// If server sends us the same core, just do nothing.
					// Server sent us a new core, start by storing it in the data store
					ILibSimpleDataStore_PutEx(agent->masterDb, "CoreModule", 10, cmd + 36, cmdLen - 36);	// Store the JavaScript in the data store
					hashref = ILibSimpleDataStore_GetHash(agent->masterDb, "CoreModule");					// Get the reference to the SHA256 hash
					if (memcmp(hashref, cmd + 4, 32) != 0) {												// Check the hash for sanity
																											// Something went wrong, clear the data store
						ILibSimpleDataStore_Delete(agent->masterDb, "CoreModule");

						// Stop the currently running core if present
						ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
							ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: Stop");
						ScriptEngine_Stop(agent, MeshAgent_JavaCore_ContextGuid);

						// Tell the server we are no longer running a core module
						((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_CoreModuleHash);			// MeshCommand_CoreModuleHash (11), SHA256 hash of the code module
						((unsigned short*)ILibScratchPad2)[1] = htons(requestid);							// Request id
						ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, 4, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
						break;
					}

					// Stop the current JavaScript core if present and launch the new one.
					// JavaScript located at (cmd + 36) of length (cmdLen - 36)
					//printf("CORE: Restart\r\n");
					ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
						ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: Restart");
					if ((coreException = ScriptEngine_Restart(agent, MeshAgent_JavaCore_ContextGuid, cmd + 40, cmdLen - 40)) != NULL)
					{
						ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
							ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: Error: %s", coreException);
						// TODO: Ylian: New Java Core threw an exception... Exception String is stored in 'coreException'
					}

					// Since we did a big write to the data store, good time to compact the store
					ILibSimpleDataStore_Compact(agent->masterDb);
				}

				// Create the server confirmation message that we are running the new core
				((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_CoreModuleHash);					// MeshCommand_CoreModuleHash (11), SHA256 hash of the code module
				((unsigned short*)ILibScratchPad2)[1] = htons(requestid);									// Request id
				memcpy_s(ILibScratchPad2 + 4, sizeof(ILibScratchPad2) - 4, hashref, UTIL_HASHSIZE);			// SHA256 hash

				// Send the confirmation to the server
				ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, 36, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
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
				((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_CoreModuleHash);					// MeshCommand_CoreModuleHash (11), SHA256 hash of the code module
				((unsigned short*)ILibScratchPad2)[1] = htons(requestid);									// Request id
				ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, 4, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
			}
			break;
		}
		case MeshCommand_CoreModuleHash: // Request/return the SHA256 hash of the core module
		{
			// Tell the server what core module we are running
			char *hashref = ILibSimpleDataStore_GetHash(agent->masterDb, "CoreModule");						// Get the reference to the SHA256 hash
			int len = 4;

			// If the agent is running with a local core, ignore this command
			if (agent->localScript != 0) break;

			// Confirm to the server what core we are running
			((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_CoreModuleHash);						// MeshCommand_CoreModuleHash (11), SHA256 hash of the code module
			((unsigned short*)ILibScratchPad2)[1] = htons(requestid);                                       // Request id
			if (hashref != NULL) { memcpy_s(ILibScratchPad2 + 4, sizeof(ILibScratchPad2) - 4, hashref, UTIL_HASHSIZE); len += 32; }

			// Send the confirmation to the server
			ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, len, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

			break;
		}
		case MeshCommand_AgentHash:
		{
			if (agent->disableUpdate != 0) { break; }

			// This is a request for the hash of the agent binary
			// Built the response that includes our self hash
			((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_AgentHash);						// MeshCommand_AgentHash (12), SHA256 hash of the agent executable
			((unsigned short*)ILibScratchPad2)[1] = htons(requestid);									// Request id
			memcpy_s(ILibScratchPad2 + 4, sizeof(ILibScratchPad2) - 4, agent->agentHash, UTIL_HASHSIZE);// SHA256 hash of the agent executable

			// Send the self hash back to the server
			ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, 36, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

			break;
		}
		case MeshCommand_AgentUpdate:
		{
#ifdef WIN32
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agent->exePath, ".update.exe");
#else
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agent->exePath, ".update");
#endif
			char updateFileHash[32];

			if (cmdLen == 4) {
				// Indicates the start of the agent update transfer
				util_deletefile(updateFilePath);
			} else if (cmdLen == 36) {
				// Indicates the end of the agent update transfer
				// Check the SHA256 hash of the received file against the file we got.
				if ((util_sha256file(updateFilePath, updateFileHash) == 0) && (memcmp(updateFileHash, cmd + 4, 32) == 0)) {
					printf("UPDATE: End OK\r\n");
					// Check the file signature & version number
					//if (signcheck_verifysign(updateFilePath, 1))
					{
						// Everything looks good, lets perform the update
						agent->performSelfUpdate = 1;
						ILibStopChain(agent->chain);
					}
				} else {
					// Hash check failed, delete the file and do nothing. On next server reconnect, we will try again.
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
			((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_AgentUpdateBlock);             // MeshCommand_AgentHash (14), SHA256 hash of the agent executable
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
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore/MeshServer_ControlChannel_IdleTimeout(): Sending Ping");
}
ILibWebClient_WebSocket_PingResponse MeshServer_ControlChannel_PingSink(ILibWebClient_StateObject WebStateObject, void *user)
{
	return ILibWebClient_WebSocket_PingResponse_Respond;
}
void MeshServer_ControlChannel_PongSink(ILibWebClient_StateObject WebStateObject, void *user)
{
#ifdef _REMOTELOGGING
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user;
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore/MeshServer_ControlChannel_IdleTimeout(): Received Poing");
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

			// Start authentication by sending a auth nonce & server TLS cert hash.
			// Send 256 bits SHA256 hash of TLS cert public key + 256 bits nonce
			util_random(32, agent->agentNonce); // Generate a new mesh agent connection nonce
			((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_AuthRequest); // MeshCommand_AuthRequest (1), server hash + nonce
			util_keyhash2(peer, ILibScratchPad2 + 2); // Hash the server certificate public key and place it
			if (peer != NULL) { X509_free(peer); }
			memcpy_s(ILibScratchPad2 + 34, sizeof(ILibScratchPad2) - 34, agent->agentNonce, UTIL_HASHSIZE); // Place our mesh agent nonce
			ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, 66, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
#endif
			break;
		}
		case ILibWebClient_ReceiveStatus_Complete: // Disconnection
			// If the channel had been authenticates, inform JavaScript core module that we are not disconnected
#ifndef MICROSTACK_NOTLS
			if (agent->serverAuthState == 3)
#endif
			{
				MeshAgentDuktapePtrs *meshBindings = agent->DuktapeMeshBindings;
				while (meshBindings != NULL)
				{
					if (meshBindings->OnConnect != NULL)
					{
						duk_push_heapptr(meshBindings->ctx, meshBindings->OnConnect);
						duk_push_heapptr(meshBindings->ctx, meshBindings->MeshAgentObject);
						duk_push_int(meshBindings->ctx, 0); // 0 here as second parameter indicates disconnection
						if (duk_pcall_method(meshBindings->ctx, 1) != 0) { ILibDuktape_Process_UncaughtException(meshBindings->ctx); }
						duk_pop(meshBindings->ctx);
					}
					meshBindings = meshBindings->Next;
				}
			}
			agent->controlChannel = NULL; // Set the agent MeshCentral server control channel
			agent->serverConnectionState = 0;
			break;
		case ILibWebClient_ReceiveStatus_MoreDataToBeReceived: // Data received
			// Process Mesh Agent commands
			MeshServer_ProcessCommand(WebStateObject, agent, bodyBuffer, endPointer);
			break;
	}

	// If there are no headers, this is a connection error. Log it and try again...
	if (header == NULL)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(ILibWebClient_GetChainFromWebStateObject(WebStateObject)), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "Agent Host Container: Mesh Server Connection Error, trying again later.");
		printf("Mesh Server Connection Error\n");
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
		agent->serverIndex = (agent->serverIndex % rs->NumResults) + 1;
		//if (agent->serverIndex == 1)
		//{
		//	printf("Aborting...\r\n");
		//	ILibDestructParserResults(rs);
		//	return;
		//}
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
			serverUrlLen = strlen(serverUrl);
		} else {
			// Multicast discovery packet to try to find our server
			if ((agent->multicastDiscovery != NULL) && (ILibSimpleDataStore_Get(agent->masterDb, "ServerID", ILibScratchPad2, sizeof(ILibScratchPad2)) == 65)) { ILibMulticastSocket_Broadcast(agent->multicastDiscovery, ILibScratchPad2, 64, 1); }
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
			printf("agentcore: Could not resolve: %s\n", ILibScratchPad);
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
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore: Attempting connection to: %s", serverUrl);
	ILibDestructParserResults(rs);

	if ((len = ILibSimpleDataStore_Get(agent->masterDb, "ServerID", ILibScratchPad2, sizeof(ILibScratchPad2))) == 0) { printf("ServerID entry not found in Db!\n"); return; }
	rs = ILibParseString(ILibScratchPad2, 0, len, ",", 1);
	f = ILibParseString_GetResultIndex(rs, agent->serverIndex);
	if (f == NULL)
	{
		// Invalid Server ID Count
		printf("ServerID Count Mismatch\r\n");
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore: ServerID Count Mismatch. Hash Count = %d, Server Index = %d", rs->NumResults, agent->serverIndex);
		ILibDestructParserResults(rs);
		return;
	}
	f->datalength = ILibTrimString(&(f->data), f->datalength);
	if (f->datalength / 2 > sizeof(agent->serverHash))
	{
		printf("ServerID too big\r\n");
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore: ServerID too big. Was %d bytes, but expected %d bytes", f->datalength / 2, sizeof(agent->serverHash) - 1);
		ILibDestructParserResults(rs);
		return;
	}

	util_hexToBuf(f->data, f->datalength, agent->serverHash);
	ILibDestructParserResults(rs);

	if (ILibSimpleDataStore_Get(agent->masterDb, "MeshID", ILibScratchPad, sizeof(ILibScratchPad)) == 0) { printf("MeshID entry not found in Db!\n"); return; }
	memcpy_s(agent->meshId, sizeof(agent->meshId), ILibScratchPad, UTIL_HASHSIZE);

#ifndef MICROSTACK_NOTLS
	util_keyhash(agent->selfcert, agent->g_selfid); // Compute our own identifier using our certificate
#endif

	req = ILibCreateEmptyPacket();
	ILibSetVersion(req, "1.1", 3);
	ILibSetDirective(req, "GET", 3, path, (int)strnlen_s(path, serverUrlLen));
	ILibAddHeaderLine(req, "Host", 4, host, (int)strnlen_s(host, serverUrlLen));

	free(path);
	free(host);

	if (meshServer.sin6_family != AF_UNSPEC)
	{
		ILibWebClient_AddWebSocketRequestHeaders(req, 65535, MeshServer_OnSendOK);
		reqToken = ILibWebClient_PipelineRequest(agent->httpClientManager, (struct sockaddr*)&meshServer, req, MeshServer_OnResponse, agent, NULL);
#ifndef MICROSTACK_NOTLS
		ILibWebClient_Request_SetHTTPS(reqToken, result == ILibParseUriResult_TLS ? ILibWebClient_RequestToken_USE_HTTPS : ILibWebClient_RequestToken_USE_HTTP);
#endif
		if ((len = ILibSimpleDataStore_Get(agent->masterDb, "WebProxy", ILibScratchPad, sizeof(ILibScratchPad))) != 0)
		{
#ifdef MICROSTACK_PROXY
			unsigned short proxyPort = 80;
			int delimiter = ILibString_LastIndexOf(ILibScratchPad, len, ":", 1);
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
#else
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore.MeshServer_ConnectEx(): Proxy Specified, but support was not enabled in this build");
#endif
		}
		agent->serverConnectionState = 1; // We are trying to connect
	}
	else
	{
		ILibDestructPacket(req);
	}
}
void MeshServer_Connect(MeshAgentHostContainer *agent)
{
	unsigned int timeout;

	// If this is called while we are in any connection state, just leave now.
	if (agent->serverConnectionState != 0) return;

	util_random(sizeof(int), (char*)&timeout);
	agent->disableUpdate = ILibSimpleDataStore_Get(agent->masterDb, "disableUpdate", NULL, 0);

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

void importSettings(MeshAgentHostContainer *agent, char* fileName)
{
	int eq;
	char* importFile;
	int importFileLen;
	parser_result *pr;
	parser_result_field *f;

	importFileLen = ILibReadFileFromDiskEx(&importFile, fileName);
	if (importFileLen == 0) { return; }
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

				if (valLen == 0) {
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
		f = f->NextResult;
	}
	ILibDestructParserResults(pr);
	free(importFile);
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

MeshAgentHostContainer* MeshAgent_Create()
{
	MeshAgentHostContainer* retVal = (MeshAgentHostContainer*)ILibMemory_Allocate(sizeof(MeshAgentHostContainer), 0, NULL, NULL);
#ifdef WIN32
	SYSTEM_POWER_STATUS stats;
#endif

	retVal->agentID = (AgentIdentifiers)MESH_AGENTID;
	retVal->chain = ILibCreateChainEx(3 * sizeof(void*));
	retVal->pipeManager = ILibProcessPipe_Manager_Create(retVal->chain);
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
	duk_destroy_heap(agent->meshCoreCtx);
}

void MeshAgent_RunScriptOnly_Finalizer(duk_context *ctx, void *user)
{
	MeshAgentHostContainer *agentHost = (MeshAgentHostContainer*)user;
	if (ILibIsChainBeingDestroyed(agentHost->chain) == 0)
	{
		MeshAgent_Stop(agentHost);
	}
}
void MeshAgent_CoreModule_UncaughtException(duk_context *ctx, char *msg, void *user)
{
}

#ifndef _NOHECI
void MicroLMS_OnNotificationEx(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	struct cimAlertIndication *values = (struct cimAlertIndication*)((void**)user)[0];
	char *xml = (char*)((void**)user)[1];
	int xmllen = ((int*)((void**)user)[2])[0];

	if (Key1 == NULL && ((SCRIPT_ENGINE_ISOLATION*)Data)->reserved != 0)
	{
		// This is a regular Duktape Context
		ILibDuktape_EventEmitter *emitter = MeshAgent_GetEventEmitter_FromCTX((duk_context*)Data);
		if (emitter != NULL)
		{
			duk_push_heapptr(emitter->ctx, emitter->object);												// [MeshAgent]
			duk_get_prop_string(emitter->ctx, -1, "emit");													// [MeshAgent][emit]
			duk_swap_top(emitter->ctx, -2);																	// [emit][this]
			duk_push_string(emitter->ctx, "lmsNotification");												// [emit][this][event]
			duk_push_object(emitter->ctx);																	// [emit][this][event][obj]
			duk_push_lstring(emitter->ctx, values->MessageID.data, values->MessageID.dataLen);				// [emit][this][event][obj][msgId]
			duk_put_prop_string(emitter->ctx, -2, "messageId");												// [emit][this][event][obj]
			duk_push_lstring(emitter->ctx, values->IndicationTime.data, values->IndicationTime.dataLen);	// [emit][this][event][obj][time]
			duk_put_prop_string(emitter->ctx, -2, "indicationTime");										// [emit][this][event][obj]
			duk_push_lstring(emitter->ctx, values->MessageArguments.data, values->MessageArguments.dataLen);// [emit][this][event][obj][msg]
			duk_put_prop_string(emitter->ctx, -2, "messageArguments");										// [emit][this][event][obj]
			duk_push_lstring(emitter->ctx, xml, xmllen);													// [emit][this][event][obj][rawXML]
			duk_put_prop_string(emitter->ctx, -2, "rawXML");												// [emit][this][event][obj]
			if (duk_pcall_method(emitter->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(emitter->ctx, "MeshAgent.onLmsNotification(): Error "); }
			duk_pop(emitter->ctx);																			// ...
		}
	}
}
void MicroLMS_OnNotification(void *module, struct cimAlertIndication *values, char* xml, int xmllen) 
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)((void**)ILibMemory_GetExtraMemory(module, ILibMemory_ILibLMS_CONTAINERSIZE))[0];
	if (agent->meshCoreCtx != NULL)
	{
		ILibDuktape_EventEmitter *emitter = MeshAgent_GetEventEmitter_FromCTX(agent->meshCoreCtx);
		if (emitter != NULL)
		{
			duk_push_heapptr(emitter->ctx, emitter->object);												// [MeshAgent]
			duk_get_prop_string(emitter->ctx, -1, "emit");													// [MeshAgent][emit]
			duk_swap_top(emitter->ctx, -2);																	// [emit][this]
			duk_push_string(emitter->ctx, "lmsNotification");												// [emit][this][event]
			duk_push_object(emitter->ctx);																	// [emit][this][event][obj]
			duk_push_lstring(emitter->ctx, values->MessageID.data, values->MessageID.dataLen);				// [emit][this][event][obj][msgId]
			duk_put_prop_string(emitter->ctx, -2, "messageId");												// [emit][this][event][obj]
			duk_push_lstring(emitter->ctx, values->IndicationTime.data, values->IndicationTime.dataLen);	// [emit][this][event][obj][time]
			duk_put_prop_string(emitter->ctx, -2, "indicationTime");										// [emit][this][event][obj]
			duk_push_lstring(emitter->ctx, values->MessageArguments.data, values->MessageArguments.dataLen);// [emit][this][event][obj][msg]
			duk_put_prop_string(emitter->ctx, -2, "messageArguments");										// [emit][this][event][obj]
			duk_push_lstring(emitter->ctx, xml, xmllen);													// [emit][this][event][obj][rawXML]
			duk_put_prop_string(emitter->ctx, -2, "rawXML");												// [emit][this][event][obj]
			if (duk_pcall_method(emitter->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(emitter->ctx, "MeshAgent.onLmsNotification(): Error "); }
			duk_pop(emitter->ctx);																			// ...
		}
	}
}
#endif

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

#ifndef WIN32
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
#endif
int MeshAgent_AgentMode(MeshAgentHostContainer *agentHost, int paramLen, char **param, int parseCommands)
{
	int resetNodeId = 0;
	//int x;
	//size_t tmpLen;
#ifdef WIN32
	int pLen;
#endif
#ifdef _POSIX
	int options = 0;
#endif

	// We are a Mesh Agent
	printf("MeshCentral2 Agent\r\n"); // MESH_AGENT_VERSION
	if (agentHost->masterDb == NULL) { agentHost->masterDb = ILibSimpleDataStore_Create(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db")); }
#ifndef WIN32
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
			printf("Unable to open database... Giving up...\r\n");
			return(0);
		default:
			printf("Unable to open database... Trying again later...\r\n");
			agentHost->dbRetryCount++;
			ILibLifeTime_AddEx(ILibGetBaseTimer(agentHost->chain), data, 2000, MeshAgent_AgentMost_dbRetryCallback, NULL);
			return(1);
		}
	}
#else
	if (agentHost->masterDb == NULL) { printf("Unable to open database...\r\n"); return(0); }
#endif
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
		char* str = NULL;
		int len = (int)util_readfile(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".proxy"), &str, 1024);
		if (str != NULL) { ILibSimpleDataStore_PutEx(agentHost->masterDb, "WebProxy", 8, str, len); free(str); } else { ILibSimpleDataStore_DeleteEx(agentHost->masterDb, "WebProxy", 8); }
	}

#ifndef _NOHECI
#ifdef WIN32
	// Check if the LMS service is installed in the service manager
	if (GetServiceState(TEXT("LMS")) == 100) {
		// If not, setup MicroLMS (Intel AMT interface service) if it's needed
		if ((agentHost->microLMS = ILibLMS_CreateEx(agentHost->chain, agentHost->exePath, MicroLMS_OnNotification, sizeof(void*))) != NULL) MSG("MicroLMS activated\r\n");
	}
#else
	// Setup MicroLMS (Intel AMT interface service) if it's needed
	if ((agentHost->microLMS = ILibLMS_CreateEx(agentHost->chain, agentHost->exePath, MicroLMS_OnNotification, sizeof(void*))) != NULL) MSG("MicroLMS activated\r\n");
#endif
	if (agentHost->microLMS != NULL) { ((void**)ILibMemory_GetExtraMemory(agentHost->microLMS, ILibMemory_ILibLMS_CONTAINERSIZE))[0] = agentHost; }
#endif

	// Check to see if we need to import a settings file
	importSettings(agentHost, MeshAgent_MakeAbsolutePath(agentHost->exePath, ".msh"));

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
			// Save the NodeId
			util_tohex(agentHost->g_selfid, UTIL_HASHSIZE, ILibScratchPad);
			RegSetValueExA(hKey, "NodeId", 0, REG_SZ, ILibScratchPad, (int)strlen(ILibScratchPad));

			// Save the AgentHash
			util_tohex(agentHost->agentHash, UTIL_HASHSIZE, ILibScratchPad);
			RegSetValueExA(hKey, "AgentHash", 0, REG_SZ, ILibScratchPad, (int)strlen(ILibScratchPad));

			// Save a bunch of values in the registry
			if (ILibSimpleDataStore_Get(agentHost->masterDb, "MeshID", NULL, 0) == 0) { RegDeleteKeyA(hKey, "MeshId"); } else { util_tohex(ILibScratchPad2, ILibSimpleDataStore_Get(agentHost->masterDb, "MeshID", ILibScratchPad2, (int)sizeof(ILibScratchPad2)), ILibScratchPad); RegSetValueExA(hKey, "MeshId", 0, REG_SZ, ILibScratchPad, (int)strlen(ILibScratchPad)); } // Save the MeshId
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
	ILibWebClient_EnableHTTPS(agentHost->httpClientManager, &(agentHost->selftlscert), agentHost->selfcert.x509, ValidateMeshServer);
#endif

#ifdef _POSIX
	if (paramLen >= 2)
	{
		if ((strcmp(param[1], "start") == 0 || strcmp(param[1], "-d") == 0)) options = 1;
		else if ((strcmp(param[1], "stop") == 0 || strcmp(param[1], "-s") == 0)) options = 2;
		else if ((strcmp(param[1], "restart") == 0 || strcmp(param[1], "-r") == 0)) options = 3;
	}

	// Stop
	if (options & 2)
	{
		FILE *fd = NULL;
		char str[15];
		pid_t pid = 0;
		size_t len;

		/*
		#if defined(__APPLE__) && defined(_DAEMON) && defined(_LINKVM)
		installOsx(0);
		#endif
		*/

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
		}
		else
		{
			printf("Unable to find process id file.\r\n");
		}
	}

	// Start
	if (options & 1)
	{
		FILE *fd = NULL;
		char str[15];
		pid_t pid, sid;
		size_t len;

		/*
		#if defined(__APPLE__) && defined(_DAEMON) && defined(_LINKVM)
		installOsx(1);
		#endif
		*/

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
	}
	else if (options) exit(EXIT_SUCCESS);

#endif

	if (parseCommands == 0 || paramLen == 1 || ((paramLen == 2) && (strcmp(param[1], "run") == 0)))
	{
#ifdef WIN32
		char* updateFilePath = MeshAgent_MakeAbsolutePath(agentHost->exePath, ".update.exe");
#else
		char* updateFilePath = MeshAgent_MakeAbsolutePath(agentHost->exePath, ".update");
#endif

		// Delete the mesh agent update file if there is one
		util_deletefile(updateFilePath);

		// Check if there is a CoreModule in the db
		char *CoreModule;
		int CoreModuleLen = agentHost->localScript == 0 ? ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", NULL, 0) : 0;
		MeshAgentDuktapePtrs* ptrs = agentHost->DuktapeMeshBindings;

		while (ptrs != NULL)
		{
			if (ptrs->OnReady != NULL)
			{
				duk_push_heapptr(ptrs->ctx, ptrs->OnReady);														// [func]
				duk_push_heapptr(ptrs->ctx, ptrs->MeshAgentObject);												// [func][this]
				if (duk_pcall_method(ptrs->ctx, 0) != 0) {ILibDuktape_Process_UncaughtException(ptrs->ctx); }	// [retVal]
				duk_pop(ptrs->ctx);																				// ...
			}
			ptrs = ptrs->Next;
		}

		if (agentHost->localScript == 0)
		{
			// Create the context for the Local CoreModule, regardless if we have one yet
			agentHost->meshCoreCtx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(0, 0, agentHost->chain, NULL, agentHost->masterDb, agentHost->exePath, agentHost->pipeManager, NULL, NULL);
			ILibDuktape_MeshAgent_Init(agentHost->meshCoreCtx, agentHost->chain, agentHost);

			ILibDuktape_SetNativeUncaughtExceptionHandler(agentHost->meshCoreCtx, MeshAgent_CoreModule_UncaughtException, agentHost);

			if (CoreModuleLen > 0)
			{
				// There is a core module, launch it now.
				CoreModule = (char*)ILibMemory_Allocate(CoreModuleLen, 0, NULL, NULL);
				ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", CoreModule, CoreModuleLen);

				if (ILibDuktape_ScriptContainer_CompileJavaScript(agentHost->meshCoreCtx, CoreModule + 4, CoreModuleLen - 4) != 0 ||
					ILibDuktape_ScriptContainer_ExecuteByteCode(agentHost->meshCoreCtx) != 0)
				{
					ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
						ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: %s", duk_safe_to_string(agentHost->meshCoreCtx, -1));
					duk_pop(agentHost->meshCoreCtx);
				}

				free(CoreModule);
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

			agentHost->multicastDiscovery = ILibMulticastSocket_Create(agentHost->chain, 1024, MESH_AGENT_PORT, &multicastAddr4, &multicastAddr6, UDPSocket_OnData, agentHost, 1);
			if (agentHost->multicastDiscovery == NULL) { ILIBMARKPOSITION(219); return 1; }
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
		if(agentHost->masterDb == NULL && strncmp(argv[i], "--script-db", 11) == 0 && ((i + 1) < argc))
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

	// Start the JavaScript engine, run the loaded .js file
	agentHost->localScript = 1;

	agentHost->meshCoreCtx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(secFlags, execTimeout, agentHost->chain, scriptArgs, connectAgent != 0 ? agentHost->masterDb : NULL, agentHost->exePath, agentHost->pipeManager, connectAgent == 0 ? MeshAgent_RunScriptOnly_Finalizer : NULL, agentHost);
	ILibDuktape_SetNativeUncaughtExceptionHandler(agentHost->meshCoreCtx, MeshAgent_ScriptMode_UncaughtExceptionSink, agentHost);
	if (connectAgent != 0) { ILibDuktape_MeshAgent_Init(agentHost->meshCoreCtx, agentHost->chain, agentHost); }

	if (ILibDuktape_ScriptContainer_CompileJavaScript(agentHost->meshCoreCtx, jsFile, jsFileLen) != 0 || ILibDuktape_ScriptContainer_ExecuteByteCode(agentHost->meshCoreCtx) != 0)
	{
		// Error
		ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "Script Error: %s", duk_safe_to_string(agentHost->meshCoreCtx, -1));
		duk_pop(agentHost->meshCoreCtx);
	}

	// JavaScript copies this, we do not need this anymore.
	free(jsFile);
	free(scriptArgs);

	// If in agent mode, setup the chain to be a mesh agent
	if (connectAgent != 0) 
	{
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
	if (MeshAgent_AgentMode((MeshAgentHostContainer*)((void**)user)[0], ((int*)((void**)user)[1])[0], (char**)((void**)user)[2], 1) == 0)
	{
		ILibStopChain(((MeshAgentHostContainer*)((void**)user)[0])->chain);
	}
}

int MeshAgent_Start(MeshAgentHostContainer *agentHost, int paramLen, char **param)
{
	char exePath[1024];
#ifdef WIN32
	int x;
#elif defined(__APPLE__)
	int len = 1024;
#elif defined(NACL)
	// Do nothing
#else
	int x;
#endif

	if ((paramLen == 1 && strcmp(param[0], "--slave") == 0) || (paramLen == 2 && strcmp(param[1], "--slave") == 0)) { MeshAgent_Slave(agentHost); return 0; }
	if (paramLen == 2 && strcmp(param[1], "--netinfo") == 0) { char* data; int len = MeshInfo_GetSystemInformation(&data); if (len > 0) { printf("%s\r\n", data); } return 0; }
	agentHost->exePath = exePath;
	exePath[0] = 0;

#ifdef WIN32
	GetModuleFileName(NULL, exePath, sizeof(exePath));
#elif defined(__APPLE__)
	if (_NSGetExecutablePath(exePath, &len) != 0) ILIBCRITICALEXIT(247);
	exePath[len] = 0;
	agentHost->exePath = exePath;
#elif defined(NACL)
#else
	x = readlink("/proc/self/exe", exePath, 1024);
	if (x < 0 || x >= 1024) ILIBCRITICALEXIT(246);
	exePath[x] = 0;
#endif

	// Perform a self SHA256 Hash
	util_sha256file(agentHost->exePath, agentHost->agentHash);

#ifdef _REMOTELOGGINGSERVER
	{
		int len;
		if (agentHost->masterDb == NULL) { agentHost->masterDb = ILibSimpleDataStore_Create(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db")); }
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
	if (paramLen >= 2 && ILibString_EndsWith(param[1], -1, ".js", 3) != 0) 
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

		// Check if we need to perform self-update
		if (agentHost->performSelfUpdate == 1)
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

			// Kill the KVM slave process if needed
#if defined(__APPLE__) && defined(_DAEMON) && defined(_LINKVM)
			if (kvm_clientProcessId != 0) kill(kvm_clientProcessId, SIGTERM);
#endif

			// Build the argument list
			str[0] = 0;
			for (i = 1; i < paramLen; i++) ptr += sprintf_s(str + ptr, 4096 - ptr, " %s", param[i]);

#ifdef WIN32
			// Windows version
			sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "%s -update:\"%s\"%s", updateFilePath, agentHost->exePath, str);
			if (!CreateProcessA(NULL, ILibScratchPad, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &info, &processInfo))
			{
				// We tried to execute a bad executable... not good. Lets try to recover.
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
			// Linux version
			{
				struct stat results;
				stat(agentHost->exePath, &results); // This the mode of the current executable
				chmod(updateFilePath, results.st_mode); // Set the new executable to the same mode as the current one.
				sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "%s -update:\"%s\"%s &", updateFilePath, agentHost->exePath, str); // Launch the new executable for update.
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
	util_freecert(&agent->selftlsclientcert);
#endif

	if (agent->masterDb != NULL) { ILibSimpleDataStore_Close(agent->masterDb); }
	if (agent->chain != NULL) { ILibChain_DestroyEx(agent->chain); }
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
	sprintf_s(ILibScratchPad2, 6000, "cp %s %s", selfpath, exepath);
	while (system(ILibScratchPad2) != 0)
	{
		sleep(5);
		remove(exepath);
	}

	// Built the argument list
	ILibScratchPad[0] = 0;
	for (i = 2; i < argc; i++) ptr += sprintf_s(ILibScratchPad + ptr, 4096 - ptr, " %s", argv[i]);
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