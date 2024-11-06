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

#include "duktape.h"

#include "ILibDuktape_net.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_DuplexStream.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktape_ChildProcess.h"
#include "microstack/ILibAsyncSocket.h"
#include "microstack/ILibCrypto.h"
#include "microstack/ILibAsyncServerSocket.h"
#include "microstack/ILibRemoteLogging.h"
#include "microstack/ILibProcessPipe.h"

#ifdef _POSIX
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

#ifdef WIN32
#include <accctrl.h>
#include <AclAPI.h>
#endif

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#ifdef OLDSSL
#define TLS_method SSLv23_method
#endif

typedef struct ILibDuktape_net_socket
{
	duk_context *ctx;
	ILibAsyncSocket_SocketModule socketModule;
	void *object;
	void *net;
	void *duplexStream;
	void *chain;
	void *OnSetTimeout;
	int unshiftBytes;
	ILibDuktape_EventEmitter *emitter;
#ifndef MICROSTACK_NOTLS
	SSL_CTX *ssl_ctx;
	SSL *ssl;
#endif
}ILibDuktape_net_socket;

typedef struct ILibDuktape_net_server
{
	duk_context *ctx;
	void *self;
	ILibAsyncServerSocket_ServerModule server;
	ILibDuktape_EventEmitter *emitter;
	int isTLS;
}ILibDuktape_net_server;
typedef struct ILibDuktape_net_server_session
{
	duk_context *ctx;
	void *self;
	ILibAsyncServerSocket_ConnectionToken connection;
	ILibDuktape_EventEmitter *emitter;
	ILibDuktape_DuplexStream *stream;

	int unshiftBytes;
}ILibDuktape_net_server_session;

int ILibDuktape_TLS_ctx2socket = -1;
int ILibDuktape_TLS_ctx2server = -1;

#ifdef WIN32
#define ILibDuktape_net_IPC_BUFFERSIZE	4096
typedef struct ILibDuktape_net_WindowsIPC
{
	duk_context *ctx;
	void *mServer, *mSocket, *mChain;
	HANDLE mPipeHandle;
	int endCalled;
	int paused;
	DWORD totalRead;
	void *user1;
	void* ipcreserved;

	OVERLAPPED read_overlapped;
	OVERLAPPED write_overlapped;
	OVERLAPPED overlapped;
	ILibDuktape_DuplexStream *ds;
	BOOL clientConnected;
	void *reservedState;
	char *metadata;
	ULONG_PTR _reserved[5];

	char *buffer;
	DWORD bufferLength;
	DWORD bufferOffset;
	DWORD bytesLeft;
	DWORD unshiftedBytes;
}ILibDuktape_net_WindowsIPC;
#endif

#define ILibDuktape_SecureContext2CertBuffer	"\xFF_SecureContext2CertBuffer"
#define ILibDuktape_SecureContext2SSLCTXPTR		"\xFF_SecureContext2SSLCTXPTR"
#define ILibDuktape_GlobalTunnel_DataPtr		"\xFF_GlobalTunnel_DataPtr"
#define ILibDuktape_GlobalTunnel_Stash			"global-tunnel"
#define ILibDuktape_net_Server_buffer			"\xFF_FixedBuffer"
#define ILibDuktape_net_server_closed			"\xFF_ILibDuktape_net_server_closed"
#define ILibDuktape_net_server_closed_needEmit	"\xFF_ILibDuktape_net_server_closed_needEmit"
#define ILibDuktape_net_Server_Session_buffer	"\xFF_SessionFixedBuffer"
#define ILibDuktape_net_socket_ptr				"\xFF_SocketPtr"
#define ILibDuktape_net_WindowsIPC_Buffer		"\xFF_WindowsIPC"
#define ILibDuktape_net_ConcurrencyArray		"\xFF_ConcurrencyArray"
#define ILibDuktape_net_ConcurrencyMaxSize		"\xFF_ConcurrencyMaxSize"
#define ILibDuktape_net_WindowsIPC_PendingArray "\xFF_WindowsIPC_PendingArray"
#define ILibDuktape_SERVER2ContextTable			"\xFF_Server2ContextTable"
#define ILibDuktape_SERVER2OPTIONS				"\xFF_ServerToOptions"
#define ILibDuktape_SERVER2LISTENOPTIONS		"\xFF_ServerToListenOptions"
#define ILibDuktape_TLSSocket2SecureContext		"\xFF_TLSSocket2SecureContext"
#define ILibDuktape_IPAddress_SockAddr			"\xFF_IPAddress_SockAddr"
#define ILibDuktape_net_server_metadata			"\xFF_net_server_metadata"
#define ILibDuktape_net_server_IPCPath			"\xFF_net_server_IPCPath"

extern void ILibAsyncServerSocket_RemoveFromChain(ILibAsyncServerSocket_ServerModule serverModule);

// Prototypes
void ILibDuktape_net_socket_PUSH(duk_context *ctx, ILibAsyncSocket_SocketModule module);
#ifndef MICROSTACK_NOTLS
duk_ret_t ILibDuktape_tls_server_addContext(duk_context *ctx);
#endif

#ifdef WIN32
ILibTransport_DoneState ILibDuktape_net_server_IPC_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user);
void ILibDuktape_net_server_IPC_EndSink(ILibDuktape_DuplexStream *stream, void *user);
void ILibDuktape_net_server_IPC_PauseSink(ILibDuktape_DuplexStream *sender, void *user);
void ILibDuktape_net_server_IPC_ResumeSink(ILibDuktape_DuplexStream *sender, void *user);
int ILibDuktape_net_server_IPC_unshiftSink(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user);
duk_ret_t ILibDuktape_net_server_IPC_ConnectSink_Finalizer(duk_context *ctx);
BOOL ILibDuktape_server_ipc_ReadSink(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, char *buffer, DWORD bytesRead, void* user);
#endif

void ILibDuktape_net_socket_OnData(ILibAsyncSocket_SocketModule socketModule, char* buffer, int *p_beginPointer, int endPointer, ILibAsyncSocket_OnInterrupt* OnInterrupt, void **user, int *PAUSE)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;
	if (ILibDuktape_DuplexStream_WriteData((ILibDuktape_DuplexStream*)ptrs->duplexStream, buffer + *p_beginPointer, endPointer - *p_beginPointer) != 0) 
	{ 
		*PAUSE = 1; 
	}

	*p_beginPointer = endPointer - ptrs->unshiftBytes;
	ptrs->unshiftBytes = 0;
}
void ILibDuktape_net_socket_OnConnect(ILibAsyncSocket_SocketModule socketModule, int Connected, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;
	struct sockaddr_in6 local;
	if (ptrs->ctx == NULL) { return; }

	duk_push_heapptr(ptrs->ctx, ptrs->object);					// [sockat]
	duk_push_false(ptrs->ctx);									// [socket][connecting]
	duk_put_prop_string(ptrs->ctx, -2, "connecting");			// [socket]
	duk_pop(ptrs->ctx);											// ...

	if (Connected != 0)
	{
		duk_push_heapptr(ptrs->ctx, ptrs->object);																		// [sock]
		if (ILibAsyncSocket_IsDomainSocket(socketModule) == 0)
		{
			ILibAsyncSocket_GetLocalInterface(socketModule, (struct sockaddr*)&local);
			duk_push_string(ptrs->ctx, ILibInet_ntop2((struct sockaddr*)&local, ILibScratchPad, sizeof(ILibScratchPad)));	// [sock][localAddr]
			duk_put_prop_string(ptrs->ctx, -2, "localAddress");																// [sock]
			duk_push_int(ptrs->ctx, (int)ntohs(local.sin6_port));															// [sock][port]
			duk_put_prop_string(ptrs->ctx, -2, "localPort");																// [sock]

			ILibAsyncSocket_GetRemoteInterface(socketModule, (struct sockaddr*)&local);
			duk_push_string(ptrs->ctx, ILibInet_ntop2((struct sockaddr*)&local, ILibScratchPad, sizeof(ILibScratchPad)));	// [sock][remoteAddr]
			duk_put_prop_string(ptrs->ctx, -2, "remoteAddress");															// [sock]
			duk_push_string(ptrs->ctx, local.sin6_family == AF_INET6 ? "IPv6" : "IPv4");									// [sock][remoteFamily]
			duk_put_prop_string(ptrs->ctx, -2, "remoteFamily");																// [sock]
			duk_push_int(ptrs->ctx, (int)ntohs(local.sin6_port));															// [sock][remotePort]
			duk_put_prop_string(ptrs->ctx, -2, "remotePort");																// [sock]
		}
		else
		{
			duk_get_prop_string(ptrs->ctx, -1, "remoteHost");																// [sock][remoteHost]
			duk_put_prop_string(ptrs->ctx, -2, "path");																		// [sock]
		}
		duk_pop(ptrs->ctx);																								// ...

#ifndef MICROSTACK_NOTLS
		if (ptrs->ssl != NULL)
		{
			const unsigned char *alpn = NULL;
			size_t alpnLen = 0;
			SSL_SESSION_get0_alpn_selected(SSL_get_session(ptrs->ssl), &alpn, &alpnLen);
			duk_push_heapptr(ptrs->ctx, ptrs->object);									// [socket]
			if (alpnLen != 0)
			{
				duk_push_lstring(ptrs->ctx, (char*)alpn, alpnLen);
			}
			else
			{
				duk_push_null(ptrs->ctx);
			}
			duk_put_prop_string(ptrs->ctx, -2, "alpnProtocol");
			duk_push_string(ptrs->ctx, SSL_get_servername(ptrs->ssl, TLSEXT_NAMETYPE_host_name));
			duk_put_prop_string(ptrs->ctx, -2, "servername");

			duk_get_prop_string(ptrs->ctx, -1, "emit");									// [socket][emit]
			duk_swap_top(ptrs->ctx, -2);												// [emit][this]
			duk_push_string(ptrs->ctx, "secureConnect");								// [emit][this][secureConnect]
			if (duk_pcall_method(ptrs->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ptrs->ctx, "tls.socket.OnSecureConnect(): "); }
			duk_pop(ptrs->ctx);															// ...
			return;
		}
#endif
		duk_push_heapptr(ptrs->ctx, ptrs->object);					// [this]
		duk_get_prop_string(ptrs->ctx, -1, "emit");					// [this][emit]
		duk_swap_top(ptrs->ctx, -2);								// [emit][this]
		duk_push_string(ptrs->ctx, "connect");						// [emit][this][connect]
		if (duk_pcall_method(ptrs->ctx, 1) != 0) { ILibDuktape_Process_UncaughtException(ptrs->ctx); }
		duk_pop(ptrs->ctx);											// ...
	}
	else 
	{
		duk_push_heapptr(ptrs->ctx, ptrs->object);					// [this]
		duk_get_prop_string(ptrs->ctx, -1, "emit");					// [this][emit]
		duk_swap_top(ptrs->ctx, -2);								// [emit][this]
		duk_push_string(ptrs->ctx, "error");						// [emit][this][error]
		duk_push_object(ptrs->ctx);									// [emit][this][error][errorObj]
#ifndef MICROSTACK_NOTLS
		if (ptrs->ssl != NULL && ILibAsyncSocket_TLS_WasHandshakeError(socketModule))
		{
			duk_push_string(ptrs->ctx, "TLS Handshake Error");		// [emit][this][error][errorObj][msg]
		}
		else
		{
			duk_push_string(ptrs->ctx, "Connection Failed");		// [emit][this][error][errorObj][msg]
		}
#else
		duk_push_string(ptrs->ctx, "Connection Failed");			// [emit][this][error][errorObj][msg]
#endif
		duk_put_prop_string(ptrs->ctx, -2, "message");				// [emit][this][error][errorObj]
		if (duk_pcall_method(ptrs->ctx, 2) != 0) { ILibDuktape_Process_UncaughtException(ptrs->ctx); }
		if (ptrs->ctx != NULL) { duk_pop(ptrs->ctx); }				// ...
	}
}
void ILibDuktape_net_socket_OnDisconnect(ILibAsyncSocket_SocketModule socketModule, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;
	if (ILibMemory_CanaryOK(ptrs->emitter))
	{
		duk_push_heapptr(ptrs->ctx, ptrs->object);			// [sock]
		duk_push_string(ptrs->ctx, "0.0.0.0");				// [sock][localAddr]
		duk_put_prop_string(ptrs->ctx, -2, "localAddress");	// [sock]
		duk_push_undefined(ptrs->ctx);						// [sock][remoteAddr]
		duk_put_prop_string(ptrs->ctx, -2, "remoteAddress");// [sock]
		duk_pop(ptrs->ctx);									// ...

		ILibDuktape_DuplexStream_Closed((ILibDuktape_DuplexStream*)ptrs->duplexStream);
	}
}
void ILibDuktape_net_socket_OnSendOK(ILibAsyncSocket_SocketModule socketModule, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;
	ILibDuktape_DuplexStream_Ready((ILibDuktape_DuplexStream*)ptrs->duplexStream);
}
ILibTransport_DoneState ILibDuktape_net_socket_WriteHandler(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)user;
#ifdef _DEBUG_NET_FRAGMENT_SEND
	int x = bufferLen / 2;
	printf("** Send 1/2: %d of %d bytes\n", x, bufferLen);
	ILibAsyncSocket_Send(ptrs->socketModule, buffer, x, ILibAsyncSocket_MemoryOwnership_USER);
	printf("** Send 2/2: %d  of %d bytes\n", bufferLen - x, bufferLen);
	return((ILibTransport_DoneState)ILibAsyncSocket_Send(ptrs->socketModule, buffer + x, bufferLen - x, ILibAsyncSocket_MemoryOwnership_USER));
#else
	return((ILibTransport_DoneState)ILibAsyncSocket_Send(ptrs->socketModule, buffer, bufferLen, ILibAsyncSocket_MemoryOwnership_USER));
#endif
}
void ILibDuktape_net_socket_EndHandler(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)user;
	ILibAsyncSocket_Disconnect(ptrs->socketModule);
}
void ILibDuktape_net_socket_PauseHandler(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)user;
	ILibAsyncSocket_Pause(ptrs->socketModule);
}
void ILibDuktape_net_socket_ResumeHandler(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)user;
	ILibAsyncSocket_Resume(ptrs->socketModule);
}
duk_ret_t ILibDuktape_net_socket_connect_errorDispatch(duk_context *ctx)
{
	duk_dup(ctx, 0);																		// [socket]
	duk_get_prop_string(ctx, -1, "emit");													// [socket][emit]
	duk_swap_top(ctx, -2);																	// [emit][this]
	duk_push_string(ctx, "error");															// [emit][this][error]
	duk_dup(ctx, 1);																		// [emit][this][error][err]
	duk_call_method(ctx, 2);
	duk_pop(ctx);																			// ...
	return(0);
}
#ifdef WIN32 
void ILibDuktape_net_socket_ipc_error(duk_context *ctx, void ** args, int argsLen)
{
	ILibDuktape_net_WindowsIPC *winIPC = ((ILibDuktape_net_WindowsIPC**)args)[0];
	ILibDuktape_EventEmitter_SetupEmit(winIPC->ctx, winIPC->mSocket, "error");		// [emit][this][error]
	duk_push_string(winIPC->ctx, "Error Connecting Named Pipe");					// [emit][this][error][err]
	duk_pcall_method(winIPC->ctx, 2); duk_pop(winIPC->ctx);							// ...
}
void ILibDuktape_net_Socket_ipc_dataHookCallbackCont(duk_context *ctx, void ** args, int argsLen)
{
	ILibDuktape_EventEmitter *emitter = (ILibDuktape_EventEmitter*)args[0];

	if (!ILibMemory_CanaryOK(emitter)) { return; }
	duk_push_heapptr(emitter->ctx, emitter->object);		// [stream]
	duk_get_prop_string(emitter->ctx, -1, "resume");		// [stream][resume]
	duk_dup(emitter->ctx, -2);								// [stream][resume][this]
	duk_pcall_method(emitter->ctx, 0);
	duk_pop(emitter->ctx);									// ...
}
void ILibDuktape_net_socket_ipc_dataHookCallback(ILibDuktape_EventEmitter *sender, char *eventName, void *hookedCallback)
{
	if (ILibDuktape_EventEmitter_HasListeners(sender, "data") == 0 && ILibDuktape_EventEmitter_HasListeners(sender, "end") == 0)
	{
		int top = duk_get_top(sender->ctx);
		duk_push_heapptr(sender->ctx, sender->object);		// [stream]
		duk_get_prop_string(sender->ctx, -1, "isPaused");	// [stream][isPaused]
		duk_dup(sender->ctx, -2);							// [stream][isPaused][this]
		if (duk_pcall_method(sender->ctx, 0) == 0)
		{														
			if (duk_get_boolean(sender->ctx, -1))			// [stream][bool]
			{
				ILibDuktape_Immediate(sender->ctx, (void**)&sender, 1, ILibDuktape_net_Socket_ipc_dataHookCallbackCont);
			}
		}
		duk_set_top(sender->ctx, top);
	}
}
duk_ret_t ILibDuktape_net_ipcSocket_connectHook(duk_context *ctx)
{
	char *eventName = (char*)duk_require_string(ctx, 0);
	if (strcmp(eventName, "connect") == 0)
	{
		// Remove ourselves
		duk_push_this(ctx);									// [socket]
		duk_get_prop_string(ctx, -1, "removeListener");		// [socket][removeListener]
		duk_swap_top(ctx, -2);								// [removeListener][this]
		duk_push_string(ctx, "newListener");				// [removeListener][this][newListener]
		duk_push_current_function(ctx);						// [removeListener][this][newListener][func]
		duk_pcall_method(ctx, 2); duk_pop(ctx);				// ...

		duk_dup(ctx, 1);					// [listener]
		duk_push_this(ctx);					// [listenter][this]
		duk_call_method(ctx, 0);
	}
	return(0);
}
#endif
duk_ret_t ILibDuktape_net_socket_connect(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int port = 0;
	char *host = "127.0.0.1";
	char *path = NULL;
	duk_size_t pathLen = 0;
	ILibDuktape_net_socket *ptrs;
	struct sockaddr_in6 dest;
	struct sockaddr_in6 proxy;
	memset(&proxy, 0, sizeof(struct sockaddr_in6));
	int onConnectSpecified = 0;

	if (nargs == 0) { return(ILibDuktape_Error(ctx, "Too few arguments")); }
	duk_push_this(ctx);														// [socket]
	duk_get_prop_string(ctx, -1, ILibDuktape_net_socket_ptr);				// [socket][ptrs]
	ptrs = (ILibDuktape_net_socket*)duk_to_pointer(ctx, -1);
	duk_pop(ctx);															// [socket]
	
	if (duk_is_object(ctx, 0))
	{
		/* This is an OPTIONS object
		port: Port the client should connect to(Required).
		host : Host the client should connect to.Defaults to 'localhost'.
		localAddress : Local interface to bind to for network connections.
		localPort : Local port to bind to for network connections.
		family : Version of IP stack.Defaults to 4.
		hints : dns.lookup() hints.Defaults to 0.
		lookup : Custom lookup function.Defaults to dns.lookup.
		*/
		host = Duktape_GetStringPropertyValue(ctx, 0, "host", "127.0.0.1");
		port = Duktape_GetIntPropertyValue(ctx, 0, "port", 0);
		path = Duktape_GetStringPropertyValueEx(ctx, 0, "path", NULL, &pathLen);
		if (duk_has_prop_string(ctx, 0, "proxy"))
		{
			duk_get_prop_string(ctx, 0, "proxy");
			ILibResolveEx(Duktape_GetStringPropertyValue(ctx, -1, "host", NULL), (unsigned short)Duktape_GetIntPropertyValue(ctx, -1, "port", 0), &proxy);
			duk_pop(ctx);
		}
		if (nargs >= 2 && duk_is_function(ctx, 1))
		{
			onConnectSpecified = 1;
			ILibDuktape_EventEmitter_AddOn(ptrs->emitter, "connect", duk_require_heapptr(ctx, 1));
		}
	}
	if (duk_is_string(ctx, 0) || (pathLen > 0 && port == 0))
	{
		// This is a PATH string (Domain Socket on Linux/MacOS, Named Pipe on Windows)
		if (onConnectSpecified == 0 && duk_is_function(ctx, 1))
		{
			onConnectSpecified = 1;
			ILibDuktape_EventEmitter_AddOn(ptrs->emitter, "connect", duk_require_heapptr(ctx, 1));
		}

#ifdef WIN32
		duk_push_this(ctx);
		duk_push_array(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_net_WindowsIPC_PendingArray);
		ILibDuktape_WriteID(ctx, "net.ipcSocket");

		ILibDuktape_net_WindowsIPC *winIPC = (ILibDuktape_net_WindowsIPC*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_net_WindowsIPC));
		duk_put_prop_string(ctx, -2, ILibDuktape_net_WindowsIPC_Buffer);
		winIPC->read_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		winIPC->write_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		winIPC->ctx = ctx;
		winIPC->mSocket = duk_get_heapptr(ctx, -1);
		winIPC->mChain = duk_ctx_chain(ctx);
		winIPC->paused = 1;
		winIPC->metadata = "net.ipcSocket";
		winIPC->bufferLength = ILibDuktape_net_IPC_BUFFERSIZE;
		ILibMemory_ReallocateRaw(&(winIPC->buffer), ILibDuktape_net_IPC_BUFFERSIZE);

		if ((winIPC->mPipeHandle = CreateFileA(path, GENERIC_READ | FILE_WRITE_DATA, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0)) == INVALID_HANDLE_VALUE)
		{
			// We'll emit the 'error' event on the next event loop, becuase if 'createConnection' was called, there is no way the event listener is set yet
			ILibDuktape_Immediate(ctx, (void**)&winIPC, 1, ILibDuktape_net_socket_ipc_error);
		}
		else
		{
			// SUCCESS
			winIPC->ds = ILibDuktape_DuplexStream_InitEx(winIPC->ctx, ILibDuktape_net_server_IPC_WriteSink, ILibDuktape_net_server_IPC_EndSink, ILibDuktape_net_server_IPC_PauseSink, ILibDuktape_net_server_IPC_ResumeSink, ILibDuktape_net_server_IPC_unshiftSink, winIPC);
			winIPC->ds->readableStream->paused = 1;
			ILibDuktape_EventEmitter_AddHook(ILibDuktape_EventEmitter_GetEmitter(winIPC->ctx, -1), "data", ILibDuktape_net_socket_ipc_dataHookCallback);
			ILibDuktape_EventEmitter_AddHook(ILibDuktape_EventEmitter_GetEmitter(winIPC->ctx, -1), "end", ILibDuktape_net_socket_ipc_dataHookCallback);
			winIPC->reservedState = ILibChain_ReadAndSaveStateEx(winIPC->mChain, winIPC->mPipeHandle, &(winIPC->read_overlapped), winIPC->buffer, winIPC->bufferLength, ILibDuktape_server_ipc_ReadSink, winIPC, winIPC->metadata);

			if (onConnectSpecified == 0)
			{
				// No connectListener was specified, so we need to hook it, becuase otherwise the caller has no way to receive this event
				ILibDuktape_EventEmitter_SetupOn(winIPC->ctx, winIPC->mSocket, "newListener");		// [on][this][newListener]
				ILibDuktape_EventEmitter_PrependOnce(winIPC->ctx, -2, "~", ILibDuktape_net_server_IPC_ConnectSink_Finalizer);
				duk_push_c_function(winIPC->ctx, ILibDuktape_net_ipcSocket_connectHook, 2);			// [on][this][newListener][func]
				if (duk_pcall_method(winIPC->ctx, 2) != 0)
				{
					ILibDuktape_Process_UncaughtExceptionEx(winIPC->ctx, "Error in net.socket.connect.onConnect(): ");
				}
			}
			else
			{
				ILibDuktape_EventEmitter_SetupEmit(winIPC->ctx, winIPC->mSocket, "connect");		//[emit][this][connect]
				ILibDuktape_EventEmitter_PrependOnce(winIPC->ctx, -2, "~", ILibDuktape_net_server_IPC_ConnectSink_Finalizer);
				if (duk_pcall_method(winIPC->ctx, 1) != 0)
				{
					ILibDuktape_Process_UncaughtExceptionEx(winIPC->ctx, "Error in net.socket.connect.onConnect(): ");
				}
			}
			duk_pop(winIPC->ctx);																	// ...
		}
	
		return(1);
#else
		
		if (pathLen > 0) 
		{ 
			host = path; 
		}
		else
		{
			host = (char*)duk_require_string(ctx, 0);
		}
		duk_push_heapptr(ptrs->ctx, ptrs->object);				// [socket]
		duk_push_string(ctx, host);								// [socket][host]
		ILibDuktape_CreateReadonlyProperty(ctx, "remoteHost");	// [socket]
		duk_pop(ctx);											// ...

		struct sockaddr_un serveraddr;
		memset(&serveraddr, 0, sizeof(serveraddr));
		serveraddr.sun_family = AF_UNIX;
		strcpy(serveraddr.sun_path, host);
		ILibAsyncSocket_ConnectTo(ptrs->socketModule, NULL, (struct sockaddr*)&serveraddr, NULL, ptrs);

		duk_push_heapptr(ptrs->ctx, ptrs->object);					// [sockat]
		duk_push_true(ptrs->ctx);									// [socket][connecting]
		duk_put_prop_string(ptrs->ctx, -2, "connecting");			// [socket]
		duk_pop(ptrs->ctx);											// ...

		if (duk_is_object(ptrs->ctx, 0))
		{
			if (duk_has_prop_string(ptrs->ctx, 0, "metadata"))
			{
				duk_size_t len;
				char *tmp = (char*)duk_push_sprintf(ptrs->ctx, "net.ipcSocket, %s", (char*)Duktape_GetStringPropertyValueEx(ptrs->ctx, 0, "metadata", "", &len));
				char *tmp2 = (char*)ILibMemory_SmartAllocate(len + 16);
				memcpy_s(tmp2, ILibMemory_Size(tmp2), tmp, ILibMemory_Size(tmp2) - 1);
				ILibChain_Link_SetMetadata(ptrs->socketModule, tmp2);
			}
			else
			{
				ILibChain_Link_SetMetadata(ptrs->socketModule, "net.ipcSocket");
			}
		}

		return(0);
#endif
	}

	if (duk_is_number(ctx, 0))
	{
		// This is a PORT number
		port = duk_require_int(ctx, 0);
		host = nargs > 1 ? (char*)duk_require_string(ctx, 1) : "127.0.0.1";
		if (nargs > 2 && duk_is_function(ctx, 2))
		{
			ILibDuktape_EventEmitter_AddOn(ptrs->emitter, "connect", duk_require_heapptr(ctx, 2));
		}
	}

	duk_push_heapptr(ptrs->ctx, ptrs->object);				// [socket]
	duk_push_string(ctx, host);								// [socket][host]
	ILibDuktape_CreateReadonlyProperty(ctx, "remoteHost");	// [socket]
	duk_pop(ctx);											// ...


	if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "proxy"))
	{
		duk_get_prop_string(ctx, 0, "proxy");
		ILibResolveEx(Duktape_GetStringPropertyValue(ctx, -1, "host", NULL), (unsigned short)Duktape_GetIntPropertyValue(ctx, -1, "port", 0), &proxy);
		duk_pop(ctx);

		// If we are going to use a proxy, we need to have the proxy resolve the remote host
		duk_push_sprintf(ctx, "%s:%d", host, port);			// [socket][string]
		duk_swap_top(ctx, -2);								// [string][socket]
		ILibAsyncSocket_ConnectToProxyEx(ptrs->socketModule, NULL, (char*)duk_get_string(ctx, -2), (struct sockaddr*)&proxy, Duktape_GetStringPropertyValue(ctx, -1, "username", NULL), Duktape_GetStringPropertyValue(ctx, -1, "password", NULL), NULL, ptrs);
		return(0);
	}


	ILibResolveEx(host, (unsigned short)port, &dest);
	if (dest.sin6_family == AF_UNSPEC || (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "proxy") && proxy.sin6_family == AF_UNSPEC))
	{
		// Can't resolve, check to see if it's cached
		duk_push_heap_stash(ctx);																			// [stash]
		if (duk_has_prop_string(ctx, -1, "_sharedDB"))
		{
			ILibSimpleDataStore db = (ILibSimpleDataStore)Duktape_GetPointerProperty(ctx, -1, "_sharedDB");
			char *dnsCache = (char*)duk_push_sprintf(ctx, "DNS[%s]", host);									// [stash][dnsCache]
			char dnsCacheBuffer[255];
			if (ILibSimpleDataStore_Get(db, dnsCache, dnsCacheBuffer, sizeof(dnsCacheBuffer)) > 0)
			{
				ILibResolveEx(dnsCacheBuffer, (unsigned short)port, &dest);
			}
			duk_pop(ctx);																					// [stash]
		}
		duk_pop(ctx);																						// ...
	}
	if (dest.sin6_family == AF_UNSPEC || (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "proxy") && proxy.sin6_family == AF_UNSPEC))
	{
		// Can't resolve... Delay event emit, until next event loop, because if app called net.createConnection(), they don't have the socket yet
		duk_push_heapptr(ctx, ptrs->object);													// [socket]																
		duk_push_global_object(ctx);															// [socket][g]
		duk_get_prop_string(ctx, -1, "setImmediate");											// [socket][g][immediate]
		duk_swap_top(ctx, -2);																	// [socket][immediate][this]
		duk_push_c_function(ctx, ILibDuktape_net_socket_connect_errorDispatch, DUK_VARARGS);	// [socket][immediate][this][callback]
		duk_dup(ctx, -4);																		// [socket][immediate][this][callback][socket]

		duk_push_error_object(ptrs->ctx, DUK_ERR_ERROR, "Cannot Resolve Hostname: %s", host);	// [socket][immediate][this][callback][socket][err]
		if (duk_pcall_method(ptrs->ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ptrs->ctx, "socket.connect(): "); }
		duk_put_prop_string(ptrs->ctx, -2, "\xFF_Immediate");									// [socket]
		duk_pop(ptrs->ctx);
	}
	else
	{
		ILibAsyncSocket_ConnectTo(ptrs->socketModule, NULL, (struct sockaddr*)&dest, NULL, ptrs);

		duk_push_heapptr(ptrs->ctx, ptrs->object);					// [sockat]
		duk_push_true(ptrs->ctx);									// [socket][connecting]
		duk_put_prop_string(ptrs->ctx, -2, "connecting");			// [socket]
		duk_pop(ptrs->ctx);											// ...
	}
	return 0;
}

duk_ret_t ILibduktape_net_socket_bytesWritten(duk_context *ctx)
{
	ILibDuktape_net_socket *ptrs;

	duk_push_this(ctx);											// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_net_socket_ptr);	// [obj][ptrs]
	ptrs = (ILibDuktape_net_socket*)duk_to_pointer(ctx, -1);

	duk_push_int(ctx, (int)ILibAsyncSocket_GetTotalBytesSent(ptrs->socketModule));
	return 1;
}
duk_ret_t ILibDuktape_net_socket_address(duk_context *ctx)
{
	ILibDuktape_net_socket *ptrs;
	struct sockaddr_in6 local;

	duk_push_this(ctx);											// [sock]
	duk_get_prop_string(ctx, -1, ILibDuktape_net_socket_ptr);	// [socks][ptrs]
	ptrs = (ILibDuktape_net_socket*)duk_to_pointer(ctx, -1);

	memset(&local, 0, sizeof(struct sockaddr_in6));
	ILibAsyncSocket_GetLocalInterface(ptrs->socketModule, (struct sockaddr*)&local);

	duk_push_object(ctx);														// [retVal]
	duk_push_int(ctx, (int)ntohs(local.sin6_port));								// [retVal][port]
	duk_put_prop_string(ctx, -2, "port");										// [retVal]

	duk_push_string(ctx, local.sin6_family == AF_INET6 ? "IPv6" : "IPv4");		// [retVal][family]
	duk_put_prop_string(ctx, -2, "family");										// [retVal]

	duk_push_string(ctx, ILibInet_ntop2((struct sockaddr*)&local, ILibScratchPad, sizeof(ILibScratchPad)));
	duk_put_prop_string(ctx, -2, "address");
	

	return 1;
}

void ILibDuktape_net_socket_timeoutSink(ILibAsyncSocket_SocketModule socketModule, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;

	duk_push_heapptr(ptrs->ctx, ptrs->object);						// [this]
	duk_get_prop_string(ptrs->ctx, -1, "emit");						// [this][emit]
	duk_swap_top(ptrs->ctx, -2);									// [emit][this]
	duk_push_string(ptrs->ctx, "timeout");							// [emit][this][timeout]
	if (duk_pcall_method(ptrs->ctx, 1) != 0) { ILibDuktape_Process_UncaughtException(ptrs->ctx); }
	duk_pop(ptrs->ctx);												// ...
}
duk_ret_t ILibDuktape_net_socket_setTimeout(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	ILibDuktape_net_socket *ptrs;
	int timeout = duk_require_int(ctx, 0);
	duk_push_this(ctx);											// [sock]
	duk_get_prop_string(ctx, -1, ILibDuktape_net_socket_ptr);	// [socks][ptrs]
	ptrs = (ILibDuktape_net_socket*)duk_to_pointer(ctx, -1);
	duk_pop(ctx);												// [socks]

	if (nargs > 1 && duk_is_function(ctx, 1))
	{
		ILibDuktape_EventEmitter_AddOnce(ptrs->emitter, "timeout", duk_require_heapptr(ctx, 1));
	}
	if (timeout == 0)
	{
		// Disable
		ILibDuktape_EventEmitter_RemoveAllListeners(ptrs->emitter, "timeout");
	}
	ILibAsyncSocket_SetTimeoutEx(ptrs->socketModule, timeout, timeout != 0 ? ILibDuktape_net_socket_timeoutSink : NULL);
	return 0;
}
duk_ret_t ILibDuktape_net_socket_finalizer(duk_context *ctx)
{
	void *chain = Duktape_GetChain(ctx);
	ILibDuktape_net_socket* ptrs;
	duk_get_prop_string(ctx, 0, ILibDuktape_net_socket_ptr);
	ptrs = (ILibDuktape_net_socket*)duk_get_pointer(ctx, -1);

	if (ptrs->socketModule != NULL)
	{
		if (ILibAsyncSocket_IsConnected(ptrs->socketModule) != 0) { ILibAsyncSocket_Disconnect(ptrs->socketModule); }
		ILibChain_SafeRemove(chain, ptrs->socketModule);
	}
	ptrs->ctx = NULL;
	return 0;
}
int ILibDuktape_net_socket_unshift(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)user;
	ptrs->unshiftBytes = unshiftBytes;
	return(unshiftBytes);
}
void ILibDuktape_net_socket_PUSH(duk_context *ctx, ILibAsyncSocket_SocketModule module)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)module)->ExtraMemoryPtr;
	if (ptrs != NULL && ptrs->object != NULL)
	{
		duk_push_heapptr(ctx, ptrs->object);
		return;
	}

	duk_push_object(ctx);										// [obj]
	ILibDuktape_WriteID(ctx, "net.socket");
	ptrs->ctx = ctx;
	ptrs->chain = ((ILibChain_Link*)module)->ParentChain;
	ptrs->object = duk_get_heapptr(ctx, -1);
	ptrs->socketModule = module;
	ILibChain_Link_SetMetadata(module, "net.socket");
	duk_push_pointer(ctx, ptrs->socketModule); duk_put_prop_string(ctx, -2, ILibDuktape_ChainLinkPtr);

	duk_push_pointer(ctx, ptrs);								// [obj][ptrs]
	duk_put_prop_string(ctx, -2, ILibDuktape_net_socket_ptr);	// [obj]
	duk_push_false(ctx);										// [obj][connecting]
	duk_put_prop_string(ctx, -2, "connecting");					// [obj]
	duk_push_string(ctx, "0.0.0.0");	
	duk_put_prop_string(ctx, -2, "localAddress");
	duk_push_int(ctx, 0);
	duk_put_prop_string(ctx, -2, "localPort");
	duk_push_undefined(ctx);
	duk_put_prop_string(ctx, -2, "remoteAddress");

	ptrs->emitter = ILibDuktape_EventEmitter_Create(ctx);
	ptrs->duplexStream = ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_net_socket_WriteHandler, ILibDuktape_net_socket_EndHandler, ILibDuktape_net_socket_PauseHandler, ILibDuktape_net_socket_ResumeHandler, ILibDuktape_net_socket_unshift, ptrs);

	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "close");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "connect");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "error");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "timeout");

	ILibDuktape_CreateProperty_InstanceMethod(ctx, "connect", ILibDuktape_net_socket_connect, DUK_VARARGS);

	ILibDuktape_CreateEventWithGetter(ctx, "bytesWritten", ILibduktape_net_socket_bytesWritten);


	ILibDuktape_CreateInstanceMethod(ctx, "address", ILibDuktape_net_socket_address, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "setTimeout", ILibDuktape_net_socket_setTimeout, DUK_VARARGS);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_net_socket_finalizer);
}

duk_ret_t ILibDuktape_net_socket_constructor(duk_context *ctx)
{
	ILibDuktape_net_socket *ptrs;
	ILibAsyncSocket_SocketModule sm;
	void *chain;
	void *net;

	if (!duk_is_constructor_call(ctx)) { return(ILibDuktape_Error(ctx, "Invalid call")); }
	
	duk_push_current_function(ctx);				// [func]
	duk_get_prop_string(ctx, -1, "chain");		// [func][chain]
	chain = duk_to_pointer(ctx, -1);
	duk_get_prop_string(ctx, -2, "net");		// [func][net]
	net = duk_get_heapptr(ctx, -1);

	sm = ILibCreateAsyncSocketModuleWithMemory(chain, 4096, ILibDuktape_net_socket_OnData, ILibDuktape_net_socket_OnConnect, ILibDuktape_net_socket_OnDisconnect, ILibDuktape_net_socket_OnSendOK, sizeof(ILibDuktape_net_socket));
	ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)sm)->ExtraMemoryPtr;
	ptrs->net = net;
	ILibDuktape_net_socket_PUSH(ctx, sm);

	return 1;
}
duk_ret_t ILibDuktape_net_createConnection(duk_context *ctx)
{
	void *chain;
	void *net;
	ILibAsyncSocket_SocketModule sm;
	ILibDuktape_net_socket *ptrs;
	int nargs = duk_get_top(ctx), i;

	duk_push_this(ctx);						// [net]
	duk_get_prop_string(ctx, -1, "chain");	// [net][chain]
	chain = duk_to_pointer(ctx, -1);
	net = duk_get_heapptr(ctx, -2);
	duk_pop(ctx);							// [net]

	sm = ILibCreateAsyncSocketModuleWithMemory(chain, 4096, ILibDuktape_net_socket_OnData, ILibDuktape_net_socket_OnConnect, ILibDuktape_net_socket_OnDisconnect, ILibDuktape_net_socket_OnSendOK, sizeof(ILibDuktape_net_socket));
	ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)sm)->ExtraMemoryPtr;
	ptrs->net = net;

	ILibDuktape_net_socket_PUSH(ctx, sm);							// [net][socket]
	duk_get_prop_string(ctx, -1, "connect");						// [net][socket][connect]
	duk_dup(ctx, -2);												// [net][socket][connect][this]
	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);											// [net][socket][connect][this][...args...]
	}
	duk_call_method(ctx, nargs); duk_pop(ctx);						// [net][socket]
	if (duk_is_object(ctx, 0))
	{
		duk_dup(ctx, 0);											// [net][socket][options]
		duk_put_prop_string(ctx, -2, ILibDuktape_SOCKET2OPTIONS);	// [net][socket]
	}	
	return 1;
}

ILibTransport_DoneState ILibDuktape_net_server_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
	if (!ILibMemory_CanaryOK(session)) { return(ILibTransport_DoneState_ERROR); }

	return((ILibTransport_DoneState)ILibAsyncServerSocket_Send(NULL, session->connection, buffer, bufferLen, ILibAsyncSocket_MemoryOwnership_USER));
}
void ILibDuktape_net_server_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
	if (!ILibMemory_CanaryOK(session)) { return; }

	if (session->connection != NULL) { ILibAsyncServerSocket_Disconnect(NULL, session->connection); }
}
void ILibDuktape_net_server_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
	if (!ILibMemory_CanaryOK(session)) { return; }

	ILibAsyncSocket_Pause(session->connection);
}
void ILibDuktape_net_server_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
	if (!ILibMemory_CanaryOK(session)) { return; }

	ILibAsyncSocket_Resume(session->connection);
}
duk_ret_t ILibDuktape_net_server_socket_Finalizer(duk_context *ctx)
{
	ILibDuktape_net_server_session *session;
	duk_get_prop_string(ctx, 0, ILibDuktape_net_Server_Session_buffer);
	session = (ILibDuktape_net_server_session*)Duktape_GetBuffer(ctx, -1, NULL);
	if (session != NULL && session->connection != NULL) 
	{
		void *data = ILibAsyncSocket_GetUser(session->connection);
		if (data != NULL) { free(data); ILibAsyncSocket_SetUser(session->connection, NULL); }
		ILibAsyncServerSocket_Disconnect(NULL, session->connection); 
	}

	return 0;
}
int ILibDuktape_net_server_unshiftSink(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
	if (!ILibMemory_CanaryOK(session)) { return(unshiftBytes); }

	session->unshiftBytes = unshiftBytes;
	return(unshiftBytes);
}
void ILibDuktape_net_server_OnConnect(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void **user)
{
	ILibDuktape_net_server *ptr = (ILibDuktape_net_server*)((void**)ILibMemory_GetExtraMemory(AsyncServerSocketModule, ILibMemory_ASYNCSERVERSOCKET_CONTAINERSIZE))[0];
	ILibDuktape_net_server_session *session;
#ifndef MICROSTACK_NOTLS
	int isTLS = ILibAsyncSocket_IsUsingTls(ConnectionToken);
#else
	int isTLS = 0;
#endif
	if (!ILibMemory_CanaryOK(ptr)) { return; }

	duk_push_heapptr(ptr->ctx, ptr->self);																					// [server]
	if (strcmp(Duktape_GetStringPropertyValue(ptr->ctx, -1, ILibDuktape_OBJID, ""), "net.ipcServer") == 0)
	{
		((ILibChain_Link*)ConnectionToken)->MetaData = "net.ipcServer.ipcSocketConnection";
	}
	else
	{
		((ILibChain_Link*)ConnectionToken)->MetaData = isTLS == 0 ? "net.serverSocketConnection" : "tls.serverSocketConnection";
	}

	duk_get_prop_string(ptr->ctx, -1, "emit");																				// [server][emit]
	duk_swap_top(ptr->ctx, -2);																								// [emit][this]
	duk_push_string(ptr->ctx, isTLS ? "secureConnection" : "connection");													// [emit][this][connection]

	duk_push_object(ptr->ctx);																								// [emit][this][connection][socket]
	ILibDuktape_WriteID(ptr->ctx, isTLS ? "tls.serverSocketConnection" : "net.serverSocketConnection");
	ILibDuktape_CreateFinalizer(ptr->ctx, ILibDuktape_net_server_socket_Finalizer);
	session = Duktape_PushBuffer(ptr->ctx, sizeof(ILibDuktape_net_server_session));											// [emit][this][connection][socket][buffer]
	duk_put_prop_string(ptr->ctx, -2, ILibDuktape_net_Server_Session_buffer);												// [emit][this][connection][socket]

	if (isTLS)
	{
		const unsigned char *alpn = NULL;
		size_t alpnLen = 0;
		SSL_SESSION_get0_alpn_selected(SSL_get_session(ILibAsyncServerSocket_GetSSL(ConnectionToken)), &alpn, &alpnLen);
		if (alpnLen != 0)
		{
			duk_push_lstring(ptr->ctx, (char*)alpn, alpnLen);
		}
		else
		{
			duk_push_null(ptr->ctx);
		}
		duk_put_prop_string(ptr->ctx, -2, "alpnProtocol");
		duk_push_string(ptr->ctx, SSL_get_servername(ILibAsyncServerSocket_GetSSL(ConnectionToken), TLSEXT_NAMETYPE_host_name));
		duk_put_prop_string(ptr->ctx, -2, "servername");
	}

	struct sockaddr_in6 local;
	ILibAsyncSocket_GetLocalInterface(ConnectionToken, (struct sockaddr*)&local);
	duk_push_string(ptr->ctx, ILibInet_ntop2((struct sockaddr*)&local, ILibScratchPad, sizeof(ILibScratchPad)));			// [emit][this][connection][sock][localAddr]
	duk_put_prop_string(ptr->ctx, -2, "localAddress");																		// [emit][this][connection][sock]
	duk_push_int(ptr->ctx, (int)ntohs(local.sin6_port));																	// [emit][this][connection][sock][port]
	duk_put_prop_string(ptr->ctx, -2, "localPort");																			// [emit][this][connection][sock]
	ILibAsyncSocket_GetRemoteInterface(ConnectionToken, (struct sockaddr*)&local);
	duk_push_string(ptr->ctx, ILibInet_ntop2((struct sockaddr*)&local, ILibScratchPad, sizeof(ILibScratchPad)));			// [emit][this][connection][sock][remoteAddr]
	duk_put_prop_string(ptr->ctx, -2, "remoteAddress");																		// [emit][this][connection][sock]
	duk_push_string(ptr->ctx, local.sin6_family == AF_INET6 ? "IPv6" : "IPv4");												// [emit][this][connection][sock][remoteFamily]
	duk_put_prop_string(ptr->ctx, -2, "remoteFamily");																		// [emit][this][connection][sock]
	duk_push_int(ptr->ctx, (int)ntohs(local.sin6_port));																	// [emit][this][connection][sock][remotePort]
	duk_put_prop_string(ptr->ctx, -2, "remotePort");																		// [emit][this][connection][sock]


	*user = session;
	session->ctx = ptr->ctx;
	session->connection = ConnectionToken;
	session->self = duk_get_heapptr(ptr->ctx, -1);
	session->emitter = ILibDuktape_EventEmitter_Create(ptr->ctx);
		

	ILibDuktape_EventEmitter_CreateEventEx(session->emitter, "timeout");

	session->stream = ILibDuktape_DuplexStream_InitEx(ptr->ctx, ILibDuktape_net_server_WriteSink, ILibDuktape_net_server_EndSink,
		ILibDuktape_net_server_PauseSink, ILibDuktape_net_server_ResumeSink, ILibDuktape_net_server_unshiftSink, session);

	if (duk_pcall_method(ptr->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ptr->ctx, (isTLS ? "tls.server.OnSecureConnection(): Exception" : "net.server.OnConnect(): Exception")); }
	duk_pop(ptr->ctx);																	// ...
}
void ILibDuktape_net_server_OnDisconnect(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
	if (!ILibMemory_CanaryOK(session)) { return; }

	if (session->connection != NULL)
	{
		ILibDuktape_DuplexStream_Closed(session->stream);
		session->connection = NULL;
	}
}
void ILibDuktape_net_server_OnReceive(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, char* buffer, int *p_beginPointer, int endPointer, ILibAsyncServerSocket_OnInterrupt *OnInterrupt, void **user, int *PAUSE)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)*user;
	if (!ILibMemory_CanaryOK(session)) { *p_beginPointer = endPointer;  return; }

	session->unshiftBytes = 0;
	ILibDuktape_DuplexStream_WriteData(session->stream, buffer + *p_beginPointer, endPointer);
	*p_beginPointer = endPointer - session->unshiftBytes;
}
void ILibDuktape_net_server_OnInterrupt(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void *user)
{
}
void ILibDuktape_net_server_OnSendOK(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
	if (!ILibMemory_CanaryOK(session)) { return; }

	ILibDuktape_DuplexStream_Ready(session->stream);
}

#ifdef WIN32
BOOL ILibDuktape_server_ipc_ReadSink(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, char *buffer, DWORD bytesRead, void* user)
{
	ILibDuktape_net_WindowsIPC *winIPC = (ILibDuktape_net_WindowsIPC*)user;
	int consumed = 0;

	if (status == ILibWaitHandle_ErrorStatus_NONE)
	{
		winIPC->totalRead += bytesRead;
		do
		{
			winIPC->unshiftedBytes = 0;
			if (winIPC->totalRead > 0)
			{
				ILibDuktape_DuplexStream_WriteData(winIPC->ds, winIPC->buffer + winIPC->bufferOffset, winIPC->totalRead);
			}
			if (winIPC->unshiftedBytes > winIPC->totalRead) { winIPC->unshiftedBytes = winIPC->totalRead; }
			consumed = winIPC->totalRead - winIPC->unshiftedBytes;
			winIPC->bufferOffset += (winIPC->totalRead - winIPC->unshiftedBytes);
			winIPC->totalRead -= (winIPC->totalRead - winIPC->unshiftedBytes);
		} while (winIPC->paused == 0 && consumed != 0 && winIPC->totalRead > 0);
		if (winIPC->totalRead == 0) { winIPC->bufferOffset = 0; }
		if (winIPC->paused == 0)
		{
			if (winIPC->bufferOffset > 0)
			{
				memmove_s(winIPC->buffer, winIPC->bufferLength, winIPC->buffer + winIPC->bufferOffset, winIPC->totalRead);
				winIPC->bufferOffset = 0;
			}
			else if (winIPC->totalRead == winIPC->bufferLength)
			{
				ILibMemory_ReallocateRaw(&(winIPC->buffer), winIPC->bufferLength == 0 ? ILibDuktape_net_IPC_BUFFERSIZE : winIPC->bufferLength * 2);
				winIPC->bufferLength = winIPC->bufferLength == 0 ? ILibDuktape_net_IPC_BUFFERSIZE : winIPC->bufferLength * 2;
			}
			ILibChain_ReadEx2(chain, h, &(winIPC->read_overlapped), winIPC->buffer + winIPC->bufferOffset + winIPC->totalRead, winIPC->bufferLength - winIPC->totalRead, ILibDuktape_server_ipc_ReadSink, winIPC, winIPC->metadata);
			return(TRUE);
		}
		else
		{
			return(FALSE);
		}
	}
	else
	{
		// I/O Errors

		if (winIPC->mServer != NULL) { winIPC->clientConnected = 0; }
		if (winIPC->reservedState != NULL) { ILibChain_WaitHandle_DestroySavedState(chain, winIPC->reservedState); winIPC->reservedState = NULL; }
		
		winIPC->endCalled = 0; 
		ILibDuktape_DuplexStream_Closed(winIPC->ds);
		if (ILibMemory_CanaryOK(winIPC) && winIPC->endCalled == 0)
		{
			duk_context *_ctx = winIPC->ctx;
			duk_push_heapptr(winIPC->ctx, winIPC->ds->readableStream->object);	// [obj]
			duk_prepare_method_call(winIPC->ctx, -1, "end");					// [obj][end][this]
			if (duk_pcall_method(winIPC->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(_ctx, "net.ipcServer.end() Error: "); }
			duk_pop_2(_ctx);												// ...
		}

		return(FALSE);
	}
}
BOOL ILibDuktape_server_ipc_WriteSink(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, DWORD bytesWritten, void* user)
{
	if (!ILibMemory_CanaryOK(user)) { return(FALSE); }
	ILibDuktape_net_WindowsIPC *winIPC = (ILibDuktape_net_WindowsIPC*)user;
	duk_idx_t top = duk_get_top(winIPC->ctx);
	duk_size_t bufLen;
	char *buf;
	ILibTransport_DoneState d = ILibTransport_DoneState_COMPLETE;
	BOOL ret = FALSE;

	duk_push_heapptr(winIPC->ctx, winIPC->mSocket);														// [obj]
	duk_get_prop_string(winIPC->ctx, -1, ILibDuktape_net_WindowsIPC_PendingArray);						// [obj][array]

	while (d == ILibTransport_DoneState_COMPLETE)
	{
		duk_dup(winIPC->ctx, -1);																		// [obj][array][array]
		duk_get_prop_string(winIPC->ctx, -1, "shift");													// [obj][array][array][shift]
		duk_swap_top(winIPC->ctx, -2);																	// [obj][array][shift][this]
		if (duk_pcall_method(winIPC->ctx, 0) != 0) { duk_set_top(winIPC->ctx, top);  return(FALSE); }	// [obj][array][buffer]
		duk_pop(winIPC->ctx);																			// [obj][array]
		if (duk_get_length(winIPC->ctx, -1) == 0) { break; }
		duk_get_prop_index(winIPC->ctx, -1, 0);															// [obj][array][buffer]
		buf = Duktape_GetBuffer(winIPC->ctx, -1, &bufLen);						
		d = ILibChain_WriteEx2(chain, h, &(winIPC->write_overlapped), buf, (DWORD)bufLen, ILibDuktape_server_ipc_WriteSink, winIPC, "server_ipc_WriteSink()");
		duk_pop(winIPC->ctx);																			// [obj][array]
	}

	switch (d)
	{
		case ILibTransport_DoneState_COMPLETE:
			// No more pending writes, so we can emit drain
			ILibDuktape_DuplexStream_Ready(winIPC->ds);
			ret = FALSE;
			break;
		case ILibTransport_DoneState_INCOMPLETE:
			// Still pending writes, so return TRUE, so we can get evented later
			ret = TRUE;
			break;
		case ILibTransport_DoneState_ERROR:
			ret = FALSE;
			break;
	}

	duk_set_top(winIPC->ctx, top);												// ...
	return(ret);
}

int ILibDuktape_net_server_IPC_unshiftSink(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user)
{
	ILibDuktape_net_WindowsIPC *winIPC = (ILibDuktape_net_WindowsIPC*)user;
	if (!ILibMemory_CanaryOK(user)) { return(0); }
	winIPC->unshiftedBytes = unshiftBytes;
	return(unshiftBytes);
}

void ILibDuktape_net_server_IPC_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
	// No-OP, becuase all we need to so is set Paused flag, which is already the  case when we get here
	ILibDuktape_net_WindowsIPC *winIPC = (ILibDuktape_net_WindowsIPC*)user;
	winIPC->paused = 1;

	if (winIPC->mServer != NULL && winIPC->clientConnected == 0) { return; } // Not connected, so just return. Probably unpiping

	winIPC->reservedState = ILibChain_WaitHandle_RemoveAndSaveState(winIPC->mChain, winIPC->read_overlapped.hEvent);
}
void ILibDuktape_net_server_IPC_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_net_WindowsIPC *winIPC = (ILibDuktape_net_WindowsIPC*)user;
	winIPC->paused = 0;
	if (winIPC->reservedState != NULL)
	{
		ILibChain_WaitHandle_RestoreState(winIPC->mChain, winIPC->reservedState);
		winIPC->reservedState = NULL;
	}
	else
	{
		ILibDuktape_server_ipc_ReadSink(winIPC->mChain, winIPC->mPipeHandle, ILibWaitHandle_ErrorStatus_NONE, NULL, 0, winIPC);
	}
}

ILibTransport_DoneState ILibDuktape_net_server_IPC_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	if (!ILibMemory_CanaryOK(user)) { return(ILibTransport_DoneState_ERROR); }
	ILibDuktape_net_WindowsIPC *winIPC = (ILibDuktape_net_WindowsIPC*)user;
	if (!duk_ctx_is_alive(winIPC->ctx) || winIPC->mPipeHandle == NULL) { return(ILibTransport_DoneState_ERROR); }

	duk_push_heapptr(winIPC->ctx, winIPC->mSocket);											// [obj]
	duk_get_prop_string(winIPC->ctx, -1, ILibDuktape_net_WindowsIPC_PendingArray);			// [obj][array]
	
	char *q = duk_push_fixed_buffer(winIPC->ctx, bufferLen);								// [obj][array][buffer]
	duk_size_t len = duk_get_length(winIPC->ctx, -2);
	duk_put_prop_index(winIPC->ctx, -2, (duk_uarridx_t)len);								// [obj][array]
	memcpy_s(q, bufferLen, buffer, bufferLen);
	duk_pop_2(winIPC->ctx);																	// ...

	if (len == 0)
	{
		// No Pending Writes
		ILibTransport_DoneState ret = ILibChain_WriteEx2(winIPC->mChain, winIPC->mPipeHandle, &(winIPC->write_overlapped), q, bufferLen, ILibDuktape_server_ipc_WriteSink, winIPC, "net_server_IPC_WriteSink()");
		if (ret != ILibTransport_DoneState_INCOMPLETE)
		{
			duk_push_heapptr(winIPC->ctx, winIPC->mSocket);											// [obj]
			duk_get_prop_string(winIPC->ctx, -1, ILibDuktape_net_WindowsIPC_PendingArray);			// [obj][array]
			duk_array_shift(winIPC->ctx, -1);														// [obj][array][val]
			duk_pop_3(winIPC->ctx);																	// ...
		}
		return(ret);
	}

	return(ILibTransport_DoneState_INCOMPLETE);
}
void ILibDuktape_net_server_IPC_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	if (!ILibMemory_CanaryOK(user)) { return; }
	ILibDuktape_net_WindowsIPC *winIPC = (ILibDuktape_net_WindowsIPC*)user;
	if (winIPC->mServer != NULL && winIPC->mPipeHandle == NULL) { return; } // Already Closed
	winIPC->endCalled = 1;
	if (winIPC->metadata != NULL) { ILibMemory_Free(winIPC->metadata); winIPC->metadata = NULL; }
	if (winIPC->reservedState != NULL)
	{
		ILibChain_WaitHandle_DestroySavedState(winIPC->mChain, winIPC->reservedState);
		winIPC->reservedState = NULL;
	}
	else
	{
		// We probably aren't paused, so we need to remove our wait handles
		if (winIPC->read_overlapped.hEvent != NULL) { ILibChain_RemoveWaitHandleEx(winIPC->mChain, winIPC->read_overlapped.hEvent, 1); }
		if (winIPC->write_overlapped.hEvent != NULL) { ILibChain_RemoveWaitHandleEx(winIPC->mChain, winIPC->write_overlapped.hEvent, 1); }
	}
	if (winIPC->mPipeHandle != NULL) 
	{
		if (winIPC->mServer != NULL) { DisconnectNamedPipe(winIPC->mPipeHandle); }
		CloseHandle(winIPC->mPipeHandle); winIPC->mPipeHandle = NULL; 
	}
	if (winIPC->read_overlapped.hEvent != NULL) { CloseHandle(winIPC->read_overlapped.hEvent); winIPC->read_overlapped.hEvent = NULL; }
	if (winIPC->write_overlapped.hEvent != NULL) { CloseHandle(winIPC->write_overlapped.hEvent); winIPC->write_overlapped.hEvent = NULL; }

	if (winIPC != NULL && winIPC->mServer != NULL)
	{
		duk_context *_ctx = winIPC->ctx;
		duk_push_heapptr(winIPC->ctx, winIPC->mServer);							// [server]
		int needEmitClose = Duktape_GetBooleanProperty(winIPC->ctx, -1, ILibDuktape_net_server_closed_needEmit, 0);

		duk_get_prop_string(winIPC->ctx, -1, ILibDuktape_net_ConcurrencyArray);	// [server][array]
		duk_prepare_method_call(winIPC->ctx, -1, "indexOf");					// [server][array][indexOf][this]
		duk_push_heapptr(winIPC->ctx, winIPC->ipcreserved);						// [server][array][indexOf][this][buffer]
		if (duk_pcall_method(winIPC->ctx, 1) == 0)								// [server][array][index]
		{
			int ix = duk_get_int(winIPC->ctx, -1);								
			if (ix >= 0)
			{
				duk_uarridx_t numObjects = (duk_uarridx_t)duk_get_length(_ctx, -2);
				int maxLen = Duktape_GetIntPropertyValue(_ctx, -3, ILibDuktape_net_ConcurrencyMaxSize, 1);
				duk_uarridx_t z;
				int setup = numObjects == maxLen ? 1 : 0;
				int connected = 0;

				for (z = 0; z < numObjects; ++z)
				{																
					duk_get_prop_index(winIPC->ctx, -2, z);						// [server][array][index][winIPC]
					if (z != ix && ((ILibDuktape_net_WindowsIPC*)Duktape_GetBuffer(winIPC->ctx, -1, NULL))->clientConnected == FALSE)
					{
						setup = 0;
					}
					if (((ILibDuktape_net_WindowsIPC*)Duktape_GetBuffer(winIPC->ctx, -1, NULL))->clientConnected == TRUE)
					{
						++connected;
					}
					duk_pop(winIPC->ctx);											// [server][array][index]
				}

				duk_array_remove(winIPC->ctx, -2, ix);

				if (setup != 0 && needEmitClose == 0)
				{
					duk_prepare_method_call(_ctx, -3, "listen");					// [server][array][index][listen][this]
					duk_get_prop_string(_ctx, -1, ILibDuktape_SERVER2LISTENOPTIONS);// [server][array][index][listen][this][options]
					duk_pcall_method(_ctx, 1); duk_pop(_ctx);						// [server][array][index]
				}
				else
				{
					if (needEmitClose != 0 && connected == 0)
					{
						// All connections are now closed, so we can emit 'close'
						ILibDuktape_EventEmitter_SetupEmitEx(_ctx, -3, "close");	// [server][array][index][emit][this][close]
						duk_pcall_method(_ctx, 1); duk_pop(_ctx);					// [server][array][index]
					}
				}
			}
		}
		duk_pop_3(_ctx);															// ...
	}
}
duk_ret_t ILibDuktape_net_server_IPC_ConnectSink_Finalizer(duk_context *ctx)
{
	ILibDuktape_net_WindowsIPC *winIPC = (ILibDuktape_net_WindowsIPC*)Duktape_GetBufferProperty(ctx, 0, ILibDuktape_net_WindowsIPC_Buffer);
	if (winIPC != NULL)
	{
		if (winIPC->mPipeHandle != NULL)
		{
			CloseHandle(winIPC->mPipeHandle);
			winIPC->mPipeHandle = NULL;
		}
		if (winIPC->read_overlapped.hEvent != NULL)
		{
			ILibChain_RemoveWaitHandleEx(duk_ctx_chain(ctx), winIPC->read_overlapped.hEvent, 1);
			CloseHandle(winIPC->read_overlapped.hEvent);
			winIPC->read_overlapped.hEvent = NULL;
		}
		if (winIPC->write_overlapped.hEvent != NULL)
		{
			ILibChain_RemoveWaitHandleEx(duk_ctx_chain(ctx), winIPC->write_overlapped.hEvent, 1);
			CloseHandle(winIPC->write_overlapped.hEvent);
			winIPC->write_overlapped.hEvent = NULL;
		}
		
		if (winIPC->buffer != NULL) { free(winIPC->buffer); }
		if (winIPC->metadata != NULL) { ILibMemory_Free(winIPC->metadata); winIPC->metadata = NULL; }
	}
	return(0);
}
duk_ret_t ILibDuktape_net_server_IPC_connection_metadata(duk_context *ctx)
{
	duk_push_this(ctx);			// [ipcSocket]
	char *id = Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_OBJID, NULL);

	ILibDuktape_net_WindowsIPC *winIPC = (ILibDuktape_net_WindowsIPC*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_net_WindowsIPC_Buffer);
	char *tmp = (char*)duk_push_sprintf(ctx, "%s, %s", winIPC->metadata, (char*)duk_require_string(ctx, 0));
	char *tmp2 = (char*)ILibMemory_SmartAllocate(1 + duk_get_length(ctx, -1));
	memcpy_s(tmp2, ILibMemory_Size(tmp2), tmp, ILibMemory_Size(tmp2) - 1);
	ILibMemory_Free(winIPC->metadata);
	winIPC->metadata = tmp2;

	return(0);
}
BOOL ILibDuktape_net_server_IPC_ConnectSink(void *chain, HANDLE event, ILibWaitHandle_ErrorStatus status, void* user)
{
	if (ILibMemory_CanaryOK(user) && status == ILibWaitHandle_ErrorStatus_NONE)
	{
		ILibDuktape_net_WindowsIPC *winIPC = (ILibDuktape_net_WindowsIPC*)user;
		if (winIPC->mServer != NULL)
		{
			if (winIPC->overlapped.hEvent != NULL) { CloseHandle(winIPC->overlapped.hEvent); winIPC->overlapped.hEvent = NULL; }

			duk_push_heapptr(winIPC->ctx, winIPC->mServer);							// [server]
			duk_get_prop_string(winIPC->ctx, -1, ILibDuktape_net_ConcurrencyArray);	// [server][array]
			int maxCount = Duktape_GetIntPropertyValue(winIPC->ctx, -2, ILibDuktape_net_ConcurrencyMaxSize, 0);	
			int curCount = (int)duk_get_length(winIPC->ctx, -1);
			duk_pop_2(winIPC->ctx);													// ...

			if (curCount < maxCount)
			{
				// We are still within concurrency limits, so lets prepare for another connection
				duk_push_heapptr(winIPC->ctx, winIPC->mServer);							// [server]
				duk_prepare_method_call(winIPC->ctx, -1, "listen");						// [server][listen][this]
				duk_remove(winIPC->ctx, -3);											// [listen][this]
				duk_get_prop_string(winIPC->ctx, -1, ILibDuktape_SERVER2LISTENOPTIONS);	// [listen][this][options]
				duk_pcall_method(winIPC->ctx, 1);
				duk_pop(winIPC->ctx);													// ...
			}
		}


		winIPC->clientConnected = TRUE;
		ILibDuktape_EventEmitter_SetupEmit(winIPC->ctx, winIPC->mServer, "connection");	// [emit][this][connection]
		duk_push_object(winIPC->ctx);													// [emit][this][connection][socket]
		ILibDuktape_WriteID(winIPC->ctx, "net.ipcSocket");
		winIPC->metadata = "net.ipcSocket";

		duk_push_heapptr(winIPC->ctx, winIPC->ipcreserved);								// [emit][this][connection][socket][buffer]
		duk_put_prop_string(winIPC->ctx, -2, ILibDuktape_net_WindowsIPC_Buffer);		// [emit][this][connection][socket]

		duk_push_array(winIPC->ctx); duk_put_prop_string(winIPC->ctx, -2, ILibDuktape_net_WindowsIPC_PendingArray);
		winIPC->mSocket = duk_get_heapptr(winIPC->ctx, -1);
		winIPC->ds = ILibDuktape_DuplexStream_InitEx(winIPC->ctx, ILibDuktape_net_server_IPC_WriteSink, ILibDuktape_net_server_IPC_EndSink, ILibDuktape_net_server_IPC_PauseSink, ILibDuktape_net_server_IPC_ResumeSink, ILibDuktape_net_server_IPC_unshiftSink, winIPC);
		winIPC->ds->readableStream->paused = 1;
		winIPC->paused = 1;

		ILibDuktape_EventEmitter_AddHook(ILibDuktape_EventEmitter_GetEmitter(winIPC->ctx, -1), "data", ILibDuktape_net_socket_ipc_dataHookCallback);
		ILibDuktape_EventEmitter_AddHook(ILibDuktape_EventEmitter_GetEmitter(winIPC->ctx, -1), "end", ILibDuktape_net_socket_ipc_dataHookCallback);
		ILibDuktape_CreateEventWithSetterEx(winIPC->ctx, "descriptorMetadata", ILibDuktape_net_server_IPC_connection_metadata);
		ILibDuktape_EventEmitter_PrependOnce(winIPC->ctx, -1, "~", ILibDuktape_net_server_IPC_ConnectSink_Finalizer);
		if (duk_pcall_method(winIPC->ctx, 2) != 0)
		{
			ILibDuktape_Process_UncaughtExceptionEx(winIPC->ctx, "Error emitting net.ipcSocket.connection");
		}
		duk_pop(winIPC->ctx);
	}
	return(FALSE);
}
#endif

duk_ret_t ILibDuktape_net_server_connections(duk_context *ctx)
{
	duk_push_this(ctx);													// [server]
	ILibDuktape_net_server *server = (ILibDuktape_net_server*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_net_Server_buffer);

	if (server->server == NULL)
	{
#ifdef WIN32
		// On Windows, IPC uses a ConcurrencyArray
		ILibDuktape_net_WindowsIPC *winIPC = NULL;
		duk_uarridx_t i;
		duk_size_t len;

		duk_get_prop_string(ctx, -1, ILibDuktape_net_ConcurrencyArray);	// [server][array]
		duk_push_array(ctx);											// [server][array][retArray]
		len = duk_get_length(ctx, -2);
		for (i = 0; i < len; ++i)
		{
			duk_get_prop_index(ctx, -2, i);								// [server][array][retArray][buffer]
			winIPC = (ILibDuktape_net_WindowsIPC*)Duktape_GetBuffer(ctx, -1, NULL);
			if (winIPC->clientConnected == TRUE)
			{
				duk_push_heapptr(ctx, winIPC->mSocket);					// [server][array][retArray][buffer][socket]
				duk_array_push(ctx, -3);								// [server][array][retArray][buffer]
			}
			duk_pop(ctx);												// [server][array][retArray]
		}
#else
		duk_push_array(ctx);
#endif
	}
	else
	{
		size_t i;
		size_t s = ILibAsyncServerSocket_GetConnections(server->server, NULL, 0);
		ILibAsyncServerSocket_ConnectionToken *connections = (ILibAsyncServerSocket_ConnectionToken*)Duktape_PushBuffer(ctx, s * sizeof(ILibAsyncServerSocket_ConnectionToken));
		ILibDuktape_net_server_session *session;

		duk_push_array(ctx);											// [server][retArray]
		s = ILibAsyncServerSocket_GetConnections(server->server, connections, s);
		for (i = 0; i < s; ++i)
		{
			session = (ILibDuktape_net_server_session*)ILibAsyncServerSocket_GetUser(connections[i]);
			if (ILibMemory_CanaryOK(session))
			{
				duk_push_heapptr(ctx, session->emitter->object);
				duk_array_push(ctx, -2);
			}
		}
	}
	return(1);
}

duk_ret_t ILibDuktape_net_server_listen(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	ILibDuktape_net_server *server = NULL;
	int i;

	unsigned short port = 0;
	int backlog = 0;
	int maxConnections = 10;
	struct sockaddr_in6 local;
#ifdef _POSIX
	struct sockaddr_un ipcaddr;
	memset(&ipcaddr, 0, sizeof(struct sockaddr_un));
#endif
	int initalBufferSize = 4096;
	char *host, *ipc;
	duk_size_t ipcLen;
	memset(&local, 0, sizeof(struct sockaddr_in6));

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_net_Server_buffer);
	server = (ILibDuktape_net_server*)Duktape_GetBuffer(ctx, -1, NULL);

	if (nargs == 0 || !duk_is_object(ctx, 0))
	{
		duk_push_this(ctx);															// [server]
		duk_get_prop_string(ctx, -1, "listen");										// [server][listen]
		duk_swap_top(ctx, -2);														// [listen][this]
		duk_push_object(ctx);														// [listen][this][Options]

		// let's call listen again, using an Options object
		if (nargs > 0 && (duk_is_number(ctx, 0) || duk_is_string(ctx, 0)))
		{
			duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, duk_is_number(ctx, 0) ? "port" : "path");					// [listen][this][Options]
			for (i = 1; i < nargs; ++i)
			{
				if (duk_is_number(ctx, i)) { duk_dup(ctx, i); duk_put_prop_string(ctx, -2, "backlog"); }
				if (duk_is_string(ctx, i)) { duk_dup(ctx, i); duk_put_prop_string(ctx, -2, "host"); }
				if (duk_is_function(ctx, i)) { duk_dup(ctx, i); break; }			// [listen][this][Options][callback]
			}
			duk_call_method(ctx, i < nargs ? 2 : 1);
			return(1);
		}
		else
		{
			duk_call_method(ctx, 1);
			return(1);
		}
	}

	// If we are here, we were called with an Options Object
	duk_push_this(ctx);													// [server]
	duk_dup(ctx, 0);													// [server][Options]
	duk_put_prop_string(ctx, -2, ILibDuktape_SERVER2LISTENOPTIONS);		// [server]


	port = (unsigned short)Duktape_GetIntPropertyValue(ctx, 0, "port", 0);
	host = Duktape_GetStringPropertyValue(ctx, 0, "host", NULL);
	ipc = Duktape_GetStringPropertyValueEx(ctx, 0, "path", NULL, &ipcLen);
	maxConnections = Duktape_GetIntPropertyValue(ctx, 0, "maxConnections", (ipc != NULL && port == 0) ? 1 : 10);

	if (nargs > 1 && duk_is_function(ctx, 1))
	{
		// Callback
		ILibDuktape_EventEmitter_AddOn(server->emitter, "listening", duk_require_heapptr(ctx, 1));
	}
	if (host != NULL)
	{
		ILibResolveEx(host, port, &local);
		if (local.sin6_family == AF_UNSPEC)
		{
			return(ILibDuktape_Error(ctx, "Socket.listen(): Could not resolve host: '%s'", host));
		}
	}
	
	if (ipc != NULL && port == 0)
	{
		duk_push_this(ctx);
		ILibDuktape_WriteID(ctx, "net.ipcServer");
		duk_push_string(ctx, ipc); duk_put_prop_string(ctx, -2, ILibDuktape_net_server_IPCPath);
		if (maxConnections >= 0 && !duk_has_prop_string(ctx, -1, ILibDuktape_net_ConcurrencyArray))
		{
			duk_push_array(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_net_ConcurrencyArray);
			duk_push_int(ctx, maxConnections); duk_put_prop_string(ctx, -2, ILibDuktape_net_ConcurrencyMaxSize);
		}
		duk_pop(ctx);

#if defined(_POSIX)
		if (ipcLen > sizeof(ipcaddr.sun_path)) { return(ILibDuktape_Error(ctx, "Path too long")); }
		ipcaddr.sun_family = AF_UNIX;
		strcpy_s((char*)(ipcaddr.sun_path), sizeof(ipcaddr.sun_path), ipc);
		int ipcmod = Duktape_GetBooleanProperty(ctx, 0, "writableAll", 0) == 0 ? 0 : 0777;
		
		server->server = ILibCreateAsyncServerSocketModuleWithMemoryExMOD(Duktape_GetChain(ctx), maxConnections, initalBufferSize, (struct sockaddr*)&ipcaddr,
			ILibDuktape_net_server_OnConnect, ILibDuktape_net_server_OnDisconnect, ILibDuktape_net_server_OnReceive,
			ILibDuktape_net_server_OnInterrupt, ILibDuktape_net_server_OnSendOK, ipcmod, sizeof(void*), sizeof(void*));
#elif defined(WIN32)
		// IPC on Windows Implemented as Named Pipe

		SECURITY_ATTRIBUTES IPC_SA = { 0 };
		SECURITY_ATTRIBUTES *pIPC_SA = &IPC_SA;
		PACL IPC_ACL;
		SECURITY_DESCRIPTOR IPC_SD;
		EXPLICIT_ACCESS IPC_EA = { 0 };
				
		duk_push_this(ctx);												// [server]
		duk_get_prop_string(ctx, -1, ILibDuktape_net_ConcurrencyArray);	// [server][array]
		ILibDuktape_net_WindowsIPC *winIPC = (ILibDuktape_net_WindowsIPC*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_net_WindowsIPC));
		duk_dup(ctx, -1);												// [server][array][buffer][buffer]
		duk_array_push(ctx, -3);										// [server][array][buffer]
		duk_remove(ctx, -2);											// [server][buffer]
		winIPC->ipcreserved = duk_get_heapptr(ctx, -1);
		duk_pop(ctx);													// [server]

		winIPC->overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		winIPC->read_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		winIPC->write_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		winIPC->ctx = ctx;
		winIPC->mServer = duk_get_heapptr(ctx, -1);
		winIPC->mChain = duk_ctx_chain(ctx);
		winIPC->clientConnected = FALSE;
		winIPC->metadata = "net.ipcServer";

		duk_eval_string(ctx, "require('child_process');");
		duk_pop(ctx);

		if (Duktape_GetBooleanProperty(ctx, 0, "writableAll", 0) != 0)
		{
			// World Writable, so we need to set the Security Descriptor to reflect that
			IPC_EA.grfAccessMode = SET_ACCESS;
			IPC_EA.grfInheritance = NO_INHERITANCE;
			IPC_EA.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
			IPC_EA.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
			IPC_EA.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			IPC_EA.Trustee.ptstrName = "EVERYONE";

			SetEntriesInAcl(1, &IPC_EA, NULL, &IPC_ACL);
			InitializeSecurityDescriptor(&IPC_SD, SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&IPC_SD, TRUE, IPC_ACL, FALSE);

			memset(&IPC_SA, 0, sizeof(SECURITY_ATTRIBUTES));
			IPC_SA.nLength = sizeof(SECURITY_ATTRIBUTES);
			IPC_SA.bInheritHandle = FALSE;
			IPC_SA.lpSecurityDescriptor = &IPC_SD;
		}
		else
		{
			// Default security is Read/Write for LocalSystem and owner, and Read for everybody else
			pIPC_SA = NULL;
		}

		winIPC->mPipeHandle = CreateNamedPipeA((LPCSTR)ipc, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
			(DWORD)maxConnections, ILibDuktape_net_IPC_BUFFERSIZE, ILibDuktape_net_IPC_BUFFERSIZE, 0, pIPC_SA);
		if (winIPC->mPipeHandle == INVALID_HANDLE_VALUE)
		{
			DWORD err = GetLastError();
			CloseHandle(winIPC->overlapped.hEvent); winIPC->overlapped.hEvent = NULL;
			return(ILibDuktape_Error(ctx, "Error Creating Named Pipe: %s", ipc));
		}
		//printf("ConnectNamedPipe(%s)\n", ipc);
		duk_push_sprintf(ctx, "net.ipcServer [listen: %s]", ipc);
		ConnectNamedPipe(winIPC->mPipeHandle, &winIPC->overlapped);
		ILibChain_AddWaitHandleEx(duk_ctx_chain(ctx), winIPC->overlapped.hEvent, -1, ILibDuktape_net_server_IPC_ConnectSink, winIPC, (char*)duk_get_string(ctx, -1));
		duk_pop(ctx);

		if (pIPC_SA != NULL) { LocalFree(IPC_ACL); }
		return(1);
#endif
	}
	else
	{
		local.sin6_family = AF_INET;
		local.sin6_port = htons(port);

		server->server = ILibCreateAsyncServerSocketModuleWithMemoryEx(Duktape_GetChain(ctx), maxConnections, initalBufferSize, (struct sockaddr*)&local,
			ILibDuktape_net_server_OnConnect, ILibDuktape_net_server_OnDisconnect, ILibDuktape_net_server_OnReceive,
			ILibDuktape_net_server_OnInterrupt, ILibDuktape_net_server_OnSendOK, sizeof(void*), sizeof(void*));
	}


	if (server->server == NULL)
	{
		return(ILibDuktape_Error(ctx, "server.listen(): Failed to bind"));
	}

	((void**)ILibMemory_GetExtraMemory(server->server, ILibMemory_ASYNCSERVERSOCKET_CONTAINERSIZE))[0] = server;
	ILibAsyncServerSocket_SetTag(server->server, server);
#ifndef MICROSTACK_NOTLS
	{
		if (server->isTLS)
		{
			duk_push_this(ctx);												// [server]
			if (duk_has_prop_string(ctx, -1, "addContext"))
			{
				duk_get_prop_string(ctx, -1, "addContext");					// [server][addContext]
				duk_swap_top(ctx, -2);										// [addContext][this]
				duk_push_string(ctx, "*");									// [addContext][this][*]
				duk_eval_string(ctx, "require('tls');");					// [addContext][this][*][tls]
				duk_get_prop_string(ctx, -1, "createSecureContext");		// [addContext][this][*][tls][createSecureContext]
				duk_swap_top(ctx, -2);										// [addContext][this][*][createSecureContext][this]
				duk_get_prop_string(ctx, -4, ILibDuktape_SERVER2OPTIONS);	// [addContext][this][*][createSecureContext][this][options]
				duk_call_method(ctx, 1);									// [addContext][this][*][secureContext]
				duk_call_method(ctx, 2); duk_pop(ctx);						// ...
			}
			else
			{
				duk_pop(ctx);												// ...
			}
		}
	}
#endif


		duk_push_heapptr(server->ctx, server->self);			// [this]
		duk_get_prop_string(server->ctx, -1, "emit");			// [this][emit]
		duk_swap_top(server->ctx, -2);							// [emit][this]
		duk_push_string(server->ctx, "listening");				// [emit][this][listenting]
		if (duk_pcall_method(server->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(server->ctx, "net.server.listen(): Error "); }
		duk_pop(server->ctx);									// ...
	
#ifndef WIN32
	ignore_result(backlog);
#endif

	duk_push_this(ctx);
	if (server->server != NULL)
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_OBJID);					// [server][str]
		if (duk_has_prop_string(ctx, -2, ILibDuktape_net_server_metadata))
		{
			duk_push_string(ctx, ", ");										// [server][str][newVal]
			duk_string_concat(ctx, -2);	duk_remove(ctx, -2);				// [server][str]
			duk_get_prop_string(ctx, -2, ILibDuktape_net_server_metadata);	// [server][str][metadata]
			duk_string_concat(ctx, -2); duk_remove(ctx, -2);				// [server][metadata]
			duk_dup(ctx, -1);												// [server][metadata][clone]
			duk_put_prop_string(ctx, -3, ILibDuktape_net_server_metadata);	// [server][metadata]
		}
		ILibChain_Link_SetMetadata(server->server, (char*)duk_get_string(ctx, -1));
		duk_pop(ctx);
	}

	return 1;
}
duk_ret_t ILibDuktape_net_server_Finalizer(duk_context *ctx)
{
	duk_push_this(ctx);												// [server]
	duk_eval_string(ctx, "require('fs');");							// [server][fs]
	duk_prepare_method_call(ctx, -1, "unlinkSync");					// [server][fs][unlinkSync][this]
	duk_get_prop_string(ctx, -4, ILibDuktape_net_server_IPCPath);	// [server][fs][unlinkSync][this][path]
	duk_pcall_method(ctx, 1);										// [server][fs][ret]

	void *chain = Duktape_GetChain(ctx);
	ILibDuktape_net_server *server;
	duk_get_prop_string(ctx, 0, ILibDuktape_net_Server_buffer);
	server = (ILibDuktape_net_server*)Duktape_GetBuffer(ctx, -1, NULL);

	if (server != NULL && server->server != NULL && ILibIsChainBeingDestroyed(chain) == 0)
	{
		ILibAsyncServerSocket_RemoveFromChain(server->server);
	}

#ifdef WIN32
	ILibDuktape_net_WindowsIPC *ipc = NULL;
	duk_get_prop_string(ctx, 0, ILibDuktape_net_ConcurrencyArray);			// [array]
	while (duk_get_length(ctx, -1) > 0)
	{
		duk_array_pop(ctx, -1);												// [array][winipc]
		ipc = (ILibDuktape_net_WindowsIPC*)Duktape_GetBuffer(ctx, -1, NULL);
		if (ipc != NULL && ipc->overlapped.hEvent != NULL)
		{
			ILibChain_RemoveWaitHandle(duk_ctx_chain(ctx), ipc->overlapped.hEvent);
			if (ipc->mPipeHandle != NULL) { CloseHandle(ipc->mPipeHandle); ipc->mPipeHandle = NULL; }
			if (ipc->overlapped.hEvent != NULL) { CloseHandle(ipc->overlapped.hEvent); ipc->overlapped.hEvent = NULL; }
		}
		duk_pop(ctx);														// [array]
	}
#endif

	return 0;
}
duk_ret_t ILibDuktape_net_server_address(duk_context *ctx)
{
	duk_push_this(ctx);															// [server]
	duk_get_prop_string(ctx, -1, ILibDuktape_net_Server_buffer);				// [server][buffer]
	ILibDuktape_net_server *server = (ILibDuktape_net_server*)Duktape_GetBuffer(ctx, -1, NULL);
	struct sockaddr_in6 local;
	memset(&local, 0, sizeof(struct sockaddr_in6));

	ILibAsyncServerSocket_GetLocal(server->server, (struct sockaddr*)&local, sizeof(struct sockaddr_in6));
	if (local.sin6_family == AF_UNSPEC) { return(ILibDuktape_Error(ctx, "net.server.address(): call to getsockname() failed")); }

	duk_push_object(ctx);
	duk_push_string(ctx, local.sin6_family == AF_INET6 ? "IPv6" : "IPv4");
	duk_put_prop_string(ctx, -2, "family");

	duk_push_int(ctx, (int)ntohs(local.sin6_port));
	duk_put_prop_string(ctx, -2, "port");

	duk_push_string(ctx, ILibRemoteLogging_ConvertAddress((struct sockaddr*)&local));
	duk_put_prop_string(ctx, -2, "address");

	return(1);
}

duk_ret_t ILibDuktape_net_server_close(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);

	duk_push_this(ctx);
	if (nargs > 0)
	{
		duk_get_prop_string(ctx, -1, "once");	// [server][once]
		duk_dup(ctx, -2);						// [server][once][this]
		duk_push_string(ctx, "close");			// [server][once][this][close]
		duk_dup(ctx, 0);						// [server][once][this][close][callback]
		duk_call_method(ctx, 2); duk_pop(ctx);	// [server]
	}

	ILibDuktape_net_server *server = (ILibDuktape_net_server*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_net_Server_buffer);
	if (server != NULL && server->server != NULL)
	{
		if (!ILibIsChainBeingDestroyed(Duktape_GetChain(ctx)))
		{
			ILibAsyncServerSocket_RemoveFromChain(server->server);
			server->server = NULL;

#ifdef _POSIX
			duk_push_this(ctx);													// [server]
			if(duk_has_prop_string(ctx, -1, ILibDuktape_net_server_IPCPath))
			{
				duk_eval_string(ctx, "require('fs');");							// [server][fs]
				duk_get_prop_string(ctx, -1, "unlinkSync");						// [server][fs][unlinkSync]
				duk_swap_top(ctx, -2);											// [server][unlinkSync][this]
				duk_get_prop_string(ctx, -3, ILibDuktape_net_server_IPCPath);	// [server][unlinkSync][this][path]
				duk_pcall_method(ctx, 1); duk_pop(ctx);							// [server]
			}
			duk_pop(ctx);														// [...]
#endif

			ILibDuktape_EventEmitter_SetupEmit(ctx, server->self, "close");		// [emit][this][close]
			duk_call_method(ctx, 1);
		}
	}
#ifdef WIN32
	else
	{
		duk_push_this(ctx);													// [server]
		duk_get_prop_string(ctx, -1, ILibDuktape_net_ConcurrencyArray);		// [server][array]

		int connections = 0;
		ILibDuktape_net_WindowsIPC *winIPC = NULL;
		duk_uarridx_t i;
		duk_size_t len = duk_get_length(ctx, -1);
		for (i = 0; i < len; ++i)
		{
			duk_get_prop_index(ctx, -1, i);									// [server][array][winipc]
			winIPC = (ILibDuktape_net_WindowsIPC*)Duktape_GetBuffer(ctx, -1, NULL);
			if (winIPC != NULL && winIPC->mPipeHandle != NULL)
			{
				if (winIPC->clientConnected == FALSE)
				{
					// This object is listening for a new connection
					DisconnectNamedPipe(winIPC->mPipeHandle);
					CancelIoEx(winIPC->mPipeHandle, NULL);
					CloseHandle(winIPC->mPipeHandle);
					winIPC->mPipeHandle = NULL;
					ILibChain_RemoveWaitHandle(duk_ctx_chain(ctx), winIPC->overlapped.hEvent);

					if (winIPC->overlapped.hEvent != NULL) { CloseHandle(winIPC->overlapped.hEvent); winIPC->overlapped.hEvent = NULL; }
					if (winIPC->read_overlapped.hEvent != NULL) { CloseHandle(winIPC->read_overlapped.hEvent); winIPC->read_overlapped.hEvent = NULL; }
					if (winIPC->write_overlapped.hEvent != NULL) { CloseHandle(winIPC->write_overlapped.hEvent); winIPC->write_overlapped.hEvent = NULL; }
				}
				else
				{
					++connections;
				}
			}
			duk_pop(ctx);													// [server][array]
		}

		if (connections == 0)
		{
			// No active connections, so we can emit 'close' now
			ILibDuktape_EventEmitter_SetupEmit(ctx, server->self, "close");		// [emit][this][close]
			duk_call_method(ctx, 1);
		}
		else
		{
			// Set a flag, so we emit this when all connections are closed
			duk_push_this(ctx);
			duk_push_true(ctx);
			duk_put_prop_string(ctx, -2, ILibDuktape_net_server_closed_needEmit);
		}
	}
#endif
	duk_push_this(ctx);
	duk_push_true(ctx);
	duk_put_prop_string(ctx, -2, ILibDuktape_net_server_closed);
	return(0);
}

duk_ret_t ILibDuktape_net_server_listening(duk_context *ctx)
{
	duk_push_this(ctx);		// [server]
	ILibDuktape_net_server *server = (ILibDuktape_net_server*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_net_Server_buffer);

	if (server->server != NULL || duk_has_prop_string(ctx, -1, ILibDuktape_net_WindowsIPC_Buffer))
	{
		duk_push_true(ctx);
	}
	else
	{
		duk_push_false(ctx);
	}

	return(1);
}
duk_ret_t ILibDuktape_net_createServer_metadata(duk_context *ctx)
{
	duk_push_this(ctx);			// [serverSocket]
	ILibDuktape_net_server *server = (ILibDuktape_net_server*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_net_Server_buffer);
	if (server->server != NULL)
	{
		// Non-IPC Server
		char *tmp = (char*)duk_push_sprintf(ctx, "%s, %s", ILibChain_Link_GetMetadata(server->server), (char*)duk_require_string(ctx, 0));
		char *tmp2 = (char*)ILibMemory_SmartAllocate(duk_get_length(ctx, -1) + 1);
		memcpy_s(tmp2, ILibMemory_Size(tmp2), tmp, ILibMemory_Size(tmp2) - 1);
		ILibChain_Link_SetMetadata(server->server, tmp2);
	}
	else
	{
		duk_dup(ctx, 0);												// [server][string]
		duk_put_prop_string(ctx, -2, ILibDuktape_net_server_metadata);
	}

	return(0);
}
duk_ret_t ILibDuktape_net_createServer(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int i;
	ILibDuktape_net_server *server;

	duk_push_current_function(ctx);
	int isTLS = Duktape_GetIntPropertyValue(ctx, -1, "tls", 0);
	duk_pop(ctx);

	duk_push_object(ctx);														// [server]
	ILibDuktape_WriteID(ctx, isTLS ? "tls.Server" : "net.Server");
	if (nargs > 0 && duk_is_object(ctx, 0))
	{
		duk_dup(ctx, 0);														// [server][Options]
		duk_put_prop_string(ctx, -2, ILibDuktape_SERVER2OPTIONS);				// [server]
	}
	server = Duktape_PushBuffer(ctx, sizeof(ILibDuktape_net_server));			// [server][fbuffer]
	duk_put_prop_string(ctx, -2, ILibDuktape_net_Server_buffer);				// [server]
	
	server->isTLS = isTLS;
	server->self = duk_get_heapptr(ctx, -1);
	server->ctx = ctx;
	server->emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(server->emitter, "close");
	ILibDuktape_EventEmitter_CreateEventEx(server->emitter, "connection");
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "close", ILibDuktape_net_server_close, DUK_VARARGS);
#ifndef MICROSTACK_NOTLS
	if (isTLS)
	{
		ILibDuktape_EventEmitter_CreateEventEx(server->emitter, "secureConnection");
		ILibDuktape_EventEmitter_CreateEventEx(server->emitter, "tlsClientError");
		ILibDuktape_CreateInstanceMethod(ctx, "addContext", ILibDuktape_tls_server_addContext, 2);
		duk_push_object(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_SERVER2ContextTable);
		if (ILibDuktape_TLS_ctx2server < 0) { ILibDuktape_TLS_ctx2server = SSL_get_ex_new_index(0, "ILibDuktape_TLS_Server index", NULL, NULL, NULL); }
	}
#endif
	ILibDuktape_EventEmitter_CreateEventEx(server->emitter, "error");
	ILibDuktape_EventEmitter_CreateEventEx(server->emitter, "listening");
	ILibDuktape_CreateEventWithGetter(ctx, "listening", ILibDuktape_net_server_listening);
	ILibDuktape_CreateEventWithSetterEx(ctx, "descriptorMetadata", ILibDuktape_net_createServer_metadata);
	ILibDuktape_CreateEventWithGetter(ctx, "connections", ILibDuktape_net_server_connections);

	ILibDuktape_CreateInstanceMethod(ctx, "listen", ILibDuktape_net_server_listen, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "address", ILibDuktape_net_server_address, 0);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_net_server_Finalizer);

	for (i = 0; i < 2 && i < nargs; ++i)
	{
		if (duk_is_function(ctx, i))
		{
			// Callback
			ILibDuktape_EventEmitter_AddOn(server->emitter, isTLS ? "secureConnection" : "connection", duk_require_heapptr(ctx, i));
		}
		if (duk_is_object(ctx, i))
		{
			// Options
			if (isTLS && !duk_has_prop_string(ctx, i, "secureProtocol"))
			{
				duk_dup(ctx, i);									// [options]
				duk_push_string(ctx, "SSLv23_server_method");		// [options][secureProtocol]
				duk_put_prop_string(ctx, -2, "secureProtocol");		// [options]
				duk_pop(ctx);										// ...
			}
		}
	}

	return 1;
}
duk_ret_t ILibDuktape_net_addr2int(duk_context *ctx)
{
	struct sockaddr_in6 addr6;
	ILibResolveEx((char*)duk_require_string(ctx, 0), 0, &addr6);
	if (addr6.sin6_family == AF_INET)
	{
		duk_push_int(ctx, ((struct sockaddr_in*)&addr6)->sin_addr.s_addr);
		return(1);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Error converting address"));
	}
}
void ILibDuktape_net_PUSH_net(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);														// [net]
	ILibDuktape_WriteID(ctx, "net");
	duk_push_pointer(ctx, chain);												// [net][chain]
	duk_put_prop_string(ctx, -2, "chain");										// [net]
	duk_push_c_function(ctx, ILibDuktape_net_socket_constructor, DUK_VARARGS);	// [net][constructor]
	duk_push_pointer(ctx, chain);												// [net][constructor][chain]
	duk_put_prop_string(ctx, -2, "chain");										// [net][constructor]
	duk_dup(ctx, -2);															// [net][constructor][net]
	duk_put_prop_string(ctx, -2, "net");										// [net][constructor]
	duk_put_prop_string(ctx, -2, "socket");										// [net]
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "tls", 0, "createServer", ILibDuktape_net_createServer, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "createConnection", ILibDuktape_net_createConnection, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "connect", ILibDuktape_net_createConnection, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "addr2int", ILibDuktape_net_addr2int, 1);
}
duk_ret_t ILibDuktape_globalTunnel_end(duk_context *ctx)
{
	ILibDuktape_globalTunnel_data *data;
	ILibHashtable tmp;
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_GlobalTunnel_DataPtr);
	data = (ILibDuktape_globalTunnel_data*)Duktape_GetBuffer(ctx, -1, NULL);
	tmp = data->exceptionsTable;
	ILibHashtable_Clear(tmp);

	memset(data, 0, sizeof(ILibDuktape_globalTunnel_data));
	data->exceptionsTable = tmp;
	return 0;
}
duk_ret_t ILibDuktape_globalTunnel_initialize(duk_context *ctx)
{
	ILibDuktape_globalTunnel_data *data;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_GlobalTunnel_DataPtr);
	data = (ILibDuktape_globalTunnel_data*)Duktape_GetBuffer(ctx, -1, NULL);

	if (duk_has_prop_string(ctx, 0, "host") && duk_has_prop_string(ctx, 0, "port"))
	{
		char *host = Duktape_GetStringPropertyValue(ctx, 0, "host", "127.0.0.1");
		int port = Duktape_GetIntPropertyValue(ctx, 0, "port", 0);
		ILibResolveEx(host, (unsigned short)port, &(data->proxyServer));
		if (data->proxyServer.sin6_family == AF_UNSPEC)
		{
			return(ILibDuktape_Error(ctx, "globalTunnel.initialize(): Error, could not resolve: %s", host));
		}
	}
	else
	{
		return(ILibDuktape_Error(ctx, "globalTunnel.initialize(): Error, invalid parameter"));
	}

	return 0;
}
duk_ret_t ILibDuktape_globalTunnel_finalizer(duk_context *ctx)
{
	ILibDuktape_globalTunnel_data *data;
	duk_get_prop_string(ctx, 0, ILibDuktape_GlobalTunnel_DataPtr);
	data = (ILibDuktape_globalTunnel_data*)Duktape_GetBuffer(ctx, -1, NULL);
	ILibHashtable_Destroy(data->exceptionsTable);
	return 0;
}
duk_ret_t ILibDuktape_globalTunnel_isProxying(duk_context *ctx)
{
	ILibDuktape_globalTunnel_data *data;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_GlobalTunnel_DataPtr);
	data = (ILibDuktape_globalTunnel_data*)Duktape_GetBuffer(ctx, -1, NULL);
	if (data->proxyServer.sin6_family == AF_UNSPEC)
	{
		duk_push_false(ctx);
	}
	else
	{
		duk_push_true(ctx);
	}
	return(1);
}
duk_ret_t ILibDuktape_globalTunnel_proxyConfig(duk_context *ctx)
{
	ILibDuktape_globalTunnel_data *data;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_GlobalTunnel_DataPtr);
	data = (ILibDuktape_globalTunnel_data*)Duktape_GetBuffer(ctx, -1, NULL);
	if (data->proxyServer.sin6_family == AF_UNSPEC)
	{
		duk_push_null(ctx);
	}
	else
	{
		duk_push_object(ctx);
		duk_push_string(ctx, ILibRemoteLogging_ConvertAddress((struct sockaddr*)&(data->proxyServer)));
		duk_put_prop_string(ctx, -2, "host");
		duk_push_int(ctx, (int)ntohs(data->proxyServer.sin6_port));
		duk_put_prop_string(ctx, -2, "port");																		
	}
	return(1);
}
ILibDuktape_globalTunnel_data* ILibDuktape_GetNewGlobalTunnelEx(duk_context *ctx, int native)
{
	ILibDuktape_globalTunnel_data *retVal;

	if (native != 0)
	{
		//
		// If native is calling us, we will use JavaScript to return the pointer value, becuase
		// JS module loader caches entries, so we need to make sure we don't instantiate a new structure,
		// but instead re-use the existing one.
		//
		duk_eval_string(ctx, "require('global-tunnel')");				// [global-tunnel]
		retVal = (ILibDuktape_globalTunnel_data*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_GlobalTunnel_DataPtr);
		duk_pop(ctx);													// ...
		return(retVal);
	}

	duk_push_object(ctx);												// [stash][tunnel]
	duk_dup(ctx, -1);													// [stash][tunnel][dup]
	duk_put_prop_string(ctx, -3, ILibDuktape_GlobalTunnel_Stash);		// [stash][tunnel]
	duk_swap_top(ctx, -2);												// [tunnel][stash]
	duk_pop(ctx);														// [tunnel]

	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_globalTunnel_data));	// [tunnel][buffer]
	retVal = (ILibDuktape_globalTunnel_data*)Duktape_GetBuffer(ctx, -1, NULL);
	memset(retVal, 0, sizeof(ILibDuktape_globalTunnel_data));
	duk_put_prop_string(ctx, -2, ILibDuktape_GlobalTunnel_DataPtr);		// [tunnel]

	retVal->exceptionsTable = ILibHashtable_Create();
	ILibDuktape_CreateInstanceMethod(ctx, "initialize", ILibDuktape_globalTunnel_initialize, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "end", ILibDuktape_globalTunnel_end, 0);
	ILibDuktape_CreateEventWithGetter_SetEnumerable(ctx, "proxyConfig", ILibDuktape_globalTunnel_proxyConfig, 1);
	ILibDuktape_CreateEventWithGetter_SetEnumerable(ctx, "isProxying", ILibDuktape_globalTunnel_isProxying, 1);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_globalTunnel_finalizer);

	return retVal;
}

void ILibDuktape_globalTunnel_PUSH(duk_context *ctx, void *chain)
{
	duk_push_heap_stash(ctx);											// [stash]

	if (duk_has_prop_string(ctx, -1, ILibDuktape_GlobalTunnel_Stash))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_GlobalTunnel_Stash);	// [stash][tunnel]
		duk_swap_top(ctx, -2);											// [tunnel][stash]
		duk_pop(ctx);													// [tunnel]
	}
	else
	{
		ILibDuktape_GetNewGlobalTunnelEx(ctx, 0);						// [tunnel]
	}	
	return;
}
ILibDuktape_globalTunnel_data* ILibDuktape_GetGlobalTunnel(duk_context *ctx)
{
	ILibDuktape_globalTunnel_data *retVal = NULL;

	duk_push_heap_stash(ctx);											// [stash]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_GlobalTunnel_Stash))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_GlobalTunnel_Stash);	// [stash][tunnel]
		duk_get_prop_string(ctx, -1, ILibDuktape_GlobalTunnel_DataPtr);	// [stash][tunnel][buffer]
		retVal = (ILibDuktape_globalTunnel_data*)Duktape_GetBuffer(ctx, -1, NULL);
		if (retVal->proxyServer.sin6_family == AF_UNSPEC) { retVal = NULL; }
		duk_pop_2(ctx);													// [stash]
	}
	duk_pop(ctx);														// ...
	return retVal;
}


#ifndef MICROSTACK_NOTLS
SSL_CTX* ILibDuktape_TLS_SecureContext_GetCTX(duk_context *ctx, void *secureContext)
{
	SSL_CTX *retVal = NULL;

	duk_push_heapptr(ctx, secureContext);																// [context]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_SecureContext2SSLCTXPTR))
	{
		retVal = (SSL_CTX*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_SecureContext2SSLCTXPTR);
	}
	duk_pop(ctx);																						// ...
	return(retVal);
}
void ILibDuktape_TLS_X509_PUSH(duk_context *ctx, X509* cert)
{
	char hash[UTIL_SHA384_HASHSIZE];
	char fingerprint[150];

	util_keyhash2(cert, hash);
	util_tohex2(hash, UTIL_SHA384_HASHSIZE, fingerprint);

	duk_push_object(ctx);							// [cert]
	duk_push_string(ctx, fingerprint);				// [cert][fingerprint]
	duk_put_prop_string(ctx, -2, "fingerprint");	// [cert]

	util_certhash2(cert, hash);
	util_tohex2(hash, UTIL_SHA384_HASHSIZE, fingerprint);
	duk_push_string(ctx, fingerprint);				// [cert][digest]
	duk_put_prop_string(ctx, -2, "digest");			// [cert]
}
int ILibDuktape_TLS_verify(int preverify_ok, X509_STORE_CTX *storectx)
{
	STACK_OF(X509) *certChain = X509_STORE_CTX_get_chain(storectx);
	SSL *ssl = (SSL*)X509_STORE_CTX_get_ex_data(storectx, SSL_get_ex_data_X509_STORE_CTX_idx());
	ILibDuktape_net_socket *data = (ILibDuktape_net_socket*)SSL_get_ex_data(ssl, ILibDuktape_TLS_ctx2socket);

	int i;
	int retVal = 0;

	duk_push_heapptr(data->ctx, data->object);												// [Socket]
	duk_get_prop_string(data->ctx, -1, ILibDuktape_SOCKET2OPTIONS);							// [Socket][Options]
	if (Duktape_GetBooleanProperty(data->ctx, -1, "rejectUnauthorized", 1) && preverify_ok != 1) { duk_pop_2(data->ctx); return(preverify_ok); }
	void *OnVerify = Duktape_GetHeapptrProperty(data->ctx, -1, "checkServerIdentity");
	if (OnVerify == NULL) { duk_pop_2(data->ctx); return(1); }

	duk_push_heapptr(data->ctx, OnVerify);													// [Socket][Options][func]
	duk_push_heapptr(data->ctx, data->object);												// [Socket][Options][func][this]
	duk_push_array(data->ctx);																// [Socket][Options][func][this][certs]
	for (i = 0; i < sk_X509_num(certChain); ++i)
	{
		ILibDuktape_TLS_X509_PUSH(data->ctx, sk_X509_value(certChain, i));					// [Socket][Options][func][this][certs][cert]
		duk_put_prop_index(data->ctx, -2, i);												// [Socket][Options][func][this][certs]
	}
	retVal = duk_pcall_method(data->ctx, 1) == 0 ? 1 : 0;									// [Socket][Options][undefined]
	duk_pop_3(data->ctx);																	// ...

	return retVal;
}
int ILibDuktape_TLS_server_verify(int preverify_ok, X509_STORE_CTX *storectx)
{
	STACK_OF(X509) *certChain = X509_STORE_CTX_get_chain(storectx);
	SSL *ssl = (SSL*)X509_STORE_CTX_get_ex_data(storectx, SSL_get_ex_data_X509_STORE_CTX_idx());
	ILibDuktape_net_server *data = (ILibDuktape_net_server*)SSL_get_ex_data(ssl, ILibDuktape_TLS_ctx2server);

	int i;
	int retVal = 0;
	if (!ILibMemory_CanaryOK(data)) { return(0); }


	duk_push_heapptr(data->ctx, data->self);													// [Server]
	duk_get_prop_string(data->ctx, -1, ILibDuktape_SERVER2OPTIONS);								// [Server][Options]
	if (Duktape_GetBooleanProperty(data->ctx, -1, "rejectUnauthorized", 1) && preverify_ok != 1) { duk_pop_2(data->ctx); return(preverify_ok); }
	void *OnVerify = Duktape_GetHeapptrProperty(data->ctx, -1, "checkClientIdentity");

	if (OnVerify == NULL) { return(1); }

	duk_push_heapptr(data->ctx, OnVerify);													// [func]
	duk_push_heapptr(data->ctx, data->self);												// [func][this]
	duk_push_array(data->ctx);																// [func][this][certs]
	for (i = 0; i < sk_X509_num(certChain); ++i)
	{
		ILibDuktape_TLS_X509_PUSH(data->ctx, sk_X509_value(certChain, i));					// [func][this][certs][cert]
		duk_put_prop_index(data->ctx, -2, i);												// [func][this][certs]
	}
	retVal = duk_pcall_method(data->ctx, 1) == 0 ? 1 : 0;									// [undefined]
	duk_pop(data->ctx);																		// ...
	return retVal;
}
void ILibDuktape_tls_server_OnSSL(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, void *ConnectionToken, SSL* ctx, void **user)
{
	ILibDuktape_net_server *server = (ILibDuktape_net_server*)ILibAsyncServerSocket_GetTag(AsyncServerSocketModule);
	if (!ILibMemory_CanaryOK(server)) { return; }

	if (ctx != NULL && ILibDuktape_TLS_ctx2server)
	{
		SSL_set_ex_data(ctx, ILibDuktape_TLS_ctx2server, server);
	}
}
static int ILibDuktape_tls_server_sniCallback(SSL *s, int *ad, void *arg)
{
	const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
	ILibDuktape_net_server *data = (ILibDuktape_net_server*)SSL_get_ex_data(s, ILibDuktape_TLS_ctx2server);
	if (!ILibMemory_CanaryOK(data)) { return(SSL_TLSEXT_ERR_OK); }

	duk_push_heapptr(data->ctx, data->self);								// [server]
	duk_get_prop_string(data->ctx, -1, ILibDuktape_SERVER2ContextTable);	// [server][table]
	if (duk_has_prop_string(data->ctx, -1, servername))
	{
		duk_get_prop_string(data->ctx, -1, servername);						// [server][table][secureContext]
		SSL_CTX *newCTX = ILibDuktape_TLS_SecureContext_GetCTX(data->ctx, duk_get_heapptr(data->ctx, -1));
		if (newCTX != NULL)
		{
			SSL_set_SSL_CTX(s, newCTX);
		}
		duk_pop(data->ctx);													// [server][table]
	}
	duk_pop_2(data->ctx);													// ...
	return(SSL_TLSEXT_ERR_OK);
}
int ILibDuktape_tls_server_alpnSink(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
	int ix = 0;
	int ret = SSL_TLSEXT_ERR_ALERT_FATAL;
	unsigned char **ptr = NULL;
	if (inlen > 255) { return(ret); }

	const unsigned char *in2 = in;
	unsigned int inlen2 = inlen;
	while (inlen2 > 0)
	{
		ix++;
		inlen2 -= (1 + in2[0]);
		in2 += (1 + in2[0]);
	}
	ptr = (unsigned char**)ILibMemory_AllocateA(ix * sizeof(unsigned char*));
	ix = 0;

	ILibDuktape_net_server *server = (ILibDuktape_net_server*)arg;
	duk_push_heapptr(server->ctx, server->self);								// [server]
	duk_push_array(server->ctx);												// [server][array]
	while (inlen > 0)
	{
		ptr[ix++] = (unsigned char*)in;
		duk_push_lstring(server->ctx, (const char*)in + 1, (duk_size_t)in[0]);	// [server][array][string]
		duk_array_push(server->ctx, -2);										// [server][array]
		inlen -= (1 + in[0]);
		in += (1 + in[0]);	
	}
	duk_get_prop_string(server->ctx, -2, ILibDuktape_SERVER2OPTIONS);			// [server][array][options]
	duk_get_prop_string(server->ctx, -1, "alpnCallback");						// [server][array][options][callback]
	if (!duk_is_null_or_undefined(server->ctx, -1))
	{
		duk_dup(server->ctx, -4);												// [server][array][options][callback][this]
		duk_dup(server->ctx, -4);												// [server][array][options][callback][this][array]
		if (duk_pcall_method(server->ctx, 1) == 0)								// [server][array][options][ret]
		{
			if (!duk_is_null_or_undefined(server->ctx, -1))
			{
				ix = -1;
				while (duk_get_length(server->ctx, -3) > 0)
				{
					++ix;
					duk_array_shift(server->ctx, -3);							// [server][array][options][ret][string]
					const char *str1 = duk_get_string(server->ctx, -2);
					const char *str2 = duk_get_string(server->ctx, -1);
					if (strcmp(str1, str2) == 0)
					{
						*out = ptr[ix] + 1;
						*outlen = ptr[ix][0];
						ret = SSL_TLSEXT_ERR_OK;
						duk_pop(server->ctx);											// [server][array][options][ret]
						break;
					}
					duk_pop(server->ctx);										// [server][array][options][ret]
				}
			}
		}
		duk_pop(server->ctx);													// [server][array][options]
	}
	else
	{
		duk_pop(server->ctx);													// [server][array][options]
		duk_get_prop_string(server->ctx, -1, "ALPNProtocols");					// [server][array][options][array]
		char *a, *b;
		int i, si;
		int clientcount = (int)duk_get_length(server->ctx, -3);
		int servercount = (int)duk_get_length(server->ctx, -1);
		for (i = 0; i < clientcount; ++i)
		{
			a = Duktape_GetStringPropertyIndexValue(server->ctx, -3, i, "");
			for (si = 0; si < servercount; ++si)
			{
				b = Duktape_GetStringPropertyIndexValue(server->ctx, -1, si, "");
				if (strcmp(a, b) == 0)
				{
					*out = ptr[i] + 1;
					*outlen = ptr[i][0];
					ret = SSL_TLSEXT_ERR_OK;
					break;
				}
			}
			if (ret == SSL_TLSEXT_ERR_OK) { break; }
		}
		duk_pop(server->ctx);													// [server][array][options]						
	}
	duk_pop_3(server->ctx);														// ...
	return(ret);
}
duk_ret_t ILibDuktape_tls_server_addContext(duk_context *ctx)
{
	duk_size_t hostLen;
	char *host = (char*)duk_get_lstring(ctx, 0, &hostLen);
	void *context = duk_require_heapptr(ctx, 1);

	duk_push_this(ctx);												// [server]
	duk_get_prop_string(ctx, -1, ILibDuktape_SERVER2ContextTable);	// [server][table]
	duk_dup(ctx, 0);												// [server][table][host]
	duk_dup(ctx, 1);												// [server][table][host][context]
	duk_put_prop(ctx, -3);											// [server][table]

	if (hostLen == 1 && strncasecmp(host, "*", 1) == 0)
	{
		// Default CTX
		SSL_CTX *ssl_ctx = ILibDuktape_TLS_SecureContext_GetCTX(ctx, context);
		duk_get_prop_string(ctx, -2, ILibDuktape_SERVER2OPTIONS);	// [server][table][options]
		if (Duktape_GetBooleanProperty(ctx, -1, "requestCert", 0) || Duktape_GetHeapptrProperty(ctx, -1, "checkClientIdentity")!=NULL)
		{
			SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, ILibDuktape_TLS_server_verify);
		}

		if (duk_has_prop_string(ctx, -1, "ALPNProtocols"))
		{
			duk_uarridx_t i;
			duk_size_t protoLen = 0;
			unsigned char *alpn = NULL;
			duk_get_prop_string(ctx, -1, "ALPNProtocols");								// [server][table][options][Array]
			duk_uarridx_t len = (duk_uarridx_t)duk_get_length(ctx, -1);
			for (i = 0; i < len; ++i)
			{
				duk_get_prop_index(ctx, -1, i);											// [server][table][options][Array][string]
				protoLen += (1 + (unsigned int)duk_get_length(ctx, -1));
				duk_pop(ctx);															// [server][table][options][Array]
			}
			if (protoLen > 0)
			{
				char *buf; duk_size_t bufLen;
				alpn = (unsigned char*)Duktape_PushBuffer(ctx, protoLen);				// [server][table][options][buffer]
				duk_put_prop_string(ctx, -4, "_ALPN");									// [server][table][options][Array]
				protoLen = 0;
				for (i = 0; i < len; ++i)
				{
					duk_get_prop_index(ctx, -1, i);										// [server][table][options][Array][buffer]
					buf = (char*)duk_get_lstring(ctx, -1, &bufLen);
					alpn[protoLen] = (unsigned char)bufLen; ++protoLen;
					memcpy_s(alpn + protoLen, ILibMemory_Size(alpn) - protoLen, buf, bufLen);
					protoLen += (unsigned int)bufLen;
					duk_pop(ctx);														// [server][table][options][Array]
				}
				SSL_CTX_set_alpn_protos(ssl_ctx, alpn, (unsigned int)protoLen);
				SSL_CTX_set_alpn_select_cb(ssl_ctx, ILibDuktape_tls_server_alpnSink, Duktape_GetBufferProperty(ctx, -4, ILibDuktape_net_Server_buffer));
			}
			duk_pop(ctx);																// [server][table][options]
		}

		duk_get_prop_string(ctx, -3, ILibDuktape_net_Server_buffer);// [server][table][options][buffer]
		ILibDuktape_net_server *server = (ILibDuktape_net_server*)Duktape_GetBuffer(ctx, -1, NULL);
		if (server->server != NULL)
		{
#ifdef MICROSTACK_TLS_DETECT
			ILibAsyncServerSocket_SetSSL_CTX(server->server, ssl_ctx, 1);
#else
			ILibAsyncServerSocket_SetSSL_CTX(server->server, ssl_ctx);
#endif
			ILibAsyncServerSocket_SSL_SetSink(server->server, ILibDuktape_tls_server_OnSSL);
		}
		SSL_CTX_set_tlsext_servername_callback(ssl_ctx, ILibDuktape_tls_server_sniCallback);
	}

	return(0);
}
void ILibDuktape_TLS_connect_resolveError(duk_context *ctx, void ** args, int argsLen)
{
	ILibDuktape_net_socket *data = (ILibDuktape_net_socket*)args[0];

	ILibDuktape_EventEmitter_SetupEmit(ctx, data->emitter->object, "error");	// [emit][this][error]
	duk_push_heapptr(ctx, args[1]);												// [emit][this][error][err]
	if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "tls.socket.OnError(): "); }
	duk_pop(ctx);
}
#ifdef _SSL_KEYS_EXPORTABLE
duk_ret_t ILibDuktape_TLS_exportKeys(duk_context *ctx)
{
	char buffer[2000];
	int bufferLen;

	ILibDuktape_net_socket *data;
	duk_push_this(ctx);			// [socket]

	data = (ILibDuktape_net_socket*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_net_socket_ptr);
	if (data != NULL)
	{
		bufferLen = util_exportkeys(data->ssl, buffer, sizeof(buffer));
		duk_push_lstring(ctx, buffer, bufferLen);
		return(1);
	}
	return(ILibDuktape_Error(ctx, "Error exporting OpenSSL Keys"));
}
#endif
duk_ret_t ILibDuktape_TLS_connect(duk_context *ctx)
{
	unsigned char* alpn = NULL;
	unsigned int protoLen = 0;
	int nargs = duk_get_top(ctx), i;
	if (nargs > 0 && duk_is_number(ctx, 0))
	{
		// tls.connect(port[, host][, options][, callback])
		// let's convert to the other overload
		duk_push_this(ctx);							// [TLS]
		duk_get_prop_string(ctx, -1, "connect");	// [TLS][connect]
		duk_swap_top(ctx, -2);						// [connect][this]
		for (i = 1; i < nargs; ++i)
		{
			if (duk_is_object(ctx, i))
			{
				duk_dup(ctx, i);					// [connect][this][Options]
				break;
			}
		}
		if (i == nargs) { duk_push_object(ctx); }	// [connect][this][Options]
		duk_dup(ctx, 0);							// [connect][this][Options][port]
		duk_put_prop_string(ctx, -2, "port");
		if (nargs > 1 && duk_is_string(ctx, 1))
		{
			duk_dup(ctx, 1);						// [connect][this][Options][host]
		}
		else
		{
			duk_push_string(ctx, "127.0.0.1");		// [connect][this][Options][host]
		}
		duk_put_prop_string(ctx, -2, "host");		// [connect][this][Options]
		for (i = 1; i < nargs; ++i)
		{
			if (duk_is_function(ctx, i))
			{
				duk_dup(ctx, i);					// [connect][this][Options][callback]
				break;
			}
		}
		duk_call_method(ctx, i == nargs ? 1 : 2);	// [socket]
		return(1);
	}

	// tls.connect(options[, callback])
	ILibAsyncSocket_SocketModule module = ILibCreateAsyncSocketModuleWithMemory(Duktape_GetChain(ctx), 4096, ILibDuktape_net_socket_OnData, ILibDuktape_net_socket_OnConnect, ILibDuktape_net_socket_OnDisconnect, ILibDuktape_net_socket_OnSendOK, sizeof(ILibDuktape_net_socket));
	ILibDuktape_net_socket *data = (ILibDuktape_net_socket*)((ILibChain_Link*)module)->ExtraMemoryPtr;

	if (ILibDuktape_TLS_ctx2socket < 0)
	{
		ILibDuktape_TLS_ctx2socket = SSL_get_ex_new_index(0, "ILibDuktape_TLS index", NULL, NULL, NULL);
	}

	ILibDuktape_net_socket_PUSH(ctx, module);													// [socket]
	ILibDuktape_WriteID(ctx, "tls.socket");
	ILibChain_Link_SetMetadata(module, "tls.socket")
#ifdef _SSL_KEYS_EXPORTABLE
	ILibDuktape_CreateInstanceMethod(ctx, "_exportKeys", ILibDuktape_TLS_exportKeys, 0);
#endif

	duk_dup(ctx, 0);																			// [socket][options]
	if (duk_has_prop_string(ctx, -1, "secureContext"))
	{
		duk_get_prop_string(ctx, -1, "secureContext");											// [socket][options][secureContext]
	}
	else
	{
		duk_push_this(ctx);																		// [socket][options][tls]
		duk_get_prop_string(ctx, -1, "createSecureContext");									// [socket][options][tls][createSecureContext]
		duk_swap_top(ctx, -2);																	// [socket][options][createSecureContext][this]
		duk_dup(ctx, -3);																		// [socket][options][createSecureContext][this][options]
		duk_call_method(ctx, 1);																// [socket][options][secureContext]
	}
	if ((data->ssl_ctx = (SSL_CTX*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_SecureContext2SSLCTXPTR)) == NULL)
	{
		return(ILibDuktape_Error(ctx, "Invalid SecureContext Object"));
	}
	SSL_CTX_set_verify(data->ssl_ctx, SSL_VERIFY_PEER, ILibDuktape_TLS_verify); /* Ask for authentication */																					
	if (duk_has_prop_string(ctx, 0, "ALPNProtocols"))
	{
		duk_uarridx_t i;
		duk_get_prop_string(ctx, 0, "ALPNProtocols");								// [Array]
		duk_uarridx_t len = (duk_uarridx_t)duk_get_length(ctx, -1);
		for (i = 0; i < len; ++i)
		{
			duk_get_prop_index(ctx, -1, i);											// [socket][options][secureContext][Array][string]
			protoLen += (1 + (unsigned int)duk_get_length(ctx, -1));
			duk_pop(ctx);															// [socket][options][secureContext][Array]
		}
		if (protoLen > 0)
		{
			char *buf; duk_size_t bufLen;
			alpn = (unsigned char*)Duktape_PushBuffer(ctx, protoLen);// [socket][options][secureContext][Array][buffer]
			duk_put_prop_string(ctx, -5, "_ALPN");									// [socket][options][secureContext][Array]
			protoLen = 0;
			for (i = 0; i < len; ++i)
			{
				duk_get_prop_index(ctx, -1, i);										// [socket][options][secureContext][Array][buffer]
				buf = (char*)duk_get_lstring(ctx, -1, &bufLen);
				alpn[protoLen] = (unsigned char)bufLen; ++protoLen;
				memcpy_s(alpn + protoLen, ILibMemory_Size(alpn) - protoLen, buf, bufLen);
				protoLen += (unsigned int)bufLen;
				duk_pop(ctx);														// [socket][options][secureContext][Array]
			}
			SSL_CTX_set_alpn_protos(data->ssl_ctx, alpn, protoLen);
		}
		duk_pop(ctx);																// [socket][options][secureContext]
	}

	duk_remove(ctx, -2);																		// [socket][secureContext]
	duk_put_prop_string(ctx, -2, ILibDuktape_TLSSocket2SecureContext);

	duk_dup(ctx, 0);																			// [socket][options]
	duk_put_prop_string(ctx, -2, ILibDuktape_SOCKET2OPTIONS);									// [socket]
	ILibDuktape_EventEmitter_CreateEventEx(data->emitter, "secureConnect");
	if (nargs > 0 && duk_is_function(ctx, 1))
	{
		ILibDuktape_EventEmitter_AddOnce(data->emitter, "secureConnect", duk_require_heapptr(ctx, 1));
	}

	duk_size_t hostLen;
	char *host = Duktape_GetStringPropertyValueEx(ctx, 0, "host", "127.0.0.1", &hostLen);
	char *sniname = Duktape_GetStringPropertyValue(ctx, 0, "servername", host);
	int port = Duktape_GetIntPropertyValue(ctx, 0, "port", 0);
	struct sockaddr_in6 dest;
	struct sockaddr_in6 proxy;
	memset(&dest, 0, sizeof(struct sockaddr_in6));
	memset(&proxy, 0, sizeof(struct sockaddr_in6));

	if (duk_has_prop_string(ctx, 0, "proxy"))
	{
		duk_get_prop_string(ctx, 0, "proxy");
		ILibResolveEx(Duktape_GetStringPropertyValue(ctx, -1, "host", NULL), (unsigned short)Duktape_GetIntPropertyValue(ctx, -1, "port", 0), &proxy);
		duk_pop(ctx);

		// If we are going to use a proxy, we need to have the proxy resolve the remote host
		duk_push_sprintf(ctx, "%s:%d", host, port);			// [socket][string]
		duk_swap_top(ctx, -2);								// [string][socket]
		ILibAsyncSocket_ConnectToProxyEx(data->socketModule, NULL, (char*)duk_get_string(ctx, -2), (struct sockaddr*)&proxy, Duktape_GetStringPropertyValue(ctx, -1, "username", NULL), Duktape_GetStringPropertyValue(ctx, -1, "password", NULL), NULL, data);
	
		data->ssl = ILibAsyncSocket_SetSSLContextEx(data->socketModule, data->ssl_ctx, ILibAsyncSocket_TLS_Mode_Client, sniname);
		SSL_set_ex_data(data->ssl, ILibDuktape_TLS_ctx2socket, data);
		return(1);
	}

	if (hostLen > 0 && hostLen < 1024 && host[0] == '[')
	{
		char hostCopy[1024];
		int pct = ILibString_LastIndexOf(host, (int)hostLen, "%", 1);

		memcpy_s(hostCopy, sizeof(hostCopy), host, hostLen);

		hostCopy[(int)hostLen - 1] = 0;
		if (pct > 0)
		{
			hostCopy[pct] = 0;
			pct = ILib_atoi2_int32(hostCopy + pct + 1, sizeof(hostCopy));
		}
		else
		{
			pct = -1;
		}

		memset(&dest, 0, sizeof(struct sockaddr_in6));
		dest.sin6_family = AF_INET6;
		ILibInet_pton(AF_INET6, hostCopy + 1, &(dest.sin6_addr));
		if (pct >= 0)
		{
			dest.sin6_scope_id = pct;
		}
		dest.sin6_port = (unsigned short)htons(port);
	}
	else
	{
		ILibResolveEx(host, (unsigned short)port, &dest);
	}
	if (dest.sin6_family == AF_UNSPEC || (duk_has_prop_string(ctx, 0, "proxy") && proxy.sin6_family == AF_UNSPEC))
	{
		// Can't resolve, check to see if it's cached
		duk_push_heap_stash(ctx);																				// [stash]
		if (duk_has_prop_string(ctx, -1, "_sharedDB"))
		{
			ILibSimpleDataStore db = (ILibSimpleDataStore)Duktape_GetPointerProperty(ctx, -1, "_sharedDB");
			char *dnsCache = (char*)duk_push_sprintf(ctx, "DNS[%s]", host);										// [stash][dnsCache]
			char dnsCacheBuffer[255];
			if (ILibSimpleDataStore_Get(db, dnsCache, dnsCacheBuffer, sizeof(dnsCacheBuffer)) > 0)
			{
				ILibResolveEx(dnsCacheBuffer, (unsigned short)port, &dest);
			}
			duk_pop(ctx);																						// [stash]
		}
		duk_pop(ctx);																							// ...
	}
	if (dest.sin6_family == AF_UNSPEC || (duk_has_prop_string(ctx, 0, "proxy") && proxy.sin6_family == AF_UNSPEC))
	{
		// Can't resolve... Delay event emit, until next event loop, because if app called net.createConnection(), they don't have the socket yet
		duk_push_error_object(ctx, DUK_ERR_ERROR, "tls.socket.connect(): Cannot resolve host '%s'", host);
		void *imm = ILibDuktape_Immediate(ctx, (void*[]) { data, duk_get_heapptr(ctx, -1) }, 2, ILibDuktape_TLS_connect_resolveError);
		duk_push_heapptr(ctx, imm);					// [socket][err][imm]
		duk_swap_top(ctx, -2);						// [socket][imm][err]
		duk_put_prop_string(ctx, -2, "\xFF_tmp");	// [socket][imm]
		duk_pop(ctx);								// [socket]
	}
	else
	{
		if (duk_has_prop_string(ctx, 0, "proxy"))
		{
			duk_get_prop_string(ctx, 0, "proxy");
			ILibAsyncSocket_ConnectToProxy(data->socketModule, NULL, (struct sockaddr*)&dest, (struct sockaddr*)&proxy, Duktape_GetStringPropertyValue(ctx, -1, "username", NULL), Duktape_GetStringPropertyValue(ctx, -1, "password", NULL), NULL, data);
			duk_pop(ctx);
		}
		else
		{
			ILibAsyncSocket_ConnectTo(data->socketModule, NULL, (struct sockaddr*)&dest, NULL, data);
		}
		data->ssl = ILibAsyncSocket_SetSSLContextEx(data->socketModule, data->ssl_ctx, ILibAsyncSocket_TLS_Mode_Client, sniname);
		SSL_set_ex_data(data->ssl, ILibDuktape_TLS_ctx2socket, data);
	}

	return(1);
}
duk_ret_t ILibDuktape_TLS_secureContext_Finalizer(duk_context *ctx)
{
	SSL_CTX_free(ILibDuktape_TLS_SecureContext_GetCTX(ctx, duk_require_heapptr(ctx, 0)));

	duk_get_prop_string(ctx, 0, ILibDuktape_SecureContext2CertBuffer);
	struct util_cert *cert = (struct util_cert*)Duktape_GetBuffer(ctx, -1, NULL);
	util_freecert(cert);
	return(0);
}
duk_ret_t ILibDuktape_TLS_createSecureContext(duk_context *ctx)
{
	duk_push_object(ctx);																				// [secureContext]
	ILibDuktape_WriteID(ctx, "tls.secureContext");	
	struct util_cert *cert = (struct util_cert*)duk_push_fixed_buffer(ctx, sizeof(struct util_cert));	// [secureContext][cert]			
	duk_put_prop_string(ctx, -2, ILibDuktape_SecureContext2CertBuffer);									// [secureContext]
	memset(cert, 0, sizeof(struct util_cert));
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_TLS_secureContext_Finalizer);

	duk_size_t secureProtocolLen;
	char *secureProtocol = (char*)Duktape_GetStringPropertyValueEx(ctx, 0, "secureProtocol", "SSLv23_method", &secureProtocolLen);
	SSL_CTX *ssl_ctx = NULL;

	if (secureProtocolLen == 13 && strncmp(secureProtocol, "SSLv23_method", 13) == 0)
	{
		ssl_ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_options(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
	}
	else if (secureProtocolLen == 20 && strncmp(secureProtocol, "SSLv23_client_method", 20) == 0)
	{
		ssl_ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_options(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
	}
	else if (secureProtocolLen == 20 && strncmp(secureProtocol, "SSLv23_server_method", 20) == 0)
	{
		ssl_ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_options(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
	}
	else if (secureProtocolLen == 12 && strncmp(secureProtocol, "TLSv1_method", 12) == 0)
	{
		ssl_ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_options(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);
	}
	else if (secureProtocolLen == 19 && strncmp(secureProtocol, "TLSv1_client_method", 19) == 0)
	{
		ssl_ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_options(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);
	}
	else if (secureProtocolLen == 19 && strncmp(secureProtocol, "TLSv1_server_method", 19) == 0)
	{
		ssl_ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_options(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);
	}
	else if (secureProtocolLen == 14 && strncmp(secureProtocol, "TLSv1_1_method", 14) == 0)
	{
		ssl_ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_options(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_2);
	}
	else if (secureProtocolLen == 21 && strncmp(secureProtocol, "TLSv1_1_client_method", 21) == 0)
	{
		ssl_ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_options(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_2);
	}
	else if (secureProtocolLen == 21 && strncmp(secureProtocol, "TLSv1_1_server_method", 21) == 0)
	{
		ssl_ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_options(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_2);
	}
	else if (secureProtocolLen == 14 && strncmp(secureProtocol, "TLSv1_2_method", 14) == 0)
	{
		ssl_ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_options(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	}
	else if (secureProtocolLen == 21 && strncmp(secureProtocol, "TLSv1_2_client_method", 21) == 0)
	{
		ssl_ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_options(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	}
	else if (secureProtocolLen == 21 && strncmp(secureProtocol, "TLSv1_2_server_method", 21) == 0)
	{
		ssl_ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_options(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	}
	else if (secureProtocolLen == 11 && strncmp(secureProtocol, "DTLS_method", 11) == 0)
	{
		ssl_ctx = SSL_CTX_new(DTLS_method());
	}
	else
	{
		return(ILibDuktape_Error(ctx, "tls.createSecureContext(): secureProtocol[%s] not supported at this time", secureProtocol));
	}
	duk_push_pointer(ctx, ssl_ctx); duk_put_prop_string(ctx, -2, ILibDuktape_SecureContext2SSLCTXPTR);

	if (duk_has_prop_string(ctx, 0, "pfx") && duk_has_prop_string(ctx, 0, "passphrase"))
	{
		duk_get_prop_string(ctx, 0, "pfx");													// [secureContext][pfx]
		duk_size_t pfxLen;
		char *pfx = (char*)Duktape_GetBuffer(ctx, -1, &pfxLen);
		if (util_from_p12(pfx, (int)pfxLen, Duktape_GetStringPropertyValue(ctx, 0, "passphrase", ""), cert) == 0)
		{
			// Failed to load certificate
			return(ILibDuktape_Error(ctx, "tls.createSecureContext(): Invalid passphrase"));
		}
		duk_pop(ctx);
		SSL_CTX_use_certificate(ssl_ctx, cert->x509);
		SSL_CTX_use_PrivateKey(ssl_ctx, cert->pkey);
	}

	util_load_system_certs(ssl_ctx);

	return(1);
}
duk_ret_t ILibDuktape_TLS_generateCertificate(duk_context *ctx)
{
	char *passphrase = (char*)duk_require_string(ctx, 0);
	int len;
	struct util_cert cert;
	char *data;
	int noUsages = 0;
	int certType = CERTIFICATE_TLS_CLIENT;
	char certHash[UTIL_SHA384_HASHSIZE];
	char fingerprint[150];

	if (!duk_is_null_or_undefined(ctx, 1) && duk_is_object(ctx, 1))
	{
		certType = Duktape_GetIntPropertyValue(ctx, 1, "certType", CERTIFICATE_TLS_CLIENT);
		noUsages = Duktape_GetIntPropertyValue(ctx, 1, "noUsages", 0);
	}

	len = util_mkCertEx(NULL, &(cert), 3072, 10000, "localhost", certType, NULL, noUsages);
	len = util_to_p12(cert, passphrase, &data);

	duk_push_fixed_buffer(ctx, len);
	memcpy_s((void*)Duktape_GetBuffer(ctx, -1, NULL), len, data, len);
	duk_push_buffer_object(ctx, -1, 0, len, DUK_BUFOBJ_NODEJS_BUFFER);
	ILibDuktape_WriteID(ctx, "tls.pfxCertificate");

	util_certhash2(cert.x509, certHash);
	util_tohex2(certHash, UTIL_SHA384_HASHSIZE, fingerprint);
	duk_push_string(ctx, fingerprint);				// [cert][digest]
	duk_put_prop_string(ctx, -2, "digest");			// [cert]

	util_free(data);
	util_freecert(&cert);
	passphrase = NULL;

	return 1;
}
duk_ret_t ILibDuktape_TLS_loadpkcs7b(duk_context *ctx)
{
	duk_size_t len;
	char *buffer = (char*)Duktape_GetBuffer(ctx, 0, &len);
	int val = util_from_pkcs7b_string(buffer, (int)len, NULL, 0);
	char *out;

	if (val > 0)
	{
		duk_push_fixed_buffer(ctx, val);
		out = Duktape_GetBuffer(ctx, -1, NULL);
		duk_push_buffer_object(ctx, -1, 0, val, DUK_BUFOBJ_NODEJS_BUFFER);
		util_from_pkcs7b_string(buffer, (int)len, out, val);
		return(1);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Error reading pkcs7b data"));
	}
}

duk_ret_t ILibDuktape_TLS_loadCertificate_finalizer(duk_context *ctx)
{
	struct util_cert *cert = (struct util_cert*)Duktape_GetBufferProperty(ctx, 0, ILibDuktape_TLS_util_cert);
	util_freecert(cert);
	return(0);
}
duk_ret_t ILibDuktape_TLS_loadCertificate_getKeyHash(duk_context *ctx)
{
	duk_push_this(ctx);
	struct util_cert *cert = (struct util_cert*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_TLS_util_cert);
	char *hash = duk_push_fixed_buffer(ctx, UTIL_SHA384_HASHSIZE);
	duk_push_buffer_object(ctx, -1, 0, UTIL_SHA384_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);
	util_keyhash(cert[0], hash);
	return(1);
}
duk_ret_t ILibDuktape_TLS_toDER(duk_context *ctx)
{
	duk_push_this(ctx);
	struct util_cert *cert = (struct util_cert*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_TLS_util_cert);
	int outLen = i2d_X509(cert->x509, NULL); 
	if (outLen <= 0)
	{
		return(ILibDuktape_Error(ctx, "Certificate Error"));
	}

	char *out = duk_push_fixed_buffer(ctx, outLen);
	duk_push_buffer_object(ctx, -1, 0, outLen, DUK_BUFOBJ_NODEJS_BUFFER);
	i2d_X509(cert->x509, (unsigned char**)&out);
	return(1);
}
duk_ret_t ILibDuktape_TLS_loadCertificate(duk_context *ctx)
{
	duk_size_t pfxLen, derLen;
	char *pfx = Duktape_GetBufferPropertyEx(ctx, 0, "pfx", &pfxLen);
	char *der = Duktape_GetBufferPropertyEx(ctx, 0, "der", &derLen);
	if (der == NULL) { der = Duktape_GetBufferPropertyEx(ctx, 0, "cer", &derLen); }

	if (pfx != NULL || der != NULL)
	{
		duk_push_object(ctx);
		ILibDuktape_WriteID(ctx, "tls.certificate");
		struct util_cert *cert = (struct util_cert*)Duktape_PushBuffer(ctx, sizeof(struct util_cert));
		duk_put_prop_string(ctx, -2, ILibDuktape_TLS_util_cert);
		if (pfx != NULL)
		{
			if (util_from_p12(pfx, (int)pfxLen, Duktape_GetStringPropertyValue(ctx, 0, "passphrase", NULL), cert) == 0)
			{
				// Failed to load certificate
				return(ILibDuktape_Error(ctx, "tls.loadCertificate(): Invalid passphrase"));
			}
		}
		else if (der != NULL)
		{
			if (util_from_cer(der, (int)derLen, cert) == 0)
			{
				// Failed to load certificate
				return(ILibDuktape_Error(ctx, "tls.loadCertificate(): Failed to parse Certificate (%s)", ERR_reason_error_string(ERR_get_error())));
			}
		}
		ILibDuktape_CreateFinalizer(ctx, ILibDuktape_TLS_loadCertificate_finalizer);
		ILibDuktape_CreateInstanceMethod(ctx, "getKeyHash", ILibDuktape_TLS_loadCertificate_getKeyHash, 0);
		ILibDuktape_CreateInstanceMethod(ctx, "toDER", ILibDuktape_TLS_toDER, 0);
		return(1);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "tls.loadCertificate(): No certificate format specified"));
	}
}
void ILibDuktape_tls_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);				// [TLS]
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "tls", 1, "createServer", ILibDuktape_net_createServer, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "connect", ILibDuktape_TLS_connect, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "createSecureContext", ILibDuktape_TLS_createSecureContext, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "generateCertificate", ILibDuktape_TLS_generateCertificate, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "loadCertificate", ILibDuktape_TLS_loadCertificate, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "loadpkcs7b", ILibDuktape_TLS_loadpkcs7b, 1);

	char generateRandomInteger[] = "exports.generateRandomInteger = function generateRandomInteger(low, high)\
									{\
										return(require('bignum').randomRange(require('bignum')(low), require('bignum')(high)).toString());\
									};";
	ILibDuktape_ModSearch_AddHandler_AlsoIncludeJS(ctx, generateRandomInteger, sizeof(generateRandomInteger) - 1);
}
#endif

duk_ret_t ILibDuktape_ipaddress_address4_mask(duk_context *ctx)
{
	duk_push_this(ctx);
	struct sockaddr_in6* addr = (struct sockaddr_in6*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_IPAddress_SockAddr);
	int mask = duk_require_int(ctx, 0);
	mask = 0xFFFFFFFF >> (32 - mask);
	((struct sockaddr_in*)addr)->sin_addr.s_addr &= mask;

	duk_push_string(ctx, ILibRemoteLogging_ConvertAddress((struct sockaddr*)addr));
	return(1);
}
duk_ret_t ILibDuktape_ipaddress_toString(duk_context *ctx)
{
	duk_push_this(ctx);
	struct sockaddr_in6* addr = (struct sockaddr_in6*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_IPAddress_SockAddr);
	
	duk_push_string(ctx, (char*)ILibRemoteLogging_ConvertAddress((struct sockaddr*)addr));
	return(1);
}
void ILibDuktape_ipaddress_PUSH(duk_context *ctx, struct sockaddr_in6* addr)
{
	duk_push_object(ctx);																					// [Address4/6]
	switch (addr->sin6_family)
	{
		case AF_INET:
			ILibDuktape_WriteID(ctx, "ip-address.Address4");
			ILibDuktape_CreateInstanceMethod(ctx, "mask", ILibDuktape_ipaddress_address4_mask, 1);
			break;
		case AF_INET6:
			ILibDuktape_WriteID(ctx, "ip-address.Address6");
			break;
		default:
			ILibDuktape_Error(ctx, "Unknown Address Family");
			break;
	}

	ILibDuktape_CreateInstanceMethod(ctx, "toString", ILibDuktape_ipaddress_toString, 1);
	struct sockaddr_in6* _addr = (struct sockaddr_in6*)Duktape_PushBuffer(ctx, sizeof(struct sockaddr_in6));// [Address4][addr]
	duk_put_prop_string(ctx, -2, ILibDuktape_IPAddress_SockAddr);											// [Address4]
	memcpy_s(_addr, sizeof(struct sockaddr_in6), addr, sizeof(struct sockaddr_in6));
}

duk_ret_t ILibDuktape_ipaddress_address4_constructor(duk_context *ctx)
{
	if (!duk_is_constructor_call(ctx)) { return(ILibDuktape_Error(ctx, "Invalid call")); }
	ILibDuktape_ipaddress_PUSH(ctx, Duktape_IPAddress4_FromString((char*)duk_require_string(ctx, 0), 0));
	return(1);
}
duk_ret_t ILibDuktape_ipaddress_address4_fromInteger(duk_context *ctx)
{
	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof(addr));
	((struct sockaddr_in*)&addr)->sin_addr.s_addr = htonl(duk_require_int(ctx, 0));
	((struct sockaddr_in*)&addr)->sin_family = AF_INET;
	ILibDuktape_ipaddress_PUSH(ctx, &addr);
	return(1);
}
duk_ret_t ILibDuktape_ipaddress_address4_fromString(duk_context *ctx)
{
	ILibDuktape_ipaddress_PUSH(ctx, Duktape_IPAddress4_FromString((char*)duk_require_string(ctx, 0), 0));
	return(1);
}

void ILibDuktape_ipaddress(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);																					// [ip-address]
	ILibDuktape_WriteID(ctx, "ip-address");
	duk_push_c_function(ctx, ILibDuktape_ipaddress_address4_constructor, 1);								// [ip-address][Address4]
	ILibDuktape_CreateInstanceMethod(ctx, "fromInteger", ILibDuktape_ipaddress_address4_fromInteger, 1);	// [ip-address][Address4]
	ILibDuktape_CreateInstanceMethod(ctx, "fromString", ILibDuktape_ipaddress_address4_fromString, 1);		// [ip-address][Address4]
	duk_put_prop_string(ctx, -2, "Address4");																// [ip-address]
}

void ILibDuktape_net_init(duk_context * ctx, void * chain)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "net", ILibDuktape_net_PUSH_net);
	ILibDuktape_ModSearch_AddHandler(ctx, "global-tunnel", ILibDuktape_globalTunnel_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "ip-address", ILibDuktape_ipaddress);
#ifndef MICROSTACK_NOTLS
	ILibDuktape_ModSearch_AddHandler(ctx, "tls", ILibDuktape_tls_PUSH);
#endif
}


#ifdef __DOXY__
/*!
\implements DuplexStream
\brief TCP socket abstraction
*/
class Socket
{
public:
	/*!
	\brief If true, 'connect' was called and hasn't finished yet. Will be set to 'false' before 'connect' event is emitted.
	*/
	bool connecting;
	/*!
	\brief The string representation of the local IP address the remote client is connecting on.
	*/
	String localAddress;
	/*!
	\brief The numeric representation of the local port
	*/
	integer localPort;
	/*!
	\brief The string representation of the remote IP address.
	*/
	String remoteAddress;
	/*!
	\brief The amount of bytes sent.
	*/
	integer bytesWritten;

	/*!
	\brief Event emitted if the socket times out from inactivity. This is only to notify that the socket has been idle. The user must manually close the connection.
	*/
	void timeout;
	/*!
	\brief The 'close' event is emitted when the stream and any of its underlying resources have been closed.
	*
	The event indicates that no more events will be emitted, and no further computation will occur.
	*/
	void close;
	/*!
	\brief Event emitted when a socket connection is successfully established
	*/
	void connect;
	/*!
	\brief The 'error' event is emitted if an error occurred while writing or piping data.
	\param arg Error argument describing the error that occured
	*/
	void error;

	/*!
	\brief Initiate a connection on a given socket
	*
	\par Possible signatures:\n
	Socket connect(options[, connectListener]);\n
	Socket connect(port[, host][, connectListener]);\n
	\param options <Object> with the following fields:\n
	<b>port</b> <number> Required. Port the socket should connect to.\n
	<b>host</b> \<String\> Host the socket should connect to. Defaults to 'localhost'.\n
	<b>localAddress</b> \<String\> Local address the socket should connect from.\n
	<b>localPort</b> <number> Local port the socket should connect from.\n
	<b>family</b> <number>: Version of IP stack, can be either 4 or 6. Defaults to 4.\n
	\param connectListener <func> that will be added as one time listener for 'connect' event.
	*/
	Socket connect();
	/*!
	\brief Returns the bound address, the address family name, and port of the socket as reported by the OS (ie: {port: 12345, family: 'IPv4', address: '127.0.0.1'})
	*/
	Object address();
	/*!
	\brief Sets the socket to timeout after timeout milliseconds of inactivity on the socket. By default Socket do not have a timeout.
	*
	When an idle timeout is triggered the socket will receive a 'timeout' event but the connection <b>will not</b> be severed.
	\param milliseconds <integer> Number of milliseconds to set the idle timeout to
	\param timeout <func> Optional callback will be set as one time listener for to the 'timeout' event.
	*/
	void setTimeout(milliseconds[, timeout]);
};
#endif
