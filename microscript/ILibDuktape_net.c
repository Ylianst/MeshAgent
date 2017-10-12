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

#include "duktape.h"

#include "ILibDuktape_net.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_DuplexStream.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_EventEmitter.h"
#include "microstack/ILibAsyncSocket.h"
#include "microstack/ILibCrypto.h"
#include "microstack/ILibAsyncServerSocket.h"

typedef struct ILibDuktape_net_socket
{
	duk_context *ctx;
	ILibAsyncSocket_SocketModule socketModule;
	void *object;
	void *net;
	void *duplexStream;
	void *chain;
	void *OnConnect;
	void *OnClose;
	void *OnError;
	void *OnTimeout;
	void *OnSetTimeout;
	ILibDuktape_EventEmitter *emitter;
}ILibDuktape_net_socket;

typedef struct ILibDuktape_net_server
{
	duk_context *ctx;
	void *self;
	ILibAsyncServerSocket_ServerModule server;
	ILibDuktape_EventEmitter *emitter;
	void *OnClose;
	void *OnConnection;
	void *OnListening;
	void *OnError;
}ILibDuktape_net_server;
typedef struct ILibDuktape_net_server_session
{
	duk_context *ctx;
	void *self;
	ILibAsyncServerSocket_ConnectionToken connection;
	ILibDuktape_EventEmitter *emitter;
	ILibDuktape_DuplexStream *stream;

	void *OnTimeout;
}ILibDuktape_net_server_session;

#define ILibDuktape_GlobalTunnel_DataPtr		"\xFF_GlobalTunnel_DataPtr"
#define ILibDuktape_GlobalTunnel_Stash			"global-tunnel"
#define ILibDuktape_net_Server_buffer			"\xFF_FixedBuffer"
#define ILibDuktape_net_Server_Session_buffer	"\xFF_SessionFixedBuffer"
#define ILibDuktape_net_socket_ptr				"\xFF_SocketPtr"

extern void ILibAsyncServerSocket_RemoveFromChain(ILibAsyncServerSocket_ServerModule serverModule);

// Prototypes
void ILibDuktape_net_socket_PUSH(duk_context *ctx, ILibAsyncSocket_SocketModule module);
#ifndef MICROSTACK_NOTLS
extern void ILibDuktape_X509_PUSH(duk_context *ctx, X509* cert);
#endif
void ILibDuktape_net_socket_OnData(ILibAsyncSocket_SocketModule socketModule, char* buffer, int *p_beginPointer, int endPointer, ILibAsyncSocket_OnInterrupt* OnInterrupt, void **user, int *PAUSE)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;
	if (ILibDuktape_DuplexStream_WriteData((ILibDuktape_DuplexStream*)ptrs->duplexStream, buffer + *p_beginPointer, endPointer - *p_beginPointer) != 0) { *PAUSE = 1; }
	else { *p_beginPointer = endPointer; }
}
void ILibDuktape_net_socket_OnConnect(ILibAsyncSocket_SocketModule socketModule, int Connected, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;
	struct sockaddr_in6 local;

	duk_push_heapptr(ptrs->ctx, ptrs->object);					// [sockat]
	duk_push_false(ptrs->ctx);									// [socket][connecting]
	duk_put_prop_string(ptrs->ctx, -2, "connecting");			// [socket]
	duk_pop(ptrs->ctx);											// ...

	if (Connected != 0)
	{
		duk_push_heapptr(ptrs->ctx, ptrs->object);																		// [sock]
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

		duk_pop(ptrs->ctx);																								// ...

		if (ptrs->OnConnect != NULL)
		{
			duk_push_heapptr(ptrs->ctx, ptrs->OnConnect);			// [func]
			ILibDuktape_net_socket_PUSH(ptrs->ctx, socketModule);	// [func][this]
			if (duk_pcall_method(ptrs->ctx, 0) != 0)				// [retVal]
			{
				ILibDuktape_Process_UncaughtException(ptrs->ctx);
			}
			duk_pop(ptrs->ctx);										// ...
		}
	}
	else if(ptrs->OnError != NULL)
	{
		duk_push_heapptr(ptrs->ctx, ptrs->OnError);					// [func]
		ILibDuktape_net_socket_PUSH(ptrs->ctx, socketModule);		// [func][this]
		duk_push_object(ptrs->ctx);									// [func][this][error]
		duk_push_string(ptrs->ctx, "Connection Failed");			// [func][this][error][msg]
		duk_put_prop_string(ptrs->ctx, -2, "message");				// [func][this][error]
		if (duk_pcall_method(ptrs->ctx, 1) != 0)					// [retVal]
		{
			ILibDuktape_Process_UncaughtException(ptrs->ctx);
		}
		duk_pop(ptrs->ctx);											// ...
	}
}
void ILibDuktape_net_socket_OnDisconnect(ILibAsyncSocket_SocketModule socketModule, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;
	
	duk_push_heapptr(ptrs->ctx, ptrs->object);			// [sock]
	duk_push_string(ptrs->ctx, "0.0.0.0");				// [sock][localAddr]
	duk_put_prop_string(ptrs->ctx, -2, "localAddress");	// [sock]
	duk_push_undefined(ptrs->ctx);						// [sock][remoteAddr]
	duk_put_prop_string(ptrs->ctx, -2, "remoteAddress");// [sock]
	duk_pop(ptrs->ctx);									// ...

	ILibDuktape_DuplexStream_Closed((ILibDuktape_DuplexStream*)ptrs->duplexStream);
}
void ILibDuktape_net_socket_OnSendOK(ILibAsyncSocket_SocketModule socketModule, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;
	ILibDuktape_DuplexStream_Ready((ILibDuktape_DuplexStream*)ptrs->duplexStream);
}
ILibTransport_DoneState ILibDuktape_net_socket_WriteHandler(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)user;
	return((ILibTransport_DoneState)ILibAsyncSocket_Send(ptrs->socketModule, buffer, bufferLen, ILibAsyncSocket_MemoryOwnership_USER));
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
duk_ret_t ILibDuktape_net_socket_connect(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int port = 0;
	char *host = "127.0.0.1";
	ILibDuktape_net_socket *ptrs;
	struct sockaddr_in6 dest;

	if (nargs == 0) { duk_push_string(ctx, "Too Few Arguments"); duk_throw(ctx); return(DUK_RET_ERROR); }
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
		if (nargs >= 2 && duk_is_function(ctx, 1))
		{
			ILibDuktape_EventEmitter_AddOn(ptrs->emitter, "connect", duk_require_heapptr(ctx, 1));
		}
	}
	if (duk_is_string(ctx, 0))
	{
		// This is a PATH string
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

	ILibResolveEx(host, (unsigned short)port, &dest);
	ILibAsyncSocket_ConnectTo(ptrs->socketModule, NULL, (struct sockaddr*)&dest, NULL, ptrs);

	duk_push_heapptr(ptrs->ctx, ptrs->object);					// [sockat]
	duk_push_true(ptrs->ctx);									// [socket][connecting]
	duk_put_prop_string(ptrs->ctx, -2, "connecting");			// [socket]
	duk_pop(ptrs->ctx);											// ...

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
	if (ptrs->OnTimeout != NULL)
	{
		duk_push_heapptr(ptrs->ctx, ptrs->OnTimeout);					// [func]
		duk_push_heapptr(ptrs->ctx, ptrs->object);						// [func][this]
		if (duk_pcall_method(ptrs->ctx, 0) != 0) { ILibDuktape_Process_UncaughtException(ptrs->ctx); }
		duk_pop(ptrs->ctx);												// ...
	}
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

	if (timeout < 1000) { return(ILibDuktape_Error(ctx, "net.socket.setTimeout(): Error, timeout must be > 1000ms. Timeout was %d ms", timeout)); }
	if (nargs > 1 && duk_is_function(ctx, 1))
	{
		ILibDuktape_EventEmitter_AddOnce(ptrs->emitter, "timeout", duk_require_heapptr(ctx, 1));
	}

	ILibAsyncSocket_SetTimeout(ptrs->socketModule, timeout / 1000, ILibDuktape_net_socket_timeoutSink);
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

	return 0;
}
void ILibDuktape_net_socket_PUSH(duk_context *ctx, ILibAsyncSocket_SocketModule module)
{
	ILibDuktape_net_socket *ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)module)->ExtraMemoryPtr;
	if (ptrs->object != NULL)
	{
		duk_push_heapptr(ctx, ptrs->object);
		return;
	}

	duk_push_object(ctx);										// [obj]
	ptrs->ctx = ctx;
	ptrs->chain = ((ILibChain_Link*)module)->ParentChain;
	ptrs->object = duk_get_heapptr(ctx, -1);
	ptrs->socketModule = module;

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
	ptrs->duplexStream = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_net_socket_WriteHandler, ILibDuktape_net_socket_EndHandler, ILibDuktape_net_socket_PauseHandler, ILibDuktape_net_socket_ResumeHandler, ptrs);

	ILibDuktape_EventEmitter_CreateEvent(ptrs->emitter, "close", &(ptrs->OnClose));
	ILibDuktape_EventEmitter_CreateEvent(ptrs->emitter, "connect", &(ptrs->OnConnect));
	ILibDuktape_EventEmitter_CreateEvent(ptrs->emitter, "error", &(ptrs->OnError));
	ILibDuktape_EventEmitter_CreateEvent(ptrs->emitter, "timeout", &(ptrs->OnTimeout));

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

	if (!duk_is_constructor_call(ctx)) { duk_push_string(ctx, "Invalid Call"); duk_throw(ctx); return(DUK_RET_ERROR); }
	
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

	duk_push_this(ctx);						// [net]
	duk_get_prop_string(ctx, -1, "chain");	// [net][chain]
	chain = duk_to_pointer(ctx, -1);
	net = duk_get_heapptr(ctx, -2);
	duk_pop(ctx);							// [net]

	sm = ILibCreateAsyncSocketModuleWithMemory(chain, 4096, ILibDuktape_net_socket_OnData, ILibDuktape_net_socket_OnConnect, ILibDuktape_net_socket_OnDisconnect, ILibDuktape_net_socket_OnSendOK, sizeof(ILibDuktape_net_socket));
	ptrs = (ILibDuktape_net_socket*)((ILibChain_Link*)sm)->ExtraMemoryPtr;
	ptrs->net = net;

	duk_push_pointer(ctx, ptrs);								// [net][ptrs]
	duk_put_prop_string(ctx, -2, ILibDuktape_net_socket_ptr);	// [net]

	ILibDuktape_net_socket_PUSH(ctx, sm);

	ILibDuktape_net_socket_connect(ctx);
	duk_push_this(ctx);
	duk_del_prop_string(ctx, -1, ILibDuktape_net_socket_ptr);
	duk_push_heapptr(ctx, ptrs->object);
	return 1;
}

#ifndef MICROSTACK_NOTLS
typedef struct ILibDuktape_net_sslStream_ptr
{
	duk_context *ctx;
	SSL_CTX *sslctx;
	SSL* ssl;
	void *sslStream_object;
	void *sslStream_en_object;
	void *OnVerify;
	void *OnConnected;
	int handshake;
	int rejectUnauthorized;
	ILibDuktape_DuplexStream *ds_clear;
	ILibDuktape_DuplexStream *ds_encrypted;
	int encrypted_processingLoop;
	int decrypted_processingLoop;
	char encryptedBuffer[4096];
	char decryptedBuffer[4096];
}ILibDuktape_net_sslStream_ptr;
#define ILibDuktape_net_sslStream_key		"\xFF_sslStreamPtr"
int ILibDuktape_net_sslStream_sslIndex = -1;

void ILibDuktape_net_sslStream_encryptedReadLoop(ILibDuktape_net_sslStream_ptr *ptrs)
{
	int j;
	if (ptrs->encrypted_processingLoop == 0)
	{
		ptrs->encrypted_processingLoop = 1;
		while (ptrs->ds_encrypted->readableStream->paused == 0 && BIO_ctrl_pending(SSL_get_wbio(ptrs->ssl)) > 0)
		{
			// Data is pending in the write buffer, send it out
			j = BIO_read(SSL_get_wbio(ptrs->ssl), ptrs->encryptedBuffer, sizeof(ptrs->encryptedBuffer));
			ILibDuktape_DuplexStream_WriteData(ptrs->ds_encrypted, ptrs->encryptedBuffer, j);
		}
		ptrs->encrypted_processingLoop = 0;
	}
}
int ILibDuktape_net_sslStream_decryptedReadLoop(ILibDuktape_net_sslStream_ptr *ptrs)
{
	int retVal = 0;
	int i = -1;
	if (ptrs->decrypted_processingLoop == 0)
	{
		ptrs->decrypted_processingLoop = 1;
		while (ptrs->ds_clear->readableStream->paused == 0 && (i = SSL_read(ptrs->ssl, ptrs->decryptedBuffer, sizeof(ptrs->decryptedBuffer)))>0)
		{
			// We got new TLS/DTLS data
			ILibDuktape_DuplexStream_WriteData(ptrs->ds_clear, ptrs->decryptedBuffer, i);
		}
		if (i == 0)
		{
			// Session Closed
			retVal = 1;
		}
		ptrs->decrypted_processingLoop = 0;	// Compiler Warning is wrong here... This is to prevent re-entrancy problems, because DuplexStream_WriteData() can end up calling back in
	}
	return retVal;
}
ILibTransport_DoneState ILibDuktape_net_sslStream_writeSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_net_sslStream_ptr *ptrs = (ILibDuktape_net_sslStream_ptr*)user;

	SSL_write(ptrs->ssl, buffer, bufferLen);
	ILibDuktape_net_sslStream_encryptedReadLoop(ptrs);
	return(ptrs->ds_encrypted->readableStream->paused == 0 ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE);
}
ILibTransport_DoneState ILibDuktape_net_sslStream_en_writeSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	int err;
	ILibDuktape_net_sslStream_ptr *ptrs = (ILibDuktape_net_sslStream_ptr*)user;
	ILibTransport_DoneState retVal = ILibTransport_DoneState_ERROR;

	BIO_write(SSL_get_rbio(ptrs->ssl), buffer, bufferLen);
	if (ptrs->handshake == 0)
	{
		switch (SSL_do_handshake(ptrs->ssl))
		{
		case 0:
			// Handshake Failed!
			while ((err = ERR_get_error()) != 0)
			{
				ERR_error_string_n(err, ILibScratchPad, sizeof(ILibScratchPad));
			}
			// TODO: We should probably do something
			break;
		case 1:
			ptrs->handshake = 1;
			retVal = ILibTransport_DoneState_COMPLETE;
			if (ptrs->OnConnected != NULL)
			{
				duk_push_heapptr(ptrs->ctx, ptrs->OnConnected);				// [func]
				duk_push_heapptr(ptrs->ctx, ptrs->sslStream_object);		// [func][this]
				if (duk_pcall_method(ptrs->ctx, 0) != 0) { ILibDuktape_Process_UncaughtException(ptrs->ctx); }
				duk_pop(ptrs->ctx);											// ...
			}
			break;
		default:
			// SSL_WANT_READ most likely, so do nothing for now
			retVal = ILibTransport_DoneState_COMPLETE;
			break;
		}
	}
	else
	{
		retVal = ILibDuktape_net_sslStream_decryptedReadLoop(ptrs) != 0 ? ILibTransport_DoneState_ERROR : (ptrs->ds_clear->readableStream->paused == 0 ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE);
	}

	ILibDuktape_net_sslStream_encryptedReadLoop(ptrs);
	return retVal;
}
void ILibDuktape_net_sslStream_endSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_net_sslStream_ptr *ptrs = (ILibDuktape_net_sslStream_ptr*)user;
	ILibDuktape_DuplexStream_WriteEnd(ptrs->ds_encrypted);
}
void ILibDuktape_net_sslStream_en_endSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_net_sslStream_ptr *ptrs = (ILibDuktape_net_sslStream_ptr*)user;
	ILibDuktape_DuplexStream_WriteEnd(ptrs->ds_clear);
}
void ILibDutkape_net_sslStream_pauseSink(ILibDuktape_DuplexStream *sender, void *user)
{

}
void ILibDuktape_net_sslStream_en_pauseSink(ILibDuktape_DuplexStream *sender, void *user)
{

}
void ILibDuktape_net_sslStream_resumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_net_sslStream_ptr *ptrs = (ILibDuktape_net_sslStream_ptr*)user;
	if (ILibDuktape_net_sslStream_decryptedReadLoop(ptrs) == 0)
	{
		if (ptrs->ds_clear->readableStream->paused == 0) { ILibDuktape_DuplexStream_Ready(ptrs->ds_encrypted); }
	}
	else
	{
		// TLS Session was closed
	}
}
void ILibDuktape_net_sslStream_en_resumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_net_sslStream_ptr *ptrs = (ILibDuktape_net_sslStream_ptr*)user;

	ILibDuktape_net_sslStream_encryptedReadLoop(ptrs);
	if (ptrs->ds_encrypted->readableStream->paused == 0) { ILibDuktape_DuplexStream_Ready(ptrs->ds_clear); }
}
int ILibDuktape_net_sslStream_verifyServer(int preverify_ok, X509_STORE_CTX *ctx)
{
	STACK_OF(X509) *certChain = X509_STORE_CTX_get_chain(ctx);
	SSL *ssl = (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	ILibDuktape_net_sslStream_ptr *ptrs = (ILibDuktape_net_sslStream_ptr*)SSL_get_ex_data(ssl, ILibDuktape_net_sslStream_sslIndex);
	int i;
	int retVal = 0;

	if (ptrs->rejectUnauthorized != 0) { return(preverify_ok); }
	else { retVal = 0; }

	if (ptrs->OnVerify == NULL) { return 1; }

	duk_push_heapptr(ptrs->ctx, ptrs->OnVerify);											// [func]
	duk_push_heapptr(ptrs->ctx, ptrs->sslStream_object);									// [func][this]
	duk_push_array(ptrs->ctx);																// [func][this][certs]
	for (i = 0; i < sk_X509_num(certChain); ++i)
	{
		ILibDuktape_X509_PUSH(ptrs->ctx, sk_X509_value(certChain, i));						// [func][this][certs][cert]
		duk_put_prop_index(ptrs->ctx, -2, i);												// [func][this][certs]
	}
	if (duk_pcall_method(ptrs->ctx, 1) != 0) { retVal = 0; } else { retVal = 1; }
	return retVal;
}
duk_ret_t ILibDuktape_net_sslStream_Finalizer(duk_context *ctx)
{
	ILibDuktape_net_sslStream_ptr *ptrs;
	duk_get_prop_string(ctx, 0, ILibDuktape_net_sslStream_key);
	ptrs = (ILibDuktape_net_sslStream_ptr*)Duktape_GetBuffer(ctx, -1, NULL);

	if (ptrs->ssl != NULL) { SSL_free(ptrs->ssl); }
	if (ptrs->sslctx != NULL) { SSL_CTX_free(ptrs->sslctx); }

	return 0;
}
duk_ret_t ILibDuktape_net_sslStream_create(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	ILibDuktape_DuplexStream *ds, *en;
	ILibDuktape_net_sslStream_ptr *ptrs;
	BIO *read, *write;
	int status, i;
	int isClient;
	struct util_cert *leafCert = NULL;
	struct util_cert *nonLeafCert = NULL;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "clientMode");
	isClient = duk_get_int(ctx, -1);

	duk_push_object(ctx);																// [sslStream]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_net_sslStream_ptr));					// [sslStream][buffer]
	ptrs = (ILibDuktape_net_sslStream_ptr*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_net_sslStream_key);						// [sslStream]
	memset(ptrs, 0, sizeof(ILibDuktape_net_sslStream_ptr));
	ILibDuktape_CreateEventWithSetter(ctx, "connected", "\xFF_connected", &(ptrs->OnConnected));
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_net_sslStream_Finalizer);
	ptrs->sslStream_object = duk_get_heapptr(ctx, -1);


	if (nargs > 1)
	{
		ptrs->rejectUnauthorized = Duktape_GetIntPropertyValue(ctx, 1, "rejectUnauthorized", 0);
		if (duk_has_prop_string(ctx, 1, "verify"))
		{
			duk_get_prop_string(ctx, 1, "verify");										// [sslStream][OnVerify]
			ptrs->OnVerify = duk_get_heapptr(ctx, -1);
			duk_put_prop_string(ctx, -2, "\xFF_OnVerify");								// [sslStream]
		}
		if (duk_has_prop_string(ctx, 1, "MeshAgent"))
		{
			duk_get_prop_string(ctx, 1, "MeshAgent");									// [sslStream][MeshAgent]
			if (isClient == 0)
			{
				duk_get_prop_string(ctx, -1, ILibDuktape_MeshAgent_Cert_Server);		// [sslStream][MeshAgent][cert]
				leafCert = (struct util_cert*)duk_get_pointer(ctx, -1);
				duk_pop_2(ctx);															// [sslStream]
			}
			else
			{
				duk_get_prop_string(ctx, -1, ILibDuktape_MeshAgent_Cert_Client);		// [sslStream][MeshAgent][clientCert]
				duk_get_prop_string(ctx, -2, ILibDuktape_MeshAgent_Cert_NonLeaf);		// [sslStream][MeshAgent][clientCert][nonLeafCert]
				leafCert = (struct util_cert*)duk_get_pointer(ctx, -2);
				nonLeafCert = (struct util_cert*)duk_get_pointer(ctx, -1);
				duk_pop_3(ctx);															// [sslStream]
			}
		}
		if (duk_has_prop_string(ctx, 1, "pfx") && duk_has_prop_string(ctx, 1, "passphrase"))
		{
			char *pfx;
			duk_size_t pfxLen;
			char *pwd;

			duk_get_prop_string(ctx, 1, "pfx");											// [sslStream][pfx]
			pfx = Duktape_GetBuffer(ctx, -1, &pfxLen);
			duk_get_prop_string(ctx, 1, "passphrase");									// [sslStream][pfx][pwd]
			pwd = (char*)duk_get_string(ctx, -1);
			util_from_p12(pfx, (int)pfxLen, pwd, leafCert);

			duk_pop_2(ctx);																// [sslStream]
		}
	}

	ds = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_net_sslStream_writeSink, ILibDuktape_net_sslStream_endSink, ILibDutkape_net_sslStream_pauseSink, ILibDuktape_net_sslStream_resumeSink, ptrs);
	duk_push_object(ctx);																// [sslStream][encryptedStream]
	ptrs->sslStream_en_object = duk_get_heapptr(ctx, -1);
	en = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_net_sslStream_en_writeSink, ILibDuktape_net_sslStream_en_endSink, ILibDuktape_net_sslStream_en_pauseSink, ILibDuktape_net_sslStream_en_resumeSink, ptrs);
	duk_put_prop_string(ctx, -2, "\xFF_internalStream");								// [sslStream]

	ptrs->ds_clear = ds;
	ptrs->ds_encrypted = en;
	ptrs->ctx = ctx;
	ptrs->sslctx = isClient != 0 ? SSL_CTX_new(SSLv23_client_method()) : SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_options(ptrs->sslctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
	SSL_CTX_set_verify(ptrs->sslctx, isClient != 0 ? SSL_VERIFY_PEER : SSL_VERIFY_CLIENT_ONCE, ILibDuktape_net_sslStream_verifyServer); // Ask for authentication
	
	if (leafCert != NULL)
	{
		SSL_CTX_use_certificate(ptrs->sslctx, leafCert->x509);
		SSL_CTX_use_PrivateKey(ptrs->sslctx, leafCert->pkey);

		if (nonLeafCert != NULL)
		{
			SSL_CTX_add_extra_chain_cert(ptrs->sslctx, X509_dup(nonLeafCert->x509));
		}
	}

	ptrs->ssl = SSL_new(ptrs->sslctx);
	if (ILibDuktape_net_sslStream_sslIndex < 0)
	{
		ILibDuktape_net_sslStream_sslIndex = SSL_get_ex_new_index(0, "ILibDuktape_net_sslstream index", NULL, NULL, NULL);
	}
	SSL_set_ex_data(ptrs->ssl, ILibDuktape_net_sslStream_sslIndex, ptrs);
	
	duk_dup(ctx, 0);									// [input]
	duk_get_prop_string(ctx, -1, "pipe");				// [input][pipe]
	duk_swap_top(ctx, -2);								// [pipe][input/this]
	duk_push_heapptr(ctx, ptrs->sslStream_en_object);	// [pipe][input/this][stream]
	if (duk_pcall_method(ctx, 1) != 0)
	{
		duk_push_string(ctx, "sslStream: Could not pipe with input stream");
		duk_throw(ctx);
		return(DUK_RET_ERROR);
	}
	duk_pop(ctx);

	duk_push_heapptr(ctx, ptrs->sslStream_en_object);	// [stream]
	duk_get_prop_string(ctx, -1, "pipe");				// [stream][pipe]
	duk_swap_top(ctx, -2);								// [pipe][stream/this]
	duk_dup(ctx, 0);									// [pipe][stream/this][input]
	if (duk_pcall_method(ctx, 1) != 0)
	{
		duk_push_string(ctx, "sslSTream: Could not pipe the input stream");
		duk_throw(ctx);
		return(DUK_RET_ERROR);
	}
	duk_pop(ctx);

	// Set up the memory-buffer BIOs
	read = BIO_new(BIO_s_mem());
	write = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(read, -1);
	BIO_set_mem_eof_return(write, -1);
	SSL_set_bio(ptrs->ssl, read, write);

	if (isClient != 0)
	{
		SSL_set_connect_state(ptrs->ssl);
		status = SSL_do_handshake(ptrs->ssl);
		if (status <= 0) { status = SSL_get_error(ptrs->ssl, (int)status); }

		if (status == SSL_ERROR_WANT_READ)
		{
			while (BIO_ctrl_pending(write) > 0)
			{
				i = BIO_read(write, ptrs->encryptedBuffer, sizeof(ptrs->encryptedBuffer));
				ILibDuktape_DuplexStream_WriteData(ptrs->ds_encrypted, ptrs->encryptedBuffer, i);
			}
			// We're going to drop out now, becuase we need to check for received data
		}
	}
	else
	{
		SSL_set_accept_state(ptrs->ssl);
	}
	return 1;
}
#endif

ILibTransport_DoneState ILibDuktape_net_server_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
	return((ILibTransport_DoneState)ILibAsyncServerSocket_Send(NULL, session->connection, buffer, bufferLen, ILibAsyncSocket_MemoryOwnership_USER));
}
void ILibDuktape_net_server_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
	ILibAsyncServerSocket_Disconnect(NULL, session->connection);
}
void ILibDuktape_net_server_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
	ILibAsyncSocket_Pause(session->connection);
}
void ILibDuktape_net_server_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
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
void ILibDuktape_net_server_OnConnect(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void **user)
{
	ILibDuktape_net_server *ptr = (ILibDuktape_net_server*)((void**)ILibMemory_GetExtraMemory(AsyncServerSocketModule, ILibMemory_ASYNCSERVERSOCKET_CONTAINERSIZE))[0];
	ILibDuktape_net_server_session *session;

	if (ptr->OnConnection != NULL)
	{
		duk_push_heapptr(ptr->ctx, ptr->OnConnection);										// [func]
		duk_push_heapptr(ptr->ctx, ptr->self);												// [func][this]
		duk_push_object(ptr->ctx);															// [func][this][socket]
		ILibDuktape_CreateFinalizer(ptr->ctx, ILibDuktape_net_server_socket_Finalizer);
		duk_push_fixed_buffer(ptr->ctx, sizeof(ILibDuktape_net_server_session));			// [func][this][socket][buffer]
		session = (ILibDuktape_net_server_session*)Duktape_GetBuffer(ptr->ctx, -1, NULL);
		memset(session, 0, sizeof(ILibDuktape_net_server_session));
		duk_put_prop_string(ptr->ctx, -2, ILibDuktape_net_Server_Session_buffer);			// [func][this][socket]
		*user = session;
		session->ctx = ptr->ctx;
		session->connection = ConnectionToken;
		session->self = duk_get_heapptr(ptr->ctx, -1);
		session->emitter = ILibDuktape_EventEmitter_Create(ptr->ctx);

		ILibDuktape_EventEmitter_CreateEvent(session->emitter, "timeout", &(session->OnTimeout));

		session->stream = ILibDuktape_DuplexStream_Init(ptr->ctx, ILibDuktape_net_server_WriteSink, ILibDuktape_net_server_EndSink,
			ILibDuktape_net_server_PauseSink, ILibDuktape_net_server_ResumeSink, session);

		if (duk_pcall_method(ptr->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ptr->ctx, "net.server.OnConnect(): Exception"); }
		duk_pop(ptr->ctx);																	// ...
	}
}
void ILibDuktape_net_server_OnDisconnect(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
	ILibDuktape_DuplexStream_WriteEnd(session->stream);
}
void ILibDuktape_net_server_OnReceive(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, char* buffer, int *p_beginPointer, int endPointer, ILibAsyncServerSocket_OnInterrupt *OnInterrupt, void **user, int *PAUSE)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)*user;
	
	ILibDuktape_DuplexStream_WriteData(session->stream, buffer + *p_beginPointer, endPointer);
	*p_beginPointer = endPointer;
}
void ILibDuktape_net_server_OnInterrupt(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void *user)
{
}
void ILibDuktape_net_server_OnSendOK(ILibAsyncServerSocket_ServerModule AsyncServerSocketModule, ILibAsyncServerSocket_ConnectionToken ConnectionToken, void *user)
{
	ILibDuktape_net_server_session *session = (ILibDuktape_net_server_session*)user;
	ILibDuktape_DuplexStream_Ready(session->stream);
}
duk_ret_t ILibDuktape_net_server_listen(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	ILibDuktape_net_server *server = NULL;
	int i;

	unsigned short port = 80;
	int backlog = 0;
	struct sockaddr_in6 local;
	int maxConnections = 10;
	int initalBufferSize = 4096;

	memset(&local, 0, sizeof(struct sockaddr_in6));

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_net_Server_buffer);
	server = (ILibDuktape_net_server*)Duktape_GetBuffer(ctx, -1, NULL);

	if (duk_is_object(ctx, 0))
	{
		// Options
		port = (unsigned short)Duktape_GetIntPropertyValue(ctx, 0, "port", 0);
		backlog = Duktape_GetIntPropertyValue(ctx, 0, "backlog", 64);
		if (nargs > 1 && duk_is_function(ctx, 1))
		{
			// Callback
			ILibDuktape_EventEmitter_AddOn(server->emitter, "listening", duk_require_heapptr(ctx, 1));
		}
	}
	else
	{
		for (i = 0; i < nargs; ++i)
		{
			if (duk_is_number(ctx, i))
			{
				if (i == 0)
				{
					// Port
					port = (unsigned short)duk_get_int(ctx, i);
				}
				else
				{
					// Backlog
					backlog = duk_get_int(ctx, i);
				}
			}
			if (duk_is_function(ctx, i)) { ILibDuktape_EventEmitter_AddOn(server->emitter, "listening", duk_require_heapptr(ctx, i)); }
			if (duk_is_string(ctx, i))
			{
				ILibResolveEx((char*)duk_require_string(ctx, i), port, &local);
				if (local.sin6_family == AF_UNSPEC)
				{
					return(ILibDuktape_Error(ctx, "server.listen(): Unknown Host '%s'", duk_require_string(ctx, i)));
				}
			}
		}
	}

	server->server = ILibCreateAsyncServerSocketModuleWithMemory(Duktape_GetChain(ctx), maxConnections, port, initalBufferSize, 0,
		ILibDuktape_net_server_OnConnect, ILibDuktape_net_server_OnDisconnect, ILibDuktape_net_server_OnReceive,
		ILibDuktape_net_server_OnInterrupt, ILibDuktape_net_server_OnSendOK, sizeof(void*), sizeof(void*));
	((void**)ILibMemory_GetExtraMemory(server->server, ILibMemory_ASYNCSERVERSOCKET_CONTAINERSIZE))[0] = server;

	if (server->OnListening != NULL)
	{
		duk_push_heapptr(server->ctx, server->OnListening);		// [func]
		duk_push_heapptr(server->ctx, server->self);			// [func][this]
		if (duk_pcall_method(server->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(server->ctx, "net.server.listen(): Error "); }
		duk_pop(server->ctx);									// ...
	}

#ifndef WIN32
	ignore_result(backlog);
#endif

	return 0;
}
duk_ret_t ILibDuktape_net_server_Finalizer(duk_context *ctx)
{
	void *chain = Duktape_GetChain(ctx);
	ILibDuktape_net_server *server;
	duk_get_prop_string(ctx, 0, ILibDuktape_net_Server_buffer);
	server = (ILibDuktape_net_server*)Duktape_GetBuffer(ctx, -1, NULL);

	if (server != NULL && server->server != NULL && ILibIsChainBeingDestroyed(chain) == 0)
	{
		ILibAsyncServerSocket_RemoveFromChain(server->server);
	}

	return 0;
}
duk_ret_t ILibDuktape_net_createServer(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int i;
	ILibDuktape_net_server *server;

	duk_push_object(ctx);														// [server]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_net_server));					// [server][fbuffer]
	server = (ILibDuktape_net_server*)Duktape_GetBuffer(ctx, -1, NULL);
	memset(server, 0, sizeof(ILibDuktape_net_server));
	duk_put_prop_string(ctx, -2, ILibDuktape_net_Server_buffer);				// [server]

	server->self = duk_get_heapptr(ctx, -1);
	server->ctx = ctx;
	server->emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEvent(server->emitter, "close", &(server->OnClose));
	ILibDuktape_EventEmitter_CreateEvent(server->emitter, "connection", &(server->OnConnection));
	ILibDuktape_EventEmitter_CreateEvent(server->emitter, "error", &(server->OnError));
	ILibDuktape_EventEmitter_CreateEvent(server->emitter, "listening", &(server->OnListening));

	ILibDuktape_CreateInstanceMethod(ctx, "listen", ILibDuktape_net_server_listen, DUK_VARARGS);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_net_server_Finalizer);

	for (i = 0; i < 2 && i < nargs; ++i)
	{
		if (duk_is_function(ctx, i))
		{
			// Callback
			ILibDuktape_EventEmitter_AddOn(server->emitter, "connection", duk_require_heapptr(ctx, i));
		}
		if (duk_is_object(ctx, i))
		{
			// Options
		}
	}

	return 1;
}
void ILibDuktape_net_PUSH_net(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);														// [net]
	duk_push_pointer(ctx, chain);												// [net][chain]
	duk_put_prop_string(ctx, -2, "chain");										// [net]
	duk_push_c_function(ctx, ILibDuktape_net_socket_constructor, DUK_VARARGS);	// [net][constructor]
	duk_push_pointer(ctx, chain);												// [net][constructor][chain]
	duk_put_prop_string(ctx, -2, "chain");										// [net][constructor]
	duk_dup(ctx, -2);															// [net][constructor][net]
	duk_put_prop_string(ctx, -2, "net");										// [net][constructor]
	duk_put_prop_string(ctx, -2, "socket");										// [net]
	ILibDuktape_CreateInstanceMethod(ctx, "createServer", ILibDuktape_net_createServer, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "createConnection", ILibDuktape_net_createConnection, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "connect", ILibDuktape_net_createConnection, DUK_VARARGS);

#ifndef MICROSTACK_NOTLS
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "clientMode", 1, "createClientSslStream", ILibDuktape_net_sslStream_create, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "clientMode", 0, "createServerSslStream", ILibDuktape_net_sslStream_create, DUK_VARARGS);
#endif
}
duk_ret_t ILibDuktape_globalTunnel_end(duk_context *ctx)
{
	duk_push_heap_stash(ctx);
	duk_del_prop_string(ctx, -1, ILibDuktape_GlobalTunnel_Stash);
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
ILibDuktape_globalTunnel_data* ILibDuktape_GetNewGlobalTunnelEx(duk_context *ctx, int native)
{
	ILibDuktape_globalTunnel_data *retVal;

	if (native != 0) { duk_push_heap_stash(ctx); }						// [stash]

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
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_globalTunnel_finalizer);

	if (native != 0) { duk_pop(ctx); }									// ...
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
		duk_pop_2(ctx);													// [stash]
	}
	duk_pop(ctx);														// ...
	return retVal;
}

void ILibDuktape_net_init(duk_context * ctx, void * chain)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "net", ILibDuktape_net_PUSH_net);
	ILibDuktape_ModSearch_AddHandler(ctx, "global-tunnel", ILibDuktape_globalTunnel_PUSH);
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