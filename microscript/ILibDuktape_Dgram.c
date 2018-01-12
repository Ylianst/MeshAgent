#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#include <Windows.h>
#include <WinBase.h>
#else
#include <sys/types.h>
#include <ifaddrs.h>
#endif

#include "ILibDuktape_Dgram.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_EventEmitter.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibAsyncUDPSocket.h"
#include "microstack/ILibAsyncSocket.h"
#include "microstack/ILibRemoteLogging.h"





#define ILibDuktape_DGRAM_CHAIN						"\xFF_DGRAM_CHAIN"
#define ILibDuktape_DGRAM_SOCKET_NATIVE				"\xFF_DGRAM_SOCKET_NATIVE"
#define ILibDuktape_DGRAM_MULTICAST_MEMBERSHIP_TYPE "\xFF_addRemove"

typedef struct ILibDuktape_DGRAM_DATA
{
	duk_context *ctx;
	ILibDuktape_EventEmitter *emitter;
	void *socketObject;
	void *dgramObject;
	void *chain;
	void *OnClose, *OnError, *OnListening, *OnMessage, *OnSendOK;
	ILibAsyncUDPSocket_SocketModule *mSocket;
}ILibDuktape_DGRAM_DATA;
typedef enum ILibDuktape_DGRAM_Config
{
	ILibDuktape_DGRAM_Config_NONE		= 0x00,
	ILibDuktape_DGRAM_Config_IPv4		= 0x01,
	ILibDuktape_DGRAM_Config_IPv6		= 0x02,
	ILibDuktape_DGRAM_Config_ReuseAddr	= 0x04
}ILibDuktape_DGRAM_Config;

ILibDuktape_DGRAM_DATA* ILibDuktape_DGram_GetPTR(duk_context *ctx)
{
	ILibDuktape_DGRAM_DATA *ptrs;

	duk_push_this(ctx);													// [socket]
	duk_get_prop_string(ctx, -1, ILibDuktape_DGRAM_SOCKET_NATIVE);		// [socket][ptrs]
	ptrs = (ILibDuktape_DGRAM_DATA*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop_2(ctx);														// ...
	return ptrs;
}
duk_ret_t ILibDuktape_Dgram_Finalizer(duk_context *ctx)
{
	return 0;
}
void ILibDuktape_Dgram_Socket_OnData(ILibAsyncUDPSocket_SocketModule socketModule, char* buffer, int bufferLength, struct sockaddr_in6 *remoteInterface, void *user, void *user2, int *PAUSE)
{
	ILibDuktape_DGRAM_DATA* ptrs = (ILibDuktape_DGRAM_DATA*)user;


	if (ptrs != NULL && ptrs->ctx != NULL && ptrs->OnMessage != NULL)
	{
		duk_push_heapptr(ptrs->ctx, ptrs->OnMessage);														// [func]
		duk_push_heapptr(ptrs->ctx, ptrs->socketObject);													// [func][this]
		duk_push_external_buffer(ptrs->ctx);
		duk_config_buffer(ptrs->ctx, -1, buffer, (duk_size_t)bufferLength);									// [func][this][buffer]
		duk_push_object(ptrs->ctx);																			// [func][this][buffer][rinfo]
		duk_push_string(ptrs->ctx, remoteInterface->sin6_family == AF_INET ? "IPv4" : "IPv6");				// [func][this][buffer][rinfo][family]
		duk_put_prop_string(ptrs->ctx, -2, "family");														// [func][this][buffer][rinfo]
		duk_push_string(ptrs->ctx, ILibRemoteLogging_ConvertAddress((struct sockaddr*)remoteInterface));	// [func][this][buffer][rinfo][address]
		duk_put_prop_string(ptrs->ctx, -2, "address");														// [func][this][buffer][rinfo]
		duk_push_int(ptrs->ctx, (int)ntohs(remoteInterface->sin6_port));									// [func][this][buffer][rinfo][port]
		duk_put_prop_string(ptrs->ctx, -2, "port");															// [func][this][buffer][rinfo]
		duk_push_int(ptrs->ctx, bufferLength);
		duk_put_prop_string(ptrs->ctx, -2, "size");

		if (duk_pcall_method(ptrs->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ptrs->ctx, "dgram.message() dispatch error"); }
		duk_pop(ptrs->ctx);																					// ...
	}
}
void ILibDuktape_Dgram_Socket_OnSendOK(ILibAsyncUDPSocket_SocketModule socketModule, void *user1, void *user2)
{
	ILibDuktape_DGRAM_DATA* ptrs = (ILibDuktape_DGRAM_DATA*)user1;
	if (ptrs != NULL && ptrs->ctx != NULL && ptrs->OnSendOK != NULL)
	{
		duk_push_heapptr(ptrs->ctx, ptrs->OnSendOK);		// [func]
		duk_push_heapptr(ptrs->ctx, ptrs->socketObject);	// [func][this]
		if (duk_pcall_method(ptrs->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ptrs->ctx, "net.dgram.socket.onSendOk"); }
	}
}

#ifndef WIN32
int ILibDuktape_DGram_getIPv6ScopeID(struct in6_addr *addr)
{
	int retVal = 0;
	struct ifaddrs *addrlist;
	struct ifaddrs *current;
	if (getifaddrs(&addrlist) == 0)
	{
		current = addrlist;
		while (current != NULL)
		{
			if (current->ifa_addr != NULL)
			{
				if (((struct sockaddr_in6*)current->ifa_addr)->sin6_family == AF_INET6 && memcmp(&(((struct sockaddr_in6*)current->ifa_addr)->sin6_addr), addr, 16)==0)
				{
					retVal = if_nametoindex(current->ifa_name);
					break;
				}
			}
			current = current->ifa_next;
		}
		freeifaddrs(addrlist);
	}
	return(retVal);
}
#endif
duk_ret_t ILibDuktape_DGram_Socket_bind(duk_context *ctx)
{
	int i;
	int config;
	int nargs = duk_get_top(ctx);
	ILibDuktape_DGRAM_DATA *ptrs = ILibDuktape_DGram_GetPTR(ctx);
	struct sockaddr_in6 local;
	void *bindCallback = NULL;
	unsigned short port = 0;

	duk_push_current_function(ctx);													// [socket][func]
	config = Duktape_GetIntPropertyValue(ctx, -1, "config", 0);

	char *address = ((config & ILibDuktape_DGRAM_Config_IPv6) == ILibDuktape_DGRAM_Config_IPv6) ? "::1" : "127.0.0.1";
																// [socket]

	if (duk_is_object(ctx, 0))
	{
		// 'options'
		port = (unsigned short)Duktape_GetIntPropertyValue(ctx, 0, "port", 0);
		address = Duktape_GetStringPropertyValue(ctx, 0, "address", address);
		if (duk_has_prop_string(ctx, 0, "exclusive"))
		{
			if (Duktape_GetBooleanProperty(ctx, 0, "exclusive", 0) == 0)
			{
				// SHARED
				if (!((config & ILibDuktape_DGRAM_Config_ReuseAddr) == ILibDuktape_DGRAM_Config_ReuseAddr))
				{
					// Set flag
					config |= ILibDuktape_DGRAM_Config_ReuseAddr;
				}
			}
			else
			{
				// EXCLUSIVE
				if ((config & ILibDuktape_DGRAM_Config_ReuseAddr) == ILibDuktape_DGRAM_Config_ReuseAddr)
				{
					// Clear flag
					config ^= ILibDuktape_DGRAM_Config_ReuseAddr;
				}
			}
		}
		if (nargs > 1) { bindCallback = duk_require_heapptr(ctx, 1); }
	}
	else
	{
		for (i = 0; i < nargs; ++i)
		{
			if (duk_is_number(ctx, i)) { port = (unsigned short)duk_require_int(ctx, i); }
			if (duk_is_string(ctx, i)) { address = (char*)duk_require_string(ctx, i); }
			if (duk_is_function(ctx, i)) { bindCallback = duk_require_heapptr(ctx, i); }
		}
	}

	if (ILibResolveEx(address, port, &local) != 0 || local.sin6_family == AF_UNSPEC) { return ILibDuktape_Error(ctx, "dgram.socket.bind(): Unable to resolve host: %s", address); }
#ifndef WIN32
	if (local.sin6_family == AF_INET6 && !IN6_IS_ADDR_UNSPECIFIED(&(local.sin6_addr)))
	{
		local.sin6_scope_id = ILibDuktape_DGram_getIPv6ScopeID(&(local.sin6_addr));
	}
#endif
	if (bindCallback != NULL) ILibDuktape_EventEmitter_AddOnce(ptrs->emitter, "listening", bindCallback);
	ptrs->mSocket = ILibAsyncUDPSocket_CreateEx(ptrs->chain,
		4096, (struct sockaddr*)&local,
		((config & ILibDuktape_DGRAM_Config_ReuseAddr) == ILibDuktape_DGRAM_Config_ReuseAddr) ? ILibAsyncUDPSocket_Reuse_SHARED : ILibAsyncUDPSocket_Reuse_EXCLUSIVE,
		ILibDuktape_Dgram_Socket_OnData, ILibDuktape_Dgram_Socket_OnSendOK, ptrs);

	if (ptrs->mSocket == NULL)
	{
#ifdef WIN32
		return(ILibDuktape_Error(ctx, "dgram.bind(): Cannot bind to (%s) Error (%d)", ILibRemoteLogging_ConvertAddress((struct sockaddr*)&local), WSAGetLastError()));
#else
		return(ILibDuktape_Error(ctx, "dgram.bind(): Cannot bind to (%s) Error (%d)", ILibRemoteLogging_ConvertAddress((struct sockaddr*)&local), errno));
#endif
	}

	if (ptrs->OnListening != NULL)
	{
		duk_push_heapptr(ctx, ptrs->OnListening);			// [func]
		duk_push_heapptr(ctx, ptrs->socketObject);			// [func][this]
		if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtException(ctx); }
		duk_pop(ctx);										// ...
	}

	return 0;
}

duk_ret_t ILibDuktape_DGram_multicastMembership(duk_context *ctx)
{
	ILibDuktape_DGRAM_DATA *ptrs = ILibDuktape_DGram_GetPTR(ctx);
	char *address = (char*)duk_require_string(ctx, 0);
	struct sockaddr_in6 multicastAddr;
	struct sockaddr_in6 localAddr;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_DGRAM_MULTICAST_MEMBERSHIP_TYPE);
	int isAdd = strcmp((char*)duk_get_string(ctx, -1), "add") == 0 ? 1 : 0;

	memset(&multicastAddr, 0, sizeof(struct sockaddr_in6));
	memset(&localAddr, 0, sizeof(struct sockaddr_in6));

	ILibResolveEx(address, 0, &multicastAddr);

	if (isAdd != 0)
	{
		switch (multicastAddr.sin6_family)
		{
		case AF_INET:
			ILibAsyncUDPSocket_JoinMulticastGroupV4(ptrs->mSocket, (struct sockaddr_in*)&multicastAddr, (struct sockaddr*)&localAddr);
			break;
		case AF_INET6:
			ILibAsyncUDPSocket_JoinMulticastGroupV6(ptrs->mSocket, &multicastAddr, 0);
			break;
		default:
			return ILibDuktape_Error(ctx, "dgram.addMembership(): Invalid Multicast Address '%s'", address);
			break;
		}
	}
	else
	{
		switch (multicastAddr.sin6_family)
		{
		case AF_INET:
			ILibAsyncUDPSocket_DropMulticastGroupV4(ptrs->mSocket, (struct sockaddr_in*)&multicastAddr, (struct sockaddr*)&localAddr);
			break;
		case AF_INET6:
			ILibAsyncUDPSocket_DropMulticastGroupV6(ptrs->mSocket, &multicastAddr, 0);
			break;
		default:
			return ILibDuktape_Error(ctx, "dgram.dropMembership(): Invalid Multicast Address '%s'", address);
			break;
		}
	}
	return 0;
}

duk_ret_t ILibDuktape_DGram_setMulticastTTL(duk_context *ctx)
{
	ILibDuktape_DGRAM_DATA *ptrs = ILibDuktape_DGram_GetPTR(ctx);
	ILibAsyncUDPSocket_SetMulticastTTL(ptrs->mSocket, duk_require_int(ctx, 0));
	return 0;
}
duk_ret_t ILibDuktape_DGram_setMulticastLoopback(duk_context *ctx)
{
	ILibDuktape_DGRAM_DATA *ptrs = ILibDuktape_DGram_GetPTR(ctx);
	ILibAsyncUDPSocket_SetMulticastLoopback(ptrs->mSocket, duk_require_boolean(ctx, 0) ? 1 : 0);
	return 0;
}
duk_ret_t ILibDuktape_DGram_send(duk_context *ctx)
{
	/*
	msg <Buffer> | <Uint8Array> | <string> | <array> Message to be sent
	offset <number> Integer.Optional.Offset in the buffer where the message starts.
	length <number> Integer.Optional.Number of bytes in the message.
	port <number> Integer.Destination port.
	address <string> Destination hostname or IP address.Optional.
	callback <Function> Called when the message has been sent.Optional.*/

	int nargs = duk_get_top(ctx);
	ILibDuktape_DGRAM_DATA *ptrs = ILibDuktape_DGram_GetPTR(ctx);
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = 0;
	unsigned short port = 0;
	int i;
	struct sockaddr_in6 local;
	local.sin6_family = AF_UNSPEC;
	void *onSendOk = NULL;

	if (nargs >= 4 && duk_is_number(ctx, 1) && duk_is_number(ctx, 2))
	{
		offset = duk_require_int(ctx, 1);
		bufferLen = (duk_size_t)duk_require_int(ctx, 2);
		port = (unsigned short)duk_require_int(ctx, 3);
		for (i = 4; i < nargs; ++i)
		{
			if (duk_is_string(ctx, i)) { ILibResolveEx((char*)duk_require_string(ctx, i), port, &local); }
			if (duk_is_function(ctx, i)) { onSendOk = duk_require_heapptr(ctx, i); }
		}
	}
	else
	{
		port = (unsigned short)duk_require_int(ctx, 1);
		for (i = 2; i < nargs; ++i)
		{
			if (duk_is_string(ctx, i)) { ILibResolveEx((char*)duk_require_string(ctx, i), port, &local); }
			if (duk_is_function(ctx, i)) { onSendOk = duk_require_heapptr(ctx, i); }
		}
	}

	if (local.sin6_family == AF_UNSPEC)
	{
		ILibAsyncUDPSocket_GetLocalInterface(ptrs->mSocket, (struct sockaddr*)&local);
		if (local.sin6_family == AF_INET6)
		{
			ILibResolveEx("::1", port, &local);
		}
		else
		{
			ILibResolveEx("127.0.0.1", port, &local);
		}
	}

	switch (ILibAsyncUDPSocket_SendTo(ptrs->mSocket, (struct sockaddr*)&local, buffer + offset, (int)bufferLen, ILibAsyncSocket_MemoryOwnership_USER))
	{
		case ILibAsyncSocket_ALL_DATA_SENT:
			if (onSendOk != NULL)
			{
				duk_push_heapptr(ctx, onSendOk);			// [func]
				duk_push_heapptr(ctx, ptrs->socketObject);	// [func][this]
				if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "net.dgram.send.callback(): Error "); }
				duk_pop(ctx);								// ...
			}
			break;
		case ILibAsyncSocket_NOT_ALL_DATA_SENT_YET:
			if (onSendOk != NULL) { ILibDuktape_EventEmitter_AddOnce(ptrs->emitter, "flushed", onSendOk); }
			break;
		default:
			// Error Occured
			if (onSendOk != NULL)
			{
				duk_push_heapptr(ctx, onSendOk);			// [func]
				duk_push_heapptr(ctx, ptrs->socketObject);	// [func][this]
				duk_push_error_object(ctx, DUK_ERR_TYPE_ERROR, "net.dgram.send(): Attempted to send on a closed socket");
				if (duk_pcall_method(ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "net.dgram.send.callback(): Error "); }
				duk_pop(ctx);								// ...
			}
			else if(ptrs->OnError != NULL)
			{
				duk_push_heapptr(ctx, ptrs->OnError);		// [func]
				duk_push_heapptr(ctx, ptrs->socketObject);	// [func][this]
				duk_push_error_object(ctx, DUK_ERR_TYPE_ERROR, "net.dgram.send(): Attempted to send on a closed socket");
				if (duk_pcall_method(ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "net.dgram.onError(): Error "); }
				duk_pop(ctx);								// ...
			}
			break;
	}

	return 0;
}
duk_ret_t ILibDuktape_DGram_setBroadcast(duk_context *ctx)
{
	ILibDuktape_DGRAM_DATA *ptrs = ILibDuktape_DGram_GetPTR(ctx);
	int enable = (int)duk_require_boolean(ctx, 0);
	ILibAsyncUDPSocket_SetBroadcast(ptrs->mSocket, enable);
	return(0);
}
duk_ret_t ILibDuktape_DGram_setTTL(duk_context *ctx)
{
	return ILibDuktape_Error(ctx, "Not implemented");
}
duk_ret_t ILibDuktape_DGram_setMulticastInterface(duk_context *ctx)
{
	ILibDuktape_DGRAM_DATA *ptrs = ILibDuktape_DGram_GetPTR(ctx);
	struct sockaddr_in addr;
	char *str = (char*)duk_require_string(ctx, 0);

	memset(&addr, 0, sizeof(struct sockaddr_in));
	ILibInet_pton(AF_INET, str, &(addr.sin_addr));

	ILibAsyncUDPSocket_SetMulticastInterface(ptrs->mSocket, (struct sockaddr*)&addr);
	return(0);
}
duk_ret_t ILibDuktape_Dgram_socket_close(duk_context *ctx)
{
	if (duk_get_top(ctx) > 0 && duk_is_function(ctx, 0)) { ILibDuktape_EventEmitter_AddOnce(ILibDuktape_EventEmitter_GetEmitter_fromThis(ctx), "close", duk_require_heapptr(ctx, 0)); }
	
	duk_push_this(ctx);												// [socket]
	duk_get_prop_string(ctx, -1, ILibDuktape_DGRAM_SOCKET_NATIVE);	// [socket][ptr]
	ILibDuktape_DGRAM_DATA *data = (ILibDuktape_DGRAM_DATA*)Duktape_GetBuffer(ctx, -1, NULL);
	ILibAsyncSocket_Disconnect(data->mSocket);
	
	return(0);
}
duk_ret_t ILibDuktape_DGram_createSocket(duk_context *ctx)
{
	ILibDuktape_DGRAM_Config config = ILibDuktape_DGRAM_Config_NONE;
	ILibDuktape_DGRAM_DATA *ptrs;
	void *chain;
	char *typ = duk_is_string(ctx, 0) ? (char*)duk_require_string : Duktape_GetStringPropertyValue(ctx, 0, "type", "udp4");
	void *dgram;

	duk_push_this(ctx);													// [dgram]
	dgram = duk_get_heapptr(ctx, -1);
	duk_get_prop_string(ctx, -1, ILibDuktape_DGRAM_CHAIN);				// [dgram][chain]
	chain = duk_get_pointer(ctx, -1);

	if (strncmp(typ, "udp4", 4) == 0) { config |= ILibDuktape_DGRAM_Config_IPv4; }
	else if (strncmp(typ, "udp6", 4) == 0) { config |= ILibDuktape_DGRAM_Config_IPv6; }
	else { return ILibDuktape_Error(ctx, "dgram.createSocket(): Invalid 'type' specified: %s", typ); }

	if (!duk_is_string(ctx, 0)) { if (Duktape_GetBooleanProperty(ctx, 0, "reuseAddr", 0) != 0) { config |= ILibDuktape_DGRAM_Config_ReuseAddr; } }

	/**************************************************************************************/
	duk_push_object(ctx);												// [socket]
	ILibDuktape_WriteID(ctx, "dgram.socket");
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_Dgram_Finalizer);		
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_DGRAM_DATA));			// [socket][native]
	ptrs = (ILibDuktape_DGRAM_DATA*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_DGRAM_SOCKET_NATIVE);		// [socket]
	memset(ptrs, 0, sizeof(ILibDuktape_DGRAM_DATA));

	ptrs->ctx = ctx;
	ptrs->chain = chain;
	ptrs->socketObject = duk_get_heapptr(ctx, -1);
	ptrs->dgramObject = dgram;
	ptrs->emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_EventEmitter_CreateEvent(ptrs->emitter, "close", &(ptrs->OnClose));
	ILibDuktape_EventEmitter_CreateEvent(ptrs->emitter, "error", &(ptrs->OnError));
	ILibDuktape_EventEmitter_CreateEvent(ptrs->emitter, "listening", &(ptrs->OnListening));
	ILibDuktape_EventEmitter_CreateEvent(ptrs->emitter, "message", &(ptrs->OnMessage));
	ILibDuktape_EventEmitter_CreateEvent(ptrs->emitter, "flushed", &(ptrs->OnSendOK));

	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "config", config, "bind", ILibDuktape_DGram_Socket_bind, DUK_VARARGS);

	ILibDuktape_CreateInstanceMethodWithStringProperty(ctx, ILibDuktape_DGRAM_MULTICAST_MEMBERSHIP_TYPE, "add", "addMembership", ILibDuktape_DGram_multicastMembership, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithStringProperty(ctx, ILibDuktape_DGRAM_MULTICAST_MEMBERSHIP_TYPE, "remove", "dropMembership", ILibDuktape_DGram_multicastMembership, DUK_VARARGS);


	ILibDuktape_CreateProperty_InstanceMethod(ctx, "close", ILibDuktape_Dgram_socket_close, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "send", ILibDuktape_DGram_send, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "setBroadcast", ILibDuktape_DGram_setBroadcast, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "setMulticastLoopback", ILibDuktape_DGram_setMulticastLoopback, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "setMulticastTTL", ILibDuktape_DGram_setMulticastTTL, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "setMulticastInterface", ILibDuktape_DGram_setMulticastInterface, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "setTTL", ILibDuktape_DGram_setTTL, 1);

	return 1;
}

void ILibDuktape_DGram_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);										// [dgram]
	duk_push_pointer(ctx, chain);								// [dgram][chain]
	duk_put_prop_string(ctx, -2, ILibDuktape_DGRAM_CHAIN);		// [dgram]
	ILibDuktape_CreateInstanceMethod(ctx, "createSocket", ILibDuktape_DGram_createSocket, DUK_VARARGS);
}

void ILibDuktape_DGram_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "dgram", ILibDuktape_DGram_PUSH);
}

#ifdef __DOXY__

/*!
\brief UDP Datagram Implementation
*/
class dgram
{
public:
	/*!
	\brief Create's a Socket object.
	*
	Once the socket is created, calling bind() will instruct the Socket to begin listening for datagram messages.\n
	When address and port are not passed to bind() the method will bind the Socket to the "all interfaces" address on a random port\n
	The bound address and port can be retrieved using address().address and address().port.
	\param options <Object>\n
	<b>type</b> \<String\> Required. The family of socket. Must be either 'udp4' or 'udp6'.\n
	<b>reuseAddr</b> <boolean> Optional If specified, will set the reuseAddr flag appropriately.
	\return New Socket instance.
	*/
	static Socket createSocket(options[, callback]);
	/*!
	\implements EventEmitter
	\brief dgram.Socket is an EventEmitter that encapsulates datagram functionality.
	*/
	class Socket
	{
	public:
		/*!
		\brief Event is emitted after a Socket is closed with close(). Once triggered, no new 'message' events will be emitted on this Socket.
		*/
		void close;
		/*!
		\brief Event is emitted whenever any error occurs. The event handler function is passed a single Error object.
		\param err <Error>
		*/
		void error;
		/*!
		\brief Event is emitted whenever a Socket begins listening for datagram messages. This occurs as soon as UDP sockets are created.
		*/
		void listening;
		/*!
		\brief Event is emitted when a new datagram is available on a Socket.
		\param msg <Buffer> The message
		\param rinfo <Object> Remote Address Information\n
		<b>address</b> \<String\> Sender Address\n
		<b>family</b> \<String\> Address Family ('IPv4' or 'IPv6')\n
		<b>port</b> <Number> Sender Port\n
		<b>size</b> <Number> Message Size\n
		*/
		void message;
		/*!
		\brief Event emitted when send buffer is empty
		*/
		void flushed;

		/*!
		\brief Causes the Socket to listen for datagram messages on a named port and optional address
		\param options <Object> Required. Supports the following properties:\n
		<b>port</b> <Number> Optional\n
		<b>address</b> \<String\> Optional\n
		<b>exclusive</b> <boolean> Optional\n
		\param callback <func> Optional callback that will be set as one time listener to 'listening' event.
		*/
		void bind(options[, callback]);
		/*!
		\brief Join a multicast group at the given multicastAddress and multicastInterface using the IP_ADD_MEMBERSHIP socket option
		\param multicastAddress \<String\> 
		\param multicastInterface \<String\> Optional
		*/
		void addMembership(multicastAddress[, multicastInterface]);
		/*!
		\brief Leave a multicast group at multicastAddress using the IP_DROP_MEMBERSHIP socket option. 
		\param multicastAddress \<String\>
		\param multicastInterface \<String\> Optional
		*/
		void dropMembership(multicastAddress[, multicastInterface]);

		/*!
		\brief Send a datagram on the socket. The destination port and address must be specified.
		\param msg \<Buffer\|String\> Message to be sent
		\param offset <Integer> Optional. Offset in the buffer where the message starts
		\param length <Integer> Optional. Number of bytes in the message
		\param port <Integer> Destination port
		\param address \<String\> Optional. Destination hostname or IP Address.
		\param callback <func> Optional. Set as one time listener for 'flush' event.
		*/
		void send(msg, [offset, length, ] port[, address][, callback]);
		/*!
		\brief Sets or clears the SO_BROADCAST socket option. 
		\param flag <boolean> When set to true, UDP packets may be sent to a local interface's broadcast address
		*/
		void setBroadcast(flag);
		/*!
		\brief Sets or clears the IP_MULTICAST_LOOP socket option. 
		\param flag <boolean> When set to true, multicast packets will also be received on the local interface.
		*/
		void setMulticastLoopback(flag);
		/*!
		\brief Sets the default outgoing multicast interface of the socket to a chosen interface or back to system interface selection. 
		\param multicastInterface \<String\> Must be a valid string representation of an IP from the socket's family.
		*/
		void setMulticastInterface(multicastInterface);
		/*!
		\brief Sets the IP_MULTICAST_TTL socket option
		\param ttl <Integer>
		*/
		void setMulticastTTL(ttl);
		/*!
		\brief Sets the IP_TTL socket option
		\param ttl <Integer>
		*/
		void setTTL(ttl)
	};

};


#endif