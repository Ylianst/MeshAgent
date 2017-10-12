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
#include <WS2tcpip.h>
#endif

#include "microstack/ILibParsers.h"
#include "microstack/ILibAsyncServerSocket.h"
#include "ILibAsyncSocket_Duktape.h"
#include "ILibDuktape_Helpers.h"

extern char *Duktape_GetStashKey(void* value);
extern char* Duktape_GetBuffer(duk_context *ctx, duk_idx_t i, duk_size_t *bufLen);
duk_idx_t ILibAsyncSocket_Duktape_PUSH_AsyncSocketModule(duk_context *ctx, ILibAsyncSocket_SocketModule module);

typedef struct ILibAsyncSocket_Duktape_Bindings
{
	duk_context *context;
	void *OnData;
	void *OnConnect;
	void *OnDisconnect;
	void *OnSendOK;
}ILibAsyncSocket_Duktape_Bindings;

void ILibAsyncSocket_Duktape_OnData(ILibAsyncSocket_SocketModule socketModule, char* buffer, int *p_beginPointer, int endPointer, ILibAsyncSocket_OnInterrupt* OnInterrupt, void **user, int *PAUSE)
{
	ILibAsyncSocket_Duktape_Bindings *bindings = (ILibAsyncSocket_Duktape_Bindings*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;
	if (bindings->OnData == NULL) { *p_beginPointer = endPointer; return; }

	duk_push_heapptr(bindings->context, bindings->OnData);									// [ptr]
	ILibAsyncSocket_Duktape_PUSH_AsyncSocketModule(bindings->context, socketModule);		// [ptr][obj]
	if (duk_has_prop_string(bindings->context, -1, "BufferPtr"))
	{
		duk_get_prop_string(bindings->context, -1, "BufferPtr");							// [ptr][obj][buffer]
	}
	else
	{
		duk_push_external_buffer(bindings->context);										// [ptr][obj][buffer]
		duk_dup(bindings->context, -1);														// [ptr][obj][buffer][buffer]
		duk_put_prop_string(bindings->context, -3, "BufferPtr");							// [ptr][obj][buffer]
	}
	duk_config_buffer(bindings->context, -1, buffer + *p_beginPointer, endPointer);
	duk_push_int(bindings->context, endPointer);											// [ptr][obj][buffer][endPointer]
	if (duk_pcall(bindings->context, 3) == 0)													// [retVal]
	{
		if (duk_is_undefined(bindings->context, -1)) { *p_beginPointer = endPointer; duk_pop(bindings->context); }
		else if (duk_is_number(bindings->context, -1))
		{
			int val = duk_to_int(bindings->context, -1);
			if (val < 0) { *PAUSE = 1; }
			else { *p_beginPointer = val; }
			duk_pop(bindings->context);															// ...
		}
	}
	else
	{
		ILibDuktape_Process_UncaughtException(bindings->context);
		duk_pop(bindings->context);
	}
}
void ILibAsyncSocket_Duktape_OnConnect(ILibAsyncSocket_SocketModule socketModule, int Connected, void *user)
{
	ILibAsyncSocket_Duktape_Bindings *bindings = (ILibAsyncSocket_Duktape_Bindings*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;
	if (bindings->OnConnect != NULL)
	{
		duk_push_heapptr(bindings->context, bindings->OnConnect);							// [ptr]
		ILibAsyncSocket_Duktape_PUSH_AsyncSocketModule(bindings->context, socketModule);	// [ptr][obj]
		duk_push_int(bindings->context, Connected);											// [ptr][obj][Connected]
		if (duk_pcall(bindings->context, 2) != 0)											// [retVal]
		{
			ILibDuktape_Process_UncaughtException(bindings->context);
		}
		duk_pop(bindings->context);															// ...
	}
}
void ILibAsyncSocket_Duktape_OnDisconnect(ILibAsyncSocket_SocketModule socketModule, void *user)
{
	ILibAsyncSocket_Duktape_Bindings *bindings = (ILibAsyncSocket_Duktape_Bindings*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;
	if (bindings->OnDisconnect != NULL)
	{
		duk_push_heapptr(bindings->context, bindings->OnDisconnect);						// [ptr]
		ILibAsyncSocket_Duktape_PUSH_AsyncSocketModule(bindings->context, socketModule);	// [ptr][obj]
		if (duk_pcall(bindings->context, 1) != 0)											// [...]
		{
			ILibDuktape_Process_UncaughtException(bindings->context);
		}
		duk_pop(bindings->context);															//
	}
}
void ILibAsyncSocket_Duktape_OnSendOK(ILibAsyncSocket_SocketModule socketModule, void *user)
{
	ILibAsyncSocket_Duktape_Bindings *bindings = (ILibAsyncSocket_Duktape_Bindings*)((ILibChain_Link*)socketModule)->ExtraMemoryPtr;
	if (bindings->OnSendOK != NULL)
	{
		duk_push_heapptr(bindings->context, bindings->OnSendOK);							// [ptr]
		ILibAsyncSocket_Duktape_PUSH_AsyncSocketModule(bindings->context, socketModule);	// [ptr][obj]
		if (duk_pcall(bindings->context, 1) != 0)											// [...]
		{
			ILibDuktape_Process_UncaughtException(bindings->context);
		}
		duk_pop(bindings->context);															//
	}
}

duk_ret_t ILibAsyncSocket_Duktape_Create(duk_context *ctx)
{
	// ILibCreateAsyncSocketModuleWithMemory(void *Chain, int initialBufferSize, ILibAsyncSocket_OnData OnData, ILibAsyncSocket_OnConnect OnConnect, ILibAsyncSocket_OnDisconnect OnDisconnect, ILibAsyncSocket_OnSendOK OnSendOK, int UserMappedMemorySize)
	
	void *chain;
	int initialBufferSize = duk_require_int(ctx, 0);
	void *OnData = duk_is_null(ctx, 1) ? NULL :  duk_require_heapptr(ctx, 1);
	void *OnConnect = duk_is_null(ctx, 2) ? NULL : duk_require_heapptr(ctx, 2);
	void *OnDisconnect = duk_is_null(ctx, 3) ? NULL : duk_require_heapptr(ctx, 3);
	void *OnSendOK = duk_is_null(ctx, 4) ? NULL : duk_require_heapptr(ctx, 4);
	ILibAsyncSocket_SocketModule module;
	
	duk_push_current_function(ctx);						// [func]
	duk_get_prop_string(ctx, -1, "chain");				// [func][chain]
	chain = duk_to_pointer(ctx, -1);

	module = ILibCreateAsyncSocketModuleWithMemory(chain, initialBufferSize, ILibAsyncSocket_Duktape_OnData, ILibAsyncSocket_Duktape_OnConnect, ILibAsyncSocket_Duktape_OnDisconnect, ILibAsyncSocket_Duktape_OnSendOK, sizeof(ILibAsyncSocket_Duktape_Bindings));
	((ILibAsyncSocket_Duktape_Bindings*)((ILibChain_Link*)module)->ExtraMemoryPtr)->context = ctx;
	((ILibAsyncSocket_Duktape_Bindings*)((ILibChain_Link*)module)->ExtraMemoryPtr)->OnConnect = OnConnect;
	((ILibAsyncSocket_Duktape_Bindings*)((ILibChain_Link*)module)->ExtraMemoryPtr)->OnData = OnData;
	((ILibAsyncSocket_Duktape_Bindings*)((ILibChain_Link*)module)->ExtraMemoryPtr)->OnDisconnect = OnDisconnect;
	((ILibAsyncSocket_Duktape_Bindings*)((ILibChain_Link*)module)->ExtraMemoryPtr)->OnSendOK = OnSendOK;
	
	ILibAsyncSocket_Duktape_PUSH_AsyncSocketModule(ctx, module);			// [obj]
	duk_dup(ctx, 1);														// [obj][OnData]
	duk_put_prop_string(ctx, -2, "OnDataPtr");								// [obj]
	duk_dup(ctx, 2);														// [obj][OnConnect]
	duk_put_prop_string(ctx, -2, "OnConnectPtr");							// [obj]
	duk_dup(ctx, 3);														// [obj][OnDisconnect]
	duk_put_prop_string(ctx, -2, "OnDisconnectPtr");						// [obj]
	duk_dup(ctx, 4);														// [obj][OnSendOK]
	duk_put_prop_string(ctx, -2, "OnSendOKPtr");							// [obj]

	return 1;
}
duk_ret_t ILibAsyncSocket_Duktape_Send(duk_context *ctx)
{
	ILibAsyncSocket_SocketModule module;
	char *buffer = Duktape_GetBuffer(ctx, 0, NULL);
	int bufferLen = duk_require_int(ctx, 1);
	ILibAsyncSocket_SendStatus retVal;

	duk_push_this(ctx);								// [obj]
	duk_get_prop_string(ctx, -1, "ModulePtr");		// [obj][ptr]
	module = duk_to_pointer(ctx, -1);

	retVal = ILibAsyncSocket_Send(module, buffer, bufferLen, ILibAsyncSocket_MemoryOwnership_USER);
	duk_push_int(ctx, retVal);
	return 1;
}
duk_ret_t ILibAsyncSocket_Duktape_Disconnect(duk_context *ctx)
{
	ILibAsyncSocket_SocketModule module;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "ModulePtr");
	module = duk_to_pointer(ctx, -1);
	ILibAsyncSocket_Disconnect(module);
	return 0;
}
duk_ret_t ILibAsyncSocket_Duktape_ConnectTo(duk_context *ctx)
{
	char *localAddress;
	int localPort;
	char *remoteAddress;
	int remotePort;
	struct sockaddr_in6 localAddr;
	struct sockaddr_in6 remoteAddr;
	ILibAsyncSocket_SocketModule module;

	if (!duk_has_prop_string(ctx, 0, "IPAddress")) { duk_push_string(ctx, "Missing [Local] IPAddress Property"); duk_throw(ctx); return DUK_RET_ERROR; }
	if (!duk_has_prop_string(ctx, 0, "Port")) { duk_push_string(ctx, "Missing [Local] Port Property"); duk_throw(ctx); return DUK_RET_ERROR; }
	if (!duk_has_prop_string(ctx, 1, "IPAddress")) { duk_push_string(ctx, "Missing [Remote] IPAddress Property"); duk_throw(ctx); return DUK_RET_ERROR; }
	if (!duk_has_prop_string(ctx, 1, "Port")) { duk_push_string(ctx, "Missing [Remote] Port Property"); duk_throw(ctx); return DUK_RET_ERROR; }

	duk_get_prop_string(ctx, 0, "IPAddress");		
	localAddress = (char*)duk_to_string(ctx, -1);
	duk_get_prop_string(ctx, 0, "Port");
	localPort = duk_to_int(ctx, -1);
	duk_get_prop_string(ctx, 1, "IPAddress");
	remoteAddress = (char*)duk_to_string(ctx, -1);
	duk_get_prop_string(ctx, 1, "Port");
	remotePort = duk_to_int(ctx, -1);

	memset(&localAddr, 0, sizeof(struct sockaddr_in6));
	memset(&remoteAddr, 0, sizeof(struct sockaddr_in6));

	((struct sockaddr_in*)&localAddr)->sin_family = AF_INET;
	((struct sockaddr_in*)&localAddr)->sin_port = htons(localPort);
	ILibInet_pton(AF_INET, localAddress, &(((struct sockaddr_in*)&localAddr)->sin_addr));

	((struct sockaddr_in*)&remoteAddr)->sin_family = AF_INET;
	((struct sockaddr_in*)&remoteAddr)->sin_port = htons(remotePort);
	ILibInet_pton(AF_INET, remoteAddress, &(((struct sockaddr_in*)&remoteAddr)->sin_addr));

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "ModulePtr");
	module = duk_to_pointer(ctx, -1);

	ILibAsyncSocket_ConnectTo(module, (struct sockaddr*)&localAddr, (struct sockaddr*)&remoteAddr, NULL, NULL);
	return 0;
}
duk_idx_t ILibAsyncSocket_Duktape_PUSH_AsyncSocketModule(duk_context *ctx, ILibAsyncSocket_SocketModule module)
{
	char* key = Duktape_GetStashKey(module);

	duk_push_heap_stash(ctx);								// [stash]
	if (duk_has_prop_string(ctx, -1, key))
	{
		duk_get_prop_string(ctx, -1, key);					// [stash][obj]
		duk_swap_top(ctx, -2);								// [obj][stash]
		duk_pop(ctx);										// [obj]
		return duk_get_top_index(ctx);
	}

	duk_push_object(ctx);									// [stash][obj]
	duk_push_pointer(ctx, module);							// [stash][obj][pointer]
	duk_put_prop_string(ctx, -2, "ModulePtr");				// [stash][obj]


	duk_dup(ctx, -1);										// [stash][obj][obj]
	duk_put_prop_string(ctx, -3, key);						// [stash][obj]
	duk_swap_top(ctx, -2);									// [obj][stash]
	duk_pop(ctx);											// [obj]

	duk_push_c_function(ctx, ILibAsyncSocket_Duktape_Send, 2);			// [obj][func]
	duk_put_prop_string(ctx, -2, "Send");								// [obj]

	duk_push_c_function(ctx, ILibAsyncSocket_Duktape_Disconnect, 0);	// [obj][func]
	duk_put_prop_string(ctx, -2, "Disconnect");							// [obj]

	duk_push_c_function(ctx, ILibAsyncSocket_Duktape_ConnectTo, 2);
	duk_put_prop_string(ctx, -2, "ConnectTo");

	return duk_get_top_index(ctx);
}

void ILibAsyncSocket_DukTape_Init(duk_context * ctx, void * chain)
{
	duk_push_global_object(ctx);										// [Global]
	duk_push_c_function(ctx, ILibAsyncSocket_Duktape_Create, 5);		// [Global][func]
	duk_push_pointer(ctx, chain);										// [Global][func][chain]
	duk_put_prop_string(ctx, -2, "chain");								// [Global][func]
	duk_put_prop_string(ctx, -2, "ILibAsyncSocket_Create");				// [Global]
	duk_pop(ctx);														// 
}
