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

#include "ILibWebClient_Duktape.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibWebClient.h"
#include "ILibDuktape_Helpers.h"

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

extern duk_idx_t ILibWebServer_DukTape_Push_PacketHeader(duk_context *ctx, ILibHTTPPacket *packet);

typedef struct ILibWebClient_DukTape_WebSocketCallbacks
{
	void *OnMessage;
	void *OnClose;
	void *OnSendOK;
}ILibWebClient_DukTape_WebSocketCallbacks;

duk_idx_t ILibWebClient_DukTape_Push_WebRequestManager(duk_context *ctx, void* wcm);
duk_ret_t ILibWebClient_DukTape_RequestToken_Cancel(duk_context *ctx)
{
	void *token;
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "TokenPtr");
	token = duk_to_pointer(ctx, -1);
	ILibWebClient_CancelRequest(token); //ToDo: Check to see if we should delete from stash here, or from somewhere else
	return 0;
}

duk_idx_t ILibWebClient_DukTape_Push_RequestToken(duk_context *ctx, ILibWebClient_RequestToken token)
{
	char *key = Duktape_GetStashKey(token);
	duk_push_heap_stash(ctx);
	if (duk_has_prop_string(ctx, -1, key) != 0)
	{
		duk_get_prop_string(ctx, -1, key);	// [stash][obj]
		duk_swap_top(ctx, -2);				// [obj][stash]
		duk_pop(ctx);						// [obj]
		return(duk_get_top_index(ctx));
	}
	duk_push_object(ctx);														// [stash][obj]
	duk_push_pointer(ctx, token);												// [stash][obj][ptr]
	duk_put_prop_string(ctx, -2, "TokenPtr");									// [stash][obj]
	duk_push_c_function(ctx, ILibWebClient_DukTape_RequestToken_Cancel, 0);		// [stash][obj][func]
	duk_put_prop_string(ctx, -2, "Cancel");										// [stash][obj]

	duk_dup(ctx, -1);					// [stash][obj1][obj2]
	duk_put_prop_string(ctx, -3, key);	// [stash][obj2]
	duk_swap_top(ctx, -2);				// [obj2][stash]
	duk_pop(ctx);						// [obj2]
	return(duk_get_top_index(ctx));
}

duk_ret_t ILibWebClient_DukTape_StateObject_Resume(duk_context *ctx)
{
	return 0;
}
duk_ret_t ILibWebClient_DukTape_StateObject_Digest_NeedAuthenticate(duk_context *ctx)
{
	ILibWebClient_StateObject wcdo;
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "StatePtr");
	wcdo = (ILibWebClient_StateObject)duk_to_pointer(ctx, -1);
	duk_push_int(ctx, ILibWebClient_Digest_NeedAuthenticate(wcdo));	
	return 1;
}
duk_ret_t ILibWebClient_DukTape_StateObject_Digest_GetRealm(duk_context *ctx)
{
	char *realm;
	ILibWebClient_StateObject wcdo;
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "StatePtr");
	wcdo = (ILibWebClient_StateObject)duk_to_pointer(ctx, -1);
	realm = ILibWebClient_Digest_GetRealm(wcdo);
	duk_push_string(ctx, realm != NULL ? realm : "");
	return 1;
}
duk_ret_t ILibWebClient_DukTape_StateObject_Digest_AddAuthenticationHeader(duk_context *ctx)
{
	ILibWebClient_StateObject wcdo;
	char *username;
	char *password;
	ILibHTTPPacket *packet;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "StatePtr");
	wcdo = (ILibWebClient_StateObject)duk_to_pointer(ctx, -1);

	duk_get_prop_string(ctx, 0, "PacketPtr");
	packet = (ILibHTTPPacket*)duk_to_pointer(ctx, -1);
	username = (char*)duk_require_string(ctx, 1);
	password = (char*)duk_require_string(ctx, 2);

	ILibWebClient_GenerateAuthenticationHeader(wcdo, packet, username, password);
	return 0;
}
duk_idx_t ILibWebClient_DukTape_WebClient_WebSocket_Send(duk_context *ctx)
{
	int bufferType = duk_require_int(ctx, 0);
	char *buffer = Duktape_GetBuffer(ctx, 1, NULL);
	int bufferLen = duk_require_int(ctx, 2);
	int fragmentFlags = duk_require_int(ctx, 3);
	ILibWebClient_StateObject wcdo;
	ILibAsyncSocket_SendStatus retVal;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "StatePtr");
	wcdo = (ILibWebClient_StateObject)duk_to_pointer(ctx, -1);

	retVal = ILibWebClient_WebSocket_Send(wcdo, bufferType, buffer, bufferLen, ILibAsyncSocket_MemoryOwnership_USER, fragmentFlags);
	duk_push_int(ctx, retVal);
	return 1;
}
duk_idx_t ILibWebClient_DukTape_Push_StateObject(duk_context *ctx, ILibWebClient_StateObject WebStateObject)
{
	char* key = Duktape_GetStashKey(WebStateObject);

	duk_push_heap_stash(ctx);						// [stash]
	if (duk_has_prop_string(ctx, -1, key) != 0)
	{
		duk_get_prop_string(ctx, -1, key);			// [stash][obj]
		duk_swap_top(ctx, -2);						// [obj][stash]
		duk_pop(ctx);								// [obj]
		return(duk_get_top_index(ctx));
	}

	duk_push_object(ctx);							// [stash][obj]
	duk_push_pointer(ctx, WebStateObject);			// [stash][obj][ptr]
	duk_put_prop_string(ctx, -2, "StatePtr");		// [stash][obj]
	duk_push_external_buffer(ctx);					// [stash][obj][buffer]
	duk_put_prop_string(ctx, -2, "BufferPtr");		// [stash][obj]
	duk_push_c_function(ctx, ILibWebClient_DukTape_StateObject_Resume, 0);						// [stash][obj][func]
	duk_put_prop_string(ctx, -2, "Resume");														// [stash][obj]
	duk_push_c_function(ctx, ILibWebClient_DukTape_StateObject_Digest_NeedAuthenticate, 0);		// [stash][obj][func]
	duk_put_prop_string(ctx, -2, "Digest_NeedAuthenticate");									// [stash][obj]
	duk_push_c_function(ctx, ILibWebClient_DukTape_StateObject_Digest_GetRealm, 0);				// [stash][obj][func]
	duk_put_prop_string(ctx, -2, "Digest_GetRealm");											// [stash][obj]
	duk_push_c_function(ctx, ILibWebClient_DukTape_StateObject_Digest_AddAuthenticationHeader, 3);		// [stash][obj][func]
	duk_put_prop_string(ctx, -2, "Digest_AddAuthenticationHeader");										// [stash][obj]
	duk_push_c_function(ctx, ILibWebClient_DukTape_WebClient_WebSocket_Send, 4);									// [stash][obj][func]
	duk_put_prop_string(ctx, -2, "WebSocket_Send");														// [stash][obj]


	duk_dup(ctx, -1);														// [stash][obj][obj]
	duk_put_prop_string(ctx, -3, key);										// [stash][obj]
	duk_swap_top(ctx, -2);													// [obj][stash]
	duk_pop(ctx);															// [obj]
	return(duk_get_top_index(ctx));				
}

void ILibWebClient_DukTape_OnResponse(ILibWebClient_StateObject WebStateObject, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, ILibWebClient_ReceiveStatus recvStatus, void *user1, void *user2, int *PAUSE)
{
	duk_context *ctx = (duk_context*)user1;
	void *OnResp = user2;
	int retVal;

	duk_push_heapptr(ctx, OnResp);									// [Func]
	ILibWebClient_DukTape_Push_StateObject(ctx, WebStateObject);	// [Func][state]
	duk_push_int(ctx, InterruptFlag);								// [Func][state][Interrupt]
	ILibWebServer_DukTape_Push_PacketHeader(ctx, header);			// [Func][state][Interrupt][header]
	duk_get_prop_string(ctx, -3, "BufferPtr");						// [Func][state][Interrupt][header][buffer]
	duk_config_buffer(ctx, -1, bodyBuffer + *beginPointer, endPointer - *beginPointer);
	duk_push_int(ctx, endPointer - *beginPointer);					// [Func][state][Interrupt][header][buffer][len]
	duk_push_int(ctx, recvStatus);									// [Func][state][Interrupt][header][buffer][len][status]
	if (duk_pcall(ctx, 6) == 0)
	{
		if (duk_get_type(ctx, -1) == DUK_TYPE_UNDEFINED)
		{
			retVal = duk_to_int(ctx, -1);
			if (retVal < 0)
			{
				*PAUSE = 1;
			}
			else
			{
				*beginPointer = retVal;
			}
		}
		else
		{
			*beginPointer = endPointer;
		}
	}
	else
	{
		ILibDuktape_Process_UncaughtException(ctx);
	}
	duk_pop(ctx);


	if (recvStatus == ILibWebClient_ReceiveStatus_Complete)
	{
		// Done, so we can clear our reference in the heap stash
		ILibWebClient_RequestToken token = ILibWebClient_GetRequestToken_FromStateObject(WebStateObject);

		duk_push_heap_stash(ctx);
		duk_del_prop_string(ctx, -1, Duktape_GetStashKey(WebStateObject));
		if (token != NULL)
		{
			duk_del_prop_string(ctx, -1, Duktape_GetStashKey(token));
		}
		duk_pop(ctx);
	}
}

duk_idx_t ILibWebClient_DukTape_PipelineRequest(duk_context *ctx)
{
	int args = duk_get_top(ctx);
	ILibHTTPPacket *packet;
	char *addr;
	int port;
	struct sockaddr_in6* dest;
	void *wcm;
	ILibWebClient_OnResponse OnResp = NULL;
	ILibWebClient_RequestToken token;

	if (args < 3) { duk_push_string(ctx, "Too few arguments"); duk_throw(ctx); return(DUK_RET_ERROR); }
	if (duk_get_prop_string(ctx, 1, "PacketPtr") == 0) { duk_push_string(ctx, "Invalid Argument[packet]"); duk_throw(ctx); return(DUK_RET_ERROR); }
	packet = (ILibHTTPPacket*)duk_to_pointer(ctx, -1);
	
	if (duk_get_prop_string(ctx, 0, "IPAddress") == 0) { duk_push_string(ctx, "Invalid Argument[RemoteEndpoint]"); duk_throw(ctx); return(DUK_RET_ERROR); }
	addr = (char*)duk_to_string(ctx, -1);
	if (duk_get_prop_string(ctx, 0, "Port") == 0) { duk_push_string(ctx, "Invalid Argument[RemoteEndpoint]"); duk_throw(ctx); return(DUK_RET_ERROR); }
	port = duk_to_int(ctx, -1);

	dest = Duktape_IPAddress4_FromString(addr, (unsigned short)port);
	OnResp = duk_require_heapptr(ctx, 2);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "ManagerPtr");
	wcm = duk_to_pointer(ctx, -1);
	duk_pop(ctx);
	duk_dup(ctx, 2);
	duk_put_prop_string(ctx, -2, "OnResponsePtr");

	token = ILibWebClient_PipelineRequest(wcm, (struct sockaddr*)dest, packet, ILibWebClient_DukTape_OnResponse, ctx, OnResp);
	ILibWebClient_DukTape_Push_RequestToken(ctx, token);
	return 1;
}

duk_idx_t ILibWebClient_DukTape_Push_WebRequestManager(duk_context *ctx, void* wcm)
{
	char* key = Duktape_GetStashKey(wcm);

	duk_push_heap_stash(ctx);
	if (duk_has_prop_string(ctx, -1, key))
	{
		duk_get_prop_string(ctx, -1, key);
	}
	else
	{
		duk_push_object(ctx);
		duk_push_pointer(ctx, wcm);
		duk_put_prop_string(ctx, -2, "ManagerPtr");

		duk_push_c_function(ctx, ILibWebClient_DukTape_PipelineRequest, DUK_VARARGS);
		duk_push_pointer(ctx, wcm);
		duk_put_prop_string(ctx, -2, "ManagerPtr");
		duk_put_prop_string(ctx, -2, "PipelineRequest");
	}
	
	duk_swap_top(ctx, -2);	// Swap Stash and Object, so stash is on top
	duk_pop(ctx);			// Pop Stash off stack, leaving the object at top
	return(duk_get_top_index(ctx));
}

duk_ret_t ILibWebClient_DukTape_Create(duk_context *ctx)
{
	int poolSize = duk_require_int(ctx, 0);
	void *chain;
	ILibWebClient_RequestManager wcm;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "chain");
	chain = duk_to_pointer(ctx, -1);
	duk_pop_2(ctx); // Pop Chain & Function

	wcm = ILibCreateWebClient(poolSize, chain);
	ILibWebClient_DukTape_Push_WebRequestManager(ctx, wcm);
	return 1;
}

duk_ret_t ILibWebClient_DukTape_WebSocket_Finalizer(duk_context *ctx)
{
	return 0;
}
duk_ret_t ILibWebClient_DukTape_WebSocket_Ptr_Setter(duk_context *ctx)
{
	if (!duk_is_null(ctx, 0) && !duk_is_undefined(ctx, 0))
	{
		duk_push_this(ctx);								// [wsock]
		duk_push_current_function(ctx);					// [wsock][func]
		duk_get_prop_string(ctx, -1, "SetterKey");		// [wsock][func][key]
		duk_swap_top(ctx, -2);							// [wsock][key][func]
		duk_pop(ctx);									// [wsock][key]
		duk_dup(ctx, 0);								// [wsock][key][Ptr]
		duk_put_prop(ctx, -3);							// [wsock]
	}
	return 0;
}

void ILibWebClient_DukTape_WebSocket_OnResponse(ILibWebClient_StateObject WebStateObject, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, ILibWebClient_ReceiveStatus recvStatus, void *user1, void *user2, int *PAUSE)
{
	duk_context *ctx = (duk_context*)user1;

	if (header == NULL || (header->StatusCode != 101 && recvStatus == ILibWebClient_ReceiveStatus_Complete))
	{
		duk_push_heapptr(ctx, user2);						// [wsock]
		if (duk_has_prop_string(ctx, -1, "OnErrorPtr"))
		{
			duk_get_prop_string(ctx, -1, "OnErrorPtr");		// [wsock][OnError]
			duk_swap_top(ctx, -2);							// [OnError][this]

			if (duk_pcall_method(ctx, 0) != 0)				// [retVal]
			{
				ILibDuktape_Process_UncaughtException(ctx);
			}
			duk_pop(ctx);
			return;
		}
		duk_pop(ctx);										// ...
		return;
	}
	else if (header->StatusCode == 101)
	{
		ILibWebClient_DukTape_WebSocketCallbacks *callbacks = (ILibWebClient_DukTape_WebSocketCallbacks*)ILibMemory_GetExtraMemory(ILibWebClient_GetRequestToken_FromStateObject(WebStateObject), ILibMemory_WebClient_RequestToken_CONTAINERSIZE);

		if (recvStatus == ILibWebClient_ReceiveStatus_Connection_Established)
		{
			memset(callbacks, 0, sizeof(ILibWebClient_DukTape_WebSocketCallbacks));
			duk_push_heapptr(ctx, user2);							// [wsock]
			if (duk_has_prop_string(ctx, -1, "OnOpenPtr"))
			{
				duk_get_prop_string(ctx, -1, "OnMessagePtr");		// [wsock][OnMessage]
				callbacks->OnMessage = duk_to_pointer(ctx, -1);
				duk_pop(ctx);										// [wsock]

				duk_get_prop_string(ctx, -1, "OnSendOKPtr");		// [wsock][OnSendOK]
				callbacks->OnSendOK = duk_to_pointer(ctx, -1);
				duk_pop(ctx);										// [wsock]

				duk_push_pointer(ctx, WebStateObject);				// [wsock][wcdo]
				duk_put_prop_string(ctx, -2, "wcdo");				// [wsock]

				duk_get_prop_string(ctx, -1, "OnOpenPtr");			// [wsock][OnOpen]
				duk_swap_top(ctx, -2);								// [OnOpen][this]
				if (duk_pcall_method(ctx, 0) != 0)					// [retVal]	
				{
					ILibDuktape_Process_UncaughtException(ctx);
				}
			}
			duk_pop(ctx);											// ...
		}
		else
		{
			if (callbacks->OnMessage != NULL)
			{
				duk_push_heapptr(ctx, callbacks->OnMessage);										// [func]
				duk_push_heapptr(ctx, user2);														// [func][this]
				duk_get_prop_string(ctx, -1, "buffer");												// [func][this][buffer]
				duk_config_buffer(ctx, -1, bodyBuffer + *beginPointer, endPointer - *beginPointer);
				duk_push_int(ctx, recvStatus);														// [func][this][buffer][fragmentFlag]
				if (duk_pcall_method(ctx, 2) == 0)													// [retVal]
				{
					if (duk_is_number(ctx, -1))
					{
						*beginPointer = duk_to_int(ctx, -1);
					}
					else
					{
						*beginPointer = endPointer;
					}
				}
				else
				{
					ILibDuktape_Process_UncaughtException(ctx);
				}
				duk_pop(ctx);
			}
		}
	}
}

void ILibWebClient_DukTape_WebSocket_OnSendOK(ILibWebClient_StateObject wcdo, void* user1, void* user2)
{
	duk_context *ctx = (duk_context*)user1;
	ILibWebClient_DukTape_WebSocketCallbacks *callbacks = (ILibWebClient_DukTape_WebSocketCallbacks*)ILibMemory_GetExtraMemory(ILibWebClient_GetRequestToken_FromStateObject(wcdo), ILibMemory_WebClient_RequestToken_CONTAINERSIZE);
	if (callbacks->OnSendOK != NULL)
	{
		duk_push_heapptr(ctx, callbacks->OnSendOK);		// [func]
		duk_push_heapptr(ctx, user2);					// [func][this]
		if (duk_pcall_method(ctx, 0) != 0)				// [retVal]
		{
			ILibDuktape_Process_UncaughtException(ctx);
		}
		duk_pop(ctx);									// ...
	}
}
duk_ret_t ILibWebClient_DukTape_W3CWebSocket_Send(duk_context *ctx)
{
	char *buffer;
	duk_size_t bufferLen;
	ILibWebClient_WebSocket_FragmentFlags fragmentFlag = ILibWebClient_WebSocket_FragmentFlag_Complete;
	ILibWebClient_WebSocket_DataTypes bufferType = duk_is_string(ctx, 0) ? ILibWebClient_WebSocket_DataType_TEXT : ILibWebClient_WebSocket_DataType_BINARY;
	ILibAsyncSocket_SendStatus status;

	int nargs = duk_get_top(ctx);
	if (nargs < 1) { duk_push_string(ctx, "Too Few Arguments"); duk_throw(ctx); return(DUK_RET_ERROR); }
	if (nargs > 1) { fragmentFlag = (ILibWebClient_WebSocket_FragmentFlags)duk_require_int(ctx, 1); }

	if (duk_is_string(ctx, 0)) 
	{
		buffer = (char*)duk_get_lstring(ctx, 0, &bufferLen); 
	}
	else 
	{ 
		buffer = Duktape_GetBuffer(ctx, 0, &bufferLen); 
	}

	duk_push_this(ctx);						// [wsock]
	duk_get_prop_string(ctx, -1, "wcdo");	// [wsock][wcdo]

	status = ILibWebClient_WebSocket_Send(duk_to_pointer(ctx, -1), bufferType, buffer, (int)bufferLen, ILibAsyncSocket_MemoryOwnership_USER, fragmentFlag);
	duk_push_int(ctx, status);
	return 1;
}
duk_ret_t ILibWebClient_DukTape_WebSocketContructor(duk_context *ctx)
{
	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "WebSocketConstructor(): Invalid Uri")); }
	duk_size_t uriLen;
	char *uri = (char*)duk_get_lstring(ctx, 0, &uriLen);
	char *host;
	char *path;
	unsigned short port;
	ILibHTTPPacket *packet;
	int len;
	int reassemblySize = 4096;
	int poolSize = 5;
	void *chain;
	ILibWebClient_RequestManager *wcm;
	ILibWebClient_RequestToken token;
	struct sockaddr_in6* dest;

	if (!duk_is_constructor_call(ctx)) 
	{
		return DUK_RET_TYPE_ERROR;
	}

	if (duk_get_top(ctx) > 1)
	{
		if (duk_has_prop_string(ctx, 1, "MaxBufferSize"))
		{
			duk_get_prop_string(ctx, 1, "MaxBufferSize");
			reassemblySize = duk_to_int(ctx, -1);
			duk_pop(ctx);
		}
		if (duk_has_prop_string(ctx, 1, "PoolSize"))
		{
			duk_get_prop_string(ctx, 1, "PoolSize");
			poolSize = duk_to_int(ctx, -1);
			duk_pop(ctx);
		}
	}

	duk_push_current_function(ctx);				// [func]
	duk_get_prop_string(ctx, -1, "chain");		// [func][chain]
	chain = duk_to_pointer(ctx, -1);
	duk_push_this(ctx);							// [func][chain][wsock]
	duk_swap_top(ctx, -2);						// [func][wsock][chain]
	duk_put_prop_string(ctx, -2, "chain");		// [func][wsock]

	ILibParseUri(uri, &host, &port, &path, NULL);
	packet = ILibCreateEmptyPacket();
	ILibSetVersion(packet, "1.1", 3);
	ILibSetDirective(packet, "GET", 3, path, (int)strnlen_s(path, (int)uriLen));
	len = sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "%s:%u", host, port);
	ILibAddHeaderLine(packet, "Host", 4, ILibScratchPad, len);
	ILibWebClient_AddWebSocketRequestHeaders(packet, reassemblySize, ILibWebClient_DukTape_WebSocket_OnSendOK);

	duk_push_heap_stash(ctx);											// [heapstash]
	if (duk_has_prop_string(ctx, -1, "WSockClient"))
	{
		duk_get_prop_string(ctx, -1, "WSockClient");					// [heapstash][wcm]
		wcm = (ILibWebClient_RequestManager)duk_to_pointer(ctx, -1);
		duk_pop_2(ctx);													// ...
	}
	else
	{
		wcm = ILibCreateWebClient(poolSize, chain);
		duk_push_pointer(ctx, wcm);						// [heapstash][wcm]
		duk_put_prop_string(ctx, -2, "WSockClient");	// [heapstash]
	}
	duk_pop(ctx);																// [func][wsock]
	duk_push_c_function(ctx, ILibWebClient_DukTape_WebSocket_Finalizer, 1);		// [func][wsock][fin]
	duk_set_finalizer(ctx, -2);													// [func][wsock]

	duk_push_external_buffer(ctx);												// [func][wsock][buffer]
	duk_put_prop_string(ctx, -2, "buffer");										// [func][wsock]
	
	duk_push_string(ctx, "onopen");												// [func][wsock][key]
	duk_push_c_function(ctx, ILibWebClient_DukTape_WebSocket_Ptr_Setter, 1);	// [func][wsock][key][func]
	duk_push_string(ctx, "OnOpenPtr");											// [func][wsock][key][func][str]
	duk_put_prop_string(ctx, -2, "SetterKey");									// [func][wsock][key][func]
	duk_def_prop(ctx, -3, DUK_DEFPROP_HAVE_SETTER);								// [func][wsock]

	duk_push_string(ctx, "onmessage");											// [func][wsock][key]
	duk_push_c_function(ctx, ILibWebClient_DukTape_WebSocket_Ptr_Setter, 1);	// [func][wsock][key][func]
	duk_push_string(ctx, "OnMessagePtr");										// [func][wsock][key][func][str]
	duk_put_prop_string(ctx, -2, "SetterKey");									// [func][wsock][key][func]
	duk_def_prop(ctx, -3, DUK_DEFPROP_HAVE_SETTER);								// [func][wsock]

	duk_push_string(ctx, "onerror");											// [func][wsock][key]
	duk_push_c_function(ctx, ILibWebClient_DukTape_WebSocket_Ptr_Setter, 1);	// [func][wsock][key][func]
	duk_push_string(ctx, "OnErrorPtr");											// [func][wsock][key][func][str]
	duk_put_prop_string(ctx, -2, "SetterKey");									// [func][wsock][key][func]
	duk_def_prop(ctx, -3, DUK_DEFPROP_HAVE_SETTER);								// [func][wsock]

	duk_push_string(ctx, "onclose");											// [func][wsock][key]
	duk_push_c_function(ctx, ILibWebClient_DukTape_WebSocket_Ptr_Setter, 1);	// [func][wsock][key][func]
	duk_push_string(ctx, "OnClosePtr");											// [func][wsock][key][func][str]
	duk_put_prop_string(ctx, -2, "SetterKey");									// [func][wsock][key][func]
	duk_def_prop(ctx, -3, DUK_DEFPROP_HAVE_SETTER);								// [func][wsock]

	duk_push_string(ctx, "onsendok");											// [func][wsock][key]
	duk_push_c_function(ctx, ILibWebClient_DukTape_WebSocket_Ptr_Setter, 1);	// [func][wsock][key][func]
	duk_push_string(ctx, "OnSendOKPtr");										// [func][wsock][key][func][str]
	duk_put_prop_string(ctx, -2, "SetterKey");									// [func][wsock][key][func]
	duk_def_prop(ctx, -3, DUK_DEFPROP_HAVE_SETTER);								// [func][wsock]

	duk_push_c_function(ctx, ILibWebClient_DukTape_W3CWebSocket_Send, DUK_VARARGS);	// [func][wsock][func]
	duk_put_prop_string(ctx, -2, "Send");											// [func][wsock]

	dest = Duktape_IPAddress4_FromString(host, port);

	token = ILibWebClient_PipelineRequest(wcm, (struct sockaddr*)dest, packet, ILibWebClient_DukTape_WebSocket_OnResponse, ctx, duk_get_heapptr(ctx, -1));
	duk_push_pointer(ctx, token);					// [func][wsock][token]
	duk_put_prop_string(ctx, -2, "RequestTokenPtr");// [func][wsock]

	return 0;
}

void ILibWebClient_DukTape_Init(duk_context * ctx, void * chain)
{
	duk_push_global_object(ctx);

	duk_push_c_function(ctx, ILibWebClient_DukTape_Create, 1);			// [global][func]
	duk_push_pointer(ctx, chain);										// [global][func][chain]
	duk_put_prop_string(ctx, -2, "chain");								// [global][func]
	duk_put_prop_string(ctx, -2, "ILibWebClient_Create");				// [global]
	
	duk_push_c_function(ctx, ILibWebClient_DukTape_WebSocketContructor, DUK_VARARGS);	// [global][func]
	duk_push_pointer(ctx, chain);														// [global][func][chain]
	duk_put_prop_string(ctx, -2, "chain");												// [global][func]
	duk_put_prop_string(ctx, -2, "WebSocket");											// [global]

	Duktape_CreateEnum(ctx, "WebSocket_Status", (char*[]) { "COMPLETE_FRAGMENT", "END", "PARTIAL_FRAGMENT", "LAST_PARTIAL_FRAGMENT" }, (int[]) { 0, 1, 10, 11 }, 4);

	duk_pop(ctx);
}
