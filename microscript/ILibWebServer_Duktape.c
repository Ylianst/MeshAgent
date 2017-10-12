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

#include "ILibWebServer_Duktape.h"
#include "ILibDuktapeModSearch.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibWebServer.h"
#include "microstack/ILibWebClient.h"
#include "ILibDuktape_Helpers.h"

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif


duk_idx_t ILibWebServer_DukTape_Push_ILibWebServerSession(duk_context *ctx, ILibWebServer_Session *session);
duk_idx_t ILibWebServer_DukTape_Push_PacketHeader(duk_context *ctx, ILibHTTPPacket *packet);
void ILibWebServer_DukTape_PUSH_IncomingMessage(duk_context *ctx, ILibHTTPPacket *packet, ILibWebServer_Session *session);
void ILibWebServer_DukTape_PUSH_ServerResponse(duk_context *ctx, ILibWebServer_Session *session);


void* Duktape_GetSessionPtr(duk_context *ctx)
{
	void *retVal;
	duk_push_this(ctx);								// [session]
	duk_get_prop_string(ctx, -1, "SessionPtr");		// [session][ptr]
	retVal = duk_to_pointer(ctx, -1);
	duk_pop_2(ctx);									// ...
	return retVal;
}

duk_ret_t ILibWebServer_DukTape_SendResponse(duk_context *ctx)
{
	ILibWebServer_Session *session;
	ILibHTTPPacket *packet;
	int retVal;

	duk_get_prop_string(ctx, 0, "PacketPtr");
	packet = (ILibHTTPPacket*)duk_to_pointer(ctx, -1);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);

	retVal = (int)ILibWebServer_Send(session, packet);
	duk_push_int(ctx, retVal);
	return 1;
}
duk_ret_t ILibWebServer_DukTape_SendResponseRaw(duk_context *ctx)
{
	ILibWebServer_Session *session;
	char* buffer;
	int bufferLen;
	int retVal;
	int doneFlag;

	bufferLen = duk_require_int(ctx, 1);
	buffer = Duktape_GetBuffer(ctx, 0, NULL);
	doneFlag = duk_require_int(ctx, 2);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);

	retVal = (int)ILibWebServer_Send_Raw(session, buffer, bufferLen, ILibAsyncSocket_MemoryOwnership_USER, (ILibWebServer_DoneFlag)doneFlag);
	duk_push_int(ctx, retVal);
	return 1;
}
duk_ret_t ILibWebServer_DukTape_Session_StreamHeader(duk_context *ctx)
{
	//	enum ILibWebServer_Status ILibWebServer_StreamHeader(struct ILibWebServer_Session *session, struct packetheader *header);

	ILibWebServer_Session *session;
	ILibHTTPPacket *packet;
	int retVal;

	duk_get_prop_string(ctx, 0, "PacketPtr");
	packet = (ILibHTTPPacket*)duk_to_pointer(ctx, -1);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);

	retVal = (int)ILibWebServer_StreamHeader(session, packet);
	duk_push_int(ctx, retVal);
	return 1;
}
duk_ret_t ILibWebServer_DukTape_Session_StreamHeaderRaw(duk_context *ctx)
{
	// enum ILibWebServer_Status ILibWebServer_StreamHeader_Raw(struct ILibWebServer_Session *session, int StatusCode, char *StatusData, char *ResponseHeaders, enum ILibAsyncSocket_MemoryOwnership ResponseHeaders_FREE)

	ILibWebServer_Session *session;
	int responseCode;
	char *statusData;
	char *responseHeaders;
	int retVal;

	responseCode = duk_require_int(ctx, 0);
	statusData = (char*)duk_require_string(ctx, 1);
	responseHeaders = (char*)duk_require_string(ctx, 2);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);

	retVal = ILibWebServer_StreamHeader_Raw(session, responseCode, statusData, responseHeaders, ILibAsyncSocket_MemoryOwnership_USER);
	duk_push_int(ctx, retVal);
	return 1;
}
duk_ret_t ILibWebServer_DukTape_Session_StreamBody(duk_context *ctx)
{
	// enum ILibWebServer_Status ILibWebServer_StreamBody(struct ILibWebServer_Session *session, char *buffer, int bufferSize, enum ILibAsyncSocket_MemoryOwnership userFree, ILibWebServer_DoneFlag done);

	ILibWebServer_Session *session;
	char *body;
	int bodyLen;
	int doneFlag;
	int retVal;

	bodyLen = duk_require_int(ctx, 1);
	doneFlag = duk_require_int(ctx, 2);
	body = Duktape_GetBuffer(ctx, 0, NULL);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);

	retVal = (int)ILibWebServer_StreamBody(session, body, bodyLen, ILibAsyncSocket_MemoryOwnership_USER, (ILibWebServer_DoneFlag)doneFlag);
	duk_push_int(ctx, retVal);
	return 1;
}
duk_ret_t ILibWebServer_DukTape_Session_Digest_IsAuthenticated(duk_context *ctx)
{
	// ILibWebServer_Digest_IsAuthenticated
	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "IsAuthenticated(): Invalid Parameter/Type")); }
	ILibWebServer_Session *session;
	duk_size_t realmLen;
	char* realm = (char*)duk_get_lstring(ctx, 0, &realmLen);
	int retVal;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);

	retVal = (int)ILibWebServer_Digest_IsAuthenticated(session, realm, (int)realmLen);
	duk_push_int(ctx, retVal);
	return 1;
}
duk_ret_t ILibWebServer_DukTape_Session_Digest_SendUnauthorized(duk_context *ctx)
{
	// void ILibWebServer_Digest_SendUnauthorized(struct ILibWebServer_Session *session, char* realm, int realmLen, char* html, int htmllen);

	ILibWebServer_Session *session;

	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "SendUnAuthorized(): Invalid Parameter/Type (realm)")); }
	duk_size_t realmLen;
	char *realm = (char*)duk_get_lstring(ctx, 0, &realmLen);
	int htmlLen = duk_require_int(ctx, 2);
	char *html = Duktape_GetBuffer(ctx, 1, NULL);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);

	ILibWebServer_Digest_SendUnauthorized(session, realm, (int)realmLen, html, htmlLen);
	return 0;
}
duk_ret_t ILibWebServer_DukTape_Session_Digest_GetUsername(duk_context *ctx)
{
	ILibWebServer_Session *session;
	char *username;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);

	username = ILibWebServer_Digest_GetUsername(session);
	duk_push_string(ctx, username != NULL ? username : "");
	return 1;
}
duk_ret_t ILibWebServer_DukTape_Session_Digest_ValidatePassword(duk_context *ctx)
{
	// int ILibWebServer_Digest_ValidatePassword(struct ILibWebServer_Session *session, char* password, int passwordLen);
	ILibWebServer_Session *session;
	int passwordLen = duk_require_int(ctx, 1);
	char *password = Duktape_GetBuffer(ctx, 0, NULL);
	int retVal;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);

	retVal = ILibWebServer_Digest_ValidatePassword(session, password, passwordLen);
	duk_push_int(ctx, retVal);
	return 1;
}

void ILibWebServer_DukTape_Session_OnReceive(struct ILibWebServer_Session *sender, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, ILibWebServer_DoneFlag done)
{
	duk_context *ctx = (duk_context*)((void**)sender->ParentExtraMemory)[0];
	void* OnReceive = ((void**)sender->Reserved_Transport.ChainLink.ExtraMemoryPtr)[0];

	duk_push_heapptr(ctx, OnReceive);

	ILibWebServer_DukTape_Push_ILibWebServerSession(ctx, sender);
	ILibWebServer_DukTape_Push_PacketHeader(ctx, header);									// [func][this][header]
	duk_get_prop_string(ctx, -2, "buffer");													// [func][this][header][buffer]
	duk_config_buffer(ctx, -1, bodyBuffer + *beginPointer, endPointer - *beginPointer);
	duk_push_int(ctx, (int)done);															// [func][this][header][buffer][done]

	if (duk_pcall_method(ctx, 3) == 0)														// [retVal]
	{
		if (duk_get_type(ctx, -1) == DUK_TYPE_NUMBER)
		{
			*beginPointer = duk_get_int(ctx, -1);
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
void ILibWebServer_DukTape_Session_OnDisconnect(struct ILibWebServer_Session *sender)
{
	duk_context *ctx = (duk_context*)((void**)sender->ParentExtraMemory)[0];
	void* OnDisconnect = ((void**)sender->Reserved_Transport.ChainLink.ExtraMemoryPtr)[1];

	duk_push_heapptr(ctx, OnDisconnect);
	ILibWebServer_DukTape_Push_ILibWebServerSession(ctx, sender);
	if (duk_pcall_method(ctx, 0) != 0)
	{
		ILibDuktape_Process_UncaughtException(ctx);
	}
	duk_pop(ctx);
}
void ILibWebServer_DukTape_Session_OnSendOk(struct ILibWebServer_Session *sender)
{
	duk_context *ctx = (duk_context*)((void**)sender->ParentExtraMemory)[0];
	void* OnSendOK = ((void**)sender->Reserved_Transport.ChainLink.ExtraMemoryPtr)[2];

	duk_push_heapptr(ctx, OnSendOK);								// [func]
	ILibWebServer_DukTape_Push_ILibWebServerSession(ctx, sender);	// [func][this]
	if (duk_pcall_method(ctx, 0) != 0)
	{
		ILibDuktape_Process_UncaughtException(ctx);
	}
	duk_pop(ctx);
}

duk_ret_t ILibWebServer_DukTape_OnReceive_Setter(duk_context *ctx)
{
	void *OnReceive = duk_require_heapptr(ctx, 0);
	ILibWebServer_Session *session;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);
	((void**)session->Reserved_Transport.ChainLink.ExtraMemoryPtr)[0] = OnReceive;
	session->OnReceive = ILibWebServer_DukTape_Session_OnReceive;

	duk_push_heapptr(ctx, session->User);			// [session]
	duk_dup(ctx, 0);								// [session][ptr]
	duk_put_prop_string(ctx, -2, "OnReceivePtr");	// [session]

	return 0;
}
duk_ret_t ILibWebServer_DukTape_OnDisconnect_Setter(duk_context *ctx)
{
	void *OnDisconnect = duk_require_heapptr(ctx, 0);
	ILibWebServer_Session *session;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);
	((void**)session->Reserved_Transport.ChainLink.ExtraMemoryPtr)[1] = OnDisconnect;
	session->OnDisconnect = ILibWebServer_DukTape_Session_OnDisconnect;

	duk_push_heapptr(ctx, session->User);				// [session]
	duk_dup(ctx, 0);									// [session][ptr]
	duk_put_prop_string(ctx, -2, "OnDisconnectPtr");	// [session]

	return 0;
}
duk_ret_t ILibWebServer_DukTape_OnSendOk_Setter(duk_context *ctx)
{
	void *OnSendOk = duk_require_heapptr(ctx, 0);
	ILibWebServer_Session *session;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);
	((void**)session->Reserved_Transport.ChainLink.ExtraMemoryPtr)[2] = OnSendOk;
	session->OnSendOK = ILibWebServer_DukTape_Session_OnSendOk;

	duk_push_heapptr(ctx, session->User);				// [session]
	duk_dup(ctx, 0);									// [session][ptr]
	duk_put_prop_string(ctx, -2, "OnSendOKPtr");		// [session]

	return 0;
}
duk_idx_t ILibWebServer_DukTape_Session_IsCrossSiteRequest(duk_context *ctx)
{
	ILibWebServer_Session *session;
	char *retVal;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);

	retVal = ILibWebServer_IsCrossSiteRequest(session);
	duk_push_string(ctx, retVal == NULL ? "" : retVal);
	return 1;
}
duk_idx_t ILibWebServer_DukTape_Session_GetWebSocketDataType(duk_context *ctx)
{
	ILibWebServer_Session *session;
	ILibWebServer_WebSocket_DataTypes retVal;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);

	retVal = ILibWebServer_WebSocket_GetDataType(session);
	duk_push_int(ctx, (int)retVal);
	return 1;
}
duk_idx_t ILibWebServer_DukTape_Session_UpgradeWebSocket(duk_context *ctx)
{
	ILibWebServer_Session *session = Duktape_GetSessionPtr(ctx);
	int fragmentReassemblySize = duk_require_int(ctx, 0);
	int retVal;

	retVal = ILibWebServer_UpgradeWebSocket(session, fragmentReassemblySize);
	duk_push_int(ctx, retVal);
	return 1;
}
duk_idx_t ILibWebServer_DukTape_Session_WebSocket_Send(duk_context *ctx)
{
	// enum ILibWebServer_Status ILibWebServer_WebSocket_Send(struct ILibWebServer_Session *session, char* buffer, int bufferLen, ILibWebServer_WebSocket_DataTypes bufferType, enum ILibAsyncSocket_MemoryOwnership userFree, ILibWebServer_WebSocket_FragmentFlags fragmentStatus);
	ILibWebServer_Session *session = Duktape_GetSessionPtr(ctx);
	char *buffer = Duktape_GetBuffer(ctx, 0, NULL);
	int bufferLen = duk_require_int(ctx, 1);
	int dataType = duk_require_int(ctx, 2);
	int fragmentFlags = duk_require_int(ctx, 3);

	ILibWebServer_Status retVal = ILibWebServer_WebSocket_Send(session, buffer, bufferLen, dataType, ILibAsyncSocket_MemoryOwnership_USER, fragmentFlags);
	duk_push_int(ctx, (int)retVal);
	return 1;
}
duk_idx_t ILibWebServer_DukTape_Session_WebSocket_Close(duk_context *ctx)
{
	ILibWebServer_Session *session = Duktape_GetSessionPtr(ctx);

	ILibWebServer_WebSocket_Close(session);
	return 0;
}
duk_ret_t ILibWebServer_DukTape_Session_Pause(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	ILibWebServer_Pause((ILibWebServer_Session*)duk_to_pointer(ctx, -1));
	return 0;
}
duk_ret_t ILibWebServer_DukTape_Session_Resume(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "SessionPtr");
	ILibWebServer_Resume((ILibWebServer_Session*)duk_to_pointer(ctx, -1));
	return 0;
}
duk_idx_t ILibWebServer_DukTape_Push_ILibWebServerSession(duk_context *ctx, ILibWebServer_Session *session)
{
	if (session->User != NULL)
	{
		duk_push_heapptr(ctx, session->User);	// [session]
		return(duk_get_top_index(ctx));
	}
	duk_push_heap_stash(ctx);																	// [stash]
	duk_push_object(ctx);																		// [stash][obj]
	session->User = duk_get_heapptr(ctx, -1);
	duk_dup(ctx, -1);																			// [stash][obj][obj]
	duk_put_prop_string(ctx, -3, Duktape_GetStashKey(session->User));							// [stash][obj]

	duk_swap_top(ctx, -2);																		// [obj][stash]
	duk_pop(ctx);																				// [obj]

	duk_push_external_buffer(ctx);																// [obj][buffer]
	duk_put_prop_string(ctx, -2, "buffer");														// [obj]

	duk_push_pointer(ctx, session);																// [obj][pointer]
	duk_put_prop_string(ctx, -2, "SessionPtr");													// [obj]

	duk_push_c_function(ctx, ILibWebServer_DukTape_SendResponse, 1);							// [obj][func]
	duk_put_prop_string(ctx, -2, "SendResponse");												// [obj]
	duk_push_c_function(ctx, ILibWebServer_DukTape_SendResponseRaw, 3);
	duk_put_prop_string(ctx, -2, "SendResponseRaw");
	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_StreamHeader, 1);
	duk_put_prop_string(ctx, -2, "StreamHeader");
	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_StreamHeaderRaw, 3);
	duk_put_prop_string(ctx, -2, "StreamHeaderRaw");
	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_StreamBody, 3);
	duk_put_prop_string(ctx, -2, "StreamBody");
	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_Pause, 0);
	duk_put_prop_string(ctx, -2, "Pause");
	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_Resume, 0);
	duk_put_prop_string(ctx, -2, "Resume");

	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_Digest_IsAuthenticated, 1);
	duk_put_prop_string(ctx, -2, "Digest_IsAuthenticated");
	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_Digest_SendUnauthorized, 3);
	duk_put_prop_string(ctx, -2, "Digest_SendUnauthorized");
	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_Digest_GetUsername, 0);
	duk_put_prop_string(ctx, -2, "Digest_GetUsername");
	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_Digest_ValidatePassword, 2);
	duk_put_prop_string(ctx, -2, "Digest_ValidatePassword");

	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_IsCrossSiteRequest, 0);
	duk_put_prop_string(ctx, -2, "IsCrossSiteRequest");

	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_GetWebSocketDataType, 0);
	duk_put_prop_string(ctx, -2, "WebSocket_GetDataType");
	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_UpgradeWebSocket, 1);
	duk_put_prop_string(ctx, -2, "WebSocket_UpgradeToWebSocket");
	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_WebSocket_Send, 4);
	duk_put_prop_string(ctx, -2, "WebSocket_Send");
	duk_push_c_function(ctx, ILibWebServer_DukTape_Session_WebSocket_Close, 0);
	duk_put_prop_string(ctx, -2, "WebSocket_Close");

	duk_push_string(ctx, "OnReceive");											//[obj][key]
	duk_push_c_function(ctx, ILibWebServer_DukTape_OnReceive_Setter, 1);		//[obj][key][Func]
	duk_def_prop(ctx, -3, DUK_DEFPROP_HAVE_SETTER);								//[obj]

	duk_push_string(ctx, "OnDisconnect");										//[obj][key]
	duk_push_c_function(ctx, ILibWebServer_DukTape_OnDisconnect_Setter, 1);		//[obj][key][Func]
	duk_def_prop(ctx, -3, DUK_DEFPROP_HAVE_SETTER);								//[obj]

	duk_push_string(ctx, "OnSendOk");											//[obj][key]
	duk_push_c_function(ctx, ILibWebServer_DukTape_OnSendOk_Setter, 1);			//[obj][key][Func]
	duk_def_prop(ctx, -3, DUK_DEFPROP_HAVE_SETTER);								//[obj]

	return duk_get_top_index(ctx);
}



duk_ret_t ILibWebServer_DukTape_GetHeaderline(duk_context *ctx)
{
	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "GetHeaderLine(): Invalid Parameter/Type")); }
	duk_size_t headerLen;
	char* header = (char*)duk_get_lstring(ctx, 0, &headerLen);
	struct packetheader *packet;
	char* val;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "PacketPtr");
	packet = (struct packetheader*)duk_to_pointer(ctx, -1);

	val = ILibGetHeaderLine(packet, header, (int)headerLen);
	if (val == NULL)
	{
		duk_push_string(ctx, "");
	}
	else
	{
		duk_push_string(ctx, val);
	}
	return 1;
}

duk_ret_t ILibWebServer_DukTape_Packet_SetDirective(duk_context *ctx)
{
	if (!duk_is_string(ctx, 0) || !duk_is_string(ctx, 1)) { return(ILibDuktape_Error(ctx, "SetDirective(): Invalid Parameter/Type(s)")); }
	duk_size_t directiveLen, pathLen;
	char *directive = (char*)duk_get_lstring(ctx, 0, &directiveLen);
	char *path = (char*)duk_get_lstring(ctx, 1, &pathLen);
	struct packetheader *packet;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "PacketPtr");
	packet = (struct packetheader*)duk_to_pointer(ctx, -1);

	ILibSetDirective(packet, directive, (int)directiveLen, path, (int)pathLen);
	return 0;
}
duk_ret_t ILibWebServer_DukTape_Packet_AddHeader(duk_context *ctx)
{
	if (!duk_is_string(ctx, 0) || !duk_is_string(ctx, 1)) { return(ILibDuktape_Error(ctx, "AddHeader(): Invalid Parameter/Type(s)")); }
	duk_size_t fieldNameLen, fieldNameValueLen;
	char* fieldName = (char*)duk_get_lstring(ctx, 0, &fieldNameLen);
	char* fieldValue = (char*)duk_get_lstring(ctx, 1, &fieldNameValueLen);
	struct packetheader *packet;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "PacketPtr");
	packet = (struct packetheader*)duk_to_pointer(ctx, -1);

	ILibAddHeaderLine(packet, fieldName, (int)fieldNameLen, fieldValue, (int)fieldNameValueLen);
	return 0;
}
duk_ret_t ILibWebServer_DukTape_Packet_SetResponse(duk_context *ctx)
{
	int statusCode = duk_require_int(ctx, 0);
	duk_size_t responseLen;
	if (!duk_is_string(ctx, 1)) { return(ILibDuktape_Error(ctx, "SetResponse(): Response was invalid ParameterType")); }
	char *response = (char*)duk_get_lstring(ctx, 1, &responseLen);
	struct packetheader *packet;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "PacketPtr");
	packet = (struct packetheader*)duk_to_pointer(ctx, -1);

	ILibSetStatusCode(packet, statusCode, response, (int)responseLen);
	return 0;
}
duk_ret_t ILibWebServer_DukTape_Packet_SetStringBody(duk_context *ctx)
{
	duk_size_t bodyLen;
	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "SetStringBody(): Invalid Parameter/Type")); }
	char *body = (char*)duk_get_lstring(ctx, 0, &bodyLen);
	struct packetheader *packet;
	char *tmp;
	char len[65];

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "PacketPtr");
	packet = (struct packetheader*)duk_to_pointer(ctx, -1);

	tmp = ILibString_Copy(body, (int)bodyLen);
	packet->Body = tmp;
	packet->BodyLength = (int)bodyLen;

#ifdef WIN32
	_itoa_s(packet->BodyLength, len, 65, 10);
#else
	sprintf_s(len, 65, "%d", packet->BodyLength);
#endif
	ILibAddHeaderLine(packet, "Content-Length", 14, len, (int)strnlen_s(len, sizeof(len)));
	return 0;
}
duk_ret_t ILibWebServer_DukTape_Packet_SetBody(duk_context *ctx)
{
	int bodyLen = duk_require_int(ctx, 1);
	char len[65];
	struct packetheader *packet;
	char* body;

	body = Duktape_GetBuffer(ctx, 0, NULL);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "PacketPtr");
	packet = (struct packetheader*)duk_to_pointer(ctx, -1);

	packet->Body = (char*)malloc(bodyLen);
	memcpy_s(packet->Body, bodyLen, body, bodyLen);
	packet->BodyLength = bodyLen;

#ifdef WIN32
	_itoa_s(packet->BodyLength, len, 65, 10);
#else
	sprintf_s(len, 65, "%d", packet->BodyLength);
#endif
	ILibAddHeaderLine(packet, "Content-Length", 14, len, (int)strnlen_s(len, sizeof(len)));
	return 0;
}

duk_idx_t ILibWebServer_DukTape_PacketHeader_AddWebSocketRequestHeaders(duk_context *ctx)
{
	ILibHTTPPacket *packet;
	int maxReassemblySize = duk_require_int(ctx, 0);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "PacketPtr");
	packet = (ILibHTTPPacket*)duk_to_pointer(ctx, -1);

	ILibWebClient_AddWebSocketRequestHeaders(packet, maxReassemblySize, NULL);
	return 0;
}

duk_idx_t ILibWebServer_DukTape_Push_PacketHeader(duk_context *ctx, ILibHTTPPacket *packet)
{
	duk_idx_t j;
	
	j = duk_push_object(ctx);
	duk_push_pointer(ctx, packet);
	duk_put_prop_string(ctx, j, "PacketPtr");
	
	if (packet->Directive != NULL)
	{
		packet->Directive[packet->DirectiveLength] = 0;
		duk_push_string(ctx, packet->Directive);
		duk_put_prop_string(ctx, j, "Directive");
		packet->DirectiveObj[packet->DirectiveObjLength] = 0;
		duk_push_string(ctx, packet->DirectiveObj);
		duk_put_prop_string(ctx, j, "Path");
	}

	if(packet->StatusData != NULL)
	{
		duk_push_int(ctx, packet->StatusCode);
		duk_put_prop_string(ctx, j, "StatusCode");
		packet->StatusData[packet->StatusDataLength] = 0;
		duk_push_string(ctx, packet->StatusData);
		duk_put_prop_string(ctx, j, "StatusData");
	}

	duk_push_c_function(ctx, ILibWebServer_DukTape_PacketHeader_AddWebSocketRequestHeaders, 1);
	duk_put_prop_string(ctx, j, "WebSocket_AddRequestHeaders");

	duk_push_c_function(ctx, ILibWebServer_DukTape_GetHeaderline, 1);
	duk_put_prop_string(ctx, j, "GetHeader");

	duk_push_c_function(ctx, ILibWebServer_DukTape_Packet_AddHeader, 2);
	duk_put_prop_string(ctx, j, "AddHeader");

	duk_push_c_function(ctx, ILibWebServer_DukTape_Packet_SetDirective, 2);
	duk_put_prop_string(ctx, j, "SetDirective");

	duk_push_c_function(ctx, ILibWebServer_DukTape_Packet_SetResponse, 2);
	duk_put_prop_string(ctx, j, "SetResponse");

	duk_push_c_function(ctx, ILibWebServer_DukTape_Packet_SetStringBody, 1);
	duk_put_prop_string(ctx, j, "SetStringBody");

	duk_push_c_function(ctx, ILibWebServer_DukTape_Packet_SetBody, 2);
	duk_put_prop_string(ctx, j, "SetBody");
	return(j);
}

void ILibWebServer_DukTape_OnSession(struct ILibWebServer_Session *SessionToken, void *User)
{
	duk_context* ctx = (duk_context*)((void**)SessionToken->ParentExtraMemory)[0];
	void* DukOnSession = ((void**)SessionToken->ParentExtraMemory)[1];

	duk_push_heapptr(ctx, DukOnSession);
	ILibWebServer_DukTape_Push_ILibWebServerSession(ctx, SessionToken);

	if (duk_pcall_method(ctx, 0) != 0)
	{
		ILibDuktape_Process_UncaughtException(ctx);
	}
	duk_pop(ctx);
}

duk_ret_t ILibWebServer_DukTape_Create(duk_context *ctx)
{
	//MaxConnections, PortNumber, OnSession
	int MaxConnection = duk_require_int(ctx, 0);
	int PortNumber = duk_require_int(ctx, 1);
	void* OnSession = duk_require_heapptr(ctx, 2);
	void* server;
	void* chain;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "chain");
	chain = duk_to_pointer(ctx, -1);

	server = ILibWebServer_Create2(chain, MaxConnection, PortNumber, ILibWebServer_DukTape_OnSession, 3 * sizeof(void*), NULL);
	((void**)((ILibChain_Link*)server)->ExtraMemoryPtr)[0] = ctx;
	((void**)((ILibChain_Link*)server)->ExtraMemoryPtr)[1] = OnSession;

	duk_push_heap_stash(ctx);
	duk_dup(ctx, 2);
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(server));

	return 0;
}

duk_ret_t ILibWebServer_DukTape_CreatePacket(duk_context *ctx)
{
	duk_size_t versionLen;
	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "CreatePacket(): Invalid Parameter/Type")); }
	char* version = (char*)duk_get_lstring(ctx, 0, &versionLen);
	struct packetheader *header = ILibCreateEmptyPacket();
	ILibSetVersion(header, version, (int)versionLen);

	ILibWebServer_DukTape_Push_PacketHeader(ctx, header);

	return 1;
}

void ILibWebServer_DukTape_Init(duk_context* ctx, void *chain)
{
	duk_idx_t i;

	duk_push_global_object(ctx);											// [global]
	i = duk_push_c_function(ctx, ILibWebServer_DukTape_Create, 3);			// [global][func]
	duk_push_pointer(ctx, chain);											// [global][func][ptr]
	duk_put_prop_string(ctx, i, "chain");								// [global][func]
	duk_put_prop_string(ctx, -2, "ILibWebServer_Create");				// [global]

	duk_push_c_function(ctx, ILibWebServer_DukTape_CreatePacket, 1);		// [global][func]
	duk_put_prop_string(ctx, -2, "ILibWebServer_CreatePacket");				// [global]
	Duktape_CreateEnum(ctx, "WebSocket_DataTypes", (char* []){ "UNKNOWN", "REQUEST", "BINARY", "TEXT" }, (int []){ 0x00, 0xFF, 0x2, 0x1 }, 4);
	Duktape_CreateEnum(ctx, "WebSocket_FragmentFlags", (char* []) { "INCOMPLETE", "COMPLETE" }, (int[]) { 0, 1 }, 2);
	Duktape_CreateEnum(ctx, "WebServer_DoneFlags", (char* []) { "NOTDONE", "DONE", "PARTIAL", "LASTPARTIAL" }, (int[]) { 0, 1, 10, 11 }, 4);

	duk_pop(ctx);															// ...
}