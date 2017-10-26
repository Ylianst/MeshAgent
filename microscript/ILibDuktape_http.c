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

#include "microstack/ILibParsers.h"
#include "ILibDuktape_http.h"
#include "ILibDuktape_net.h"
#include "ILibDuktapeModSearch.h"
#include "microstack/ILibWebServer.h"
#include "microstack/ILibWebClient.h"

#include "ILibDuktape_ReadableStream.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_WritableStream.h"
#include "ILibDuktape_DuplexStream.h"
#include "ILibDuktape_EventEmitter.h"
#include "microstack/ILibCrypto.h"

#define HTTP_SERVER_PTR					"\xFF_ServerPtr"
#define HTTP_WEBCLIENT_MGR				"_RequestManagerPtr"
#define NativeSessionPtr				"\xFF_SessionPtr"
#define SessionPtrJS					"\xFF_SessionPtr_JS"
#define TLSPTR							"\xFF_tlsSettings"
#define TLS_CERT						"\xFF_cert"
#define TLS_CERT_NON_LEAF				"\xFF_cert_nonleaf"
#define HTTP_DEFAULT_PROTO_KEY			"\xFF_defaultProto"
#define HTTP_REQUEST_USER_PTR			"\xFF_request_user_ptr"
#define HTTP_REQUEST_TOKEN_PTR			"_TokenPtr"
#define HTTP_SOCKET_PTRS				"\xFF_socket_ptrs"
#define HTTP_SOCKET_BUFFERPTR			"\xFF_socket_bufferptr"
#define HTTP_STREAM_WRAPPER				"\xFF_http_StreamWrapper"
#define HTTP_STREAM_WRAPPER_BUFSIZE		4096
#define HTTP_CLIENTREQUEST_PARAMETER	"\xFF_http_clientRequest_parameter"
#define CLIENTREQUEST_HTTP				"\xFF_clientRequest_HTTP"
#define HTTP_INCOMINGMSG_WebStateObject	"\xFF_incomingMessage_WebStateObject"
#define DIGEST_USERNAME					"\xFF_DigestUsername"
#define DIGEST_PASSWORD					"\xFF_DigestPassword"
#define HTTP_DIGEST						"\xFF_HTTP_DIGEST"
#define DIGEST_CLIENT_REQUEST			"\xFF_DIGEST_CLIENT_REQUEST"
#define HTTP_CLIENTREQUEST_DATAPTR		"\xFF_CLIENTREQUEST_DATAPTR"
#define CLIENTREQUEST_EVENT_NAME		"\xFF_CLIENTREQUEST_EVENT_NAME"

extern duk_idx_t ILibWebServer_DukTape_Push_ILibWebServerSession(duk_context *ctx, ILibWebServer_Session *session);
void* ILibDuktape_http_request_PUSH_clientRequest(duk_context *ctx, ILibWebClient_RequestToken token, int isWebSocket);

typedef enum ILibDuktape_http_request_dataTypes
{
	ILibDuktape_http_request_dataType_UNKNOWN = 0,
	ILibDuktape_http_request_dataType_request = 1,
	ILibDuktape_http_request_dataType_webSocket = 2
}ILibDuktape_http_request_dataTypes;

#pragma pack(push, 1)
typedef struct ILibDuktape_http_request_dataType
{
	ILibDuktape_http_request_dataTypes STRUCT_TYPE;
}ILibDuktape_http_request_dataType;

typedef struct ILibDuktape_http_requestClient_callbacks
{
	ILibDuktape_http_request_dataTypes STRUCT_TYPE;
	void *clientRequest;
	void *readableStream;
	void *requestStream;
	void *OnReceive;
	void *OnContinue;
#ifndef MICROSTACK_NOTLS
	int rejectUnauthorized;
	void *checkServerIdentity;
#endif
}ILibDuktape_http_requestClient_callbacks;

typedef struct ILibDuktape_http_server_ptrs
{
	void *ctx;
	void *serverObject;
	void *OnResponse;
	void *OnUpgrade;
	void *OnCheckContinue;
	void *OnConnect;
}ILibDuktape_http_server_ptrs;
typedef struct ILibDuktape_http_session_ptrs
{
	ILibDuktape_readableStream *req;
	ILibDuktape_WritableStream *res;
}ILibDuktape_http_session_ptrs;
typedef struct ILibDuktape_http_server_websocket_ptrs
{
	ILibDuktape_EventEmitter *emitter;
	ILibDuktape_DuplexStream *ds;
	ILibWebServer_Session *session;
}ILibDuktape_http_server_websocket_ptrs;

typedef struct ILibDuktape_WebSocket_Pointers
{
	ILibDuktape_http_request_dataTypes STRUCT_TYPE;
	duk_context *ctx;
	void *clientRequest_ptr;
	void *socket_ptr;
	ILibDuktape_DuplexStream *stream;
	ILibWebClient_StateObject *wcdo;
	int timeout;
	void *onTimeout;
	void *onPing;
	void *onPong;
#ifndef MICROSTACK_NOTLS
	int rejectUnauthorized;
	void *checkServerIdentity;
#endif
}ILibDuktape_WebSocket_Pointers;
#pragma pack(pop)


typedef struct ILibDuktape_http_rawSocket
{
	duk_context *ctx;
	void *self;
	void *ConnectionToken;
	ILibDuktape_EventEmitter *emitter;
	ILibDuktape_DuplexStream *stream;
}ILibDuktape_http_rawSocket;

typedef struct ILibDuktape_http_streamWrapper
{
	duk_context *ctx;
	void *self;
	ILibDuktape_EventEmitter *emitter;
	ILibDuktape_DuplexStream *ds;
	ILibWebClient_StateObject *wcdo;
	ILibHTTPPacket *impliedHeaders;
	ILibDuktape_WritableStream *serverResponse_stream;
	void *OnRequest;
	void *OnResponse;
	int chunkEncoded;

	void *PipedReader;
	ILibDuktape_WritableStream *PipedWriter;
	char reserved[sizeof(ILibTransport) + sizeof(void*)];
	char hex[16];
	char buffer[HTTP_STREAM_WRAPPER_BUFSIZE];
	int bufferLen;
}ILibDuktape_http_streamWrapper;


char * ILibDuktape_http_getDefaultProto(duk_context *ctx)
{
	char *retVal;
	duk_push_this(ctx);										// [http]
	duk_get_prop_string(ctx, -1, HTTP_DEFAULT_PROTO_KEY);	// [http][default]
	retVal = (char*)duk_get_string(ctx, -1);
	duk_pop_2(ctx);											// ...
	return retVal;
}
#ifndef MICROSTACK_NOTLS
void ILibDuktape_X509_PUSH(duk_context *ctx, X509* cert)
{
	char hash[32];
	char fingerprint[100];

	util_keyhash2(cert, hash);
	util_tohex2(hash, 32, fingerprint);

	duk_push_object(ctx);							// [cert]
	duk_push_string(ctx, fingerprint);				// [cert][fingerprint]
	duk_put_prop_string(ctx, -2, "fingerprint");	// [cert]
}
#endif
ILibWebClient_RequestManager ILibDuktape_http_GetRequestManager(duk_context *ctx)
{
	ILibWebClient_RequestManager retVal = NULL;

	duk_push_this(ctx);														// [http]
	if (duk_has_prop_string(ctx, -1, HTTP_WEBCLIENT_MGR))
	{
		duk_get_prop_string(ctx, -1, HTTP_WEBCLIENT_MGR);					// [http][mgr]
		retVal = (ILibWebClient_RequestManager)duk_get_pointer(ctx, -1);
		duk_pop_2(ctx);														// ...
	}
	else
	{
		duk_get_prop_string(ctx, -1, "chain");								// [http][chain]
		duk_get_prop_string(ctx, -2, "RequestPoolSize");					// [http][chain][poolSize]
		retVal = ILibCreateWebClient(duk_get_int(ctx, -1), duk_get_pointer(ctx, -2));
		duk_pop_2(ctx);														// [http]
		duk_push_pointer(ctx, retVal);										// [http][mgr]
		duk_put_prop_string(ctx, -2, HTTP_WEBCLIENT_MGR);					// [http]
		duk_pop(ctx);														// ...
	}
	return retVal;
}

duk_ret_t ILibDuktape_http_serverresponse_end(duk_context *ctx)
{
	ILibWebServer_Session *session;
	ILibHTTPPacket *packet;
	int statusCode;
	char *statusMessage;
	duk_size_t statusMessageLen;

	int nargs = duk_get_top(ctx);
	duk_push_this(ctx);																	// [res]
	duk_get_prop_string(ctx, -1, NativeSessionPtr);										// [res][session]
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);							// [res][session]
	duk_pop(ctx);																		// [res]
	duk_get_prop_string(ctx, -1, "PacketPtr");											// [res][packet]
	packet = (ILibHTTPPacket*)duk_to_pointer(ctx, -1);									// [res][packet]
	duk_pop(ctx);																		// [res]
	duk_get_prop_string(ctx, -1, "statusCode");											// [res][code]
	statusCode = duk_to_int(ctx, -1); duk_pop(ctx);										// [res]
	duk_get_prop_string(ctx, -1, "statusMessage");										// [res][msg]
	statusMessage = (char*)duk_get_lstring(ctx, -1, &statusMessageLen); duk_pop(ctx);	// [res]
	ILibSetStatusCode(packet, statusCode, statusMessage, (int)statusMessageLen);

	((ILibDuktape_http_session_ptrs*)session->Reserved_Transport.ChainLink.ExtraMemoryPtr)->req = NULL;

	if (nargs == 0)
	{
		ILibWebServer_Send(session, packet);
		return 0;
	}

	ILibWebServer_StreamHeader(session, packet);

	if (nargs > 0)
	{
		char *body;
		duk_size_t bodyLen = 0;

		if (duk_is_string(ctx, 0))
		{
			body = (char*)duk_get_lstring(ctx, 0, &bodyLen);
		}
		else
		{
			body = Duktape_GetBuffer(ctx, 0, &bodyLen);
		}
		ILibWebServer_StreamBody(session, body, (int)bodyLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebServer_DoneFlag_Done);
	}
	return 0;
}
duk_ret_t ILibDuktape_http_serverresponse_setHeader(duk_context *ctx)
{
	ILibHTTPPacket *packet;
	if (!duk_is_string(ctx, 0) || !duk_is_string(ctx, 1)) { return(ILibDuktape_Error(ctx, "http.serverresponse.setHeader(): Invalid Parameters")); }
	duk_size_t fieldLen, valueLen;
	char *field = (char*)duk_get_lstring(ctx, 0, &fieldLen);
	char *value = (char*)duk_get_lstring(ctx, 1, &valueLen);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "PacketPtr");
	packet = (ILibHTTPPacket*)duk_to_pointer(ctx, -1);
	ILibAddHeaderLine(packet, field, (int)fieldLen, value, (int)valueLen);
	return 0;
}

duk_ret_t ILibDuktape_http_serverresponse_writeHead(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int statusCode;
	char *statusMessage = nargs > 1 ? (char*)duk_require_string(ctx, 1) : "OK";
	ILibHTTPPacket *packet;
	ILibWebServer_Session *session;

	duk_push_this(ctx);											// [response]
	duk_get_prop_string(ctx, -1, "PacketPtr");					// [response][packet]
	packet = (ILibHTTPPacket*)duk_to_pointer(ctx, -1);
	duk_del_prop_string(ctx, -2, "PacketPtr");
	duk_get_prop_string(ctx, -2, NativeSessionPtr);				// [response][packet][session]
	session = (ILibWebServer_Session*)duk_to_pointer(ctx, -1);

	if (nargs < 1) { duk_push_string(ctx, "Missing Status Code"); duk_throw(ctx); return(DUK_RET_ERROR); }
	statusCode = duk_require_int(ctx, 0);
	ILibSetStatusCode(packet, statusCode, statusMessage, -1);

	if (nargs > 2)
	{
		duk_enum(ctx, 2, 0);
		while (duk_next(ctx, -1, 1))
		{							
			ILibAddHeaderLine(packet, duk_to_string(ctx, -2), -1, duk_to_string(ctx, -1), -1);	// [enum][key][value]
			duk_pop_2(ctx);																		// [enum]
		}
	}

	ILibWebServer_StreamHeader(session, packet);
	return 0;
}

ILibTransport_DoneState ILibDuktape_http_server_WriteResponse(ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibWebServer_Status status = ILibWebServer_ALL_DATA_SENT;
	ILibWebServer_Session *session = (ILibWebServer_Session*)user;
	duk_push_heapptr(stream->ctx, stream->obj);							// [res]
	if (duk_has_prop_string(stream->ctx, -1, "PacketPtr"))
	{
		ILibHTTPPacket *packet;
		duk_get_prop_string(stream->ctx, -1, "PacketPtr");				// [res][packet]
		packet = (ILibHTTPPacket*)duk_to_pointer(stream->ctx, -1);
		duk_pop(stream->ctx);											// [res]
		duk_del_prop_string(stream->ctx, -1, "PacketPtr");
		duk_get_prop_string(stream->ctx, -1, "statusCode");				// [res][code]
		duk_get_prop_string(stream->ctx, -2, "statusMessage");			// [res][code][message]
		ILibSetStatusCode(packet, duk_to_int(stream->ctx, -2), (char*)duk_to_string(stream->ctx, -1), -1);
		duk_pop_3(stream->ctx);											// ...
		status = ILibWebServer_StreamHeader(session, packet);
	}
	if (bufferLen > 0)
	{
		status = ILibWebServer_StreamBody(session, buffer, bufferLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebServer_DoneFlag_NotDone);
	}

	switch (status)
	{
	case ILibWebServer_ALL_DATA_SENT:
		return(ILibTransport_DoneState_COMPLETE);
	case ILibWebServer_NOT_ALL_DATA_SENT_YET:
		return(ILibTransport_DoneState_INCOMPLETE);
	default:
		return(ILibTransport_DoneState_ERROR);
	}
}
void ILibDuktape_http_server_EndResponse(ILibDuktape_WritableStream *stream, void *user)
{
	ILibWebServer_Session *session = (ILibWebServer_Session*)user;
	ILibDuktape_http_server_WriteResponse(stream, NULL, 0, user);
	ILibWebServer_StreamBody(session, NULL, 0, ILibAsyncSocket_MemoryOwnership_USER, ILibWebServer_DoneFlag_Done);
}
duk_ret_t ILibDuktape_http_server_ServerResponse_Finalizer(duk_context *ctx)
{
	if (duk_has_prop_string(ctx, 0, "PacketPtr"))
	{
		duk_get_prop_string(ctx, 0, "PacketPtr");
		ILibDestructPacket((ILibHTTPPacket*)duk_to_pointer(ctx, -1));
		duk_del_prop_string(ctx, 0, "PacketPtr");
	}
	return 0;
}
duk_ret_t ILibDuktape_http_server_ServerResponse_writeContinue(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, NativeSessionPtr);
	ILibWebServer_Session *session = (ILibWebServer_Session*)duk_get_pointer(ctx, -1);

	ILibWebServer_Send_Raw(session, "HTTP/1.1 100 Continue\r\n\r\n", 25, ILibAsyncSocket_MemoryOwnership_STATIC, ILibWebServer_DoneFlag_NotDone);
	return(0);
}
ILibDuktape_WritableStream* ILibDuktape_http_server_PUSH_ServerResponse(duk_context *ctx, ILibWebServer_Session *session)
{
	ILibHTTPPacket *packet = ILibCreateEmptyPacket();
	ILibSetVersion(packet, "1.1", 3);

	duk_push_object(ctx);							// [obj]
	duk_push_pointer(ctx, session);					// [obj][session]
	duk_put_prop_string(ctx, -2, NativeSessionPtr);	// [obj]
	duk_push_pointer(ctx, packet);					// [obj][packet]
	duk_put_prop_string(ctx, -2, "PacketPtr");		// [obj]
	duk_push_int(ctx, 500);							// [obj][statusCode]
	duk_put_prop_string(ctx, -2, "statusCode");		// [obj]
	duk_push_string(ctx, "");						// [obj][statusMessage]
	duk_put_prop_string(ctx, -2, "statusMessage");	// [obj]

	duk_push_c_function(ctx, ILibDuktape_http_server_ServerResponse_Finalizer, 1);	// [obj][fin]
	duk_set_finalizer(ctx, -2);														// [obj]

	duk_push_c_function(ctx, ILibDuktape_http_serverresponse_setHeader, 2);			// [obj][func]
	duk_put_prop_string(ctx, -2, "setHeader");										// [obj]

	duk_push_c_function(ctx, ILibDuktape_http_serverresponse_writeHead, DUK_VARARGS);	// [obj][func]
	duk_put_prop_string(ctx, -2, "writeHead");											// [obj]

	ILibDuktape_CreateInstanceMethod(ctx, "writeContinue", ILibDuktape_http_server_ServerResponse_writeContinue, 0);

	return ILibDuktape_WritableStream_Init(ctx, ILibDuktape_http_server_WriteResponse, ILibDuktape_http_server_EndResponse, session);
}

ILibWebServer_Session* ILibDuktape_http_server_NativeSession_GetSession(duk_context *ctx)
{
	ILibWebServer_Session *retVal = NULL;
	duk_push_this(ctx);									// [session]
	duk_get_prop_string(ctx, -1, NativeSessionPtr);		// [session][ptr]
	retVal = (ILibWebServer_Session*)duk_get_pointer(ctx, -1);
	duk_pop_2(ctx);										// ...
	return retVal;
}
duk_ret_t ILibDuktape_http_server_NativeSession_Digest_IsAuthenticated(duk_context *ctx)
{
	ILibWebServer_Session *session = ILibDuktape_http_server_NativeSession_GetSession(ctx);
	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "server.NativeSession.IsAuthenticated(): Invalid Parameters")); }
	duk_size_t realmLen;
	char *realm = (char*)duk_get_lstring(ctx, 0, &realmLen);

	duk_push_int(ctx, ILibWebServer_Digest_IsAuthenticated(session, realm, (int)realmLen));
	return 1;
}
duk_ret_t ILibDuktape_http_server_NativeSession_Digest_SendUnAuthorized(duk_context *ctx)
{
	ILibWebServer_Session *session = ILibDuktape_http_server_NativeSession_GetSession(ctx);
	if (!duk_is_string(ctx, 0) || !duk_is_string(ctx, 1)) { return(ILibDuktape_Error(ctx, "server.NativeSession.SendUnAuthorized(): Invalid Parameters")); }
	duk_size_t realmLen, htmlLen;
	char *realm = (char*)duk_get_lstring(ctx, 0, &realmLen);
	char *html = (char*)duk_get_lstring(ctx, 1, &htmlLen);
	ILibDuktape_http_session_ptrs *sessionPtrs = (ILibDuktape_http_session_ptrs*)session->Reserved_Transport.ChainLink.ExtraMemoryPtr;

	ILibWebServer_Digest_SendUnauthorized(session, realm, (int)realmLen, html, (int)htmlLen);
	sessionPtrs->req = NULL;

	return 0;
}
duk_ret_t ILibDuktape_http_server_NativeSession_Digest_GetUsername(duk_context *ctx)
{
	ILibWebServer_Session *session = ILibDuktape_http_server_NativeSession_GetSession(ctx);
	duk_push_string(ctx, ILibWebServer_Digest_GetUsername(session));
	return 1;
}
duk_ret_t ILibDuktape_http_server_NativeSession_Digest_ValidatePassword(duk_context *ctx)
{
	ILibWebServer_Session *session = ILibDuktape_http_server_NativeSession_GetSession(ctx);
	duk_size_t pwdLen;
	char *pwd = (char*)duk_get_lstring(ctx, 0, &pwdLen);
	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "server.NativeSession.ValidatePassword(): Invalid Parameter")); }

	duk_push_int(ctx, ILibWebServer_Digest_ValidatePassword(session, pwd, (int)pwdLen));
	return 1;
}
duk_ret_t ILibDuktape_http_server_NativeSession_WebSocket_GetDataType(duk_context *ctx)
{
	ILibWebServer_WebSocket_DataTypes dType;
	ILibWebServer_Session *session;
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, NativeSessionPtr);
	session = (ILibWebServer_Session*)duk_get_pointer(ctx, -1);

	dType = ILibWebServer_WebSocket_GetDataType(session);
	duk_push_int(ctx, (int)dType);
	return(1);
}
duk_ret_t ILibDuktape_http_server_NativeSession_WebSocket_Upgrade(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int maxBuffer = nargs > 0 ? (int)duk_require_int(ctx, 0) : 65535;
	ILibWebServer_Session *session;
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, NativeSessionPtr);
	session = (ILibWebServer_Session*)duk_get_pointer(ctx, -1);
	ILibWebServer_UpgradeWebSocket(session, maxBuffer);
	return(0);
}
void ILibDuktape_http_server_NativeSession_PUSH(duk_context *ctx, ILibWebServer_Session* session)
{
	if (session->User != NULL) { duk_push_heapptr(ctx, session->User); return; }

	duk_push_object(ctx);								// [session]
	duk_push_pointer(ctx, session);						// [session][ptr]
	duk_put_prop_string(ctx, -2, NativeSessionPtr);		// [session]
	session->User = duk_get_heapptr(ctx, -1);

	ILibDuktape_CreateInstanceMethod(ctx, "Digest_IsAuthenticated", ILibDuktape_http_server_NativeSession_Digest_IsAuthenticated, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "Digest_SendUnauthorized", ILibDuktape_http_server_NativeSession_Digest_SendUnAuthorized, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "Digest_GetUsername", ILibDuktape_http_server_NativeSession_Digest_GetUsername, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "Digest_ValidatePassword", ILibDuktape_http_server_NativeSession_Digest_ValidatePassword, 1);
	//ILibDuktape_CreateInstanceMethod(ctx, "WebSocket_GetDataType", ILibDuktape_http_server_NativeSession_WebSocket_GetDataType, 0);
	//ILibDuktape_CreateInstanceMethod(ctx, "WebSocket_Upgrade", ILibDuktape_http_server_NativeSession_WebSocket_Upgrade, DUK_VARARGS);

}

duk_ret_t ILibDuktape_http_server_NativeSession_Getter(duk_context *ctx)
{
	ILibWebServer_Session *session;

	duk_push_this(ctx);												// [incomingMessage]
	duk_get_prop_string(ctx, -1, NativeSessionPtr);					// [incomingMessage][ptr]
	session = (ILibWebServer_Session*)duk_get_pointer(ctx, -1);
	duk_pop(ctx);													// [incomingMessage]
	ILibDuktape_http_server_NativeSession_PUSH(ctx, session);		// [incomingMessage][session]
	if (!duk_has_prop_string(ctx, -2, SessionPtrJS))
	{
		duk_dup(ctx, -1);											// [incomingMessage][session][session]
		duk_put_prop_string(ctx, -3, SessionPtrJS);					// [incomingMessage][session]
	}
	return 1;
}


ILibTransport_DoneState ILibDutkape_http_server_rawSocket_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_http_rawSocket *ptrs = (ILibDuktape_http_rawSocket*)user;
	return((ILibTransport_DoneState)ILibAsyncSocket_Send(ptrs->ConnectionToken, buffer, bufferLen, ILibAsyncSocket_MemoryOwnership_USER));
}
void ILibDuktape_http_server_rawSocket_OnData(ILibAsyncSocket_SocketModule socketModule, char* buffer, int *p_beginPointer, int endPointer, ILibAsyncSocket_OnInterrupt* OnInterrupt, void **user, int *PAUSE)
{
	ILibDuktape_http_rawSocket *ptrs = (ILibDuktape_http_rawSocket*)user;
	buffer += *p_beginPointer;
	*p_beginPointer = endPointer;
	*PAUSE = ILibDuktape_DuplexStream_WriteData(ptrs->stream, buffer, endPointer);
}
void ILibDuktape_http_server_rawSocket_OnDisconnect(ILibAsyncSocket_SocketModule socketModule, void *user)
{
	ILibDuktape_http_rawSocket *ptrs = (ILibDuktape_http_rawSocket*)user;
	ILibDuktape_DuplexStream_WriteEnd(ptrs->stream);
}
void ILibDuktape_http_server_rawSocket_OnSendOK(ILibAsyncSocket_SocketModule socketModule, void *user)
{
	ILibDuktape_http_rawSocket *ptrs = (ILibDuktape_http_rawSocket*)user;
	ILibDuktape_DuplexStream_Ready(ptrs->stream);
}
void ILibDuktape_http_server_rawSocket_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_http_rawSocket *ptrs = (ILibDuktape_http_rawSocket*)user;
	ILibAsyncSocket_Disconnect(ptrs->ConnectionToken);
}
void ILibDuktape_http_server_rawSocket_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_http_rawSocket *ptrs = (ILibDuktape_http_rawSocket*)user;
	ILibAsyncSocket_Pause(ptrs->ConnectionToken);
}
void ILibDuktape_http_server_rawSocket_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_http_rawSocket *ptrs = (ILibDuktape_http_rawSocket*)user;
	ILibAsyncSocket_Resume(ptrs->ConnectionToken);
}
duk_ret_t ILibDuktape_http_server_IncomingMessage_rawSocket(duk_context *ctx)
{
	void *ConnectionToken;
	ILibDuktape_http_rawSocket *ptrs;

	duk_push_this(ctx);										// [incomingMessage]
	if (!duk_has_prop_string(ctx, -1, NativeSessionPtr))
	{
		duk_push_null(ctx);
		return 1;
	}

	duk_get_prop_string(ctx, -1, NativeSessionPtr);
	ConnectionToken = ILibWebServer_Session_GetConnectionToken((ILibWebServer_Session*)duk_get_pointer(ctx, -1));
	if (ConnectionToken == NULL)
	{
		duk_push_null(ctx);
		return 1;
	}

	duk_push_object(ctx);													// [socket]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_http_rawSocket));			// [socket][buffer]
	ptrs = (ILibDuktape_http_rawSocket*)Duktape_GetBuffer(ctx, -1, NULL);
	memset(ptrs, 0, sizeof(ILibDuktape_http_rawSocket));
	duk_put_prop_string(ctx, -2, HTTP_SOCKET_BUFFERPTR);					// [socket]

	ptrs->ctx = ctx;
	ptrs->ConnectionToken = ConnectionToken;
	ptrs->self = duk_get_heapptr(ctx, -1);
	ptrs->emitter = ILibDuktape_EventEmitter_Create(ctx);
	ptrs->stream = ILibDuktape_DuplexStream_Init(ctx, ILibDutkape_http_server_rawSocket_WriteSink, ILibDuktape_http_server_rawSocket_EndSink, ILibDuktape_http_server_rawSocket_PauseSink, ILibDuktape_http_server_rawSocket_ResumeSink, ptrs);
	ILibAsyncSocket_UpdateCallbacks(ConnectionToken, ILibDuktape_http_server_rawSocket_OnData, NULL, ILibDuktape_http_server_rawSocket_OnDisconnect, ILibDuktape_http_server_rawSocket_OnSendOK);
	free(ILibAsyncSocket_GetUser(ConnectionToken));
	ILibAsyncSocket_SetUser(ConnectionToken, ptrs);
	return 1;
}
void ILibDuktape_http_server_PUSH_IncomingMessage(duk_context *ctx, ILibHTTPPacket *packet, ILibWebServer_Session *session)
{
	duk_push_object(ctx);							// [obj]
	duk_push_pointer(ctx, packet);					// [obj][packet]
	duk_put_prop_string(ctx, -2, "PacketPtr");		// [obj]
	//duk_push_external_buffer(ctx);					// [obj][buffer]
	//duk_put_prop_string(ctx, -2, "_buffer");		// [obj]

	if (session != NULL)
	{
		duk_push_pointer(ctx, session);						// [obj][session]
		duk_put_prop_string(ctx, -2, NativeSessionPtr);		// [obj]
		ILibDuktape_CreateInstanceMethod(ctx, "Digest_IsAuthenticated", ILibDuktape_http_server_NativeSession_Digest_IsAuthenticated, 1);
		ILibDuktape_CreateInstanceMethod(ctx, "Digest_SendUnauthorized", ILibDuktape_http_server_NativeSession_Digest_SendUnAuthorized, 2);
		ILibDuktape_CreateInstanceMethod(ctx, "Digest_GetUsername", ILibDuktape_http_server_NativeSession_Digest_GetUsername, 0);
		ILibDuktape_CreateInstanceMethod(ctx, "Digest_ValidatePassword", ILibDuktape_http_server_NativeSession_Digest_ValidatePassword, 1);
	}
	if (packet != NULL && packet->Directive != NULL)
	{
		packet->Directive[packet->DirectiveLength] = 0;
		duk_push_string(ctx, packet->Directive);	// [obj][method]
		duk_put_prop_string(ctx, -2, "method");

		packet->DirectiveObj[packet->DirectiveObjLength] = 0;
		duk_push_string(ctx, packet->DirectiveObj);	// [obj][path]
		duk_put_prop_string(ctx, -2, "url");		// [obj]
	}
	else if(packet != NULL)
	{
		duk_push_int(ctx, packet->StatusCode);
		duk_put_prop_string(ctx, -2, "statusCode");
		if (packet->StatusData != NULL)
		{
			packet->StatusData[packet->StatusDataLength] = 0;
			duk_push_string(ctx, packet->StatusData);
			duk_put_prop_string(ctx, -2, "statusMessage");
		}
	}

	if (packet != NULL)
	{
		packetheader_field_node *n = packet->FirstField;
		duk_push_object(ctx);											// [obj][header]
		while (n != NULL)
		{
			duk_push_lstring(ctx, n->Field, n->FieldLength);			// [obj][header][fieldName]
			duk_push_lstring(ctx, n->FieldData, n->FieldDataLength);	// [obj][header][fieldName][fieldValue]
			duk_put_prop(ctx, -3);										// [obj][header]
			n = n->NextField;
		}
		duk_put_prop_string(ctx, -2, "header");							// [obj]
	}
	if (session != NULL) { ILibDuktape_CreateEventWithGetter(ctx, "socket", ILibDuktape_http_server_IncomingMessage_rawSocket); }
}

void ILibDuktape_http_server_Pause(ILibDuktape_readableStream *sender, void *user)
{
	ILibWebServer_Pause((ILibWebServer_Session*)user);
}
void ILibDuktape_http_server_Resume(ILibDuktape_readableStream *sender, void *user)
{
	ILibWebServer_Resume((ILibWebServer_Session*)user);
}
ILibTransport_DoneState ILibDuktape_http_server_webSocket_WriteHandler(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	return((ILibTransport_DoneState)ILibWebServer_WebSocket_Send(((ILibDuktape_http_server_websocket_ptrs*)user)->session, buffer, bufferLen, stream->writableStream->Reserved == 0 ? ILibWebServer_WebSocket_DataType_BINARY : ILibWebServer_WebSocket_DataType_TEXT, ILibAsyncSocket_MemoryOwnership_USER, ILibWebServer_WebSocket_FragmentFlag_Complete));
}
void ILibDuktape_http_server_webSocket_EndHandler(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibWebServer_WebSocket_Close(((ILibDuktape_http_server_websocket_ptrs*)user)->session);
}
void ILibDuktape_http_server_webSocket_PauseHandler(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibWebServer_Pause(((ILibDuktape_http_server_websocket_ptrs*)user)->session);
}
void ILibDuktape_http_server_webSocket_ResumeHandler(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibWebServer_Resume(((ILibDuktape_http_server_websocket_ptrs*)user)->session);
}
void ILibDuktape_http_server_webSocket_OnReceive(struct ILibWebServer_Session *sender, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, ILibWebServer_DoneFlag done)
{
	ILibDuktape_http_server_websocket_ptrs *ptrs = (ILibDuktape_http_server_websocket_ptrs*)((void**)sender->Reserved_Transport.ChainLink.ExtraMemoryPtr)[0];
	*beginPointer = endPointer;

	if (done == ILibWebServer_DoneFlag_Done)
	{
		ILibDuktape_DuplexStream_WriteEnd(ptrs->ds);
		sender->OnDisconnect = NULL;
	}
	else
	{
		ILibDuktape_DuplexStream_WriteDataEx(ptrs->ds, ILibWebServer_WebSocket_GetDataType(sender) == ILibWebServer_WebSocket_DataType_TEXT ? 1 : 0, bodyBuffer, endPointer);
	}
}
void ILibDuktape_http_server_webSocket_OnDisconnect(struct ILibWebServer_Session *sender)
{
	ILibDuktape_http_server_websocket_ptrs *ptrs = (ILibDuktape_http_server_websocket_ptrs*)((void**)sender->Reserved_Transport.ChainLink.ExtraMemoryPtr)[0];
	ILibDuktape_DuplexStream_WriteEnd(ptrs->ds);
	sender->OnDisconnect = NULL;

	duk_push_heapptr(ptrs->emitter->ctx, ptrs->emitter->object);
	duk_del_prop_string(ptrs->emitter->ctx, -1, NativeSessionPtr);
	duk_pop(ptrs->emitter->ctx);
}
void ILibDuktape_http_server_webSocket_OnSendOK(struct ILibWebServer_Session *sender)
{
	ILibDuktape_http_server_websocket_ptrs *ptrs = (ILibDuktape_http_server_websocket_ptrs*)((void**)sender->Reserved_Transport.ChainLink.ExtraMemoryPtr)[0];
	ILibDuktape_DuplexStream_Ready(ptrs->ds);
}
void ILibDuktape_http_server_IntermediateSocket_Finalizer(duk_context *ctx, void *obj)
{
	duk_push_heapptr(ctx, obj);
	if (duk_has_prop_string(ctx, -1, NativeSessionPtr))
	{
		duk_get_prop_string(ctx, -1, NativeSessionPtr);
		ILibWebServer_Session *session = (ILibWebServer_Session*)duk_get_pointer(ctx, -1);

		session->OnDisconnect = NULL;
		session->OnReceive = NULL;
		session->OnSendOK = NULL;

		ILibWebServer_DisconnectSession(session);
	}
}
duk_ret_t ILibDuktape_http_server_IntermediateSocket_upgradeWebSocket(duk_context *ctx)
{
	ILibWebServer_Session *session;
	int bufferSize = duk_get_top(ctx) == 0 ? 65535 : duk_require_int(ctx, 0);
	duk_push_this(ctx);																// [socket]
	duk_get_prop_string(ctx, -1, NativeSessionPtr);									// [socket][ptr]
	session = (ILibWebServer_Session*)duk_get_pointer(ctx, -1);
	duk_pop(ctx);																	// [socket]
	if (ILibWebServer_UpgradeWebSocket(session, bufferSize) != 0) { return(ILibDuktape_Error(ctx, "upgradeWebSocket(): Invalid State")); }
	
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_http_server_websocket_ptrs));		// [socket][buffer]
	ILibDuktape_http_server_websocket_ptrs *ptrs = (ILibDuktape_http_server_websocket_ptrs*)Duktape_GetBuffer(ctx, -1, NULL);
	memset(ptrs, 0, sizeof(ILibDuktape_http_server_websocket_ptrs));
	duk_put_prop_string(ctx, -2, HTTP_SOCKET_PTRS);									// [socket]

	ILibDuktape_CreateIndependentFinalizer(ctx, ILibDuktape_http_server_IntermediateSocket_Finalizer);

	((void**)session->Reserved_Transport.ChainLink.ExtraMemoryPtr)[0] = ptrs;
	ptrs->session = session;
	ptrs->emitter = ILibDuktape_EventEmitter_Create(ctx);
	ptrs->ds = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_http_server_webSocket_WriteHandler, ILibDuktape_http_server_webSocket_EndHandler, ILibDuktape_http_server_webSocket_PauseHandler, ILibDuktape_http_server_webSocket_ResumeHandler, ptrs);
	
	// Redirect these events, because it's now a websocket
	session->OnDisconnect = ILibDuktape_http_server_webSocket_OnDisconnect;
	session->OnReceive = ILibDuktape_http_server_webSocket_OnReceive;
	session->OnSendOK = ILibDuktape_http_server_webSocket_OnSendOK;
	
	return(1);
}
duk_ret_t ILibDuktape_http_server_IntermediateSocket_end(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, NativeSessionPtr);
	ILibWebServer_DisconnectSession((ILibWebServer_Session*)duk_get_pointer(ctx, -1));
	return(0);
}
void ILibDuktape_http_server_PUSH_IntermediateSocket(duk_context *ctx, ILibWebServer_Session *session)
{
	duk_push_object(ctx);								// [sock]
	duk_push_pointer(ctx, session);						// [sock][session]
	duk_put_prop_string(ctx, -2, NativeSessionPtr);		// [sock]

	ILibDuktape_CreateInstanceMethod(ctx, "upgradeWebSocket", ILibDuktape_http_server_IntermediateSocket_upgradeWebSocket, DUK_VARARGS);
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "end", ILibDuktape_http_server_IntermediateSocket_end, 0);
}
void ILibDuktape_http_server_OnReceive(struct ILibWebServer_Session *sender, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, ILibWebServer_DoneFlag done)
{
	ILibDuktape_http_server_ptrs* serverPtrs = (ILibDuktape_http_server_ptrs*)sender->ParentExtraMemory;
	ILibDuktape_http_session_ptrs *sessionPtrs = (ILibDuktape_http_session_ptrs*)sender->Reserved_Transport.ChainLink.ExtraMemoryPtr;
	char *headerVal;
	int headerValLen;
	int r = 0;

	if (ILibGetHeaderLineEx(header, "upgrade", 7, NULL) != NULL)
	{
		if (serverPtrs->OnUpgrade != NULL)
		{
			duk_push_heapptr(serverPtrs->ctx, serverPtrs->OnUpgrade);						// [func]
			duk_push_heapptr(serverPtrs->ctx, serverPtrs->serverObject);					// [func][this]
			ILibDuktape_http_server_PUSH_IncomingMessage(serverPtrs->ctx, header, sender);	// [func][this][incoming]
			ILibDuktape_http_server_PUSH_IntermediateSocket(serverPtrs->ctx, sender);		// [func][this][incoming][socket]
			duk_push_null(serverPtrs->ctx);													// [func][this][incoming][socket][head]
						
			if (duk_pcall_method(serverPtrs->ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(serverPtrs->ctx, "Server.OnUpgrade(): "); }
			duk_pop(serverPtrs->ctx);													    // ...
		}

		return;
	}
	if ((headerVal = ILibGetHeaderLineEx(header, "expect", 6, &headerValLen)) != NULL)
	{
		if (ILibString_StartsWith(headerVal, headerValLen, "100-", 4))
		{
			if (serverPtrs->OnCheckContinue != NULL)
			{
				duk_push_heapptr(serverPtrs->ctx, serverPtrs->OnCheckContinue);							// [func]
				duk_push_heapptr(serverPtrs->ctx, serverPtrs->serverObject);							// [func][this]

				ILibDuktape_http_server_PUSH_IncomingMessage(serverPtrs->ctx, header, sender);			// [func][this][incoming]
				sessionPtrs->req = ILibDuktape_InitReadableStream(serverPtrs->ctx, NULL, NULL, NULL);
				ILibDuktape_readableStream_SetPauseResumeHandlers(sessionPtrs->req, ILibDuktape_http_server_Pause, ILibDuktape_http_server_Resume, sender);
				sessionPtrs->res = ILibDuktape_http_server_PUSH_ServerResponse(serverPtrs->ctx, sender);// [func][this][incoming][res]
				if (duk_pcall_method(serverPtrs->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(serverPtrs->ctx, "httpServer.onCheckContinue(): "); }
				duk_pop(serverPtrs->ctx);																// ...
			}
			else
			{
				// Noboddy is listening for checkContinue, so we must send a 100-Continue manually
				ILibWebServer_Send_Raw(sender, "HTTP/1.1 Continue\r\n\r\n", 25, ILibAsyncSocket_MemoryOwnership_STATIC, ILibWebServer_DoneFlag_NotDone);
			}
			ILibDeleteHeaderLine(header, "expect", 6);
		}
	}
	else
	{
		// The very first time, Server.request event will be emitted
		if (sessionPtrs->req == NULL && serverPtrs->OnResponse != NULL)
		{
			duk_push_heapptr(serverPtrs->ctx, serverPtrs->OnResponse);										// [func]
			ILibDuktape_http_server_PUSH_IncomingMessage(serverPtrs->ctx, header, sender);					// [func][req]
			sessionPtrs->req = ILibDuktape_InitReadableStream(serverPtrs->ctx, NULL, NULL, NULL);
			ILibDuktape_readableStream_SetPauseResumeHandlers(sessionPtrs->req, ILibDuktape_http_server_Pause, ILibDuktape_http_server_Resume, sender);

			duk_push_heap_stash(serverPtrs->ctx);														// [func][req][stash]
			duk_dup(serverPtrs->ctx, -2);																// [func][req][stash][req]
			duk_put_prop_string(serverPtrs->ctx, -2, Duktape_GetStashKey(sessionPtrs->req->object));	// [func][req][stash]
			duk_pop(serverPtrs->ctx);																	// [func][req]

			sessionPtrs->res = ILibDuktape_http_server_PUSH_ServerResponse(serverPtrs->ctx, sender);	// [func][req][res]
			if (duk_pcall(serverPtrs->ctx, 2) != 0)														// [retVal]
			{
				ILibDuktape_Process_UncaughtException(serverPtrs->ctx);
			}
			duk_pop(serverPtrs->ctx);																	// ...
		}
	}
	// Now we just write to the ReadableStream
	if (sessionPtrs->req != NULL)
	{
		if (endPointer > 0)
		{
			r += ILibDuktape_readableStream_WriteData(sessionPtrs->req, bodyBuffer + *beginPointer, endPointer - *beginPointer);
		}
		if (done == ILibWebServer_DoneFlag_Done && r == 0)
		{
			r += ILibDuktape_readableStream_WriteEnd(sessionPtrs->req);
		}
		if (done == ILibWebServer_DoneFlag_Done && r == 0)
		{
			duk_push_heap_stash(serverPtrs->ctx);	// [stash]
			duk_del_prop_string(serverPtrs->ctx, -1, Duktape_GetStashKey(sessionPtrs->req->object));
			duk_pop(serverPtrs->ctx);				// ...
		}
	}

	if (r == 0) { *beginPointer = endPointer; }
	if (done == ILibWebServer_DoneFlag_Done && sender->OnReceive == ILibDuktape_http_server_OnReceive) { sessionPtrs->req = NULL; }
}
void ILibDuktape_http_server_OnSendOK(ILibWebServer_Session *sender)
{
	ILibDuktape_http_session_ptrs *sessionPtrs = (ILibDuktape_http_session_ptrs*)sender->Reserved_Transport.ChainLink.ExtraMemoryPtr;
	ILibDuktape_WritableStream_Ready(sessionPtrs->res);
}

void ILibDuktape_http_server_OnSession(ILibWebServer_Session *session, void *user)
{
	session->OnReceive = ILibDuktape_http_server_OnReceive;
	session->OnSendOK = ILibDuktape_http_server_OnSendOK;
}

#ifndef MICROSTACK_NOTLS
int ILibDuktape_http_server_clientVerify(ILibWebServer_ServerToken sender, int preverify_ok, STACK_OF(X509) *certs, struct sockaddr_in6* address)
{
	int i;
	int retVal = 1;
	ILibDuktape_http_server_ptrs *ptrs = (ILibDuktape_http_server_ptrs*)((ILibChain_Link*)sender)->ExtraMemoryPtr;
	void *OnVerify;
	int rejectUnauthorized = 0;
	char addr[512];

	duk_push_heapptr(ptrs->ctx, ptrs->serverObject);											// [server]
	duk_get_prop_string(ptrs->ctx, -1, TLSPTR);													// [server][tlsSettings]
	OnVerify = Duktape_GetHeapptrProperty(ptrs->ctx, -1, "checkClientIdentity");
	rejectUnauthorized = Duktape_GetBooleanProperty(ptrs->ctx, -1, "rejectUnauthorized ", 0);
	duk_pop_2(ptrs->ctx);																		// ...

	if (rejectUnauthorized != 0 && preverify_ok == 0) { retVal = 0; }
	if (OnVerify != NULL)
	{
		duk_push_heapptr(ptrs->ctx, OnVerify);													// [func]
		duk_push_heapptr(ptrs->ctx, ptrs->serverObject);										// [func][this]
		ILibInet_ntop2((struct sockaddr*)address, addr, sizeof(addr));
		duk_push_string(ptrs->ctx, addr);														// [func][this][server]
		duk_push_array(ptrs->ctx);																// [func][this][server][certs]
		for (i = 0; i < sk_X509_num(certs); ++i)
		{
			ILibDuktape_X509_PUSH(ptrs->ctx, sk_X509_value(certs, i));							// [func][this][server][certs][cert]
			duk_put_prop_index(ptrs->ctx, -2, i);												// [func][this][server][certs]
		}
		if (duk_pcall_method(ptrs->ctx, 2) != 0) { retVal = 0; }								// [retVal]
		duk_pop(ptrs->ctx);																		// ...
	}
	return retVal;
}
#endif
duk_ret_t ILibDuktape_http_server_finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, HTTP_SERVER_PTR);
	ILibWebServer_ServerToken server = (ILibWebServer_ServerToken)duk_get_pointer(ctx, -1);
	void *chain = Duktape_GetChain(ctx);

	if (ILibIsChainBeingDestroyed(chain) == 0)
	{
		// SafeRemove Server here...
		ILibChain_SafeRemove(chain, server);
	}

	return(0);
}
duk_ret_t ILibDuktape_http_server_listen(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int port = duk_require_int(ctx, 0);
	//char *host = nargs > 1 ? ((char*)duk_require_string(ctx, 1)) : NULL;
	int maxConnections = nargs > 2 ? duk_require_int(ctx, 2) : 5;
	void *chain;
	ILibWebServer_ServerToken server;
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_GetEmitter_fromThis(ctx);

	duk_push_this(ctx);								// [server]
	duk_get_prop_string(ctx, -1, "chain");			// [server][chain]
	chain = duk_to_pointer(ctx, -1);
	duk_pop(ctx);									// [server]

	server = ILibWebServer_Create2(chain, maxConnections, port, ILibDuktape_http_server_OnSession, sizeof(ILibDuktape_http_server_ptrs), NULL);
	((ILibDuktape_http_server_ptrs*)((ILibChain_Link*)server)->ExtraMemoryPtr)->ctx = ctx;
	((ILibDuktape_http_server_ptrs*)((ILibChain_Link*)server)->ExtraMemoryPtr)->serverObject = duk_get_heapptr(ctx, -1);
	
	ILibDuktape_EventEmitter_AddEventHeapptr(emitter, "request", &(((ILibDuktape_http_server_ptrs*)((ILibChain_Link*)server)->ExtraMemoryPtr)->OnResponse));
	ILibDuktape_EventEmitter_AddEventHeapptr(emitter, "connect", &(((ILibDuktape_http_server_ptrs*)((ILibChain_Link*)server)->ExtraMemoryPtr)->OnConnect));
	ILibDuktape_EventEmitter_AddEventHeapptr(emitter, "upgrade", &(((ILibDuktape_http_server_ptrs*)((ILibChain_Link*)server)->ExtraMemoryPtr)->OnUpgrade));
	ILibDuktape_EventEmitter_AddEventHeapptr(emitter, "checkContinue", &(((ILibDuktape_http_server_ptrs*)((ILibChain_Link*)server)->ExtraMemoryPtr)->OnCheckContinue));

#ifndef MICROSTACK_NOTLS
	if (duk_has_prop_string(ctx, -1, TLSPTR))
	{
		struct util_cert *cert;
		struct util_cert *nonleaf = NULL;

		duk_get_prop_string(ctx, -1, TLSPTR);									// [server][tlsSettings]
		duk_get_prop_string(ctx, -1, TLS_CERT);									// [server][tlsSettings][cert]
		cert = (struct util_cert*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop(ctx);															// [server][tlsSettings]
		if (duk_has_prop_string(ctx, -1, TLS_CERT_NON_LEAF))
		{
			duk_get_prop_string(ctx, -1, TLS_CERT_NON_LEAF);					// [server][tlsSettings][nonleaf]
			nonleaf = (struct util_cert*)Duktape_GetBuffer(ctx, -1, NULL);
			duk_pop(ctx);														// [server][tlsSettings]
		}

		ILibWebServer_EnableHTTPS(server, cert, nonleaf != NULL ? nonleaf->x509 : NULL, Duktape_GetBooleanProperty(ctx, -1, "requestCert", 0), ILibDuktape_http_server_clientVerify);
		duk_pop(ctx);															// [server]
	}
#endif

	duk_push_pointer(ctx, server);					// [server][serverPtr]
	duk_put_prop_string(ctx, -2, HTTP_SERVER_PTR);	// [server]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_http_server_finalizer);

	return 0;
}

duk_ret_t ILibDuktape_http_server_tlsSettings_Finalizer(duk_context *ctx)
{
	return 0;
}
duk_ret_t ILibDuktape_http_createServer(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int i;

	ILibDuktape_EventEmitter *emitter;

	duk_push_this(ctx);								// [http]
	duk_get_prop_string(ctx, -1, "chain");			// [http][chain]

	duk_push_object(ctx);							// [http][chain][server]
	duk_swap_top(ctx, -2);							// [http][server][chain]
	duk_put_prop_string(ctx, -2, "chain");			// [http][server]

	emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "request");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "listening");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "upgrade");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "connect");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "checkContinue");

	for (i = 0; i < nargs; ++i)
	{
		if (duk_is_function(ctx, i))
		{
			// requestListener
			ILibDuktape_EventEmitter_AddOn(emitter, "request", duk_require_heapptr(ctx, i));
		}
		else if (duk_is_object(ctx, i))
		{
			// options
			if (duk_has_prop_string(ctx, 0, "request"))
			{
				ILibDuktape_EventEmitter_AddOn(emitter, "request", Duktape_GetHeapptrProperty(ctx, 0, "request"));
			}
			else if (duk_has_prop_string(ctx, i, "MeshAgent"))
			{
#ifndef MICROSTACK_NOTLS
				struct util_cert *cert;
				struct util_cert *nonleaf;

				duk_get_prop_string(ctx, i, "MeshAgent");														// [http][server][MeshAgent]
				duk_get_prop_string(ctx, -1, ILibDuktape_MeshAgent_Cert_Server);								// [http][server][MeshAgent][cert]
				cert = (struct util_cert*)duk_get_pointer(ctx, -1);
				duk_get_prop_string(ctx, -2, ILibDuktape_MeshAgent_Cert_NonLeaf);								// [http][server][MeshAgent][cert][nonleaf]
				nonleaf = (struct util_cert*)duk_get_pointer(ctx, -1);
				duk_pop_3(ctx);																					// [http][server]
				duk_push_object(ctx);																			// [http][server][tlsSettings]
				duk_push_external_buffer(ctx);																	// [http][server][tlsSettings][cert]
				duk_config_buffer(ctx, -1, cert, sizeof(struct util_cert));
				duk_put_prop_string(ctx, -2, TLS_CERT);															// [http][server][tlsSettings]
				duk_push_external_buffer(ctx);																	// [http][server][tlsSettings][nonleaf]
				duk_config_buffer(ctx, -1, nonleaf, sizeof(struct util_cert));			
				duk_put_prop_string(ctx, -2, TLS_CERT_NON_LEAF);												// [http][server][tlsSettings]
				duk_put_prop_string(ctx, -2, TLSPTR);															// [http][server]
#else
				return(ILibDuktape_Error(ctx, "createServer(): Invalid Argument. MeshAgent only valid with TLS support"));
#endif
			}
#ifndef MICROSTACK_NOTLS
			else if (duk_has_prop_string(ctx, i, "pfx") && duk_has_prop_string(ctx, i, "passphrase"))
			{
				struct util_cert *cert;
				char *pfx;
				duk_size_t pfxLen;
				char *passphrase;

				duk_get_prop_string(ctx, i, "pfx");							// [http][server][pfx]
				pfx = Duktape_GetBuffer(ctx, -1, &pfxLen);
				duk_pop(ctx);												// [http][server]
				duk_get_prop_string(ctx, i, "passphrase");					// [http][server][passphrase]
				passphrase = Duktape_GetBuffer(ctx, -1, NULL);		
				duk_pop(ctx);												// [http][server]

				duk_push_object(ctx);										// [http][server][tlsSettings]
				duk_push_fixed_buffer(ctx, sizeof(struct util_cert));		// [http][server][tlsSettings][cert]
				cert = (struct util_cert*)Duktape_GetBuffer(ctx, -1, NULL);
				duk_put_prop_string(ctx, -2, TLS_CERT);						// [http][server][tlsSettings]

				if (util_from_p12(pfx, (int)pfxLen, passphrase, cert) == 0) { duk_push_string(ctx, "ERROR reading certificate");	duk_throw(ctx);	return(DUK_RET_ERROR); }
				else
				{
					ILibDuktape_CreateFinalizer(ctx, ILibDuktape_http_server_tlsSettings_Finalizer);
					duk_put_prop_string(ctx, -2, TLSPTR);					// [http][server]
				}
			}
#endif

			if (duk_has_prop_string(ctx, -1, TLSPTR))															// [http][server]
			{
				duk_get_prop_string(ctx, -1, TLSPTR);															// [http][server][tlsSettings]
				duk_push_boolean(ctx, (duk_bool_t)Duktape_GetBooleanProperty(ctx, i, "requestCert", 0));		// [http][server][tlsSettings][requestCert]
				duk_put_prop_string(ctx, -2, "requestCert");													// [http][server][tlsSettings]
				duk_push_boolean(ctx, (duk_bool_t)Duktape_GetBooleanProperty(ctx, i, "rejectUnauthorized", 0));	// [http][server][tlsSettings][reject]
				duk_put_prop_string(ctx, -2, "rejectUnauthorized");												// [http][server][tlsSettings]
				duk_push_heapptr(ctx, Duktape_GetHeapptrProperty(ctx, i, "checkClientIdentity"));				// [http][server][tlsSettings][checkClient]
				duk_put_prop_string(ctx, -2, "checkClientIdentity");											// [http][server][tlsSettings]
				duk_put_prop_string(ctx, -2, TLSPTR);															// [http][server]
			}

		}
	}

	duk_push_c_function(ctx, ILibDuktape_http_server_listen, DUK_VARARGS);	// [http][server][func]
	duk_put_prop_string(ctx, -2, "listen");									// [http][server]

	return 1;
}

void ILibDuktape_http_request_Pause(ILibDuktape_readableStream* sender, void *user)
{
	ILibWebClient_Pause(user);
}
void ILibDuktape_http_request_Resume(ILibDuktape_readableStream* sender, void *user)
{
	ILibWebClient_Resume(user);
}

void ILibDuktape_http_request_OnResponse(ILibWebClient_StateObject WebStateObject, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, ILibWebClient_ReceiveStatus recvStatus, void *user1, void *user2, int *PAUSE)
{
	int r = 0;
	duk_context *ctx = (duk_context*)user1;
	ILibDuktape_http_requestClient_callbacks *ptrs = (ILibDuktape_http_requestClient_callbacks*)user2;
	
	if (ptrs == NULL) { return; }
	if(ptrs->readableStream != NULL)
	{
		if (endPointer > 0)
		{
			r += ILibDuktape_readableStream_WriteData(ptrs->readableStream, bodyBuffer + *beginPointer, endPointer - *beginPointer);
		}
		if(r == 0 && recvStatus == ILibWebClient_ReceiveStatus_Complete)
		{
			r += ILibDuktape_readableStream_WriteEnd(ptrs->readableStream);
		}
	}
	else
	{
		if (InterruptFlag != 0 || header == NULL)
		{
			if (ctx != NULL)
			{
				duk_push_heapptr(ctx, ptrs->OnReceive);				// [func]
				duk_push_heapptr(ctx, ptrs->clientRequest);			// [func][this]
				duk_del_prop_string(ctx, -1, HTTP_REQUEST_TOKEN_PTR);						// (Prevents crash in Request Finalizer)
				duk_push_null(ctx);									// [func][this][null]
				if (duk_pcall_method(ctx, 1) != 0)					// [retVal]
				{
					ILibDuktape_Process_UncaughtException(ctx);
				}
				duk_pop(ctx);										// ...
			}
			return;
		}

		if ((header->StatusCode == 100 && ptrs->OnContinue != NULL) || ptrs->OnReceive != NULL)
		{
			ILibDuktape_http_server_PUSH_IncomingMessage(ctx, header, NULL);							// [iMsg]
			duk_push_pointer(ctx, WebStateObject);
			duk_put_prop_string(ctx, -2, HTTP_INCOMINGMSG_WebStateObject);

			ptrs->readableStream = ILibDuktape_InitReadableStream(ctx, NULL, NULL, NULL);
			ILibDuktape_readableStream_SetPauseResumeHandlers(ptrs->readableStream, ILibDuktape_http_request_Pause, ILibDuktape_http_request_Resume, WebStateObject);

			duk_push_heapptr(ctx, ptrs->clientRequest);													// [iMsg][clientRequest]
			duk_swap_top(ctx, -2);																		// [clientRequest][iMsg]
			duk_dup(ctx, -1);																			// [clientRequest][iMsg][iMsg]
			duk_put_prop_string(ctx, -3, "_iMsgPtr");													// [clientRequest][iMsg]
			duk_swap_top(ctx, -2);																		// [iMsg][clientRequest]
			if (header->StatusCode == 100 && ptrs->OnContinue != NULL)
			{
				duk_push_heapptr(ctx, ptrs->OnContinue);												// [iMsg][clientRequest][func]
			}
			else
			{
				duk_push_heapptr(ctx, ptrs->OnReceive);													// [iMsg][clientRequest][func]
			}
			duk_swap(ctx, -3, -1);																		// [func][clientRequest/this][iMsg]
			if (duk_pcall_method(ctx, 1) != 0)															// [retVal]
			{
				ILibDuktape_Process_UncaughtException(ctx);
			}
			duk_pop(ctx);																				// ...
		}
		if (endPointer > 0) { r += ILibDuktape_readableStream_WriteData(ptrs->readableStream, bodyBuffer + *beginPointer, endPointer - *beginPointer); }
		if (r == 0 && recvStatus == ILibWebClient_ReceiveStatus_Complete) { r += ILibDuktape_readableStream_WriteEnd(ptrs->readableStream); }
	}

	if (r == 0) { *beginPointer = endPointer; }
	if (recvStatus == ILibWebClient_ReceiveStatus_Complete)
	{
		duk_push_heapptr(ctx, ptrs->clientRequest);							// [clientRequest]
		duk_del_prop_string(ctx, -1, HTTP_REQUEST_TOKEN_PTR);
		ILibDuktape_EventEmitter_RemoveAll(ILibDuktape_EventEmitter_GetEmitter(ctx, -1));
		duk_pop(ctx);														// ...
	}
}


ILibTransport_DoneState ILibDuktape_http_WebSocket_socket_write(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_WebSocket_Pointers *ptrs = (ILibDuktape_WebSocket_Pointers*)user;
	if (ptrs->wcdo == NULL) 
	{ 
		return(ILibTransport_DoneState_ERROR); 
	}
	return((ILibTransport_DoneState)ILibWebClient_WebSocket_Send(ptrs->wcdo, ILibWebClient_WebSocket_DataType_BINARY, buffer, bufferLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete));
}
void ILibDuktape_http_WebSocket_socket_end(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_WebSocket_Pointers *ptrs = (ILibDuktape_WebSocket_Pointers*)user;
	ILibWebClient_StateObject wcdo = ptrs->wcdo;

	ptrs->wcdo = NULL;
	if (wcdo != NULL) { ILibWebClient_Disconnect(wcdo); }
}
void ILibDuktape_http_WebSocket_socket_pause(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_WebSocket_Pointers *ptrs = (ILibDuktape_WebSocket_Pointers*)user;
	ILibWebClient_Pause(ptrs->wcdo);
}
void ILibDuktape_http_WebSocket_socket_resume(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_WebSocket_Pointers *ptrs = (ILibDuktape_WebSocket_Pointers*)user;
	ILibWebClient_Resume(ptrs->wcdo);
}
duk_ret_t ILibDuktape_http_WebSocket_socket_finalizer(duk_context *ctx)
{
	ILibDuktape_WebSocket_Pointers *ptrs;

	if (duk_has_prop_string(ctx, 0, HTTP_SOCKET_PTRS))
	{
		duk_get_prop_string(ctx, 0, HTTP_SOCKET_PTRS);
		ptrs = (ILibDuktape_WebSocket_Pointers*)duk_get_pointer(ctx, -1);
		ILibWebClient_Disconnect(ptrs->wcdo);
	}
	return 0;
}
void ILibDuktape_http_WebSocket_timeoutSink(ILibWebClient_StateObject state, void *user)
{
	ILibDuktape_WebSocket_Pointers *ptrs = (ILibDuktape_WebSocket_Pointers*)user;

	if (ptrs->onTimeout != NULL)
	{
		duk_push_heapptr(ptrs->ctx, ptrs->onTimeout);	// [func]
		duk_push_heapptr(ptrs->ctx, ptrs->socket_ptr);	// [func][this]
		if (duk_pcall_method(ptrs->ctx, 0) != 0) { ILibDuktape_Process_UncaughtException(ptrs->ctx); }
		duk_pop(ptrs->ctx);
	}
	if (ptrs->timeout > 0) { ILibWebClient_SetTimeout(ptrs->wcdo, ptrs->timeout, ILibDuktape_http_WebSocket_timeoutSink, ptrs); }
}
duk_ret_t ILibDuktape_http_WebSocket_setTimeout(duk_context *ctx)
{
	ILibDuktape_EventEmitter *emitter;
	ILibDuktape_WebSocket_Pointers *ptrs;
	int nargs = duk_get_top(ctx);
	int milliseconds = duk_require_int(ctx, 0);

	duk_push_this(ctx);															// [socket]
	duk_get_prop_string(ctx, -1, HTTP_SOCKET_PTRS);								// [socket][ptrs]
	ptrs = (ILibDuktape_WebSocket_Pointers*)duk_get_pointer(ctx, -1);
	
	if (milliseconds < 1000) { return(ILibDuktape_Error(ctx, "http/net.socket.setTimeout(): Error, timeout cannot be less than 1 second")); }
	ILibWebClient_SetTimeout(ptrs->wcdo, milliseconds / 1000, ILibDuktape_http_WebSocket_timeoutSink, ptrs);
	ptrs->timeout = milliseconds / 1000;
	if (nargs > 1)
	{
		emitter = ILibDuktape_EventEmitter_GetEmitter_fromThis(ctx);
		ILibDuktape_EventEmitter_AddOnce(emitter, "timeout", duk_require_heapptr(ctx, 1));
	}

	return 0;
}
duk_ret_t ILibDuktape_http_WebSocket_ping(duk_context *ctx)
{
	ILibDuktape_WebSocket_Pointers *ptrs;

	duk_push_this(ctx);															// [socket]
	duk_get_prop_string(ctx, -1, HTTP_SOCKET_PTRS);								// [socket][ptrs]
	ptrs = (ILibDuktape_WebSocket_Pointers*)duk_get_pointer(ctx, -1);

	ILibWebClient_WebSocket_Ping(ptrs->wcdo);

	return 0;
}
duk_ret_t ILibDuktape_http_WebSocket_pong(duk_context *ctx)
{
	ILibDuktape_WebSocket_Pointers *ptrs;

	duk_push_this(ctx);															// [socket]
	duk_get_prop_string(ctx, -1, HTTP_SOCKET_PTRS);								// [socket][ptrs]
	ptrs = (ILibDuktape_WebSocket_Pointers*)duk_get_pointer(ctx, -1);

	ILibWebClient_WebSocket_Pong(ptrs->wcdo);
	return 0;
}
ILibWebClient_WebSocket_PingResponse ILibDuktape_http_WebSocket_pingHandler(ILibWebClient_StateObject state, void *user)
{
	ILibDuktape_WebSocket_Pointers *ptrs = (ILibDuktape_WebSocket_Pointers*)user;
	ILibWebClient_WebSocket_PingResponse retVal = ILibWebClient_WebSocket_PingResponse_Respond;

	if (ptrs->onPing != NULL)
	{
		duk_push_heapptr(ptrs->ctx, ptrs->onPing);			// [func]
		duk_push_heapptr(ptrs->ctx, ptrs->socket_ptr);		// [func][this]
		if (duk_pcall_method(ptrs->ctx, 0) != 0) { retVal = ILibWebClient_WebSocket_PingResponse_None; }
		duk_pop(ptrs->ctx);									// ...
	}

	return retVal;
}
void ILibDuktape_http_WebSocket_pongHandler(ILibWebClient_StateObject state, void *user)
{
	ILibDuktape_WebSocket_Pointers *ptrs = (ILibDuktape_WebSocket_Pointers*)user;

	if (ptrs->onPong != NULL)
	{
		duk_push_heapptr(ptrs->ctx, ptrs->onPong);			// [func]
		duk_push_heapptr(ptrs->ctx, ptrs->socket_ptr);		// [func][this]
		if (duk_pcall_method(ptrs->ctx, 0) != 0) { ILibDuktape_Process_UncaughtException(ptrs->ctx); }
		duk_pop(ptrs->ctx);									// ...
	}
}
void ILibDuktape_http_WebSocket_PUSH_socket(duk_context *ctx, ILibWebClient_StateObject *wcdo, ILibDuktape_WebSocket_Pointers* ptrs)
{
	ILibDuktape_EventEmitter *emitter;

	if (ptrs->socket_ptr == NULL)
	{
		duk_push_object(ctx);																// [socket]
		duk_push_pointer(ctx, ptrs);														// [socket][ptr]
		duk_put_prop_string(ctx, -2, HTTP_SOCKET_PTRS);										// [socket]
		ptrs->socket_ptr = duk_get_heapptr(ctx, -1);
		ptrs->stream = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_http_WebSocket_socket_write, ILibDuktape_http_WebSocket_socket_end, ILibDuktape_http_WebSocket_socket_pause, ILibDuktape_http_WebSocket_socket_resume, ptrs);
		ptrs->wcdo = wcdo;
		ILibDuktape_CreateFinalizer(ctx, ILibDuktape_http_WebSocket_socket_finalizer);
		emitter = ILibDuktape_EventEmitter_Create(ctx);
		ILibDuktape_EventEmitter_CreateEvent(emitter, "timeout", &(ptrs->onTimeout));
		ILibDuktape_EventEmitter_CreateEvent(emitter, "ping", &(ptrs->onPing));
		ILibDuktape_EventEmitter_CreateEvent(emitter, "pong", &(ptrs->onPong));
		ILibDuktape_CreateProperty_InstanceMethod(ctx, "ping", ILibDuktape_http_WebSocket_ping, DUK_VARARGS);
		ILibDuktape_CreateProperty_InstanceMethod(ctx, "pong", ILibDuktape_http_WebSocket_pong, DUK_VARARGS);
		ILibDuktape_CreateInstanceMethod(ctx, "setTimeout", ILibDuktape_http_WebSocket_setTimeout, DUK_VARARGS);

		ILibWebClient_WebSocket_SetPingPongHandler(ptrs->wcdo, ILibDuktape_http_WebSocket_pingHandler, ILibDuktape_http_WebSocket_pongHandler, ptrs);
	}
	else
	{
		duk_push_heapptr(ctx, ptrs->socket_ptr);											// [socket]
	}
}

void ILibDuktape_http_request_WebSocket_OnResponse(ILibWebClient_StateObject WebStateObject, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, ILibWebClient_ReceiveStatus recvStatus, void *user1, void *user2, int *PAUSE)
{
	duk_context *ctx = (duk_context*)user1;
	ILibDuktape_WebSocket_Pointers *ptrs = (ILibDuktape_WebSocket_Pointers*)user2;

	if (ctx == NULL || ptrs == NULL) { return; }
	duk_push_heapptr(ctx, ptrs->clientRequest_ptr);
	duk_del_prop_string(ctx, -1, HTTP_REQUEST_TOKEN_PTR);
	void **user = ILibWebClient_RequestToken_GetUserObjects(ILibWebClient_GetRequestToken_FromStateObject(WebStateObject));
	duk_pop(ctx);

	if (header != NULL && header->StatusCode != 101)
	{
		duk_push_heapptr(ctx, ptrs->clientRequest_ptr);												// [clientRequest]
		duk_get_prop_string(ctx, -1, "emit");														// [clientRequest][emit]
		duk_swap_top(ctx, -2);																		// [emit][this]
		duk_push_string(ctx, "response");															// [emit][this][response]

		ILibDuktape_http_server_PUSH_IncomingMessage(ctx, header, NULL);							// [emit][this][response][iMsg]
		duk_push_pointer(ctx, WebStateObject);
		duk_put_prop_string(ctx, -2, HTTP_INCOMINGMSG_WebStateObject);								// [emit][this][response][iMsg]
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http_request_WebSocket_OnResponse(): Error dispatching 'response' "); }
		duk_pop(ctx);																				// ...

		*beginPointer = endPointer;
		user[1] = NULL;
		return;
	}

	if (header != NULL && header->StatusCode == 101)
	{
		switch (recvStatus)
		{
			case ILibWebClient_ReceiveStatus_Connection_Established:
				duk_push_heapptr(ctx, ptrs->clientRequest_ptr);							// [clientRequest]
				duk_get_prop_string(ctx, -1, "emit");									// [clientRequest][emit]
				duk_swap_top(ctx, -2);													// [emit][this]
				duk_push_string(ctx, "upgrade");										// [emit][this][upgrade]

				ILibDuktape_http_WebSocket_PUSH_socket(ctx, WebStateObject, ptrs);		// [emit][this][upgrade][socket]
				duk_dup(ctx, -1);														// [emit][this][upgrade][socket][socket]
				duk_put_prop_string(ctx, -4, "\xFF_socket");							// [emit][this][upgrade][socket]
				ILibDuktape_http_server_PUSH_IncomingMessage(ctx, header, NULL);		// [emit][this][upgrade][socket][msg]
				duk_swap_top(ctx, -2);													// [emit][this][upgrade][msg][socket]
				duk_push_null(ctx);														// [emit][this][upgrade][msg][socket][head]
				if (duk_pcall_method(ctx, 4) != 0)										// [retVal]
				{
					ILibDuktape_Process_UncaughtException(ctx);
				}
				duk_pop(ctx);															// ...
				
				*beginPointer = endPointer;
				break;
			case ILibWebClient_ReceiveStatus_MoreDataToBeReceived:
				if (ptrs->socket_ptr != NULL && ptrs->stream != NULL)
				{
					ILibDuktape_DuplexStream_WriteData(ptrs->stream, bodyBuffer, endPointer);
				}
				*beginPointer = endPointer;
				break;
			default:
				// ToDo: See if we need to handle Partial/LastPartial
				break;
		}
	}
	if (recvStatus == ILibWebClient_ReceiveStatus_Complete)
	{
		if (ptrs->socket_ptr != NULL && ptrs->stream != NULL)
		{
			ILibDuktape_DuplexStream_WriteEnd(ptrs->stream);
		}
		duk_push_heapptr(ctx, ptrs->clientRequest_ptr);			//[clientRequest]
		if (header == NULL && ptrs->stream == NULL)
		{
			duk_get_prop_string(ctx, -1, "emit");				//[clientRequest][emit]
			duk_dup(ctx, -2);									//[clientRequest][emit][this]
			duk_push_string(ctx, "error");						//[clientRequest][emit][this][error]
			duk_push_string(ctx, "WebSocket Connection Error");	//[clientRequest][emit][this][error][msg]
			if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "Error: http.clientRequet.onError()"); }
			duk_pop(ctx);										//[clientRequest]
		}
		duk_del_prop_string(ctx, -1, HTTP_REQUEST_TOKEN_PTR);	
		duk_del_prop_string(ctx, -1, HTTP_REQUEST_USER_PTR);
		duk_pop(ctx);

		if (ptrs->socket_ptr != NULL)
		{
			duk_push_heapptr(ctx, ptrs->socket_ptr);				//[socket]
			duk_del_prop_string(ctx, -1, HTTP_SOCKET_PTRS);
			ILibDuktape_EventEmitter_RemoveAll(ILibDuktape_EventEmitter_GetEmitter(ctx, -1));
			duk_pop(ctx);
		}
		if (ptrs->clientRequest_ptr != NULL)
		{
			duk_push_heapptr(ctx, ptrs->clientRequest_ptr);
			ILibDuktape_EventEmitter_RemoveAll(ILibDuktape_EventEmitter_GetEmitter(ctx, -1));
			duk_pop(ctx);
		}
		user[1] = NULL;
	}
}
void ILibDuktape_http_request_OnSendOK(ILibWebClient_StateObject sender, void *user1, void *user2)
{
	//duk_context *ctx = (duk_context*)user1;
	ILibDuktape_http_requestClient_callbacks *ptrs = (ILibDuktape_http_requestClient_callbacks*)user2;

	if (ptrs->requestStream != NULL)
	{
		ILibDuktape_WritableStream_Ready(ptrs->requestStream);
	}
}

#ifndef MICROSTACK_NOTLS
int ILibDuktape_http_request_tls_verify(ILibWebClient_RequestToken sender, int preverify_ok, STACK_OF(X509) *certs, struct sockaddr_in6 *address)
{
	int i;
	char addr[512];
	int retVal = 0;
	void **user = (void**)ILibWebClient_RequestToken_GetUserObjects(sender);
	
	duk_context *ctx = (duk_context*)user[0];
	void *clientRequest = NULL;
	void *checkServerIdentity = NULL;
	int rejectUnauthorised = 0;

	if(((ILibDuktape_http_request_dataType*)user[1])->STRUCT_TYPE == ILibDuktape_http_request_dataType_request)
	{
		ILibDuktape_http_requestClient_callbacks* ptrs = (ILibDuktape_http_requestClient_callbacks*)user[1];
		clientRequest = ptrs->clientRequest;
		checkServerIdentity = ptrs->checkServerIdentity;
		rejectUnauthorised = ptrs->rejectUnauthorized;
	}
	else
	{
		ILibDuktape_WebSocket_Pointers *ptrs = (ILibDuktape_WebSocket_Pointers*)user[1];
		clientRequest = ptrs->clientRequest_ptr;
		checkServerIdentity = ptrs->checkServerIdentity;
		rejectUnauthorised = ptrs->rejectUnauthorized;
	}

	if (rejectUnauthorised != 0 && preverify_ok == 0) { return 0; }
	if (checkServerIdentity != NULL)
	{
		duk_push_heapptr(ctx, checkServerIdentity);						// [func]
		duk_push_heapptr(ctx, clientRequest);							// [func][this]
		ILibInet_ntop2((struct sockaddr*)address, addr, sizeof(addr));
		duk_push_string(ctx, addr);										// [func][this][server]
		duk_push_array(ctx);											// [func][this][server][certs]
		for (i = 0; i < sk_X509_num(certs); ++i)
		{
			ILibDuktape_X509_PUSH(ctx, sk_X509_value(certs, i));		// [func][this][server][certs][cert]
			duk_put_prop_index(ctx, -2, i);								// [func][this][server][certs]
		}

		if (duk_pcall_method(ctx, 2) == 0) { retVal = 1; }				// [retVal]
		duk_pop(ctx);													// ...
	}
	else
	{
		retVal = 1;
	}
	return retVal;
}
#endif

void ILibDuktape_http_webSocket_onSendOk(ILibWebClient_StateObject sender, void *user1, void *user2)
{
	ILibDuktape_WebSocket_Pointers *ptrs = (ILibDuktape_WebSocket_Pointers*)user2;
	if (ptrs != NULL && ptrs->ctx != NULL && ptrs->stream != NULL)
	{
		ILibDuktape_DuplexStream_Ready(ptrs->stream);
	}
}
duk_ret_t ILibDuktape_http_request(duk_context *ctx)
{
	ILibHTTPPacket *packet;
	char *host;
	duk_size_t hostLen;
	char *key;
	int nargs = duk_get_top(ctx);
	if (nargs < 1) { duk_push_string(ctx, "Too Few Arguments"); duk_throw(ctx); return(DUK_RET_ERROR); }
	int isWebSocket = 0;
	ILibWebClient_RequestManager wcm;
	struct sockaddr_in6 dest;
	ILibWebClient_RequestToken token;
	ILibDuktape_globalTunnel_data *globalTunnel = ILibDuktape_GetGlobalTunnel(ctx);
	char *path, *method;
	duk_size_t pathLen, methodLen;

	char *proto = Duktape_GetStringPropertyValue(ctx, 0, "protocol", ILibDuktape_http_getDefaultProto(ctx));
#ifndef MICROSTACK_NOTLS
	ILibWebClient_RequestToken_HTTPS protocol = (strncmp(proto, "https:", 6) == 0 || strncmp(proto, "wss:", 4) == 0) ? ILibWebClient_RequestToken_USE_HTTPS : ILibWebClient_RequestToken_USE_HTTP;
#else
	ILibWebClient_RequestToken_HTTPS protocol = ILibWebClient_RequestToken_USE_HTTP;
#endif

	if (strncmp(proto, "wss:", 4) == 0 || strncmp(proto, "ws:", 3) == 0) { isWebSocket = 1; }

	duk_push_this(ctx);
	if (duk_has_prop_string(ctx, -1, HTTP_WEBCLIENT_MGR))
	{
		duk_get_prop_string(ctx, -1, HTTP_WEBCLIENT_MGR);
		wcm = (ILibWebClient_RequestManager)duk_to_pointer(ctx, -1);
	}
	else
	{
		duk_get_prop_string(ctx, -1, "chain");				// [http][chain]
		duk_get_prop_string(ctx, -2, "RequestPoolSize");	// [http][chain][poolSize]
		wcm = ILibCreateWebClient(duk_to_int(ctx, -1), duk_to_pointer(ctx, -2));
		duk_pop_2(ctx);										// [http]

#ifndef MICROSTACK_NOTLS
		{
			char *pfx;
			duk_size_t pfxLen;
			char *passphrase = Duktape_GetStringPropertyValue(ctx, 0, "passphrase", "");

			if (duk_has_prop_string(ctx, 0, "pfx") && protocol == ILibWebClient_RequestToken_USE_HTTPS)
			{
				struct util_cert cert;

				duk_get_prop_string(ctx, 0, "pfx");				// [http][pfx]
				pfx = Duktape_GetBuffer(ctx, -1, &pfxLen);
				duk_pop(ctx);									// [http]
				if (util_from_p12(pfx, (int)pfxLen, passphrase, &cert) != 0)
				{
					duk_push_pointer(ctx, cert.pkey);			// [http][pkey]
					duk_put_prop_string(ctx, -2, "\xFF_pkey");	// [http]
					duk_push_pointer(ctx, cert.x509);			// [http][x509]
					duk_put_prop_string(ctx, -2, "\xFF_x509");	// [http]

					ILibWebClient_EnableHTTPS(wcm, &cert, NULL, ILibDuktape_http_request_tls_verify);
				}
			}
			else if (duk_has_prop_string(ctx, 0, "MeshAgent") && protocol == ILibWebClient_RequestToken_USE_HTTPS)
			{
				duk_get_prop_string(ctx, 0, "MeshAgent");							// [http][MeshAgent]
				duk_get_prop_string(ctx, -1, ILibDuktape_MeshAgent_Cert_Client);	// [http][MeshAgent][clientCert]
				duk_get_prop_string(ctx, -2, ILibDuktape_MeshAgent_Cert_NonLeaf);	// [http][MeshAgent][clientCert][nonLeafCert]
				ILibWebClient_EnableHTTPS(wcm, (struct util_cert*)duk_get_pointer(ctx, -2), ((struct util_cert*)duk_get_pointer(ctx, -1))->x509, ILibDuktape_http_request_tls_verify);
				duk_pop_3(ctx);														// [http]
			}
			else if (protocol == ILibWebClient_RequestToken_USE_HTTPS)
			{
				ILibWebClient_EnableHTTPS(wcm, NULL, NULL, ILibDuktape_http_request_tls_verify);
			}
		}
#endif

		
		duk_push_pointer(ctx, wcm);							// [http][wcm]
		duk_put_prop_string(ctx, -2, HTTP_WEBCLIENT_MGR);	// [http]
	}

	if (duk_has_prop_string(ctx, 0, "hostname"))
	{
		host = Duktape_GetStringPropertyValueEx(ctx, 0, "hostname", "127.0.0.1", &hostLen);
	}
	else
	{
		host = Duktape_GetStringPropertyValueEx(ctx, 0, "host", "127.0.0.1", &hostLen);
	}
	

	if (duk_has_prop_string(ctx, 0, "proxy"))
	{
		duk_get_prop_string(ctx, 0, "proxy");
		globalTunnel = (ILibDuktape_globalTunnel_data*)ILibScratchPad;
		memset(globalTunnel, 0, sizeof(ILibDuktape_globalTunnel_data));
		ILibResolveEx(Duktape_GetStringPropertyValueEx(ctx, -1, "host", "127.0.0.1", NULL), (unsigned short)Duktape_GetIntPropertyValue(ctx, -1, "port", 8080), &(globalTunnel->proxyServer));
		if (globalTunnel->proxyServer.sin6_family == AF_UNSPEC) { return(ILibDuktape_Error(ctx, "http.get(): Cannot resolve proxy host %s", Duktape_GetStringPropertyValueEx(ctx, -1, "host", "127.0.0.1", NULL))); }
	}
	else if (duk_has_prop_string(ctx, 0, "noProxy")) { globalTunnel = NULL; }


	packet = ILibCreateEmptyPacket();
	ILibSetVersion(packet, "1.1", 3);
	method = Duktape_GetStringPropertyValueEx(ctx, 0, "method", "GET", &methodLen);
	path = Duktape_GetStringPropertyValueEx(ctx, 0, "path", "/", &pathLen);
	ILibSetDirective(packet, method, (int)methodLen, path, (int)pathLen);

	if (isWebSocket != 0)
	{
		union { int i; void*p; }u;
		int len;
		char value[32];
		char nonce[16];
		char *enc = value;
		util_random(16, nonce);
		len = ILibBase64Encode((unsigned char*)nonce, 16, (unsigned char**)&enc);
		enc[len] = 0;
		u.i = Duktape_GetIntPropertyValue(ctx, 0, "webSocketBufferSize", 65535);

		ILibAddHeaderLine(packet, "Upgrade", -1, "websocket", -1);
		ILibAddHeaderLine(packet, "Connection", -1, "Upgrade", -1);
		ILibAddHeaderLine(packet, "Sec-WebSocket-Key", -1, enc, -1);
		ILibAddHeaderLine(packet, "Sec-WebSocket-Version", -1, "13", -1);
		ILibHTTPPacket_Stash_Put(packet, "_WebSocketBufferSize", -1, u.p);
		ILibHTTPPacket_Stash_Put(packet, "_WebSocketOnSendOK", -1, ILibDuktape_http_webSocket_onSendOk);
	}

	if (duk_has_prop_string(ctx, 0, "headers"))
	{
		duk_get_prop_string(ctx, 0, "headers");
		duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);
		while (duk_next(ctx, -1, 1))
		{
			key = (char*)duk_to_string(ctx, -2);
			ILibAddHeaderLine(packet, key, -1, (char*)duk_to_string(ctx, -1), -1);
			duk_pop_2(ctx);
		}
	}

	if (ILibGetHeaderLine(packet, "host", 4) == NULL)
	{
		ILibAddHeaderLine(packet, "host", 4, host, (int)hostLen);
	}

	memset(&dest, 0, sizeof(struct sockaddr_in6));
	ILibResolveEx(host, (unsigned short)Duktape_GetIntPropertyValue(ctx, 0, "port", protocol == ILibWebClient_RequestToken_USE_HTTP ? 80 : 443), &dest);
	if (dest.sin6_family == AF_UNSPEC)
	{
		duk_push_string(ctx, host);
		duk_throw(ctx);
		return(DUK_RET_ERROR);
	}

	if (isWebSocket == 0)
	{
		// Make PipelineStreamedRequest
		token = ILibWebClient_PipelineStreamedRequest(wcm, (struct sockaddr*)&dest, packet, ILibDuktape_http_request_OnResponse, ILibDuktape_http_request_OnSendOK, ctx, NULL);
		if (globalTunnel != NULL)
		{
			if (ILibHashtable_Get(globalTunnel->exceptionsTable, NULL, host, (int)hostLen) == NULL)
			{
				ILibWebClient_SetProxyEx(token, &(globalTunnel->proxyServer), (char*)globalTunnel->proxyUser, (char*)globalTunnel->proxyPass);
			}
		}
#ifndef MICROSTACK_NOTLS
		ILibWebClient_Request_SetHTTPS(token, protocol);
		ILibDuktape_http_requestClient_callbacks *cb = (ILibDuktape_http_requestClient_callbacks*)ILibDuktape_http_request_PUSH_clientRequest(ctx, token, 0);
		cb->rejectUnauthorized = Duktape_GetIntPropertyValue(ctx, 0, "rejectUnauthorized", 0);
		cb->checkServerIdentity = Duktape_GetHeapptrProperty(ctx, 0, "checkServerIdentity");
#else
		ILibDuktape_http_request_PUSH_clientRequest(ctx, token, 0);
#endif
		
	}
	else
	{
		token = ILibWebClient_PipelineRequest(wcm, (struct sockaddr*)&dest, packet, ILibDuktape_http_request_WebSocket_OnResponse, ctx, NULL);
#ifndef MICROSTACK_NOTLS
		ILibWebClient_Request_SetHTTPS(token, protocol);
#endif
		if (globalTunnel != NULL)
		{
			if (ILibHashtable_Get(globalTunnel->exceptionsTable, NULL, host, (int)hostLen) == NULL)
			{
				ILibWebClient_SetProxyEx(token, &(globalTunnel->proxyServer), (char*)globalTunnel->proxyUser, (char*)globalTunnel->proxyPass);
			}
		}

#ifndef MICROSTACK_NOTLS
		ILibDuktape_WebSocket_Pointers *ptrs = ILibDuktape_http_request_PUSH_clientRequest(ctx, token, 1);
		ptrs->rejectUnauthorized = Duktape_GetIntPropertyValue(ctx, 0, "rejectUnauthorized", 0);
		ptrs->checkServerIdentity = Duktape_GetHeapptrProperty(ctx, 0, "checkServerIdentity");
#else
		ILibDuktape_http_request_PUSH_clientRequest(ctx, token, 1);
#endif
	}
	duk_dup(ctx, 0);
	duk_put_prop_string(ctx, -2, HTTP_CLIENTREQUEST_PARAMETER);
	duk_push_this(ctx);
	duk_put_prop_string(ctx, -2, CLIENTREQUEST_HTTP);

	if (nargs > 1) { ILibDuktape_EventEmitter_AddOnce(ILibDuktape_EventEmitter_GetEmitter(ctx, -1), "response", duk_require_heapptr(ctx, 1)); }
	return 1;
}

ILibTransport_DoneState ILibDuktape_http_request_write(ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibWebClient_RequestToken token = (ILibWebClient_RequestToken)user;
	ILibTransport_DoneState retVal = ILibTransport_DoneState_COMPLETE;

	if (bufferLen > 0) { retVal = ILibWebClient_StreamRequestBody(token, buffer, bufferLen, ILibAsyncSocket_MemoryOwnership_USER, ILibTransport_DoneState_INCOMPLETE); }
	return retVal;
}
void ILibDuktape_http_request_end(ILibDuktape_WritableStream *stream, void *user)
{
	ILibWebClient_RequestToken token = (ILibWebClient_RequestToken)user;
	ILibWebClient_StreamRequestBody(token, NULL, 0, ILibAsyncSocket_MemoryOwnership_USER, ILibTransport_DoneState_COMPLETE);
}

duk_ret_t ILibDuktape_http_clientRequest_upgrade_setter(duk_context *ctx)
{
	duk_push_this(ctx);								// [clientRequest]
	duk_dup(ctx, 0);								// [clientRequest][upgrade]
	duk_put_prop_string(ctx, -2, "\xFF_Upgrade");	// [clientRequest]

	return 0;
}
duk_ret_t ILibDuktape_http_request_finalizer(duk_context *ctx)
{
	ILibWebClient_RequestToken token;
	void **user;

	if (duk_has_prop_string(ctx, 0, HTTP_REQUEST_USER_PTR))
	{
		duk_get_prop_string(ctx, 0, HTTP_REQUEST_USER_PTR);
		user = (void**)duk_get_pointer(ctx, -1);
		user[1] = NULL;
	}
	

	if (duk_has_prop_string(ctx, 0, HTTP_CLIENTREQUEST_DATAPTR))
	{
		duk_get_prop_string(ctx, 0, HTTP_CLIENTREQUEST_DATAPTR);
		duk_size_t bufLen;
		char *buf = (char*)Duktape_GetBuffer(ctx, -1, &bufLen);
		memset(buf, 0, bufLen);
	}
	if (duk_has_prop_string(ctx, 0, HTTP_REQUEST_TOKEN_PTR))
	{
		duk_get_prop_string(ctx, 0, HTTP_REQUEST_TOKEN_PTR);
		token = duk_get_pointer(ctx, -1);

		if (token != NULL)
		{
			user = (void**)ILibWebClient_RequestToken_GetUserObjects(token);
			if (user != NULL)
			{
				user[0] = NULL;
				user[1] = NULL;
			}
			ILibWebClient_CancelRequest(token);
		}
	}

	return 0;
}
duk_ret_t ILibDuktape_http_request_no_op(duk_context *ctx)
{
	return 0;
}
void* ILibDuktape_http_request_PUSH_clientRequest(duk_context *ctx, ILibWebClient_RequestToken token, int isWebSocket)
{
	ILibDuktape_EventEmitter *emitter = NULL;
	void **user = ILibWebClient_RequestToken_GetUserObjects_Tail(token);

	if (user[1] != NULL && ((ILibDuktape_http_request_dataType*)user[1])->STRUCT_TYPE == ILibDuktape_http_request_dataType_request && 
		((ILibDuktape_http_requestClient_callbacks*)user[1])->clientRequest != NULL)
	{
		duk_push_heapptr(ctx, ((ILibDuktape_http_requestClient_callbacks*)user[1])->clientRequest);
		return(user[1]);
	}

	duk_push_object(ctx);															// [obj]
	duk_push_pointer(ctx, user);
	duk_put_prop_string(ctx, -2, HTTP_REQUEST_USER_PTR);		

	duk_push_pointer(ctx, token);													// [obj][token]
	duk_put_prop_string(ctx, -2, HTTP_REQUEST_TOKEN_PTR);							// [obj]
	duk_push_fixed_buffer(ctx, isWebSocket == 0 ? sizeof(ILibDuktape_http_requestClient_callbacks) : sizeof(ILibDuktape_WebSocket_Pointers));
	user[1] = Duktape_GetBuffer(ctx, -1, NULL);
	((ILibDuktape_http_request_dataType*)user[1])->STRUCT_TYPE = isWebSocket == 0 ? ILibDuktape_http_request_dataType_request : ILibDuktape_http_request_dataType_webSocket;
	duk_put_prop_string(ctx, -2, HTTP_CLIENTREQUEST_DATAPTR);

	emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "upgrade");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "error");

	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_http_request_finalizer);

	if (((ILibDuktape_http_request_dataType*)user[1])->STRUCT_TYPE == ILibDuktape_http_request_dataType_request)
	{ 
		ILibDuktape_EventEmitter_CreateEvent(emitter, "response", &(((ILibDuktape_http_requestClient_callbacks*)user[1])->OnReceive));
		ILibDuktape_EventEmitter_CreateEvent(emitter, "continue", &(((ILibDuktape_http_requestClient_callbacks*)user[1])->OnContinue));
		((ILibDuktape_http_requestClient_callbacks*)user[1])->requestStream = ILibDuktape_WritableStream_Init(ctx, ILibDuktape_http_request_write, ILibDuktape_http_request_end, token);
		((ILibDuktape_http_requestClient_callbacks*)user[1])->clientRequest = duk_get_heapptr(ctx, -1);
	}
	else
	{
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "response");
		((ILibDuktape_WebSocket_Pointers*)user[1])->ctx = ctx;
		((ILibDuktape_WebSocket_Pointers*)user[1])->clientRequest_ptr = duk_get_heapptr(ctx, -1);
		ILibDuktape_CreateInstanceMethod(ctx, "end", ILibDuktape_http_request_no_op, 0);
	}

	return(user[1]);
}

duk_ret_t ILibDuktape_http_get(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	ILibWebClient_RequestToken token;
	char *host;
	unsigned short port;
	char *path;
	struct sockaddr_in6 dest;
	duk_size_t uriLen;
	char *uri;
	int hostLen;
	ILibDuktape_globalTunnel_data *globalTunnel = ILibDuktape_GetGlobalTunnel(ctx);

	if (duk_is_string(ctx, 0))
	{
		uri = (char*)duk_get_lstring(ctx, 0, &uriLen);
	}
	else if (duk_is_object(ctx, 0))
	{
		uri = Duktape_GetStringPropertyValueEx(ctx, 0, "uri", "http://127.0.0.1/", &uriLen);
		if (duk_has_prop_string(ctx, 0, "proxy"))
		{
			duk_get_prop_string(ctx, 0, "proxy");
			globalTunnel = (ILibDuktape_globalTunnel_data*)ILibScratchPad;
			memset(globalTunnel, 0, sizeof(ILibDuktape_globalTunnel_data));
			ILibResolveEx(Duktape_GetStringPropertyValueEx(ctx, -1, "host", "127.0.0.1", NULL), (unsigned short)Duktape_GetIntPropertyValue(ctx, -1, "port", 8080), &(globalTunnel->proxyServer));
			if (globalTunnel->proxyServer.sin6_family == AF_UNSPEC) { return(ILibDuktape_Error(ctx, "http.get(): Cannot resolve proxy host %s", Duktape_GetStringPropertyValueEx(ctx, -1, "host", "127.0.0.1", NULL))); }
		}
		else if (duk_has_prop_string(ctx, 0, "noProxy")) { globalTunnel = NULL; }
	}
	else
	{
		return(ILibDuktape_Error(ctx, "http.get(): Invalid parameter"));
	}


	ILibHTTPPacket *packet = ILibCreateEmptyPacket();

#ifndef MICROSTACK_NOTLS
	ILibWebClient_RequestManager manager = ILibDuktape_http_GetRequestManager(ctx);
	ILibParseUriResult result = ILibParseUri(uri, &host, &port, &path, &dest);
	ILibWebClient_EnableHTTPS(manager, NULL, NULL, ILibDuktape_http_request_tls_verify);
#else
	ILibParseUri(uri, &host, &port, &path, &dest);
#endif

	ILibSetVersion(packet, "1.1", 3);

	if (dest.sin6_family == AF_UNSPEC)
	{
		ILibDestructPacket(packet);
		free(host); free(path);
		duk_push_string(ctx, "Could not resolve URI");
		duk_throw(ctx);
		return(DUK_RET_ERROR);
	}

	hostLen = (int)strnlen_s(host, uriLen);
	ILibSetDirective(packet, "GET", 3, path, (int)strnlen_s(path, uriLen));
	ILibAddHeaderLine(packet, "Host", 4, host, hostLen);
	if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "headers"))
	{
		duk_get_prop_string(ctx, 0, "headers");
		duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);
		while (duk_next(ctx, -1, 1))
		{
			duk_size_t keyLen, valueLen;
			char *key = (char*)duk_to_lstring(ctx, -2, &keyLen), *value = (char*)duk_to_lstring(ctx, -1, &valueLen);

			ILibAddHeaderLine(packet, key, (int)keyLen, value, (int)valueLen);
			duk_pop_2(ctx);
		}
	}
	ILibAddHeaderLine(packet, "Content-Length", 14, "0", 1);

	token = ILibWebClient_PipelineRequest(ILibDuktape_http_GetRequestManager(ctx), (struct sockaddr*)&dest, packet, ILibDuktape_http_request_OnResponse, ctx, NULL);
	
#ifndef MICROSTACK_NOTLS
	ILibWebClient_Request_SetHTTPS(token, result == ILibParseUriResult_TLS ? ILibWebClient_RequestToken_USE_HTTPS : ILibWebClient_RequestToken_USE_HTTP);
#endif

	if (globalTunnel != NULL)
	{
		if (ILibHashtable_Get(globalTunnel->exceptionsTable, NULL, host, hostLen) == NULL)
		{
			ILibWebClient_SetProxyEx(token, &(globalTunnel->proxyServer), (char*)globalTunnel->proxyUser, (char*)globalTunnel->proxyPass);
		}
	}

	free(path); free(host);
	ILibDuktape_http_request_PUSH_clientRequest(ctx, token, 0);		// [clientRequest]
	duk_dup(ctx, 0);												// [clientRequest][param]
	duk_put_prop_string(ctx, -2, HTTP_CLIENTREQUEST_PARAMETER);		// [clientRequest]
	duk_push_this(ctx);												// [clientRequest][http]
	duk_put_prop_string(ctx, -2, CLIENTREQUEST_HTTP);				// [clientRequest]
	if (nargs > 1)
	{
		ILibDuktape_EventEmitter_AddOnce(ILibDuktape_EventEmitter_GetEmitter(ctx, -1), "response", duk_get_heapptr(ctx, 1));
	}

	return 1;
}
duk_ret_t ILibDuktape_http_finalizer(duk_context *ctx)
{
	ILibWebClient_RequestManager wcm;

	if (duk_has_prop_string(ctx, 0, HTTP_WEBCLIENT_MGR))
	{
		duk_get_prop_string(ctx, 0, HTTP_WEBCLIENT_MGR);
		wcm = (ILibWebClient_RequestManager)duk_get_pointer(ctx, -1);
		ILibChain_SafeRemove(((ILibChain_Link*)wcm)->ParentChain, wcm);
	}
	return 0;
}
duk_ret_t ILibDuktape_http_parseUri(duk_context *ctx)
{
	duk_size_t uriLen;
	char *uri;
	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "http.parseUri(): Invalid Parameters")); }

	char *path, *addr;
	unsigned short port;
	int protocolIndex;

	uri = (char*)duk_get_lstring(ctx, 0, &uriLen);
	protocolIndex = 1 + ILibString_IndexOf(uri, (int)uriLen, "://", 3);
	if (protocolIndex > 0)
	{
		ILibParseUriEx(uri, (size_t)uriLen, &addr, &port, &path, NULL);

		duk_push_object(ctx);							// [options]
		duk_push_lstring(ctx, uri, protocolIndex);		// [options][protocol]
		duk_put_prop_string(ctx, -2, "protocol");
		duk_push_string(ctx, addr);						// [options][host]
		duk_put_prop_string(ctx, -2, "host");
		duk_push_int(ctx, port);						// [options][port]
		duk_put_prop_string(ctx, -2, "port");			// [options]
		duk_push_string(ctx, path);						// [options][path]
		duk_put_prop_string(ctx, -2, "path");			// [options]
		duk_push_string(ctx, "GET");					// [options][method]
		duk_put_prop_string(ctx, -2, "method");			// [options]

		free(path);
		free(addr);
	}
	else
	{
		duk_push_null(ctx);
	}
	return 1;
}

void ILibDuktape_http_stream_ServerResponse_sendHeaders(ILibDuktape_http_streamWrapper *wrapper, ILibHTTPPacket *headers)
{
	char *data;
	int dataLen = ILibGetRawPacket(headers, &data);

	if (wrapper->PipedWriter != NULL)
	{
		((ILibDuktape_WritableStream*)wrapper->PipedWriter)->WriteSink(((ILibDuktape_WritableStream*)wrapper->PipedWriter), data, dataLen, ((ILibDuktape_WritableStream*)wrapper->PipedWriter)->WriteSink_User);
	}
	else
	{
		duk_push_heapptr(wrapper->ctx, wrapper->PipedReader);					// [stream]
		duk_get_prop_string(wrapper->ctx, -1, "write");							// [stream][func]
		duk_swap_top(wrapper->ctx, -2);											// [func][this]
		duk_push_external_buffer(wrapper->ctx);									// [func][this][chunk]
		duk_config_buffer(wrapper->ctx, -1, data, dataLen);
		if (duk_pcall_method(wrapper->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(wrapper->ctx, "http.httpStream.onWriteHead(): Error "); }
		duk_pop(wrapper->ctx);													// ...
	}

	free(data);
}

duk_ret_t ILibDuktape_http_stream_ServerResponse_writeHead(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	ILibHTTPPacket *headers;
	ILibDuktape_http_streamWrapper *wrapper;

	int statusCode = 200;
	char *statusData = "OK";
	duk_size_t statusDataLen = 2;

	duk_push_this(ctx);										// [response]
	duk_get_prop_string(ctx, -1, HTTP_STREAM_WRAPPER);		// [response][wrapper]
	wrapper = (ILibDuktape_http_streamWrapper*)duk_get_pointer(ctx, -1);
	headers = wrapper->impliedHeaders;
	wrapper->impliedHeaders = NULL;

	statusCode = duk_require_int(ctx, 0);
	if (nargs > 1 && duk_is_string(ctx, 1))
	{
		statusData = (char*)duk_get_lstring(ctx, 1, &statusDataLen);
	}
	else
	{
		switch (statusCode)
		{
		case 100:
			statusData = "Continue";
			statusDataLen = 8;
			break;
		case 200:
			statusData = "OK";
			statusDataLen = 2;
			break;
		case 400:
			statusData = "Bad Request";
			statusDataLen = 11;
			break;
		case 401:
			statusData = "Unauthorized";
			statusDataLen = 12;
			break;
		case 404:
			statusData = "Not Found";
			statusDataLen = 9;
			break;
		case 500:
			statusData = "Internal Server Error";
			statusDataLen = 21;
			break;
		default:
			statusData = "Unspecified";
			statusDataLen = 11;
			break;
		}
	}
	ILibSetStatusCode(headers, statusCode, statusData, (int)statusDataLen);

	ILibDuktape_http_stream_ServerResponse_sendHeaders(wrapper, headers);
	ILibDestructPacket(headers);
	return 0;
}
void ILibDuktape_http_stream_serverResponse_WriteSinkFlushedNative(struct ILibDuktape_WritableStream *stream, void *user)
{
	ILibDuktape_http_streamWrapper *wrapper = (ILibDuktape_http_streamWrapper*)user;
	ILibDuktape_WritableStream_Ready(wrapper->serverResponse_stream);
}
duk_ret_t ILibDuktape_http_stream_serverResponse_WriteSinkFlushed(duk_context *ctx)
{
	duk_push_current_function(ctx);						// [func]
	duk_get_prop_string(ctx, -1, "\xFF_USER");
	ILibDuktape_http_stream_serverResponse_WriteSinkFlushedNative(NULL, duk_get_pointer(ctx, -1));
	return 0;
}
ILibTransport_DoneState ILibDuktape_http_stream_serverResponse_WriteSink(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibTransport_DoneState retVal = ILibTransport_DoneState_ERROR;
	ILibDuktape_http_streamWrapper *wrapper = (ILibDuktape_http_streamWrapper*)user;
	if (wrapper->impliedHeaders != NULL)
	{
		// Need to send out headers first
		ILibDuktape_http_stream_ServerResponse_sendHeaders(wrapper, wrapper->impliedHeaders);
		ILibDestructPacket(wrapper->impliedHeaders);
		wrapper->impliedHeaders = NULL;
	}

	if (wrapper->PipedWriter != NULL)
	{
		ILibDuktape_WritableStream *ws = (ILibDuktape_WritableStream*)wrapper->PipedWriter;
		ws->OnWriteFlushEx = ILibDuktape_http_stream_serverResponse_WriteSinkFlushedNative;
		ws->OnWriteFlushEx_User = wrapper;
		if (wrapper->chunkEncoded == 0)
		{
			return(ws->WriteSink(ws, buffer, bufferLen, ws->WriteSink_User));
		}
		else
		{
			int hexLen = sprintf_s(wrapper->hex, sizeof(wrapper->hex), "%X\r\n", bufferLen);
			ws->WriteSink(ws, wrapper->hex, hexLen, ws->WriteSink_User);
			ws->WriteSink(ws, buffer, bufferLen, ws->WriteSink_User);
			return(ws->WriteSink(ws, "\r\n", 2, ws->WriteSink_User));
		}
	}
	else
	{
		if (wrapper->chunkEncoded != 0)
		{
			int hexLen = sprintf_s(wrapper->hex, sizeof(wrapper->hex), "%X\r\n", bufferLen);
			duk_push_heapptr(wrapper->ctx, wrapper->PipedReader);											// [stream]
			duk_get_prop_string(wrapper->ctx, -1, "write");													// [stream][func]
			duk_swap_top(wrapper->ctx, -2);																	// [func][this]
			duk_push_external_buffer(wrapper->ctx);															// [func][this][chunk]
			duk_config_buffer(wrapper->ctx, -1, wrapper->hex, hexLen);
			if (duk_pcall_method(wrapper->ctx, 2) != 0)
			{
				ILibDuktape_Process_UncaughtExceptionEx(wrapper->ctx, "http.httpStream.onWrite(): Error ");
				retVal = ILibTransport_DoneState_ERROR;
				duk_pop(wrapper->ctx);																		// ...
				return retVal;
			}
			duk_pop(wrapper->ctx);																			// ...
		}
		duk_push_heapptr(wrapper->ctx, wrapper->PipedReader);											// [stream]
		duk_get_prop_string(wrapper->ctx, -1, "write");													// [stream][func]
		duk_swap_top(wrapper->ctx, -2);																	// [func][this]
		duk_push_external_buffer(wrapper->ctx);															// [func][this][chunk]
		duk_config_buffer(wrapper->ctx, -1, buffer, bufferLen);
		if (duk_pcall_method(wrapper->ctx, 1) != 0) 
		{ 
			ILibDuktape_Process_UncaughtExceptionEx(wrapper->ctx, "http.httpStream.onWrite(): Error "); 
			retVal = ILibTransport_DoneState_ERROR;
			duk_pop(wrapper->ctx);
			return retVal;
		}
		else
		{
			retVal = duk_get_boolean(wrapper->ctx, -1) ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
		}
		duk_pop(wrapper->ctx);																				// ...			

		if (wrapper->chunkEncoded != 0)
		{
			duk_push_heapptr(wrapper->ctx, wrapper->PipedReader);											// [stream]
			duk_get_prop_string(wrapper->ctx, -1, "write");													// [stream][func]
			duk_swap_top(wrapper->ctx, -2);																	// [func][this]
			duk_push_external_buffer(wrapper->ctx);															// [func][this][chunk]
			duk_config_buffer(wrapper->ctx, -1, "\r\n", 2);
			duk_push_c_function(wrapper->ctx, ILibDuktape_http_stream_serverResponse_WriteSinkFlushed, 0);	// [func][this][chunk][callback]
			duk_push_pointer(wrapper->ctx, wrapper);														// [func][this][chunk][callback][ptr]
			duk_put_prop_string(wrapper->ctx, -2, "\xFF_USER");												// [func][this][chunk][callback]
			if (duk_pcall_method(wrapper->ctx, 2) != 0)
			{
				ILibDuktape_Process_UncaughtExceptionEx(wrapper->ctx, "http.httpStream.onWrite(): Error ");
				retVal = ILibTransport_DoneState_ERROR;
			}
			else
			{
				retVal = duk_get_boolean(wrapper->ctx, -1) ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
			}
			duk_pop(wrapper->ctx);
		}
	}
	return retVal;
}
void ILibDuktape_http_stream_serverResponse_EndSink(struct ILibDuktape_WritableStream *stream, void *user)
{
	ILibDuktape_http_streamWrapper *wrapper = (ILibDuktape_http_streamWrapper*)user;

	if (wrapper->chunkEncoded == 0)
	{
		// No choice but to propogate the End up, becuase we aren't chunked
		if (wrapper->PipedWriter != NULL)
		{
			wrapper->PipedWriter->EndSink(wrapper->PipedWriter, wrapper->PipedWriter->WriteSink_User);
		}
		else
		{
			duk_push_heapptr(wrapper->ctx, wrapper->PipedReader);			// [stream]
			duk_get_prop_string(wrapper->ctx, -1, "end");					// [stream][func]
			duk_swap_top(wrapper->ctx, -2);									// [func][this]
			if (duk_pcall_method(wrapper->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(wrapper->ctx, "http.httpStream.onEnd(): Error "); }
			duk_pop(wrapper->ctx);											// ...
		}
	}
	else
	{
		// Since we're chunked, we can just write a zero length chunk
		if (wrapper->PipedWriter != NULL)
		{
			wrapper->PipedWriter->WriteSink(wrapper->PipedWriter, "0\r\n\r\n", 5, wrapper->PipedWriter->WriteSink_User);
		}
		else
		{
			duk_push_heapptr(wrapper->ctx, wrapper->PipedReader);											// [stream]
			duk_get_prop_string(wrapper->ctx, -1, "write");													// [stream][func]
			duk_swap_top(wrapper->ctx, -2);																	// [func][this]
			duk_push_external_buffer(wrapper->ctx);															// [func][this][chunk]
			duk_config_buffer(wrapper->ctx, -1, "0\r\n\r\n", 5);
			if (duk_pcall_method(wrapper->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(wrapper->ctx, "http.httpStream.onEnd(): Error "); }
			duk_pop(wrapper->ctx);																			// ...
		}
	}
	ILibWebClient_FinishedResponse_Server(wrapper->wcdo);
}
void ILibduktape_http_stream_PUSH_ServerResponse(duk_context *ctx, ILibDuktape_http_streamWrapper *wrapper)
{
	duk_push_object(ctx);									// [response]
	wrapper->impliedHeaders = ILibCreateEmptyPacket();
	if (wrapper->chunkEncoded == 0)
	{
		ILibSetVersion(wrapper->impliedHeaders, "1.0", 3);
	}
	else
	{
		ILibSetVersion(wrapper->impliedHeaders, "1.1", 3);
		ILibAddHeaderLine(wrapper->impliedHeaders, "Transfer-Encoding", 17, "chunked", 7);
	}
	
	ILibSetStatusCode(wrapper->impliedHeaders, 200, "OK", 2);
	duk_push_pointer(ctx, wrapper);							// [response][wrapper]
	duk_put_prop_string(ctx, -2, HTTP_STREAM_WRAPPER);		// [response]

	ILibDuktape_CreateInstanceMethod(ctx, "writeHead", ILibDuktape_http_stream_ServerResponse_writeHead, DUK_VARARGS);
	wrapper->serverResponse_stream = ILibDuktape_WritableStream_Init(ctx, ILibDuktape_http_stream_serverResponse_WriteSink, ILibDuktape_http_stream_serverResponse_EndSink, wrapper);
}
void ILibDuktape_http_stream_OnReceive(ILibWebClient_StateObject WebStateObject, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, ILibWebClient_ReceiveStatus recvStatus, void *user1, void *user2, int *PAUSE)
{
	ILibDuktape_http_streamWrapper *wrapper = (ILibDuktape_http_streamWrapper*)user1;
	if (!(header->VersionLength == 3 && memcmp(header->Version, "1.0", 3) == 0)) { wrapper->chunkEncoded = 1; }

	if (wrapper->OnRequest != NULL)
	{
		duk_push_heapptr(wrapper->ctx, wrapper->OnRequest);							// [func]
		duk_push_heapptr(wrapper->ctx, wrapper->self);								// [func][this]
		ILibDuktape_http_server_PUSH_IncomingMessage(wrapper->ctx, header, NULL);	// [func][this][msg]
		ILibduktape_http_stream_PUSH_ServerResponse(wrapper->ctx, wrapper);			// [func][this][msg][rsp]
		if (duk_pcall_method(wrapper->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(wrapper->ctx, "http.httpStream.OnRequest(); Error "); }
		duk_pop(wrapper->ctx);														// ...
	}
}
duk_ret_t ILibDuktape_http_stream_finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, HTTP_STREAM_WRAPPER);
	ILibDuktape_http_streamWrapper *wrapper = (ILibDuktape_http_streamWrapper*)Duktape_GetBuffer(ctx, -1, NULL);

	if (wrapper->wcdo != NULL)
	{
		((int*)(wrapper->reserved + sizeof(ILibTransport)))[0] = ~0;
		ILibWebClient_DestroyWebClientDataObject(wrapper->wcdo);
	}
	return 0;
}
ILibTransport_DoneState ILibDuktape_http_stream_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_http_streamWrapper *wrapper = (ILibDuktape_http_streamWrapper*)user;
	ILibAsyncSocket_SocketModule module = (ILibAsyncSocket_SocketModule)wrapper->reserved;
	int PAUSE = 0;
	int i = 0, consumed = 0;

	if (wrapper->bufferLen == 0)
	{
		do
		{
			consumed = 0;
			ILibWebClient_OnData(module, buffer + i, &consumed, bufferLen, NULL, (void**)&(wrapper->wcdo), &PAUSE);
			i += consumed;
			bufferLen -= i;
		} while (consumed != 0 && bufferLen != 0 && PAUSE == 0);
		if (bufferLen != 0)
		{
			if (bufferLen > (int)(sizeof(wrapper->buffer) - wrapper->bufferLen)) { return(ILibTransport_DoneState_ERROR); }
			if (wrapper->bufferLen + bufferLen > HTTP_STREAM_WRAPPER_BUFSIZE) { return(ILibTransport_DoneState_ERROR); }
			memcpy_s(wrapper->buffer + wrapper->bufferLen, sizeof(wrapper->buffer) - wrapper->bufferLen, buffer + i, bufferLen);
			wrapper->bufferLen += bufferLen;
		}
	}
	else if (wrapper->bufferLen > 0)
	{
		if (wrapper->bufferLen + bufferLen > HTTP_STREAM_WRAPPER_BUFSIZE) { return(ILibTransport_DoneState_ERROR); }
		memcpy_s(wrapper->buffer + wrapper->bufferLen, sizeof(wrapper->buffer) - wrapper->bufferLen, buffer, bufferLen);
		wrapper->bufferLen += bufferLen;

		i = 0; 
		do
		{
			consumed = 0;
			ILibWebClient_OnData(module, wrapper->buffer + i, &consumed, wrapper->bufferLen, NULL, (void**)&(wrapper->wcdo), &PAUSE);
			i += consumed;
			wrapper->bufferLen -= i;
		} while (consumed != 0 && wrapper->bufferLen != 0 && PAUSE == 0);
		if (wrapper->bufferLen != 0)
		{
			memmove_s(wrapper->buffer, sizeof(wrapper->buffer), wrapper->buffer + i, wrapper->bufferLen);
		}
	}


	return(PAUSE == 0 ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE);
}
void ILibDuktape_http_stream_EndSink(ILibDuktape_DuplexStream *ds, void *user)
{
	ILibDuktape_http_streamWrapper *stream = (ILibDuktape_http_streamWrapper*)user;
	if (stream->PipedWriter != NULL)
	{
		((ILibDuktape_WritableStream*)stream->PipedWriter)->EndSink((ILibDuktape_WritableStream*)stream->PipedWriter, ((ILibDuktape_WritableStream*)stream->PipedWriter)->WriteSink_User);
	}
	else
	{
		duk_push_heapptr(stream->ctx, stream->PipedReader);										// [stream]
		duk_get_prop_string(stream->ctx, -1, "end");											// [stream][end]
		duk_swap_top(stream->ctx, -2);															// [end][this]
		if (duk_pcall_method(stream->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "http.httpStream.OnEnd(): Error "); }
		duk_pop(stream->ctx);																	// ...
	}																
}
void ILibDuktape_http_stream_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_http_streamWrapper *stream = (ILibDuktape_http_streamWrapper*)user;
	if (stream->PipedWriter != NULL)
	{
		ILibDuktape_readableStream *rs = (ILibDuktape_readableStream*)stream->PipedReader;
		if (rs->PauseHandler != NULL)
		{
			rs->PauseHandler(rs, rs->user);
		}
		else
		{
			duk_push_string(stream->ctx, "net.http.httpStream.OnPause(): Error, Native Readable Stream does not have a PauseHandler");
			ILibDuktape_Process_UncaughtException(stream->ctx);
			duk_pop(stream->ctx);
		}
	}
	else
	{
		duk_push_heapptr(stream->ctx, stream->PipedReader);				// [reader]
		duk_get_prop_string(stream->ctx, -1, "pause");					// [reader][func]
		duk_swap_top(stream->ctx, -2);									// [func][this]
		if (duk_pcall_method(stream->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "net.http.httpStream.OnPause(): Error "); }
		duk_pop(stream->ctx);											// ...
	}
}
void ILibDuktape_http_stream_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_http_streamWrapper *stream = (ILibDuktape_http_streamWrapper*)user;
	if (stream->PipedWriter != NULL)
	{
		ILibDuktape_readableStream *rs = (ILibDuktape_readableStream*)stream->PipedReader;
		if (rs->ResumeHandler != NULL)
		{
			rs->ResumeHandler(rs, rs->user);
		}
		else
		{
			duk_push_string(stream->ctx, "net.http.httpStream.OnResume(): Error, Native Readable Stream does not have a ResumeHandler");
			ILibDuktape_Process_UncaughtException(stream->ctx);
			duk_pop(stream->ctx);
		}
	}
	else
	{
		duk_push_heapptr(stream->ctx, stream->PipedReader);				// [reader]
		duk_get_prop_string(stream->ctx, -1, "resume");					// [reader][func]
		duk_swap_top(stream->ctx, -2);									// [func][this]
		if (duk_pcall_method(stream->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "net.http.httpStream.OnResume(): Error "); }
		duk_pop(stream->ctx);											// ...
	}
}
void ILibDuktape_http_Stream_PipeSink(duk_context *ctx, void *object, char *eventName, void *duk_eventArgs)
{
	ILibDuktape_http_streamWrapper *stream;
	duk_push_heapptr(ctx, object);													// [stream]
	duk_get_prop_string(ctx, -1, HTTP_STREAM_WRAPPER);								// [stream][buffer]
	stream = (ILibDuktape_http_streamWrapper*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop_2(ctx);																	// ...

	duk_push_heapptr(ctx, duk_eventArgs);											// [args]
	if (duk_get_length(ctx, -1) > 0)
	{
		duk_get_prop_index(ctx, -1, 0);												// [args][pipe]
		if (duk_has_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS) && duk_has_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS))
		{
			duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);		// [args][pipe][rstream]
			duk_get_prop_string(ctx, -2, ILibDuktape_WritableStream_WSPTRS);		// [args][pipe][rstream][wstream]
			stream->PipedReader = Duktape_GetBuffer(ctx, -2, NULL);
			stream->PipedWriter = (ILibDuktape_WritableStream*)Duktape_GetBuffer(ctx, -1, NULL);
			duk_pop_2(ctx);															// [args][pipe]								
		}
		else
		{
			stream->PipedReader = duk_get_heapptr(ctx, -1);
			stream->PipedWriter = NULL;
		}
		duk_pop(ctx);																// [args]
	}
	duk_pop(ctx);																	// ...
}
duk_ret_t ILibDuktape_http_createStream(duk_context *ctx)
{
	ILibDuktape_http_streamWrapper *stream;
	duk_push_object(ctx);																			// [stream]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_http_streamWrapper));								// [stream][buffer]
	stream = (ILibDuktape_http_streamWrapper*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, HTTP_STREAM_WRAPPER);												// [stream]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_http_stream_finalizer);

	memset(stream, 0, sizeof(ILibDuktape_http_streamWrapper));
	stream->ctx = ctx;
	stream->self = duk_get_heapptr(ctx, -1);
	stream->emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEvent(stream->emitter, "request", &(stream->OnRequest));
	ILibDuktape_EventEmitter_CreateEvent(stream->emitter, "response", &(stream->OnResponse));
	stream->wcdo = ILibCreateWebClientEx(ILibDuktape_http_stream_OnReceive, (ILibAsyncSocket_SocketModule)(stream->reserved), stream, NULL);
	stream->ds = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_http_stream_WriteSink, ILibDuktape_http_stream_EndSink, ILibDuktape_http_stream_PauseSink, ILibDuktape_http_stream_ResumeSink, stream);
	
	ILibDuktape_EventEmitter_AddSink(stream->emitter, "pipe", ILibDuktape_http_Stream_PipeSink);

	return 1;
}
void ILibDuktape_http_PUSH_EX(duk_context *ctx, void *chain, int https)
{
	duk_push_object(ctx);									// [http]
	duk_push_pointer(ctx, chain);							// [http][chain]
	duk_put_prop_string(ctx, -2, "chain");					// [http]
	duk_push_string(ctx, https == 0 ? "http:" : "https:");
	duk_put_prop_string(ctx, -2, HTTP_DEFAULT_PROTO_KEY);	// [http]

	ILibDuktape_CreateInstanceMethod(ctx, "parseUri", ILibDuktape_http_parseUri, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "createServer", ILibDuktape_http_createServer, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "request", ILibDuktape_http_request, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "get", ILibDuktape_http_get, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "createStream", ILibDuktape_http_createStream, 0);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_http_finalizer);

	duk_push_int(ctx, 5);								// [http][pool]
	duk_put_prop_string(ctx, -2, "RequestPoolSize");	// [http]
}
void ILibDuktape_http_PUSH(duk_context *ctx, void *chain)
{
	ILibDuktape_http_PUSH_EX(ctx, chain, 0);
}
void ILibDuktape_https_PUSH(duk_context *ctx, void *chain)
{
	ILibDuktape_http_PUSH_EX(ctx, chain, 1);
}

duk_ret_t ILibDuktape_httpDigest_clientRequest_response2(duk_context *ctx)
{
	ILibHTTPPacket *packet;
	duk_get_prop_string(ctx, 0, "PacketPtr");
	packet = (ILibHTTPPacket*)duk_get_pointer(ctx, -1);

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "digestClientRequest");// [digestClientRequest]

	if (packet->StatusCode == 200)
	{
		duk_get_prop_string(ctx, -1, "emit");	// [digestClientRequest][emit]
		duk_swap_top(ctx, -2);					// [emit][this]
		duk_push_string(ctx, "response");		// [emit][this][response]
		duk_dup(ctx, 0);						// [emit][this][response][imsg]
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http-digest: Error dispatching response event"); }
	}

	return(0);
}

duk_ret_t ILibDuktape_httpDigest_clientRequest_onDrain(duk_context *ctx)
{
	duk_push_this(ctx);											// [clientRequest]
	if (duk_has_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST))
	{
		duk_get_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);	// [clientRequest][digestClientRequest]
		if (duk_has_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS))
		{
			duk_get_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS);
			ILibDuktape_WritableStream_Ready((ILibDuktape_WritableStream*)Duktape_GetBuffer(ctx, -1, NULL));
		}
	}
	return(0);
}

duk_ret_t ILibDuktape_httpDigest_clientRequest_propagateEvent(duk_context *ctx)
{
	int i, nargs = duk_get_top(ctx);
	duk_push_current_function(ctx);							// [func]
	duk_get_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);	// [func][digestClientRequest]
	duk_get_prop_string(ctx, -1, "emit");					// [func][digestClientRequest][emit]
	duk_swap_top(ctx, -2);									// [func][emit][this]
	duk_get_prop_string(ctx, -3, CLIENTREQUEST_EVENT_NAME);	// [func][emit][this][eventName]
	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);									// [func][emit][this][eventName][params]
	}
	if (duk_pcall_method(ctx, 1 + nargs) != 0) { duk_throw(ctx); return(DUK_RET_ERROR); }
	return(0);
}

extern void* ILibWebClient_Digest_GenerateTable(ILibWebClient_StateObject state);
duk_ret_t ILibDuktape_httpDigest_clientRequest_response(duk_context *ctx)
{
	ILibHTTPPacket *packet;
	ILibWebClient_StateObject wcdo;
	char *username, *password;
	int tmpLen = 0;
	char *uri = NULL;
	void *digestClientPtr;
	void *paramPtr = NULL;

	duk_push_current_function(ctx);													
	duk_get_prop_string(ctx, -1, "digestClientRequest");							
	digestClientPtr = duk_get_heapptr(ctx, -1);
	duk_get_prop_string(ctx, -1, "digest");
	duk_get_prop_string(ctx, -1, DIGEST_USERNAME);
	username = (char*)duk_get_string(ctx, -1);
	duk_get_prop_string(ctx, -2, DIGEST_PASSWORD);
	password = (char*)duk_get_string(ctx, -1);

	duk_get_prop_string(ctx, 0, "PacketPtr");
	packet = (ILibHTTPPacket*)duk_get_pointer(ctx, -1);

	if (packet->StatusCode == 401)
	{
		duk_push_heapptr(ctx, digestClientPtr);						// [digestClientRequest]
		if (duk_has_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST))
		{
			duk_get_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);	// [digestClientRequest][clientRequest]
			duk_get_prop_string(ctx, -1, "end");					// [digestClientRequest][clientRequest][end]
			duk_dup(ctx, -2);										// [digestClientRequest][clientRequest][end][this]
			if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http-digest.onResponse(): "); }
			duk_pop_2(ctx);											// [digestClientRequest]
		}
		duk_pop(ctx);												// ...

		// UnAuthorized, need to retry request with Authorization Headers
		duk_get_prop_string(ctx, 0, HTTP_INCOMINGMSG_WebStateObject);
		wcdo = (ILibWebClient_StateObject)duk_get_pointer(ctx, -1);

		int freePath = 0;
		char *method, *path;
		char result1[33];
		char result2[33];
		char result3[33];
		void* table = ILibWebClient_Digest_GenerateTable(wcdo);
		char* realm = (char*)ILibGetEntry(table, "realm", 5);
		char* nonce = (char*)ILibGetEntry(table, "nonce", 5);
		char* opaque = (char*)ILibGetEntry(table, "opaque", 6);
		ILibDestroyHashTree(table);

		duk_push_this(ctx);												// [clientRequest]
		duk_get_prop_string(ctx, -1, HTTP_CLIENTREQUEST_PARAMETER);		// [clientRequest][param]
		if (duk_is_string(ctx, -1))
		{
			// Parameter was a uri string
			char *tmpHost;
			unsigned short tmpPort;
			uri = (char*)duk_get_string(ctx, -1);
			ILibParseUri(uri, &tmpHost, &tmpPort, &path, NULL);
			tmpLen = sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s:%s", (method = "GET"), path);
			util_md5hex(ILibScratchPad2, tmpLen, result2);
			free(tmpHost);
			freePath = 1;
		}
		else
		{
			tmpLen = sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s:%s", (method = Duktape_GetStringPropertyValue(ctx, -1, "method", "GET")), (path = Duktape_GetStringPropertyValue(ctx, -1, "path", "/")));
			util_md5hex(ILibScratchPad2, tmpLen, result2);
			paramPtr = duk_get_heapptr(ctx, -1);
		}

		tmpLen = sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s:%s:%s", username, realm, password);
		util_md5hex(ILibScratchPad2, tmpLen, result1);

		tmpLen = sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s:%s:%s", result1, nonce, result2);
		util_md5hex(ILibScratchPad2, tmpLen, result3);

		tmpLen = sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", opaque=\"%s\", response=\"%s\"", username, realm, nonce, path, opaque, result3);
		
		duk_push_this(ctx);																			// [clientReqeust]
		duk_get_prop_string(ctx, -1, CLIENTREQUEST_HTTP);											// [clientReqeust][http]
		if (freePath != 0) { free(path); }
		

		if (paramPtr == NULL)
		{
			duk_get_prop_string(ctx, -1, "get");												// [clientRequest][http][get]
			duk_swap_top(ctx, -2);																// [clientRequest][get][this]
			duk_push_object(ctx);																// [clientReqeust][get][this][options]
			duk_push_string(ctx, uri);
			duk_put_prop_string(ctx, -2, "uri");
		}
		else
		{
			duk_get_prop_string(ctx, -1, "request");											// [clientRequest][http][request]
			duk_swap_top(ctx, -2);																// [clientRequest][request][this]
			duk_push_heapptr(ctx, paramPtr);													// [clientRequest][request][this][options]
		}

		if(!duk_has_prop_string(ctx, -1, "headers")) 
		{ 
			duk_push_object(ctx);																// [clientReqeust][get][this][options][headers]
		}
		else
		{
			duk_get_prop_string(ctx, -1, "headers");											// [clientReqeust][get][this][options][headers]
		}
																			
		duk_push_lstring(ctx, ILibScratchPad2, tmpLen);											// [clientReqeust][get][this][options][headers][Auth]
		duk_put_prop_string(ctx, -2, "Authorization");											// [clientReqeust][get][this][options][headers]
		duk_put_prop_string(ctx, -2, "headers");												// [clientReqeust][get][this][options]
		duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_response2, DUK_VARARGS);	// [clientReqeust][get][this][options][callback]
		duk_push_heapptr(ctx, digestClientPtr);													// [clientReqeust][get][this][options][callback][digestClientRequest]
		duk_put_prop_string(ctx, -2, "digestClientRequest");									// [clientReqeust][get][this][options][callback]
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "digest_onResponse: Error Invoking http.get"); }



		duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_propagateEvent, DUK_VARARGS);	// [clientReqeust][EventDispatcher]
		duk_push_heapptr(ctx, digestClientPtr);														// [clientReqeust][EventDispatcher][digestClientRequest]
		duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);										// [clientReqeust][EventDispatcher]
		duk_push_string(ctx, "upgrade");															// [clientReqeust][EventDispatcher][eventName]
		duk_put_prop_string(ctx, -2, CLIENTREQUEST_EVENT_NAME);										// [clientReqeust][EventDispatcher]
		ILibDuktape_EventEmitter_AddOnce(ILibDuktape_EventEmitter_GetEmitter(ctx, -2), "upgrade", duk_get_heapptr(ctx, -1));
		duk_pop(ctx);																				// [clientReqeust]
		

		duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_propagateEvent, DUK_VARARGS);	// [clientReqeust][EventDispatcher]
		duk_push_heapptr(ctx, digestClientPtr);														// [clientReqeust][EventDispatcher][digestClientRequest]
		duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);										// [clientReqeust][EventDispatcher]
		duk_push_string(ctx, "error");																// [clientReqeust][EventDispatcher][eventName]
		duk_put_prop_string(ctx, -2, CLIENTREQUEST_EVENT_NAME);										// [clientReqeust][EventDispatcher]
		ILibDuktape_EventEmitter_AddOnce(ILibDuktape_EventEmitter_GetEmitter(ctx, -2), "error", duk_get_heapptr(ctx, -1));			
		duk_pop(ctx);																				// [clientReqeust]

		duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_propagateEvent, DUK_VARARGS);	// [clientReqeust][EventDispatcher]
		duk_push_heapptr(ctx, digestClientPtr);														// [clientReqeust][EventDispatcher][digestClientRequest]
		duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);										// [clientReqeust][EventDispatcher]
		duk_push_string(ctx, "continue");															// [clientReqeust][EventDispatcher][eventName]
		duk_put_prop_string(ctx, -2, CLIENTREQUEST_EVENT_NAME);										// [clientReqeust][EventDispatcher]
		ILibDuktape_EventEmitter_AddOnce(ILibDuktape_EventEmitter_GetEmitter(ctx, -2), "continue", duk_get_heapptr(ctx, -1));
		duk_pop(ctx);																				// [clientReqeust]

		duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_onDrain, DUK_VARARGS);		// [clientReqeust][onDrain]
		duk_push_heapptr(ctx, digestClientPtr);														// [clientReqeust][onDrain][digestClientRequest]
		duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);										// [clientReqeust][onDrain]
		ILibDuktape_EventEmitter_AddOn(ILibDuktape_EventEmitter_GetEmitter(ctx, -2), "drain", duk_get_heapptr(ctx, -1));
		duk_pop(ctx);																				// [clientReqeust]

		duk_push_heapptr(ctx, digestClientPtr);														// [clientRequest][digestClientRequest]
		duk_swap_top(ctx, -2);																		// [digestClientRequest][clientRequest]
		duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);										// [digestClientRequest]
	}

	return(0);
}
duk_ret_t ILibDuktape_httpDigest_clientRequest_setter(duk_context *ctx)
{
	duk_dup(ctx, 0);																		// [clientRequest]
	duk_get_prop_string(ctx, -1, "once");													// [clientRequest][once]
	duk_swap_top(ctx, -2);																	// [once][this]
	duk_push_string(ctx, "response");														// [once][this][response]
	duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_response, DUK_VARARGS);	// [once][this][response][method]
	duk_push_this(ctx);																		// [once][this][response][method][digest]
	duk_put_prop_string(ctx, -2, "digest");													// [once][this][response][method]
	if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http-digest: Error setting clientRequest"); }
	duk_pop(ctx);																			// ..
	return(0);
}
duk_ret_t ILibDuktape_httpDigest_http_setter(duk_context *ctx)
{
	duk_push_this(ctx);							// [digest]
	duk_dup(ctx, 0);							// [digest][http]
	duk_put_prop_string(ctx, -2, HTTP_DIGEST);	// [digest]
	return(0);
}
duk_ret_t ILibDuktape_httpDigest_digestRequest_end(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int i;
	duk_push_this(ctx);										// [digestClientRequest]
	if (duk_has_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST))
	{
		duk_get_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);	// [digestClientRequest][clientRequest]
		duk_get_prop_string(ctx, -1, "end");					// [digestClientRequest][clientRequest][end]
		duk_swap_top(ctx, -2);									// [digestClientRequest][end][this]

		for (i = 0; i < nargs; ++i)
		{
			duk_dup(ctx, i);									// [digestClientRequest][end][this][params...]
		}
		if (duk_pcall_method(ctx, nargs) != 0) { duk_throw(ctx); return(DUK_RET_ERROR); }

		duk_push_this(ctx);
		duk_del_prop_string(ctx, -1, "DIGEST_CLIENT_REQUEST");
	}
	return(0);
}

ILibTransport_DoneState ILibDuktape_httpDigest_http_request_WriteHandler(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibTransport_DoneState retVal = ILibTransport_DoneState_ERROR;

	duk_context *ctx = stream->ctx;
	duk_push_heapptr(ctx, stream->obj);							// [digestClientRequest]
	if (duk_has_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST))
	{
		duk_get_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);	// [digestClientRequest][clientRequest]
		duk_get_prop_string(ctx, -1, "write");					// [digestClientRequest][clientRequest][write]
		duk_swap_top(ctx, -2);									// [digestClientRequest][write][this]

		if (stream->Reserved == 0)
		{
			duk_push_external_buffer(ctx);
			duk_config_buffer(ctx, -1, buffer, (duk_size_t)bufferLen);
		}
		else
		{
			duk_push_lstring(ctx, buffer, (duk_size_t)bufferLen);
		}

		if (duk_pcall_method(ctx, 1) != 0) 
		{ 
			ILibDuktape_Process_UncaughtExceptionEx(ctx, "http-digest.clientRequest.write(): "); 
			retVal = ILibTransport_DoneState_ERROR; 
		}
		else
		{
			retVal = duk_get_boolean(ctx, -1) ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
		}
		duk_pop(ctx);											// [digestClientRequest]

	}
	duk_pop(ctx);												// ...
	return(retVal);
}
void ILibDuktape_httpDigest_http_request_DoneHandler(struct ILibDuktape_WritableStream *stream, void *user)
{
	duk_context *ctx = stream->ctx;

	duk_push_heapptr(ctx, stream->obj);							// [digestClientRequest]
	if (duk_has_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST))
	{
		duk_get_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);	// [digestClientRequest][clientRequest]
		duk_get_prop_string(ctx, -1, "end");					// [digestClientRequest][clientRequest][end]
		duk_swap_top(ctx, -2);									// [digestClientRequest][end][this]

		if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http-digest.clientRequest.end(): "); }
		duk_pop(ctx);											// [digestClientRequest]
		duk_del_prop_string(ctx, -1, "DIGEST_CLIENT_REQUEST");
	}
	duk_pop(ctx);												// ...
}
duk_ret_t ILibDuktape_httpDigest_http_request(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	void *clientRequest = NULL;
	ILibDuktape_EventEmitter *emitter;
	ILibDuktape_EventEmitter *crEmitter;

	duk_push_current_function(ctx);				// [func]
	duk_get_prop_string(ctx, -1, "isGet");		// [func][isGet]
	duk_push_this(ctx);							// [func][isGet][digest]
	duk_get_prop_string(ctx, -1, HTTP_DIGEST);	// [func][isGet][digest][http]
	if (duk_get_int(ctx, -3) != 0)
	{
		duk_get_prop_string(ctx, -1, "get");	// [func][isGet][digest][http][get]
	}
	else
	{
		duk_get_prop_string(ctx, -1, "request");// [func][isGet][digest][http][request]
	}
	duk_swap_top(ctx, -2);						// [func][isGet][digest][get/request][this]
	duk_dup(ctx, 0);							// [func][isGet][digest][get/request][this][param1]

	if (duk_pcall_method(ctx, 1) != 0) { duk_throw(ctx); return(DUK_RET_ERROR); }
																							// [clientRequest]
	clientRequest = duk_get_heapptr(ctx, -1);
	crEmitter = ILibDuktape_EventEmitter_GetEmitter(ctx, -1);

	duk_get_prop_string(ctx, -1, "once");													// [clientRequest][once]
	duk_swap_top(ctx, -2);																	// [once][this]
	duk_push_string(ctx, "response");														// [once][this][response]
	duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_response, DUK_VARARGS);	// [once][this][response][method] 
	
	duk_push_object(ctx);																	// [once][this][response][method][digest-clientRequest]
	duk_push_heapptr(ctx, clientRequest);													// [once][this][response][method][digest-clientRequest][clientRequest]
	duk_dup(ctx, -2);																		// [once][this][response][method][digest-clientRequest][clientRequest][digest-clientRequest]
	duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);									// [once][this][response][method][digest-clientRequest][clientRequest]
	duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);									// [once][this][response][method][digest-clientRequest]
	emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "response");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "error");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "upgrade");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "continue");
	
	ILibDuktape_WritableStream_Init(ctx, ILibDuktape_httpDigest_http_request_WriteHandler, ILibDuktape_httpDigest_http_request_DoneHandler, NULL);

	if (nargs > 1 && duk_is_function(ctx, 1))
	{
		ILibDuktape_EventEmitter_AddOnce(ILibDuktape_EventEmitter_GetEmitter(ctx, -1), "response", duk_require_heapptr(ctx, 1));
	}
	
	duk_push_this(ctx);																		// [once][this][response][method][digest-clientRequest][digest]
	duk_put_prop_string(ctx, -2, "digest");													// [once][this][response][method][digest-clientRequest]
	duk_put_prop_string(ctx, -2, "digestClientRequest");									// [once][this][response][method]
	if (duk_pcall_method(ctx, 2) != 0) { duk_throw(ctx); return(DUK_RET_ERROR); }
																							// [clientRequest]

	duk_push_heapptr(emitter->ctx, emitter->object);											// [digestClientRequest]
	duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_propagateEvent, DUK_VARARGS);	// [digestClientRequest][EventDispatcher]
	duk_dup(ctx, -2);																			// [digestClientRequest][EventDispatcher][digestClientRequest]
	duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);										// [digestClientRequest][EventDispatcher]
	duk_push_string(ctx, "upgrade");															// [digestClientRequest][EventDispatcher][eventName]
	duk_put_prop_string(ctx, -2, CLIENTREQUEST_EVENT_NAME);										// [digestClientRequest][EventDispatcher]
	ILibDuktape_EventEmitter_AddOnce(crEmitter, "upgrade", duk_get_heapptr(ctx, -1));			// [digestClientRequest][EventDispatcher]
	duk_pop(ctx);																				// [digestClientRequest]

	duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_propagateEvent, DUK_VARARGS);	// [digestClientRequest][EventDispatcher]
	duk_dup(ctx, -2);																			// [digestClientRequest][EventDispatcher][digestClientRequest]
	duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);										// [digestClientRequest][EventDispatcher]
	duk_push_string(ctx, "error");																// [digestClientRequest][EventDispatcher][eventName]
	duk_put_prop_string(ctx, -2, CLIENTREQUEST_EVENT_NAME);										// [digestClientRequest][EventDispatcher]
	ILibDuktape_EventEmitter_AddOnce(crEmitter, "error", duk_get_heapptr(ctx, -1));				// [digestClientRequest][EventDispatcher]
	duk_pop(ctx);																				// [digestClientRequest]

	duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_propagateEvent, DUK_VARARGS);	// [digestClientRequest][EventDispatcher]
	duk_dup(ctx, -2);																			// [digestClientRequest][EventDispatcher][digestClientRequest]
	duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);										// [digestClientRequest][EventDispatcher]
	duk_push_string(ctx, "continue");															// [digestClientRequest][EventDispatcher][eventName]
	duk_put_prop_string(ctx, -2, CLIENTREQUEST_EVENT_NAME);										// [digestClientRequest][EventDispatcher]
	ILibDuktape_EventEmitter_AddOnce(crEmitter, "continue", duk_get_heapptr(ctx, -1));			// [digestClientRequest][EventDispatcher]
	duk_pop(ctx);																				// [digestClientRequest]

	duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_onDrain, DUK_VARARGS);		// [digestClientRequest][onDrain]
	duk_dup(ctx, -2);																			// [digestClientRequest][onDrain][digestClientRequest]
	duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);										// [digestClientRequest][onDrain]
	ILibDuktape_EventEmitter_AddOn(crEmitter, "drain", duk_get_heapptr(ctx, -1));				// [digestClientRequest][onDrain]
	duk_pop(ctx);																				// [digestClientRequest]

	return(1);
}
duk_ret_t ILibduktape_httpDigest_create(duk_context *ctx)
{
	duk_size_t usernameLen, passwordLen;
	char *username = (char*)duk_require_lstring(ctx, 0, &usernameLen), *password = (char*)duk_require_lstring(ctx, 1, &passwordLen);
	ILibDuktape_EventEmitter *emitter;

	duk_push_object(ctx);					// [obj]
	ILibDuktape_CreateEventWithSetterEx(ctx, "clientRequest", ILibDuktape_httpDigest_clientRequest_setter);
	ILibDuktape_CreateEventWithSetterEx(ctx, "http", ILibDuktape_httpDigest_http_setter);
	emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "response");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "error");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "upgrade");
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "isGet", 1, "get", ILibDuktape_httpDigest_http_request, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "isGet", 0, "request", ILibDuktape_httpDigest_http_request, DUK_VARARGS);
	duk_push_string(ctx, username);
	duk_put_prop_string(ctx, -2, DIGEST_USERNAME);
	duk_push_string(ctx, password);
	duk_put_prop_string(ctx, -2, DIGEST_PASSWORD);

	return(1);
}

void ILibDuktape_httpDigest_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_CreateInstanceMethod(ctx, "create", ILibduktape_httpDigest_create, 2);
}
duk_ret_t ILibDuktape_httpHeaders(duk_context *ctx)
{
	ILibHTTPPacket *packet = NULL;
	packetheader_field_node *node;
	int headersOnly = duk_get_top(ctx) > 1 ? (duk_require_boolean(ctx, 1) ? 1 : 0) : 0;

	duk_size_t bufferLen;
	char *buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);

	packet = ILibParsePacketHeader(buffer, 0, (int)bufferLen);
	if (packet == NULL) { return(ILibDuktape_Error(ctx, "http-headers(): Error parsing data")); }

	if (headersOnly == 0)
	{
		duk_push_object(ctx);
		if (packet->Directive != NULL)
		{
			duk_push_lstring(ctx, packet->Directive, packet->DirectiveLength);
			duk_put_prop_string(ctx, -2, "method");
			duk_push_lstring(ctx, packet->DirectiveObj, packet->DirectiveObjLength);
			duk_put_prop_string(ctx, -2, "url");
		}
		else
		{
			duk_push_int(ctx, packet->StatusCode);
			duk_put_prop_string(ctx, -2, "statusCode");
			duk_push_lstring(ctx, packet->StatusData, packet->StatusDataLength);
			duk_put_prop_string(ctx, -2, "statusMessage");
		}
		if (packet->VersionLength == 3)
		{
			duk_push_object(ctx);
			duk_push_lstring(ctx, packet->Version, 1);
			duk_put_prop_string(ctx, -2, "major");
			duk_push_lstring(ctx, packet->Version + 2, 1);
			duk_put_prop_string(ctx, -2, "minor");
			duk_put_prop_string(ctx, -2, "version");
		}
	}

	duk_push_object(ctx);		// headers
	node = packet->FirstField;
	while (node != NULL)
	{
		duk_push_lstring(ctx, node->Field, node->FieldLength);
		duk_push_lstring(ctx, node->FieldData, node->FieldDataLength);
		duk_put_prop(ctx, -3);
		node = node->NextField;
	}
	if (headersOnly == 0)
	{
		duk_put_prop_string(ctx, -2, "headers");
	}
	ILibDestructPacket(packet);
	return(1);
}
void ILibDuktape_httpHeaders_PUSH(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_httpHeaders, DUK_VARARGS);
}
void ILibDuktape_http_init(duk_context * ctx, void * chain)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "http", ILibDuktape_http_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "https", ILibDuktape_https_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "http-digest", ILibDuktape_httpDigest_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "http-headers", ILibDuktape_httpHeaders_PUSH);
}

#ifdef __DOXY__

/*!
\brief Http exposed using Node APIs. <b>Note:</b> To use, must <b>require('http')</b> or <b>require('https')</b>
*/
class Http
{
public:
	/*!
	\brief Parses a uri string
	\param str \<String\> The uri to parse
	\return Uri object of the parsed string
	*/
	static Uri parseUri(str);
	/*!
	\brief Returns a new instance of Server
	*
	static Server createServer([options][, callback]);
	\param options <Object> that specifies various parameters such as:\n
	'request' = <func> callback to be dispatched when a request is received\n
	'pfx' = \<Buffer\|String\> containing PKS encoded certificate\n
	'passphrase' = \<String\> containing the passphrase to unlock the private key of the specified certificate\n
	'MeshAgent' = <MeshAgent> object, whose certificates we are going to use.\n
	'requestCert' = <boolean> indicating if the client certificate will be requested\n
	'rejectUnauthorized' = <boolean> indicating if the certificate must have a valid root of trust\n
	'checkClientIdentity' = <func> callback to be dispatched to verify client certificate. <b>Note:</b> When dispatched, throw an exception to fail verification.\n
	\param callback <func> callback to be dispatched when a request is received
	\return Server instance.
	*/
	static Server createServer([options][, callback]);
	/*!
	\brief Issues an HTTP Request onto the network
	*
	static ClientRequest request(options[, callback]);
	\param options \<Object\|String\|Url\>\n
	<b>protocol</b> \<String\> Protocol to use. Defaults to 'http:' or 'https:' depending on configuration\n
	<b>host</b> \<String\> A domain name or IP address of the server to issue the request to. Defaults to localhost.\n
	<b>hostname</b> \<String\> Alias for host. To support url.parse(), hostname is preferred over host.\n
	<b>port</b> <number> Port of remote server. Defaults to 80, or 443, depending on configuration\n
	<b>localAddress</b> \<String\> Local interface to bind for network connections.\n
	<b>method</b> \<String\> A string specifying the HTTP request method. Defaults to 'GET'.\n
	<b>path</b> \<String\> Request path. Defaults to '/'\n
	<b>headers</b> <Object> An object containing request headers.\n
	<b>proxy</b> <Object> An object containing proxy settings, (ie: 'host' and 'port'), to use for this connection\n
	<b>noProxy</b> <boolean> When present, will override any previously set proxies, and disable it for this connection\n
	<b>pfx</b> \<Buffer\|String\> containing pks encoded certificate\n
	<b>passphrase</b> \<String\> containing passphrase used to unlock specified certificate\n
	<b>MeshAgent</b> <MeshAgent> containing the MeshAgent instance, whose certificates will be used\n
	<b>rejectUnauthorized</b> <boolean> If true, will reject server's whose root of trust cannot be validated\n
	<b>checkServerIdentity</b> <func> callback that will be dispatched to validate server certificate. <b>Note:</b> To fail validation, throw an exception from the dispatch.\n
	\param callback <func> Optional. Set as one time listener for ClientRequest.response event.
	\return ClientRequest instance.
	*/
	static ClientRequest request(options[, callback]);

	/*!
	\brief Issues an HTTP Request onto the network. 
	\param url \<String\> The url to issue a GET reqeust
	\return ClientRequest instance
	*/
	static ClientRequest get(url);
	static DuplexStream createStream();


	/*!
	\implements EventEmitter
	\brief Http Server Abstraction
	*/
	class Server
	{
	public:
		/*!
		\brief Event emitted each time a request with an HTTP Expect: 100-continue is received. If this event is not listened for, the server will automatically respond with a 100 Continue as appropriate.
		*
		<b>Note:</b> When this event is emitted and handled, Http.request event will not be emitted.
		\param request \<IncomingMessage\>
		\param response \<ServerResponse\>
		*/
		void checkContinue;
		/*!
		\brief Event emitted each time a request with an HTTP Expect header is received, where the value is not 100-continue. If this event is not listened for, the server will automatically respond with a 417 Expectation Failed as appropriate.
		*
		<b>Note:</b> When this event is emitted and handled, Http.request event will not be emitted.
		*/
		void checkExpectation;
		/*!
		\brief Event emitted if the underlying Socket emits an error
		\param err <Error>
		\param socket \<Socket\>
		*/
		void clientError;
		/*!
		\brief Event emitted when the Server closes.
		*/
		void close;
		/*!
		\brief Event emitted when the client issues a 'CONNECT' method. If this event is not listened for, then clients requesting a CONNECT method will have their connections closed.
		\param request \<IncomingMessage\> Arguments for the HTTP request, as it is in the 'request' event
		\param socket \<Socket\> Network socket between the server and client
		\param head \<Buffer\> The first packet of the tunneling stream (may be empty)
		*/
		void connect;
		/*!
		\brief Event emitted each time a client requests an HTTP upgrade.  If this event is not listened for, then clients requesting an upgrade will have their connections closed.
		\param request \<IncomingMessage\> Arguments for the HTTP request, as it is in the 'request' event
		\param socket \<Socket\> Network socket between the server and client
		\param head \<Buffer\> The first packet of the tunneling stream (may be empty)
		*/
		void upgrade;
		/*!
		\brief Event emitted each time there is a request. <b>Note:</b> There may be multiple requests per connection (in the case of HTTP Keep-Alive connections).
		\param request \<IncomingMessage\>
		\param response \<ServerResponse\>
		*/
		void request;
		/*!
		\brief Event emitted when server is listening for incoming connections
		*/
		void listening;
		/*!
		\brief Stops the server from accepting new connections
		\param callback <func> Optional. Set as one time listener for 'close' event.
		*/
		void close([callback]);
		/*!
		\brief Event emitted when an idle timeout has elapsed
		\param socket \<Socket\> Timed out socket
		*/
		void timeout;
		/*!
		\brief Begin accepting connections on the specified port and hostname
		\param port <Integer>
		\param hostname \<String\>
		\param backlog <Integer>
		\param callback <func> Optional. Set as one time listener to 'listening' event
		*/
		void listen([port][, hostname][, backlog][, callback]);
		/*!
		\brief Sets the timeout value for sockets, and emits a 'timeout' event on the Server object, passing the socket as an argument, if a timeout occurs.
		\param msecs <Integer> Optional <b>Default: 120000</b> milliseconds (2 minutes)
		\param callback <func> Optional. Set as one time listener for 'timeout' event
		*/
		void setTimeout([msecs][, callback]);
		/*!
		\implements WritableStream
		\implements EventEmitter
		\brief Created internally by Http.
		*/
		class ServerResponse
		{
		public:
			/*!
			\brief 	Sets a single header value for implicit headers.If this header already exists in the to - be - sent headers, its value will be replaced
			\param name \<String\>
			\param value \<String\>
			*/
			void setHeader(name, value);
			/*!
			\brief Sends a response header to the request.
			\param statusCode <Integer> 3 digit code (ie: 200, 404, etc)
			\param statusMessage \<String\> Human readable status message (ie: 'OK', 'File Not Found', etc)
			\param headers <Object> Optional. JSON object where each name/value pair is a header/value pair.
			*/
			void writeHead(statusCode[, statusMessage][, headers]);
			/*!
			\brief When using implicit headers (not calling writeHead() explicitly), this property controls the status code that will be sent to the client when the headers get flushed.
			*/
			Integer statusCode;
			/*!
			\brief When using implicit headers (not calling writeHead() explicitly), this property controls the status message that will be sent to the client when the headers get flushed
			*/
			String statusMessage;
		};
	};
	/*!
	\implements WritableStream
	\brief This object is created internally and returned from http.request(). It represents an in-progress request whose header has already been queued.
	*/
	class ClientRequest
	{
	public:
		/*!
		\brief Event emitted when a response is received to this request. This event is emitted only once.
		\param msg IncomingMessage object containing the received request
		*/
		void response;
		/*!
		\brief Event emitted each time a server responds to a request with an upgrade. 
		\param response IncomingMessage
		\param socket WebSocket
		\param head <Buffer>
		*/
		void upgrade;
	};

	/*!
	\implements Socket
	\brief WebSocket abstraction
	*/
	class WebSocket
	{
	public:
		/*!
		\brief Event emitted when a 'ping' web socket control packet is received.
		\param data \<Buffer\|String\|NULL\> Optional data that was attached to the received 'ping' control packet.
		*/
		void ping;
		/*!
		\brief Event emitted when a 'pong' web socket control packet is received.
		\param data \<Buffer\|String\|NULL\> Optional data that was attached to the received 'pong' control packet.
		*/
		void pong;
		/*!
		\brief Send a 'ping' web socket control packet to the connected peer.
		*
		void ping([data]);
		\param data \<Buffer\|String\|NULL\> Optional data to attach to the 'ping' control packet.
		*/
		void ping([data]);
		/*!
		\brief Send a 'pong' web socket control packet to the connected peer.
		*
		void pong([data]);
		\param data \<Buffer\|String\|NULL\> Optional data to attach to the 'pong' control packet.
		*/
		void pong([data]);
	};


	/*!
	\brief An IncomingMessage object may be used to access response status, headers and data.
	*/
	class IncomingMessage
	{
	public:
		/*!
		\brief Key-value pairs of header names and values. Header names are lower-cased
		*/
		Object headers;
		/*!
		\brief HTTP Version sent by client. Usually either '1.0' or '1.1'
		*/
		String httpVersion;
		/*!
		\brief Request Method as a String. (ie: GET, PUT, etc)
		*/
		String method;
		/*!
		\brief The Socket object associated with this connection
		*/
		Socket socket;
		/*!
		\brief 3 digit HTTP Status Code. (ie: 200, 404, etc)
		*/
		integer statusCode;
		/*!
		\brief HTTP Status Message (ie: 'OK', 'File Not Found', etc)
		*/
		String statusMessage;
		/*!
		\brief HTTP Request Path line (ie: '/index.html', etc)
		*/
		String url;
	};

	/*!
	\brief Network Uri abstraction
	*/
	class Uri
	{
	public:
		/*!
		\brief Protocol (ie: http, https, wss, etc)
		*/
		String protocol;
		/*!
		\brief Host IP or DNS Name
		*/
		String host;
		/*!
		\brief Host port
		*/
		integer port;
		/*!
		\brief Method Path (ie: /index.html)
		*/
		String path;
		/*!
		\brief Method. (ie: GET, PUT, HEAD, etc)
		*/
		String method;
	};
};


/*!
\brief Provides HTTP-Digest Authentication Services. <b>Note:</b> To use must <b>require('http-digest').Create()</b>
*
After creation, the 'http' property must be set, typically with <b>require('http')</b>. Afterwards, calls to 'request' can be made.
*/
class HttpDigest 
{
public:
	/*!
	\brief Initializes an HttpDigest object with the specified username and password.
	\param username \<String\> The username to encode
	\param password \<String\> The password to encode
	\return HttpDigest instance
	*/
	static HttpDigest Create(username, password);
	/*!
	\brief Wrapped Http implementation, which <b>must</b> be set. Typically set to <b>require('http')</b> or <b>require('https')</b>
	*/
	Http http;
	/*!
	\brief Issues a Digest-Authenticated HTTP Request onto the network
	*
	static DigestClientRequest request(options[, callback]);
	\param options \<Object\|String\|Url\>\n
	<b>protocol</b> \<String\> Protocol to use. Defaults to 'http:' or 'https:' depending on configuration\n
	<b>host</b> \<String\> A domain name or IP address of the server to issue the request to. Defaults to localhost.\n
	<b>hostname</b> \<String\> Alias for host. To support url.parse(), hostname is preferred over host.\n
	<b>port</b> <number> Port of remote server. Defaults to 80, or 443, depending on configuration\n
	<b>localAddress</b> \<String\> Local interface to bind for network connections.\n
	<b>method</b> \<String\> A string specifying the HTTP request method. Defaults to 'GET'.\n
	<b>path</b> \<String\> Request path. Defaults to '/'\n
	<b>headers</b> <Object> An object containing request headers.\n
	<b>proxy</b> <Object> An object containing proxy settings, (ie: 'host' and 'port'), to use for this connection\n
	<b>noProxy</b> <boolean> When present, will override any previously set proxies, and disable it for this connection\n
	<b>pfx</b> \<Buffer\|String\> containing pks encoded certificate\n
	<b>passphrase</b> \<String\> containing passphrase used to unlock specified certificate\n
	<b>MeshAgent</b> <MeshAgent> containing the MeshAgent instance, whose certificates will be used\n
	<b>rejectUnauthorized</b> <boolean> If true, will reject server's whose root of trust cannot be validated\n
	<b>checkServerIdentity</b> <func> callback that will be dispatched to validate server certificate. <b>Note:</b> To fail validation, throw an exception from the dispatch.\n
	\param callback <func> Optiona. Set as one time listener to DigestClientRequest.response event.
	\return \<DigestClientRequest\>
	*/
	DigestClientRequest request(options[, callback]);

	/*!
	\implements Http::ClientRequest
	\brief Encapsulation of Http::ClientRequest. Digest-Authentication may require multiple request/response sequences, so the underlying Http::ClientRequest may change
	*/
	class DigestClientRequest
	{
	};
};


/*!
\brief Helper function to parse HTTP Headers. <b>Note:</b> To use, must <b>require('http-headers')</b>
*/
class HttpHeaders
{
public:
	/*!
	\brief Parses the specified buffer
	*
	static HttpHeaders HttpHeaders(data[, headersOnly]);
	\param data \<Buffer\|String\> The data to parse
	\param headersOnly <boolean> Optional parameter, that if true, will indicate to the parser to skip parsing of the Method/Path/Version/etc.
	\return HttpHeaders representing the parsed data
	*/
	static HttpHeaders HttpHeaders(data[, headersOnly]);

	/*!
	\brief HTTP Method. (ie: GET, PUT, HEAD, etc)
	*/
	public String method;
	/*!
	\brief HTTP Method Path (ie: /index.html)
	*/
	public String url;
	/*!
	\brief HTTP Status Code (ie: 200)
	*/
	public integer statusCode;
	/*!
	\brief HTTP Status Code Message (ie: OK)
	*/
	public String statusMessage;
	/*!
	\brief HttpVersion of the decoded HTTP headers
	*/
	public HttpVersion version;
	/*!
	\brief JSON object of decoded HTTP headers. Property key is header name, Property value is header value.
	*/
	public object headers;

	/*!
	\brief HTTP Version 
	*/
	class HttpVersion
	{
	public:
		/*!
		\brief major version
		*/
		public String major;
		/*!
		\brief minor version
		*/
		public String minor;
	};
};
#endif