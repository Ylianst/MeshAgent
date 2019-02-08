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
#endif

#include "../microstack/ILibParsers.h"

#include "duktape.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktape_DuplexStream.h"
#include "ILibDuktape_net.h"

#include "../microstack/ILibWebClient.h"
#include "../microstack/ILibRemoteLogging.h"

struct ILibWebClientDataObject;
extern int ILibWebServer_WebSocket_CreateHeader(char* header, unsigned short FLAGS, unsigned short OPCODE, int payloadLength);
extern void ILibWebClient_ResetWCDO(struct ILibWebClientDataObject *wcdo);

#define ILibDuktape_Agent_SocketJustCreated "\xFF_Agent_SocketJustCreated"
#define ILibDuktape_ClientRequest			"\xFF_CR"
#define ILibDuktape_CR_EndCalled			"\xFF_CR_EndCalled"
#define ILibDuktape_CR_RequestBuffer		"\xFF_CR_RequestBuffer"
#define ILibDuktape_CR2Agent				"\xFF_CR2Agent"
#define ILibDuktape_CR2HTTPStream			"\xFF_CR2HTTPStream"
#define ILibDuktape_CR2TLSStream			"\xFF_CR2TLSStream"
#define ILibDuktape_CR2Transform			"\xFF_CR2Transform"
#define ILibDuktape_FUNC					"\xFF_FUNC"
#define IILibDuktape_HTTP_HoldingQueue		"\xFF_HoldingQueue"
#define ILibDuktape_Http_Server_FixedBuffer "\xFF_Http_Server_FixedBuffer"
#define ILibDuktape_Http_Server2NetServer	"\xFF_HttpServer2NetServer"
#define ILibduktape_HttpStream2HttpServer	"\xFF_HttpStream_2_HttpServer"
#define ILibDuktape_HttpServer_TimeoutCB	"\xFF_HttpServer_TimeoutCB"
#define ILibDuktape_HTTP2CR					"\xFF_HTTP2ClientRequest"
#define ILibDuktape_HTTP2PipedReadable		"\xFF_HTTP2PipedReadable"
#define ILibDuktape_HTTP2PipedWritable		"\xFF_HTTP2PipedWritable"
#define ILibDuktape_HTTPStream2Data			"\xFF_HTTPStream2Data"
#define ILibDuktape_HTTPStream2HTTP			"\xFF_HTTPStream2HTTP"
#define ILibDuktape_HTTPStream2IMSG			"\xFF_HTTPStream2IMSG"
#define ILibDuktape_HTTPStream2Socket		"\xFF_HTTPStream2Socket"
#define ILibDuktape_IMSG2HttpStream			"\xFF_IMSG2HttpStream"
#define ILibDuktape_IMSG2Ptr				"\xFF_IMSG2Ptr"
#define ILibDuktape_IMSG2SR					"\xFF_IMSG2ServerResponse"
#define ILibDuktape_NS2HttpServer			"\xFF_Http_NetServer2HttpServer"
#define ILibDuktape_Options2ClientRequest	"\xFF_Options2ClientRequest"
#define ILibDuktape_PipedReadable			"\xFF_PipedReadable"
#define ILibDuktape_Socket2AgentStash		"\xFF_Socket2AgentStash"
#define ILibDuktape_Socket2Agent			"\xFF_Socket2Agent"
#define ILibDuktape_Socket2AgentKey			"\xFF_Socket2AgentKey"
#define ILibDuktape_Socket2CR				"\xFF_Socket2CR"
#define ILibDuktape_Socket2HttpServer		"\xFF_Socket2HttpServer"
#define ILibDuktape_Socket2HttpStream		"\xFF_Socket2HttpStream"
#define ILibDuktape_Socket2DiedListener		"\xFF_Socket2DiedListener"
#define ILibDuktape_Socket2TLS				"\xFF_Socket2TLS"
#define ILibDuktape_SR2HttpStream			"\xFF_ServerResponse2HttpStream"
#define ILibDuktape_SR2ImplicitHeaders		"\xFF_ServerResponse2ImplicitHeaders"
#define ILibDuktape_SR2State				"\xFF_ServerResponse2State"
#define ILibDuktape_SRUSER					"\xFF_SRUSER"
#define ILibDuktape_SR2WS					"\xFF_Http_ServerResponse2WS"
#define ILibDuktape_WebSocket_Client		((void*)0x01)
#define ILibDuktape_WebSocket_Server		((void*)0x02)
#define ILibDuktape_WebSocket_StatePtr		"\xFF_WebSocketState"
#define ILibDuktape_WSENC2WS				"\xFF_WSENC2WS"
#define ILibDuktape_WS2CR					"\xFF_WS2ClientRequest"
#define ILibDuktape_WSDEC2WS				"\xFF_WSDEC2WS"

extern void ILibWebServer_Digest_ParseAuthenticationHeader(void* table, char* value, int valueLen);

typedef struct ILibDuktape_Http_ClientRequest_WriteData
{
	char *buffer;
	int noMoreWrites;
	int headersFinished;
	int contentLengthSpecified;
	int needRetry;
	int retryCounter;
	size_t bufferWriteLen;
	size_t bufferLen;
}ILibDuktape_Http_ClientRequest_WriteData;

typedef struct ILibDuktape_HttpStream_Data
{
	ILibDuktape_DuplexStream *DS;
	ILibDuktape_readableStream *bodyStream;

	int bodyStream_unshiftedBytes;

	void *DynamicBuffer;
	int connectionCloseSpecified;
	int contentLengthSpecified;
	void *WCDO;
	void *chain;
	int ConnectMethod;
	int endPropagated;
}ILibDuktape_HttpStream_Data;

typedef struct ILibDuktape_HttpStream_ServerResponse_State
{
	duk_context *ctx;
	void *chain;
	void *writeStream;
	void *serverResponse;
	ILibDuktape_WritableStream *nativeWriteStream;
	int implicitHeaderHandling;
	int chunkSupported;
	int contentLengthSpecified;
}ILibDuktape_HttpStream_ServerResponse_State;
typedef struct ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State
{
	void *ctx;
	void *writeStream;
	void *serverResponseObj;
	void *serverResponseStream;
	int endBytes;
	int chunk;
	size_t bufferLen;
	char buffer[];
}ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State;

typedef struct ILibDuktape_WebSocket_State
{
	void *chain;
	int	  noMasking;
	int   WebSocketFragmentFlag;			// WebSocketFragmentFlag
	int   WebSocketFragmentFlag_Write;		// WebSocketFragmentFlag
	int   WebSocketDataFrameType;			// WebSocketDataFrameType
	char* WebSocketFragmentBuffer;			// WebSocketFragmentBuffer
	int   WebSocketFragmentIndex;			// WebSocketFragmentIndex;
	int	  WebSocketFragmentBufferSize;		// WebSocketFragmentBufferSize;
	int	  WebSocketFragmentMaxBufferSize;	// WebSocketFragmentMaxBufferSize;
	char  WebSocketCloseFrameSent;			// WebSocketCloseFrameSent
	void *ObjectPtr;						// Used to emit Ping/Pong events
	duk_context *ctx;						// Used to emit Ping/Pong events

	int noResume;
	int closed;

	ILibDuktape_DuplexStream *encodedStream;
	ILibDuktape_DuplexStream *decodedStream;
}ILibDuktape_WebSocket_State;

typedef struct ILibDuktape_Http_Server
{
	duk_context *ctx;
	
}ILibDuktape_Http_Server;

typedef struct ILibDuktape_http_ServerResponse
{
	duk_context *ctx;
	ILibDuktape_WritableStream *ws;

}ILibDuktape_http_ServerResponse;

int ILibDuktape_Headers_IsChunkSupported(ILibHTTPPacket *header)
{
	if (header->VersionLength == 3 && strncmp(header->Version, "1.0", 3) == 0)
	{
		return(0);
	}
	else
	{
		return(1);
	}
}
void ILibDuktape_serverResponse_resetHttpStream(duk_context *ctx, void *serverResponse)
{
	// Need to reset HttpStream
	duk_push_heapptr(ctx, serverResponse);									// [serverResponse]
	duk_get_prop_string(ctx, -1, ILibDuktape_SR2HttpStream);				// [serverResponse][httpStream]
	duk_get_prop_string(ctx, -1, ILibDuktape_HTTPStream2Data);				// [serverResponse][httpStream][data]
	ILibDuktape_HttpStream_Data *data = (ILibDuktape_HttpStream_Data*)Duktape_GetBuffer(ctx, -1, NULL);

	ILibWebClient_FinishedResponse_Server(data->WCDO);
	if (data->bodyStream != NULL)
	{
		ILibDuktape_readableStream_WriteEnd(data->bodyStream);
		data->bodyStream = NULL;
	}

	duk_pop_n(ctx, 3);														// ...
}
void ILibDuktape_Digest_CalculateNonce(duk_context *ctx, void *heapptr, long long expiration, char *opaque, int opaqueLen, char* buffer)
{
	char temp[33];
	if (expiration == 0)
	{
		char tmp[8];
		util_hexToBuf(opaque, opaqueLen, tmp);
		expiration = ((long long*)tmp)[0];
	}
	memcpy_s(temp, sizeof(temp), &expiration, 8);
	memcpy_s(temp + 8, sizeof(temp) - 8, &heapptr, sizeof(void*));

	util_md5hex(temp, 8 + sizeof(void*), buffer);
}
duk_ret_t ILibDuktape_HttpStream_http_get(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	if (duk_is_string(ctx, 0))
	{
		// First Param is a string
		duk_push_this(ctx);							// [http]
		duk_get_prop_string(ctx, -1, "parseUri");	// [http][parseUri]
		duk_swap_top(ctx, -2);						// [parseUri][this]
		duk_dup(ctx, 0);							// [parseUri][this][uri]
		duk_call_method(ctx, 1);					// [uri]
		duk_push_this(ctx);							// [uri][http]
		duk_get_prop_string(ctx, -1, "request");	// [uri][http][request]
		duk_swap_top(ctx, -2);						// [uri][request][this]
		duk_push_object(ctx);						// [uri][request][this][options]
		duk_get_prop_string(ctx, -4, "protocol");	// [uri][request][this][options][protocol]
		duk_put_prop_string(ctx, -2, "protocol");	// [uri][request][this][options]
		duk_get_prop_string(ctx, -4, "host");		// [uri][request][this][options][host]
		duk_put_prop_string(ctx, -2, "host");		// [uri][request][this][options]
		duk_get_prop_string(ctx, -4, "port");		// [uri][request][this][options][port]
		duk_put_prop_string(ctx, -2, "port");		// [uri][request][this][options]
		duk_get_prop_string(ctx, -4, "path");		// [uri][request][this][options][path]
		duk_put_prop_string(ctx, -2, "path");		// [uri][request][this][options]
		duk_push_string(ctx, "GET");				// [uri][request][this][options][method]
		duk_put_prop_string(ctx, -2, "method");		// [uri][request][this][options]
	}
	else if (duk_is_object(ctx, 0))
	{
		duk_push_this(ctx);										// [http]
		duk_get_prop_string(ctx, -1, "request");				// [http][request]
		duk_swap_top(ctx, -2);									// [request][this]
		duk_dup(ctx, 0);										// [request][this][options]
		duk_push_string(ctx, "GET");							// [request][this][options][method]
		duk_put_prop_string(ctx, -2, "method");					// [request][this][options]
	}
	else
	{
		return(ILibDuktape_Error(ctx, "http.get(): invalid parameter type"));
	}

	if (nargs > 1 && duk_is_function(ctx, 1))
	{
		duk_dup(ctx, 1);						// [request][this][options][callback]
		duk_call_method(ctx, 2);				// [retVal]
	}
	else
	{											// [request][this][options]
		duk_call_method(ctx, 1);				// [retVal]
	}

												// [clientRequest]
	duk_get_prop_string(ctx, -1, "end");		// [clientRequest][end]
	duk_dup(ctx, -2);							// [clientRequest][end][this]
	duk_call_method(ctx, 0); duk_pop(ctx);		// [clientRequest]

	return(1);
}
duk_ret_t ILibDuktape_HttpStream_http_checkIdentity(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int i;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_FUNC);				// [func]
	duk_get_prop_string(ctx, -2, ILibDuktape_ClientRequest);	// [func][this]
	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);										// [func][this][...args]
	}
	duk_call_method(ctx, nargs);
	return(1);
}

void ILibDuktape_HttpStream_http_ConvertOptionToSend(duk_context *ctx, void *ObjectPtr, void *OptionsPtr)
{
	char *tmp, *buffer = NULL;
	duk_size_t len;
	size_t bufferLen = 0;
	int i;
	int expectSpecified = 0;
	ILibDuktape_Http_ClientRequest_WriteData *data;

	duk_push_heapptr(ctx, ObjectPtr);									// [stream]
	duk_push_heapptr(ctx, OptionsPtr);									// [stream][Options]
	duk_get_prop_string(ctx, -1, ILibDuktape_Options2ClientRequest);	// [stream][Options][CR]
	duk_get_prop_string(ctx, -1, ILibDuktape_CR_RequestBuffer);			// [stream][Options][CR][data]
	data = (ILibDuktape_Http_ClientRequest_WriteData*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop_2(ctx);													// [stream][Options]

	char *protocol = Duktape_GetStringPropertyValue(ctx, -1, "protocol", "");
	if (strcmp(protocol, "ws:") == 0 || strcmp(protocol, "wss:") == 0)
	{
		if (duk_has_prop_string(ctx, -1, "headers"))
		{
			duk_get_prop_string(ctx, -1, "headers");					// [stream][Options][headers]
		}
		else
		{
			duk_push_object(ctx);										// [stream][Options][headers]
			duk_dup(ctx, -1);											// [stream][Options][headers][dup]
			duk_put_prop_string(ctx, -3, "headers");					// [stream][Options][headers]
		}
		char nonce[16];
		char value[26];
		char *enc = value;

		util_random(16, nonce);
		ILibBase64Encode((unsigned char*)nonce, 16, (unsigned char**)&enc);

		duk_push_string(ctx, "websocket");
		duk_put_prop_string(ctx, -2, "Upgrade");

		duk_push_string(ctx, "Upgrade");
		duk_put_prop_string(ctx, -2, "Connection");

		duk_push_string(ctx, enc);
		duk_put_prop_string(ctx, -2, "Sec-WebSocket-Key");

		duk_push_string(ctx, "13");
		duk_put_prop_string(ctx, -2, "Sec-WebSocket-Version");
		duk_pop(ctx);													// [stream][options]
	}

	for (i = 0; i < 2; ++i)
	{
		// measure how big a buffer we'll need
		duk_get_prop_string(ctx, -1, "method");							// [stream][options][method]
		tmp = (char*)duk_get_lstring(ctx, -1, &len);
		if (buffer != NULL) { memcpy_s(buffer + bufferLen, ILibMemory_AllocateA_Size(buffer) - bufferLen, tmp, len); (buffer + bufferLen)[len] = ' '; }
		bufferLen += (len + 1); // ('GET ')
		duk_pop(ctx);													// [stream][options]

		duk_get_prop_string(ctx, -1, "path");							// [stream][options][path]
		tmp = (char*)duk_get_lstring(ctx, -1, &len);
		if (buffer != NULL)
		{
			memcpy_s(buffer + bufferLen, ILibMemory_AllocateA_Size(buffer), tmp, len);
			memcpy_s(buffer + bufferLen + len, ILibMemory_AllocateA_Size(buffer) - bufferLen - len, " HTTP/1.1\r\n", 11);
		}
		bufferLen += (len + 11); // ('/path HTTP/1.1\r\n')
		duk_pop(ctx);													// [stream][options]

		if (duk_has_prop_string(ctx, -1, "headers"))
		{
			duk_get_prop_string(ctx, -1, "headers");					// [stream][options][headers]
			duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);			// [stream][options][headers][enumerator]
			while (duk_next(ctx, -1, 1))
			{
				tmp = (char*)duk_get_lstring(ctx, -2, &len);
				if (buffer != NULL) { memcpy_s(buffer + bufferLen, ILibMemory_AllocateA_Size(buffer) - bufferLen, tmp, len); (buffer + bufferLen)[len] = ':'; (buffer + bufferLen)[len + 1] = ' '; }
				if (len == 6 && strncasecmp(tmp, "expect", 6) == 0) { expectSpecified = 1; }
				if (len == 14 && strncasecmp(tmp, "content-length", 14) == 0) { data->contentLengthSpecified = 1; }
				bufferLen += (len + 2); // ('key: ')
				tmp = (char*)duk_get_lstring(ctx, -1, &len);
				if (buffer != NULL) { memcpy_s(buffer + bufferLen, ILibMemory_AllocateA_Size(buffer) - bufferLen, tmp, len); (buffer + bufferLen)[len] = '\r'; (buffer + bufferLen)[len + 1] = '\n'; }
				bufferLen += (len + 2); // ('value\r\n')
				duk_pop_2(ctx);											// [stream][options][headers][enumerator]
			}
			duk_pop_2(ctx);												// [stream][options]
		}
		if (expectSpecified)
		{
			if (buffer != NULL) { buffer[bufferLen] = '\r'; buffer[bufferLen + 1] = '\n'; }
			bufferLen += 2; // (\r\n')
		}
		if (buffer == NULL)
		{
			buffer = ILibMemory_AllocateA(bufferLen);
			bufferLen = 0;
		}
	}

	if (expectSpecified)
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_Options2ClientRequest);	// [stream][options][clientRequest]
		duk_get_prop_string(ctx, -1, ILibDuktape_CR_RequestBuffer);			// [stream][options][clientRequest][buffer]
		((ILibDuktape_Http_ClientRequest_WriteData*)Duktape_GetBuffer(ctx, -1, NULL))->headersFinished = 1;
		duk_pop_2(ctx);														// [stream][options]
	}

	duk_push_external_buffer(ctx);											// [stream][options][extBuffer]
	duk_config_buffer(ctx, -1, buffer, bufferLen);							// [stream][options][extBuffer]
	duk_dup(ctx, -3);														// [stream][options][extBuffer][stream]
	duk_get_prop_string(ctx, -1, "write");									// [stream][options][extBuffer][stream][write]
	duk_swap_top(ctx, -2);													// [stream][options][extBuffer][write][this]
	duk_push_buffer_object(ctx, -3, 0, bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);// [stream][options][extBuffer][write][this][buffer]

	if (duk_pcall_method(ctx, 1) != 0)										// [stream][options][extBuffer][retVal]
	{
		ILibDuktape_Error(ctx, "http.onConnect(): %s", duk_safe_to_string(ctx, -1));
	}

	duk_pop_n(ctx, 4);														// ...
}

duk_ret_t ILibDuktape_HttpStream_http_WebSocket_closed(duk_context *ctx)
{
	duk_push_this(ctx);						// [socket]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_Socket2CR))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_Socket2CR);	// [socket][CR]
		duk_push_undefined(ctx);								// [socket][CR][undefined]
		ILibDuktape_CreateReadonlyProperty(ctx, "socket");		// [socket][CR]
		duk_pop(ctx);											// [socket]
		duk_del_prop_string(ctx, -1, ILibDuktape_Socket2CR);
	}
	duk_get_prop_string(ctx, -1, "unpipe");	// [socket][unpipe]
	duk_swap_top(ctx, -2);					// [unpipe][this]
	duk_call_method(ctx, 0);
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_onUpgrade(duk_context *ctx)
{
	char *decodedKey;
	duk_size_t decodedKeyLen;
	char *key;
	duk_size_t keyLen;

	duk_get_prop_string(ctx, 0, "headers");					// [headers]
	duk_get_prop_string(ctx, -1, "Sec-WebSocket-Accept");	// [headers][key]
	key = (char*)Duktape_GetBuffer(ctx, -1, &keyLen);

	decodedKey = ILibMemory_AllocateA(keyLen);
	decodedKeyLen = ILibBase64Decode((unsigned char*)key, (int)keyLen, (unsigned char**)&decodedKey);

	// We were upgraded to WebSocket, so we need to create a WebSocket Stream, detach the HTTPStream, and emit the event
	// Upstream Readable => X => HttpStream
	duk_push_this(ctx);															// [HTTPStream]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_HTTP2CR))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_HTTP2CR);						// [HTTPStream][CR]
		duk_del_prop_string(ctx, -1, ILibDuktape_CR2HTTPStream);
		duk_pop(ctx);															// [HTTPStream]
	}
	duk_get_prop_string(ctx, -1, ILibDuktape_HTTP2PipedReadable);				// [HTTPStream][readable]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_Socket2HttpStream))
	{
		duk_del_prop_string(ctx, -1, ILibDuktape_Socket2HttpStream);
	}
	duk_get_prop_string(ctx, -1, "unpipe");										// [HTTPStream][readable][unpipe]
	duk_dup(ctx, -2);															// [HTTPStream][readable][unpipe][this]
	duk_call_method(ctx, 0);													// [HTTPStream][readable][...]
	duk_pop(ctx);																// [HTTPStream][readable]

	duk_get_prop_string(ctx, -1, "prependOnceListener");						// [HTTPStream][readable][prepend]
	duk_dup(ctx, -2);															// [HTTPStream][readable][prepend][this]
	duk_push_string(ctx, "close");												// [HTTPStream][readable][prepend][this]['close']
	duk_push_c_function(ctx, ILibDuktape_HttpStream_http_WebSocket_closed, DUK_VARARGS);
	duk_call_method(ctx, 2); duk_pop(ctx);										// [HTTPStream][readable]
	
	duk_push_external_buffer(ctx);												// [HTTPStream][readable][ext]
	duk_config_buffer(ctx, -1, decodedKey, decodedKeyLen);

	duk_eval_string(ctx, "require('http');");									// [HTTPStream][readable][ext][HTTP]
	duk_get_prop_string(ctx, -1, "webSocketStream");							// [HTTPStream][readable][ext][HTTP][wss]
	duk_remove(ctx, -2);														// [HTTPStream][readable][ext][wss]
	duk_push_buffer_object(ctx, -2, 0, decodedKeyLen, DUK_BUFOBJ_NODEJS_BUFFER);// [HTTPStream][readable][ext][wss][buffer]
	duk_new(ctx, 1);															// [HTTPStream][readable][ext][websocket]
	duk_remove(ctx, -2);														// [HTTPStream][readable][websocket]

	duk_get_prop_string(ctx, -3, ILibDuktape_HTTP2CR);							// [HTTPStream][readable][websocket][clientRequest]
	//duk_dup(ctx, -2);															// [HTTPStream][readable][websocket][clientRequest][websocket]
	//duk_put_prop_string(ctx, -2, ILibDuktape_CR2WS);							// [HTTPStream][readable][websocket][clientRequest]
	duk_put_prop_string(ctx, -2, ILibDuktape_WS2CR);							// [HTTPStream][readable][websocket]

	// Upstream Readable => WebSocket Encoded
	duk_get_prop_string(ctx, -2, "pipe");										// [HTTPStream][readable][websocket][pipe]
	duk_dup(ctx, -3);															// [HTTPStream][readable][websocket][pipe][this]
	duk_get_prop_string(ctx, -3, "encoded");									// [HTTPStream][readable][websocket][pipe][this][WS_ENC]
	duk_call_method(ctx, 1);													// [HTTPStream][readable][websocket][...]
	duk_pop(ctx);																// [HTTPStream][readable][websocket]
	duk_remove(ctx, -2);														// [HTTPStream][websocket]

	if (duk_has_prop_string(ctx, -2, ILibDuktape_HTTP2PipedWritable))
	{
		// Web Socket Encoded => Destination Stream
		duk_get_prop_string(ctx, -1, "encoded");									// [HTTPStream][websocket][WS_ENC]
		duk_get_prop_string(ctx, -1, "pipe");										// [HTTPStream][websocket][WS_ENC][pipe]
		duk_swap_top(ctx, -2);														// [HTTPStream][websocket][pipe][this]
		duk_get_prop_string(ctx, -4, ILibDuktape_HTTP2PipedWritable);				// [HTTPStream][websocket][pipe][this][destination]
		duk_call_method(ctx, 1);													// [HTTPStream][websocket][...]
		duk_pop(ctx);																// [HTTPStream][websocket]
	}
	
	duk_get_prop_string(ctx, -1, ILibDuktape_WS2CR);							// [HTTPStream][websocket][clientRequest]
	duk_get_prop_string(ctx, -1, "emit");										// [HTTPStream][websocket][clientRequest][emit]

	duk_swap_top(ctx, -2);														// [HTTPStream][websocket][emit][this]
	duk_push_string(ctx, "upgrade");											// [HTTPStream][websocket][emit][this][upgrade]
	duk_dup(ctx, 0);															// [HTTPStream][websocket][emit][this][upgrade][imsg]
	duk_dup(ctx, -5);															// [HTTPStream][websocket][emit][this][upgrade][imsg][websocket]
	duk_get_prop_string(ctx, -1, "decoded");									// [HTTPStream][websocket][emit][this][upgrade][imsg][websocket][WS_DEC]
	duk_remove(ctx, -2);														// [HTTPStream][websocket][emit][this][upgrade][imsg][WS_DEC]
	duk_push_null(ctx);															// [HTTPStream][websocket][emit][this][upgrade][imsg][WS_DEC][null]
	duk_call_method(ctx, 4); duk_pop(ctx);										// [HTTPStream][websocket]
	
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_endResponseSink(duk_context *ctx)
{
	duk_push_this(ctx);											// [imsg]
	//ILibDuktape_Log_Object(ctx, -1, "IMSG");

	duk_del_prop_string(ctx, -1, ILibDuktape_IMSG2Ptr);
	duk_get_prop_string(ctx, -1, ILibDuktape_IMSG2HttpStream);	// [imsg][httpstream]
	duk_get_prop_string(ctx, -1, ILibDuktape_HTTP2CR);			// [imsg][httpstream][CR]

	duk_del_prop_string(ctx, -3, ILibDuktape_IMSG2HttpStream);
	duk_del_prop_string(ctx, -2, ILibDuktape_HTTP2CR);
	duk_del_prop_string(ctx, -1, ILibDuktape_CR2HTTPStream);
	
	duk_get_prop_string(ctx, -1, "unpipe");						// [imsg][httpstream][CR][unpipe]
	duk_dup(ctx, -2);											// [imsg][httpstream][CR][unpipe][this]
	duk_call_method(ctx, 0); duk_pop(ctx);						// [imsg][httpstream][CR]

	duk_get_prop_string(ctx, -1, "socket");						// [imsg][httpstream][CR][socket]
	duk_insert(ctx, -4);										// [socket][imsg][httpstream][CR]
	duk_push_undefined(ctx);									// [socket][imsg][httpstream][CR][undefined]
	ILibDuktape_CreateReadonlyProperty(ctx, "socket");			// [socket][imsg][httpstream][CR]
	if (Duktape_GetBooleanProperty(ctx, -2, "connectionCloseSpecified", 0) != 0)
	{
		// We cant persist this connection, so close the socket.
		// Agent is already listening for the 'close' event, so it'll cleanup automatically
		duk_dup(ctx, -4);										// [socket][imsg][httpstream][CR][socket]
		duk_get_prop_string(ctx, -1, "end");					// [socket][imsg][httpstream][CR][socket][end]
		duk_swap_top(ctx, -2);									// [socket][imsg][httpstream][CR][end][this]
		duk_call_method(ctx, 0);
		return(0);
	}
	duk_get_prop_string(ctx, -1, ILibDuktape_CR2Agent);			// [socket][imsg][httpstream][CR][Agent]
	duk_get_prop_string(ctx, -1, "keepSocketAlive");			// [socket][imsg][httpstream][CR][Agent][keepSocketAlive]
	duk_swap_top(ctx, -2);										// [socket][imsg][httpstream][CR][keepSocketAlive][this]
	duk_dup(ctx, -6);											// [socket][imsg][httpstream][CR][keepSocketAlive][this][socket]

	//printf("End Response -->\n");
	//if (duk_has_prop_string(ctx, -1, ILibDuktape_Socket2HttpStream))
	//{
	//	duk_get_prop_string(ctx, -1, ILibDuktape_Socket2HttpStream);
	//	printf(" [Socket: %p] => [HTTPStream: %p]\n", duk_get_heapptr(ctx, -2), duk_get_heapptr(ctx, -1));
	//	ILibDuktape_Log_Object(ctx, -1, "HTTPStream");
	//	duk_pop(ctx);
	//}
	//if (duk_has_prop_string(ctx, -1, ILibDuktape_SOCKET2OPTIONS))
	//{
	//	duk_get_prop_string(ctx, -1, ILibDuktape_SOCKET2OPTIONS);
	//	ILibDuktape_Log_Object(ctx, -1, "OPTIONS");
	//	duk_pop(ctx);
	//}
	//ILibDuktape_Log_Object(ctx, -1, "SOCKET");
	//printf("\n");

	duk_call_method(ctx, 1); duk_pop(ctx);						// [socket][imsg][httpstream][CR]
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_responseSink(duk_context *ctx)
{
	duk_push_this(ctx);											// [httpstream]
	duk_dup(ctx, 0);											// [httpstream][imsg]
	duk_swap_top(ctx, -2);										// [imsg][httpstream]
	duk_put_prop_string(ctx, -2, ILibDuktape_IMSG2HttpStream);	// [imsg]
	ILibDuktape_EventEmitter_AddOnceEx3(ctx, 0, "end", ILibDuktape_HttpStream_http_endResponseSink);
	duk_pop(ctx);
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_SocketDiedPrematurely(duk_context *ctx)
{
	duk_push_this(ctx);											// [socket]
	duk_get_prop_string(ctx, -1, ILibDuktape_Socket2CR);		// [socket][clientRequest]
	ILibDuktape_Transform *tf = (ILibDuktape_Transform*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_CR2Transform);
	if (tf->target->resumeImmediate != NULL)
	{
		duk_push_global_object(ctx);						// [g]
		duk_get_prop_string(ctx, -1, "clearImmediate");		// [g][clearImmediate]
		duk_swap_top(ctx, -2);								// [clearImmediate][this]
		duk_push_heapptr(ctx, tf->target->resumeImmediate);	// [clearImmediate][this][immedate]
		duk_call_method(ctx, 1); duk_pop(ctx);				// ...
		tf->target->resumeImmediate = NULL;
	}

	duk_get_prop_string(ctx, -1, "unpipe");						// [socket][clientRequest][unpipe]
	duk_dup(ctx, -2);											// [socket][clientRequest][unpipe][this]
	duk_call_method(ctx, 0); duk_pop(ctx);						// [socket][clientRequest]

	ILibDuktape_ReadableStream_DestroyPausedData(tf->target);


	// Need to specify some stuff, so the request body will go out again
	duk_get_prop_string(ctx, -1, ILibDuktape_CR_RequestBuffer);	// [socket][clientRequest][buffer]
	ILibDuktape_Http_ClientRequest_WriteData *wdata = (ILibDuktape_Http_ClientRequest_WriteData*)Duktape_GetBuffer(ctx, -1, NULL);
	++wdata->retryCounter;
	wdata->needRetry = 1;
	wdata->bufferWriteLen = wdata->bufferLen;
	wdata->headersFinished = 0;
	duk_pop(ctx);													// [socket][clientRequest]

	if (wdata->retryCounter < 3)
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_CR2Agent);			// [socket][clientRequest][agent]
		duk_get_prop_string(ctx, -1, "requests");					// [socket][clientReqeust][agent][requests]
		duk_get_prop_string(ctx, -4, ILibDuktape_Socket2AgentKey);	// [socket][clientRequest][agent][requests][key]
		duk_get_prop(ctx, -2);										// [socket][clientRequest][agent][requests][array]
		if (!duk_is_undefined(ctx, -1))
		{
			// We need to prepend the clientRequest into the request Queue
			duk_get_prop_string(ctx, -1, "unshift");				// [socket][clientRequest][agent][requests][array][unshift]
			duk_swap_top(ctx, -2);									// [socket][clientRequest][agent][requests][unshift][this]
			duk_dup(ctx, -5);										// [socket][clientRequest][agent][requests][unshift][this][clientRequest]
			duk_call_method(ctx, 1);
		}
	}
	else
	{
		ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, -1), "error");	// [emit][this][error]
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Too many failed attempts");		// [emit][this][error][err]
		duk_call_method(ctx, 2);
	}
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_SocketResponseReceived(duk_context *ctx)
{
	duk_push_this(ctx);												// [httpStream]
	duk_get_prop_string(ctx, -1, ILibDuktape_HTTPStream2Socket);	// [httpStream][socket]
	duk_get_prop_string(ctx, -1, ILibDuktape_Socket2CR);			// [httpStream][socket][CR]
	duk_get_prop_string(ctx, -1, ILibDuktape_CR2Options);			// [httpStream][socket][CR][Options]
	duk_del_prop_string(ctx, -1, ILibDuktape_Options2ClientRequest);

	duk_pop_2(ctx);													// [httpStream][socket]
	duk_del_prop_string(ctx, -1, ILibDuktape_Socket2CR);			

	duk_get_prop_string(ctx, -1, "removeListener");					// [httpStream][socket][removeListener]
	duk_swap_top(ctx, -2);											// [httpStream][removeListener][this]
	duk_push_string(ctx, "close");									// [httpStream][removeListener][this][close]
	duk_get_prop_string(ctx, -2, ILibDuktape_Socket2DiedListener);	// [httpStream][removeListener][this][close][listener]
	duk_call_method(ctx, 2);
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_OnSocketClosed(duk_context *ctx)
{
	duk_push_this(ctx);													// [socket]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_Socket2HttpStream))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_Socket2HttpStream);	// [socket][stream]
		duk_pop(ctx);													// [socket]
		duk_del_prop_string(ctx, -1, ILibDuktape_Socket2HttpStream);
	}
	duk_pop(ctx);														// ...
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_OnSocketReady(duk_context *ctx)
{
	void *httpStream;

	duk_dup(ctx, 0);													// [socket]
	duk_push_c_function(ctx, ILibDuktape_HttpStream_http_SocketDiedPrematurely, DUK_VARARGS);
	duk_put_prop_string(ctx, -2, ILibDuktape_Socket2DiedListener);		// [socket]

	duk_push_this(ctx);													// [socket][clientRequest]

	// Register ourselves for the close event, becuase we'll need to put ourselves back in the Queue if the socket dies before we are done
	duk_get_prop_string(ctx, -2, "prependOnceListener");				// [socket][clientRequest][prependOnce]
	duk_dup(ctx, -3);													// [socket][clientRequest][prependOnce][this]
	duk_push_string(ctx, "close");										// [socket][clientRequest][prependOnce][this][close]
	duk_get_prop_string(ctx, -5, ILibDuktape_Socket2DiedListener);		// [socket][clientRequest][prependOnce][this][close][listener]
	duk_call_method(ctx, 2); duk_pop(ctx);								// [socket][clientRequest]
	duk_put_prop_string(ctx, -2, ILibDuktape_Socket2CR);				// [socket]
	duk_push_this(ctx);													// [socket][clientRequest]
	
	if (duk_has_prop_string(ctx, -2, ILibDuktape_Socket2HttpStream))
	{
		// HTTP and/or TLS was already setup previously
		duk_get_prop_string(ctx, -2, ILibDuktape_Socket2HttpStream);	// [socket][clientRequest][HTTPStream]
		ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "write", ILibDuktape_HttpStream_http_SocketResponseReceived);

		duk_get_prop_string(ctx, -1, ILibDuktape_HTTPStream2Data);		// [socket][clientRequest][HTTPStream][data]
		ILibDuktape_HttpStream_Data *data = (ILibDuktape_HttpStream_Data*)Duktape_GetBuffer(ctx, -1, NULL);
		ILibWebClient_ResetWCDO(data->WCDO);
		if (data->bodyStream != NULL) { ILibDuktape_readableStream_WriteEnd(data->bodyStream); data->bodyStream = NULL; }
		duk_pop(ctx);													// [socket][clientRequest][HTTPStream]

		ILibDuktape_EventEmitter_DeleteForwardEvent(ctx, -1, "response");
		ILibDuktape_EventEmitter_DeleteForwardEvent(ctx, -1, "continue");

		// We need to change the events to propagate to the new clientRequest instead of the old one
		duk_get_prop_string(ctx, -1, "removeAllListeners");				// [socket][clientRequest][HTTPStream][remove]
		duk_dup(ctx, -2);												// [socket][clientRequest][HTTPStream][remove][this]
		duk_push_string(ctx, "response");								// [socket][clientRequest][HTTPStream][remove][this][response]
		duk_call_method(ctx, 1); duk_pop(ctx);							// [socket][clientRequest][HTTPStream]
		duk_get_prop_string(ctx, -1, "removeAllListeners");				// [socket][clientRequest][HTTPStream][remove]
		duk_dup(ctx, -2);												// [socket][clientRequest][HTTPStream][remove][this]
		duk_push_string(ctx, "continue");								// [socket][clientRequest][HTTPStream][remove][this][continue]
		duk_call_method(ctx, 1); duk_pop(ctx);							// [socket][clientRequest][HTTPStream]
		duk_get_prop_string(ctx, -1, "removeAllListeners");				// [socket][clientRequest][HTTPStream][remove]
		duk_dup(ctx, -2);												// [socket][clientRequest][HTTPStream][remove][this]
		duk_push_string(ctx, "upgrade");								// [socket][clientRequest][HTTPStream][remove][this][upgrade]
		duk_call_method(ctx, 1); duk_pop(ctx);							// [socket][clientRequest][HTTPStream]


		duk_push_this(ctx);												// [socket][clientRequest][HTTPStream][clientRequest]
		duk_put_prop_string(ctx, -2, ILibDuktape_HTTP2CR);				// [socket][clientRequest][HTTPStream]

		ILibDuktape_EventEmitter_ForwardEvent(ctx, -1, "response", -2, "response");
		ILibDuktape_EventEmitter_ForwardEvent(ctx, -1, "continue", -2, "continue");
		ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "upgrade", ILibDuktape_HttpStream_http_onUpgrade);
		ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "response", ILibDuktape_HttpStream_http_responseSink);


		duk_get_prop_string(ctx, -1, ILibDuktape_HTTP2PipedWritable);	// [socket][clientRequest][HTTPStream][destination]
		duk_get_prop_string(ctx, -3, ILibDuktape_CR2Options);			// [socket][clientRequest][HTTPStream][destination][Options]
		ILibDuktape_HttpStream_http_ConvertOptionToSend(ctx, duk_get_heapptr(ctx, -2), duk_get_heapptr(ctx, -1));

		// If HTTP stream was already setup, then we need to pipe the clientRequest to the upstream object, because it wasn't attached yet.
		duk_dup(ctx, -4);												// [socket][clientRequest][HTTPStream][destination][Options][clientRequest]
		duk_get_prop_string(ctx, -1, "pipe");							// [socket][clientRequest][HTTPStream][destination][Options][clientRequest][pipe]
		duk_swap_top(ctx, -2);											// [socket][clientRequest][HTTPStream][destination][Options][pipe][this]
		duk_dup(ctx, -4);												// [socket][clientRequest][HTTPStream][destination][Options][pipe][this][destination]
		duk_call_method(ctx, 1);	

		return(0);
	}

	if (duk_peval_string(ctx, "require('http').createStream();") != 0)	// [socket][clientRequest][error]
	{
		// Need to Abort this connection
		duk_get_prop_string(ctx, -2, "emit");							// [socket][clientRequest][error][emit]
		duk_dup(ctx, -3);												// [socket][clientRequest][error][emit][this]
		duk_push_string(ctx, "abort");									// [socket][clientRequest][error][emit][this][ebort]
		duk_push_string(ctx, duk_safe_to_string(ctx, -3));				// [socket][clientRequest][error][emit][this][abort][errorString]
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.onConnect(): "); }
		return(0);
	}

	httpStream = duk_get_heapptr(ctx, -1);								// [socket][clientRequest][httpStream]
	duk_dup(ctx, -3);													// [socket][clientRequest][httpStream][socket]
	duk_dup(ctx, -2);													// [socket][clientRequest][httpStream][socket][httpStream]
	duk_put_prop_string(ctx, -2, ILibDuktape_Socket2HttpStream);		// [socket][clientRequest][httpStream][socket]
	duk_pop(ctx);														// [socket][clientRequest][httpStream]
	duk_dup(ctx, -2);													// [socket][clientRequest][httpStream][clientRequest]
	duk_put_prop_string(ctx, -2, ILibDuktape_HTTP2CR);					// [socket][clientRequest][httpStream]
	ILibDuktape_EventEmitter_ForwardEvent(ctx, -1, "response", -2, "response");
	ILibDuktape_EventEmitter_ForwardEvent(ctx, -1, "continue", -2, "continue");
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "upgrade", ILibDuktape_HttpStream_http_onUpgrade);
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "response", ILibDuktape_HttpStream_http_responseSink);
	ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "write", ILibDuktape_HttpStream_http_SocketResponseReceived);
	ILibDuktape_EventEmitter_AddOnceEx3(ctx, -3, "close", ILibDuktape_HttpStream_http_OnSocketClosed); // We need to detach HttpStream when socket closes

	duk_put_prop_string(ctx, -2, ILibDuktape_CR2HTTPStream);			// [socket][clientRequest]
	duk_get_prop_string(ctx, -1, ILibDuktape_CR2Options);				// [socket][clientRequest][options]
	ILibDuktape_HttpStream_http_ConvertOptionToSend(ctx, duk_get_heapptr(ctx, -3), duk_get_heapptr(ctx, -1));
	duk_pop(ctx);														// [socket][clientRequest]
	
	// ClientRequest => Socket
	duk_get_prop_string(ctx, -1, "pipe");								// [socket][clientRequest][pipe]
	duk_swap_top(ctx, -2);												// [socket][pipe][this]
	duk_dup(ctx, -3);													// [socket][pipe][this][socket]
	duk_push_object(ctx);												// [socket][pipe][this][socket][options]
	duk_push_false(ctx); duk_put_prop_string(ctx, -2, "end");			
	if (duk_pcall_method(ctx, 2) != 0) { return(ILibDuktape_Error(ctx, "http.onConnect(): Error Piping with socket ")); }
	duk_pop(ctx);														// [socket]

	// Save this value, so we can unregister 'close' from socket later
	duk_push_heapptr(ctx, httpStream);									// [socket][httpStream]
	duk_dup(ctx, -2);													// [socket][httpStream][socket]
	duk_put_prop_string(ctx, -2, ILibDuktape_HTTPStream2Socket);		// [socket][httpStream]
	duk_pop(ctx);														// [socket]

	// Socket => HttpStream
	duk_get_prop_string(ctx, -1, "pipe");								// [socket][pipe]
	duk_dup(ctx, -2);													// [socket][pipe][this]
	duk_push_heapptr(ctx, httpStream);									// [socket][pipe][this][http]
	if (duk_pcall_method(ctx, 1) != 0) { return(ILibDuktape_Error(ctx, "http.onConnect(): Error calling pipe ")); }
	duk_pop(ctx);														// [socket]

	// HttpStream => Socket
	duk_push_heapptr(ctx, httpStream);									// [socket][http]
	duk_get_prop_string(ctx, -1, "pipe");								// [socket][http][pipe]
	duk_swap_top(ctx, -2);												// [socket][pipe][this]
	duk_dup(ctx, -3);													// [socket][pipe][this][socket]

	if (duk_pcall_method(ctx, 1) != 0) { return(ILibDuktape_Error(ctx, "http.onConnect(): Error calling pipe ")); }
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_OnConnectError(duk_context *ctx)
{
	duk_push_this(ctx);													// [socket]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_Socket2CR))
	{
		// Socket was created via 'createConnection' specified by the application
		duk_get_prop_string(ctx, -1, ILibDuktape_Socket2CR);			// [socket][CR]
		duk_get_prop_string(ctx, -1, "emit");							// [socket][CR][emit]
		duk_swap_top(ctx, -2);											// [socket][emit][this]
		duk_push_string(ctx, "error");									// [socket][emit][this][error]
		duk_dup(ctx, 0);												// [socket][emit][this][error][err]
		duk_call_method(ctx, 2);
	}
	else if (duk_has_prop_string(ctx, -1, ILibDuktape_Socket2Agent))
	{
		// Socket was created via 'http.Agent'
		if (duk_has_prop_string(ctx, -1, "\xFF_NET_SOCKET2OPTIONS"))
		{
			duk_get_prop_string(ctx, -1, ILibDuktape_Socket2Agent);			// [socket][agent]
			duk_get_prop_string(ctx, -1, "requests");						// [socket][agent][requests]
			duk_get_prop_string(ctx, -2, "getName");						// [socket][agent][requests][getName]
			duk_dup(ctx, -3);												// [socket][agent][requests][getName][this]
			duk_get_prop_string(ctx, -5, "\xFF_NET_SOCKET2OPTIONS");		// [socket][agent][requests][getName][this][options]
			duk_call_method(ctx, 1);										// [socket][agent][requests][name]
			duk_get_prop(ctx, -2);											// [socket][agent][requests][Array]
			duk_get_prop_string(ctx, -1, "pop");							// [socket][agent][requests][Array][pop]
			duk_swap_top(ctx, -2);											// [socket][agent][requests][pop][this]
			duk_call_method(ctx, 0);										// [socket][agent][requests][request]
			duk_get_prop_string(ctx, -1, "emit");							// [socket][agent][requests][request][emit]
			duk_swap_top(ctx, -2);											// [socket][agent][requests][emit][this]
			duk_push_string(ctx, "error");									// [socket][agent][requests][emit][this][error]
			duk_dup(ctx, 0);												// [socket][agent][requests][emit][this][error][err]
			duk_call_method(ctx, 2);
		}
	}
	return(0);
}

//duk_ret_t ILibDuktape_HttpStream_http_proxyData(duk_context *ctx)
//{
//	char *buffer;
//	duk_size_t bufferLen;
//
//	buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);
//	if (bufferLen > 13 && ILibString_IndexOf(buffer, bufferLen, "\r\n\r\n", 4) > 0)
//	{
//		if (strncasecmp(buffer + 9, "200", 3) == 0)
//		{
//			// SUCCESS!
//			duk_push_this(ctx);									// [socket]
//			duk_get_prop_string(ctx, -1, "removeAllListeners");	// [socket][remove]
//			duk_dup(ctx, -2);									// [socket][remove][this]
//			duk_push_string(ctx, "data");						// [socket][remove][this]['data']
//			duk_call_method(ctx, 1); duk_pop(ctx);				// [socket]
//
//			if (duk_has_prop_string(ctx, -1, ILibDuktape_Socket2CR))
//			{
//				// Socket was created with passed in createConnection
//				duk_get_prop_string(ctx, -1, ILibDuktape_Socket2CR);	// [socket][clientRequest]
//				duk_get_prop_string(ctx, -1, "emit");					// [socket][clientRequest][emit]
//				duk_swap_top(ctx, -2);									// [socket][emit][this]
//				duk_dup(ctx, -3);										// [socket][emit][this][socket]
//				if (duk_pcall_method(ctx, 1) != 0) { return(ILibDuktape_Error(ctx, "createConnection().proxyOnConnect(): ")); }
//			}
//			else
//			{
//				// Socket was created with Agent
//				if (!duk_has_prop_string(ctx, -1, ILibDuktape_Socket2Agent))
//				{
//					return(ILibDuktape_Error(ctx, "createConnection().proxyOnConnect(): Internal Error, 'Agent' was not specified"));
//				}
//				else
//				{
//					duk_get_prop_string(ctx, -1, ILibDuktape_Socket2Agent);	// [socket][agent]
//					duk_get_prop_string(ctx, -1, "keepSocketAlive");		// [socket][agent][keepSocketAlive]
//					duk_swap_top(ctx, -2);									// [socket][keepSocketAlive][this]
//					duk_dup(ctx, -3);										// [socket][keepSocketAlive][this][socket]
//					if (duk_pcall_method(ctx, 1) != 0) { return(ILibDuktape_Error(ctx, "createConnection().proxyOnConnect(): Error calling Agent.keepSocketAlive [%s]", duk_safe_to_string(ctx, -1))); }
//				}
//			}
//			return(0);
//		}
//		else
//		{
//			// FAIL!
//		}
//	}
//	else
//	{
//		// We don't have the entire response yet
//		duk_push_this(ctx);							// [socket]
//		duk_get_prop_string(ctx, -1, "unshift");	// [socket][unshift]
//		duk_swap_top(ctx, -2);						// [unshift][this]
//		duk_dup(ctx, 0);							// [unshift][this][chunk]
//		duk_call_method(ctx, 1);
//	}
//	return(0);
//}

duk_ret_t ILibDuktape_HttpStream_http_OnConnect(duk_context *ctx)
{
	duk_ret_t retVal = 0;
	duk_push_this(ctx);											// [socket]

	if (duk_has_prop_string(ctx, -1, ILibDuktape_Socket2CR))
	{
		// Socket was created with passed in createConnection
		duk_get_prop_string(ctx, -1, ILibDuktape_Socket2CR);	// [socket][clientRequest]
		duk_get_prop_string(ctx, -1, "emit");					// [socket][clientRequest][emit]
		duk_swap_top(ctx, -2);									// [socket][emit][this]
		duk_dup(ctx, -3);										// [socket][emit][this][socket]
		if (duk_pcall_method(ctx, 1) != 0) { retVal = ILibDuktape_Error(ctx, "createConnection().onConnect(): "); }
	}
	else
	{
		// Socket was created with Agent
		if (!duk_has_prop_string(ctx, -1, ILibDuktape_Socket2Agent))
		{
			retVal = ILibDuktape_Error(ctx, "createConnection().onConnect(): Internal Error, 'Agent' was not specified");
		}
		else
		{
			duk_get_prop_string(ctx, -1, ILibDuktape_Socket2Agent);	// [socket][agent]
			duk_get_prop_string(ctx, -1, "keepSocketAlive");		// [socket][agent][keepSocketAlive]
			duk_swap_top(ctx, -2);									// [socket][keepSocketAlive][this]
			duk_dup(ctx, -3);										// [socket][keepSocketAlive][this][socket]
			if (duk_pcall_method(ctx, 1) != 0) { retVal = ILibDuktape_Error(ctx, "createConnection().onConnect(): Error calling Agent.keepSocketAlive [%s]", duk_safe_to_string(ctx, -1)); }
		}
	}
	return(retVal);
}

void ILibDuktape_HttpStream_http_request_transformPiped(struct ILibDuktape_Transform *sender, void *user)
{
	char tmp[100];
	int tmpLen;

	ILibDuktape_Http_ClientRequest_WriteData *data = (ILibDuktape_Http_ClientRequest_WriteData*)user;
	if (data->noMoreWrites != 0)
	{
		// We have the entire request body
		data->headersFinished = 1;
		tmpLen = sprintf_s(tmp, sizeof(tmp), "Content-Length: %d\r\n\r\n", (int)data->bufferWriteLen);
		ILibDuktape_readableStream_WriteData(sender->target, tmp, tmpLen);
		if (data->bufferWriteLen > 0) { ILibDuktape_readableStream_WriteData(sender->target, data->buffer, (int)data->bufferWriteLen); }
	}
	else if(data->needRetry != 0)
	{
		if (data->headersFinished)
		{
			tmpLen = sprintf_s(tmp, sizeof(tmp), "%X\r\n", (unsigned int)data->bufferWriteLen);
		}
		else
		{
			data->headersFinished = 1;
			if (data->contentLengthSpecified)
			{
				tmpLen = sprintf_s(tmp, sizeof(tmp), "Content-Length: %d\r\n\r\n", (int)data->bufferWriteLen);
			}
			else
			{
				tmpLen = sprintf_s(tmp, sizeof(tmp), "Transfer-Encoding: chunked\r\n\r\n%X\r\n", (unsigned int)data->bufferWriteLen);
			}
		}

		ILibDuktape_readableStream_WriteData(sender->target, tmp, tmpLen);
		if (data->bufferWriteLen > 0)
		{
			ILibDuktape_readableStream_WriteData(sender->target, data->buffer, (int)data->bufferWriteLen);
			if (!data->contentLengthSpecified) { ILibDuktape_readableStream_WriteData(sender->target, "\r\n", 2); }

			free(data->buffer);
			data->buffer = NULL;
		}
		data->bufferLen = data->bufferWriteLen = 0;
		data->needRetry = 0;
	}
}
void ILibDuktape_HttpStream_http_request_transform(struct ILibDuktape_Transform *sender, int Reserved, int flush, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_Http_ClientRequest_WriteData *data = (ILibDuktape_Http_ClientRequest_WriteData*)user;

	char tmp[100];
	int tmpLen;

	if (data->headersFinished == 0)
	{
		// Need to write out the end of the headers
		data->headersFinished = 1;
		if (flush != 0)
		{
			tmpLen = sprintf_s(tmp, sizeof(tmp), "Content-Length: %d\r\n\r\n", bufferLen);
			ILibDuktape_readableStream_WriteData(sender->target, tmp, tmpLen);
			if (bufferLen > 0)
			{
				ILibDuktape_readableStream_WriteData(sender->target, buffer, bufferLen);
			}
			data->contentLengthSpecified = 1;
			if (bufferLen > 0)
			{
				data->buffer = (char*)ILibMemory_Allocate(bufferLen, 0, NULL, NULL);
				data->bufferLen = bufferLen;
				memcpy_s(data->buffer, bufferLen, buffer, bufferLen);
			}
		}
		else
		{
			tmpLen = sprintf_s(tmp, sizeof(tmp), "Transfer-Encoding: chunked\r\n\r\n%X\r\n", bufferLen);
			ILibDuktape_readableStream_WriteData(sender->target, tmp, tmpLen);
			if (bufferLen > 0)
			{
				ILibDuktape_readableStream_WriteData(sender->target, buffer, bufferLen);
			}
			ILibDuktape_readableStream_WriteData(sender->target, "\r\n", 2);
		}
	}
	else
	{
		tmpLen = sprintf_s(tmp, sizeof(tmp), "%X\r\n", bufferLen);
		ILibDuktape_readableStream_WriteData(sender->target, tmp, tmpLen);
		if (bufferLen > 0)
		{
			ILibDuktape_readableStream_WriteData(sender->target, buffer, bufferLen);
		}
		ILibDuktape_readableStream_WriteData(sender->target, "\r\n", 2);
	}

}
duk_ret_t ILibDuktape_ClientRequest_Finalizer(duk_context *ctx)
{
	if (duk_has_prop_string(ctx, 0, ILibDuktape_CR_RequestBuffer))
	{
		duk_get_prop_string(ctx, 0, ILibDuktape_CR_RequestBuffer);
		ILibDuktape_Http_ClientRequest_WriteData *data = (ILibDuktape_Http_ClientRequest_WriteData*)Duktape_GetBuffer(ctx, -1, NULL);
		if (data->buffer != NULL)
		{
			free(data->buffer);
			data->buffer = NULL;
		}
	}
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_request(duk_context *ctx)
{
	char *proto;
	duk_size_t protoLen;
	int isTLS = 0;
	int nargs = duk_get_top(ctx);

	duk_require_stack(ctx, DUK_API_ENTRY_STACK);											

	if (duk_is_string(ctx, 0))
	{
		// Call 'get' instead, since we already handle that case there...
		duk_push_this(ctx);						// [http]
		duk_get_prop_string(ctx, -1, "get");	// [http][get]
		duk_swap_top(ctx, -2);					// [get][this]
		duk_dup(ctx, 0);						// [get][this][uri]
		if (nargs > 1 && duk_is_function(ctx, 1))
		{
			duk_dup(ctx, 1);					// [get][this][uri][callback]
			duk_call_method(ctx, 2);			// [retVal]
		}
		else
		{
			duk_call_method(ctx, 1);			// [retVal]
		}
		return(1);
	}
	else
	{
		// Make sure 'host' field is present
		duk_dup(ctx, 0);								// [options]
		duk_get_prop_string(ctx, -1, "protocol");		// [options][protocol]
		proto = (char*)Duktape_GetBuffer(ctx, -1, &protoLen);
		if ((protoLen == 4 && strncasecmp(proto, "wss:", 4) == 0) || (protoLen == 3 && strncasecmp(proto, "ws:", 3) == 0))
		{
			duk_dup(ctx, 0);							// [options][protocol][options]
			duk_push_false(ctx);						// [options][protocol][options][false]
			duk_put_prop_string(ctx, -2, "agent");		// [options][protocol][options]
			duk_pop(ctx);								// [options][protocol]
		}
		if ((protoLen == 4 && strncasecmp(proto, "wss:", 4) == 0) || (protoLen == 6 && strncasecmp(proto, "https:", 6) == 0)) { isTLS = 1; }

		duk_pop(ctx);									// [options]
		if (!duk_has_prop_string(ctx, -1, "headers"))
		{
			duk_push_object(ctx);						// [options][headers]
			duk_get_prop_string(ctx, -2, "host");		// [options][headers][hostname]
			duk_get_prop_string(ctx, -1, "concat");		// [options][headers][hostname][concat]
			duk_swap_top(ctx, -2);						// [options][headers][concat][this]
			duk_push_string(ctx, ":");					// [options][headers][concat][this][:]
			duk_get_prop_string(ctx, -5, "port");		// [options][headers][concat][this][:][port]
			duk_call_method(ctx, 2);					// [options][headers][hostname]
			duk_put_prop_string(ctx, -2, "Host");		// [options][headers]
			duk_put_prop_string(ctx, -2, "headers");	// [options]
		}
		duk_get_prop_string(ctx, -1, "headers");		// [options][headers]
		if (duk_has_prop_string(ctx, -1, "Expect") && !duk_has_prop_string(ctx, -1, "Transfer-Encoding") && !duk_has_prop_string(ctx, -1, "Content-Length"))
		{
			return(ILibDuktape_Error(ctx, "http.request(): Cannot specify header 'Expect' without specifying 'Content-Length' or 'Transfer-Encoding'"));
		}
		duk_pop_2(ctx);									// ...
	}

	duk_dup(ctx, 0);												// [options]
	duk_push_object(ctx);											// [options][clientRequest]
	duk_dup(ctx, -1);												// [options][clientRequest][dup]
	duk_put_prop_string(ctx, -3, ILibDuktape_Options2ClientRequest);// [options][clientRequest]
	duk_remove(ctx, -2);											// [clientRequest]
	duk_push_this(ctx);												// [clientRequest][http]
	duk_put_prop_string(ctx, -2, ILibDuktape_CR2HTTP);				// [clientRequest]

	duk_push_false(ctx);
	duk_put_prop_string(ctx, -2, ILibDuktape_CR_EndCalled);								// [clientRequest]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_Http_ClientRequest_WriteData));		// [clientRequest][buffer]
	ILibDuktape_Http_ClientRequest_WriteData *wdata = (ILibDuktape_Http_ClientRequest_WriteData*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_CR_RequestBuffer);							// [clientRequest]
	memset(wdata, 0, sizeof(ILibDuktape_Http_ClientRequest_WriteData));

	duk_push_pointer(ctx, ILibDuktape_Transform_Init(ctx, ILibDuktape_HttpStream_http_request_transform, ILibDuktape_HttpStream_http_request_transformPiped, wdata));
	duk_put_prop_string(ctx, -2, ILibDuktape_CR2Transform);								// [clientRequest]

	ILibDuktape_WriteID(ctx, isTLS ? "https.clientRequest" : "http.clientRequest");
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "abort");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "connect");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "continue");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "response");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "socket");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "timeout");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "upgrade");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "error");
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "socket", ILibDuktape_HttpStream_http_OnSocketReady);
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "~", ILibDuktape_ClientRequest_Finalizer);


	if (nargs > 1 && duk_is_function(ctx, 1))
	{
		duk_get_prop_string(ctx, -1, "once");						// [clientRequest][once]
		duk_dup(ctx, -2);											// [clientRequest][once][this]
		duk_push_string(ctx, "response");							// [clientRequest][once][this][response]
		duk_dup(ctx, 1);											// [clientRequest][once][this][response][handler]
		duk_call_method(ctx, 2); duk_pop(ctx);						// [clientRequest]
	}

	duk_dup(ctx, 0);											// [clientRequest][options]
	duk_put_prop_string(ctx, -2, ILibDuktape_CR2Options);		// [clientReqeust]

	void *createConnection = NULL;
	void *agent = NULL;

	if (duk_has_prop_string(ctx, 0, "createConnection"))
	{
		createConnection = Duktape_GetHeapptrProperty(ctx, 0, "createConnection");
	}
	else
	{
		if (duk_has_prop_string(ctx, 0, "agent"))
		{
			duk_get_prop_string(ctx, 0, "agent");						// [clientRequest][Agent]
			if (duk_is_boolean(ctx, -1))
			{
				if (duk_get_boolean(ctx, -1) == 0)
				{
					duk_pop(ctx);										// [clientRequest]
					duk_eval_string(ctx, "require('http').Agent();");	// [clientRequest][tempAgent]
					agent = duk_get_heapptr(ctx, -1);
					duk_put_prop_string(ctx, -2, ILibDuktape_CR2Agent);	// [clientRequest]
				}
				else
				{
					duk_pop(ctx);										// [clientRequest]
					duk_push_this(ctx);									// [clientRequest][http]
					duk_get_prop_string(ctx, -1, "globalAgent");		// [clientRequest][http][agent]
					agent = duk_get_heapptr(ctx, -1);
					duk_remove(ctx, -2);								// [clientRequest][agent]
					duk_put_prop_string(ctx, -2, ILibDuktape_CR2Agent);	// [clientRequest]
				}
			}
			else if (duk_is_object(ctx, -1))
			{
				agent = duk_get_heapptr(ctx, -1);						// [clientRequest][agent]
				duk_put_prop_string(ctx, -2, ILibDuktape_CR2Agent);		// [clientRequest]
			}
			else
			{
				return(ILibDuktape_Error(ctx, "http.request(): Invalid Option Parameter 'Agent'"));
			}
		}
		else
		{
			duk_push_this(ctx);											// [clientRequest][http]
			duk_get_prop_string(ctx, -1, "globalAgent");				// [clientRequest][http][agent]
			agent = duk_get_heapptr(ctx, -1);
			duk_remove(ctx, -2);										// [clientRequest][agent]
			duk_put_prop_string(ctx, -2, ILibDuktape_CR2Agent);			// [clientRequest]
		}
	}

	//
	// Check Proxy
	//
	ILibDuktape_globalTunnel_data *globalTunnel = ILibDuktape_GetGlobalTunnel(ctx);
	if (duk_has_prop_string(ctx, 0, "proxy"))
	{
		duk_get_prop_string(ctx, 0, "proxy");							// [clientRequest][proxy]
		if (duk_is_string(ctx, -1)) { if (strcmp((char*)duk_get_string(ctx, -1), "none") == 0) { globalTunnel = NULL; duk_del_prop_string(ctx, -2, "proxy"); } }
		duk_pop(ctx);													// [clientRequest]
	}
	if (globalTunnel != NULL && !duk_has_prop_string(ctx, 0, "proxy"))
	{
		duk_dup(ctx, 0);																							// [options]
		duk_push_object(ctx);																						// [options][proxy]

		duk_push_string(ctx, ILibRemoteLogging_ConvertAddress((struct sockaddr*)&(globalTunnel->proxyServer)));
		duk_put_prop_string(ctx, -2, "host");
		duk_push_int(ctx, (int)ntohs(globalTunnel->proxyServer.sin6_port));
		duk_put_prop_string(ctx, -2, "port");																		// [options][proxy]
		duk_put_prop_string(ctx, -2, "proxy");																		// [options]
		duk_pop(ctx);																								// ...
	}

	if (createConnection != NULL)										// [clientRequest]
	{
		duk_push_heapptr(ctx, createConnection);						// [clientRequest][createConnection]
		duk_dup(ctx, 0);												// [clientRequest][createConnection][options]
		duk_call(ctx, 1);												// [clientRequest][socket]
		duk_dup(ctx, -1);												// [clientRequest][socket][clientRequest]
		duk_put_prop_string(ctx, -2, ILibDuktape_Socket2CR);			// [clientRequest][socket]
		ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "connect", ILibDuktape_HttpStream_http_OnConnect);
		ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "error", ILibDuktape_HttpStream_http_OnConnectError);
		ILibDuktape_CreateReadonlyProperty(ctx, "socket");				// [clientRequest]
	}
	else if (agent != NULL)												// [clientRequest]
	{
		duk_push_heapptr(ctx, agent);									// [clientRequest][agent]
		duk_get_prop_string(ctx, -1, "getName");						// [clientRequest][agent][getName]
		duk_dup(ctx, -2);												// [clientRequest][agent][getName][this]
		duk_dup(ctx, 0);												// [clientRequest][agent][getName][this][options]
		duk_call_method(ctx, 1);										// [clientRequest][agent][key]
		duk_get_prop_string(ctx, -2, "freeSockets");					// [clientRequest][agent][key][freeSockets]
		duk_dup(ctx, -2);												// [clientRequest][agent][key][freeSockets][key]
		duk_get_prop(ctx, -2);											// [clientRequest][agent][key][freeSockets][Array]
		if (!duk_is_undefined(ctx, -1))
		{
			duk_get_prop_string(ctx, -1, "shift");						// [clientRequest][agent][key][freeSockets][Array][shift]
			duk_swap_top(ctx, -2);										// [clientRequest][agent][key][freeSockets][shift][this]
			duk_call_method(ctx, 0);									// [clientRequest][agent][key][freeSockets][socket]
			if (!duk_is_undefined(ctx, -1))
			{
				duk_remove(ctx, -2);									// [clientRequest][agent][key][socket]
				duk_get_prop_string(ctx, -3, "reuseSocket");			// [clientRequest][agent][key][socket][reuseSocket]
				duk_dup(ctx, -4);										// [clientRequest][agent][key][socket][reuseSocket][this]
				duk_dup(ctx, -3);										// [clientRequest][agent][key][socket][reuseSocket][this][socket]
				duk_dup(ctx, -7);										// [clientRequest][agent][key][socket][reuseSocket][this][socket][request]
				duk_call_method(ctx, 2);								// [clientRequest][agent][key][socket][undefined]
				duk_pop_n(ctx, 4);										// [clientRequest]
				agent = NULL;
			}
			else
			{
				duk_pop_2(ctx);											// [clientRequest][agent][key]
			}
		}
		else
		{
			duk_pop_2(ctx);												// [clientRequest][agent][key]
		}

		if (agent != NULL)												// [clientRequest][agent][key]
		{
			// If we are here, it means there was not a freeSocket

			// Let's start by adding ourselves to the Pending Requests Queue
			duk_get_prop_string(ctx, -2, "requests");				// [clientRequest][agent][key][requests]
			duk_dup(ctx, -2);										// [clientRequest][agent][key][requests][key]
			if (!duk_has_prop(ctx, -2))								// [clientRequest][agent][key][requests]
			{
				// No waiting requests, so attach a new queue
				duk_dup(ctx, -2);									// [clientRequest][agent][key][requests][key]
				duk_push_array(ctx);								// [clientRequest][agent][key][requests][key][value]
				duk_get_prop_string(ctx, -1, "push");				// [clientRequest][agent][key][requests][key][value][push]
				duk_dup(ctx, -2);									// [clientRequest][agent][key][requests][key][value][push][this]
				duk_dup(ctx, -8);									// [clientRequest][agent][key][requests][key][value][push][this][clieentRequest]
				duk_call_method(ctx, 1);							// [clientRequest][agent][key][requests][key][value][retVal]
				duk_pop(ctx);										// [clientRequest][agent][key][requests][key][value]
				duk_put_prop(ctx, -3);								// [clientRequest][agent][key][requests]
				duk_pop(ctx);										// [clientRequest][agent][key]
			}
			else
			{
				// There is already a queue here
				duk_dup(ctx, -2);									// [clientRequest][agent][key][requests][key]
				duk_get_prop(ctx, -2);								// [clientRequest][agent][key][requests][array]
				duk_get_prop_string(ctx, -1, "push");				// [clientRequest][agent][key][requests][array][push]
				duk_swap_top(ctx, -2);								// [clientRequest][agent][key][requests][push][this]
				duk_dup(ctx, -6);									// [clientRequest][agent][key][requests][push][this][clientRequest]
				duk_call_method(ctx, 1);							// [clientRequest][agent][key][requests][retVal]
				duk_pop_2(ctx);										// [clientRequest][agent][key]
			}

			// Let's check to see if there is already a socket in use talking to our same host
			duk_get_prop_string(ctx, -2, "sockets");				// [clientRequest][agent][key][sockets]
			duk_dup(ctx, -2);										// [clientRequest][agent][key][sockets][key]
			duk_get_prop(ctx, -2);									// [clientRequest][agent][key][sockets][Array]
			if (duk_is_undefined(ctx, -1) || duk_get_length(ctx, -1) < (duk_size_t)Duktape_GetIntPropertyValue(ctx, -4, "maxSockets", 0))
			{
				// We can create a new socket
				duk_pop_3(ctx);											// [clientRequest][agent]
				duk_dup(ctx, -1);										// [clientRequest][agent][agent]
				duk_get_prop_string(ctx, -1, "createConnection");		// [clientRequest][agent][agent][createConnection]
				duk_swap_top(ctx, -2);									// [clientRequest][agent][createConnection][this]
				duk_dup(ctx, 0);										// [clientRequest][agent][createConnection][this][options]
				if (duk_has_prop_string(ctx, -1, "checkClientIdentity"))
				{
					duk_push_c_function(ctx, ILibDuktape_HttpStream_http_checkIdentity, DUK_VARARGS);	// [clientRequest][agent][createConnection][this][options][checkIdentity]
					duk_get_prop_string(ctx, -2, "checkClientIdentity");								// [clientRequest][agent][createConnection][this][options][checkIdentity][checkClient]
					duk_put_prop_string(ctx, -2, ILibDuktape_FUNC);										// [clientRequest][agent][createConnection][this][options][checkIdentity]
					duk_dup(ctx, -6);																	// [clientRequest][agent][createConnection][this][options][checkIdentity][ClientRequest]
					duk_put_prop_string(ctx, -2, ILibDuktape_ClientRequest);							// [clientRequest][agent][createConnection][this][options][checkIdentity]
					duk_put_prop_string(ctx, -2, "checkClientIdentity");								// [clientRequest][agent][createConnection][this][options]
				}

				duk_push_c_function(ctx, ILibDuktape_HttpStream_http_OnConnect, DUK_VARARGS);
				duk_call_method(ctx, 2);								// [clientRequest][agent][socket]
				duk_swap_top(ctx, -2);									// [clientRequest][socket][agent]
				duk_put_prop_string(ctx, -2, ILibDuktape_Socket2Agent);	// [clientRequest][socket]
				ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "error", ILibDuktape_HttpStream_http_OnConnectError);
				duk_pop(ctx);											// [clientRequest]
			}
			else
			{
				duk_pop_n(ctx, 4);										// [clientRequest]
			}
		}
	}

	return(1);
}

duk_ret_t ILibDuktape_HttpStream_http_server_close(duk_context *ctx)
{
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_server_upgradeWebsocket(duk_context *ctx)
{
	char wsguid[] = WEBSOCKET_GUID;
	char *key, *keyResult;
	int keyResultLen;
	duk_size_t keyLen;
	SHA_CTX c;
	char shavalue[21];

	duk_push_this(ctx);									// [socket]
	duk_push_current_function(ctx);						// [socket][func]
	duk_get_prop_string(ctx, -2, "unpipe");				// [socket][func][unpipe]
	duk_dup(ctx, -3);									// [socket][func][unpipe][this]
	duk_call_method(ctx, 0); duk_pop(ctx);				// [socket][func]

	duk_get_prop_string(ctx, -1, "imsg");				// [socket][func][imsg]
	duk_get_prop_string(ctx, -1, "headers");			// [socket][func][imsg][headers]
	duk_get_prop_string(ctx, -1, "Sec-WebSocket-Key");	// [socket][func][imsg][headers][key]

	key = (char*)Duktape_GetBuffer(ctx, -1, &keyLen);
	keyResult = ILibString_Cat(key, (int)keyLen, wsguid, sizeof(wsguid));

	SHA1_Init(&c);
	SHA1_Update(&c, keyResult, strnlen_s(keyResult, sizeof(wsguid) + keyLen));
	SHA1_Final((unsigned char*)shavalue, &c);
	shavalue[20] = 0;
	free(keyResult);
	keyResult = NULL;

	keyResultLen = ILibBase64Encode((unsigned char*)shavalue, 20, (unsigned char**)&keyResult);

	duk_push_this(ctx);									// [socket]
	duk_get_prop_string(ctx, -1, "write");				// [socket][write]
	duk_dup(ctx, -2);									// [socket][write][this]
	duk_push_string(ctx, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
	duk_call_method(ctx, 1); duk_pop(ctx);				// ...

	duk_push_this(ctx);									// [socket]
	duk_get_prop_string(ctx, -1, "write");				// [socket][write]
	duk_dup(ctx, -2);									// [socket][write][this]
	duk_push_lstring(ctx, keyResult, keyResultLen);
	duk_call_method(ctx, 1); duk_pop(ctx);				// ...

	duk_push_this(ctx);									// [socket]
	duk_get_prop_string(ctx, -1, "write");				// [socket][write]
	duk_dup(ctx, -2);									// [socket][write][this]
	duk_push_string(ctx, "\r\n\r\n");
	duk_call_method(ctx, 1); duk_pop(ctx);				// ...

	duk_eval_string(ctx, "require('http');");			// [http]
	duk_get_prop_string(ctx, -1, "webSocketStream");	// [http][constructor]
	duk_push_lstring(ctx, keyResult, keyResultLen);		// [http][constructor][key]
	duk_new(ctx, 1);									// [http][wss]

	duk_push_this(ctx);									// [http][wss][socket]
	duk_get_prop_string(ctx, -1, "pipe");				// [http][wss][socket][pipe]
	duk_swap_top(ctx, -2);								// [http][wss][pipe][this]
	duk_get_prop_string(ctx, -3, "encoded");			// [http][wss][pipe][this][WS_ENC]
	duk_call_method(ctx, 1); duk_pop(ctx);				// [http][wss]

	duk_get_prop_string(ctx, -1, "encoded");			// [http][wss][WS_ENC]
	duk_get_prop_string(ctx, -1, "pipe");				// [http][wss][WS_ENC][pipe]
	duk_swap_top(ctx, -2);								// [http][wss][pipe][this]
	duk_push_this(ctx);									// [http][wss][pipe][this][socket]
	duk_call_method(ctx, 1); duk_pop(ctx);				// [http][wss]

	duk_get_prop_string(ctx, -1, "decoded");			// [http][wss][WS_DEC]
	
	free(keyResult);
	return(1);
}
duk_ret_t ILibDuktape_HttpStream_http_server_onUpgrade_digestWriteUnauth(duk_context *ctx)
{
	int nargs = duk_get_top(ctx), i;
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "imsg");
	duk_get_prop_string(ctx, -1, ILibDuktape_IMSG2SR);			// [serverResponse]
	duk_get_prop_string(ctx, -1, "Digest_writeUnauthorized");	// [serverResponse][writeUnAuth]
	duk_swap_top(ctx, -2);										// [writeUnAuth][this]
	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);										// [writeUnAuth][this][...]
	}
	duk_call_method(ctx, nargs);
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_server_onUpgrade(duk_context *ctx)
{
	duk_push_this(ctx);																			// [HS]
	duk_get_prop_string(ctx, -1, ILibduktape_HttpStream2HttpServer);							// [HS][server]
	duk_get_prop_string(ctx, -1, "emit");														// [HS][server][emit]
	duk_swap_top(ctx, -2);																		// [HS][emit][this]
	duk_push_string(ctx, "upgrade");															// [HS][emit][this][upgrade]
	duk_dup(ctx, 0);																			// [HS][emit][this][upgrade][imsg]
	duk_get_prop_string(ctx, -5, ILibDuktape_HTTP2PipedReadable);								// [HS][emit][this][upgrade][imsg][sck]
	duk_push_c_function(ctx, ILibDuktape_HttpStream_http_server_upgradeWebsocket, DUK_VARARGS);	// [HS][emit][this][upgrade][imsg][sck][func]
	duk_dup(ctx, -3);																			// [HS][emit][this][upgrade][imsg][sck][func][imsg]
	duk_put_prop_string(ctx, -2, "imsg");														// [HS][emit][this][upgrade][imsg][sck][func]
	duk_put_prop_string(ctx, -2, "upgradeWebSocket");											// [HS][emit][this][upgrade][imsg][sck]
	duk_push_c_function(ctx, ILibDuktape_HttpStream_http_server_onUpgrade_digestWriteUnauth, DUK_VARARGS);
	duk_dup(ctx, -3);																			// [HS][emit][this][upgrade][imsg][sck][func][imsg]
	duk_put_prop_string(ctx, -2, "imsg");														// [HS][emit][this][upgrade][imsg][sck][func]
	duk_put_prop_string(ctx, -2, "Digest_writeUnauthorized");									// [HS][emit][this][upgrade][imsg][sck]
	duk_push_null(ctx);																			// [HS][emit][this][upgrade][imsg][sck][head]
	duk_get_prop_string(ctx, -3, "headers");
	duk_pop(ctx);
	duk_call_method(ctx, 4); duk_pop(ctx);														// [HS]
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_server_onConnection_TLSConnect(duk_context *ctx)
{
	//duk_get_prop_string(ctx, -1, ILibDuktape_NS2HttpServer);			// [NS][HS]
	//duk_get_prop_string(ctx, -1, "emit");								// [NS][HS][emit]
	//duk_swap_top(ctx, -2);												// [NS][emit][this]
	//duk_push_string(ctx, "connection");									// [NS][emit][this][connection]
	//duk_dup(ctx, 0);													// [NS][emit][this][connection][socket]
	//if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.server.onConnection() => Error dispatching connection event "); }

	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_server_onConnectionTimeout(duk_context *ctx)
{
	void *cb = NULL;
	duk_push_this(ctx);																			// [socket]
	duk_get_prop_string(ctx, -1, ILibDuktape_Socket2HttpServer);								// [socket][HttpServer]
	if ((cb = Duktape_GetHeapptrProperty(ctx, -1, ILibDuktape_HttpServer_TimeoutCB)) != NULL)
	{
		// Callback was specified, so the callback MUST explictly handle the situation
		duk_push_heapptr(ctx, cb);																// [socket][HttpServer][func]
		duk_swap_top(ctx, -2);																	// [socket][func][this]
		duk_dup(ctx, -3);																		// [socket][func][this][socket]
		duk_call_method(ctx, 1); duk_pop_2(ctx);												// ...
	}
	else
	{
		// No callback was specified, so the timed out socket MUST be closed.
		duk_pop(ctx);																			// [socket]
		duk_get_prop_string(ctx, -1, "end");													// [socket][end]
		duk_swap_top(ctx, -2);																	// [end][this]
		duk_call_method(ctx, 0); duk_pop(ctx);													// ...
	}
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_server_onConnection(duk_context *ctx)
{
	duk_push_this(ctx);													// [NS]
	duk_get_prop_string(ctx, -1, ILibDuktape_NS2HttpServer);			// [NS][HttpServer]

	// Check to see if we need to set a timeout
	duk_get_prop_string(ctx, -1, "timeout");							// [NS][HttpServer][timeout]
	if (duk_is_number(ctx, -1))
	{
		duk_dup(ctx, 0);												// [NS][HttpServer][timeout][socket]
		duk_dup(ctx, -3);												// [NS][HttpServer][timeout][socket][HttpServer]
		duk_put_prop_string(ctx, -2, ILibDuktape_Socket2HttpServer);	// [NS][HttpServer][timeout][socket]
		duk_get_prop_string(ctx, -1, "setTimeout");						// [NS][HttpServer][timeout][socket][setTimeout]
		duk_swap_top(ctx, -2);											// [NS][HttpServer][timeout][setTimeout][this]
		duk_get_int(ctx, -3);											// [NS][HttpServer][timeout][setTimeout][this][value]
		duk_push_c_function(ctx, ILibDuktape_HttpStream_http_server_onConnectionTimeout, DUK_VARARGS);	   // [setTimeout][this][value][callback]
		duk_call_method(ctx, 2); duk_pop(ctx);							// [NS][HttpServer][timeout]
	}
	duk_pop_2(ctx);														// [NS]

	// Pipe: Socket => HttpStream
	duk_dup(ctx, 0);													// [NS][socket]
	duk_get_prop_string(ctx, -1, "pipe");								// [NS][socket][pipe]
	duk_dup(ctx, -2);													// [NS][socket][pipe][this]

	duk_eval_string(ctx, "require('http').createStream();");			// [NS][socket][pipe][this][httpStream]	
	duk_get_prop_string(ctx, -5, ILibDuktape_NS2HttpServer);			// [NS][socket][pipe][this][httpStream][httpServer]
	duk_dup(ctx, -1);													// [NS][socket][pipe][this][httpStream][httpServer][dup]
	duk_put_prop_string(ctx, -3, ILibduktape_HttpStream2HttpServer);	// [NS][socket][pipe][this][httpStream][httpServer]
	ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "checkContinue", -1, "checkContinue");
	ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "checkExpectation", -1, "checkExpectation");
	ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "clientError", -1, "clientError");
	//ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "close", -1, "close");
	ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "connect", -1, "connect");
	ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "request", -1, "request");
	if (ILibDuktape_EventEmitter_HasListenersEx(ctx, -1, "upgrade") > 0) { ILibDuktape_EventEmitter_AddOnceEx3(ctx, -2, "upgrade", ILibDuktape_HttpStream_http_server_onUpgrade); }
	
	duk_pop(ctx);														// [NS][socket][pipe][this][httpStream]
	duk_call_method(ctx, 1); duk_pop_2(ctx);							// [NS]

	duk_get_prop_string(ctx, -1, ILibDuktape_NS2HttpServer);			// [NS][HS]
	duk_get_prop_string(ctx, -1, "emit");								// [NS][HS][emit]
	duk_swap_top(ctx, -2);												// [NS][emit][this]
	duk_push_string(ctx, "connection");									// [NS][emit][this][connection]
	duk_dup(ctx, 0);													// [NS][emit][this][connection][socket]
	if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "server.onConnection() => Error dispatching connection event "); }

	return(0);
}
duk_ret_t ILibDuktape_HttpStream_http_server_listen(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	
	duk_push_this(ctx);													// [server]
	duk_get_prop_string(ctx, -1, ILibDuktape_Http_Server2NetServer);	// [server][ns]

	duk_get_prop_string(ctx, -1, "listen");								// [server][ns][listen]
	duk_dup(ctx, -2);													// [server][ns][listen][this]
	if (nargs == 0)
	{
		// Nothing was specified, convert to Options
		duk_push_object(ctx);											// [server][ns][listen][this][options]
		duk_push_int(ctx, 0); duk_put_prop_string(ctx, -2, "port");							
	}
	else
	{
		if (duk_is_object(ctx, 0))
		{
			duk_dup(ctx, 0);											// [server][ns][listen][this][options]
		}
		else
		{
			// Options weren't used, so lets convert it to Options
			duk_push_object(ctx);										// [server][ns][listen][this][options]
			if (duk_is_number(ctx, 0))
			{
				duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, "port");	
			}
			else
			{
				return(ILibDuktape_Error(ctx, "server.listen(): Unknown parameter "));
			}
		}
	}

	duk_call_method(ctx, 1); duk_pop(ctx);							// [server]
	return(1);
}
duk_ret_t ILibDuktape_HttpStream_http_setTimeout(duk_context *ctx)
{
	int nargs = duk_get_top(ctx), i;
	int timeout = 120000;
	void *callback = NULL;

	for (i = 0; i < nargs; ++i)
	{
		if (duk_is_number(ctx, i)) { timeout = duk_require_int(ctx, i); }
		if (duk_is_function(ctx, i)) { callback = duk_require_heapptr(ctx, i); }
	}

	duk_push_this(ctx);													// [server]
	duk_push_int(ctx, timeout);											// [server][timeout]
	duk_put_prop_string(ctx, -2, "timeout");							// [server]
	if (callback != NULL)
	{
		duk_push_heapptr(ctx, callback);								// [server][cb]
		duk_put_prop_string(ctx, -2, ILibDuktape_HttpServer_TimeoutCB);	// [server]
	}
	return(1);
}
duk_ret_t ILibDuktape_HttpStream_http_server_address(duk_context *ctx)
{
	duk_push_this(ctx);													// [httpServer]
	if (!duk_has_prop_string(ctx, -1, ILibDuktape_Http_Server2NetServer)) { return(ILibDuktape_Error(ctx, "http.server.address(): Cannot call 'address' when listen was not called")); }

	duk_get_prop_string(ctx, -1, ILibDuktape_Http_Server2NetServer);	// [httpServer][NS]
	duk_get_prop_string(ctx, -1, "address");							// [httpServer][NS][address]
	duk_swap_top(ctx, -2);												// [httpServer][address][this]
	duk_call_method(ctx, 0);											// [httpServer][result]
	return(1);
}

duk_ret_t ILibDuktape_HttpStream_http_createServer(duk_context *ctx)
{
	ILibDuktape_Http_Server *server;

	int nargs = duk_get_top(ctx);
	duk_push_this(ctx);															// [http/s]
	int isHTTPS = Duktape_GetBooleanProperty(ctx, -1, "isHTTPS", 0);
	duk_pop(ctx);

	duk_push_object(ctx);														// [server]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_Http_Server));				// [server][fxBuffer]
	server = (ILibDuktape_Http_Server*)Duktape_GetBuffer(ctx, -1, NULL);	
	duk_put_prop_string(ctx, -2, ILibDuktape_Http_Server_FixedBuffer);			// [server]

	memset(server, 0, sizeof(ILibDuktape_Http_Server));
	server->ctx = ctx;

	ILibDuktape_WriteID(ctx, isHTTPS ? "https.server" : "http.server");
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_EventEmitter_CreateEventEx(emitter, "checkContinue");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "checkExpectation");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "clientError");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "close");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "connect");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "connection");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "request");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "upgrade");
	
	duk_push_undefined(ctx);
	duk_put_prop_string(ctx, -2, "timeout");

	if (nargs > 0 && duk_is_function(ctx, 0))
	{
		ILibDuktape_EventEmitter_AddOn(emitter, "request", duk_require_heapptr(ctx, 0));
	}

	ILibDuktape_CreateInstanceMethod(ctx, "close", ILibDuktape_HttpStream_http_server_close, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "listen", ILibDuktape_HttpStream_http_server_listen, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "setTimeout", ILibDuktape_HttpStream_http_setTimeout, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "address", ILibDuktape_HttpStream_http_server_address, 0);


	// Now let's create a net.server or tls.server
	if (isHTTPS)
	{
		duk_eval_string(ctx, "require('tls');");						// [server][tls]
	}
	else
	{
		duk_eval_string(ctx, "require('net');");						// [server][net]
	}
	duk_get_prop_string(ctx, -1, "createServer");						// [server][nettls][createServer]
	duk_swap_top(ctx, -2);												// [server][createServer][this]

	if (nargs > 0 && duk_is_object(ctx, 0) && !duk_is_function(ctx, 0))
	{
		// Options was specified
		duk_dup(ctx, 0);												// [server][createServer][this][options]
	}
	duk_push_c_function(ctx, ILibDuktape_HttpStream_http_server_onConnection, DUK_VARARGS);

	duk_call_method(ctx, (nargs > 0 && duk_is_object(ctx, 0) && !duk_is_function(ctx, 0)) ? 2 : 1);	// [server][netServer]
	duk_dup(ctx, -2);													// [server][netServer][server]
	duk_put_prop_string(ctx, -2, ILibDuktape_NS2HttpServer);			// [server][netServer]
	duk_put_prop_string(ctx, -2, ILibDuktape_Http_Server2NetServer);	// [server]
	return(1);
}

typedef struct ILibDuktape_HttpStream_DispatchWrite_data
{
	ILibDuktape_HttpStream_Data *httpStream;
	int bufferLen;
	char buffer[];
}ILibDuktape_HttpStream_DispatchWrite_data;

duk_ret_t ILibDuktape_HttpStream_WriteSink_ChainSink_DynamicBuffer_WriteSink(duk_context *ctx)
{
	char *buffer;
	duk_size_t bufferLen;
	int beginPointer = 0;
	int PAUSE = 0;

	ILibDuktape_HttpStream_Data *data;
	duk_push_this(ctx);												// [DynamicBuffer]
	duk_get_prop_string(ctx, -1, "\xFF_HTTP");
	data = (ILibDuktape_HttpStream_Data*)duk_get_pointer(ctx, -1);

	buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);
	ILibWebClient_OnData(NULL, buffer, &beginPointer, (int)bufferLen, NULL, (void**)&(data->WCDO), &PAUSE);

	return(0);
}
duk_ret_t ILibDuktape_HttpStream_WriteSink_ChainSink_DynamicBuffer_EndSink(duk_context *ctx)
{
	return(0);
}
void ILibDuktape_HttpStream_WriteSink_ChainSink(void *chain, void *user)
{
	ILibDuktape_HttpStream_DispatchWrite_data *data = (ILibDuktape_HttpStream_DispatchWrite_data*)user;
	duk_context *ctx = data->httpStream->DS->writableStream->ctx;

	if (data->httpStream->DynamicBuffer == NULL)
	{
		duk_push_heapptr(ctx, data->httpStream->DS->ParentObject);												// [httpStream]
		if (duk_peval_string(ctx, "require('DynamicBuffer')(4096);") != 0)										// [httpStream][DynamicBuffer]
		{
			ILibDuktape_Process_UncaughtExceptionEx(ctx, "httpStream.writeSink_chainSink->DynamicBuffer(): ");
			duk_pop(ctx);																						// ...
			return;
		}
		data->httpStream->DynamicBuffer = duk_get_heapptr(ctx, -1);												// [httpStream][DynamicBuffer]
		ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "data", ILibDuktape_HttpStream_WriteSink_ChainSink_DynamicBuffer_WriteSink);
		ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "end", ILibDuktape_HttpStream_WriteSink_ChainSink_DynamicBuffer_EndSink);
		duk_push_pointer(ctx, data->httpStream);																// [httpStream][DynamicBuffer][ptr]
		duk_put_prop_string(ctx, -2, "\xFF_HTTP");																// [httpStream][DynamicBuffer]
		duk_put_prop_string(ctx, -2, "\xFF_DynamicBuffer");														// [httpStream]
		duk_pop(ctx);																							// ...
	}

	duk_push_external_buffer(ctx);																				// [extBuffer]
	duk_config_buffer(ctx, -1, data->buffer, data->bufferLen);

	duk_push_heapptr(ctx, data->httpStream->DynamicBuffer);														// [extBuffer][DynamicBuffer]
	duk_get_prop_string(ctx, -1, "write");																		// [extBuffer][DynamicBuffer][write]
	duk_swap_top(ctx, -2);																						// [extBuffer][write][this]
	duk_push_buffer_object(ctx, -3, 0, data->bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);								// [extBuffer][write][this][buffer]
	if (duk_pcall_method(ctx, 1) != 0)																			// [extBuffer][retVal]
	{
		ILibDuktape_Process_UncaughtExceptionEx(ctx, "httpStream.WriteSink_ChainSink->DynamicBuffer.Write(): ");
		duk_pop(ctx);																							// [extBuffer]
	}
	duk_pop(ctx);																								// ...
	free(data);
}
ILibTransport_DoneState ILibDuktape_HttpStream_WriteSink(ILibDuktape_DuplexStream *DS, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_HttpStream_Data *data = (ILibDuktape_HttpStream_Data*)user;

	if (ILibIsRunningOnChainThread(data->chain) == 0)
	{
		// We need to context switch, because the event dispatch MUST be on the chain thread
		ILibDuktape_HttpStream_DispatchWrite_data *tmp = (ILibDuktape_HttpStream_DispatchWrite_data*)ILibMemory_Allocate(sizeof(ILibDuktape_HttpStream_DispatchWrite_data) + bufferLen, 0, NULL, NULL);
		tmp->httpStream = data;
		tmp->bufferLen = bufferLen;
		memcpy_s(tmp->buffer, bufferLen, buffer, bufferLen);
		ILibChain_RunOnMicrostackThread(data->chain, ILibDuktape_HttpStream_WriteSink_ChainSink, tmp);
		return(ILibTransport_DoneState_INCOMPLETE);
	}

	duk_push_heapptr(DS->readableStream->ctx, DS->ParentObject);		// [httpStream]
	duk_get_prop_string(DS->readableStream->ctx, -1, "emit");			// [httpStream][emit]
	duk_swap_top(DS->readableStream->ctx, -2);							// [emit][this]
	duk_push_string(DS->readableStream->ctx, "write");					// [emit][this][write]
	if (duk_pcall_method(DS->readableStream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(DS->readableStream->ctx, "httpStream.write(): Error dispatching 'write' event "); }
	duk_pop(DS->readableStream->ctx);									// ...

	// We're already on Chain Thread, so we can just directly write
	int beginPointer = 0;
	int PAUSE = 0;
	int MustBuffer = 0;
	ILibDuktape_WritableStream *stream = DS->writableStream;

	ILibWebClient_OnData(NULL, buffer, &beginPointer, (int)bufferLen, NULL, (void**)&(data->WCDO), &PAUSE);

	if ((bufferLen - beginPointer) > 0)
	{
		// Not all the data was consumed, so let's try to push the unprocess data back
		if (stream->pipedReadable != NULL)
		{
			// Make a JavaScript call to readable.unshift()
			duk_push_heapptr(stream->ctx, stream->pipedReadable);													// [readable]
			if (duk_has_prop_string(stream->ctx, -1, "unshift"))
			{
				duk_push_external_buffer(stream->ctx);																// [readable][extBuffer]
				duk_config_buffer(stream->ctx, -1, buffer + beginPointer, (int)bufferLen - beginPointer);
				duk_swap_top(stream->ctx, -2);																		// [extBuffer][readable]
				duk_get_prop_string(stream->ctx, -1, "unshift");													// [extBuffer][readable][unshift]
				duk_swap_top(stream->ctx, -2);																		// [extBuffer][unshift][this]
				duk_push_buffer_object(stream->ctx, -3, 0, (int)bufferLen - beginPointer, DUK_BUFOBJ_NODEJS_BUFFER);// [extBuffer][unshift][this][buffer]
				if (duk_pcall_method(stream->ctx, 1) != 0) { MustBuffer = 1; }
				duk_pop_2(stream->ctx);																				// ...
			}
			else
			{
				duk_pop(stream->ctx);
				MustBuffer = 1;
			}
		}
		else if (stream->pipedReadable_native != NULL && stream->pipedReadable_native->UnshiftHandler != NULL)
		{
			if (stream->pipedReadable_native->UnshiftHandler(stream->pipedReadable_native, (int)bufferLen - beginPointer, stream->pipedReadable_native->user) == 0)
			{
				MustBuffer = 1;
			}
		}
		else
		{
			MustBuffer = 1;
		}
		if (MustBuffer != 0)
		{
			// We couldn't unshift unprocessed bytes, so we have to buffer it for later
			// The good news is that we are on the Chain Thread, so we can have JavaScript manage the memory
			duk_push_heapptr(stream->ctx, stream->obj);									// [HttpStream]
			if (duk_has_prop_string(stream->ctx, -1, IILibDuktape_HTTP_HoldingQueue))
			{
				duk_get_prop_string(stream->ctx, -1, IILibDuktape_HTTP_HoldingQueue);	// [HttpStream][Holding]
			}
			else
			{
				duk_push_array(stream->ctx);											// [HttpStream][Holding]
				duk_dup(stream->ctx, -1);												// [HttpStream][Holding][Holding]
				duk_put_prop_string(stream->ctx, -3, IILibDuktape_HTTP_HoldingQueue);	// [HttpStream][Holding]
			}
				
			duk_get_prop_string(stream->ctx, -1, "push");								// [HttpStream][Holding][push]
			duk_swap_top(stream->ctx, -2);												// [HttpStream][push][this]
			duk_push_fixed_buffer(stream->ctx, (int)bufferLen - beginPointer);			// [HttpStream][push][this][buffer]
			memcpy_s(Duktape_GetBuffer(stream->ctx, -1, NULL), (int)bufferLen - beginPointer, buffer + beginPointer, (int)bufferLen - beginPointer);
			if (duk_pcall_method(stream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "HttpStream.Write() -> Error calling Array.push() "); }
			duk_pop_2(stream->ctx);														// ...

			return(ILibTransport_DoneState_INCOMPLETE);
		}
		else
		{
			// We successfully unshifted bytes, so we're done here
			return(ILibTransport_DoneState_COMPLETE);
		}
	}
	else
	{
		// Consumed All Data
		return(ILibTransport_DoneState_COMPLETE);
	}
}
void ILibDuktape_HttpStream_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_HttpStream_Data *data = (ILibDuktape_HttpStream_Data*)user;

	if (data->bodyStream != NULL && data->endPropagated == 0)
	{
		ILibDuktape_readableStream_WriteEnd(data->bodyStream);
		data->endPropagated = 1;
	}
}
void ILibDuktape_HttpStream_ServerResponse_WriteImplicitHeaders(void *chain, void *user)
{
	int retVal;
	ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State *state = (ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State*)user;
	if (!ILibMemory_CanaryOK(state->serverResponseStream)) { free(user); return; }

	// We are on Microstack Thread, so we can access the JS object, and write the implicit headers
	duk_push_heapptr(state->ctx, state->serverResponseObj);					// [SR]
	duk_get_prop_string(state->ctx, -1, "writeHead");						// [SR][writeHead]
	duk_swap_top(state->ctx, -2);											// [writeHead][this]
	duk_get_prop_string(state->ctx, -1, "statusCode");						// [writeHead][this][statusCode]
	duk_get_prop_string(state->ctx, -2, "statusMessage");					// [writeHead][this][statusCode][statusMessage]
	duk_get_prop_string(state->ctx, -3, ILibDuktape_SR2ImplicitHeaders);	// [writeHead][this][statusCode][statusMessage][headers]
	if (state->endBytes >= 0) // -1: Unknown, 0: No Data, >0: Content-Length
	{
		duk_push_string(state->ctx, "Content-Length");						// [writeHead][this][statusCode][statusMessage][headers][name]
		duk_push_int(state->ctx, state->endBytes);							// [writeHead][this][statusCode][statusMessage][headers][name][value]
		duk_put_prop(state->ctx, -3);										// [writeHead][this][statusCode][statusMessage][headers]
	}
	else
	{
		if (state->chunk)
		{
			duk_push_string(state->ctx, "Transfer-Encoding");					// [writeHead][this][statusCode][statusMessage][headers][name]
			duk_push_string(state->ctx, "chunked");								// [writeHead][this][statusCode][statusMessage][headers][name][value]
			duk_put_prop(state->ctx, -3);										// [writeHead][this][statusCode][statusMessage][headers]
		}
	}
	if ((retVal = duk_pcall_method(state->ctx, 3)) != 0) { ILibDuktape_Process_UncaughtExceptionEx(state->ctx, "http.serverResponse.writeImplicitHeaders(): Error "); }
	duk_pop(state->ctx);													// ...

	if (state->bufferLen > 0 && retVal == 0)
	{
		duk_push_external_buffer(state->ctx);														// [ext]
		duk_push_heapptr(state->ctx, state->writeStream);											// [ext][stream]
		duk_get_prop_string(state->ctx, -1, "write");												// [ext][stream][write]
		duk_swap_top(state->ctx, -2);																// [ext][write][this]

		if (state->endBytes > 0 || state->chunk == 0)
		{
			// We can just directly write the data
			duk_config_buffer(state->ctx, -3, state->buffer, state->bufferLen);
			duk_push_buffer_object(state->ctx, -3, 0, state->bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);	// [ext][write][this][buffer]
			retVal = duk_pcall_method(state->ctx, 1);
			duk_pop_2(state->ctx);																	// ...
		}
		else
		{
			// We must chunk encode the data
			char *tmp = ILibMemory_AllocateA(state->bufferLen + 16);
			int i = sprintf_s(tmp, state->bufferLen + 16, "%X\r\n", (unsigned int)state->bufferLen);
			memcpy_s(tmp + i, state->bufferLen, state->buffer, state->bufferLen);
			i += ((int)state->bufferLen + sprintf_s(tmp + i + state->bufferLen, 16 - i, "\r\n"));
			duk_config_buffer(state->ctx, -3, tmp, i);

			duk_push_buffer_object(state->ctx, -3, 0, i, DUK_BUFOBJ_NODEJS_BUFFER);					// [ext][write][this][buffer]
			retVal = duk_pcall_method(state->ctx, 1);
			duk_pop_2(state->ctx);																	// ...
		}
	}

	if (retVal == 0 && chain != NULL)
	{
		// Since we context switched to get here, we must signal that we are done
		ILibDuktape_WritableStream *WS = ILibDuktape_DuplexStream_GetNativeWritable(state->ctx, state->serverResponseObj);
		if (WS != NULL)
		{
			ILibDuktape_WritableStream_Ready(WS);
		}
	}
}
int ILibDuktape_HttpStream_ServerResponse_WriteSink_Flush(struct ILibDuktape_WritableStream *stream, void *user)
{
	ILibDuktape_WritableStream_Ready((struct ILibDuktape_WritableStream *)user);
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_ServerResponse_WriteSink_JS_Flushed(duk_context *ctx)
{
	duk_push_this(ctx);									// [stream]
	duk_get_prop_string(ctx, -1, ILibDuktape_SRUSER);	// [stream][ptr]
	ILibDuktape_WritableStream *WS = (ILibDuktape_WritableStream*)duk_get_pointer(ctx, -1);

	ILibDuktape_WritableStream_Ready(WS);
	return(0);
}
void ILibDuktape_HttpStream_ServerResponse_WriteSink_Chain(void *chain, void *user)
{
	ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State *state = (ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State*)user;

	// We good to go
	int noDrain;
	duk_push_external_buffer(state->ctx);												// [ext]
	duk_push_heapptr(state->ctx, state->writeStream);									// [ext][stream]
	duk_get_prop_string(state->ctx, -1, "write");										// [ext][stream][write]
	duk_dup(state->ctx, -2);															// [ext][stream][write][this]
	if (state->chunk)
	{
		char tmp[16];
		int tmpLen = sprintf_s(tmp, sizeof(tmp), "%X\r\n", (int)state->bufferLen);
		duk_config_buffer(state->ctx, -4, tmp, tmpLen);
		duk_push_buffer_object(state->ctx, -4, 0, tmpLen, DUK_BUFOBJ_NODEJS_BUFFER);	// [ext][stream][write][this][buffer]
		if (duk_pcall_method(state->ctx, 1) != 0) { duk_pop_2(state->ctx); return; }
		duk_pop(state->ctx);															// [ext][stream]
		duk_get_prop_string(state->ctx, -1, "write");									// [ext][stream][write]
		duk_dup(state->ctx, -2);														// [ext][stream][write][this]
	}
	duk_config_buffer(state->ctx, -4, state->buffer, state->bufferLen);
	duk_push_buffer_object(state->ctx, -4, 0, state->bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);	// [ext][stream][write][this][buffer]
	if (duk_pcall_method(state->ctx, 1) != 0) { duk_pop_2(state->ctx); return; }
	noDrain = duk_get_int(state->ctx, -1);
	duk_pop(state->ctx);																// [ext][stream]
	if (state->chunk)
	{
		char tmp[] = "\r\n";
		duk_get_prop_string(state->ctx, -1, "write");									// [ext][stream][write]
		duk_dup(state->ctx, -2);														// [ext][stream][write][this]

		duk_config_buffer(state->ctx, -4, tmp, 2);
		duk_push_buffer_object(state->ctx, -4, 0, state->bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);// [ext][stream][write][this][buffer]
		if (duk_pcall_method(state->ctx, 1) != 0) { duk_pop_2(state->ctx); return; }
		noDrain = duk_get_int(state->ctx, -1);
		duk_pop(state->ctx);															// [ext][stream]
	}
	if (!noDrain)
	{
		duk_push_pointer(state->ctx, ILibDuktape_DuplexStream_GetNativeWritable(state->ctx, state->serverResponseObj));
		duk_put_prop_string(state->ctx, -2, ILibDuktape_SRUSER);
		ILibDuktape_EventEmitter_AddOnceEx3(state->ctx, -1, "drain", ILibDuktape_HttpStream_ServerResponse_WriteSink_JS_Flushed);
	}
	else
	{
		ILibDuktape_WritableStream_Ready(ILibDuktape_DuplexStream_GetNativeWritable(state->ctx, state->serverResponseObj));
	}
	free(state);
}
ILibTransport_DoneState ILibDuktape_HttpStream_ServerResponse_WriteSink(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_HttpStream_ServerResponse_State *state = (ILibDuktape_HttpStream_ServerResponse_State*)user;
	if (state->implicitHeaderHandling)
	{
		state->implicitHeaderHandling = 0;
		if (ILibIsRunningOnChainThread(state->chain))
		{			
			ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State *tmp = (ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State*)ILibMemory_AllocateA(sizeof(ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State) + bufferLen);
			memset(tmp, 0, sizeof(ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State));
			tmp->ctx = stream->ctx;
			tmp->serverResponseObj = stream->obj;
			tmp->serverResponseStream = stream;
			tmp->writeStream = state->writeStream;
			tmp->endBytes = stream->endBytes;
			tmp->chunk = state->chunkSupported;
			if (bufferLen > 0) { memcpy_s(tmp->buffer, bufferLen, buffer, bufferLen); tmp->bufferLen = bufferLen; }

			ILibDuktape_HttpStream_ServerResponse_WriteImplicitHeaders(NULL, tmp);
			return(ILibTransport_DoneState_COMPLETE);
		}
		else
		{
			ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State *buffered = (ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State*)ILibMemory_Allocate(sizeof(ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State) + bufferLen, 0, NULL, NULL);
			memset(buffered, 0, sizeof(ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State));
			buffered->ctx = stream->ctx;
			buffered->serverResponseObj = stream->obj;
			buffered->serverResponseStream = stream;
			buffered->writeStream = state->writeStream;
			buffered->bufferLen = bufferLen;
			buffered->endBytes = stream->endBytes;
			buffered->chunk = state->chunkSupported;
			if (bufferLen > 0) { memcpy_s(buffered->buffer, bufferLen, buffer, bufferLen); }

			ILibChain_RunOnMicrostackThreadEx(state->chain, ILibDuktape_HttpStream_ServerResponse_WriteImplicitHeaders, buffered);
			return(ILibTransport_DoneState_INCOMPLETE);
		}
	}
	else
	{
		// Headers were already sent, so we can just send data along
		ILibTransport_DoneState retVal;
		if (state->nativeWriteStream != NULL)
		{
			state->nativeWriteStream->OnWriteFlushEx = ILibDuktape_HttpStream_ServerResponse_WriteSink_Flush;
			state->nativeWriteStream->OnWriteFlushEx_User = stream;
			if (state->chunkSupported && !state->contentLengthSpecified)
			{
				char tmp[16];
				int tmpLen = sprintf_s(tmp, sizeof(tmp), "%X\r\n", (int)bufferLen);
				state->nativeWriteStream->WriteSink(state->nativeWriteStream, tmp, tmpLen, state->nativeWriteStream->WriteSink_User);
			}
			retVal = state->nativeWriteStream->WriteSink(state->nativeWriteStream, buffer, (int)bufferLen, state->nativeWriteStream->WriteSink_User);
			if (state->chunkSupported && !state->contentLengthSpecified)
			{
				retVal = state->nativeWriteStream->WriteSink(state->nativeWriteStream, "\r\n", 2, state->nativeWriteStream->WriteSink_User);
			}
		}
		else
		{
			// Upstream is a pure ECMA Script Object
			if (ILibIsRunningOnChainThread(state->chain))
			{
				// We good to go
				int noDrain;
				duk_push_external_buffer(stream->ctx);												// [ext]
				duk_push_heapptr(stream->ctx, state->writeStream);									// [ext][stream]
				duk_get_prop_string(stream->ctx, -1, "write");										// [ext][stream][write]
				duk_dup(stream->ctx, -2);															// [ext][stream][write][this]
				if (state->chunkSupported && !state->contentLengthSpecified)
				{
					char tmp[16];
					int tmpLen = sprintf_s(tmp, sizeof(tmp), "%X\r\n", (int)bufferLen);
					duk_config_buffer(stream->ctx, -4, tmp, tmpLen);
					duk_push_buffer_object(stream->ctx, -4, 0, tmpLen, DUK_BUFOBJ_NODEJS_BUFFER);	// [ext][stream][write][this][buffer]
					if (duk_pcall_method(stream->ctx, 1) != 0) { duk_pop_2(stream->ctx); return(ILibTransport_DoneState_ERROR); }
					duk_pop(stream->ctx);															// [ext][stream]
					duk_get_prop_string(stream->ctx, -1, "write");									// [ext][stream][write]
					duk_dup(stream->ctx, -2);														// [ext][stream][write][this]
				}
				duk_config_buffer(stream->ctx, -4, buffer, bufferLen);
				duk_push_buffer_object(stream->ctx, -4, 0, bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);	// [ext][stream][write][this][buffer]
				if (duk_pcall_method(stream->ctx, 1) != 0) { duk_pop_2(stream->ctx); return(ILibTransport_DoneState_ERROR); }
				noDrain = duk_get_int(stream->ctx, -1);
				duk_pop(stream->ctx);																// [ext][stream]
				if (state->chunkSupported && !state->contentLengthSpecified)
				{
					char tmp[] = "\r\n";
					duk_get_prop_string(stream->ctx, -1, "write");									// [ext][stream][write]
					duk_dup(stream->ctx, -2);														// [ext][stream][write][this]

					duk_config_buffer(stream->ctx, -4, tmp, 2);
					duk_push_buffer_object(stream->ctx, -4, 0, bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);// [ext][stream][write][this][buffer]
					if (duk_pcall_method(stream->ctx, 1) != 0) { duk_pop_2(stream->ctx); return(ILibTransport_DoneState_ERROR); }
					noDrain = duk_get_int(stream->ctx, -1);
					duk_pop(stream->ctx);															// [ext][stream]
				}
				if (!noDrain)
				{
					duk_push_pointer(stream->ctx, stream);
					duk_put_prop_string(stream->ctx, -2, ILibDuktape_SRUSER);
					ILibDuktape_EventEmitter_AddOnceEx3(stream->ctx, -1, "drain", ILibDuktape_HttpStream_ServerResponse_WriteSink_JS_Flushed);
					retVal = ILibTransport_DoneState_INCOMPLETE;
				}
				else
				{
					retVal = ILibTransport_DoneState_COMPLETE;
				}
			}
			else
			{
				// Gotta context switch
				ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State *data = (ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State*)ILibMemory_Allocate(sizeof(ILibDuktape_HttpStream_ServerResponse_BufferedImplicit_State) + bufferLen, 0, NULL, NULL);
				data->chunk = state->chunkSupported;
				data->ctx = stream->ctx;
				data->endBytes = stream->endBytes;
				data->serverResponseObj = stream->obj;
				data->serverResponseStream = stream;
				data->writeStream = state->writeStream;
				data->bufferLen = bufferLen;
				memcpy_s(data->buffer, bufferLen, buffer, bufferLen);
				ILibChain_RunOnMicrostackThreadEx(state->chain, ILibDuktape_HttpStream_ServerResponse_WriteSink_Chain, data);
				return(ILibTransport_DoneState_INCOMPLETE);
			}
		}
		return(retVal);
	}
}
void ILibDuktape_HttpStream_ServerResponse_EndSink_Chain(void *chain, void *user)
{
	struct ILibDuktape_WritableStream *stream = (struct ILibDuktape_WritableStream*)user;

	duk_push_heapptr(stream->ctx, stream->obj);								// [serverResponse]
	duk_get_prop_string(stream->ctx, -1, "writeHead");						// [serverResponse][writeHead]
	duk_swap_top(stream->ctx, -2);											// [writeHead][this]
	duk_get_prop_string(stream->ctx, -1, "statusCode");						// [writeHead][this][statusCode]
	duk_get_prop_string(stream->ctx, -2, "statusMessage");					// [writeHead][this][statusCode][statusMessage]
	duk_get_prop_string(stream->ctx, -3, ILibDuktape_SR2ImplicitHeaders);	// [writeHead][this][statusCode][statusMessage][headers]
	duk_push_string(stream->ctx, "Content-Length");							// [writeHead][this][statusCode][statusMessage][headers][name]
	duk_push_int(stream->ctx, 0);											// [writeHead][this][statusCode][statusMessage][headers][name][value]
	duk_put_prop(stream->ctx, -3);											// [writeHead][this][statusCode][statusMessage][headers]
	if (duk_pcall_method(stream->ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "http.serverResponse.end(): Error writing implicit headers "); }
	duk_pop(stream->ctx);													// ...

	// Need to reset HttpStream
	ILibDuktape_serverResponse_resetHttpStream(stream->ctx, stream->obj);
}
void ILibDuktape_HttpStream_ServerResponse_EndSink_ZeroChunk_Chain(void *chain, void *user)
{
	ILibDuktape_HttpStream_ServerResponse_State *state = (ILibDuktape_HttpStream_ServerResponse_State*)user;
	
	if (state->chunkSupported && !state->contentLengthSpecified)
	{
		// Send zero size chunk
		char tmp[] = "0\r\n\r\n";
		if (state->nativeWriteStream != NULL)
		{
			state->nativeWriteStream->OnWriteFlushEx = NULL;
			state->nativeWriteStream->OnWriteFlushEx_User = NULL;
			state->nativeWriteStream->WriteSink(state->nativeWriteStream, tmp, 5, state->nativeWriteStream->WriteSink_User);
		}
		else
		{
			duk_push_external_buffer(state->ctx);
			duk_config_buffer(state->ctx, -1, tmp, 5);								// [ext]
			duk_push_heapptr(state->ctx, state->writeStream);						// [ext][stream]
			duk_get_prop_string(state->ctx, -1, "write");							// [ext][stream][write]
			duk_swap_top(state->ctx, -2);											// [ext][write][this]
			duk_push_buffer_object(state->ctx, -3, 0, 5, DUK_BUFOBJ_NODEJS_BUFFER);	// [ext][write][this][buffer]
			if (duk_pcall_method(state->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(state->ctx, "http.serverResponse.end(): Error writing upstream "); }
			duk_pop_2(state->ctx);													// ...
		}
	}
	else
	{
		if (!state->chunkSupported)
		{
			// Close the connection
			if (state->nativeWriteStream != NULL)
			{
				state->nativeWriteStream->EndSink(state->nativeWriteStream, state->nativeWriteStream->WriteSink_User);
			}
			else
			{
				duk_push_heapptr(state->ctx, state->writeStream);						// [stream]
				duk_get_prop_string(state->ctx, -1, "end");								// [stream][end]
				duk_swap_top(state->ctx, -2);											// [end][this]
				if (duk_pcall_method(state->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(state->ctx, "http.serverResponse.end(): Error ending upstream "); }
				duk_pop(state->ctx);													// ...
			}
		}
	}

	// Need to reset HttpStream
	ILibDuktape_serverResponse_resetHttpStream(state->ctx, state->serverResponse);
}
void ILibDuktape_HttpStream_ServerResponse_EndSink(struct ILibDuktape_WritableStream *stream, void *user)
{
	ILibDuktape_HttpStream_ServerResponse_State *state = (ILibDuktape_HttpStream_ServerResponse_State*)user;
	
	if (state->implicitHeaderHandling)
	{
		if (ILibIsRunningOnChainThread(state->chain))
		{
			duk_push_this(stream->ctx);												// [serverResponse]
			duk_get_prop_string(stream->ctx, -1, "writeHead");						// [serverResponse][writeHead]
			duk_swap_top(stream->ctx, -2);											// [writeHead][this]
			duk_get_prop_string(stream->ctx, -1, "statusCode");						// [writeHead][this][statusCode]
			duk_get_prop_string(stream->ctx, -2, "statusMessage");					// [writeHead][this][statusCode][statusMessage]
			duk_get_prop_string(stream->ctx, -3, ILibDuktape_SR2ImplicitHeaders);	// [writeHead][this][statusCode][statusMessage][headers]
			duk_push_string(stream->ctx, "Content-Length");							// [writeHead][this][statusCode][statusMessage][headers][name]
			duk_push_int(stream->ctx, 0);											// [writeHead][this][statusCode][statusMessage][headers][name][value]
			duk_put_prop(stream->ctx, -3);											// [writeHead][this][statusCode][statusMessage][headers]
			if (duk_pcall_method(stream->ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "http.serverResponse.end(): Error writing implicit headers "); }
			duk_pop(stream->ctx);													// ...

			// Need to reset HttpStream
			ILibDuktape_serverResponse_resetHttpStream(stream->ctx, stream->obj);
		}
		else
		{
			// Need to context switch before sending Implicit Headers
			ILibChain_RunOnMicrostackThreadEx(state->chain, ILibDuktape_HttpStream_ServerResponse_EndSink_Chain, stream);
		}
	}
	else
	{
		// Headers already sent...
		if (state->nativeWriteStream != NULL)
		{
			ILibDuktape_HttpStream_ServerResponse_EndSink_ZeroChunk_Chain(state->chain, state);
		}
		else
		{
			ILibChain_RunOnMicrostackThread(state->chain, ILibDuktape_HttpStream_ServerResponse_EndSink_ZeroChunk_Chain, state);
		}
	}
}
duk_ret_t ILibDuktape_HttpStream_ServerResponse_writeHead(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int statusCode = duk_require_int(ctx, 0);
	char *statusMessage = NULL;
	duk_size_t statusMessageLen = 0;
	void *headers = NULL;
	int i;
	int contentLengthSpecified = 0;

	char *buffer = NULL;
	duk_size_t bufferLen = 0, len = 0;
	if (statusCode < 100 || statusCode > 999) { return(ILibDuktape_Error(ctx, "http.serverResponse.writeHead(): Invalid status code")); }

	for (i = 1; i < nargs; ++i)
	{
		if (duk_is_string(ctx, i)) { statusMessage = (char*)duk_get_lstring(ctx, i, &statusMessageLen); }
		if (duk_is_object(ctx, i)) { headers = duk_require_heapptr(ctx, i); }
	}

	if (statusMessage == NULL)
	{
		switch (statusCode)
		{
		case 100:
			statusMessage = "Continue";
			statusMessageLen = 8;
			break;
		case 200:
			statusMessage = "Bad Request";
			statusMessageLen = 11;
			break;
		case 401:
			statusMessage = "Unauthorized";
			statusMessageLen = 12;
			break;
		case 404:
			statusMessage = "Not Found";
			statusMessageLen = 9;
			break;
		case 500:
			statusMessage = "Internal Server Error";
			statusMessageLen = 21;
			break;
		default:
			statusMessage = "Unspecified";
			statusMessageLen = 11;
			break;
		}
	}

	for (i = 0; i < 2; ++i)
	{
		if (buffer == NULL)
		{
			bufferLen = 15 + statusMessageLen;						//'HTTP/1.1 XXX statusMessage\r\n'
		}
		else
		{
			len += sprintf_s(buffer + len, bufferLen - len, "HTTP/1.1 %d %s\r\n", statusCode, statusMessage);
		}
		if (headers != NULL)
		{
			duk_push_heapptr(ctx, headers);						// [headers]
			duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);	// [headers][enum]
			while (duk_next(ctx, -1, 1))						// [headers][enum][key][value]
			{
				char *key, *value;
				duk_size_t keyLen, valueLen;
				key = (char*)duk_get_lstring(ctx, -2, &keyLen);
				if (duk_is_string(ctx, -1))
				{
					value = (char*)duk_get_lstring(ctx, -1, &valueLen);
				}
				else
				{
					duk_get_prop_string(ctx, -1, "toString");		// [key][value][toString]
					duk_swap_top(ctx, -2);							// [key][toString][this]
					duk_call_method(ctx, 0);						// [key][valueString]
					value = (char*)duk_get_lstring(ctx, -1, &valueLen);
				}
				if (buffer == NULL)
				{
					bufferLen += (keyLen + 2 + valueLen + 2);		// key: value\r\n
					if (keyLen == 14 && strncasecmp(key, "Content-Length", 14) == 0) { contentLengthSpecified = 1; }
				}
				else
				{
					len += sprintf_s(buffer + len, bufferLen - len, "%s: %s\r\n", key, value);
				}
				duk_pop_2(ctx);									// [headers][enum]
			}
		}
		if (buffer == NULL)
		{
			bufferLen += 2; // End of Headers
		}
		else
		{
			len += sprintf_s(buffer + len, bufferLen - len, "\r\n");
		}
		if (buffer == NULL) { ++bufferLen;  buffer = ILibMemory_AllocateA(bufferLen); }
	}

	duk_push_this(ctx);														// [SR]
	duk_get_prop_string(ctx, -1, ILibDuktape_SR2State);						// [SR][state]
	((ILibDuktape_HttpStream_ServerResponse_State*)Duktape_GetBuffer(ctx, -1, NULL))->implicitHeaderHandling = 0;
	((ILibDuktape_HttpStream_ServerResponse_State*)Duktape_GetBuffer(ctx, -1, NULL))->contentLengthSpecified = contentLengthSpecified;
	duk_pop(ctx);															// [SR]


	duk_push_external_buffer(ctx);											// [SR][ext]
	duk_config_buffer(ctx, -1, buffer, bufferLen-1);							
	duk_get_prop_string(ctx, -2, ILibDuktape_SR2WS);						// [SR][ext][WS]
	duk_get_prop_string(ctx, -1, "write");									// [SR][ext][WS][write]
	duk_swap_top(ctx, -2);													// [SR][ext][write][this]
	duk_push_buffer_object(ctx, -3, 0, bufferLen-1, DUK_BUFOBJ_NODEJS_BUFFER);// [SR][ext][write][this][buffer]

	duk_call_method(ctx, 1);												// [SR][ext][retVal]
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_ServerResponse_setHeader(duk_context *ctx)
{
	duk_push_this(ctx);													// [SR]
	duk_get_prop_string(ctx, -1, ILibDuktape_SR2ImplicitHeaders);		// [SR][headers]
	duk_dup(ctx, 0);													// [SR][headers][name]
	duk_dup(ctx, 1);													// [SR][headers][name][value]
	duk_put_prop(ctx, -3);												// [SR][headers]
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_ServerResponse_removeHeader(duk_context *ctx)
{
	duk_push_this(ctx);													// [SR]
	duk_get_prop_string(ctx, -1, ILibDuktape_SR2ImplicitHeaders);		// [SR][headers]
	duk_dup(ctx, 0);													// [SR][headers][name]
	duk_del_prop(ctx, -2);												// [SR][headers]
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_ServerResponse_Digest_SendUnauthorized(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	long long nonceExpiration = ILibGetUptime() + (long long)(900000); // 15 minutes
	char nonce[33];
	char opaque[17];

	char *realm;
	duk_size_t realmLen, htmlLen = 0;
	void *hptr;

	if (nargs > 0)
	{
		duk_get_lstring(ctx, 1, &htmlLen);
	}
	

	duk_push_this(ctx);											// [serverResponse]
	duk_get_prop_string(ctx, -1, ILibDuktape_SR2HttpStream);	// [serverResponse][httpStream]
	duk_get_prop_string(ctx, -1, ILibDuktape_HTTPStream2HTTP);	// [serverResponse][httpStream][http]
	hptr = duk_get_heapptr(ctx, -1);

	util_tohex((char*)&nonceExpiration, 8, opaque);
	realm = (char*)duk_get_lstring(ctx, 0, &realmLen);
	ILibDuktape_Digest_CalculateNonce(ctx, hptr, nonceExpiration, opaque, 16, nonce);

	duk_push_this(ctx);								// [serverResponse]
	duk_get_prop_string(ctx, -1, "writeHead");		// [serverResponse][writeHead]
	duk_swap_top(ctx, -2);							// [writeHead][this]
	duk_push_int(ctx, 401);							// [writeHead][this][401]
	duk_push_string(ctx, "Unauthorized");			// [writeHead][this][401][Unauthorized]
	duk_push_object(ctx);							// [writeHead][this][401][Unauthorized][headers]
	duk_push_string(ctx, "WWW-Authenticate");		// [writeHead][this][401][Unauthorized][headers][name]
	int wwwLen = sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "Digest realm=\"%s\", nonce=\"%s\", opaque=\"%s\"", realm, nonce, opaque);
	duk_push_lstring(ctx, ILibScratchPad, wwwLen);	// [writeHead][this][401][Unauthorized][headers][name][value]
	duk_put_prop(ctx, -3);							// [writeHead][this][401][Unauthorized][headers]
	if (htmlLen > 0)
	{
		duk_push_string(ctx, "Content-Type");		// [writeHead][this][401][Unauthorized][headers][name]
		duk_push_string(ctx, "text/html");			// [writeHead][this][401][Unauthorized][headers][name][value]
		duk_put_prop(ctx, -3);						// [writeHead][this][401][Unauthorized][headers]
	}
	duk_push_string(ctx, "Content-Length");			// [writeHead][this][401][Unauthorized][headers][name]
	duk_push_int(ctx, (int)htmlLen);						// [writeHead][this][401][Unauthorized][headers][name][value]
	duk_put_prop(ctx, -3);							// [writeHead][this][401][Unauthorized][headers]

	duk_call_method(ctx, 3); duk_pop(ctx);			// ...

	duk_push_this(ctx);								// [serverResponse]
	duk_get_prop_string(ctx, -1, "end");			// [serverResponse][end]
	duk_swap_top(ctx, -2);							// [end][this]
	if (htmlLen > 0)
	{
		duk_dup(ctx, 1);							// [end][this][html]
	}
	duk_call_method(ctx, htmlLen > 0 ? 1 : 0); duk_pop(ctx);		// ...
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_ServerResponse_writeContinue(duk_context *ctx)
{
	duk_push_this(ctx);							// [serverResponse]
	duk_get_prop_string(ctx, -1, "writeHead");	// [serverResponse][writeHead]
	duk_swap_top(ctx, -2);						// [writeHead][this]
	duk_push_int(ctx, 100);						// [writeHead][this][100]
	duk_push_string(ctx, "Continue");			// [writeHead][this][100][continue]
	duk_call_method(ctx, 2);
	return(0);
}
void ILibDuktape_HttpStream_ServerResponse_PUSH(duk_context *ctx, void* writeStream, ILibHTTPPacket *header, void *httpStream)
{
	ILibDuktape_HttpStream_ServerResponse_State *state;

	duk_push_object(ctx);																					// [resp]
	duk_push_heapptr(ctx, httpStream);																		// [resp][httpStream]
	duk_dup(ctx, -1);																						// [resp][httpStream][dup]
	duk_put_prop_string(ctx, -3, ILibDuktape_SR2HttpStream);												// [resp][httpStream]
	duk_get_prop_string(ctx, -1, ILibDuktape_HTTPStream2HTTP);												// [resp][httpStream][http]
	duk_get_prop_string(ctx, -1, ILibDuktape_OBJID);														// [resp][httpStream][http][id]
	duk_remove(ctx, -2);																					// [resp][httpStream][id]
	duk_get_prop_string(ctx, -1, "concat");																	// [resp][httpStream][id][concat]
	duk_swap_top(ctx, -2);																					// [resp][httpStream][concat][this]
	duk_push_string(ctx, ".serverResponse");																// [resp][httpStream][concat][this][serverResponse]
	if (duk_pcall_method(ctx, 1) != 0) { duk_pop(ctx); duk_push_string(ctx, "http[s].serverResponse"); }	// [resp][httpStream][http/s.serverResponse]
	duk_remove(ctx, -2);																					// [resp][http/s.serverResponse]
	duk_put_prop_string(ctx, -2, ILibDuktape_OBJID);														// [resp]

	ILibDuktape_WriteID(ctx, "http.serverResponse");
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_HttpStream_ServerResponse_State));			// [resp][state]
	state = (ILibDuktape_HttpStream_ServerResponse_State*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_SR2State);											// [resp]
	memset(state, 0, sizeof(ILibDuktape_HttpStream_ServerResponse_State));
	state->ctx = ctx;
	state->serverResponse = duk_get_heapptr(ctx, -1);
	state->implicitHeaderHandling = 1;
	state->chain = Duktape_GetChain(ctx);
	state->writeStream = writeStream;
	state->nativeWriteStream = ILibDuktape_DuplexStream_GetNativeWritable(ctx, writeStream);
	state->chunkSupported = ILibDuktape_Headers_IsChunkSupported(header);
	duk_push_object(ctx);																		// [resp][implicitHeaders]
	duk_put_prop_string(ctx, -2, ILibDuktape_SR2ImplicitHeaders);								// [resp]
	
	duk_push_int(ctx, 200);
	duk_put_prop_string(ctx, -2, "statusCode");
	duk_push_string(ctx, "OK");
	duk_put_prop_string(ctx, -2, "statusMessage");

	duk_push_heapptr(ctx, writeStream);
	duk_put_prop_string(ctx, -2, ILibDuktape_SR2WS);

	ILibDuktape_WritableStream_Init(ctx, ILibDuktape_HttpStream_ServerResponse_WriteSink, ILibDuktape_HttpStream_ServerResponse_EndSink, state);
	ILibDuktape_CreateInstanceMethod(ctx, "writeHead", ILibDuktape_HttpStream_ServerResponse_writeHead, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "writeContinue", ILibDuktape_HttpStream_ServerResponse_writeContinue, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "setHeader", ILibDuktape_HttpStream_ServerResponse_setHeader, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "removeHeader", ILibDuktape_HttpStream_ServerResponse_removeHeader, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "Digest_writeUnauthorized", ILibDuktape_HttpStream_ServerResponse_Digest_SendUnauthorized, DUK_VARARGS);
}

int ILibDuktape_Digest_IsCorrectRealmAndNonce(duk_context *ctx, void *IMSG, char* realm, int realmLen)
{
	char* auth;
	duk_size_t authLen;
	char* userRealm = NULL;
	int userRealmLen;
	char* nonce = NULL;
	char* opaque = NULL;
	int opaqueLen, nonceLen;
	long long current = ILibGetUptime();
	char expiration[8];
	char calculatedNonce[33];
	void *DigestTable = ILibInitHashTree_CaseInSensitiveEx(ILibMemory_AllocateA(8000));
	void *hptr;

	duk_push_heapptr(ctx, IMSG);								// [IMSG]
	duk_get_prop_string(ctx, -1, ILibDuktape_IMSG2HttpStream);	// [IMSG][httpStream]
	duk_get_prop_string(ctx, -1, ILibDuktape_HTTPStream2HTTP);	// [IMSG][httpStream][http]
	hptr = duk_get_heapptr(ctx, -1);
	duk_pop_2(ctx);												// [IMSG]
	duk_get_prop_string(ctx, -1, "headers");					// [IMSG][headers]
	auth = (char*)Duktape_GetStringPropertyValueEx(ctx, -1, "Authorization", "", &authLen);
	duk_pop_2(ctx);												// ...

	ILibWebServer_Digest_ParseAuthenticationHeader(DigestTable, auth, (int)authLen);
	ILibGetEntryEx(DigestTable, "realm", 5, (void**)&userRealm, &userRealmLen);
	ILibGetEntryEx(DigestTable, "nonce", 5, (void**)&nonce, &nonceLen);
	ILibGetEntryEx(DigestTable, "opaque", 6, (void**)&opaque, &opaqueLen);

	if (opaque != NULL && userRealm != NULL && userRealmLen == realmLen && strncmp(userRealm, realm, realmLen) == 0)
	{
		// Realm is correct, now check the Nonce & Opaque Values
		if (opaqueLen != 16) { return 0; } // Invalid Opaque Block

		util_hexToBuf(opaque, 16, expiration);
		if (((long long*)expiration)[0] < current) { return 0; } // Opaque Block Expired

		ILibDuktape_Digest_CalculateNonce(ctx, hptr, ((long long*)expiration)[0], opaque, opaqueLen, calculatedNonce);
		return((nonceLen == 32 && strncmp(nonce, calculatedNonce, 32)) == 0 ? 1 : 0);
	}
	else
	{
		return 0;
	}
}

duk_ret_t ILibDuktape_HttpStream_IncomingMessage_Digest_IsAuthenticated(duk_context *ctx)
{
	// ILibWebServer_Digest_IsAuthenticated
	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "IsAuthenticated(): Invalid Parameter/Type")); }
	duk_size_t realmLen;
	char* realm = (char*)duk_get_lstring(ctx, 0, &realmLen);
	int retVal;

	duk_push_this(ctx);											// [IMSG]

	retVal = (int)ILibDuktape_Digest_IsCorrectRealmAndNonce(ctx, duk_get_heapptr(ctx, -1) , realm, (int)realmLen);
	duk_push_int(ctx, retVal);
	return 1;
}
duk_ret_t ILibDuktape_HttpStream_IncomingMessage_Digest_GetUsername(duk_context *ctx)
{
	char *auth;
	duk_size_t authLen;
	void *DigestTable = ILibInitHashTree_CaseInSensitiveEx(ILibMemory_AllocateA(8000));

	char *username;
	int usernameLen;

	duk_push_this(ctx);							// [IMSG]
	duk_get_prop_string(ctx, -1, "headers");	// [IMSG][headers]
	auth = (char*)Duktape_GetStringPropertyValueEx(ctx, -1, "Authorization", "", &authLen);
	duk_pop_2(ctx);								// ...

	ILibWebServer_Digest_ParseAuthenticationHeader(DigestTable, auth, (int)authLen);
	ILibGetEntryEx(DigestTable, "username", 8, (void**)&username, &usernameLen);
	
	duk_push_lstring(ctx, username, usernameLen);
	return(1);
}
duk_ret_t ILibDuktape_HttpStream_IncomingMessage_Digest_ValidatePassword(duk_context *ctx)
{
	int retVal;
	char nonce[33];
	char result1[33];
	char result2[33];
	char result3[33];
	char val[16];

	MD5_CTX mctx;

	char *auth, *username, *password, *opaque, *response, *uri, *realm, *method;
	duk_size_t authLen, passwordLen, methodLen;
	int usernameLen, opaqueLen, responseLen, uriLen, realmLen;

	void *DigestTable = ILibInitHashTree_CaseInSensitiveEx(ILibMemory_AllocateA(8000));
	void *hptr;

	password = (char*)duk_get_lstring(ctx, 0, &passwordLen);

	duk_push_this(ctx);											// [IMSG]
	duk_get_prop_string(ctx, -1, ILibDuktape_IMSG2HttpStream);	// [IMSG][httpStream]
	duk_get_prop_string(ctx, -1, ILibDuktape_HTTPStream2HTTP);	// [IMSG][httpStream][http]
	hptr = duk_get_heapptr(ctx, -1);
	duk_pop_2(ctx);												// [IMSG]
	duk_get_prop_string(ctx, -1, "method");
	method = (char*)duk_get_lstring(ctx, -1, &methodLen);
	duk_pop(ctx);

	duk_get_prop_string(ctx, -1, "headers");					// [IMSG][headers]
	auth = (char*)Duktape_GetStringPropertyValueEx(ctx, -1, "Authorization", "", &authLen);
	ILibWebServer_Digest_ParseAuthenticationHeader(DigestTable, auth, (int)authLen);
	duk_pop_2(ctx);												// ...

	ILibGetEntryEx(DigestTable, "username", 8, (void**)&username, &usernameLen);
	ILibGetEntryEx(DigestTable, "realm", 5, (void**)&realm, &realmLen);
	ILibGetEntryEx(DigestTable, "uri", 3, (void**)&uri, &uriLen);
	ILibGetEntryEx(DigestTable, "response", 8, (void**)&response, &responseLen);
	ILibGetEntryEx(DigestTable, "opaque", 6, (void**)&opaque, &opaqueLen);

	if (username == NULL || uri == NULL || password == NULL || passwordLen == 0 || response == NULL)
	{
		duk_push_false(ctx);
		return(1);
	}

	ILibDuktape_Digest_CalculateNonce(ctx, hptr, 0, opaque, opaqueLen, nonce);

	MD5_Init(&mctx);
	MD5_Update(&mctx, username, usernameLen);
	MD5_Update(&mctx, ":", 1);
	MD5_Update(&mctx, realm, realmLen);
	MD5_Update(&mctx, ":", 1);
	MD5_Update(&mctx, password, passwordLen);
	MD5_Final((unsigned char*)val, &mctx);
	util_tohex_lower(val, 16, result1);

	MD5_Init(&mctx);
	MD5_Update(&mctx, method, methodLen);
	MD5_Update(&mctx, ":", 1);
	MD5_Update(&mctx, uri, uriLen);
	MD5_Final((unsigned char*)val, &mctx);
	util_tohex_lower(val, 16, result2);

	MD5_Init(&mctx);
	MD5_Update(&mctx, result1, 32);
	MD5_Update(&mctx, ":", 1);
	MD5_Update(&mctx, nonce, 32);
	MD5_Update(&mctx, ":", 1);
	MD5_Update(&mctx, result2, 32);
	MD5_Final((unsigned char*)val, &mctx);
	util_tohex_lower(val, 16, result3);

	retVal = (responseLen == 32 && strncmp(result3, response, 32)) == 0 ? 1 : 0;
	duk_push_int(ctx, retVal);
	return(1);
}
duk_ret_t ILibDuktape_HttpStream_IncomingMessage_finalizer(duk_context *ctx)
{
	return(0);
}
void ILibDuktape_HttpStream_IncomingMessage_PUSH(duk_context *ctx, ILibHTTPPacket *header, void *httpstream)
{
	duk_push_object(ctx);														// [message]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_HttpStream_IncomingMessage_finalizer);
	duk_push_heapptr(ctx, httpstream);											// [message][httpStream]
	duk_dup(ctx, -1);															// [message][httpStream][dup]
	duk_put_prop_string(ctx, -3, ILibDuktape_IMSG2HttpStream);					// [message][httpStream]
	duk_get_prop_string(ctx, -1, ILibDuktape_HTTPStream2HTTP);					// [message][httpStream][http]
	duk_remove(ctx, -2);														// [message][http]
	duk_get_prop_string(ctx, -1, ILibDuktape_OBJID);							// [message][http][id]
	duk_get_prop_string(ctx, -1, "concat");										// [message][http][id][concat]
	duk_swap_top(ctx, -2);														// [message][http][concat][this]
	duk_push_string(ctx, ".IncomingMessage");									// [message][http][concat][this][.IncomingMessage]
	if (duk_pcall_method(ctx, 1) != 0) { duk_pop(ctx); duk_push_string(ctx, "http[s].IncomingMessage"); }
	duk_remove(ctx, -2);														// [message][http/s.IncomingMessage]
	duk_put_prop_string(ctx, -2, ILibDuktape_OBJID);							// [message]

	duk_push_object(ctx);														// [message][headers]
	packetheader_field_node *node = header->FirstField;
	while (node != NULL)
	{																			 
		duk_push_lstring(ctx, node->Field, node->FieldLength);					// [message][headers][key]
		duk_push_lstring(ctx, node->FieldData, node->FieldDataLength);			// [message][headers][key][value]
		duk_put_prop(ctx, -3);													// [message][headers]
		node = node->NextField;
	}
	duk_put_prop_string(ctx, -2, "headers");
	duk_push_lstring(ctx, header->Version, header->VersionLength);				// [message][version]
	duk_put_prop_string(ctx, -2, "httpVersion");

	if (header->Directive != NULL)
	{
		duk_push_lstring(ctx, header->Directive, header->DirectiveLength);		// [message][method]
		duk_get_prop_string(ctx, -1, "toUpperCase");							// [message][method][toUpper]
		duk_swap_top(ctx, -2);													// [message][toUpper][this]
		duk_call_method(ctx, 0);												// [message][method]
		ILibDuktape_CreateReadonlyProperty(ctx, "method");						// [message]

		duk_push_lstring(ctx, header->DirectiveObj, header->DirectiveObjLength);// [message][url]
		duk_put_prop_string(ctx, -2, "url");									// [message]
	}
	else
	{
		duk_push_int(ctx, header->StatusCode);									// [message][statusCode]
		duk_put_prop_string(ctx, -2, "statusCode");								// [message]
		duk_push_lstring(ctx, header->StatusData, header->StatusDataLength);	// [message][statusMessage]
		duk_put_prop_string(ctx, -2, "statusMessage");							// [message]
	}
	ILibDuktape_CreateInstanceMethod(ctx, "Digest_IsAuthenticated", ILibDuktape_HttpStream_IncomingMessage_Digest_IsAuthenticated, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "Digest_GetUsername", ILibDuktape_HttpStream_IncomingMessage_Digest_GetUsername, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "Digest_ValidatePassword", ILibDuktape_HttpStream_IncomingMessage_Digest_ValidatePassword, 1);
}

void ILibDuktape_HttpStream_IncomingMessage_PauseSink(ILibDuktape_readableStream* sender, void *user)
{

}
void ILibDuktape_HttpStream_IncomingMessage_ResumeSink(ILibDuktape_readableStream* sender, void *user)
{

}
int ILibDuktape_HttpStream_IncomingMessage_UnshiftBytes(ILibDuktape_readableStream *sender, int unshiftBytes, void *user)
{
	ILibDuktape_HttpStream_Data *data = (ILibDuktape_HttpStream_Data*)user;
	data->bodyStream_unshiftedBytes = unshiftBytes;
	return(unshiftBytes);
}
void ILibDuktape_HttpStream_DispatchEnd(void *chain, void *user)
{
	if(ILibMemory_CanaryOK(((void**)user)[1]))
	{
		duk_context *ctx = (duk_context*)((void**)user)[0];
		void *heapPtr = ((ILibDuktape_DuplexStream*)((void**)user)[1])->ParentObject;
		((ILibDuktape_HttpStream_Data*)((void**)user)[2])->bodyStream = NULL;

		duk_push_heapptr(ctx, heapPtr);			// [httpStream]
		duk_get_prop_string(ctx, -1, "emit");	// [httpStream][emit]
		duk_swap_top(ctx, -2);					// [emit][this]
		duk_push_string(ctx, "error");			// [emit][this][end]
		if (duk_pcall_method(ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "httpStream.onEnd(): "); }
		duk_pop(ctx);							// ...
	}
	free(user);
}
void ILibDuktape_HttpStream_ForceDisconnect(duk_context *ctx, void ** args, int argsLen)
{
	duk_push_heapptr(ctx, args[0]);
	duk_get_prop_string(ctx, -1, "end");
	duk_swap_top(ctx, -2);
	if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "httpStream.OnUpgrade(): "); }
	duk_pop(ctx);
}

duk_ret_t ILibDuktape_HttpStream_OnReceive_bodyStreamFinalized(duk_context *ctx)
{
	ILibDuktape_HttpStream_Data *data = (ILibDuktape_HttpStream_Data*)Duktape_GetPointerProperty(ctx, 0, ILibDuktape_IMSG2Ptr);
	if (data != NULL) 
	{ 
		if ((data->endPropagated == 0) && (data->bodyStream != NULL)) { ILibDuktape_readableStream_WriteEnd(data->bodyStream); }
		data->endPropagated = 1;
		data->bodyStream = NULL; 
	}
	return(0);
}
void ILibDuktape_HttpStream_OnReceive(ILibWebClient_StateObject WebStateObject, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, ILibWebClient_ReceiveStatus recvStatus, void *user1, void *user2, int *PAUSE)
{
	ILibDuktape_HttpStream_Data *data = (ILibDuktape_HttpStream_Data*)user1;
	duk_context *ctx = data->DS->writableStream->ctx;

	if (data->bodyStream != NULL)
	{
		if (endPointer > 0) { ILibDuktape_readableStream_WriteData(data->bodyStream, bodyBuffer + *beginPointer, endPointer); *beginPointer = endPointer - data->bodyStream_unshiftedBytes; data->bodyStream_unshiftedBytes = 0; }
		if (recvStatus == ILibWebClient_ReceiveStatus_Complete) 
		{ 
			ILibDuktape_readableStream_WriteEnd(data->bodyStream); 
			data->bodyStream = NULL; 
		}
		return;
	}

	duk_push_heapptr(ctx, data->DS->ParentObject);									// [httpStream]
	duk_get_prop_string(ctx, -1, "emit");											// [httpStream][emit]
	duk_swap_top(ctx, -2);															// [emit][this]

	if (header == NULL)
	{
		duk_push_string(ctx, "error");												// [emit][this][error]
		if (duk_pcall_method(ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.httpStream.onReceive->error(): "); }
		duk_pop(ctx);
		return;
	}

	if (header->Directive != NULL)
	{
		// We are a server
		
		if (header->DirectiveLength == 7 && strncasecmp(header->Directive, "CONNECT", 7) == 0)
		{
			// Connect
		}
		else
		{
			// Check Headers
			if (ILibGetHeaderLine(header, "Upgrade", 7) != NULL)
			{
				duk_push_string(ctx, "upgrade");														// [emit][this][upgrade]
				ILibDuktape_HttpStream_IncomingMessage_PUSH(ctx, header, data->DS->ParentObject);		// [emit][this][upgrade][imsg]
				ILibDuktape_HttpStream_ServerResponse_PUSH(ctx, data->DS->writableStream->pipedReadable, header, data->DS->ParentObject);	// [emit][this][request][imsg][rsp]
				duk_put_prop_string(ctx, -2, ILibDuktape_IMSG2SR);
				if (duk_pcall_method(ctx, 2) != 0) 
				{ ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.httpStream.onReceive->upgrade(): "); }
				else
				{
					if (!duk_get_boolean(ctx, -1))
					{
						// No upgrade listener... Close connection
						printf("\n\nNo Upgrade Listener\n");
						void *imm = ILibDuktape_Immediate(ctx, (void*[]) { data->DS->writableStream->pipedReadable }, 1, ILibDuktape_HttpStream_ForceDisconnect);
						duk_push_heapptr(ctx, imm);
						duk_push_heapptr(ctx, data->DS->writableStream->pipedReadable);
						duk_put_prop_string(ctx, -2, "r");
						duk_pop_2(ctx);
						return;
					}
				}
				duk_pop(ctx);																			// ...
			}
			else
			{
				char *val;
				int valLen;

				val = ILibGetHeaderLineEx(header, "Expect", 6, &valLen);
				if (val != NULL)
				{
					if (valLen == 12 && strncasecmp(val, "100-Continue", 12) == 0)
					{
						// Is there a listener for 'checkContinue'?
						if (ILibDuktape_EventEmitter_HasListenersEx(ctx, -1, "checkContinue"))
						{
							duk_push_string(ctx, "checkContinue");																									// [emit][this][checkContinue]
							ILibDuktape_HttpStream_IncomingMessage_PUSH(ctx, header, data->DS->ParentObject);														// [emit][this][checkContinue][imsg]
							data->bodyStream = ILibDuktape_ReadableStream_InitEx(ctx, ILibDuktape_HttpStream_IncomingMessage_PauseSink, ILibDuktape_HttpStream_IncomingMessage_ResumeSink, ILibDuktape_HttpStream_IncomingMessage_UnshiftBytes, data);
							duk_dup(ctx, -3); duk_dup(ctx, -2);																										// [emit][this][checkContinue][imsg][httpstream][imsg]
							duk_put_prop_string(ctx, -2, ILibDuktape_HTTPStream2IMSG); duk_pop(ctx);																// [emit][this][checkContinue][imsg]

							ILibDuktape_HttpStream_ServerResponse_PUSH(ctx, data->DS->writableStream->pipedReadable, header, data->DS->ParentObject);				// [emit][this][checkContinue][imsg][rsp]
							if (duk_pcall_method(ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.httpStream.onReceive->checkContinue(): "); }	// [rsp][hadListener]
							duk_pop(ctx);																															// ...
						}
						else
						{
							// Nobody listening for 'checkContinue', so we need to respond with 100 Continue
							ILibDuktape_HttpStream_ServerResponse_PUSH(ctx, data->DS->writableStream->pipedReadable, header, data->DS->ParentObject);			// [emit][this][rsp]
							duk_get_prop_string(ctx, -1, "writeContinue");																						// [emit][this][rsp][writeContinue]
							duk_swap_top(ctx, -2);																												// [emit][this][writeContinue][this]
							duk_call_method(ctx, 0); duk_pop(ctx);																								// [emit][this]
							
							// Since nobody was listening for 'checkContinue', need to process this as a 'request'
							duk_push_string(ctx, "request");																									// [emit][this][request]
							ILibDuktape_HttpStream_IncomingMessage_PUSH(ctx, header, data->DS->ParentObject);													// [emit][this][request][imsg]
							data->bodyStream = ILibDuktape_ReadableStream_InitEx(ctx, ILibDuktape_HttpStream_IncomingMessage_PauseSink, ILibDuktape_HttpStream_IncomingMessage_ResumeSink, ILibDuktape_HttpStream_IncomingMessage_UnshiftBytes, data);
							duk_dup(ctx, -3); duk_dup(ctx, -2);																									// [emit][this][request][imsg][httpstream][imsg]
							duk_put_prop_string(ctx, -2, ILibDuktape_HTTPStream2IMSG); duk_pop(ctx);															// [emit][this][request][imsg]
							
							ILibDuktape_HttpStream_ServerResponse_PUSH(ctx, data->DS->writableStream->pipedReadable, header, data->DS->ParentObject);			// [emit][this][request][imsg][rsp]
							if (duk_pcall_method(ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.httpStream.onReceive->request(): "); }
							duk_pop(ctx);																														// ...
						}																													
					}
				}
				else
				{
					duk_push_string(ctx, "request");																							// [emit][this][request]
					ILibDuktape_HttpStream_IncomingMessage_PUSH(ctx, header, data->DS->ParentObject);											// [emit][this][request][imsg]
					data->bodyStream = ILibDuktape_ReadableStream_InitEx(ctx, ILibDuktape_HttpStream_IncomingMessage_PauseSink, ILibDuktape_HttpStream_IncomingMessage_ResumeSink, ILibDuktape_HttpStream_IncomingMessage_UnshiftBytes, data);
					duk_dup(ctx, -3); duk_dup(ctx, -2);																							// [emit][this][request][imsg][httpstream][imsg]
					duk_put_prop_string(ctx, -2, ILibDuktape_HTTPStream2IMSG); duk_pop(ctx);													// [emit][this][request][imsg]

					ILibDuktape_HttpStream_ServerResponse_PUSH(ctx, data->DS->writableStream->pipedReadable, header, data->DS->ParentObject);	// [emit][this][request][imsg][rsp]

					if (duk_pcall_method(ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.httpStream.onReceive->request(): "); }
					duk_pop(ctx);

					if (bodyBuffer != NULL && endPointer > 0)
					{
						ILibDuktape_readableStream_WriteData(data->bodyStream, bodyBuffer + *beginPointer, endPointer);
					}
				}
			}
		}
	}
	else
	{
		// We are a client

		// First, lets check to see if 'Connection: close' was specified
		char *value;
		int valueLen;
		value = ILibGetHeaderLineEx(header, "connection", 10, &valueLen);
		if (value != NULL && valueLen == 5 && strncasecmp(value, "close", 5) == 0) { data->connectionCloseSpecified = 1; }
		if (header->VersionLength == 3 && strncmp(header->Version, "1.0", 3) == 0) { if (!(value != NULL && valueLen == 10 && strncasecmp(value, "keep-alive", 10) == 0)) { data->connectionCloseSpecified = 1; } }

		if (data->ConnectMethod != 0)
		{
			duk_push_string(ctx, "connect");														// [emit][this][connect]
			ILibDuktape_HttpStream_IncomingMessage_PUSH(ctx, header, data->DS->ParentObject);		// [emit][this][connect][imsg]
			if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.httpStream.onReceive->connect(): "); }
			duk_pop(ctx);
			return;
		}

		switch (header->StatusCode)
		{
			case 100:
				duk_push_string(ctx, "continue");													// [emit][this][continue]
				if (duk_pcall_method(ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.httpStream.onReceive(): "); } 
				duk_pop(ctx);	
				break;
			case 101:
				duk_push_string(ctx, "upgrade");													// [emit][this][upgrade]
				ILibDuktape_HttpStream_IncomingMessage_PUSH(ctx, header, data->DS->ParentObject);	// [emit][this][upgrade][imsg]
				duk_del_prop_string(ctx, -1, ILibDuktape_IMSG2HttpStream); 
				duk_insert(ctx, -4);																// [imsg][emit][this][upgrade]
				duk_dup(ctx, -4);																	// [imsg][emit][this][upgrade][imsg]
				if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.httpStream.onReceive->upgrade(): "); }
				duk_pop(ctx);
				duk_pop(ctx);
				break;
			default:
				duk_push_string(ctx, "response");													// [emit][this][response]
				ILibDuktape_HttpStream_IncomingMessage_PUSH(ctx, header, data->DS->ParentObject);	// [emit][this][response][imsg]
				data->bodyStream = ILibDuktape_ReadableStream_InitEx(ctx, ILibDuktape_HttpStream_IncomingMessage_PauseSink, ILibDuktape_HttpStream_IncomingMessage_ResumeSink, ILibDuktape_HttpStream_IncomingMessage_UnshiftBytes, data);
				duk_push_pointer(ctx, data);
				duk_put_prop_string(ctx, -2, ILibDuktape_IMSG2Ptr);
				duk_dup(ctx, -3);																	// [emit][this][response][imsg][httpstream]
				duk_dup(ctx, -2);																	// [emit][this][response][imsg][httpstream][imsg]
				duk_put_prop_string(ctx, -2, ILibDuktape_HTTPStream2IMSG);							// [emit][this][response][imsg][httpstream]
				duk_pop(ctx);																		// [emit][this][response][imsg]

				ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "~", ILibDuktape_HttpStream_OnReceive_bodyStreamFinalized);
				if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.httpStream.onReceive->response(): "); }
				duk_pop(ctx);

				if (bodyBuffer != NULL && endPointer > 0)
				{
					ILibDuktape_readableStream_WriteData(data->bodyStream, bodyBuffer + *beginPointer, endPointer);
				}
				break;
		}
	}

	if (data->bodyStream != NULL && recvStatus == ILibWebClient_ReceiveStatus_Complete)
	{
		ILibDuktape_readableStream_WriteEnd(data->bodyStream);
		data->endPropagated = 1;
	}
	if (recvStatus == ILibWebClient_ReceiveStatus_Complete)
	{
		if (ILibIsRunningOnChainThread(data->chain) != 0)
		{
			// We're on the Chain Thread, so we can directly emit the 'end' event
			data->bodyStream = NULL;

			duk_push_heapptr(ctx, data->DS->ParentObject);					// [httpStream]
			duk_get_prop_string(ctx, -1, "emit");							// [httpStream][emit]
			duk_swap_top(ctx, -2);											// [emit][this]
			duk_push_string(ctx, "end");									// [emit]][this][end]
			if (duk_pcall_method(ctx, 1) != 0) ILibDuktape_Process_UncaughtExceptionEx(ctx, "httpStream.onReceive(): Error dispatching 'end': %s", duk_safe_to_string(ctx, -1));
			duk_pop(ctx);													// ...

			if (header->Directive == NULL && data->connectionCloseSpecified == 0)
			{
				duk_push_heapptr(ctx, data->DS->ParentObject);					// [httpStream]
				duk_get_prop_string(ctx, -1, ILibDuktape_HTTPStream2Socket);	// [httpStream][socket]
				if (duk_has_prop_string(ctx, -1, ILibDuktape_Socket2Agent))
				{
					duk_get_prop_string(ctx, -1, ILibDuktape_Socket2Agent);		// [httpStream][socket][agent]
					duk_get_prop_string(ctx, -1, "keepSocketAlive");			// [httpStream][socket][agent][keepSocketAlive]
					duk_swap_top(ctx, -2);										// [httpStream][socket][keepSocketAlive][this]
					duk_dup(ctx, -3);											// [httpStream][socket][keepSocketAlive][this][socket]
					if (duk_pcall_method(ctx, 1) != 0) {}
					duk_pop(ctx);												// [httpStream][socket]
					duk_pop_2(ctx);												// ...
				}			
			}

		}
		else
		{
			// We're on the wrong thread to dispatch the 'end' event, so we have to context switch
			void **tmp = (void**)ILibMemory_Allocate(3 * sizeof(void*), 0, NULL, NULL);
			tmp[0] = ctx;
			tmp[1] = data->DS;
			tmp[2] = data;
			ILibChain_RunOnMicrostackThread(data->chain, ILibDuktape_HttpStream_DispatchEnd, tmp);
		}
	}
}
duk_ret_t ILibDuktape_HttpStream_Finalizer(duk_context *ctx)
{
	duk_del_prop_string(ctx, 0, ILibDuktape_HTTPStream2IMSG);
	duk_get_prop_string(ctx, 0, ILibDuktape_HTTPStream2Data);
	ILibDuktape_HttpStream_Data *data = (ILibDuktape_HttpStream_Data*)Duktape_GetBuffer(ctx, -1, NULL);

	ILibWebClient_DestroyWebClientDataObject(data->WCDO);
	return(0);
}

duk_ret_t ILibDuktape_HttpStream_connectionCloseSpecified(duk_context *ctx)
{
	ILibDuktape_HttpStream_Data *data;

	duk_push_this(ctx);															// [httpstream]
	duk_get_prop_string(ctx, -1, ILibDuktape_HTTPStream2Data);					// [httpstream][data]
	data = (ILibDuktape_HttpStream_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_push_boolean(ctx, data->connectionCloseSpecified);
	return(1);
}
void ILibDuktape_HttpStream_piped(struct ILibDuktape_readableStream *sender, void *writableStream, void *user)
{
	duk_push_heapptr(sender->ctx, sender->object);							// [httpStream]
	duk_push_heapptr(sender->ctx, writableStream);							// [httpStream][dest]
	duk_put_prop_string(sender->ctx, -2, ILibDuktape_HTTP2PipedWritable);	// [httpStream]
	duk_pop(sender->ctx);													// ...
}
duk_ret_t ILibDuktape_HttpStream_pipeEvent(duk_context *ctx)
{
	duk_push_this(ctx);												// [httpStream]
	duk_dup(ctx, 0);												// [httpStream][readable]
	duk_put_prop_string(ctx, -2, ILibDuktape_HTTP2PipedReadable);	// [httpStream]
	return(0);
}
duk_ret_t ILibduktape_HttpStream_create(duk_context *ctx)
{
	ILibDuktape_HttpStream_Data *data;
	duk_push_object(ctx);														// [httpStream] 
	duk_push_this(ctx);															// [httpStream][http]
	duk_put_prop_string(ctx, -2, ILibDuktape_HTTPStream2HTTP);					// [httpStream]
	ILibDuktape_WriteID(ctx, "http.httpStream");
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_Create(ctx);
	data = (ILibDuktape_HttpStream_Data*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_HttpStream_Data));
	duk_put_prop_string(ctx, -2, ILibDuktape_HTTPStream2Data);					// [httpStream]

	ILibDuktape_EventEmitter_CreateEventEx(emitter, "end");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "error");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "continue");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "response");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "upgrade");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "checkContinue");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "checkExpectation");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "clientError");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "request");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "connect");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "write");

	data->DS = ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_HttpStream_WriteSink, ILibDuktape_HttpStream_EndSink,
		NULL, NULL, NULL, data);
	data->DS->readableStream->PipeHookHandler = ILibDuktape_HttpStream_piped;
	data->WCDO = ILibCreateWebClientEx(ILibDuktape_HttpStream_OnReceive, (ILibAsyncSocket_SocketModule)NULL, data, NULL);
	data->chain = Duktape_GetChain(ctx);

	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "pipe", ILibDuktape_HttpStream_pipeEvent);

	ILibDuktape_CreateEventWithGetter(ctx, "connectionCloseSpecified", ILibDuktape_HttpStream_connectionCloseSpecified);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_HttpStream_Finalizer);
	return(1);
}
duk_ret_t ILibDuktape_HttpStream_Agent_getName(duk_context *ctx)
{
	char *host = Duktape_GetStringPropertyValue(ctx, 0, "host", "127.0.0.1");
	int port = Duktape_GetIntPropertyValue(ctx, 0, "port", 0);

	sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s:%d:%s", host, port, Duktape_GetStringPropertyValue(ctx, 0, "localAddress", "0.0.0.0"));
	
	duk_push_string(ctx, ILibScratchPad2);
	return(1);
}
int ILibDuktape_RemoveObjFromArray(duk_context *ctx, void *arrObj, void *obj)
{
	int retVal = -1;
	int len, i;
	duk_push_heapptr(ctx, arrObj);								// [array]
	len = (int)duk_get_length(ctx, -1);
	for (i = 0; i < len; ++i)
	{
		duk_get_prop_index(ctx, -1, i);							// [array][obj]
		if (duk_get_heapptr(ctx, -1) == obj)					
		{
			duk_pop(ctx);										// [array]
			duk_get_prop_string(ctx, -1, "splice");				// [array][splice]
			duk_dup(ctx, -2);									// [array][splice][this]
			duk_push_int(ctx, i);								// [array][splice][this][i]
			duk_push_int(ctx, 1);								// [array][splice][this][i][1]
			duk_call_method(ctx, 2); duk_pop(ctx);				// [array]
			break;
		}
		duk_pop(ctx);											// [array]
	}
	retVal = (int)duk_get_length(ctx, -1);
	duk_pop(ctx);												// ...
	return(retVal);
}
void ILibDuktape_RemoveObjFromTable(duk_context *ctx, duk_idx_t tableIdx, char *key, void *obj)
{
	if (duk_has_prop_string(ctx, tableIdx, key))
	{
		duk_get_prop_string(ctx, tableIdx, key);										// [Array]
		if (ILibDuktape_RemoveObjFromArray(ctx, duk_get_heapptr(ctx, -1), obj) == 0)
		{
			duk_pop(ctx);																// ...
			duk_del_prop_string(ctx, tableIdx, key);
		}
		else
		{
			duk_pop(ctx);																// ...
		}
	}
}
duk_ret_t ILibDuktape_HttpStream_Agent_socketEndSink(duk_context *ctx)
{
	duk_push_this(ctx);												// [socket]
	//printf("socket has closed: %p\n", duk_get_heapptr(ctx, -1));
	duk_get_prop_string(ctx, -1, ILibDuktape_Socket2Agent);			// [socket][agent]
	duk_get_prop_string(ctx, -2, ILibDuktape_Socket2AgentKey);		// [socket][agent][key]
	char *key = Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop(ctx);													// [socket][agent[]

	// Check to see if this socket was in the freeSockets table
	duk_get_prop_string(ctx, -1, "freeSockets");					// [socket][agent][freeSockets]
	ILibDuktape_RemoveObjFromTable(ctx, -1, key, duk_get_heapptr(ctx, 0));
	duk_pop(ctx);													// [socket][agent]

	// Check to see if this socket was in the sockets table
	duk_get_prop_string(ctx, -1, "sockets");						// [socket][agent][socketsTable]
	ILibDuktape_RemoveObjFromTable(ctx, -1, key, duk_get_heapptr(ctx, 0));
	duk_pop(ctx);													// [socket][agent]

	// Now that we cleared this socket out of all the tables, we need to check to see if we need to create a new connection
	duk_get_prop_string(ctx, -1, "requests");						// [socket][agent][requestTable]
	if (duk_has_prop_string(ctx, -1, key))
	{
		duk_get_prop_string(ctx, -1, key);							// [socket][agent][requestTable][array]
		if (duk_get_length(ctx, -1) > 0)
		{
			// There is at least one request waiting for a socket
			duk_get_prop_string(ctx, -3, "sockets");				// [socket][agent][requestTable][array][socketsTable]
			duk_get_prop_string(ctx, -1, key);						// [socket][agent][requestTable][array][socketsTable][array]
			if (duk_is_undefined(ctx, -1) || (duk_get_length(ctx, -1) < (size_t)Duktape_GetIntPropertyValue(ctx, -5, "maxSockets", 1)))
			{
				// We need to create a new socket
				duk_pop_n(ctx, 4);											// [socket][agent]
				duk_dup(ctx, -1);											// [socket][agent][agent]
				duk_get_prop_string(ctx, -1, "createConnection");			// [socket][agent][agent][createConnection]
				duk_swap_top(ctx, -2);										// [socket][agent][createConnection][this]
				duk_get_prop_string(ctx, -4, "\xFF_NET_SOCKET2OPTIONS");	// [socket][agent][createConnection][this][options]
				duk_push_c_function(ctx, ILibDuktape_HttpStream_http_OnConnect, DUK_VARARGS); // We need to register here, because TLS/NonTLS have different event names
				duk_call_method(ctx, 2);									// [socket][agent][newsocket]
				duk_swap_top(ctx, -2);										// [socket][newsocket][agent]
				duk_put_prop_string(ctx, -2, ILibDuktape_Socket2Agent);		// [socket][newsocket]
				ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "error", ILibDuktape_HttpStream_http_OnConnectError);
			}
		}
	}

	return(0);
}
duk_ret_t ILibDuktape_HttpStream_Agent_keepSocketAlive_timeout(duk_context *ctx)
{
	duk_push_this(ctx);						// [socket]
	duk_get_prop_string(ctx, -1, "end");	// [socket][end]
	duk_swap_top(ctx, -2);					// [end][this]
	duk_call_method(ctx, 0); 
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_Agent_keepSocketAlive(duk_context *ctx)
{
	int retVal = 0;
	char *remoteAddress = Duktape_GetStringPropertyValue(ctx, 0, "remoteAddress", "127.0.0.1");
	char *remoteHost = Duktape_GetStringPropertyValue(ctx, 0, "remoteHost", remoteAddress);
	char *key;

	if (duk_has_prop_string(ctx, 0, ILibDuktape_Socket2AgentKey))
	{
		key = (char*)Duktape_GetStringPropertyValue(ctx, 0, ILibDuktape_Socket2AgentKey, NULL);
	}
	else
	{
		duk_push_this(ctx);							// [Agent]
		duk_get_prop_string(ctx, -1, "getName");	// [Agent][getName]
		duk_swap_top(ctx, -2);						// [getName][this]
		duk_push_object(ctx);						// [getName][this][options]
		duk_push_string(ctx, remoteHost);			// [getName][this][options][host]
		duk_put_prop_string(ctx, -2, "host");		// [getName][this][options]
		duk_get_prop_string(ctx, 0, "remotePort");	// [getName][this][options][port]
		duk_put_prop_string(ctx, -2, "port");		// [getName][this][options]
		duk_call_method(ctx, 1);					// [key]
		key = (char*)duk_get_string(ctx, -1);
	}

	duk_push_this(ctx);							// [key][Agent]
	if (duk_has_prop_string(ctx, 0, ILibDuktape_Agent_SocketJustCreated))
	{
		duk_del_prop_string(ctx, 0, ILibDuktape_Agent_SocketJustCreated);
	}
	else if (Duktape_GetBooleanProperty(ctx, -1, "keepAlive", 0) == 0)
	{
		duk_get_prop_string(ctx, 0, "end");		// [end]
		duk_dup(ctx, 0);						// [end][this]
		duk_call_method(ctx, 0);
		return(0);
	}


	duk_get_prop_string(ctx, -1, "requests");	// [key][Agent][requests]
	//ILibDuktape_Log_Object(ctx, -1, "Agent/Requests");

	if (duk_has_prop_string(ctx, -1, key))
	{
		// Has Key, check the Array
		duk_get_prop_string(ctx, -1, key);		// [key][Agent][requests][Array]
		//ILibDuktape_Log_Object(ctx, -1, "Agent/Request/ArrayIndex");

		duk_get_prop_string(ctx, -1, "shift");	// [key][Agent][requests][Array][shift]
		duk_swap_top(ctx, -2);					// [key][Agent][requests][shift][this]
		duk_call_method(ctx, 0);				// [key][Agent][requests][request]
		if (!duk_is_undefined(ctx, -1))
		{
			// There was a request
			duk_push_this(ctx);							// [key][Agent][requests][request][Agent]
			duk_get_prop_string(ctx, -1, "reuseSocket");// [key][Agent][requests][request][Agent][reuseSocket]
			duk_swap_top(ctx, -2);						// [key][Agent][requests][request][reuseSocket][this]
			duk_dup(ctx, 0);							// [key][Agent][requests][request][reuseSocket][this][socket]
			duk_dup(ctx, -4);							// [key][Agent][requests][request][reuseSocket][this][socket][request]
			duk_call_method(ctx, 2);					// [key][Agent][requests][request][retVal]
			retVal = 1;
			duk_pop(ctx);								// [key][Agent][requests][request]
		}
	}
	if (retVal == 0)
	{
		// No Requests Found
		duk_push_this(ctx);								// [Agent]
		duk_get_prop_string(ctx, -1, "freeSockets");	// [Agent][table]
		if (!duk_has_prop_string(ctx, -1, key))
		{
			duk_push_array(ctx);						// [Agent][table][Array]
			duk_dup(ctx, -1);							// [Agent][table][Array][Array]
			duk_put_prop_string(ctx, -3, key);			// [Agent][table][Array]
		}
		else
		{
			duk_get_prop_string(ctx, -1, key);			// [Agent][table][Array]
		}
		duk_get_prop_string(ctx, -1, "push");			// [Agent][table][Array][push]
		duk_swap_top(ctx, -2);							// [Agent][table][push][this]
		duk_dup(ctx, 0);								// [AGent][table][push][this][socket]

		duk_get_prop_string(ctx, -1, "setTimeout");														// [AGent][table][push][this][socket][setTimeout]
		duk_dup(ctx, -2);																				// [AGent][table][push][this][socket][setTimeout][this]
		duk_get_prop_string(ctx, -7, "keepAliveMsecs");													// [AGent][table][push][this][socket][setTimeout][this][milliseconds]
		duk_push_c_function(ctx, ILibDuktape_HttpStream_Agent_keepSocketAlive_timeout, DUK_VARARGS);	// [AGent][table][push][this][socket][setTimeout][this][milliseconds][callback]
		duk_call_method(ctx, 2); duk_pop(ctx);															// [AGent][table][push][this][socket]

		duk_call_method(ctx, 1);						// [Agent][table][retVal]
		retVal = 1;
	}
	duk_push_int(ctx, retVal);
	return(1);
}
void ILibDuktape_HttpStream_Agent_reuseSocketEx(duk_context *ctx, void ** args, int argsLen)
{
	duk_push_this(ctx);									// [immediate]
	duk_del_prop_string(ctx, -1, "CR");
	duk_del_prop_string(ctx, -2, "Socket");
	duk_pop(ctx);										// ...

	duk_push_heapptr(ctx, args[1]);						// [clientRequest]
	duk_push_heapptr(ctx, args[0]);						// [clientRequest][socket]

	duk_get_prop_string(ctx, -1, "setTimeout");			// [clientRequest][socket][setTimeout]
	duk_dup(ctx, -2);									// [clientRequest][socket][setTimeout][this]
	duk_push_int(ctx, 0);								// [clientRequest][socket][setTimeout][this][0] (Disable Idle Timeout)
	duk_call_method(ctx, 1); duk_pop(ctx);				// [clientRequest][socket]

	ILibDuktape_CreateReadonlyProperty(ctx, "socket");	// [clientRequest]

	duk_get_prop_string(ctx, -1, "emit");				// [clientRequest][emit]
	duk_swap_top(ctx, -2);								// [emit][this]
	duk_push_string(ctx, "socket");						// [emit][this][name]
	duk_push_heapptr(ctx, args[0]);						// [emit][this][name][socket]
	if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "Agent.reuseSocket() => Error emitting 'socket' on clientRequest: %s", duk_safe_to_string(ctx, -1)); }
	duk_pop(ctx);										// ...
}
duk_ret_t ILibDuktape_HttpStream_Agent_reuseSocket(duk_context *ctx)
{
	// Yield to the next loop, before we emit a 'socket' event, because emitting this event before anyone has the clientRequest object is pointless
	void *imm = ILibDuktape_Immediate(ctx, (void*[]) { duk_get_heapptr(ctx, 0), duk_get_heapptr(ctx, 1) }, 2, ILibDuktape_HttpStream_Agent_reuseSocketEx);
	duk_push_heapptr(ctx, imm);				// [immediate]
	duk_dup(ctx, 1);						// [immediate][ClientRequest]
	duk_put_prop_string(ctx, -2, "CR");		// [immediate]
	duk_dup(ctx, 0);						// [immediate][Socket]
	duk_put_prop_string(ctx, -2, "Socket");	// [immediate]
	duk_pop(ctx);
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_Agent_createConnection_eventSink(duk_context *ctx)
{
	duk_push_this(ctx);																		// [socket]
	char *key = Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_Socket2AgentKey, "");
	duk_get_prop_string(ctx, -1, ILibDuktape_Socket2Agent);									// [socket][agent]
	duk_get_prop_string(ctx, -1, "sockets");												// [socket][agent][socketsTable]
	ILibDuktape_RemoveObjFromTable(ctx, -1, key, duk_get_heapptr(ctx, -3));
	return(0);
}
duk_ret_t ILibDuktape_HttpStream_Agent_createConnection(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int i;
	duk_size_t protocolLen;
	char *protocol = Duktape_GetStringPropertyValueEx(ctx, 0, "protocol", "http:", &protocolLen);

	duk_push_this(ctx);																			// [Agent]
	if ((protocolLen == 6 && strncasecmp("https:", protocol, 6) == 0) || (protocolLen == 4 && strncasecmp("wss:", protocol, 4) == 0))
	{
		duk_eval_string(ctx, "require('tls');");													// [Agent][net]
		duk_get_prop_string(ctx, -1, "connect");													// [Agent][net][createConnection]
	}
	else
	{
		duk_eval_string(ctx, "require('net');");													// [Agent][net]
		duk_get_prop_string(ctx, -1, "createConnection");											// [Agent][net][createConnection]
	}
	duk_swap_top(ctx, -2);																		// [Agent][createConnection][this]
	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);
	}
	duk_call_method(ctx, nargs);																// [Agent][Socket]
	duk_push_true(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_Agent_SocketJustCreated);
	duk_get_prop_string(ctx, -2, "getName");													// [Agent][Socket][getName]
	duk_dup(ctx, -3);																			// [Agent][Socket][getName][this]
	duk_dup(ctx, 0);																			// [Agent][Socket][getName][this][options]
	duk_call_method(ctx, 1);																	// [Agent][Socket][key]
	duk_put_prop_string(ctx, -2, ILibDuktape_Socket2AgentKey);									// [Agent][Socket]
	duk_dup(ctx, -2);																			// [Agent][Socket][Agent]
	duk_put_prop_string(ctx, -2, ILibDuktape_Socket2Agent);										// [Agent][Socket]

	duk_get_prop_string(ctx, -2, "sockets");													// [Agent][Socket][socketsTable]
	duk_get_prop_string(ctx, -2, ILibDuktape_Socket2AgentKey);									// [Agent][Socket][socketsTable][key]
	if (!duk_has_prop(ctx, -2))																	// [Agent][Socket][socketsTable]
	{
		duk_get_prop_string(ctx, -2, ILibDuktape_Socket2AgentKey);								// [Agent][Socket][socketsTable][key]
		duk_push_array(ctx);																	// [Agent][Socket][socketsTable][key][array]
		duk_put_prop(ctx, -3);																	// [Agent][Socket][socketsTable]
	}
	duk_get_prop_string(ctx, -2, ILibDuktape_Socket2AgentKey);									// [Agent][Socket][socketsTable][key]
	duk_get_prop(ctx, -2);																		// [Agent][Socket][socketsTable][array]
	duk_get_prop_string(ctx, -1, "push");														// [Agent][Socket][socketsTable][array][push]
	duk_swap_top(ctx, -2);																		// [Agent][Socket][socketsTable][push][this]
	duk_dup(ctx, -4);																			// [Agent][Socket][socketsTable][push][this][socket]
	duk_call_method(ctx, 1); duk_pop_2(ctx);													// [Agent][Socket]

	ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "error", ILibDuktape_HttpStream_Agent_createConnection_eventSink);
	ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "close", ILibDuktape_HttpStream_Agent_socketEndSink);

	return(1);
}
duk_ret_t ILibDuktape_HttpStream_Agent_new(duk_context *ctx)
{
	if (duk_get_top(ctx) > 0 && duk_is_object(ctx, 0)) { duk_dup(ctx, 0); } else { duk_push_object(ctx); }
	int keepAlive = Duktape_GetBooleanProperty(ctx, -1, "keepAlive", 1);
	int keepAliveMsecs = Duktape_GetIntPropertyValue(ctx, -1, "keepAliveMsecs", 15000);
	int maxSockets = Duktape_GetIntPropertyValue(ctx, -1, "maxSockets", 1);
	int maxFreeSockets = Duktape_GetIntPropertyValue(ctx, -1, "maxFreeSockets", 32);

	duk_push_object(ctx);							// [Agent]
	ILibDuktape_WriteID(ctx, "http.Agent");
	duk_push_boolean(ctx, (duk_bool_t)keepAlive);	// [Agent][keepAlive]
	duk_put_prop_string(ctx, -2, "keepAlive");		// [Agent]
	duk_push_int(ctx, keepAliveMsecs);				// [Agent][keepAliveMsecs]
	duk_put_prop_string(ctx, -2, "keepAliveMsecs");	// [Agent]
	duk_push_int(ctx, maxSockets);					// [Agent][maxSockets]
	duk_put_prop_string(ctx, -2, "maxSockets");		// [Agent]
	duk_push_int(ctx, maxFreeSockets);				// [Agent][maxFreeSockets]
	duk_put_prop_string(ctx, -2, "maxFreeSockets");	// [Agent]

	duk_push_object(ctx);							// [Agent][freeSockets]
	duk_put_prop_string(ctx, -2, "freeSockets");	// [Agent]
	duk_push_object(ctx);							// [Agent][requests]
	duk_put_prop_string(ctx, -2, "requests");		// [Agent]
	duk_push_object(ctx);							// [Agent][sockets]
	duk_put_prop_string(ctx, -2, "sockets");		// [Agent]

	ILibDuktape_CreateInstanceMethod(ctx, "getName", ILibDuktape_HttpStream_Agent_getName, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "keepSocketAlive", ILibDuktape_HttpStream_Agent_keepSocketAlive, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "reuseSocket", ILibDuktape_HttpStream_Agent_reuseSocket, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "createConnection", ILibDuktape_HttpStream_Agent_createConnection, DUK_VARARGS);

	return(1);
}
duk_ret_t ILibDuktape_httpStream_parseUri(duk_context *ctx)
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


ILibTransport_DoneState ILibDuktape_httpStream_webSocket_WriteWebSocketPacket(ILibDuktape_WebSocket_State *state, int opcode, char *_buffer, int _bufferLen, ILibWebClient_WebSocket_FragmentFlags _bufferFragment)
{
	state->noMasking = 1;
	char header[10];
	int maskKeyInt;
	int headerLen;
	unsigned short flags = state->noMasking == 0 ? WEBSOCKET_MASK : 0;

	char *buffer;
	int bufferLen;
	ILibTransport_DoneState retVal = ILibTransport_DoneState_ERROR;

	ILibWebClient_WebSocket_FragmentFlags bufferFragment;


	buffer = _buffer;
	bufferLen = _bufferLen;
	bufferFragment = _bufferFragment;

	if (bufferFragment == ILibWebClient_WebSocket_FragmentFlag_Complete)
	{
		if (state->WebSocketFragmentFlag_Write == 0)
		{
			// This is a self contained fragment
			headerLen = ILibWebServer_WebSocket_CreateHeader(header, flags | WEBSOCKET_FIN, (unsigned short)opcode, bufferLen);
		}
		else
		{
			// Termination of an ongoing Fragment
			state->WebSocketFragmentFlag_Write = 0;
			headerLen = ILibWebServer_WebSocket_CreateHeader(header, flags | WEBSOCKET_FIN, WEBSOCKET_OPCODE_FRAMECONT, bufferLen);
		}
	}
	else
	{
		if (state->WebSocketFragmentFlag_Write == 0)
		{
			// Start a new fragment
			state->WebSocketFragmentFlag_Write = 1;
			headerLen = ILibWebServer_WebSocket_CreateHeader(header, flags, (unsigned short)opcode, bufferLen);
		}
		else
		{
			// Continuation of an ongoing fragment
			headerLen = ILibWebServer_WebSocket_CreateHeader(header, flags, WEBSOCKET_OPCODE_FRAMECONT, bufferLen);
		}
	}

	if (flags & WEBSOCKET_MASK) 
	{
		// We have to copy memory anyways to mask, so we might as well copy the extra few bytes and make a single buffer
		char *dataFrame = ILibMemory_AllocateA(headerLen + bufferLen);
		char *maskKey = (dataFrame + headerLen);
		memcpy_s(dataFrame, headerLen, header, headerLen);

		// Mask the payload
		util_random(4, maskKey);
		maskKeyInt = ((int*)(maskKey))[0];
		if (bufferLen > 0) 
		{
			int x;
			for (x = 0; x < (bufferLen >> 2); ++x) { ((int*)(dataFrame+headerLen+4))[x] = ((int*)buffer)[x] ^ (int)maskKeyInt; } // Mask 4 bytes at a time
			for (x = (x << 2); x < bufferLen; ++x) { dataFrame[x + headerLen + 4] = buffer[x] ^ maskKey[x % 4]; } // Mask the reminder
		}
		retVal = ILibDuktape_DuplexStream_WriteData(state->encodedStream, dataFrame, headerLen + 4 + bufferLen) == 0 ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
	}
	else 
	{
		// Send payload without masking
		if (ILibIsRunningOnChainThread(state->chain) != 0)
		{
			// We're on the Duktape Thread, so we can just call write multiple times, cuz we won't interleave with JavaScript
			if (bufferLen > 0)
			{
				ILibDuktape_DuplexStream_WriteData(state->encodedStream, header, headerLen);
				retVal = ILibDuktape_DuplexStream_WriteData(state->encodedStream, buffer, bufferLen) == 0 ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
			}
			else
			{
				retVal = ILibDuktape_DuplexStream_WriteData(state->encodedStream, header, headerLen) == 0 ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
			}
		}
		else
		{
			// We're not on the Duktape Thread, so we need to merge these buffers, to make a single write
			char *dataFrame = ILibMemory_SmartAllocate(headerLen + bufferLen);
			memcpy_s(dataFrame, headerLen, header, headerLen);
			memcpy_s(dataFrame + headerLen, bufferLen, buffer, bufferLen);
			retVal = ILibDuktape_DuplexStream_WriteData(state->encodedStream, dataFrame, headerLen + bufferLen) == 0 ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
			ILibMemory_Free(dataFrame);
		}
	}

	return retVal;
}
ILibTransport_DoneState ILibDuktape_httpStream_webSocket_EncodedWriteSink_DispatchUnshift(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen)
{
	if (stream->writableStream->pipedReadable != NULL || stream->writableStream->pipedReadable_native != NULL)
	{
		if (stream->writableStream->pipedReadable != NULL)
		{
			duk_context *ctx = stream->writableStream->ctx;
			if (ILibIsRunningOnChainThread(stream->readableStream->chain) != 0)
			{
				// We can dispatch directly
				duk_push_external_buffer(ctx);														// [ext]
				duk_config_buffer(ctx, -1, buffer, (duk_size_t)bufferLen);
				duk_push_heapptr(ctx, stream->writableStream->pipedReadable);						// [ext][readable]
				duk_get_prop_string(ctx, -1, "unshift");											// [ext][readable][unshift]
				duk_swap_top(ctx, -2);																// [ext][unshift][this]
				duk_push_buffer_object(ctx, -3, 0, (duk_size_t)bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);// [ext][unshift][this][buffer]
				if (duk_pcall_method(ctx, 1) != 0)
				{
					ILibDuktape_Error(ctx, "http.webSocketStream.encoded.write() => Error calling unshift: %s", duk_safe_to_string(ctx, -1));
					return(ILibTransport_DoneState_ERROR);
				}
				duk_pop_2(ctx);																		// ...
				return(ILibTransport_DoneState_COMPLETE);
			}
			else
			{
				return(ILibTransport_DoneState_ERROR);	// Something is wrong, if we're called by a JavaScript object on an external thread
			}
		}

		// We were dispatched directly by a native ReadableStream
		if (stream->writableStream->pipedReadable_native->UnshiftHandler == NULL ||
			stream->writableStream->pipedReadable_native->UnshiftHandler(stream->writableStream->pipedReadable_native, bufferLen, stream->writableStream->pipedReadable_native->user) <= 0)
		{
			return(ILibTransport_DoneState_ERROR);
		}
		else
		{
			return(ILibTransport_DoneState_COMPLETE);
		}
	}
	else
	{
		// We can't unshift, so we need to buffer. But we won't...
		return(ILibTransport_DoneState_ERROR);
	}
}

ILibTransport_DoneState ILibDuktape_httpStream_webSocket_EncodedWriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	int x;
	int i = 2;
	int plen;
	unsigned short hdr;
	char* maskingKey = NULL;
	int FIN;
	unsigned char OPCODE;
	unsigned char RSV;
	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)user;

	if (!ILibMemory_CanaryOK(state)) { return(ILibTransport_DoneState_ERROR); }

	if (bufferLen < 2) 
	{ 
		// We need at least 2 bytes to read enough of the headers to know how long the frame is
		return(ILibDuktape_httpStream_webSocket_EncodedWriteSink_DispatchUnshift(stream, buffer, bufferLen));
	} 

	hdr = ntohs(((unsigned short*)(buffer))[0]);
	FIN = (hdr & WEBSOCKET_FIN) != 0;
	OPCODE = (hdr & WEBSOCKET_OPCODE) >> 8;
	RSV = (hdr & WEBSOCKET_RSV) >> 8;

	if (RSV != 0)
	{
		char msg[] = "Reserved Field of Websocket was not ZERO";
		Duktape_Console_Log(state->ctx, state->chain, ILibDuktape_LogType_Error, msg, sizeof(msg) - 1);
		return(ILibTransport_DoneState_ERROR);
	}

	plen = (unsigned char)(hdr & WEBSOCKET_PLEN);
	if (plen == 126)
	{
		if (bufferLen < 4) { return(ILibDuktape_httpStream_webSocket_EncodedWriteSink_DispatchUnshift(stream, buffer, bufferLen)); } // We need at least 4 bytes to read enough of the headers
		plen = (unsigned short)ntohs(((unsigned short*)(buffer))[1]);
		i += 2;
	}
	else if (plen == 127)
	{
		if (bufferLen < 10)
		{
			return(ILibDuktape_httpStream_webSocket_EncodedWriteSink_DispatchUnshift(stream, buffer, bufferLen)); // We need at least 10 bytes to read enough of the headers
		}
		else
		{
			unsigned long long v = ILibNTOHLL(((unsigned long long*)(buffer + 2))[0]);
			if (v > 0x7FFFFFFFUL)
			{
				// this value is too big to store in a 32 bit signed variable, so disconnect the websocket.
				return(ILibTransport_DoneState_ERROR);
			}
			else
			{
				// this value can be represented with a signed 32 bit variable
				plen = (int)v;
				i += 8;
			}
		}
	}

	if (bufferLen < (i + plen + ((unsigned char)(hdr & WEBSOCKET_MASK) != 0 ? 4 : 0)))
	{
		return(ILibDuktape_httpStream_webSocket_EncodedWriteSink_DispatchUnshift(stream, buffer, bufferLen)); // Don't have the entire packet
	}

	maskingKey = ((unsigned char)(hdr & WEBSOCKET_MASK) == 0) ? NULL : (buffer + i);
	if (maskingKey != NULL)
	{
		// Unmask the data
		i += 4;	// Move ptr to start of data

		int maskKeyInt = ((int*)(maskingKey))[0];
		if (plen > 0)
		{
			for (x = 0; x < (plen >> 2); ++x) { ((int*)(buffer+i))[x] = ((int*)(buffer+i))[x] ^ (int)maskKeyInt; } // Mask 4 bytes at a time
			for (x = (x << 2); x < plen; ++x) { buffer[x + i] = buffer[x + i] ^ maskingKey[x % 4]; } // Mask the reminder
		}
	}

	if (OPCODE < 0x8)
	{
		// NON-CONTROL OP-CODE
		// We will try to automatically re-assemble fragments, up to the max buffer size the user specified
		if (OPCODE != 0) { state->WebSocketDataFrameType = (int)OPCODE; } // Set the DataFrame Type, so the user can query it

		if (FIN != 0 && state->WebSocketFragmentIndex == 0)
		{
			// We have an entire fragment, and we didn't save any of it yet... We can just forward it up without copying the buffer
			ILibDuktape_DuplexStream_WriteDataEx(state->decodedStream, OPCODE == WEBSOCKET_OPCODE_TEXTFRAME ? 1 : 0, buffer + i, plen);
		}
		else
		{
			if (state->WebSocketFragmentIndex + plen >= state->WebSocketFragmentBufferSize)
			{
				// Need to grow the buffer
				state->WebSocketFragmentBufferSize = state->WebSocketFragmentBufferSize * 2;
				if ((state->WebSocketFragmentBuffer = (char*)realloc(state->WebSocketFragmentBuffer, state->WebSocketFragmentBufferSize)) == NULL) { ILIBCRITICALEXIT(254); } // MS Static Analyser erroneously reports that this leaks the original memory block
			}

			memcpy_s(state->WebSocketFragmentBuffer + state->WebSocketFragmentIndex, state->WebSocketFragmentBufferSize - state->WebSocketFragmentIndex, buffer + i, plen);
			state->WebSocketFragmentIndex += plen;

			if (FIN != 0)
			{
				ILibDuktape_DuplexStream_WriteDataEx(state->decodedStream, OPCODE == WEBSOCKET_OPCODE_TEXTFRAME ? 1 : 0, state->WebSocketFragmentBuffer, state->WebSocketFragmentIndex);
				state->WebSocketFragmentIndex = 0; // Reset (We can write to the start of the buffer)
			}
		}
	}
	else
	{
		// CONTROL
		switch (OPCODE)
		{
		case WEBSOCKET_OPCODE_CLOSE:
			state->closed = 1;
			ILibDuktape_DuplexStream_WriteEnd(state->decodedStream);
			if (ILibIsRunningOnChainThread(state->chain) != 0 && state->encodedStream->writableStream->pipedReadable != NULL)
			{
				duk_push_heapptr(state->ctx, state->encodedStream->writableStream->pipedReadable);	// [stream]
				duk_get_prop_string(state->ctx, -1, "end");											// [stream][end]
				duk_swap_top(state->ctx, -2);														// [end][this]
				if (duk_pcall_method(state->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(state->ctx, "http.webSocketStream.write(): Error Dispatching 'end' "); }
				duk_pop(state->ctx);																// ...
			}
			break;
		case WEBSOCKET_OPCODE_PING:
			if (ILibIsRunningOnChainThread(state->chain) != 0)
			{
				duk_push_heapptr(state->ctx, state->decodedStream->ParentObject);		// [stream]
				duk_get_prop_string(state->ctx, -1, "emit");							// [stream][emit]
				duk_swap_top(state->ctx, -2);											// [emit][this]
				duk_push_string(state->ctx, "ping");									// [emit][this][ping]

				if (duk_pcall_method(state->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(state->ctx, "http.webSocketStream.write(): Error Dispatching Ping "); }
				duk_pop(state->ctx);													// ...
			}

			ILibDuktape_httpStream_webSocket_WriteWebSocketPacket(state, WEBSOCKET_OPCODE_PONG, NULL, 0, ILibWebClient_WebSocket_FragmentFlag_Complete);
			break;
		case WEBSOCKET_OPCODE_PONG:
			if (ILibIsRunningOnChainThread(state->chain) != 0)
			{
				duk_push_heapptr(state->ctx, state->decodedStream->ParentObject);		// [stream]
				duk_get_prop_string(state->ctx, -1, "emit");							// [stream][emit]
				duk_swap_top(state->ctx, -2);											// [emit][this]
				duk_push_string(state->ctx, "pong");									// [emit][this][pong]

				if (duk_pcall_method(state->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(state->ctx, "http.webSocketStream.write(): Error Dispatching Pong "); }
				duk_pop(state->ctx);													// ...
			}
			break;
		}
	}

	if (bufferLen > (i + plen))
	{
		return(ILibDuktape_httpStream_webSocket_EncodedWriteSink_DispatchUnshift(stream, buffer + i + plen, bufferLen - (i + plen))); // We need at least 10 bytes to read enough of the headers
	}

	return(ILibTransport_DoneState_COMPLETE);
}
void ILibDuktape_httpStream_webSocket_EncodedEndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)user;
	if (!state->closed) { ILibDuktape_DuplexStream_WriteEnd(state->decodedStream); }
}
void ILibDuktape_httpStream_webSocket_EncodedPauseSink_Chain(void *chain, void *user)
{
	if (!ILibMemory_CanaryOK(user)) { return; }

	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)user;
	duk_context *ctx = state->decodedStream->writableStream->ctx;

	if (state->decodedStream->writableStream->pipedReadable != NULL)
	{
		duk_push_heapptr(ctx, state->decodedStream->writableStream->pipedReadable);			// [readable]
		duk_get_prop_string(ctx, -1, "pause");												// [readable][pause]
		duk_swap_top(ctx, -2);																// [pause][this]
		if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.webSocketStream.Encoded_Pause(): Error pausing upstream "); }
		duk_pop(ctx);																		// ...
	}
}
void ILibDuktape_httpStream_webSocket_EncodedPauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
	//printf("WebSocket.Encoded.Pause();\n");
	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)user;
	if (state->decodedStream->writableStream->pipedReadable_native != NULL && state->decodedStream->writableStream->pipedReadable_native->PauseHandler != NULL)
	{
		state->decodedStream->writableStream->pipedReadable_native->paused = 1;
		state->decodedStream->writableStream->pipedReadable_native->PauseHandler(state->decodedStream->writableStream->pipedReadable_native, state->decodedStream->writableStream->pipedReadable_native->user);
	}
	else
	{
		if (ILibIsRunningOnChainThread(state->chain))
		{
			ILibDuktape_httpStream_webSocket_EncodedPauseSink_Chain(NULL, state);
		}
		else
		{
			ILibChain_RunOnMicrostackThreadEx(state->chain, ILibDuktape_httpStream_webSocket_EncodedPauseSink_Chain, state);
		}
	}
}
void ILibDuktape_httpStream_webSocket_EncodedResumeSink_Chain(void *chain, void *user)
{
	if (!ILibMemory_CanaryOK(user)) { return; }

	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)user;
	duk_context *ctx = state->decodedStream->writableStream->ctx;

	if (state->decodedStream->writableStream->pipedReadable == NULL) { return; }
	duk_push_heapptr(ctx, state->decodedStream->writableStream->pipedReadable);			// [readable]
	duk_get_prop_string(ctx, -1, "resume");												// [readable][resume]
	duk_swap_top(ctx, -2);																// [resume][this]
	if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.webSocketStream.Encoded_Resume(): Error resuming upstream "); }
	duk_pop(ctx);																		// ...
}
void ILibDuktape_httpStream_webSocket_EncodedResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	//printf("WebSocket.Encoded.Resume();\n");
	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)user;
	if (state->decodedStream->writableStream->pipedReadable_native != NULL && state->decodedStream->writableStream->pipedReadable_native->ResumeHandler != NULL)
	{
		state->decodedStream->writableStream->pipedReadable_native->paused = 0;
		state->decodedStream->writableStream->pipedReadable_native->ResumeHandler(state->decodedStream->writableStream->pipedReadable_native, state->decodedStream->writableStream->pipedReadable_native->user);
	}
	else
	{
		if (ILibIsRunningOnChainThread(state->chain))
		{
			ILibDuktape_httpStream_webSocket_EncodedResumeSink_Chain(NULL, state);
		}
		else
		{
			ILibChain_RunOnMicrostackThreadEx(state->chain, ILibDuktape_httpStream_webSocket_EncodedResumeSink_Chain, state);
		}
	}
}
int ILibDuktape_httpStream_webSocket_EncodedUnshiftSink(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user)
{
	// Block Mode should never need to be unshifted
	return(0);
}

ILibTransport_DoneState ILibDuktape_httpStream_webSocket_DecodedWriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)user;
	return(ILibDuktape_httpStream_webSocket_WriteWebSocketPacket(state, stream->writableStream->Reserved == 1 ? ILibWebClient_WebSocket_DataType_TEXT : ILibWebClient_WebSocket_DataType_BINARY, buffer, bufferLen, ILibWebClient_WebSocket_FragmentFlag_Complete));
}
void ILibDuktape_httpStream_webSocket_DecodedEndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)user;
	ILibDuktape_httpStream_webSocket_WriteWebSocketPacket(state, WEBSOCKET_OPCODE_CLOSE, NULL, 0, ILibWebClient_WebSocket_FragmentFlag_Complete);
}
void ILibDuktape_httpStream_webSocket_DecodedPauseSink_Chain(void *chain, void *user)
{
	if (!ILibMemory_CanaryOK(user)) { return; }

	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)user;
	duk_context *ctx = state->encodedStream->writableStream->ctx;

	if (state->encodedStream->writableStream->pipedReadable == NULL)
	{
		// We're not piped yet, so just set a flag, and we'll make sure we don't resume
		state->noResume = 1;
		return;
	}


	duk_push_heapptr(ctx, state->encodedStream->writableStream->pipedReadable);		// [readable]
	duk_get_prop_string(ctx, -1, "pause");											// [readable][pause]
	duk_swap_top(ctx, -2);															// [pause][this]
	if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.webSocketStream.Decoded_Pause(): Error pausing upstream "); }
	duk_pop(ctx);																	// ...
}
void ILibDuktape_httpStream_webSocket_DecodedPauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)user;
	if (state->encodedStream->writableStream->pipedReadable_native != NULL && state->encodedStream->writableStream->pipedReadable_native->PauseHandler != NULL)
	{
		state->encodedStream->writableStream->pipedReadable_native->paused = 1;
		state->encodedStream->writableStream->pipedReadable_native->PauseHandler(state->encodedStream->writableStream->pipedReadable_native, state->encodedStream->writableStream->pipedReadable_native->user);
	}
	else
	{
		if (ILibIsRunningOnChainThread(state->chain))
		{
			ILibDuktape_httpStream_webSocket_DecodedPauseSink_Chain(NULL, state);
		}
		else
		{
			ILibChain_RunOnMicrostackThreadEx(state->chain, ILibDuktape_httpStream_webSocket_DecodedPauseSink_Chain, state);
		}
	}
}
void ILibDuktape_httpStream_webSocket_DecodedResumeSink_Chain(void *chain, void *user)
{
	if (!ILibMemory_CanaryOK(user)) { return; }
	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)user;
	duk_context *ctx = state->encodedStream->writableStream->ctx;

	if (state->encodedStream->writableStream->pipedReadable == NULL)
	{
		state->noResume = 0;
		return;
	}

	duk_push_heapptr(ctx, state->encodedStream->writableStream->pipedReadable);		// [readable]
	duk_get_prop_string(ctx, -1, "resume");											// [readable][resume]
	duk_swap_top(ctx, -2);															// [resume][this]
	if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http.webSocketStream.Decoded_Resume(): Error resuming upstream "); }
	duk_pop(ctx);																	// ...
}
void ILibDuktape_httpStream_webSocket_DecodedResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)user;
	if (state->encodedStream->writableStream->pipedReadable_native != NULL && state->encodedStream->writableStream->pipedReadable_native->ResumeHandler != NULL)
	{
		state->encodedStream->writableStream->pipedReadable_native->paused = 0;
		state->encodedStream->writableStream->pipedReadable_native->ResumeHandler(state->encodedStream->writableStream->pipedReadable_native, state->encodedStream->writableStream->pipedReadable_native->user);
	}
	else
	{
		if (ILibIsRunningOnChainThread(state->chain))
		{
			ILibDuktape_httpStream_webSocket_DecodedResumeSink_Chain(NULL, state);
		}
		else
		{
			ILibChain_RunOnMicrostackThreadEx(state->chain, ILibDuktape_httpStream_webSocket_DecodedResumeSink_Chain, state);
		}
	}
}
int ILibDuktape_httpStream_webSocket_DecodedUnshiftSink(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user)
{
	// Block Mode Data Transfers should never need to be unshifted, otherwise you're doing it wrong
	return(0);
}

duk_ret_t ILibDuktape_httpStream_webSocketStream_finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, ILibDuktape_WebSocket_StatePtr);
	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)Duktape_GetBuffer(ctx, -1, NULL);
	
	if (state->encodedStream != NULL && state->encodedStream->writableStream->pipedReadable != NULL)
	{
		duk_push_heapptr(ctx, state->encodedStream->writableStream->pipedReadable);		// [readable]
		duk_get_prop_string(ctx, -1, "unpipe");											// [readable][unpipe]
		duk_swap_top(ctx, -2);															// [unpipe][this]
		duk_push_heapptr(ctx, state->encodedStream->writableStream->obj);				// [unpipe][this][ws]
		duk_call_method(ctx, 1); duk_pop(ctx);											// ...
	}

	return(0);
}
duk_ret_t ILibDuktape_httpStream_webSocketStream_sendPing(duk_context *ctx)
{
	duk_push_this(ctx);															// [WS_DEC]
	duk_get_prop_string(ctx, -1, ILibDuktape_WSDEC2WS);							// [WS_DEC][WS]
	duk_get_prop_string(ctx, -1, ILibDuktape_WebSocket_StatePtr);				// [WS_DEC][WS][PTR]

	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)Duktape_GetBuffer(ctx, -1, NULL);
	ILibDuktape_httpStream_webSocket_WriteWebSocketPacket(state, WEBSOCKET_OPCODE_PING, NULL, 0, ILibWebClient_WebSocket_FragmentFlag_Complete);
	return(0);
}
duk_ret_t ILibDuktape_httpStream_webSocketStream_sendPong(duk_context *ctx)
{
	duk_push_this(ctx);															// [WS_DEC]
	duk_get_prop_string(ctx, -1, ILibDuktape_WSDEC2WS);							// [WS_DEC][WS]
	duk_get_prop_string(ctx, -1, ILibDuktape_WebSocket_StatePtr);				// [WS_DEC][WS][PTR]

	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)Duktape_GetBuffer(ctx, -1, NULL);
	ILibDuktape_httpStream_webSocket_WriteWebSocketPacket(state, WEBSOCKET_OPCODE_PONG, NULL, 0, ILibWebClient_WebSocket_FragmentFlag_Complete);
	return(0);
}
duk_ret_t ILibDuktape_httpStream_webSocketStream_encodedPiped(duk_context *ctx)
{
	// Someone Piped to the Encoded Stream
	duk_push_this(ctx);												// [ENC]
	duk_get_prop_string(ctx, -1, ILibDuktape_WSENC2WS);				// [ENC][WS]
	duk_get_prop_string(ctx, -1, ILibDuktape_WebSocket_StatePtr);	// [ENC][WS][state]

	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)Duktape_GetBuffer(ctx, -1, NULL);
	if (state->noResume)
	{
		state->noResume = 0;
		duk_push_heapptr(state->ctx, state->encodedStream->writableStream->pipedReadable);	// [Readable]
		duk_get_prop_string(state->ctx, -1, "pause");										// [Readable][pause]
		duk_swap_top(ctx, -2);																// [pause][this]
		duk_call_method(ctx, 0);
	}
	return(0);
}
duk_ret_t ILibDuktape_httpStream_webSocketStream_encoded_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, ILibDuktape_WSENC2WS);
	duk_get_prop_string(ctx, -1, ILibDuktape_WebSocket_StatePtr);
	ILibDuktape_WebSocket_State *state = (ILibDuktape_WebSocket_State*)Duktape_GetBuffer(ctx, -1, NULL);

	state->encodedStream = NULL;

	return(0);
}
duk_ret_t ILibDuktape_httpStream_webSocketStream_new(duk_context *ctx)
{
	ILibDuktape_WebSocket_State *state;
	duk_push_object(ctx);																				// [WebSocket]
	ILibDuktape_WriteID(ctx, "http.WebSocketStream");
	state = (ILibDuktape_WebSocket_State*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_WebSocket_State));	// [WebSocket][data]
	duk_put_prop_string(ctx, -2, ILibDuktape_WebSocket_StatePtr);										// [WebSocket]

	state->ctx = ctx;
	state->ObjectPtr = duk_get_heapptr(ctx, -1);
	state->chain = Duktape_GetChain(ctx);

	duk_push_object(ctx);														// [WebSocket][Encoded]
	ILibDuktape_WriteID(ctx, "http.WebSocketStream.encoded");
	state->encodedStream = ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_httpStream_webSocket_EncodedWriteSink, ILibDuktape_httpStream_webSocket_EncodedEndSink, ILibDuktape_httpStream_webSocket_EncodedPauseSink, ILibDuktape_httpStream_webSocket_EncodedResumeSink, ILibDuktape_httpStream_webSocket_EncodedUnshiftSink, state);
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "pipe", ILibDuktape_httpStream_webSocketStream_encodedPiped);
	duk_dup(ctx, -2);															// [WebSocket][Encoded][WebSocket]
	duk_put_prop_string(ctx, -2, ILibDuktape_WSENC2WS);							// [WebSocket][Encoded]
	ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "~", ILibDuktape_httpStream_webSocketStream_encoded_Finalizer);

	ILibDuktape_CreateReadonlyProperty(ctx, "encoded");							// [WebSocket]
	duk_push_object(ctx);														// [WebSocket][Decoded]
	ILibDuktape_WriteID(ctx, "http.WebSocketStream.decoded");
	duk_dup(ctx, -2);															// [WebSocket][Decoded][WebSocket]
	duk_put_prop_string(ctx, -2, ILibDuktape_WSDEC2WS);							// [WebSocket][Decoded]
	state->decodedStream = ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_httpStream_webSocket_DecodedWriteSink, ILibDuktape_httpStream_webSocket_DecodedEndSink, ILibDuktape_httpStream_webSocket_DecodedPauseSink, ILibDuktape_httpStream_webSocket_DecodedResumeSink, ILibDuktape_httpStream_webSocket_DecodedUnshiftSink, state);
	ILibDuktape_EventEmitter_CreateEventEx(ILibDuktape_EventEmitter_GetEmitter(ctx, -1), "ping");
	ILibDuktape_EventEmitter_CreateEventEx(ILibDuktape_EventEmitter_GetEmitter(ctx, -1), "pong");
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "ping", ILibDuktape_httpStream_webSocketStream_sendPing, DUK_VARARGS);
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "pong", ILibDuktape_httpStream_webSocketStream_sendPong, DUK_VARARGS);

	ILibDuktape_CreateReadonlyProperty(ctx, "decoded");							// [WebSocket]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_httpStream_webSocketStream_finalizer);

	return(1);
}

duk_ret_t ILibDuktape_http_generateNonce(duk_context *ctx)
{
	int len = (int)duk_require_int(ctx, 0);
	if ((len+1) < sizeof(ILibScratchPad))
	{
		util_randomtext(len, ILibScratchPad);
		ILibScratchPad[len] = 0;
		duk_push_string(ctx, ILibScratchPad);
		return(1);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Specified length is too long. Please Specify a value < %d", sizeof(ILibScratchPad)));
	}
}

void ILibDuktape_HttpStream_http_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);																							// [http]
	ILibDuktape_WriteID(ctx, "http");
	ILibDuktape_CreateInstanceMethod(ctx, "request", ILibDuktape_HttpStream_http_request, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "createServer", ILibDuktape_HttpStream_http_createServer, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "get", ILibDuktape_HttpStream_http_get, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "createStream", ILibduktape_HttpStream_create, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "Agent", ILibDuktape_HttpStream_Agent_new, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "parseUri", ILibDuktape_httpStream_parseUri, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "webSocketStream", ILibDuktape_httpStream_webSocketStream_new, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "generateNonce", ILibDuktape_http_generateNonce, 1);

	// HTTP Global Agent
	duk_push_c_function(ctx, ILibDuktape_HttpStream_Agent_new, DUK_VARARGS);										// [http][newAgent]
	duk_dup(ctx, -2);																								// [http][newAgent][this]
	duk_call_method(ctx, 0);																						// [http][Agent]
	duk_put_prop_string(ctx, -2, "globalAgent");																	// [http][Agent]
}
void ILibDuktape_HttpStream_https_PUSH(duk_context *ctx, void *chain)
{
	ILibDuktape_HttpStream_http_PUSH(ctx, chain);			// [https]
	ILibDuktape_WriteID(ctx, "https");
	duk_push_boolean(ctx, 1);
	ILibDuktape_CreateReadonlyProperty(ctx, "isHTTPS");		// [https]
}
void ILibDuktape_HttpStream_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "http", ILibDuktape_HttpStream_http_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "https", ILibDuktape_HttpStream_https_PUSH);
}
