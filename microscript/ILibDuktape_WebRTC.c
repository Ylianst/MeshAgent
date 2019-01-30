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
#include <WinSock2.h>
#include <WS2tcpip.h>
#endif

#include "ILibDuktape_WebRTC.h"
#include "microstack/ILibParsers.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktape_DuplexStream.h"

#ifndef MICROSTACK_NOTLS
#include "microstack/ILibWebRTC.h"
#include "microstack/ILibWrapperWebRTC.h"


#define ILibDuktape_WebRTC_ConnectionFactoryPtr		"\xFF_WebRTC_ConnectionFactoryPtr"
#define ILibDuktape_WebRTC_ConnectionPtr			"\xFF_WebRTC_ConnectionPtr"
#define ILibDuktape_WebRTC_DataChannelPtr			"\xFF_WebRTC_DataChannelPtr"
extern void ILibWrapper_WebRTC_ConnectionFactory_RemoveFromChain(ILibWrapper_WebRTC_ConnectionFactory factory);
int ILibDuktape_WebRTC_SSL2Duktape = -1;

typedef struct ILibWebRTC_Duktape_Handlers
{
	duk_context *ctx;
	void *ConnectionObject;
	ILibDuktape_EventEmitter *emitter;
#ifdef _WEBRTCDEBUG
	int debugRegistered;
#endif

	void *OnConnectionSendOK;
}ILibWebRTC_Duktape_Handlers;
typedef struct ILibDuktape_WebRTC_DataChannel
{
	ILibWrapper_WebRTC_DataChannel *dataChannel;
	duk_context *ctx;
	ILibDuktape_EventEmitter *emitter;
	ILibDuktape_DuplexStream *stream;
}ILibDuktape_WebRTC_DataChannel;

extern void* ILibWrapper_WebRTC_Connection_GetStunModule(ILibWrapper_WebRTC_Connection connection);


duk_ret_t ILibWebRTC_Duktape_ConnectionFactory_SetTurn(duk_context *ctx)
{
	char *host = Duktape_GetStringPropertyValue(ctx, 0, "Host", NULL);
	int	 port = Duktape_GetIntPropertyValue(ctx, 0, "Port", 3478);
	duk_size_t usernameLen;
	char *username = Duktape_GetStringPropertyValueEx(ctx, 0, "Username", NULL, &usernameLen);
	duk_size_t passwordLen;
	char *password = Duktape_GetStringPropertyValueEx(ctx, 0, "Password", "", &passwordLen);
	ILibWebRTC_TURN_ConnectFlags flags = (ILibWebRTC_TURN_ConnectFlags)Duktape_GetIntPropertyValue(ctx, 0, "Mode", (int)ILibWebRTC_TURN_ENABLED);
	struct sockaddr_in6* server;
	ILibWrapper_WebRTC_ConnectionFactory factory;

	if (host == NULL || username == NULL) { return(ILibDuktape_Error(ctx, "Invalid TURN parameters")); }
	server = Duktape_IPAddress4_FromString(host, (unsigned short)port);

	duk_push_this(ctx);
	factory = Duktape_GetPointerProperty(ctx, -1, "FactoryPtr");
	
	ILibWrapper_WebRTC_ConnectionFactory_SetTurnServer(factory, server, username, (int)usernameLen, password, (int)passwordLen, flags);
	return 0;
}

duk_idx_t ILibWebRTC_Duktape_Connection_AddRemoteCandidate(duk_context *ctx)
{
	char *username;
	struct sockaddr_in6 *candidate = NULL;
	ILibWrapper_WebRTC_Connection connection;

	duk_push_this(ctx);														// [connection]
	duk_get_prop_string(ctx, -1, "ConnectionPtr");							// [connection][ptr]
	connection = (ILibWrapper_WebRTC_Connection*)duk_to_pointer(ctx, -1);
	if (strcmp(Duktape_GetStringPropertyValue(ctx, 0, "Family", "IPv4"), "IPv4") == 0)
	{
		candidate = Duktape_IPAddress4_FromString(Duktape_GetStringPropertyValue(ctx, 0, "Address", "127.0.0.1"), (unsigned short)Duktape_GetIntPropertyValue(ctx, 0, "Port", 65535));
		username = ILibWrapper_WebRTC_Connection_GetLocalUsername(connection);
		ILibORTC_AddRemoteCandidate(ILibWrapper_WebRTC_Connection_GetStunModule(connection), username, candidate);
	}
	return 0;
}


/*------------------------------------------------------------------------------------------*/


ILibWrapper_WebRTC_Connection ILibDuktape_WebRTC_Native_GetConnection(duk_context *ctx)
{
	ILibWrapper_WebRTC_Connection retVal = NULL;
	duk_push_this(ctx);													// [this]
	duk_get_prop_string(ctx, -1, ILibDuktape_WebRTC_ConnectionPtr);		// [this][connection]
	retVal = (ILibWrapper_WebRTC_Connection)duk_get_pointer(ctx, -1);
	duk_pop_2(ctx);														// ...
	return retVal;
}
ILibTransport_DoneState ILibDuktape_WebRTC_DataChannel_Stream_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_WebRTC_DataChannel *ptrs = (ILibDuktape_WebRTC_DataChannel*)user;
	if (ptrs->dataChannel != NULL)
	{
		return(ILibWrapper_WebRTC_DataChannel_SendEx(ptrs->dataChannel, buffer, bufferLen, stream->writableStream->Reserved == 1 ? 51 : 53));
	}
	else
	{
		return(ILibTransport_DoneState_ERROR);
	}
}
void ILibDuktape_WebRTC_DataChannel_Stream_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_WebRTC_DataChannel *ptrs = (ILibDuktape_WebRTC_DataChannel*)user;
	if (ptrs->dataChannel != NULL)
	{
		ILibWrapper_WebRTC_DataChannel_Close(ptrs->dataChannel);
	}
}
void ILibDuktape_WebRTC_DataChannel_Stream_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_WebRTC_DataChannel *ptrs = (ILibDuktape_WebRTC_DataChannel*)user;
	if (ptrs->dataChannel != NULL)
	{
		void *sctpSession = ((void**)ptrs->dataChannel->parent)[0];
		ILibSCTP_Pause(sctpSession);
	}
}
void ILibDuktape_WebRTC_DataChannel_Stream_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_WebRTC_DataChannel *ptrs = (ILibDuktape_WebRTC_DataChannel*)user;
	if (ptrs->dataChannel != NULL)
	{
		void *sctpSession = ((void**)ptrs->dataChannel->parent)[0];
		ILibSCTP_Resume(sctpSession);
	}
}
void ILibDuktape_WebRTC_OnDataChannelSendOK(void *dataChannel)
{
	ILibDuktape_WebRTC_DataChannel *ptrs = (ILibDuktape_WebRTC_DataChannel*)((ILibWrapper_WebRTC_DataChannel*)dataChannel)->userData;
	if (ptrs != NULL) { ILibDuktape_DuplexStream_Ready(ptrs->stream); }
}
void ILibDuktape_WebRTC_DataChannel_OnClose(struct ILibWrapper_WebRTC_DataChannel* dataChannel)
{
	ILibDuktape_WebRTC_DataChannel *ptrs = (ILibDuktape_WebRTC_DataChannel*)dataChannel->userData;
	if (ptrs != NULL) 
	{ 
		ILibDuktape_DuplexStream_WriteEnd(ptrs->stream); 
		ptrs->dataChannel = NULL; 
	}
}
void ILibDuktape_WebRTC_DataChannel_OnData(struct ILibWrapper_WebRTC_DataChannel* dataChannel, char* data, int dataLen, int dataType)
{
	ILibDuktape_WebRTC_DataChannel *ptrs = (ILibDuktape_WebRTC_DataChannel*)dataChannel->userData;
	
	if (ptrs != NULL) { ILibDuktape_DuplexStream_WriteDataEx(ptrs->stream, dataType == 51 ? 1 : 0, data, dataLen); }
}
duk_ret_t ILibDuktape_WebRTC_DataChannel_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, ILibDuktape_WebRTC_DataChannelPtr);
	ILibDuktape_WebRTC_DataChannel *ptrs = (ILibDuktape_WebRTC_DataChannel*)Duktape_GetBuffer(ctx, -1, NULL);
	if (ptrs->dataChannel != NULL)
	{
		//printf("WebRTC Data Channel Finalizer on Connection: %p\n", ptrs->dataChannel->parent);
		ptrs->dataChannel->userData = NULL;
		ILibWrapper_WebRTC_DataChannel_Close(ptrs->dataChannel);
	}

	return 0;
}

void ILibDuktape_WebRTC_DataChannel_PUSH(duk_context *ctx, ILibWrapper_WebRTC_DataChannel *dataChannel)
{
	if (dataChannel == NULL) { duk_push_null(ctx); return; }
	if (dataChannel->userData != NULL) { duk_push_heapptr(((ILibDuktape_WebRTC_DataChannel*)dataChannel->userData)->ctx, ((ILibDuktape_WebRTC_DataChannel*)dataChannel->userData)->emitter->object); return; }
	ILibDuktape_WebRTC_DataChannel *ptrs;

	dataChannel->TransportSendOKPtr = ILibDuktape_WebRTC_OnDataChannelSendOK;
	dataChannel->OnClosed = ILibDuktape_WebRTC_DataChannel_OnClose;
	dataChannel->OnRawData = ILibDuktape_WebRTC_DataChannel_OnData;

	duk_push_object(ctx);														// [dataChannel]
	ILibDuktape_WriteID(ctx, "webRTC.dataChannel");
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_WebRTC_DataChannel));			// [dataChannel][buffer]
	ptrs = (ILibDuktape_WebRTC_DataChannel*)Duktape_GetBuffer(ctx, -1, NULL);
	dataChannel->userData = ptrs;
	duk_put_prop_string(ctx, -2, ILibDuktape_WebRTC_DataChannelPtr);			// [dataChannel]
	ptrs->dataChannel = dataChannel;
	ptrs->ctx = ctx;
	ptrs->emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_WebRTC_DataChannel_Finalizer);

	duk_push_string(ctx, dataChannel->channelName);
	duk_put_prop_string(ctx, -2, "name");
	duk_push_int(ctx, dataChannel->streamId);
	duk_put_prop_string(ctx, -2, "id");

	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "ack");

	ptrs->stream = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_WebRTC_DataChannel_Stream_WriteSink, ILibDuktape_WebRTC_DataChannel_Stream_EndSink,
		ILibDuktape_WebRTC_DataChannel_Stream_PauseSink, ILibDuktape_WebRTC_DataChannel_Stream_ResumeSink, ptrs);
}

duk_ret_t ILibDuktape_WebRTC_ConnectionFactory_Finalizer(duk_context *ctx)
{
	void *chain = Duktape_GetChain(ctx);
	ILibWrapper_WebRTC_ConnectionFactory factory;
	duk_get_prop_string(ctx, 0, ILibDuktape_WebRTC_ConnectionFactoryPtr);
	factory = (ILibWrapper_WebRTC_ConnectionFactory)duk_get_pointer(ctx, -1);

	//printf("WebRTC Factory Finalizer: %p\n", factory);

	if (factory != NULL && ILibIsChainBeingDestroyed(chain) == 0)
	{
		ILibWrapper_WebRTC_ConnectionFactory_RemoveFromChain(factory);
	}

	return 0;
}
#ifdef _WEBRTCDEBUG
void ILibDuktape_WebRTC_Connection_Debug(void* dtlsSession, char* debugField, int data)
{
	SSL *ssl = (SSL*)ILibWrapper_WebRTC_DtlsSessionToSSL(dtlsSession);
	ILibWebRTC_Duktape_Handlers *ptrs = (ILibWebRTC_Duktape_Handlers*)SSL_get_ex_data(ssl, ILibDuktape_WebRTC_SSL2Duktape);

	if (ptrs != NULL && ptrs->ConnectionObject != NULL)
	{
		if (strcmp(debugField, "OnHold") == 0)
		{
			ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "_hold");							// [emit][this][name]
		}
		else if (strcmp(debugField, "OnCongestionWindowSizeChanged") == 0)
		{
			ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "_congestionWindowSizeChange");	// [emit][this][name]
		}
		else if (strcmp(debugField, "OnRTTCalculated") == 0)
		{
			ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "_rttCalculated");				// [emit][this][name]
		}
		else if (strcmp(debugField, "OnFastRecovery") == 0)
		{
			ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "_fastRecovery");					// [emit][this][name]
		}
		else if (strcmp(debugField, "OnLastSackTime") == 0)
		{
			ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "_lastSackTime");					// [emit][this][name]
		}
		else if (strcmp(debugField, "OnLastSentTime") == 0)
		{
			ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "_lastSentTime");					// [emit][this][name]
		}
		else if (strcmp(debugField, "OnReceiverCredits") == 0)
		{
			ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "_receiverCredits");				// [emit][this][name]
		}
		else if (strcmp(debugField, "OnT3RTX") == 0)
		{
			ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "_t3tx");							// [emit][this][name]
		}
		else if (strcmp(debugField, "OnSendRetry") == 0)
		{
			ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "_retransmit");					// [emit][this][name]
		}
		else if (strcmp(debugField, "OnSACKReceived") == 0)
		{
			ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "_sackReceived");					// [emit][this][name]
		}
		else if (strcmp(debugField, "OnRetryPacket") == 0)
		{
			duk_push_external_buffer(ptrs->ctx);																		// [extBuffer]
			ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "_retransmitPacket");					// [extBuffer][emit][this][name]
			duk_config_buffer(ptrs->ctx, -4, debugField + 14, data);
			duk_push_buffer_object(ptrs->ctx, -4, 0, data, DUK_BUFOBJ_NODEJS_BUFFER);
			if (duk_pcall_method(ptrs->ctx, 2) != 0) { ILibDuktape_Process_UncaughtException(ptrs->ctx); }
			duk_pop_2(ptrs->ctx);																						// ...
			return;
		}
		else
		{
			return;
		}
		duk_push_int(ptrs->ctx, data);																				// [emit][this][name][val]
		if (duk_pcall_method(ptrs->ctx, 2) != 0) { ILibDuktape_Process_UncaughtException(ptrs->ctx); }
		duk_pop(ptrs->ctx);																							// ...
	}
}
#endif
void ILibDuktape_WebRTC_OnConnection(ILibWrapper_WebRTC_Connection connection, int connected)
{
	ILibWebRTC_Duktape_Handlers *ptrs = (ILibWebRTC_Duktape_Handlers*)ILibMemory_Extra(connection);
	if (!ILibMemory_CanaryOK(ptrs->emitter)) { return; }

	if (connected == 0)
	{
		ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "disconnected");		// [emit][this][disconnected]
		duk_del_prop_string(ptrs->ctx, -2, ILibDuktape_WebRTC_ConnectionPtr);
	}
	else
	{
		ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "connected");			// [emit][this][connected]
	}
	if (duk_pcall_method(ptrs->ctx, 1) != 0) { ILibDuktape_Process_UncaughtException(ptrs->ctx); }
	duk_pop(ptrs->ctx);																				// ...
#ifdef _WEBRTCDEBUG
	if (connected == 0 && ptrs->debugRegistered != 0)
	{
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnHold", NULL);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnCongestionWindowSizeChanged", NULL);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnRTTCalculated", NULL);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnFastRecovery", NULL);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnReceiverCredits", NULL);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnT3RTX", NULL);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnSendRetry", NULL);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnSendFastRetry", NULL);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnRetryPacket", NULL);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnSACKReceived", NULL);
	}
#endif

}

void ILibDuktape_WebRTC_OnDataChannel(ILibWrapper_WebRTC_Connection connection, ILibWrapper_WebRTC_DataChannel *dataChannel)
{
	ILibWebRTC_Duktape_Handlers *ptrs = (ILibWebRTC_Duktape_Handlers*)ILibMemory_Extra(connection);
	if (ILibMemory_CanaryOK(ptrs->emitter))
	{
		ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "dataChannel");	// [emit][this][dataChannel]
		ILibDuktape_WebRTC_DataChannel_PUSH(ptrs->ctx, dataChannel);							// [emit][this][dataChannel][dc]
		if (duk_pcall_method(ptrs->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ptrs->ctx, "webrtc.connection.onDataChannel(): "); }
		duk_pop(ptrs->ctx);											// ...
	}
}

void ILibDuktape_WebRTC_offer_onCandidate(ILibWrapper_WebRTC_Connection connection, struct sockaddr_in6* candidate)
{
	if (candidate != NULL)
	{
		ILibWebRTC_Duktape_Handlers *ptrs = (ILibWebRTC_Duktape_Handlers*)ILibMemory_Extra(connection);
		if (ILibMemory_CanaryOK(ptrs->emitter))
		{
			ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->ConnectionObject, "candidate");		// [emit][this][candidate]
			ILibDuktape_SockAddrToOptions(ptrs->ctx, candidate);									// [emit][this][candidate][options]
			if (duk_pcall_method(ptrs->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ptrs->ctx, "webrtc.connection.onCandidate(): "); }
			duk_pop(ptrs->ctx);										// ...
		}
	}
}
duk_ret_t ILibDuktape_WebRTC_generateOffer(duk_context *ctx)
{
	ILibWrapper_WebRTC_Connection connection = ILibDuktape_WebRTC_Native_GetConnection(ctx);

	char *offer = ILibWrapper_WebRTC_Connection_GenerateOffer(connection, ILibDuktape_WebRTC_offer_onCandidate);
	if (offer != NULL)
	{
		duk_push_string(ctx, offer);
		free(offer);
	}
	else
	{
		duk_push_null(ctx);
	}
	return 1;
}
duk_ret_t ILibDuktape_WebRTC_setOffer(duk_context *ctx)
{
	ILibWrapper_WebRTC_Connection connection = ILibDuktape_WebRTC_Native_GetConnection(ctx);

	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "webrtc.connection.setOffer(): Invalid Parameter")); }
	duk_size_t offerLen;
	char *offer;
	char *counterOffer;

	offer = (char*)duk_get_lstring(ctx, 0, &offerLen);
	counterOffer = ILibWrapper_WebRTC_Connection_SetOffer(connection, offer, (int)offerLen, ILibDuktape_WebRTC_offer_onCandidate);
	if (counterOffer != NULL)
	{
		duk_push_string(ctx, counterOffer);
		free(counterOffer);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "WebRTC: Error setting offer. Most likely too many outstanding offers"));
	}
	return 1;
}
void ILibDuktape_WebRTC_DataChannel_OnAck(struct ILibWrapper_WebRTC_DataChannel* dataChannel)
{
	ILibDuktape_WebRTC_DataChannel *ptrs = (ILibDuktape_WebRTC_DataChannel*)dataChannel->userData;
	ILibDuktape_EventEmitter_SetupEmit(ptrs->ctx, ptrs->emitter->object, "ack");	// [emit][this][ack]
	if (duk_pcall_method(ptrs->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ptrs->ctx, "webrtc.dataChannel.onAck(): "); };
	duk_pop(ptrs->ctx);																// ...
}
duk_ret_t ILibDuktape_WebRTC_createDataChannel(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	ILibWrapper_WebRTC_DataChannel *retVal;
	ILibWrapper_WebRTC_Connection connection = ILibDuktape_WebRTC_Native_GetConnection(ctx);

	duk_size_t nameLen;
	char *name;
	int stream = -1;
	int i;
	void *OnAck = NULL;

	name = (char*)duk_get_lstring(ctx, 0, &nameLen);

	for (i = 1; i < nargs; ++i)
	{
		if (duk_is_number(ctx, i)) { stream = duk_require_int(ctx, i); }
		if (duk_is_function(ctx, i)) { OnAck = duk_require_heapptr(ctx, i); }
	}

	if (stream < 0)
	{
		retVal = ILibWrapper_WebRTC_DataChannel_Create(connection, name, (int)nameLen, ILibDuktape_WebRTC_DataChannel_OnAck);
	}
	else
	{
		retVal = ILibWrapper_WebRTC_DataChannel_CreateEx(connection, name, (int)nameLen, (unsigned short)stream, ILibDuktape_WebRTC_DataChannel_OnAck);
	}

	ILibDuktape_WebRTC_DataChannel_PUSH(ctx, retVal);
	if (OnAck != NULL)
	{
		ILibDuktape_EventEmitter_AddOnce(((ILibDuktape_WebRTC_DataChannel*)retVal->userData)->emitter, "ack", OnAck);
	}
	return 1;
}
duk_ret_t  ILibDuktape_WebRTC_addRemoteCandidate(duk_context *ctx)
{
	//ILibWrapper_WebRTC_Connection connection = ILibDuktape_WebRTC_Native_GetConnection(ctx);
	//ILibWebRTC_Duktape_Handlers *ptrs = (ILibWebRTC_Duktape_Handlers*)ILibMemory_GetExtraMemory(connection, ILibMemory_WebRTC_Connection_CONTAINERSIZE);


	return(ILibDuktape_Error(ctx, "webrtc.connection.addRemoteCandidate(): Not Supported Yet"));
}
duk_ret_t ILibDuktape_WebRTC_closeDataChannels(duk_context *ctx)
{
	ILibWrapper_WebRTC_Connection connection = ILibDuktape_WebRTC_Native_GetConnection(ctx);

	ILibWrapper_WebRTC_Connection_CloseAllDataChannels(connection);
	return 0;
}
duk_ret_t ILibDuktape_WebRTC_Connection_Finalizer(duk_context *ctx)
{
	ILibWrapper_WebRTC_Connection connection;
	duk_get_prop_string(ctx, 0, ILibDuktape_WebRTC_ConnectionPtr);
	connection = (ILibWrapper_WebRTC_Connection)duk_get_pointer(ctx, -1);
	//printf("WebRTCConnection Finalizer on %p\n", (void*)connection);
	if (connection == NULL) { return 0; }

	if (ILibWrapper_WebRTC_Connection_IsConnected(connection) != 0)
	{
		ILibWrapper_WebRTC_Connection_CloseAllDataChannels(connection);
		ILibWrapper_WebRTC_Connection_Disconnect(connection);
	}

	return 0;
}
#ifdef _WEBRTCDEBUG
void ILibDuktape_WebRTC_Connection_DebugHook(ILibDuktape_EventEmitter *sender, char *eventName, void *hookedCallback)
{
	// Only register the debug handlers if someone actually subscribed to the event
	duk_push_heapptr(sender->ctx, sender->object);									// [connection]
	ILibWrapper_WebRTC_Connection connection = (ILibWrapper_WebRTC_Connection)Duktape_GetPointerProperty(sender->ctx, -1, ILibDuktape_WebRTC_ConnectionPtr);
	ILibWebRTC_Duktape_Handlers *ptrs = (ILibWebRTC_Duktape_Handlers*)ILibMemory_Extra(connection);
	duk_pop(sender->ctx);															// ...
	
	if (ptrs->debugRegistered == 0)
	{
		SSL* ssl = ILibWrapper_WebRTC_DtlsSessionToSSL(ILibWrapper_WebRTC_Connection2DtlsSession(connection));
		if (ILibDuktape_WebRTC_SSL2Duktape < 0) { ILibDuktape_WebRTC_SSL2Duktape = SSL_get_ex_new_index(0, "ILibDuktape_WebRTC_SSL2Connection index", NULL, NULL, NULL); }
		SSL_set_ex_data(ssl, ILibDuktape_WebRTC_SSL2Duktape, ptrs);

		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnHold", ILibDuktape_WebRTC_Connection_Debug);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnCongestionWindowSizeChanged", ILibDuktape_WebRTC_Connection_Debug);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnRTTCalculated", ILibDuktape_WebRTC_Connection_Debug);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnFastRecovery", ILibDuktape_WebRTC_Connection_Debug);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnReceiverCredits", ILibDuktape_WebRTC_Connection_Debug);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnT3RTX", ILibDuktape_WebRTC_Connection_Debug);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnSendRetry", ILibDuktape_WebRTC_Connection_Debug);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnSendFastRetry", ILibDuktape_WebRTC_Connection_Debug);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnRetryPacket", ILibDuktape_WebRTC_Connection_Debug);
		ILibSCTP_Debug_SetDebugCallback(ILibWrapper_WebRTC_Connection2DtlsSession(connection), "OnSACKReceived", ILibDuktape_WebRTC_Connection_Debug);
	}
}
#endif
duk_ret_t ILibDuktape_WebRTC_CreateConnection(duk_context *ctx)
{
	ILibWebRTC_Duktape_Handlers *ptrs;
	ILibWrapper_WebRTC_Connection connection;
	ILibWrapper_WebRTC_ConnectionFactory factory;
	duk_push_this(ctx);																// [factory]
	duk_get_prop_string(ctx, -1, ILibDuktape_WebRTC_ConnectionFactoryPtr);
	factory = (ILibWrapper_WebRTC_ConnectionFactory)duk_get_pointer(ctx, -1);

	duk_push_object(ctx);															// [factory][connection]
	ILibDuktape_WriteID(ctx, "webRTC.peerConnection");
	connection = ILibWrapper_WebRTC_ConnectionFactory_CreateConnection2(factory, ILibDuktape_WebRTC_OnConnection, ILibDuktape_WebRTC_OnDataChannel, NULL, sizeof(ILibWebRTC_Duktape_Handlers));
	ptrs = (ILibWebRTC_Duktape_Handlers*)ILibMemory_Extra(connection);
	ptrs->ctx = ctx;
	ptrs->ConnectionObject = duk_get_heapptr(ctx, -1);
	ptrs->emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "candidate");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "dataChannel");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "connected");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "disconnected");

#ifdef _WEBRTCDEBUG
	ptrs->debugRegistered = 0;
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "_hold");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "_lastSackTime");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "_lastSentTime");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "_congestionWindowSizeChange");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "_fastRecovery");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "_rttCalculated");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "_receiverCredits");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "_t3tx");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "_retransmit");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "_retransmitPacket");
	ILibDuktape_EventEmitter_CreateEventEx(ptrs->emitter, "_sackReceived");

	ILibDuktape_EventEmitter_AddHook(ptrs->emitter, "_hold", ILibDuktape_WebRTC_Connection_DebugHook);
	ILibDuktape_EventEmitter_AddHook(ptrs->emitter, "_lastSackTime", ILibDuktape_WebRTC_Connection_DebugHook);
	ILibDuktape_EventEmitter_AddHook(ptrs->emitter, "_lastSentTime", ILibDuktape_WebRTC_Connection_DebugHook);
	ILibDuktape_EventEmitter_AddHook(ptrs->emitter, "_congestionWindowSizeChange", ILibDuktape_WebRTC_Connection_DebugHook);
	ILibDuktape_EventEmitter_AddHook(ptrs->emitter, "_fastRecovery", ILibDuktape_WebRTC_Connection_DebugHook);
	ILibDuktape_EventEmitter_AddHook(ptrs->emitter, "_rttCalculated", ILibDuktape_WebRTC_Connection_DebugHook);
	ILibDuktape_EventEmitter_AddHook(ptrs->emitter, "_receiverCredits", ILibDuktape_WebRTC_Connection_DebugHook);
	ILibDuktape_EventEmitter_AddHook(ptrs->emitter, "_t3tx", ILibDuktape_WebRTC_Connection_DebugHook);
	ILibDuktape_EventEmitter_AddHook(ptrs->emitter, "_retransmit", ILibDuktape_WebRTC_Connection_DebugHook);
	ILibDuktape_EventEmitter_AddHook(ptrs->emitter, "_retransmitPacket", ILibDuktape_WebRTC_Connection_DebugHook);
	ILibDuktape_EventEmitter_AddHook(ptrs->emitter, "_sackReceived", ILibDuktape_WebRTC_Connection_DebugHook);
#endif
	duk_push_pointer(ctx, connection);												// [factory][connection][ptr]
	duk_put_prop_string(ctx, -2, ILibDuktape_WebRTC_ConnectionPtr);					// [factory][connection]

	duk_push_int(ctx, ILibWrapper_WebRTC_Connection_GetID(connection));				// [factory][connection][id]
	duk_put_prop_string(ctx, -2, "ID");												// [factory][connection]

	ILibDuktape_CreateInstanceMethod(ctx, "generateOffer", ILibDuktape_WebRTC_generateOffer, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "setOffer", ILibDuktape_WebRTC_setOffer, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "createDataChannel", ILibDuktape_WebRTC_createDataChannel, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "closeDataChannels", ILibDuktape_WebRTC_closeDataChannels, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "addRemoteCandidate", ILibDuktape_WebRTC_addRemoteCandidate, 1);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_WebRTC_Connection_Finalizer);

	return 1;
}
void ILibDuktape_WebRTC_Push(duk_context *ctx, void *chain)
{
	ILibWrapper_WebRTC_ConnectionFactory factory;
	struct util_cert *rtcert = NULL;

	if (duk_peval_string(ctx, "require('MeshAgent');") == 0)	// [MeshAgent]
	{
		// We can use the Agent Cert
		rtcert = (struct util_cert*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_MeshAgent_Cert_Server);
	}
	duk_pop(ctx);												// ...

	duk_push_object(ctx);																// [factory]
	ILibDuktape_WriteID(ctx, "webRTC");
	factory = ILibWrapper_WebRTC_ConnectionFactory_CreateConnectionFactory2(chain, 0, rtcert);
	duk_push_pointer(ctx, factory);														// [factory][ptr]
	duk_put_prop_string(ctx, -2, ILibDuktape_WebRTC_ConnectionFactoryPtr);				// [factory]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_WebRTC_ConnectionFactory_Finalizer);

	ILibDuktape_CreateInstanceMethod(ctx, "createConnection", ILibDuktape_WebRTC_CreateConnection, 0);
}
void ILibDuktape_WebRTC_Init(duk_context * ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "ILibWebRTC", ILibDuktape_WebRTC_Push);
	Duktape_CreateEnum(ctx, "ILibWebRTC_TURN_ConnectModes", (char*[]) { "DISABLED", "ENABLED", "ALWAYS_RELAY" }, (int[]) { 0, 1, 2 }, 3);
}
#else
void ILibDuktape_WebRTC_Init(duk_context * ctx)
{
	Duktape_CreateEnum(ctx, "ILibWebRTC_TURN_ConnectModes", (char*[]) { "DISABLED", "ENABLED", "ALWAYS_RELAY" }, (int[]) { 0, 1, 2 }, 3);
}
#endif

#ifdef __DOXY__
/*!
\brief WebRTC Connection Factory. <b>Note:</b> To use, must <b>require('ILibWebRTC')</b>
*/
class ILibWebRTC
{
public:
	/*!
	\brief Creates a new unconnected peer Connection object.
	\return <Connection> Unconnected Connection
	*/
	static Connection createConnection();

	/*!
	\implements EventEmitter
	\brief WebRTC Connection
	*/
	class Connection
	{
	public:
		/*!
		\brief Event emitted when a connection candidate is found
		\param options <Object>\n
		<b>host</b> Host Name or IP Address of the candidate\n
		<b>port</b> Port Number of the candidate\n
		*/
		void candidate;
		/*!
		\brief Event emitted when a DataChannel is created
		\param channel DataChannel
		*/
		void dataChannel;
		/*!
		\brief Event emitted when a peer connection is established
		*/
		void connected;
		/*!
		\brief Event emitted when a peer connection is severed
		*/
		void disconnected;

		/*!
		\brief Generates a WebRTC SDP Offer.
		\return \<String\|NULL\> On succes, the SDP offer is returned, otherwise NULL.
		*/
		String generateOffer();
		/*!
		\brief Sets the remote WebRTC SDP Offer
		\return \<String\|NULL\> On success, returns the counter WebRTC SDP offer, otherwise NULL.
		*/
		String setOffer(offer);
		/*!
		\brief Creates a WebRTC DataChannel instance
		\param friendlyName \<String\> Friendly name to associate with the new DataChannel
		\param streamNumber <integer> Optional. If specified, uses the desired stream number. Otherwise, one will be auto-generated.
		\param callback <func> Optional. If specified, will be added as one time listener to DataChannel.ack event.
		\return DataChannel instance
		*/
		DataChannel createDataChannel(friendlyName[, streamNumber][, callback]);
		/*!
		\brief Closes all DataChannel instances associated with this Connection.
		*/
		void closeDataChannels();
		ILibDuktape_CreateInstanceMethod(ctx, "addRemoteCandidate", ILibDuktape_WebRTC_addRemoteCandidate, 1);
	};
	/*!
	\implements EventEmitter
	\implements DuplexStream
	\brief WebRTC Data Channel
	*/
	class DataChannel
	{
	public:
		/*!
		\brief WebRTC Stream ID
		*/
		integer id;
		/*!
		\brief WebRTC DataChannel Friendly Name
		*/
		String name;
		/*!
		\brief Event emitted when the connected peer ACK's this DataChannel creation
		*/
		void ack;
	};
};
#endif
