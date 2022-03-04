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

#ifdef MEMORY_CHECK
#include <assert.h>
#define MEMCHECK(x) x
#else
#define MEMCHECK(x)
#endif

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#if defined(WINSOCK2)
#include <winsock2.h>
#include <ws2tcpip.h>
#define MSG_NOSIGNAL 0
#elif defined(WINSOCK1)
#include <winsock.h>
#include <wininet.h>
#endif

#ifdef __APPLE__	// OSX
#define MSG_NOSIGNAL SO_NOSIGPIPE
#endif

#ifdef _VX_CPU		// VxWorks
#define MSG_NOSIGNAL 0
#endif

#include "ILibParsers.h"
#include "ILibAsyncSocket.h"
#include "ILibRemoteLogging.h"

#ifdef _DEBUG
#include "ILibCrypto.h"
#endif

#ifdef _POSIX
#include <sys/socket.h>
#include <sys/un.h>
#endif

#ifndef MICROSTACK_NOTLS
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif
#include <assert.h>

#if defined(_TLSLOG)
	#define TLSLOG1 printf
#else
	#define TLSLOG1(...) ;
#endif
#define INET_SOCKADDR_LENGTH(x) ((x==AF_INET6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))



#ifdef SEMAPHORE_TRACKING
#define SEM_TRACK(x) x
void AsyncSocket_TrackLock(const char* MethodName, int Occurance, void *data)
{
	char v[100];
	wchar_t wv[100];
	size_t l;

	sprintf_s(v, 100, "  LOCK[%s, %d] (%x)\r\n",MethodName,Occurance,data);
#ifdef WIN32
	mbstowcs_s(&l, wv, 100, v, 100);
	OutputDebugString(wv);
#else
	printf(v);
#endif
}
void AsyncSocket_TrackUnLock(const char* MethodName, int Occurance, void *data)
{
	char v[100];
	wchar_t wv[100];
	size_t l;

	sprintf_s(v, 100, "UNLOCK[%s, %d] (%x)\r\n",MethodName,Occurance,data);
#ifdef WIN32
	mbstowcs_s(&l, wv, 100, v, 100);
	OutputDebugString(wv);
#else
	printf(v);
#endif
}
#else
#define SEM_TRACK(x)
#endif

char ILibAsyncSocket_ScratchPad[65535];

typedef struct ILibAsyncSocket_SendData
{
	char* buffer;
	int bufferSize;
	int bytesSent;

	struct sockaddr_in6 remoteAddress;

	ILibAsyncSocket_MemoryOwnership UserFree;
	struct ILibAsyncSocket_SendData *Next;
}ILibAsyncSocket_SendData;

typedef struct ILibAsyncSocketModule
{
	ILibTransport Transport;
#if defined(_WIN32_WCE) || defined(WIN32)
	SOCKET internalSocket;
#elif defined(_POSIX)
	int internalSocket;
#endif

	// DO NOT MODIFY THE ABOVE FIELDS (ILibTransport, internalSocket)

	unsigned int PendingBytesToSend;
	unsigned int TotalBytesSent;

#ifdef _POSIX
	struct sockaddr_un DomainAddress;
#endif


	// The IPv4/IPv6 compliant address of the remote endpoint. We are not going to be using IPv6 all the time,
	// but we use the IPv6 structure to allocate the meximum space we need.
	struct sockaddr_in6 RemoteAddress;

	// Local interface of a given socket. This module will bind to any interface, but the actual interface used
	// is stored here.
	struct sockaddr_in6 LocalAddress;

	// Source address. Here is stored the actual source of a packet, usualy used with UDP where the source
	// of the traffic changes.
	struct sockaddr_in6 SourceAddress;

#ifdef MICROSTACK_PROXY
	// The address and port of a HTTPS proxy
	struct sockaddr_in6 ProxyAddress;
	char ProxiedRemoteHost[255];
	int ProxyState;
	char* ProxyUser;
	char* ProxyPass;
#endif

	ILibAsyncSocket_OnData OnData;
	ILibAsyncSocket_OnConnect OnConnect;
	ILibAsyncSocket_OnDisconnect OnDisconnect;
	ILibAsyncSocket_OnSendOK OnSendOK;
	ILibAsyncSocket_OnInterrupt OnInterrupt;

	ILibAsyncSocket_OnBufferSizeExceeded OnBufferSizeExceeded;
	ILibAsyncSocket_OnBufferReAllocated OnBufferReAllocated;

	void *LifeTime;
	void *user;
	void *user2;
	int user3;
	int PAUSE;
	int FinConnect;
	int BeginPointer;
	int EndPointer;
	char* buffer;
	int MallocSize;
	int InitialSize;

	struct ILibAsyncSocket_SendData *PendingSend_Head;
	struct ILibAsyncSocket_SendData *PendingSend_Tail;
	ILibSpinLock SendLock;

	int MaxBufferSize;
	int MaxBufferSizeExceeded;
	void *MaxBufferSizeUserObject;

	// Added for TLS support
#ifndef MICROSTACK_NOTLS
	int TLS_HandshakeError_Occurred;
	int SSLConnect;
	SSL* ssl;
	SSL_CTX *ssl_ctx;
	BIO *readBio, *writeBio;
	BUF_MEM *readBioBuffer, *writeBioBuffer;
	char readBioBuffer_mem[MEMORYCHUNKSIZE];
	int TLSHandshakeCompleted;
#ifdef MICROSTACK_TLS_DETECT
	int TLSChecked;
#endif
	#endif
	long long timeout_lastActivity;
	int timeout_milliSeconds;
	ILibAsyncSocket_TimeoutHandler timeout_handler;
}ILibAsyncSocketModule;

void ILibAsyncSocket_PostSelect(void* object,int slct, fd_set *readset, fd_set *writeset, fd_set *errorset);
void ILibAsyncSocket_PreSelect(void* object,fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime);
const int ILibMemory_ASYNCSOCKET_CONTAINERSIZE = (const int)sizeof(ILibAsyncSocketModule);

typedef enum ILibAsyncSocket_TLSPlainText_ContentType
{
	ILibAsyncSocket_TLSPlainText_ContentType_ChangeCipherSpec = 20,
	ILibAsyncSocket_TLSPlainText_ContentType_Alert = 21,
	ILibAsyncSocket_TLSPlainText_ContentType_Handshake = 22,
	ILibAsyncSocket_TLSPlainText_ContentType_ApplicationData = 23
}ILibAsyncSocket_TLSPlainText_ContentType;
typedef enum ILibAsyncSocket_TLSHandshakeType
{
	ILibAsyncSocket_TLSHandshakeType_hello = 0,
	ILibAsyncSocket_TLSHandshakeType_clienthello = 1,
	ILibAsyncSocket_TLSHandshakeType_serverhello = 2,
	ILibAsyncSocket_TLSHandshakeType_certificate = 11,
	ILibAsyncSocket_TLSHandshakeType_serverkeyexchange = 12,
	ILibAsyncSocket_TLSHandshakeType_certificaterequest = 13,
	ILibAsyncSocket_TLSHandshakeType_serverhellodone = 14,
	ILibAsyncSocket_TLSHandshakeType_certificateverify = 15,
	ILibAsyncSocket_TLSHandshakeType_clientkeyexchange = 16,
	ILibAsyncSocket_TLSHandshakeType_finished = 20
}ILibAsyncSocket_TLSHandshakeType;

#ifndef MICROSTACK_NOTLS
#ifdef _REMOTELOGGING
char* ILibAsyncSocket_ContentTypeString(ILibAsyncSocket_TLSPlainText_ContentType val)
{
	char *retVal = "unknown";
	switch (val)
	{
		case ILibAsyncSocket_TLSPlainText_ContentType_ChangeCipherSpec:
			retVal = "ChangeCipherSpec";
			break;
		case ILibAsyncSocket_TLSPlainText_ContentType_Alert:
			retVal = "Alert";
			break;
		case ILibAsyncSocket_TLSPlainText_ContentType_Handshake:
			retVal = "Handshake";
			break;
		case ILibAsyncSocket_TLSPlainText_ContentType_ApplicationData:
			retVal = "ApplicationData";
			break;
	}
	return retVal;
}
char* ILibAsyncSocket_HandshakeString(ILibAsyncSocket_TLSHandshakeType val)
{
	char *retVal = "unknown";
	switch (val)
	{
		case ILibAsyncSocket_TLSHandshakeType_hello:
			retVal = "hello";
			break;
		case ILibAsyncSocket_TLSHandshakeType_clienthello:
			retVal = "clienthello";
			break;
		case ILibAsyncSocket_TLSHandshakeType_serverhello:
			retVal = "serverhello";
			break;
		case ILibAsyncSocket_TLSHandshakeType_certificate:
			retVal = "certificate";
			break;
		case ILibAsyncSocket_TLSHandshakeType_serverkeyexchange:
			retVal = "serverkeyexchange";
			break;
		case ILibAsyncSocket_TLSHandshakeType_certificaterequest:
			retVal = "certificaterequest";
			break;
		case ILibAsyncSocket_TLSHandshakeType_serverhellodone:
			retVal = "serverhellodone";
			break;
		case ILibAsyncSocket_TLSHandshakeType_certificateverify:
			retVal = "certificateverify";
			break;
		case ILibAsyncSocket_TLSHandshakeType_clientkeyexchange:
			retVal = "clientkeyexchange";
			break;
		case ILibAsyncSocket_TLSHandshakeType_finished:
			retVal = "finished";
			break;
	}
	return retVal;
}
#else
#define ILibAsyncSocket_HandshakeString(val) ""
#define ILibAsyncSocket_ContentTypeString(val) ""
#endif
int ILibAsyncSocket_TLSDetect(ILibAsyncSocketModule *module, char* buffer, int offset, int endPointer)
{
	if (endPointer < 5) { return 0; }

	ILibAsyncSocket_TLSPlainText_ContentType contentType = (ILibAsyncSocket_TLSPlainText_ContentType)buffer[offset+0];
	unsigned char versionMajor = buffer[offset+1];
	//unsigned char versionMinor = buffer[offset+2];
	//unsigned short length = ntohs(((unsigned short*)(buffer+offset+3))[0]);
	ILibAsyncSocket_TLSHandshakeType tlsHandshakeType = (ILibAsyncSocket_TLSHandshakeType)(buffer+offset+5)[0];

	UNREFERENCED_PARAMETER(endPointer);
	UNREFERENCED_PARAMETER(module);

	if(contentType == ILibAsyncSocket_TLSPlainText_ContentType_Handshake && versionMajor >= 1 && (tlsHandshakeType == ILibAsyncSocket_TLSHandshakeType_hello || tlsHandshakeType == ILibAsyncSocket_TLSHandshakeType_clienthello || tlsHandshakeType == ILibAsyncSocket_TLSHandshakeType_serverhello))
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
void ILibAsyncSocket_TLSHeader_Parse(ILibAsyncSocketModule *module, char* buffer, int offset, int endPointer)
{
#if defined(_REMOTELOGGING) || defined(MICROSTACK_TLS_DETECT)
	ILibAsyncSocket_TLSPlainText_ContentType contentType = (ILibAsyncSocket_TLSPlainText_ContentType)buffer[offset + 0];
#endif
#ifdef _REMOTELOGGING
	unsigned char versionMajor = buffer[offset + 1];
	unsigned char versionMinor = buffer[offset+2];
	ILibAsyncSocket_TLSHandshakeType tlsHandshakeType = (ILibAsyncSocket_TLSHandshakeType)(buffer + offset + 5)[0];
#endif

	UNREFERENCED_PARAMETER(endPointer);
	
#ifdef _REMOTELOGGING
	ILibRemoteLogging_printf(ILibChainGetLogger(module->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_WebRTC_DTLS, ILibRemoteLogging_Flags_VerbosityLevel_2, "ILibAsyncSocket(%p) TLS Header Parsing:  TLS v%u.%u , Type[%s]", (void*)module, versionMajor - 2, versionMinor - 1, ILibAsyncSocket_ContentTypeString(contentType));
	if (contentType == ILibAsyncSocket_TLSPlainText_ContentType_Handshake)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(module->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_WebRTC_DTLS, ILibRemoteLogging_Flags_VerbosityLevel_2, "...Handshake Step = %s", ILibAsyncSocket_HandshakeString(tlsHandshakeType));
	}
#endif

#ifdef MICROSTACK_TLS_DETECT
	if(contentType == ILibAsyncSocket_TLSPlainText_ContentType_ApplicationData) { module->TLSHandshakeCompleted = 1; }
#endif
}
int ILibAsyncSocket_IsUsingTls(ILibAsyncSocket_SocketModule AsyncSocketToken)
{
	return(((struct ILibAsyncSocketModule*)AsyncSocketToken)->ssl != NULL ? 1:0);
}
#endif

//
// An internal method called by Chain as Destroy, to cleanup AsyncSocket
//
// <param name="socketModule">The AsyncSocketModule</param>
void ILibAsyncSocket_Destroy(void *socketModule)
{
	struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;
	struct ILibAsyncSocket_SendData *temp, *current;

	// Call the interrupt event if necessary
	if (!ILibAsyncSocket_IsFree(module))
	{
		if (module->OnInterrupt != NULL) module->OnInterrupt(module, module->user);
	}

	#ifndef MICROSTACK_NOTLS
	// If this is an SSL socket, free the SSL state
	if (module->ssl != NULL)
	{
		SSL_TRACE1("SSL_free()");
		SSL_free(module->ssl); // Frees SSL session and BIO buffer at the same time
		module->ssl = NULL;
		SSL_TRACE2("SSL_free()");
	}
	#endif

	// Close socket if necessary
	if (module->internalSocket != ~0)
	{
#if defined(_WIN32_WCE) || defined(WIN32)
#if defined(WINSOCK2)
		shutdown(module->internalSocket, SD_BOTH);
#endif
		closesocket(module->internalSocket);
#elif defined(_POSIX)
		shutdown(module->internalSocket, SHUT_RDWR);
		close(module->internalSocket);
#endif
		module->internalSocket = (SOCKET)~0;
	}

	// Free the buffer if necessary
	if (module->buffer != NULL)
	{
		if (module->buffer != ILibAsyncSocket_ScratchPad) free(module->buffer);
		module->buffer = NULL;
		module->MallocSize = 0;
	}

	// Clear all the data that is pending to be sent
	temp = current = module->PendingSend_Head;
	while (current != NULL)
	{
		temp = current->Next;
		if (current->UserFree == 0) free(current->buffer);
		free(current);
		current = temp;
	}

	module->FinConnect = 0;
	module->user = NULL;
	#ifndef MICROSTACK_NOTLS
	module->SSLConnect = 0;
	#endif
}
/*! \fn ILibAsyncSocket_SetReAllocateNotificationCallback(ILibAsyncSocket_SocketModule AsyncSocketToken, ILibAsyncSocket_OnBufferReAllocated Callback)
\brief Set the callback handler for when the internal data buffer has been resized
\param AsyncSocketToken The specific connection to set the callback with
\param Callback The callback handler to set
*/
void ILibAsyncSocket_SetReAllocateNotificationCallback(ILibAsyncSocket_SocketModule AsyncSocketToken, ILibAsyncSocket_OnBufferReAllocated Callback)
{
	if (AsyncSocketToken != NULL) { ((struct ILibAsyncSocketModule*)AsyncSocketToken)->OnBufferReAllocated = Callback; }
}

ILibTransport_DoneState ILibAsyncSocket_TransportSend(void *transport, char* buffer, int bufferLength, ILibTransport_MemoryOwnership ownership, ILibTransport_DoneState done)
{
	UNREFERENCED_PARAMETER(done);
	return((ILibTransport_DoneState)ILibAsyncSocket_Send(transport, buffer, bufferLength, (enum ILibAsyncSocket_MemoryOwnership)ownership));
}


/*! \fn ILibCreateAsyncSocketModule(void *Chain, int initialBufferSize, ILibAsyncSocket_OnData OnData, ILibAsyncSocket_OnConnect OnConnect, ILibAsyncSocket_OnDisconnect OnDisconnect,ILibAsyncSocket_OnSendOK OnSendOK)
\brief Creates a new AsyncSocketModule
\param Chain The chain to add this module to. (Chain must <B>not</B> be running)
\param initialBufferSize The initial size of the receive buffer
\param OnData Function Pointer that triggers when Data is received
\param OnConnect Function Pointer that triggers upon successfull connection establishment
\param OnDisconnect Function Pointer that triggers upon disconnect
\param OnSendOK Function Pointer that triggers when pending sends are complete
\param AutoFreeMemorySize Amount of memory to create along side the object, that will be freed when the parent object is freed
\returns An ILibAsyncSocket token
*/
ILibAsyncSocket_SocketModule ILibCreateAsyncSocketModuleWithMemory(void *Chain, int initialBufferSize, ILibAsyncSocket_OnData OnData, ILibAsyncSocket_OnConnect OnConnect, ILibAsyncSocket_OnDisconnect OnDisconnect, ILibAsyncSocket_OnSendOK OnSendOK, int UserMappedMemorySize)
{
	struct ILibAsyncSocketModule *RetVal = (struct ILibAsyncSocketModule*)ILibChain_Link_Allocate(sizeof(struct ILibAsyncSocketModule), UserMappedMemorySize);
	RetVal->Transport.ChainLink.MetaData = ILibMemory_SmartAllocate_FromString("ILibAsyncSocket");
	RetVal->Transport.IdentifierFlags = ILibTransports_AsyncSocket;
	RetVal->Transport.SendPtr = &ILibAsyncSocket_TransportSend;
	RetVal->Transport.ClosePtr = &ILibAsyncSocket_Disconnect;
	RetVal->Transport.PendingBytesPtr = &ILibAsyncSocket_GetPendingBytesToSend;
	RetVal->Transport.ChainLink.ParentChain = Chain;

	if (initialBufferSize != 0)
	{
		// Use a new buffer
		if ((RetVal->buffer = (char*)malloc(initialBufferSize)) == NULL) ILIBCRITICALEXIT(254);
	}
	else
	{
		// Use a static buffer, often used for UDP.
		initialBufferSize = sizeof(ILibAsyncSocket_ScratchPad);
		RetVal->buffer = ILibAsyncSocket_ScratchPad;
	}
	RetVal->Transport.ChainLink.PreSelectHandler = &ILibAsyncSocket_PreSelect;
	RetVal->Transport.ChainLink.PostSelectHandler = &ILibAsyncSocket_PostSelect;
	RetVal->Transport.ChainLink.DestroyHandler = &ILibAsyncSocket_Destroy;
	RetVal->internalSocket = (SOCKET)~0;
	RetVal->OnData = OnData;
	RetVal->OnConnect = OnConnect;
	RetVal->OnDisconnect = OnDisconnect;
	RetVal->OnSendOK = OnSendOK;
	RetVal->InitialSize = initialBufferSize;
	RetVal->MallocSize = initialBufferSize;
	RetVal->LifeTime = ILibGetBaseTimer(Chain); //ILibCreateLifeTime(Chain);

	ILibSpinLock_Init(&(RetVal->SendLock));

	ILibAddToChain(Chain, RetVal);

	return((void*)RetVal);
}

/*! \fn ILibAsyncSocket_ClearPendingSend(ILibAsyncSocket_SocketModule socketModule)
\brief Clears all the pending data to be sent for an AsyncSocket
\param socketModule The ILibAsyncSocket to clear
*/
void ILibAsyncSocket_ClearPendingSend(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	struct ILibAsyncSocket_SendData *data, *temp;

	data = module->PendingSend_Head;
	module->PendingSend_Tail = NULL;
	module->PendingSend_Head = NULL;
	module->PendingBytesToSend = 0;
	while (data != NULL)
	{
		temp = data->Next;
		// We only need to free this if we have ownership of this memory
		if (data->UserFree == ILibAsyncSocket_MemoryOwnership_CHAIN) free(data->buffer);
		free(data);
		data = temp;
	}
}

void ILibAsyncSocket_SendError(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;

	module->PAUSE = 1;
	ILibAsyncSocket_ClearPendingSend(module); // This causes a segfault
	
	ILibSpinLock_UnLock(&(module->SendLock));

	// Ensure Calling On_Disconnect with MicroStackThread
	ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);

	ILibSpinLock_Lock(&(module->SendLock));
}

ILibSpinLock *ILibAsyncSocket_GetSpinLock(ILibAsyncSocket_SocketModule socketModule)
{
	return(&((struct ILibAsyncSocketModule*)socketModule)->SendLock);
}


/*! \fn ILibAsyncSocket_SendTo(ILibAsyncSocket_SocketModule socketModule, char* buffer, int length, int remoteAddress, unsigned short remotePort, enum ILibAsyncSocket_MemoryOwnership UserFree)
\brief Sends data on an AsyncSocket module to a specific destination. (Valid only for <B>UDP</B>)
\param socketModule The ILibAsyncSocket module to send data on
\param remoteAddress The IPAddress of the destination 
\param count The number of triplets passed in the ellipses. A triplet consists of {char* buffer, int length, ILibAsyncSocket_MemoryOwnership userFree}
\returns \a ILibAsyncSocket_SendStatus indicating the send status
*/
ILibAsyncSocket_SendStatus ILibAsyncSocket_SendTo_MultiWrite(ILibAsyncSocket_SocketModule socketModule, struct sockaddr *remoteAddress, unsigned int count, ...)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	struct ILibAsyncSocket_SendData *data;
	int bytesSent = 0;
	enum ILibAsyncSocket_SendStatus retVal = ILibAsyncSocket_ALL_DATA_SENT;
	unsigned int vi;
	char *buffer;
	size_t bufferLen;
	ILibAsyncSocket_MemoryOwnership UserFree;
	int lockOverride = ((count & ILibAsyncSocket_LOCK_OVERRIDE) == ILibAsyncSocket_LOCK_OVERRIDE) ? (count ^= ILibAsyncSocket_LOCK_OVERRIDE, 1) : 0;

	// If the socket is empty, return now.
	if (socketModule == NULL) return ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR;
	int notok = 0;

	va_list vlist;
	va_start(vlist, count); 
	
#ifndef MICROSTACK_NOTLS
	if (module->ssl != NULL)
	{
		if (lockOverride == 0) { ILibSpinLock_Lock(&(module->SendLock)); }
		
		for (vi = 0; vi < count; ++vi)
		{
			buffer = va_arg(vlist, char*);
			bufferLen = va_arg(vlist, size_t);
			UserFree = va_arg(vlist, ILibAsyncSocket_MemoryOwnership);

			if (bufferLen > INT32_MAX || notok != 0)
			{
				if (UserFree == ILibAsyncSocket_MemoryOwnership_CHAIN) { free(buffer); }
				notok = 1;
				continue;
			}

			SSL_TRACE1("SSL_write()");
			SSL_write(module->ssl, buffer, (int)bufferLen); // No dataloss, becuase we capped at INT32_MAX
			SSL_TRACE2("SSL_write()");
			TLSLOG1("SSL_write[%d]: %d bytes...\n", module->internalSocket, bufferLen);

			if (UserFree == ILibAsyncSocket_MemoryOwnership_CHAIN) { free(buffer); }
		}
		va_end(vlist); 
	
		if (notok == 0)
		{
			if (module->PendingSend_Tail == NULL)
			{
				// No pending data, so we can send now
				if (module->writeBioBuffer->length > 0)
				{
					BIO_clear_retry_flags(module->writeBio); // Klocwork reports this could block, but this is a memory bio, so it will never block.
					bytesSent = send(module->internalSocket, module->writeBioBuffer->data, (int)(module->writeBioBuffer->length), MSG_NOSIGNAL); // Klocwork reports that this could block while holding a lock... This socket has been set to O_NONBLOCK, so that will never happen
					TLSLOG1("--> SOCKET WRITE[%d]: %d bytes...\n", module->internalSocket, bytesSent);
#ifdef WIN32
					if ((bytesSent > 0 && bytesSent < (int)(module->writeBioBuffer->length)) || (bytesSent < 0 && WSAGetLastError() == WSAEWOULDBLOCK))
#else
					if ((bytesSent > 0 && bytesSent < (int)(module->writeBioBuffer->length)) || (bytesSent < 0 && errno == EWOULDBLOCK))
#endif
					{
						// Still Pending Data to be sent
						data = (ILibAsyncSocket_SendData*)ILibMemory_Allocate(sizeof(ILibAsyncSocket_SendData), bytesSent < 0 ? 0 : (int)(module->writeBioBuffer->length) - bytesSent, NULL, NULL);
						data->UserFree = ILibAsyncSocket_MemoryOwnership_BIO;
						data->bytesSent = 0;
						module->PendingSend_Head = module->PendingSend_Tail = data;
						if (bytesSent > 0)
						{
							// Some data was sent, so we need to pull the data and buffer it
							module->PendingSend_Head->buffer = ILibMemory_GetExtraMemory(data, sizeof(ILibAsyncSocket_SendData));
							module->PendingSend_Head->bufferSize = (int)(module->writeBioBuffer->length) - bytesSent;
							memcpy_s(module->PendingSend_Head->buffer, module->PendingSend_Head->bufferSize, module->writeBioBuffer->data + bytesSent, module->PendingSend_Head->bufferSize);

							module->TotalBytesSent += bytesSent;
							module->PendingBytesToSend = (unsigned int)(module->PendingSend_Head->bufferSize);
							TLSLOG1("   --> BUFFERING[%d]: %d bytes...\n", module->internalSocket, module->PendingSend_Head->bufferSize);

							ignore_result(BIO_reset(module->writeBio));
						}
						else if (bytesSent < 0)
						{
							TLSLOG1("   -- > [INCOMPLETE] Accumulated into BIOBUFFER[%d]\n", module->internalSocket);
						}
						retVal = ILibAsyncSocket_NOT_ALL_DATA_SENT_YET;
					}
					else if (bytesSent == module->writeBioBuffer->length)
					{
						retVal = ILibAsyncSocket_ALL_DATA_SENT;
						ignore_result(BIO_reset(module->writeBio));
						module->TotalBytesSent += bytesSent;
						module->PendingBytesToSend = (unsigned int)(module->writeBioBuffer->length);
						TLSLOG1("   --> COMPLETE[%d]\n", module->internalSocket);
					}
					else
					{
						retVal = ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR;
						ILibAsyncSocket_SendError(module);
					}
				}
				else
				{
					// Something went wrong
					retVal = ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR;
					ILibAsyncSocket_SendError(module);
				}
			}
			else
			{
				// Send will happen in ILibAsyncSocket_PostSelect()
				retVal = ILibAsyncSocket_NOT_ALL_DATA_SENT_YET;
				module->PendingBytesToSend = (unsigned int)(module->writeBioBuffer->length);
				TLSLOG1("   --> [IN PROGRESS] Accumulated into BIOBUFFER[%d]...\n", module->internalSocket);
			}
		}
		else
		{
			retVal = ILibAsyncSocket_BUFFER_TOO_LARGE;
			ILibAsyncSocket_SendError(module);
		}

		if (lockOverride == 0) { ILibSpinLock_UnLock(&(module->SendLock)); }
		if (retVal != ILibAsyncSocket_ALL_DATA_SENT && !ILibIsRunningOnChainThread(module->Transport.ChainLink.ParentChain)) ILibForceUnBlockChain(module->Transport.ChainLink.ParentChain);
		return retVal;
	}
#endif

	// If we got here, we aren't doing TLS
	if (lockOverride == 0) { ILibSpinLock_Lock(&(module->SendLock)); }
	if (module->internalSocket == ~0)
	{
		// Too Bad, the socket closed
		for (vi = 0; vi < count; ++vi)
		{
			buffer = va_arg(vlist, char*);
			bufferLen = va_arg(vlist, int);
			UserFree = va_arg(vlist, ILibAsyncSocket_MemoryOwnership);
			if (UserFree == ILibAsyncSocket_MemoryOwnership_CHAIN) { free(buffer); }
		}
		if (lockOverride == 0) { ILibSpinLock_UnLock(&(module->SendLock)); }
		va_end(vlist);
		return ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR;
	}

	for (vi = 0; vi < count; ++vi)
	{
		buffer = va_arg(vlist, char*);
		bufferLen = va_arg(vlist, size_t);
		UserFree =  va_arg(vlist, ILibAsyncSocket_MemoryOwnership);

		if (bufferLen > INT32_MAX || notok != 0)
		{
			notok = 1;
			if (UserFree == ILibAsyncSocket_MemoryOwnership_CHAIN) { free(buffer); }
			continue;
		}
		if (module->PendingSend_Tail != NULL || module->FinConnect == 0)
		{
			// There are still bytes that are pending to be sent, or pending connection, so we need to queue this up
			data = (ILibAsyncSocket_SendData*)ILibMemory_Allocate(sizeof(ILibAsyncSocket_SendData), 0, NULL, NULL);
			data->bufferSize = (int)bufferLen; // No dataloss, capped to INT32_MAX
			module->PendingBytesToSend += (int)bufferLen;
			if (UserFree == ILibAsyncSocket_MemoryOwnership_USER)
			{
				if ((data->buffer = (char*)malloc(data->bufferSize)) == NULL) ILIBCRITICALEXIT(254);
				memcpy_s(data->buffer, data->bufferSize, buffer, bufferLen);
				data->UserFree = ILibAsyncSocket_MemoryOwnership_CHAIN;
			}
			else
			{
				data->buffer = buffer;
				data->UserFree = UserFree;
			}
			data->bytesSent = 0;
			if (remoteAddress != NULL) memcpy_s(&(data->remoteAddress), sizeof(struct sockaddr_in6), remoteAddress, INET_SOCKADDR_LENGTH(remoteAddress->sa_family));
			data->Next = NULL;

			if (module->PendingSend_Tail == NULL)
			{
				module->PendingSend_Head = module->PendingSend_Tail = data;
			}
			else
			{
				module->PendingSend_Tail->Next = data;
				module->PendingSend_Tail = data;
			}
		}
		else if (module->PendingSend_Tail == NULL && module->FinConnect != 0)
		{
			// No pending data, so we can try to send now
			if (remoteAddress == NULL || remoteAddress->sa_family == AF_UNIX)
			{
				// Set MSG_NOSIGNAL since we don't want to get Broken Pipe signals in Linux, ignored if Windows.
				bytesSent = send(module->internalSocket, buffer, (int)bufferLen, MSG_NOSIGNAL);  // No dataloss, capped to INT32_MAX
			}
			else
			{
				bytesSent = sendto(module->internalSocket, buffer, (int)bufferLen, MSG_NOSIGNAL, (struct sockaddr*)remoteAddress, INET_SOCKADDR_LENGTH(remoteAddress->sa_family)); // No dataloss, capped to INT32_MAX
			}
#ifdef WIN32
			if ((bytesSent > 0 && bytesSent < (int)bufferLen) || (bytesSent < 0 && WSAGetLastError() == WSAEWOULDBLOCK))
#else
			if ((bytesSent > 0 && bytesSent < (int)bufferLen) || (bytesSent < 0 && errno == EWOULDBLOCK))
#endif
			{
				// Not all data was sent
				if (bytesSent < 0) { bytesSent = 0; }
				data = (ILibAsyncSocket_SendData*)ILibMemory_Allocate(sizeof(ILibAsyncSocket_SendData), 0, NULL, NULL);
				if (UserFree == ILibAsyncSocket_MemoryOwnership_USER)
				{
					data->bufferSize = (int)bufferLen - bytesSent; // No dataloss, capped to INT32_MAX
					if ((data->buffer = (char*)malloc(data->bufferSize)) == NULL) ILIBCRITICALEXIT(254);
					memcpy_s(data->buffer, data->bufferSize, buffer + bytesSent, data->bufferSize);
					data->UserFree = ILibAsyncSocket_MemoryOwnership_CHAIN;
				}
				else
				{
					data->buffer = buffer;
					data->bufferSize = (int)bufferLen; // No dataloss, capped to INT32_MAX
					data->bytesSent = bytesSent;
					data->UserFree = UserFree;
				}
				module->PendingSend_Head = module->PendingSend_Tail = data;
				retVal = ILibAsyncSocket_NOT_ALL_DATA_SENT_YET;
			}
			else if (bytesSent == (int)bufferLen) // No dataloss, capped to INT32_MAX
			{
				// All Data was sent
				retVal = ILibAsyncSocket_ALL_DATA_SENT;
				if (UserFree == ILibAsyncSocket_MemoryOwnership_CHAIN) { free(buffer); }
			}
			else
			{
				retVal = ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR;
				ILibAsyncSocket_SendError(module);
			}
			if (bytesSent > 0) 
			{
				module->TotalBytesSent += bytesSent; module->PendingBytesToSend -= bytesSent;
				if ((int)(module->PendingBytesToSend) < 0) { module->PendingBytesToSend = 0; }
			}
		}
	}
	va_end(vlist); 

	if (lockOverride == 0) { ILibSpinLock_UnLock(&(module->SendLock)); }
	if (notok != 0)
	{
		retVal = ILibAsyncSocket_BUFFER_TOO_LARGE;
		ILibAsyncSocket_SendError(module);
	}

	if (retVal != ILibAsyncSocket_ALL_DATA_SENT && !ILibIsRunningOnChainThread(module->Transport.ChainLink.ParentChain)) ILibForceUnBlockChain(module->Transport.ChainLink.ParentChain);
	return (retVal);
}

/*! \fn ILibAsyncSocket_Disconnect(ILibAsyncSocket_SocketModule socketModule)
\brief Disconnects an ILibAsyncSocket
\param socketModule The ILibAsyncSocket to disconnect
*/
void ILibAsyncSocket_Disconnect(ILibAsyncSocket_SocketModule socketModule)
{
#if defined(_WIN32_WCE) || defined(WIN32)
	SOCKET s;
#else
	int s;
#endif
	#ifndef MICROSTACK_NOTLS
	SSL *wasssl;
	#endif

	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	if (module == NULL) { return; }

	ILibRemoteLogging_printf(ILibChainGetLogger(module->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_AsyncSocket, ILibRemoteLogging_Flags_VerbosityLevel_1, "AsyncSocket[%p] << DISCONNECT", (void*)module);

	ILibSpinLock_Lock(&(module->SendLock));
	module->timeout_handler = NULL;
	module->timeout_milliSeconds = 0;

	#ifndef MICROSTACK_NOTLS
	wasssl = module->ssl;
	if (module->ssl != NULL)
	{
		SSL_TRACE1("ILibAsyncSocket_Disconnect()");
		SSL_shutdown(module->ssl);
		ILibSpinLock_UnLock(&(module->SendLock));
		SSL_free(module->ssl); // Frees SSL session and both BIO buffers at the same time
		ILibSpinLock_Lock(&(module->SendLock));
		module->ssl = NULL;
		SSL_TRACE2("ILibAsyncSocket_Disconnect()");
	}
	#endif


	// There is an associated socket that is still valid, so we need to close it
	module->PAUSE = 1;
	s = module->internalSocket;
	module->internalSocket = (SOCKET)~0;
	if (s != -1)
	{
#if defined(_WIN32_WCE) || defined(WIN32)
#if defined(WINSOCK2)
		shutdown(s, SD_SEND);
#endif
		closesocket(s);
#elif defined(_POSIX)
		shutdown(s, SHUT_WR);
		close(s);
#endif
	}

	// Since the socket is closing, we need to clear the data that is pending to be sent
	ILibAsyncSocket_ClearPendingSend(socketModule);
	ILibSpinLock_UnLock(&(module->SendLock));

	#ifndef MICROSTACK_NOTLS
	if (wasssl == NULL)
	{
	#endif
		// This was a normal socket, fire the event notifying the user. Depending on connection state, we event differently
		if (module->FinConnect <= 0 && module->OnConnect != NULL) { module->OnConnect(module, 0, module->user); } // Connection Failed
		if (module->FinConnect > 0 && module->OnDisconnect != NULL) { module->OnDisconnect(module, module->user); } // Socket Disconnected
	#ifndef MICROSTACK_NOTLS
	}
	else
	{
		// This was a SSL socket, fire the event notifying the user. Depending on connection state, we event differently
		if (module->SSLConnect == 0 && module->OnConnect != NULL) { module->OnConnect(module, 0, module->user); } // Connection Failed
		if (module->SSLConnect != 0 && module->OnDisconnect != NULL) { module->OnDisconnect(module, module->user); } // Socket Disconnected
	}
	#endif
	module->FinConnect = 0;
	module->user = NULL;
	#ifndef MICROSTACK_NOTLS
	module->SSLConnect = 0;
	#endif
	

}


/*! \fn ILibAsyncSocket_ConnectTo(ILibAsyncSocket_SocketModule socketModule, int localInterface, int remoteInterface, int remotePortNumber, ILibAsyncSocket_OnInterrupt InterruptPtr,void *user)
\brief Attempts to establish a TCP connection
\param socketModule The ILibAsyncSocket to initiate the connection
\param localInterface The interface to use to establish the connection
\param remoteInterface The remote interface to connect to
\param InterruptPtr Function Pointer that triggers if connection attempt is interrupted
\param user User object that will be passed to the \a OnConnect method
*/
void ILibAsyncSocket_ConnectTo(void* socketModule, struct sockaddr *localInterface, struct sockaddr *remoteInterface, ILibAsyncSocket_OnInterrupt InterruptPtr, void *user)
{
	int flags = 1, v;
	char *tmp;
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	struct sockaddr_in6 any;

	// If there is something going on and we try to connect using this socket, fail! This is not supposed to happen.
	if (module->internalSocket != -1)
	{
		PRINTERROR(); ILIBCRITICALEXIT2(253, (int)(module->internalSocket));
	}

	// Clean up
	memset(&(module->RemoteAddress), 0, sizeof(struct sockaddr_in6));
	memset(&(module->LocalAddress) , 0, sizeof(struct sockaddr_in6));
	memset(&(module->SourceAddress), 0, sizeof(struct sockaddr_in6));
#ifdef _POSIX
	memset(&(module->DomainAddress), 0, sizeof(struct sockaddr_un));
#endif

	// Setup
	if (remoteInterface != NULL)
	{
		if (remoteInterface->sa_family == AF_UNIX)
		{
#ifdef _POSIX
			memcpy_s(&(module->DomainAddress), sizeof(struct sockaddr_un), remoteInterface, sizeof(struct sockaddr_un));
#endif
			module->RemoteAddress.sin6_family = AF_UNIX;
		}
		else
		{
			memcpy_s(&(module->RemoteAddress), sizeof(struct sockaddr_in6), remoteInterface, INET_SOCKADDR_LENGTH(remoteInterface->sa_family));
		}
	}
	module->PendingBytesToSend = 0;
	module->TotalBytesSent = 0;
	module->PAUSE = 0;
	module->user = user;
	module->OnInterrupt = InterruptPtr;
	if ((tmp = (char*)realloc(module->buffer, module->InitialSize)) == NULL) ILIBCRITICALEXIT(254);
	module->buffer = tmp;
	module->MallocSize = module->InitialSize;

	// If localInterface is NULL, we will assume INADDRANY - IPv4/IPv6 based on remote address
	if (localInterface == NULL && module->RemoteAddress.sin6_family != AF_UNIX)
	{
		memset(&any, 0, sizeof(struct sockaddr_in6));
		#ifdef MICROSTACK_PROXY
		if (module->ProxyAddress.sin6_family == 0)
		{
			any.sin6_family = remoteInterface->sa_family;
		}
		else
		{
			any.sin6_family = module->ProxyAddress.sin6_family;
		}
		#else
		any.sin6_family = remoteInterface->sa_family;
		#endif
		localInterface = (struct sockaddr*)&any;
	}

	// The local port should always be zero
#ifdef _DEBUG
	if (localInterface != NULL)
	{
		if (localInterface->sa_family == AF_INET && ((struct sockaddr_in*)localInterface)->sin_port != 0) { PRINTERROR(); ILIBCRITICALEXIT(253); }
		if (localInterface->sa_family == AF_INET6 && ((struct sockaddr_in6*)localInterface)->sin6_port != 0) { PRINTERROR(); ILIBCRITICALEXIT(253); }
	}
#endif

	// Allocate a new socket
	if (module->RemoteAddress.sin6_family != AF_UNIX)
	{
		if (((struct sockaddr_in*)localInterface)->sin_family == AF_UNSPEC ||  (module->internalSocket = ILibGetSocket(localInterface, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{
			module->internalSocket = ~0;
			module->FinConnect = -1;
			ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);
			return;
		}
	}
	else
	{
		if ((int)(module->internalSocket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) { ILIBCRITICALEXIT(253); return; }
	}

	// Initialise the buffer pointers, since no data is in them yet.
	module->FinConnect = 0;
	#ifndef MICROSTACK_NOTLS
	module->SSLConnect = 0;
	#endif
	module->BeginPointer = 0;
	module->EndPointer = 0;

	if (module->RemoteAddress.sin6_family != AF_UNIX)
	{
		// Turn on keep-alives for the socket
		if (setsockopt(module->internalSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&flags, sizeof(flags)) != 0) ILIBCRITICALERREXIT(253);
	}

	// Set the socket to non-blocking mode, because we need to play nice and share the MicroStack thread
#if defined(_WIN32_WCE) || defined(WIN32)
	ioctlsocket(module->internalSocket, FIONBIO, (u_long *)(&flags));
#elif defined(_POSIX)
	flags = fcntl(module->internalSocket, F_GETFL,0);
	fcntl(module->internalSocket, F_SETFL, O_NONBLOCK | flags);
#endif

	// Connect the socket, and force the chain to unblock, since the select statement doesn't have us in the fdset yet.
#ifdef MICROSTACK_PROXY
	if (module->ProxyAddress.sin6_family != 0 && module->RemoteAddress.sin6_family != AF_UNIX)
	{
		if ((v=connect(module->internalSocket, (struct sockaddr*)&(module->ProxyAddress), INET_SOCKADDR_LENGTH(module->ProxyAddress.sin6_family))) != -1)
		{
			// Connect failed. Set a short time and call disconnect.
			module->FinConnect = -1;
			ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);
			return;
		}
	}
	else
#endif
		if (module->RemoteAddress.sin6_family != AF_UNIX)
		{
			if ((v=connect(module->internalSocket, (struct sockaddr*)remoteInterface, INET_SOCKADDR_LENGTH(remoteInterface->sa_family))) != -1)
			{
				// Connect failed. Set a short time and call disconnect.
				module->FinConnect = -1;
				ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);
				return;
			}
		}
		else
		{
#ifdef _POSIX
			if ((v=connect(module->internalSocket, (struct sockaddr *)&(module->DomainAddress), SUN_LEN(&(module->DomainAddress)))) < 0)
#endif
			{
				// Connect failed. Set a short time and call disconnect.
				module->FinConnect = -1;
				ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);
				return;
			}
		}

#ifdef _DEBUG
	#ifdef _POSIX
		if (v != 0 && errno != EINPROGRESS) // The result of the connect should always be "WOULD BLOCK" on Linux. But sometimes this fails.
		{
			// This happens when the interface is no longer available. Disconnect socket.
			module->FinConnect = -1;
			ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);
			return;
		}
	#endif
	#ifdef WIN32
		{
			if (GetLastError() != WSAEWOULDBLOCK) // The result of the connect should always be "WOULD BLOCK" on Windows.
			{
				// This happens when the interface is no longer available. Disconnect socket.
				module->FinConnect = -1;
				ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);
				return;
			}
		}
	#endif
#endif

	ILibForceUnBlockChain(module->Transport.ChainLink.ParentChain);
}

#ifdef MICROSTACK_PROXY
void ILibAsyncSocket_ClearProxySettings(void *socketModule)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	memset(&(module->ProxyAddress), 0, sizeof(struct sockaddr_in6));
	memset(module->ProxiedRemoteHost, 0, sizeof(module->ProxiedRemoteHost));
	module->ProxyState = 0;
}

//! Connect using an HTTPS proxy. If "proxyAddress" is set to NULL, this call acts just to a normal connect call without a proxy.
/*!
	\param socketModule ILibAsyncSocket Client to initiate the connection
	\param localInterface Local endpoint to originate the connection request from
	\param remoteAddress Destination endpoint to connect to
	\param proxyAddress Proxy Server to relay the connection thru.
	\param proxyUser Proxy Server username (Username is stored by reference, so this memory must remain valid for duration of connection)
	\param proxyPass Proxy Server password (Password is stored by reference, so this memory must remain valid for duration of connection)
	\param InterruptPtr Event handler triggered if connection request is interrupted
	\param user Custom user state data
*/
void ILibAsyncSocket_ConnectToProxy(void* socketModule, struct sockaddr *localInterface, struct sockaddr *remoteAddress, struct sockaddr *proxyAddress, char* proxyUser, char* proxyPass, ILibAsyncSocket_OnInterrupt InterruptPtr, void *user)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	memset(&(module->ProxyAddress), 0, sizeof(struct sockaddr_in6));
	memset(module->ProxiedRemoteHost, 0, sizeof(module->ProxiedRemoteHost));
	module->ProxyState = 0;
	module->ProxyUser = proxyUser; // Proxy user & password are kept by reference!!!
	module->ProxyPass = proxyPass;

	if (proxyAddress != NULL) memcpy_s(&(module->ProxyAddress), sizeof(struct sockaddr_in6), proxyAddress, INET_SOCKADDR_LENGTH(proxyAddress->sa_family));
	ILibAsyncSocket_ConnectTo(socketModule, localInterface, remoteAddress, InterruptPtr, user);
}
void ILibAsyncSocket_ConnectToProxyEx(void* socketModule, struct sockaddr *localInterface, char *remoteAddressAndPort, struct sockaddr *proxyAddress, char* proxyUser, char* proxyPass, ILibAsyncSocket_OnInterrupt InterruptPtr, void *user)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	memset(&(module->ProxyAddress), 0, sizeof(struct sockaddr_in6));
	module->ProxyState = 0;
	module->ProxyUser = proxyUser; // Proxy user & password are kept by reference!!!
	module->ProxyPass = proxyPass;
	
	size_t proxylen = strnlen_s(remoteAddressAndPort, sizeof(module->ProxiedRemoteHost) - 1);
	memcpy_s(module->ProxiedRemoteHost, sizeof(module->ProxiedRemoteHost), remoteAddressAndPort, proxylen);

	if (proxyAddress != NULL) memcpy_s(&(module->ProxyAddress), sizeof(struct sockaddr_in6), proxyAddress, INET_SOCKADDR_LENGTH(proxyAddress->sa_family));
	ILibAsyncSocket_ConnectTo(socketModule, localInterface, NULL, InterruptPtr, user);

}
#endif
#ifndef MICROSTACK_NOTLS
ILibAsyncSocket_SendStatus ILibAsyncSocket_ProcessEncryptedBuffer(ILibAsyncSocketModule *Reader)
{
	int j;
	ILibAsyncSocket_SendData *data;
	ILibAsyncSocket_SendStatus retVal = ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR;

	ILibSpinLock_Lock(&(Reader->SendLock));
	if (Reader->writeBioBuffer->length > 0)
	{
		if (Reader->PendingSend_Tail == NULL)
		{
			// No Pending Sends
			if (Reader->FinConnect == 0)
			{
				// Not connected yet, so lets make sure we send this stuff later
				data = (ILibAsyncSocket_SendData*)ILibMemory_Allocate(sizeof(ILibAsyncSocket_SendData), 0, NULL, NULL);
				data->UserFree = ILibAsyncSocket_MemoryOwnership_BIO;
				Reader->PendingSend_Head = Reader->PendingSend_Tail = data;
				retVal = ILibAsyncSocket_NOT_ALL_DATA_SENT_YET;
			}
			else
			{
				BIO_clear_retry_flags(Reader->writeBio);
				j = send(Reader->internalSocket, Reader->writeBioBuffer->data, (int)(Reader->writeBioBuffer->length), MSG_NOSIGNAL); // Klockwork says this can block, but it won't, because it's a nonblocking socket
				if (j > 0)
				{
					if (j < (int)(Reader->writeBioBuffer->length))
					{
						// Not all data was sent
						data = (ILibAsyncSocket_SendData*)ILibMemory_Allocate((int)sizeof(ILibAsyncSocket_SendData), (int)Reader->writeBioBuffer->length - j, NULL, NULL);
						data->buffer = ILibMemory_GetExtraMemory(data, (int)sizeof(ILibAsyncSocket_SendData));
						data->bufferSize = (int)Reader->writeBioBuffer->length - j;
						data->UserFree = ILibAsyncSocket_MemoryOwnership_BIO;
						memcpy_s(data->buffer, data->bufferSize, Reader->writeBioBuffer->data + j, data->bufferSize);
						Reader->PendingSend_Head = Reader->PendingSend_Tail = data;
						retVal = ILibAsyncSocket_NOT_ALL_DATA_SENT_YET;
						ignore_result(BIO_reset(Reader->writeBio));
					}
					else if (j == (int)(Reader->writeBioBuffer->length))
					{
						// All Data was sent
						ignore_result(BIO_reset(Reader->writeBio));
						retVal = ILibAsyncSocket_ALL_DATA_SENT;
					}
				}
			}
		}
		else
		{
			// Pending Sends
			// Don't need to do anything, becuase it'll get picked up in the PostSelect
		}
	}
	ILibSpinLock_UnLock(&(Reader->SendLock));
	return retVal;
}
#endif
//
// Internal method called when data is ready to be processed on an ILibAsyncSocket
//
// <param name="Reader">The ILibAsyncSocket with pending data</param>
void ILibProcessAsyncSocket(struct ILibAsyncSocketModule *Reader, int pendingRead)
{
	#ifndef MICROSTACK_NOTLS
	int sslerror = -1;
	SSL *wasssl;
	int j;
	#endif
	int bytesReceived = 0;
#ifdef WIN32
	int len;
#else
	socklen_t len;
#endif
	char *temp;

	if (Reader->PAUSE > 0)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(Reader->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_AsyncSocket, ILibRemoteLogging_Flags_VerbosityLevel_2, "AsyncSocket[%p] is PAUSED", (void*)Reader);
		return;
	}

	
	//
	// Try to read from the socket
	//
	if (pendingRead != 0)
	{
#ifndef MICROSTACK_NOTLS
#ifdef MICROSTACK_TLS_DETECT
		if (Reader->ssl != NULL && Reader->TLSChecked == 0)
		{
#ifndef __APPLE__
			bytesReceived = recv(Reader->internalSocket, Reader->buffer, Reader->MallocSize, MSG_PEEK | MSG_NOSIGNAL);
			if (ILibAsyncSocket_TLSDetect(Reader, Reader->buffer, 0, bytesReceived) == 0)
			{
				SSL_free(Reader->ssl);
				Reader->ssl = NULL;
				if (Reader->OnConnect != NULL)
				{
					if (Reader->OnConnect != NULL) Reader->OnConnect(Reader, -1, Reader->user);
				}
			}
#endif
			Reader->TLSChecked = 1;
		}
#endif
#endif

		// Read data off the non-SSL, generic socket.
		// Set the receive address buffer size and read from the socket.
#ifdef WIN32
		len = (int)sizeof(struct sockaddr_in6);
#else
		len = (socklen_t)sizeof(struct sockaddr_in6);
#endif
#ifndef MICROSTACK_NOTLS
		if (Reader->ssl != NULL)
		{
			BIO_clear_retry_flags(Reader->readBio);
			if (Reader->RemoteAddress.sin6_family == AF_UNIX)
			{
				bytesReceived = recv(Reader->internalSocket, Reader->readBioBuffer_mem + Reader->readBioBuffer->length, (int)(Reader->readBioBuffer->max - Reader->readBioBuffer->length), 0);
			}
			else
			{
				bytesReceived = recvfrom(Reader->internalSocket, Reader->readBioBuffer_mem + Reader->readBioBuffer->length, (int)(Reader->readBioBuffer->max - Reader->readBioBuffer->length), 0, (struct sockaddr*)&(Reader->SourceAddress), &len);
			}
			if (bytesReceived > 0)
			{
				Reader->readBioBuffer->length += bytesReceived;
				if (Reader->TLSHandshakeCompleted == 0)
				{
					SSL_TRACE1("SSL_handshake()");
					switch ((sslerror = SSL_do_handshake(Reader->ssl)))
					{
					case 0:
						// Handshake Failed!
						while ((sslerror = ERR_get_error()) != 0)
						{
							ERR_error_string_n(sslerror, ILibScratchPad, sizeof(ILibScratchPad));
						}
						// TODO: We should probably do something
						break;
					case 1:
						Reader->SSLConnect = Reader->TLSHandshakeCompleted = 1;
						if (Reader->OnConnect != NULL)
						{
							Reader->OnConnect(Reader, -1, Reader->user);
#ifdef _DEBUG
							//util_savekeys(Reader->ssl); // SAVES TLS PRIVATE KEYS - WARNING: !!! THIS CODE SHOULD ALWAYS BE COMMENTED OUT !!!!
#endif
						}
						ILibAsyncSocket_ProcessEncryptedBuffer(Reader);
						break;
					default:
						// SSL_WANT_READ most likely
						sslerror = SSL_get_error(Reader->ssl, sslerror);
						if (sslerror == SSL_ERROR_SSL)
						{
							Reader->TLS_HandshakeError_Occurred = 1;
							bytesReceived = -1;
						}
						else
						{
							ILibAsyncSocket_ProcessEncryptedBuffer(Reader);
						}
						break;
					}
					SSL_TRACE2("SSL_handshake()");
				}
				
				// Even if we get completed the TLS handshake, we must still read if data remains, this is possible with TLS 1.3
				if ((Reader->TLSHandshakeCompleted == 1) && (Reader->readBioBuffer->length > 0))
				{
					SSL_TRACE1("SSL_read()");
					while ((j = SSL_read(Reader->ssl, Reader->buffer + Reader->EndPointer, Reader->MallocSize - Reader->EndPointer))>0)
					{
						// We got new TLS Data
						if (j > 0) 
						{ 
							Reader->EndPointer += j; 
							if (Reader->MallocSize - Reader->EndPointer == 0)
							{
								Reader->MallocSize = (Reader->MallocSize + MEMORYCHUNKSIZE < Reader->MaxBufferSize) ? (Reader->MallocSize + MEMORYCHUNKSIZE) : (Reader->MaxBufferSize == 0 ? (Reader->MallocSize + MEMORYCHUNKSIZE) : Reader->MaxBufferSize);
								temp = Reader->buffer;
								if ((Reader->buffer = (char*)realloc(Reader->buffer, Reader->MallocSize)) == NULL) ILIBCRITICALEXIT(254);
								//
								// If this realloc moved the buffer somewhere, we need to inform people of it
								//
								if (Reader->buffer != temp && Reader->OnBufferReAllocated != NULL) Reader->OnBufferReAllocated(Reader, Reader->user, Reader->buffer - temp);
							}
						}
					}
					if (j < 0)
					{
						sslerror = SSL_get_error(Reader->ssl, j);
						if (Reader->writeBioBuffer->length > 0)
						{
							ILibAsyncSocket_ProcessEncryptedBuffer(Reader);
						}
					}
					SSL_TRACE2("SSL_read()");
				}
			}
			if (Reader->readBioBuffer->length == 0)
			{
				ignore_result(BIO_reset(Reader->readBio));
				Reader->readBioBuffer->length = 0;
			}
		}
		else
#endif
		{
#if defined(WINSOCK2)
			if (Reader->RemoteAddress.sin6_family == AF_UNIX)
			{
				bytesReceived = recv(Reader->internalSocket, Reader->buffer + Reader->EndPointer, Reader->MallocSize - Reader->EndPointer, 0);
			}
			else
			{
				bytesReceived = recvfrom(Reader->internalSocket, Reader->buffer + Reader->EndPointer, Reader->MallocSize - Reader->EndPointer, 0, (struct sockaddr*)&(Reader->SourceAddress), &len);
			}
#else
			if (Reader->RemoteAddress.sin6_family == AF_UNIX)
			{
				bytesReceived = (int)recv(Reader->internalSocket, Reader->buffer + Reader->EndPointer, Reader->MallocSize - Reader->EndPointer, 0);
			}
			else
			{
				bytesReceived = (int)recvfrom(Reader->internalSocket, Reader->buffer + Reader->EndPointer, Reader->MallocSize - Reader->EndPointer, 0, (struct sockaddr*)&(Reader->SourceAddress), &len);
			}
#endif
			if (Reader->RemoteAddress.sin6_family != AF_UNIX)
			{
				ILib6to4((struct sockaddr*)&(Reader->SourceAddress));
				ILibRemoteLogging_printf(ILibChainGetLogger(Reader->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_AsyncSocket, ILibRemoteLogging_Flags_VerbosityLevel_2, "AsyncSocket[%p] recv returned %d", (void*)Reader, bytesReceived);
			}

			if (bytesReceived > 0)
			{
				//
				// Data was read, so increment our counters
				//
				Reader->EndPointer += bytesReceived;
			}
		}
	}

	//
	// Event OnData up the stack, to process any data that is available
	//
	while (Reader->internalSocket != ~0 && Reader->PAUSE <= 0 && Reader->BeginPointer != Reader->EndPointer && Reader->EndPointer != 0)
	{
		int iPointer = 0;

		if (Reader->OnData != NULL)
		{
			Reader->OnData(Reader, Reader->buffer + Reader->BeginPointer, &(iPointer), Reader->EndPointer - Reader->BeginPointer, &(Reader->OnInterrupt), &(Reader->user), &(Reader->PAUSE));
			if (Reader->buffer != NULL)
			{
				if (iPointer <= (Reader->EndPointer - Reader->BeginPointer))
				{
					assert(iPointer <= (Reader->EndPointer - Reader->BeginPointer));
					if (iPointer == 0) { break; }
					Reader->BeginPointer += iPointer;
				}
			}
		}
	}
	if (Reader->BeginPointer == Reader->EndPointer) { Reader->BeginPointer = Reader->EndPointer = 0; }


	if (bytesReceived <= 0 && pendingRead != 0)
	{
		// If a UDP packet is larger than the buffer, drop it.
#if defined(WINSOCK2)
		if (bytesReceived == SOCKET_ERROR && WSAGetLastError() == 10040) { return; }
#else
		// TODO: Linux errno
		//if (bytesReceived == -1 && errno != 0) printf("ERROR: errno = %d, %s\r\n", errno, strerror(errno));
#endif

		//
		// This means the socket was gracefully closed by the remote endpoint
		//
		SEM_TRACK(AsyncSocket_TrackLock("ILibProcessAsyncSocket", 1, Reader);)
			ILibAsyncSocket_ClearPendingSend(Reader);
		SEM_TRACK(AsyncSocket_TrackUnLock("ILibProcessAsyncSocket", 2, Reader);)

#if defined(_WIN32_WCE) || defined(WIN32)
#if defined(WINSOCK2)
			shutdown(Reader->internalSocket, SD_BOTH);
#endif
		closesocket(Reader->internalSocket);
#elif defined(_POSIX)
			shutdown(Reader->internalSocket, SHUT_RDWR);
		close(Reader->internalSocket);
#endif
		Reader->internalSocket = (SOCKET)~0;

		ILibAsyncSocket_ClearPendingSend(Reader);

#ifndef MICROSTACK_NOTLS
		wasssl = Reader->ssl;
		if (Reader->ssl != NULL)
		{
			SSL_free(Reader->ssl); // Frees SSL session and BIO buffer at the same time
			ILibSpinLock_Lock(&(Reader->SendLock));
			Reader->ssl = NULL;
			ILibSpinLock_UnLock(&(Reader->SendLock));
		}
#endif
		
		//
		// Inform the user the socket has closed
		//
		Reader->timeout_handler = NULL;
		Reader->timeout_milliSeconds = 0;
#ifndef MICROSTACK_NOTLS
		if (wasssl != NULL)
		{
			// This was a SSL socket, fire the event notifying the user. Depending on connection state, we event differently
			if (Reader->SSLConnect == 0 && Reader->OnConnect != NULL) { Reader->OnConnect(Reader, 0, Reader->user); } // Connection Failed
			if (Reader->SSLConnect != 0 && Reader->OnDisconnect != NULL) { Reader->OnDisconnect(Reader, Reader->user); } // Socket Disconnected
		}
		else
		{
#endif
			// This was a normal socket, fire the event notifying the user. Depending on connection state, we event differently
			if (Reader->FinConnect <= 0 && Reader->OnConnect != NULL) { Reader->OnConnect(Reader, 0, Reader->user); } // Connection Failed
			if (Reader->FinConnect > 0 && Reader->OnDisconnect != NULL) { Reader->OnDisconnect(Reader, Reader->user); } // Socket Disconnected
#ifndef MICROSTACK_NOTLS
		}
		Reader->SSLConnect = 0;
#endif
		Reader->FinConnect = 0;

		//
		// If we need to free the buffer, do so
		//
		if (Reader->buffer != NULL)
		{
			if (Reader->buffer != ILibAsyncSocket_ScratchPad) free(Reader->buffer);
			Reader->buffer = NULL;
			Reader->MallocSize = 0;
		}
	}
	else
	{
		// 
		// Only do these checks if the socket was not closed, otherwise we're wasting time
		//

		//
		// Check to see if we need to move any data, to maximize buffer space
		//
		if (Reader->BeginPointer != 0)
		{
			//
			// We can save some cycles by moving the data back to the top
			// of the buffer, instead of just allocating more memory.
			//
			temp = Reader->buffer + Reader->BeginPointer;
			
			memmove_s(Reader->buffer, Reader->MallocSize, temp, Reader->EndPointer - Reader->BeginPointer);
			Reader->EndPointer -= Reader->BeginPointer;
			Reader->BeginPointer = 0;

			//
			// Even though we didn't allocate new memory, we still moved data in the buffer, 
			// so we need to inform people of that, because it might be important
			//
			if (Reader->OnBufferReAllocated != NULL) Reader->OnBufferReAllocated(Reader, Reader->user, temp - Reader->buffer);
		}

		//
		// Check to see if we should grow the buffer
		//
		if (Reader->MallocSize - Reader->EndPointer < 1024 && (Reader->MaxBufferSize == 0 || Reader->MallocSize < Reader->MaxBufferSize))
		{
			Reader->MallocSize = (Reader->MallocSize + MEMORYCHUNKSIZE < Reader->MaxBufferSize) ? (Reader->MallocSize + MEMORYCHUNKSIZE) : (Reader->MaxBufferSize == 0 ? (Reader->MallocSize + MEMORYCHUNKSIZE) : Reader->MaxBufferSize);

			temp = Reader->buffer;
			if ((Reader->buffer = (char*)realloc(Reader->buffer, Reader->MallocSize)) == NULL) ILIBCRITICALEXIT(254);
			//
			// If this realloc moved the buffer somewhere, we need to inform people of it
			//
			if (Reader->buffer != temp && Reader->OnBufferReAllocated != NULL) Reader->OnBufferReAllocated(Reader, Reader->user, Reader->buffer - temp);
		}
	}
}

/*! \fn ILibAsyncSocket_GetUser(ILibAsyncSocket_SocketModule socketModule)
\brief Returns the user object
\param socketModule The ILibAsyncSocket token to fetch the user object from
\returns The user object
*/
void *ILibAsyncSocket_GetUser(ILibAsyncSocket_SocketModule socketModule)
{
	return(socketModule == NULL?NULL:((struct ILibAsyncSocketModule*)socketModule)->user);
}

void ILibAsyncSocket_SetUser(ILibAsyncSocket_SocketModule socketModule, void* user)
{
	if (socketModule == NULL) return;
	((struct ILibAsyncSocketModule*)socketModule)->user = user;
}

void *ILibAsyncSocket_GetUser2(ILibAsyncSocket_SocketModule socketModule)
{
	return(socketModule == NULL?NULL:((struct ILibAsyncSocketModule*)socketModule)->user2);
}

void ILibAsyncSocket_SetUser2(ILibAsyncSocket_SocketModule socketModule, void* user2)
{
	if (socketModule == NULL) return;
	((struct ILibAsyncSocketModule*)socketModule)->user2 = user2;
}

int ILibAsyncSocket_GetUser3(ILibAsyncSocket_SocketModule socketModule)
{
	return(socketModule == NULL?-1:((struct ILibAsyncSocketModule*)socketModule)->user3);
}

void ILibAsyncSocket_SetUser3(ILibAsyncSocket_SocketModule socketModule, int user3)
{
	if (socketModule == NULL) return;
	((struct ILibAsyncSocketModule*)socketModule)->user3 = user3;
}

void ILibAsyncSocket_SetTimeoutEx(ILibAsyncSocket_SocketModule socketModule, int timeoutMilliseconds, ILibAsyncSocket_TimeoutHandler timeoutHandler)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	module->timeout_milliSeconds = timeoutMilliseconds;
	module->timeout_handler = timeoutHandler;
}

//
// Chained PreSelect handler for ILibAsyncSocket
//
// <param name="readset"></param>
// <param name="writeset"></param>
// <param name="errorset"></param>
// <param name="blocktime"></param>
void ILibAsyncSocket_PreSelect(void* socketModule,fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	if (module->internalSocket == -1) return; // If there is not internal socket, just return now.

	ILibRemoteLogging_printf(ILibChainGetLogger(module->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_AsyncSocket, ILibRemoteLogging_Flags_VerbosityLevel_5, "AsyncSocket[%p] entered PreSelect", (void*)module);

	ILibSpinLock_Lock(&(module->SendLock));

	if (module->internalSocket != -1)
	{
		if (module->timeout_milliSeconds != 0)
		{
			// User has set idle timeout, so we need to start checking
			if (module->timeout_lastActivity == 0)
			{
				// No activity yet on socket, so set the idle timeout for the full duration
				*blocktime = module->timeout_milliSeconds;
			}
			else
			{
				long long activity = ILibGetUptime() - module->timeout_lastActivity; // number of milliseconds since last activity
				if (activity >= module->timeout_milliSeconds) 
				{
					// Idle Timeout Occured
					ILibAsyncSocket_TimeoutHandler h = module->timeout_handler;
					module->timeout_milliSeconds = 0;
					module->timeout_handler = NULL;
					if (h != NULL)
					{
						ILibSpinLock_UnLock(&(module->SendLock));
						h(module, module->user);
						ILibSpinLock_Lock(&(module->SendLock));
						if (module->timeout_milliSeconds != 0) 
						{ 
							*blocktime = module->timeout_milliSeconds; 
							module->timeout_lastActivity = ILibGetUptime();
						}
					}
				}
				else
				{
					// Idle Timeout did not occur yet, so set the blocktime for the rest of the timeout
					*blocktime = (int)(module->timeout_milliSeconds - activity);
				}
			}
		}

		if (module->PAUSE < 0) *blocktime = 0;
		if (module->FinConnect == 0)
		{
			// Not Connected Yet
			#if defined(WIN32)
			#pragma warning( push, 3 ) // warning C4127: conditional expression is constant
			#endif
			FD_SET(module->internalSocket, writeset);
			FD_SET(module->internalSocket, errorset);
			#if defined(WIN32)
			#pragma warning( pop )
			#endif
		}
		else
		{
			if (module->PAUSE == 0) // Only if this is zero. <0 is resume, so we want to process first
			{
				// Already Connected, just needs reading
				#if defined(WIN32)
				#pragma warning( push, 3 ) // warning C4127: conditional expression is constant
				#endif
				FD_SET(module->internalSocket, readset);
				FD_SET(module->internalSocket, errorset);
				#if defined(WIN32)
				#pragma warning( pop )
				#endif
			}
		}

		if (module->PendingSend_Head != NULL)
		{
			// If there is pending data to be sent, then we need to check when the socket is writable
			#if defined(WIN32)
			#pragma warning( push, 3 ) // warning C4127: conditional expression is constant
			#endif
			FD_SET(module->internalSocket, writeset);
			#if defined(WIN32)
			#pragma warning( pop )
			#endif
		}
	}

	ILibSpinLock_UnLock(&(module->SendLock));

	ILibRemoteLogging_printf(ILibChainGetLogger(module->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_AsyncSocket, ILibRemoteLogging_Flags_VerbosityLevel_5, "...AsyncSocket[%p] exited PreSelect", (void*)module);
}

void ILibAsyncSocket_PrivateShutdown(void* socketModule)
{
	#ifndef MICROSTACK_NOTLS
	SSL *wasssl;
	#endif
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;

	// If this is an SSL socket, close down the SSL state
	#ifndef MICROSTACK_NOTLS
	if ((wasssl = module->ssl) != NULL)
	{
		SSL_TRACE1("ILibAsyncSocket_PrivateShutdown()");
		SSL_free(module->ssl); // Frees SSL session and BIO buffer at the same time
		module->ssl = NULL;
		SSL_TRACE2("ILibAsyncSocket_PrivateShutdown()");
	}
	#endif

	// Now shutdown the socket and set it to zero
	#if defined(_WIN32_WCE) || defined(WIN32)
	#if defined(WINSOCK2)
		shutdown(module->internalSocket, SD_BOTH);
	#endif
		closesocket(module->internalSocket);
	#elif defined(_POSIX)
		shutdown(module->internalSocket, SHUT_RDWR);
		close(module->internalSocket);
	#endif
	module->internalSocket = (SOCKET)~0;
	module->timeout_handler = NULL;
	module->timeout_milliSeconds = 0;

	#ifndef MICROSTACK_NOTLS
	if (wasssl != NULL)
	{
		// This was a SSL socket, fire the event notifying the user. Depending on connection state, we event differently
		if (module->SSLConnect == 0 && module->OnConnect != NULL) { module->OnConnect(module, 0, module->user); } // Connection Failed
		if (module->SSLConnect != 0 && module->OnDisconnect != NULL) { module->OnDisconnect(module, module->user); } // Socket Disconnected
	}
	else
	{
	#endif
		// This was a normal socket, fire the event notifying the user. Depending on connection state, we event differently
		if (module->FinConnect <= 0 && module->OnConnect != NULL) { module->OnConnect(module, 0, module->user); } // Connection Failed
		if (module->FinConnect > 0 && module->OnDisconnect != NULL) { module->OnDisconnect(module, module->user); } // Socket Disconnected
	#ifndef MICROSTACK_NOTLS
	}
	module->SSLConnect = 0;
	#endif
	module->FinConnect = 0;
}

//
// Chained PostSelect handler for ILibAsyncSocket
//
// <param name="socketModule"></param>
// <param name="slct"></param>
// <param name="readset"></param>
// <param name="writeset"></param>
// <param name="errorset"></param>
void ILibAsyncSocket_PostSelect(void* socketModule, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	int TriggerSendOK = 0;
	struct ILibAsyncSocket_SendData *temp;
	int bytesSent = 0;
	int flags;
#ifdef WIN32
	int len;
#else
	socklen_t len;
#endif
	int TRY_TO_SEND = 1;
	int triggerReadSet = 0;
	int triggerResume = 0;
	int triggerWriteSet = 0;
	int serr = 0, serrlen = sizeof(serr);
	int fd_error, fd_read, fd_write;
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;

	// If there is no internal socket or no events, just return now.
	if (module->internalSocket == -1 || module->FinConnect == -1) return;
	fd_error = FD_ISSET(module->internalSocket, errorset);
	fd_read = FD_ISSET(module->internalSocket, readset);
	fd_write = FD_ISSET(module->internalSocket, writeset);

	ILibRemoteLogging_printf(ILibChainGetLogger(module->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_AsyncSocket, ILibRemoteLogging_Flags_VerbosityLevel_5, "AsyncSocket[%p] entered PostSelect", (void*)module);
	
	UNREFERENCED_PARAMETER( slct );

	ILibSpinLock_Lock(&(module->SendLock)); // Lock!
	
	//if (fd_error != 0) printf("ILibAsyncSocket_PostSelect-ERROR\r\n");
	//if (fd_read != 0) printf("ILibAsyncSocket_PostSelect-READ\r\n");
	//if (fd_write != 0) printf("ILibAsyncSocket_PostSelect-WRITE\r\n");

	//
	// Error Handling. If the ERROR flag is set we have a problem. If not, we must check the socket status for an error.
	// Yes, this is odd, but it's possible for a socket to report a read set and still have an error, in this past this
	// was not handled and caused a lot of problems.
	//
	if (fd_error != 0)
	{
		serr = 1;
	}
	else if(fd_read!=0)
	{
		// Fetch the socket error code
#if defined(WINSOCK2)
		getsockopt(module->internalSocket, SOL_SOCKET, SO_ERROR, (char*)&serr, (int*)&serrlen);
#else
		getsockopt(module->internalSocket, SOL_SOCKET, SO_ERROR, (char*)&serr, (socklen_t*)&serrlen);
#endif
	}

	#ifdef MICROSTACK_PROXY
	// Handle proxy, we need to read the proxy response, all of it and not a byte more.
	if (module->FinConnect == 1 && module->ProxyState == 1 && serr == 0 && fd_read != 0 && module->RemoteAddress.sin6_family != AF_UNIX)
	{
		char *ptr1, *ptr2;
		int len2;
		int slen = sizeof(struct sockaddr_in6);
		serr = 555; // Fake proxy error
		len2 = recvfrom(module->internalSocket, ILibScratchPad2, 1024, 0, (struct sockaddr*)&(module->SourceAddress), (socklen_t*)&slen);
		if (len2 > 0 && len2 < 1024)
		{
			ILibScratchPad2[len2] = 0;
			ptr1 = strstr(ILibScratchPad2, "\r\n\r\n");
			ptr2 = strstr(ILibScratchPad2, " 200 ");
			if (ptr1 != NULL && ptr2 != NULL && ptr2 < ptr1)
			{
				module->FinConnect = 0; // Let pretend we never connected, this will trigger all the connection stuff.
				module->ProxyState = 2; // Move the proxy connection state forward.
				serr = 0;				// Proxy connected collectly.
			}
		}
	}
	#endif

	// If there are any errors, shutdown this socket
	if (serr != 0)
	{
		// Unlock before fireing the event
		ILibSpinLock_UnLock(&(module->SendLock));
		ILibAsyncSocket_PrivateShutdown(module);
	}
	else
	{
		// There are no errors, lets keep processing the socket normally
		if (module->FinConnect == 0)
		{
			// Check to see if the socket is connected
#ifdef MICROSTACK_PROXY
			if (fd_write != 0 || module->ProxyState == 2)
#else
			if (fd_write != 0)
#endif
			{
				// Connected
#ifdef WIN32
				len = (int)sizeof(struct sockaddr_in6);
#else
				len = (socklen_t)sizeof(struct sockaddr_in6);
#endif

				if (module->RemoteAddress.sin6_family != AF_UNIX)
				{
#if defined(WINSOCK2)
					getsockname(module->internalSocket, (struct sockaddr*)(&module->LocalAddress), &len);
#else
					getsockname(module->internalSocket, (struct sockaddr*)(&module->LocalAddress), &len);
#endif
				}
				module->FinConnect = 1;
				module->PAUSE = 0;

				// Set the socket to non-blocking mode, so we can play nice and share the thread
				#if defined(_WIN32_WCE) || defined(WIN32)
				flags = 1;
				ioctlsocket(module->internalSocket, FIONBIO, (u_long *)(&flags));
				#elif defined(_POSIX)
				flags = fcntl(module->internalSocket, F_GETFL,0);
				fcntl(module->internalSocket, F_SETFL, O_NONBLOCK|flags);
				#endif

				// If this is a proxy connection, send the proxy connect header now.
#ifdef MICROSTACK_PROXY
				if (module->ProxyAddress.sin6_family != 0 && module->ProxyState == 0 && module->RemoteAddress.sin6_family != AF_UNIX)
				{
					int len2;
					ILibInet_ntop((int)(module->RemoteAddress.sin6_family), (void*)&(((struct sockaddr_in*)&(module->RemoteAddress))->sin_addr), ILibScratchPad, 4096);
					if (module->ProxyUser == NULL || module->ProxyPass == NULL)
					{
						if (module->ProxiedRemoteHost[0] != 0)
						{
							len2 = sprintf_s(ILibScratchPad2, 4096, "CONNECT %s HTTP/1.1\r\nProxy-Connection: keep-alive\r\nHost: %s\r\n\r\n", module->ProxiedRemoteHost, module->ProxiedRemoteHost);
						}
						else
						{
							len2 = sprintf_s(ILibScratchPad2, 4096, "CONNECT %s:%u HTTP/1.1\r\nProxy-Connection: keep-alive\r\nHost: %s\r\n\r\n", ILibScratchPad, ntohs(module->RemoteAddress.sin6_port), ILibScratchPad);
						}
					}
					else
					{
						char* ProxyAuth = NULL;
						len2 = sprintf_s(ILibScratchPad2, 4096, "%s:%s", module->ProxyUser, module->ProxyPass);
						len2 = ILibBase64Encode((unsigned char*)ILibScratchPad2, len2, (unsigned char**)&ProxyAuth);
						if (module->ProxiedRemoteHost[0] != 0)
						{
							len2 = sprintf_s(ILibScratchPad2, 4096, "CONNECT %s HTTP/1.1\r\nProxy-Connection: keep-alive\r\nHost: %s\r\nProxy-authorization: basic %s\r\n\r\n", module->ProxiedRemoteHost, module->ProxiedRemoteHost, ProxyAuth);
						}
						else
						{
							len2 = sprintf_s(ILibScratchPad2, 4096, "CONNECT %s:%u HTTP/1.1\r\nProxy-Connection: keep-alive\r\nHost: %s\r\nProxy-authorization: basic %s\r\n\r\n", ILibScratchPad, ntohs(module->RemoteAddress.sin6_port), ILibScratchPad, ProxyAuth);
						}
						if (ProxyAuth != NULL) free(ProxyAuth);
					}
					module->timeout_lastActivity = ILibGetUptime();
					send(module->internalSocket, ILibScratchPad2, len2, MSG_NOSIGNAL); // Klockwork says this could block, but it can't becuase socket was set to nonblock
					module->ProxyState = 1;
					// TODO: Set timeout. If the proxy does not respond, we need to close this connection.
					// On the other hand... This is not generally a problem, proxies will disconnect after a timeout anyway.
					
					ILibSpinLock_UnLock(&(module->SendLock));
					return;
				}
				if (module->ProxyState == 2) module->ProxyState = 3;
#endif

				// Connection Complete
				triggerWriteSet = 1;
			}

			// Unlock before fireing the event
			ILibSpinLock_UnLock(&(module->SendLock));

			// If we did connect, we got more things to do
			if (triggerWriteSet != 0)
			{
				module->timeout_lastActivity = ILibGetUptime();
				#ifndef MICROSTACK_NOTLS
				if (module->ssl_ctx != NULL)
				{
					// Make this call to setup the SSL stuff
					ILibAsyncSocket_SetSSLContext(module, module->ssl_ctx, ILibAsyncSocket_TLS_Mode_Client);
				}
				else
				#endif
				{
					// If this is a normal socket, event the connection now.
					if (module->OnConnect != NULL) module->OnConnect(module, -1, module->user);
				}
			}
		}
		else
		{
			// Connected socket, we need to read data
			if (fd_read != 0)
			{
				module->timeout_lastActivity = ILibGetUptime();
				triggerReadSet = 1; // Data Available
			}
			else if (module->PAUSE < 0)
			{
				// Someone resumed a paused connection, but the FD_SET was not triggered because there is no new data on the socket.
				module->timeout_lastActivity = ILibGetUptime();
				triggerResume = 1;
				++module->PAUSE;
				ILibRemoteLogging_printf(ILibChainGetLogger(module->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_AsyncSocket, ILibRemoteLogging_Flags_VerbosityLevel_2, "AsyncSocket[%p] was RESUMED with no new data on socket", (void*)module);
			}

			// Unlock before fireing the event
			ILibSpinLock_UnLock(&(module->SendLock));

			if (triggerReadSet != 0 || triggerResume != 0) ILibProcessAsyncSocket(module, triggerReadSet);
		}
	}


	ILibSpinLock_Lock(&(module->SendLock));
	// Write Handling
	if (module->FinConnect > 0 && module->internalSocket != ~0 && fd_write != 0 && module->PendingSend_Head != NULL && (module->ProxyState != 1))
	{
		//
		// Keep trying to send data, until we are told we can't
		//
		module->timeout_lastActivity = ILibGetUptime();
		while (TRY_TO_SEND != 0)
		{
			if (module->PendingSend_Head == NULL) break;
#ifndef MICROSTACK_NOTLS
			if (module->ssl != NULL)
			{
				while (TRY_TO_SEND != 0)
				{
					// First check to see if there is a buffer for us to send
					if (module->PendingSend_Head->buffer != NULL && module->PendingSend_Head->bytesSent != module->PendingSend_Head->bufferSize)
					{
						bytesSent = (int)send(module->internalSocket, module->PendingSend_Head->buffer + module->PendingSend_Head->bytesSent, module->PendingSend_Head->bufferSize - module->PendingSend_Head->bytesSent, MSG_NOSIGNAL); // Klocwork reports that this could block while holding a lock... This socket has been set to O_NONBLOCK, so that will never happen
						TLSLOG1("  << Draining[%d]: %d >>\n", module->internalSocket, bytesSent);

						if (bytesSent > 0)
						{
							module->PendingSend_Head->bytesSent += bytesSent;
							if (module->PendingSend_Head->bytesSent == module->PendingSend_Head->bufferSize && module->PendingSend_Head->UserFree == ILibAsyncSocket_MemoryOwnership_CHAIN)
							{
								free(module->PendingSend_Head->buffer);
								module->PendingSend_Head->buffer = NULL;
								TLSLOG1("     --> DRAINED --<\n");
								break;
							}
							else
							{
								if (module->PendingSend_Head->bufferSize - module->PendingSend_Head->bytesSent == 0 && module->PendingSend_Head->UserFree == ILibAsyncSocket_MemoryOwnership_BIO)
								{
									TLSLOG1("     --> DRAINED (BIOBUFFER still has %d bytes)\n", (int)(module->writeBioBuffer->length));
								}
								else
								{
									TLSLOG1("     --> REMAINING: %d bytes --<\n", module->PendingSend_Head->bufferSize - module->PendingSend_Head->bytesSent);
								}
							}
						}
						if (bytesSent <= 0)
						{
							TRY_TO_SEND = 0;
						}
					}
					else
					{
						break;
					}
				}
				if (TRY_TO_SEND == 0) { break; }
				if (module->writeBioBuffer->length > 0 && TRY_TO_SEND != 0)
				{
					BIO_clear_retry_flags(module->writeBio);
					bytesSent = (int)send(module->internalSocket, module->writeBioBuffer->data, (int)(module->writeBioBuffer->length), MSG_NOSIGNAL); // Klocwork reports that this could block while holding a lock... This socket has been set to O_NONBLOCK, so that will never happen
					TLSLOG1("  << BIOBUFFER[%d] drain: %d of %d bytes >>\n", module->internalSocket, bytesSent, (int)module->writeBioBuffer->length);
#ifdef WIN32
					if ((bytesSent > 0 && bytesSent < (int)(module->writeBioBuffer->length)) || (bytesSent < 0 && WSAGetLastError() == WSAEWOULDBLOCK))
#else
					if ((bytesSent > 0 && bytesSent < (int)(module->writeBioBuffer->length)) || (bytesSent < 0 && errno == EWOULDBLOCK))
#endif
					{
						if (bytesSent > 0) 
						{ 
							// Some Data was sent, so we need to grab all the data from SSL and buffer it
							module->PendingSend_Head->UserFree = ILibAsyncSocket_MemoryOwnership_CHAIN;
							module->PendingSend_Head->buffer = ILibMemory_Allocate((int)module->writeBioBuffer->length - bytesSent, 0, NULL, NULL);
							module->PendingSend_Head->bufferSize = (int)module->writeBioBuffer->length - bytesSent;
							module->PendingSend_Head->bytesSent = 0;						
							memcpy_s(module->PendingSend_Head->buffer, module->PendingSend_Head->bufferSize, module->writeBioBuffer->data + bytesSent, module->PendingSend_Head->bufferSize);

							TLSLOG1("  <<-- BUFFERING[%d]: %d bytes -->>\n", module->internalSocket, module->PendingSend_Head->bufferSize);

							module->TotalBytesSent += bytesSent;
							module->PendingBytesToSend = (unsigned int)(module->PendingSend_Head->bufferSize);
							ignore_result(BIO_reset(module->writeBio));
						}
						else
						{
							// No Data was sent, so we can just leave the data in the writeBio, and fetch it later
						}
						TRY_TO_SEND = 0;
					}
					else if(bytesSent == module->writeBioBuffer->length)
					{
						// All data was sent
						ignore_result(BIO_reset(module->writeBio));
						module->TotalBytesSent += bytesSent;
						module->PendingBytesToSend = (unsigned int)(module->writeBioBuffer->length);
						if (module->PendingSend_Head->buffer != NULL && module->PendingSend_Head->UserFree == ILibAsyncSocket_MemoryOwnership_CHAIN) { free(module->PendingSend_Head->buffer); }

						free(module->PendingSend_Head);
						module->PendingSend_Head = module->PendingSend_Tail = NULL;
						TRY_TO_SEND = 0;
					}
					else
					{
						// Something went wrong
						ignore_result(BIO_reset(module->writeBio));
						if (module->PendingSend_Head->buffer != NULL && module->PendingSend_Head->UserFree == ILibAsyncSocket_MemoryOwnership_CHAIN) { free(module->PendingSend_Head->buffer); }
						free(module->PendingSend_Head);
						module->PendingSend_Head = module->PendingSend_Tail = NULL;
						TRY_TO_SEND = 0;
					}
				}
				else
				{
					// All data was sent
					ignore_result(BIO_reset(module->writeBio));
					module->TotalBytesSent += bytesSent;
					module->PendingBytesToSend = (unsigned int)(module->writeBioBuffer->length);
					if (module->PendingSend_Head->buffer != NULL && module->PendingSend_Head->UserFree == ILibAsyncSocket_MemoryOwnership_CHAIN) { free(module->PendingSend_Head->buffer); }
					free(module->PendingSend_Head);
					module->PendingSend_Head = module->PendingSend_Tail = NULL;
					TRY_TO_SEND = 0;

					TLSLOG1(" ** CLEARING **\n");
				}
			}
			else
#endif
			{
				if (module->PendingSend_Head->remoteAddress.sin6_family == 0 || module->PendingSend_Head->remoteAddress.sin6_family == AF_UNIX)
				{
					bytesSent = (int)send(module->internalSocket, module->PendingSend_Head->buffer + module->PendingSend_Head->bytesSent, module->PendingSend_Head->bufferSize - module->PendingSend_Head->bytesSent, MSG_NOSIGNAL); // Klocwork reports that this could block while holding a lock... This socket has been set to O_NONBLOCK, so that will never happen
				}
				else
				{
					bytesSent = (int)sendto(module->internalSocket, module->PendingSend_Head->buffer + module->PendingSend_Head->bytesSent, module->PendingSend_Head->bufferSize - module->PendingSend_Head->bytesSent, MSG_NOSIGNAL, (struct sockaddr*)&module->PendingSend_Head->remoteAddress, INET_SOCKADDR_LENGTH(module->PendingSend_Head->remoteAddress.sin6_family)); // Klocwork reports that this could block while holding a lock... This socket has been set to O_NONBLOCK, so that will never happen
				}

				if (bytesSent == 0) { TRY_TO_SEND = 0; } //To avoid get stuck in an infinite loop when bytesSent == 0

				if (bytesSent > 0)
				{
					module->PendingBytesToSend -= bytesSent;
					if ((int)module->PendingBytesToSend < 0) { module->PendingBytesToSend = 0; }
					module->TotalBytesSent += bytesSent;
					module->PendingSend_Head->bytesSent += bytesSent;
					if (module->PendingSend_Head->bytesSent == module->PendingSend_Head->bufferSize)
					{
						// Finished Sending this block
						if (module->PendingSend_Head == module->PendingSend_Tail)
						{
							module->PendingSend_Tail = NULL;
						}
						if (module->PendingSend_Head->UserFree == 0)
						{
							free(module->PendingSend_Head->buffer);
						}
						temp = module->PendingSend_Head->Next;
						free(module->PendingSend_Head);
						module->PendingSend_Head = temp;
						if (module->PendingSend_Head == NULL) { TRY_TO_SEND = 0; }
					}
					else
					{
						// We sent data, but not everything that needs to get sent was sent, try again
						TRY_TO_SEND = 0;
					}
				}
			}

			#ifndef MICROSTACK_NOTLS
			if (bytesSent == -1 && module->ssl == NULL)
			#else
			if (bytesSent == -1)
			#endif
			{
				// Error, clean up everything
				TRY_TO_SEND = 0;
#if defined(_WIN32_WCE) || defined(WIN32)
				if (WSAGetLastError() != WSAEWOULDBLOCK)
#elif defined(_POSIX)
				if (errno != EWOULDBLOCK)
#endif
				{
					// There was an error sending
					ILibAsyncSocket_ClearPendingSend(socketModule);
					ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);
				}
			}
			#ifndef MICROSTACK_NOTLS
			else if (bytesSent == -1 && module->ssl != NULL)
			{
				// OpenSSL returned an error
				TRY_TO_SEND = 0;
				int sslerr = SSL_get_error(module->ssl, -1);
				if (sslerr != SSL_ERROR_WANT_WRITE  && sslerr != SSL_ERROR_WANT_READ)
				{
					// There was an error sending
					ILibAsyncSocket_ClearPendingSend(socketModule);
					ILibLifeTime_Add(module->LifeTime, socketModule, 0, &ILibAsyncSocket_Disconnect, NULL);
				}
			}
			#endif
		}



		// This triggers OnSendOK, if all the pending data has been sent.
		if (module->PendingSend_Head == NULL && bytesSent != -1) { TriggerSendOK = 1; }
		ILibSpinLock_UnLock(&(module->SendLock));
#ifndef MICROSTACK_NOTLS
		if (TriggerSendOK != 0 && (module->ssl == NULL || module->SSLConnect != 0))
#else
		if (TriggerSendOK != 0)
#endif
		{
			module->OnSendOK(module, module->user);
			if (module->Transport.SendOkPtr != NULL) { module->Transport.SendOkPtr(module); }
		}

		if (bytesSent == 0) 
		{ 
			ILibAsyncSocket_ClearPendingSend(socketModule); 
		} //If bytesSent == 0 then clear pending data
	}
	else
	{
		ILibSpinLock_UnLock(&(module->SendLock));
	}

	ILibRemoteLogging_printf(ILibChainGetLogger(module->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_AsyncSocket, ILibRemoteLogging_Flags_VerbosityLevel_5, "...AsyncSocket[%p] exited PostSelect", (void*)module);
}

/*! \fn ILibAsyncSocket_IsFree(ILibAsyncSocket_SocketModule socketModule)
\brief Determines if an ILibAsyncSocket is in use
\param socketModule The ILibAsyncSocket to query
\returns 0 if in use, nonzero otherwise
*/
int ILibAsyncSocket_IsFree(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	return((module == NULL || module->internalSocket==~0)?1:0);
}

int ILibAsyncSocket_IsConnected(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	return module->FinConnect;
}

/*! \fn ILibAsyncSocket_GetPendingBytesToSend(ILibAsyncSocket_SocketModule socketModule)
\brief Returns the number of bytes that are pending to be sent
\param socketModule The ILibAsyncSocket to query
\returns Number of pending bytes
*/
unsigned int ILibAsyncSocket_GetPendingBytesToSend(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	return(module->PendingBytesToSend);
}

/*! \fn ILibAsyncSocket_GetTotalBytesSent(ILibAsyncSocket_SocketModule socketModule)
\brief Returns the total number of bytes that have been sent, since the last reset
\param socketModule The ILibAsyncSocket to query
\returns Number of bytes sent
*/
unsigned int ILibAsyncSocket_GetTotalBytesSent(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	return(module->TotalBytesSent);
}

/*! \fn ILibAsyncSocket_ResetTotalBytesSent(ILibAsyncSocket_SocketModule socketModule)
\brief Resets the total bytes sent counter
\param socketModule The ILibAsyncSocket to reset
*/
void ILibAsyncSocket_ResetTotalBytesSent(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	module->TotalBytesSent = 0;
}

/*! \fn ILibAsyncSocket_GetBuffer(ILibAsyncSocket_SocketModule socketModule, char **buffer, int *BeginPointer, int *EndPointer)
\brief Returns the buffer associated with an ILibAsyncSocket
\param socketModule The ILibAsyncSocket to obtain the buffer from
\param[out] buffer The buffer
\param[out] BeginPointer Stating offset of the buffer
\param[out] EndPointer Length of buffer
*/
void ILibAsyncSocket_GetBuffer(ILibAsyncSocket_SocketModule socketModule, char **buffer, int *BeginPointer, int *EndPointer)
{
	struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;

	*buffer = module->buffer;
	*BeginPointer = module->BeginPointer;
	*EndPointer = module->EndPointer;
}

void ILibAsyncSocket_ModuleOnConnect(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;
	if (module != NULL && module->OnConnect != NULL) module->OnConnect(module, -1, module->user);
}

//! Set the SSL client context used by all connections done by this socket module. The SSL context must
//! be set before using this module. If left to NULL, all connections are in the clear using TCP.
//!
//! This is utilized by the ILibAsyncServerSocket module
/*!
	\param socketModule The ILibAsyncSocket to modify
	\param ssl_ctx The ssl_ctx structure
	\param server ILibAsyncSocket_TLS_Mode Configuration setting to set
*/
#ifndef MICROSTACK_NOTLS
//! Associate an OpenSSL Context Object
/*!
	\ingroup TLSGroup
	\param socketModule ILibAsyncSocket_SocketModule to associate the SSL Context
	\param ssl_ctx SSL_CTX Context object
	\param server ILibAsyncSocket_TLS_Mode Configuration
*/
SSL* ILibAsyncSocket_SetSSLContextEx(ILibAsyncSocket_SocketModule socketModule, SSL_CTX *ssl_ctx, ILibAsyncSocket_TLS_Mode server, char *hostName)
{
	if (socketModule != NULL)
	{
		struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;
		if (ssl_ctx == NULL) return(NULL);

		if (module->ssl_ctx == NULL)
		{
			module->ssl_ctx = ssl_ctx;
		}

		// If a socket is ready, setup SSL right now (otherwise, we will do this upon connection).
		if (module->internalSocket != 0 && module->internalSocket != ~0 && module->ssl == NULL)
		{
			int status;

#ifdef MICROSTACK_TLS_DETECT
			module->TLSChecked = server == ILibAsyncSocket_TLS_Mode_Server_with_TLSDetectLogic ? 0 : 1;
#endif
			SSL_TRACE1("SetSSLContextEx()");
			module->ssl = SSL_new(ssl_ctx);
			module->TLSHandshakeCompleted = 0;
			module->readBio = BIO_new_mem_buf(module->readBioBuffer_mem, (int)sizeof(module->readBioBuffer_mem));
			module->writeBio = BIO_new(BIO_s_mem());
			BIO_set_mem_eof_return(module->readBio, -1);
			BIO_set_mem_eof_return(module->writeBio, -1);
			SSL_set_bio(module->ssl, module->readBio, module->writeBio);
			BIO_get_mem_ptr(module->readBio, &(module->readBioBuffer));
			BIO_get_mem_ptr(module->writeBio, &(module->writeBioBuffer));
			module->readBioBuffer->length = 0;

			if (server == ILibAsyncSocket_TLS_Mode_Client)
			{
				if (hostName != NULL) { SSL_set_tlsext_host_name(module->ssl, hostName); }
				SSL_set_connect_state(module->ssl);
				status = SSL_do_handshake(module->ssl);
				if (status <= 0) { status = SSL_get_error(module->ssl, status); }
				if (status == SSL_ERROR_WANT_READ)
				{
					ILibAsyncSocket_ProcessEncryptedBuffer(module);
					// We're going to drop out now, becuase we need to check for received data
				}
			}
			else
			{
				SSL_set_accept_state(module->ssl); // Setup server SSL state
			}
			SSL_TRACE2("SetSSLContextEx()");
			return(module->ssl);
		}
	}
	return NULL;
}
//! Get's the OpenSSL Context Structure
/*!\
	\ingroup TLSGroup
	\param socketModule ILibAsyncSocket_SocketModule to fetch the SSL Context from
	\return OpenSSL Context Structure [NULL if not set]
*/
SSL_CTX *ILibAsyncSocket_GetSSLContext(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;
	return module->ssl_ctx;
}
SSL* ILibAsyncSocket_GetSSL(ILibAsyncSocket_SocketModule socketModule)
{
	return(((ILibAsyncSocketModule*)socketModule)->ssl);
}
#endif


//! Sets the remote address field.
//! This is utilized by the ILibAsyncServerSocket module
/*!
	\param socketModule ILibAsyncSocket_SocketModule to modify
	\param remoteAddress The remote endpoint to set
*/
void ILibAsyncSocket_SetRemoteAddress(ILibAsyncSocket_SocketModule socketModule, struct sockaddr *remoteAddress)
{
	if (socketModule != NULL)
	{
		struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;
		memcpy_s(&(module->RemoteAddress), sizeof(struct sockaddr_in6), remoteAddress, INET_SOCKADDR_LENGTH(remoteAddress->sa_family));
	}
}

/*! \fn ILibAsyncSocket_UseThisSocket(ILibAsyncSocket_SocketModule socketModule,void* UseThisSocket,ILibAsyncSocket_OnInterrupt InterruptPtr,void *user)
\brief Associates an actual socket with ILibAsyncSocket
\par
Instead of calling \a ConnectTo, you can call this method to associate with an already
connected socket.
\param socketModule The ILibAsyncSocket to associate
\param UseThisSocket The socket to associate
\param InterruptPtr Function Pointer that triggers when the TCP connection is interrupted
\param user User object to associate with this session
*/
#if defined(_WIN32_WCE) || defined(WIN32)
void ILibAsyncSocket_UseThisSocket(ILibAsyncSocket_SocketModule socketModule, SOCKET UseThisSocket, ILibAsyncSocket_OnInterrupt InterruptPtr, void *user)
#elif defined(_POSIX)
void ILibAsyncSocket_UseThisSocket(ILibAsyncSocket_SocketModule socketModule, int UseThisSocket, ILibAsyncSocket_OnInterrupt InterruptPtr, void *user)
#endif
{
	int flags;
	char *tmp;
	struct ILibAsyncSocketModule* module = (struct ILibAsyncSocketModule*)socketModule;

	module->PendingBytesToSend = 0;
	module->TotalBytesSent = 0;
	module->internalSocket = UseThisSocket;
	module->OnInterrupt = InterruptPtr;
	module->user = user;
	module->FinConnect = 1;
	module->PAUSE = 0;
	#ifndef MICROSTACK_NOTLS
	module->SSLConnect = 0;
	#endif

	ILibRemoteLogging_printf(ILibChainGetLogger(module->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_AsyncSocket, ILibRemoteLogging_Flags_VerbosityLevel_1, "AsyncSocket[%p] Initialized", (void*)module);

	//
	// If the buffer is too small/big, we need to realloc it to the minimum specified size
	//
	if (module->buffer != ILibAsyncSocket_ScratchPad)
	{
		if ((tmp = (char*)realloc(module->buffer, module->InitialSize)) == NULL) ILIBCRITICALEXIT(254);
		module->buffer = tmp;
		module->MallocSize = module->InitialSize;
	}
	module->BeginPointer = 0;
	module->EndPointer = 0;

	//
	// Make sure the socket is non-blocking, so we can play nice and share the thread
	//
#if defined(_WIN32_WCE) || defined(WIN32)
	flags = 1;
	ioctlsocket(module->internalSocket, FIONBIO,(u_long *)(&flags));
#elif defined(_POSIX)
	flags = fcntl(module->internalSocket,F_GETFL,0);
	fcntl(module->internalSocket,F_SETFL,O_NONBLOCK|flags);
#endif
}

int ILibAsyncSocket_IsDomainSocket(ILibAsyncSocket_SocketModule socketModule)
{
	return(((struct ILibAsyncSocketModule*)socketModule)->RemoteAddress.sin6_family == AF_UNIX ? 1 : 0);
}

/*! \fn ILibAsyncSocket_GetRemoteInterface(ILibAsyncSocket_SocketModule socketModule)
\brief Returns the Remote Interface of a connected session
\param socketModule The ILibAsyncSocket to query
\param[in,out] remoteAddress The remote interface
\returns Number of bytes written into remoteAddress
*/
int ILibAsyncSocket_GetRemoteInterface(ILibAsyncSocket_SocketModule socketModule, struct sockaddr *remoteAddress)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	if (module->RemoteAddress.sin6_family != 0)
	{
		memcpy_s(remoteAddress, sizeof(struct sockaddr_in6), &(module->RemoteAddress), INET_SOCKADDR_LENGTH(module->RemoteAddress.sin6_family));
		return INET_SOCKADDR_LENGTH(module->RemoteAddress.sin6_family);
	}
	memcpy_s(remoteAddress, sizeof(struct sockaddr_in6), &(module->SourceAddress), INET_SOCKADDR_LENGTH(module->SourceAddress.sin6_family));
	return INET_SOCKADDR_LENGTH(module->SourceAddress.sin6_family);
}

/*! \fn ILibAsyncSocket_GetLocalInterface(ILibAsyncSocket_SocketModule socketModule)
\brief Returns the Local Interface of a connected session, in network order
\param socketModule The ILibAsyncSocket to query
\param[in,out] localAddress The local interface
\returns The number of bytes written to localAddress
*/
int ILibAsyncSocket_GetLocalInterface(ILibAsyncSocket_SocketModule socketModule, struct sockaddr *localAddress)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	int receivingAddressLength = sizeof(struct sockaddr_in6);

	if (module->LocalAddress.sin6_family !=0)
	{
		memcpy_s(localAddress, INET_SOCKADDR_LENGTH(module->LocalAddress.sin6_family), &(module->LocalAddress), INET_SOCKADDR_LENGTH(module->LocalAddress.sin6_family));
		return INET_SOCKADDR_LENGTH(module->LocalAddress.sin6_family);
	}
	else
	{
#if defined(WIN32)
		getsockname(module->internalSocket, localAddress, (int*)&receivingAddressLength);
#else
		if (getsockname(module->internalSocket, localAddress, (socklen_t*)&receivingAddressLength) < 0)
		{
			receivingAddressLength = sizeof(struct sockaddr_in);
			if (getsockname(module->internalSocket, localAddress, (socklen_t*)&receivingAddressLength) < 0) { receivingAddressLength = 0; }
		}
#endif
		return receivingAddressLength;
	}
}
//! Get's the locally bound port
/*!
	\param socketModule ILibAsyncSocket_SocketModule object to query
	\return The locallly bound port
*/
unsigned short ILibAsyncSocket_GetLocalPort(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	int receivingAddressLength = sizeof(struct sockaddr_in6);
	struct sockaddr_in6 localAddress;

	if (module->LocalAddress.sin6_family == AF_INET6) return ntohs(module->LocalAddress.sin6_port);
	if (module->LocalAddress.sin6_family == AF_INET) return ntohs((((struct sockaddr_in*)(&(module->LocalAddress)))->sin_port));
#if defined(WINSOCK2)
	getsockname(module->internalSocket, (struct sockaddr*)&localAddress, (int*)&receivingAddressLength);
#else
	getsockname(module->internalSocket, (struct sockaddr*)&localAddress, (socklen_t*)&receivingAddressLength);
#endif
	if (localAddress.sin6_family == AF_INET6) return ntohs(localAddress.sin6_port);
	if (localAddress.sin6_family == AF_INET) return ntohs((((struct sockaddr_in*)(&localAddress))->sin_port));
	return 0;
}
/*! \fn ILibAsyncSocket_Pause(ILibAsyncSocket_SocketModule socketModule)
\brief Pauses a session
\par
Sessions can be paused, such that further data is not read from the socket until resumed. NOTE: MUST be called from Microstack thread
\param socketModule The ILibAsyncSocket to pause.
*/
void ILibAsyncSocket_Pause(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)socketModule;
	if (socketModule == NULL) { return; }

	sm->PAUSE = 1;
}
/*! \fn ILibAsyncSocket_Resume(ILibAsyncSocket_SocketModule socketModule)
\brief Resumes a paused session
\par
Sessions can be paused, such that further data is not read from the socket until resumed
\param socketModule The ILibAsyncSocket to resume
*/
void ILibAsyncSocket_Resume(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)socketModule;
	if (sm == NULL) { return; }
	ILibRemoteLogging_printf(ILibChainGetLogger(sm->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_AsyncSocket, ILibRemoteLogging_Flags_VerbosityLevel_2, "AsyncSocket[%p] was RESUMED", (void*)socketModule);
	if (sm->PAUSE > 0)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(sm->Transport.ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_AsyncSocket, ILibRemoteLogging_Flags_VerbosityLevel_2, "...Unblocking Chain");
		sm->PAUSE = -1;
		ILibForceUnBlockChain(sm->Transport.ChainLink.ParentChain);
	}
}

/*! \fn ILibAsyncSocket_GetSocket(ILibAsyncSocket_SocketModule module)
\brief Obtain the underlying raw socket
\param module The ILibAsyncSocket to query
\returns The pointer to raw socket
*/
void* ILibAsyncSocket_GetSocket(ILibAsyncSocket_SocketModule module)
{
	struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)module;
	return(&(sm->internalSocket));
}
//! Sets the local endpoint associated with this ILibAsyncSocket
/*!
	\param module ILibAsyncSocket_SocketModule to modify
	\param LocalAddress Local endpoint to set
*/
void ILibAsyncSocket_SetLocalInterface(ILibAsyncSocket_SocketModule module, struct sockaddr *LocalAddress)
{
	struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)module;
	memcpy_s(&(sm->LocalAddress), sizeof(struct sockaddr_in6), LocalAddress, INET_SOCKADDR_LENGTH(LocalAddress->sa_family));
}
//! Sets the maximum size that the internal buffer can be grown
/*!
	\param module ILibAsyncSocket_SocketModule to configure
	\param maxSize Maximum size in bytes
	\param OnBufferSizeExceededCallback ILibAsyncSocket_OnBufferSizeExceeded handler to be dispatched if the max size is exceeded
	\param user Custom user state data
*/
void ILibAsyncSocket_SetMaximumBufferSize(ILibAsyncSocket_SocketModule module, int maxSize, ILibAsyncSocket_OnBufferSizeExceeded OnBufferSizeExceededCallback, void *user)
{
	struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)module;
	sm->MaxBufferSize = maxSize;
	sm->OnBufferSizeExceeded = OnBufferSizeExceededCallback;
	sm->MaxBufferSizeUserObject = user;
}
//! Sets the SendOK event handler
/*!
	\param module ILibAsyncSocket_SocketModule to configure
	\param OnSendOK ILibAsyncSocket_OnSendOK handler to dispatch on an OnSendOK event
*/
void ILibAsyncSocket_SetSendOK(ILibAsyncSocket_SocketModule module, ILibAsyncSocket_OnSendOK OnSendOK)
{
	struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)module;
	sm->OnSendOK = OnSendOK;
}

//! Determines if the specified IPv6 address is a link local address
/*!
	\param LocalAddress IPv6 Address
	\return 1 = Link Local, 0 = Not Link Local
*/
int ILibAsyncSocket_IsIPv6LinkLocal(struct sockaddr *LocalAddress)
{
	struct sockaddr_in6 *x = (struct sockaddr_in6*)LocalAddress;
#if defined(_WIN32_WCE) || defined(WIN32)
	if (LocalAddress->sa_family == AF_INET6 && x->sin6_addr.u.Byte[0] == 0xFE && x->sin6_addr.u.Byte[1] == 0x80) return 1;
#else
	if (LocalAddress->sa_family == AF_INET6 && x->sin6_addr.s6_addr[0] == 0xFE && x->sin6_addr.s6_addr[1] == 0x80) return 1;
#endif
	return 0;
}
//! Determines if the internal socket is a link local socket
/*!
	\param socketModule ILibAsyncSocket_SocketModule to query
	\return 0 = Not Link Local, 1 = Link Local
*/
int ILibAsyncSocket_IsModuleIPv6LinkLocal(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule *module = (struct ILibAsyncSocketModule*)socketModule;
	return ILibAsyncSocket_IsIPv6LinkLocal((struct sockaddr*)&(module->LocalAddress));
}
//! Returns 1 if the ILibAsyncSocket was disconnected because the buffer size was exceeded
/*!
	\param socketModule ILibAsyncSocket_SocketModule to query
	\return 1 = BufferSizeExceeded
*/
int ILibAsyncSocket_WasClosedBecauseBufferSizeExceeded(ILibAsyncSocket_SocketModule socketModule)
{
	struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)socketModule;
	return(sm->MaxBufferSizeExceeded);
}

void ILibAsyncSocket_UpdateOnData(ILibAsyncSocket_SocketModule module, ILibAsyncSocket_OnData OnData)
{
	((ILibAsyncSocketModule*)module)->OnData = OnData;
}
void ILibAsyncSocket_UpdateCallbacks(ILibAsyncSocket_SocketModule module, ILibAsyncSocket_OnData OnData, ILibAsyncSocket_OnConnect OnConnect, ILibAsyncSocket_OnDisconnect OnDisconnect, ILibAsyncSocket_OnSendOK OnSendOK)
{
	((ILibAsyncSocketModule*)module)->OnData = OnData;
	((ILibAsyncSocketModule*)module)->OnConnect = OnConnect;
	((ILibAsyncSocketModule*)module)->OnDisconnect = OnDisconnect;
	((ILibAsyncSocketModule*)module)->OnSendOK = OnSendOK;
}
#ifndef MICROSTACK_NOTLS
int ILibAsyncSocket_TLS_WasHandshakeError(ILibAsyncSocket_SocketModule socketModule)
{
	return(((struct ILibAsyncSocketModule*)socketModule)->TLS_HandshakeError_Occurred || ((struct ILibAsyncSocketModule*)socketModule)->TLSHandshakeCompleted == 0 ? 1 : 0);
}
//! Gets the Peer's TLS Certificate
/*!
	\ingroup TLSGroup
	\b NOTE: Must call X509_free() on the certificate when done with it!
	\param socketModule ILibAsyncSocket_SocketModule to query
	\return Peer's TLS Certificate. NULL if none was presented. Must call X509_free() when done with the certificate.
*/
X509 *ILibAsyncSocket_SslGetCert(ILibAsyncSocket_SocketModule socketModule)
{
	X509 *ret;
	SSL_TRACE1("ILibAsyncSocket_SslGetCert()");
	struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)socketModule;
	ret = SSL_get_peer_certificate(sm->ssl);
	SSL_TRACE2("ILibAsyncSocket_SslGetCert()");

	return(ret);
}

//! Get's the Cert Chain presented by the Peer
/*!
	\ingroup TLSGroup
	\b NOTE: X509 Cert's Reference Count is not incremented. 
	\param socketModule ILibAsyncSocket_SocketModule to query
	\return Cert Chain presented by Peer. NULL if none presented
*/
STACK_OF(X509) *ILibAsyncSocket_SslGetCerts(ILibAsyncSocket_SocketModule socketModule)
{
	STACK_OF(X509) *ret;
	SSL_TRACE1("ILibAsyncSocket_SslGetCerts()");
	struct ILibAsyncSocketModule *sm = (struct ILibAsyncSocketModule*)socketModule;
	ret = SSL_get_peer_cert_chain(sm->ssl);
	SSL_TRACE2("ILibAsyncSocket_SslGetCerts()");
	return (ret);
}
#endif
