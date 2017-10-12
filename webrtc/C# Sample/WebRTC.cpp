/*
Copyright 2014 Intel Corporation

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

//
// MicrostackWrapper.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "WebRTC.h"

#include <WinSock2.h>
#include <WS2tcpip.h>

#if defined(WIN32)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
extern "C"
{
	#include "../../microstack/ILibAsyncSocket.h"
	#include "../../microstack/ILibParsers.h"
	#include "../../microstack/ILibWebRTC.h"
	#include "../../microstack/ILibCrypto.h"
	#include "../../microstack/ILibWrapperWebRTC.h"
	#include "../../microstack/ILibWebServer.h"
	#include "../../microstack/ILibRemoteLogging.h"
	#include <openssl/ssl.h>

	char g_SessionRandom[32];
	unsigned int g_SessionRandomId;
	char g_selfid[UTIL_HASHSIZE];

	struct util_cert selfcert;
	struct util_cert selftlscert;
	struct util_cert selftlsclientcert;
	SSL_CTX* ctx = NULL;
	char tlsServerCertThumbprint[32];
	extern void* ILibWrapper_WebRTC_Connection_GetStunModule(ILibWrapper_WebRTC_Connection connection);

	__declspec(dllexport) void ILibWrapper_Free(void* ptr)
	{
		free(ptr);
	}

	//
	// Chain Management
	//
	__declspec(dllexport) void* ILibWrapper_CreateMicrostackChain()
	{
		return(ILibCreateChain());
	}
	__declspec(dllexport) void ILibWrapper_StartChain(void *chain)
	{
		ILibStartChain(chain);
	}
	__declspec(dllexport) void ILibWrapper_StopChain(void *chain)
	{
		ILibStopChain(chain);
	}
	__declspec(dllexport) int ILibWrapper_IsChainRunning(void* chain)
	{
		return(ILibIsChainRunning(chain));
	}
	__declspec(dllexport) void* ILibWrapper_DLL_GetBaseTimer(void* chain)
	{
		return(ILibGetBaseTimer(chain));
	}

	__declspec(dllexport) int ILibWrapper_DLL_IsChainDisposing(void *chain)
	{
		return(ILibIsChainBeingDestroyed(chain));
	}


	__declspec(dllexport) unsigned short ILibWrapper_StartDefaultLogger(void *chain, unsigned short portNumber)
	{
#if defined(_REMOTELOGGING) && defined(_REMOTELOGGINGSERVER)
		return(ILibStartDefaultLogger(chain, portNumber));
#else
		return(0);
#endif
	}

	__declspec(dllexport) void ILibWrapper_RemoteLogging_Print(void *chain, ILibRemoteLogging_Modules module, ILibRemoteLogging_Flags flags, char *msg)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(chain), module, flags, "%s", msg);
	}

	//
	// XML Parsing
	//
	__declspec(dllexport) void* ILibWrapper_ParseXML(char* buffer, int offset, int length)
	{
		struct ILibXMLNode *n = ILibParseXML(buffer, offset, length);
		if(n!=NULL)
		{
			ILibProcessXMLNodeList(n);
		}
		return(n);			
	}
	__declspec(dllexport) void* ILibWrapper_GetXMLAttributes(struct ILibXMLNode *node)
	{
		return(ILibGetXMLAttributes(node));
	}
	__declspec(dllexport) void ILibWrapper_BuildXMLNamespaceLookupTable(struct ILibXMLNode *node)
	{
		ILibXML_BuildNamespaceLookupTable(node);
	}
	__declspec(dllexport) char* ILibWrapper_LookupXMLNamespace(struct ILibXMLNode* current, char* prefix, int prefixLength)
	{
		return(ILibXML_LookupNamespace(current, prefix, prefixLength));
	}
	__declspec(dllexport) void ILibWrapper_DestructXMLNodeList(struct ILibXMLNode *node)
	{
		ILibDestructXMLNodeList(node);
	}
	__declspec(dllexport) void ILibWrapper_DestructXMLAttributeList(struct ILibXMLAttribute *a)
	{
		ILibDestructXMLAttributeList(a);
	}


	//
	// LifeTimeMonitor
	//
	__declspec(dllexport) void* ILibWrapper_CreateLifeTime(void *chain)
	{
		return(ILibCreateLifeTime(chain));
	}
	__declspec(dllexport) void ILibWrapper_LifeTimeAddEx(void *LifetimeMonitorObject, void *data, int ms, ILibLifeTime_OnCallback Callback, ILibLifeTime_OnCallback Destroy)
	{
		ILibLifeTime_AddEx(LifetimeMonitorObject, data, ms, Callback, Destroy);
	}
		__declspec(dllexport) void ILibWrapper_LifeTimeRemove(void *LifeTimeToken, void *data)
	{
		ILibLifeTime_Remove(LifeTimeToken, data);
	}


	//
	// String Parsing
	//
	__declspec(dllexport) void* ILibWrapper_ParseString(char* buffer, int offset, int length, const char* Delimiter, int DelimiterLength)
	{
		return(ILibParseString(buffer, offset, length, Delimiter, DelimiterLength));
	}
	__declspec(dllexport) void* ILibWrapper_ParseStringAdv(char* buffer, int offset, int length, const char* Delimiter, int DelimiterLength)
	{
		return(ILibParseStringAdv(buffer, offset, length, Delimiter, DelimiterLength));
	}
	__declspec(dllexport) void ILibWrapper_DestructParserResults(struct parser_result *result)
	{
		ILibDestructParserResults(result);
	}


	//
	// Crypto
	//
	__declspec(dllexport) void ILibWrapper_OpenSSL_Init()
	{
		util_openssl_init();
	}

	__declspec(dllexport) void ILibWrapper_OpenSSL_UnInit()
	{
		util_openssl_uninit();
	}
	__declspec(dllexport) void ILibWrapper_InitializeCerts()
	{
		memset(&selfcert,0,sizeof(struct util_cert));
		memset(&selftlscert,0,sizeof(struct util_cert));
		memset(&selftlsclientcert,0,sizeof(struct util_cert));

		util_mkCert(NULL, &selfcert, 2048, 10000, "localhost", CERTIFICATE_ROOT, NULL);
		util_keyhash(selfcert,g_selfid);

		util_mkCert(&selfcert, &selftlscert, 2048, 10000, "localhost", CERTIFICATE_TLS_SERVER, NULL);
		util_mkCert(&selfcert, &selftlsclientcert, 2048, 10000, "localhost", CERTIFICATE_TLS_CLIENT, NULL);
	}
	__declspec(dllexport) void ILibWrapper_InitializeDTLS()
	{
		ctx = SSL_CTX_new(DTLSv1_method());
		SSL_CTX_use_certificate(ctx, selftlscert.x509);
		SSL_CTX_use_PrivateKey(ctx,selftlscert.pkey);
		
		int l = 32;
		X509_digest(selftlscert.x509, EVP_get_digestbyname("sha256"), (unsigned char*)tlsServerCertThumbprint, (unsigned int*)&l);
	}

	__declspec(dllexport) void ILibWrapper_UnInitializeDTLS()
	{
		SSL_CTX_free(ctx);
		ctx = NULL;
	}
	__declspec(dllexport) void ILibWrapper_UnInitializeCerts()
	{
		util_freecert(&selftlsclientcert);
		util_freecert(&selftlscert);
		util_freecert(&selfcert);

		memset(&selfcert,0,sizeof(struct util_cert));
		memset(&selftlscert,0,sizeof(struct util_cert));
		memset(&selftlsclientcert,0,sizeof(struct util_cert));
	}

	__declspec(dllexport) void* ILibWrapper_GetCTX()
	{
		return(ctx);
	}
	__declspec(dllexport) char* ILibWrapper_GetTLSServerThumbprint()
	{
		return(tlsServerCertThumbprint);
	}

	//
	// IPAddress Helper
	//
	__declspec(dllexport) char* ILibWrapper_SockAddr_GetAddressString(struct sockaddr* addr, char* buffer, int bufferLength)
	{
		return(ILibInet_ntop2(addr, buffer, bufferLength));
	}
	__declspec(dllexport) unsigned short ILibWrapper_SockAddr_GetPort(struct sockaddr* addr)
	{
		unsigned short retVal = 0;
		switch(addr->sa_family)
		{
			case AF_INET:
				retVal = ntohs(((struct sockaddr_in*)addr)->sin_port);
				break;
			case AF_INET6:
				retVal = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
				break;
			default:
				break;
		}
		return(retVal);
	}

	__declspec(dllexport) int ILibWrapper_SockAddrIn6_Size()
	{
		return(sizeof(struct sockaddr_in6));
	}
	__declspec(dllexport) void* ILibWrapper_SockAddr_FromString(char* buffer, unsigned short port)
	{
		struct sockaddr_in* retVal = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in6));
		if(retVal==NULL){ILIBCRITICALEXIT(254);}
		memset(retVal,0,sizeof(struct sockaddr_in6));

		retVal->sin_family = AF_INET;
		retVal->sin_port = htons(port);
		ILibInet_pton(AF_INET, buffer, &(retVal->sin_addr));
		return(retVal);
	}
	__declspec(dllexport) void* ILibWrapper_SockAddr_FromString6(char* buffer, unsigned short port)
	{
		struct sockaddr_in6* retVal = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));
		if(retVal==NULL){ILIBCRITICALEXIT(254);}
		memset(retVal,0,sizeof(struct sockaddr_in6));

		retVal->sin6_family = AF_INET6;
		retVal->sin6_port = htons(port);
		ILibInet_pton(AF_INET6, buffer, &(retVal->sin6_addr));
		return(retVal);
	}
	__declspec(dllexport) void ILibWrapper_FreeSockAddr(void *addr)
	{
		free(addr);
	}

	__declspec(dllexport) void* ILibWrapper_SockAddr_FromBytes(char* buffer, int offset, int length)
	{
		struct sockaddr_in6* retVal = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));
		if(retVal==NULL){ILIBCRITICALEXIT(254);}
		memset(retVal, 0, sizeof(struct sockaddr_in6));

		memcpy(retVal, buffer+offset, length);
		return(retVal);
	}



	//
	// WebRTC
	//

	__declspec(dllexport) unsigned short ILibWrapper_DLL_WebRTC_StartDefaultLogger(ILibWrapper_WebRTC_ConnectionFactory factory, unsigned short port)
	{
#if defined(_REMOTELOGGING) && defined(_REMOTELOGGINGSERVER)
		void *chain = ((ILibChain_Link*)factory)->ParentChain;
		if (ILibChainGetLogger(chain) == NULL)
		{
			return(ILibStartDefaultLogger(chain, port));
		}
		else
		{
			if (chain != NULL)
			{
				return(ILibWebServer_GetPortNumber((ILibWebServer_ServerToken)(((void**)&((int*)chain)[2])[1])));
			}
			else
			{
				return(0);
			}
		}
#else
		return(0);
#endif
	}

	//
	// ConnectionFactory Methods
	//

	// Creates a Factory object that can create WebRTC Connection objects.
	__declspec(dllexport) ILibWrapper_WebRTC_ConnectionFactory ILibWrapper_DLL_WebRTC_ConnectionFactory_CreateConnectionFactory(void* chain, unsigned short localPort)
	{
		return(ILibWrapper_WebRTC_ConnectionFactory_CreateConnectionFactory(chain, localPort));
	}

	// Sets the TURN server to use for all WebRTC connections
	__declspec(dllexport) void ILibWrapper_DLL_WebRTC_ConnectionFactory_SetTurnServer(ILibWrapper_WebRTC_ConnectionFactory factory, struct sockaddr_in6* turnServer, char* username, char* password, ILibWebRTC_TURN_ConnectFlags turnSetting)
	{
		ILibWrapper_WebRTC_ConnectionFactory_SetTurnServer(factory, turnServer, username, (int)strlen(username), password, (int)strlen(password), turnSetting);
	}

	// Creates an unconnected WebRTC Connection 
	__declspec(dllexport) ILibWrapper_WebRTC_Connection ILibWrapper_DLL_WebRTC_ConnectionFactory_CreateConnection(ILibWrapper_WebRTC_ConnectionFactory factory, ILibWrapper_WebRTC_Connection_OnConnect OnConnectHandler, ILibWrapper_WebRTC_Connection_OnDataChannel OnDataChannelHandler, ILibWrapper_WebRTC_Connection_OnSendOK OnConnectionSendOK)
	{
		return(ILibWrapper_WebRTC_ConnectionFactory_CreateConnection(factory, OnConnectHandler, OnDataChannelHandler, OnConnectionSendOK));
	}

	// 
	// Connection Methods
	//

	// Set the STUN Servers to use with the WebRTC Connection when gathering candidates
	__declspec(dllexport) void ILibWrapper_DLL_WebRTC_Connection_SetStunServers(ILibWrapper_WebRTC_Connection connection, char** serverList, int serverLength)
	{
		ILibWrapper_WebRTC_Connection_SetStunServers(connection, serverList, serverLength);
	}

	__declspec(dllexport) void ILibWrapper_DLL_WebRTC_Connection_AddRemoteCandidate(ILibWrapper_WebRTC_Connection connection, struct sockaddr_in6* candidate)
	{
		ILibORTC_AddRemoteCandidate(ILibWrapper_WebRTC_Connection_GetStunModule(connection), ILibWrapper_WebRTC_Connection_GetLocalUsername(connection), candidate);
	}

	// Non zero value if the underlying SCTP session is established
	__declspec(dllexport) int ILibWrapper_DLL_WebRTC_Connection_IsConnected(ILibWrapper_WebRTC_Connection connection)
	{
		return(ILibWrapper_WebRTC_Connection_IsConnected(connection));
	}

	// Disconnects the unerlying SCTP session, if it is connected
	__declspec(dllexport) void ILibWrapper_DLL_WebRTC_Connection_Disconnect(ILibWrapper_WebRTC_Connection connection)
	{
		ILibWrapper_WebRTC_Connection_Disconnect(connection);
	}

	// Creates a WebRTC Data Channel, using the next available Stream ID
	__declspec(dllexport) ILibWrapper_WebRTC_DataChannel* ILibWrapper_DLL_WebRTC_DataChannel_Create(ILibWrapper_WebRTC_Connection connection, char* channelName, int channelNameLen, ILibWrapper_WebRTC_DataChannel_OnDataChannelAck OnAckHandler, void *userData)
	{
		ILibWrapper_WebRTC_DataChannel* retVal = ILibWrapper_WebRTC_DataChannel_Create(connection, channelName, channelNameLen, OnAckHandler);
		retVal->userData = userData;
		return(retVal);
	}

	__declspec(dllexport) void ILibWrapper_DLL_WebRTC_DataChannel_Close(ILibWrapper_WebRTC_DataChannel* dataChannel)
	{
		ILibWrapper_WebRTC_DataChannel_Close(dataChannel);
	}

	// Creates a WebRTC Data Channel, using the specified Stream ID
	__declspec(dllexport) ILibWrapper_WebRTC_DataChannel* ILibWrapper_DLL_WebRTC_DataChannel_CreateEx(ILibWrapper_WebRTC_Connection connection, char* channelName, int channelNameLen, unsigned short streamId, ILibWrapper_WebRTC_DataChannel_OnDataChannelAck OnAckHandler, void* userData)
	{
		ILibWrapper_WebRTC_DataChannel* retVal = ILibWrapper_WebRTC_DataChannel_CreateEx(connection, channelName, channelNameLen, streamId, OnAckHandler);
		retVal->userData = userData;
		return(retVal);
	}

	__declspec(dllexport) void ILibWrapper_DLL_WebRTC_Connection_SetUserData(ILibWrapper_WebRTC_Connection connection, void *user1, void *user2, void *user3)
	{
		ILibWrapper_WebRTC_Connection_SetUserData(connection, user1, user2, user3);
	}
	__declspec(dllexport) void ILibWrapper_DLL_WebRTC_Connection_GetUserData(ILibWrapper_WebRTC_Connection connection, void **user1, void **user2, void **user3)
	{
		ILibWrapper_WebRTC_Connection_GetUserData(connection, user1, user2, user3);
	}

	//
	// WebRTC Connection Management
	//

	// Generate an SDP Offer (WebRTC Initiator)
	__declspec(dllexport) char* ILibWrapper_DLL_WebRTC_Connection_GenerateOffer(ILibWrapper_WebRTC_Connection connection, ILibWrapper_WebRTC_OnConnectionCandidate onCandidates)
	{
		return(ILibWrapper_WebRTC_Connection_GenerateOffer(connection, onCandidates));
	}

	// Set an SDP Answer/Offer (WebRTC Receiver)
	__declspec(dllexport) char* ILibWrapper_DLL_WebRTC_Connection_SetOffer(ILibWrapper_WebRTC_Connection connection, char* offer, int offerLen, ILibWrapper_WebRTC_OnConnectionCandidate onCandidates)
	{
		return(ILibWrapper_WebRTC_Connection_SetOffer(connection, offer, offerLen, onCandidates));
	}

	// Generate an udpated SDP offer containing the candidate specified
	__declspec(dllexport) char* ILibWrapper_DLL_WebRTC_Connection_AddServerReflexiveCandidateToLocalSDP(ILibWrapper_WebRTC_Connection connection, struct sockaddr_in6* candidate)
	{
		return(ILibWrapper_WebRTC_Connection_AddServerReflexiveCandidateToLocalSDP(connection, candidate));
	}

	__declspec(dllexport) void ILibWrapper_DLL_WebRTC_Connection_Pause(ILibWrapper_WebRTC_Connection connection)
	{
		ILibWrapper_WebRTC_Connection_Pause(connection);
	}
	__declspec(dllexport) void ILibWrapper_DLL_WebRTC_Connection_Resume(ILibWrapper_WebRTC_Connection connection)
	{
		ILibWrapper_WebRTC_Connection_Resume(connection);
	}

	//
	// WebRTC Data Channel
	//

	// Send Binary Data over the specified Data Channel
	__declspec(dllexport) ILibTransport_DoneState ILibWrapper_DLL_WebRTC_DataChannel_Send(ILibWrapper_WebRTC_DataChannel* dataChannel, char* data, int dataLen)
	{
		return(ILibWrapper_WebRTC_DataChannel_Send(dataChannel, data, dataLen));
	}

	// Send Arbitrary Data over the specified Data Channel. (Must specify the data type)
	__declspec(dllexport) ILibTransport_DoneState ILibWrapper_DLL_WebRTC_DataChannel_SendEx(ILibWrapper_WebRTC_DataChannel* dataChannel, char* data, int dataLen, int dataType)
	{
		return(ILibWrapper_WebRTC_DataChannel_SendEx(dataChannel, data, dataLen, dataType));
	}

	// Send String Data over the specified Data Channel
	__declspec(dllexport) ILibTransport_DoneState ILibWrapper_DLL_WebRTC_DataChannel_SendString(ILibWrapper_WebRTC_DataChannel* dataChannel, char* data, int dataLen)
	{
		return(ILibWrapper_WebRTC_DataChannel_SendString(dataChannel, data, dataLen));
	}

#ifdef _WEBRTCDEBUG
	// SCTP Instrumentation
	__declspec(dllexport) void ILibWrapper_DLL_WebRTC_ConnectionFactory_SetSimulatedLossPercentage(void* connectionFactory, int lossPercentage)
	{
		ILibWrapper_WebRTC_ConnectionFactory_SetSimulatedLossPercentage(connectionFactory, lossPercentage);
	}
	__declspec(dllexport) void ILibWrapper_SCTP_SetTSNCallback(void *dtlsSession, ILibSCTP_OnTSNChanged tsnHandler)
	{
		ILibSCTP_SetTSNCallback(dtlsSession, tsnHandler);
	}

	__declspec(dllexport) int ILibWrapper_DLL_SCTP_Debug_SetDebug(void *connection, char* debugField, ILibSCTP_OnSCTPDebug handler)
	{
		return(ILibSCTP_Debug_SetDebugCallback(((void**)connection)[0], debugField, handler));
	}
#endif
}