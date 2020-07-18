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

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#if defined(WINSOCK2)
	#include <winsock2.h>
	#include <ws2ipdef.h>
#elif defined(WINSOCK1)
	#include <winsock.h>
	#include <wininet.h>
#endif

#include "ILibParsers.h"
#include "ILibAsyncUDPSocket.h"
#include "ILibAsyncSocket.h"

#define INET_SOCKADDR_LENGTH(x) ((x==AF_INET6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)

struct ILibMulticastSocket_StateModule
{
	ILibChain_Link ChainLink;
	void *UDPServer;
	void *UDPServer6;
	void **UDPServers;
	void *User;
	void *Tag;
	int TTL;
	int Loopback;
	unsigned short LocalPort;
	ILibAsyncUDPSocket_OnData OnData;

	// The IPv4 and IPv6 multicast addresses.
	struct sockaddr_in MulticastAddr;
	struct sockaddr_in6 MulticastAddr6;

	// Lists of local IPv4 and IPv6 interfaces
	struct sockaddr_in *AddressListV4;
	int AddressListLengthV4;
	int* IndexListV6;
	int IndexListLenV6;
};

// Received a UDP packet on the IPv4 socket, process it.
void UDPSocket_OnDataV4(ILibAsyncUDPSocket_SocketModule socketModule, char* buffer, int bufferLength, struct sockaddr_in6 *remoteInterface, void *user, void *user2, int *PAUSE)
{
	struct ILibMulticastSocket_StateModule* module = (struct ILibMulticastSocket_StateModule*)user;

	// Call the user
	if (module->OnData != NULL) module->OnData(socketModule, buffer, bufferLength, remoteInterface, module->User, user2, PAUSE);
}

// Received a UDP packet on the IPv6 socket, process it.
void UDPSocket_OnDataV6(ILibAsyncUDPSocket_SocketModule socketModule, char* buffer, int bufferLength, struct sockaddr_in6 *remoteInterface, void *user, void *user2, int *PAUSE)
{
	struct ILibMulticastSocket_StateModule* module = (struct ILibMulticastSocket_StateModule*)user;

	// Remove any traffic from IPv4 mapped addresses because the IPv4 socket will take care of it.
	if (ILibIsIPv4MappedAddr((struct sockaddr*)remoteInterface)) return;

	// Call the user
	if (module->OnData != NULL) module->OnData(socketModule, buffer, bufferLength, remoteInterface, module->User, user2, PAUSE);
}

int ILibMulticastSocket_ResetMulticast(struct ILibMulticastSocket_StateModule *module, int cleanuponly)
{
	int i;
	int change = 0;
	struct sockaddr_in any4;
	struct sockaddr_in6 any6;
	int tAddressListLengthV4 = 0;
	struct sockaddr_in* tAddressListV4 = NULL;
	int tIndexListLenV6 = 0;
	int* tIndexListV6 = NULL;
	SOCKET socket;
	#ifdef WINSOCK2
	DWORD dwBytesReturned = 0;
	BOOL bNewBehavior = FALSE;
	#endif

	// If this is not just cleanup, lets check to see if this operation is really needed
	if (!cleanuponly)
	{
		tAddressListLengthV4 = ILibGetLocalIPv4AddressList(&tAddressListV4, 0);

		// See if there are any changes in IPv4 interfaces
		if (tAddressListLengthV4 != module->AddressListLengthV4) change = 1;
		else if (tAddressListV4 == NULL && module->AddressListV4 != NULL) change = 1;
		else if (tAddressListV4 != NULL && module->AddressListV4 == NULL) change = 1;
		else if (tAddressListV4 != NULL && module->AddressListV4 != NULL && memcmp(tAddressListV4, module->AddressListV4, sizeof(struct sockaddr_in) * tAddressListLengthV4) != 0) change = 1;
		
		if (module->UDPServer6 != NULL)
		{
			tIndexListLenV6 = ILibGetLocalIPv6IndexList(&tIndexListV6);

			// See if there are any changes in IPv6 interfaces
			if (tIndexListLenV6 != module->IndexListLenV6) change = 1;
			else if (tIndexListV6 != NULL && module->IndexListV6 == NULL) change = 1;
			else if (tIndexListV6 == NULL && module->IndexListV6 != NULL) change = 1;
			else if (tIndexListV6 != NULL && module->IndexListV6 != NULL && memcmp(tIndexListV6, module->IndexListV6, sizeof(int) * tIndexListLenV6) != 0) change = 1;
		}

		// If change is zero, this update is not needed.
		if (change == 0) { free(tAddressListV4); free(tIndexListV6); return 0; }
	}

	// Free the address lists
	if (module->AddressListV4 != NULL) { free(module->AddressListV4); module->AddressListV4 = NULL; }
	if (module->IndexListV6   != NULL) { free(module->IndexListV6);   module->IndexListV6 = NULL; }

	// Free the IPv4 server sockets
	if (module->UDPServers != NULL)
	{
		for(i = 0; i < module->AddressListLengthV4; ++i) { if (module->UDPServers[i] != NULL) { ILibChain_SafeRemove(module->ChainLink.ParentChain, module->UDPServers[i]); } }
		free(module->UDPServers);
		module->UDPServers = NULL;
	}

	// If we only want to cleanup, exit now
	if (cleanuponly) return 0;

	// Setup Any4 address
	memset(&any4, 0, sizeof(struct sockaddr_in));
	any4.sin_family = AF_INET;
	any4.sin_port = htons(module->LocalPort);

	// Setup Any6 address
	memset(&any6, 0, sizeof(struct sockaddr_in6));
	any6.sin6_family = AF_INET6;
	any6.sin6_port = htons(module->LocalPort);
	// Join the IPv4 multicast group
	if (tAddressListV4 != NULL && module->MulticastAddr.sin_family != 0)
	{
		// Get the list of local interfaces
		module->AddressListLengthV4 = tAddressListLengthV4;
		module->AddressListV4 = tAddressListV4;
		if (module->AddressListLengthV4 > 0 && module->AddressListV4 != NULL)
		{
			if ((module->UDPServers = (void**)malloc(sizeof(void*) * module->AddressListLengthV4)) == NULL) ILIBCRITICALEXIT(254);

			// Join the same multicast group on all interfaces & create interface-specific sockets
			for(i = 0; i < module->AddressListLengthV4; ++i)
			{
				module->AddressListV4[i].sin_port = htons(module->LocalPort);
				module->UDPServers[i] = ILibAsyncUDPSocket_CreateEx(module->ChainLink.ParentChain, 0, (struct sockaddr*)&(module->AddressListV4[i]), ILibAsyncUDPSocket_Reuse_SHARED, UDPSocket_OnDataV4, NULL, module);
				if (module->UDPServers[i] != NULL)
				{
					ILibChain_Link_SetMetadata(module->UDPServers[i], "ILibMulticastSocket_v4");
					ILibAsyncUDPSocket_JoinMulticastGroupV4(module->UDPServers[i], &(module->MulticastAddr), (struct sockaddr*)&(module->AddressListV4[i]));
					ILibAsyncUDPSocket_SetLocalInterface(module->UDPServers[i], (struct sockaddr*)&(module->AddressListV4[i]));
					socket = ILibAsyncUDPSocket_GetSocket(module->UDPServers[i]);
#if !defined(NACL)
					if (setsockopt(socket, IPPROTO_IP, IP_MULTICAST_TTL, (const char*)&(module->TTL), sizeof(int)) != 0) ILIBCRITICALERREXIT(253);
					if (setsockopt(socket, IPPROTO_IP, IP_MULTICAST_LOOP, (const char*)&(module->Loopback), sizeof(int)) != 0) ILIBCRITICALERREXIT(253);
					if (setsockopt(socket, IPPROTO_IP, IP_MULTICAST_LOOP, (const char*)&(module->Loopback), sizeof(int)) != 0) ILIBCRITICALERREXIT(253);
#endif
					module->AddressListV4[i].sin_port = 0;

					// This will cause the socket not to stop if sending a packet to an invalid UDP port
					#ifdef WINSOCK2
					WSAIoctl(socket, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), NULL, 0, &dwBytesReturned, NULL, NULL);
					#endif
				}
			}
		}
	} else if (tAddressListV4 != NULL) free(tAddressListV4);
	// Join the IPv6 multicast group
	if (tIndexListLenV6 != 0 && tIndexListV6 != NULL && module->MulticastAddr6.sin6_family != 0 && module->UDPServer6 != NULL)
	{
		// Get the list of local interfaces
		module->IndexListLenV6 = tIndexListLenV6;
		module->IndexListV6 = tIndexListV6;

		// Join the same multicast group on all interfaces
		for(i = 0; i<module->IndexListLenV6; ++i) { ILibAsyncUDPSocket_JoinMulticastGroupV6(module->UDPServer6, &(module->MulticastAddr6), module->IndexListV6[i]); }
	}
	else if (tIndexListV6 != NULL) free(tIndexListV6);
	return 1;
}


// Perform a local network broadcast of this packet
void ILibMulticastSocket_BroadcastUdpPacketV4(struct ILibMulticastSocket_StateModule *module, struct sockaddr_in* addr, char* data, int datalen, int count, struct sockaddr *localif)
{
	int i,j;
	SOCKET socket;
	//printf("IPv4 Broadcasting %d bytes.\r\n", datalen);

	for(i = 0; i < module->AddressListLengthV4; ++i)
	{
#ifdef WINSOCK2
		if (localif == NULL || ((struct sockaddr_in*)localif)->sin_addr.S_un.S_addr == module->AddressListV4[i].sin_addr.S_un.S_addr)
#else
		if (localif == NULL || ((struct sockaddr_in*)localif)->sin_addr.s_addr == module->AddressListV4[i].sin_addr.s_addr)
#endif
		{
			#ifndef NACL
			if (module->UDPServers[i] != NULL)
			{
				socket = ILibAsyncUDPSocket_GetSocket(module->UDPServer);
				setsockopt(socket, IPPROTO_IP, IP_MULTICAST_IF, (const char*)&(module->AddressListV4[i].sin_addr), sizeof(struct in_addr));
				setsockopt(socket, IPPROTO_IP, IP_MULTICAST_TTL, (const char*)&(module->TTL), sizeof(int));
				for (j = 0; j < count; j++) sendto(socket, data, datalen, 0, (struct sockaddr*)addr, sizeof(struct sockaddr_in));
			}
			#endif			
		}
	}
}


// Perform a local network broadcast of this packet
void ILibMulticastSocket_BroadcastUdpPacketV6(struct ILibMulticastSocket_StateModule *module, struct sockaddr_in6* addr, char* data, int datalen, int count, struct sockaddr *localif)
{
	int i,j;
	//printf("IPv6 Broadcasting %d bytes.\r\n", datalen);

	// TODO: Consider the local interface
	UNREFERENCED_PARAMETER( localif );

	for(i = 0; i < module->IndexListLenV6; i++)
	{
		#ifndef NACL
		setsockopt(ILibAsyncUDPSocket_GetSocket(module->UDPServer6), IPPROTO_IPV6, IPV6_MULTICAST_IF, (const char*)&(module->IndexListV6[i]), 4);
		for (j=0;j<count;j++) sendto(ILibAsyncUDPSocket_GetSocket(module->UDPServer6), data, datalen, 0, (struct sockaddr*)addr, sizeof(struct sockaddr_in6));
		#endif
	}
}

// Perform network broadcast of this packet
void ILibMulticastSocket_Broadcast(struct ILibMulticastSocket_StateModule *module, char* data, int datalen, int count)
{
	// Broadcast on both IPv4 and IPv6, but lets use IPv6 first.
	if (module->MulticastAddr6.sin6_family != 0) ILibMulticastSocket_BroadcastUdpPacketV6(module, &(module->MulticastAddr6), data, datalen, count, NULL);
	if (module->MulticastAddr.sin_family != 0) ILibMulticastSocket_BroadcastUdpPacketV4(module, &(module->MulticastAddr), data, datalen, count, NULL);
}

// Perform network broadcast of this packet on a specific local interface
void ILibMulticastSocket_BroadcastIF(struct ILibMulticastSocket_StateModule *module, char* data, int datalen, int count, struct sockaddr *localif)
{
	// Broadcast on both IPv4 and IPv6, but lets use IPv6 first.
	if ((localif == NULL || localif->sa_family == AF_INET6) && module->MulticastAddr6.sin6_family != 0) ILibMulticastSocket_BroadcastUdpPacketV6(module, &(module->MulticastAddr6), data, datalen, count, localif);
	if ((localif == NULL || localif->sa_family == AF_INET) && module->MulticastAddr.sin_family != 0) ILibMulticastSocket_BroadcastUdpPacketV4(module, &(module->MulticastAddr), data, datalen, count, localif);
}

// Perform unicast transmit using this socket.
int ILibMulticastSocket_Unicast(struct ILibMulticastSocket_StateModule *module, struct sockaddr* target, char* data, int datalen)
{
	if (target->sa_family == AF_INET6) return sendto(ILibAsyncUDPSocket_GetSocket(module->UDPServer6), data, datalen, 0, target, INET_SOCKADDR_LENGTH(target->sa_family));
	if (target->sa_family == AF_INET) return sendto(ILibAsyncUDPSocket_GetSocket(module->UDPServer), data, datalen, 0, target, INET_SOCKADDR_LENGTH(target->sa_family));
	return -1;
}

// Private method called when the chain is destroyed, we want to do our cleanup here
void ILibMulticastSocket_Destroy(void *object)
{
	ILibMulticastSocket_ResetMulticast((struct ILibMulticastSocket_StateModule*)object, 1);
}

// Create a new MulticastSocket module. This module handles all send and receive traffic for IPv4 and IPv6 on a given multicast group.
struct ILibMulticastSocket_StateModule *ILibMulticastSocket_Create(void *Chain, int BufferSize, unsigned short LocalPort, struct sockaddr_in *MulticastAddr, struct sockaddr_in6 *MulticastAddr6, ILibAsyncUDPSocket_OnData OnData, void *user, int loopback)
{
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct ILibMulticastSocket_StateModule* module;

	UNREFERENCED_PARAMETER( BufferSize );

	// Allocate the new socket state
	module = (struct ILibMulticastSocket_StateModule*)malloc(sizeof(struct ILibMulticastSocket_StateModule));
	if (module == NULL) { PRINTERROR(); return NULL; }
	memset(module, 0, sizeof(struct ILibMulticastSocket_StateModule));

	// Setup local IPv4 binding address
	memset(&addr4, 0, sizeof(struct sockaddr_in));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(LocalPort);

	// Setup local IPv6 binding address
	memset(&addr6, 0, sizeof(struct sockaddr_in6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(LocalPort);

	// Setup the multicasting module
	module->ChainLink.MetaData = "ILibMulticastSocket";
	module->ChainLink.DestroyHandler = &ILibMulticastSocket_Destroy;
	module->ChainLink.ParentChain = Chain;
	module->LocalPort = LocalPort;
	module->TTL = 4;
	module->Loopback = loopback;
	module->OnData = OnData;
	module->User = user;
	if (MulticastAddr != NULL)
	{
		// Setup the IPv4 multicast address
		memcpy(&(module->MulticastAddr), MulticastAddr, sizeof(struct sockaddr_in));
		if (module->MulticastAddr.sin_port == 0) module->MulticastAddr.sin_port = htons(LocalPort);

		// Setup incoming IPv4 socket
		module->UDPServer = ILibAsyncUDPSocket_CreateEx(Chain, 0, (struct sockaddr*)&addr4, ILibAsyncUDPSocket_Reuse_SHARED, UDPSocket_OnDataV4, NULL, module);
		if (module->UDPServer == NULL) { free(module); PRINTERROR(); return NULL; }
		ILibChain_Link_SetMetadata(module->UDPServer, "ILibMulticastSocketListener_v4");

#ifndef NACL
		if (setsockopt(ILibAsyncUDPSocket_GetSocket(module->UDPServer), IPPROTO_IP, IP_MULTICAST_TTL, (const char*)&(module->TTL), sizeof(int)) != 0) {ILIBCRITICALERREXIT(253);}
		if (setsockopt(ILibAsyncUDPSocket_GetSocket(module->UDPServer), IPPROTO_IP, IP_MULTICAST_LOOP, (const char*)&(module->Loopback), sizeof(int)) != 0) {ILIBCRITICALERREXIT(253);}
		
		// Allow IPv4 Broadcast on this socket
		//if (setsockopt(module->NOTIFY_SEND_socks, SOL_SOCKET, SO_BROADCAST, (char*)&optval, 4) != 0) ILIBCRITICALERREXIT(253);
#endif


	}
	if (MulticastAddr6 != NULL)
	{
		
		// Setup incoming IPv6 socket
		module->UDPServer6 = ILibAsyncUDPSocket_CreateEx(Chain, 0, (struct sockaddr*)&addr6, ILibAsyncUDPSocket_Reuse_SHARED, UDPSocket_OnDataV6, NULL, module);
		if (module->UDPServer6 != NULL)
		{
			ILibChain_Link_SetMetadata(module->UDPServer6, "ILibMulticastSocketListener_v6");

			// Setup the IPv6 multicast address
			memcpy(&(module->MulticastAddr6), MulticastAddr6, sizeof(struct sockaddr_in6));
			if (module->MulticastAddr6.sin6_port == 0) module->MulticastAddr6.sin6_port = htons(LocalPort);

			// Set TTL, IPv6, Loop and Reuse flags assumed to already be set
#ifndef NACL
			if (setsockopt(ILibAsyncUDPSocket_GetSocket(module->UDPServer6), IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char*)&(module->TTL), sizeof(int)) != 0) ILIBCRITICALERREXIT(253);
			if (setsockopt(ILibAsyncUDPSocket_GetSocket(module->UDPServer6), IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char*)&(module->Loopback), sizeof(int)) != 0) ILIBCRITICALERREXIT(253);
#endif
		}
	}

#if !defined( NACL )
	ILibMulticastSocket_ResetMulticast(module, 0);
#endif

	ILibAddToChain(Chain, module);
	return module;
}

void ILibSetTTL(void *vmodule, int ttl)
{
	struct ILibMulticastSocket_StateModule* module = (struct ILibMulticastSocket_StateModule*)vmodule;
	module->TTL = ttl;
#ifdef NACL

#else
	if (setsockopt(ILibAsyncUDPSocket_GetSocket(module->UDPServer), IPPROTO_IP, IP_MULTICAST_TTL, (const char*)&(module->TTL), sizeof(int)) != 0) ILIBCRITICALERREXIT(253);
	if (setsockopt(ILibAsyncUDPSocket_GetSocket(module->UDPServer6), IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char*)&(module->TTL), sizeof(int)) != 0) ILIBCRITICALERREXIT(253);
#endif
}

void ILibMulticastSocket_WakeOnLan(void *module, char* mac)
{
	int i;
	struct sockaddr_in addr4;

	// Create an IPv4 broadcast address
	memset(&addr4, 0, sizeof(struct sockaddr_in));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(16990);
	#ifdef WINSOCK2
	addr4.sin_addr.S_un.S_addr = INADDR_BROADCAST;				// Broadcast
	#else
	addr4.sin_addr.s_addr = INADDR_BROADCAST;					// Broadcast
	#endif

	// Create the magic packet
	memset(ILibScratchPad, 0xFF, 6);
	for (i = 1; i < 17; i++) memcpy(ILibScratchPad + (6 * i), mac, 6);

	// Send it
	for (i = 0; i < 2; i++)
	{
		// IPv4 Broadcast, works only in the same subnet
		sendto(ILibAsyncUDPSocket_GetSocket(((struct ILibMulticastSocket_StateModule*)module)->UDPServer), ILibScratchPad, 102, 0, (const struct sockaddr*)&addr4, sizeof(struct sockaddr_in));

		// IPv4 & IPv6 Multicast. Only works if the machine still is subscribed to SSDP messages (S1 or S3 usualy), but has out-of-subnet range.
		ILibMulticastSocket_Broadcast((struct ILibMulticastSocket_StateModule*)module, ILibScratchPad, 102, 1);
	}
}
