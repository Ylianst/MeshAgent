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

/*! \file MulticastSocket.h 
	\brief MicroStack APIs for UDP multicasting functionality
*/

#ifndef __ILibMulticastSocket__
#define __ILibMulticastSocket__
#include "ILibAsyncSocket.h"

#ifdef __cplusplus
extern "C" {
#endif

void *ILibMulticastSocket_Create(void *Chain, int BufferSize, unsigned short LocalPort, struct sockaddr_in *MulticastAddr, struct sockaddr_in6 *MulticastAddr6, ILibAsyncUDPSocket_OnData OnData, void *user, int loopback);
int  ILibMulticastSocket_Unicast(void *module, struct sockaddr* target, char* data, int datalen);
void ILibMulticastSocket_BroadcastIF(void *module, char* data, int datalen, int count, struct sockaddr *localif);
void ILibMulticastSocket_Broadcast(void *module, char* data, int datalen, int count);
int  ILibMulticastSocket_ResetMulticast(void *module, int cleanuponly);
void ILibMulticastSocket_WakeOnLan(void *module, char* mac);
void ILibSetTTL(void *module, int ttl);

#ifdef __cplusplus
}
#endif

#endif

