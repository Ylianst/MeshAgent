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

#ifndef ___ILIBDUKTAPENET___
#define ___ILIBDUKTAPENET___

#include "duktape.h"
#if defined(WINSOCK2)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "microstack/ILibParsers.h"

#define ILibDuktape_SOCKET2OPTIONS	"\xFF_NET_SOCKET2OPTIONS"
void ILibDuktape_net_init(duk_context *ctx, void *chain);

typedef struct ILibDuktape_globalTunnel_data
{
	struct sockaddr_in6 proxyServer;
	ILibHashtable exceptionsTable;
	char proxyUser[255];
	char proxyPass[255];
}ILibDuktape_globalTunnel_data;

ILibDuktape_globalTunnel_data* ILibDuktape_GetGlobalTunnel(duk_context *ctx);
ILibDuktape_globalTunnel_data* ILibDuktape_GetNewGlobalTunnelEx(duk_context *ctx, int native);
#define ILibDuktape_GetNewGlobalTunnel(ctx) ILibDuktape_GetNewGlobalTunnelEx(ctx, 1)

#endif
