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
#include <WinSock2.h>
#include <ws2tcpip.h>
#endif

#include "microstack/ILibParsers.h"
#include "microstack/ILibAsyncServerSocket.h"
#include "ILibDuktape_Helpers.h"
#include "duktape.h"



typedef struct ILibDuktape_Debugger
{
	duk_context *ctx;
#ifdef WIN32
	SOCKET listener;
	SOCKET client;
#else
	int listener;
	int client;
#endif
}ILibDuktape_Debugger;


duk_size_t ILibDuktape_Debugger_ReadCB(void *udata, char *buffer, duk_size_t length)
{
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)udata;

	return (duk_size_t)recv(dbg->client, buffer, (int)length, 0);
}
duk_size_t ILibDuktape_Debugger_WriteCB(void *udata, const char *buffer, duk_size_t length)
{
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)udata;
	return (duk_size_t)send(dbg->client, buffer, (int)length, 0);
}
void ILibDuktape_Debugger_DetachCB(void *udata)
{

}
void ILibDuktape_Debugger_Start(duk_context *ctx, unsigned short debugPort)
{
	ILibDuktape_Debugger *dbg;
	struct sockaddr_in6 local_int;
	struct sockaddr_in6 remote_int;
	int remote_int_size = sizeof(struct sockaddr_in6);

	memset(&local_int, 0, sizeof(struct sockaddr_in6));
	local_int.sin6_family = AF_INET;
	((struct sockaddr_in*)&local_int)->sin_addr.s_addr = INADDR_ANY;
	local_int.sin6_port = htons(debugPort);

	duk_push_global_object(ctx);								// [obj]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_Debugger));	// [obj][buf]
	dbg = (ILibDuktape_Debugger*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, "_DbgObj");					// [obj]
	duk_pop(ctx);												// ...

	memset(dbg, 0, sizeof(ILibDuktape_Debugger));
	dbg->ctx = ctx;
	if((dbg->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) { dbg->listener = (SOCKET)~0;  return; }
	
	bind(dbg->listener, (struct sockaddr*)&local_int, sizeof(struct sockaddr_in6));
	listen(dbg->listener, 1);
	dbg->client = accept(dbg->listener, (struct sockaddr*)&remote_int, &remote_int_size);

	duk_debugger_attach(ctx, ILibDuktape_Debugger_ReadCB, ILibDuktape_Debugger_WriteCB, NULL, NULL, NULL, ILibDuktape_Debugger_DetachCB, (void*)dbg);
}

void ILibDuktape_Debugger_Stop(duk_context *ctx)
{

}

