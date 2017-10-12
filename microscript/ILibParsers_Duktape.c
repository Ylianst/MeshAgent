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
#include <WS2tcpip.h>
#endif

#include "ILibWebServer_Duktape.h"
#include "microstack/ILibParsers.h"
#include "ILibParsers_Duktape.h"
#include "ILibDuktape_Helpers.h"
#include "microstack/ILibRemoteLogging.h"
#include "microstack/ILibCrypto.h"

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif


void ILibParsers_Duktape_OnStart(void *chain, void *user)
{
	duk_context *ctx = (duk_context*)((void**)user)[0];
	void *OnStart = ((void**)user)[1];

	duk_push_heapptr(ctx, OnStart);
	if (duk_pcall(ctx, 0) != 0)
	{
		ILibDuktape_Process_UncaughtException(ctx);
	}
	duk_pop(ctx);

	free(user);
}
duk_ret_t ILibParsers_Duktape_ChainOnStart(duk_context *ctx)
{
	void *chain;
	void *OnStart = (duk_is_undefined(ctx, 0) || duk_is_null(ctx, 0)) ? NULL : duk_require_heapptr(ctx, 0);
	void **state;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "chain");
	chain = duk_to_pointer(ctx, -1);

	if (OnStart != NULL)
	{
		state = (void**)ILibMemory_Allocate(2 * sizeof(void*), 0, NULL, NULL);
		duk_push_heap_stash(ctx);
		duk_dup(ctx, 0);
		duk_put_prop_string(ctx, -2, Duktape_GetStashKey(OnStart));

		state[0] = ctx;
		state[1] = OnStart;

		ILibChain_OnStartEvent_AddHandler(chain, ILibParsers_Duktape_OnStart, state);
		ILibStartChain(chain);
	}

	return 0;
}

#ifdef _REMOTELOGGING
duk_ret_t ILibParsers_Duktape_StartLogger(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	void *chain;
	int port = duk_require_int(ctx, 0);
	int actualPort;
	char *path = nargs > 1 ? (char*)duk_require_string(ctx, 1) : NULL;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "chain");
	chain = duk_to_pointer(ctx, -1);

	actualPort = ILibStartDefaultLoggerEx(chain, port, path);

	duk_push_int(ctx, actualPort);
	return 1;
}
#endif

void ILibParsers_DukTape_Init(duk_context * ctx, void * chain)
{
	duk_push_heap_stash(ctx);					// [stash]
	duk_push_pointer(ctx, chain);				// [stash][chainPtr]
	duk_put_prop_string(ctx, -2, "gChainPtr");	// [stash]
	duk_pop(ctx);								// ...


	duk_push_global_object(ctx);									// [g]

	duk_push_c_function(ctx, ILibParsers_Duktape_ChainOnStart, 1);	// [g][func]
	duk_push_pointer(ctx, chain);									// [g][func][chain]
	duk_put_prop_string(ctx, -2, "chain");							// [g][func]
	duk_put_prop_string(ctx, -2, "ILibParsers_Start");				// [g]


#ifdef _REMOTELOGGING
	duk_push_c_function(ctx, ILibParsers_Duktape_StartLogger, DUK_VARARGS);	// [g][func]
	duk_push_pointer(ctx, chain);											// [g][func][chain]
	duk_put_prop_string(ctx, -2, "chain");									// [g][func]
	duk_put_prop_string(ctx, -2, "ILibParsers_StartDefaultLogger");			// [g]
#endif

	Duktape_CreateEnum(ctx, "RemoteLogging_Modules", (char*[]) { "UNKNOWN", "WEBRTC_ICE", "WEBRTC_DTLS", "WEBRTC_SCTP", "MESHAGENT_GUARDPOST", "MESHAGENT_P2P", "MESHAGENT_KVM", "MICROSTACK_ASYNCSOCKET", "MICROSTACK_WEB", "MICROSTACK_PIPE", "MICROSTACK_GENERIC" }, (int[]) { 0x00, 0x02, 0x04, 0x08, 0x10, 0x20, 0x200, 0x40, 0x80, 0x400, 0x100 }, 11);
	Duktape_CreateEnum(ctx, "RemoteLogging_Flags", (char*[]) { "NONE", "DISABLE", "VERBOSITY_1", "VERBOSITY_2", "VERBOSITY_3", "VERBOSITY_4", "VERBOSITY_5" }, (int[]) { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20 }, 7);


	duk_pop(ctx); // Pop Global Object
}
