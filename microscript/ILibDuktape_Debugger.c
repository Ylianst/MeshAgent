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
#include "microstack/ILibSimpleDataStore.h"
#include "ILibDuktape_Helpers.h"
#include "duktape.h"
#include "ILibDuktape_ScriptContainer.h"
#include "ILibDuktape_Debugger.h"
#include "ILibDuktapeModSearch.h"

#define ILibDuktape_Debugger_SCRIPT_SOURCE			"_scriptSourceForDebugger"
#define ILibDuktape_Debugger_SCRIPT_PATH			"_scriptPathForDebugger"
#define ILibDuktape_Debugger_AttachOptions			"\xFF_debugger_attachOptions"
#define ILibDuktape_Debugger_Options_Rejector		"\xFF_rejector"
#define ILibDuktape_Debugger_Options_Resolver		"\xFF_resolver"
#define ILibDuktape_Debugger_DebugObject			"_DbgObj"
#define ILibDuktape_Debugger_HostChain				"_HostChain"
#define ILibDuktape_Debugger_MemoryReportInterval	"_Debugger_MemoryReporting"
extern size_t ILibDuktape_ScriptContainer_TotalAllocations;

typedef struct ILibDuktape_Debugger
{
	ILibChain_Link *chainedObject;
	duk_context *ctx;
	duk_thread_state hoststate;
	sem_t hostlock;
	int waitConnection;
	void *debugThread;
	int webport;
	void *interval;
	char data[sizeof(char*)];
#ifdef WIN32
	SOCKET listener;
	SOCKET client;
#else
	int listener;
	int client;
#endif
}ILibDuktape_Debugger;

void *DebugWebEngine_Context;
void *DebugWebEngine_Chain;
void *DebugWebEngine_Thread;

void ILibDuktape_Debugger_AsyncWaitConn(ILibDuktape_Debugger *dbg);
duk_ret_t ILibDuktape_Debugger_MemoryReportingSink(duk_context *ctx)
{
	duk_push_string(ctx, "MemoryAllocations");
	duk_push_int(ctx, (duk_int_t)ILibDuktape_ScriptContainer_TotalAllocations);
	duk_debugger_notify(ctx, 2);
	return(0);
}
void ILibDuktape_Debugger_StartMemoryReporting(duk_context *ctx)
{
	duk_push_global_object(ctx);											// [g]
	duk_get_prop_string(ctx, -1, "setInterval");							// [g][setInterval]
	duk_swap_top(ctx, -2);													// [setInterVal][this]
	duk_push_c_function(ctx, ILibDuktape_Debugger_MemoryReportingSink, 0);	// [setInterVal][this][func]
	duk_push_int(ctx, 5000);												// [setInterVal][this][func][delay]
	if (duk_pcall_method(ctx, 2) != 0) { duk_pop(ctx); return; }			// [interval]
	duk_push_heap_stash(ctx);												// [interval][stash]
	duk_swap_top(ctx, -2);													// [stash][interval]
	duk_put_prop_string(ctx, -2, ILibDuktape_Debugger_MemoryReportInterval);// [stash]
	duk_pop(ctx);															// ...
}
void ILibDuktape_Debugger_StopMemoryReporting(duk_context *ctx)
{
	duk_push_heap_stash(ctx);
	duk_del_prop_string(ctx, -1, ILibDuktape_Debugger_MemoryReportInterval);
	duk_pop(ctx);
}

void ILibDuktape_Debugger_Socket_finish(void *udata)
{
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)udata;

	if (dbg->client != ~0)
	{
#ifdef WIN32
		closesocket(dbg->client);
#else
		shutdown(dbg->client, SHUT_RDWR);
		close(dbg->client);
#endif
		dbg->client = ~0;
	}

	ILibDuktape_Debugger_StopMemoryReporting(dbg->ctx);
}

void ILibDuktape_Debugger_Socket_waitconn(void *udata)
{
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)udata;
	if (!ILibMemory_CanaryOK(dbg))
	{
		printf("INVALID CANARY\n");
	}


	dbg->client = accept(dbg->listener, NULL, NULL);
	((void**)dbg->data)[0] = dbg;

	if (dbg->client == ~0)
	{
#ifdef WIN32
		printf("Ooops, invalid socket: %d\n", WSAGetLastError());
#else
		printf("Ooops, invalid socket: %d\n", errno);
#endif
	}
}

duk_size_t ILibDuktape_Debugger_PeekCB(void *udata)
{
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)udata;
	int bytes = 0;
#ifndef WIN32
	char tmp[8];
#endif

	// Set the socket to non-blocking mode, because we need to play nice and share the MicroStack thread
#if defined(WIN32)

	if (dbg->client == ~0)
	{
		return(0);
	}


	//// On Windows must set NON_BLOCK to check this
	//int flags = 1;
	//ioctlsocket(dbg->client, FIONBIO, (u_long *)(&flags));

	//bytes = recv(dbg->client, tmp, sizeof(tmp), MSG_PEEK);

	//flags = 0;
	//ioctlsocket(dbg->client, FIONBIO, (u_long *)(&flags));
	u_long avail = 0;
	int rc = ioctlsocket(dbg->client, FIONREAD, &avail);
	if (rc != 0) 
	{
		fprintf(stderr, "%s: ioctlsocket() returned %d, closing connection\n",
			__FILE__, rc);
		fflush(stderr);
		return(0);
	}
	else 
	{
		if (avail == 0) 
		{
			return 0;  /* nothing to read */
		}
		else 
		{
			return 1;  /* something to read */
		}
	}
#else
	// Everything else, use MSG_DONTWAIT
	bytes = recv(dbg->client, tmp, sizeof(tmp), MSG_PEEK | MSG_DONTWAIT);
#endif

	return(bytes > 0 ? 1 : 0);
}
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
void ILibDuktape_Debugger_DetachCB(duk_context *ctx, void *udata)
{
	ILibDuktape_Debugger_Socket_finish(udata);
	ILibDuktape_Debugger_AsyncWaitConn((ILibDuktape_Debugger*)udata);
	UNREFERENCED_PARAMETER(ctx);
}

void ILibDuktape_Debugger_AsyncWaitConn_PreSelect(void* object, fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime)
{
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[0];
	if (dbg == NULL || !ILibMemory_CanaryOK(dbg))
	{
		((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[0] = NULL;
		ILibChain_SafeRemove(((ILibChain_Link*)object)->ParentChain, object);
		return;
	}

	if (dbg->waitConnection != 0 && dbg->listener != (SOCKET)~0)
	{
		FD_SET(dbg->listener, readset);
	}
}

void ILibDuktape_Debugger_AsyncWaitConn_PostSelect(void* object, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[0];
	if (dbg == NULL || !ILibMemory_CanaryOK(dbg)) { return; }

	if (dbg->waitConnection != 0 && dbg->listener != (SOCKET)~0 && FD_ISSET(dbg->listener, readset))
	{
		dbg->waitConnection = 0;
		dbg->client = accept(dbg->listener, NULL, NULL);
		((void**)dbg->data)[0] = dbg;

		if (dbg->client != ~0)
		{
			ILibDuktape_Debugger_StartMemoryReporting(dbg->ctx);
			duk_debugger_attach(dbg->ctx, ILibDuktape_Debugger_ReadCB, ILibDuktape_Debugger_WriteCB, ILibDuktape_Debugger_PeekCB, NULL, NULL, NULL, ILibDuktape_Debugger_DetachCB, (void*)dbg);
		}
	}
}
void ILibDuktape_Debugger_AsyncWaitConn(ILibDuktape_Debugger *dbg)
{
	if (dbg->chainedObject == NULL)
	{
		dbg->chainedObject = ILibChain_Link_Allocate(sizeof(ILibChain_Link), sizeof(void*));
		dbg->chainedObject->MetaData = "ILibDuktape_Debugger_AsyncWaitConn";
		((void**)dbg->chainedObject->ExtraMemoryPtr)[0] = dbg;
		dbg->chainedObject->PreSelectHandler = ILibDuktape_Debugger_AsyncWaitConn_PreSelect;
		dbg->chainedObject->PostSelectHandler = ILibDuktape_Debugger_AsyncWaitConn_PostSelect;
		ILibChain_SafeAdd(Duktape_GetChain(dbg->ctx), dbg->chainedObject);
	}
	else
	{
		ILibForceUnBlockChain(Duktape_GetChain(dbg->ctx));
	}
	dbg->waitConnection = 1;
}

void ILibDuktape_Debugger_DestroyEx(void *chain, void *user)
{
	Duktape_SafeDestroyHeap(DebugWebEngine_Context);
}

void DebugWebEngine_RunEx(void *chain, void *user)
{
	ILibChain_OnDestroyEvent_AddHandler(chain, ILibDuktape_Debugger_DestroyEx, NULL);
	if (duk_peval_string(DebugWebEngine_Context, "process.on('uncaughtException', function(e){console.log('Uncaught:', e);}); var duktape_debugger = require('duktape-debugger'); var dbg = new duktape_debugger(); dbg.run();") == 0)
	{
		printf("Debugger Initialized...\n");
	}
	else
	{
		printf("Unable to launch debugger client: %s\n", duk_safe_to_string(DebugWebEngine_Context, -1));
	}
	duk_pop(DebugWebEngine_Context);
}

void DebugWebEngine_Run(void *obj)
{
	ILibChain_RunOnMicrostackThreadEx(DebugWebEngine_Chain, DebugWebEngine_RunEx, NULL);
	ILibStartChain(DebugWebEngine_Chain);
}
void ILibDuktape_Debugger_Destroy(void *chain, void *user)
{
	ILibStopChain(DebugWebEngine_Chain);
#ifdef WIN32
	WaitForSingleObject(DebugWebEngine_Thread, INFINITE);
#endif
}

duk_ret_t ILibDuktape_Debugger_StartEngine_UpdatePort(duk_context *ctx)
{
	duk_push_current_function(ctx);
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Debugger_DebugObject);
	int port = duk_require_int(ctx, 0);
	if (dbg != NULL && ILibMemory_CanaryOK(dbg))
	{
		dbg->webport = port;
		sem_post(&(dbg->hostlock));
	}
	return(0);
}
void ILibDuktape_Debugger_hostCooperate_Sink(void *chain, void *user)
{
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)user;
	if (ILibMemory_CanaryOK(dbg))
	{
		duk_debugger_cooperate(dbg->ctx);
	}
}
duk_ret_t ILibDuktape_Debugger_hostCooperate(duk_context *ctx)
{
	duk_push_current_function(ctx);
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Debugger_DebugObject);
	void *chain = Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Debugger_HostChain);
	if (chain != NULL && dbg != NULL && ILibMemory_CanaryOK(dbg))
	{
		ILibChain_RunOnMicrostackThreadEx(chain, ILibDuktape_Debugger_hostCooperate_Sink, dbg);
	}
	return(0);
}
void ILibDuktape_Debugger_detachCleanup_Sink(void *chain, void *user)
{
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)user;
	if (ILibMemory_CanaryOK(dbg))
	{		
		if (dbg->client != (SOCKET)~0 && dbg->waitConnection==0)
		{
			ILibDuktape_Debugger_Socket_finish((void*)dbg);
			ILibDuktape_Debugger_AsyncWaitConn(dbg);
		}
	}
}
duk_ret_t ILibDuktape_Debugger_detachCleanup(duk_context *ctx)
{
	duk_push_current_function(ctx);
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Debugger_DebugObject);
	void *chain = Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Debugger_HostChain);
	if (chain != NULL && dbg != NULL && ILibMemory_CanaryOK(dbg))
	{
		ILibChain_RunOnMicrostackThreadEx(chain, ILibDuktape_Debugger_detachCleanup_Sink, dbg);
	}
	return(0);
}
void ILibDuktape_Debugger_hostGC_sink(void *chain, void *user)
{
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)user;
	if (ILibMemory_CanaryOK(dbg))
	{
		duk_peval_string(dbg->ctx, "_debugGC();"); duk_pop(dbg->ctx);
		duk_push_string(dbg->ctx, "MemoryAllocations");
		duk_push_int(dbg->ctx, (duk_int_t)ILibDuktape_ScriptContainer_TotalAllocations);
		duk_debugger_notify(dbg->ctx, 2);
	}
}
duk_ret_t ILibDuktape_Debugger_hostGC(duk_context *ctx)
{
	duk_push_current_function(ctx);
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Debugger_DebugObject);
	void *chain = Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Debugger_HostChain);
	if (chain != NULL && dbg != NULL && ILibMemory_CanaryOK(dbg))
	{
		ILibChain_RunOnMicrostackThreadEx(chain, ILibDuktape_Debugger_hostGC_sink, dbg);
	}
	return(0);

}
void* ILibDuktape_Debugger_StartEngine(duk_context *ctx, int transport, int webport)
{
	char *promise = NULL, *duktapeDebugger = NULL;
	duk_size_t promiseLen, duktapeDebuggerLen;
	ILibDuktape_Debugger *retVal = NULL;

	if (ILibDuktape_ScriptContainer_DebuggingOK(ctx) != 0)
	{
		// Check to made sure we have the debugger dependencies
		int argTop = duk_get_top(ctx);
		if (duk_peval_string(ctx, "getJSModule('promise');") == 0 && duk_peval_string(ctx, "getJSModule('duktape-debugger');") == 0)
		{
			promise = (char*)duk_to_lstring(ctx, -2, &promiseLen);
			duktapeDebugger = (char*)duk_to_lstring(ctx, -1, &duktapeDebuggerLen);
		}
		else
		{
			// Missing Dependencies, so cannot continue with setup
			duk_peval_string(ctx, "process.emit('uncaughtException', 'Cannot setup debugger, missing promise and/or duktape-debugger');");
			duk_set_top(ctx, argTop);
			return(NULL);
		}

		// Setup WebEngine
		DebugWebEngine_Chain = ILibCreateChain();
		DebugWebEngine_Context = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(SCRIPT_ENGINE_NO_DEBUGGER | SCRIPT_ENGINE_NO_MESH_AGENT_ACCESS | SCRIPT_ENGINE_NO_GENERIC_MARSHAL_ACCESS | SCRIPT_ENGINE_NO_PROCESS_SPAWNING, 0, DebugWebEngine_Chain, NULL, NULL, NULL, NULL, NULL, NULL);
		ILibChain_OnDestroyEvent_AddHandler(Duktape_GetChain(ctx), ILibDuktape_Debugger_Destroy, NULL);

		ILibDuktape_ModSearch_AddModule(DebugWebEngine_Context, "promise", promise, (int)promiseLen);
		ILibDuktape_ModSearch_AddModule(DebugWebEngine_Context, "duktape-debugger", duktapeDebugger, (int)duktapeDebuggerLen);

		duk_push_heap_stash(ctx);
		char *src = Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_Debugger_SCRIPT_SOURCE, NULL);
		char *srcPath = Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_Debugger_SCRIPT_PATH, NULL);
		duk_pop(ctx);

		if (src != NULL)
		{
			if (srcPath == NULL)
			{
				duk_push_global_object(ctx); 										// [g]
				duk_get_prop_string(ctx, -1, "process");							// [g][process]
				duk_get_prop_string(ctx, -1, "argv0");								// [g][process][argv0]
				srcPath = (char*)duk_get_string(ctx, -1);
				duk_pop_n(ctx, 3);													// ...
			}
			duk_push_global_object(DebugWebEngine_Context);						// [g]
			duk_push_string(DebugWebEngine_Context, src);						// [g][str]
			duk_get_prop_string(DebugWebEngine_Context, -1, "split");			// [g][str][split]
			duk_swap_top(DebugWebEngine_Context, -2);							// [g][split][this]
			duk_push_string(DebugWebEngine_Context, "\n");						// [g][split][this][\n]
			duk_pcall_method(DebugWebEngine_Context, 1);						// [g][tokens]
			duk_put_prop_string(DebugWebEngine_Context, -2, "_scriptTokens");	// [g]
			duk_push_string(DebugWebEngine_Context, srcPath);					// [g][path]
			duk_put_prop_string(DebugWebEngine_Context, -2, "_scriptPath");		// [g]
			duk_pop(DebugWebEngine_Context);									// ...
		}

		duk_push_heap_stash(ctx);																		// [stash]
		retVal = (ILibDuktape_Debugger*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_Debugger));			// [stash][dbgobj]
		duk_put_prop_string(ctx, -2, ILibDuktape_Debugger_DebugObject);									// [stash]
		duk_pop(ctx);																					// ...

		duk_push_global_object(DebugWebEngine_Context);													// [g]
		duk_push_c_function(DebugWebEngine_Context, ILibDuktape_Debugger_StartEngine_UpdatePort, 1);	// [g][func]
		duk_push_pointer(DebugWebEngine_Context, retVal);												// [g][func][ptr]
		duk_put_prop_string(DebugWebEngine_Context, -2, ILibDuktape_Debugger_DebugObject);				// [g][func]
		duk_put_prop_string(DebugWebEngine_Context, -2, "updateWebPort");								// [g]

		duk_push_c_function(DebugWebEngine_Context, ILibDuktape_Debugger_hostCooperate, 0);				// [g][func]
		duk_push_pointer(DebugWebEngine_Context, retVal);												// [g][func][ptr]
		duk_put_prop_string(DebugWebEngine_Context, -2, ILibDuktape_Debugger_DebugObject);				// [g][func]
		duk_push_pointer(DebugWebEngine_Context, Duktape_GetChain(ctx));								// [g][func][ptr]
		duk_put_prop_string(DebugWebEngine_Context, -2, ILibDuktape_Debugger_HostChain);				// [g][func]
		duk_put_prop_string(DebugWebEngine_Context, -2, "hostCooperate");								// [g]

		duk_push_c_function(DebugWebEngine_Context, ILibDuktape_Debugger_hostGC, 0);					// [g][func]
		duk_push_pointer(DebugWebEngine_Context, retVal);												// [g][func][ptr]
		duk_put_prop_string(DebugWebEngine_Context, -2, ILibDuktape_Debugger_DebugObject);				// [g][func]
		duk_push_pointer(DebugWebEngine_Context, Duktape_GetChain(ctx));								// [g][func][ptr]
		duk_put_prop_string(DebugWebEngine_Context, -2, ILibDuktape_Debugger_HostChain);				// [g][func]
		duk_put_prop_string(DebugWebEngine_Context, -2, "hostGC");										// [g]


		duk_push_c_function(DebugWebEngine_Context, ILibDuktape_Debugger_detachCleanup, 0);				// [g][func]
		duk_push_pointer(DebugWebEngine_Context, retVal);												// [g][func][ptr]
		duk_put_prop_string(DebugWebEngine_Context, -2, ILibDuktape_Debugger_DebugObject);				// [g][func]
		duk_push_pointer(DebugWebEngine_Context, Duktape_GetChain(ctx));								// [g][func][ptr]
		duk_put_prop_string(DebugWebEngine_Context, -2, ILibDuktape_Debugger_HostChain);				// [g][func]
		duk_put_prop_string(DebugWebEngine_Context, -2, "detachCleanup");								// [g]


		duk_push_int(DebugWebEngine_Context, transport); 
		duk_put_prop_string(DebugWebEngine_Context, -2, "transport");
		duk_push_int(DebugWebEngine_Context, webport);
		duk_put_prop_string(DebugWebEngine_Context, -2, "webport");
		duk_pop(DebugWebEngine_Context);																// ...

		retVal->ctx = ctx;
		sem_init(&(retVal->hostlock), 0, 0);
		retVal->webport = webport;

		duk_push_global_object(DebugWebEngine_Context);									// *[g]
		duk_push_object(DebugWebEngine_Context);										// *[g][obj]
		char *strkey, *strval;
		duk_double_t nval;

		duk_push_heap_stash(ctx);												// [stash]
		duk_get_prop_string(ctx, -1, ILibDuktape_Debugger_AttachOptions);		// [stash][options]
		duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);						// [stash][options][enum]
		while (duk_next(ctx, -1, 1))											// [stash][options][enum][key][val]
		{																		
			if (duk_is_string(ctx, -2) && duk_is_string(ctx, -1))
			{
				strkey = (char*)duk_get_string(ctx, -2);
				strval = (char*)duk_get_string(ctx, -1);
				duk_push_string(DebugWebEngine_Context, strkey);						// *[g][obj][key]
				duk_push_string(DebugWebEngine_Context, strval);						// *[g][obj][key][val]
				duk_put_prop(DebugWebEngine_Context, -3);								// *[g][obj]
			}
			else if (duk_is_string(ctx, -2) && duk_is_number(ctx, -1))
			{
				strkey = (char*)duk_get_string(ctx, -2);
				nval = duk_get_number(ctx, -1);
				duk_push_string(DebugWebEngine_Context, strkey);						// *[g][obj][key]
				duk_push_number(DebugWebEngine_Context, nval);							// *[g][obj][key][val]
				duk_put_prop(DebugWebEngine_Context, -3);								// *[g][obj]
			}
			duk_pop_2(ctx);														// [stash][options][enum]
		}
		duk_pop_3(ctx);															// ...
		duk_put_prop_string(DebugWebEngine_Context, -2, "attachOptions");				// *[g]
		duk_pop(DebugWebEngine_Context);												// ...

		DebugWebEngine_Thread = ILibSpawnNormalThread(DebugWebEngine_Run, NULL);
	}
	return(retVal);
}
duk_ret_t ILibDuktape_Debugger_JSAttach_promise_wait(duk_context *ctx)
{
	char *eventName = (char*)duk_require_string(ctx, 0);
	if (strcmp(eventName, "settled") != 0) { return(0); }

	duk_push_heap_stash(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_Debugger_DebugObject);
	ILibDuktape_Debugger *dbg = (ILibDuktape_Debugger*)Duktape_GetBuffer(ctx, -1, NULL);
	if (dbg == NULL)
	{
		printf("Error setting up debugger...\n");
	}
	else
	{
		listen(dbg->listener, 1);
		ILibDuktape_Debugger_Socket_waitconn(dbg);
		ILibDuktape_Debugger_StartMemoryReporting(dbg->ctx);
		duk_debugger_attach(dbg->ctx, ILibDuktape_Debugger_ReadCB, ILibDuktape_Debugger_WriteCB, ILibDuktape_Debugger_PeekCB, NULL, NULL, NULL, ILibDuktape_Debugger_DetachCB, (void*)dbg);
	}
	return(0);
}

void ILibDuktape_Debugger_JSAttach_PopulateSource(duk_context *ctx, char *source)
{
	if (source != NULL)
	{
		duk_push_heap_stash(ctx);											// [stash]
		duk_push_string(ctx, source);										// [stash][src]
		duk_put_prop_string(ctx, -2, ILibDuktape_Debugger_SCRIPT_SOURCE);	// [stash]
		duk_pop(ctx);														// ...
	}
	else
	{
		char *script, *scriptPath;
		int scriptLen;

		duk_push_global_object(ctx);										// [g]
		duk_get_prop_string(ctx, -1, "process");							// [g][process]
		duk_get_prop_string(ctx, -1, "argv0");								// [g][process][argv0]
		scriptPath = (char*)duk_to_string(ctx, -1);
		ILibDuktape_ScriptContainer_CheckEmbeddedEx(scriptPath, &script, &scriptLen);
		duk_pop_3(ctx);														// ...

		if (script != NULL)
		{
			duk_push_heap_stash(ctx);											// [stash]
			duk_push_lstring(ctx, script, (duk_size_t)scriptLen);				// [stash][src]
			duk_put_prop_string(ctx, -2, ILibDuktape_Debugger_SCRIPT_SOURCE);	// [stash]
			duk_push_string(ctx, "[embedded].js");
			duk_put_prop_string(ctx, -2, ILibDuktape_Debugger_SCRIPT_PATH);		// [stash]

			duk_pop(ctx);														// ...
			free(script);
		}
		else
		{
			duk_push_global_object(ctx);										// [g]
			duk_get_prop_string(ctx, -1, "process");							// [g][process]
			duk_get_prop_string(ctx, -1, "argv0");								// [g][process][argv0]
			if (duk_get_length(ctx, -1) == 0)
			{
				// JS was not specified on command line
				if (duk_peval_string(ctx, "require('MeshAgent');") == 0)		
				{
					int CoreModuleLen = 0;
					ILibSimpleDataStore *db = (ILibSimpleDataStore*)Duktape_GetPointerProperty(ctx, -1, "\xFF_MasterDB");
					if (db == NULL || (CoreModuleLen = ILibSimpleDataStore_Get(db, "CoreModule", NULL, 0)) <= 4)
					{
						ILibDuktape_Error(ctx, "Could Not retrive CoreModule from MeshAgent"); return;
					}
																				// [g][process][argv0][MeshAgent]
					char* CoreModule = ILibMemory_Allocate(CoreModuleLen, 0, NULL, NULL);
					ILibSimpleDataStore_Get(db, "CoreModule", CoreModule, CoreModuleLen);					
					duk_push_lstring(ctx, CoreModule + 4, CoreModuleLen - 4);	// [g][process][argv0][MeshAgent][CoreModule]
					duk_push_heap_stash(ctx);
					duk_swap_top(ctx, -2);
					duk_put_prop_string(ctx, -2, ILibDuktape_Debugger_SCRIPT_SOURCE);
					duk_push_string(ctx, "CoreModule.js");
					duk_put_prop_string(ctx, -2, ILibDuktape_Debugger_SCRIPT_PATH);
					free(CoreModule);
					return;
				}
				else
				{
					ILibDuktape_Error(ctx, "Unable to retrive running java script"); return;
				}
			}
			else
			{
				duk_eval_string(ctx, "require('fs');");								// [g][process][argv0][fs]
				duk_get_prop_string(ctx, -1, "readFileSync");						// [g][process][argv0][fs][rfs]
				duk_swap_top(ctx, -2);												// [g][process][argv0][rfs][this]
				duk_dup(ctx, -3);													// [g][process][argv0][rfs][this][path]
				duk_call_method(ctx, 1);											// [g][process][argv0][sourceBuffer]
			}
			duk_get_prop_string(ctx, -1, "toString");							// [g][process][argv0][sourceBuffer][toString]
			duk_swap_top(ctx, -2);												// [g][process][argv0][toString][this]
			duk_call_method(ctx, 0);											// [g][process][argv0][sourceBuffer]
			duk_push_heap_stash(ctx);											// [g][process][argv0][source][stash]
			duk_dup(ctx, -2);													// [g][process][argv0][source][stash][source]
			duk_put_prop_string(ctx, -2, ILibDuktape_Debugger_SCRIPT_SOURCE);	// [g][process][argv0][source][stash]
		}
	}
}

duk_ret_t ILibDuktape_Debugger_JSAttach_promise(duk_context *ctx)
{
	int needWait = 0;
#ifndef DUK_USE_DEBUGGER_SUPPORT
	duk_dup(ctx, 1);								// [rejector]
	duk_push_this(ctx);								// [rejector][this]
	duk_push_string(ctx, "No debugger support");	// [rejector][this][err]
	duk_call_method(ctx, 1);						// [ret]
	return(0);
#endif
#ifdef WIN32
	SOCKET listenerSocket;
#else
	int listenerSocket;
#endif
	struct sockaddr_in6 *local_int;
	struct sockaddr_in6 localBounded;
	int localBoundedSize = sizeof(struct sockaddr_in);

	duk_push_heap_stash(ctx);												// [stash]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_Debugger_AttachOptions))
	{
		duk_dup(ctx, 1);													// [stash][rejector]
		duk_push_this(ctx);													// [stash][rejector][this]
		duk_push_string(ctx, "attachDebugger() already called");			// [stash][rejector][this][err]
		duk_call_method(ctx, 1);											// [stash][ret]
		return(0);
	}
	else
	{
		duk_push_current_function(ctx);										// [stash][func]
		duk_get_prop_string(ctx, -1, "options");							// [stash][func][options]
		duk_remove(ctx, -2);												// [stash][options]
		duk_dup(ctx, -1);													// [stash][options][options]
		duk_put_prop_string(ctx, -3, ILibDuktape_Debugger_AttachOptions);	// [stash][options]
		duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, ILibDuktape_Debugger_Options_Resolver);
		duk_dup(ctx, 1); duk_put_prop_string(ctx, -2, ILibDuktape_Debugger_Options_Rejector);
	}

	int transport = Duktape_GetIntPropertyValue(ctx, -1, "transport", 0);
	int webport = Duktape_GetIntPropertyValue(ctx, -1, "webport", 0);
	char *source = Duktape_GetStringPropertyValue(ctx, -1, "source", NULL);

	local_int = Duktape_IPAddress4_FromString("127.0.0.1", transport);
#ifdef WIN32
	if ((listenerSocket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_NO_HANDLE_INHERIT)) == -1) { listenerSocket = (SOCKET)~0; }
#else
	if ((listenerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) { listenerSocket = (SOCKET)~0; }
#endif
	if (listenerSocket == (SOCKET)~0)
	{
		// Error creating socket
		duk_dup(ctx, 1);												// [rejector]
		duk_push_this(ctx);												// [rejector][this]
		duk_push_string(ctx, "Error Creating Debug Transport Socket");	// [rejector][this][err]
		duk_call_method(ctx, 1);
		return(0);
	}
	if (bind(listenerSocket, (struct sockaddr*)local_int, sizeof(struct sockaddr_in)) != 0) { return(ILibDuktape_Error(ctx, "BIND error")); }
#if defined(WINSOCK2)
	getsockname(listenerSocket, (struct sockaddr*)&localBounded, (int*)&localBoundedSize);
#else
	if (getsockname(listenerSocket, (struct sockaddr*)&localBounded, (socklen_t*)&localBoundedSize) != 0)
	{
		localBoundedSize = (int)sizeof(struct sockaddr_in);
		if (getsockname(listenerSocket, (struct sockaddr*)&localBounded, (socklen_t*)&localBoundedSize) != 0)
		{
		}
	}
#endif
	transport = (int)ntohs(localBounded.sin6_port);

	if (Duktape_GetIntPropertyValue(ctx, -1, "wait", 0) == 1)
	{
		needWait = 1;

		// WaitForDebugger... We'll hookup an event hook, so we can be notified when somebody calls 'then'
		duk_push_this(ctx);														// [promise]
		duk_get_prop_string(ctx, -1, "_internal");								// [promise][internal]
		duk_get_prop_string(ctx, -1, "once");									// [promise][internal][once]
		duk_swap_top(ctx, -2);													// [promise][on][this]
		duk_push_string(ctx, "newListener");									// [promise][on][this][newListener]
		duk_push_c_function(ctx, ILibDuktape_Debugger_JSAttach_promise_wait, 2);// [promise][on][this][newListener][func]
		duk_call_method(ctx, 2);
	}

	// Before we do anything, we need to setup the source
	ILibDuktape_Debugger_JSAttach_PopulateSource(ctx, source);

	ILibDuktape_Debugger *dbg;
	if ((dbg = ILibDuktape_Debugger_StartEngine(ctx, transport, webport)) == NULL)
	{
		// error
		duk_dup(ctx, 1);									// [rejector]
		duk_push_this(ctx);									// [rejector][this]
		duk_push_string(ctx, "Error Starting Debug Engine");// [rejector][this][err]
		duk_call_method(ctx, 1);
	}
	else
	{
		// success
		duk_suspend(ctx, &(dbg->hoststate));
		dbg->listener = listenerSocket;
		sem_wait(&(dbg->hostlock));
		sem_destroy(&(dbg->hostlock));
		duk_resume(ctx, &(dbg->hoststate));

		if (needWait == 0)
		{
			listen(dbg->listener, 1);
			ILibDuktape_Debugger_AsyncWaitConn(dbg);
		}

		// Resolve the promise with the bounded WebPort
		duk_dup(ctx, 0);									// [resolver]
		duk_push_this(ctx);									// [resolver][this]
		duk_push_int(ctx, dbg->webport);					// [resolver][this][webport]
		duk_call_method(ctx, 1);
	}

	return(0);
}
duk_ret_t ILibDuktape_Debugger_JSAttach(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	duk_eval_string(ctx, "require('promise');");						// [promisectr]
	duk_push_c_function(ctx, ILibDuktape_Debugger_JSAttach_promise, 2);	// [promisectr][func]
	if (nargs > 0 && duk_is_object(ctx, 0))
	{
		duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, "options");
	}
	else
	{
		duk_push_object(ctx); duk_put_prop_string(ctx, -2, "options");
	}
	duk_new(ctx, 1);													// [promise]
	return(1);
}
void ILibDuktape_Debugger_Init(duk_context *ctx, unsigned short debugPort)
{
	duk_push_global_object(ctx);
	ILibDuktape_CreateInstanceMethod(ctx, "attachDebugger", ILibDuktape_Debugger_JSAttach, DUK_VARARGS);
	duk_pop(ctx);
}
void ILibDuktape_Debugger_SetScriptEx(void *chain, void *user)
{
	if (ILibMemory_CanaryOK(user))
	{
		duk_push_global_object(DebugWebEngine_Context);
		if (!duk_has_prop_string(DebugWebEngine_Context, -1, "_scriptTokens"))
		{
			duk_push_lstring(DebugWebEngine_Context, ILibMemory_Extra(user), ILibMemory_ExtraSize(user));
			duk_put_prop_string(DebugWebEngine_Context, -2, "_scriptPath");
			duk_pop(DebugWebEngine_Context);

			duk_push_lstring(DebugWebEngine_Context, (char*)user, (duk_size_t)ILibMemory_Size(user));	// [str]
			duk_get_prop_string(DebugWebEngine_Context, -1, "split");									// [str][split]
			duk_swap_top(DebugWebEngine_Context, -2);													// [split][this]
			duk_push_string(DebugWebEngine_Context, "\n");												// [split][this][\n]
			if (duk_pcall_method(DebugWebEngine_Context, 1) == 0)
			{																							// [tokens]
				duk_push_global_object(DebugWebEngine_Context);											// [tokens][g]
				duk_swap_top(DebugWebEngine_Context, -2);												// [g][tokens]
				duk_put_prop_string(DebugWebEngine_Context, -2, "_scriptTokens");						// [g]
			}
		}
		duk_pop(DebugWebEngine_Context);
		ILibMemory_Free(user);
	}
}
void ILibDuktape_Debugger_SetScript(char *js, int jsLen, char *fileName, int fileNameLen)
{
	if (DebugWebEngine_Chain != NULL)
	{
		if (fileNameLen <= 0 && fileName != NULL)
		{
			fileNameLen = (int)strnlen_s(fileName, _MAX_PATH);
		}
		char *jsRef = (char*)ILibMemory_SmartAllocateEx(jsLen, fileNameLen);
		memcpy_s(jsRef, jsLen, js, jsLen);
		if (fileNameLen > 0)
		{
			memcpy_s(ILibMemory_Extra(jsRef), ILibMemory_ExtraSize(jsRef), fileName, fileNameLen);
		}
		ILibChain_RunOnMicrostackThreadEx(DebugWebEngine_Chain, ILibDuktape_Debugger_SetScriptEx, jsRef);
	}
}
