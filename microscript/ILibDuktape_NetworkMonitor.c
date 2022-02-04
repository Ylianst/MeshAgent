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

#include "duktape.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktape_Helpers.h"

#include "../microstack/ILibParsers.h"
#include "../microstack/ILibIPAddressMonitor.h"

#define ILibDuktape_NetworkMonitor_PTR			"\xFF_ILibDuktape_NetworkMonitor"

typedef struct ILibDuktape_NetworkMonitor
{
	duk_context *ctx;
	ILibDuktape_EventEmitter *emitter;
	ILibIPAddressMonitor addressMonitor;
	ILibHashtable *addressTable;
}ILibDuktape_NetworkMonitor;


ILibHashtable ILibDuktape_NetworkMonitor_CreateTable(duk_context *ctx)
{
	int i;
	duk_size_t bufferLen;
	char *buffer;

	ILibHashtable retVal = NULL;
	if (duk_peval_string(ctx, "require('os').networkInterfaces();") != 0)
	{
		ILibDuktape_Process_UncaughtExceptionEx(ctx, "NetworkMonitor: ");
		duk_pop(ctx);
	}
	else
	{														// [networkInterfaces]
		retVal = ILibHashtable_Create();
		duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);	// [networkInterfaces][enum]
		while (duk_next(ctx, -1, 1))
		{
			// [networkInterfaces][enum][adapter][array]
			int count = (int)duk_get_length(ctx, -1);
			for (i = 0; i < count; ++i)
			{
				duk_get_prop_index(ctx, -1, i);				// [networkInterfaces][enum][adapter][array][obj]
				if (duk_has_prop_string(ctx, -1, "address") && strcmp(Duktape_GetStringPropertyValue(ctx, -1, "status", "up"), "up") == 0)
				{
					duk_get_prop_string(ctx, -1, "address");// [networkInterfaces][enum][adapter][array][obj][address]
					buffer = (char*)duk_get_lstring(ctx, -1, &bufferLen);
					ILibHashtable_Put(retVal, NULL, buffer, (int)bufferLen, (void*)0x01);
					duk_pop(ctx);							//  [networkInterfaces][enum][adapter][array][obj]
				}
				duk_pop(ctx);								//  [networkInterfaces][enum][adapter][array]
			}
			duk_pop_2(ctx);									//  [networkInterfaces][enum]
		}
		duk_pop_2(ctx);										//  ...
	}
	return(retVal);
}

void ILibDuktape_NetworkMonitor_EventSink_OnEnumerateCurrent(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	duk_context *ctx = (duk_context*)((void**)user)[0];
	char *eventName = (char*)((void**)user)[1];
	void *Self = ((void**)user)[2];
	ILibHashtable other = (ILibHashtable)((void**)user)[3];

	if (ILibHashtable_Get(other, NULL, Key2, Key2Len) == NULL)
	{
		ILibDuktape_EventEmitter_SetupEmit(ctx, Self, eventName);	// [emit][this][eventName]
		duk_push_lstring(ctx, Key2, (duk_size_t)Key2Len);			// [emit][this][eventName][address]
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "NetworkMonitor.OnAdd/Remove(): "); }
		duk_pop(ctx);
	}
}
void ILibDuktape_NetworkMonitor_EventSink(ILibIPAddressMonitor sender, void *user)
{
	ILibDuktape_NetworkMonitor *nm = (ILibDuktape_NetworkMonitor*)user;
		
	ILibDuktape_EventEmitter_SetupEmit(nm->ctx, nm->emitter->object, "change");	// [emit][this][change]
	if (duk_pcall_method(nm->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(nm->ctx, "NetworkMonitor.change(): "); }
	duk_pop(nm->ctx);															// ...
	

	ILibHashtable current = ILibDuktape_NetworkMonitor_CreateTable(nm->ctx);
	ILibHashtable_Enumerate(current, ILibDuktape_NetworkMonitor_EventSink_OnEnumerateCurrent, (void*[]){ nm->ctx, "add", nm->emitter->object, nm->addressTable });
	ILibHashtable_Enumerate(nm->addressTable, ILibDuktape_NetworkMonitor_EventSink_OnEnumerateCurrent, (void*[]) { nm->ctx, "remove", nm->emitter->object, current });


	ILibHashtable_Destroy(nm->addressTable);
	nm->addressTable = current;
}
duk_ret_t ILibDuktape_NetworkMonitor_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, ILibDuktape_NetworkMonitor_PTR);

	ILibDuktape_NetworkMonitor *nm = (ILibDuktape_NetworkMonitor*)Duktape_GetBuffer(ctx, -1, NULL);
	if (nm->addressTable != NULL) { ILibHashtable_Destroy(nm->addressTable); }

	if (ILibIsChainBeingDestroyed(Duktape_GetChain(ctx)) != 0) { return(0); }
	ILibChain_SafeRemoveEx(Duktape_GetChain(ctx), nm->addressMonitor);

	return(0);
}
void ILibDuktape_NetworkMonitor_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_NetworkMonitor));
	ILibDuktape_NetworkMonitor *nm = (ILibDuktape_NetworkMonitor*)Duktape_GetBuffer(ctx, -1, NULL);
	memset(nm, 0, sizeof(ILibDuktape_NetworkMonitor));
	duk_put_prop_string(ctx, -2, ILibDuktape_NetworkMonitor_PTR);

	nm->ctx = ctx;
	nm->emitter = ILibDuktape_EventEmitter_Create(ctx);
	nm->addressMonitor = ILibIPAddressMonitor_Create(chain, ILibDuktape_NetworkMonitor_EventSink, nm);

	ILibDuktape_EventEmitter_CreateEventEx(nm->emitter, "change");
	ILibDuktape_EventEmitter_CreateEventEx(nm->emitter, "add");
	ILibDuktape_EventEmitter_CreateEventEx(nm->emitter, "remove");
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_NetworkMonitor_Finalizer);

	//
	// Get initial list of addresses
	//
	nm->addressTable = ILibDuktape_NetworkMonitor_CreateTable(ctx);
}
void ILibDuktape_NetworkMonitor_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "NetworkMonitor", ILibDuktape_NetworkMonitor_PUSH);
}
