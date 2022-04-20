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


#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "duktape.h"
#include "ILibDuktape_GenericMarshal.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_EventEmitter.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibCrypto.h"
#include "microstack/ILibRemoteLogging.h"

#ifdef _POSIX
#include <pthread.h>
#endif

typedef uintptr_t PTRSIZE;

#ifdef WIN32
#define APICALLTYPE __stdcall

#else
#define APICALLTYPE
#include <dlfcn.h>
#endif

#define ILibDuktape_GenericMarshal_INVALID_PROMISE		((void*)(uintptr_t)0x01)

#define ILibDuktape_GenericMarshal_FuncHandler			"\xFF_GenericMarshal_FuncHandler"
#define ILibDuktape_GenericMarshal_VariableType			"\xFF_GenericMarshal_VarType"
#define ILibDuktape_GenericMarshal_GlobalSet_List		"\xFF_GenericMarshal_GlobalSet_List"
#define ILibDuktape_GenericMarshal_GlobalSet			"\xFF_GenericMarshal_GlobalSet"
#define ILibDuktape_GenericMarshal_GlobalSet_Dispatcher	"\xFF_GenericMArshal_GlobalSet_Dispatcher"
#define ILibDuktape_GenericMarshal_Variable_AutoFree	"\xFF_GenericMarshal_Variable_AutoFree"
#define ILibDuktape_GenericMarshal_Variable_Parms		"\xFF_GenericMarshal_Variable_Parms"
#define ILibDuktape_GenericMarshal_StashTable			"\xFF_GenericMarshal_StashTable"
#define ILibDuktape_GenericMarshal_GlobalCallback_ThreadID "\xFF_GenericMarshal_ThreadID"
#define ILibDutkape_GenericMarshal_INTERNAL				"\xFF_INTERNAL"
#define ILibDutkape_GenericMarshal_INTERNAL_X			"\xFF_INTERNAL_X"
#define ILibDuktape_GenericMarshal_Variable_EnableAutoFree(ctx, idx) duk_dup(ctx, idx);duk_push_true(ctx);duk_put_prop_string(ctx, -2, ILibDuktape_GenericMarshal_Variable_AutoFree);duk_pop(ctx)
#define ILibDuktape_GenericMarshal_Variable_DisableAutoFree(ctx, idx) duk_dup(ctx, idx);duk_push_false(ctx);duk_put_prop_string(ctx, -2, ILibDuktape_GenericMarshal_Variable_AutoFree);duk_pop(ctx)
#define WAITING_FOR_RESULT__DISPATCHER					2
#define ILibDuktape_GenericMarshal_MethodInvoke_Native(parms, fptr, vars) ILibDuktape_GenericMarshal_MethodInvoke_NativeEx(parms, fptr, vars, ILibDuktape_GenericMarshal_CallTypes_DEFAULT)
void ILibDuktape_GenericMarshal_Variable_PUSH(duk_context *ctx, void *ptr, int size);

typedef PTRSIZE(APICALLTYPE *R0)();
typedef PTRSIZE(APICALLTYPE *R1)(PTRSIZE V1);
typedef PTRSIZE(APICALLTYPE *R2)(PTRSIZE V1, PTRSIZE V2);
typedef PTRSIZE(APICALLTYPE *R3)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3);
typedef PTRSIZE(APICALLTYPE *R4)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4);
typedef PTRSIZE(APICALLTYPE *R5)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5);
typedef PTRSIZE(APICALLTYPE *R6)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6);
typedef PTRSIZE(APICALLTYPE *R7)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7);
typedef PTRSIZE(APICALLTYPE *R8)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8);
typedef PTRSIZE(APICALLTYPE *R9)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8, PTRSIZE V9);
typedef PTRSIZE(APICALLTYPE *R10)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8, PTRSIZE V9, PTRSIZE V10);
typedef PTRSIZE(APICALLTYPE *R11)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8, PTRSIZE V9, PTRSIZE V10, PTRSIZE V11);
typedef PTRSIZE(APICALLTYPE *R12)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8, PTRSIZE V9, PTRSIZE V10, PTRSIZE V11, PTRSIZE V12);
typedef PTRSIZE(APICALLTYPE *R13)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8, PTRSIZE V9, PTRSIZE V10, PTRSIZE V11, PTRSIZE V12, PTRSIZE V13);
typedef PTRSIZE(APICALLTYPE *R14)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8, PTRSIZE V9, PTRSIZE V10, PTRSIZE V11, PTRSIZE V12, PTRSIZE V13, PTRSIZE V14);
typedef PTRSIZE(APICALLTYPE *R15)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8, PTRSIZE V9, PTRSIZE V10, PTRSIZE V11, PTRSIZE V12, PTRSIZE V13, PTRSIZE V14, PTRSIZE V15);
typedef PTRSIZE(APICALLTYPE *R16)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8, PTRSIZE V9, PTRSIZE V10, PTRSIZE V11, PTRSIZE V12, PTRSIZE V13, PTRSIZE V14, PTRSIZE V15, PTRSIZE V16);
typedef PTRSIZE(APICALLTYPE *R17)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8, PTRSIZE V9, PTRSIZE V10, PTRSIZE V11, PTRSIZE V12, PTRSIZE V13, PTRSIZE V14, PTRSIZE V15, PTRSIZE V16, PTRSIZE V17);
typedef PTRSIZE(APICALLTYPE *R18)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8, PTRSIZE V9, PTRSIZE V10, PTRSIZE V11, PTRSIZE V12, PTRSIZE V13, PTRSIZE V14, PTRSIZE V15, PTRSIZE V16, PTRSIZE V17, PTRSIZE V18);
typedef PTRSIZE(APICALLTYPE *R19)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8, PTRSIZE V9, PTRSIZE V10, PTRSIZE V11, PTRSIZE V12, PTRSIZE V13, PTRSIZE V14, PTRSIZE V15, PTRSIZE V16, PTRSIZE V17, PTRSIZE V18, PTRSIZE V19);
typedef PTRSIZE(APICALLTYPE *R20)(PTRSIZE V1, PTRSIZE V2, PTRSIZE V3, PTRSIZE V4, PTRSIZE V5, PTRSIZE V6, PTRSIZE V7, PTRSIZE V8, PTRSIZE V9, PTRSIZE V10, PTRSIZE V11, PTRSIZE V12, PTRSIZE V13, PTRSIZE V14, PTRSIZE V15, PTRSIZE V16, PTRSIZE V17, PTRSIZE V18, PTRSIZE V19, PTRSIZE V20);

#ifdef WIN32
typedef PTRSIZE(APICALLTYPE *C2)(PTRSIZE V1, VARIANT V2);
typedef PTRSIZE(APICALLTYPE *C3)(PTRSIZE V1, VARIANT V2, VARIANT V3);
typedef PTRSIZE(APICALLTYPE *C4)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4);
typedef PTRSIZE(APICALLTYPE *C5)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5);
typedef PTRSIZE(APICALLTYPE *C6)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6);
typedef PTRSIZE(APICALLTYPE *C7)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7);
typedef PTRSIZE(APICALLTYPE *C8)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8);
typedef PTRSIZE(APICALLTYPE *C9)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8, VARIANT V9);
typedef PTRSIZE(APICALLTYPE *C10)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8, VARIANT V9, VARIANT V10);
typedef PTRSIZE(APICALLTYPE *C11)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8, VARIANT V9, VARIANT V10, VARIANT V11);
typedef PTRSIZE(APICALLTYPE *C12)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8, VARIANT V9, VARIANT V10, VARIANT V11, VARIANT V12);
typedef PTRSIZE(APICALLTYPE *C13)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8, VARIANT V9, VARIANT V10, VARIANT V11, VARIANT V12, VARIANT V13);
typedef PTRSIZE(APICALLTYPE *C14)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8, VARIANT V9, VARIANT V10, VARIANT V11, VARIANT V12, VARIANT V13, VARIANT V14);
typedef PTRSIZE(APICALLTYPE *C15)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8, VARIANT V9, VARIANT V10, VARIANT V11, VARIANT V12, VARIANT V13, VARIANT V14, VARIANT V15);
typedef PTRSIZE(APICALLTYPE *C16)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8, VARIANT V9, VARIANT V10, VARIANT V11, VARIANT V12, VARIANT V13, VARIANT V14, VARIANT V15, VARIANT V16);
typedef PTRSIZE(APICALLTYPE *C17)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8, VARIANT V9, VARIANT V10, VARIANT V11, VARIANT V12, VARIANT V13, VARIANT V14, VARIANT V15, VARIANT V16, VARIANT V17);
typedef PTRSIZE(APICALLTYPE *C18)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8, VARIANT V9, VARIANT V10, VARIANT V11, VARIANT V12, VARIANT V13, VARIANT V14, VARIANT V15, VARIANT V16, VARIANT V17, VARIANT V18);
typedef PTRSIZE(APICALLTYPE *C19)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8, VARIANT V9, VARIANT V10, VARIANT V11, VARIANT V12, VARIANT V13, VARIANT V14, VARIANT V15, VARIANT V16, VARIANT V17, VARIANT V18, VARIANT V19);
typedef PTRSIZE(APICALLTYPE *C20)(PTRSIZE V1, VARIANT V2, VARIANT V3, VARIANT V4, VARIANT V5, VARIANT V6, VARIANT V7, VARIANT V8, VARIANT V9, VARIANT V10, VARIANT V11, VARIANT V12, VARIANT V13, VARIANT V14, VARIANT V15, VARIANT V16, VARIANT V17, VARIANT V18, VARIANT V19, VARIANT V20);

typedef uintptr_t(__stdcall *Z1)(uintptr_t V1, uintptr_t V2, uintptr_t V3, uintptr_t V4, VARIANT V5, VARIANT V6, uintptr_t V7, VARIANT V8, uintptr_t V9);
typedef uintptr_t(__stdcall *Z2)(uintptr_t V1, VARIANT V2, uintptr_t V3);

#endif

#define ILibDuktape_GenericMarshal_CUSTOM_HANDLER 0x80000000
#define ILibDuktape_GenericMarshal_CUSTOM_HANDLER_VERIFY 0x40000000
#define ILibDuktape_GenericMarshal_CUSTOM_HANDLER_MASK 0x3FFFFFFF
ILibHashtable marshal_data = NULL;

uintptr_t ILibDuktape_GenericMarshal_MethodInvoke_CustomEx(int parms, void *fptr, uintptr_t *vars, int check, int index)
{
	uintptr_t retVal = 0;

	switch (index)
	{
#ifdef WIN32
		case 1:
			if (parms == 9)
			{
				if (check) { return(1); }
				retVal = ((Z1)fptr)(vars[0], vars[1], vars[2], vars[3], ((VARIANT*)vars[4])[0], ((VARIANT*)vars[5])[0], vars[6], ((VARIANT*)vars[7])[0], vars[8]);
			}
		case 2:
			if (parms == 3)
			{
				if (check) { return(1); }
				retVal = ((Z2)fptr)(vars[0], ((VARIANT*)vars[1])[0], vars[2]);
			}
			break;
#endif
		default:
			retVal = 0;
			break;
	}

	return(retVal);
}


ILibDuktape_EventEmitter *GenericMarshal_CustomEventHandler_Events[255] = { 0 };
void ILibDuktape_GenericMarshal_GetGlobalGenericCallbackEx_CustomHandler_Setup(duk_context *ctx, void *func, uint32_t index)
{
	if (index < 0 || index >((sizeof(GenericMarshal_CustomEventHandler_Events) / sizeof(uintptr_t)) - 1))
	{
		ILibDuktape_Error(ctx, "Custom Event Index out of range");
		return;
	}

	ILibDuktape_GenericMarshal_Variable_PUSH(ctx, func, sizeof(uintptr_t));
	ILibDuktape_GenericMarshal_Variable_DisableAutoFree(ctx, -1);
	ILibDuktape_EventEmitter_CreateEventEx(ILibDuktape_EventEmitter_Create(ctx), "GlobalCallback");
	GenericMarshal_CustomEventHandler_Events[index] = ILibDuktape_EventEmitter_GetEmitter(ctx, -1);
	duk_push_uint(ctx, index);
	duk_put_prop_string(ctx, -2, ILibDutkape_GenericMarshal_INTERNAL_X);
}

uintptr_t GenericMarshal_CustomEventHandler_DispatchEx(ILibDuktape_EventEmitter *e, uintptr_t *args, size_t argsLen)
{
	duk_context *ctx = e->ctx;
	uintptr_t ret = 0;
	size_t i;
	ILibDuktape_EventEmitter_SetupEmit(e->ctx, e->object, "GlobalCallback");					// [emit][this][Name]
	for (i = 0; i < argsLen; ++i)
	{
		ILibDuktape_GenericMarshal_Variable_PUSH(e->ctx, (void*)args[i], sizeof(uintptr_t));	// [emit][this][Name][...]
		ILibDuktape_GenericMarshal_Variable_DisableAutoFree(e->ctx, -1);
	}
	if (duk_pcall_method(e->ctx, (duk_idx_t)argsLen + 1) == 0)
	{
		if (ILibMemory_CanaryOK(e))
		{
			if (e->lastReturnValue != NULL)
			{
				duk_push_heapptr(e->ctx, e->lastReturnValue);
				ret = (uintptr_t)Duktape_GetPointerProperty(ctx, -1, "_ptr");
				duk_pop(ctx);
			}
		}
	}
	duk_pop(ctx);
	return(ret);
}

typedef struct GenericMarshal_CustomEventHandler_Dispatch_Data
{
	ILibDuktape_EventEmitter *emitter;
	uintptr_t *args;
	size_t argsLen;
	uintptr_t ret;
	sem_t waiter;
}GenericMarshal_CustomEventHandler_Dispatch_Data;

void GenericMarshal_CustomEventHandler_Dispatch_Chain(void *chain, void *user)
{
	GenericMarshal_CustomEventHandler_Dispatch_Data *data = (GenericMarshal_CustomEventHandler_Dispatch_Data*)user;
	duk_push_heapptr(data->emitter->ctx, data->emitter->object);		// [obj]
	duk_push_true(data->emitter->ctx);									// [obj][true]
	duk_put_prop_string(data->emitter->ctx, -2, "callbackDispatched");	// [obj]
	data->ret = GenericMarshal_CustomEventHandler_DispatchEx(data->emitter, data->args, data->argsLen);
	duk_del_prop_string(data->emitter->ctx, -1, "callbackDispatched");
	sem_post(&(data->waiter));
}
uintptr_t GenericMarshal_CustomEventHandler_Dispatch2(ILibDuktape_EventEmitter *emitter, uintptr_t *args, size_t argsLen)
{
	uintptr_t ret = 0;
	if (emitter != NULL && ILibMemory_CanaryOK(emitter))
	{
		int dispatch = ILibIsRunningOnChainThread(duk_ctx_chain(emitter->ctx)) == 0;
		GenericMarshal_CustomEventHandler_Dispatch_Data user = { 0 };

		if (dispatch)
		{
			user.args = args;
			user.argsLen = argsLen;
			user.emitter = emitter;
			sem_init(&(user.waiter), 0, 0);
			ILibChain_RunOnMicrostackThread(duk_ctx_chain(emitter->ctx), GenericMarshal_CustomEventHandler_Dispatch_Chain, &user);
			sem_wait(&(user.waiter));
			sem_destroy(&(user.waiter));
			ret = user.ret;
		}
		else
		{
			ret = GenericMarshal_CustomEventHandler_DispatchEx(emitter, args, argsLen);
		}
	}
	return(ret);
}
uintptr_t GenericMarshal_CustomEventHandler_Dispatch(uintptr_t *args, size_t argsLen, uint32_t index)
{
	ILibDuktape_EventEmitter *emitter = GenericMarshal_CustomEventHandler_Events[index];
	return(GenericMarshal_CustomEventHandler_Dispatch2(emitter, args, argsLen));
}

#ifdef WIN32
uintptr_t __stdcall GenericMarshal_CustomEventHandler_10(uintptr_t var1, uintptr_t var2, uintptr_t var3)
{
	uintptr_t args[] = { var1, var2, var3 };
	return(GenericMarshal_CustomEventHandler_Dispatch(args, sizeof(args) / sizeof(uintptr_t), 10));
}
uintptr_t __stdcall GenericMarshal_CustomEventHandler_11(uintptr_t var1)
{
	uintptr_t args[] = { var1 };
	return(GenericMarshal_CustomEventHandler_Dispatch(args, sizeof(args) / sizeof(uintptr_t), 11));
}
uintptr_t __stdcall GenericMarshal_CustomEventHandler_12(uintptr_t var1)
{
	uintptr_t args[] = { var1 };
	return(GenericMarshal_CustomEventHandler_Dispatch(args, sizeof(args) / sizeof(uintptr_t), 12));
}
uintptr_t __stdcall GenericMarshal_CustomEventHandler_13(uintptr_t var1, uintptr_t var2, uintptr_t var3)
{
	uintptr_t args[] = { var1, var2, var3 };
	return(GenericMarshal_CustomEventHandler_Dispatch(args, sizeof(args) / sizeof(uintptr_t), 13));
}
uintptr_t __stdcall GenericMarshal_CustomEventHandler_14(uintptr_t var1, uintptr_t var2, uintptr_t var3, uintptr_t var4, uintptr_t var5)
{
	uintptr_t args[] = { var1, var2, var3, var4, var5 };
	return(GenericMarshal_CustomEventHandler_Dispatch(args, sizeof(args) / sizeof(uintptr_t), 14));
}
uintptr_t __stdcall GenericMarshal_CustomEventHandler_55(uintptr_t var1, uintptr_t var2, uintptr_t var3, uintptr_t var4)
{
	uintptr_t args[] = { var1, var2, var3, var4 };
	uintptr_t ret = 0;
	
	void **val;

	if (marshal_data != NULL)
	{
		ILibHashtable_Lock(marshal_data);
		val = (void**)ILibHashtable_Get(marshal_data, (void*)var1, NULL, 0);
		ILibHashtable_UnLock(marshal_data);

		if (val != NULL)
		{
			WNDPROC func = (WNDPROC)val[0];
			ret = (uintptr_t)func((HWND)var1, (UINT)var2, (WPARAM)var3, (LPARAM)var4);
			if (val[1] != NULL)
			{
				GenericMarshal_CustomEventHandler_Dispatch2(val[1], args, sizeof(args) / sizeof(uintptr_t));
			}
		}
	}
	return(ret);
}
#endif

void ILibDuktape_GenericMarshal_GetGlobalGenericCallbackEx_CustomHandler(duk_context *ctx, int paramCount, uint32_t index)
{
	int ok = 0;
	switch (index)
	{
#ifdef WIN32
		case 10:
			if (paramCount == 3)
			{
				ok = 1;
				ILibDuktape_GenericMarshal_GetGlobalGenericCallbackEx_CustomHandler_Setup(ctx, GenericMarshal_CustomEventHandler_10, index);
			}
			break;
		case 11:
			if (paramCount == 1)
			{
				ok = 1;
				ILibDuktape_GenericMarshal_GetGlobalGenericCallbackEx_CustomHandler_Setup(ctx, GenericMarshal_CustomEventHandler_11, index);
			}
			break;
		case 12:
			if (paramCount == 1)
			{
				ok = 1;
				ILibDuktape_GenericMarshal_GetGlobalGenericCallbackEx_CustomHandler_Setup(ctx, GenericMarshal_CustomEventHandler_12, index);
			}
			break;
		case 13:
			if (paramCount == 3)
			{
				ok = 1;
				ILibDuktape_GenericMarshal_GetGlobalGenericCallbackEx_CustomHandler_Setup(ctx, GenericMarshal_CustomEventHandler_13, index);
			}
			break;
		case 14:
			if (paramCount == 5)
			{
				ok = 1;
				ILibDuktape_GenericMarshal_GetGlobalGenericCallbackEx_CustomHandler_Setup(ctx, GenericMarshal_CustomEventHandler_14, index);
			}
			break;
		case 55:
			if (paramCount == 4)
			{
				ok = 1;
				ILibDuktape_GenericMarshal_GetGlobalGenericCallbackEx_CustomHandler_Setup(ctx, GenericMarshal_CustomEventHandler_55, index);
			}
			break;
#endif
		default:
			ILibDuktape_Error(ctx, "Undefined Custom Event Handler Index: %u", index);
			break;
	}
	if (ok == 0)
	{
		ILibDuktape_Error(ctx, "Invalid Parameter count: %d for Custom Event Handler Index: %u", paramCount, index);
	}
}

ILibLinkedList GlobalCallbackList = NULL;

typedef struct Duktape_GenericMarshal_Proxy
{
	duk_context *ctx;
	void *jsCallbackPtr;
	void *jsProxyObject;
}Duktape_GenericMarshal_Proxy;

#ifdef WIN32
typedef struct Duktape_GlobalGeneric_DispatcherData
{
	DWORD finished;
	HANDLE WorkerThreadHandle;
	void *promise;
	void *retValue;
}Duktape_GlobalGeneric_DispatcherData;
#endif

typedef struct Duktape_GlobalGeneric_Data
{
	ILibDuktape_EventEmitter *emitter;
	uintptr_t ctxnonce;
	void *retVal;
	void *chain;
	sem_t contextWaiter;
#ifdef WIN32
	DWORD callingThread;
	Duktape_GlobalGeneric_DispatcherData *dispatch;
#else
	pthread_t callingThread;
#endif
	int numArgs;
	PTRSIZE args[];
}Duktape_GlobalGeneric_Data;
typedef struct Duktape_MarshalledObject
{
	duk_context *ctx;
	void *heapptr;
}Duktape_MarshalledObject;


duk_ret_t ILibDuktape_GenericMarshal_Variable_Val_STRING(duk_context *ctx)
{
	void *ptr;
	//int size;
	
	duk_push_this(ctx);							// [var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [var][ptr]
	ptr = duk_to_pointer(ctx, -1);
	//duk_get_prop_string(ctx, -2, "_size");		// [var][ptr][size]
	//size = duk_to_int(ctx, -1);

	duk_push_string(ctx, (char*)ptr);

	return 1;
}
duk_ret_t ILibDuktape_GenericMarshal_Variable_Val_HSTRING(duk_context *ctx)
{
	void *ptr;
	int size;
	char hexString[600];

	duk_push_this(ctx);							// [var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [var][ptr]
	ptr = duk_to_pointer(ctx, -1);
	duk_get_prop_string(ctx, -2, "_size");		// [var][ptr][size]
	size = duk_to_int(ctx, -1);

	util_tohex((char*)ptr, size < 255 ? size : 254, hexString);

	duk_push_string(ctx, (char*)hexString);
	return 1;
}
duk_ret_t ILibDuktape_GenericMarshal_Variable_Val_HSTRING2(duk_context *ctx)
{
	void *ptr;
	int size;
	char hexString[3*255];

	duk_push_this(ctx);							// [var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [var][ptr]
	ptr = duk_to_pointer(ctx, -1);
	duk_get_prop_string(ctx, -2, "_size");		// [var][ptr][size]
	size = duk_to_int(ctx, -1);

	util_tohex2((char*)ptr, size < 255 ? size : 254, hexString);

	duk_push_string(ctx, (char*)hexString);
	return 1;
}

duk_ret_t ILibDuktape_GenericMarshal_Variable_Val_UTFSTRING(duk_context *ctx)
{
	void *ptr;
	int size;


	duk_push_this(ctx);							// [var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [var][ptr]
	ptr = duk_to_pointer(ctx, -1);
	duk_get_prop_string(ctx, -2, "_size");		// [var][ptr][size]
	size = duk_to_int(ctx, -1);

	ILibDuktape_String_PushWideString(ctx, ptr, size == 0 ? -1 : size/2);
	return 1;
}

duk_ret_t ILibDuktape_GenericMarshal_Variable_Val_GET(duk_context *ctx)
{
	void *ptr;

	duk_push_this(ctx);							// [var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [var][ptr]
	ptr = duk_to_pointer(ctx, -1);
	
	duk_push_int(ctx, (int)(PTRSIZE)ptr);

	return 1;
}

duk_ret_t ILibDuktape_GenericMarshal_Variable_Val_SET(duk_context *ctx)
{
	void *ptr;
	int size;

	duk_push_this(ctx);							// [var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [var][ptr]
	ptr = duk_to_pointer(ctx, -1);
	duk_get_prop_string(ctx, -2, "_size");		// [var][ptr][size]
	size = duk_to_int(ctx, -1);

	if (duk_is_number(ctx, 0))
	{
		switch (size)
		{
		case 2:
			((unsigned short*)ptr)[0] = (unsigned short)duk_require_int(ctx, 0);
			break;
		case 4:
			((unsigned int*)ptr)[0] = (unsigned int)duk_require_int(ctx, 0);
			break;
		default:
			return(ILibDuktape_Error(ctx, "Unsupported VAL size, with integral type"));
		}
	}
	else if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, ILibDuktape_GenericMarshal_VariableType))
	{
		((void**)ptr)[0] = Duktape_GetPointerProperty(ctx, 0, "_ptr");
		duk_push_this(ctx);		// [var]
		duk_dup(ctx, 0);		// [var][var]
		duk_put_prop_string(ctx, -2, "\xFF_ref");
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Invalid Parameter"));
	}
	return 0;
}

duk_ret_t ILibDuktape_GenericMarshal_Variable_Deref(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *ptr;
	//int size;

	duk_push_this(ctx);							// [var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [var][ptr]
	ptr = (char*)duk_to_pointer(ctx, -1);
	//duk_get_prop_string(ctx, -2, "_size");		// [var][ptr][size]
	//size = duk_to_int(ctx, -1);

	if (nargs < 2)
	{
		// Just Dereference Memory
		ILibDuktape_GenericMarshal_Variable_PUSH(ctx, ((void**)ptr)[0], nargs == 1 ? duk_require_int(ctx, 0) : 0);
	}
	else
	{
		ILibDuktape_GenericMarshal_Variable_PUSH(ctx, (void*)(ptr + duk_require_int(ctx, 0)), duk_require_int(ctx, 1));
	}

	// We need to add a reference to the root variable, for memory management purposes
	duk_push_this(ctx);							// [deref][parent]
	if (duk_has_prop_string(ctx, -1, "_root"))
	{
		// Parent Var is not the root, but has a reference to it
		duk_get_prop_string(ctx, -1, "_root");	// [deref][parent][root]
		duk_put_prop_string(ctx, -3, "_root");	// [deref][parent]
		duk_pop(ctx);							// [deref]
	}
	else
	{
		// Parent Var is the root
		duk_put_prop_string(ctx, -2, "_root");	// [deref]
	}

	return 1;
}

duk_ret_t ILibDuktape_GenericMarshal_Variable_GetEx(duk_context *ctx)
{
	int varSize = 0;
	void *ptr;

	duk_push_current_function(ctx);				// [func]
	duk_get_prop_string(ctx, -1, "_VarSize");	// [func][varSize]
	varSize = duk_to_int(ctx, -1);

	duk_push_this(ctx);							// [func][varSize][var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [func][varSize][var][ptr]
	ptr = duk_to_pointer(ctx, -1);

	switch (varSize)
	{
	case 2:
		duk_push_int(ctx, (int)((unsigned short*)ptr)[0]);
		break;
	case 4:
		duk_push_int(ctx, (int)((unsigned int*)ptr)[0]);
		break;
	default:
		return(ILibDuktape_Error(ctx, "Invalid Variable"));
	}
	return 1;
}
duk_ret_t ILibDuktape_GenericMarshal_Variable_SetEx(duk_context *ctx)
{
	int varSize = 0;
	void *ptr;
	int newVal = duk_require_int(ctx, 0);

	duk_push_current_function(ctx);				// [func]
	duk_get_prop_string(ctx, -1, "_VarSize");	// [func][varSize]
	varSize = duk_to_int(ctx, -1);

	duk_push_this(ctx);							// [func][varSize][var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [func][varSize][var][ptr]
	ptr = duk_to_pointer(ctx, -1);

	switch (varSize)
	{
	case 2:
		((unsigned short*)ptr)[0] = (unsigned short)newVal;
		break;
	case 4:
		((unsigned int*)ptr)[0] = (unsigned int)newVal;
		break;
	default:
		return(ILibDuktape_Error(ctx, "Invalid Variable"));
	}
	return 0;
}
duk_ret_t ILibDuktape_GenericMarshal_Variable_toBuffer(duk_context *ctx)
{
	duk_push_this(ctx);						// [variable]

	void *buffer = Duktape_GetPointerProperty(ctx, -1, "_ptr");
	int bufferLen = Duktape_GetIntPropertyValue(ctx, -1, "_size", 0);

	duk_push_external_buffer(ctx);								// [variable][ext]
	duk_config_buffer(ctx, -1, buffer, (duk_size_t)bufferLen);
	duk_push_buffer_object(ctx, -1, 0, (duk_size_t)bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_Variable_Finalizer(duk_context *ctx)
{
	void *ptr = NULL;
	if (duk_has_prop_string(ctx, 0, "_ptr") && Duktape_GetBooleanProperty(ctx, 0, ILibDuktape_GenericMarshal_Variable_AutoFree, 0))
	{
		duk_get_prop_string(ctx, 0, "_ptr");
		ptr = duk_to_pointer(ctx, -1);
		if (ptr != NULL)
		{
			free(ptr);
			duk_del_prop_string(ctx, 0, "_ptr");
		}
	}

	return 0;
}
duk_ret_t ILibDuktape_GenericMarshal_Variable_autoFree(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	duk_push_this(ctx);																// [variable]
	if (nargs > 0 && !duk_require_boolean(ctx, 0))
	{
		ILibDuktape_GenericMarshal_Variable_DisableAutoFree(ctx, -1);
	}
	else
	{
		ILibDuktape_GenericMarshal_Variable_EnableAutoFree(ctx, -1);
	}
	return(0);
}
duk_ret_t ILibDuktape_GenericMarshal_Variable_pointerBuffer(duk_context *ctx)
{
	duk_push_this(ctx);							// [var]
	void *ptr = Duktape_GetPointerProperty(ctx, -1, "_ptr");
	duk_push_fixed_buffer(ctx, sizeof(void*));
	duk_push_buffer_object(ctx, -1, 0, sizeof(void*), DUK_BUFOBJ_NODEJS_BUFFER);
	if (ptr != NULL)
	{
		memcpy_s(Duktape_GetBuffer(ctx, -2, NULL), sizeof(void*), (void*)&ptr, sizeof(void*));
	}
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_Variable_pointerpointer(duk_context *ctx)
{
	duk_push_this(ctx);																// [var]
	void *ptr = Duktape_GetPointerProperty(ctx, -1, "_ptr");
	duk_push_fixed_buffer(ctx, sizeof(void*));										// [var][ptrptr]
	void **ptrptr = (void**)Duktape_GetBuffer(ctx, -1, NULL);
	ptrptr[0] = ptr;

	ILibDuktape_GenericMarshal_Variable_PUSH(ctx, ptrptr, (int)sizeof(void*));		// [var][ptrptr][var2]
	ILibDuktape_GenericMarshal_Variable_DisableAutoFree(ctx, -1);
	duk_swap_top(ctx, -2);															// [var][var2][ptrptr]
	duk_put_prop_string(ctx, -2, "_ptrptr");										// [var][var2]
	return(1);
}
#ifndef MICROSTACK_NOTLS
duk_ret_t ILibDuktape_GenericMarshal_Variable_bignum_GET(duk_context *ctx)
{
	int16_t test = 0x0001;
	int LE = ((char*)&test)[0] ? 1 : 0;

	duk_push_this(ctx);														// [var]
	void *ptr = Duktape_GetPointerProperty(ctx, -1, "_ptr");
	uint64_t v = (uint64_t)(uintptr_t)ptr;
	duk_eval_string(ctx, "require('bignum')");								// [var][bignum]
	duk_prepare_method_call(ctx, -1, "fromBuffer");							// [var][bignum][fromBuffer][this]
	duk_push_external_buffer(ctx);											// [var][bignum][fromBuffer][this][buffer]
	duk_config_buffer(ctx, -1, &v, sizeof(v));
	duk_push_buffer_object(ctx, -1, 0, sizeof(v), DUK_BUFOBJ_NODEJS_BUFFER);// [var][bignum][fromBuffer][this][buffer][nodebuffer]
	duk_remove(ctx, -2);													// [var][bignum][fromBuffer][this][nodeBuffer]
	duk_push_object(ctx);													// [var][bignum][fromBuffer][this][nodeBuffer][options
	duk_push_string(ctx, LE ? "little" : "big");							// [var][bignum][fromBuffer][this][nodeBuffer][options][endian]
	duk_put_prop_string(ctx, -2, "endian");
	duk_call_method(ctx, 2);												// [var][bignum][bignum]
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_Variable_bignum_SET(duk_context *ctx)
{
	duk_prepare_method_call(ctx, 0, "toString");							// [toString][this]
	duk_call_method(ctx, 0);												// [string]
	uint64_t val = (uint64_t)strtoull((char*)duk_to_string(ctx, -1), NULL, 10);

	duk_push_this(ctx);														// [var]
	duk_push_pointer(ctx, (void*)(uintptr_t)val);							// [var][ptr]
	duk_put_prop_string(ctx, -2, "_ptr");									// [var]
	return(0);
}
#endif
duk_ret_t ILibDuktape_GenericMarshal_Variable_Increment(duk_context *ctx)
{
	duk_push_this(ctx);											// [var]
	int isAutoFree = Duktape_GetBooleanProperty(ctx, -1, ILibDuktape_GenericMarshal_Variable_AutoFree, 0);
	ILibDuktape_GenericMarshal_Variable_DisableAutoFree(ctx, -1);
	void *_ptr = Duktape_GetPointerProperty(ctx, -1, "_ptr");
	int offset = duk_require_int(ctx, 0);
	if (duk_is_boolean(ctx, 1) && duk_require_boolean(ctx, 1))
	{
		if (isAutoFree != 0) { free(_ptr); }
		_ptr = (void*)(uintptr_t)duk_require_uint(ctx, 0);
	}
	else
	{
		_ptr = (char*)_ptr + offset;
	}
	duk_push_this(ctx);
	duk_push_pointer(ctx, _ptr);
	duk_put_prop_string(ctx, -2, "_ptr");
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_Variable_debug(duk_context *ctx)
{
	UNREFERENCED_PARAMETER(ctx);
#ifdef WIN32
	duk_push_this(ctx);
	void *ptr = Duktape_GetPointerProperty(ctx, -1, "_ptr");

	UNREFERENCED_PARAMETER(ptr);
#endif
	return(0);
}
void ILibDuktape_GenericMarshal_Variable_PUSH(duk_context *ctx, void *ptr, int size)
{
	duk_push_object(ctx);						// [var]
	ILibDuktape_WriteID(ctx, "_GenericMarshal.Variable");
	duk_push_pointer(ctx, ptr);					// [var][ptr]
	duk_put_prop_string(ctx, -2, "_ptr");		// [var]
	duk_push_int(ctx, size);					// [var][size]
	duk_put_prop_string(ctx, -2, "_size");		// [var]
	duk_push_true(ctx);
	duk_put_prop_string(ctx, -2, ILibDuktape_GenericMarshal_VariableType);

	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "Val", ILibDuktape_GenericMarshal_Variable_Val_GET, ILibDuktape_GenericMarshal_Variable_Val_SET);
#ifndef MICROSTACK_NOTLS
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "bignum", ILibDuktape_GenericMarshal_Variable_bignum_GET, ILibDuktape_GenericMarshal_Variable_bignum_SET);
#endif
	ILibDuktape_CreateInstanceMethod(ctx, "Deref", ILibDuktape_GenericMarshal_Variable_Deref, DUK_VARARGS);
	ILibDuktape_CreateEventWithGetter(ctx, "String", ILibDuktape_GenericMarshal_Variable_Val_STRING);
	ILibDuktape_CreateEventWithGetter(ctx, "AnsiString", ILibDuktape_GenericMarshal_Variable_Val_UTFSTRING);
	ILibDuktape_CreateEventWithGetter(ctx, "Wide2UTF8", ILibDuktape_GenericMarshal_Variable_Val_UTFSTRING);

	ILibDuktape_CreateEventWithGetter(ctx, "HexString", ILibDuktape_GenericMarshal_Variable_Val_HSTRING);
	ILibDuktape_CreateEventWithGetter(ctx, "HexString2", ILibDuktape_GenericMarshal_Variable_Val_HSTRING2);

	ILibDuktape_CreateInstanceMethod(ctx, "toBuffer", ILibDuktape_GenericMarshal_Variable_toBuffer, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "autoFree", ILibDuktape_GenericMarshal_Variable_autoFree, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "pointerBuffer", ILibDuktape_GenericMarshal_Variable_pointerBuffer, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "getPointerPointer", ILibDuktape_GenericMarshal_Variable_pointerpointer, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "increment", ILibDuktape_GenericMarshal_Variable_Increment, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "_debug", ILibDuktape_GenericMarshal_Variable_debug, 0);


	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_GenericMarshal_Variable_Finalizer);
}

duk_ret_t ILibDuktape_GenericMarshal_CreateVariable(duk_context *ctx)
{
	char* ptr;
	int size;
	char *str = NULL;
	duk_size_t strLen;

	if (duk_is_number(ctx, 0))
	{
		size = duk_require_int(ctx, 0);
	}
	else if(duk_is_string(ctx, 0))
	{
		str = Duktape_GetBuffer(ctx, 0, &strLen);
		size = (int)strLen + 1;

		if (duk_is_object(ctx, 1))
		{
			if (Duktape_GetBooleanProperty(ctx, 1, "wide", 0) != 0)
			{
#ifdef WIN32
				wchar_t *wbuffer = (wchar_t*)ILibMemory_AllocateA(((int)strLen * 2) + 2);
				if (MultiByteToWideChar(CP_UTF8, 0, (LPCCH)str, size, wbuffer, (int)strLen + 1) == 0)
				{
					return(ILibDuktape_Error(ctx, "UTF8 Conversion Error"));
				}
				str = (char*)wbuffer;
				size = (int)ILibMemory_AllocateA_Size(str);
				strLen = size - 1;
#else
				return(ILibDuktape_Error(ctx, "Not supported on this platform"));
#endif
			}
		}
	}
	else if (duk_is_buffer_data(ctx, 0))
	{
		ptr = Duktape_GetBuffer(ctx, 0, &strLen);
		ILibDuktape_GenericMarshal_Variable_PUSH(ctx, ptr, (int)strLen);	
		ILibDuktape_GenericMarshal_Variable_DisableAutoFree(ctx, -1);
		duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, "\xFF_DuplicateBuffer");
		return(1);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "_GenericMarshal.CreateVariable(): Invalid Parameter"));
	}
	if (size < 0) { return(ILibDuktape_Error(ctx, "Invalid Size: %d ", size)); }
	ptr = (char*)ILibMemory_Allocate(size, 0, NULL, NULL);
	if (str != NULL)
	{
		memcpy_s(ptr, size, str, strLen);
		ptr[strLen] = 0;
	}
	ILibDuktape_GenericMarshal_Variable_PUSH(ctx, ptr, size);							// [var]
	ILibDuktape_GenericMarshal_Variable_EnableAutoFree(ctx, -1);

	return 1;
}

void ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_0()
{

}
void ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_1(PTRSIZE v1)
{
	Duktape_GenericMarshal_Proxy  *user = (Duktape_GenericMarshal_Proxy*)v1;
	duk_push_heapptr(user->ctx, user->jsCallbackPtr);									// [func]
	duk_push_heapptr(user->ctx, user->jsProxyObject);									// [func][this]
	if (duk_pcall_method(user->ctx, 0) != 0)											// [retVal]
	{
		ILibDuktape_Process_UncaughtException(user->ctx);
	}
	duk_pop(user->ctx);																	// ...
}
void ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_2(PTRSIZE v1, PTRSIZE v2)
{
	Duktape_GenericMarshal_Proxy  *user = (Duktape_GenericMarshal_Proxy*)v2;
	duk_push_heapptr(user->ctx, user->jsCallbackPtr);									// [func]
	duk_push_heapptr(user->ctx, user->jsProxyObject);									// [func][this]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v1, sizeof(PTRSIZE));	// [func][this][v1]
	if(duk_pcall_method(user->ctx, 1)!=0)												// [retVal]
	{
		ILibDuktape_Process_UncaughtException(user->ctx);
	}
	duk_pop(user->ctx);																	// ...
}
void ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_3(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3)
{
	Duktape_GenericMarshal_Proxy  *user = (Duktape_GenericMarshal_Proxy*)v3;
	duk_push_heapptr(user->ctx, user->jsCallbackPtr);									// [func]
	duk_push_heapptr(user->ctx, user->jsProxyObject);									// [func][this]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v1, sizeof(PTRSIZE));	// [func][this][v1]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v2, sizeof(PTRSIZE));	// [func][this][v1][v2]
	if(duk_pcall_method(user->ctx, 2)!=0)												// [retVal]
	{
		ILibDuktape_Process_UncaughtException(user->ctx);
	}
	duk_pop(user->ctx);																	// ...
}
void ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_4(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3, PTRSIZE v4)
{
	Duktape_GenericMarshal_Proxy  *user = (Duktape_GenericMarshal_Proxy*)v4;
	duk_push_heapptr(user->ctx, user->jsCallbackPtr);									// [func]
	duk_push_heapptr(user->ctx, user->jsProxyObject);									// [func][this]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v1, sizeof(PTRSIZE));	// [func][this][v1]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v2, sizeof(PTRSIZE));	// [func][this][v1][v2]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v3, sizeof(PTRSIZE));	// [func][this][v1][v2][v3]
	if(duk_pcall_method(user->ctx, 3)!=0)												// [retVal]
	{
		ILibDuktape_Process_UncaughtException(user->ctx);
	}
	duk_pop(user->ctx);																	// ...
}
void ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_5(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3, PTRSIZE v4, PTRSIZE v5)
{
	Duktape_GenericMarshal_Proxy  *user = (Duktape_GenericMarshal_Proxy*)v5;
	duk_push_heapptr(user->ctx, user->jsCallbackPtr);									// [func]
	duk_push_heapptr(user->ctx, user->jsProxyObject);									// [func][this]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v1, sizeof(PTRSIZE));	// [func][this][v1]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v2, sizeof(PTRSIZE));	// [func][this][v1][v2]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v3, sizeof(PTRSIZE));	// [func][this][v1][v2][v3]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v4, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4]
	if(duk_pcall_method(user->ctx, 4)!=0)												// [retVal]
	{
		ILibDuktape_Process_UncaughtException(user->ctx);
	}
	duk_pop(user->ctx);																	// ...
}
void ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_6(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3, PTRSIZE v4, PTRSIZE v5, PTRSIZE v6)
{
	Duktape_GenericMarshal_Proxy  *user = (Duktape_GenericMarshal_Proxy*)v6;
	duk_push_heapptr(user->ctx, user->jsCallbackPtr);									// [func]
	duk_push_heapptr(user->ctx, user->jsProxyObject);									// [func][this]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v1, sizeof(PTRSIZE));	// [func][this][v1]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v2, sizeof(PTRSIZE));	// [func][this][v1][v2]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v3, sizeof(PTRSIZE));	// [func][this][v1][v2][v3]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v4, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v5, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4][v5]
	if(duk_pcall_method(user->ctx, 5)!=0)												// [retVal]
	{
		ILibDuktape_Process_UncaughtException(user->ctx);
	}
	duk_pop(user->ctx);
}
void ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_7(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3, PTRSIZE v4, PTRSIZE v5, PTRSIZE v6, PTRSIZE v7)
{
	Duktape_GenericMarshal_Proxy  *user = (Duktape_GenericMarshal_Proxy*)v7;
	duk_push_heapptr(user->ctx, user->jsCallbackPtr);									// [func]
	duk_push_heapptr(user->ctx, user->jsProxyObject);									// [func][this]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v1, sizeof(PTRSIZE));	// [func][this][v1]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v2, sizeof(PTRSIZE));	// [func][this][v1][v2]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v3, sizeof(PTRSIZE));	// [func][this][v1][v2][v3]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v4, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v5, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4][v5]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v6, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4][v5][v6]
	if(duk_pcall_method(user->ctx, 6)!=0)												// [retVal]
	{
		ILibDuktape_Process_UncaughtException(user->ctx);
	}
	duk_pop(user->ctx);
}
void ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_8(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3, PTRSIZE v4, PTRSIZE v5, PTRSIZE v6, PTRSIZE v7, PTRSIZE v8)
{
	Duktape_GenericMarshal_Proxy  *user = (Duktape_GenericMarshal_Proxy*)v8;
	duk_push_heapptr(user->ctx, user->jsCallbackPtr);									// [func]
	duk_push_heapptr(user->ctx, user->jsProxyObject);									// [func][this]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v1, sizeof(PTRSIZE));	// [func][this][v1]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v2, sizeof(PTRSIZE));	// [func][this][v1][v2]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v3, sizeof(PTRSIZE));	// [func][this][v1][v2][v3]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v4, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v5, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4][v5]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v6, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4][v5][v6]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v7, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4][v5][v6][v7]
	if(duk_pcall_method(user->ctx, 7)!=0)												// [retVal]
	{
		ILibDuktape_Process_UncaughtException(user->ctx);
	}
	duk_pop(user->ctx);
}
void ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_9(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3, PTRSIZE v4, PTRSIZE v5, PTRSIZE v6, PTRSIZE v7, PTRSIZE v8, PTRSIZE v9)
{
	Duktape_GenericMarshal_Proxy  *user = (Duktape_GenericMarshal_Proxy*)v9;
	duk_push_heapptr(user->ctx, user->jsCallbackPtr);									// [func]
	duk_push_heapptr(user->ctx, user->jsProxyObject);									// [func][this]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v1, sizeof(PTRSIZE));	// [func][this][v1]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v2, sizeof(PTRSIZE));	// [func][this][v1][v2]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v3, sizeof(PTRSIZE));	// [func][this][v1][v2][v3]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v4, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v5, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4][v5]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v6, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4][v5][v6]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v7, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4][v5][v6][v7]
	ILibDuktape_GenericMarshal_Variable_PUSH(user->ctx, (void*)v8, sizeof(PTRSIZE));	// [func][this][v1][v2][v3][v4][v5][v6][v7][v8]
	if(duk_pcall_method(user->ctx, 8)!=0)												// [retVal]
	{
		ILibDuktape_Process_UncaughtException(user->ctx);
	}
	duk_pop(user->ctx);
}

duk_ret_t ILibDuktape_GenericMashal_CallbackProxy_Callback(duk_context *ctx)
{
	int parms;
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "_numParms");
	parms = duk_to_int(ctx, -1);

	switch (parms)
	{
		case 0:
			duk_push_pointer(ctx, (void*)ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_0);
			break;
		case 1:
			duk_push_pointer(ctx, (void*)ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_1);
			break;
		case 2:
			duk_push_pointer(ctx, (void*)ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_2);
			break;
		case 3:
			duk_push_pointer(ctx, (void*)ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_3);
			break;
		case 4:
			duk_push_pointer(ctx, (void*)ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_4);
			break;
		case 5:
			duk_push_pointer(ctx, (void*)ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_5);
			break;
		case 6:
			duk_push_pointer(ctx, (void*)ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_6);
			break;
		case 7:
			duk_push_pointer(ctx, (void*)ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_7);
			break;
		case 8:
			duk_push_pointer(ctx, (void*)ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_8);
			break;
		case 9:
			duk_push_pointer(ctx, (void*)ILibDuktape_GenericMarshal_CallbackProxy_NativeSink_9);
			break;
		default:
			return(ILibDuktape_Error(ctx, "More than 9 parameters in the callback isn't supported yet"));
			break;
	}
	return 1;
}
duk_ret_t ILibDuktape_GenericMashal_CallbackProxy_State(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "_statePtr");
	return 1;
}
duk_ret_t ILibDuktape_GenericMarshal_CreateCallbackProxy(duk_context *ctx)
{
	Duktape_GenericMarshal_Proxy *ptr;

	duk_push_object(ctx);													// [proxy]
	ptr = Duktape_PushBuffer(ctx, sizeof(Duktape_GenericMarshal_Proxy));	// [proxy][buffer]
	duk_put_prop_string(ctx, -2, "_buffer");								// [proxy]

	duk_dup(ctx, 1);														// [proxy][parms]
	duk_put_prop_string(ctx, -2, "_numParms");								// [proxy]

	duk_push_pointer(ctx, ptr);												// [proxy][statePtr]
	duk_put_prop_string(ctx, -2, "_statePtr");								// [proxy]

	ptr->ctx = ctx;
	ptr->jsCallbackPtr = (void*)duk_require_heapptr(ctx, 0);
	ptr->jsProxyObject = (void*)duk_get_heapptr(ctx, -1);

	duk_dup(ctx, 0);														// [proxy][jsCallback]
	duk_put_prop_string(ctx, -2, "_jsCallback");							// [proxy]
	
	ILibDuktape_CreateEventWithGetter(ctx, "Callback", ILibDuktape_GenericMashal_CallbackProxy_Callback);
	ILibDuktape_CreateEventWithGetter(ctx, "State", ILibDuktape_GenericMashal_CallbackProxy_State);


	return 1;
}

PTRSIZE ILibDuktape_GenericMarshal_MethodInvoke_NativeEx(int parms, void *fptr, PTRSIZE *vars, ILibDuktape_GenericMarshal_CallTypes calltype)
{
	PTRSIZE retVal = 0;

	if ((calltype & ILibDuktape_GenericMarshal_CUSTOM_HANDLER_VERIFY) == ILibDuktape_GenericMarshal_CUSTOM_HANDLER_VERIFY)
	{
		return(ILibDuktape_GenericMarshal_MethodInvoke_CustomEx(parms, fptr, vars, 1, calltype & ILibDuktape_GenericMarshal_CUSTOM_HANDLER_MASK));
	}
	if ((calltype & ILibDuktape_GenericMarshal_CUSTOM_HANDLER) == ILibDuktape_GenericMarshal_CUSTOM_HANDLER)
	{
		return(ILibDuktape_GenericMarshal_MethodInvoke_CustomEx(parms, fptr, vars, 0, calltype & ILibDuktape_GenericMarshal_CUSTOM_HANDLER_MASK));
	}

	switch (calltype)
	{
		default:
			switch (parms)
			{
			case 0:
				retVal = ((R0)fptr)();
				break;
			case 1:
				retVal = ((R1)fptr)(vars[0]);
				break;
			case 2:
				retVal = ((R2)fptr)(vars[0], vars[1]);
				break;
			case 3:
				retVal = ((R3)fptr)(vars[0], vars[1], vars[2]);
				break;
			case 4:
				retVal = ((R4)fptr)(vars[0], vars[1], vars[2], vars[3]);
				break;
			case 5:
				retVal = ((R5)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4]);
				break;
			case 6:
				retVal = ((R6)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5]);
				break;
			case 7:
				retVal = ((R7)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6]);
				break;
			case 8:
				retVal = ((R8)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7]);
				break;
			case 9:
				retVal = ((R9)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8]);
				break;
			case 10:
				retVal = ((R10)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8], vars[9]);
				break;
			case 11:
				retVal = ((R11)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8], vars[9], vars[10]);
				break;
			case 12:
				retVal = ((R12)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8], vars[9], vars[10], vars[11]);
				break;
			case 13:
				retVal = ((R13)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8], vars[9], vars[10], vars[11], vars[12]);
				break;
			case 14:
				retVal = ((R14)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8], vars[9], vars[10], vars[11], vars[12], vars[13]);
				break;
			case 15:
				retVal = ((R15)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8], vars[9], vars[10], vars[11], vars[12], vars[13], vars[14]);
				break;
			case 16:
				retVal = ((R16)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8], vars[9], vars[10], vars[11], vars[12], vars[13], vars[14], vars[15]);
				break;
			case 17:
				retVal = ((R17)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8], vars[9], vars[10], vars[11], vars[12], vars[13], vars[14], vars[15], vars[16]);
				break;
			case 18:
				retVal = ((R18)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8], vars[9], vars[10], vars[11], vars[12], vars[13], vars[14], vars[15], vars[16], vars[17]);
				break;
			case 19:
				retVal = ((R19)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8], vars[9], vars[10], vars[11], vars[12], vars[13], vars[14], vars[15], vars[16], vars[17], vars[18]);
				break;
			case 20:
				retVal = ((R20)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8], vars[9], vars[10], vars[11], vars[12], vars[13], vars[14], vars[15], vars[16], vars[17], vars[18], vars[19]);
				break;
			}
			break;
#ifdef WIN32
		case ILibDuktape_GenericMarshal_CallTypes_COM_VARIANT:
			switch (parms)
			{
				case 0:
					retVal = ((R0)fptr)();
					break;
				case 1:
					retVal = ((R1)fptr)(vars[0]);
					break;
				case 2:
					retVal = ((C2)fptr)(vars[0], ((VARIANT*)(vars[1]))[0]);
					break;
				case 3:
					retVal = ((C3)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0]);
					break;
				case 4:
					retVal = ((C4)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0]);
					break;
				case 5:
					retVal = ((C5)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0]);
					break;
				case 6:
					retVal = ((C6)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0]);
					break;
				case 7:
					retVal = ((C7)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0]);
					break;
				case 8:
					retVal = ((C8)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0]);
					break;
				case 9:
					retVal = ((C9)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0], ((VARIANT*)(vars[8]))[0]);
					break;
				case 10:
					retVal = ((C10)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0], ((VARIANT*)(vars[8]))[0], ((VARIANT*)(vars[9]))[0]);
					break;
				case 11:
					retVal = ((C11)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0], ((VARIANT*)(vars[8]))[0], ((VARIANT*)(vars[9]))[0], ((VARIANT*)(vars[9]))[0]);
					break;
				case 12:
					retVal = ((C12)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0], ((VARIANT*)(vars[8]))[0], ((VARIANT*)(vars[9]))[0], ((VARIANT*)(vars[10]))[0], ((VARIANT*)(vars[11]))[0]);
					break;
				case 13:
					retVal = ((C13)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0], ((VARIANT*)(vars[8]))[0], ((VARIANT*)(vars[9]))[0], ((VARIANT*)(vars[10]))[0], ((VARIANT*)(vars[11]))[0], ((VARIANT*)(vars[12]))[0]);
					break;
				case 14:
					retVal = ((C14)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0], ((VARIANT*)(vars[8]))[0], ((VARIANT*)(vars[9]))[0], ((VARIANT*)(vars[10]))[0], ((VARIANT*)(vars[11]))[0], ((VARIANT*)(vars[12]))[0], ((VARIANT*)(vars[13]))[0]);
					break;
				case 15:
					retVal = ((C15)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0], ((VARIANT*)(vars[8]))[0], ((VARIANT*)(vars[9]))[0], ((VARIANT*)(vars[10]))[0], ((VARIANT*)(vars[11]))[0], ((VARIANT*)(vars[12]))[0], ((VARIANT*)(vars[13]))[0], ((VARIANT*)(vars[14]))[0]);
					break;
				case 16:
					retVal = ((C16)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0], ((VARIANT*)(vars[8]))[0], ((VARIANT*)(vars[9]))[0], ((VARIANT*)(vars[10]))[0], ((VARIANT*)(vars[11]))[0], ((VARIANT*)(vars[12]))[0], ((VARIANT*)(vars[13]))[0], ((VARIANT*)(vars[14]))[0], ((VARIANT*)(vars[15]))[0]);
					break;
				case 17:
					retVal = ((C17)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0], ((VARIANT*)(vars[8]))[0], ((VARIANT*)(vars[9]))[0], ((VARIANT*)(vars[10]))[0], ((VARIANT*)(vars[11]))[0], ((VARIANT*)(vars[12]))[0], ((VARIANT*)(vars[13]))[0], ((VARIANT*)(vars[14]))[0], ((VARIANT*)(vars[15]))[0], ((VARIANT*)(vars[16]))[0]);
					break;
				case 18:
					retVal = ((C18)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0], ((VARIANT*)(vars[8]))[0], ((VARIANT*)(vars[9]))[0], ((VARIANT*)(vars[10]))[0], ((VARIANT*)(vars[11]))[0], ((VARIANT*)(vars[12]))[0], ((VARIANT*)(vars[13]))[0], ((VARIANT*)(vars[14]))[0], ((VARIANT*)(vars[15]))[0], ((VARIANT*)(vars[16]))[0], ((VARIANT*)(vars[17]))[0]);
					break;
				case 19:
					retVal = ((C19)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0], ((VARIANT*)(vars[8]))[0], ((VARIANT*)(vars[9]))[0], ((VARIANT*)(vars[10]))[0], ((VARIANT*)(vars[11]))[0], ((VARIANT*)(vars[12]))[0], ((VARIANT*)(vars[13]))[0], ((VARIANT*)(vars[14]))[0], ((VARIANT*)(vars[15]))[0], ((VARIANT*)(vars[16]))[0], ((VARIANT*)(vars[17]))[0], ((VARIANT*)(vars[18]))[0]);
					break;
				case 20:
					retVal = ((C20)fptr)(vars[0], ((VARIANT*)(vars[1]))[0], ((VARIANT*)(vars[2]))[0], ((VARIANT*)(vars[3]))[0], ((VARIANT*)(vars[4]))[0], ((VARIANT*)(vars[5]))[0], ((VARIANT*)(vars[6]))[0], ((VARIANT*)(vars[7]))[0], ((VARIANT*)(vars[8]))[0], ((VARIANT*)(vars[9]))[0], ((VARIANT*)(vars[10]))[0], ((VARIANT*)(vars[11]))[0], ((VARIANT*)(vars[12]))[0], ((VARIANT*)(vars[13]))[0], ((VARIANT*)(vars[14]))[0], ((VARIANT*)(vars[15]))[0], ((VARIANT*)(vars[16]))[0], ((VARIANT*)(vars[17]))[0], ((VARIANT*)(vars[18]))[0], ((VARIANT*)(vars[19]))[0]);
					break;
			}
			break;
#endif
	}
	

	return(retVal);
}
void ILibDuktape_GenericMarshal_MethodInvoke_ThreadSink_Return(void *chain, void *args)
{
	if (!ILibMemory_CanaryOK(args)) { return; }

	PTRSIZE *vars = (PTRSIZE*)((void**)args)[2];
	ILibDuktape_EventEmitter *e = (ILibDuktape_EventEmitter*)((void**)args)[0];
	PTRSIZE retVal = (PTRSIZE)((void**)args)[3];

	if (!ILibMemory_CanaryOK(e) || e->ctx == NULL) { return; }

	duk_context *ctx = e->ctx;
	ILibDuktape_EventEmitter_SetupEmit(e->ctx, e->object, "done");									// [emit][this][done]
	ILibDuktape_GenericMarshal_Variable_PUSH(e->ctx, (void*)(PTRSIZE)retVal, (int)sizeof(void*));	// [emit][this][done][retVal]
	if (duk_pcall_method(e->ctx, 2) != 0) 
	{ 
		ILibDuktape_Process_UncaughtException(e->ctx); duk_pop(e->ctx);
	}
	else
	{
		duk_pop(ctx);
	}
	ILibMemory_Free(vars);
}
void ILibDuktape_GenericMarshal_MethodInvoke_ThreadSink(void *args)
{
	ILibDuktape_EventEmitter *e = (ILibDuktape_EventEmitter*)((void**)args)[0];
	void *chain = ((void**)args)[1];
	PTRSIZE *vars = (PTRSIZE*)((void**)args)[2];
	int parms = (int)(PTRSIZE)((void**)args)[3];
	void *fptr = ((void**)args)[4];
	uintptr_t nonce = (uintptr_t)((void**)args)[5];
	PTRSIZE retVal = ILibDuktape_GenericMarshal_MethodInvoke_Native(parms, fptr, vars);

	((void**)args)[3] = (void*)retVal;
	Duktape_RunOnEventLoop(chain, nonce, e->ctx, ILibDuktape_GenericMarshal_MethodInvoke_ThreadSink_Return, NULL, args);
}

#define ILibDuktape_FFI_AsyncDataPtr "\xFF_FFI_AsyncDataPtr"
typedef struct ILibDuktape_FFI_AsyncData
{
	duk_context *ctx;
	void *chain;
	void *workerThread;
	uintptr_t ctxnonce;
#ifdef WIN32
	DWORD workerThreadId;
#else
	pthread_t workerThreadId;
#endif
	void *fptr;
	void *fptr_redirection;
	char *fptr_redirectionName;
	int abort;
	int waitingForResult;
	PTRSIZE *vars;
	void *promise;
	char *methodName;
	uint32_t lastError;
	sem_t workAvailable;
	sem_t workStarted;
	sem_t workFinished;
}ILibDuktape_FFI_AsyncData;

void ILibDuktape_GenericMarshal_MethodInvokeAsync_ChainDispatch(void *chain, void *user)
{
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)user;
	if (!ILibMemory_CanaryOK(data)) { return; }
	duk_context *ctx = data->ctx;

	duk_push_heapptr(data->ctx, data->promise);																// [promise]
	duk_get_prop_string(data->ctx, -1, "_RES");																// [promise][resolver]
	duk_swap_top(data->ctx, -2);																			// [resolver][this]
	ILibDuktape_GenericMarshal_Variable_PUSH(data->ctx, (void*)(PTRSIZE)data->vars, (int)sizeof(void*));	// [resolver][this][var]
	duk_push_int(data->ctx, data->lastError); duk_put_prop_string(data->ctx, -2, "_LastError");
	data->promise = NULL;

	if (duk_pcall_method(data->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "Error Resolving Promise: "); }
	duk_pop(ctx);																						// ...
}
void ILibDuktape_GenericMarshal_MethodInvokeAsync_WorkerRunLoop(void *arg)
{
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)arg;
	PTRSIZE var[20];
	int varCount, i;

#ifdef WIN32
	data->workerThreadId = GetCurrentThreadId();
#else
	data->workerThreadId = pthread_self();
#endif

	while (data->abort == 0)
	{
		sem_wait(&(data->workAvailable));
		if (data->abort != 0) { break; }
		varCount = (int)(ILibMemory_Size(data->vars) / sizeof(PTRSIZE));
		for (i = (data->fptr_redirection == NULL ? 0 : 1); i < varCount; ++i)
		{
			var[(data->fptr_redirection == NULL ? i : (i - 1))] = data->vars[i];
		}
		sem_post(&(data->workStarted));

		if (data->fptr_redirection == NULL)
		{
			data->vars = (PTRSIZE*)ILibDuktape_GenericMarshal_MethodInvoke_Native(varCount, data->fptr, var);
		}
		else
		{
			data->vars = (PTRSIZE*)ILibDuktape_GenericMarshal_MethodInvoke_Native(varCount-1, data->fptr_redirection, var);
			data->fptr_redirection = NULL;
		}
#ifdef WIN32
		data->lastError = (DWORD)GetLastError();
#endif
		if (ILibMemory_CanaryOK(data))
		{
			if (data->waitingForResult == 0)
			{
				Duktape_RunOnEventLoop(data->chain, data->ctxnonce, data->ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_ChainDispatch, NULL, data);
			}
			else
			{
				data->waitingForResult = 0;
				sem_post(&(data->workFinished));
			}
		}
	}
	sem_destroy(&(data->workAvailable));
	sem_destroy(&(data->workStarted));
	sem_destroy(&(data->workFinished));
	ILibMemory_Free(data);
}
duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_promise(duk_context *ctx)
{
	duk_push_this(ctx);		// [promise]
	duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, "_RES");
	duk_dup(ctx, 1); duk_put_prop_string(ctx, -2, "_REJ");
	return(0);
}
duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_abort(duk_context *ctx)
{
	duk_push_this(ctx);
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_FFI_AsyncDataPtr);
	if (!ILibMemory_CanaryOK(data)) { return(ILibDuktape_Error(ctx, "FFI_AsyncData was already freed")); }

	if (data != NULL)
	{
		if (data->promise == NULL)
		{
			sem_t *workAvailable = &(data->workAvailable);
			void *workerThread = data->workerThread;

			// We can gracefully exit this thread
			data->abort = 1;
			sem_post(workAvailable);
			ILibThread_Join(workerThread);
		}
		else
		{
			if (data->waitingForResult == 0)
			{
				if (data->promise != ILibDuktape_GenericMarshal_INVALID_PROMISE)
				{
					// We cannot gracefully exit the thread, so let's reject the promise, and let the app layer figure it out
					duk_push_heapptr(data->ctx, data->promise);		// [promise]
					duk_get_prop_string(data->ctx, -1, "_REJ");		// [promise][rej]
					duk_swap_top(data->ctx, -2);					// [rej][this]
					duk_push_string(data->ctx, "ABORT");			// [rej][this][abort]

					data->abort = 1;
					duk_call_method(ctx, 1);
					duk_pop(ctx);									// ...

					//
					// We are purposefully not clearing the promise, becuase the hope is that the above layer
					// will receive this rejection, and do a proper cleanup, which may need the promise to accomplish that.
					// 
				}
			}
			else
			{
				// Invalid scenario
				return(ILibDuktape_Error(ctx, "Cannot abort operation that is marked as 'wait for result'"));
			}
		}
		duk_push_this(ctx);
		duk_del_prop_string(ctx, -1, ILibDuktape_FFI_AsyncDataPtr);
	}
	return(0);
}
duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_dataFinalizer(duk_context *ctx)
{
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)Duktape_GetPointerProperty(ctx, 0, ILibDuktape_FFI_AsyncDataPtr);

	if (data != NULL && ILibMemory_CanaryOK(data))
	{
		if (data->promise == NULL)
		{
			sem_t *workAvailable = &(data->workAvailable);
			void *workerThread = data->workerThread;

			data->abort = 1;
			sem_post(workAvailable);
			ILibThread_Join(workerThread);
		}
		else
		{
			if (duk_ctx_shutting_down(ctx))
			{
				ILibLinkedList_AddTail(duk_ctx_context_data(ctx)->threads, data->workerThread);
			}
			data->abort = 1;
		}
	}
	return(0);
}

#ifdef WIN32
void ILibDuktape_GenericMarshal_MethodInvokeAsync_Done_chain(void *chain, void* u)
{
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)u;
	duk_context *ctx;
	if (!ILibMemory_CanaryOK(data)) { return; }
	if (!ILibMemory_CanaryOK(data->ctx) || data->promise == NULL || data->promise == ILibDuktape_GenericMarshal_INVALID_PROMISE)
	{
		return;
	}

	duk_push_heapptr(data->ctx, data->promise);																// [promise]
	duk_get_prop_string(data->ctx, -1, "_RES");																// [promise][resolver]
	duk_swap_top(data->ctx, -2);																			// [resolver][this]
	ILibDuktape_GenericMarshal_Variable_PUSH(data->ctx, (void*)data->workAvailable, (int)sizeof(void*));	// [resolver][this][var]
	duk_push_int(data->ctx, data->lastError); duk_put_prop_string(data->ctx, -2, "_LastError");
	data->promise = NULL;
	if (duk_pcall_method(data->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(data->ctx, "Error Resolving Promise: "); }
	
	ctx = data->ctx;
	ILibMemory_Free(data->vars);
	ILibMemory_Free(data);
	duk_pop(ctx);																							// ...
}
void __stdcall ILibDuktape_GenericMarshal_MethodInvokeAsync_APC(ULONG_PTR u)
{
	if (!ILibMemory_CanaryOK((void*)u)) { return; }

	int i;
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)u;
	int varCount = (int)(ILibMemory_Size(data->vars) / sizeof(PTRSIZE));
	PTRSIZE var[20];

	for (i =  1; i < varCount; ++i)
	{
		var[i-1] = data->vars[i];
	}
	data->workAvailable = (void*)ILibDuktape_GenericMarshal_MethodInvoke_Native(varCount-1, data->fptr, var);
	data->lastError = (DWORD)GetLastError();

	ILibChain_RunOnMicrostackThread(data->chain, ILibDuktape_GenericMarshal_MethodInvokeAsync_Done_chain, data);
}
#endif
duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_promfin(duk_context *ctx)
{
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)Duktape_GetPointerProperty(ctx, 0, "_data");
	void *h = duk_get_heapptr(ctx, 0);

	if (ILibMemory_CanaryOK(data) && data->promise == h)
	{
		data->promise = ILibDuktape_GenericMarshal_INVALID_PROMISE;
	}
	return(0);
}
duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync(duk_context *ctx)
{
	void *redirectionPtr = NULL, *redirectionPtrName = NULL;
	int i;
	int parms = duk_get_top(ctx);
	ILibDuktape_FFI_AsyncData *data = NULL;
	if (parms > 20) { return(ILibDuktape_Error(ctx, "Too many parameters")); }

	if (duk_is_function(ctx, 0))
	{
		data = (ILibDuktape_FFI_AsyncData*)Duktape_GetPointerProperty(ctx, 0, ILibDuktape_FFI_AsyncDataPtr);
		if (data != NULL)
		{
			if (ILibMemory_CanaryOK(data))
			{
				redirectionPtr = Duktape_GetPointerProperty(ctx, 0, "_address");
			}
			else
			{
				return(ILibDuktape_Error(ctx, "FFI Object was already freed"));
			}
		}
	}
#ifdef WIN32
	if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, ILibDuktape_GenericMarshal_GlobalSet_Dispatcher))
	{
		Duktape_GlobalGeneric_Data *ggd = (Duktape_GlobalGeneric_Data*)Duktape_GetPointerProperty(ctx, 0, ILibDuktape_GenericMarshal_GlobalSet_Dispatcher);
		redirectionPtr = NULL;

		data = (ILibDuktape_FFI_AsyncData*)ILibMemory_SmartAllocate(sizeof(ILibDuktape_FFI_AsyncData));
		duk_push_pointer(ctx, data);
		duk_put_prop_string(ctx, -2, ILibDuktape_FFI_AsyncDataPtr);

		duk_eval_string(ctx, "require('promise');");		// [func][promise]
		duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_promise, 2);
		duk_new(ctx, 1);
		ILibDuktape_CreateFinalizer(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_promfin);
		duk_push_pointer(ctx, data); duk_put_prop_string(ctx, -2, "_data");
		ggd->dispatch->promise = duk_get_heapptr(ctx, -1);

		data->ctx = ctx;
		data->ctxnonce = duk_ctx_nonce(ctx);
		data->promise = ggd->dispatch->promise;
		data->chain = duk_ctx_chain(ctx);

		duk_push_current_function(ctx);																		// [promise][func]
		data->fptr = Duktape_GetPointerProperty(ctx, -1, "_address");
		data->methodName = Duktape_GetStringPropertyValue(ctx, -1, "_funcName", NULL);
		data->waitingForResult = WAITING_FOR_RESULT__DISPATCHER;
		data->workFinished = ILibChain_GetMicrostackThreadHandle(Duktape_GetChain(ctx));
		data->workStarted = ggd->dispatch->WorkerThreadHandle;
		data->vars = (PTRSIZE*)ILibMemory_SmartAllocate(sizeof(PTRSIZE)*parms);
		data->fptr_redirection = NULL;
	}
	else
	{
#endif
		if (redirectionPtr == NULL)
		{
			duk_push_current_function(ctx);																		// [func]
			data = (ILibDuktape_FFI_AsyncData*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_FFI_AsyncDataPtr);
			if (data == NULL)
			{
				data = ILibMemory_SmartAllocate(sizeof(ILibDuktape_FFI_AsyncData));								// [func][buff]
				duk_push_pointer(ctx, data);
				duk_push_current_function(ctx);																	// [func][buff][func]
				duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_dataFinalizer, 1);		// [func][buff][func][cfunc]
				duk_set_finalizer(ctx, -2);																		// [func][buff][func]
				duk_pop(ctx);																					// [func][buff]

				duk_put_prop_string(ctx, -2, ILibDuktape_FFI_AsyncDataPtr);										// [func]
				data->ctx = ctx;
				data->ctxnonce = duk_ctx_nonce(ctx);
				data->chain = Duktape_GetChain(ctx);
				data->fptr = Duktape_GetPointerProperty(ctx, -1, "_address");
				data->methodName = Duktape_GetStringPropertyValue(ctx, -1, "_funcName", NULL);
				sem_init(&(data->workAvailable), 0, 0);
				sem_init(&(data->workStarted), 0, 0);
				sem_init(&(data->workFinished), 0, 0);
				data->workerThread = ILibSpawnNormalThreadEx(ILibDuktape_GenericMarshal_MethodInvokeAsync_WorkerRunLoop, data, 0);
			}
		}
		else
		{
			duk_push_current_function(ctx);
			redirectionPtr = Duktape_GetPointerProperty(ctx, -1, "_address");
			redirectionPtrName = Duktape_GetStringPropertyValue(ctx, -1, "_funcName", NULL);		
		}
		if (data->promise != NULL) { return(ILibDuktape_Error(ctx, "Async Operation already in progress")); }
		if (data->waitingForResult == 0)
		{
			// Only need to create a promise, if it's fully async
			duk_eval_string(ctx, "require('promise');");		// [func][promise]
			duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_promise, 2);
			duk_new(ctx, 1);
			ILibDuktape_CreateFinalizer(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_promfin);
			duk_push_pointer(ctx, data); duk_put_prop_string(ctx, -2, "_data");
			data->promise = duk_get_heapptr(ctx, -1);
		}
		data->vars = (PTRSIZE*)ILibMemory_AllocateA(sizeof(PTRSIZE)*parms);
		data->fptr_redirection = redirectionPtr;
		data->fptr_redirectionName = redirectionPtrName;

#ifdef WIN32
	}
#endif 

	duk_push_array(ctx);
	for (i = 0; i < parms; ++i)
	{
		duk_dup(ctx, i);
		duk_put_prop_index(ctx, -2, i);			// Stash the input arguments in the promise, so they don't get GC'ed until we're done
	}
	duk_put_prop_string(ctx, -2, "_varArray");

	for (i = 0; i < parms; ++i)
	{
		if (duk_is_object(ctx, i))
		{
			duk_get_prop_string(ctx, i, "_ptr");
			data->vars[i] = (PTRSIZE)duk_to_pointer(ctx, -1);
		}
		else if (duk_is_number(ctx, i))
		{
			data->vars[i] = (uintptr_t)(duk_require_uint(ctx, i) == 0 ? duk_require_int(ctx, i) : duk_require_uint(ctx, i));
		}
		else if (duk_is_pointer(ctx, i))
		{
			data->vars[i] = (PTRSIZE)duk_require_pointer(ctx, i);
		}
		else if(!(i==0 && duk_is_function(ctx, 0)))
		{
			return(ILibDuktape_Error(ctx, "INVALID Parameter"));
		}
	}

#ifdef WIN32
	if (data->waitingForResult == WAITING_FOR_RESULT__DISPATCHER)
	{
		QueueUserAPC((PAPCFUNC)ILibDuktape_GenericMarshal_MethodInvokeAsync_APC, data->workStarted, (ULONG_PTR)data);
	}
	else
	{
#endif
		sem_post(&(data->workAvailable));			// Let worker know there is work available
		sem_wait(&(data->workStarted));				// Wait for work to start before exiting, because VARS will be gone when we leave
#ifdef WIN32
	}
#endif

	duk_push_heapptr(ctx, data->promise);		// [promise]

	duk_push_current_function(ctx);				// [promise][func]
	duk_get_prop_string(ctx, -1, "_obj");		// [promise][func][obj]
	duk_remove(ctx, -2);						// [promise][obj]
	duk_put_prop_string(ctx, -2, "nativeProxy");// [promise]

	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_wait(duk_context *ctx)
{
	int nargs = duk_get_top(ctx), i;

	ILibDuktape_FFI_AsyncData *data;
	duk_push_this(ctx);																						// [func]
	data = (ILibDuktape_FFI_AsyncData*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_FFI_AsyncDataPtr);
	if (data == NULL)
	{
		data = ILibMemory_SmartAllocate(sizeof(ILibDuktape_FFI_AsyncData));									// [func][buffer]
		duk_push_pointer(ctx, data);
		duk_push_this(ctx);																					// [func][buffer][func]
		duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_dataFinalizer, 1);			// [func][buffer][func][finalizer]
		duk_set_finalizer(ctx, -2);																			// [func][buffer][func]
		duk_pop(ctx);																						// [func][buffer]

		duk_put_prop_string(ctx, -2, ILibDuktape_FFI_AsyncDataPtr);											// [func]
		data->ctx = ctx;
		data->ctxnonce = duk_ctx_nonce(ctx);
		data->chain = Duktape_GetChain(ctx);
		data->fptr = Duktape_GetPointerProperty(ctx, -1, "_address");
		sem_init(&(data->workAvailable), 0, 0);
		sem_init(&(data->workStarted), 0, 0);
		sem_init(&(data->workFinished), 0, 0);
		data->workerThread = ILibSpawnNormalThreadEx(ILibDuktape_GenericMarshal_MethodInvokeAsync_WorkerRunLoop, data, 0);
	}

	if (data->waitingForResult == WAITING_FOR_RESULT__DISPATCHER) { return(ILibDuktape_Error(ctx, "This method call is not waitable")); }

	// If we set this flag, a promise won't be created, instead we can just wait for the response
	data->waitingForResult = 1;																				// [func]
	duk_get_prop_string(ctx, -1, "apply");																	// [func][apply]
	duk_swap_top(ctx, -2);																					// [apply][this]
	duk_dup(ctx, -1);																						// [apply][this][this]
	duk_push_array(ctx);																					// [apply][this][this][args]
	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);																					// [apply][this][this][args][arg]
		duk_put_prop_index(ctx, -2, i);																		// [apply][this][this][args]
	}
	duk_call_method(ctx, 2);
	
	sem_wait(&(data->workFinished));
	ILibDuktape_GenericMarshal_Variable_PUSH(ctx, (void*)(PTRSIZE)data->vars, (int)sizeof(void*));			
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_MethodInvoke(duk_context *ctx)
{
	char *exposedName = NULL;
	void *fptr = NULL;
	int parms = duk_get_top(ctx);
	int i;
	PTRSIZE retVal = (PTRSIZE)(-1);
	if (parms > 20) { return(ILibDuktape_Error(ctx, "Too many parameters")); }
	
	duk_push_current_function(ctx);					// [func]
	exposedName = Duktape_GetStringPropertyValue(ctx, -1, "_exposedName", NULL);
	int spawnThread = Duktape_GetBooleanProperty(ctx, -1, "_spawnThread", 0);
#ifndef WIN32
	ILibDuktape_GenericMarshal_CallTypes calltypes = ILibDuktape_GenericMarshal_CallTypes_DEFAULT;
#else
	ILibDuktape_GenericMarshal_CallTypes calltypes = Duktape_GetIntPropertyValue(ctx, -1, "_callType", ILibDuktape_GenericMarshal_CallTypes_DEFAULT);
	if (sizeof(void*) != 4) { calltypes = ILibDuktape_GenericMarshal_CallTypes_DEFAULT; }
#endif
	PTRSIZE *vars = spawnThread == 0 ? ILibMemory_AllocateA(sizeof(PTRSIZE)*parms) : ILibMemory_SmartAllocateEx(sizeof(PTRSIZE)*parms, 6 * sizeof(void*));
	duk_get_prop_string(ctx, -1, "_address");		// [func][addr]
	fptr = duk_to_pointer(ctx, -1);



	if (fptr == NULL || exposedName == NULL)
	{
		return(ILibDuktape_Error(ctx, "Invalid Method"));
	}

	for (i = 0; i < parms; ++i)
	{
		if (duk_is_object(ctx, i))
		{
			duk_get_prop_string(ctx, i, "_ptr");
			vars[i] = (PTRSIZE)duk_to_pointer(ctx, -1);
		}
		else if (duk_is_number(ctx, i))
		{
			vars[i] = (uintptr_t)(duk_require_uint(ctx, i) == 0 ? duk_require_int(ctx, i) : duk_require_uint(ctx, i));
		}
		else if (duk_is_pointer(ctx, i))
		{
			vars[i] = (PTRSIZE)duk_require_pointer(ctx, i);
		}
		else
		{
			return(ILibDuktape_Error(ctx, "Invalid Parameter"));
		}
	}

	if (parms > 20)
	{
		return(ILibDuktape_Error(ctx, "Invalid number of parameters (%d), max of 20", parms));
	}
	else
	{
		if (spawnThread == 0)
		{
			if ((calltypes & ILibDuktape_GenericMarshal_CUSTOM_HANDLER) == ILibDuktape_GenericMarshal_CUSTOM_HANDLER)
			{
				if (ILibDuktape_GenericMarshal_MethodInvoke_NativeEx(parms, fptr, vars, calltypes | ILibDuktape_GenericMarshal_CUSTOM_HANDLER_VERIFY) == 1)
				{
					retVal = ILibDuktape_GenericMarshal_MethodInvoke_NativeEx(parms, fptr, vars, calltypes);
				}
				else
				{
					return(ILibDuktape_Error(ctx, "Specified custom handler doesn't exit: %u", calltypes & ILibDuktape_GenericMarshal_CUSTOM_HANDLER_MASK));
				}
			}
			else
			{
				retVal = ILibDuktape_GenericMarshal_MethodInvoke_NativeEx(parms, fptr, vars, calltypes);
			}
#ifdef WIN32
			DWORD err = GetLastError();
#else
			int err = errno;
#endif
			ILibDuktape_GenericMarshal_Variable_PUSH(ctx, (void*)(PTRSIZE)retVal, (int)sizeof(void*));
			duk_push_int(ctx, err); duk_put_prop_string(ctx, -2, "_LastError");
		}
		else
		{
			duk_push_object(ctx);														// [ret]
			ILibDuktape_WriteID(ctx, "GenericMarshal.Variable.DispatcherEvent");
			ILibDuktape_EventEmitter *e = ILibDuktape_EventEmitter_Create(ctx);
			ILibDuktape_EventEmitter_CreateEventEx(e, "done");

			void **args = (void**)ILibMemory_Extra(vars);
			args[0] = e;
			args[1] = Duktape_GetChain(ctx);
			args[2] = vars;
			args[3] = (void*)(PTRSIZE)parms;
			args[4] = fptr;
			args[5] = (void*)duk_ctx_nonce(ctx);

			void *thptr = ILibSpawnNormalThread(ILibDuktape_GenericMarshal_MethodInvoke_ThreadSink, args);
			duk_push_fixed_buffer(ctx, sizeof(void*));									// [ret][buffer]
			((void**)Duktape_GetBuffer(ctx, -1, NULL))[0] = thptr;
			duk_push_buffer_object(ctx, -1, 0, sizeof(void*), DUK_BUFOBJ_NODEJS_BUFFER);// [ret][buffer][NodeBuffer]

			duk_swap_top(ctx, -2);														// [ret][NodeBuffer][buffer]
			duk_put_prop_string(ctx, -3, "\xFF_BuffPtr");								// [ret][NodeBuffer]	
			ILibDuktape_CreateReadonlyProperty(ctx, "_ThreadHandle");					// [ret]
		}
	}

	return 1;
}
duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_thread(duk_context *ctx)
{
	duk_push_this(ctx);		// [async]
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_FFI_AsyncDataPtr);
	if (data == NULL) { return(ILibDuktape_Error(ctx, "No thread")); }
	if (!ILibMemory_CanaryOK(data)) { return(ILibDuktape_Error(ctx, "FFI Object was already freed")); }
	ILibDuktape_GenericMarshal_Variable_PUSH(ctx, data->workerThread, sizeof(void*));
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_thread_id(duk_context *ctx)
{
	duk_push_this(ctx);		// [async]
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_FFI_AsyncDataPtr);
	if (!ILibMemory_CanaryOK(data)) { return(ILibDuktape_Error(ctx, "FFI Object was already freed")); }

	char tmp[255];
	sprintf_s(tmp, sizeof(tmp), "%llu", (uint64_t)data->workerThreadId);
	duk_push_string(ctx, tmp);
	return(1);
	
}
duk_ret_t ILibDuktape_GenericMarshal_CreateMethod(duk_context *ctx)
{
	void* module = NULL;
	void* funcAddress = NULL;
	char* funcName;
	char* exposedMethod;
	int threadDispatch = 0;
	int deref = 0;

	if (duk_is_object(ctx, 0))
	{
		funcName = Duktape_GetStringPropertyValue(ctx, 0, "method", NULL);
		exposedMethod = Duktape_GetStringPropertyValue(ctx, 0, "newName", funcName);
		threadDispatch = Duktape_GetIntPropertyValue(ctx, 0, "threadDispatch", 0);
		deref = Duktape_GetIntPropertyValue(ctx, 0, "dereferencePointer", 0);
	}
	else
	{
		funcName = (char*)duk_require_string(ctx, 0);
		exposedMethod = duk_get_top(ctx) == 1 ? funcName : (char*)duk_require_string(ctx, 1);
	}

	duk_push_this(ctx);																	// [obj]
	duk_get_prop_string(ctx, -1, "_moduleAddress");										// [obj][module]
	module = duk_to_pointer(ctx, -1);
	duk_pop(ctx);																		// [obj]

#ifdef WIN32
	funcAddress = (void*)GetProcAddress((HMODULE)module, (LPCSTR)funcName);
#else
	funcAddress = (void*)dlsym(module, funcName);
#endif

	if (funcAddress == NULL)
	{
		return(ILibDuktape_Error(ctx, "CreateMethod Error: Method Name [%s] Not Found", funcName));
	}
	else if(deref!=0)
	{
		funcAddress = ((void**)funcAddress)[0];
	}

	duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvoke, DUK_VARARGS);					// [obj][func]
	duk_push_string(ctx, exposedMethod); duk_put_prop_string(ctx, -2, "_exposedName");
	duk_push_pointer(ctx, funcAddress);																// [obj][func][addr]
	duk_put_prop_string(ctx, -2, "_address");														// [obj][func]
	if (threadDispatch != 0) { duk_push_true(ctx); duk_put_prop_string(ctx, -2, "_spawnThread"); }	// [obj][func]

	// Add an 'async' method, to use a dispatch thread to invoke the method
	duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync, DUK_VARARGS);			// [obj][func][func]
	duk_push_pointer(ctx, funcAddress);																// [obj][func][func][addr]
	duk_put_prop_string(ctx, -2, "_address");														// [obj][func][func]
	duk_push_string(ctx, funcName); duk_put_prop_string(ctx, -2, "_funcName");
	duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_abort, 0); 				// [obj][func][func][func]
	duk_put_prop_string(ctx, -2, "abort");															// [obj][func][func]
	duk_push_this(ctx);	duk_put_prop_string(ctx, -2, "_obj");
	duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_thread, 0); duk_put_prop_string(ctx, -2, "thread");
	duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_wait, DUK_VARARGS); duk_put_prop_string(ctx, -2, "wait");
	duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_thread_id, 0); duk_put_prop_string(ctx, -2, "threadId");

	duk_put_prop_string(ctx, -2, "async");															// [obj][func]

	duk_put_prop_string(ctx, -2, exposedMethod);													// [obj]

	return 0;
}
duk_ret_t ILibDuktape_GenericMarshal_NativeProxy_Finalizer(duk_context *ctx)
{
#ifdef WIN32
	HMODULE hm = (HMODULE)Duktape_GetPointerProperty(ctx, 0, "_moduleAddress");
	if (hm != NULL)
	{
		FreeLibrary(hm);
	}
#else
	void *hm = Duktape_GetPointerProperty(ctx, 0, "_moduleAddress");
	if (hm != NULL)
	{
		dlclose(hm);
	}
#endif
	return(0);
}
duk_ret_t ILibDuktape_GenericMarshal_CreateNativeProxy(duk_context *ctx)
{
	void* module = NULL;
	char* libName = duk_is_string(ctx, 0) ? (char*)duk_require_string(ctx, 0) : NULL;

#ifdef WIN32
	if (libName != NULL)
	{
		DWORD flags = 0;
		if (duk_is_object(ctx, 1) && (flags=(DWORD)Duktape_GetIntPropertyValue(ctx, 1, "flags", 0)) != 0)
		{
			module = (void*)LoadLibraryExA((LPCSTR)libName, NULL, flags);
			if (module == NULL && GetLastError() == ERROR_INVALID_PARAMETER)
			{
				return(ILibDuktape_Error(ctx, "Unsupported Flag value"));
			}
		}
		else
		{
			module = (void*)LoadLibraryA((LPCSTR)libName);
		}
	}
	else
	{
		HMODULE hModule = NULL;
		GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)ILibDuktape_GenericMarshal_CreateNativeProxy, &hModule);
		module = (void*)hModule;
	}
#else
	module = dlopen(libName, RTLD_NOW);
#endif

	if (module == NULL)
	{
#ifdef WIN32
		duk_push_string(ctx, "Could not create Native Proxy");
		return(ILibDuktape_Error(ctx, "Could not create Native Proxy"));
#else
		duk_push_string(ctx, dlerror());
		return(ILibDuktape_Error(ctx, "%s", dlerror()));
#endif
	}
	duk_push_object(ctx);																							// [obj]
	if (sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "_GenericMarshal.NativeProxy [%s]", libName) > 0)
	{
		ILibDuktape_WriteID(ctx, ILibScratchPad);
	}
	duk_push_pointer(ctx, module);																					// [obj][module]
	duk_put_prop_string(ctx, -2, "_moduleAddress");																	// [obj]
	ILibDuktape_CreateInstanceMethod(ctx, "CreateMethod", ILibDuktape_GenericMarshal_CreateMethod, DUK_VARARGS);	// [obj]
	if (libName != NULL) { ILibDuktape_CreateFinalizer(ctx, ILibDuktape_GenericMarshal_NativeProxy_Finalizer); }

	return 1;
}
duk_ret_t ILibDuktape_GenericMarshal_CreateVariableEx(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char* ptr = NULL;
	int size;
	duk_push_current_function(ctx);														// [func]
	duk_get_prop_string(ctx, -1, "_VarSize");											// [func][size]
	size = duk_to_int(ctx, -1);

	if (nargs == 1)
	{
		duk_size_t buflen;
		ptr = Duktape_GetBuffer(ctx, 0, &buflen);
	}
	
	if (ptr == NULL)
	{
		ptr = (char*)ILibMemory_Allocate(size, 0, NULL, NULL);
		ILibDuktape_GenericMarshal_Variable_PUSH(ctx, ptr, size);							// [func][size][var]
		ILibDuktape_GenericMarshal_Variable_EnableAutoFree(ctx, -1);
	}
	else
	{
		ILibDuktape_GenericMarshal_Variable_PUSH(ctx, ((void**)ptr)[0], size);				// [func][size][var]
		ILibDuktape_GenericMarshal_Variable_DisableAutoFree(ctx, -1);
	}
	return 1;
}
void ILibDuktape_GlobalGenericCallback_ProcessEx_Abort(void *chain, void *user)
{
	Duktape_GlobalGeneric_Data *data = (Duktape_GlobalGeneric_Data*)user;
	if (ILibMemory_CanaryOK(data))
	{
		data->retVal = NULL;
		sem_post(&(data->contextWaiter));
	}
}
void ILibDuktape_GlobalGenericCallback_ProcessEx(void *chain, void *user)
{
	int i;
	//void *retVal = NULL;
	Duktape_GlobalGeneric_Data *data = (Duktape_GlobalGeneric_Data*)user;
	if (!ILibMemory_CanaryOK(data->emitter)) { return; }

	char tmp[255];
	sprintf_s(tmp, sizeof(tmp), "%llu", (uint64_t)data->callingThread);
	duk_push_heapptr(data->emitter->ctx, data->emitter->object);										// [obj]
	duk_push_string(data->emitter->ctx, tmp);														    // [obj][str]
	duk_put_prop_string(data->emitter->ctx, -2, ILibDuktape_GenericMarshal_GlobalCallback_ThreadID);	// [obj]
	duk_push_pointer(data->emitter->ctx, user); duk_put_prop_string(data->emitter->ctx, -2, ILibDuktape_GenericMarshal_GlobalSet);
	duk_pop(data->emitter->ctx);																		// ...

	ILibDuktape_EventEmitter_SetupEmit(data->emitter->ctx, data->emitter->object, "GlobalCallback");	// [emit][this][GlobalCallback]
	for (i = 0; i < data->numArgs; ++i)
	{
		ILibDuktape_GenericMarshal_Variable_PUSH(data->emitter->ctx, (void*)data->args[i], sizeof(void*));
	}
	if (duk_pcall_method(data->emitter->ctx, data->numArgs + 1) != 0) 
	{ 
		ILibDuktape_Process_UncaughtException(data->emitter->ctx); 
	}

	duk_pop(data->emitter->ctx);

	if (data->emitter->lastReturnValue != NULL)
	{
		duk_push_heapptr(data->emitter->ctx, data->emitter->lastReturnValue);
		data->retVal = Duktape_GetPointerProperty(data->emitter->ctx, -1, "_ptr");
		duk_pop(data->emitter->ctx);
	}

	sem_post(&(data->contextWaiter));
}
void* ILibDuktape_GlobalGenericCallback_Process(int numParms, ...)
{
	void *retVal = NULL;
	PTRSIZE v;
	Duktape_GlobalGeneric_Data *user;
#ifdef WIN32
	Duktape_GlobalGeneric_DispatcherData *windispatch = NULL;
#endif

	if (GlobalCallbackList == NULL) { return(NULL); }

	ILibLinkedList_Lock(GlobalCallbackList);
	Duktape_GlobalGeneric_Data *data;
	int i = 0, maxCount = ILibLinkedList_GetCount(GlobalCallbackList), count = 0, j = 0;
	void *node = ILibLinkedList_GetNode_Head(GlobalCallbackList);
	Duktape_GlobalGeneric_Data **refList = (Duktape_GlobalGeneric_Data**)ILibMemory_AllocateA(maxCount * sizeof(Duktape_GlobalGeneric_Data*));
	
	while (node != NULL)
	{
		data = (Duktape_GlobalGeneric_Data*)ILibLinkedList_GetDataFromNode(node);
		if (data != NULL) { refList[count++] = data; }
		node = ILibLinkedList_GetNextNode(node);
	}
	ILibLinkedList_UnLock(GlobalCallbackList);

	for (i = 0; i < count; ++i)
	{
		user = NULL;
		ILibLinkedList_Lock(GlobalCallbackList);
		if (ILibMemory_CanaryOK(refList[i]))
		{
			if (!ILibIsRunningOnChainThread(refList[i]->chain))
			{
				// Need to context switch
				user = ILibMemory_SmartAllocate(sizeof(Duktape_GlobalGeneric_Data) + (numParms * sizeof(PTRSIZE)));
#ifdef WIN32
				user->callingThread = GetCurrentThreadId();
#else
				user->callingThread = pthread_self();
#endif
				sem_init(&(user->contextWaiter), 0, 0);
				user->chain = refList[i]->chain;
				user->ctxnonce = refList[i]->ctxnonce;
				user->emitter = refList[i]->emitter;
				user->numArgs = numParms;
				if (numParms > 0)
				{
					va_list vlist;
					va_start(vlist, numParms);
					for (j = 0; j < numParms; ++j)
					{
						user->args[j] = va_arg(vlist, PTRSIZE);
					}
					va_end(vlist);
				}
				Duktape_RunOnEventLoop(refList[i]->chain, refList[i]->ctxnonce, refList[i]->emitter->ctx, ILibDuktape_GlobalGenericCallback_ProcessEx, ILibDuktape_GlobalGenericCallback_ProcessEx_Abort, user);
			}
			else
			{
				// No need to context switch
				duk_push_heapptr(refList[i]->emitter->ctx, refList[i]->emitter->object);										// [obj]
				duk_del_prop_string(refList[i]->emitter->ctx, -1, ILibDuktape_GenericMarshal_GlobalCallback_ThreadID);
				duk_del_prop_string(refList[i]->emitter->ctx, -1, ILibDuktape_GenericMarshal_GlobalSet);
				duk_pop(refList[i]->emitter->ctx);																				// ...
				ILibDuktape_EventEmitter_SetupEmit(refList[i]->emitter->ctx, refList[i]->emitter->object, "GlobalCallback");	// [emit][this][GlobalCallback]
				if (numParms > 0)
				{
					int z;
					va_list vlist;
					va_start(vlist, numParms);
					for (z = 0; z < numParms; ++z)
					{
						v = va_arg(vlist, PTRSIZE);
						ILibDuktape_GenericMarshal_Variable_PUSH(refList[i]->emitter->ctx, (void*)v, sizeof(void*));
						ILibDuktape_GenericMarshal_Variable_DisableAutoFree(refList[i]->emitter->ctx, -1);
					}
					va_end(vlist);
				}
				if (duk_pcall_method(refList[i]->emitter->ctx, numParms + 1) != 0)
				{
					ILibDuktape_Process_UncaughtException(refList[i]->emitter->ctx);
				}
				else
				{
					if ((retVal = refList[i]->emitter->lastReturnValue) != NULL)
					{
						duk_push_heapptr(refList[i]->emitter->ctx, refList[i]->emitter->lastReturnValue);				// [retVal]
						if (duk_has_prop_string(refList[i]->emitter->ctx, -1, ILibDuktape_GenericMarshal_VariableType))
						{
							retVal = Duktape_GetPointerProperty(refList[i]->emitter->ctx, -1, "_ptr");
						}
						duk_pop(refList[i]->emitter->ctx);																// ...
					}
				}
				duk_pop(refList[i]->emitter->ctx);
			}
		}
		ILibLinkedList_UnLock(GlobalCallbackList);	

		if (user != NULL)
		{
			sem_wait(&(user->contextWaiter));

			if (user->retVal != NULL) { retVal = user->retVal; }
#ifdef WIN32
			if (user->dispatch != NULL) { windispatch = user->dispatch; }
#endif
			sem_destroy(&(user->contextWaiter));
			
#ifdef WIN32
			if (windispatch) { break; } else { ILibMemory_Free(user); }
#else
			ILibMemory_Free(user);
#endif
		}
	}

#ifdef WIN32
	if (windispatch)
	{
		while (windispatch->finished == 0) 
		{
			if (SleepEx(5000, TRUE) == 0) { break; }
		}
		retVal = windispatch->retValue;
		ILibMemory_Free(windispatch);
		ILibMemory_Free(user);
	}
#endif

	return(retVal);
}

PTRSIZE ILibDuktape_GlobalGenericCallback0()
{
	return (PTRSIZE)ILibDuktape_GlobalGenericCallback_Process(0);
}
PTRSIZE ILibDuktape_GlobalGenericCallback1(PTRSIZE v1)
{
	return (PTRSIZE)ILibDuktape_GlobalGenericCallback_Process(1, v1);
}										 
PTRSIZE ILibDuktape_GlobalGenericCallback2(PTRSIZE v1, PTRSIZE v2)
{
	return (PTRSIZE)ILibDuktape_GlobalGenericCallback_Process(2, v1, v2);
}										  
PTRSIZE ILibDuktape_GlobalGenericCallback3(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3)
{
	return (PTRSIZE)ILibDuktape_GlobalGenericCallback_Process(3, v1, v2, v3);
}										 
PTRSIZE ILibDuktape_GlobalGenericCallback4(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3, PTRSIZE v4)
{
	return (PTRSIZE)ILibDuktape_GlobalGenericCallback_Process(4, v1, v2, v3, v4);
}										  
PTRSIZE ILibDuktape_GlobalGenericCallback5(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3, PTRSIZE v4, PTRSIZE v5)
{
	return (PTRSIZE)ILibDuktape_GlobalGenericCallback_Process(5, v1, v2, v3, v4, v5);
}										 
PTRSIZE ILibDuktape_GlobalGenericCallback6(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3, PTRSIZE v4, PTRSIZE v5, PTRSIZE v6)
{
	return (PTRSIZE)ILibDuktape_GlobalGenericCallback_Process(6, v1, v2, v3, v4, v5, v6);
}										  
PTRSIZE ILibDuktape_GlobalGenericCallback7(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3, PTRSIZE v4, PTRSIZE v5, PTRSIZE v6, PTRSIZE v7)
{
	return (PTRSIZE)ILibDuktape_GlobalGenericCallback_Process(7, v1, v2, v3, v4, v5, v6, v7);
}										  
PTRSIZE ILibDuktape_GlobalGenericCallback8(PTRSIZE v1, PTRSIZE v2, PTRSIZE v3, PTRSIZE v4, PTRSIZE v5, PTRSIZE v6, PTRSIZE v7, PTRSIZE v8)
{
	return (PTRSIZE)ILibDuktape_GlobalGenericCallback_Process(8, v1, v2, v3, v4, v5, v6, v7, v8);
}
duk_ret_t ILibDuktape_GenericMarshal_GlobalGenericCallback_EventSink(duk_context *ctx)
{
	int nargs = duk_get_top(ctx), i;
	duk_push_current_function(ctx);			// [func]
	duk_get_prop_string(ctx, -1, "self");	// [func][variable]
	void *self = duk_get_heapptr(ctx, -1);
#ifdef WIN32
	void *dispatchArray = NULL;
#endif

	if (Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_GenericMarshal_Variable_Parms, -1) == nargs)
	{
		duk_dup(ctx, -1);										// [var]
		duk_eval_string(ctx, "require('_GenericMarshal');");	// [var][GM]
		duk_get_prop_string(ctx, -1, "CallingThread");			// [var][GM][CallingThread]
		duk_swap_top(ctx, -2);									// [var][CallingThread][this]
		duk_call_method(ctx, 0);								// [var][ThreadId]
		duk_put_prop_string(ctx, -2, ILibDuktape_GenericMarshal_GlobalCallback_ThreadID);
		duk_pop(ctx);

#ifdef WIN32
		duk_push_this(ctx);
		Duktape_GlobalGeneric_Data *ud = (Duktape_GlobalGeneric_Data*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_GenericMarshal_GlobalSet);
		duk_pop(ctx);

		if (ud != NULL) // This is null if we didn't context switch threads
		{
			if (ud->dispatch == NULL || ud->callingThread == GetCurrentThreadId())
			{
				// Put this into a 'stack', so we can be properly re-entrant
				duk_get_prop_string(ctx, -1, ILibDuktape_GenericMarshal_GlobalSet);		// [var][array]
				dispatchArray = duk_get_heapptr(ctx, -1);
				duk_get_prop_string(ctx, -1, "push");									// [var][array][push]
				duk_swap_top(ctx, -2);													// [var][push][this]
				duk_push_pointer(ctx, ud);												// [var][push][this][value]
				duk_call_method(ctx, 1); duk_pop(ctx);									// [var]
			}
		}

		if (ud == NULL || ud->dispatch == NULL || ud->callingThread == GetCurrentThreadId())
		{
#endif

			ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, -1), "GlobalCallback");	// [emit][this][GlobalCallback]
			for (i = 0; i < nargs; ++i) { duk_dup(ctx, i); }
			duk_pcall_method(ctx, nargs + 1);

#ifdef WIN32
			if (ud != NULL && ud->dispatch == NULL)
			{
				// Dispatcher wasn't used, so we can just pop the dispatcher stack
				duk_push_heapptr(ctx, dispatchArray);			// [array]
				duk_get_prop_string(ctx, -1, "pop");			// [array][pop]
				duk_swap_top(ctx, -2);							// [pop][this]
				duk_call_method(ctx, 0);						// [ret]
				duk_pop(ctx);									// ...
			}
#endif

			duk_push_heapptr(ctx, self);						// [this]
			duk_get_prop_string(ctx, -1, "emit_returnValue");	// [this][emit_returnValue]
			duk_swap_top(ctx, -2);								// [emit_returnValue][this]
			duk_call_method(ctx, 0);
			return(1);
#ifdef WIN32
		}
		else
		{
			return(0);
		}
#endif

	}
	else
	{
		return(0);
	}
}
duk_ret_t ILibDuktape_GenericMarshal_ObjectToPtr_Verify(duk_context *ctx)
{
	void *ptr = duk_require_heapptr(ctx, 0);
	void *var = Duktape_GetPointerProperty(ctx, 1, "_ptr");

	duk_push_boolean(ctx, ptr == var);
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_GlobalCallback_CallingThread(duk_context *ctx)
{
	duk_push_this(ctx);
	if (duk_has_prop_string(ctx, -1, ILibDuktape_GenericMarshal_GlobalCallback_ThreadID))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_GenericMarshal_GlobalCallback_ThreadID);
	}
	else
	{
		duk_eval_string(ctx, "require('_GenericMarshal');");	// [GM]
		duk_get_prop_string(ctx, -1, "GetCurrentThread");		// [GM][GCT]
		duk_swap_top(ctx, -2);									// [GCT][this]
		duk_call_method(ctx, 0);								// [ThreadId]
	}
	return(1);
}


#ifdef WIN32
duk_ret_t ILibDuktape_GenericMarshal_GlobalCallback_StartDispatcher(duk_context *ctx)
{
	Duktape_GlobalGeneric_Data *data;
	duk_push_this(ctx);													// [var]
	duk_get_prop_string(ctx, -1, ILibDuktape_GenericMarshal_GlobalSet);	// [var][array]
	duk_get_prop_index(ctx, -1, (duk_uarridx_t)duk_get_length(ctx, -1) - 1);
	data = (Duktape_GlobalGeneric_Data*)duk_get_pointer(ctx, -1);

	if (data == NULL) { return(ILibDuktape_Error(ctx, "Internal Error")); }
	if (data->callingThread == GetCurrentThreadId()) { return(ILibDuktape_Error(ctx, "No Dispatcher")); }
	if (data->dispatch != NULL) 
	{
		return(ILibDuktape_Error(ctx, "Dispatcher already started"));
	}

	data->dispatch = (Duktape_GlobalGeneric_DispatcherData*)ILibMemory_SmartAllocate(sizeof(Duktape_GlobalGeneric_DispatcherData));
	data->dispatch->WorkerThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, data->callingThread);

	duk_push_object(ctx);
	ILibDuktape_WriteID(ctx, "GlobalCallback.Dispatcher");
	duk_push_pointer(ctx, data); duk_put_prop_string(ctx, -2, ILibDuktape_GenericMarshal_GlobalSet_Dispatcher);
	return(1);
}
void __stdcall ILibDuktape_GenericMarshal_GlobalCallback_EndDispatcher_APC(ULONG_PTR u)
{
	((Duktape_GlobalGeneric_Data*)u)->dispatch->finished = 1;
	CloseHandle(((Duktape_GlobalGeneric_Data*)u)->dispatch->WorkerThreadHandle);
}
duk_ret_t ILibDuktape_GenericMarshal_GlobalCallback_EndDispatcher(duk_context *ctx)
{
	Duktape_GlobalGeneric_Data *data;
	duk_push_this(ctx);													// [var]
	duk_get_prop_string(ctx, -1, ILibDuktape_GenericMarshal_GlobalSet);	// [var][array]
	duk_get_prop_string(ctx, -1, "pop");								// [var][array][pop]
	duk_swap_top(ctx, -2);												// [var][pop][this]
	duk_call_method(ctx, 0);											// [var][data]

	data = (Duktape_GlobalGeneric_Data*)duk_get_pointer(ctx, -1);

	if (data == NULL) { return(ILibDuktape_Error(ctx, "Internal Error")); }
	if (data->dispatch == NULL || data->dispatch->WorkerThreadHandle == NULL) { return(ILibDuktape_Error(ctx, "No Dispatcher")); }
	data->dispatch->retValue = Duktape_GetPointerProperty(ctx, 0, "_ptr");
	QueueUserAPC((PAPCFUNC)ILibDuktape_GenericMarshal_GlobalCallback_EndDispatcher_APC, data->dispatch->WorkerThreadHandle, (ULONG_PTR)data);
	
	return(0);
}
#endif

duk_ret_t ILibDuktape_GenericMarshal_GlobalCallback_close(duk_context *ctx)
{
	// We need to unhook from a global event, becuase we are reference by the callback function
	// which is referenced by the global event, meaning that a global object is referencing us.

	duk_push_this(ctx);														// [Variable]
	duk_eval_string(ctx, "require('_GenericMarshal');");					// [Variable][GenericMarshal]
	duk_get_prop_string(ctx, -1, "removeListener");							// [Variable][GenericMarshal][removeListener]
	duk_swap_top(ctx, -2);													// [Variable][removeListener][this]
	duk_push_string(ctx, "GlobalCallback");									// [Variable][removeListener][this][GlobalCallback]
	duk_get_prop_string(ctx, -4, ILibDuktape_GenericMarshal_FuncHandler);	// [Variable][removeListener][this][GlobalCallback][function]
	duk_call_method(ctx, 2); duk_pop(ctx);									// [Variable]

	return(0);
}

int ILibDuktape_GlobalGenericCallbackEx_n[22] = { 0 };
int ILibDuktape_GlobalGenericCallbackEx_active[22] = { 0 };
ILibDuktape_EventEmitter *ILibDuktape_GlobalGenericCallbackEx_nctx[22] = { 0 };
extern void* gILibChain;

duk_ret_t ILibDuktape_GlobalGenericCallbackEx_Process_ChainEx_2(ILibDuktape_EventEmitter *emitter)
{
	duk_push_heapptr(emitter->ctx, emitter->object);		// [array][var]
	duk_get_prop_string(emitter->ctx, -1, "emit");			// [array][var][emit]
	duk_get_prop_string(emitter->ctx, -1, "apply");			// [array][var][emit][apply]

	duk_dup(emitter->ctx, -2);								// [array][var][emit][apply][emit]
	duk_dup(emitter->ctx, -4);								// [array][var][emit][apply][emit][this]
	duk_dup(emitter->ctx, -6);								// [array][var][emit][apply][emit][this][array]
	duk_push_string(emitter->ctx, "GlobalCallback");		// [array][var][emit][apply][emit][this][array][GlobalCallback]
	duk_array_unshift(emitter->ctx, -2);					// [array][var][emit][apply][emit][this][array]
	duk_remove(emitter->ctx, -5);							// [array][var][apply][emit][this][array]
	duk_remove(emitter->ctx, -5);							// [array][apply][emit][this][array]
	duk_remove(emitter->ctx, -5);							// [apply][emit][this][array]
	return(duk_pcall_method(emitter->ctx, 2));				// [retVal]
}
void ILibDuktape_GlobalGenericCallbackEx_Process_ChainEx(void * chain, void *user)
{
	Duktape_GlobalGeneric_Data *data = (Duktape_GlobalGeneric_Data*)user;
	duk_context *ctx = data->emitter->ctx;
	int i;

	duk_idx_t top = duk_get_top(ctx);
	duk_push_array(ctx);																		// [array]
	for (i = 0; i < data->numArgs; ++i)
	{
		ILibDuktape_GenericMarshal_Variable_PUSH(ctx, (void*)data->args[i], sizeof(PTRSIZE));	// [array][var]
		duk_array_push(ctx, -2);																// [array]
	}
	duk_push_heapptr(ctx, data->emitter->object);												// [array][obj]
	duk_push_true(ctx); duk_put_prop_string(ctx, -2, "callbackDispatched"); duk_pop(ctx);		// [array]
	if (ILibDuktape_GlobalGenericCallbackEx_Process_ChainEx_2(data->emitter) != 0)
	{
		// Exception was thrown
		ILibDuktape_Process_UncaughtExceptionEx(ctx, "Exception occured in GlobalCallback: %s", duk_safe_to_string(ctx, -1));
		data->retVal = NULL;
	}
	else
	{
		if (ILibMemory_CanaryOK(data->emitter))
		{
			duk_push_heapptr(ctx, data->emitter->object);			// [obj]
			duk_prepare_method_call(ctx, -1, "emit_returnValue");	// [obj][emitRV][this]
			if (duk_pcall_method(ctx, 0) == 0)
			{
				data->retVal = Duktape_GetPointerProperty(ctx, -1, "_ptr");
			}
		}
	}
	duk_set_top(ctx, top);
	sem_post(&(data->contextWaiter));
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_Process(PTRSIZE arg1, int index, va_list args)
{
	int i;
	int count = ILibDuktape_GlobalGenericCallbackEx_n[index];
	ILibDuktape_EventEmitter *emitter = ILibDuktape_GlobalGenericCallbackEx_nctx[index];

	if (ILibDuktape_GlobalGenericCallbackEx_active[index] == 0)
	{
		return(0);
	}

	if (gILibChain != NULL && ILibIsRunningOnChainThread(gILibChain) == 0)
	{
		// Need to Context Switch to different thread, but before we do, we need to export all the parameters from va_list
		void *ret = NULL;
		Duktape_GlobalGeneric_Data *user = ILibMemory_SmartAllocate(sizeof(Duktape_GlobalGeneric_Data) + ((count + 1) * sizeof(PTRSIZE)));
		user->chain = gILibChain;
		user->numArgs = count + 1;
		user->emitter = emitter;
		for (i = 0; i < user->numArgs; ++i)
		{
			user->args[i] = i == 0 ? arg1 : va_arg(args, PTRSIZE);
		}
		sem_init(&(user->contextWaiter), 0, 0);
		ILibChain_RunOnMicrostackThread(user->chain, ILibDuktape_GlobalGenericCallbackEx_Process_ChainEx, user);
		
		sem_wait(&(user->contextWaiter));
		if (user->retVal != NULL) { ret = user->retVal; }
		sem_destroy(&(user->contextWaiter));
		ILibMemory_Free(user);
		return((PTRSIZE)ret);
	}

	// No Context Switch is necessary
	duk_push_array(emitter->ctx);																							// [array]
	for (i = 0; i < (count + 1); ++i)
	{
		ILibDuktape_GenericMarshal_Variable_PUSH(emitter->ctx, (void*)( i == 0 ? arg1 : va_arg(args, PTRSIZE)), sizeof(PTRSIZE));		// [array][var]
		duk_array_push(emitter->ctx, -2);																					// [array]
	}
	duk_push_heapptr(emitter->ctx, emitter->object);												// [array][obj]
	duk_push_false(emitter->ctx); duk_put_prop_string(emitter->ctx, -2, "callbackDispatched");		// [array][obj]
	duk_pop(emitter->ctx);																			// [array]

	if (ILibDuktape_GlobalGenericCallbackEx_Process_ChainEx_2(emitter) != 0)
	{
		// Exception was thrown
		ILibDuktape_Process_UncaughtExceptionEx(emitter->ctx, "Exception occured in GlobalCallback: ");
		duk_pop(emitter->ctx);
		return(0);
	}
	uintptr_t ret = 0;
	duk_pop(emitter->ctx);
	if (emitter->lastReturnValue != NULL)
	{
		duk_push_heapptr(emitter->ctx, emitter->lastReturnValue);
		ret = (uintptr_t)Duktape_GetPointerProperty(emitter->ctx, -1, "_ptr");
		duk_pop(emitter->ctx);
	}
	return((PTRSIZE)ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_0(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 0, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_1(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 1, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_2(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 2, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_3(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 3, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_4(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 4, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_5(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 5, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_6(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 6, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_7(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 7, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_8(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 8, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_9(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 9, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_10(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 10, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_11(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 11, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_12(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 12, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_13(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 13, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_14(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 14, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_15(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 15, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_16(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 16, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_17(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 17, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_18(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 18, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_19(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 19, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_20(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 20, args);
	va_end(args);
	return(ret);
}
PTRSIZE ILibDuktape_GlobalGenericCallbackEx_21(PTRSIZE arg1, ...)
{
	PTRSIZE ret;
	va_list args;
	va_start(args, arg1);
	ret = ILibDuktape_GlobalGenericCallbackEx_Process(arg1, 21, args);
	va_end(args);
	return(ret);
}

duk_ret_t ILibDuktape_GenericMarshal_PutGlobalGenericCallbackEx(duk_context *ctx)
{
	duk_push_global_stash(ctx);											// [stash]
	duk_get_prop_string(ctx, -1, "GlobalCallBacksEx");					// [stash][array]
	if (!duk_has_prop_string(ctx, 0, ILibDutkape_GenericMarshal_INTERNAL))
	{
		if (duk_has_prop_string(ctx, 0, ILibDutkape_GenericMarshal_INTERNAL_X))
		{
			uint32_t x = Duktape_GetUIntPropertyValue(ctx, 0, ILibDutkape_GenericMarshal_INTERNAL_X, 0);
			if (x < sizeof(GenericMarshal_CustomEventHandler_Events) / sizeof(void*))
			{
				GenericMarshal_CustomEventHandler_Events[x] = NULL;
			}
		}
		return(0);
	}
	duk_get_prop_string(ctx, 0, ILibDutkape_GenericMarshal_INTERNAL);	// [stash][array][obj]
	int index = Duktape_GetIntPropertyValue(ctx, -1, "INDEX", -1);
	duk_array_unshift(ctx, -2);											// [stash][array]

	ILibDuktape_GlobalGenericCallbackEx_n[index] = 0;
	ILibDuktape_GlobalGenericCallbackEx_active[index] = 0;
	ILibDuktape_GlobalGenericCallbackEx_nctx[index] = NULL;

	return(0);
}

duk_ret_t ILibDuktape_GenericMarshal_GetGlobalGenericCallbackEx(duk_context *ctx)
{
	int numParms = duk_require_int(ctx, 0);
	if (duk_is_number(ctx, 1))
	{	
		ILibDuktape_GenericMarshal_GetGlobalGenericCallbackEx_CustomHandler(ctx, numParms, duk_require_uint(ctx, 1));
		return(1);
	}

	duk_push_global_stash(ctx);			// [stash]
	if (!duk_has_prop_string(ctx, -1, "GlobalCallBacksEx"))
	{
		duk_push_array(ctx);			// [stash][array]

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_0); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 0); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_1); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 1); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_2); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 2); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_3); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 3); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_4); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 4); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_5); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 5); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_6); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 6); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_7); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 7); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_8); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 8); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_9); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 9); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_10); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 10); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_11); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 11); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_12); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 12); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_13); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 13); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_14); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 14); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_15); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 15); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_16); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 16); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_17); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 17); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_18); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 18); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_19); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 19); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_20); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 20); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);

		duk_push_object(ctx);
		duk_push_pointer(ctx, (void*)ILibDuktape_GlobalGenericCallbackEx_21); duk_put_prop_string(ctx, -2, "PTR");
		duk_push_int(ctx, 21); duk_put_prop_string(ctx, -2, "INDEX");
		duk_array_push(ctx, -2);


		duk_put_prop_string(ctx, -2, "GlobalCallBacksEx");				// [stash]
	}
	duk_get_prop_string(ctx, -1, "GlobalCallBacksEx");					// [stash][array]

	if (numParms < 1) { return(ILibDuktape_Error(ctx, "Must have 1 or more arguments")); }
	duk_array_pop(ctx, -1);												// [stash][array][obj]
	int index = Duktape_GetIntPropertyValue(ctx, -1, "INDEX", -1);
	void *PTR = Duktape_GetPointerProperty(ctx, -1, "PTR");
	ILibDuktape_GenericMarshal_Variable_PUSH(ctx, PTR, sizeof(PTRSIZE));// [stash][array][obj][var]
	ILibDuktape_GenericMarshal_Variable_DisableAutoFree(ctx, -1);
	ILibDuktape_EventEmitter_CreateEventEx(ILibDuktape_EventEmitter_Create(ctx), "GlobalCallback");

	duk_dup(ctx, -2);													// [stash][array][obj][var][obj]
	duk_put_prop_string(ctx, -2, ILibDutkape_GenericMarshal_INTERNAL);	// [stash][array][obj][var]
	ILibDuktape_GlobalGenericCallbackEx_n[index] = numParms;
	ILibDuktape_GlobalGenericCallbackEx_active[index] = 1;
	ILibDuktape_GlobalGenericCallbackEx_nctx[index] = ILibDuktape_EventEmitter_GetEmitter(ctx, -1);
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_GetGlobalGenericCallback(duk_context *ctx)
{
	int numParms = duk_require_int(ctx, 0);
	Duktape_GlobalGeneric_Data *data = NULL;
	duk_push_this(ctx);																		// [GenericMarshal]
	if (!duk_has_prop_string(ctx, -1, ILibDuktape_GenericMarshal_GlobalSet_List))
	{
		if (GlobalCallbackList == NULL)
		{
			GlobalCallbackList = ILibLinkedList_Create();
		}
		
		data = (Duktape_GlobalGeneric_Data*)ILibMemory_SmartAllocate(sizeof(Duktape_GlobalGeneric_Data));
		data->emitter = ILibDuktape_EventEmitter_Create(ctx);
		data->ctxnonce = duk_ctx_nonce(ctx);
		data->chain = Duktape_GetChain(ctx);
		ILibDuktape_EventEmitter_CreateEventEx(data->emitter, "GlobalCallback");
		ILibDuktape_CreateInstanceMethod(ctx, "CallingThread", ILibDuktape_GenericMarshal_GlobalCallback_CallingThread, 0);

		ILibLinkedList_Lock(GlobalCallbackList);
		ILibLinkedList_AddTail(GlobalCallbackList, data);
		ILibLinkedList_UnLock(GlobalCallbackList);
		duk_push_true(ctx);
		duk_put_prop_string(ctx, -2, ILibDuktape_GenericMarshal_GlobalSet_List);
	}
	else
	{
		data = (Duktape_GlobalGeneric_Data*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_GenericMarshal_GlobalSet);
	}
	
	void *ptr = NULL;
	switch (numParms)
	{
		case 0:
			ptr = (void*)(R0)ILibDuktape_GlobalGenericCallback0;
			break;
		case 1:
			ptr = (void*)(R1)ILibDuktape_GlobalGenericCallback1;
			break;
		case 2:
			ptr = (void*)(R2)ILibDuktape_GlobalGenericCallback2;
			break;
		case 3:
			ptr = (void*)(R3)ILibDuktape_GlobalGenericCallback3;
			break;
		case 4:
			ptr = (void*)(R4)ILibDuktape_GlobalGenericCallback4;
			break;
		case 5:
			ptr = (void*)(R5)ILibDuktape_GlobalGenericCallback5;
			break;
		case 6:
			ptr = (void*)(R6)ILibDuktape_GlobalGenericCallback6;
			break;
		case 7:
			ptr = (void*)(R7)ILibDuktape_GlobalGenericCallback7;
			break;
		case 8:
			ptr = (void*)(R8)ILibDuktape_GlobalGenericCallback8;
			break;
		default:
			return(ILibDuktape_Error(ctx, "%d callback parameters not currently supported. Max 8", numParms));
	}
	ILibDuktape_GenericMarshal_Variable_PUSH(ctx, ptr, (int)sizeof(void*));								// [GenericMarshal][Variable]
	ILibDuktape_EventEmitter *varEmitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(varEmitter, "GlobalCallback");
	duk_push_int(ctx, numParms); duk_put_prop_string(ctx, -2, ILibDuktape_GenericMarshal_Variable_Parms);
	duk_push_array(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_GenericMarshal_GlobalSet);
	ILibDuktape_CreateInstanceMethod(ctx, "CallingThread", ILibDuktape_GenericMarshal_GlobalCallback_CallingThread, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "close", ILibDuktape_GenericMarshal_GlobalCallback_close, 0);

	duk_get_prop_string(ctx, -2, "on");																	// [GenericMarshal][Variable][on]
	duk_dup(ctx, -3);																					// [GenericMarshal][Variable][on][this/GM]
	duk_push_string(ctx, "GlobalCallback");																// [GenericMarshal][Variable][on][this/GM][GlobalCallback]
	duk_push_c_function(ctx, ILibDuktape_GenericMarshal_GlobalGenericCallback_EventSink, DUK_VARARGS);	// [GenericMarshal][Variable][on][this/GM][GlobalCallback][func]
	duk_dup(ctx, -5);																					// [GenericMarshal][Variable][on][this/GM][GlobalCallback][func][Variable]

	duk_dup(ctx, -2);																					// [GenericMarshal][Variable][on][this/GM][GlobalCallback][func][Variable][func]
	duk_put_prop_string(ctx, -2, ILibDuktape_GenericMarshal_FuncHandler);								// [GenericMarshal][Variable][on][this/GM][GlobalCallback][func][Variable]

	duk_put_prop_string(ctx, -2, "self");																// [GenericMarshal][Variable][on][this/GM][GlobalCallback][func]
	duk_call_method(ctx, 2); duk_pop(ctx);																// [GenericMarshal][Variable]

	ILibDuktape_CreateInstanceMethod(ctx, "ObjectToPtr_Verify", ILibDuktape_GenericMarshal_ObjectToPtr_Verify, 2);
#ifdef WIN32
	ILibDuktape_CreateInstanceMethod(ctx, "StartDispatcher", ILibDuktape_GenericMarshal_GlobalCallback_StartDispatcher, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "EndDispatcher", ILibDuktape_GenericMarshal_GlobalCallback_EndDispatcher, 1);
#endif

	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_Finalizer(duk_context *ctx)
{
	if (GlobalCallbackList != NULL)
	{
		ILibLinkedList_Lock(GlobalCallbackList);
		void *node = ILibLinkedList_GetNode_Head(GlobalCallbackList);
		while (node != NULL)
		{
			Duktape_GlobalGeneric_Data *data = (Duktape_GlobalGeneric_Data*)ILibLinkedList_GetDataFromNode(node);
			if (data != NULL && data->chain == duk_ctx_chain(ctx) && data->ctxnonce == duk_ctx_nonce(ctx))
			{
				ILibMemory_Free(data);
				void *next = ILibLinkedList_GetNextNode(node);
				ILibLinkedList_Remove(node);
				node = next;
			}
			else
			{
				node = ILibLinkedList_GetNextNode(node);
			}
		}
		ILibLinkedList_UnLock(GlobalCallbackList);
	}
	return(0);
}
duk_ret_t ILibDuktape_GenericMarshal_WrapObject(duk_context *ctx)
{
	void *hptr = duk_require_heapptr(ctx, 0);

	duk_push_heap_stash(ctx);														// [stash]
	duk_dup(ctx, 0);																// [stash][obj]
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));	// [stash]
	duk_push_fixed_buffer(ctx, sizeof(Duktape_MarshalledObject));
	Duktape_MarshalledObject *marshalled = (Duktape_MarshalledObject*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_push_buffer_object(ctx, -1, 0, sizeof(Duktape_MarshalledObject), DUK_BUFOBJ_NODEJS_BUFFER);
	marshalled->ctx = ctx;
	marshalled->heapptr = hptr;
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_UnWrapObject(duk_context *ctx)
{
	duk_size_t len;
	Duktape_MarshalledObject *marshalled = (Duktape_MarshalledObject*)Duktape_GetBuffer(ctx, 0, &len);
	if (len != sizeof(Duktape_MarshalledObject) || marshalled->ctx != ctx)
	{
		return(ILibDuktape_Error(ctx, "Invalid WrappedObject, cannot UnWrapObject()"));
	}
	duk_push_heapptr(ctx, marshalled->heapptr);
	duk_push_heap_stash(ctx);
	duk_del_prop_string(ctx, -1, Duktape_GetStashKey(marshalled->heapptr));
	duk_pop(ctx);
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_StashObject(duk_context *ctx)
{
	void *ptr = duk_require_heapptr(ctx, 0);

	duk_push_this(ctx);															// [Marshal]
	duk_get_prop_string(ctx, -1, ILibDuktape_GenericMarshal_StashTable);		// [Marshal][StashTable]
	duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, Duktape_GetStashKey(ptr));	// [Marshal][StashTable]
	ILibDuktape_GenericMarshal_Variable_PUSH(ctx, ptr, sizeof(void*));
	ILibDuktape_GenericMarshal_Variable_DisableAutoFree(ctx, -1);
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_UnstashObject(duk_context *ctx)
{
	void *ptr = Duktape_GetPointerProperty(ctx, 0, "_ptr");
	if (ptr == NULL) 
	{ 
		duk_push_null(ctx); 
	}
	else
	{
		duk_push_this(ctx);															// [Marshal]
		duk_get_prop_string(ctx, -1, ILibDuktape_GenericMarshal_StashTable);		// [Marshal][StashTable]
		char *key = Duktape_GetStashKey(ptr);
		if (duk_has_prop_string(ctx, -1, key))
		{
			duk_get_prop_string(ctx, -1, key);										// [Marshal][StashTable][obj]
			if (duk_is_boolean(ctx, 1) && duk_get_boolean(ctx, 1))
			{
				duk_del_prop_string(ctx, -2, key);									// [Marshal][StashTable][obj]
			}
		}
		else
		{
			duk_push_null(ctx);
		}
	}
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_ObjectToPtr(duk_context *ctx)
{
	void *ptr = duk_require_heapptr(ctx, 0);

	ILibDuktape_GenericMarshal_Variable_PUSH(ctx, ptr, sizeof(void*));		// [var]
	ILibDuktape_GenericMarshal_Variable_DisableAutoFree(ctx, -1);
	return(1);
}

duk_ret_t ILibDuktape_GenericMarshal_GetCurrentThread(duk_context *ctx)
{
	char tmp[255];
#if defined(WIN32)
	sprintf_s(tmp, sizeof(tmp), "%ul", GetCurrentThreadId());
#else
	sprintf_s(tmp, sizeof(tmp), "%llu", pthread_self());
#endif
	duk_push_string(ctx, tmp);
	return(1);
}

duk_ret_t ILibDuktape_GenericMarshal_MarshalFunction(duk_context *ctx)
{
	if (duk_is_object(ctx, 0) && strcmp("_GenericMarshal.Variable", Duktape_GetStringPropertyValue(ctx, 0, ILibDuktape_OBJID, "")) == 0)
	{
		duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvoke, DUK_VARARGS);		// [func]
		duk_get_prop_string(ctx, 0, "_ptr");												// [func][addr]
		if (duk_is_number(ctx, 1))
		{
			void **p = (void**)duk_get_pointer(ctx, -1);
			int i = (int)duk_require_int(ctx, 1);
			duk_push_pointer(ctx, p[i]);													// [func][addr][ptr]
			duk_remove(ctx, -2);															// [func][ptr]
		}
		duk_put_prop_string(ctx, -2, "_address");											// [func]
		if (duk_is_number(ctx, 2))
		{
			duk_dup(ctx, 2); duk_put_prop_string(ctx, -2, "_callType");
		}

		duk_push_string(ctx, "_MarshalledFunction"); duk_put_prop_string(ctx, -2, "_exposedName");
		return(1);
	}
	return(ILibDuktape_Error(ctx, "Invalid Parameter"));
}
duk_ret_t ILibDuktape_GenericMarshal_MarshalFunctions(duk_context *ctx)
{
	if (duk_is_object(ctx, 0) && strcmp("_GenericMarshal.Variable", Duktape_GetStringPropertyValue(ctx, 0, ILibDuktape_OBJID, "")) == 0 && duk_is_array(ctx, 1))
	{
		int i = 0;
		duk_array_clone(ctx, 1);									// [array]
		duk_push_object(ctx);										// [array][ret]
		while (duk_get_length(ctx, -2) > 0)
		{
			duk_array_shift(ctx, -2);								// [array][ret][str]
			duk_push_this(ctx);										// [array][ret][str][this]
			duk_prepare_method_call(ctx, -1, "MarshalFunction");	// [array][ret][str][this][func][this]
			duk_dup(ctx, 0);										// [array][ret][str][this][func][this][parm]
			duk_push_int(ctx, i++);									// [array][ret][str][this][func][this][parm][val]
			duk_call_method(ctx, 2);								// [array][ret][str][this][marshalled]
			duk_remove(ctx, -2);									// [array][ret][str][marshalled]
			duk_dup(ctx, -2);										// [array][ret][str][marshalled][str]
			duk_put_prop_string(ctx, -2, "_exposedName");			// [array][ret][str][marshalled]
			duk_put_prop(ctx, -3);									// [array][ret]
		}
		return(1);
	}
	return(ILibDuktape_Error(ctx, "Invalid Parameters"));
}

duk_ret_t ILibDuktape_GenericMarshal_PutData(duk_context *ctx)
{
	void *arg1 = Duktape_GetPointerProperty(ctx, 0, "_ptr");
	void *arg2 = Duktape_GetPointerProperty(ctx, 1, "_ptr");
	ILibDuktape_EventEmitter *e = NULL;
	if (!duk_is_null_or_undefined(ctx, 2)) { e = ILibDuktape_EventEmitter_GetEmitter(ctx, 2); }
	void **val = (void**)ILibMemory_SmartAllocate(2 * sizeof(void*));
	val[0] = arg2;
	val[1] = e;

	if (marshal_data == NULL) { marshal_data = ILibHashtable_Create(); }
	if (!duk_is_null_or_undefined(ctx, 2))
	{
		duk_push_heap_stash(ctx);																																				// [stash]
		if (!duk_has_prop_string(ctx, -1, ILibDutkape_GenericMarshal_INTERNAL)) { duk_push_object(ctx); duk_put_prop_string(ctx, -2, ILibDutkape_GenericMarshal_INTERNAL); }	// [stash][obj]
		duk_push_sprintf(ctx, "%p", arg1);																																		// [stash][obj][key]
		duk_dup(ctx, 2);																																						// [stash][obj][key][val]
		duk_put_prop(ctx, -3);
	}

	ILibHashtable_Lock(marshal_data);
	ILibHashtable_Put(marshal_data, arg1, NULL, 0, val);
	ILibHashtable_UnLock(marshal_data);
	return(0);
}
duk_ret_t ILibDuktape_GenericMarshal_RemoveData(duk_context *ctx)
{
	if (marshal_data != NULL)
	{
		void *arg1 = Duktape_GetPointerProperty(ctx, 0, "_ptr");

		ILibHashtable_Lock(marshal_data);
		ILibHashtable_Remove(marshal_data, arg1, NULL, 0);
		ILibHashtable_UnLock(marshal_data);
	}
	return(0);
}
void ILibDuktape_GenericMarshal_Push(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);												// [obj]
	duk_push_object(ctx);												// [obj][stashTable]
	duk_put_prop_string(ctx, -2, ILibDuktape_GenericMarshal_StashTable);// [obj]
	ILibDuktape_WriteID(ctx, "_GenericMarshal");

	ILibDuktape_CreateInstanceMethod(ctx, "CreateVariable", ILibDuktape_GenericMarshal_CreateVariable, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "CreateCallbackProxy", ILibDuktape_GenericMarshal_CreateCallbackProxy, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "CreateNativeProxy", ILibDuktape_GenericMarshal_CreateNativeProxy, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "GetGenericGlobalCallback", ILibDuktape_GenericMarshal_GetGlobalGenericCallback, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "GetGenericGlobalCallbackEx", ILibDuktape_GenericMarshal_GetGlobalGenericCallbackEx, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "PutGenericGlobalCallbackEx", ILibDuktape_GenericMarshal_PutGlobalGenericCallbackEx, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "WrapObject", ILibDuktape_GenericMarshal_WrapObject, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "UnWrapObject", ILibDuktape_GenericMarshal_UnWrapObject, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "StashObject", ILibDuktape_GenericMarshal_StashObject, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "UnstashObject", ILibDuktape_GenericMarshal_UnstashObject, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "ObjectToPtr", ILibDuktape_GenericMarshal_ObjectToPtr, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "GetCurrentThread", ILibDuktape_GenericMarshal_GetCurrentThread, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "MarshalFunction", ILibDuktape_GenericMarshal_MarshalFunction, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "MarshalFunctions", ILibDuktape_GenericMarshal_MarshalFunctions, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "PutData", ILibDuktape_GenericMarshal_PutData, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "RemoveData", ILibDuktape_GenericMarshal_RemoveData, 1);


#ifdef WIN32
	duk_push_object(ctx);
	duk_push_uint(ctx, LOAD_LIBRARY_SEARCH_SYSTEM32); duk_put_prop_string(ctx, -2, "SYSTEM32");
	ILibDuktape_CreateReadonlyProperty(ctx, "FLAGS");
#endif

	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "_VarSize", 4, "CreateInteger", ILibDuktape_GenericMarshal_CreateVariableEx, 0);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "_VarSize", ((int)sizeof(void*)), "CreatePointer", ILibDuktape_GenericMarshal_CreateVariableEx, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "_VarSize", 2, "CreateShort", ILibDuktape_GenericMarshal_CreateVariableEx, 0);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_GenericMarshal_Finalizer);

	duk_push_int(ctx, sizeof(Duktape_MarshalledObject));
	ILibDuktape_CreateReadonlyProperty(ctx, "WrappedObjectLength");
	duk_push_int(ctx, sizeof(void*));
	ILibDuktape_CreateReadonlyProperty(ctx, "PointerSize");
}

void ILibDuktape_GenericMarshal_ChainDestroySink(void *chain, void *user)
{
	if (GlobalCallbackList != NULL)
	{
		ILibLinkedList_Lock(GlobalCallbackList);
		void *node = ILibLinkedList_GetNode_Head(GlobalCallbackList);
		while (node != NULL)
		{
			Duktape_GlobalGeneric_Data *data = (Duktape_GlobalGeneric_Data*)ILibLinkedList_GetDataFromNode(node);
			ILibMemory_Free(data);
			void *next = ILibLinkedList_GetNextNode(node);
			ILibLinkedList_Remove(node);
			node = next;
		}
		ILibLinkedList_UnLock(GlobalCallbackList);
		ILibLinkedList_Destroy(GlobalCallbackList);
		GlobalCallbackList = NULL;
	}
}
void ILibDuktape_GenericMarshal_init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "_GenericMarshal", ILibDuktape_GenericMarshal_Push);
	ILibChain_OnDestroyEvent_AddHandler(duk_ctx_chain(ctx), ILibDuktape_GenericMarshal_ChainDestroySink, NULL);
}

#ifdef __DOXY__
/*!
\brief Helper class, similar to <b>'FFI'</b> that allows JavaScript to make native calls. <b>Note:</b> To use, must <b>require('_GenericMarshal')</b>
*/
class _GenericMarshal
{
public:
	/*!
	\brief Creates a NativeProxy object for the given <b>dll</b> or <b>.so</b> file.
	\param path \<String\> The <b>dll</b> or <b>.so</b> file name or path. For example, 'wlanapi.dll'
	\return <NativeProxy> NativeProxy abstraction object to use for method invocation.
	*/
	NativeProxy CreateNativeProxy(path);
	/*!
	\brief Create a NativeCallbackProxy object that can be used with a NativeProxy object for callback reception. <b>Note:</b> The last parameter of the native callback must be an opaque user state object/ptr.
	\param func The function to dispatch on callback
	\param numVars The number of parameters in the native callback function signature
	\return <NativeCallbackProxy> NativeCallbackProxy object to use for native callback reception.
	*/
	NativeCallbackProxy CreateCallbackProxy(func, numVars);

	/*!
	\brief Initializes a proxy variable to use with a NativeProxy object.
	\param sz <Integer> Amount of memory in bytes to initialize
	\return <NativeVariable> NativeVariable object to use with NativeProxy object method calls.
	*/
	NativeVariable CreateVariable(sz);
	/*!
	\brief Initializes an integer (4 bytes) as a proxy variable to use with a NativeProxy object.
	\return <NativeVariable> NativeVariable object to use with NativeProxy object method calls.
	*/
	NativeVariable CreateInteger();
	/*!
	\brief Initializes an short (2 bytes) as a proxy variable to use with a NativeProxy object.
	\return <NativeVariable> NativeVariable object to use with NativeProxy object method calls.
	*/
	NativeVariable CreateShort();
	/*!
	\brief Initializes a pointer as a proxy variable to use with a NativeProxy object. The size used is the actual size of a void* pointer.
	\return <NativeVariable> NativeVariable object to use with NativeProxy object method calls.
	*/
	NativeVariable CreatePointer();


	/*!
	\brief Variable abstraction used by NativeProxy and NativeCallbackProxy
	*/
	class NativeVariable
	{
	public:
		/*!
		\brief GET/SET property. 64 bit values are only supported on 64 bit builds. 2 and 4 bytes values are passed as int. 8 byte value passes as a pointer.
		*/
		void Val;
		/*!
		\brief GET/SET 4 byte integer property.
		*/
		void IntVal;
		/*!
		\brief GET/SET 2 byte short property.
		*/
		void ShortVal;

		/*!
		\brief Dereferences the specified memory region
		*
		NativeVariable Deref([offset], length);
		\param offset <integer> Optional offset, specifying where to start dereferencing. 0 if not specified.
		\param length <integer> The number of bytes to dereference
		\return <NativeVariable> NativeVariable object representing the dereferenced memory.
		*/
		NativeVariable Deref([offset], length);

		/*!
		\brief Property GET that returns memory as a simple string
		\return \<String\>
		*/
		object String;
		/*!
		\brief Property GET that returns memory as a simple string. <b>Note:</b> On Win32, this will perform a Wide to Ansi conversion.
		\return \<String\>
		*/
		object AnsiString;
		/*!
		\brief Property GET that returns memory as a Hex String of bytes (ie AABBCCDD)
		\return \<String\>
		*/
		object HexString;
		/*!
		\brief Property GET that returns memory as a Colon delimited Hex String of bytes (ie AA:BB:CC:DD)
		\return \<String\>
		*/
		object HexString2;
	};
	/*!
	\brief JavaScript abstraction object for a Native library. <b>Note:</b> Must call 'CreateMethod' to add instance methods, that will dispatch into the native library.
	*/
	class NativeProxy
	{
	public:
		/*!
		\brief Adds an instance method, that will proxy method calls into Native.
		\param methodName \<String\> The name of the exposed method to proxy
		\param newMethodName \<String\> The name of the instance method to add to the NativeProxy object. If not specified, the name specified by 'methodName' will be used.
		*/
		void CreateMethod(methodName[, newMethodName]);
	};
	/*!
	\brief JavaScript abstraction to proxy callbacks between Native and JavaScript, using NativeProxy
	*/
	class NativeCallbackProxy
	{
	public:
		/*!
		\brief JavaScript dispatcher that should be passed as the callback function pointer when invoking a native method using NativeProxy
		\return NativeVariable object that proxies the callback, which should be passed as the callback function when invoking a method with NativeProxy
		*/
		NativeVariable Callback;
		/*!
		\brief NativeVariable encapsulation of JavaScript dispatcher data, that must be passed as 'opaque user data' when invoking a method with NativeProxy <b>Note:</b> The callback signature must return this opaque data as the last parameter
		\return NativeVariable object passed as 'opaque user data' that is used by the callback dispatcher.
		*/
		NativeVariable State;
	};
};

#endif
