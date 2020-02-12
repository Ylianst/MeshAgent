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

#if defined(_WIN64) || defined(__LP64__)
	typedef uint_fast64_t PTRSIZE;
#else
	typedef uint_fast32_t PTRSIZE;
#endif

#ifdef WIN32
#define APICALLTYPE __stdcall

#else
#define APICALLTYPE
#include <dlfcn.h>
#endif

#define ILibDuktape_GenericMarshal_FuncHandler			"\xFF_GenericMarshal_FuncHandler"
#define ILibDuktape_GenericMarshal_VariableType			"\xFF_GenericMarshal_VarType"
#define ILibDuktape_GenericMarshal_GlobalSet_List		"\xFF_GenericMarshal_GlobalSet_List"
#define ILibDuktape_GenericMarshal_GlobalSet			"\xFF_GenericMarshal_GlobalSet"
#define ILibDuktape_GenericMarshal_GlobalSet_Dispatcher	"\xFF_GenericMArshal_GlobalSet_Dispatcher"
#define ILibDuktape_GenericMarshal_Variable_AutoFree	"\xFF_GenericMarshal_Variable_AutoFree"
#define ILibDuktape_GenericMarshal_Variable_Parms		"\xFF_GenericMarshal_Variable_Parms"
#define ILibDuktape_GenericMarshal_StashTable			"\xFF_GenericMarshal_StashTable"
#define ILibDuktape_GenericMarshal_GlobalCallback_ThreadID "\xFF_GenericMarshal_ThreadID"
#define ILibDuktape_GenericMarshal_Variable_EnableAutoFree(ctx, idx) duk_dup(ctx, idx);duk_push_true(ctx);duk_put_prop_string(ctx, -2, ILibDuktape_GenericMarshal_Variable_AutoFree);duk_pop(ctx)
#define ILibDuktape_GenericMarshal_Variable_DisableAutoFree(ctx, idx) duk_dup(ctx, idx);duk_push_false(ctx);duk_put_prop_string(ctx, -2, ILibDuktape_GenericMarshal_Variable_AutoFree);duk_pop(ctx)
#define WAITING_FOR_RESULT__DISPATCHER					2


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

void ILibDuktape_GenericMarshal_Variable_PUSH(duk_context *ctx, void *ptr, int size);

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
	char hexString[255];

	duk_push_this(ctx);							// [var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [var][ptr]
	ptr = duk_to_pointer(ctx, -1);
	duk_get_prop_string(ctx, -2, "_size");		// [var][ptr][size]
	size = duk_to_int(ctx, -1);

	util_tohex2((char*)ptr, size < 255 ? size : 254, hexString);

	duk_push_string(ctx, (char*)hexString);
	return 1;
}

duk_ret_t ILibDuktape_GenericMarshal_Variable_Val_ASTRING(duk_context *ctx)
{
	void *ptr;
	int size;

#ifdef WIN32
	char astr[65535];
	size_t s;
#endif

	duk_push_this(ctx);							// [var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [var][ptr]
	ptr = duk_to_pointer(ctx, -1);
	duk_get_prop_string(ctx, -2, "_size");		// [var][ptr][size]
	size = duk_to_int(ctx, -1);

#ifdef WIN32
	if (size == 0) { size = (int)wcsnlen_s((const wchar_t*)ptr, sizeof(astr) * 2); }
	wcstombs_s(&s, astr, sizeof(astr), (const wchar_t*)ptr, size);
	duk_push_string(ctx, (char*)astr);
#else
	duk_push_lstring(ctx, (const char*)ptr, size);
#endif
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

	ILibDuktape_CreateInstanceMethod(ctx, "Deref", ILibDuktape_GenericMarshal_Variable_Deref, DUK_VARARGS);
	ILibDuktape_CreateEventWithGetter(ctx, "String", ILibDuktape_GenericMarshal_Variable_Val_STRING);
	ILibDuktape_CreateEventWithGetter(ctx, "AnsiString", ILibDuktape_GenericMarshal_Variable_Val_ASTRING);
	ILibDuktape_CreateEventWithGetter(ctx, "Wide2UTF8", ILibDuktape_GenericMarshal_Variable_Val_UTFSTRING);

	ILibDuktape_CreateEventWithGetter(ctx, "HexString", ILibDuktape_GenericMarshal_Variable_Val_HSTRING);
	ILibDuktape_CreateEventWithGetter(ctx, "HexString2", ILibDuktape_GenericMarshal_Variable_Val_HSTRING2);

	ILibDuktape_CreateInstanceMethod(ctx, "toBuffer", ILibDuktape_GenericMarshal_Variable_toBuffer, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "autoFree", ILibDuktape_GenericMarshal_Variable_autoFree, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "pointerBuffer", ILibDuktape_GenericMarshal_Variable_pointerBuffer, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "getPointerPointer", ILibDuktape_GenericMarshal_Variable_pointerpointer, 0);

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

PTRSIZE ILibDuktape_GenericMarshal_MethodInvoke_Native(int parms, void *fptr, PTRSIZE *vars)
{
	PTRSIZE retVal = 0;

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
	void *chain = ((void**)args)[1];
	PTRSIZE *vars = (PTRSIZE*)((void**)args)[2];
	int parms = (int)(PTRSIZE)((void**)args)[3];
	void *fptr = ((void**)args)[4];
	PTRSIZE retVal = ILibDuktape_GenericMarshal_MethodInvoke_Native(parms, fptr, vars);

	((void**)args)[3] = (void*)retVal;
	ILibChain_RunOnMicrostackThreadEx(chain, ILibDuktape_GenericMarshal_MethodInvoke_ThreadSink_Return, args);

}

#define ILibDuktape_FFI_AsyncDataPtr "\xFF_FFI_AsyncDataPtr"
typedef struct ILibDuktape_FFI_AsyncData
{
	duk_context *ctx;
	void *chain;
	void *workerThread;
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
				ILibChain_RunOnMicrostackThread(data->chain, ILibDuktape_GenericMarshal_MethodInvokeAsync_ChainDispatch, data);
			}
			else
			{
				data->waitingForResult = 0;
				sem_post(&(data->workFinished));
			}
		}
	}
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
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_FFI_AsyncDataPtr);
	if (!ILibMemory_CanaryOK(data)) { return(ILibDuktape_Error(ctx, "FFI_AsyncData was already freed")); }

	if (data != NULL)
	{
		data->abort = 1;
		if (data->promise == NULL)
		{
			// We can gracefully exit this thread
			sem_post(&(data->workAvailable));
#ifdef WIN32
			ILibThread_Join(data->workerThread);
#endif
		}
		else
		{
			if (data->waitingForResult == 0)
			{
				// We cannot gracefully exit the thread, so let's reject the promise, and let the app layer figure it out
				duk_push_heapptr(data->ctx, data->promise);		// [promise]
				duk_get_prop_string(data->ctx, -1, "_REJ");		// [promise][rej]
				duk_swap_top(data->ctx, -2);					// [rej][this]
				duk_push_string(data->ctx, "ABORT");			// [rej][this][abort]
				duk_call_method(data->ctx, 1);
				duk_pop(data->ctx);								// ...

				// We are purposefully not clearing the promise, becuase the hope is that the above layer
				// will receive this rejection, and do a proper cleanup, which may need the promise to accomplish that
			}
			else
			{
				// Invalid scenario
				return(ILibDuktape_Error(ctx, "Cannot abort operation that is marked as 'wait for result'"));
			}
		}
		duk_push_this(ctx);
		sem_destroy(&(data->workAvailable));
		sem_destroy(&(data->workStarted));
		sem_destroy(&(data->workFinished));
		duk_del_prop_string(ctx, -1, ILibDuktape_FFI_AsyncDataPtr);
	}
	return(0);
}
duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_dataFinalizer(duk_context *ctx)
{
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)Duktape_GetBufferProperty(ctx, 0, ILibDuktape_FFI_AsyncDataPtr);

	if (data != NULL && ILibMemory_CanaryOK(data))
	{
		data->abort = 1;
		if (data->promise == NULL)
		{
			data->abort = 1;
			sem_post(&(data->workAvailable));
#ifdef WIN32
			ILibThread_Join(data->workerThread);
#endif
			sem_destroy(&(data->workAvailable));
			sem_destroy(&(data->workStarted));
			sem_destroy(&(data->workFinished));
		}
	}
	return(0);
}

#ifdef WIN32
void __stdcall ILibDuktape_GenericMarshal_MethodInvokeAsync_Done_APC(ULONG_PTR u)
{
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)u;
	duk_context *ctx;
	if (!ILibMemory_CanaryOK(data)) { return; }

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

	QueueUserAPC((PAPCFUNC)ILibDuktape_GenericMarshal_MethodInvokeAsync_Done_APC, data->workFinished, (ULONG_PTR)data);
}
#endif

duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync(duk_context *ctx)
{
	void *redirectionPtr = NULL, *redirectionPtrName = NULL;
	int i;
	int parms = duk_get_top(ctx);
	ILibDuktape_FFI_AsyncData *data = NULL;
	if (parms > 20) { return(ILibDuktape_Error(ctx, "Too many parameters")); }

	if (duk_is_function(ctx, 0))
	{
		data = (ILibDuktape_FFI_AsyncData*)Duktape_GetBufferProperty(ctx, 0, ILibDuktape_FFI_AsyncDataPtr);
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

		duk_eval_string(ctx, "require('promise');");		// [func][promise]
		duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_promise, 2);
		duk_new(ctx, 1);
		ggd->dispatch->promise = duk_get_heapptr(ctx, -1);
		data = (ILibDuktape_FFI_AsyncData*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_FFI_AsyncData));
		duk_put_prop_string(ctx, -2, ILibDuktape_FFI_AsyncDataPtr);

		data->ctx = ctx;
		data->promise = ggd->dispatch->promise;

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
			data = (ILibDuktape_FFI_AsyncData*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_FFI_AsyncDataPtr);
			if (data == NULL)
			{
				data = Duktape_PushBuffer(ctx, sizeof(ILibDuktape_FFI_AsyncData));								// [func][buff]

				duk_push_current_function(ctx);																	// [func][buff][func]
				duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_dataFinalizer, 1);		// [func][buff][func][cfunc]
				duk_set_finalizer(ctx, -2);																		// [func][buff][func]
				duk_pop(ctx);																					// [func][buff]

				duk_put_prop_string(ctx, -2, ILibDuktape_FFI_AsyncDataPtr);										// [func]
				data->ctx = ctx;
				data->chain = Duktape_GetChain(ctx);
				data->fptr = Duktape_GetPointerProperty(ctx, -1, "_address");
				data->methodName = Duktape_GetStringPropertyValue(ctx, -1, "_funcName", NULL);
				sem_init(&(data->workAvailable), 0, 0);
				sem_init(&(data->workStarted), 0, 0);
				sem_init(&(data->workFinished), 0, 0);
				data->workerThread = ILibSpawnNormalThread(ILibDuktape_GenericMarshal_MethodInvokeAsync_WorkerRunLoop, data);
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
			data->vars[i] = (PTRSIZE)duk_require_int(ctx, i);
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
	data = (ILibDuktape_FFI_AsyncData*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_FFI_AsyncDataPtr);
	if (data == NULL)
	{
		data = Duktape_PushBuffer(ctx, sizeof(ILibDuktape_FFI_AsyncData));									// [func][buffer]

		duk_push_this(ctx);																					// [func][buffer][func]
		duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_dataFinalizer, 1);			// [func][buffer][func][finalizer]
		duk_set_finalizer(ctx, -2);																			// [func][buffer][func]
		duk_pop(ctx);																						// [func][buffer]

		duk_put_prop_string(ctx, -2, ILibDuktape_FFI_AsyncDataPtr);											// [func]
		data->ctx = ctx;
		data->chain = Duktape_GetChain(ctx);
		data->fptr = Duktape_GetPointerProperty(ctx, -1, "_address");
		sem_init(&(data->workAvailable), 0, 0);
		sem_init(&(data->workStarted), 0, 0);
		sem_init(&(data->workFinished), 0, 0);
		data->workerThread = ILibSpawnNormalThread(ILibDuktape_GenericMarshal_MethodInvokeAsync_WorkerRunLoop, data);
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
	PTRSIZE *vars = spawnThread == 0 ? ILibMemory_AllocateA(sizeof(PTRSIZE)*parms) : ILibMemory_SmartAllocateEx(sizeof(PTRSIZE)*parms, 5 * sizeof(void*));
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
			vars[i] = (PTRSIZE)duk_require_int(ctx, i);
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
			retVal = ILibDuktape_GenericMarshal_MethodInvoke_Native(parms, fptr, vars);
#ifdef WIN32
			DWORD err = GetLastError();
#endif
			ILibDuktape_GenericMarshal_Variable_PUSH(ctx, (void*)(PTRSIZE)retVal, (int)sizeof(void*));
#ifdef WIN32
			duk_push_int(ctx, err); duk_put_prop_string(ctx, -2, "_LastError");
#endif
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
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_FFI_AsyncDataPtr);
	if (data == NULL) { return(ILibDuktape_Error(ctx, "No thread")); }
	if (!ILibMemory_CanaryOK(data)) { return(ILibDuktape_Error(ctx, "FFI Object was already freed")); }
	ILibDuktape_GenericMarshal_Variable_PUSH(ctx, data->workerThread, sizeof(void*));
	return(1);
}
duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_thread_id(duk_context *ctx)
{
	duk_push_this(ctx);		// [async]
	ILibDuktape_FFI_AsyncData *data = (ILibDuktape_FFI_AsyncData*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_FFI_AsyncDataPtr);
	if (!ILibMemory_CanaryOK(data)) { return(ILibDuktape_Error(ctx, "FFI Object was already freed")); }

	char tmp[255];
	sprintf_s(tmp, sizeof(tmp), "%ul", data->workerThreadId);
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
		module = (void*)LoadLibraryA((LPCSTR)libName);
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
	sprintf_s(tmp, sizeof(tmp), "%ul", data->callingThread);
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
		refList[count++] = data;
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
				ILibChain_RunOnMicrostackThreadEx3(refList[i]->chain, ILibDuktape_GlobalGenericCallback_ProcessEx, ILibDuktape_GlobalGenericCallback_ProcessEx_Abort, user);
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
		while (windispatch->finished == 0) { SleepEx(INFINITE, TRUE); }
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
	void *tmp = NULL;
	if (GlobalCallbackList != NULL)
	{
		ILibLinkedList_Lock(GlobalCallbackList);
		void *node = ILibLinkedList_GetNode_Head(GlobalCallbackList);
		while (node != NULL)
		{
			Duktape_GlobalGeneric_Data *data = (Duktape_GlobalGeneric_Data*)ILibLinkedList_GetDataFromNode(node);
			if (data->chain == Duktape_GetChain(ctx))
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
		if (ILibLinkedList_GetCount(GlobalCallbackList) == 0) { tmp = GlobalCallbackList; }
		ILibLinkedList_UnLock(GlobalCallbackList);
		if (tmp != NULL)
		{
			GlobalCallbackList = NULL;
		}
	}
	if (tmp != NULL) { ILibLinkedList_Destroy(tmp); }
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
	sprintf_s(tmp, sizeof(tmp), "%ul", pthread_self());
#endif
	duk_push_string(ctx, tmp);
	return(1);
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
	ILibDuktape_CreateInstanceMethod(ctx, "WrapObject", ILibDuktape_GenericMarshal_WrapObject, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "UnWrapObject", ILibDuktape_GenericMarshal_UnWrapObject, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "StashObject", ILibDuktape_GenericMarshal_StashObject, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "UnstashObject", ILibDuktape_GenericMarshal_UnstashObject, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "ObjectToPtr", ILibDuktape_GenericMarshal_ObjectToPtr, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "GetCurrentThread", ILibDuktape_GenericMarshal_GetCurrentThread, 0);

	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "_VarSize", 4, "CreateInteger", ILibDuktape_GenericMarshal_CreateVariableEx, 0);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "_VarSize", ((int)sizeof(void*)), "CreatePointer", ILibDuktape_GenericMarshal_CreateVariableEx, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "_VarSize", 2, "CreateShort", ILibDuktape_GenericMarshal_CreateVariableEx, 0);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_GenericMarshal_Finalizer);

	duk_push_int(ctx, sizeof(Duktape_MarshalledObject));
	ILibDuktape_CreateReadonlyProperty(ctx, "WrappedObjectLength");
	duk_push_int(ctx, sizeof(void*));
	ILibDuktape_CreateReadonlyProperty(ctx, "PointerSize");
}

void ILibDuktape_GenericMarshal_init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "_GenericMarshal", ILibDuktape_GenericMarshal_Push);
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
