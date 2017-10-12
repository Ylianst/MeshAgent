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


#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "duktape.h"
#include "ILibDuktape_GenericMarshal.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_Helpers.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibCrypto.h"
#include "microstack/ILibRemoteLogging.h"

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

typedef struct Duktape_GenericMarshal_Proxy
{
	duk_context *ctx;
	void *jsCallbackPtr;
	void *jsProxyObject;
}Duktape_GenericMarshal_Proxy;

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
	char hexString[255];

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
	wcstombs_s(&s, astr, sizeof(astr), (const wchar_t*)ptr, size);
	duk_push_string(ctx, (char*)astr);
#else
	duk_push_lstring(ctx, (const char*)ptr, size);
#endif
	return 1;
}

duk_ret_t ILibDuktape_GenericMarshal_Variable_Val_GET(duk_context *ctx)
{
	void *ptr;
	int size;

	duk_push_this(ctx);							// [var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [var][ptr]
	ptr = duk_to_pointer(ctx, -1);
	duk_get_prop_string(ctx, -2, "_size");		// [var][ptr][size]
	size = duk_to_int(ctx, -1);
	
	switch (size)
	{
	case 2:
		duk_push_int(ctx, (int)((unsigned short*)ptr)[0]);
		break;
	case 4:
		duk_push_int(ctx, (int)((unsigned int*)ptr)[0]);
		break;
	case 8:
#if UINTPTR_MAX == 0xffffffffffffffff
		duk_push_pointer(ctx, (void*)((uint64_t*)ptr)[0]);
#else
		return(ILibDuktape_Error(ctx, "GenericMarshal.get(): Cannot get 64bit value on 32bit platform"));
#endif
		break;
	default:
		duk_push_int(ctx, 0);
		break;
	}

	return 1;
}

duk_ret_t ILibDuktape_GenericMarshal_Variable_Val_SET(duk_context *ctx)
{
	void *ptr;
	int size;
	int value = duk_require_int(ctx, 0);

	duk_push_this(ctx);							// [var]
	duk_get_prop_string(ctx, -1, "_ptr");		// [var][ptr]
	ptr = duk_to_pointer(ctx, -1);
	duk_get_prop_string(ctx, -2, "_size");		// [var][ptr][size]
	size = duk_to_int(ctx, -1);

	switch (size)
	{
		case 2:
			((unsigned short*)ptr)[0] = (unsigned short)value;
			break;
		case 4:
			((unsigned int*)ptr)[0] = (unsigned int)value;
			break;
		default:
			duk_push_string(ctx, "UNSUPPORTED VAL SIZE");
			duk_throw(ctx);
			return(DUK_RET_ERROR);
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
		duk_push_string(ctx, "Invalid Variable"); duk_throw(ctx); return(DUK_RET_ERROR);
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
		duk_push_string(ctx, "Invalid Variable"); duk_throw(ctx); return(DUK_RET_ERROR);
	}
	return 0;
}
void ILibDuktape_GenericMarshal_Variable_PUSH(duk_context *ctx, void *ptr, int size)
{
	duk_push_object(ctx);						// [var]
	duk_push_pointer(ctx, ptr);					// [var][ptr]
	duk_put_prop_string(ctx, -2, "_ptr");		// [var]
	duk_push_int(ctx, size);					// [var][size]
	duk_put_prop_string(ctx, -2, "_size");		// [var]


	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "Val", ILibDuktape_GenericMarshal_Variable_Val_GET, ILibDuktape_GenericMarshal_Variable_Val_SET);
	ILibDuktape_CreateEventWithGetterAndSetterWithIntMetaData(ctx, "_VarSize", 4, "IntVal", ILibDuktape_GenericMarshal_Variable_GetEx, ILibDuktape_GenericMarshal_Variable_SetEx);
	ILibDuktape_CreateEventWithGetterAndSetterWithIntMetaData(ctx, "_VarSize", 2, "ShortVal", ILibDuktape_GenericMarshal_Variable_GetEx, ILibDuktape_GenericMarshal_Variable_SetEx);

	ILibDuktape_CreateInstanceMethod(ctx, "Deref", ILibDuktape_GenericMarshal_Variable_Deref, DUK_VARARGS);
	ILibDuktape_CreateEventWithGetter(ctx, "String", ILibDuktape_GenericMarshal_Variable_Val_STRING);
	ILibDuktape_CreateEventWithGetter(ctx, "AnsiString", ILibDuktape_GenericMarshal_Variable_Val_ASTRING);
	ILibDuktape_CreateEventWithGetter(ctx, "HexString", ILibDuktape_GenericMarshal_Variable_Val_HSTRING);
	ILibDuktape_CreateEventWithGetter(ctx, "HexString2", ILibDuktape_GenericMarshal_Variable_Val_HSTRING2);
}
duk_ret_t ILibDuktape_GenericMarshal_Variable_Finalizer(duk_context *ctx)
{
	void *ptr = NULL;
	if (duk_has_prop_string(ctx, 0, "_ptr"))
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
duk_ret_t ILibDuktape_GenericMarshal_CreateVariable(duk_context *ctx)
{
	char* ptr;
	int size = duk_require_int(ctx, 0);

	ptr = (char*)ILibMemory_Allocate(size, 0, NULL, NULL);
	ILibDuktape_GenericMarshal_Variable_PUSH(ctx, ptr, size);							// [var]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_GenericMarshal_Variable_Finalizer);

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
			duk_push_string(ctx, "More than 9 parameters in the callback isn't supported yet");
			duk_throw(ctx);
			return(DUK_RET_ERROR);
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
	duk_push_fixed_buffer(ctx, sizeof(Duktape_GenericMarshal_Proxy));		// [proxy][buffer]
	ptr = (Duktape_GenericMarshal_Proxy*)Duktape_GetBuffer(ctx, -1, NULL);
	memset(ptr, 0, sizeof(Duktape_GenericMarshal_Proxy));
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

duk_ret_t ILibDuktape_GenericMarshal_MethodInvoke(duk_context *ctx)
{
	void *fptr = NULL;
	int parms = duk_get_top(ctx);
	int i;
	PTRSIZE vars[10];
	int retVal = -1;

	duk_push_current_function(ctx);					// [func]
	duk_get_prop_string(ctx, -1, "_address");		// [func][addr]
	fptr = duk_to_pointer(ctx, -1);

	if (fptr == NULL)
	{
		duk_push_string(ctx, "INVALID METHOD");
		duk_throw(ctx);
		return(DUK_RET_ERROR);
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
			duk_push_string(ctx, "INVALID PARAMETER");
			duk_throw(ctx);
			return(DUK_RET_ERROR);
		}
	}

	switch (parms)
	{
	case 0:
		retVal = (int)((R0)fptr)();
		break;
	case 1:
		retVal = (int)((R1)fptr)(vars[0]);
		break;
	case 2:
		retVal = (int)((R2)fptr)(vars[0], vars[1]);
		break;
	case 3:
		retVal = (int)((R3)fptr)(vars[0], vars[1], vars[2]);
		break;
	case 4:
		retVal = (int)((R4)fptr)(vars[0], vars[1], vars[2], vars[3]);
		break;
	case 5:
		retVal = (int)((R5)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4]);
		break;
	case 6:
		retVal = (int)((R6)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5]);
		break;
	case 7:
		retVal = (int)((R7)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6]);
		break;
	case 8:
		retVal = (int)((R8)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7]);
		break;
	case 9:
		retVal = (int)((R9)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8]);
		break;
	case 10:
		retVal = (int)((R10)fptr)(vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7], vars[8], vars[9]);
		break;
	default:
		duk_push_string(ctx, "INVALID NUMBER OF PARAMETERS, MAX of 10");
		duk_throw(ctx);
		return(DUK_RET_ERROR);
	}

	duk_push_int(ctx, retVal);
	return 1;
}
duk_ret_t ILibDuktape_GenericMarshal_CreateMethod(duk_context *ctx)
{
	void* module = NULL;
	char* funcName = (char*)duk_require_string(ctx, 0);
	void* funcAddress = NULL;
	char* exposedMethod = duk_get_top(ctx) == 1 ? funcName : (char*)duk_require_string(ctx, 1);

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
		char errstr[4096];
		sprintf_s(errstr, sizeof(errstr), "CreateMethod Error: Method Name [%s] Not Found", funcName);
		duk_push_string(ctx, errstr);
		duk_throw(ctx);
		return(DUK_RET_ERROR);
	}


	duk_push_c_function(ctx, ILibDuktape_GenericMarshal_MethodInvoke, DUK_VARARGS);		// [obj][func]
	duk_push_pointer(ctx, funcAddress);													// [obj][func][addr]
	duk_put_prop_string(ctx, -2, "_address");											// [obj][func]
	duk_put_prop_string(ctx, -2, exposedMethod);										// [obj]

	return 0;
}
duk_ret_t ILibDuktape_GenericMarshal_CreateNativeProxy(duk_context *ctx)
{
	void* module = NULL;
	char* libName = duk_is_string(ctx, 0) ? (char*)duk_require_string(ctx, 0) : NULL;

#ifdef WIN32
	module = (void*)LoadLibraryA((LPCSTR)libName);
#else
	module = dlopen(libName, RTLD_NOW);
#endif

	if (module == NULL)
	{
#ifdef WIN32
		duk_push_string(ctx, "Could not create Native Proxy");
#else
		duk_push_string(ctx, dlerror());
#endif
		duk_throw(ctx);
		return(DUK_RET_ERROR);
	}

	duk_push_object(ctx);																							// [obj]
	duk_push_pointer(ctx, module);																					// [obj][module]
	duk_put_prop_string(ctx, -2, "_moduleAddress");																	// [obj]
	ILibDuktape_CreateInstanceMethod(ctx, "CreateMethod", ILibDuktape_GenericMarshal_CreateMethod, DUK_VARARGS);	// [obj]

	return 1;
}
duk_ret_t ILibDuktape_GenericMarshal_CreateVariableEx(duk_context *ctx)
{
	char* ptr;
	int size;
	duk_push_current_function(ctx);														// [func]
	duk_get_prop_string(ctx, -1, "_VarSize");											// [func][size]
	size = duk_to_int(ctx, -1);

	ptr = (char*)ILibMemory_Allocate(size, 0, NULL, NULL);
	ILibDuktape_GenericMarshal_Variable_PUSH(ctx, ptr, size);							// [func][size][var]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_GenericMarshal_Variable_Finalizer);

	return 1;
}
void ILibDuktape_GenericMarshal_Push(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);				// [obj]

	ILibDuktape_CreateInstanceMethod(ctx, "CreateVariable", ILibDuktape_GenericMarshal_CreateVariable, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "CreateCallbackProxy", ILibDuktape_GenericMarshal_CreateCallbackProxy, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "CreateNativeProxy", ILibDuktape_GenericMarshal_CreateNativeProxy, 1);

	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "_VarSize", 4, "CreateInteger", ILibDuktape_GenericMarshal_CreateVariableEx, 0);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "_VarSize", ((int)sizeof(void*)), "CreatePointer", ILibDuktape_GenericMarshal_CreateVariableEx, 0);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "_VarSize", 2, "CreateShort", ILibDuktape_GenericMarshal_CreateVariableEx, 0);
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