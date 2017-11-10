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

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "duktape.h"
#include "microstack/ILibParsers.h"
#include "ILibDuktape_Helpers.h"
#include "ILibParsers_Duktape.h"
#include "microstack/ILibCrypto.h"
#include "ILibDuktape_EventEmitter.h"

char stash_key[32];
struct sockaddr_in6 duktape_internalAddress;

#define ILibDuktape_EventEmitter_Table						"\xFF_EventEmitterTable"
#define ILibDuktape_Process_ExitCode						"\xFF_ExitCode"
#define ILibDuktape_Memory_AllocTable						"\xFF_MemoryAllocTable"
#define ILibDuktape_ObjectStashKey							"\xFF_ObjectStashKey"

void ILibDuktape_Push_ObjectStash(duk_context *ctx)
{
	if (duk_has_prop_string(ctx, -1, ILibDuktape_ObjectStashKey))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_ObjectStashKey);	// [obj][stash]
	}
	else
	{
		duk_push_object(ctx);										// [obj][stash]
		duk_dup(ctx, -1);											// [obj][stash][stash]
		duk_put_prop_string(ctx, -3, ILibDuktape_ObjectStashKey);	// [obj][stash]
	}
}
duk_ret_t ILibDuktape_Error(duk_context *ctx, char *format, ...)
{
	char dest[4096];
	int len = 0;
	va_list argptr;

	va_start(argptr, format);
	len += vsnprintf(dest + len, sizeof(dest) - len, format, argptr);
	va_end(argptr);

	duk_push_string(ctx, dest);
	duk_throw(ctx);

	return DUK_RET_ERROR;
}
int Duktape_GetBooleanProperty(duk_context *ctx, duk_idx_t i, char *propertyName, int defaultValue)
{
	int retVal = defaultValue;
	if (duk_has_prop_string(ctx, i, propertyName))
	{
		duk_get_prop_string(ctx, i, propertyName);
		retVal = (int)duk_get_boolean(ctx, -1);
		duk_pop(ctx);
	}
	return retVal;
}
void *Duktape_GetHeapptrProperty(duk_context *ctx, duk_idx_t i, char* propertyName)
{
	void *retVal = NULL;
	if (duk_has_prop_string(ctx, i, propertyName))
	{
		duk_get_prop_string(ctx, i, propertyName);
		retVal = duk_get_heapptr(ctx, -1);
		duk_pop(ctx);
	}
	return retVal;
}
void *Duktape_GetPointerProperty(duk_context *ctx, duk_idx_t i, char* propertyName)
{
	void *retVal = NULL;
	if (duk_has_prop_string(ctx, i, propertyName))
	{
		duk_get_prop_string(ctx, i, propertyName);
		retVal = duk_to_pointer(ctx, -1);
		duk_pop(ctx);
	}
	return retVal;
}

char* Duktape_GetStringPropertyValueEx(duk_context *ctx, duk_idx_t i, char* propertyName, char* defaultValue, duk_size_t *len)
{
	char *retVal = defaultValue;
	if (duk_has_prop_string(ctx, i, propertyName))
	{
		duk_get_prop_string(ctx, i, propertyName);
		retVal = (char*)duk_get_lstring(ctx, -1, len);
		duk_pop(ctx);
	}
	else
	{
		if (len != NULL) { *len = (defaultValue == NULL) ? 0 : strnlen_s(defaultValue, sizeof(ILibScratchPad)); }
	}
	return retVal;
}
int Duktape_GetIntPropertyValue(duk_context *ctx, duk_idx_t i, char* propertyName, int defaultValue)
{
	int retVal = defaultValue;
	if (duk_has_prop_string(ctx, i, propertyName))
	{
		duk_get_prop_string(ctx, i, propertyName);
		retVal = duk_to_int(ctx, -1);
		duk_pop(ctx);
	}
	return retVal;
}
void Duktape_CreateEnum(duk_context *ctx, char* enumName, char** fieldNames, int * fieldValues, int numFields)
{
	int i;
	duk_push_global_object(ctx);						// [global]
	duk_push_object(ctx);								// [global][obj]

	for (i = 0; i < numFields; ++i)
	{
		duk_push_int(ctx, fieldValues[i]);				// [global][obj][val]
		duk_put_prop_string(ctx, -2, fieldNames[i]);	// [global][obj]
	}
	duk_put_prop_string(ctx, -2, enumName);				// [global]

	duk_pop(ctx);
}
char *Duktape_GetStashKey(void* value)
{
	sprintf_s(stash_key, sizeof(stash_key), "%p", value);
	return((char*)stash_key);
}

char* Duktape_GetBuffer(duk_context *ctx, duk_idx_t i, duk_size_t *bufLen)
{
	char *retVal = NULL;
	if (bufLen != NULL) { *bufLen = 0; }

	if (duk_is_string(ctx, i))
	{
		retVal = (char*)duk_get_lstring(ctx, i, bufLen);
	}
	else if (duk_is_buffer(ctx, i))
	{
		retVal = (char*)duk_require_buffer(ctx, i,bufLen);
	}
	else if(duk_is_buffer_data(ctx, i))
	{
		retVal = (char*)duk_require_buffer_data(ctx, i, bufLen);
	}
	else if (duk_is_object(ctx, i))
	{
		duk_json_encode(ctx, i);
		retVal = (char*)duk_get_lstring(ctx, i, bufLen);
	}
	else
	{
		ILibDuktape_Error(ctx, "Duktape_GetBuffer(): Unknown parameter");
	}
	return retVal;
}
struct sockaddr_in6* Duktape_IPAddress4_FromString(char* address, unsigned short port)
{
	memset(&duktape_internalAddress, 0, sizeof(struct sockaddr_in6));

	duktape_internalAddress.sin6_family = AF_INET;
	duktape_internalAddress.sin6_port = htons(port);

	ILibInet_pton(AF_INET, address, &(((struct sockaddr_in*)&duktape_internalAddress)->sin_addr));
	return(&duktape_internalAddress);
}
struct sockaddr_in6* Duktape_IPAddress6_FromString(char* address, unsigned short port)
{
	memset(&duktape_internalAddress, 0, sizeof(struct sockaddr_in6));

	duktape_internalAddress.sin6_family = AF_INET6;
	duktape_internalAddress.sin6_port = htons(port);

	ILibInet_pton(AF_INET6, address, &(duktape_internalAddress.sin6_addr));
	return(&duktape_internalAddress);
}
void ILibDuktape_SockAddrToOptions(duk_context *ctx, struct sockaddr_in6 *addr)
{
	char *str = ILibInet_ntop2((struct sockaddr*)addr, ILibScratchPad, sizeof(ILibScratchPad));
	unsigned short port = ntohs(addr->sin6_port);

	duk_push_object(ctx);					// [options]
	duk_push_string(ctx, str);				// [options][host]
	duk_put_prop_string(ctx, -2, "host");	// [options]
	duk_push_int(ctx, (int)port);			// [options][port]
	duk_put_prop_string(ctx, -2, "port");	// [options]
}
duk_ret_t ILibDuktape_CreateEventWithSetter_SetterSink(duk_context *ctx)
{
	void **ptr;
	char *name;

	duk_push_current_function(ctx);			// [func]
	duk_get_prop_string(ctx, -1, "_ptr");	// [func][ptr]
	ptr = (void**)duk_to_pointer(ctx, -1);	// [func][ptr]
	duk_get_prop_string(ctx, -2, "_pname");	// [func][ptr][pname]
	name = (char*)duk_to_string(ctx, -1);	// [func][ptr][pname]

	duk_push_this(ctx);						// [obj]
	duk_dup(ctx, 0);						// [obj][handler]
	duk_put_prop_string(ctx, -2, name);		// [obj]

	*ptr = !duk_is_null_or_undefined(ctx, 0) ? duk_require_heapptr(ctx, 0) : NULL;
	return 0;
}
duk_ret_t ILibDuktape_CreateEventWithGetterExSink(duk_context *ctx)
{
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "\xFF_return");
	return 1;
}
void ILibDuktape_CreateEventWithGetterEx(duk_context *ctx, char *propName, void *heapptr)
{
	duk_push_string(ctx, propName);																	// [obj][prop]
	duk_push_c_function(ctx, ILibDuktape_CreateEventWithGetterExSink, 1);							// [obj][prop][func]												// [obj][prop][getFunc]
	duk_push_heapptr(ctx, heapptr);																	// [obj][prop][func][ptr]
	duk_put_prop_string(ctx, -2, "\xFF_return");													// [obj][prop][func]
	duk_def_prop(ctx, -3, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_GETTER);								// [obj]
}
void ILibDuktape_CreateEventWithGetter(duk_context *ctx, char *propName, duk_c_function getterMethod)
{
	duk_push_string(ctx, propName);																	// [obj][prop]
	duk_push_c_function(ctx, getterMethod, 1);														// [obj][prop][getFunc]
	duk_def_prop(ctx, -3, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_GETTER);								// [obj]
}

void ILibDuktape_CreateEventWithGetterAndSetterEx(duk_context *ctx, char *propName, duk_c_function getterMethod, duk_c_function setterMethod)
{
	duk_push_string(ctx, propName);																	// [obj][prop]
	duk_push_c_function(ctx, getterMethod, 1);														// [obj][prop][getFunc]
	duk_push_c_function(ctx, setterMethod, 1);														// [obj][prop][getFunc][setFunc]

	duk_def_prop(ctx, -4, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_GETTER | DUK_DEFPROP_HAVE_SETTER);	// [obj]
}
void ILibDuktape_CreateEventWithGetterAndSetterWithMetaData(duk_context *ctx, char* metaDataPropName, duk_idx_t metaDataPropIndex, char *propName, duk_c_function getterMethod, duk_c_function setterMethod)
{
	duk_dup(ctx, metaDataPropIndex);																// [obj][metaData]
	if (metaDataPropIndex < 0)
	{
		duk_remove(ctx, metaDataPropIndex - 1);
	}

	duk_push_string(ctx, propName);																	// [obj][metaData][prop]
	duk_swap_top(ctx, -2);																			// [obj][prop][metaData]
	duk_push_c_function(ctx, getterMethod, 1);														// [obj][prop][metaData][getFunc]
	duk_swap_top(ctx, -2);																			// [obj][prop][getFunc][metaData]
	duk_dup(ctx, -1);																				// [obj][prop][getFunc][metaData][metaData]
	duk_put_prop_string(ctx, -3, metaDataPropName);													// [obj][prop][getFunc][metaData]
	duk_push_c_function(ctx, setterMethod, 1);														// [obj][prop][getFunc][metaData][setFunc]
	duk_swap_top(ctx, -2);																			// [obj][prop][getFunc][setFunc][metaData]
	duk_put_prop_string(ctx, -2, metaDataPropName);													// [obj][prop][getFunc][setFunc]

	duk_def_prop(ctx, -4, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_GETTER | DUK_DEFPROP_HAVE_SETTER);	// [obj]
}
void ILibDuktape_CreateEventWithGetterAndSetter(duk_context *ctx, char *propName, char *propNamePtr, void **hptr, duk_c_function getterMethod)
{
	duk_push_string(ctx, propName);																			// [obj][prop]
	duk_push_c_function(ctx, getterMethod, 1);																// [obj][prop][getFunc]
	duk_push_c_function(ctx, ILibDuktape_CreateEventWithSetter_SetterSink, 1);								// [obj][prop][getFunc][setFunc]
	duk_push_pointer(ctx, hptr);																			// [obj][prop][getFunc][setFunc][ptr]
	duk_put_prop_string(ctx, -2, "_ptr");																	// [obj][prop][getFunc][setFunc]
	duk_push_string(ctx, propNamePtr);																		// [obj][prop][getFunc][setFunc][name]
	duk_put_prop_string(ctx, -2, "_pname");																	// [obj][prop][getFunc][setFunc]
	duk_def_prop(ctx, -4, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_GETTER | DUK_DEFPROP_HAVE_SETTER);			// [obj]
}
void ILibDuktape_CreateEventWithSetterEx(duk_context *ctx, char *propName, duk_c_function setterMethod)
{
	duk_push_string(ctx, propName);																	// [obj][prop]
	duk_push_c_function(ctx, setterMethod, 1);														// [obj][prop][setFunc]
	duk_push_string(ctx, propName);																	// [obj][prop][setFunc][name]
	duk_put_prop_string(ctx, -2, "name");															// [obj][prop][setFunc]
	duk_def_prop(ctx, -3, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_SETTER);								// [obj]
}
void ILibDuktape_CreateEventWithSetter(duk_context *ctx, char *propName, char *propNamePtr, void **hptr)
{
	duk_push_string(ctx, propName);												// [obj][setter]
	duk_push_c_function(ctx, ILibDuktape_CreateEventWithSetter_SetterSink, 1);	// [obj][setter][func]
	duk_push_pointer(ctx, hptr);												// [obj][setter][func][ptr]
	duk_put_prop_string(ctx, -2, "_ptr");										// [obj][setter][func]
	duk_push_string(ctx, propNamePtr);											// [obj][setter][func][name]
	duk_put_prop_string(ctx, -2, "_pname");										// [obj][setter][func]
	duk_def_prop(ctx, -3, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_SETTER);			// [obj]
	
}
duk_ret_t ILibDuktape_Helper_AddHeapFinalizerSink(duk_context *ctx)
{
	ILibDuktape_HelperEvent handler;
	void *user;

	duk_dup(ctx, 0);												// [obj]
	duk_get_prop_string(ctx, -1, "handler");						// [obj][handler]
	handler = (ILibDuktape_HelperEvent)duk_get_pointer(ctx, -1);
	duk_get_prop_string(ctx, -2, "user");							// [obj][handler][user]
	user = duk_get_pointer(ctx, -1);

	if (handler != NULL) { handler(ctx, user); }
	return 0;
}
void ILibDuktape_Helper_AddHeapFinalizer(duk_context *ctx, ILibDuktape_HelperEvent handler, void *user)
{
	char *key = Duktape_GetStashKey(user != NULL ? user : (void*)handler);

	duk_push_heap_stash(ctx);				// [g]
	duk_push_object(ctx);					// [g][obj]
	duk_push_pointer(ctx, user);			// [g][obj][user]
	duk_put_prop_string(ctx, -2, "user");	// [g][obj]
	duk_push_pointer(ctx, handler);			// [g][obj][handler]
	duk_put_prop_string(ctx, -2, "handler");// [g][obj]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_Helper_AddHeapFinalizerSink);
	
	duk_put_prop_string(ctx, -2, key);		// [g]
	duk_pop(ctx);							// ...
}

int ILibDuktape_Process_GetExitCode(duk_context *ctx)
{
	int retVal = 0;
	duk_push_global_object(ctx);											// [g]
	if (duk_has_prop_string(ctx, -1, "process"))
	{
		duk_get_prop_string(ctx, -1, "process");							// [g][process]
		if (duk_has_prop_string(ctx, -1, ILibDuktape_Process_ExitCode))
		{
			duk_get_prop_string(ctx, -1, ILibDuktape_Process_ExitCode);		// [g][process][code]
			retVal = (int)duk_get_int(ctx, -1);
			duk_pop(ctx);													// [g][process]
		}
		duk_pop(ctx);														// [g]
	}
	duk_pop(ctx);															// ...
	return(retVal);
}

ILibDuktape_EventEmitter *ILibDuktape_Process_GetEventEmitter(duk_context *ctx)
{
	ILibDuktape_EventEmitter *retVal = NULL;
	duk_push_global_object(ctx);					// [g]
	if (duk_has_prop_string(ctx, -1, "process"))
	{
		duk_get_prop_string(ctx, -1, "process");	// [g][process]
		retVal = ILibDuktape_EventEmitter_GetEmitter_fromCurrent(ctx);
		duk_pop(ctx);								// [g]
	}
	duk_pop(ctx);									// ...
	return retVal;
}

void *ILibDuktape_GetProcessObject(duk_context *ctx)
{
	void *retVal = NULL;
	duk_push_global_object(ctx);					// [g]
	if (duk_has_prop_string(ctx, -1, "process"))
	{
		duk_get_prop_string(ctx, -1, "process");	// [g][process]
		retVal = duk_get_heapptr(ctx, -1);
		duk_pop(ctx);								// [g]
	}
	duk_pop(ctx);									// ...
	return retVal;
}

void ILibDuktape_SetNativeUncaughtExceptionHandler(duk_context * ctx, ILibDuktape_NativeUncaughtExceptionHandler handler, void * user)
{
	void *j = ILibDuktape_GetProcessObject(ctx);
	
	if (j != NULL)
	{
		duk_push_heapptr(ctx, j);													// [process]
		duk_push_pointer(ctx, handler);												// [process][handler]
		duk_put_prop_string(ctx, -2, ILibDuktape_NativeUncaughtExceptionPtr);		// [process]
		duk_push_pointer(ctx, user);												// [process][user]
		duk_put_prop_string(ctx, -2, ILibDuktape_NativeUncaughtExceptionUserPtr);	// [process]
		duk_pop(ctx);																// ...
	}
}
duk_ret_t ILibDuktape_Process_UncaughtExceptionExGetter(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "\xFF_customMessage");
	return 1;
}
void ILibDuktape_Process_UncaughtExceptionEx(duk_context *ctx, char *format, ...)
{
	char dest[4096];
	int len = 0;
	va_list argptr;
	duk_size_t errmsgLen;
	char *errmsg = (char*)duk_safe_to_lstring(ctx, -1, &errmsgLen);
	void *j = ILibDuktape_GetProcessObject(ctx);
	ILibDuktape_EventEmitter *emitter;

	if (strcmp(errmsg, "Process.exit() forced script termination") == 0) { return; }

	duk_push_heapptr(ctx, j);															// [process]
	emitter = ILibDuktape_EventEmitter_GetEmitter_fromCurrent(ctx);
	duk_pop(ctx);																		// ...

	va_start(argptr, format);
	len += vsnprintf(dest + len, sizeof(dest) - len, format, argptr);
	va_end(argptr);

	if (errmsgLen + len < sizeof(dest))
	{
		len += sprintf_s(dest + len, sizeof(dest) - len, " => %s", errmsg);
	}

	if (j != NULL)
	{
		duk_push_heapptr(ctx, j);														// [process]
		if (duk_has_prop_string(ctx, -1, ILibDuktape_NativeUncaughtExceptionPtr))
		{
			duk_get_prop_string(ctx, -1, ILibDuktape_NativeUncaughtExceptionPtr);		// [process][ptr]
			duk_get_prop_string(ctx, -2, ILibDuktape_NativeUncaughtExceptionUserPtr);	// [process][ptr][user]
			((ILibDuktape_NativeUncaughtExceptionHandler)duk_get_pointer(ctx, -2))(ctx, (char*)dest, duk_get_pointer(ctx, -1));
			duk_pop_2(ctx);																// [process]
		}
		duk_pop(ctx);																	// ...
	}

	if (emitter != NULL)
	{
		duk_push_heapptr(emitter->ctx, emitter->object);								// [process]
		duk_get_prop_string(emitter->ctx, -1, "emit");									// [process][emit]
		duk_swap_top(emitter->ctx, -2);													// [emit][this]
		duk_push_string(emitter->ctx, "uncaughtException");								// [emit][this][eventName]
		duk_push_error_object(emitter->ctx, DUK_ERR_UNCAUGHT_ERROR, "%s", dest);
		duk_pcall_method(emitter->ctx, 2);
		duk_pop(emitter->ctx);															// ...
	}
}
// Error MUST be at top of stack when calling this method
void ILibDuktape_Process_UncaughtException(duk_context *ctx)
{
	ILibDuktape_Process_UncaughtExceptionEx(ctx, "");
}
char* Duktape_GetContextGuidHex(duk_context *ctx)
{
	char *retVal = NULL;

	duk_push_heap_stash(ctx);												// [stash]
	if (duk_has_prop_string(ctx, -1, "\xFF_ScriptContainerSettings_DB"))
	{
		duk_get_prop_string(ctx, -1, "\xFF_ScriptContainerSettings_DB");	// [stash][db]
		if (duk_get_pointer(ctx, -1) != NULL) { retVal = "0"; }
		duk_pop(ctx);														// [stash]
	}
	duk_pop(ctx);															// ...
	return retVal;
}
void *Duktape_GetChain(duk_context *ctx)
{
	void *retVal = NULL;
	duk_push_heap_stash(ctx);										// [stash]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_Context_Chain))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_Context_Chain);	// [stash][ptr]
		retVal = duk_get_pointer(ctx, -1);
		duk_pop_2(ctx);												// ...
	}
	else
	{
		duk_pop(ctx);												// ...
	}
	return retVal;
}
duk_ret_t ILibDuktape_ExternalEventEmitter(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *name = (char*)duk_require_string(ctx, 0);
	void **hptr;
	int i;

	duk_push_this(ctx);												// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_Table);	// [obj][table]
	if (!duk_has_prop_string(ctx, -1, name))
	{
		return(ILibDuktape_Error(ctx, "ExternalEventEmitter(): Event '%s' not found", name));
	}
	duk_get_prop_string(ctx, -1, name);								// [obj][table][ptr]
	hptr = (void**)duk_get_pointer(ctx, -1);
	if (*hptr != NULL)
	{
		duk_push_heapptr(ctx, *hptr);								// [func]
		duk_push_this(ctx);											// [func][this]
		for (i = 1; i < nargs; ++i)
		{
			duk_dup(ctx, i);										// [func][this][...]
		}
		if (duk_pcall_method(ctx, nargs - 1) != 0) { ILibDuktape_Process_UncaughtException(ctx); }
		duk_pop(ctx);												// ...
	}
	return 0;
}

duk_ret_t ILibDuktape_IndependentFinalizer_Dispatch(duk_context *ctx)
{
	ILibDuktape_IndependentFinalizerHandler handler;
	duk_get_prop_string(ctx, 0, "ptr");
	duk_get_prop_string(ctx, 0, "parent");

	handler = (ILibDuktape_IndependentFinalizerHandler)duk_get_pointer(ctx, -2);
	handler(ctx, duk_get_heapptr(ctx, -1));
	return 0;
}
void ILibDuktape_CreateIndependentFinalizer(duk_context *ctx, ILibDuktape_IndependentFinalizerHandler handler)
{
	char tmp[255];

	duk_push_object(ctx);															// [obj]
	duk_push_pointer(ctx, handler);													// [obj][ptr]
	duk_put_prop_string(ctx, -2, "ptr");											// [obj]
	duk_dup(ctx, -2);																// [obj][parent]
	duk_put_prop_string(ctx, -2, "parent");											// [obj]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_IndependentFinalizer_Dispatch);
	sprintf_s(tmp, sizeof(tmp), "\xFF_%s", Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));
	duk_put_prop_string(ctx, -2, tmp);
}
duk_ret_t ILibDuktape_CreateProperty_InstanceMethod_Sink(duk_context *ctx)
{
	duk_push_current_function(ctx);				// [func]
	duk_get_prop_string(ctx, -1, "actualFunc");	// [func][actualFunc]
	return 1;
}
void ILibDuktape_CreateProperty_InstanceMethodEx(duk_context *ctx, char *methodName, void *funcHeapPtr)
{
	duk_push_string(ctx, methodName);														// [obj][prop]
	duk_push_c_function(ctx, ILibDuktape_CreateProperty_InstanceMethod_Sink, 1);			// [obj][prop][getFunc]
	duk_push_heapptr(ctx, funcHeapPtr);														// [obj][prop][getFunc][func]
	duk_put_prop_string(ctx, -2, "actualFunc");												// [obj][prop][getFunc]
	duk_def_prop(ctx, -3, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_GETTER);						// [obj]
}
void ILibDuktape_CreateProperty_InstanceMethod(duk_context *ctx, char *methodName, duk_c_function impl, duk_idx_t argCount)
{
	duk_push_string(ctx, methodName);														// [obj][prop]
	duk_push_c_function(ctx, ILibDuktape_CreateProperty_InstanceMethod_Sink, 1);			// [obj][prop][getFunc]
	duk_push_c_function(ctx, impl, argCount);												// [obj][prop][getFunc][func]
	duk_put_prop_string(ctx, -2, "actualFunc");												// [obj][prop][getFunc]
	duk_def_prop(ctx, -3, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_GETTER);						// [obj]
}

duk_ret_t ILibDuktape_ReadonlyProperty_Get(duk_context *ctx)
{
	duk_push_current_function(ctx);						// [getFunc]
	duk_get_prop_string(ctx, -1, "\xFF_PropValue");		// [getFunc][value]
	return 1;
}
void ILibDuktape_CreateReadonlyProperty(duk_context *ctx, char *propName)
{																									// [obj][value]
	duk_push_string(ctx, propName);																	// [obj][value][prop]
	duk_swap_top(ctx, -2);																			// [obj][prop][value]
	duk_push_c_function(ctx, ILibDuktape_ReadonlyProperty_Get, 1);									// [obj][prop][value][getFunc]
	duk_swap_top(ctx, -2);																			// [obj][prop][getFunc][value]
	duk_put_prop_string(ctx, -2, "\xFF_PropValue");													// [obj][prop][getFunc]
	duk_def_prop(ctx, -3, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_GETTER);								// [obj]
}
void *ILibDuktape_Memory_Alloc(duk_context *ctx, duk_size_t size)
{
	void *retVal = NULL;

	duk_push_heap_stash(ctx);											// [s]
	if (!duk_has_prop_string(ctx, -1, ILibDuktape_Memory_AllocTable))	
	{																	
		duk_push_object(ctx);											// [s][table]
		duk_dup(ctx, -1);												// [s][table][table]
		duk_put_prop_string(ctx, -3, ILibDuktape_Memory_AllocTable);	// [s][table]
	}																	
	else																
	{																	
		duk_get_prop_string(ctx, -1, ILibDuktape_Memory_AllocTable);	// [s][table]
	}
	duk_push_fixed_buffer(ctx, size);									// [s][table][buffer]
	retVal = Duktape_GetBuffer(ctx, -1, NULL);							
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(retVal));			// [s][table]
	duk_pop_2(ctx);

	return(retVal);
}
