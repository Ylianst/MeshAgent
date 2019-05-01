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
#include "microstack/ILibCrypto.h"
#include "ILibDuktape_EventEmitter.h"

char stash_key[32];
struct sockaddr_in6 duktape_internalAddress;

#define ILibDuktape_EventEmitter_Table						"\xFF_EventEmitterTable"
#define ILibDuktape_Process_ExitCode						"\xFF_ExitCode"
#define ILibDuktape_Memory_AllocTable						"\xFF_MemoryAllocTable"
#define ILibDuktape_ObjectStashKey							"\xFF_ObjectStashKey"

int ILibDuktape_GetReferenceCount(duk_context *ctx, duk_idx_t i)
{
	int retVal = -1;
	duk_inspect_value(ctx, i);
	retVal = Duktape_GetIntPropertyValue(ctx, -1, "refc", -1);
	duk_pop(ctx);
	return(retVal-1);
}
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

#ifdef _POSIX
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-value"
#endif
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
#ifdef _POSIX
#pragma GCC diagnostic pop
#endif

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
void *Duktape_GetBufferPropertyEx(duk_context *ctx, duk_idx_t i, char* propertyName, duk_size_t* bufferLen)
{
	void *retVal = NULL;
	if (bufferLen != NULL) { *bufferLen = 0; }
	if (duk_has_prop_string(ctx, i, propertyName))
	{
		duk_get_prop_string(ctx, i, propertyName);			// [prop]
		retVal = (void*)Duktape_GetBuffer(ctx, -1, bufferLen);
		duk_pop(ctx);										// ...
	}
	return(retVal);
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
	if (ctx != NULL && duk_has_prop_string(ctx, i, propertyName))
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
	if (ctx!=NULL && duk_has_prop_string(ctx, i, propertyName))
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
	duk_size_t len = 0;
	if (bufLen != NULL) { *bufLen = 0; }

	if (duk_is_string(ctx, i))
	{
		retVal = (char*)duk_get_lstring(ctx, i, bufLen);
	}
	else if (duk_is_buffer(ctx, i))
	{
		retVal = (char*)duk_require_buffer(ctx, i, &len);
		if (ILibMemory_CanaryOK(ILibMemory_FromRaw(retVal)) && ILibMemory_RawSize(ILibMemory_FromRaw(retVal)) == len)
		{
			retVal = ILibMemory_FromRaw(retVal);
			if (bufLen != NULL) { *bufLen = ILibMemory_Size(retVal); }
		}
		else if (bufLen != NULL)
		{
			*bufLen = len;
		}
	}
	else if(duk_is_buffer_data(ctx, i))
	{
		retVal = (char*)duk_require_buffer_data(ctx, i, &len);
		if (ILibMemory_CanaryOK(ILibMemory_FromRaw(retVal)) && ILibMemory_RawSize(ILibMemory_FromRaw(retVal)) == len)
		{
			retVal = ILibMemory_FromRaw(retVal);
			if (bufLen != NULL) { *bufLen = ILibMemory_Size(retVal); }
		}
		else if (bufLen != NULL)
		{
			*bufLen = len;
		}
	}
	else if (duk_is_object(ctx, i))
	{
		duk_json_encode(ctx, i);
		retVal = (char*)duk_get_lstring(ctx, i, bufLen);
	}
	else if (duk_is_null_or_undefined(ctx, i))
	{
		retVal = NULL;
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
void ILibDuktape_CreateEventWithGetterAndCustomProperty(duk_context *ctx, char *customPropName, char *propName, duk_c_function getterMethod)
{
	duk_push_string(ctx, propName);																	// [obj][customProp][prop]
	duk_push_c_function(ctx, getterMethod, 1);														// [obj][customProp][prop][getFunc]
	duk_dup(ctx, -3);																				// [obj][customProp][prop][getFunc][customProp]
	duk_put_prop_string(ctx, -2, customPropName);													// [obj][customProp][prop][getFunc]
	duk_remove(ctx, -3);																			// [obj][prop][getFunc]
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
	duk_put_prop_string(ctx, -2, "propName");														// [obj][prop][setFunc]
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
	ILibDuktape_WriteID(ctx, "Mesh.ScriptContainer.heapFinalizer");
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
	if (ctx == NULL) { return; }
	char dest[4096];
	int len = 0;
	va_list argptr;
	duk_size_t errmsgLen;
	char *errmsg = (char*)duk_safe_to_lstring(ctx, -1, &errmsgLen);
	void *j = ILibDuktape_GetProcessObject(ctx);
	ILibDuktape_EventEmitter *emitter;

	if (ILibString_IndexOf(errmsg, (int)errmsgLen, "Process.exit() forced script termination", 40) >= 0) { return; }

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
		duk_push_error_object(emitter->ctx, DUK_ERR_ERROR, "%s", dest);
		duk_pcall_method(emitter->ctx, 2);
		duk_pop(emitter->ctx);															// ...
	}
}
// Error MUST be at top of stack when calling this method
void ILibDuktape_Process_UncaughtException(duk_context *ctx)
{
	if (ctx != NULL) { ILibDuktape_Process_UncaughtExceptionEx(ctx, ""); }
}
char* Duktape_GetContextGuidHex(duk_context *ctx, void *db)
{
	char *retVal = NULL;

	duk_push_heap_stash(ctx);												// [stash]
	if (duk_has_prop_string(ctx, -1, "\xFF_ScriptContainerSettings_DB"))
	{
		duk_get_prop_string(ctx, -1, "\xFF_ScriptContainerSettings_DB");	// [stash][db]
		if (duk_get_pointer(ctx, -1) != NULL && duk_get_pointer(ctx, -1) == db) { retVal = "0"; }
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

void ILibDuktape_CreateFinalizerEx(duk_context *ctx, duk_c_function func, int singleton)
{
	ILibDuktape_EventEmitter *e = ILibDuktape_EventEmitter_Create(ctx);
	if (singleton != 0) { ILibDuktape_EventEmitter_RemoveAllListeners(e, "~"); }
	ILibDuktape_EventEmitter_PrependOnce(ctx, -1, "~", func);
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
void *ILibDuktape_Memory_AllocEx(duk_context *ctx, duk_idx_t index, duk_size_t size)
{
	char *retVal = NULL;

	duk_dup(ctx, index);											// [object]
	ILibDuktape_Push_ObjectStash(ctx);								// [object][stash]
	duk_push_fixed_buffer(ctx, size);								// [object][stash][buffer]
	retVal = (char*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(retVal));		// [object][stash]
	duk_pop_2(ctx);													// ...
	return(retVal);
}
duk_ret_t ILibDuktape_Timeout_Sink(duk_context *ctx)
{
	ILibDuktape_TimeoutHandler userCallback = (ILibDuktape_TimeoutHandler)duk_get_pointer(ctx, 0);
	void **args = NULL;
	int argsLen, i;

	duk_push_this(ctx);													// [timeout]
	duk_dup(ctx, 1);													// [timeout][array]
	if ((argsLen = (int)duk_get_length(ctx, -1)) > 0)
	{
		args = ILibMemory_AllocateA(sizeof(void*)*argsLen);
		for (i = 0; i < argsLen; ++i)
		{
			duk_get_prop_index(ctx, -1, i);								// [timeout][array][arg]
			args[i] = duk_get_pointer(ctx, -1);
			duk_pop(ctx);												// [timeout][array]
		}
	}

	if (userCallback != NULL) { userCallback(ctx, args, argsLen); }
	return(0);
}
void* ILibDuktape_Timeout(duk_context *ctx, void **args, int argsLen, int delay, ILibDuktape_TimeoutHandler callback)
{
	void *retval = NULL;
	int i = 0;
	duk_push_global_object(ctx);										// [g]
	duk_get_prop_string(ctx, -1, "setTimeout");							// [g][setTimeout]
	duk_swap_top(ctx, -2);												// [setTimeout][this]
	duk_push_c_function(ctx, ILibDuktape_Timeout_Sink, DUK_VARARGS);	// [setTimeout][this][func]
	duk_push_int(ctx, delay);											// [setTimeout][this][func][delay]
	duk_push_pointer(ctx, callback);									// [setTimeout][this][func][delay][userFunc]
	duk_push_array(ctx);												// [setTimeout][this][func][delay][userFunc][array]

	while (i < argsLen && args[i] != NULL)
	{
		duk_get_prop_string(ctx, -1, "push");							// [setInterval][this][func][delay][userFunc][array][push]
		duk_dup(ctx, -2);												// [setInterval][this][func][delay][userFunc][array][push][this]
		duk_push_pointer(ctx, args[i]);									// [setInterval][this][func][delay][userFunc][array][push][this][val]
		if (duk_pcall_method(ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "ILibDuktape_Timeout => Array.push(): "); }
		duk_pop(ctx);													// [setInterval][this][func][delay][userFunc][array]
		++i;
	}

	if (duk_pcall_method(ctx, 4) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "ILibDuktape_Timeout => timeout(): "); duk_pop(ctx); return(NULL); }


	retval = duk_get_heapptr(ctx, -1);											// [timeout]
	return(retval);
}
duk_ret_t ILibDuktape_Immediate_Sink(duk_context *ctx)
{
	ILibDuktape_ImmediateHandler userCallback = (ILibDuktape_ImmediateHandler)duk_get_pointer(ctx, 0);
	void **args = NULL;
	int argsLen, i;

	duk_push_this(ctx);													// [immediate]
	duk_dup(ctx, 1);													// [immediate][array]
	if ((argsLen = (int)duk_get_length(ctx, -1)) > 0)
	{
		args = ILibMemory_AllocateA(sizeof(void*)*argsLen);
		for (i = 0; i < argsLen; ++i)
		{
			duk_get_prop_index(ctx, -1, i);								// [immediate][array][arg]
			args[i] = duk_get_pointer(ctx, -1);
			duk_pop(ctx);												// [immediate][array]
		}
	}


	if (userCallback != NULL) { userCallback(ctx, args, argsLen); }

	duk_push_heap_stash(ctx);											// [stash]
	duk_push_this(ctx);													// [stash][immediate]
	duk_del_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));
	return(0);
}
void* ILibDuktape_Immediate(duk_context *ctx, void ** args, int argsLen, ILibDuktape_ImmediateHandler callback)
{
	void *retval = NULL;
	int i = 0;
	duk_push_global_object(ctx);										// [g]
	duk_get_prop_string(ctx, -1, "setImmediate");						// [g][setImmediate]
	duk_swap_top(ctx, -2);												// [setImmediate][this]
	duk_push_c_function(ctx, ILibDuktape_Immediate_Sink, DUK_VARARGS);	// [setImmediate][this][func]
	duk_push_pointer(ctx, callback);									// [setImmediate][this][func][userFunc]
	duk_push_array(ctx);												// [setImmediate][this][func][userFunc][array]

	while (args[i] != NULL && i < argsLen)
	{
		duk_get_prop_string(ctx, -1, "push");							// [setImmediate][this][func][userFunc][array][push]
		duk_dup(ctx, -2);												// [setImmediate][this][func][userFunc][array][push][this]
		duk_push_pointer(ctx, args[i]);									// [setImmediate][this][func][userFunc][array][push][this][val]
		if (duk_pcall_method(ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "ILibDuktape_Immediate => Array.push(): "); }
		duk_pop(ctx);													// [setImmediate][this][func][userFunc][array]
		++i;
	}

	if (duk_pcall_method(ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "ILibDuktape_Immediate => immediate(): "); duk_pop(ctx); return(NULL); }

																				
	retval = duk_get_heapptr(ctx, -1);											// [immediate]
	duk_push_heap_stash(ctx);													// [immediate][stash]
	duk_swap_top(ctx, -2);														// [stash][immediate]
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(retval));					// [stash]
	duk_pop(ctx);																// ...
	return(retval);
}
duk_ret_t ILibDuktape_Interval_Sink(duk_context *ctx)
{
	ILibDuktape_ImmediateHandler userCallback = (ILibDuktape_ImmediateHandler)duk_get_pointer(ctx, 0);
	void **args = NULL;
	int argsLen, i;

	duk_push_this(ctx);													// [immediate]
	duk_dup(ctx, 1);													// [immediate][array]
	if ((argsLen = (int)duk_get_length(ctx, -1)) > 0)
	{
		args = ILibMemory_AllocateA(sizeof(void*)*argsLen);
		for (i = 0; i < argsLen; ++i)
		{
			duk_get_prop_index(ctx, -1, i);								// [immediate][array][arg]
			args[i] = duk_get_pointer(ctx, -1);
			duk_pop(ctx);												// [immediate][array]
		}
	}


	if (userCallback != NULL) { userCallback(ctx, args, argsLen); }
	return(0);
}
void* ILibDuktape_Interval(duk_context *ctx, void **args, int argsLen, int delay, ILibDuktape_IntervalHandler callback)
{
	void *retval = NULL;
	int i = 0;
	duk_push_global_object(ctx);										// [g]
	duk_get_prop_string(ctx, -1, "setInterval");						// [g][setInterval]
	duk_swap_top(ctx, -2);												// [setInterval][this]
	duk_push_c_function(ctx, ILibDuktape_Interval_Sink, DUK_VARARGS);	// [setInterval][this][func]
	duk_push_int(ctx, delay);											// [setInterval][this][func][delay]
	duk_push_pointer(ctx, callback);									// [setInterval][this][func][delay][userFunc]
	duk_push_array(ctx);												// [setInterval][this][func][delay][userFunc][array]

	while (args[i] != NULL && i < argsLen)
	{
		duk_get_prop_string(ctx, -1, "push");							// [setInterval][this][func][delay][userFunc][array][push]
		duk_dup(ctx, -2);												// [setInterval][this][func][delay][userFunc][array][push][this]
		duk_push_pointer(ctx, args[i]);									// [setInterval][this][func][delay][userFunc][array][push][this][val]
		if (duk_pcall_method(ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "ILibDuktape_Immediate => Array.push(): "); }
		duk_pop(ctx);													// [setInterval][this][func][delay][userFunc][array]
		++i;
	}

	if (duk_pcall_method(ctx, 4) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "ILibDuktape_Interval => interval(): "); duk_pop(ctx); return(NULL); }


	retval = duk_get_heapptr(ctx, -1);											// [immediate]
	duk_push_heap_stash(ctx);													// [immediate][stash]
	duk_swap_top(ctx, -2);														// [stash][immediate]
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(retval));					// [stash]
	duk_pop(ctx);																// ...
	return(retval);
}
void ILibDuktape_CreateInstanceMethodWithProperties(duk_context *ctx, char *funcName, duk_c_function funcImpl, duk_idx_t numArgs, unsigned int propertyCount, ...)
{
	unsigned int i;
	char *name;
	duk_idx_t valueIndex;
	
	duk_push_c_function(ctx, funcImpl, numArgs);		// [func]

	va_list vlist;
	va_start(vlist, propertyCount);
	for (i = 0; i < propertyCount; ++i)
	{
		name = va_arg(vlist, char*);
		valueIndex = va_arg(vlist, duk_idx_t);

		duk_dup(ctx, valueIndex);						// [func][value]
		duk_put_prop_string(ctx, -2, name);				// [func]
	}
	va_end(vlist);

	while (propertyCount-- > 0) { duk_remove(ctx, -2); }

	duk_put_prop_string(ctx, -2, funcName);
}
duk_idx_t duk_push_int_ex(duk_context *ctx, duk_int_t val)
{
	return(duk_push_int(ctx, val), duk_get_top_index(ctx));
}

void Duktape_Console_Log_ChainEx(duk_context *ctx, ILibDuktape_LogTypes logType, char *msg, duk_size_t msgLen)
{
	duk_push_global_object(ctx);						// [g]
	duk_get_prop_string(ctx, -1, "console");			// [g][console]
	switch (logType)
	{
		case ILibDuktape_LogType_Error:
			duk_get_prop_string(ctx, -1, "error");		// [g][console][error]
			break;
		case ILibDuktape_LogType_Warn:
			duk_get_prop_string(ctx, -1, "warn");		// [g][console][warn]
			break;
		default:
			duk_get_prop_string(ctx, -1, "log");		// [g][console][log]
			break;
	}
	duk_swap_top(ctx, -2);								// [g][log][this]
	duk_push_lstring(ctx, msg, msgLen);					// [g][log][this][str]
	duk_pcall_method(ctx, 1); duk_pop(ctx);				// [g]
	duk_pop(ctx);										// ...
}

typedef struct Duktape_Console_Log_data
{
	duk_context *ctx;
	ILibDuktape_LogTypes logType;
}Duktape_Console_Log_data;

void Duktape_Console_Log_Chain(void *chain, void *user)
{
	Duktape_Console_Log_data *data = (Duktape_Console_Log_data*)user;
	char *msg = (char*)ILibMemory_Extra(data);

	Duktape_Console_Log_ChainEx(data->ctx, data->logType, msg, ILibMemory_Size(msg));
	
	ILibMemory_Free(user);
}
void Duktape_Console_Log(duk_context *ctx, void *chain, ILibDuktape_LogTypes logType, char *msg, duk_size_t msgLen)
{
	if (ILibIsRunningOnChainThread(chain))
	{
		Duktape_Console_Log_ChainEx(ctx, logType, msg, msgLen);
	}
	else
	{
		Duktape_Console_Log_data *data = (Duktape_Console_Log_data*)ILibMemory_SmartAllocateEx(sizeof(Duktape_Console_Log_data), msgLen);
		data->ctx = ctx;
		data->logType = logType;
		memcpy_s(ILibMemory_Extra(data), ILibMemory_ExtraSize(data), msg, msgLen);

		ILibChain_RunOnMicrostackThreadEx(chain, Duktape_Console_Log_Chain, data);
	}
}

char* ILibDuktape_String_AsWide(duk_context *ctx, duk_idx_t idx, duk_size_t *len)
{
	char *src;
	src = (char*)duk_require_string(ctx, idx);

#ifdef WIN32
	size_t inBufferLen = 2 + (2 * MultiByteToWideChar(CP_UTF8, 0, (LPCCH)src, -1, NULL, 0));
	LPWSTR inBuffer = (LPWSTR)ILibMemory_AllocateTemp(Duktape_GetChain(ctx), inBufferLen);

	int r = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)src, -1, inBuffer, (int)inBufferLen);
	if (len != NULL)
	{
		*len = (duk_size_t)r;
	}
	return(r == 0 ? NULL : (char*)inBuffer);
#else
	return(src);
#endif
}
void ILibDuktape_String_PushWideString(duk_context *ctx, char *wstr, size_t wstrlen)
{
#ifdef WIN32
	char *tmp;
	size_t tmpLen;

	tmpLen = 2 + (size_t)WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wstr, (int)(wstrlen > 0 ? wstrlen : -1), NULL, 0, NULL, NULL);
	tmp = (char*)ILibMemory_AllocateTemp(Duktape_GetChain(ctx), tmpLen);

	if (WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wstr, (int)(wstrlen > 0 ? wstrlen : -1), (LPSTR)tmp, (int)tmpLen, NULL, NULL) != 0)
	{
		duk_push_string(ctx, tmp);
	}
	else
	{
		ILibDuktape_Error(ctx, "String_PushWideString() Error: %u", GetLastError());
	}
#else
	if (wstrlen == 0)
	{
		duk_push_string(ctx, wstr);
	}
	else
	{
		duk_push_lstring(ctx, wstr, wstrlen);
	}
#endif
}
char *ILibDuktape_String_WideToUTF8(duk_context *ctx, char *wstr)
{
#ifdef WIN32
	char *tmp;
	size_t tmpLen;

	tmpLen = 2 + (size_t)WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wstr, -1, NULL, 0, NULL, NULL);
	tmp = (char*)ILibMemory_AllocateTemp(Duktape_GetChain(ctx), tmpLen);
	WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wstr, -1, tmp, (int)tmpLen, NULL, NULL);
	return(tmp);
#else
	// NOP for non-Windows, because should already be UTF8
	return(wstr);
#endif
}
char *ILibDuktape_String_UTF8ToWide(duk_context *ctx, char *str)
{
#ifdef WIN32
	size_t tmpLen = 2 + (2 * MultiByteToWideChar(CP_UTF8, 0, (LPCCH)str, -1, NULL, 0));
	LPWSTR retVal = (LPWSTR)ILibMemory_AllocateTemp(Duktape_GetChain(ctx), tmpLen);
	MultiByteToWideChar(CP_UTF8, 0, (LPCCH)str, -1, retVal, (int)tmpLen);
	return((char*)retVal);
#else
	// NOP on non-Windows, as strings should always be UTF-8 by default
	return(str);
#endif
}
void ILibDuktape_Log_Object(duk_context *ctx, duk_idx_t i, char *meta)
{
	void *h = duk_get_heapptr(ctx, i);
	duk_enum(ctx, i, DUK_ENUM_INCLUDE_HIDDEN | DUK_ENUM_INCLUDE_SYMBOLS);
	while (duk_next(ctx, -1, 1))
	{
		printf(" [%s: %p] => %s (%p)\n", (meta==NULL?"OBJ":meta), h, (char*)duk_get_string(ctx, -2), duk_get_heapptr(ctx, -1));
		duk_pop_2(ctx);
	}
	duk_pop(ctx);
}

