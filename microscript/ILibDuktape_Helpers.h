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

#ifndef ___ILIBDUKTAPE_HELPERS___
#define ___ILIBDUKTAPE_HELPERS___

#include "duktape.h"
#ifndef MICROSTACK_NOTLS
#include <openssl/ssl.h>
#endif

typedef void(*ILibDuktape_HelperEvent)(duk_context *ctx, void *user);

#define ILibDuktape_NativeUncaughtExceptionPtr				"\xFF_NativeUncaughtExceptionPtr"
#define ILibDuktape_NativeUncaughtExceptionUserPtr			"\xFF_NativeUncaughtExceptionUserPtr"

#define ILibDuktape_MeshAgent_Cert_NonLeaf					"\xFF_selfcert"		
#define ILibDuktape_MeshAgent_Cert_Server					"\xFF_selftlscert"
#define CONTEXT_GUID_BUFFER									"_CONTEXT_GUID"
#define ILibDuktape_OBJID									"_ObjectID"

#define ILibDuktape_CR2HTTP									"\xFF_CR2HTTP"
#define ILibDuktape_CR2Options								"\xFF_CR2Options"
#define ILibDuktape_TLS_util_cert							"\xFF_TLS_util_cert"
#define ILibDuktape_ChainLinkPtr							"\xFF_Duktape_ChainLink"

typedef enum ILibDuktape_LogTypes
{
	ILibDuktape_LogType_Normal = 0,
	ILibDuktape_LogType_Warn,
	ILibDuktape_LogType_Error,
	ILibDuktape_LogType_Info1,
	ILibDuktape_LogType_Info2,
	ILibDuktape_LogType_Info3
}ILibDuktape_LogTypes;

typedef struct ILibDuktape_ContextData
{
	uintptr_t nonce;
	uint32_t flags;
#ifdef WIN32
	uint32_t apc_flags;
#endif
	uint32_t executionCount;
	uint64_t executionTime;
	uint32_t maxExecutionTime;
	void *threads;
	int fakechain;
	void *chain;
	void *user;
}ILibDuktape_ContextData;

#define DUKTAPE_DEFAULT_MAX_EXECUTION_TIMEOUT 0
#define duk_destroy_heap_in_progress	0x01
#define duk_ctx_context_data(ctx) ((ILibDuktape_ContextData*)(ILibMemory_CanaryOK(ctx)?((void**)ILibMemory_Extra(ctx))[0]:NULL))
#define duk_ctx_nonce(ctx) (duk_ctx_context_data(ctx)->nonce)
#define duk_ctx_is_alive(ctx) (ILibMemory_CanaryOK(ctx)&&ILibMemory_ExtraSize(ctx)==sizeof(void*))
#define duk_ctx_is_valid(nvalue, ctx) (duk_ctx_is_alive(ctx) && duk_ctx_nonce(ctx) == nvalue)
#define duk_ctx_shutting_down(ctx) ((duk_ctx_context_data(ctx)->flags & duk_destroy_heap_in_progress)==duk_destroy_heap_in_progress)
#define duk_ctx_chain(ctx) (duk_ctx_is_alive(ctx)?duk_ctx_context_data(ctx)->chain:NULL)

#define duk_stream_flags_string		0x01
#define duk_stream_flags_buffer		0x00
#define duk_stream_flags_flush		0x04

#define duk_stream_flags_isString(flags)	(((flags)&duk_stream_flags_string)==duk_stream_flags_string)
#define duk_stream_flags_isBuffer(flags)	(((flags)&duk_stream_flags_string)==duk_stream_flags_buffer)
#define duk_stream_flags_isFlush(flags)		(((flags)&duk_stream_flags_flush)==duk_stream_flags_flush)

typedef void(*Duktape_EventLoopDispatch)(void *chain, void *user);
void Duktape_RunOnEventLoop(void *chain, uintptr_t nonce, duk_context *ctx, Duktape_EventLoopDispatch handler, Duktape_EventLoopDispatch abortHandler, void *user);
#define Duktape_RunOnEventLoopEx(chain, nonce, ctx, handler, user, freeOnShutdown) Duktape_RunOnEventLoop(chain, nonce, ctx, handler, (freeOnShutdown==0?NULL:(Duktape_EventLoopDispatch)(uintptr_t)0x01), user)
extern void *_duk_get_tval(void *thr, duk_idx_t idx);
extern duk_int_t* _get_refcount_ptr(void *thr, duk_idx_t idx);

void ILibDuktape_ExecutorTimeout_Start(duk_context *ctx);
void ILibDuktape_ExecutorTimeout_Stop(duk_context *ctx);

void ILibDuktape_Log_Object(duk_context *ctx, duk_idx_t i, char *meta);
char* Duktape_GetContextGuidHex(duk_context *ctx, void *db);
void Duktape_SafeDestroyHeap(duk_context *ctx);
void *Duktape_GetChain(duk_context *ctx);
char *Duktape_GetStashKey(void* value);
char* Duktape_GetBuffer(duk_context *ctx, duk_idx_t i, duk_size_t *bufLen);
void Duktape_CreateEnumEx(duk_context *ctx, char** fieldNames, int * fieldValues, int numFields);
void Duktape_CreateEnum(duk_context *ctx, char* enumName, char **fieldNames, int *fieldValues, int numFields);
char* Duktape_GetStringPropertyIndexValueEx(duk_context *ctx, duk_idx_t i, duk_uarridx_t x, char* defaultValue, duk_size_t *len);
#define Duktape_GetStringPropertyIndexValue(ctx, i, ax, defaultValue) Duktape_GetStringPropertyIndexValueEx(ctx, i, ax, defaultValue, NULL)
char* Duktape_GetStringPropertyValueEx(duk_context *ctx, duk_idx_t i, char* propertyName, char* defaultValue, duk_size_t *len);
#define Duktape_GetStringPropertyValue(ctx, i, propertyName, defaultValue) Duktape_GetStringPropertyValueEx(ctx, i, propertyName, defaultValue, NULL)
int Duktape_GetIntPropertyValue(duk_context *ctx, duk_idx_t i, char* propertyName, int defaultValue);
uint32_t Duktape_GetUIntPropertyValue(duk_context *ctx, duk_idx_t i, char* propertyName, uint32_t defaultValue);
void *Duktape_GetPointerProperty(duk_context *ctx, duk_idx_t i, char* propertyName);
void *Duktape_GetHeapptrProperty(duk_context *ctx, duk_idx_t i, char* propertyName);
void *Duktape_GetBufferPropertyEx(duk_context *ctx, duk_idx_t i, char* propertyName, duk_size_t* bufferLen);
#define Duktape_GetBufferProperty(ctx, i, propertyName) Duktape_GetBufferPropertyEx(ctx, i, propertyName, NULL)
void *Duktape_GetHeapptrIndexProperty(duk_context *ctx, duk_idx_t i, duk_uarridx_t x);
int Duktape_GetIntPropertyValueFromHeapptr(duk_context *ctx, void *h, char *propertyName, int defaultValue);
void *Duktape_GetHeapptrPropertyValueFromHeapptr(duk_context *ctx, void *h, char *propertyName);

char* Duktape_Duplicate_GetStringPropertyValueEx(duk_context *ctx, duk_idx_t i, char* propertyName, char* defaultValue, duk_size_t *len);
#define Duktape_Duplicate_GetStringPropertyValue(ctx, i, propertyName, defaultValue) Duktape_Duplicate_GetStringPropertyValueEx(ctx, i, propertyName, defaultValue, NULL)
void *Duktape_Duplicate_GetBufferPropertyEx(duk_context *ctx, duk_idx_t i, char* propertyName, duk_size_t* bufferLen);
#define Duktape_Duplicate_GetBufferProperty(ctx, i, propertyName) Duktape_Duplicate_GetBufferPropertyEx(ctx, i, propertyName, NULL)
char *Duktape_Duplicate_GetStringEx(duk_context *ctx, duk_idx_t i, duk_size_t *len);
#define Duktape_Duplicate_GetString(ctx, i) Duktape_Duplicate_GetStringEx(ctx, i, NULL)

extern duk_ret_t ILibDuktape_EventEmitter_DefaultNewListenerHandler(duk_context *ctx);
#define duk_prepare_method_call(ctx, i, name) duk_dup(ctx, i);duk_get_prop_string(ctx, -1, name);duk_swap_top(ctx, -2);
#define duk_array_shift(ctx, i) duk_dup(ctx, i);duk_get_prop_string(ctx, -1, "shift");duk_swap_top(ctx, -2);duk_call_method(ctx, 0);
#define duk_array_pop(ctx, i) duk_dup(ctx, i);duk_get_prop_string(ctx, -1, "pop");duk_swap_top(ctx, -2);duk_call_method(ctx, 0);
#define duk_array_push(ctx, i) duk_dup(ctx, i);duk_get_prop_string(ctx, -1, "push");duk_swap_top(ctx, -2);duk_dup(ctx,-3);duk_pcall_method(ctx, 1);duk_pop_2(ctx);
#define duk_array_join(ctx, i, str) duk_dup(ctx, i);duk_get_prop_string(ctx, -1, "join");duk_swap_top(ctx, -2);duk_push_string(ctx, str);duk_pcall_method(ctx, 1);
#define duk_array_unshift(ctx, i) duk_dup(ctx, i);duk_get_prop_string(ctx, -1, "unshift");duk_swap_top(ctx, -2);duk_dup(ctx, -3);duk_remove(ctx, -4);duk_pcall_method(ctx, 1);duk_pop(ctx);
#define duk_array_partialIncludes(ctx, i, str) duk_prepare_method_call(ctx, i, "partialIncludes");duk_push_string(ctx, str);duk_pcall_method(ctx, 1);
#define duk_array_clone(ctx, i) duk_prepare_method_call(ctx, i, "slice");if(duk_pcall_method(ctx, 0)!=0){duk_pop(ctx);duk_push_array(ctx);}
#define duk_array_remove(ctx, i, x) duk_prepare_method_call(ctx, i, "splice");duk_push_int(ctx,x);duk_push_int(ctx,1);duk_pcall_method(ctx, 2);duk_pop(ctx);
#define duk_array_replace(ctx, i, ix, str) duk_prepare_method_call(ctx, i, "splice");duk_push_int(ctx, ix);duk_push_int(ctx, 1);duk_push_string(ctx,str);duk_pcall_method(ctx, 3);duk_pop(ctx);

#define duk_events_setup_on(ctx, i, name, func) duk_prepare_method_call(ctx, i, "on");duk_push_string(ctx, name);duk_push_c_function(ctx, func, DUK_VARARGS);
#define duk_events_newListener(ctx, i, name, func) duk_events_setup_on(ctx, i, "newListener", ILibDuktape_EventEmitter_DefaultNewListenerHandler);duk_push_string(ctx, name);duk_put_prop_string(ctx, -2, "event_name");duk_push_c_function(ctx, func, DUK_VARARGS);duk_put_prop_string(ctx, -2, "event_callback");if(duk_pcall_method(ctx, 2)!=0){printf("oops\n");ILibDuktape_Process_UncaughtExceptionEx(ctx, "duk_events_newListener (%s,%d)", __FILE__, __LINE__);}duk_pop(ctx);
#define duk_events_newListener2(ctx, i, name, func) duk_events_setup_on(ctx, i, "newListener2", ILibDuktape_EventEmitter_DefaultNewListenerHandler);duk_push_string(ctx, name);duk_put_prop_string(ctx, -2, "event_name");duk_push_c_function(ctx, func, DUK_VARARGS);duk_put_prop_string(ctx, -2, "event_callback");if(duk_pcall_method(ctx, 2)!=0){printf("oops\n");ILibDuktape_Process_UncaughtExceptionEx(ctx, "duk_events_newListener (%s,%d)", __FILE__, __LINE__);}duk_pop(ctx);

#define duk_queue_create(ctx) duk_push_array(ctx)
#define duk_queue_enQueue(ctx, i) duk_array_push(ctx, i)
#define duk_queue_deQueue(ctx, i) duk_array_shift(ctx, i)
#define duk_queue_peek(ctx, i) duk_get_prop_index(ctx, i, 0)
#define duk_queue_isEmpty(ctx, i) (duk_get_length(ctx, i)==0)

#define duk_table_put(ctx, i, key) duk_put_prop_string(ctx, i, key)
#define duk_table_get(ctx, i, key) duk_get_prop_string(ctx, i, key)
#define duk_table_get_buffer(ctx, i, key) Duktape_GetBufferProperty(ctx, i, key)
#define duk_table_keys(ctx, i) duk_dup(ctx, i);duk_get_prop_string(ctx, -1, "keys");duk_swap_top(ctx, -2);if(duk_pcall_method(ctx, 0)!=0){duk_pop(ctx);duk_push_null(ctx);}
#define duk_table_hasKey(ctx, i, key) duk_has_prop_string(ctx, i, key)
#define duk_table_delKey(ctx, i, key) duk_del_prop_string(ctx, i, key)

#define duk_buffer_concat(ctx) duk_push_global_object(ctx);duk_get_prop_string(ctx,-1,"Buffer");duk_remove(ctx,-2);duk_get_prop_string(ctx, -1, "concat");duk_swap_top(ctx, -2);duk_dup(ctx, -3);duk_call_method(ctx,1);duk_remove(ctx, -2);
#define duk_buffer_slice(ctx, i, start, len) duk_dup(ctx, i);duk_get_prop_string(ctx, -1, "slice");duk_swap_top(ctx, -2);duk_push_int(ctx, start);duk_push_int(ctx, len);duk_pcall_method(ctx, 2);duk_remove(ctx, -2);
#define duk_string_concat(ctx, i) duk_dup(ctx, i);duk_get_prop_string(ctx, -1, "concat");duk_swap_top(ctx, -2);duk_dup(ctx, -3);duk_pcall_method(ctx, 1);duk_remove(ctx, -2);
#define duk_string_split(ctx, i, delim) duk_dup(ctx, i);duk_get_prop_string(ctx, -1, "split");duk_swap_top(ctx, -2);duk_push_string(ctx, delim);duk_call_method(ctx, 1);
#define duk_string_endsWith(ctx, i, val) duk_prepare_method_call(ctx, i, "endsWith");duk_push_string(ctx,val);duk_pcall_method(ctx, 1);
#define duk_string_substring(ctx, i, start, end) duk_prepare_method_call(ctx, i, "substring");duk_push_int(ctx, start);duk_push_int(ctx, end);duk_pcall_method(ctx, 2);

int Duktape_GetBooleanProperty(duk_context *ctx, duk_idx_t i, char *propertyName, int defaultValue);
struct sockaddr_in6* Duktape_IPAddress4_FromString(char* address, unsigned short port);
struct sockaddr_in6* Duktape_IPAddress6_FromString(char* address, unsigned short port);
void ILibDuktape_SockAddrToOptions(duk_context *ctx, struct sockaddr_in6 *addr);
void ILibDuktape_IPV4AddressToOptions(duk_context *ctx, int addr);
void *ILibDuktape_GetProcessObject(duk_context *ctx);

char* ILibDuktape_String_AsWide(duk_context *ctx, duk_idx_t idx, duk_size_t *len);
void ILibDuktape_String_PushWideString(duk_context *ctx, char *wstr, size_t wstrlen);
char *ILibDuktape_String_WideToUTF8(duk_context *ctx, char *wstr);
char *ILibDuktape_String_UTF8ToWide(duk_context *ctx, char *str);
void ILibDuktape_String_UTF8ToWideEx(duk_context *ctx, char *str);

void duk_buffer_enable_autoclear(duk_context *ctx);
#define Duktape_PushBuffer(ctx, bufSize) ILibMemory_Init(duk_push_fixed_buffer(ctx, (duk_size_t)(bufSize) + sizeof(ILibMemory_Header)), (bufSize), 0, ILibMemory_Types_OTHER)
#define Duktape_PushDynamicBuffer(ctx, bufSize) ILibMemory_Init(duk_push_dynamic_buffer(ctx, (duk_size_t)(bufSize) + sizeof(ILibMemory_Header)), (bufSize), 0, ILibMemory_Types_OTHER)
void* Duktape_DynamicBuffer_Resize(duk_context *ctx, duk_idx_t idx, duk_size_t bufSize);

void Duktape_Console_Log(duk_context *ctx, void *chain, ILibDuktape_LogTypes logType, char *msg, duk_size_t msgLen);
void Duktape_Console_LogEx(duk_context *ctx, ILibDuktape_LogTypes logType, char *format, ...);

typedef void(*ILibDuktape_NativeUncaughtExceptionHandler)(duk_context *ctx, char *msg, void *user);
void ILibDuktape_SetNativeUncaughtExceptionHandler(duk_context *ctx, ILibDuktape_NativeUncaughtExceptionHandler handler, void *user);

void ILibDuktape_Process_UncaughtException(duk_context *ctx);
void ILibDuktape_Process_UncaughtExceptionEx(duk_context *ctx, char *format, ...);

duk_ret_t ILibDuktape_Error(duk_context *ctx, char *format, ...);
typedef void(*ILibDuktape_IndependentFinalizerHandler)(duk_context *ctx, void *object);
int ILibDuktape_Process_GetExitCode(duk_context *ctx);

void ILibDuktape_CreateEventWithGetter_SetEnumerable(duk_context *ctx, char *propName, duk_c_function getterMethod, int enumerable);
#define ILibDuktape_CreateEventWithGetter(ctx, propName, getterFunc) ILibDuktape_CreateEventWithGetter_SetEnumerable(ctx, propName, getterFunc, 0)
void ILibDuktape_CreateEventWithGetterEx(duk_context *ctx, char *propName, void *heapptr);
void ILibDuktape_CreateEventWithGetterAndCustomProperty(duk_context *ctx, char *customPropName, char *propName, duk_c_function getterMethod);
void ILibDuktape_CreateEventWithSetter(duk_context *ctx, char *propName, char *propNamePtr, void **hptr);
void ILibDuktape_CreateEventWithSetterEx(duk_context *ctx, char *propName, duk_c_function setterMethod);
void ILibDuktape_CreateEventWithGetterAndSetter(duk_context *ctx, char *propName, char *propNamePtr, void **hptr, duk_c_function getterMethod);
void ILibDuktape_CreateEventWithGetterAndSetterEx(duk_context *ctx, char *propName, duk_c_function getterMethod, duk_c_function setterMethod);
void ILibDuktape_CreateEventWithGetterAndSetterWithMetaData(duk_context *ctx, char* metaDataPropName, duk_idx_t metaDataPropIndex, char *propName, duk_c_function getterMethod, duk_c_function setterMethod);
#define ILibDuktape_CreateEventWithGetterAndSetterWithIntMetaData(context, metaDataPropName, metaDataIntValue, propName, getterMethod, setterMethod) duk_push_int(context, metaDataIntValue);ILibDuktape_CreateEventWithGetterAndSetterWithMetaData(context, metaDataPropName, -1, propName, getterMethod, setterMethod);
#define ILibDuktape_CreateInstanceMethod(context, methodName, funcImpl, numArgs) duk_push_c_function(context, funcImpl, numArgs); duk_put_prop_string(context, -2, methodName)
#define ILibDuktape_CreateInstanceMethodWithPropertyEx(context, propName, propIndex, methodName, funcImpl, numArgs) duk_dup(context, propIndex);if(propIndex<0){duk_remove(context, propIndex - 1);};duk_push_c_function(context, funcImpl, numArgs);duk_swap_top(context, -2);duk_put_prop_string(context, -2, propName);duk_put_prop_string(context, -2, methodName);
#define ILibDuktape_CreateInstanceMethodWithStringProperty(context, propName, propValue, methodName, funcImpl, numArgs) duk_push_string(context, propValue);ILibDuktape_CreateInstanceMethodWithPropertyEx(context, propName, -1, methodName, funcImpl, numArgs);
#define ILibDuktape_CreateInstanceMethodWithBooleanProperty(context, propName, propValue, methodName, funcImpl, numArgs) duk_push_c_function(context, funcImpl, numArgs);duk_push_boolean(context, propValue);duk_put_prop_string(ctx, -2, propName);duk_put_prop_string(ctx, -2, methodName);
#define ILibDuktape_CreateInstanceMethodWithIntProperty(context, propName, propValue, methodName, funcImpl, numArgs) duk_push_c_function(context, funcImpl, numArgs);duk_push_int(context, propValue);duk_put_prop_string(ctx, -2, propName);duk_put_prop_string(ctx, -2, methodName);
#define ILibDuktape_CreateInstanceMethodWithNumberProperty(context, propName, propValue, methodName, funcImpl, numArgs) duk_push_c_function(context, funcImpl, numArgs);duk_push_number(context, (propValue));duk_put_prop_string(ctx, -2, propName);duk_put_prop_string(ctx, -2, methodName);
#define ILibDuktape_CreateInstanceMethodWithPointerProperty(context, propName, propValue, methodName, funcImpl, numArgs) duk_push_pointer(context, propValue);ILibDuktape_CreateInstanceMethodWithPropertyEx(context, propName, -1, methodName, funcImpl, numArgs);
void ILibDuktape_CreateInstanceMethodWithProperties(duk_context *ctx, char *funcName, duk_c_function funcImpl, duk_idx_t numArgs, unsigned int propertyCount, ...);
duk_idx_t duk_push_int_ex(duk_context *ctx, duk_int_t val);

#define ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, methodName, impl, argCount, enumerable) duk_push_c_function(ctx, impl, argCount);ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx,methodName,enumerable)
#define ILibDuktape_CreateProperty_InstanceMethod(ctx, methodName, impl, argCount) duk_push_c_function(ctx, impl, argCount);ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx,methodName,1)
#define ILibDuktape_CreateProperty_InstanceMethodEx(ctx, methodName, funcHeapPtr) duk_push_heapptr(ctx, funcHeapPtr);ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx,methodName,0)

#define ILibDuktape_DeleteReadOnlyProperty(ctx, i, propName) duk_dup(ctx,i);duk_push_string(ctx,propName);duk_def_prop(ctx,-2,DUK_DEFPROP_FORCE|DUK_DEFPROP_SET_CONFIGURABLE);duk_pop(ctx);duk_del_prop_string(ctx,i,propName);
#define ILibDuktape_CreateReadonlyProperty(ctx, propName) ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx, propName, 0)
void ILibDuktape_CreateReadonlyProperty_SetEnumerable(duk_context *ctx, char *propName, int enumerable);
#define ILibDuktape_CreateReadonlyProperty_int(ctx, propName, propValue) duk_push_int(ctx, propValue);ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx, propName, 1)
void ILibDuktape_CreateFinalizerEx(duk_context *ctx, duk_c_function func, int singleton);
#define ILibDuktape_CreateFinalizer(ctx, func) ILibDuktape_CreateFinalizerEx(ctx, func, 0)

void *ILibDuktape_Memory_Alloc(duk_context *ctx, duk_size_t size);
void *ILibDuktape_Memory_AllocEx(duk_context *ctx, duk_idx_t index, duk_size_t size);
void ILibDuktape_Helper_AddHeapFinalizer(duk_context *ctx, ILibDuktape_HelperEvent handler, void *user);

void ILibDuktape_Push_ObjectStash(duk_context *ctx);

typedef void(*ILibDuktape_ImmediateHandler)(duk_context *ctx, void ** args, int argsLen);
typedef ILibDuktape_ImmediateHandler ILibDuktape_IntervalHandler;
typedef ILibDuktape_ImmediateHandler ILibDuktape_TimeoutHandler;

void* ILibDuktape_Immediate(duk_context *ctx, void ** args, int argsLen, ILibDuktape_ImmediateHandler callback);
void* ILibDuktape_Interval(duk_context *ctx, void **args, int argsLen, int delay, ILibDuktape_IntervalHandler callback);
void* ILibDuktape_Timeout(duk_context *ctx, void **args, int argsLen, int delay, ILibDuktape_TimeoutHandler callback);
int ILibDuktape_GetReferenceCount(duk_context *ctx, duk_idx_t i);

#define ILibDuktape_WriteID(ctx, id) duk_push_string(ctx, id);duk_put_prop_string(ctx, -2, ILibDuktape_OBJID)
void ILibDuktape_DisplayProperties(duk_context *ctx, duk_idx_t idx);

#endif
