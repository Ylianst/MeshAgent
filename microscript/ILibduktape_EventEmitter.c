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
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_Polyfills.h"

#define ILibDuktape_EventEmitter_MaxEventNameLen		255
#define ILibDuktape_EventEmitter_Data					"\xFF_EventEmitter_Data"
#define ILibDuktape_EventEmitter_RetVal					"\xFF_EventEmitter_RetVal"
#define ILibDuktape_EventEmitter_LastRetValueTable		"\xFF_EventEmitter_LastRetValueTable"
#define ILibDuktape_EventEmitter_GlobalListenerCount	"\xFF_EventEmitter_GlobalListenerCount"
#define ILibDuktape_EventEmitter_Forward_SourceName		"\xFF_EventEmitter_SourceName"
#define ILibDuktape_EventEmitter_Forward_TargetName		"\xFF_EventEmitter_TargetName"
#define ILibDuktape_EventEmitter_Forward_SourceObject	"\xFF_EventEmitter_SourceObject"
#define ILibDuktape_EventEmitter_ForwardTable			"\xFF_EventEmitter_ForwardTable"
#define ILibDuktape_EventEmitter_EventTable				"\xFF_EventEmitter_EventTable"
#define ILibDuktape_EventEmitter_CountTable				"\xFF_EventEmitter_CountTable"

typedef struct ILibDuktape_EventEmitter_EmitStruct
{
	void *func;
	int once;
}ILibDuktape_EventEmitter_EmitStruct;

#ifdef __DOXY__


/*!
\brief Asynchronous event-driven class, that periodically emit named events that cause Function objects ("listeners") to be called.
*/
class EventEmitter
{
public:
	/*!
	\brief Adds the listener function to the end of the listeners array for the event specified by eventName.
	\param eventName \<String\> The name of the event to associate the listener with.
	\param func The listener function to attach.
	*/
	void on(eventName, func);
	/*!
	\brief Adds a one time listener function for the event named by eventName. The next time the event is triggered, this listener is removed and then invoked.
	\param eventName \<String\> The name of the event to associate the listener with.
	\param func The listener function to attach.
	*/
	void once(eventName, func);
	/*!
	\brief Synchronously calls each of the listeners registered for the event named by eventName, in the order they were registered, passing the supplied arguments to each.
	\param eventName \<String\> The named event whose registered listeners are to be dispatched
	\param args <Any> The optional parameters that will be passed to the listener functions.
	*/
	void emit(eventName[, ...args]);

	/*!
	\brief Removes the specified listener from the listener array for the event named eventName.
	\param eventName \<String\> 
	\param listener <func>
	*/
	void removeListener(eventName, listener);
	/*!
	\brief Removes all listeners, or those of the specified eventName. <b>Note:</b> It is bad practice to remove listeners added elsewhere in the code, particularly when the EventEmitter instance was created by some other component or module.
	*
	void removeAllListeners([eventName]);
	\param eventName \<String\> Optional
	*/
	void removeAllListeners([eventName]);

	/*!
	\brief EventEmitter helper class. <b>Note:</b> To use, must <b>require('events')</b>
	*/
	class events
	{
	public:
		/*!
		\brief Adds EventEmitter methods and events to the supplied object
		\param obj Normally, <b>'this'</b> object should be passed, so that EventEmitter can be added to it.
		\return Returns an events instance object that can be used to add events and methods to the EventEmitter implementation that was integrated
		*/
		static events inherits(obj);

		/*!
		\brief Helper method, that will implement the necessary plumbing to expose a named event
		*
		void createEvent(name);
		\param name \<String\> The named event to create
		*/
		void createEvent(name);
		/*!
		\brief Helper method, that will implement the necessary plumbing to expose an object instance method. Particularly useful if the method name is the same as a named event.
		*
		void addMethod(name, func);\n
		The instance method will be implemented as a Property, in which the getter returns the supplied function.
		\param name The name of the instance method to expose
		\param func The function to dispatch when the method is called
		*/
		void addMethod(name, func);
	};
};

#endif
ILibDuktape_EventEmitter* ILibDuktape_EventEmitter_GetEmitter_fromObject(duk_context *ctx, void *objHeapptr)
{
	ILibDuktape_EventEmitter *retVal = NULL;
	duk_push_heapptr(ctx, objHeapptr);						// [obj]
	retVal = ILibDuktape_EventEmitter_GetEmitter(ctx, -1);
	duk_pop(ctx);											// ...
	return(retVal);
}

int ILibDuktape_EventEmitter_HasListeners2(ILibDuktape_EventEmitter *emitter, char *eventName, int defaultValue)
{
	char numtmp[32];
	int retVal = defaultValue;
	if (emitter != NULL && ILibMemory_CanaryOK(emitter) && duk_ctx_is_alive(emitter->ctx))
	{
		sem_wait(&(emitter->listenerCountTableLock));
		if (emitter->listenerCountTableLength > 2 && emitter->listenerCountTableLength < INT32_MAX)
		{
			size_t eventNameLen = strnlen_s(eventName, ILibDuktape_EventEmitter_MaxEventNameLen);
			parser_result *pr = ILibParseString((char*)emitter->listenerCountTable, 1, (int)emitter->listenerCountTableLength - 2, ",", 1);
			if (pr->NumResults > 0)
			{
				parser_result *pr2 = NULL;
				parser_result_field *f = pr->FirstResult;

				while (f != NULL)
				{
					if (f->datalength > 2)
					{
						pr2 = ILibParseString(f->data + 1, 0, f->datalength - 2, "=", 1);
						if (pr2->NumResults == 2)
						{
							if (eventNameLen == pr2->FirstResult->datalength && strncmp(eventName, pr2->FirstResult->data, eventNameLen) == 0)
							{
								if (sizeof(numtmp) > pr2->LastResult->datalength)
								{
									memcpy_s(numtmp, sizeof(numtmp), pr2->LastResult->data, pr2->LastResult->datalength);
									numtmp[pr2->LastResult->datalength] = 0;
									retVal = atoi(numtmp);
									ILibDestructParserResults(pr2);
									break;
								}
							}
						}
						ILibDestructParserResults(pr2);
					}
					f = f->NextResult;
				}
			}
			ILibDestructParserResults(pr);
		}
		sem_post(&(emitter->listenerCountTableLock));
	}
	return(retVal);
}

duk_ret_t ILibDuktape_EventEmitter_DefaultNewListenerHandler(duk_context *ctx)
{
	char *currentEventName = (char*)duk_require_string(ctx, 0);

	duk_push_current_function(ctx);
	char *name = Duktape_GetStringPropertyValue(ctx, -1, "event_name", NULL);
	void *callback = Duktape_GetPointerProperty(ctx, -1, "event_callback");
	if (strcmp(name, currentEventName) == 0)
	{
		duk_push_heapptr(ctx, callback);		// [callback]
		duk_push_this(ctx);						// [callback][this]
		duk_dup(ctx, 0);						// [callback][this][name]
		duk_dup(ctx, 1);						// [callback][this][name][handler]
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "EventEmitter.DefaultNewListenerHandler() "); }
		duk_pop(ctx);							// ...
	}

	return(0);
}

void ILibDuktape_EventEmitter_emit_removeListener(duk_context *ctx, const char* eventName, duk_idx_t objix, duk_idx_t listenerix)
{
	ILibDuktape_EventEmitter_SetupEmitEx(ctx, objix, "removeListener");				// [emit][this][removeListener]
	duk_push_string(ctx, eventName);												// [emit][this][removeListener][eventName]
	duk_get_prop_string(ctx, listenerix < 0 ? listenerix - 4 : listenerix, "func");	// [emit][this][removeListener][eventName][func]
	if (duk_pcall_method(ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "events.onRemoveListener(%s) error ", eventName); }
	duk_pop(ctx);																	// ...
}

duk_ret_t ILibDuktape_EventEmitter_emit(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	duk_size_t nameLen;
	if (!duk_is_string(ctx, 0)) { return ILibDuktape_Error(ctx, "EventEmitter.emit(): Invalid Parameter Name/Type"); }
	char *name = (char*)duk_get_lstring(ctx, 0, &nameLen);
	duk_size_t arrSize, arrIndex;
	int j;
	int emitted = 0;

	duk_require_stack(ctx, 4 + nargs + DUK_API_ENTRY_STACK);				// This will make sure we have enough stack space to get the emitter object
	duk_push_this(ctx);														// [object]
	
	ILibDuktape_EventEmitter *data = (ILibDuktape_EventEmitter*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_EventEmitter_Data);
	char *objid = Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_OBJID, "unknown");
	duk_push_heapptr(ctx, data->retValTable);								// [object][retTable]
	duk_push_heapptr(ctx, data->table);										// [object][retTable][table]
	if (!duk_has_prop_string(ctx, -1, name))
	{
		if (data->eventType == ILibDuktape_EventEmitter_Type_IMPLICIT)
		{
			duk_push_false(ctx);  return(1); 
		}
		else
		{
			return ILibDuktape_Error(ctx, "EventEmitter.emit(): Event '%s' not found on object '%s'", name, objid);
		}
	}
	duk_get_prop_string(ctx, -1, name);										// [object][retTable][table][array]
	duk_array_clone(ctx, -1);												// [object][retTable][table][array][array]
	do
	{
		arrSize = duk_get_length(ctx, -2);
		for (arrIndex = 0; arrIndex < arrSize; ++arrIndex)
		{
			if (Duktape_GetIntPropertyValueFromHeapptr(ctx, Duktape_GetHeapptrIndexProperty(ctx, -2, (duk_uarridx_t)arrIndex), "once", 0) != 0)
			{
				// This handler is a 'once' handler, so we need to delete it here
				duk_get_prop_index(ctx, -2, (duk_uarridx_t)arrIndex);			// [object][retTable][table][array][array][listener]
				duk_array_remove(ctx, -3, (duk_uarridx_t)arrIndex);		

				// Now we need to emit 'removeListener'
				ILibDuktape_EventEmitter_emit_removeListener(ctx, name, -6, -1);// [object][retTable][table][array][array][listener]
				duk_pop(ctx);													// [object][retTable][table][array][array]
				break;
			}
		}
	} while (arrIndex < arrSize);
	duk_remove(ctx, -2);													// [object][retTable][table][array]

	// Before we dispatch, lets clear our last return values for this event
	duk_push_heapptr(ctx, data->retValTable);								// [object][retTable][table][array][retTable]
	duk_del_prop_lstring(ctx, -1, name, nameLen);
	duk_pop(ctx);															// [object][retTable][table][array]
	duk_del_prop_string(ctx, -4, ILibDuktape_EventEmitter_RetVal);
	data->lastReturnValue = NULL;

	while (duk_get_length(ctx, -1) > 0)
	{
		emitted = 1;
		duk_array_shift(ctx, -1);											// [object][retTable][table][array][J]
		duk_get_prop_string(ctx, -1, "func");								// [object][retTable][table][array][J][func]
		duk_push_this(ctx);													// [object][retTable][table][array][J][func][this]
		for (j = 1; j < nargs; ++j)
		{
			duk_dup(ctx, j);												// [object][retTable][table][array][J][func][this][..args..]
		}
		if (duk_pcall_method(ctx, nargs - 1) != 0)							// [object][retTable][table][array][J][ret]
		{
			// Invocation Error
			if (strcmp(duk_safe_to_string(ctx, -1), "Process.exit() forced script termination") == 0)
			{
				duk_dup(ctx, -1);
				duk_throw(ctx);
				return(DUK_RET_ERROR);
			}
			else
			{
				duk_get_prop_string(ctx, -2, "func");						// [object][retTable][table][array][J][e][func]
				return(ILibDuktape_Error(ctx, "EventEmitter.emit(): Event dispatch for '%s' on '%s' threw an exception: %s in method '%s()'", name, objid, duk_safe_to_string(ctx, -2), Duktape_GetStringPropertyValue(ctx, -1, "name", "unknown_method")));
			}
		}
		if (!duk_is_undefined(ctx, -1))										// [object][retTable][table][array][J][ret]
		{
			duk_dup(ctx, -1);												// [object][retTable][table][array][J][ret][ret]
			duk_put_prop_string(ctx, -7, ILibDuktape_EventEmitter_RetVal);	// [object][retTable][table][array][J][ret]
			data->lastReturnValue = duk_get_heapptr(ctx, -1);
			duk_put_prop_lstring(ctx, -5, name, nameLen);					// [object][retTable][table][array][J]
			duk_pop(ctx);													// [object][retTable][table][array]
		}
		else
		{
			duk_pop_2(ctx);													// [object][retTable][table][array]
		}
	}
	duk_push_boolean(ctx, emitted);
	return(1);
}
int ILibDuktape_EventEmitter_PrependOnce(duk_context *ctx, duk_idx_t i, char *eventName, duk_c_function func)
{
	int retVal = 1;

	duk_dup(ctx, i);										// [this]
	duk_get_prop_string(ctx, -1, "prependOnceListener");	// [this][prependOnce]
	duk_swap_top(ctx, -2);									// [prependOnce][this]
	duk_push_string(ctx, eventName);						// [prependOnce][this][eventName]
	duk_push_c_function(ctx, func, DUK_VARARGS);			// [prependOnce][this][eventName][func]
	if (duk_pcall_method(ctx, 2) != 0) { retVal = 0; }
	duk_pop(ctx);											// ...
	return(retVal);
}

int ILibDuktape_EventEmitter_AddOnce(ILibDuktape_EventEmitter *emitter, char *eventName, void *heapptr)
{
	int retVal = 1;
	duk_push_heapptr(emitter->ctx, emitter->object);		// [obj]
	duk_get_prop_string(emitter->ctx, -1, "once");			// [obj][once/func]
	duk_swap_top(emitter->ctx, -2);							// [once/func][this]
	duk_push_string(emitter->ctx, eventName);				// [once/func][this][eventName]
	duk_push_heapptr(emitter->ctx, heapptr);				// [once/func][this][eventName][callback]
	if (duk_pcall_method(emitter->ctx, 2) == 0) { retVal = 0; }
	duk_pop(emitter->ctx);									// ...

	return retVal;
}
int ILibDuktape_EventEmitter_AddOnceEx3(duk_context *ctx, duk_idx_t idx, char *eventName, duk_c_function func)
{
	int retVal = 1;

	duk_prepare_method_call(ctx, idx, "once");														// [once][this]
	duk_push_string(ctx, eventName);																// [once][this][event]
	duk_push_c_function(ctx, func, DUK_VARARGS);													// [once][this][event][func]
	retVal = duk_pcall_method(ctx, 2);																// [ret]
	duk_pop(ctx);																					// ...

	return(retVal);
}
int ILibDuktape_EventEmitter_AddOnceEx(ILibDuktape_EventEmitter *emitter, char *eventName, duk_c_function func, duk_idx_t funcArgs)
{
	int retVal = 1;

	duk_push_heapptr(emitter->ctx, emitter->object);							// [obj]
	duk_prepare_method_call(emitter->ctx, -1, "once");							// [obj][once][this]
	duk_push_string(emitter->ctx, eventName);									// [obj][once][this][eventName]
	duk_push_c_function(emitter->ctx, func, funcArgs);							// [obj][once][this][eventName][func]
	retVal = duk_pcall_method(emitter->ctx, 2);									// [obj][ret]
	duk_pop_2(emitter->ctx);													// ...

	return(retVal);
}
int ILibDuktape_EventEmitter_AddOn(ILibDuktape_EventEmitter *emitter, char *eventName, void *heapptr)
{
	int retVal = 1;
	duk_push_heapptr(emitter->ctx, emitter->object);		// [obj]
	duk_get_prop_string(emitter->ctx, -1, "on");			// [obj][once/func]
	duk_swap_top(emitter->ctx, -2);							// [once/func][this]
	duk_push_string(emitter->ctx, eventName);				// [once/func][this][eventName]
	duk_push_heapptr(emitter->ctx, heapptr);				// [once/func][this][eventName][callback]
	if (duk_pcall_method(emitter->ctx, 2) == 0) { retVal = 0; }
	duk_pop(emitter->ctx);									// ...

	return retVal;
}
duk_ret_t ILibDuktape_EventEmitter_on(duk_context *ctx)
{
	duk_size_t propNameLen;
	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "EventEmitter.on(): Invalid Parameter Name/Type")); }
	char *propName = (char*)duk_get_lstring(ctx, 0, &propNameLen);
	void *callback = duk_require_heapptr(ctx, 1);
	ILibDuktape_EventEmitter *data;
	int once;
	int prepend;

	duk_require_stack(ctx, 10);

	duk_push_current_function(ctx);
	once = Duktape_GetIntPropertyValue(ctx, -1, "once", 0);
	prepend = Duktape_GetIntPropertyValue(ctx, -1, "prepend", 0);


	duk_push_this(ctx);														// [object]
	data = (ILibDuktape_EventEmitter*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_EventEmitter_Data);
	duk_push_heapptr(ctx, data->table);										// [object][table]
	if (!duk_has_prop_string(ctx, -1, propName)) { duk_push_array(ctx); duk_put_prop_string(ctx, -2, propName); }
	duk_get_prop_string(ctx, -1, propName);									// [object][table][array]

	duk_push_object(ctx);													// [object][table][array][handler]
	duk_dup(ctx, 1); duk_put_prop_string(ctx, -2, "func");
	duk_push_int(ctx, once); duk_put_prop_string(ctx, -2, "once");

	if (!(propNameLen == 11 && strncmp(propName, "newListener", 11) == 0) && !(propNameLen == 12 && strncmp(propName, "newListener2", 12) == 0))
	{
		// Only emit 'newListener' when the event itself isn't 'newListener' or 'newListener2'
		ILibDuktape_EventEmitter_SetupEmit(ctx, data->object, "newListener");	// [emit][this][newListener]
		duk_push_lstring(ctx, propName, propNameLen);							// [emit][this][newListener][propName]
		duk_push_heapptr(ctx, callback);										// [emit][this][newListener][propName][callback]
		duk_call_method(ctx, 3); duk_pop(ctx);									// ...
	}

	if (prepend != 0)
	{
		duk_array_unshift(ctx, -2);												// [object][table][array]
	}
	else
	{
		duk_array_push(ctx, -2);												// [object][table][array]
	}

	if (!(propNameLen == 11 && strncmp(propName, "newListener", 11) == 0) && !(propNameLen == 12 && strncmp(propName, "newListener2", 12) == 0))
	{
		// Only emit 'newListener2' when the event itself isn't 'newListener' or 'newListener2'
		ILibDuktape_EventEmitter_SetupEmit(ctx, data->object, "newListener2");	// [emit][this][newListener2]
		duk_push_lstring(ctx, propName, propNameLen);							// [emit][this][newListener2][propName]
		duk_push_heapptr(ctx, callback);										// [emit][this][newListener2][propName][callback]
		duk_call_method(ctx, 3); duk_pop(ctx);									// ...
	}

	duk_push_this(ctx);
	return 1;
}
ILibDuktape_EventEmitter* ILibDuktape_EventEmitter_GetEmitter_fromThis(duk_context *ctx)
{
	ILibDuktape_EventEmitter *retVal = NULL;
	duk_push_this(ctx);															// [this]
	retVal = ILibDuktape_EventEmitter_GetEmitter_fromCurrent(ctx);
	duk_pop(ctx);																// ...
	return retVal;
}
ILibDuktape_EventEmitter* ILibDuktape_EventEmitter_GetEmitter(duk_context *ctx, duk_idx_t i)
{
	ILibDuktape_EventEmitter *retVal = (ILibDuktape_EventEmitter*)Duktape_GetBufferProperty(ctx, i, ILibDuktape_EventEmitter_Data);
	return retVal;
}
duk_ret_t ILibDuktape_EventEmitter_removeListener(duk_context *ctx)
{
	char *eventName = (char*)duk_require_string(ctx, 0);
	void *func = duk_require_heapptr(ctx, 1);

	duk_size_t arrSize;
	duk_uarridx_t arrIndex;

	duk_push_this(ctx);														// [object]
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_EventTable);		// [object][table]
	if (duk_has_prop_string(ctx, -1, eventName))
	{
		duk_get_prop_string(ctx, -1, eventName);							// [object][table][array]
		arrSize = duk_get_length(ctx, -1);
		for (arrIndex = 0; arrIndex < arrSize; ++arrIndex)
		{
			if (Duktape_GetHeapptrPropertyValueFromHeapptr(ctx, Duktape_GetHeapptrIndexProperty(ctx, -1, arrIndex), "func") == func)
			{
				duk_get_prop_index(ctx, -1, arrIndex);						// [object][table][array][listener]
				duk_array_remove(ctx, -2, arrIndex);						// [object][table][array][listener]
				ILibDuktape_EventEmitter_emit_removeListener(ctx, eventName, -4, -1);
				duk_pop(ctx);												// [object][table][array]
				break;
			}
		}
	}

	return(0);
}
duk_ret_t ILibDuktape_EventEmitter_removeAllListeners(duk_context *ctx)
{
	char *eventName = (char*)duk_require_string(ctx, 0);

	duk_push_this(ctx);														// [object]
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_EventTable);		// [object][table]
	if (duk_has_prop_string(ctx, -1, eventName))
	{
		duk_get_prop_string(ctx, -1, eventName);							// [object][table][array]
		duk_array_clone(ctx, -1);											// [object][table][array][clone]
		duk_del_prop_string(ctx, -3, eventName);							// [object][table][array][clone]
		duk_remove(ctx, -2);												// [object][table][clone]
		duk_push_array(ctx);												// [object][table][clone][empty]
		duk_put_prop_string(ctx, -3, eventName);							// [object][table][clone]
		
		while (duk_get_length(ctx, -1) > 0)
		{
			duk_array_shift(ctx, -1);										// [object][table][clone][listener]
			ILibDuktape_EventEmitter_emit_removeListener(ctx, eventName, -4, -1);
			duk_pop(ctx);													// [object][table][clone]
		}
	}

	return(0);
}

duk_ret_t ILibDuktape_EventEmitter_EmbeddedFinalizer(duk_context *ctx)
{
	ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, 0), "~");	// [emit][this][~]
	duk_dup(ctx, 0);														// [emit][this][~][self]
	if (g_displayFinalizerMessages)
	{
		printf("+-+- Finalizer Event for: %s [%p] -+-+\n", Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_OBJID, "UNKNOWN"), duk_get_heapptr(ctx, -1));
		if (strcmp(Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_OBJID, "UNKNOWN"), "UNKNOWN") == 0)
		{
			int first = 1;
			ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_GetEmitter(ctx, -1);
			if (emitter != NULL)
			{
				printf("UNKNOWN: Listeners=%d\n", ILibDuktape_EventEmitter_HasListeners(emitter, "~"));

				duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);			// [enumerator]
				while (duk_next(ctx, -1, 1))
				{
					printf("Key: %s, Val: %s\n", duk_get_string(ctx, -2), duk_get_string(ctx, -1));// [enumerator][key][val]
					duk_pop_2(ctx);											// [enumerator]
				}
				duk_pop(ctx);												// ...
				printf("Event Names: ");

				duk_push_heapptr(ctx, emitter->table);						// [table]
				duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);			// [table][enumerator]
				while (duk_next(ctx, -1, 0))								// [table][enumerator][key]
				{
					printf("%s%s", (first == 0 ? ", " : ""), duk_get_string(ctx, -1));
					first = 0;
					duk_pop(ctx);											// [table][enumerator]
				}
				duk_pop_2(ctx);												// ...
				printf("\n");
			}
		}
	}
	if (duk_pcall_method(ctx, 2) != 0)
	{
		ILibDuktape_Process_UncaughtExceptionEx(ctx, "Error in Finalizer: [Invalid C function means you forgot to return 0] ");
	}

	ILibDuktape_EventEmitter *data = ILibDuktape_EventEmitter_GetEmitter(ctx, 0);
	if (data == NULL) { return(ILibDuktape_Error(ctx, "Internal Error")); }			// This is deadcode, will never occur, but is here because Klockwork thinks this could happen
	if (!ILibMemory_CanaryOK(data) || !duk_ctx_is_alive(data->ctx)) { return(0); }
	sem_destroy(&(data->listenerCountTableLock));

	// We need to clear the Native Dispatcher, while destroying the Hashtable
	memset(data, 0, sizeof(ILibDuktape_EventEmitter));
	return(0);
}
duk_ret_t ILibDuktape_EventEmitter_emitReturnValue(duk_context *ctx)
{
	int retVal = 1;
	int nargs = duk_get_top(ctx);
	duk_push_this(ctx);																// [this]

	switch (nargs)
	{
	case 0:
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_RetVal);				// [this][retVal]
		break;
	case 1:
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_LastRetValueTable);	// [this][table]
		duk_dup(ctx, 0);															// [this][table][key]
		duk_get_prop(ctx, -2);														// [this][table][val]
		break;
	case 2:
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_LastRetValueTable);	// [this][table]
		duk_dup(ctx, 0);															// [this][table][key]
		duk_dup(ctx, 1);															// [this][table][key][value]
		duk_put_prop(ctx, -3);
		retVal = 0;
		break;
	default:
		retVal = ILibDuktape_Error(ctx, "INVALID Parameter Count");
		break;
	}

	return(retVal);
}
duk_ret_t ILibDuktape_EventEmitter_listenerCount(duk_context *ctx)
{
	char *name = (char*)duk_require_string(ctx, 0);
	duk_push_this(ctx);													// [events]
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_EventTable);	// [events][table]
	if (duk_has_prop_string(ctx, -1, name))
	{
		duk_get_prop_string(ctx, -1, name);								// [events][table][array]
		duk_push_uint(ctx, (duk_uint_t)duk_get_length(ctx, -1));		// [events][table][array][len]
	}
	else
	{
		duk_push_uint(ctx, 0);
	}
	return(1);
}

duk_ret_t ILibDuktape_EventEmitter_eventNames(duk_context *ctx)
{
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_GetEmitter_fromThis(ctx);
	duk_push_array(ctx);							// [array]
	duk_push_heapptr(ctx, emitter->table);			// [array][table]
	duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);// [array][table][enumerator]
	while (duk_next(ctx, -1, 0))					// [array][table][enumerator][key]
	{
		duk_array_push(ctx, -4);					// [array][table][enumerator]
	}
	duk_pop_2(ctx);									// [array]
	return(1);
}
duk_ret_t ILibDuktape_EventEmitter_listeners(duk_context *ctx)
{
	duk_uarridx_t x;
	duk_size_t sz;

	char *eventName = (char*)duk_require_string(ctx, 0);
	duk_push_this(ctx);													// [object]
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_EventTable);	// [object][table]
	duk_push_array(ctx);												// [object][table][array]
	if (duk_has_prop_string(ctx, -2, eventName))
	{
		duk_get_prop_string(ctx, -2, eventName);						// [object][table][array][handlers]
		sz = duk_get_length(ctx, -1);
		for (x = 0; x < sz; ++x)
		{
			duk_push_heapptr(ctx, Duktape_GetHeapptrPropertyValueFromHeapptr(ctx, Duktape_GetHeapptrIndexProperty(ctx, -1, x), "func"));
			duk_array_push(ctx, -3);
		}
		duk_pop(ctx);													// [object][table][array]
	}
	return(1);
}
duk_ret_t ILibDuktape_EventEmitter_listeners_tableinit_findIndex(duk_context *ctx)
{
	duk_push_current_function(ctx);		// [func]
	char *eventName = Duktape_GetStringPropertyValue(ctx, -1, "eventName", "");

	duk_dup(ctx, 0);					// [func][string]
	duk_string_split(ctx, -1, "=");		// [func][string][array]
	duk_array_shift(ctx, -1);			// [func][string][array][string]
	if (strcmp(duk_get_string(ctx, -1), eventName) == 0)
	{
		duk_push_true(ctx);
	}
	else
	{
		duk_push_false(ctx);
	}
	return(1);
}
duk_ret_t ILibDuktape_EventEmitter_listeners_tableinit(duk_context *ctx)
{
	duk_push_current_function(ctx);
	int isAdd = Duktape_GetIntPropertyValue(ctx, -1, "add", 0);
	const char *eventName = duk_require_string(ctx, 0);

	duk_push_this(ctx);													
	ILibDuktape_EventEmitter *emitter = (ILibDuktape_EventEmitter*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_EventEmitter_Data);

	sem_wait(&(emitter->listenerCountTableLock));
	duk_push_global_object(ctx);											// [g]
	duk_get_prop_string(ctx, -1, "JSON");									// [g][JSON]
	duk_prepare_method_call(ctx, -1, "parse");								// [g][JSON][parse][this]
	duk_push_string(ctx, emitter->listenerCountTable);						// [g][JSON][parse][this][string]
	if (duk_pcall_method(ctx, 1) == 0)										// [g][JSON][array]
	{
		duk_prepare_method_call(ctx, -1, "findIndex");						// [g][JSON][array][findIndex][this]
		duk_push_c_function(ctx, ILibDuktape_EventEmitter_listeners_tableinit_findIndex, DUK_VARARGS);// .[this][func]
		duk_push_string(ctx, eventName); duk_put_prop_string(ctx, -2, "eventName");
		if (duk_pcall_method(ctx, 1) == 0)									// [g][JSON][array][index]
		{
			int index = duk_get_int(ctx, -1);
			if (duk_is_number(ctx, -1) && duk_get_int(ctx, -1) >= 0)
			{
				duk_get_prop_index(ctx, -2, duk_get_uint(ctx, -1));			// [g][JSON][array][index][string]
			}
			else
			{
				duk_push_sprintf(ctx, "%s=0", eventName);					// [g][JSON][array][index][string]
			}
			duk_string_split(ctx, -1, "=");									// [g][JSON][array][index][string][array]
			duk_array_pop(ctx, -1);											// [g][JSON][array][index][string][array][int]
			int v = duk_to_int(ctx, -1);									// [g][JSON][array][index][string][array][int]
			if (isAdd) 
			{
				++v;
			}
			else
			{
				if (--v < 0) { v = 0; }
			}
			duk_push_sprintf(ctx, "%d", v);									// [g][JSON][array][index][string][array][int][new]
			duk_array_push(ctx, -3);										// [g][JSON][array][index][string][array][int]
			duk_pop(ctx);													// [g][JSON][array][index][string][array]
			duk_array_join(ctx, -1, "=");									// [g][JSON][array][index][string][array][string]
			const char *tmp = duk_get_string(ctx, -1);
			if (index < 0)
			{
				duk_array_push(ctx, -5);									// [g][JSON][array][index][string][array]
				duk_push_string(ctx, tmp);									// [g][JSON][array][index][string][array][string]
			}
			else
			{
				duk_array_replace(ctx, -5, index, tmp);
			}
			duk_prepare_method_call(ctx, -6, "stringify");					// [g][JSON][array][index][string][array][string][stringify][this]
			duk_dup(ctx, -7);												// [g][JSON][array][index][string][array][string][stringify][this][array]
			if (duk_pcall_method(ctx, 1) == 0)								// [g][JSON][array][index][string][array][string][string]
			{
				duk_size_t len = 0;
				emitter->listenerCountTable = duk_get_lstring(ctx, -1, &len);
				emitter->listenerCountTableLength = len;
				duk_push_this(ctx);											// [g][JSON][array][index][string][array][string][string][this]
				duk_swap_top(ctx, -2);										// [g][JSON][array][index][string][array][string][this][string]
				duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_CountTable);
			}
		}
	}
	sem_post(&(emitter->listenerCountTableLock));
	return(0);
}

ILibDuktape_EventEmitter* ILibDuktape_EventEmitter_Create(duk_context *ctx)
{
	ILibDuktape_EventEmitter *retVal;
	if (duk_has_prop_string(ctx, -1, ILibDuktape_EventEmitter_Data))
	{
		// This object already has an EventEmitter
		return((ILibDuktape_EventEmitter*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_EventEmitter_Data));
	}

	retVal = (ILibDuktape_EventEmitter*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_EventEmitter));	// [event][data]
	duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_Data);									// [event]

	retVal->ctx = ctx;
	retVal->object = duk_get_heapptr(ctx, -1);

	duk_push_object(ctx); 
	retVal->table = duk_get_heapptr(ctx, -1);
	duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_EventTable);

	duk_push_object(ctx);
	retVal->retValTable = duk_get_heapptr(ctx, -1);
	duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_LastRetValueTable);
	sem_init(&(retVal->listenerCountTableLock), 0, 1);
	retVal->listenerCountTable = (char*)"[]";
	retVal->listenerCountTableLength = 2;

	ILibDuktape_CreateInstanceMethodWithProperties(ctx, "once", ILibDuktape_EventEmitter_on, 2, 2, "once", duk_push_int_ex(ctx, 1), "prepend", duk_push_int_ex(ctx, 0));
	ILibDuktape_CreateInstanceMethodWithProperties(ctx, "on", ILibDuktape_EventEmitter_on, 2, 2, "once", duk_push_int_ex(ctx, 0), "prepend", duk_push_int_ex(ctx, 0));
	ILibDuktape_CreateInstanceMethodWithProperties(ctx, "prependOnceListener", ILibDuktape_EventEmitter_on, 2, 2, "once", duk_push_int_ex(ctx, 1), "prepend", duk_push_int_ex(ctx, 1));
	ILibDuktape_CreateInstanceMethodWithProperties(ctx, "prependListener", ILibDuktape_EventEmitter_on, 2, 2, "once", duk_push_int_ex(ctx, 0), "prepend", duk_push_int_ex(ctx, 1));
	
	ILibDuktape_CreateInstanceMethod(ctx, "eventNames", ILibDuktape_EventEmitter_eventNames, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "listenerCount", ILibDuktape_EventEmitter_listenerCount, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "listeners", ILibDuktape_EventEmitter_listeners, 1);

	ILibDuktape_EventEmitter_CreateEventEx(retVal, "removeListener");
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "removeListener", ILibDuktape_EventEmitter_removeListener, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "removeAllListeners", ILibDuktape_EventEmitter_removeAllListeners, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "emit", ILibDuktape_EventEmitter_emit, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "emit_returnValue", ILibDuktape_EventEmitter_emitReturnValue, DUK_VARARGS);

	duk_push_heap_stash(ctx);
	if (duk_has_prop_string(ctx, -1, ILibDuktape_EventEmitter_GlobalListenerCount))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_GlobalListenerCount);
		retVal->totalListeners = (unsigned int *)Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop(ctx);
	}
	else
	{
		Duktape_PushBuffer(ctx, sizeof(unsigned int));
		retVal->totalListeners = (unsigned int *)Duktape_GetBuffer(ctx, -1, NULL);
		duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_GlobalListenerCount);
		*(retVal->totalListeners) = 0;
	}
	duk_pop(ctx);

	ILibDuktape_EventEmitter_CreateEventEx(retVal, "~");
	duk_push_c_function(ctx, ILibDuktape_EventEmitter_EmbeddedFinalizer, 1);
	duk_set_finalizer(ctx, -2);

	ILibDuktape_EventEmitter_CreateEventEx(retVal, "newListener");
	ILibDuktape_EventEmitter_CreateEventEx(retVal, "newListener2");

	duk_events_setup_on(ctx, -1, "newListener2", ILibDuktape_EventEmitter_listeners_tableinit);		// [on][this][newListener][func]
	duk_push_int(ctx, 1); duk_put_prop_string(ctx, -2, "add");
	duk_pcall_method(ctx, 2); duk_pop(ctx);															// ...

	duk_events_setup_on(ctx, -1, "removeListener", ILibDuktape_EventEmitter_listeners_tableinit);	// [on][this][removeListener][func]
	duk_push_int(ctx, 0); duk_put_prop_string(ctx, -2, "add");
	duk_pcall_method(ctx, 2); duk_pop(ctx);															// ...

	return retVal;
}

duk_ret_t ILibDuktape_EventEmitter_AddHookSink(duk_context *ctx)
{
	duk_push_this(ctx);															// [object]
	duk_push_current_function(ctx);												// [object][func]
	char *eventName = Duktape_GetStringPropertyValue(ctx, -1, "eventName", "");
	if (strcmp(eventName, duk_require_string(ctx, 0)) == 0)
	{
		ILibDuktape_EventEmitter_HookHandler handler = (ILibDuktape_EventEmitter_HookHandler)Duktape_GetPointerProperty(ctx, -1, "handler");
		ILibDuktape_EventEmitter *emitter = (ILibDuktape_EventEmitter*)Duktape_GetBufferProperty(ctx, -2, ILibDuktape_EventEmitter_Data);
		if (handler != NULL) { handler(emitter, eventName, duk_require_heapptr(ctx, 1)); }
	}
	return(0);
}
void ILibDuktape_EventEmitter_AddHook(ILibDuktape_EventEmitter *emitter, char *eventName, ILibDuktape_EventEmitter_HookHandler handler)
{
	if (ILibMemory_CanaryOK(emitter) && duk_ctx_is_alive(emitter->ctx))
	{
		duk_push_heapptr(emitter->ctx, emitter->object);									// [object]
		duk_prepare_method_call(emitter->ctx, -1, "on");									// [object][on][this]
		duk_push_string(emitter->ctx, "newListener");										// [object][on][this][newListener]
		duk_push_c_function(emitter->ctx, ILibDuktape_EventEmitter_AddHookSink, DUK_VARARGS);// [object][on][this][newListener][func]
		duk_push_string(emitter->ctx, eventName); duk_put_prop_string(emitter->ctx, -2, "eventName");
		duk_push_pointer(emitter->ctx, handler); duk_put_prop_string(emitter->ctx, -2, "handler");
		if (duk_pcall_method(emitter->ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(emitter->ctx, "events.addHook() Error"); }
		duk_pop_2(emitter->ctx);															// ...
	}
}
void ILibDuktape_EventEmitter_ClearHook(ILibDuktape_EventEmitter *emitter, char *eventName)
{
	if (ILibMemory_CanaryOK(emitter) && duk_ctx_is_alive(emitter->ctx))
	{
		duk_push_heapptr(emitter->ctx, emitter->object);						// [object]
		duk_prepare_method_call(emitter->ctx, -1, "listeners");					// [object][listeners][this]
		duk_push_string(emitter->ctx, "newListener");							// [object][listeners][this][newListener]
		if (duk_pcall_method(emitter->ctx, 1) == 0)								// [object][array/error]
		{
			while (duk_get_length(emitter->ctx, -1) > 0)
			{
				duk_array_pop(emitter->ctx, -1);								// [object][array][func]
				if (strcmp(eventName, Duktape_GetStringPropertyValue(emitter->ctx, -1, "eventName", "")) == 0)
				{
					duk_prepare_method_call(emitter->ctx, -3, "removeListener");// [object][array][func][removeListener][this]
					duk_push_string(emitter->ctx, "newListener");				// [object][array][func][removeListener][this][newListener]
					duk_dup(emitter->ctx, -4);									// [object][array][func][removeListener][this][newListener][func]
					duk_pcall_method(emitter->ctx, 2); duk_pop(emitter->ctx);	// [object][array][func]
				}
				duk_pop(emitter->ctx);											// [object][array]
			}
		}
		duk_pop_2(emitter->ctx);												// ...
	}
}
duk_ret_t ILibDuktape_EventEmitter_SetEvent(duk_context *ctx)
{
	char *propName;
	duk_size_t propNameLen;

	duk_push_current_function(ctx);												// [func]
	duk_get_prop_string(ctx, -1, "eventName");									// [func][name]
	propName = (char*)duk_get_lstring(ctx, -1, &propNameLen);

	duk_push_this(ctx);															// [obj]
	if (duk_is_null_or_undefined(ctx, 0))
	{
		// NULL was passed, we'll need to clear all listeners. 
		duk_prepare_method_call(ctx, -1, "removeAllListeners");					// [obj][removeAllListeners][this]
		duk_push_string(ctx, propName);											// [obj][removeAllListeners][this][eventName]
		duk_call_method(ctx, 1);												// [obj][ret]
	}
	else
	{
		// Hook new event
		duk_prepare_method_call(ctx, -1, "on");									// [obj][on][this]
		duk_push_string(ctx, propName);											// [obj][on][this][eventName]
		duk_dup(ctx, 0);														// [obj][on][this][eventName][handler]
		duk_call_method(ctx, 2);
	}
	return(0);

	//char *propName;
	//duk_size_t propNameLen;
	//ILibDuktape_EventEmitter *data;
	//ILibLinkedList eventList = NULL;

	//duk_push_current_function(ctx);												// [func]
	//duk_get_prop_string(ctx, -1, "eventName");									// [func][name]
	//propName = (char*)duk_get_lstring(ctx, -1, &propNameLen);

	//duk_push_this(ctx);															// [obj]
	//duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_TempObject);			// [this][tmp]
	//duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_Data);				// [this][tmp][data]
	//data = (ILibDuktape_EventEmitter*)Duktape_GetBuffer(ctx, -1, NULL);

	//eventList = ILibHashtable_Get(data->eventTable, NULL, propName, (int)propNameLen);
	//if (eventList == NULL) { return(ILibDuktape_Error(ctx, "EventEmitter(): Cannot add listener becuase event '%s' is not found", propName)); }

	//if (duk_is_null_or_undefined(ctx, 0))
	//{
	//	// NULL was passed, we'll need to clear all listeners. 
	//	duk_push_this(ctx);														// [obj]
	//	duk_get_prop_string(ctx, -1, "removeAllListeners");						// [obj][removeAll]
	//	duk_swap_top(ctx, -2);													// [removeAll][this]
	//	duk_push_string(ctx, propName);											// [removeAll][this][name]
	//	duk_call_method(ctx, 1); duk_pop(ctx);
	//}
	//else
	//{
	//	ILibDuktape_EventEmitter_AddOn(data, propName, duk_get_heapptr(ctx, 0));
	//}

	//return 0;
}

void ILibDuktape_EventEmitter_RemoveAllListeners(ILibDuktape_EventEmitter *emitter, char *eventName)
{
	duk_push_heapptr(emitter->ctx, emitter->object);				// [this]
	duk_get_prop_string(emitter->ctx, -1, "removeAllListeners");	// [this][func]
	duk_swap_top(emitter->ctx, -2);									// [func][this]
	duk_push_string(emitter->ctx, eventName);						// [func][this][eventName]
	if (duk_pcall_method(emitter->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(emitter->ctx, "EventEmitter.removeAllListeners(): "); }
	duk_pop(emitter->ctx);											// ...
}

void ILibDuktape_EventEmitter_CreateEventEx(ILibDuktape_EventEmitter *emitter, char *eventName)
{
	duk_push_heapptr(emitter->ctx, emitter->object);									// [obj]
	duk_get_prop_string(emitter->ctx, -1, ILibDuktape_EventEmitter_EventTable);			// [obj][table]
	if (duk_has_prop_string(emitter->ctx, -1, eventName) == 0)
	{
		duk_push_array(emitter->ctx); duk_put_prop_string(emitter->ctx, -2, eventName);
		duk_pop(emitter->ctx);															// [obj]

		// Create the Property Setter
		duk_push_string(emitter->ctx, eventName);										// [obj][prop]
		duk_push_c_function(emitter->ctx, ILibDuktape_EventEmitter_SetEvent, 1);		// [obj][prop][setFunc]
		duk_push_string(emitter->ctx, eventName);										// [obj][prop][setFunc][name]
		duk_put_prop_string(emitter->ctx, -2, "eventName");								// [obj][prop][setFunc]

		duk_def_prop(emitter->ctx, -3, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_SETTER);	// [obj]
		duk_pop(emitter->ctx);															// ...
	}
	else
	{
		// Already Exists
		duk_pop_2(emitter->ctx);														// ...
	}
}

duk_ret_t ILibDuktape_EventEmitter_Inherits_createEvent(duk_context *ctx)
{
	char *name = (char*)duk_require_string(ctx, 0);
	ILibDuktape_EventEmitter *emitter;

	duk_push_this(ctx);									// [emitterUtils]
	duk_get_prop_string(ctx, -1, "emitter");			// [emitterUtils][ptr]
	emitter = (ILibDuktape_EventEmitter*)duk_get_pointer(ctx, -1);
	duk_pop(ctx);										// [emitterUtils]

	ILibDuktape_EventEmitter_CreateEventEx(emitter, name);
	return(1);
}
duk_ret_t ILibDuktape_EventEmitter_Inherits_addMethod(duk_context *ctx)
{
	ILibDuktape_EventEmitter *emitter;
	duk_push_this(ctx);									// [emitterUtils]
	duk_get_prop_string(ctx, -1, "emitter");			// [emitterUtils][ptr]
	emitter = (ILibDuktape_EventEmitter*)duk_get_pointer(ctx, -1);

	duk_push_heapptr(ctx, emitter->object);				// [emitterUtils][ptr][target]
	ILibDuktape_CreateProperty_InstanceMethodEx(ctx, (char*)duk_require_string(ctx, 0), duk_require_heapptr(ctx, 1));
	
	duk_push_this(ctx);
	return(1);
}

duk_ret_t ILibDuktape_EventEmitter_Inherits(duk_context *ctx)
{
	ILibDuktape_EventEmitter *emitter;

	duk_dup(ctx, 0);									// [target]
	emitter = ILibDuktape_EventEmitter_Create(ctx);
	duk_push_object(ctx);								// [target][emitterUtils]
	duk_dup(ctx, -1);									// [target][emitterUtils][dup]
	duk_put_prop_string(ctx, -3, "\xFF_emitterUtils");	// [target][emitterUtils]
	duk_push_pointer(ctx, emitter);						// [target][emitterUtils][ptr]
	duk_put_prop_string(ctx, -2, "emitter");			// [target][emitterUtils]
	ILibDuktape_CreateInstanceMethod(ctx, "createEvent", ILibDuktape_EventEmitter_Inherits_createEvent, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "addMethod", ILibDuktape_EventEmitter_Inherits_addMethod, 2);
	return 1;
}
duk_ret_t ILibDuktape_EventEmitter_EventEmitter(duk_context *ctx)
{
	ILibDuktape_EventEmitter *emitter;
	int nargs = duk_get_top(ctx);
	int retVal = 0;

	duk_push_this(ctx);									// [target]
	emitter = ILibDuktape_EventEmitter_Create(ctx);
	duk_push_object(ctx);								// [target][emitterUtils]
	duk_dup(ctx, -1);									// [target][emitterUtils][dup]
	duk_put_prop_string(ctx, -3, "\xFF_emitterUtils");	// [target][emitterUtils]
	duk_push_pointer(ctx, emitter);						// [target][emitterUtils][ptr]
	duk_put_prop_string(ctx, -2, "emitter");			// [target][emitterUtils]

	if (nargs == 1 && duk_require_boolean(ctx, 0))
	{
		// Explicit Events
		ILibDuktape_CreateInstanceMethod(ctx, "createEvent", ILibDuktape_EventEmitter_Inherits_createEvent, 1);
		ILibDuktape_CreateInstanceMethod(ctx, "addMethod", ILibDuktape_EventEmitter_Inherits_addMethod, 2);
		retVal = 1;
	}
	else
	{
		// Implicit Events
		emitter->eventType = ILibDuktape_EventEmitter_Type_IMPLICIT;
	}

	return(retVal);
}
void ILibDuktape_EventEmitter_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);			// [emitter]
	ILibDuktape_CreateInstanceMethod(ctx, "inherits", ILibDuktape_EventEmitter_Inherits, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "EventEmitter", ILibDuktape_EventEmitter_EventEmitter, DUK_VARARGS);
}
void ILibDuktape_EventEmitter_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "events", ILibDuktape_EventEmitter_PUSH);
}
duk_ret_t ILibDuktape_EventEmitter_ForwardEvent_Sink(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int i;
	char *name;
	duk_push_current_function(ctx);					// [func]
	duk_get_prop_string(ctx, -1, "targetObject");	// [func][obj]
	duk_get_prop_string(ctx, -1, "emit");			// [func][obj][emit]
	duk_swap_top(ctx, -2);							// [func][emit][this]
	duk_get_prop_string(ctx, -3, "targetName");		// [func][emit][this][name]
	name = (char*)duk_get_string(ctx, -1);

	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);							// [func][emit][this][name][...args...]
	}

	if (duk_pcall_method(ctx, 1 + nargs) != 0) { return(ILibDuktape_Error(ctx, "EventEmitter.ForwardEvent() [%s]: %s", name, duk_safe_to_string(ctx, -1))); }
	return(0);	
}

duk_ret_t ILibDuktape_EventEmitter_ForwardEvent_Finalizer(duk_context *ctx)
{
	void *src = NULL;
	char *srcName = NULL;

	if (g_displayFinalizerMessages) 
	{
		duk_push_this(ctx);
		src = duk_get_heapptr(ctx, -1);
		srcName = Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_OBJID, "UNKNOWN");
		duk_pop(ctx);
	}
	duk_push_current_function(ctx);					// [func]
	if (duk_has_prop_string(ctx, -1, "fptr"))
	{
		duk_get_prop_string(ctx, -1, "fptr");			// [func][fptr]
		if (duk_has_prop_string(ctx, -1, "targetObject"))
		{
			duk_get_prop_string(ctx, -1, "targetObject");	// [func][fptr][target]
			duk_del_prop_string(ctx, -2, "targetObject");
			if (g_displayFinalizerMessages) { printf("EventEmitter.Forwarder[%s]: Deleted reference to [%s/%p] RC=%d from [%s/%p]\n", Duktape_GetStringPropertyValue(ctx, -3, "targetName", "UNKNOWN"), Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_OBJID, "UNKNOWN"), duk_get_heapptr(ctx, -1), ILibDuktape_GetReferenceCount(ctx, -1) - 1, srcName, src); }
			duk_pop_n(ctx, 3);
		}
	}
	if (g_displayFinalizerMessages) { duk_eval_string(ctx, "_debugGC();"); duk_pop(ctx); }
	return(0);
}
duk_ret_t ILibDuktape_EventEmitter_ForwardEvent_HookSink(duk_context *ctx)
{
	duk_push_current_function(ctx);
	duk_size_t sourceLen, targetLen, hookLen;
	char *source, *target, *hook;
	void *sourceObject, *fptr;

	source = Duktape_GetStringPropertyValueEx(ctx, -1, ILibDuktape_EventEmitter_Forward_SourceName, NULL, &sourceLen);
	target = Duktape_GetStringPropertyValueEx(ctx, -1, ILibDuktape_EventEmitter_Forward_TargetName, NULL, &targetLen);
	sourceObject = Duktape_GetHeapptrProperty(ctx, -1, ILibDuktape_EventEmitter_Forward_SourceObject);

	if (source != NULL && target != NULL && sourceObject != NULL)
	{
		hook = (char*)duk_get_lstring(ctx, 0, &hookLen);
		if (!(hookLen == targetLen && strncmp(target, hook, hookLen) == 0))
		{
			// This hooked event wasn't for us, so let's rehook this logic up for next time
			duk_push_this(ctx);																		// [this]
			duk_get_prop_string(ctx, -1, "once");													// [this][once]
			duk_swap_top(ctx, -2);																	// [once][this]
			duk_push_string(ctx, "newListener");													// [once][this][newListener]
			duk_push_c_function(ctx, ILibDuktape_EventEmitter_ForwardEvent_HookSink, DUK_VARARGS);	// [once][this][newListener][func]
			duk_push_lstring(ctx, source, sourceLen); duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_Forward_SourceName);
			duk_push_lstring(ctx, target, targetLen); duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_Forward_TargetName);
			duk_push_heapptr(ctx, sourceObject); duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_Forward_SourceObject);
			duk_call_method(ctx, 2); duk_pop(ctx);													// ...
		}
		else
		{
			// This hooked event is for us
			ILibDuktape_EventEmitter_SetupOn(ctx, sourceObject, source);							// [on][this][source]
			duk_push_c_function(ctx, ILibDuktape_EventEmitter_ForwardEvent_Sink, DUK_VARARGS);		// [on][this][source][sink]
			fptr = duk_get_heapptr(ctx, -1);
			duk_push_this(ctx); duk_put_prop_string(ctx, -2, "targetObject");
			duk_push_lstring(ctx, target, targetLen); duk_put_prop_string(ctx, -2, "targetName");
			if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "EventEmitter_ForwardEvent(): "); }
			duk_pop(ctx);																			// ...

			ILibDuktape_EventEmitter_SetupPrependOnce(ctx, sourceObject, "~");						// [prependOnce][this][~]
			duk_push_c_function(ctx, ILibDuktape_EventEmitter_ForwardEvent_Finalizer, DUK_VARARGS);	// [prependOnce][this]['~'][func]
			duk_push_heapptr(ctx, fptr); duk_put_prop_string(ctx, -2, "fptr");
			duk_push_lstring(ctx, target, targetLen); duk_put_prop_string(ctx, -2, "targetName");
			if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "EventEmitter_ForwardEvent_SetFinalizer(): "); }
			duk_pop(ctx);																			// ...
		}
	}

	return(0);
}
void ILibDuktape_EventEmitter_DeleteForwardEvent(duk_context *ctx, duk_idx_t eventSourceIndex, char *sourceEventName)
{
	duk_dup(ctx, eventSourceIndex);															// [source]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_EventEmitter_ForwardTable))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_ForwardTable);				// [source][table]
		if (duk_has_prop_string(ctx, -1, sourceEventName))
		{
			duk_get_prop_string(ctx, -1, sourceEventName);									// [source][table][sink]
			duk_del_prop_string(ctx, -1, "targetObject");
			duk_get_prop_string(ctx, -3, "removeListener");									// [source][table][sink][removeListener]
			duk_dup(ctx, -4);																// [source][table][sink][removeListener][this]
			duk_push_string(ctx, sourceEventName);											// [source][table][sink][removeListener][this][name]
			duk_dup(ctx, -4);																// [source][table][sink][removeListener][this][name][sink]
			duk_call_method(ctx, 2); duk_pop_2(ctx);										// [source][table]
			if (duk_has_prop_string(ctx, -1, "~"))
			{
				duk_get_prop_string(ctx, -1, "~");											// [source][table][sink]
				duk_del_prop_string(ctx, -1, "fptr");
				duk_get_prop_string(ctx, -3, "removeListener");								// [source][table][sink][removeListener]
				duk_dup(ctx, -4);															// [source][table][sink][removeListener][this]
				duk_push_string(ctx, "~");													// [source][table][sink][removeListener][this][name]
				duk_dup(ctx, -4);															// [source][table][sink][removeListener][this][name][sink]
				duk_call_method(ctx, 2); duk_pop_2(ctx);									// [source][table]
			}
			if (duk_has_prop_string(ctx, -1, "newListener"))
			{
				duk_get_prop_string(ctx, -1, "newListener");								// [source][table][sink]
				duk_get_prop_string(ctx, -3, "removeListener");								// [source][table][sink][removeListener]
				duk_dup(ctx, -4);															// [source][table][sink][removeListener][this]
				duk_push_string(ctx, "newListener");										// [source][table][sink][removeListener][this][name]
				duk_dup(ctx, -4);															// [source][table][sink][removeListener][this][name][sink]
				duk_call_method(ctx, 2); duk_pop_2(ctx);									// [source][table]
			}
		}
		duk_pop(ctx);																		// [source]
	}
	duk_pop(ctx);																			// ...
}
void ILibDuktape_EventEmitter_ForwardEvent(duk_context *ctx, duk_idx_t eventSourceIndex, char *sourceEventName, duk_idx_t eventTargetIndex, char *targetEventName)
{
	void *fptr;
	void *source;
	void *target;
	void *table = NULL;
	duk_dup(ctx, eventTargetIndex);															// [targetObject]
	target = duk_get_heapptr(ctx, -1);
	duk_pop(ctx);																			// ...
	duk_dup(ctx, eventSourceIndex);															// [sourceObject]
	source = duk_get_heapptr(ctx, -1);
	duk_pop(ctx);																			// ...


	duk_push_heapptr(ctx, source);															// [source]
	ILibDuktape_EventEmitter_DeleteForwardEvent(ctx, -1, sourceEventName);
	if (duk_has_prop_string(ctx, -1, ILibDuktape_EventEmitter_ForwardTable))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_ForwardTable);				// [source][table]
		table = duk_get_heapptr(ctx, -1);
		duk_pop(ctx);																		// [source]
	}
	else
	{
		duk_push_object(ctx);																// [source][table]
		table = duk_get_heapptr(ctx, -1);
		duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_ForwardTable);				// [source]
	}
	duk_pop(ctx);																			// ...


	duk_push_heapptr(ctx, target);															// [target]
	if (ILibDuktape_EventEmitter_HasListeners(ILibDuktape_EventEmitter_GetEmitter(ctx, -1), targetEventName) > 0)
	{
		// Target already has listeners, so we can go ahead and forward events
		duk_pop(ctx);																		// ...

		ILibDuktape_EventEmitter_SetupOn(ctx, source, sourceEventName);							// [on][this][source]
		duk_push_c_function(ctx, ILibDuktape_EventEmitter_ForwardEvent_Sink, DUK_VARARGS);		// [on][this][source][sink]
		fptr = duk_get_heapptr(ctx, -1);
		duk_push_heapptr(ctx, target); duk_put_prop_string(ctx, -2, "targetObject");
		duk_push_string(ctx, targetEventName); duk_put_prop_string(ctx, -2, "targetName");
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "EventEmitter_ForwardEvent(): "); }
		duk_pop(ctx);																			// ...

		duk_push_heapptr(ctx, table);															// [table]          
		duk_push_heapptr(ctx, fptr);        													// [table][func]
		duk_put_prop_string(ctx, -2, sourceEventName);											// [table]
		duk_pop(ctx);																			// ...

		ILibDuktape_EventEmitter_SetupPrependOnce(ctx, source, "~");							// [prependOnce][this][~]
		duk_push_c_function(ctx, ILibDuktape_EventEmitter_ForwardEvent_Finalizer, DUK_VARARGS);	// [prependOnce][this]['~'][func]

		duk_push_heapptr(ctx, table);															// [prependOnce][this]['~'][func][table]          
		duk_dup(ctx, -2);	       																// [prependOnce][this]['~'][func][table][func]
		duk_put_prop_string(ctx, -2, "~");														// [prependOnce][this]['~'][func][table]
		duk_pop(ctx);																			// [prependOnce][this]['~'][func]

		duk_push_heapptr(ctx, fptr); duk_put_prop_string(ctx, -2, "fptr");
		duk_push_string(ctx, targetEventName); duk_put_prop_string(ctx, -2, "targetName");
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "EventEmitter_ForwardEvent_SetFinalizer(): "); }
		duk_pop(ctx);																			// ...
	}
	else
	{
		// Target has no listeners, so only forward events if someone adds a listener
		duk_get_prop_string(ctx, -1, "once");													// [target][once]
		duk_swap_top(ctx, -2);																	// [once][this]
		duk_push_string(ctx, "newListener");													// [once][this][newListener]
		duk_push_c_function(ctx, ILibDuktape_EventEmitter_ForwardEvent_HookSink, DUK_VARARGS);	// [once][this][newListener][func]
		duk_push_string(ctx, sourceEventName); duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_Forward_SourceName);
		duk_push_string(ctx, targetEventName); duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_Forward_TargetName);
		duk_push_heapptr(ctx, source); duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_Forward_SourceObject);
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "Error hooking event: %s ", targetEventName); }
		duk_pop(ctx);																			// ...																		
	}
}
int ILibDuktape_EventEmitter_AddOnEx(duk_context *ctx, duk_idx_t idx, char *eventName, duk_c_function func)
{
	int retVal = 1;
	duk_dup(ctx, idx);								// [object]
	duk_get_prop_string(ctx, -1, "on");				// [object][on]
	duk_swap_top(ctx, -2);							// [on][this]
	duk_push_string(ctx, eventName);				// [on][this][name]
	duk_push_c_function(ctx, func, DUK_VARARGS);	// [on][this][name][func]
	if (duk_pcall_method(ctx, 2) != 0) { retVal = 0; }

	duk_pop(ctx);									// ...
	return(retVal);
}
