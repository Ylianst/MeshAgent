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
#define ILibDuktape_EventEmitter_TempObject				"\xFF_EventEmitter_TempObject"
#define ILibDuktape_EventEmitter_DispatcherFunc			"\xFF_EventEmitter_DispatcherFunc"
#define ILibDuktape_EventEmitter_SetterFunc				((void*)0xFFFF)
#define ILibDuktape_EventEmitter_HPTR_LIST				"\xFF_EventEmitter_HPTR_LIST"
#define ILibDuktape_EventEmitter_Hook					((void*)0xEEEE)
#define ILibDuktape_EventEmitter_LastRetValueTable		"\xFF_EventEmitter_LastRetValueTable"
#define ILibDuktape_EventEmitter_GlobalListenerCount	"\xFF_EventEmitter_GlobalListenerCount"
#define ILibDuktape_EventEmitter_Forward_SourceName		"\xFF_EventEmitter_SourceName"
#define ILibDuktape_EventEmitter_Forward_TargetName		"\xFF_EventEmitter_TargetName"
#define ILibDuktape_EventEmitter_Forward_SourceObject	"\xFF_EventEmitter_SourceObject"
#define ILibDuktape_EventEmitter_ForwardTable			"\xFF_EventEmitter_ForwardTable"

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
void ILibDuktape_EventEmitter_FinalizerEx(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	ILibDuktape_EventEmitter *data = (ILibDuktape_EventEmitter*)user;
	int count, i;
	void  **hptr;

	if (Key1 == NULL)
	{
		// If this is NULL, then 'Data' is a LinkedList of JavaScript Subscribers
		ILibLinkedList_Destroy(Data);
	}
	else if(Key1 == ILibDuktape_EventEmitter_SetterFunc)
	{
		// If this is not NULL, this is the JavaScript Setter Func
		duk_push_heapptr(data->ctx, Data);											// [Setter]
		duk_get_prop_string(data->ctx, -1, ILibDuktape_EventEmitter_HPTR_LIST);		// [Setter][list]
		count = (int)duk_get_length(data->ctx, -1);
		for (i = 0; i < count; ++i)
		{
			duk_get_prop_index(data->ctx, -1, i);									// [Setter][list][pointer]
			hptr = (void**)duk_get_pointer(data->ctx, -1);
			if (hptr != NULL) { *hptr = NULL; }
			duk_pop(data->ctx);														// [Setter][list]
		}
		duk_pop_2(data->ctx);														// ...
	}
}

int ILibDuktape_EventEmitter_HasListeners(ILibDuktape_EventEmitter *emitter, char *eventName)
{
	int retVal = 0;
	if(ILibMemory_CanaryOK(emitter) && emitter!=NULL && emitter->eventTable != NULL && emitter->ctx != NULL)
	{
		ILibLinkedList eventList = ILibHashtable_Get(emitter->eventTable, NULL, eventName, (int)strnlen_s(eventName, 255));
		if (eventList != NULL)
		{
			retVal = ILibLinkedList_GetCount(eventList);
		}
	}
	return(retVal);
}
duk_ret_t ILibDuktape_EventEmitter_emit(duk_context *ctx)
{
	duk_size_t nameLen;
	if (!duk_is_string(ctx, 0)) { return ILibDuktape_Error(ctx, "EventEmitter.emit(): Invalid Parameter Name/Type"); }
	char *name = (char*)duk_get_lstring(ctx, 0, &nameLen);
	ILibLinkedList eventList;
	void *self;
	int nargs = duk_get_top(ctx);
	ILibDuktape_EventEmitter *data;
	void *node, *nextNode, *func;
	int i, j;
	void **emitList;
	char *objid;
	int wasReturnSpecified = 0;

	duk_require_stack(ctx, 4 + nargs + DUK_API_ENTRY_STACK);											// This will make sure we have enough stack space to get the emitter object


	duk_push_this(ctx);													// [this]
	objid = Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_OBJID, "unknown");
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_TempObject);	// [this][tmp]
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_Data);		// [this][tmp][data]
	data = (ILibDuktape_EventEmitter*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop_2(ctx);														// [this]
	self = duk_get_heapptr(ctx, -1);
	duk_pop(ctx);														// ...

	if(!ILibMemory_CanaryOK(data) || data->eventTable == NULL || data->ctx == NULL) { duk_push_false(ctx);  return(1); } // This probably means the finalizer was already run on the eventEmitter

	eventList = ILibHashtable_Get(data->eventTable, NULL, name, (int)nameLen);
	if (eventList == NULL) 
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

	// Copy the list, so we can enumerate with local memory, so the list can be manipulated while we are dispatching
#ifdef WIN32
	emitList = (void**)_alloca(((unsigned int)ILibLinkedList_GetCount(eventList) + 1) * sizeof(void*));
#else
	emitList = (void**)alloca(((unsigned int)ILibLinkedList_GetCount(eventList) + 1) * sizeof(void*));
#endif
	node = ILibLinkedList_GetNode_Head(eventList);
	i = 0;
	while (node != NULL)
	{
		nextNode = ILibLinkedList_GetNextNode(node);
		emitList[i++] = ILibLinkedList_GetDataFromNode(node);

		if (((int*)ILibLinkedList_GetExtendedMemory(node))[0] == 1)
		{
			// Dispatch only Once
			ILibLinkedList_Remove(node);
			data->totalListeners[0]--;
		}
		node = nextNode;
	}
	emitList[i] = NULL;


	// Before we dispatch, lets clear our last return values for this event
	duk_push_heapptr(ctx, data->retValTable);				// [table]
	duk_del_prop_lstring(ctx, -1, name, nameLen);
	duk_pop(ctx);											// ...

	// Now that we have all the housekeeping stuff out of the way, we can actually dispatch our events
	i = 0;
	while ((func = emitList[i++]) != NULL)
	{
		duk_push_heapptr(ctx, func);						// [func]
		duk_push_heapptr(ctx, self);						// [func][this]
		for (j = 1; j < nargs; ++j)
		{
			duk_dup(ctx, j);								// [func][this][...args...]
		}
		if (duk_pcall_method(ctx, nargs - 1) != 0)
		{
			duk_push_heapptr(ctx, func);					// [func]
			return(ILibDuktape_Error(ctx, "EventEmitter.emit(): Event dispatch for '%s' on '%s' threw an exception: %s in method '%s()'", name, objid, duk_safe_to_string(ctx, -2), Duktape_GetStringPropertyValue(ctx, -1, "name", "unknown_method")));
		}

		// Check for return value
		if (!duk_is_undefined(ctx, -1))
		{
			duk_push_heapptr(ctx, data->retValTable);				// [retVal][table]
			duk_dup(ctx, -2);										// [retVal][table][retVal]
			duk_put_prop_lstring(ctx, -2, name, nameLen);			// [retVal][table]
			duk_pop(ctx);											// [retVal]
			
			duk_push_heapptr(ctx, self);									// [retVal][this]
			duk_swap_top(ctx, -2);											// [this][retVal]
			data->lastReturnValue = duk_get_heapptr(ctx, -1);
			duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_RetVal);	// [this]
			duk_pop(ctx);													// ...
			wasReturnSpecified = 1;
		}
	}

	if (wasReturnSpecified == 0)
	{
		data->lastReturnValue = NULL;
		duk_push_heapptr(ctx, self);									// [this]
		duk_del_prop_string(ctx, -1, ILibDuktape_EventEmitter_RetVal);	// [this]
		duk_pop(ctx);													// ...

		duk_push_heapptr(ctx, data->retValTable);					    // [table]
		duk_del_prop_lstring(ctx, -1, name, nameLen);	
		duk_pop(ctx);													// ...
	}

	duk_push_boolean(ctx, i > 1 ? 1 : 0);
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

	duk_dup(ctx, idx);																				// [obj]
	ILibDuktape_Push_ObjectStash(ctx);																// [obj][stash]
	duk_push_c_function(ctx, func, DUK_VARARGS);													// [obj][stash][func]
	duk_dup(ctx, -1);																				// [obj][stash][func][func]
	duk_put_prop_string(ctx, -3, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));					// [obj][stash][func]
	duk_get_prop_string(ctx, -3, "once");															// [obj][stash][func][once]
	duk_swap(ctx, -3, -1);																			// [obj][once][func][stash]
	duk_swap(ctx, -4, -3);																			// [once][this][func][stash]
	duk_pop(ctx);																					// [once][this][func]
	duk_push_string(ctx, eventName);																// [once][this][func][eventName]
	duk_swap_top(ctx, -2);																			// [once][this][eventName][func]
	retVal = duk_pcall_method(ctx, 2);																// [retVal]
	duk_pop(ctx);																					// ...

	return(retVal);
}
int ILibDuktape_EventEmitter_AddOnceEx(ILibDuktape_EventEmitter *emitter, char *eventName, duk_c_function func, duk_idx_t funcArgs)
{
	int retVal = 1;

	duk_push_heapptr(emitter->ctx, emitter->object);												// [obj]
	ILibDuktape_Push_ObjectStash(emitter->ctx);														// [obj][stash]

	duk_push_c_function(emitter->ctx, func, funcArgs);												// [obj][stash][func]
	retVal = ILibDuktape_EventEmitter_AddOnce(emitter, eventName, duk_get_heapptr(emitter->ctx, -1));
	duk_put_prop_string(emitter->ctx, -2, Duktape_GetStashKey(duk_get_heapptr(emitter->ctx, -1)));	// [obj][stash]
	duk_pop_2(emitter->ctx);																		// ...
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
	void *eventList, *node;
	int prepend;
	ILibDuktape_EventEmitter_HookHandler hookHandler = NULL;

	duk_require_stack(ctx, 10);

	duk_push_current_function(ctx);
	once = Duktape_GetIntPropertyValue(ctx, -1, "once", 0);
	prepend = Duktape_GetIntPropertyValue(ctx, -1, "prepend", 0);


	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_TempObject);
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_Data);
	data = (ILibDuktape_EventEmitter*)Duktape_GetBuffer(ctx, -1, NULL);

	eventList = ILibHashtable_Get(data->eventTable, NULL, propName, (int)propNameLen);
	if (eventList == NULL) 
	{ 
		if (data->eventType == ILibDuktape_EventEmitter_Type_IMPLICIT)
		{
			ILibDuktape_EventEmitter_CreateEventEx(data, propName);
			eventList = ILibHashtable_Get(data->eventTable, NULL, propName, (int)propNameLen);
		}
		else
		{
			return(ILibDuktape_Error(ctx, "EventEmitter.on(): Event '%s' not found", propName));
		}
	}
	hookHandler = ILibHashtable_Get(data->eventTable, ILibDuktape_EventEmitter_Hook, propName, (int)propNameLen);

	node = prepend ? ILibLinkedList_AddHead(eventList, callback) : ILibLinkedList_AddTail(eventList, callback);
	((int*)ILibLinkedList_GetExtendedMemory(node))[0] = once;
	data->totalListeners[0]++;

	duk_push_heapptr(ctx, data->tmpObject);
	duk_push_heapptr(ctx, callback);
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(callback)); // Save the callback to the tmp object, so it won't get GC'ed

	if (hookHandler != NULL) { hookHandler(data, propName, callback); }
	if (!(propNameLen == 10 && strncmp(propName, "_eventHook", 10) == 0))
	{
		// Only emit '_eventHook' when the event itself isn't '_eventHook'
		ILibDuktape_EventEmitter_SetupEmit(ctx, data->object, "_eventHook");	// [emit][this][_eventHook]
		duk_push_lstring(ctx, propName, propNameLen);							// [emit][this][_eventHook][propName]
		duk_push_heapptr(ctx, callback);										// [emit][this][_eventHook][propName][callback]
		duk_call_method(ctx, 3); duk_pop(ctx);									// ...
	}
	return 0;
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
	ILibDuktape_EventEmitter *retVal = NULL;
	if (duk_has_prop_string(ctx, i, ILibDuktape_EventEmitter_TempObject))
	{
		// This object already has an EventEmitter
		duk_get_prop_string(ctx, i, ILibDuktape_EventEmitter_TempObject);		// [tmp]
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_Data);			// [tmp][data]
		retVal = (ILibDuktape_EventEmitter*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop_2(ctx);
	}
	return retVal;
}
duk_ret_t ILibDuktape_EventEmitter_removeListener(duk_context *ctx)
{
	void *callback = duk_require_heapptr(ctx, 1);
	duk_size_t eventNameLen;
	char *eventName = Duktape_GetBuffer(ctx, 0, &eventNameLen);
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_GetEmitter_fromThis(ctx);
	void *eventList;
	void *node;

	if (emitter != NULL)
	{
		eventList = ILibHashtable_Get(emitter->eventTable, NULL, eventName, (int)eventNameLen);
		if (eventList == NULL) { return(ILibDuktape_Error(ctx, "EventEmitter.removeListener(): Event '%s' not found", eventName)); }
		node = ILibLinkedList_GetNode_Search(eventList, NULL, callback);
		if (node != NULL)
		{
			ILibLinkedList_Remove(node);
			emitter->totalListeners[0]--;
		}
	}
	
	return(0);
}
duk_ret_t ILibDuktape_EventEmitter_removeAllListeners(duk_context *ctx)
{
	duk_size_t eventNameLen;
	char *eventName = Duktape_GetBuffer(ctx, 0, &eventNameLen);
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_GetEmitter_fromThis(ctx);
	void *eventList;

	if (emitter != NULL)
	{
		eventList = ILibHashtable_Get(emitter->eventTable, NULL, eventName, (int)eventNameLen);
		if (eventList == NULL) { return(ILibDuktape_Error(ctx, "EventEmitter.removeAllListeners(): Event '%s' not found", eventName)); }

		ILibLinkedList_Clear(eventList);
		emitter->totalListeners[0] = 0;
	}
	return(0);
}

void ILibDuktape_EventEmitter_EmbeddedFinalizer2(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	if (Key1 == NULL)
	{
		char *name = (char*)ILibMemory_AllocateA(Key2Len + 1);
		name[Key2Len] = 0;
		memcpy_s(name, Key2Len + 1, Key2, Key2Len);
		printf("%s ", name);
	}
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
				if (emitter->eventTable != NULL) { ILibHashtable_Enumerate(emitter->eventTable, ILibDuktape_EventEmitter_EmbeddedFinalizer2, NULL); }
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

	// We need to clear the Native Dispatcher, while destroying the Hashtable
	ILibHashtable_DestroyEx(data->eventTable, ILibDuktape_EventEmitter_FinalizerEx, data);
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
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_TempObject);			// [this][tmp]
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_LastRetValueTable);	// [this][tmp][table]
		duk_dup(ctx, 0);															// [this][tmp][table][key]
		duk_get_prop(ctx, -2);														// [this][tmp][table][val]
		break;
	case 2:
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_TempObject);			// [this][tmp]
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_LastRetValueTable);	// [this][tmp][table]
		duk_dup(ctx, 0);															// [this][tmp][table][key]
		duk_dup(ctx, 1);															// [this][tmp][table][key][value]
		duk_put_prop(ctx, -3);
		retVal = 0;
		break;
	default:
		retVal = ILibDuktape_Error(ctx, "INVALID Parameter Count");
		break;
	}

	return(retVal);
}
ILibDuktape_EventEmitter* ILibDuktape_EventEmitter_Create(duk_context *ctx)
{
	ILibDuktape_EventEmitter *retVal;
	if (duk_has_prop_string(ctx, -1, ILibDuktape_EventEmitter_TempObject))
	{
		// This object already has an EventEmitter
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_TempObject);		// [tmp]
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_Data);			// [tmp][data]
		retVal = (ILibDuktape_EventEmitter*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop_2(ctx);
		return retVal;
	}

	duk_push_object(ctx);																			// [emitterTmp]
	retVal = (ILibDuktape_EventEmitter*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_EventEmitter));	// [emitterTmp][data]
	retVal->tmpObject = duk_get_heapptr(ctx, -2);

	duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_Data);									// [emitterTmp]
	duk_push_object(ctx);																			// [emitterTmp][retValTable]
	retVal->retValTable = duk_get_heapptr(ctx, -1);
	duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_LastRetValueTable);						// [emitterTmp]
	duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_TempObject);								// [...parent...]

	retVal->ctx = ctx;
	retVal->object = duk_get_heapptr(ctx, -1);
	retVal->eventTable = ILibHashtable_Create();

	ILibDuktape_CreateInstanceMethodWithProperties(ctx, "once", ILibDuktape_EventEmitter_on, 2, 2, "once", duk_push_int_ex(ctx, 1), "prepend", duk_push_int_ex(ctx, 0));
	ILibDuktape_CreateInstanceMethodWithProperties(ctx, "on", ILibDuktape_EventEmitter_on, 2, 2, "once", duk_push_int_ex(ctx, 0), "prepend", duk_push_int_ex(ctx, 0));
	ILibDuktape_CreateInstanceMethodWithProperties(ctx, "prependOnceListener", ILibDuktape_EventEmitter_on, 2, 2, "once", duk_push_int_ex(ctx, 1), "prepend", duk_push_int_ex(ctx, 1));
	ILibDuktape_CreateInstanceMethodWithProperties(ctx, "prependListener", ILibDuktape_EventEmitter_on, 2, 2, "once", duk_push_int_ex(ctx, 0), "prepend", duk_push_int_ex(ctx, 1));

	ILibDuktape_CreateInstanceMethod(ctx, "removeListener", ILibDuktape_EventEmitter_removeListener, 2);
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

	ILibDuktape_EventEmitter_CreateEventEx(retVal, "_eventHook");

	return retVal;
}

void ILibDuktape_EventEmitter_AddHook(ILibDuktape_EventEmitter *emitter, char *eventName, ILibDuktape_EventEmitter_HookHandler handler)
{
	if (ILibHashtable_Get(emitter->eventTable, ILibDuktape_EventEmitter_Hook, eventName, (int)strnlen_s(eventName, 255)) == NULL && handler != NULL)
	{
		ILibHashtable_Put(emitter->eventTable, ILibDuktape_EventEmitter_Hook, eventName, (int)strnlen_s(eventName, 255), handler);
	}
}
void ILibDuktape_EventEmitter_ClearHook(ILibDuktape_EventEmitter *emitter, char *eventName)
{
	ILibHashtable_Remove(emitter->eventTable, ILibDuktape_EventEmitter_Hook, eventName, (int)strnlen_s(eventName, 255));
}
duk_ret_t ILibDuktape_EventEmitter_SetEvent(duk_context *ctx)
{
	char *propName;
	duk_size_t propNameLen;
	ILibDuktape_EventEmitter *data;
	ILibLinkedList eventList = NULL;

	duk_push_current_function(ctx);												// [func]
	duk_get_prop_string(ctx, -1, "eventName");									// [func][name]
	propName = (char*)duk_get_lstring(ctx, -1, &propNameLen);

	duk_push_this(ctx);															// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_TempObject);			// [this][tmp]
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_Data);				// [this][tmp][data]
	data = (ILibDuktape_EventEmitter*)Duktape_GetBuffer(ctx, -1, NULL);

	eventList = ILibHashtable_Get(data->eventTable, NULL, propName, (int)propNameLen);
	if (eventList == NULL) { return(ILibDuktape_Error(ctx, "EventEmitter(): Cannot add listener becuase event '%s' is not found", propName)); }

	if (duk_is_null_or_undefined(ctx, 0))
	{
		// NULL was passed, we'll need to clear all listeners. 
		duk_push_this(ctx);														// [obj]
		duk_get_prop_string(ctx, -1, "removeAllListeners");						// [obj][removeAll]
		duk_swap_top(ctx, -2);													// [removeAll][this]
		duk_push_string(ctx, propName);											// [removeAll][this][name]
		duk_call_method(ctx, 1); duk_pop(ctx);
	}
	else
	{
		ILibDuktape_EventEmitter_AddOn(data, propName, duk_get_heapptr(ctx, 0));
	}

	return 0;
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
void ILibDuktape_EventEmitter_GetEventCountSink(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	int *count = (int*)user;
	if (Key1 == NULL)
	{
		++(*count);
	}
}
int ILibDuktape_EventEmitter_GetEventCount(ILibDuktape_EventEmitter *emitter)
{
	int retVal = 0;
	if (emitter->eventTable != NULL) { ILibHashtable_Enumerate(emitter->eventTable, ILibDuktape_EventEmitter_GetEventCountSink, &retVal); }
	return(retVal);
}

void ILibDuktape_EventEmitter_CreateEventEx(ILibDuktape_EventEmitter *emitter, char *eventName)
{
	int eventNameLen = (int)strnlen_s(eventName, ILibDuktape_EventEmitter_MaxEventNameLen);
	
	if (ILibHashtable_Get(emitter->eventTable, NULL, eventName, eventNameLen) != NULL)
	{
		// This event already exists... 
		return;
	}

	duk_push_heapptr(emitter->ctx, emitter->object);													// [obj]

	// Create the Property Setter
	duk_push_string(emitter->ctx, eventName);															// [obj][prop]
	duk_push_c_function(emitter->ctx, ILibDuktape_EventEmitter_SetEvent, 1);							// [obj][prop][setFunc]
	duk_push_string(emitter->ctx, eventName);															// [obj][prop][setFunc][name]
	duk_put_prop_string(emitter->ctx, -2, "eventName");													// [obj][prop][setFunc]

	duk_def_prop(emitter->ctx, -3, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_SETTER);						// [obj]
	duk_pop(emitter->ctx);																				// ...

	ILibHashtable_Put(emitter->eventTable, NULL, eventName, eventNameLen, ILibLinkedList_CreateEx(sizeof(int)));
}

void *ILibDuktape_EventEmitter_GetDispatcher(ILibDuktape_EventEmitter *emitter, char *eventName)
{
	return ILibHashtable_Get(emitter->eventTable, ILibDuktape_EventEmitter_SetterFunc, eventName, (int)strnlen_s(eventName, ILibDuktape_EventEmitter_MaxEventNameLen));
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
	return(0);
}
duk_ret_t ILibDuktape_EventEmitter_EmitterUtils_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, "\xFF_MainObject");		// [obj]
	duk_get_prop_string(ctx, -1, "emit");				// [obj][emit]
	duk_swap_top(ctx, -2);								// [emit][this]
	duk_push_string(ctx, "~");							// [emit][this][~]
	duk_call_method(ctx, 1);
	return(0);
}
duk_ret_t ILibDuktape_EventEmitter_Inherits(duk_context *ctx)
{
	ILibDuktape_EventEmitter *emitter;

	duk_dup(ctx, 0);									// [target]
	emitter = ILibDuktape_EventEmitter_Create(ctx);
	duk_push_object(ctx);								// [target][emitterUtils]
	duk_dup(ctx, -2);									// [target][emitterUtils][target]
	duk_put_prop_string(ctx, -2, "\xFF_MainObject");	// [target][emitterUtils]
	duk_dup(ctx, -1);									// [target][emitterUtils][dup]
	duk_put_prop_string(ctx, -3, "\xFF_emitterUtils");	// [target][emitterUtils]
	duk_push_pointer(ctx, emitter);						// [target][emitterUtils][ptr]
	duk_put_prop_string(ctx, -2, "emitter");			// [target][emitterUtils]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_EventEmitter_EmitterUtils_Finalizer);
	ILibDuktape_CreateInstanceMethod(ctx, "createEvent", ILibDuktape_EventEmitter_Inherits_createEvent, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "addMethod", ILibDuktape_EventEmitter_Inherits_addMethod, 2);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "~");
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
	duk_dup(ctx, -2);									// [target][emitterUtils][target]
	duk_put_prop_string(ctx, -2, "\xFF_MainObject");	// [target][emitterUtils]
	duk_dup(ctx, -1);									// [target][emitterUtils][dup]
	duk_put_prop_string(ctx, -3, "\xFF_emitterUtils");	// [target][emitterUtils]
	duk_push_pointer(ctx, emitter);						// [target][emitterUtils][ptr]
	duk_put_prop_string(ctx, -2, "emitter");			// [target][emitterUtils]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_EventEmitter_EmitterUtils_Finalizer);

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

	ILibDuktape_EventEmitter_CreateEventEx(emitter, "~");

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
			duk_push_string(ctx, "_eventHook");														// [once][this][_eventHook]
			duk_push_c_function(ctx, ILibDuktape_EventEmitter_ForwardEvent_HookSink, DUK_VARARGS);	// [once][this][_eventHook][func]
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
			if (duk_has_prop_string(ctx, -1, "_eventHook"))
			{
				duk_get_prop_string(ctx, -1, "_eventHook");									// [source][table][sink]
				duk_get_prop_string(ctx, -3, "removeListener");								// [source][table][sink][removeListener]
				duk_dup(ctx, -4);															// [source][table][sink][removeListener][this]
				duk_push_string(ctx, "_eventHook");											// [source][table][sink][removeListener][this][name]
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
		duk_push_string(ctx, "_eventHook");														// [once][this][_eventHook]
		duk_push_c_function(ctx, ILibDuktape_EventEmitter_ForwardEvent_HookSink, DUK_VARARGS);	// [once][this][_eventHook][func]
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
