#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "duktape.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_Helpers.h"

#define ILibDuktape_EventEmitter_MaxEventNameLen		255
#define ILibDuktape_EventEmitter_Data					"\xFF_EventEmitter_Data"
#define ILibDuktape_EventEmitter_TempObject				"\xFF_EventEmitter_TempObject"
#define ILibDuktape_EventEmitter_DispatcherFunc			"\xFF_EventEmitter_DispatcherFunc"
#define ILibDuktape_EventEmitter_SetterFunc				((void*)0xFFFF)
#define ILibDuktape_EventEmitter_HPTR_LIST				"\xFF_EventEmitter_HPTR_LIST"
#define ILibDuktape_EventEmitter_Hook					((void*)0xEEEE)
#define ILibDuktape_EventEmitter_GlobalListenerCount	"\xFF_EventEmitter_GlobalListenerCount"

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
duk_ret_t ILibDuktape_EventEmitter_Finalizer(duk_context *ctx)
{
	ILibDuktape_EventEmitter *data;
	duk_get_prop_string(ctx, 0, ILibDuktape_EventEmitter_Data);		
	data = (ILibDuktape_EventEmitter*)Duktape_GetBuffer(ctx, -1, NULL);

	// Check to see if this is the process object going away
	if (ILibDuktape_GetProcessObject(ctx) == data->object)
	{
		// We need to dispatch the 'exit' event
		int exitCode = 0;
		duk_push_heapptr(data->ctx, data->object);					// [process]
		if (duk_has_prop_string(data->ctx, -1, "\xFF_ExitCode"))
		{
			duk_get_prop_string(data->ctx, -1, "\xFF_ExitCode");	// [process][exitCode]
			exitCode = duk_get_int(data->ctx, -1);
			duk_pop(data->ctx);										// [process]
		}
		duk_get_prop_string(data->ctx, -1, "emit");					// [process][emit]
		duk_swap_top(data->ctx, -2);								// [emit][this]
		duk_push_string(data->ctx, "exit");							// [emit][this][eventName/exit]
		duk_push_int(data->ctx, exitCode);							// [emit][this][eventName/exit][exitCode]
		duk_pcall_method(data->ctx, 2);
		duk_pop(data->ctx);
	}


	// We need to clear the Native Dispatcher, while destroying the Hashtable
	ILibHashtable_DestroyEx(data->eventTable, ILibDuktape_EventEmitter_FinalizerEx, data);

	memset(data, 0, sizeof(ILibDuktape_EventEmitter));

	return 0;
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
	void *node, *nextNode, *func, *dispatcher;
	int i, j, count;
	void **hptr;
	void **emitList;

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_TempObject);	// [this][tmp]
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_Data);		// [this][tmp][data]
	data = (ILibDuktape_EventEmitter*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop_2(ctx);														// [this]
	self = duk_get_heapptr(ctx, -1);

	if (data->eventTable == NULL) { return 0; } // This probably means the finalizer was already run on the eventEmitter

	eventList = ILibHashtable_Get(data->eventTable, NULL, name, (int)nameLen);
	if (eventList == NULL) { return ILibDuktape_Error(ctx, "EventEmitter.emit(): Event '%s' not found", name); }
	dispatcher = ILibHashtable_Get(data->eventTable, ILibDuktape_EventEmitter_SetterFunc, name, (int)nameLen);
	if (dispatcher == NULL) { return ILibDuktape_Error(ctx, "EventEmitter.emit(): Internal Error with event '%s'", name); }


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

	// If no more listeners, we can set the hptr to NULL
	if (ILibLinkedList_GetCount(eventList) == 0)
	{
		duk_push_heapptr(ctx, dispatcher);									// [dispatcher]
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_HPTR_LIST);	// [dispatcher][hptrList]
		count = (int)duk_get_length(ctx, -1);
		for (i = 0; i < count; ++i)
		{
			duk_get_prop_index(ctx, -1, i);									// [dispatcher][hptrList][hptr]
			hptr = (void**)duk_get_pointer(ctx, -1);
			*hptr = NULL;
			duk_pop(ctx);													// [dispatcher][hptrList]
		}
		duk_pop_2(ctx);														// ...
	}

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
			return(ILibDuktape_Error(ctx, "EventEmitter.emit(): Event dispatch for '%s' threw an exception: %s", name, duk_safe_to_string(ctx, -1)));
		}
		duk_pop(ctx);										// ...
	}

	return 0;
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
	void *eventList, *node, *dispatcher, **hptr;
	int i, count;

	duk_push_current_function(ctx);
	once = Duktape_GetIntPropertyValue(ctx, -1, "once", 0);

	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_TempObject);
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_Data);
	data = (ILibDuktape_EventEmitter*)Duktape_GetBuffer(ctx, -1, NULL);

	eventList = ILibHashtable_Get(data->eventTable, NULL, propName, (int)propNameLen);
	if (eventList == NULL) 
	{ 
		return(ILibDuktape_Error(ctx, "EventEmitter.on(): Event '%s' not found", propName)); 
	}
	dispatcher = ILibHashtable_Get(data->eventTable, ILibDuktape_EventEmitter_SetterFunc, propName, (int)propNameLen);
	if (dispatcher == NULL) { return(ILibDuktape_Error(ctx, "EventEmitter.on(): Internal error with Event '%s'", propName)); }

	node = ILibLinkedList_AddTail(eventList, callback);
	((int*)ILibLinkedList_GetExtendedMemory(node))[0] = once;
	data->totalListeners[0]++;

	duk_push_heapptr(ctx, data->tmpObject);
	duk_push_heapptr(ctx, callback);
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(callback)); // Save the callback to the tmp object, so it won't get GC'ed

	duk_push_heapptr(ctx, dispatcher);									// [dispatcher]
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_HPTR_LIST);	// [dispatcher][hptrList]
	count = (int)duk_get_length(ctx, -1);
	for (i = 0; i < count; ++i)
	{
		duk_get_prop_index(ctx, -1, i);									// [dispatcher][hptrList][hptr]
		hptr = (void**)duk_get_pointer(ctx, -1);
		*hptr = dispatcher;
		duk_pop(ctx);													// [dispatcher][hptrList]
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
	void *eventList, *dispatcher;
	int count, i;
	void **hptr;

	if (emitter != NULL)
	{
		eventList = ILibHashtable_Get(emitter->eventTable, NULL, eventName, (int)eventNameLen);
		if (eventList == NULL) { return(ILibDuktape_Error(ctx, "EventEmitter.removeAllListeners(): Event '%s' not found", eventName)); }
		dispatcher = ILibHashtable_Get(emitter->eventTable, ILibDuktape_EventEmitter_SetterFunc, eventName, (int)eventNameLen);
		if (dispatcher == NULL) { return(ILibDuktape_Error(ctx, "EventEmitter.removeAllListeners(): Internal error with Event '%s'", eventName)); }


		// NULL was passed, we'll need to clear all listeners. 
		// Start by setting the Native Dispatcher to NULL, so it appears there are no subscribers
		duk_push_heapptr(ctx, dispatcher);									// [dispatcher]
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_HPTR_LIST);	// [dispatcher][hptrList]
		count = (int)duk_get_length(ctx, -1);
		for (i = 0; i < count; ++i)
		{
			duk_get_prop_index(ctx, -1, i);									// [dispatcher][hptrList][hptr]
			hptr = (void**)duk_get_pointer(ctx, -1);
			*hptr = NULL;
			duk_pop(ctx);													// [dispatcher][hptrList]
		}

		ILibLinkedList_Clear(eventList);
		emitter->totalListeners[0] = 0;
	}
	return(0);
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

	duk_push_object(ctx);													// [emitterTmp]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_EventEmitter));			// [emitterTmp][data]
	retVal = (ILibDuktape_EventEmitter*)Duktape_GetBuffer(ctx, -1, NULL);
	memset(retVal, 0, sizeof(ILibDuktape_EventEmitter));
	retVal->tmpObject = duk_get_heapptr(ctx, -2);

	duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_Data);			// [emitterTmp]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_EventEmitter_Finalizer);
	duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_TempObject);		// [...parent...]

	
	retVal->ctx = ctx;
	retVal->object = duk_get_heapptr(ctx, -1);
	retVal->eventTable = ILibHashtable_Create();

	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "once", 1, "once", ILibDuktape_EventEmitter_on, 2);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "once", 0, "on", ILibDuktape_EventEmitter_on, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "removeListener", ILibDuktape_EventEmitter_removeListener, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "removeAllListeners", ILibDuktape_EventEmitter_removeAllListeners, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "emit", ILibDuktape_EventEmitter_emit, DUK_VARARGS);

	duk_push_heap_stash(ctx);
	if (duk_has_prop_string(ctx, -1, ILibDuktape_EventEmitter_GlobalListenerCount))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_GlobalListenerCount);
		retVal->totalListeners = (unsigned int *)Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop(ctx);
	}
	else
	{
		duk_push_fixed_buffer(ctx, sizeof(unsigned int));
		retVal->totalListeners = (unsigned int *)Duktape_GetBuffer(ctx, -1, NULL);
		duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_GlobalListenerCount);
		*(retVal->totalListeners) = 0;
	}
	duk_pop(ctx);

	return retVal;
}

void ILibDuktape_EventEmitter_AddHook(ILibDuktape_EventEmitter *emitter, char *eventName, ILibDuktape_EventEmitter_HookHandler handler)
{
	if (ILibHashtable_Get(emitter->eventTable, ILibDuktape_EventEmitter_Hook, eventName, (int)strnlen_s(eventName, 255)) == NULL && handler != NULL)
	{
		ILibHashtable_Put(emitter->eventTable, ILibDuktape_EventEmitter_Hook, eventName, (int)strnlen_s(eventName, 255), handler);
	}
}
duk_ret_t ILibDuktape_EventEmitter_SetEvent(duk_context *ctx)
{
	char *propName;
	duk_size_t propNameLen;
	ILibDuktape_EventEmitter *data;
	ILibLinkedList eventList = NULL;
	void **hptr;
	void *dispatcher;
	int i, count;

	duk_push_current_function(ctx);												// [func]
	duk_get_prop_string(ctx, -1, "name");										// [func][name]
	propName = (char*)duk_get_lstring(ctx, -1, &propNameLen);
	duk_get_prop_string(ctx, -2, ILibDuktape_EventEmitter_DispatcherFunc);		// [func][name][dispatcher]
	dispatcher = duk_get_heapptr(ctx, -1);

	duk_push_this(ctx);															// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_TempObject);			// [this][tmp]
	duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_Data);				// [this][tmp][data]
	data = (ILibDuktape_EventEmitter*)Duktape_GetBuffer(ctx, -1, NULL);

	eventList = ILibHashtable_Get(data->eventTable, NULL, propName, (int)propNameLen);
	if (eventList == NULL) { return(ILibDuktape_Error(ctx, "EventEmitter(): Cannot add listener becuase event '%s' is not found", propName)); }

	if (duk_is_null_or_undefined(ctx, 0))
	{
		// NULL was passed, we'll need to clear all listeners. 
		// Start by setting the Native Dispatcher to NULL, so it appears there are no subscribers
		duk_push_heapptr(ctx, dispatcher);									// [dispatcher]
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_HPTR_LIST);	// [dispatcher][hptrList]
		count = (int)duk_get_length(ctx, -1);
		for (i = 0; i < count; ++i)
		{
			duk_get_prop_index(ctx, -1, i);									// [dispatcher][hptrList][hptr]
			hptr = (void**)duk_get_pointer(ctx, -1);
			*hptr = NULL;		
			duk_pop(ctx);													// [dispatcher][hptrList]
		}

		ILibLinkedList_Clear(eventList);
	}
	else
	{
		void *callback = duk_require_heapptr(ctx, 0);
		ILibDuktape_EventEmitter_HookHandler hookHandler = ILibHashtable_Get(data->eventTable, ILibDuktape_EventEmitter_Hook, propName, (int)propNameLen);

		ILibLinkedList_AddTail(eventList, callback);
		duk_push_heapptr(ctx, data->tmpObject);
		duk_push_heapptr(ctx, callback);
		duk_put_prop_string(ctx, -2, Duktape_GetStashKey(callback)); // Save callback to tmpObject so it won't get GC'ed

		duk_push_heapptr(ctx, dispatcher);									// [dispatcher]
		duk_get_prop_string(ctx, -1, ILibDuktape_EventEmitter_HPTR_LIST);	// [dispatcher][hptrList]
		count = (int)duk_get_length(ctx, -1);
		for (i = 0; i < count; ++i)
		{
			duk_get_prop_index(ctx, -1, i);									// [dispatcher][hptrList][hptr]
			hptr = (void**)duk_get_pointer(ctx, -1);
			*hptr = dispatcher;												// Set this, so from Native, it looks like there is a subscriber.
			duk_pop(ctx);													// [dispatcher][hptrList]
		}

		if (hookHandler != NULL)
		{
			hookHandler(data, propName, callback);
		}
	}

	return 0;
}
duk_ret_t ILibDuktape_EventEmitter_Dispatcher(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	void *self;
	int i;
	char *name;

	duk_push_current_function(ctx);										// [func]
	duk_get_prop_string(ctx, -1, "name");								// [func][name]
	name = (char*)duk_get_string(ctx, -1);
	duk_get_prop_string(ctx, -2, "this");								// [func][name][this]
	self = duk_get_heapptr(ctx, -1);
	duk_get_prop_string(ctx, -1, "emit");								// [func][name][this][emitter]

	//-------------------------------------------------------------------------------------------------

	duk_push_heapptr(ctx, self);										// [emitter][this]
	duk_push_string(ctx, name);											// [emitter][this][name]
	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);												// [emitter][this][name][...args...]
	}
	duk_call_method(ctx, nargs + 1);									// Exception will bubble up.

	return 0;
}
duk_ret_t ILibDuktape_EventEmitter_NativeDispatch(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *name;
	ILibDuktape_EventEmitter_Handler handler;
	void *args;
	int i = 0;

	duk_push_current_function(ctx);											// [func]
	duk_get_prop_string(ctx, -1, "name");									// [func][name]
	name = (char*)duk_get_string(ctx, -1);
	duk_get_prop_string(ctx, -2, "handler");								// [func][name][handler]
	handler = (ILibDuktape_EventEmitter_Handler)duk_get_pointer(ctx, -1);
	
	duk_push_array(ctx);													// [func][name][handler][args]
	args = duk_get_heapptr(ctx, -1);

	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);													// [func][name][handler][args][...arg...]
		duk_put_prop_index(ctx, -2, i);										// [func][name][handler][args]
	}

	duk_push_this(ctx);
	handler(ctx, duk_get_heapptr(ctx, -1), name, args);
	
	return 0;
}
int ILibDuktape_EventEmitter_AddSink(ILibDuktape_EventEmitter *emitter, char *eventName, ILibDuktape_EventEmitter_Handler handler)
{
	ILibLinkedList eventList;
	void *func;

	duk_push_heapptr(emitter->ctx, emitter->tmpObject);											// [tmp]
	duk_push_c_function(emitter->ctx, ILibDuktape_EventEmitter_NativeDispatch, DUK_VARARGS);	// [tmp][dispatch]
	duk_push_string(emitter->ctx, eventName);													// [tmp][dispatch][name]
	duk_put_prop_string(emitter->ctx, -2, "name");												// [tmp][dispatch]
	duk_push_pointer(emitter->ctx, handler);													// [tmp][dispatch][nativePtr]
	duk_put_prop_string(emitter->ctx, -2, "handler");											// [tmp][dispatch]
	func = duk_get_heapptr(emitter->ctx, -1);
	eventList = ILibHashtable_Get(emitter->eventTable, NULL, eventName, (int)strnlen_s(eventName, ILibDuktape_EventEmitter_MaxEventNameLen));
	if (eventList == NULL) { return 1; }

	((int*)ILibLinkedList_GetExtendedMemory(ILibLinkedList_AddTail(eventList, func)))[0] = 2;
	emitter->totalListeners[0]++;

	duk_put_prop_string(emitter->ctx, -2, Duktape_GetStashKey(func));							// [tmp]
	duk_pop(emitter->ctx);																		// ...

	return 0;
}
void ILibDuktape_EventEmitter_RemoveAllEx(ILibHashtable sender, void *Key1, char* Key2, int Key2Len, void *Data, void *user)
{
	ILibDuktape_EventEmitter *data = (ILibDuktape_EventEmitter*)user;
	if (Key1 == ILibDuktape_EventEmitter_SetterFunc)
	{
		// If this is not NULL, this is the JavaScript Setter Func
		memcpy_s(ILibScratchPad, sizeof(ILibScratchPad), Key2, Key2Len);
		ILibScratchPad[Key2Len] = 0;
		duk_push_heapptr(data->ctx, Data);											// [Setter]
		duk_del_prop_string(data->ctx, -1, ILibDuktape_EventEmitter_HPTR_LIST);
		duk_push_array(data->ctx);													// [Setter][list]
		duk_put_prop_string(data->ctx, -2, ILibDuktape_EventEmitter_HPTR_LIST);		// [Setter]

		duk_pop(data->ctx);															// ...
	}
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
void ILibDuktape_EventEmitter_RemoveAll(ILibDuktape_EventEmitter *emitter)
{
	if (emitter->eventTable != NULL) { ILibHashtable_Enumerate(emitter->eventTable, ILibDuktape_EventEmitter_RemoveAllEx, emitter); }
}
void ILibDuktape_EventEmitter_RemoveEventHeapptr(ILibDuktape_EventEmitter *emitter, char *eventName, void **heapptr)
{
	int i, count;
	void *dispatcher = NULL;
	int eventNameLen = (int)strnlen_s(eventName, ILibDuktape_EventEmitter_MaxEventNameLen);
	if ((dispatcher = ILibHashtable_Get(emitter->eventTable, ILibDuktape_EventEmitter_SetterFunc, eventName, eventNameLen)) != NULL)
	{
		// This event already exists... Let's hook up the hptr to the existing dispatcher
		duk_push_heapptr(emitter->ctx, dispatcher);															// [dispatcher]
		if (heapptr != NULL)
		{
			duk_get_prop_string(emitter->ctx, -1, ILibDuktape_EventEmitter_HPTR_LIST);						// [dispatcher][hptrList]
			count = (int)duk_get_length(emitter->ctx, -1);
			for (i = 0; i < count; ++i)
			{
				duk_get_prop_index(emitter->ctx, -1, i);													// [dispatcher][hptrList][hptr]
				if (duk_get_pointer(emitter->ctx, -1) == heapptr)
				{
					duk_pop(emitter->ctx);																	// [dispatcher][hptrList]
					duk_del_prop_index(emitter->ctx, -1, i);
					break;
				}
				duk_pop(emitter->ctx);																		// [dispatcher][hptrList]
			}
			duk_pop(emitter->ctx);																			// [dispatcher]
		}
		else
		{
			duk_del_prop_string(emitter->ctx, -1, ILibDuktape_EventEmitter_HPTR_LIST);						// [dispatcher]
			duk_push_array(emitter->ctx);																	// [dispatcher][hptrList]
			duk_put_prop_string(emitter->ctx, -2, ILibDuktape_EventEmitter_HPTR_LIST);						// [dispatcher]
		}
		duk_pop(emitter->ctx);																				// ...
	}
}
int ILibDuktape_EventEmitter_AddEventHeapptr(ILibDuktape_EventEmitter *emitter, char *eventName, void **heapptr)
{
	ILibLinkedList eventList = NULL;
	void *dispatcher = NULL;
	int eventNameLen = (int)strnlen_s(eventName, ILibDuktape_EventEmitter_MaxEventNameLen);
	if ((dispatcher = ILibHashtable_Get(emitter->eventTable, ILibDuktape_EventEmitter_SetterFunc, eventName, eventNameLen)) != NULL)
	{
		// This event already exists... Let's hook up the hptr to the existing dispatcher
		duk_push_heapptr(emitter->ctx, dispatcher);														// [dispatcher]
		duk_get_prop_string(emitter->ctx, -1, ILibDuktape_EventEmitter_HPTR_LIST);						// [dispatcher][hptrList]
		duk_push_pointer(emitter->ctx, heapptr);														// [dispatcher][hptrList][hptr]
		duk_put_prop_index(emitter->ctx, -2, (duk_uarridx_t)duk_get_length(emitter->ctx, -2));			// [dispatcher][hptrList]
		duk_pop_2(emitter->ctx);																		// ...

		// Now lets check if there was already a subscriber
		if ((eventList = ILibHashtable_Get(emitter->eventTable, NULL, eventName, eventNameLen)) != NULL && ILibLinkedList_GetCount(eventList) > 0)
		{
			*heapptr = dispatcher;
		}
		return 0;
	}
	return 1;
}
void ILibDuktape_EventEmitter_CreateEventEx(ILibDuktape_EventEmitter *emitter, char *eventName)
{
	void **heapptr;
	duk_push_heapptr(emitter->ctx, emitter->tmpObject);												// [emitter]
	duk_push_object(emitter->ctx);																	// [emitter][tmp]
	duk_push_fixed_buffer(emitter->ctx, sizeof(void*));												// [emitter][tmp][buffer]
	heapptr = (void**)Duktape_GetBuffer(emitter->ctx, -1, NULL);
	memset((void*)heapptr, 0, sizeof(void*));
	duk_put_prop_string(emitter->ctx, -2, "\xFF_buffer");											// [emitter][tmp]
	duk_put_prop_string(emitter->ctx, -2, Duktape_GetStashKey(duk_get_heapptr(emitter->ctx, -1)));	// [emitter]
	duk_pop(emitter->ctx);																			// ...

	ILibDuktape_EventEmitter_CreateEvent(emitter, eventName, heapptr);
}
void ILibDuktape_EventEmitter_CreateEvent(ILibDuktape_EventEmitter *emitter, char *eventName, void **hptr)
{
	void *dispatcher = NULL;
	int eventNameLen = (int)strnlen_s(eventName, ILibDuktape_EventEmitter_MaxEventNameLen);
	if ((dispatcher = ILibHashtable_Get(emitter->eventTable, ILibDuktape_EventEmitter_SetterFunc, eventName, eventNameLen)) != NULL)
	{
		// This event already exists... Let's hook up the hptr to the existing dispatcher
		duk_push_heapptr(emitter->ctx, dispatcher);														// [dispatcher]
		duk_get_prop_string(emitter->ctx, -1, ILibDuktape_EventEmitter_HPTR_LIST);						// [dispatcher][hptrList]
		duk_push_pointer(emitter->ctx, hptr);															// [dispatcher][hptrList][hptr]
		duk_put_prop_index(emitter->ctx, -2, (duk_uarridx_t)duk_get_length(emitter->ctx, -2));			// [dispatcher][hptrList]
		duk_pop_2(emitter->ctx);																		// ...
		return;
	}


	duk_push_heapptr(emitter->ctx, emitter->object);													// [obj]

	// Create the Property Setter
	duk_push_string(emitter->ctx, eventName);															// [obj][prop]
	duk_push_c_function(emitter->ctx, ILibDuktape_EventEmitter_SetEvent, 1);							// [obj][prop][setFunc]
	duk_push_string(emitter->ctx, eventName);															// [obj][prop][setFunc][name]
	duk_put_prop_string(emitter->ctx, -2, "name");														// [obj][prop][setFunc]
	
	// Set some custom properties into the setter func, so we can access it later
	duk_push_c_function(emitter->ctx, ILibDuktape_EventEmitter_Dispatcher, DUK_VARARGS);				// [obj][prop][setFunc][dispatcher]
	dispatcher = duk_get_heapptr(emitter->ctx, -1);
	duk_push_heapptr(emitter->ctx, emitter->object);													// [obj][prop][setFunc][dispatcher][this]
	duk_put_prop_string(emitter->ctx, -2, "this");														// [obj][prop][setFunc][dispatcher]			
	duk_push_string(emitter->ctx, eventName);															// [obj][prop][setFunc][dispatcher][name]
	duk_put_prop_string(emitter->ctx, -2, "name");														// [obj][prop][setFunc][dispatcher]
	duk_push_array(emitter->ctx);																		// [obj][prop][setFunc][dispatcher][hptrList]
	duk_push_pointer(emitter->ctx, hptr);																// [obj][prop][setFunc][dispatcher][hptrList][hptr]
	duk_put_prop_index(emitter->ctx, -2, 0);															// [obj][prop][setFunc][dispatcher][hptrList]
	duk_put_prop_string(emitter->ctx, -2, ILibDuktape_EventEmitter_HPTR_LIST);							// [obj][prop][setFunc][dispatcher]
	duk_put_prop_string(emitter->ctx, -2, ILibDuktape_EventEmitter_DispatcherFunc);						// [obj][prop][setFunc]

	duk_def_prop(emitter->ctx, -3, DUK_DEFPROP_FORCE | DUK_DEFPROP_HAVE_SETTER);						// [obj]
	duk_pop(emitter->ctx);																				// ...

	ILibHashtable_Put(emitter->eventTable, NULL, eventName, eventNameLen, ILibLinkedList_CreateEx(sizeof(int)));
	ILibHashtable_Put(emitter->eventTable, ILibDuktape_EventEmitter_SetterFunc, eventName, eventNameLen, dispatcher);
}
void *ILibDuktape_EventEmitter_GetDispatcher(ILibDuktape_EventEmitter *emitter, char *eventName)
{
	return ILibHashtable_Get(emitter->eventTable, ILibDuktape_EventEmitter_SetterFunc, eventName, (int)strnlen_s(eventName, ILibDuktape_EventEmitter_MaxEventNameLen));
}
duk_ret_t ILibDuktape_EventEmitter_Inherits_createEvent(duk_context *ctx)
{
	char *name = (char*)duk_require_string(ctx, 0);
	ILibDuktape_EventEmitter *emitter;
	void **hptr;
	duk_push_this(ctx);									// [emitterUtils]
	duk_get_prop_string(ctx, -1, "emitter");			// [emitterUtils][ptr]
	emitter = (ILibDuktape_EventEmitter*)duk_get_pointer(ctx, -1);
	duk_pop(ctx);										// [emitterUtils]
	duk_push_fixed_buffer(ctx, sizeof(void*));			// [emitterUtils][buffer]
	hptr = (void**)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, name);					// [emitterUtils]

	ILibDuktape_EventEmitter_CreateEvent(emitter, name, hptr);
	return 0;
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
void ILibDuktape_EventEmitter_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);			// [emitter]
	ILibDuktape_CreateInstanceMethod(ctx, "inherits", ILibDuktape_EventEmitter_Inherits, 1);
}
void ILibDuktape_EventEmitter_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "events", ILibDuktape_EventEmitter_PUSH);
}
