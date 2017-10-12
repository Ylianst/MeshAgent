#ifndef __ILibDuktape_EVENT_EMITTER__
#define __ILibDuktape_EVENT_EMITTER__

#include "duktape.h"
#include "microstack/ILibParsers.h"

typedef void(*ILibDuktape_EventEmitter_Handler)(duk_context *ctx, void *object, char *eventName, void *duk_eventArgs);
typedef struct ILibDuktape_EventEmitter
{
	duk_context *ctx;
	void *object;
	void *tmpObject;
	unsigned int *totalListeners;
	ILibHashtable eventTable;
}ILibDuktape_EventEmitter;
typedef void(*ILibDuktape_EventEmitter_HookHandler)(ILibDuktape_EventEmitter *sender, char *eventName, void *hookedCallback);

ILibDuktape_EventEmitter* ILibDuktape_EventEmitter_Create(duk_context *ctx);
ILibDuktape_EventEmitter* ILibDuktape_EventEmitter_GetEmitter(duk_context *ctx, duk_idx_t i);
ILibDuktape_EventEmitter* ILibDuktape_EventEmitter_GetEmitter_fromThis(duk_context *ctx);
#define ILibDuktape_EventEmitter_GetEmitter_fromCurrent(ctx) ILibDuktape_EventEmitter_GetEmitter(ctx, -1)

void ILibDuktape_EventEmitter_Init(duk_context *ctx);
void ILibDuktape_EventEmitter_RemoveAll(ILibDuktape_EventEmitter *emitter);															// Removes all event handlers/dispatchers
void ILibDuktape_EventEmitter_RemoveAllListeners(ILibDuktape_EventEmitter *emitter, char *eventName);								// Invokes JavaScript method EventEmitter.removeAllListeners()
void ILibDuktape_EventEmitter_CreateEvent(ILibDuktape_EventEmitter *emitter, char *eventName, void **hptr);							// Create Event with hybrid dispatcher
void ILibDuktape_EventEmitter_CreateEventEx(ILibDuktape_EventEmitter *emitter, char *eventName);									// Create Event with virtual dispatcher
void ILibDuktape_EventEmitter_RemoveEventHeapptr(ILibDuktape_EventEmitter *emitter, char *eventName, void **heapptr);				// Remove native callback pointer
int ILibDuktape_EventEmitter_AddEventHeapptr(ILibDuktape_EventEmitter *emitter, char *eventName, void **heapptr);					// Add Callback after the fact
int ILibDuktape_EventEmitter_AddSink(ILibDuktape_EventEmitter *emitter, char *eventName, ILibDuktape_EventEmitter_Handler handler);	// Add Native Event Handler
int ILibDuktape_EventEmitter_AddOnce(ILibDuktape_EventEmitter *emitter, char *eventName, void *heapptr);							// Add native event handler 'once'
int ILibDuktape_EventEmitter_AddOn(ILibDuktape_EventEmitter *emitter, char *eventName, void *heapptr);								// Add native event handler

void ILibDuktape_EventEmitter_AddHook(ILibDuktape_EventEmitter *emitter, char *eventName, ILibDuktape_EventEmitter_HookHandler handler);


#endif
