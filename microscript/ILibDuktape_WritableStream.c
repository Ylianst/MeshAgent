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

#include "duktape.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_WritableStream.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktape_Polyfills.h"

#ifdef __DOXY__
/*!
\implements EventEmitter
\brief Writable streams are an abstraction for a destination to which data is written.
*/
public class WritableStream
{
public:
	/*!
	\brief Calling this method signals that no more data will be written to the WritableStream
	*
	void end([chunk][,callback])
	\param chunk <Buffer | String> The optional chunk argument allows one final additional chunk of data to be written immediately before closing the stream. 
	\param callback If provided, the optional callback function is attached as a one time listener for the 'finish' event.
	*/
	void end([chunk][,callback]);

	/*!
	\brief This method writes some data to the stream, and calls the supplied callback once the data has been fully handled
	\param chunk <Buffer | String> The data to write
	\param callback If provided, the optional callback function is emitted when the data is flushed
	\returns false if the calling code should wait for the 'drain' event before writing more data. true otherwise.
	*/	
	bool write(chunk[, callback]);

	/*!
	\brief The 'close' event is emitted when the stream and any of its underlying resources have been closed. 
	*
	 The event indicates that no more events will be emitted, and no further computation will occur.
	*/
	void close;
	/*!
	\brief If a call to write(chunk) returns false, the 'drain' event will be emitted when it is appropriate to resume writing data to the stream.
	*/
	void drain;
	/*!
	\brief The 'error' event is emitted if an error occurred while writing or piping data.
	\param arg Error argument describing the error that occured
	*/
	void error;
	/*!
	\brief The 'finish' event is emitted after the end() method has been called, and all data has been flushed to the underlying system.
	*/
	void finish;
	/*!
	\brief The 'pipe' event is emitted when the ReadableStream.pipe() method is called on a ReadableStream, adding this WriteableStream to its set of destinations.
	\param src The ReadableStream that is piping to this WritableStream.
	*/
	void pipe;
	/*!
	\brief The 'unpipe' event is emitted when the unpipe() method is called on a ReadableStream, removing this WritableStream from its set of destinations.
	\param src The ReadableStream that is unpiping this WritableStream.
	*/
	void unpipe;
};
#endif

ILibDuktape_WritableStream* ILibDuktape_WritableStream_GetStream(duk_context *ctx)
{
	ILibDuktape_WritableStream* retVal;

	duk_push_this(ctx);														// [stream]
	duk_get_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS);		// [stream][ptr]
	retVal = (ILibDuktape_WritableStream*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop_2(ctx);															// ...
	return retVal;
}
void ILibDuktape_WritableStream_Finish(ILibDuktape_WritableStream *stream)
{
	if (stream == NULL || !ILibMemory_CanaryOK(stream)) { return; }

	duk_push_heapptr(stream->ctx, stream->obj);						// [stream]
	duk_get_prop_string(stream->ctx, -1, "emit");					// [stream][emit]
	duk_swap_top(stream->ctx, -2);									// [emit][this]
	duk_push_string(stream->ctx, "finish");							// [emit][this][finish]
	if (duk_pcall_method(stream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtException(stream->ctx); }
	duk_pop(stream->ctx);											// ...
}
void ILibDuktape_WritableStream_Ready(ILibDuktape_WritableStream *stream)
{
	if (stream == NULL || !ILibMemory_CanaryOK(stream)) { return; }
	if (stream->WaitForEnd == 0)
	{
		if (stream->OnWriteFlushEx != NULL)
		{
			// Keep it native
			ILibDuktape_WriteableStream_WriteFlushNative native = stream->OnWriteFlushEx;
			void *user = stream->OnWriteFlushEx_User;

			stream->OnWriteFlushEx = NULL;
			stream->OnWriteFlushEx_User = NULL;

			native(stream, user);
		}
		else if (stream->OnWriteFlush != NULL)
		{
			duk_push_this(stream->ctx);									// [stream]
			duk_push_heapptr(stream->ctx, stream->OnWriteFlush);		// [stream][func]
			duk_swap_top(stream->ctx, -2);								// [func][stream]
			stream->OnWriteFlush = NULL;
			duk_del_prop_string(stream->ctx, -1, "_WriteFlush");
			duk_pop(stream->ctx);										// [func]

			duk_push_heapptr(stream->ctx, stream->obj);					// [func][this]
			if (duk_pcall_method(stream->ctx, 0) != 0)					// [retVal]
			{
				ILibDuktape_Process_UncaughtException(stream->ctx);
			}
			duk_pop(stream->ctx);										// ...
		}
		else
		{
			duk_push_heapptr(stream->ctx, stream->obj);					// [this]
			duk_get_prop_string(stream->ctx, -1, "emit");				// [this][emit]
			duk_swap_top(stream->ctx, -2);								// [emit][this]
			duk_push_string(stream->ctx, "drain");						// [emit][this][drain]
			if (duk_pcall_method(stream->ctx, 1) != 0)					// [retVal]
			{
				ILibDuktape_Process_UncaughtException(stream->ctx);
			}
			duk_pop(stream->ctx);										// ...
		}
	}
	else
	{
		// End of Stream
		if (stream->EndSink != NULL)
		{
			stream->EndSink(stream, stream->WriteSink_User);
		}

		duk_push_heapptr(stream->ctx, stream->obj);						// [stream]
		duk_get_prop_string(stream->ctx, -1, "emit");					// [stream][emit]
		duk_swap_top(stream->ctx, -2);									// [emit][this]
		duk_push_string(stream->ctx, "finish");							// [emit][this][finish]
		if (duk_pcall_method(stream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtException(stream->ctx); }
		duk_pop(stream->ctx);											// ...
	}
}

duk_ret_t ILibDuktape_WritableStream_Write(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	ILibDuktape_WritableStream *stream = ILibDuktape_WritableStream_GetStream(ctx);
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int cbIndex = 0;

	stream->Reserved = duk_is_string(ctx, 0) ? 1 : 0;

	for (cbIndex = 1; cbIndex < nargs; ++cbIndex)
	{
		if (duk_is_function(ctx, cbIndex)) { break; }
	}
	if (cbIndex == nargs) { cbIndex = 0; }

	if (stream->WriteSink != NULL)
	{
		stream->endBytes = -1;
		switch (stream->WriteSink(stream, buffer, (int)bufferLen, stream->WriteSink_User))
		{
			case ILibTransport_DoneState_COMPLETE:
				if (cbIndex != 0)
				{
					duk_dup(ctx, cbIndex);				// [func]
					duk_push_heapptr(ctx, stream->obj);	// [func][this]
					if (duk_pcall_method(ctx, 0) != 0)	// [retVal]
					{
						ILibDuktape_Process_UncaughtException(ctx);
					}
				}
				duk_push_true(ctx);
				break;
			case ILibTransport_DoneState_INCOMPLETE:
				if (cbIndex != 0)
				{
					stream->OnWriteFlush = duk_require_heapptr(ctx, cbIndex);
					duk_push_this(ctx);								// [stream]
					duk_dup(ctx, cbIndex);							// [stream][flush]
					duk_put_prop_string(ctx, -2, "_WriteFlush");	// [stream]
				}
				duk_push_false(ctx);
				break;
			default:
				duk_push_heapptr(ctx, stream->obj);					// [this]
				duk_get_prop_string(ctx, -1, "emit");				// [this][emit]
				duk_swap_top(ctx, -2);								// [emit][this]
				duk_push_string(ctx, "error");						// [emit][this][error]
				duk_push_object(ctx);								// [emit][this][error][errorObj]
				duk_push_string(ctx, "ILibDuktape_WritableStream_Write");
				duk_put_prop_string(ctx, -2, "stack");
				duk_push_string(ctx, "ILibDuktape_WriteableStream_Write/Handler returned Error");
				duk_put_prop_string(ctx, -2, "message");
				if (duk_pcall_method(ctx, 2) != 0)					// [retVal]
				{
					ILibDuktape_Process_UncaughtException(ctx);
				}
				duk_push_false(ctx);
				break;
		}
	}
	else
	{
		duk_push_false(ctx);
	}
	return 1;
}
duk_ret_t ILibDuktape_WritableStream_End(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	ILibDuktape_WritableStream *stream = ILibDuktape_WritableStream_GetStream(ctx);
	duk_size_t bufferLen;
	char *buffer;
	int i;

	if (nargs > 0)
	{
		for (i = 0; i < nargs; ++i)
		{
			if (duk_is_function(ctx, i))
			{
				ILibDuktape_EventEmitter_AddOnce(ILibDuktape_EventEmitter_GetEmitter_fromThis(ctx), "finish", duk_require_heapptr(ctx, i));
				break;
			}
		}

		buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
		if (buffer != NULL && stream->WriteSink != NULL)
		{
			stream->endBytes = (int)bufferLen;
			if (stream->WriteSink(stream, buffer, (int)bufferLen, stream->WriteSink_User) == ILibTransport_DoneState_INCOMPLETE)
			{
				// Incomplete, wait for SendOK
				stream->WaitForEnd = 1;
			}
		}
	}

	if (stream->WaitForEnd == 0)
	{
		// Continue with closing stream
		if (stream->EndSink != NULL) { stream->EndSink(stream, stream->WriteSink_User); }		
		
		duk_push_heapptr(stream->ctx, stream->obj);						// [stream]
		duk_get_prop_string(stream->ctx, -1, "emit");					// [stream][emit]
		duk_swap_top(stream->ctx, -2);									// [emit][this]
		duk_push_string(stream->ctx, "finish");							// [emit][this][finish]
		if (duk_pcall_method(stream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtException(stream->ctx); }
		duk_pop(stream->ctx);											// ...
	}

	return 0;
}
duk_ret_t ILibDuktape_WritableStream_End_Getter(duk_context *ctx)
{
	duk_push_c_function(ctx, ILibDuktape_WritableStream_End, DUK_VARARGS);
	return 1;
}
duk_ret_t ILibDuktape_WritableStream_UnPipeSink(duk_context *ctx)
{
	ILibDuktape_WritableStream *ws;

	duk_dup(ctx, 0);														// [readable]											
	duk_push_this(ctx);														// [readable][writable]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS);	// [readable][writable][ptr]
		ws = (ILibDuktape_WritableStream*)Duktape_GetBuffer(ctx, -1, NULL);
		ws->pipedReadable = NULL;
		ws->pipedReadable_native = NULL;
		duk_pop(ctx);														// [readable][writable]
		if (g_displayStreamPipeMessages) { printf("UNPIPE: [%s] => X => [%s:%d]\n", Duktape_GetStringPropertyValue(ctx, -2, ILibDuktape_OBJID, "unknown"), Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_OBJID, "unknown"), ILibDuktape_GetReferenceCount(ctx, -1) - 1);	if (g_displayFinalizerMessages) { duk_eval_string(ctx, "_debugGC();"); duk_pop(ctx); } }
	}
	duk_pop_2(ctx);
	return(0);
}
duk_ret_t ILibDuktape_WritableStream_PipeSink(duk_context *ctx)
{
	ILibDuktape_WritableStream *ws;
	duk_push_this(ctx);													// [writable]
	duk_get_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS);
	ws = (ILibDuktape_WritableStream*)Duktape_GetBuffer(ctx, -1, NULL);

	if (duk_has_prop_string(ctx, 0, "\xFF_ReadableStream_PTRS"))
	{
		duk_get_prop_string(ctx, 0, "\xFF_ReadableStream_PTRS");	// [writable][rs]
		ws->pipedReadable_native = (struct ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);
	}
	ws->pipedReadable = duk_get_heapptr(ctx, 0);
	
	duk_dup(ctx, 0);
	duk_push_this(ctx);
	if (g_displayStreamPipeMessages) { printf("PIPE: [%s/%p] => [%s:%d]\n", Duktape_GetStringPropertyValue(ctx, -2, ILibDuktape_OBJID, "unknown"), (void*)ws, Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_OBJID, "unknown"), ILibDuktape_GetReferenceCount(ctx, -1)); }
	return(0);
}
duk_ret_t ILibDuktape_WritableStream_Ended(duk_context *ctx)
{
	duk_push_this(ctx);			// WS
	ILibDuktape_WritableStream *WS = (ILibDuktape_WritableStream*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_WritableStream_WSPTRS);
	
	if (WS != NULL)
	{
		duk_push_boolean(ctx, WS->endBytes > 0);
	}
	else
	{
		duk_push_false(ctx);
	}
	return(1);
}
ILibDuktape_WritableStream* ILibDuktape_WritableStream_Init(duk_context *ctx, ILibDuktape_WritableStream_WriteHandler WriteHandler, ILibDuktape_WritableStream_EndHandler EndHandler, void *user)
{
	ILibDuktape_WritableStream *retVal;
	ILibDuktape_EventEmitter *emitter;

	retVal = (ILibDuktape_WritableStream*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_WritableStream));	// [obj][buffer]
	duk_put_prop_string(ctx, -2, ILibDuktape_WritableStream_WSPTRS);									// [obj]
	
	retVal->ctx = ctx;
	retVal->obj = duk_get_heapptr(ctx, -1);
	retVal->WriteSink = WriteHandler;
	retVal->EndSink = EndHandler;
	retVal->WriteSink_User = user;

	emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "pipe");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "unpipe");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "drain");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "finish");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "error");

	ILibDuktape_CreateInstanceMethod(ctx, "writeCalledByEnd", ILibDuktape_WritableStream_Ended, 0);
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "write", ILibDuktape_WritableStream_Write, DUK_VARARGS);
	ILibDuktape_CreateEventWithGetter(ctx, "end", ILibDuktape_WritableStream_End_Getter);
	ILibDuktape_EventEmitter_AddOn_Infrastructure(ctx, -1, "pipe", ILibDuktape_WritableStream_PipeSink);
	ILibDuktape_EventEmitter_AddOn_Infrastructure(ctx, -1, "unpipe", ILibDuktape_WritableStream_UnPipeSink);
	return retVal;
}
