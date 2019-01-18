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

#include "ILibDuktape_ReadableStream.h"
#include "ILibDuktape_WritableStream.h"
#include "ILibDuktape_Helpers.h"
#include "microstack/ILibParsers.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktape_Polyfills.h"


#define ILibDuktape_readableStream_WritePipes			"\xFF_WritePipes"
#define ILibDuktape_readableStream_WritePipes_PTRBUFFER	"\xFF_WritePipesPtrBuffer"
#define ILibDuktape_readableStream_WritePipes_Stream	"\xFF_WritePipes_Stream"
#define ILibDuktape_readableStream_PipeArray			"\xFF_RS_PipeArray"

int ILibDuktape_readableStream_resume_flush(ILibDuktape_readableStream *rs);

#ifdef __DOXY__
/*! 
\implements EventEmitter
\brief Readable streams are an abstraction for a source from which data is consumed
*/
public class ReadableStream
{
public:
	/*! 
	\brief This method returns the current operating state of the ReadableStream. 
	*
	* This is used primarily by the mechanism that underlies the readable.pipe() method. 
	* In most typical cases, there will be no reason to use this method directly
	*/
	bool isPaused();
	/*! 
	\brief ReadableStream.pause() method will cause a stream in flowing mode to stop emitting 'data' events, switching out of flowing mode. 
	*
	* Any data that becomes available will remain in the internal buffer.*/
	void pause();
	/*! 
	\brief ReadableStream.resume() method causes an explicitly paused ReadableStream to resume emitting 'data' events, switching the stream into flowing mode.
	*/
	void resume();
	/*! 
	\brief The ReadableStream.pipe() method attaches a WritableStream to the readable, causing it to switch automatically into flowing mode and push all of its data to the attached WritableStream. 
	*
	* Flow control of data will be automatically managed so that the destination WritableStream is not overwhelmed by a faster ReadableStream.
	\param destination \<WritableStream\> The WritableStream to attach to the ReadableStream.
	\param options <Object> Optional parameters:\n
	<b>dataTypeSkip</b> If set to 1, String values will only emit 'data' events instead of being piped to the WritableStream
	*/
	void pipe(destination[, options]);
	/*! 
	\brief The ReadableStream.unpipe() method detaches a WritableStream previously attached using the ReadableStream.pipe() method.
	*
	\param destination \<WritableStream\> If specified, the WritableStream to detach. If not specified, all streams will be dettached.
	*/
	void unpipe(destination);


	/*! 
	\brief The 'close' event is emitted when the stream and any of its underlying resources have been closed. 
	*
	* The event indicates that no more events will be emitted, and no further computation will occur.
	* Not all ReadableStreams will emit the 'close' event.
	*/
	void close;
	/*! 
	\brief The 'data' event is emitted whenever the stream is relinquishing ownership of a chunk of data to a consumer. 
	*
	* This may occur whenever the stream is switched in flowing mode by calling readable.pipe(), readable.resume(), or by attaching a listener callback to the 'data' event. 
	\param chunk A chunk of data. Can be a Buffer or a string.
	*/
	void data;
	/*!
	\brief The 'end' event is emitted when there is no more data to be consumed from the stream.
	*/
	void end;
	/*!
	\brief The 'error' event may be emitted by a Readable implementation at any time. 
	*
	* Typically, this may occur if the underlying stream is unable to generate data due to an underlying internal failure, or when a stream implementation attempts to push an invalid chunk of data.
	\param err Error object
	*/
	void error;
};
#endif


typedef struct ILibDuktape_readableStream_bufferedData
{
	struct ILibDuktape_readableStream_bufferedData *Next;
	int bufferLen;
	int Reserved;
	char buffer[];
}ILibDuktape_readableStream_bufferedData;

void ILibDuktape_ReadableStream_DestroyPausedData(ILibDuktape_readableStream *stream)
{
	ILibDuktape_readableStream_bufferedData *buffered = (ILibDuktape_readableStream_bufferedData*)stream->paused_data;
	ILibDuktape_readableStream_bufferedData *tmp;

	while (buffered != NULL)
	{
		tmp = buffered->Next;
		free(buffered);
		buffered = tmp;
	}
	stream->paused_data = NULL;
}
void ILibDuktape_readableStream_WriteData_buffer(ILibDuktape_readableStream *stream, int streamReserved, char *buffer, int bufferLen)
{
	ILibDuktape_readableStream_bufferedData *buffered = (ILibDuktape_readableStream_bufferedData*)ILibMemory_Allocate(bufferLen + sizeof(ILibDuktape_readableStream_bufferedData), 0, NULL, NULL);
	buffered->Reserved = streamReserved;
	buffered->bufferLen = bufferLen;
	memcpy_s(buffered->buffer, bufferLen,  buffer, bufferLen);

	if (stream->paused_data == NULL)
	{
		stream->paused_data = buffered;
	}
	else
	{
		ILibDuktape_readableStream_bufferedData *tmp = stream->paused_data;
		while (tmp->Next != NULL)
		{
			tmp = tmp->Next;
		}
		tmp->Next = buffered;
	}
}
void ILibDuktape_readableStream_WriteData_OnData_ChainThread(void *chain, void *user)
{
	ILibDuktape_readableStream_bufferedData *data = (ILibDuktape_readableStream_bufferedData*)user;
	ILibDuktape_readableStream *stream = (ILibDuktape_readableStream*)data->Next;

	if (!ILibMemory_CanaryOK(stream))
	{
		free(data);
		return;
	}

	stream->paused = 0;
	if (data->Reserved == 0)
	{
		duk_push_external_buffer(stream->ctx);																// [ext]
		duk_config_buffer(stream->ctx, -1, data->buffer, data->bufferLen);
	}

	ILibDuktape_EventEmitter_SetupEmit(stream->ctx, stream->object, "data");								// [ext][emit][this][data]
	if (data->Reserved == 0)
	{
		duk_push_buffer_object(stream->ctx, -4, 0, data->bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);				// [ext][emit][this][data][buffer]
	}
	else
	{
		duk_push_lstring(stream->ctx, data->buffer, data->bufferLen);										// [ext][emit][this][data][buffer/string]
	}
	if (duk_pcall_method(stream->ctx, 2) != 0)																// [...][retVal]
	{
		ILibDuktape_Process_UncaughtException(stream->ctx);
	}
	if (data->Reserved == 0)
	{																										
		duk_pop_2(stream->ctx);																				// ...
	}
	else
	{
		duk_pop(stream->ctx);																				// ...
	}
	free(data);
	if (stream->paused == 0 && stream->ResumeHandler != NULL) { stream->ResumeHandler(stream, stream->user); }
}
int ILibDuktape_readableStream_WriteData_Flush(struct ILibDuktape_WritableStream *ws, void *user)
{
	ILibDuktape_readableStream *stream = (ILibDuktape_readableStream*)user;
	int unpipeInProgress = 0;

#ifdef WIN32
	if(InterlockedDecrement(&(stream->pipe_pendingCount)) == 0)
#elif defined(__ATOMIC_SEQ_CST)
	if (__atomic_sub_fetch(&(stream->pipe_pendingCount), 1, __ATOMIC_SEQ_CST) == 0)
#else
	sem_wait(&(stream->pipeLock));
	--stream->pipe_pendingCount;
	sem_post(&(stream->pipeLock));
	if(stream->pipe_pendingCount == 0)
#endif
	{
		if (stream->emitter->ctx == NULL) { return(1); }

		sem_wait(&(stream->pipeLock));
		stream->pipeInProgress = 0;
		unpipeInProgress = stream->unpipeInProgress;
		sem_post(&(stream->pipeLock));

		if (stream->paused != 0 && stream->paused_data != NULL)
		{
			stream->paused = 0;
			if (ILibDuktape_readableStream_resume_flush(stream) == 0 && stream->ResumeHandler != NULL)
			{
				stream->ResumeHandler(stream, stream->user);
			}
		}
		else
		{
			if (unpipeInProgress == 0 && stream->ResumeHandler != NULL && stream->paused != 0) { stream->paused = 0; stream->ResumeHandler(stream, stream->user); }
		}
		return(1);
	}
	return(0);
}

duk_ret_t ILibDuktape_readableStream_WriteDataEx_Flush(duk_context *ctx)
{
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "\xFF_STREAM");
	ILibDuktape_readableStream *stream = (ILibDuktape_readableStream*)duk_to_pointer(ctx, -1);

	ILibDuktape_readableStream_WriteData_Flush(NULL, stream);
	return(0);
}

int ILibDuktape_readableStream_WriteDataEx_Chain_Dispatch(ILibDuktape_readableStream *stream, void *ws, char *buffer, int bufferLen)
{
	int retVal = 0;
	duk_push_external_buffer(stream->ctx);														// [ext]
	duk_config_buffer(stream->ctx, -1, buffer, bufferLen);
	duk_push_heapptr(stream->ctx, ws);															// [ext][ws]
	duk_get_prop_string(stream->ctx, -1, "write");												// [ext][ws][write]
	duk_swap_top(stream->ctx, -2);																// [ext][write][this]
	duk_push_buffer_object(stream->ctx, -3, 0, bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);			// [ext][write][this][buffer]
	duk_push_c_function(stream->ctx, ILibDuktape_readableStream_WriteDataEx_Flush, DUK_VARARGS);// [ext][write][this][buffer][flush]
	duk_push_pointer(stream->ctx, stream);														// [ext][write][this][buffer][flush][ptr]
	duk_put_prop_string(stream->ctx, -2, "\xFF_STREAM");										// [ext][write][this][buffer][flush]
	if (duk_pcall_method(stream->ctx, 2) != 0)													// [ext][...]
	{
		ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "readable.write(): Error Piping ");
		if (ILibDuktape_readableStream_WriteData_Flush(NULL, stream)) { retVal = 2; }
	}
	retVal = duk_to_boolean(stream->ctx, -1) ? 1 : 0;
	duk_pop_2(stream->ctx);

	return(retVal);
}
void ILibDuktape_readableStream_WriteDataEx_Chain(void *chain, void *user)
{
	ILibDuktape_readableStream_bufferedData *data = (ILibDuktape_readableStream_bufferedData*)user;
	ILibDuktape_readableStream *stream = (ILibDuktape_readableStream*)data->Next;
	ILibDuktape_readableStream_nextWriteablePipe *w = stream->nextWriteable;

	while (w != NULL)
	{
		if (w->writableStream != NULL && w->nativeWritable == NULL)
		{
			if (ILibDuktape_readableStream_WriteDataEx_Chain_Dispatch(stream, w->writableStream, data->buffer, data->bufferLen) == 2) { break; }
		}
		w = w->next;
	}
	free(data);
}

int ILibDuktape_readableStream_WriteDataEx(ILibDuktape_readableStream *stream, int streamReserved, char* buffer, int bufferLen)
{
	ILibDuktape_readableStream_nextWriteablePipe *w;
	int dispatchedNonNative = 0;
	int noContinue = 0;
	int dispatched = 0;
	int needPause = 0;

	if (stream == NULL || !ILibMemory_CanaryOK(stream)) { return(1); }

	if (stream->paused != 0)
	{
		ILibDuktape_readableStream_WriteData_buffer(stream, streamReserved, buffer, bufferLen);
		if (stream->paused == 0 && stream->PauseHandler != NULL) { stream->paused = 1; stream->PauseHandler(stream, stream->user); }
		return(stream->paused);
	}

	if (stream->bypassValue == 0 || stream->bypassValue != streamReserved)
	{
		sem_wait(&(stream->pipeLock));
		stream->pipeInProgress = 1;
		sem_post(&(stream->pipeLock));

		w = stream->nextWriteable;
		stream->pipe_pendingCount = 0;
		while (w != NULL)
		{
			++stream->pipe_pendingCount;
			w = w->next;
		}
		dispatched = stream->pipe_pendingCount;
		w = stream->nextWriteable;
		while (w != NULL)
		{
			if (w->nativeWritable != NULL)
			{
				ILibDuktape_WritableStream *ws = (ILibDuktape_WritableStream*)w->nativeWritable;
				ws->Reserved = streamReserved;
				ws->endBytes = -1;
				switch (ws->WriteSink(ws, buffer, bufferLen, ws->WriteSink_User))
				{
					case ILibTransport_DoneState_INCOMPLETE:
						ws->OnWriteFlushEx = ILibDuktape_readableStream_WriteData_Flush;
						ws->OnWriteFlushEx_User = stream;
						needPause = 1;
						break;
					case ILibTransport_DoneState_COMPLETE:
						ws->OnWriteFlushEx = NULL;
						ws->OnWriteFlushEx_User = NULL;
						if (ILibDuktape_readableStream_WriteData_Flush(ws, stream)) { noContinue = 1; }
						break;
					case ILibTransport_DoneState_ERROR:
						if (ILibDuktape_readableStream_WriteData_Flush(ws, stream)) { noContinue = 1; }
						break;
				}
				if (noContinue != 0) { break; }
			}
			else if (w->writableStream != NULL && dispatchedNonNative == 0)
			{
				if (ILibIsRunningOnChainThread(stream->chain) == 0)
				{
					ILibDuktape_readableStream_bufferedData *tmp = (ILibDuktape_readableStream_bufferedData*)ILibMemory_Allocate(sizeof(ILibDuktape_readableStream_bufferedData) + bufferLen, 0, NULL, NULL);
					tmp->Next = (ILibDuktape_readableStream_bufferedData*)stream;
					tmp->Reserved = streamReserved;
					tmp->bufferLen = bufferLen;
					memcpy_s(tmp->buffer, bufferLen, buffer, bufferLen);
					dispatchedNonNative = 1;
					needPause = 1;
					ILibChain_RunOnMicrostackThreadEx(stream->chain, ILibDuktape_readableStream_WriteDataEx_Chain, tmp);
				}
				else
				{
					// We're running on the Chain Thread, so we can directly dispatch into JS
					switch (ILibDuktape_readableStream_WriteDataEx_Chain_Dispatch(stream, w->writableStream, buffer, bufferLen))
					{
						case 0: // Need to Pause
							needPause = 1;
							break;
						case 1: // Complete
							noContinue = 1;
							break;
						default: // NOP
							break;
					}
				}
			}
			if (noContinue != 0) { break; }
			w = w->next;
		}
	}
	
	if (dispatched == 0)
	{
		sem_wait(&(stream->pipeLock));
		stream->pipeInProgress = 0;
		sem_post(&(stream->pipeLock));

		if(ILibDuktape_EventEmitter_HasListeners(stream->emitter, "data"))
		{
			if (ILibIsRunningOnChainThread(stream->chain))
			{
				if (streamReserved == 0)
				{
					duk_push_external_buffer(stream->ctx);												// [extBuffer]
					duk_config_buffer(stream->ctx, -1, buffer, bufferLen);
				}
				ILibDuktape_EventEmitter_SetupEmit(stream->ctx, stream->object, "data");				// [extBuffer][emit][this][data]
				if (streamReserved == 0)
				{
					duk_push_buffer_object(stream->ctx, -4, 0, bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);	// [extBuffer][emit][this][data][nodeBuffer]
				}
				else
				{
					duk_push_lstring(stream->ctx, buffer, bufferLen);									// [extBuffer][emit][this][data][string]
				}
				if (duk_pcall_method(stream->ctx, 2) != 0)												// [retVal]
				{
					ILibDuktape_Process_UncaughtException(stream->ctx);
				}
				if (streamReserved == 0)
				{
					duk_pop_2(stream->ctx);
				}
				else
				{
					duk_pop(stream->ctx);																// ...
				}
			}
			else
			{
				// Need to PAUSE, and context switch to Chain Thread, so we can dispatch into JavaScript
				ILibDuktape_readableStream_bufferedData *tmp = (ILibDuktape_readableStream_bufferedData*)ILibMemory_Allocate(sizeof(ILibDuktape_readableStream_bufferedData) + bufferLen, 0, NULL, NULL);
				tmp->bufferLen = bufferLen;
				tmp->Reserved = streamReserved;
				tmp->Next = (ILibDuktape_readableStream_bufferedData*)stream;
				memcpy_s(tmp->buffer, bufferLen, buffer, bufferLen);
				needPause = 1;
				ILibChain_RunOnMicrostackThread(stream->chain, ILibDuktape_readableStream_WriteData_OnData_ChainThread, tmp);
			}
		}
		else if (stream->PauseHandler != NULL && ILibDuktape_EventEmitter_HasListeners(stream->emitter, "end") == 0)
		{
			// If we get here, it means we are writing data, but nobody is going to be receiving it...
			// So we need to buffer the data, so when we are resumed later, we can retry
			needPause = 1;
			ILibDuktape_readableStream_WriteData_buffer(stream, streamReserved, buffer, bufferLen);
		}
		else if (ILibDuktape_EventEmitter_HasListeners(stream->emitter, "end") != 0)
		{
			return 0;
		}
	}
	if (needPause)
	{
		if (stream->paused == 0 && stream->PauseHandler != NULL) { stream->paused = 1; stream->PauseHandler(stream, stream->user); }
	}
	return(stream->paused);
}
void ILibDuktape_readableStream_WriteEnd_ChainSink(void *chain, void *user)
{
	ILibDuktape_readableStream_WriteEnd((ILibDuktape_readableStream*)user);
}
int ILibDuktape_readableStream_WriteEnd(ILibDuktape_readableStream *stream)
{
	int retVal = 1;
	if (!ILibMemory_CanaryOK(stream)) { return(retVal); }

	if (ILibIsRunningOnChainThread(stream->chain) == 0)
	{
		// Must context switch to Microstack Thread, in order to dispatch into Java Script
		ILibChain_RunOnMicrostackThread(stream->chain, ILibDuktape_readableStream_WriteEnd_ChainSink, stream);
	}
	else
	{
		if (stream->endRelayed != 0) { return(retVal); }
		
		stream->endRelayed = 1;
		ILibDuktape_readableStream_nextWriteablePipe *next;
		
		if (stream->noPropagateEnd == 0 && stream->nextWriteable != NULL)
		{
			next = stream->nextWriteable;
			while (next != NULL)
			{
				duk_push_heapptr(stream->ctx, next->writableStream);												// [stream]
				duk_get_prop_string(stream->ctx, -1, "end");														// [stream][func]
				duk_swap_top(stream->ctx, -2);																		// [func][this]
				if (duk_pcall_method(stream->ctx, 0) != 0)															// [retVal]
				{
					ILibDuktape_Process_UncaughtException(stream->ctx);
				}
				duk_pop(stream->ctx);																				// ...
				next = next->next;
				retVal = 0;
			}
		}
		else if (ILibDuktape_EventEmitter_HasListeners(stream->emitter, "end") != 0)
		{
			ILibDuktape_EventEmitter_SetupEmit(stream->ctx, stream->object, "end");	// [emit][this][end]
			if (duk_pcall_method(stream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtException(stream->ctx); }
			duk_pop(stream->ctx);													// ...
			retVal = 0;
		}
	}
	return retVal;
}
void ILibDuktape_readableStream_Closed(ILibDuktape_readableStream *stream)
{
	ILibDuktape_readableStream_WriteEnd(stream);
	if(ILibDuktape_EventEmitter_HasListeners(stream->emitter, "close")!=0)
	{
		ILibDuktape_EventEmitter_SetupEmit(stream->ctx, stream->object, "close");	// [emit][this][close]
		if (duk_pcall_method(stream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtException(stream->ctx); }
		duk_pop(stream->ctx);														// ...
	}
	
	duk_push_heapptr(stream->ctx, stream->object);		// [stream]
	duk_get_prop_string(stream->ctx, -1, "unpipe");		// [stream][unpipe]
	duk_swap_top(stream->ctx, -2);						// [unpipe][this]
	if (duk_pcall_method(stream->ctx, 0) != 0) { ILibDuktape_Process_UncaughtException(stream->ctx); }
	duk_pop(stream->ctx);								// ...
}

duk_ret_t ILibDuktape_readableStream_pause(duk_context *ctx)
{
	ILibDuktape_readableStream *ptr;

	duk_push_this(ctx);														// [stream]
	duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);		// [stream][ptrs]
	ptr = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop(ctx);															// [stream]

	if (ptr->PauseHandler != NULL) 
	{ 
		ptr->paused = 1; ptr->PauseHandler(ptr, ptr->user); 
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Pause Not Supported"));
	}
	return 1;
}

int ILibDuktape_readableStream_resume_flush(ILibDuktape_readableStream *rs)
{
	// Sanity check, and make sure there is a listener first, otherwise we're wasting our time
	if(ILibDuktape_EventEmitter_HasListeners(rs->emitter, "data")==0 && rs->nextWriteable == NULL && ILibDuktape_EventEmitter_HasListeners(rs->emitter, "end")==0)
	{
		return 1; // No listeners....
	}
	else if (rs->paused_data == NULL)
	{
		return 0; // No data was buffered, so we're good
	}
	else
	{
		// Let's try to resend as much as we can...
		ILibDuktape_readableStream_bufferedData *buffered;
		rs->paused = 0;

		while ((buffered = rs->paused_data))
		{
			rs->paused_data = buffered->Next;
			if (ILibDuktape_readableStream_WriteDataEx(rs, buffered->Reserved, buffered->buffer, buffered->bufferLen) != 0)
			{
				// Send did not complete, so lets exit out, and we'll continue next time.
				free(buffered);
				break;
			}
			free(buffered);
		}
		return(rs->paused_data == NULL ? 0 : 1);
	}
}

duk_ret_t ILibDuktape_readableStream_resume(duk_context *ctx)
{
	ILibDuktape_readableStream *ptr;

	duk_push_this(ctx);														// [stream]
	duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);		// [stream][ptrs]
	ptr = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop(ctx);															// [stream]
	if (ptr->ResumeHandler == NULL) { return(ILibDuktape_Error(ctx, "Resume not supported")); }
	if (!ptr->paused) { return(0); }
	if (ILibDuktape_readableStream_resume_flush(ptr) == 0 && ptr->ResumeHandler != NULL) { ptr->paused = 0; ptr->ResumeHandler(ptr, ptr->user); }
	return 1;
}

void ILibDuktape_ReadableStream_pipe_ResumeLater(duk_context *ctx, void **args, int argsLen)
{
	ILibDuktape_readableStream *rs = (ILibDuktape_readableStream*)args[0];
	rs->resumeImmediate = NULL;
	if (ILibDuktape_readableStream_resume_flush(rs) == 0 && rs->ResumeHandler != NULL) { rs->paused = 0; rs->ResumeHandler(rs, rs->user); }
	if (rs->PipeHookHandler != NULL) { rs->PipeHookHandler(rs, args[1], rs->user); }
}
void ILibDuktape_readableStream_pipe_later(duk_context *ctx, void **args, int argsLen)
{
	ILibDuktape_readableStream *rs = (ILibDuktape_readableStream*)args[0];
	if (!ILibMemory_CanaryOK(rs)) { return; }

	duk_push_heapptr(ctx, rs->object);						// [readable]
	duk_get_prop_string(ctx, -1, "pipe");					// [readable][pipe]
	duk_swap_top(ctx, -2);									// [pipe][this]
	duk_push_heapptr(ctx, args[1]);							// [pipe][this][writable]
	if (argsLen > 2) { duk_push_heapptr(ctx, args[2]); }	// [pipe][this][writable][options]

	duk_push_heapptr(ctx, rs->pipeImmediate);				// [pipe][this][writable][options][immediate]
	duk_del_prop_string(ctx, -1, "dest");
	duk_pop(ctx);											// [pipe][this][writable][options]
	rs->pipeImmediate = NULL;

	if (duk_pcall_method(ctx, argsLen - 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "readableStream.pipeLater(): "); }
	duk_pop(ctx);											// ...
}
duk_ret_t ILibDuktape_readableStream_pipe(duk_context *ctx)
{
	ILibDuktape_readableStream *rstream;
	ILibDuktape_readableStream_nextWriteablePipe *w, *tmp;
	int nargs = duk_get_top(ctx);

	duk_push_this(ctx);																		// [readable]
	duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);						// [readable][ptrs]
	rstream = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop_2(ctx);																			// ...
	
	sem_wait(&(rstream->pipeLock));
	if (rstream->pipeInProgress != 0)
	{
		// We must YIELD and try again later, becuase there is an active dispatch going on
		rstream->pipeImmediate = ILibDuktape_Immediate(ctx, (void*[]) { rstream, duk_get_heapptr(ctx, 0), nargs > 1 ? duk_get_heapptr(ctx, 1) : NULL }, 1 + nargs, ILibDuktape_readableStream_pipe_later);
		duk_push_heapptr(ctx, rstream->pipeImmediate);	// [immediate]
		duk_dup(ctx, 0);								// [immediate][ws]
		duk_put_prop_string(ctx, -2, "dest");			// [immediate]
		if (nargs > 1)
		{
			duk_dup(ctx, 1);
			duk_put_prop_string(ctx, -2, "opt");
		}
		duk_dup(ctx, 0);
		sem_post(&(rstream->pipeLock));
		return(1);
	}
	else
	{
		// No Active Dispatch, so while we hold this lock, we can setup/add the pipe
		duk_push_heapptr(ctx, rstream->pipeArray);											// [pipeArray]
		duk_get_prop_string(ctx, -1, "push");												// [pipeArray][push]
		duk_swap_top(ctx, -2);																// [push][this]
		duk_dup(ctx, 0);																	// [push][this][dest]
		ILibDuktape_Push_ObjectStash(ctx);													// [push][this][dest][stash]
		duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_readableStream_nextWriteablePipe));	// [push][this][dest][stash][buffer]
		w = (ILibDuktape_readableStream_nextWriteablePipe*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));		// [push][this][dest][stash]
		duk_pop(ctx);																		// [push][this][dest]
		duk_call_method(ctx, 1); duk_pop(ctx);												// ...
		memset(w, 0, sizeof(ILibDuktape_readableStream_nextWriteablePipe));
		w->writableStream = duk_get_heapptr(ctx, 0);
		if (duk_has_prop_string(ctx, 0, ILibDuktape_WritableStream_WSPTRS))
		{
			// This is one of our writable stream implementation... So we can keep everything native
			duk_get_prop_string(ctx, 0, ILibDuktape_WritableStream_WSPTRS);					// [wrsPTR]
			w->nativeWritable = Duktape_GetBuffer(ctx, -1, NULL);
			duk_pop(ctx);																	// ...
			// If JSCreate is non-zero, it means this is actually a JS Stream, not a native one
			if (((int*)w->nativeWritable)[0] != 0) { w->nativeWritable = NULL; }
		}
		
		// Now lets lets add this entry to the end of the list, so it can be dispatched without invoking into JS to access the array
		if (rstream->nextWriteable == NULL)
		{
			rstream->nextWriteable = w;
		}
		else
		{
			tmp = rstream->nextWriteable;
			while (tmp->next != NULL) { tmp = tmp->next; }
			tmp->next = w;
			w->previous = tmp;
		}
	}
	if (nargs > 1 && duk_is_object(ctx, 1))
	{
		rstream->bypassValue = Duktape_GetIntPropertyValue(ctx, 1, "dataTypeSkip", 0);
		rstream->noPropagateEnd = Duktape_GetBooleanProperty(ctx, 1, "end", 1) == 0 ? 1 : 0;
	}
	sem_post(&(rstream->pipeLock));

	// Now we need to emit a 'pipe' event on the writable that we just attached
	duk_push_heapptr(ctx, w->writableStream);			// [dest]
	duk_get_prop_string(ctx, -1, "emit");				// [dest][emit]
	duk_swap_top(ctx, -2);								// [emit][this]
	duk_push_string(ctx, "pipe");						// [emit][this][pipe]
	duk_push_this(ctx);									// [emit][this][pipe][readable]
	duk_call_method(ctx, 2); duk_pop(ctx);				// ...
	if (rstream->paused != 0)
	{
		// We are paused, so we should yield and resume... We yield, so in case the user tries to chain multiple pipes, it will chain first
		rstream->resumeImmediate = ILibDuktape_Immediate(ctx, (void*[]) { rstream, duk_get_heapptr(ctx, 0) }, 1, ILibDuktape_ReadableStream_pipe_ResumeLater);
		duk_push_heapptr(ctx, rstream->resumeImmediate);		// [immediate]
		duk_push_this(ctx);										// [immediate][this]
		duk_put_prop_string(ctx, -2, "self");					// [immediate]
		duk_pop(ctx);											// ...
	}
	else
	{
		if (rstream->PipeHookHandler != NULL) { rstream->PipeHookHandler(rstream, duk_get_heapptr(ctx, 0), rstream->user); }
	}

	duk_dup(ctx, 0);
	return 1;
}
void ILibDuktape_readableStream_unpipe_later(duk_context *ctx, void ** args, int argsLen)
{
	ILibDuktape_readableStream *data;
	ILibDuktape_readableStream_nextWriteablePipe *w;
	int i;
	duk_size_t arrayLen;

	duk_push_heapptr(ctx, args[0]);											// [readable]
	duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);		// [readable][ptrs]
	data = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop_2(ctx);															// ...

	if (data->emitter->ctx == NULL) { return; }
	sem_wait(&(data->pipeLock));
	if (data->pipeInProgress != 0)
	{
		// We must yield, and try again, because there's an active dispatch going on
		void *imm = ILibDuktape_Immediate(ctx, (void*[]) { args[0], args[1] }, argsLen, ILibDuktape_readableStream_unpipe_later);
		duk_push_heapptr(ctx, imm);					// [immediate]
		duk_push_heapptr(ctx, args[0]);				// [immediate][this]
		duk_put_prop_string(ctx, -2, "\xFF_Self");	// [immediate]
		if (args[1] != NULL) { duk_push_heapptr(ctx, args[1]); duk_put_prop_string(ctx, -2, "\xFF_w"); }
		duk_pop(ctx);								// ...
		sem_post(&(data->pipeLock));
		return;
	}
	else
	{
		i = 0;
		w = data->nextWriteable;
		if (argsLen > 1)
		{
			// Specific stream was specified in 'unpipe'
			while (w != NULL)
			{
				if (w->writableStream == args[1])
				{
					// Emit the 'unpipe' event
					duk_push_heapptr(ctx, args[1]);										// [ws]
					duk_get_prop_string(ctx, -1, "emit");								// [ws][emit]
					duk_swap_top(ctx, -2);												// [emit][this]
					duk_push_string(ctx, "unpipe");										// [emit][this][unpipe]
					duk_push_heapptr(ctx, args[0]);										// [emit][this][unpipe][readable]
					if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "readable.unpipe(): "); }
					duk_pop(ctx);														// ...

					if (w->previous != NULL)
					{
						w->previous->next = w->next;
					}
					else
					{
						data->nextWriteable = w->next;
					}
					duk_push_heapptr(ctx, data->pipeArray);								// [array]
					arrayLen = duk_get_length(ctx, -1);									   
					for (i = 0; i < (int)arrayLen; ++i)									   
					{																	   
						duk_get_prop_index(ctx, -1, i);									// [array][ws]
						if(duk_get_heapptr(ctx, -1) == args[1])
						{		
							if (g_displayFinalizerMessages) { printf("*** UNPIPE/Removing Reference to Writeable: %s (RefCount: %d)\n", Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_OBJID, "UNKNOWN"), ILibDuktape_GetReferenceCount(ctx, -1)); }
							// Removing the entry from the Array
							duk_pop(ctx);												// [array]
							duk_get_prop_string(ctx, -1, "splice");						// [array][splice]
							duk_swap_top(ctx, -2);										// [splice][this]
							duk_push_int(ctx, i);										// [splice][this][i]
							duk_push_int(ctx, 1);										// [splice][this][i][1]
							duk_call_method(ctx, 2);									// [undefined]
							duk_pop(ctx);												// ...
							break;														   
						}	
						else
						{
							duk_pop(ctx);												// [array]
						}
					}
					duk_pop(ctx);														// ...
					break;
				}
				w = w->next;
			}
		}
		else
		{
			// 'unpipe' all pipes
			while (w != NULL)
			{
				duk_push_heapptr(ctx, w->writableStream);			// [ws]
				if (g_displayFinalizerMessages) { printf("*** UNPIPE/Removing Reference to Writeable: %s (RefCount: %d)\n", Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_OBJID, "UNKNOWN"), ILibDuktape_GetReferenceCount(ctx, -1)); }
				duk_get_prop_string(ctx, -1, "emit");				// [ws][emit]
				duk_swap_top(ctx, -2);								// [emit][this]
				duk_push_string(ctx, "unpipe");						// [emit][this][unpipe]
				duk_push_heapptr(ctx, args[0]);						// [emit][this][unpipe][readable]
				if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "readable.unpipe(): "); }
				duk_pop(ctx);										// ...
				w = w->next;
			}
			data->nextWriteable = NULL;
			duk_push_heapptr(ctx, args[0]);										// [readable]
			duk_del_prop_string(ctx, -1, ILibDuktape_readableStream_PipeArray);
			duk_push_array(ctx);												// [readable][array]
			data->pipeArray = duk_get_heapptr(ctx, -1);
			duk_put_prop_string(ctx, -2, ILibDuktape_readableStream_PipeArray);	// [readable]
			duk_pop(ctx);														// ...
		}
	}
	data->unpipeInProgress = 0;
	sem_post(&(data->pipeLock));
}
duk_ret_t ILibDuktape_readableStream_unpipe(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int onlyItem = 0;
	ILibDuktape_readableStream *data;

	duk_push_this(ctx);														// [readable]
	duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);		// [readable][ptrs]
	data = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop(ctx);															// [readable]

	if (data->emitter->ctx == NULL) { return(0); }

	sem_wait(&(data->pipeLock));
	data->unpipeInProgress = 1;
	if (nargs == 1 && duk_is_object(ctx, 0))
	{
		void *w = duk_require_heapptr(ctx, 0);
		duk_push_heapptr(ctx, data->pipeArray);									// [readable][array]
		int wcount = (int)duk_get_length(ctx, -1);
		duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);						// [readable][array][enum]
		while (duk_next(ctx, -1, 1))
		{																		// [readable][array][enum][key][val]
			if (duk_get_heapptr(ctx, -1) == w) { onlyItem = 1; }
			duk_pop_2(ctx);														// [readable][array][enum]
			if (onlyItem) { break; }
		}
		if (onlyItem && wcount > 1) { onlyItem = 0; }
		duk_pop_2(ctx);															// [readable]
	}
	sem_post(&(data->pipeLock));
	
	if (nargs == 0 || onlyItem != 0)
	{
		// We need to pause first
		duk_push_this(ctx);						// [readable]
		duk_get_prop_string(ctx, -1, "pause");	// [readable][pause]
		duk_dup(ctx, -2);						// [readable][pause][this]
		duk_call_method(ctx, 0); duk_pop(ctx);	// [readable]
	}
	
	// We must yield, and do this on the next event loop, because we can't unpipe if we're called from a pipe'ed call
	void *imm = ILibDuktape_Immediate(ctx, (void*[]) { duk_get_heapptr(ctx, -1), nargs == 1 ? duk_get_heapptr(ctx, 0) : NULL }, nargs + 1, ILibDuktape_readableStream_unpipe_later);
	duk_push_heapptr(ctx, imm);					// [immediate]
	duk_push_this(ctx);							// [immediate][this]
	duk_put_prop_string(ctx, -2, "\xFF_Self");	// [immediate]
	if (nargs == 1) { duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, "\xFF_w"); }
	duk_pop(ctx);								// ...

	return 0;
}
duk_ret_t ILibDuktape_readableStream_isPaused(duk_context *ctx)
{
	ILibDuktape_readableStream *data;
	duk_push_this(ctx);													// [stream]
	duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);	// [stream][ptrs]
	data = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);

	if (data->paused == 0)
	{
		duk_push_false(ctx);
	}
	else
	{
		duk_push_true(ctx);
	}
	return 1;
}
duk_ret_t ILibDuktape_readableStream_pipe_getter(duk_context *ctx)
{
	duk_push_c_function(ctx, ILibDuktape_readableStream_pipe, DUK_VARARGS);
	return 1;
}
duk_ret_t ILibDuktape_ReadableStream_PipeLockFinalizer(duk_context *ctx)
{
	ILibDuktape_readableStream_bufferedData *tmp;
	ILibDuktape_readableStream *ptrs;

	duk_push_this(ctx);														// [stream]
	duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);		// [stream][buffer]
	ptrs = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);
	if (ptrs->pipeImmediate != NULL)
	{
		duk_push_global_object(ctx);						// [g]
		duk_get_prop_string(ctx, -1, "clearImmediate");		// [g][clearImmediate]
		duk_swap_top(ctx, -2);								// [clearImmediate][this]
		duk_push_heapptr(ctx, ptrs->pipeImmediate);			// [clearImmediate][this][immedate]
		duk_call_method(ctx, 1); duk_pop(ctx);				// ...
		ptrs->pipeImmediate = NULL;
	}

	while ((tmp = (ILibDuktape_readableStream_bufferedData*)ptrs->paused_data) != NULL)
	{
		tmp = tmp->Next;
		free(ptrs->paused_data);
		ptrs->paused_data = tmp;
	}

	sem_destroy(&(ptrs->pipeLock));
	duk_pop_2(ctx);
	return(0);
}
duk_ret_t ILibDuktape_ReadableStream_unshift(duk_context *ctx)
{
	ILibDuktape_readableStream *rs;
	duk_push_this(ctx);													// [stream]
	duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);	// [stream][ptrs]
	rs = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);

	if (rs->UnshiftHandler == NULL)
	{
		return(ILibDuktape_Error(ctx, "readable.unshift(): Not Implemented"));
	}
	else
	{
		duk_size_t bufferLen;
		rs->unshiftReserved = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);
		duk_push_int(ctx, rs->UnshiftHandler(rs, (int)bufferLen, rs->user));
		return(1);
	}
}
ILibDuktape_readableStream* ILibDuktape_ReadableStream_InitEx(duk_context *ctx, ILibDuktape_readableStream_PauseResumeHandler OnPause, ILibDuktape_readableStream_PauseResumeHandler OnResume, ILibDuktape_readableStream_UnShiftHandler OnUnshift, void *user)
{
	ILibDuktape_readableStream *retVal;
	ILibDuktape_EventEmitter *emitter;

	retVal = (ILibDuktape_readableStream*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_readableStream));	// [obj][buffer]
	duk_put_prop_string(ctx, -2, ILibDuktape_readableStream_RSPTRS);									// [obj]

	duk_push_array(ctx);																				// [obj][array]
	retVal->pipeArray = duk_get_heapptr(ctx, -1);
	duk_put_prop_string(ctx, -2, ILibDuktape_readableStream_PipeArray);									// [obj]

	retVal->ctx = ctx;
	retVal->chain = Duktape_GetChain(ctx);
	retVal->object = duk_get_heapptr(ctx, -1);
	retVal->user = user;
	retVal->PauseHandler = OnPause;
	retVal->ResumeHandler = OnResume;
	retVal->UnshiftHandler = OnUnshift;
	sem_init(&(retVal->pipeLock), 0, 1);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_ReadableStream_PipeLockFinalizer);

	retVal->emitter = emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "end");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "data");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "close");

	ILibDuktape_CreateInstanceMethod(ctx, "pause", ILibDuktape_readableStream_pause, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "resume", ILibDuktape_readableStream_resume, 0);
	ILibDuktape_CreateEventWithGetter(ctx, "pipe", ILibDuktape_readableStream_pipe_getter);
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "unpipe", ILibDuktape_readableStream_unpipe, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "isPaused", ILibDuktape_readableStream_isPaused, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "unshift", ILibDuktape_ReadableStream_unshift, 1);
	return retVal;
}
