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

#include "ILibDuktape_ReadableStream.h"
#include "ILibDuktape_WritableStream.h"
#include "ILibDuktape_Helpers.h"
#include "ILibParsers_Duktape.h"
#include "microstack/ILibParsers.h"
#include "ILibDuktape_EventEmitter.h"


#define ILibDuktape_readableStream_WritePipes			"\xFF_WritePipes"
#define ILibDuktape_readableStream_WritePipes_PTRBUFFER	"\xFF_WritePipesPtrBuffer"
#define ILibDuktape_readableStream_WritePipes_Stream	"\xFF_WritePipes_Stream"

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
	\param destination[in] The WritableStream to attach to the ReadableStream.
	*/
	void pipe(WritableStream destination);
	/*! 
	\brief The ReadableStream.unpipe() method detaches a WritableStream previously attached using the ReadableStream.pipe() method.
	*
	\param destination[in] If specified, the WritableStream to detach. If not specified, all streams will be dettached.
	*/
	void unpipe(WritableStream destination);


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
	char buffer[];
}ILibDuktape_readableStream_bufferedData;

void ILibDuktape_readableStream_WriteData_buffer(ILibDuktape_readableStream *stream, char *buffer, int bufferLen)
{
	ILibDuktape_readableStream_bufferedData *buffered = (ILibDuktape_readableStream_bufferedData*)ILibMemory_Allocate(bufferLen + sizeof(ILibDuktape_readableStream_bufferedData), 0, NULL, NULL);
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

	if (stream->paused == 0)
	{
		stream->paused = 1;
		stream->PauseHandler(stream, stream->user);
	}
}
void ILibDuktape_readableStream_WriteData_OnData_ChainThread(void *chain, void *user)
{
	ILibDuktape_readableStream *stream = (ILibDuktape_readableStream*)user;

	stream->paused = 0;
	duk_push_heapptr(stream->ctx, stream->OnData);		// [func]
	duk_push_heapptr(stream->ctx, stream->object);		// [func][this]
	duk_push_heapptr(stream->ctx, stream->extBuffer);	// [func][this][buffer]
	duk_config_buffer(stream->ctx, -1, stream->extBuffer_buffer, stream->extBuffer_bufferLen);
	if (duk_pcall_method(stream->ctx, 1) != 0)			// [retVal]
	{
		ILibDuktape_Process_UncaughtException(stream->ctx);
	}
	duk_pop(stream->ctx);								// ...
	if (stream->paused == 0 && stream->ResumeHandler != NULL) { stream->ResumeHandler(stream, stream->user); }
}
void ILibDuktape_readableStream_WriteData_Flush(struct ILibDuktape_WritableStream *ws, void *user)
{
	ILibDuktape_readableStream *stream = (ILibDuktape_readableStream*)user;
	
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
		if (stream->ResumeHandler != NULL) { stream->paused = 0; stream->ResumeHandler(stream, stream->user); }
	}
}
duk_ret_t ILibDuktape_readableStream_WriteData_Flush_JS(duk_context *ctx)
{
	ILibDuktape_readableStream *stream;
	
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "readable");
	stream = (ILibDuktape_readableStream*)duk_get_pointer(ctx, -1);

	ILibDuktape_readableStream_WriteData_Flush(NULL, stream);

	return 0;
}
void ILibDuktape_readableStream_WriteData_ChainThread(void *chain, void *user)
{
	ILibDuktape_readableStream *stream = (ILibDuktape_readableStream*)user;
	ILibDuktape_readableStream_nextWriteablePipe *w;
	int jsCount = 0;

	sem_wait(&(stream->pipeLock));
	w = stream->nextWriteable;
	stream->pipe_pendingCount = 0;

	while (w != NULL)
	{
		if (w->nativeWritable != NULL || w->writableStream != NULL) { stream->pipe_pendingCount++; }
		w = w->next;
	}

	w = stream->nextWriteable;
	while (w != NULL)
	{
		if (w->nativeWritable != NULL)
		{
			ILibDuktape_WritableStream *ws = (ILibDuktape_WritableStream*)w->nativeWritable;
			switch (ws->WriteSink(ws, stream->extBuffer_buffer, stream->extBuffer_bufferLen, ws->WriteSink_User))
			{
				case ILibTransport_DoneState_INCOMPLETE:
					ws->OnWriteFlushEx = ILibDuktape_readableStream_WriteData_Flush;
					ws->OnWriteFlushEx_User = stream;
					break;
				case ILibTransport_DoneState_COMPLETE:
					ws->OnWriteFlushEx = NULL;
					ws->OnWriteFlushEx_User = NULL;
#ifdef WIN32
					InterlockedDecrement(&(stream->pipe_pendingCount));
#elif defined(__ATOMIC_SEQ_CST)
					__atomic_sub_fetch(&(stream->pipe_pendingCount), 1, __ATOMIC_SEQ_CST);
#else
					--stream->pipe_pendingCount;
#endif
					break;
				case ILibTransport_DoneState_ERROR:
#ifdef WIN32
					InterlockedDecrement(&(stream->pipe_pendingCount));
#elif defined(__ATOMIC_SEQ_CST)
					__atomic_sub_fetch(&(stream->pipe_pendingCount), 1, __ATOMIC_SEQ_CST);
#else
					--stream->pipe_pendingCount;
#endif
					break;
			}
		}
		else if(w->writableStream != NULL)
		{
			duk_push_heapptr(stream->ctx, w->writableStream);													// [stream]
			duk_get_prop_string(stream->ctx, -1, "write");														// [stream][func]
			duk_swap_top(stream->ctx, -2);																		// [func][this]
			duk_push_heapptr(stream->ctx, stream->extBuffer);													// [func][this][chunk]
			duk_config_buffer(stream->ctx, -1, stream->extBuffer_buffer, stream->extBuffer_bufferLen);
			duk_push_c_function(stream->ctx, ILibDuktape_readableStream_WriteData_Flush_JS, DUK_VARARGS);		// [func][this][chunk][callback]
			duk_push_pointer(stream->ctx, stream);																// [func][this][chunk][callback][user]
			duk_put_prop_string(stream->ctx, -2, "readable");													// [func][this][chunk][callback]
			if (duk_pcall_method(stream->ctx, 2) != 0)															// [retVal]
			{
				ILibDuktape_Process_UncaughtException(stream->ctx);
			}
			else
			{
				jsCount += duk_get_int(stream->ctx, -1);
			}
			duk_pop(stream->ctx);
		}
		w = w->next;
	}
	if (stream->paused != 0 && stream->pipe_pendingCount == 0)
	{
		sem_post(&(stream->pipeLock));
		if (stream->ResumeHandler != NULL) { stream->paused = 0; stream->ResumeHandler(stream, stream->user); }
	}
	else
	{
		sem_post(&(stream->pipeLock));
	}
}

int ILibDuktape_readableStream_WriteData(ILibDuktape_readableStream *stream, char* buffer, int bufferLen)
{
	ILibDuktape_readableStream_nextWriteablePipe *w;
	int nonNativeCount = 0;
	int nativeCount = 0;

	if (stream->paused != 0)
	{
		ILibDuktape_readableStream_WriteData_buffer(stream, buffer, bufferLen);
		return(stream->paused);
	}

	sem_wait(&(stream->pipeLock));
	w = stream->nextWriteable;
	while (w != NULL)
	{
		if (w->nativeWritable == 0) { ++nonNativeCount; }
		else { ++nativeCount; }
		w = w->next;
	}
	w = stream->nextWriteable;
	if (w != NULL)
	{
		if (nonNativeCount > 0)
		{
			// There are piped Pure JavaScript objects... We must context switch to Microstack Thread
			stream->extBuffer_buffer = buffer;
			stream->extBuffer_bufferLen = bufferLen;
			sem_post(&(stream->pipeLock));
			if (stream->PauseHandler != NULL) { stream->paused = 1;  stream->PauseHandler(stream, stream->user); }
			ILibChain_RunOnMicrostackThread(stream->chain, ILibDuktape_readableStream_WriteData_ChainThread, stream);
			return(stream->paused);
		}
		else
		{
			// All piped objects are native, so we can blast out a send
			stream->pipe_pendingCount = nativeCount;
			while (w != NULL)
			{
				if (w->nativeWritable != NULL)
				{
					ILibDuktape_WritableStream *ws = (ILibDuktape_WritableStream*)w->nativeWritable;
					switch (ws->WriteSink(ws, buffer, bufferLen, ws->WriteSink_User))
					{
						case ILibTransport_DoneState_INCOMPLETE:
							ws->OnWriteFlushEx = ILibDuktape_readableStream_WriteData_Flush;
							ws->OnWriteFlushEx_User = stream;
							break;
						case ILibTransport_DoneState_COMPLETE:
							ws->OnWriteFlushEx = NULL;
							ws->OnWriteFlushEx_User = NULL;
#ifdef WIN32
							InterlockedDecrement(&(stream->pipe_pendingCount));
#elif defined(__ATOMIC_SEQ_CST)
							__atomic_sub_fetch(&(stream->pipe_pendingCount), 1, __ATOMIC_SEQ_CST);
#else
							--stream->pipe_pendingCount;
#endif
							break;
						case ILibTransport_DoneState_ERROR:
#ifdef WIN32
							InterlockedDecrement(&(stream->pipe_pendingCount));
#elif defined(__ATOMIC_SEQ_CST)
							__atomic_sub_fetch(&(stream->pipe_pendingCount), 1, __ATOMIC_SEQ_CST);
#else
							--stream->pipe_pendingCount;
#endif
							break;
					}
				}
				w = w->next;
			}
			if (stream->pipe_pendingCount == 0)
			{
				sem_post(&(stream->pipeLock));
				return(stream->paused);
			}
			else
			{
				sem_post(&(stream->pipeLock));
				if (stream->PauseHandler != NULL) { stream->paused = 1;  stream->PauseHandler(stream, stream->user); }
				return(stream->paused);
			}
		}
	}
	else
	{
		sem_post(&(stream->pipeLock));
	}


	if (stream->OnData != NULL)
	{
		if (ILibIsRunningOnChainThread(stream->chain))
		{
			duk_push_heapptr(stream->ctx, stream->OnData);		// [func]
			duk_push_heapptr(stream->ctx, stream->object);		// [func][this]
			duk_push_heapptr(stream->ctx, stream->extBuffer);	// [func][this][buffer]
			duk_config_buffer(stream->ctx, -1, buffer, bufferLen);
			if (duk_pcall_method(stream->ctx, 1) != 0)			// [retVal]
			{
				ILibDuktape_Process_UncaughtException(stream->ctx);
			}
			duk_pop(stream->ctx);								// ...
		}
		else
		{
			// Need to PAUSE, and context switch to Chain Thread, so we can dispatch into JavaScript
			if (stream->paused == 0 && stream->PauseHandler != NULL) { stream->paused = 1; stream->PauseHandler(stream, stream->user); }
			stream->extBuffer_buffer = buffer;
			stream->extBuffer_bufferLen = bufferLen;
			ILibChain_RunOnMicrostackThread(stream->chain, ILibDuktape_readableStream_WriteData_OnData_ChainThread, stream);
		}
	}
	else if(stream->PauseHandler != NULL && stream->OnEnd == NULL)
	{
		// If we get here, it means we are writing data, but nobody is going to be receiving it...
		// So we need to buffer the data, so when we are resumed later, we can retry

		ILibDuktape_readableStream_WriteData_buffer(stream, buffer, bufferLen);
	}
	else if (stream->OnEnd != NULL)
	{
		return 0;
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

	if (ILibIsRunningOnChainThread(stream->chain) == 0)
	{
		// Must context switch to Microstack Thread, in order to dispatch into Java Script
		ILibChain_RunOnMicrostackThread(stream->chain, ILibDuktape_readableStream_WriteEnd_ChainSink, stream);
	}
	else
	{
		ILibDuktape_readableStream_nextWriteablePipe *next;
		
		if (stream->OnEnd != NULL)
		{
			duk_context *x = stream->ctx;
			duk_push_heapptr(stream->ctx, stream->OnEnd);		// [func]
			duk_push_heapptr(stream->ctx, stream->object);		// [func][this]
			if (duk_pcall_method(stream->ctx, 0) != 0)			// [retVal]
			{
				ILibDuktape_Process_UncaughtException(stream->ctx);
			}
			duk_pop(x);								// ...
			retVal = 0;
		}
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
	return retVal;
}
void ILibDuktape_readableStream_Closed(ILibDuktape_readableStream *stream)
{
	if (stream->OnClose != NULL)
	{
		duk_push_heapptr(stream->ctx, stream->OnEnd);		// [func]
		duk_push_heapptr(stream->ctx, stream->object);		// [func][this]
		if (duk_pcall_method(stream->ctx, 0) != 0)			// [retVal]
		{
			ILibDuktape_Process_UncaughtException(stream->ctx);
		}
		duk_pop(stream->ctx);								// ...
	}
}

duk_ret_t ILibDuktape_readableStream_pause(duk_context *ctx)
{
	ILibDuktape_readableStream *ptr;

	duk_push_this(ctx);														// [stream]
	duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);		// [stream][ptrs]
	ptr = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop(ctx);															// [stream]

	if (ptr->PauseHandler != NULL) { ptr->paused = 1; ptr->PauseHandler(ptr, ptr->user); }
	return 1;
}

int ILibDuktape_readableStream_resume_flush(ILibDuktape_readableStream *rs)
{
	// Sanity check, and make sure there is a listener first, otherwise we're wasting our time
	if (rs->OnData == NULL && rs->nextWriteable == NULL && rs->OnEnd == NULL)
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

			if (ILibDuktape_readableStream_WriteData(rs, buffered->buffer, buffered->bufferLen) != 0)
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
	if (ILibDuktape_readableStream_resume_flush(ptr) == 0 && ptr->ResumeHandler != NULL) { ptr->paused = 0; ptr->ResumeHandler(ptr, ptr->user); }
	return 1;
}
void ILibDuktape_readableStream_pipe_resumeFromTimer(void *obj)
{
	ILibDuktape_readableStream* ptr = (ILibDuktape_readableStream*)((void**)obj)[0];
	if (ILibDuktape_readableStream_resume_flush(ptr) == 0 && ptr->ResumeHandler != NULL) { ptr->paused = 0; ptr->ResumeHandler(ptr, ptr->user); }
	free(obj);
}
void ILibDuktape_readableStream_pipe_resumeFromTimer2(void *obj)
{
	free(obj);
}
duk_ret_t ILibDuktape_readableStream_pipe(duk_context *ctx)
{
	ILibDuktape_readableStream *rstream;
	ILibDuktape_readableStream_nextWriteablePipe *w;

	duk_push_this(ctx);																		// [readable]
	duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);						// [readable][ptrs]
	rstream = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop(ctx);																			// [readable]
	
	duk_push_object(ctx);																	// [readable][nextWriteable]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_readableStream_nextWriteablePipe));		// [readable][nextWriteable][ptrBuffer]
	w = (ILibDuktape_readableStream_nextWriteablePipe*)Duktape_GetBuffer(ctx, -1, NULL);
	memset(w, 0, sizeof(ILibDuktape_readableStream_nextWriteablePipe));
	duk_put_prop_string(ctx, -2, ILibDuktape_readableStream_WritePipes_PTRBUFFER);			// [readable][nextWriteable]


	if (duk_has_prop_string(ctx, -2, ILibDuktape_readableStream_WritePipes))
	{
		// There are already associated pipes
		duk_get_prop_string(ctx, -2, ILibDuktape_readableStream_WritePipes);				// [readable][nextWriteable][prevWriteable]
		duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_WritePipes_PTRBUFFER);		// [readable][nextWriteable][prevWriteable][ptr]
		w->next = (ILibDuktape_readableStream_nextWriteablePipe*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop(ctx);																		// [readable][nextWriteable][prevWriteable]
		duk_put_prop_string(ctx, -2, ILibDuktape_readableStream_WritePipes);				// [readable][nextWriteable]
	}
	
	duk_dup(ctx, 0);																		// [readable][nextWriteable][stream]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS))
	{
		// This is one of our writable stream implementation... So we can keep everything native
		duk_get_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS);					// [readable][nextWriteable][stream][buffer]
		w->nativeWritable = Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop(ctx);																		// [readable][nextWriteable][stream]
	}
	w->writableStream = duk_get_heapptr(ctx, -1);
	duk_put_prop_string(ctx, -2, ILibDuktape_readableStream_WritePipes_Stream);				// [readable][nextWriteable]

	rstream->nextWriteable = w;

	// Save to the readableStream
	duk_put_prop_string(ctx, -2, ILibDuktape_readableStream_WritePipes);					// [readable]

	duk_dup(ctx, 0);																		// [readable][writable]
	if (duk_has_prop_string(ctx, -1, "emit"))
	{
		duk_push_string(ctx, "emit");															// [readable][writable][key]
		duk_push_string(ctx, "pipe");															// [readable][writable][key][eventName]
		duk_dup(ctx, -4);																		// [readable][writable][key][eventName][readable]
		if (duk_pcall_prop(ctx, -4, 2) != 0)													// [readable][writable][retVal/err]
		{
			ILibDuktape_Process_UncaughtException(ctx);
		}
		duk_pop_2(ctx);																			// [readable]
	}
	else
	{
		duk_pop(ctx);
	}

	if (rstream->paused != 0)
	{
		void *chain = Duktape_GetChain(ctx);
		if (chain != NULL)
		{
			// We are paused, so we should yield and resume... We yield, so in case the user tries to chain multiple pipes, it will chain first
			void **tmp = (void**)ILibMemory_Allocate(sizeof(void*), 0, NULL, NULL);
			tmp[0] = rstream;
			ILibLifeTime_AddEx(ILibGetBaseTimer(chain), tmp, 0, ILibDuktape_readableStream_pipe_resumeFromTimer, ILibDuktape_readableStream_pipe_resumeFromTimer2);
		}
		else
		{
			// Oops
			duk_push_string(ctx, "ILibParsers_Duktape *MISSING*");
			duk_throw(ctx);
			return(DUK_RET_ERROR);
		}
	}

	if (rstream->PipeHookHandler != NULL) { rstream->PipeHookHandler(rstream, rstream->user); }
	return 1;
}
duk_ret_t ILibDuktape_readableStream_unpipe(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	ILibDuktape_readableStream *data;
	ILibDuktape_readableStream_nextWriteablePipe *w, *prev;

	duk_push_this(ctx);													// [stream]
	duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);	// [stream][ptrs]
	data = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);

	if (nargs == 0)
	{
		duk_del_prop_string(ctx, -2, ILibDuktape_readableStream_WritePipes);
		data->nextWriteable = NULL;
	}
	else if (data->nextWriteable != NULL)
	{
		w = data->nextWriteable;
		prev = NULL;
		while (w != NULL)
		{
			if (w->writableStream == duk_get_heapptr(ctx, 0))
			{
				memset(w, 0, 2 * sizeof(void*));
				if (data->nextWriteable == w)
				{
					//printf("Unpiping object: %p\n", (void*)w);
					data->nextWriteable = w->next;
					break;
				}
				else
				{
					prev->next = w->next;
					break;
				}
			}
			else
			{
				prev = w;
				w = w->next;
			}
		}
	}

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
void ILibDuktape_ReadableStream_PipeLockFinalizer(duk_context *ctx, void *stream)
{
	ILibDuktape_readableStream_bufferedData *tmp;
	ILibDuktape_readableStream *ptrs;
	duk_push_heapptr(ctx, stream);											// [stream]
	duk_get_prop_string(ctx, -1, ILibDuktape_readableStream_RSPTRS);		// [stream][buffer]
	ptrs = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);

	while ((tmp = (ILibDuktape_readableStream_bufferedData*)ptrs->paused_data) != NULL)
	{
		tmp = tmp->Next;
		free(ptrs->paused_data);
		ptrs->paused_data = tmp;
	}

	sem_destroy(&(ptrs->pipeLock));
	duk_pop_2(ctx);
}
ILibDuktape_readableStream* ILibDuktape_InitReadableStream(duk_context *ctx, ILibDuktape_readableStream_PauseResumeHandler OnPause, ILibDuktape_readableStream_PauseResumeHandler OnResume, void *user)
{
	ILibDuktape_readableStream *retVal;
	ILibDuktape_EventEmitter *emitter;

	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_readableStream));			// [obj][buffer]
	duk_dup(ctx, -1);														// [obj][buffer][buffer]
	duk_put_prop_string(ctx, -3, ILibDuktape_readableStream_RSPTRS);		// [obj][buffer]
	retVal = (ILibDuktape_readableStream*)Duktape_GetBuffer(ctx, -1, NULL);	// [obj][buffer]
	memset(retVal, 0, sizeof(ILibDuktape_readableStream));

	duk_pop(ctx);															// [obj]
	duk_push_external_buffer(ctx);											// [obj][extBuffer]
	retVal->extBuffer = duk_get_heapptr(ctx, -1);
	duk_put_prop_string(ctx, -2, "_extBuffer");								// [obj]

	retVal->ctx = ctx;
	retVal->chain = Duktape_GetChain(ctx);
	retVal->object = duk_get_heapptr(ctx, -1);
	retVal->user = user;
	retVal->PauseHandler = OnPause;
	retVal->ResumeHandler = OnResume;
	sem_init(&(retVal->pipeLock), 0, 1);
	ILibDuktape_CreateIndependentFinalizer(ctx, ILibDuktape_ReadableStream_PipeLockFinalizer);

	emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEvent(emitter, "end", &(retVal->OnEnd));
	ILibDuktape_EventEmitter_CreateEvent(emitter, "data", &(retVal->OnData));
	ILibDuktape_EventEmitter_CreateEvent(emitter, "close", &(retVal->OnClose));

	ILibDuktape_CreateInstanceMethod(ctx, "pause", ILibDuktape_readableStream_pause, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "resume", ILibDuktape_readableStream_resume, 0);
	ILibDuktape_CreateEventWithGetter(ctx, "pipe", ILibDuktape_readableStream_pipe_getter);
	ILibDuktape_CreateInstanceMethod(ctx, "unpipe", ILibDuktape_readableStream_unpipe, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "isPaused", ILibDuktape_readableStream_isPaused, 0);
	return retVal;
}
