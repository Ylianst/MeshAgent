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
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_DuplexStream.h"
#include "../microstack/ILibParsers.h"


#define ILibDuktape_MemoryStream_Internal		"\xFF_MemoryStream_Internal"

#ifdef __DOXY__
/*! 
\implements DuplexStream
\brief Buffer Accumulator object, sort of like StringBuilder, etc. <b>Note:</b> To use, must <b>require('MemoryStream')</b> and then <b>new</b> it.
*
* To utilize MemoryStream, you must require('MemoryStream')
*/
class MemoryStream
{
public:
	
	/*! 
	\brief Returns a new MemoryStream object
	*
	MemoryStream([initialSize]);
	\param initialSize <integer> Optional parameter specifying the initial size of the internal buffer. Default size is 4096 bytes.
	*/
	MemoryStream([initialSize]);

	/*! property buffer
	\brief Property returning the accumulated byte[] buffer object
	*/
	Buffer buffer;
};
#endif


typedef struct ILibDuktape_MemoryStream
{
	duk_context *ctx;
	size_t initial;
	ILibDuktape_DuplexStream *s;

	char *buffer;
	size_t bufferLen;
	size_t bufferSize;
}ILibDuktape_MemoryStream;

ILibTransport_DoneState ILibDuktape_MemoryStream_OnWrite(struct ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_MemoryStream *ms = (ILibDuktape_MemoryStream*)user;

	if (ms->bufferSize - ms->bufferLen < (size_t)bufferLen)
	{
		if ((size_t)bufferLen > ms->bufferSize)
		{
			if ((ms->buffer = (char*)realloc(ms->buffer, ms->bufferSize + bufferLen)) == NULL) { ILIBCRITICALEXITMSG(254, "OUT OF MEMORY"); }
			ms->bufferSize += bufferLen;
		}
		else
		{
			if((ms->buffer = (char*)realloc(ms->buffer, 2*ms->bufferSize)) == NULL) { ILIBCRITICALEXITMSG(254, "OUT OF MEMORY"); }
			ms->bufferSize = (2 * ms->bufferSize);
		}
	}

	memcpy_s(ms->buffer + ms->bufferLen, ms->bufferSize - ms->bufferLen, buffer, bufferLen);
	ms->bufferLen += bufferLen;

	return(ILibTransport_DoneState_COMPLETE);
}
void ILibDuktape_MemoryStream_OnEnd(struct ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_MemoryStream *ms = (ILibDuktape_MemoryStream*)user;
	ILibDuktape_DuplexStream_WriteEnd(ms->s);
}
duk_ret_t ILibDuktape_MemoryStream_buffer(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_MemoryStream_Internal);
	ILibDuktape_MemoryStream *ms = (ILibDuktape_MemoryStream*)Duktape_GetBuffer(ctx, -1, NULL);

	duk_push_external_buffer(ctx);
	duk_config_buffer(ctx, -1, ms->buffer, ms->bufferLen);
	duk_push_buffer_object(ctx, -1, 0, ms->bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);

	return(1);
}
duk_ret_t ILibDuktape_MemoryStream_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, ILibDuktape_MemoryStream_Internal);
	ILibDuktape_MemoryStream *ms = (ILibDuktape_MemoryStream*)Duktape_GetBuffer(ctx, -1, NULL);

	free(ms->buffer);
	return(0);
}

duk_ret_t ILibDuktape_MemoryStream_writeBE(duk_context *ctx)
{
	duk_push_current_function(ctx);
	int size = Duktape_GetIntPropertyValue(ctx, -1, "size", 0);
	char buffer[16];
	int value = duk_require_int(ctx, 0);

	switch (size)
	{
		case 1:
			buffer[0] = (char)value;
			break;
		case 2:
			((unsigned short*)buffer)[0] = htons((unsigned short)value);
			break;
		case 4:
			((unsigned int*)buffer)[0] = htonl((unsigned int)value);
			break;
		default:
			break;
	}

	if (size > 0)
	{
		duk_push_this(ctx);							// [ms]
		duk_get_prop_string(ctx, -1, "write");		// [ms][write]
		duk_swap_top(ctx, -2);						// [write][this]
		duk_push_external_buffer(ctx);				// [write][this][buffer]
		duk_config_buffer(ctx, -1, buffer, size);
		duk_call_method(ctx, 1);					// [retVal]
		return(1);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "MemoryStream.writeBE() Unknown Error"));
	}
}
duk_ret_t ILibDuktape_MemoryStream_new(duk_context *ctx)
{
	int initial = duk_get_top(ctx) > 0 ? duk_require_int(ctx, 0) : 4096;

	ILibDuktape_MemoryStream *ms;
	duk_push_object(ctx);												// [ms]
	ILibDuktape_WriteID(ctx, "memoryStream");
	ms = (ILibDuktape_MemoryStream*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_MemoryStream));
	duk_put_prop_string(ctx, -2, ILibDuktape_MemoryStream_Internal);	// [ms]
	ms->buffer = (char*)ILibMemory_Allocate(initial, 0, NULL, NULL);
	ms->bufferSize = (size_t)initial;
	ms->ctx = ctx;

	ms->s = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_MemoryStream_OnWrite, ILibDuktape_MemoryStream_OnEnd, NULL, NULL, ms);
	ILibDuktape_CreateEventWithGetter(ctx, "buffer", ILibDuktape_MemoryStream_buffer);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_MemoryStream_Finalizer);

	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "size", 4, "writeUInt32BE", ILibDuktape_MemoryStream_writeBE, 1);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "size", 2, "writeUInt16BE", ILibDuktape_MemoryStream_writeBE, 1);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "size", 1, "writeUInt8", ILibDuktape_MemoryStream_writeBE, 1);

	return(1);
}
void ILibDuktape_MemoryStream_PUSH(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_MemoryStream_new, DUK_VARARGS);
}

void ILibDuktape_MemoryStream_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "MemoryStream", ILibDuktape_MemoryStream_PUSH);
}
