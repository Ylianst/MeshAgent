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
#define ILibDuktape_MemoryStream_MemoryBuffer	"\xFF_MemoryStream_MemoryBuffer"

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
}ILibDuktape_MemoryStream;

ILibTransport_DoneState ILibDuktape_MemoryStream_OnWrite(struct ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_MemoryStream *ms = (ILibDuktape_MemoryStream*)user;
	
	if (ILibMemory_Size(ms->buffer) - ms->bufferLen < (size_t)bufferLen)
	{
		duk_push_heapptr(ms->ctx, stream->ParentObject);						// [obj]
		duk_get_prop_string(ms->ctx, -1, ILibDuktape_MemoryStream_MemoryBuffer);// [obj][buffer]
		if ((size_t)bufferLen > ILibMemory_Size(ms->buffer))
		{
			ms->buffer = Duktape_DynamicBuffer_Resize(ms->ctx, -1, ILibMemory_Size(ms->buffer) + (duk_size_t)bufferLen);
		}
		else
		{
			ms->buffer = Duktape_DynamicBuffer_Resize(ms->ctx, -1, 2 * ILibMemory_Size(ms->buffer));
		}
		duk_pop_2(ms->ctx);														// ...
	}

	memcpy_s(ms->buffer + ms->bufferLen, ILibMemory_Size(ms->buffer) - ms->bufferLen, buffer, bufferLen);
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
	duk_push_this(ctx);													// [ms]
	ILibDuktape_MemoryStream *ms = (ILibDuktape_MemoryStream*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_MemoryStream_Internal);
	duk_get_prop_string(ctx, -1, ILibDuktape_MemoryStream_MemoryBuffer);// [ms][buffer]
	duk_push_buffer_object(ctx, -1, sizeof(ILibMemory_Header), ms->bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);
	return(1);
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
	ms->buffer = Duktape_PushDynamicBuffer(ctx, (duk_size_t)initial);
	duk_put_prop_string(ctx, -2, ILibDuktape_MemoryStream_MemoryBuffer);
	ms->ctx = ctx;

	ms->s = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_MemoryStream_OnWrite, ILibDuktape_MemoryStream_OnEnd, NULL, NULL, ms);
	ILibDuktape_CreateEventWithGetter(ctx, "buffer", ILibDuktape_MemoryStream_buffer);

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
