/*
Copyright 2020 Intel Corporation

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

#include "microscript/ILibDuktape_CompressedStream.h"
#include "microscript/duktape.h"
#include "microstack/ILibParsers.h"

#include "microscript/ILibDuktape_Helpers.h"
#include "microscript/ILibDuktapeModSearch.h"
#include "microscript/ILibDuktape_DuplexStream.h"
#include "microscript/ILibDuktape_WritableStream.h"
#include "microscript/ILibDuktape_ReadableStream.h"
#include "microscript/ILibDuktape_EventEmitter.h"

#include "meshcore/zlib/zlib.h"

#define ILibDuktape_CompressorStream_ptr			"\xFF_Duktape_CompressorStream_ptr"
#define ILibDuktape_CompressorStream_ResumeBuffer	"\xFF_Duktape_CompressorStream_ResumeBuffer"
extern uint32_t crc32(uint32_t crc, const unsigned char* buf, uint32_t len);

typedef struct ILibDuktape_CompressorStream
{
	duk_context *ctx;
	void *object;
	ILibDuktape_DuplexStream *ds;
	z_stream Z;
	uint32_t crc;
}ILibDuktape_CompressorStream;


void ILibDuktape_Compressor_Resume(ILibDuktape_DuplexStream *sender, void *user)
{

}
void ILibDuktape_Compressor_Pause(ILibDuktape_DuplexStream *sender, void *user)
{

}
void ILibDuktape_deCompressor_Resume(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_CompressorStream *cs = (ILibDuktape_CompressorStream*)user;
	duk_push_heapptr(cs->ctx, cs->object);														// [stream]
	char *inbuffer = (char*)Duktape_GetBufferProperty(cs->ctx, -1, ILibDuktape_CompressorStream_ResumeBuffer);
	if (inbuffer == NULL)
	{
		ILibDuktape_DuplexStream_Ready(cs->ds);
		return;
	}
	char buffer[16384];
	size_t avail = 0;
	int res = 0;
	cs->Z.avail_in = (uint32_t)ILibMemory_Size(inbuffer);
	cs->Z.next_in = (Bytef*)inbuffer;
	do
	{
		cs->Z.avail_out = sizeof(buffer);
		cs->Z.next_out = (Bytef*)buffer;
		ignore_result(inflate(&(cs->Z), Z_NO_FLUSH));
		avail = sizeof(buffer) - cs->Z.avail_out;
		if (avail > 0)
		{
			cs->crc = crc32(cs->crc, (unsigned char*)buffer, (unsigned int)avail);
			res = ILibDuktape_DuplexStream_WriteData(cs->ds, buffer, (int)avail);				// [stream]
			if (res == 1)
			{
				// Downstream Paused
				if (cs->Z.avail_in > 0)
				{
					char *tmp = (char*)Duktape_PushBuffer(cs->ctx, cs->Z.avail_in);				// [stream][buffer]
					duk_put_prop_string(cs->ctx, -2, ILibDuktape_CompressorStream_ResumeBuffer);// [stream]
					memcpy_s(tmp, ILibMemory_Size(tmp), cs->Z.next_in, ILibMemory_Size(tmp));
				}
				else
				{
					duk_del_prop_string(cs->ctx, -1, ILibDuktape_CompressorStream_ResumeBuffer);
				}
				break;
			}
		}
	} while (cs->Z.avail_out == 0);
	if (res == 0) { duk_del_prop_string(cs->ctx, -1, ILibDuktape_CompressorStream_ResumeBuffer); }
	duk_pop(cs->ctx);																			// ...
	if (res == 0)
	{
		ILibDuktape_DuplexStream_Ready(cs->ds);
	}
}
void ILibDuktape_deCompressor_Pause(ILibDuktape_DuplexStream *sender, void *user)
{

}
void ILibDuktape_Compressor_End(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_CompressorStream *cs = (ILibDuktape_CompressorStream*)user;
	duk_context *ctx = cs->ctx;
	char tmp[16384];
	size_t avail;
	cs->Z.avail_in = 0;
	cs->Z.next_in = (Bytef*)ILibScratchPad;

	do
	{
		cs->Z.avail_out = sizeof(tmp);
		cs->Z.next_out = (Bytef*)tmp;
		ignore_result(deflate(&(cs->Z), Z_FINISH));
		avail = sizeof(tmp) - cs->Z.avail_out;
		if (avail > 0) 
		{
			cs->crc = crc32(cs->crc, (unsigned char*)tmp, (unsigned int)avail);
			ILibDuktape_DuplexStream_WriteData(cs->ds, tmp, (int)avail);
		}
	} while (cs->Z.avail_out == 0);
	ILibDuktape_DuplexStream_WriteEnd(cs->ds);

	ignore_result(deflateEnd(&(cs->Z)));
	duk_push_heapptr(ctx, cs->object);
	duk_del_prop_string(ctx, -1, ILibDuktape_CompressorStream_ptr);
	duk_pop(ctx);
}
ILibTransport_DoneState ILibDuktape_Compressor_Write(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	char tmp[16384];
	size_t avail;
	int ret = 0;
	ILibDuktape_CompressorStream *cs = (ILibDuktape_CompressorStream*)user;
	cs->Z.avail_in = bufferLen;
	cs->Z.next_in = (Bytef*)buffer;

	do 
	{
		cs->Z.avail_out = sizeof(tmp);
		cs->Z.next_out = (Bytef*)tmp;
		ignore_result(deflate(&(cs->Z), Z_NO_FLUSH));
		avail = sizeof(tmp) - cs->Z.avail_out;
		if (avail > 0)
		{
			cs->crc = crc32(cs->crc, (unsigned char*)tmp, (unsigned int)avail);
			ret = ILibDuktape_DuplexStream_WriteData(cs->ds, tmp, (int)avail);
		}
	} while (cs->Z.avail_out == 0);
	return(ret == 1 ? ILibTransport_DoneState_INCOMPLETE : ILibTransport_DoneState_COMPLETE);
}
duk_ret_t ILibDuktape_Compressor_Finalizer(duk_context *ctx)
{
	duk_push_this(ctx);
	ILibDuktape_CompressorStream *cs = (ILibDuktape_CompressorStream*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_CompressorStream_ptr);
	if (cs != NULL)
	{
		ignore_result(deflateEnd(&(cs->Z)));
	}
	return(0);
}
duk_ret_t ILibDuktape_CompressedStream_resume_newListener(duk_context *ctx)
{
	duk_push_this(ctx);							// [stream]
	duk_prepare_method_call(ctx, -1, "resume");	// [stream][resume][this]
	duk_pcall_method(ctx, 0);
	return(0);
}
duk_ret_t ILibDuktape_CompressedStream_crc(duk_context *ctx)
{
	duk_push_this(ctx);
	ILibDuktape_CompressorStream *cs = (ILibDuktape_CompressorStream*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_CompressorStream_ptr);
	duk_push_uint(ctx, cs->crc);
	return(1);
}

duk_ret_t ILibDuktape_CompressedStream_compressor(duk_context *ctx)
{
	int t = duk_get_top(ctx);
	duk_push_object(ctx);										// [compressed-stream]
	ILibDuktape_WriteID(ctx, "compressedStream.compressor");
	ILibDuktape_CompressorStream *cs = (ILibDuktape_CompressorStream*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_CompressorStream));
	duk_put_prop_string(ctx, -2, ILibDuktape_CompressorStream_ptr);
	cs->ctx = ctx;
	cs->object = duk_get_heapptr(ctx, -1);
	cs->ds = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_Compressor_Write, ILibDuktape_Compressor_End, ILibDuktape_Compressor_Pause, ILibDuktape_Compressor_Resume, cs);
	cs->Z.zalloc = Z_NULL;
	cs->Z.zfree = Z_NULL;
	cs->Z.opaque = Z_NULL;
	if (t>0 && duk_is_object(ctx, 0))
	{
		int maxbit = Duktape_GetIntPropertyValue(ctx, 0, "WBITS", -MAX_WBITS);
		int strat = Duktape_GetIntPropertyValue(ctx, 0, "STRATEGY", Z_DEFAULT_STRATEGY);
		int level = Duktape_GetIntPropertyValue(ctx, 0, "LEVEL", Z_DEFAULT_COMPRESSION);
		if (deflateInit2(&(cs->Z), level, Z_DEFLATED, maxbit, 8, strat) != Z_OK) { return(ILibDuktape_Error(ctx, "zlib error")); }
	}
	else
	{
		if (deflateInit(&(cs->Z), Z_DEFAULT_COMPRESSION) != Z_OK) { return(ILibDuktape_Error(ctx, "zlib error")); }
	}

	ILibDuktape_CreateEventWithGetter(ctx, "crc", ILibDuktape_CompressedStream_crc);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_Compressor_Finalizer);
	cs->ds->readableStream->paused = 1;
	duk_events_newListener2(ctx, -1, "data", ILibDuktape_CompressedStream_resume_newListener);

	return(1);
}
ILibTransport_DoneState ILibDuktape_deCompressor_Write(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_CompressorStream *cs = (ILibDuktape_CompressorStream*)user;
	char tmp[16384];
	size_t avail;
	int ret = 0;
	cs->Z.avail_in = bufferLen;
	cs->Z.next_in = (Bytef*)buffer;

	do
	{
		cs->Z.avail_out = sizeof(tmp);
		cs->Z.next_out = (Bytef*)tmp;
		ignore_result(inflate(&(cs->Z), Z_NO_FLUSH));
		avail = sizeof(tmp) - cs->Z.avail_out;
		if (avail > 0)
		{
			cs->crc = crc32(cs->crc, (unsigned char*)tmp, (unsigned int)avail);
			ret = ILibDuktape_DuplexStream_WriteData(cs->ds, tmp, (int)avail);
			if (ret == 1)
			{
				// Downstream was paused, so we have to save state, so we can resume later
				duk_push_heapptr(cs->ctx, cs->object);											// [stream]
				if (cs->Z.avail_in > 0)
				{
					char *tmp = Duktape_PushBuffer(cs->ctx, cs->Z.avail_in);					// [stream][buffer]
					memcpy_s(tmp, ILibMemory_Size(tmp), cs->Z.next_in, ILibMemory_Size(tmp));
					duk_put_prop_string(cs->ctx, -2, ILibDuktape_CompressorStream_ResumeBuffer);// [stream]
				}
				else
				{
					duk_del_prop_string(cs->ctx, -1, ILibDuktape_CompressorStream_ResumeBuffer);
				}
				duk_pop(cs->ctx);																// ...
				break;
			}
		}
	} while (cs->Z.avail_out == 0);

	if (ret == 0)
	{
		duk_push_heapptr(cs->ctx, cs->object);												// [stream]
		duk_del_prop_string(cs->ctx, -1, ILibDuktape_CompressorStream_ResumeBuffer);
		duk_pop(cs->ctx);																	// ...
	}

	return(ret == 1 ? ILibTransport_DoneState_INCOMPLETE : ILibTransport_DoneState_COMPLETE);
}
void ILibDuktape_deCompressor_End(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_CompressorStream *cs = (ILibDuktape_CompressorStream*)user;
	duk_context *ctx = cs->ctx;
	char tmp[16384];
	size_t avail;
	cs->Z.avail_in = 0;
	cs->Z.next_in = (Bytef*)ILibScratchPad;

	do
	{
		cs->Z.avail_out = sizeof(tmp);
		cs->Z.next_out = (Bytef*)tmp;
		ignore_result(inflate(&(cs->Z), Z_FINISH));
		avail = sizeof(tmp) - cs->Z.avail_out;
		if (avail > 0) 
		{
			cs->crc = crc32(cs->crc, (unsigned char*)tmp, (unsigned int)avail);
			ILibDuktape_DuplexStream_WriteData(cs->ds, tmp, (int)avail); 
		}
	} while (cs->Z.avail_out == 0);
	ILibDuktape_DuplexStream_WriteEnd(cs->ds);
	ignore_result(inflateEnd(&(cs->Z)));

	duk_push_heapptr(ctx, cs->object);	
	duk_del_prop_string(ctx, -1, ILibDuktape_CompressorStream_ptr);
	duk_pop(ctx);
}
duk_ret_t ILibDuktape_deCompressor_Finalizer(duk_context *ctx)
{
	duk_push_this(ctx);
	ILibDuktape_CompressorStream *cs = (ILibDuktape_CompressorStream*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_CompressorStream_ptr);
	if (cs != NULL)
	{
		ignore_result(inflateEnd(&(cs->Z)));
	}
	return(0);
}
duk_ret_t ILibDuktape_CompressedStream_decompressor(duk_context *ctx)
{
	duk_push_object(ctx);										// [compressed-stream]
	ILibDuktape_WriteID(ctx, "compressedStream.decompressor");
	ILibDuktape_CompressorStream *cs = (ILibDuktape_CompressorStream*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_CompressorStream));
	duk_put_prop_string(ctx, -2, ILibDuktape_CompressorStream_ptr);
	cs->ctx = ctx;
	cs->object = duk_get_heapptr(ctx, -1);
	cs->ds = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_deCompressor_Write, ILibDuktape_deCompressor_End, ILibDuktape_deCompressor_Pause, ILibDuktape_deCompressor_Resume, cs);
	cs->Z.zalloc = Z_NULL;
	cs->Z.zfree = Z_NULL;
	cs->Z.opaque = Z_NULL;
	cs->Z.avail_in = 0;
	cs->Z.next_in = Z_NULL;
	if (duk_is_object(ctx, 0))
	{
		int wbits = Duktape_GetIntPropertyValue(ctx, 0, "WBITS", -15);
		if (inflateInit2(&(cs->Z), wbits) != Z_OK) { return(ILibDuktape_Error(ctx, "zlib error")); }
	}
	else
	{
		if (inflateInit(&(cs->Z)) != Z_OK) { return(ILibDuktape_Error(ctx, "zlib error")); }
	}

	ILibDuktape_CreateEventWithGetter(ctx, "crc", ILibDuktape_CompressedStream_crc);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_deCompressor_Finalizer);
	cs->ds->readableStream->paused = 1;
	duk_events_newListener2(ctx, -1, "data", ILibDuktape_CompressedStream_resume_newListener);
	return(1);
}
void ILibDuktape_CompressedStream_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);							// [compressed-stream]
	ILibDuktape_WriteID(ctx, "compressedStream");
	ILibDuktape_CreateInstanceMethod(ctx, "createCompressor", ILibDuktape_CompressedStream_compressor, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "createDecompressor", ILibDuktape_CompressedStream_decompressor, DUK_VARARGS);
}

void ILibDuktape_CompressedStream_init(duk_context * ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "compressed-stream", ILibDuktape_CompressedStream_PUSH);
}
