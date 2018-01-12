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

#ifndef ___ILIBDUKTAPE_WRITABLESTREAM___
#define ___ILIBDUKTAPE_WRITABLESTREAM___

#include "duktape.h"
#include "microstack/ILibParsers.h"

struct ILibDuktape_WritableStream;
typedef ILibTransport_DoneState(*ILibDuktape_WritableStream_WriteHandler)(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user);
typedef void(*ILibDuktape_WritableStream_EndHandler)(struct ILibDuktape_WritableStream *stream, void *user);
typedef int(*ILibDuktape_WriteableStream_WriteFlushNative)(struct ILibDuktape_WritableStream *stream, void *user);
typedef void(*ILibDuktape_WritableStream_PipeHandler)(struct ILibDuktape_WritableStream *stream, void *readableSource, void *user);

struct ILibDuktape_readableStream;

typedef struct ILibDuktape_WritableStream
{
	int JSCreated;
	duk_context *ctx;
	void *obj;
	void *OnDrain;
	void *OnWriteFlush;

	ILibDuktape_WriteableStream_WriteFlushNative OnWriteFlushEx;
	void *OnWriteFlushEx_User;

	void *OnError;
	void *OnFinish;
	char WaitForEnd;

	ILibDuktape_WritableStream_WriteHandler WriteSink;
	ILibDuktape_WritableStream_EndHandler EndSink;

	void *pipedReadable;
	struct ILibDuktape_readableStream* pipedReadable_native;

	void *WriteSink_User;
	int endBytes;
	int Reserved;
} ILibDuktape_WritableStream;

#define ILibDuktape_WritableStream_WSPTRS				"\xFF_WritableStream_PTRS"

ILibDuktape_WritableStream* ILibDuktape_WritableStream_Init(duk_context *ctx, ILibDuktape_WritableStream_WriteHandler WriteHandler, ILibDuktape_WritableStream_EndHandler EndHandler, void *user);
void ILibDuktape_WritableStream_Ready(ILibDuktape_WritableStream *stream);


#endif