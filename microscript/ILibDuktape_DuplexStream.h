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

#ifndef ___ILIBDUKTAPE_DUPLEXSTREAM___
#define ___ILIBDUKTAPE_DUPLEXSTREAM___

#include "duktape.h"
#include "microstack/ILibParsers.h"
#include "ILibDuktape_ReadableStream.h"
#include "ILibDuktape_WritableStream.h"

#define ILibDuktape_DuplexStream_bufferPtr			"\xFF_DuplexStreamPtr"

typedef struct ILibDuktape_DuplexStream
{
	ILibDuktape_readableStream *readableStream;
	ILibDuktape_WritableStream *writableStream;
	void *user;
	void *ParentObject;
	void *OnWrite;
	void *OnEnd;
	void *OnPause;
	void *OnResume;
}ILibDuktape_DuplexStream;

typedef ILibTransport_DoneState(*ILibDuktape_DuplexStream_WriteHandler)(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user);
typedef void(*ILibDuktape_DuplexStream_EndHandler)(ILibDuktape_DuplexStream *stream, void *user);
typedef void(*ILibDuktape_DuplexStream_PauseResumeHandler)(ILibDuktape_DuplexStream *sender, void *user);

#define ILibDuktape_DuplexStream_Ready(duplexStream) ILibDuktape_WritableStream_Ready((duplexStream)->writableStream)
#define ILibDuktape_DuplexStream_WriteData(duplexStream, buffer, bufferLen) ILibDuktape_readableStream_WriteData((duplexStream)->readableStream, buffer, bufferLen)
#define ILibDuktape_DuplexStream_WriteDataEx(duplexStream, streamReserved, buffer, bufferLen) ILibDuktape_readableStream_WriteDataEx((duplexStream)->readableStream, streamReserved, buffer, bufferLen)
#define ILibDuktape_DuplexStream_WriteEnd(duplexStream) ILibDuktape_readableStream_WriteEnd((duplexStream)->readableStream)
#define ILibDuktape_DuplexStream_Closed(duplexStream) ILibDuktape_readableStream_Closed((duplexStream)->readableStream)

ILibDuktape_DuplexStream* ILibDuktape_DuplexStream_Init(duk_context *ctx, ILibDuktape_DuplexStream_WriteHandler WriteHandler, ILibDuktape_DuplexStream_EndHandler EndHandler, ILibDuktape_DuplexStream_PauseResumeHandler PauseHandler, ILibDuktape_DuplexStream_PauseResumeHandler ResumeHandler, void *user);


#endif
