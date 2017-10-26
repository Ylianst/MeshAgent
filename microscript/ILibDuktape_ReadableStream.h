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

#ifndef ___ILIBDUKTAPE_READABLESTREAM___
#define ___ILIBDUKTAPE_READABLESTREAM___

#include "duktape.h"
#include "microstack/ILibParsers.h"

#define ILibDuktape_readableStream_RSPTRS				"\xFF_ReadableStream_PTRS"

struct ILibDuktape_readableStream;
typedef void(*ILibDuktape_readableStream_PauseResumeHandler)(struct ILibDuktape_readableStream *sender, void *user);
typedef void(*ILibDuktape_readableStream_MethodHookHandler)(struct ILibDuktape_readableStream *sender, void *user);
typedef struct ILibDuktape_readableStream_nextWriteablePipe
{
	void *writableStream;
	void *nativeWritable;
	struct ILibDuktape_readableStream_nextWriteablePipe *next;
}ILibDuktape_readableStream_nextWriteablePipe;

typedef struct ILibDuktape_readableStream
{
	duk_context *ctx;
	void *chain;
	void *object;
	void *OnClose;
	void *OnData;
	void *OnEnd;
	void *extBuffer;
	char *extBuffer_buffer;
	int extBuffer_bufferLen, extBuffer_Reserved;

	void *user;
	ILibDuktape_readableStream_nextWriteablePipe *nextWriteable;
	sem_t pipeLock;
#if defined(WIN32)
	volatile LONG pipe_pendingCount;	// Use Windows Built-in Atomic Intrinsics
#elif defined(__ATOMIC_SEQ_CST)
	volatile int pipe_pendingCount;		// Use GCC Built-in Atomic Intrinsics
#else
	int pipe_pendingCount;				// No Atomic Built-ins... Use a Mutex
#endif
	int bypassValue;
	int paused;
	void *paused_data;
	ILibDuktape_readableStream_PauseResumeHandler PauseHandler;
	ILibDuktape_readableStream_PauseResumeHandler ResumeHandler;
	ILibDuktape_readableStream_MethodHookHandler PipeHookHandler;
}ILibDuktape_readableStream;

ILibDuktape_readableStream* ILibDuktape_InitReadableStream(duk_context *ctx, ILibDuktape_readableStream_PauseResumeHandler OnPause, ILibDuktape_readableStream_PauseResumeHandler OnResume, void *user);
#define ILibDuktape_ReadableStream_Init(ctx, OnPause, OnResume, user) ILibDuktape_InitReadableStream(ctx, OnPause, OnResume, user)
#define ILibDuktape_readableStream_SetPauseResumeHandlers(stream, PauseFunc, ResumeFunc, userObj) ((ILibDuktape_readableStream*)stream)->PauseHandler = PauseFunc; ((ILibDuktape_readableStream*)stream)->ResumeHandler = ResumeFunc; ((ILibDuktape_readableStream*)stream)->user = userObj;

int ILibDuktape_readableStream_WriteDataEx(ILibDuktape_readableStream *stream, int streamReserved, char* buffer, int bufferLen);
int ILibDuktape_readableStream_WriteEnd(ILibDuktape_readableStream *stream);
#define ILibDuktape_readableStream_WriteData(stream, buffer, bufferLen) ILibDuktape_readableStream_WriteDataEx(stream, 0, buffer, bufferLen)
void ILibDuktape_readableStream_Closed(ILibDuktape_readableStream *stream);

#endif

