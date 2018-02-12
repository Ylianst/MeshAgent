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

#include "ILibDuktape_ChildProcess.h"

#include "ILibDuktapeModSearch.h"
#include "../microstack/ILibParsers.h"
#include "../microstack/ILibProcessPipe.h"

#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_ReadableStream.h"
#include "ILibDuktape_WritableStream.h"
#include "ILibDuktape_EventEmitter.h"

#define ILibDuktape_ChildProcess_Process	"\xFF_ChildProcess_Process"
#define ILibDuktape_ChildProcess_MemBuf		"\xFF_ChildProcess_MemBuf"

typedef struct ILibDuktape_ChildProcess_SubProcess
{
	duk_context *ctx;
	void *subProcess;
	void *chain;
	ILibProcessPipe_Process childProcess;

	ILibDuktape_readableStream *stdOut;
	ILibDuktape_readableStream *stdErr;
	ILibDuktape_WritableStream *stdIn;
	
	int exitCode;
}ILibDuktape_ChildProcess_SubProcess;

void ILibDuktape_ChildProcess_SubProcess_StdOut_OnPause(ILibDuktape_readableStream *sender, void *user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	ILibProcessPipe_Pipe_Pause(ILibProcessPipe_Process_GetStdOut(p->childProcess));
}
void ILibDuktape_ChildProcess_SubProcess_StdOut_OnResume(ILibDuktape_readableStream *sender, void *user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	ILibProcessPipe_Pipe_Resume(ILibProcessPipe_Process_GetStdOut(p->childProcess));
}
void ILibDuktape_ChildProcess_SubProcess_StdErr_OnPause(ILibDuktape_readableStream *sender, void *user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	ILibProcessPipe_Pipe_Pause(ILibProcessPipe_Process_GetStdErr(p->childProcess));
}
void ILibDuktape_ChildProcess_SubProcess_StdErr_OnResume(ILibDuktape_readableStream *sender, void *user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	ILibProcessPipe_Pipe_Resume(ILibProcessPipe_Process_GetStdErr(p->childProcess));
}
ILibTransport_DoneState ILibDuktape_ChildProcess_SubProcess_StdIn_WriteHandler(ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	return(ILibProcessPipe_Process_WriteStdIn(p->childProcess, buffer, bufferLen, ILibTransport_MemoryOwnership_USER));
}
void ILibDuktape_ChildProcess_SubProcess_StdIn_EndHandler(ILibDuktape_WritableStream *sender, void *user)
{
}

void ILibDuktape_ChildProcess_SubProcess_ExitHandler(ILibProcessPipe_Process sender, int exitCode, void* user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	p->exitCode = exitCode;

	duk_push_heapptr(p->ctx, p->subProcess);		// [childProcess]
	duk_get_prop_string(p->ctx, -1, "emit");		// [childProcess][emit]
	duk_swap_top(p->ctx, -2);						// [emit][this]
	duk_push_string(p->ctx, "exit");				// [emit][this][exit]
	duk_push_int(p->ctx, p->exitCode);				// [emit][this][exit][exitCode]
	duk_push_null(p->ctx);							// [emit][this][exit][exitCode][sig]
	if (duk_pcall_method(p->ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(p->ctx, "child_process.subProcess.exit(): "); }
	duk_pop(p->ctx);
	
}
void ILibDuktape_ChildProcess_SubProcess_StdOutHandler(ILibProcessPipe_Process sender, char *buffer, int bufferLen, int* bytesConsumed, void* user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	ILibDuktape_readableStream_WriteData(p->stdOut, buffer, bufferLen);
	*bytesConsumed = bufferLen;
}
void ILibDuktape_ChildProcess_SubProcess_StdErrHandler(ILibProcessPipe_Process sender, char *buffer, int bufferLen, int* bytesConsumed, void* user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	ILibDuktape_readableStream_WriteData(p->stdErr, buffer, bufferLen);
	*bytesConsumed = bufferLen;
}
void ILibDuktape_ChildProcess_SubProcess_SendOK(ILibProcessPipe_Process sender, void* user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	ILibDuktape_WritableStream_Ready(p->stdIn);
}
duk_ret_t ILibDuktape_ChildProcess_Kill(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_ChildProcess_MemBuf);
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)Duktape_GetBuffer(ctx, -1, NULL);

	ILibProcessPipe_Process_SoftKill(p->childProcess);

	return(0);
}
ILibDuktape_ChildProcess_SubProcess* ILibDuktape_ChildProcess_SpawnedProcess_PUSH(duk_context *ctx, ILibProcessPipe_Process mProcess, void *callback)
{
	duk_push_object(ctx);														// [ChildProcess]
	ILibDuktape_WriteID(ctx, "childProcess.subProcess");
	duk_push_pointer(ctx, mProcess);											// [ChildProcess][ptr]
	duk_put_prop_string(ctx, -2, ILibDuktape_ChildProcess_Process);				// [ChildProcess]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_ChildProcess_SubProcess));	// [ChildProcess][buffer]
	ILibDuktape_ChildProcess_SubProcess *retVal = (ILibDuktape_ChildProcess_SubProcess*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_ChildProcess_MemBuf); 				// [ChildProcess]

	memset(retVal, 0, sizeof(ILibDuktape_ChildProcess_SubProcess));
	retVal->ctx = ctx;
	retVal->subProcess = duk_get_heapptr(ctx, -1);
	retVal->childProcess = mProcess;
	retVal->chain = Duktape_GetChain(ctx);

	ILibDuktape_CreateReadonlyProperty_int(ctx, "pid", ILibProcessPipe_Process_GetPID(mProcess));
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_EventEmitter_CreateEventEx(emitter, "exit");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "error");

	ILibDuktape_CreateInstanceMethod(ctx, "kill", ILibDuktape_ChildProcess_Kill, 0);

	duk_push_object(ctx);
	ILibDuktape_WriteID(ctx, "childProcess.subProcess.stdout");
	duk_dup(ctx, -2);
	ILibDuktape_CreateReadonlyProperty(ctx, "parent");
	retVal->stdOut = ILibDuktape_ReadableStream_Init(ctx, ILibDuktape_ChildProcess_SubProcess_StdOut_OnPause, ILibDuktape_ChildProcess_SubProcess_StdOut_OnResume, retVal);
	ILibDuktape_CreateReadonlyProperty(ctx, "stdout");

	duk_push_object(ctx);
	ILibDuktape_WriteID(ctx, "childProcess.subProcess.stderr");
	duk_dup(ctx, -2);
	ILibDuktape_CreateReadonlyProperty(ctx, "parent");
	retVal->stdErr = ILibDuktape_ReadableStream_Init(ctx, ILibDuktape_ChildProcess_SubProcess_StdErr_OnPause, ILibDuktape_ChildProcess_SubProcess_StdErr_OnResume, retVal);
	ILibDuktape_CreateReadonlyProperty(ctx, "stderr");

	duk_push_object(ctx);
	ILibDuktape_WriteID(ctx, "childProcess.subProcess.stdin");
	duk_dup(ctx, -2);
	ILibDuktape_CreateReadonlyProperty(ctx, "parent");
	retVal->stdIn = ILibDuktape_WritableStream_Init(ctx, ILibDuktape_ChildProcess_SubProcess_StdIn_WriteHandler, ILibDuktape_ChildProcess_SubProcess_StdIn_EndHandler, retVal);
	ILibDuktape_CreateReadonlyProperty(ctx, "stdin");

	if (callback != NULL) { ILibDuktape_EventEmitter_AddOnce(emitter, "exit", callback); }

	ILibProcessPipe_Process_AddHandlers(mProcess, 4096, ILibDuktape_ChildProcess_SubProcess_ExitHandler, 
		ILibDuktape_ChildProcess_SubProcess_StdOutHandler,
		ILibDuktape_ChildProcess_SubProcess_StdErrHandler,
		ILibDuktape_ChildProcess_SubProcess_SendOK, retVal);

	return(retVal);
}

duk_ret_t ILibDuktape_ChildProcess_Manager_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, ILibDuktape_ChildProcess_Manager);
	ILibProcessPipe_Manager manager = (ILibProcessPipe_Manager)duk_get_pointer(ctx, -1);

	ILibChain_SafeRemove(((ILibChain_Link*)manager)->ParentChain, manager);
	return(0);
}
duk_ret_t ILibDuktape_ChildProcess_execFile(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_ChildProcess_Manager);
	ILibProcessPipe_Manager manager = (ILibProcessPipe_Manager)duk_get_pointer(ctx, -1);
	duk_size_t targetLen;
	char *target = (char*)duk_get_lstring(ctx, 0, &targetLen);
	char **args = NULL;
	int i, x;
	void *callback = NULL;
	ILibProcessPipe_Process p = NULL;
	ILibProcessPipe_SpawnTypes spawnType = ILibProcessPipe_SpawnTypes_DEFAULT;

	for (i = 0; i < nargs; ++i)
	{
		if (duk_is_array(ctx, i) != 0)
		{
			int arrLen = (int)duk_get_length(ctx, i);
#ifdef WIN32
			args = (char**)_alloca((arrLen + 1) * sizeof(char*));
#else
			args = (char**)alloca((arrLen + 1) * sizeof(char*));
#endif
			for (x = 0; x < arrLen; ++x)
			{
				duk_get_prop_index(ctx, i, x);
				args[x] = (char*)duk_get_string(ctx, -1);
			}
			args[x] = NULL;
		}
		else if (duk_is_function(ctx, i))
		{
			callback = duk_get_heapptr(ctx, i);
		}
		else if (duk_is_object(ctx, i))
		{
			// Options
			spawnType = (ILibProcessPipe_SpawnTypes)Duktape_GetIntPropertyValue(ctx, i, "type", (int)ILibProcessPipe_SpawnTypes_DEFAULT);
		}
	}

#ifdef WIN32
	if (target[0] == '%')
	{
		size_t evsize;
		int pctx = ILibString_IndexOf(target + 1, (int)targetLen - 1, "%", 1);
		if (pctx > 0)
		{
			memcpy_s(ILibScratchPad, sizeof(ILibScratchPad), target + 1, pctx);
			ILibScratchPad[pctx] = 0;
			getenv_s(&evsize, ILibScratchPad2, sizeof(ILibScratchPad2), ILibScratchPad);
			if (evsize > 0)
			{
				strncpy_s(ILibScratchPad2 + evsize - 1, sizeof(ILibScratchPad2) - evsize, target + pctx + 2, targetLen - pctx - 2);
				target = ILibScratchPad2;
			}
		}
	}
#endif

	p = ILibProcessPipe_Manager_SpawnProcessEx2(manager, target, args, spawnType, 0);
	if (p == NULL)
	{
		return(ILibDuktape_Error(ctx, "child_process.execFile(): Could not exec [%s]", target));
	}
	ILibDuktape_ChildProcess_SpawnedProcess_PUSH(ctx, p, callback);
	return(1);
}
void ILibDuktape_ChildProcess_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_WriteID(ctx, "childProcess");
	duk_push_pointer(ctx, (void*)ILibProcessPipe_Manager_Create(chain));
	duk_put_prop_string(ctx, -2, ILibDuktape_ChildProcess_Manager);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_ChildProcess_Manager_Finalizer);

	ILibDuktape_CreateInstanceMethod(ctx, "execFile", ILibDuktape_ChildProcess_execFile, DUK_VARARGS);
	duk_push_object(ctx);
	duk_push_int(ctx, 0);
	duk_put_prop_string(ctx, -2, "DEFAULT");
	duk_push_int(ctx, 1);
	duk_put_prop_string(ctx, -2, "USER");
	duk_push_int(ctx, 2);
	duk_put_prop_string(ctx, -2, "WINLOGON");
	duk_push_int(ctx, 3);
	duk_put_prop_string(ctx, -2, "TERM");
	duk_put_prop_string(ctx, -2, "SpawnTypes");
}
void ILibDuktape_ChildProcess_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "child_process", ILibDuktape_ChildProcess_PUSH);
}

#ifdef __DOXY__
/*!
\implements EventEmitter
\brief The child_process module provides the ability to spawn child processes. <b>Note:</b> To use, must <b>require('child_process')</b>
*/
class ChildProcess
{
public:
	/*!
	\brief The specified file is spawned as a child process
	\param file \<String\> Required. The name or path of the executable file to run
	\param args \<String[]\> Optional. List of string arguments
	\param options <Object> Optional. \n
	cwd \<String\> Current working directory\n
	env <Object> Environment key-value pairs\n
	timeout <number> <b>Default</b>: 0\n
	\returns \<ChildProcess\>
	*/
	static ChildProcess execFile(file[, args][, options][, callback]);

	/*!
	\brief Event emitted whenever process cannot be killed or spawned
	\param err <Error> The Error
	*/
	void error;
	/*!
	\brief Event emitted after the child process ends
	\param code <number> Exit code
	\param signal \<String\> Not used.
	*/
	void exit;
	/*!
	\brief Process ID of the child process
	*/
	Integer pid;
	/*!
	\brief Sends SIGTERM to child process
	*/
	void kill();

	/*!
	\brief StdOut ReadableStream
	*/
	ReadableStream stdout;
	/*!
	\brief StdErr ReadableStream
	*/
	ReadableStream stderr;
	/*!
	\brief StdIn WritableStream
	*/
	WritableStream stdin;

};
#endif