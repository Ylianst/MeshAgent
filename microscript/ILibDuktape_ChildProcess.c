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
#ifdef WIN32
	int dispatchFlags;
#endif

	ILibDuktape_readableStream *stdOut;
	ILibDuktape_readableStream *stdErr;
	ILibDuktape_WritableStream *stdIn;
	
	int exitCode;
}ILibDuktape_ChildProcess_SubProcess;

void ILibDuktape_ChildProcess_SubProcess_StdOut_OnPause(ILibDuktape_readableStream *sender, void *user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	if (ILibMemory_CanaryOK(p->childProcess))
	{
		ILibProcessPipe_Pipe_Pause(ILibProcessPipe_Process_GetStdOut(p->childProcess));
	}
}
void ILibDuktape_ChildProcess_SubProcess_StdOut_OnResume(ILibDuktape_readableStream *sender, void *user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	if (ILibMemory_CanaryOK(p->childProcess))
	{
		ILibProcessPipe_Pipe_Resume(ILibProcessPipe_Process_GetStdOut(p->childProcess));
	}
}
void ILibDuktape_ChildProcess_SubProcess_StdErr_OnPause(ILibDuktape_readableStream *sender, void *user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	if (ILibMemory_CanaryOK(p->childProcess))
	{
		ILibProcessPipe_Pipe_Pause(ILibProcessPipe_Process_GetStdErr(p->childProcess));
	}
}
void ILibDuktape_ChildProcess_SubProcess_StdErr_OnResume(ILibDuktape_readableStream *sender, void *user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	if (ILibMemory_CanaryOK(p->childProcess))
	{
		ILibProcessPipe_Pipe_Resume(ILibProcessPipe_Process_GetStdErr(p->childProcess));
	}
}
ILibTransport_DoneState ILibDuktape_ChildProcess_SubProcess_StdIn_WriteHandler(ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	if (ILibMemory_CanaryOK(p->childProcess))
	{
		return(ILibProcessPipe_Process_WriteStdIn(p->childProcess, buffer, bufferLen, ILibTransport_MemoryOwnership_USER));
	}
	else
	{
		return(ILibTransport_DoneState_ERROR);
	}
}
void ILibDuktape_ChildProcess_SubProcess_StdIn_EndHandler(ILibDuktape_WritableStream *sender, void *user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	if (ILibMemory_CanaryOK(p->childProcess))
	{
		ILibProcessPipe_Process_CloseStdIn(p->childProcess);
	}
}
void ILibDuktape_ChildProcess_SubProcess_ExitHandler(ILibProcessPipe_Process sender, int exitCode, void* user);
void ILibDuktape_ChildProcess_SubProcess_ExitHandler_sink1(void *chain, void *user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	if (!ILibMemory_CanaryOK(p)) { return; }

	ILibDuktape_ChildProcess_SubProcess_ExitHandler(NULL, p->exitCode, p);
}
void ILibDuktape_ChildProcess_SubProcess_ExitHandler(ILibProcessPipe_Process sender, int exitCode, void* user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	if (!ILibMemory_CanaryOK(p)) { return; }

#ifdef WIN32
	if (duk_ctx_context_data(p->ctx)->apc_flags == 0 && p->dispatchFlags == 0)
	{
		// This method was called with an APC, but this thread was running an unknown alertable method when it was interrupted
		// So we must unwind the stack, and use a non-apc method to re-dispatch to this thread, becuase we can't risk
		// calling a winsock method, in case this thread was inside winsock when it was interrupted, because otherwise, it 
		// will corrupt memory, resulting in a possible crash.
		//
		// We had to do the APC first, becuase otherwise child_process.waitExit() will not work, becuase that method is blocking
		// the event loop thread with an alertable wait object, so APC is the only way to propagate this event
		p->exitCode = exitCode;
		p->dispatchFlags = 1;
		Duktape_RunOnEventLoop(p->chain, duk_ctx_nonce(p->ctx), p->ctx, ILibDuktape_ChildProcess_SubProcess_ExitHandler_sink1, NULL, p);
		return;
	}
#endif

	p->exitCode = exitCode;
	p->childProcess = NULL;
	duk_push_heapptr(p->ctx, p->subProcess);		// [childProcess]
	
#ifdef WIN32
	HANDLE exitptr = (HANDLE)Duktape_GetPointerProperty(p->ctx, -1, "\xFF_WaitExit");
	if (exitptr != NULL)
	{
		SetEvent(exitptr);
	}
#else
	if (Duktape_GetIntPropertyValue(p->ctx, -1, "\xFF_WaitExit", 0) != 0)
	{
		ILibChain_EndContinue(Duktape_GetChain(p->ctx));
	}
#endif
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
	if (!ILibMemory_CanaryOK(p)) { return; }

	ILibDuktape_readableStream_WriteData(p->stdOut, buffer, bufferLen);
	*bytesConsumed = bufferLen;
}
void ILibDuktape_ChildProcess_SubProcess_StdErrHandler(ILibProcessPipe_Process sender, char *buffer, int bufferLen, int* bytesConsumed, void* user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	if (!ILibMemory_CanaryOK(p)) { return; }

	ILibDuktape_readableStream_WriteData(p->stdErr, buffer, bufferLen);
	*bytesConsumed = bufferLen;
}
void ILibDuktape_ChildProcess_SubProcess_SendOK(ILibProcessPipe_Process sender, void* user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	if (!ILibMemory_CanaryOK(p)) { return; }

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
duk_ret_t ILibDuktape_ChildProcess_waitExit(duk_context *ctx)
{
	void *chain = Duktape_GetChain(ctx);
	if (ILibIsChainBeingDestroyed(chain))
	{
		return(ILibDuktape_Error(ctx, "Cannot waitExit() because current thread is exiting"));
	}

	duk_push_this(ctx);									// [spawnedProcess]
	if (!ILibChain_IsLinkAlive(Duktape_GetPointerProperty(ctx, -1, ILibDuktape_ChildProcess_Manager)))
	{
		return(ILibDuktape_Error(ctx, "Cannot waitExit() because JS Engine is exiting"));
	}

#ifdef WIN32
	DWORD result;
	HANDLE eptr = CreateEventA(NULL, TRUE, FALSE, NULL);
	duk_push_pointer(ctx, (void*)eptr);
#else
	duk_push_int(ctx, 1);								// [spawnedProcess][flag]
#endif
	duk_put_prop_string(ctx, -2, "\xFF_WaitExit");		// [spawnedProcess]

#ifdef WIN32
	duk_ctx_context_data(ctx)->apc_flags = 1;
	while ((result=WaitForSingleObjectEx(eptr, duk_is_number(ctx, 0) ? duk_require_int(ctx, 0) : INFINITE, TRUE)) != WAIT_OBJECT_0 && result != WAIT_TIMEOUT);
	duk_ctx_context_data(ctx)->apc_flags = 0;
	CloseHandle(eptr);
	if (result == WAIT_TIMEOUT) { return(ILibDuktape_Error(ctx, "timeout")); }
#else
	void *mods[] = { ILibGetBaseTimer(Duktape_GetChain(ctx)), Duktape_GetPointerProperty(ctx, -1, ILibDuktape_ChildProcess_Manager) };
	ILibChain_Continue(chain, (ILibChain_Link**)mods, 2, -1);
#endif

	return(0);
}
duk_ret_t ILibDuktape_ChildProcess_SpawnedProcess_Finalizer(duk_context *ctx)
{
#ifdef WIN32
	ILibDuktape_ChildProcess_SubProcess *retVal = (ILibDuktape_ChildProcess_SubProcess*)Duktape_GetBufferProperty(ctx, 0, ILibDuktape_ChildProcess_MemBuf);
	ILibProcessPipe_Process_RemoveHandlers(retVal->childProcess);
#endif
	duk_get_prop_string(ctx, 0, "kill");	// [kill]
	duk_dup(ctx, 0);						// [kill][this]
	duk_call_method(ctx, 0);
	return(0);
}

#ifndef WIN32
duk_ret_t ILibDuktape_ChildProcess_tcsetsize(duk_context *ctx)
{
	duk_push_this(ctx);
	int fd = (int)Duktape_GetIntPropertyValue(ctx, -1, "pty", 0);

	struct winsize ws;
	ws.ws_row = (int)duk_require_int(ctx, 0);
	ws.ws_col = (int)duk_require_int(ctx, 1);
	if (ioctl(fd, TIOCSWINSZ, &ws) == -1)
	{
		return(ILibDuktape_Error(ctx, "Error making TIOCSWINSZ/IOCTL"));
	}

	return(0);
}
#endif

ILibDuktape_ChildProcess_SubProcess* ILibDuktape_ChildProcess_SpawnedProcess_PUSH(duk_context *ctx, ILibProcessPipe_Process mProcess, void *callback)
{
	duk_push_object(ctx);														// [ChildProcess]
	ILibDuktape_WriteID(ctx, "childProcess.subProcess");
	duk_push_pointer(ctx, mProcess);											// [ChildProcess][ptr]
	duk_put_prop_string(ctx, -2, ILibDuktape_ChildProcess_Process);				// [ChildProcess]

	ILibDuktape_ChildProcess_SubProcess *retVal = (ILibDuktape_ChildProcess_SubProcess*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_ChildProcess_SubProcess));
	duk_put_prop_string(ctx, -2, ILibDuktape_ChildProcess_MemBuf); 				// [ChildProcess]

	retVal->ctx = ctx;
	retVal->subProcess = duk_get_heapptr(ctx, -1);
	retVal->childProcess = mProcess;
	retVal->chain = Duktape_GetChain(ctx);

	ILibDuktape_CreateReadonlyProperty_int(ctx, "pid", ILibProcessPipe_Process_GetPID(mProcess));
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_EventEmitter_CreateEventEx(emitter, "exit");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "error");
	ILibDuktape_CreateInstanceMethod(ctx, "kill", ILibDuktape_ChildProcess_Kill, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "waitExit", ILibDuktape_ChildProcess_waitExit, DUK_VARARGS);

	if (ILibProcessPipe_Process_IsDetached(mProcess) == 0)
	{
		ILibDuktape_EventEmitter_PrependOnce(ctx, -1, "~", ILibDuktape_ChildProcess_SpawnedProcess_Finalizer); // Kill child if object is collected while process is alive

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
#ifndef WIN32
		if (ILibProcessPipe_Process_GetPTY(mProcess) != 0)
		{
			duk_push_int(ctx, ILibProcessPipe_Process_GetPTY(mProcess));
			ILibDuktape_CreateReadonlyProperty(ctx, "pty");
			ILibDuktape_CreateInstanceMethod(ctx, "tcsetsize", ILibDuktape_ChildProcess_tcsetsize, 2);
		}
#endif

		if (callback != NULL) { ILibDuktape_EventEmitter_AddOnce(emitter, "exit", callback); }

		ILibProcessPipe_Process_AddHandlers(mProcess, 4096, ILibDuktape_ChildProcess_SubProcess_ExitHandler,
			ILibDuktape_ChildProcess_SubProcess_StdOutHandler,
			ILibDuktape_ChildProcess_SubProcess_StdErrHandler,
			ILibDuktape_ChildProcess_SubProcess_SendOK, retVal);
	}
	else
	{
		if (callback != NULL) { ILibDuktape_EventEmitter_AddOnce(emitter, "exit", callback); }
	}
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
	int uid = -1;
	char **envargs = NULL;

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
			uid = Duktape_GetIntPropertyValue(ctx, i, "uid", -1);
#ifdef WIN32
			if (uid >= 0 && spawnType == ILibProcessPipe_SpawnTypes_USER) { spawnType = ILibProcessPipe_SpawnTypes_SPECIFIED_USER; }
#endif
			if (Duktape_GetBooleanProperty(ctx, i, "detached", 0) != 0) { spawnType |= ILibProcessPipe_SpawnTypes_POSIX_DETACHED; }
			if (duk_has_prop_string(ctx, i, "env"))
			{
				int ecount = 0;
				duk_get_prop_string(ctx, i, "env");												// [env]
				duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);								// [env][enum]
				while (duk_next(ctx, -1, 0))
				{	
					++ecount;
					duk_pop(ctx);																// [env][enum]
				}
				if (ecount > 0)
				{
					duk_pop(ctx);																// [env]
					duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);							// [env][enum]
					envargs = (char**)duk_push_fixed_buffer(ctx, (ecount+1) * 2*sizeof(void*));	// [env][enum][buf]
					memset(envargs, 0, (ecount + 1) * 2*sizeof(void*));
					duk_insert(ctx, -3);														// [buf][env][enum]					
					ecount = 0;
					while (duk_next(ctx, -1, 1))												// [buf][env][enum][key][val]
					{
						
						envargs[ecount] = (char*)duk_get_string(ctx, -2);
						envargs[ecount + 1] = (char*)duk_to_string(ctx, -1);
						ecount += 2;
						duk_pop_2(ctx);															// [buf][env][enum]
					}
				}
			}
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
	
#ifdef WIN32
	p = ILibProcessPipe_Manager_SpawnProcessEx3(manager, target, args, spawnType, (void*)(ILibPtrCAST)(uint64_t)(uid < 0 ? 0 : uid), 0);
#else
	p = ILibProcessPipe_Manager_SpawnProcessEx4(manager, target, args, spawnType, (void*)(ILibPtrCAST)(uint64_t)uid, envargs, 0);
#endif
	if (p == NULL)
	{
		return(ILibDuktape_Error(ctx, "child_process.execFile(): Could not exec [%s]", target));
	}
	ILibDuktape_ChildProcess_SpawnedProcess_PUSH(ctx, p, callback);
	duk_push_pointer(ctx, manager); duk_put_prop_string(ctx, -2, ILibDuktape_ChildProcess_Manager);
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
	duk_push_int(ctx, 4);
	duk_put_prop_string(ctx, -2, "DETACHED");
	duk_put_prop_string(ctx, -2, "SpawnTypes");

	char flags[] = "exports.c_iflags = {'IGNBRK': 01, 'BRKINT': 02, 'IGNPAR': 04, 'PARMRK': 010,'INPCK': 020, 'ISTRIP': 040, 'INLCR': 0100, 'IGNCR': 0200, 'ICRNL': 0400, 'IUCLC': 01000, 'IXON': 02000, 'IXANY': 04000, 'IXOFF': 010000, 'IMAXBEL': 020000};\
					exports.c_oflags = {'OPOST': 001, 'OLCUC': 002, 'ONLCR': 004, 'OCRNL': 010, 'ONOCR': 020, 'ONLRET': 040, 'OFILL': 0100, 'OFDEL': 0200};\
					exports.c_lflags = {'ISIG': 001, 'ICANON': 002, 'ECHO': 010, 'ECHOE': 020, 'ECHOK': 040, 'ECHONL': 0100, 'NOFLSH': 0200, 'IEXTEN': 0400, 'TOSTOP': 0100000, 'ITOSTOP': 0100000}\
		";
	ILibDuktape_ModSearch_AddHandler_AlsoIncludeJS(ctx, flags, sizeof(flags) - 1);
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
