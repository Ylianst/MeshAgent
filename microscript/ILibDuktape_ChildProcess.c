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
#include "ILibDuktape_ScriptContainer.h"

#ifdef WIN32
#include <process.h>
#endif

#define ILibDuktape_ChildProcess_Process	"\xFF_ChildProcess_Process"
#define ILibDuktape_ChildProcess_MemBuf		"\xFF_ChildProcess_MemBuf"
extern int g_displayFinalizerMessages;

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

void ILibDuktape_ChildProcess_DeleteBackReferences(duk_context *ctx, duk_idx_t i, char *name)
{
	if (duk_has_prop_string(ctx, i, name))
	{
		duk_get_prop_string(ctx, i, name);			// [sub]
		duk_del_prop_string(ctx, -1, "parent");
		duk_pop(ctx);								// ...
	}
}

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
		if (g_displayFinalizerMessages)
		{
			duk_push_this(stream->ctx);
			if (!duk_has_prop_string(stream->ctx, -1, ILibDuktape_EventEmitter_FinalizerDebugMessage))
			{
				char tmp[100] = { 0 };
				memcpy_s(tmp, sizeof(tmp), buffer, bufferLen > sizeof(tmp) ? sizeof(tmp) - 1 : bufferLen);
				duk_push_string(stream->ctx, tmp);
				duk_put_prop_string(stream->ctx, -2, ILibDuktape_EventEmitter_FinalizerDebugMessage);
				printf("   => [%s]\n", tmp);
			}
			duk_pop(stream->ctx);
		}
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

	p->exitCode = exitCode;
	p->childProcess = NULL;
	duk_push_heapptr(p->ctx, p->subProcess);																// [childProcess]

#if defined(_POSIX)
	if (duk_has_prop_string(p->ctx, -1, "_sigsink"))
	{
		ILibDuktape_EventEmitter_SetupRemoveListener(p->ctx, ILibDuktape_GetProcessObject(p->ctx), "SIGCHLD"); //......][remove][process][SIGCHLD]
		duk_get_prop_string(p->ctx, -4, "_sigsink");														// [childProcess][remove][process][SIGCHLD][func]
		duk_del_prop_string(p->ctx, -1, "_child");
		duk_pcall_method(p->ctx, 2); duk_pop(p->ctx);														// [childProcess]
	}
#endif

	if (Duktape_GetIntPropertyValue(p->ctx, -1, "\xFF_WaitExit", 0) != 0)
	{
		ILibChain_EndContinue(Duktape_GetChain(p->ctx));
	}

	duk_get_prop_string(p->ctx, -1, "emit");		// [childProcess][emit]
	duk_swap_top(p->ctx, -2);						// [emit][this]
	duk_push_string(p->ctx, "exit");				// [emit][this][exit]
	duk_push_int(p->ctx, p->exitCode);				// [emit][this][exit][exitCode]
	duk_push_null(p->ctx);							// [emit][this][exit][exitCode][sig]
	if (duk_pcall_method(p->ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(p->ctx, "child_process.subProcess.exit(): "); }
	duk_pop(p->ctx);

	duk_push_heapptr(p->ctx, p->subProcess);		// [childProcess]
	ILibDuktape_ChildProcess_DeleteBackReferences(p->ctx, -1, "stdin");
	ILibDuktape_ChildProcess_DeleteBackReferences(p->ctx, -1, "stdout");
	ILibDuktape_ChildProcess_DeleteBackReferences(p->ctx, -1, "stderr");
	duk_pop(p->ctx);								// ...
}
void ILibDuktape_ChildProcess_SubProcess_StdOutHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)
{
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)user;
	if (!ILibMemory_CanaryOK(p)) { return; }

	ILibDuktape_readableStream_WriteData(p->stdOut, buffer, bufferLen);
	*bytesConsumed = bufferLen;
}
void ILibDuktape_ChildProcess_SubProcess_StdErrHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)
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
	ILibDuktape_ChildProcess_SubProcess *p = (ILibDuktape_ChildProcess_SubProcess*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_ChildProcess_MemBuf);

	if (p != NULL) 
	{
		if (p->childProcess != NULL)
		{
			if (duk_ctx_shutting_down(ctx) == 0)
			{
				ILibProcessPipe_Process_SoftKill(p->childProcess);
			}
			else
			{
				ILibProcessPipe_Process_HardKill(p->childProcess);
			}
		}
	}
	return(0);
}
duk_ret_t ILibDuktape_ChildProcess_waitExit(duk_context *ctx)
{
	ILibChain_Continue_Result continueResult;
	int ret = 0;
	int timeout = duk_is_number(ctx, 0) ? duk_require_int(ctx, 0) : -1;
	void *chain = Duktape_GetChain(ctx);
	if (ILibIsChainBeingDestroyed(chain))
	{
		return(ILibDuktape_Error(ctx, "Cannot waitExit() because current thread is exiting"));
	}

	duk_push_this(ctx);									// [spawnedProcess]
	//char *_target = Duktape_GetStringPropertyValue(ctx, -1, "_target", NULL);

	if (!ILibChain_IsLinkAlive(Duktape_GetPointerProperty(ctx, -1, ILibDuktape_ChildProcess_Manager)))
	{
		return(ILibDuktape_Error(ctx, "Cannot waitExit() because JS Engine is exiting"));
	}

	if (ILibChain_GetContinuationState(chain) != ILibChain_ContinuationState_CONTINUE)
	{
		duk_push_int(ctx, 1);								// [spawnedProcess][flag]
		duk_put_prop_string(ctx, -2, "\xFF_WaitExit");		// [spawnedProcess]
	}

	void *mods[] = { ILibGetBaseTimer(Duktape_GetChain(ctx)), Duktape_GetPointerProperty(ctx, -1, ILibDuktape_ChildProcess_Manager), ILibDuktape_Process_GetSignalListener(ctx) };
#ifdef WIN32
	HANDLE handles[] = { NULL, NULL, NULL, NULL, NULL };
	ILibProcessPipe_Process p = Duktape_GetPointerProperty(ctx, -1, ILibDuktape_ChildProcess_Process);
	ILibProcessPipe_Process_GetWaitHandles(p, &(handles[0]), &(handles[1]), &(handles[2]), &(handles[3]));
	continueResult = ILibChain_Continue(chain, (ILibChain_Link**)mods, 2, timeout, (HANDLE**)handles);
#else
	continueResult = ILibChain_Continue(chain, (ILibChain_Link**)mods, 3, timeout);
#endif
	switch (continueResult)
	{
		case ILibChain_Continue_Result_ERROR_INVALID_STATE:
			ret = ILibDuktape_Error(ctx, "waitExit() already in progress");
			break;
		case ILibChain_Continue_Result_ERROR_CHAIN_EXITING:
			ret = ILibDuktape_Error(ctx, "waitExit() aborted because thread is exiting");
			break;
		case ILibChain_Continue_Result_ERROR_EMPTY_SET:
			ret = ILibDuktape_Error(ctx, "waitExit() cannot wait on empty set");
			break;
		default:
			ret = 0;
			break;
	}
	return(ret);
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

duk_ret_t ILibDuktape_SpawnedProcess_descriptorSetter(duk_context *ctx)
{
	duk_push_this(ctx);
	ILibDuktape_ChildProcess_SubProcess *retVal = (ILibDuktape_ChildProcess_SubProcess*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_ChildProcess_MemBuf);
	if (retVal != NULL)
	{
		duk_push_string(ctx, ILibProcessPipe_Process_GetMetadata(retVal->childProcess));		// [string]
		duk_get_prop_string(ctx, -1, "split");													// [string][split]
		duk_swap_top(ctx, -2);																	// [split][this]
		duk_push_string(ctx, " [EXIT]");														// [split][this][delim]
		duk_call_method(ctx, 1);																// [array]
		duk_get_prop_string(ctx, -1, "shift");													// [array][shift]
		duk_swap_top(ctx, -2);																	// [shift][this]
		duk_call_method(ctx, 0);																// [string]
		duk_push_sprintf(ctx, "%s, %s", duk_get_string(ctx, -1), duk_require_string(ctx, 0));	// [string][newVal]

		if (g_displayFinalizerMessages)
		{
			duk_push_this(ctx);																	// [string][newVal][obj]
			duk_dup(ctx, -2);																	// [string][newVal][obj][val]
			printf("\nSETTING: %s\n", duk_get_string(ctx, -1));
			duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_FinalizerDebugMessage);		// [string][newVal][obj]
			duk_pop(ctx);																		// [string][newVal]
		}

		ILibProcessPipe_Process_ResetMetadata(retVal->childProcess, (char*)duk_get_string(ctx, -1));
	}
	return(0);
}

#if defined(_POSIX) 
extern void ILibProcessPipe_Process_Destroy(void *p);
duk_ret_t ILibDuktape_SpawnedProcess_SIGCHLD_sink(duk_context *ctx)
{
	int statusCode = duk_require_int(ctx, 1);
	int pid = duk_require_int(ctx, 2);
	duk_push_current_function(ctx);				// [func]
	duk_get_prop_string(ctx, -1, "_child");		// [func][child]
	void *child = duk_get_heapptr(ctx, -1);

	if (Duktape_GetIntPropertyValue(ctx, -1, "pid", -1) == pid)
	{
		// This SIGCHLD is for us. Let's unhook from SIGCHLD
		duk_del_prop_string(ctx, -1, "_sigsink");
		ILibDuktape_EventEmitter_SetupRemoveListener(ctx, ILibDuktape_GetProcessObject(ctx), "SIGCHLD");	// [remove][this][SIGCHLD]
		duk_push_current_function(ctx);																		// [remove][this][SIGCHLD][func]
		duk_pcall_method(ctx, 2);
		// Let's chec to see if we were detached or not
		duk_push_heapptr(ctx, child);								// [child]
		if (!duk_has_prop_string(ctx, -1, "stdout"))
		{
			// We are detached, so we can just emit 'exit' and be done
			ILibDuktape_EventEmitter_SetupEmit(ctx, child, "exit");	// [child][emit][this][exit]
			duk_push_int(ctx, statusCode);							// [child][emit][this][exit][code]
			duk_push_null(ctx);										// [child][emit][this][exit][code][null]
			duk_call_method(ctx, 3); duk_pop(ctx);					// [child]
		}
		else
		{
			// We are not detached, so we need to call the same method that broken pipe would've
			ILibDuktape_ChildProcess_SubProcess *childprocess = (ILibDuktape_ChildProcess_SubProcess*)Duktape_GetBufferProperty(ctx, -1, ILibDuktape_ChildProcess_MemBuf);
			if (childprocess != NULL)
			{
				ILibDuktape_ChildProcess_SubProcess_ExitHandler(childprocess->childProcess, statusCode, childprocess);
			}	
			duk_push_heapptr(ctx, child);
			ILibDuktape_ChildProcess_DeleteBackReferences(ctx, -1, "stdin");
			ILibDuktape_ChildProcess_DeleteBackReferences(ctx, -1, "stdout");
			ILibDuktape_ChildProcess_DeleteBackReferences(ctx, -1, "stderr");
			duk_pop(ctx);
		}

		duk_push_current_function(ctx);							// [func]
		duk_del_prop_string(ctx, -1, "_child");
		duk_pop(ctx);											// ...

		duk_push_heapptr(ctx, child);							// [child]
		void *mProcess = Duktape_GetPointerProperty(ctx, -1, ILibDuktape_ChildProcess_Process);
		if (mProcess != NULL)
		{
			duk_del_prop_string(ctx, -1, ILibDuktape_ChildProcess_Process);
			duk_del_prop_string(ctx, -1, ILibDuktape_ChildProcess_MemBuf);
			ILibProcessPipe_Process_Destroy(mProcess);
		}
	}

	return(0);
}
#endif

void ILibDuktape_SpawnedProcess_exitHandler_immediateSink(duk_context *ctx, void ** args, int argsLen)
{
	duk_push_this(ctx);											// [immediate]
	duk_get_prop_string(ctx, -1, "process");					// [immediate][spawnedProcess]
	duk_del_prop_string(ctx, -2, "process");
	if (duk_has_prop_string(ctx, -1, "stdout"))
	{
		duk_get_prop_string(ctx, -1, "stdout");					// [immediate][spawnedProcess][stdout]
		duk_prepare_method_call(ctx, -1, "removeAllListeners"); // [immediate][spawnedProcess][stdout][removeAll][this] 
		duk_pcall_method(ctx, 0); duk_pop_2(ctx);				// [immediate][spawnedProcess]
	}
	if (duk_has_prop_string(ctx, -1, "stderr"))
	{
		duk_get_prop_string(ctx, -1, "stderr");					// [immediate][spawnedProcess][stderr]
		duk_prepare_method_call(ctx, -1, "removeAllListeners"); // [immediate][spawnedProcess][stderr][removeAll][this] 
		duk_pcall_method(ctx, 0); duk_pop_2(ctx);				// [immediate][spawnedProcess]
	}
	duk_prepare_method_call(ctx, -1, "removeAllListeners");		// [immediate][spawnedProcess][removeAll][this]
	duk_pcall_method(ctx, 0); duk_pop_3(ctx);					// ...
}
duk_ret_t ILibDuktape_SpawnedProcess_exitHandler(duk_context *ctx)
{
	void *i = ILibDuktape_Immediate(ctx, (void*[]) { ctx }, 1, ILibDuktape_SpawnedProcess_exitHandler_immediateSink);
	duk_push_heapptr(ctx, i);					// [immediate]
	duk_push_this(ctx);							// [immediate][spawnedProcess]
	duk_put_prop_string(ctx, -2, "process");	// [immediate]
	duk_pop(ctx);								// ...
	return(0);
}
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
		duk_dup(ctx, -2); duk_put_prop_string(ctx, -2, "parent");
		retVal->stdOut = ILibDuktape_ReadableStream_Init(ctx, ILibDuktape_ChildProcess_SubProcess_StdOut_OnPause, ILibDuktape_ChildProcess_SubProcess_StdOut_OnResume, retVal);
		ILibDuktape_CreateReadonlyProperty(ctx, "stdout");

		duk_push_object(ctx);
		ILibDuktape_WriteID(ctx, "childProcess.subProcess.stderr");
		duk_dup(ctx, -2); duk_put_prop_string(ctx, -2, "parent");
		retVal->stdErr = ILibDuktape_ReadableStream_Init(ctx, ILibDuktape_ChildProcess_SubProcess_StdErr_OnPause, ILibDuktape_ChildProcess_SubProcess_StdErr_OnResume, retVal);
		ILibDuktape_CreateReadonlyProperty(ctx, "stderr");

		duk_push_object(ctx);
		ILibDuktape_WriteID(ctx, "childProcess.subProcess.stdin");
		duk_dup(ctx, -2); duk_put_prop_string(ctx, -2, "parent");
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
		char tmp[255];
		sprintf_s(tmp, sizeof(tmp), "childProcess (pid=%d)", ILibProcessPipe_Process_GetPID(mProcess));
		ILibProcessPipe_Process_ResetMetadata(mProcess, tmp);
		ILibProcessPipe_Process_AddHandlers(mProcess, 4096, ILibDuktape_ChildProcess_SubProcess_ExitHandler,
			ILibDuktape_ChildProcess_SubProcess_StdOutHandler,
			ILibDuktape_ChildProcess_SubProcess_StdErrHandler,
			ILibDuktape_ChildProcess_SubProcess_SendOK, retVal);
	}

#if defined(_POSIX)
	ILibDuktape_EventEmitter_SetupOn(ctx, ILibDuktape_GetProcessObject(ctx), "SIGCHLD");	// [child][on][process][SIGCHLD]
	duk_push_c_function(ctx, ILibDuktape_SpawnedProcess_SIGCHLD_sink, DUK_VARARGS);			// [child][on][process][SIGCHLD][func]
	duk_dup(ctx, -5);																		// [child][on][process][SIGCHLD][func][child]
	duk_put_prop_string(ctx, -2, "_child");													// [child][on][process][SIGCHLD][func]
	duk_dup(ctx, -1);																		// [child][on][process][SIGCHLD][func][func]
	duk_put_prop_string(ctx, -6, "_sigsink");												// [child][on][process][SIGCHLD][func]
	duk_pcall_method(ctx, 2); duk_pop(ctx);													// [child]
#endif

	ILibDuktape_CreateEventWithSetterEx(ctx, "descriptorMetadata", ILibDuktape_SpawnedProcess_descriptorSetter);
	if (callback != NULL) { ILibDuktape_EventEmitter_AddOnce(emitter, "exit", callback); }

	ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "exit", ILibDuktape_SpawnedProcess_exitHandler);
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

	if (nargs > 32) { return(ILibDuktape_Error(ctx, "Too many parameters")); }

	for (i = 0; i < nargs; ++i)
	{
		if (duk_is_array(ctx, i) != 0)
		{
			if (duk_get_length(ctx, i) > 255) { return(ILibDuktape_Error(ctx, "Array too big")); }
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
	p = ILibProcessPipe_Manager_SpawnProcessEx4(manager, target, args, spawnType, (void*)(ILibPtrCAST)(uint64_t)(uid < 0 ? 0 : uid), envargs, 0);
#else
	p = ILibProcessPipe_Manager_SpawnProcessEx4(manager, target, args, spawnType, (void*)(ILibPtrCAST)(uint64_t)uid, envargs, 0);
#endif
	if (p == NULL)
	{
		return(ILibDuktape_Error(ctx, "child_process.execFile(): Could not exec [%s]", target));
	}
	ILibDuktape_ChildProcess_SpawnedProcess_PUSH(ctx, p, callback);
	if (g_displayFinalizerMessages)
	{
		printf("++++ childProcess.subProcess (pid: %u, %s) [%p]\n", ILibProcessPipe_Process_GetPID(p), target, duk_get_heapptr(ctx, -1));
		duk_push_sprintf(ctx, "%s ", target);			// [string]
		if (duk_is_array(ctx, 1))
		{
			int z;
			duk_prepare_method_call(ctx, -1, "concat");		// [string][concat][this]
			duk_push_global_object(ctx);					// [string][concat][this][g]
			duk_get_prop_string(ctx, -1, "JSON");			// [string][concat][this][g][JSON]
			duk_prepare_method_call(ctx, -1, "stringify");	// [string][concat][this][g][JSON][serialize][this]
			duk_dup(ctx, 1);								// [string][concat][this][g][JSON][serialize][this][array]
			z=duk_pcall_method(ctx, 1);						// [string][concat][this][g][JSON][string]
			duk_remove(ctx, -2); duk_remove(ctx, -2);		// [string][concat][this][string]
			z=duk_pcall_method(ctx, 1);						// [string][string]
			duk_remove(ctx, -2);							// [string]
		}
		duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_FinalizerDebugMessage);
	}
	duk_push_string(ctx, target); duk_put_prop_string(ctx, -2, "_target");
	duk_push_pointer(ctx, manager); duk_put_prop_string(ctx, -2, ILibDuktape_ChildProcess_Manager);
	return(1);
}

duk_ret_t ILibDuktape_ChildProcess_execve(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int i;

	void **args = NULL;
	void **env = NULL;
	char *path = (char*)duk_require_string(ctx, 0);
#ifdef WIN32
	int tmplen;
	WCHAR* wtmp;
#endif

	if (nargs < 3 || !(duk_is_object(ctx, 2) && duk_has_prop_string(ctx, 2, "env")))
	{
		duk_push_this(ctx);								// [childprocess]
		duk_prepare_method_call(ctx, -1, "_execve");	// [childprocess][execve][this]
		duk_dup(ctx, 0); duk_dup(ctx, 1);				// [childprocess][execve][this][path][parms]
		if (nargs > 2 && duk_is_object(ctx, 2))
		{
			duk_dup(ctx, 2);							// [childprocess][execve][this][path][parms][options]
		}
		else
		{
			duk_push_object(ctx);						// [childprocess][execve][this][path][parms][options]
		}
		duk_eval_string(ctx, "process.env");			// [childprocess][execve][this][path][parms][options][env]
		duk_put_prop_string(ctx, -2, "env");			// [childprocess][execve][this][path][parms][options]
		duk_call_method(ctx, 3);
		return(ILibDuktape_Error(ctx, "execve() error"));
	}

	duk_push_array(ctx);																	// [WCHAR_ARRAY]
	args = (void**)ILibMemory_SmartAllocate(sizeof(char*) * (1 + duk_get_length(ctx, 1)));
	for (i = 0; i < (int)duk_get_length(ctx, 1); ++i)
	{
		duk_get_prop_index(ctx, 1, (duk_uarridx_t)i);										// [WCHAR_ARRAY][arg]
		args[i] = (void*)duk_get_string(ctx, -1);
#ifdef WIN32
		tmplen = ILibUTF8ToWideCount((char*)args[i]);
		wtmp = (WCHAR*)duk_push_fixed_buffer(ctx, sizeof(WCHAR) * tmplen);					// [WCHAR_ARRAY][arg][buffer]
		duk_array_push(ctx, -3);															// [WCHAR_ARRAY][arg]
		args[i] = (void*)ILibUTF8ToWideEx((char*)args[i], -1, wtmp, tmplen);				// [WCHAR_ARRAY][arg]
#endif
		duk_pop(ctx);																		// [WCHAR_ARRAY]
	}
	if (nargs > 2 && duk_is_object(ctx, 2) && duk_has_prop_string(ctx, 2, "env"))
	{
		duk_get_prop_string(ctx, 2, "env");														// [WCHAR_ARRAY][obj]

		duk_push_array(ctx);																	// [WCHAR_ARRAY][obj][array]
		duk_enum(ctx, -2, DUK_ENUM_OWN_PROPERTIES_ONLY);										// [WCHAR_ARRAY][obj][array][enum]
		while (duk_next(ctx, -1, 1))															// [WCHAR_ARRAY][obj][array][enum][key][value]
		{
			duk_push_sprintf(ctx, "%s=%s", duk_get_string(ctx, -2), duk_get_string(ctx, -1));	// [WCHAR_ARRAY][obj][array][enum][key][value][string]
			duk_array_push(ctx, -5);															// [WCHAR_ARRAY][obj][array][enum][key][value]
			duk_pop_2(ctx);																		// [WCHAR_ARRAY][obj][array][enum]
		}
		duk_pop(ctx);																			// [WCHAR_ARRAY][obj][array]

		env = (void**)ILibMemory_SmartAllocate(sizeof(char*) * (1 + duk_get_length(ctx, -1)));
		for (i = 0; i < (int)duk_get_length(ctx, -1); ++i)
		{
			duk_get_prop_index(ctx, -1, (duk_uarridx_t)i);										// [WCHAR_ARRAY][obj][array][arg]
			env[i] = (char*)duk_get_string(ctx, -1);
#ifdef WIN32
			tmplen = ILibUTF8ToWideCount((char*)env[i]);
			wtmp = (WCHAR*)duk_push_fixed_buffer(ctx, tmplen * sizeof(WCHAR));					// [WCHAR_ARRAY][obj][array][arg][buffer]
			duk_array_push(ctx, -5);															// [WCHAR_ARRAY][obj][array][arg]
			env[i] = (void*)ILibUTF8ToWideEx((char*)env[i], -1, wtmp, tmplen);
#endif
			duk_pop(ctx);																		// [WCHAR_ARRAY][obj][array]
		}
	}

#ifndef WIN32

	//
	// We must close all open descriptors first, since the "new" process will have no idea about any that are still open
	//
	if (nargs > 2 && duk_is_object(ctx, 2) && Duktape_GetBooleanProperty(ctx, 2, "close", 1) != 0)
	{
		int d;
		duk_eval_string(ctx, "require('util-descriptors').getOpenDescriptors();");	// [array]
		while (duk_get_length(ctx, -1) > 0)
		{
			duk_array_pop(ctx, -1);													// [array][fd]
			d = duk_get_int(ctx, -1); duk_pop(ctx);									// [array]
			if (d > 2) { close(d); }												// [array]
		}
	}
	execve(path, (char**)args, (char**)env);
	return(ILibDuktape_Error(ctx, "_execve() returned error: %d ", errno));
#else
	if (_wexecve(ILibUTF8ToWide(path, -1), (WCHAR**)args, (WCHAR**)env) < 0)
	{
		return(ILibDuktape_Error(ctx, "_wexecve() failed"));
	}
	else
	{
		_exit(0);
	}
#endif
}
void ILibDuktape_ChildProcess_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_WriteID(ctx, "childProcess");
	duk_push_pointer(ctx, (void*)ILibProcessPipe_Manager_Create(chain));
	duk_put_prop_string(ctx, -2, ILibDuktape_ChildProcess_Manager);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_ChildProcess_Manager_Finalizer);

	ILibDuktape_CreateInstanceMethod(ctx, "execFile", ILibDuktape_ChildProcess_execFile, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "_execve", ILibDuktape_ChildProcess_execve, DUK_VARARGS);

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
