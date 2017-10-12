#include "duktape.h"

#if defined(WINSOCK2)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "microstack/ILibParsers.h"
#include "microstack/ILibProcessPipe.h"
#include "ILibDuktape_ProcessPipe.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_DuplexStream.h"
#include "ILibDuktapeModSearch.h"

#define ILibDuktape_ProcessPipe_Process_ErrorStreamPtr			"\xFF_ErrorStreamPtr"
#define ILibDuktape_ProcessPipe_Process_ErrorStreamPtrNative	"\xFF_ErrorStreamPtrNative"
#define ILibDuktape_ProcessPipe_Process_PTR						"\xFFProcessPtr"

ILibTransport_DoneState ILibDuktape_ProcessPipe_Process_JSOnWrite(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	// Called when JavaScript has written bytes to this object

	ILibProcessPipe_Process mProcess = (ILibProcessPipe_Process)user;
	return(ILibProcessPipe_Process_WriteStdIn(mProcess, buffer, bufferLen, ILibTransport_MemoryOwnership_USER));
}
void ILibDuktape_ProcessPipe_Process_JSOnEnd(ILibDuktape_DuplexStream *stream, void *user)
{
	// Called when JavaScript has specified that it will no longer write data

	ILibProcessPipe_Process mProcess = (ILibProcessPipe_Process)user;

	if (mProcess != NULL)
	{
		ILibProcessPipe_Process_KillEx(mProcess);

		duk_push_heapptr(stream->readableStream->ctx, stream->ParentObject);						// [process]
		duk_del_prop_string(stream->readableStream->ctx, -1, ILibDuktape_ProcessPipe_Process_PTR);
		duk_pop(stream->readableStream->ctx);
		ILibProcessPipe_Process_UpdateUserObject(mProcess, NULL);
		stream->user = NULL;
	}
}
void ILibDuktape_ProcessPipe_Process_JSPause(ILibDuktape_DuplexStream *sender, void *user)
{
	// Called when either JavaScript called Pause, or JavaScript has not attached a reader yet

	ILibProcessPipe_Process mProcess = (ILibProcessPipe_Process)user;
	ILibProcessPipe_Pipe_Pause(ILibProcessPipe_Process_GetStdOut(mProcess));
}
void ILibDuktape_ProcessPipe_Process_JSResume(ILibDuktape_DuplexStream *sender, void *user)
{
	// Called when JavaScript called Resume

	ILibProcessPipe_Process mProcess = (ILibProcessPipe_Process)user;
	ILibProcessPipe_Pipe_Resume(ILibProcessPipe_Process_GetStdOut(mProcess));
}

void ILibDuktape_ProcessPipe_Process_OnExit(ILibProcessPipe_Process sender, int exitCode, void* user)
{
	if (user == NULL) { return; }

	// Called when process has exited
	ILibDuktape_DuplexStream* stream = (ILibDuktape_DuplexStream*)user;
	ILibProcessPipe_Process_UpdateUserObject(sender, NULL);

	ILibDuktape_DuplexStream_WriteEnd(stream);
	duk_push_heapptr(stream->readableStream->ctx, stream->ParentObject);						// [process]
	duk_del_prop_string(stream->readableStream->ctx, -1, ILibDuktape_ProcessPipe_Process_PTR);
	duk_pop(stream->readableStream->ctx);

}
void ILibDuktape_ProcessPipe_Process_OnStdOut(ILibProcessPipe_Process sender, char *buffer, int bufferLen, int* bytesConsumed, void* user)
{
	if (user == NULL) { return; }

	// Called when process has written data
	ILibDuktape_DuplexStream* ds = (ILibDuktape_DuplexStream*)user;
	ILibDuktape_DuplexStream_WriteData(ds, buffer, bufferLen);
	*bytesConsumed = bufferLen;
}
void ILibDuktape_ProcessPipe_Process_OnStdErr(ILibProcessPipe_Process sender, char *buffer, int bufferLen, int* bytesConsumed, void* user)
{
	if (user == NULL) { return; }

	// Called when process has written error data
	ILibDuktape_DuplexStream* ds = (ILibDuktape_DuplexStream*)user;
	ILibDuktape_readableStream *rs;
	duk_push_heapptr(ds->readableStream->ctx, ds->ParentObject);											// [process]
	duk_get_prop_string(ds->readableStream->ctx, -1, ILibDuktape_ProcessPipe_Process_ErrorStreamPtrNative);	// [process][error]
	rs = (ILibDuktape_readableStream*)duk_get_pointer(ds->readableStream->ctx, -1);

	ILibDuktape_readableStream_WriteData(rs, buffer, bufferLen);
	*bytesConsumed = bufferLen;
}
void ILibDuktape_ProcessPipe_Process_OnSendOK(ILibProcessPipe_Process sender, void* user)
{
	if (user == NULL) { return; }
	//ToDo: Finish this
}
duk_ret_t ILibDuktape_ProcessPipe_Process_Finalizer(duk_context *ctx)
{
	ILibProcessPipe_Process mProcess;

	duk_dup(ctx, 0);
	duk_get_prop_string(ctx, -1, ILibDuktape_ProcessPipe_Process_PTR);
	mProcess = (ILibProcessPipe_Process)duk_get_pointer(ctx, -1);

	if (mProcess != NULL)
	{
		ILibProcessPipe_Process_UpdateUserObject(mProcess, NULL);
		ILibProcessPipe_Process_KillEx(mProcess);
	}

	if (duk_has_prop_string(ctx, 0, ILibDuktape_DuplexStream_bufferPtr))
	{
		duk_get_prop_string(ctx, 0, ILibDuktape_DuplexStream_bufferPtr);
		memset(Duktape_GetBuffer(ctx, -1, NULL), 0, sizeof(ILibDuktape_DuplexStream));
	}

	return 0;
}
void ILibDuktape_ProcessPipe_ErrorStream_Pause(struct ILibDuktape_readableStream *sender, void *user)
{
	ILibProcessPipe_Process mProcess = (ILibProcessPipe_Process)user;
	ILibProcessPipe_Pipe_Pause(ILibProcessPipe_Process_GetStdErr(mProcess));
}
void ILibDuktape_ProcessPipe_ErrorStream_Resume(struct ILibDuktape_readableStream *sender, void *user)
{
	ILibProcessPipe_Process mProcess = (ILibProcessPipe_Process)user;
	ILibProcessPipe_Pipe_Resume(ILibProcessPipe_Process_GetStdErr(mProcess));
}
duk_ret_t ILibDuktape_ProcessPipe_ErrorStream_Getter(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_ProcessPipe_Process_ErrorStreamPtr);
	return 1;
}
duk_ret_t ILibDuktape_ProcessPipe_CreateProcess(duk_context *ctx)
{
	ILibProcessPipe_Manager pipeManager;
	ILibProcessPipe_Process mProcess;
	ILibDuktape_DuplexStream* ds;
	ILibDuktape_readableStream *rs;
	duk_size_t targetLen;
	int nargs = duk_get_top(ctx);
	char *target;
	char **params = NULL;
	int i, x;
	ILibProcessPipe_SpawnTypes asUser = ILibProcessPipe_SpawnTypes_DEFAULT;

	if (nargs < 1) { duk_push_string(ctx, "ProcessPipe.CreateProcess: Invalid number of args"); duk_throw(ctx); return(DUK_RET_ERROR); }

	// Parse Parameters
	target = (char*)duk_get_lstring(ctx, 0, &targetLen);
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

	if (nargs > 1)
	{
		x = 0;
		params = (char**)ILibMemory_Allocate((nargs * sizeof(char*)), 0, NULL, NULL);
		for (i = 1; i < nargs; ++i)
		{
			if (duk_is_number(ctx, i))
			{
				asUser = (ILibProcessPipe_SpawnTypes)duk_require_int(ctx, i);
			}
			else
			{
				params[x++] = (char*)duk_require_string(ctx, i);
			}
		}
		params[x] = NULL;
	}

	duk_push_this(ctx);																				// [manager]
	duk_get_prop_string(ctx, -1, "\xFFPipeManager");												// [manager][pipeManager]
	pipeManager = (ILibProcessPipe_Manager)duk_get_pointer(ctx, -1);
	
	mProcess = ILibProcessPipe_Manager_SpawnProcessEx(pipeManager, target, params, asUser);
	if (params != NULL) { free(params); }
	if (mProcess != NULL)
	{
		duk_push_object(ctx);																			// [manager][pipeManager][retVal]	
		duk_push_pointer(ctx, mProcess);																// [manager][pipeManager][retVal][process]
		duk_put_prop_string(ctx, -2, ILibDuktape_ProcessPipe_Process_PTR);								// [manager][pipeManager][retVal]
		ILibDuktape_CreateReadonlyProperty_int(ctx, "pid", ILibProcessPipe_Process_GetPID(mProcess));


		ds = ILibDuktape_DuplexStream_Init(ctx, ILibDuktape_ProcessPipe_Process_JSOnWrite,
			ILibDuktape_ProcessPipe_Process_JSOnEnd, ILibDuktape_ProcessPipe_Process_JSPause,
			ILibDuktape_ProcessPipe_Process_JSResume, mProcess);
		ILibDuktape_CreateFinalizer(ctx, ILibDuktape_ProcessPipe_Process_Finalizer);

		ILibProcessPipe_Process_AddHandlers(mProcess, 4096, ILibDuktape_ProcessPipe_Process_OnExit,
			ILibDuktape_ProcessPipe_Process_OnStdOut, ILibDuktape_ProcessPipe_Process_OnStdErr,
			ILibDuktape_ProcessPipe_Process_OnSendOK, ds);

		duk_push_object(ctx);																			// [manager][pipeManager][retVal][error]
		ILibDuktape_CreateEventWithGetterEx(ctx, "parent", duk_get_heapptr(ctx, -2));
		rs = ILibDuktape_ReadableStream_Init(ctx, ILibDuktape_ProcessPipe_ErrorStream_Pause, ILibDuktape_ProcessPipe_ErrorStream_Resume, mProcess);
		duk_put_prop_string(ctx, -2, ILibDuktape_ProcessPipe_Process_ErrorStreamPtr);					// [manager][pipeManager][retVal]
		ILibDuktape_CreateEventWithGetter(ctx, "error", ILibDuktape_ProcessPipe_ErrorStream_Getter);
		duk_push_pointer(ctx, rs);																		// [manager][pipeManager][retVal][ptr]
		duk_put_prop_string(ctx, -2, ILibDuktape_ProcessPipe_Process_ErrorStreamPtrNative);				// [manager][pipeManager][retVal]
	}
	else
	{
		duk_push_null(ctx);
	}
	return 1;
}

duk_ret_t ILibDuktape_ProcessPipe_Finalizer(duk_context *ctx)
{
	ILibProcessPipe_Manager *pipeManager;

	duk_dup(ctx, 0);													// [obj]
	duk_get_prop_string(ctx, -1, "\xFFPipeManager");					// [obj][manager]
	pipeManager = (ILibProcessPipe_Manager)duk_get_pointer(ctx, -1);

	ILibChain_SafeRemove(((ILibChain_Link*)pipeManager)->ParentChain, pipeManager);

	return 0;
}
void ILibDuktape_ProcessPipe_PUSH(duk_context *ctx, void *chain)
{
	ILibProcessPipe_Manager pipeManager = ILibProcessPipe_Manager_Create(chain);

	duk_push_object(ctx);								// [obj]
	duk_push_pointer(ctx, pipeManager);					// [obj][pipeManager]
	duk_put_prop_string(ctx, -2, "\xFFPipeManager");	// [obj]
	ILibDuktape_CreateInstanceMethod(ctx, "CreateProcess", ILibDuktape_ProcessPipe_CreateProcess, DUK_VARARGS);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_ProcessPipe_Finalizer);
	Duktape_CreateEnum(ctx, "ILibProcessPipe_SpawnTypes", (char*[]) { "DEFAULT", "USER", "WINLOGON", "TERM" }, (int[]) { 0, 1, 2, 3 }, 4);
}
void ILibDuktape_ProcessPipe_Init(duk_context * ctx, void * chain)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "ILibProcessPipe", ILibDuktape_ProcessPipe_PUSH);
}
