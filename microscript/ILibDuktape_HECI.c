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

#include "ILibDuktape_HECI.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_DuplexStream.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktape_ChildProcess.h"
#include "../microstack/ILibParsers.h"
#include "../microstack/ILibProcessPipe.h"
#include "../microstack/ILibRemoteLogging.h"


#ifdef WIN32
#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <winioctl.h>
DEFINE_GUID(GUID_DEVINTERFACE_HECI, 0xE2D1FF34, 0x3458, 0x49A9, 0x88, 0xDA, 0x8E, 0x69, 0x15, 0xCE, 0x9B, 0xE5);
#elif defined(_POSIX)
typedef struct HECI_client 
{
	unsigned int max_msg_length;
	unsigned char protocol_version;
	unsigned char reserved[3];
}HECI_client;
typedef struct uuid_le
{
	unsigned char b[16];
}uuid_le;
struct HECI_CONNECT_client_data
{
	union
	{
		uuid_le uuid;
		HECI_client properties;
	};
};
#endif

#define ILibDuktape_HECI_ChainLink			"\xFF_HECI_ChainLink"
#define ILibDuktape_HECI_Descriptor			"\xFF_HECI_Descriptor"
#define ILibDuktape_HECI_ChildProcess		"\xFF_HECI_ChildProcess"
#define ILibDuktape_HECI_Q					"\xFF_HECI_Q"
#define ILibDuktape_HECI_IoctlWaitHandle	"\xFF_HECI_IoctlWaitHandle"
#define ILibDuktape_HECI_Child				"\xFF_HECI_Child"
#define ILibDuktape_HECI_Parent				"\xFF_HECI_Parent"
#define ILibDuktape_HECI_MaxBufferSize		"\xFF_HECI_MaxBufSize"
#define ILibDuktape_HECI_SessionMemPtr		"\xFF_HECI_SessionMemPtr"
#define ILibDuktape_HECI_Session_NoPipeline	"\xFF_HECI_Session_NoPipeline"

#ifdef __DOXY__
/*!
\implements EventEmitter
\brief JavaScript object interface for HECI calls. <b>require('heci')</b> to use;
*/
class Heci
{
public:
	/*!
	\brief Performs an Ioctl on the HECI device
	\param code <Integer> Ioctl Code to invoke
	\param inBuffer \<Buffer\> Input data for Ioctl. Can be null
	\param outBuffer \<Buffer\> Optional. Output data from Ioctl. Must be specified if Ioctl code returns data
	\param callback <Function> Dispatched when a response is received from the HECI device\n
	status <Integer> Success Code. 0 = Success, Error code on failure\n
	buffer \<Buffer\> Output Buffer\n
	args <Any> Optional parameters that were passed in\n
	\param args <any> Optional arguments to pass when the callback is called
	*/
	void doIoctl(code, inBuffer[, outBuffer], callback[, ...args]);
};
#endif

typedef struct ILibDuktape_HECI_ioctl_data
{
	duk_context *ctx;
	void *heciObject;
	void *data;
	void *Q;
	void *chain;
	ILibProcessPipe_Manager pipeManager;
#ifdef WIN32
	OVERLAPPED v;
	HANDLE device;
	DWORD bytesReceived;
#elif defined(_POSIX)
	int device;
#endif

	int code;
	char *outBuffer;
	void *outBuffer_obj;
	duk_size_t outBufferLen;
	duk_size_t bufferLen;
	char buffer[];
}ILibDuktape_HECI_ioctl_data;

typedef struct ILibDuktape_HECI_Session
{
	void *chain;
	int noPipelining;
	ILibDuktape_DuplexStream *stream;
#ifdef WIN32
	OVERLAPPED v;
	OVERLAPPED wv;
	ILibProcessPipe_Manager mgr;
	HANDLE descriptor;
	DWORD bytesRead;
#else
	int descriptor;
#endif
	ILibQueue PendingWrites;
	duk_size_t bufferSize;
	char buffer[];
}ILibDuktape_HECI_Session;
typedef struct ILibDuktape_HECI_WriteState
{
	ILibDuktape_HECI_Session *session;
	int returnIgnored;
#ifndef WIN32
	int bufferOffset;
#endif
	int bufferLen;
	char buffer[];
}ILibDuktape_HECI_WriteState;

typedef struct HECI_chainLink
{
	ILibChain_Link link;
	duk_context *ctx;
	void *Q;
	ILibDuktape_HECI_Session *session;
	void *heciObject;
	int descriptor;
	int paused;
}HECI_chainLink;

void ILibDuktape_HECI_Push(duk_context *ctx, void *chain);
ILibTransport_DoneState ILibDuktape_HECI_Session_WriteHandler_Process(ILibDuktape_HECI_Session *session);

#ifdef WIN32
HANDLE ILibDuktape_HECI_windowsInit()
{
	PSP_DEVICE_INTERFACE_DETAIL_DATA deviceDetail = NULL;
    HDEVINFO hDeviceInfo;
    DWORD bufferSize;
	SP_DEVICE_INTERFACE_DATA interfaceData;  
    LONG ii = 0;
	HANDLE retVal = NULL;

	// Find all devices that have our interface
	hDeviceInfo = SetupDiGetClassDevs((LPGUID)&GUID_DEVINTERFACE_HECI, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDeviceInfo == INVALID_HANDLE_VALUE) 
	{        
		return(NULL);
    }

	// Setup the interface data struct
    interfaceData.cbSize = sizeof(interfaceData);
	for (ii = 0; 
         SetupDiEnumDeviceInterfaces(hDeviceInfo, NULL, (LPGUID)&GUID_DEVINTERFACE_HECI, ii, &interfaceData);
         ++ii) 
	{
        // Found our device instance
        if (!SetupDiGetDeviceInterfaceDetail(hDeviceInfo, &interfaceData, NULL,  0, &bufferSize, NULL)) 
		{
			DWORD err = GetLastError();
            if (err != ERROR_INSUFFICIENT_BUFFER) 
			{
                continue;
            }
        }

        // Allocate a big enough buffer to get detail data
		deviceDetail = (PSP_DEVICE_INTERFACE_DETAIL_DATA)ILibMemory_AllocateA(bufferSize);
		if (deviceDetail == NULL) { continue; }

        // Setup the device interface struct
        deviceDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        // Try again to get the device interface detail info
        if (!SetupDiGetDeviceInterfaceDetail(hDeviceInfo, &interfaceData, deviceDetail, bufferSize, NULL, NULL))
		{
			deviceDetail = NULL;
            continue;
        }

		break;
    }
	SetupDiDestroyDeviceInfoList(hDeviceInfo);

	if (deviceDetail == NULL) { return(NULL); }

	retVal = CreateFile(deviceDetail->DevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (retVal == INVALID_HANDLE_VALUE) { return(NULL); }

	return(retVal);
}
#else
int ILibDuktape_HECI_linuxInit()
{
	int fd, flags;

	if ((fd = open("/dev/mei", O_RDWR)) == -1 && (fd = open("/dev/mei0", O_RDWR)) == -1)
	{
		return(-1);
	}
	else
	{
		flags = fcntl(fd, F_GETFL, 0);
		if (fcntl(fd, F_SETFL, O_NONBLOCK | flags) == -1) { printf("Failed to set O_NONBLOCK\n"); close(fd); fd = -1; }
		return(fd);
	}
}
#endif

duk_ret_t ILibDuktape_HECI_SessionFinalizer(duk_context *ctx)
{
	if (duk_has_prop_string(ctx, 0, ILibDuktape_HECI_SessionMemPtr))
	{
		duk_get_prop_string(ctx, 0, ILibDuktape_HECI_SessionMemPtr);
		ILibDuktape_HECI_Session *s = (ILibDuktape_HECI_Session*)Duktape_GetBuffer(ctx, -1, NULL);
		if (s != NULL && s->PendingWrites != NULL) { ILibQueue_Destroy(s->PendingWrites); } // ToDo: If there is anything pending, we need to clear that too
		if (s != NULL) { s->stream = NULL; }
	}
	return(0);
}


void ILibDuktape_HECI_Session_EmitErrorEvent(void *chain, void *session)
{
	if (ILibIsRunningOnChainThread(chain) == 0) { ILibChain_RunOnMicrostackThreadEx(chain, ILibDuktape_HECI_Session_EmitErrorEvent, session); return; }
	ILibDuktape_HECI_Session *s = (ILibDuktape_HECI_Session*)session;
	duk_context *ctx = s->stream->readableStream->ctx;

	duk_push_heapptr(ctx, s->stream->ParentObject);							// [session]
	duk_get_prop_string(ctx, -1, "emit");									// [session][emit]
	duk_swap_top(ctx, -2);													// [emit][this]
	duk_push_string(ctx, "error");											// [emit][this][error]
	duk_push_error_object(ctx, DUK_ERR_ERROR, "HECI Connection Error");		// [emit][this][error][err]
	if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "HECI.session.onError(): "); }
	duk_pop(ctx);															// ...
}
void ILibDuktape_HECI_Session_EmitStreamReady(void *chain, void *session)
{
	if (ILibIsRunningOnChainThread(chain) == 0) { ILibChain_RunOnMicrostackThreadEx(chain, ILibDuktape_HECI_Session_EmitStreamReady, session); return; }
	ILibDuktape_DuplexStream_Ready(((ILibDuktape_HECI_Session*)session)->stream);
}

#ifdef WIN32
BOOL ILibDuktape_HECI_Session_WriteHandler_Ready(HANDLE event, ILibWaitHandle_ErrorStatus errors, void* user)
{
	if (errors != ILibWaitHandle_ErrorStatus_NONE) { return(FALSE); }

	ILibDuktape_HECI_Session *session = (ILibDuktape_HECI_Session*)user;
	DWORD bytesWritten;

	if (!ILibMemory_CanaryOK(session)) { return(FALSE); }

	ILibProcessPipe_WaitHandle_Remove(session->mgr, session->wv.hEvent);
	
	if (session->noPipelining == 0)
	{
		ILibDuktape_HECI_WriteState *state = (ILibDuktape_HECI_WriteState*)ILibQueue_DeQueue(session->PendingWrites);
		free(state);
	}

	if (GetOverlappedResult(session->descriptor, &(session->wv), &bytesWritten, FALSE) == 0)
	{
		// Broken Connection
		ILibDuktape_HECI_Session_EmitErrorEvent(session->chain, (void*)session);
	}
	else
	{
		if (session->noPipelining == 0)
		{
			// Write Completed
			ILibDuktape_HECI_Session_WriteHandler_Process(session);
		}
	}
	return(TRUE);
}
#endif

ILibTransport_DoneState ILibDuktape_HECI_Session_WriteHandler_Process(ILibDuktape_HECI_Session *session)
{
	ILibTransport_DoneState retVal = ILibTransport_DoneState_ERROR;
	int returnIgnored = 0;

#ifdef WIN32
	DWORD bytesWritten;
	BOOL result = TRUE;
#else
	ssize_t bytesWritten;
#endif

	while (session->noPipelining || ILibQueue_GetCount(session->PendingWrites) > 0)
	{
		ILibDuktape_HECI_WriteState *state = (ILibDuktape_HECI_WriteState*)ILibQueue_PeekQueue(session->PendingWrites);
		returnIgnored = state->returnIgnored;

#ifdef WIN32
		if ((result = WriteFile(state->session->descriptor, state->buffer, state->bufferLen, &bytesWritten, &(state->session->wv))) == TRUE)
		{
			if (session->noPipelining == 0) { ILibQueue_DeQueue(state->session->PendingWrites); free(state); }
		}
		else
		{
			break;
		}
#elif defined(_POSIX)

		bytesWritten = write(state->session->descriptor, state->buffer + state->bufferOffset, state->bufferLen - state->bufferOffset);
		if (bytesWritten > 0)
		{
			state->bufferOffset += bytesWritten;
			if (state->bufferOffset == state->bufferLen) { ILibQueue_DeQueue(state->session->PendingWrites); free(state); retVal = session->noPipelining == 0 ? ILibTransport_DoneState_COMPLETE:ILibTransport_DoneState_INCOMPLETE; }
		}
		else
		{
			if (errno != EAGAIN)
			{
				// Error Occured
				retVal = ILibTransport_DoneState_ERROR;
				ILibDuktape_HECI_Session_EmitErrorEvent(session->chain, (void*)session);
			}
			else
			{
				retVal = ILibTransport_DoneState_INCOMPLETE;
			}
			break;
		}
#endif

		if (session->noPipelining != 0) { break; }
	}

#ifdef WIN32
	if (result == FALSE)
	{
		if (GetLastError() == ERROR_IO_PENDING)
		{
			// Not done writing
			retVal = ILibTransport_DoneState_INCOMPLETE;
			ILibProcessPipe_WaitHandle_Add(session->mgr, session->wv.hEvent, session, ILibDuktape_HECI_Session_WriteHandler_Ready);
		}
		else
		{
			// Error Occured
			retVal = ILibTransport_DoneState_ERROR;
			ILibDuktape_HECI_Session_EmitErrorEvent(session->chain, (void*)session);
		}
	}
	else
	{
		if (session->noPipelining == 0)
		{
			// No more Pending Writes
			retVal = ILibTransport_DoneState_COMPLETE;
			if (returnIgnored != 0) { ILibDuktape_HECI_Session_EmitStreamReady(session->chain, (void*)session); }
		}
		else
		{
			retVal = ILibTransport_DoneState_INCOMPLETE;
		}
	}
#else
	if (ILibQueue_GetCount(session->PendingWrites) == 0 && session->noPipelining == 0)
	{
		// No more Pending Writes
		retVal = ILibTransport_DoneState_COMPLETE;
		if (returnIgnored != 0) { ILibDuktape_HECI_Session_EmitStreamReady(session->chain, (void*)session); }
	}
#endif
	return(retVal);
}

#ifdef WIN32
void __stdcall ILibDuktape_HECI_Session_WriteHandler(ULONG_PTR obj)
{
	// This Method is always dispatched from the WindowsRunLoop APC Thread

	ILibDuktape_HECI_WriteState *state = (ILibDuktape_HECI_WriteState*)obj;
	ILibQueue_EnQueue(state->session->PendingWrites, state);

	if (ILibQueue_GetCount(state->session->PendingWrites) == 1)
	{
		// No Pending Writes, so we can go ahead and send out the first block
		ILibDuktape_HECI_Session_WriteHandler_Process(state->session);
	}
}
#elif defined(_POSIX)
ILibTransport_DoneState ILibDuktape_HECI_Session_WriteHandler(void *chain, ILibDuktape_HECI_WriteState* state)
{
	// This Method is always dispatched from the Microstack Thread
	ILibQueue_EnQueue(state->session->PendingWrites, state);

	if (ILibQueue_GetCount(state->session->PendingWrites) == 1)
	{
		return(ILibDuktape_HECI_Session_WriteHandler_Process(state->session));
	}
	else
	{
		return(ILibTransport_DoneState_INCOMPLETE);
	}
}
#endif

ILibTransport_DoneState ILibDuktape_HECI_Session_WriteSink_NoPipeline(void *chain, void *user)
{
	// This is always called from the Microstack Thread

	ILibDuktape_HECI_WriteState *state = (ILibDuktape_HECI_WriteState*)user;
	ILibQueue_EnQueue(state->session->PendingWrites, state);
	if (ILibQueue_GetCount(state->session->PendingWrites) == 1) 
	{ 
		return(ILibDuktape_HECI_Session_WriteHandler_Process(state->session));
	}
	else
	{
		return(ILibTransport_DoneState_INCOMPLETE);
	}
}
ILibTransport_DoneState ILibDuktape_HECI_Session_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	if ((duk_size_t)bufferLen > ((ILibDuktape_HECI_Session*)user)->bufferSize) { return(ILibTransport_DoneState_ERROR); }
	
	ILibDuktape_HECI_Session *session = (ILibDuktape_HECI_Session*)user;
	ILibDuktape_HECI_WriteState *state = (ILibDuktape_HECI_WriteState*)ILibMemory_Allocate(bufferLen + sizeof(ILibDuktape_HECI_WriteState), 0, NULL, NULL);
	state->session = session;
	state->bufferLen = bufferLen;
	memcpy_s(state->buffer, bufferLen, buffer, bufferLen);
	
	if (session->noPipelining == 0)
	{
#if defined(WIN32)
		state->returnIgnored = 1;
		QueueUserAPC((PAPCFUNC)ILibDuktape_HECI_Session_WriteHandler, ILibProcessPipe_Manager_GetWorkerThread(session->mgr), (ULONG_PTR)state);
#elif defined(_POSIX)
		if (ILibIsRunningOnChainThread(stream->readableStream->chain) != 0)
		{
			return(ILibDuktape_HECI_Session_WriteHandler(NULL, state));
		}
		else
		{
			state->returnIgnored = 1;
			ILibChain_RunOnMicrostackThreadEx(stream->readableStream->chain, (ILibChain_StartEvent)ILibDuktape_HECI_Session_WriteHandler, state);
		}
#endif
	}
	else
	{
		// We can't pipeline write requests
		if (ILibIsRunningOnChainThread(stream->readableStream->chain) != 0)
		{
			return(ILibDuktape_HECI_Session_WriteSink_NoPipeline(stream->readableStream->chain, state));
		}
		else
		{
			state->returnIgnored = 1;
			ILibChain_RunOnMicrostackThreadEx(stream->readableStream->chain, (ILibChain_StartEvent)ILibDuktape_HECI_Session_WriteSink_NoPipeline, state);
		}
	}

	return(ILibTransport_DoneState_INCOMPLETE);
}
void ILibDuktape_HECI_Session_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	duk_context *ctx = stream->readableStream->ctx;
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, "disconnect");
	duk_swap_top(ctx, -2);
	if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtException(ctx); }
	duk_pop(ctx);
}
void ILibDuktape_HECI_Session_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
#ifdef WIN32
	// NO-OP Because we are already PAUSED, since we context switched
	UNREFERENCED_PARAMETER(sender);
	UNREFERENCED_PARAMETER(user);
#else
	UNREFERENCED_PARAMETER(sender);
	UNREFERENCED_PARAMETER(user);
#endif
}
#ifdef WIN32
BOOL ILibDuktape_HECI_Session_ReceiveSink(HANDLE event, ILibWaitHandle_ErrorStatus errors, void* user);
void __stdcall ILibDuktape_HECI_Session_ResumeSink2(ULONG_PTR obj)
{
	ILibDuktape_HECI_Session *session = (ILibDuktape_HECI_Session*)obj;
	BOOL result = ReadFile(session->descriptor, session->buffer, (DWORD)session->bufferSize, &(session->bytesRead), &(session->v));
	if (result == TRUE || GetLastError() == ERROR_IO_PENDING)
	{
		ILibProcessPipe_WaitHandle_Add(session->mgr, session->v.hEvent, session, ILibDuktape_HECI_Session_ReceiveSink);
	}
}
#endif
void ILibDuktape_HECI_Session_ResumeSink_NoPipeline(void *chain, void *user)
{
	// This is always called from the Microstack Thread
	ILibDuktape_HECI_Session *session = (ILibDuktape_HECI_Session*)user;
	ILibDuktape_HECI_WriteState *state = (ILibDuktape_HECI_WriteState*)ILibQueue_DeQueue(session->PendingWrites);
	free(state);

	if (ILibQueue_GetCount(session->PendingWrites) == 0)
	{
		ILibDuktape_HECI_Session_EmitStreamReady(session->chain, session);
	}
	else
	{
		ILibDuktape_HECI_Session_WriteHandler_Process(session);
	}
}
void ILibDuktape_HECI_Session_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_HECI_Session *session = (ILibDuktape_HECI_Session*)user;
	if (session->noPipelining != 0)
	{
		ILibChain_RunOnMicrostackThread(sender->readableStream->chain, ILibDuktape_HECI_Session_ResumeSink_NoPipeline, session);
		// Note: DO NOT 'return' here, because we still need to QueueUserAPC, to resume the stream on Windows
	}

#ifdef WIN32
	// To Resume, we need to first context switch to the Windows Thread
	QueueUserAPC((PAPCFUNC)ILibDuktape_HECI_Session_ResumeSink2, ILibProcessPipe_Manager_GetWorkerThread(session->mgr), (ULONG_PTR)session);
#endif
}
#ifdef WIN32
void ILibDuktape_HECI_Session_ReceiveSink2(void *chain, void *user)
{
	ILibDuktape_HECI_Session *session = (ILibDuktape_HECI_Session*)user;
	if (!ILibMemory_CanaryOK(session)) { return; }

	ILibDuktape_DuplexStream_WriteData(session->stream, session->buffer, session->bytesRead);
	if (session->stream != NULL && !session->stream->readableStream->paused)
	{
		ILibDuktape_HECI_Session_ResumeSink(session->stream, session->stream->user);
	}
}
BOOL ILibDuktape_HECI_Session_ReceiveSink(HANDLE event, ILibWaitHandle_ErrorStatus errors, void* user)
{
	if (errors != ILibWaitHandle_ErrorStatus_NONE) { return(FALSE); }
	ILibDuktape_HECI_Session *session = (ILibDuktape_HECI_Session*)user;
	if (ILibMemory_CanaryOK(session))
	{
		if (GetOverlappedResult(session->descriptor, &(session->v), &(session->bytesRead), FALSE) == TRUE) { ILibChain_RunOnMicrostackThreadEx(session->chain, ILibDuktape_HECI_Session_ReceiveSink2, session); }
	}
	return(FALSE);
}
void __stdcall ILibDuktape_HECI_Session_Start(ULONG_PTR obj)
{
	ILibDuktape_HECI_Session *session = (ILibDuktape_HECI_Session*)obj;
	DWORD bytesRead;
	BOOL result = ReadFile(session->descriptor, session->buffer, (DWORD)session->bufferSize, &bytesRead, &(session->v));
	ILibProcessPipe_WaitHandle_Add(session->mgr, session->v.hEvent, session, ILibDuktape_HECI_Session_ReceiveSink);
}
#endif

duk_ret_t ILibDuktape_HECI_create_OnClientConnect(duk_context *ctx)
{
	int statusCode = duk_require_int(ctx, 0);
	ILibDuktape_HECI_Session *session = NULL;
	duk_dup(ctx, 2);															// [Session]
	if (statusCode != 0) 
	{ 
		duk_get_prop_string(ctx, -1, "emit");									// [session][emit]
		duk_swap_top(ctx, -2);													// [emit][this]
		duk_push_string(ctx, "error");											// [emit][this][error]
		duk_push_error_object(ctx, DUK_ERR_ERROR, "HECI Connection Error [%d]", statusCode);		// [emit][this][error][err]
		duk_push_int(ctx, statusCode); duk_put_prop_string(ctx, -2, "errno");
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "HECI.session.onError(): "); }
		duk_pop(ctx);															// ...
	}	
	else
	{
		duk_size_t bufferLen;
		char *buffer = (char*)Duktape_GetBuffer(ctx, 1, &bufferLen);
		if (bufferLen > 4)
		{
			duk_push_int(ctx, ((int*)buffer)[0]);
			duk_put_prop_string(ctx, -2, ILibDuktape_HECI_MaxBufferSize);														// [session]

			session = (ILibDuktape_HECI_Session*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_HECI_Session) + ((int*)buffer)[0]);	// [session][buffer]
			duk_put_prop_string(ctx, -2, ILibDuktape_HECI_SessionMemPtr);														// [session]
#ifdef WIN32	
			session->v.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
			session->wv.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
#endif
			session->chain = Duktape_GetChain(ctx);														
			session->bufferSize = (duk_size_t)((int*)buffer)[0];										
			session->stream = ILibDuktape_DuplexStream_Init(ctx,										
				ILibDuktape_HECI_Session_WriteSink, ILibDuktape_HECI_Session_EndSink,					
				ILibDuktape_HECI_Session_PauseSink, ILibDuktape_HECI_Session_ResumeSink, session);		
			ILibDuktape_CreateReadonlyProperty_int(ctx, "maxBufferSize", (int)session->bufferSize);
			session->PendingWrites = ILibQueue_Create();
			duk_push_current_function(ctx);
			session->noPipelining = Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_HECI_Session_NoPipeline, 0);
			duk_pop(ctx);
#ifdef _POSIX
			//printf("Session: %p\n", session);
			duk_get_prop_string(ctx, -1, ILibDuktape_HECI_Child);										// [session][heci]
			duk_get_prop_string(ctx, -1, ILibDuktape_HECI_ChainLink);									// [session][heci][link]
			HECI_chainLink *link = (HECI_chainLink*)duk_get_pointer(ctx, -1);
			link->session = session;
			duk_pop_2(ctx);																				// [session]
#endif

			//printf("NoPipeline: %d\n", session->noPipelining);
		}
		else
		{
			// Even tho it was a success, the result buffer is invalid
			duk_get_prop_string(ctx, -1, "emit");									// [session][emit]
			duk_swap_top(ctx, -2);													// [emit][this]
			duk_push_string(ctx, "error");											// [emit][this][error]
			duk_push_error_object(ctx, DUK_ERR_ERROR, "HECI Connection Error");		// [emit][this][error][err]
			if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "HECI.session.onError(): "); }
			duk_pop(ctx);															// ...
		}
	}

	if (session != NULL)
	{
		// Hookup the Send/Receive logic
#ifdef WIN32
		duk_push_this(ctx);													// [HECI]
		session->descriptor = (HANDLE)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_HECI_Descriptor);
		duk_get_prop_string(ctx, -1, ILibDuktape_HECI_ChildProcess);		// [HECI][childProcess]
		duk_get_prop_string(ctx, -1, ILibDuktape_ChildProcess_Manager);		// [HECI][childProcess][manager]
		session->mgr = (ILibProcessPipe_Manager)duk_get_pointer(ctx, -1);	
		QueueUserAPC((PAPCFUNC)ILibDuktape_HECI_Session_Start, ILibProcessPipe_Manager_GetWorkerThread(session->mgr), (ULONG_PTR)session);
#else
		duk_push_this(ctx);													// [HECI]
		session->descriptor = Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_HECI_Descriptor, -1);
		ILibForceUnBlockChain(session->chain);
#endif
		
		duk_dup(ctx, 2);
		duk_get_prop_string(ctx, -1, "emit");									// [session][emit]
		duk_swap_top(ctx, -2);													// [emit][this]
		duk_push_string(ctx, "connect");										// [emit][this][connect]
		if (duk_pcall_method(ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "HECI.session.onConnect(): "); }
		duk_pop(ctx);															// ...

	
	}
	return(0);
}
duk_ret_t ILibDuktape_HECI_Session_connect(duk_context *ctx)
{
	int i;
	int nargs = duk_get_top(ctx);
	duk_push_this(ctx);																// [Session]
	duk_get_prop_string(ctx, -1, ILibDuktape_HECI_Child);							// [Session][HECI]
	duk_remove(ctx, -2);															// [HECI]
	
	duk_get_prop_string(ctx, -1, "doIoctl");										// [HECI][func]
	duk_swap_top(ctx, -2);															// [doIoctl][this]
	duk_get_prop_string(ctx, -1, "IOCTL");											// [doIoctl][this][IOCTL]
	duk_get_prop_string(ctx, -1, "CLIENT_CONNECT");									// [doIoctl][this][IOCTL][CLIENT_CONNECT]
	duk_remove(ctx, -2);															// [doIoctl][this][CLIENT_CONNECT]
	duk_dup(ctx, 0);																// [doIoctl][this][CLIENT_CONNECT][guid]
	duk_push_fixed_buffer(ctx, 16);													// [doIoctl][this][CLIENT_CONNECT][guid][outBuffer]
	duk_push_c_function(ctx, ILibDuktape_HECI_create_OnClientConnect, DUK_VARARGS);	// [doIoctl][this][CLIENT_CONNECT][guid][outBuffer][callback]
	duk_push_int(ctx, 0);
	duk_put_prop_string(ctx, -2, ILibDuktape_HECI_Session_NoPipeline);

	for (i = 1; i < nargs; ++i)
	{
		if (duk_is_function(ctx, i)) { ILibDuktape_EventEmitter_AddOnce(ILibDuktape_EventEmitter_GetEmitter_fromThis(ctx), "connect", duk_require_heapptr(ctx, i)); }
		else if (duk_is_object(ctx, i))
		{
			int noPipeline = Duktape_GetIntPropertyValue(ctx, i, "noPipeline", 0);
			duk_push_int(ctx, noPipeline);
			duk_put_prop_string(ctx, -2, ILibDuktape_HECI_Session_NoPipeline);
		}
	}
	duk_push_this(ctx);																// [doIoctl][this][CLIENT_CONNECT][guid][outBuffer][callback][Session]
	duk_call_method(ctx, 5);														// [retVal]
	duk_pop(ctx);																	// ...
	return(0);
}
#ifdef WIN32
void __stdcall ILibDuktape_HECI_Session_CloseSink2(ULONG_PTR obj)
{
	HANDLE h = (HANDLE)obj;
	CloseHandle(h);
}
#endif
duk_ret_t ILibDuktape_HECI_Session_close(duk_context *ctx)
{
	duk_push_this(ctx);										// [session]

	if (duk_has_prop_string(ctx, -1, ILibDuktape_HECI_Child))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_HECI_Child);	// [session][heci]
		duk_get_prop_string(ctx, -1, "disconnect");				// [session][heci][close]
		duk_swap_top(ctx, -2);									// [session][close][this]
		duk_call_method(ctx, 0);
	}

	duk_push_this(ctx);
#ifdef WIN32
	ILibDuktape_HECI_Session *session = NULL;
	if (duk_has_prop_string(ctx, -1, ILibDuktape_HECI_SessionMemPtr))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_HECI_SessionMemPtr);								// [HECI][SESSION]
		session = (ILibDuktape_HECI_Session*)Duktape_GetBuffer(ctx, -1, NULL);

		ILibProcessPipe_WaitHandle_Remove(session->mgr, session->v.hEvent);
		ILibProcessPipe_WaitHandle_Remove(session->mgr, session->wv.hEvent);
		session->stream = NULL;
		QueueUserAPC((PAPCFUNC)ILibDuktape_HECI_Session_CloseSink2, ILibProcessPipe_Manager_GetWorkerThread(session->mgr), (ULONG_PTR)session->descriptor);
	}
#else
	int d = Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_HECI_Descriptor, -1);
	HECI_chainLink *hcl = (HECI_chainLink*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_HECI_ChainLink);
	if (hcl != NULL)
	{
		hcl->descriptor = -1;
		if (d != -1) { close(d); };
		duk_del_prop_string(ctx, -1, ILibDuktape_HECI_Descriptor);
	}
#endif

	return(0);
}
duk_ret_t ILibDuktape_HECI_create(duk_context *ctx)
{
	duk_push_object(ctx);															// [Session]
	ILibDuktape_WriteID(ctx, "heci.session");
	ILibDuktape_HECI_Push(ctx, NULL);												// [Session][HECI]
	duk_dup(ctx, -2);																// [Session][HECI][Session]
	duk_put_prop_string(ctx, -2, ILibDuktape_HECI_Parent);							// [Session][HECI]
	duk_put_prop_string(ctx, -2, ILibDuktape_HECI_Child);							// [Session]

	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "connect");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "error");
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "connect", ILibDuktape_HECI_Session_connect, DUK_VARARGS);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_HECI_SessionFinalizer);
	ILibDuktape_CreateInstanceMethod(ctx, "disconnect", ILibDuktape_HECI_Session_close, 0);
	return(1);
}


void ILibDuktape_HECI_IoctlHandler_Dispatch(void *chain, void *user)
{
	ILibDuktape_HECI_ioctl_data *data = (ILibDuktape_HECI_ioctl_data*)user;
	duk_size_t count;
	int i;
	duk_context *ctx = data->ctx;

	duk_push_heapptr(data->ctx, data->data);												// [array]
	duk_push_heapptr(data->ctx, data->heciObject);											// [array][heci]
	duk_get_prop_index(data->ctx, -2, 2);													// [array][heci][callback]
	duk_swap_top(data->ctx, -2);															// [array][callback][this]
	count = duk_get_length(data->ctx, -3);	
	duk_push_int(data->ctx, data->code);													// [array][callback][this][status]
	duk_get_prop_index(data->ctx, -4, 1);													// [array][callback][this][status][buffer]

	for (i = 3; i < (int)count; ++i)
	{
		duk_get_prop_index(data->ctx, -i - 2, i);											// [array][callback][this][status][buffer][...args...]
	}
	if (duk_pcall_method(data->ctx, (duk_idx_t)count - 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(data->ctx, "heci.ioctlHandler_Dispatch.callback(): "); }
	duk_pop_2(data->ctx);																	// ...

	duk_push_heapptr(data->ctx, data->heciObject);											// [heci]
	ILibDuktape_Push_ObjectStash(data->ctx);												// [heci][stash]
	duk_del_prop_string(data->ctx, -1, Duktape_GetStashKey(data->data));					// (This will free data internally)
	duk_pop_2(ctx);																			// ...
}
#ifdef WIN32
void ILibDuktape_HECI_NextIoctl(ILibQueue q);
BOOL ILibDuktape_HECI_IoctlHandler(HANDLE h, ILibWaitHandle_ErrorStatus errors, void *user)
{
	if (errors == ILibWaitHandle_ErrorStatus_INVALID_HANDLE) { return(FALSE); }
	ILibDuktape_HECI_ioctl_data *data = (ILibDuktape_HECI_ioctl_data*)user;
	ILibQueue Q = data->Q;

	if (errors == ILibWaitHandle_ErrorStatus_NONE)
	{
		BOOL result = GetOverlappedResult(data->device, &(data->v), &(data->bytesReceived), FALSE);
		data->code = result == TRUE ? 0 : (int)GetLastError();
	}
	else
	{
		data->code = -1;
	}

	ILibQueue_DeQueue(data->Q);
	ILibProcessPipe_WaitHandle_Remove(data->pipeManager, h);
	ILibChain_RunOnMicrostackThread(data->chain, ILibDuktape_HECI_IoctlHandler_Dispatch, data);

	if (ILibQueue_GetCount(Q) > 0)
	{
		void ILibDuktape_HECI_NextIoctl(Q);
	}
	return(TRUE);
}
void ILibDuktape_HECI_NextIoctl(ILibQueue q)
{
	ILibDuktape_HECI_ioctl_data *data = (ILibDuktape_HECI_ioctl_data*)ILibQueue_PeekQueue(q);
	int res;
	if (data == NULL) { return; } // This line is unnecessary, because this method is only called on a non-empty Queue, but to satisfy Klockwork...

	data->bytesReceived = 0;

	ResetEvent(data->v.hEvent);
	res = DeviceIoControl(data->device, (DWORD)data->code, data->buffer, (DWORD)data->bufferLen, data->outBuffer, (DWORD)data->outBufferLen, &(data->bytesReceived), &(data->v));
	ILibProcessPipe_WaitHandle_Add_WithNonZeroTimeout(data->pipeManager, data->v.hEvent, 2000, data, ILibDuktape_HECI_IoctlHandler);

}
void __stdcall ILibDuktape_HECI_apc_AddIoctl(ULONG_PTR obj)
{
	ILibDuktape_HECI_ioctl_data *data = (ILibDuktape_HECI_ioctl_data*)obj;
	ILibQueue_EnQueue(data->Q, data);
	if (ILibQueue_GetCount(data->Q) == 1)
	{
		ILibDuktape_HECI_NextIoctl(data->Q);
	}
}
#endif
#ifdef _POSIX
void ILibDuktape_HECI_AddIoctl(ILibDuktape_HECI_ioctl_data *data)
{
	ILibQueue_EnQueue(data->Q, data);
	if (ILibQueue_GetCount(data->Q) == 1)
	{
		ILibForceUnBlockChain(data->chain);
	}
}
#endif

duk_ret_t ILibDuktape_HECI_doIoctl(duk_context *ctx)
{
	int code = duk_require_int(ctx, 0);
	duk_size_t bufferLen = 0;
	char *buffer = duk_is_null(ctx, 1) ? NULL : (char*)Duktape_GetBuffer(ctx, 1, &bufferLen);
	int nargs = duk_get_top(ctx);
	int i;
	ILibQueue Q;
	duk_size_t outBufferLen;
	char *outBuffer;
	int cbx;
	
	if (duk_is_buffer(ctx, 2) || duk_is_buffer_data(ctx, 2))
	{
		outBuffer = (char*)Duktape_GetBuffer(ctx, 2, &outBufferLen);
		cbx = 3;
	}
	else
	{
		outBuffer = NULL;
		outBufferLen = 0;
		cbx = 2;
	}

#ifdef _POSIX
	if (outBuffer == NULL)
	{
		outBuffer = buffer;
		outBufferLen = bufferLen;
	}
	else
	{
		if (bufferLen < outBufferLen) { return(ILibDuktape_Error(ctx, "HECI.doIoctl(): Output Buffer too small")); }
		memcpy_s(outBuffer, outBufferLen, buffer, bufferLen);
	}
#endif

	duk_require_function(ctx, cbx);
	duk_push_this(ctx);																// [heci]
	duk_get_prop_string(ctx, -1, ILibDuktape_HECI_Q);								// [heci][q]
	Q = (ILibQueue)duk_get_pointer(ctx, -1);
	duk_pop(ctx);																	// [heci]

	ILibDuktape_Push_ObjectStash(ctx);												// [heci][stash]
	duk_push_array(ctx);															// [heci][stash][array]
	ILibDuktape_HECI_ioctl_data *data;
	data = (ILibDuktape_HECI_ioctl_data*)Duktape_PushBuffer(ctx, bufferLen + sizeof(ILibDuktape_HECI_ioctl_data));
	duk_put_prop_index(ctx, -2, 0);													// [heci][stash][array]
	if (outBufferLen > 0)
	{																				// [heci][stash][array][buffer]
		duk_dup(ctx, 2);
	}
	else
	{
		duk_push_null(ctx);															// [heci][stash][array][buffer]
	}
																	
	duk_put_prop_index(ctx, -2, 1);													// [heci][stash][array]
	data->ctx = ctx;

	duk_dup(ctx, cbx);																// [heci][stash][array][callback]
	duk_put_prop_index(ctx, -2, 2);													// [heci][stash][array]

#ifdef WIN32
	duk_get_prop_string(ctx, -3, ILibDuktape_HECI_IoctlWaitHandle);					// [heci][stash][array][handle]
	data->v.hEvent = (HANDLE)duk_get_pointer(ctx, -1);
	duk_pop(ctx);																	// [heci][stash][array]
#endif

	duk_get_prop_string(ctx, -3, ILibDuktape_HECI_Descriptor);						// [heci][stash][array][descriptor]
#ifdef WIN32
	data->device = (HANDLE)duk_get_pointer(ctx, -1);
#elif defined(_POSIX)
	data->device = duk_get_int(ctx, -1);
#endif
	duk_pop(ctx);																	// [heci][stash][array]
	data->chain = Duktape_GetChain(ctx);
	data->Q = Q;
	data->code = code;
	data->outBuffer = outBuffer;
	data->outBufferLen = outBufferLen;
	data->heciObject = duk_get_heapptr(ctx, -3);
	data->bufferLen = bufferLen;													
	data->data = duk_get_heapptr(ctx, -1);
	memcpy_s(data->buffer, bufferLen, buffer, bufferLen);

	for (i = cbx + 1; i < nargs; ++i)
	{																				
		duk_dup(ctx, i);															// [heci][stash][array][object]
		duk_put_prop_index(ctx, -2, i-1);											// [heci][stash][array]
	}																				
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));	// [heci][stash]
														

#ifdef WIN32
	duk_get_prop_string(ctx, -2, ILibDuktape_HECI_ChildProcess);					// [heci][stash][childProcess]
	duk_get_prop_string(ctx, -1, ILibDuktape_ChildProcess_Manager);					// [heci][stash][childProcess][manager]
	data->pipeManager = (ILibProcessPipe_Manager)duk_get_pointer(ctx, -1);
	QueueUserAPC((PAPCFUNC)ILibDuktape_HECI_apc_AddIoctl, ILibProcessPipe_Manager_GetWorkerThread(data->pipeManager), (ULONG_PTR)data);
#elif defined(_POSIX)
	ILibDuktape_HECI_AddIoctl(data);
#endif

	return(0);
}
duk_ret_t ILibDuktape_HECI_Finalizer(duk_context *ctx)
{
#ifdef WIN32
	HANDLE h = Duktape_GetPointerProperty(ctx, 0, ILibDuktape_HECI_IoctlWaitHandle);
	if (h != NULL) { CloseHandle(h); }
#endif

	if (duk_has_prop_string(ctx, 0, ILibDuktape_HECI_Q))
	{
		duk_get_prop_string(ctx, 0, ILibDuktape_HECI_Q);
		ILibQueue_Destroy((ILibQueue)duk_get_pointer(ctx, -1));
	}

#ifdef _POSIX
	if (duk_has_prop_string(ctx, 0, ILibDuktape_HECI_ChainLink))
	{
		duk_get_prop_string(ctx, 0, ILibDuktape_HECI_ChainLink);		
		HECI_chainLink *h = (HECI_chainLink*)duk_get_pointer(ctx, -1);
		h->ctx = NULL;
		h->heciObject = NULL;
		ILibChain_SafeRemove(h->link.ParentChain, h);
	}
#endif

	return(0);
}
#if !defined(WIN32) && !defined(__APPLE__)
void ILibDuktape_HECI_PreSelect(void* object, fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime)
{

	int result;
	HECI_chainLink *h = (HECI_chainLink*)object;
	//printf("h = %p, descriptor = %d, paused = %d, session = %p\n", (void*)h, h->descriptor, h->paused, (void*)h->session);
	
	if (h->descriptor <= 0) { return; }
	if (h->paused == 0 && h->session != NULL) { FD_SET(h->descriptor, readset); }
	if (h->session != NULL && ILibQueue_GetCount(h->session->PendingWrites) > 0) { FD_SET(h->descriptor, writeset); }

	while (ILibQueue_GetCount(h->Q) > 0 && h->paused == 0)
	{
		ILibDuktape_HECI_ioctl_data *data = (ILibDuktape_HECI_ioctl_data*)ILibQueue_DeQueue(h->Q);
		switch (data->code)
		{
			case 0x00:
				break;
			case 0x01:
			case 0x02:
			case 0x03:
				result = ioctl(h->descriptor, _IOC(_IOC_READ | _IOC_WRITE, 'H', data->code, data->outBufferLen), data->outBuffer);
				data->code = result ? errno : 0;
				ILibDuktape_HECI_IoctlHandler_Dispatch(NULL, data);
				break;
			default:
				break;
		}
	}
}
void ILibDuktape_HECI_PostSelect(void* object, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	HECI_chainLink *h = (HECI_chainLink*)object;
	if (h->descriptor <= 0) { return; }

	if (FD_ISSET(h->descriptor, readset))
	{
		//printf("session = %p\n", (void*)h->session);
		//printf("Attempting to read: %d bytes from %p\n", h->session->bufferSize, (void*)h->session->buffer);
		int bytesRead = read(h->descriptor, h->session->buffer, h->session->bufferSize);
		if (bytesRead >= 0)
		{
			ILibDuktape_DuplexStream_WriteData(h->session->stream, h->session->buffer, bytesRead);
		}
		else
		{
			ILibDuktape_EventEmitter_SetupEmit(h->ctx, h->session->stream->ParentObject, "error");		// [emit][this][error]
			duk_push_string(h->ctx, "HECI Read Error");													// [emit][this][error][msg]
			duk_pcall_method(h->ctx, 2); duk_pop(h->ctx);												// ...

			duk_push_heapptr(h->ctx, h->session->stream->ParentObject);									// [heci]
			duk_del_prop_string(h->ctx, -1, ILibDuktape_HECI_Descriptor);								
			duk_pop(h->ctx);																			// ...
			
			int td = h->descriptor;
			h->descriptor = -1;
			close(td);
		}
	}
	if (FD_ISSET(h->descriptor, writeset))
	{
		ILibDuktape_HECI_Session_WriteHandler_Process(h->session);
	}
}
void ILibDuktape_HECI_Destroy(void *object)
{
	HECI_chainLink *h = (HECI_chainLink*)object;
	if (h->ctx != NULL && h->heciObject != NULL)
	{
		duk_push_heapptr(h->ctx, h->heciObject);						// [heci]
		duk_del_prop_string(h->ctx, -1, ILibDuktape_HECI_ChainLink);
		duk_pop(h->ctx);												// ...
	}
	close(h->descriptor);
}
#endif

void ILibDuktape_HECI_Push(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);																	// [HECI]
	ILibDuktape_WriteID(ctx, "heci");
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_HECI_Finalizer);

#ifdef WIN32
	HANDLE h = ILibDuktape_HECI_windowsInit();
	if (h == NULL) { ILibDuktape_Error(ctx, "Error initializing HECI"); return; }
	duk_push_pointer(ctx, h);																// [HECI][HANDLE]
	duk_put_prop_string(ctx, -2, ILibDuktape_HECI_Descriptor);								// [HECI]

	if (duk_peval_string(ctx, "require('child_process');") != 0)							// [HECI][child_process]
	{
		ILibDuktape_Error(ctx, "Error instantiating dependency 'child_process'");
		return;
	}

	duk_put_prop_string(ctx, -2, ILibDuktape_HECI_ChildProcess);							// [HECI]
	duk_push_pointer(ctx, CreateEvent(NULL, TRUE, FALSE, NULL));
	duk_put_prop_string(ctx, -2, ILibDuktape_HECI_IoctlWaitHandle);							// [HECI]
#elif defined(_POSIX) && !defined(__APPLE__)
	int h = ILibDuktape_HECI_linuxInit();
	if (h < 0) { ILibDuktape_Error(ctx, "error initializing HECI"); return; }
	duk_push_int(ctx, h);																	// [HECI][descriptor]
	duk_put_prop_string(ctx, -2, ILibDuktape_HECI_Descriptor);								// [HECI]
	
	HECI_chainLink *hlink = ILibMemory_Allocate(sizeof(HECI_chainLink), 0, NULL, NULL);
	hlink->ctx = ctx;
	hlink->descriptor = h;
	hlink->link.PreSelectHandler = ILibDuktape_HECI_PreSelect;
	hlink->link.PostSelectHandler = ILibDuktape_HECI_PostSelect;
	hlink->link.DestroyHandler = ILibDuktape_HECI_Destroy;
	hlink->Q = ILibQueue_Create();
	duk_push_pointer(ctx, hlink);															// [HECI][link]
	duk_put_prop_string(ctx, -2, ILibDuktape_HECI_ChainLink);								// [HECI]

	ILibChain_SafeAdd(Duktape_GetChain(ctx), hlink);
#endif
	if (chain != NULL) { ILibDuktape_CreateInstanceMethod(ctx, "create", ILibDuktape_HECI_create, 0); }
	ILibDuktape_CreateInstanceMethod(ctx, "doIoctl", ILibDuktape_HECI_doIoctl, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "disconnect", ILibDuktape_HECI_Session_close, 0);
#if defined(_POSIX) && !defined(__APPLE__)
	duk_push_pointer(ctx, hlink->Q);														// [HECI][Q]
#else
	duk_push_pointer(ctx, ILibQueue_Create());												// [HECI][Q]
#endif
	duk_put_prop_string(ctx, -2, ILibDuktape_HECI_Q);										// [HECI]
	duk_push_object(ctx);
#ifdef WIN32
	ILibDuktape_CreateReadonlyProperty_int(ctx, "HECI_VERSION", (int)(CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)));
	ILibDuktape_CreateReadonlyProperty_int(ctx, "CLIENT_CONNECT", (int)(CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)));
#elif defined(_POSIX)
	ILibDuktape_CreateReadonlyProperty_int(ctx, "HECI_VERSION", (int)0x00);
	ILibDuktape_CreateReadonlyProperty_int(ctx, "CLIENT_CONNECT", (int)0x01);
#endif

	ILibDuktape_CreateReadonlyProperty(ctx, "IOCTL");
	duk_push_object(ctx);
	duk_peval_string(ctx, "Buffer.from('DBA4336776047B4EB3AFBCFC29BEE7A7', 'hex');");
	ILibDuktape_CreateReadonlyProperty(ctx, "LME");
	duk_peval_string(ctx, "Buffer.from('2800F812B7B42D4BACA846E0FF65814C', 'hex');");
	ILibDuktape_CreateReadonlyProperty(ctx, "AMT");
	ILibDuktape_CreateReadonlyProperty(ctx, "GUIDS");

}	// KLOCKWORK: We are not losing reference to created Event... It is freed in the object finalizer 'ILibDuktape_HECI_Finalizer'
void ILibDuktape_HECI_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "heci", ILibDuktape_HECI_Push);
}
