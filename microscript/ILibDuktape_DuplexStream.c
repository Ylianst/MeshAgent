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
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_DuplexStream.h"

#define ILibDuktape_Transform_Data		"\xFF_Transform_Data"

#ifdef __DOXY__
/*! 
\implements ReadableStream
\implements WritableStream
\brief DuplexStreams are streams that implement both the Readable and Writable interfaces.
*/
public class DuplexStream 
{
	private DuplexStream();
};
#endif

void ILibDuktape_DuplexStream_OnPause(struct ILibDuktape_readableStream *sender, void *user)
{
	ILibDuktape_DuplexStream *ds = (ILibDuktape_DuplexStream*)user;
	if (ds->OnPause != NULL) { ((ILibDuktape_DuplexStream_PauseResumeHandler)ds->OnPause)(ds, ds->user); }
}
void ILibDuktape_DuplexStream_OnResume(struct ILibDuktape_readableStream *sender, void *user)
{
	ILibDuktape_DuplexStream *ds = (ILibDuktape_DuplexStream*)user;
	if (ds->OnResume != NULL) { ((ILibDuktape_DuplexStream_PauseResumeHandler)ds->OnResume)(ds, ds->user); }
}
ILibTransport_DoneState ILibDuktape_DuplexStream_OnWrite(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_DuplexStream *ds = (ILibDuktape_DuplexStream*)user;
	if (ds->OnWrite != NULL) { return ((ILibDuktape_DuplexStream_WriteHandler)ds->OnWrite)(ds, buffer, bufferLen, ds->user); }
	return ILibTransport_DoneState_ERROR;
}
void ILibDuktape_DuplexStream_OnEnd(struct ILibDuktape_WritableStream *stream, void *user)
{
	ILibDuktape_DuplexStream *ds = (ILibDuktape_DuplexStream*)user;
	if (ds->OnEnd != NULL) { ((ILibDuktape_DuplexStream_EndHandler)ds->OnEnd)(ds, ds->user); }
}

int ILibDuktape_DuplexStream_OnUnshift(ILibDuktape_readableStream *sender, int unshiftBytes, void *user)
{
	ILibDuktape_DuplexStream *ds = (ILibDuktape_DuplexStream*)user;
	if (ds->unshiftHandler == NULL)
	{
		return(0);
	}
	else
	{
		return(((ILibDuktape_DuplexStream_UnshiftHandler)ds->unshiftHandler)(ds, unshiftBytes, ds->user));
	}
}
ILibDuktape_DuplexStream * ILibDuktape_DuplexStream_InitEx(duk_context * ctx, ILibDuktape_DuplexStream_WriteHandler WriteHandler, ILibDuktape_DuplexStream_EndHandler EndHandler, ILibDuktape_DuplexStream_PauseResumeHandler PauseHandler, ILibDuktape_DuplexStream_PauseResumeHandler ResumeHandler, ILibDuktape_DuplexStream_UnshiftHandler UnshiftHandler, void * user)
{
	ILibDuktape_DuplexStream *retVal;

	retVal = (ILibDuktape_DuplexStream*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_DuplexStream));	// [obj][buffer]
	duk_put_prop_string(ctx, -2, ILibDuktape_DuplexStream_bufferPtr);								// [obj]

	retVal->user = user;
	retVal->readableStream = ILibDuktape_ReadableStream_InitEx(ctx, ILibDuktape_DuplexStream_OnPause, ILibDuktape_DuplexStream_OnResume, UnshiftHandler != NULL ? ILibDuktape_DuplexStream_OnUnshift : NULL, retVal);
	retVal->writableStream = ILibDuktape_WritableStream_Init(ctx, ILibDuktape_DuplexStream_OnWrite, ILibDuktape_DuplexStream_OnEnd, retVal);
	retVal->OnEnd = EndHandler;
	retVal->OnWrite = WriteHandler;
	retVal->OnPause = PauseHandler;
	retVal->OnResume = ResumeHandler;
	retVal->ParentObject = duk_get_heapptr(ctx, -1);
	retVal->unshiftHandler = UnshiftHandler;
	return retVal;
}

ILibTransport_DoneState ILibDuktape_Transform_WriteSink(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_Transform *TF = (ILibDuktape_Transform*)user;
	TF->writerEnded = stream->endBytes >= 0 ? -1 : 0;
	TF->On_NativeTransform(TF, TF->source->Reserved, stream->endBytes >= 0, buffer, bufferLen, TF->user);
	return(TF->target->paused == 0 ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE);
}
void ILibDuktape_Transform_EndSink(struct ILibDuktape_WritableStream *stream, void *user)
{
	ILibDuktape_Transform *TF = (ILibDuktape_Transform*)user;
	if (TF->writerEnded == 0)
	{
		TF->writerEnded = -1;
		TF->On_NativeTransform(TF, 0, -1, NULL, 0, TF->user);
	}
	ILibDuktape_readableStream_WriteEnd(TF->target);
}
void ILibDuktape_Transform_PauseSink(struct ILibDuktape_readableStream *sender, void *user)
{
	UNREFERENCED_PARAMETER(sender);
	UNREFERENCED_PARAMETER(user);

	// NO-OP, because it is handled in the WriteSink
}
void ILibDuktape_Transform_ResumeSink(struct ILibDuktape_readableStream *sender, void *user)
{
	ILibDuktape_Transform *TF = (ILibDuktape_Transform*)user;
	ILibDuktape_WritableStream_Ready(TF->source);
}
void ILibDuktape_Transform_ReaderPipeHook(struct ILibDuktape_readableStream *sender, void *wstream, void *user)
{
	ILibDuktape_Transform *TF = (ILibDuktape_Transform*)user;
	TF->readerIsPiped = 1;
	if (TF->On_NativePipedSink != NULL) { TF->On_NativePipedSink(TF, TF->user); }
}
int ILibDuktape_Transform_UnshiftSink(struct ILibDuktape_readableStream *sender, int unshiftBytes, void *user)
{
	ILibDuktape_Transform *TF = (ILibDuktape_Transform*)user;
	return(TF->On_NativeUnshift(TF, unshiftBytes, TF->user));
}
ILibDuktape_Transform* ILibDuktape_Transform_InitEx(duk_context *ctx, ILibDuktape_TransformStream_TransformHandler transformHandler, ILibDuktape_TransformStream_UnShiftHandler unshiftHandler, ILibDuktape_TransformStream_TargetPipedHandler pipedHandler, void *user)
{
	ILibDuktape_Transform *TF;

	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_Transform));		// [buffer]
	TF = (ILibDuktape_Transform*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_Transform_Data);		// ...

	TF->source = ILibDuktape_WritableStream_Init(ctx, ILibDuktape_Transform_WriteSink, ILibDuktape_Transform_EndSink, TF);
	if (unshiftHandler != NULL)
	{
		TF->target = ILibDuktape_ReadableStream_InitEx(ctx, ILibDuktape_Transform_PauseSink, ILibDuktape_Transform_ResumeSink, ILibDuktape_Transform_UnshiftSink, TF);
	}
	else
	{
		TF->target = ILibDuktape_ReadableStream_Init(ctx, ILibDuktape_Transform_PauseSink, ILibDuktape_Transform_ResumeSink, TF);
	}
	TF->target->PipeHookHandler = ILibDuktape_Transform_ReaderPipeHook;
	TF->On_NativePipedSink = pipedHandler;
	TF->On_NativeTransform = transformHandler;
	TF->On_NativeUnshift = unshiftHandler;
	TF->user = user;

	return(TF);
}

ILibDuktape_WritableStream *ILibDuktape_DuplexStream_GetNativeWritable(duk_context *ctx, void *stream)
{
	ILibDuktape_WritableStream *retVal = NULL;
	duk_push_heapptr(ctx, stream);											// [stream]
	if (duk_has_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS);	// [stream][ws]
		retVal = (ILibDuktape_WritableStream*)Duktape_GetBuffer(ctx, -1, NULL);
		if (retVal->JSCreated) { retVal = NULL; }
		duk_pop(ctx);														// [stream]
	}
	duk_pop(ctx);															// ...
	return(retVal);
}
