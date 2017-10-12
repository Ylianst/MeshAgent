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

#include "duktape.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_DuplexStream.h"


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

ILibDuktape_DuplexStream * ILibDuktape_DuplexStream_Init(duk_context * ctx, ILibDuktape_DuplexStream_WriteHandler WriteHandler, ILibDuktape_DuplexStream_EndHandler EndHandler, ILibDuktape_DuplexStream_PauseResumeHandler PauseHandler, ILibDuktape_DuplexStream_PauseResumeHandler ResumeHandler, void * user)
{
	ILibDuktape_DuplexStream *retVal;

	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_DuplexStream));			// [obj][buffer]
	retVal = (ILibDuktape_DuplexStream*)Duktape_GetBuffer(ctx, -1, NULL);	// [obj][buffer]
	duk_put_prop_string(ctx, -2, ILibDuktape_DuplexStream_bufferPtr);		// [obj]

	memset(retVal, 0, sizeof(ILibDuktape_DuplexStream));
	retVal->user = user;
	retVal->readableStream = ILibDuktape_InitReadableStream(ctx, ILibDuktape_DuplexStream_OnPause, ILibDuktape_DuplexStream_OnResume, retVal);
	retVal->writableStream = ILibDuktape_WritableStream_Init(ctx, ILibDuktape_DuplexStream_OnWrite, ILibDuktape_DuplexStream_OnEnd, retVal);
	retVal->OnEnd = EndHandler;
	retVal->OnWrite = WriteHandler;
	retVal->OnPause = PauseHandler;
	retVal->OnResume = ResumeHandler;
	retVal->ParentObject = duk_get_heapptr(ctx, -1);
	return retVal;
}
