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

#include "ILibDuktape_http.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktape_DuplexStream.h"
#include "microstack/ILibRemoteLogging.h"
#include "microstack/ILibCrypto.h"

#define DIGEST_USERNAME					"\xFF_DigestUsername"
#define DIGEST_PASSWORD					"\xFF_DigestPassword"
#define DIGEST_AUTHTOKEN				"\xFF_DigestAuthToken"
#define HTTP_DIGEST						"\xFF_HTTP_DIGEST"
#define DIGEST_CLIENT_REQUEST			"\xFF_DIGEST_CLIENT_REQUEST"
#define HTTP_CLIENTREQUEST_DATAPTR		"\xFF_CLIENTREQUEST_DATAPTR"
#define CLIENTREQUEST_EVENT_NAME		"\xFF_CLIENTREQUEST_EVENT_NAME"
#define CLIENTREQUEST_IMSG_RSPTR		"\xFF_CLIENTREQUEST_IMSG_RSPTR"

#define DIGEST2CNONCE					"\xFF_DIGEST2CNONCE"
#define DIGEST2NC						"\xFF_DIGEST2NONCECOUNT"
#define DIGEST2WWWAUTH					"\xFF_DIGEST2WWWAUTH"

#define DIGESTCLIENTREQUEST_END_CALLED	"\xFF_DIGESTCLIENTREQUEST_END_CALLED"
#define DIGESTCLIENTREQUEST_CONTINUE	"\xFF_DIGESTCLIENTREQUEST_CONTINUE"
#define DIGESTCLIENTREQUEST_TmpBuffer	"\xFF_DIGESTCLIENTREQUEST_TmpBuffer"
#define DIGESTCLIENTREQUEST_DIGEST		"\xFF_DIGESTCLIENTREQUEST_DIGEST"

duk_ret_t ILibDuktape_httpDigest_clientRequest_response2(duk_context *ctx)
{
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "digestClientRequest");// [digestClientRequest]

	int statusCode = Duktape_GetIntPropertyValue(ctx, 0, "statusCode", 0);

	if (statusCode == 200)
	{
		duk_get_prop_string(ctx, -1, "emit");	// [digestClientRequest][emit]
		duk_swap_top(ctx, -2);					// [emit][this]
		duk_push_string(ctx, "response");		// [emit][this][response]
		duk_dup(ctx, 0);						// [emit][this][response][imsg]
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http-digest: Error dispatching response event"); }
	}
	else
	{
		duk_get_prop_string(ctx, -1, "emit");	// [digestClientRequest][emit]
		duk_swap_top(ctx, -2);					// [emit][this]
		duk_push_string(ctx, "error");			// [emit][this][error]
		duk_dup(ctx, 0);						// [emit][this][error][imsg]
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http-digest: Error dispatching response event"); }
	}

	return(0);
}

duk_ret_t ILibDuktape_httpDigest_clientRequest_onDrain(duk_context *ctx)
{
	duk_push_this(ctx);											// [clientRequest]
	if (duk_has_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST))
	{
		duk_get_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);	// [clientRequest][digestClientRequest]
		if (duk_has_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS))
		{
			duk_get_prop_string(ctx, -1, ILibDuktape_WritableStream_WSPTRS);
			ILibDuktape_WritableStream_Ready((ILibDuktape_WritableStream*)Duktape_GetBuffer(ctx, -1, NULL));
		}
	}
	return(0);
}

duk_ret_t ILibDuktape_httpDigest_clientRequest_propagateEvent(duk_context *ctx)
{
	int i, nargs = duk_get_top(ctx);
	duk_push_current_function(ctx);							// [func]
	duk_get_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);	// [func][digestClientRequest]
	duk_get_prop_string(ctx, -1, "emit");					// [func][digestClientRequest][emit]
	duk_swap_top(ctx, -2);									// [func][emit][this]
	duk_get_prop_string(ctx, -3, CLIENTREQUEST_EVENT_NAME);	// [func][emit][this][eventName]
	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);									// [func][emit][this][eventName][params]
	}
	if (duk_pcall_method(ctx, 1 + nargs) != 0) { return(ILibDuktape_Error(ctx, "propagateEvent() Error")); }
	return(0);
}

void ILibDuktape_httpDigest_clientRequest_IncomingMessage_PauseHandler(ILibDuktape_readableStream *sender, void *user)
{
	duk_push_heapptr(sender->ctx, user);			// [imsg]
	duk_get_prop_string(sender->ctx, -1, "pause");	// [imsg][pause]
	duk_swap_top(sender->ctx, -2);					// [pause][this]
	if (duk_pcall_method(sender->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(sender->ctx, "ILibDuktape_httpDigest_clientRequest_IncomingMessage_PauseHandler: Error Invoking Pause on ClientRequest: "); }
	duk_pop(sender->ctx);							// ...
}
void ILibDuktape_httpDigest_clientRequest_IncomingMessage_ResumeHandler(ILibDuktape_readableStream *sender, void *user)
{
	duk_push_heapptr(sender->ctx, user);			// [imsg]
	duk_get_prop_string(sender->ctx, -1, "resume");	// [imsg][pause]
	duk_swap_top(sender->ctx, -2);					// [pause][this]
	if (duk_pcall_method(sender->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(sender->ctx, "ILibDuktape_httpDigest_clientRequest_IncomingMessage_ResumeHandler: Error Invoking Resume on ClientRequest: "); }
	duk_pop(sender->ctx);							// ...
}
duk_ret_t ILibDuktape_httpDigest_clientRequest_OnData(duk_context *ctx)
{
	// http.IncomingMessage.data

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, CLIENTREQUEST_IMSG_RSPTR);
	ILibDuktape_readableStream *rs = (ILibDuktape_readableStream*)duk_get_pointer(ctx, -1);
	duk_size_t bufferLen;
	char *buffer;

	buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	ILibDuktape_readableStream_WriteData(rs, buffer, (int)bufferLen);

	return(0);
}
duk_ret_t ILibDuktape_httpDigest_clientRequest_OnEnd(duk_context *ctx)
{
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, CLIENTREQUEST_IMSG_RSPTR);
	ILibDuktape_readableStream *rs = (ILibDuktape_readableStream*)duk_get_pointer(ctx, -1);
	ILibDuktape_readableStream_WriteEnd(rs);
	return(0);
}

extern void ILibWebServer_Digest_ParseAuthenticationHeader(void* table, char* value, int valueLen);
char *ILibDuktape_httpDigest_generateAuthenticationHeader(duk_context *ctx, void *digestObj, void *optionsObj)
{
	int top = duk_get_top(ctx);
	int NC = 0;
	char *CNONCE = NULL;

	char *wwwauth, *username, *password;
	char *method, *path;
	duk_size_t wwwauthLen;
	void *ReservedMemory = ILibMemory_AllocateA(8000);
	void *table = ILibInitHashTree_CaseInSensitiveEx(ReservedMemory);
	int tmpLen;
	char result1[33];
	char result2[33];
	char result3[33];

	duk_push_heapptr(ctx, digestObj);																	// [digest]
	wwwauth = (char*)Duktape_GetStringPropertyValueEx(ctx, -1, DIGEST2WWWAUTH, NULL, &wwwauthLen);
	username = (char*)Duktape_GetStringPropertyValue(ctx, -1, DIGEST_USERNAME, NULL);
	password = (char*)Duktape_GetStringPropertyValue(ctx, -1, DIGEST_PASSWORD, NULL);
	if (!duk_has_prop_string(ctx, -1, DIGEST_AUTHTOKEN))
	{
		if (wwwauth == NULL || username == NULL || password == NULL) { duk_pop(ctx); return(NULL); }
	}
	duk_push_heapptr(ctx, optionsObj);																	// [digest][options]
	method = (char*)Duktape_GetStringPropertyValue(ctx, -1, "method", NULL);
	path = (char*)Duktape_GetStringPropertyValue(ctx, -1, "path", NULL);
	duk_pop(ctx);																						// [digest]
	
	ILibWebServer_Digest_ParseAuthenticationHeader(table, wwwauth, (int)wwwauthLen);
	char *realm, *nonce, *opaque, *qop;
	int realmLen, nonceLen, opaqueLen, qopLen;

	ILibGetEntryEx(table, "realm", 5, (void**)&realm, &realmLen); if (realmLen > 0) { realm[realmLen] = 0; }
	ILibGetEntryEx(table, "nonce", 5, (void**)&nonce, &nonceLen); if (nonceLen > 0) { nonce[nonceLen] = 0; }
	ILibGetEntryEx(table, "opaque", 6, (void**)&opaque, &opaqueLen); if (opaqueLen > 0) { opaque[opaqueLen] = 0; }
	ILibGetEntryEx(table, "qop", 3, (void**)&qop, &qopLen); if (qopLen > 0) { qop[qopLen] = 0; }

	if (duk_has_prop_string(ctx, -1, DIGEST_AUTHTOKEN))
	{
		duk_size_t authTokenLen;
		char *authToken = Duktape_GetStringPropertyValueEx(ctx, -1, DIGEST_AUTHTOKEN, NULL, &authTokenLen);
		
		if (authTokenLen < sizeof(result1))
		{
			memcpy_s(result1, sizeof(result1), authToken, authTokenLen);
			result1[32] = 0;
			username = "admin";
			tmpLen = (int)authTokenLen;
		}
	}
	else
	{
		tmpLen = sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s:%s:%s", username, realm, password);
		util_md5hex(ILibScratchPad2, tmpLen, result1);
	}
	tmpLen = sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s:%s", method, path);
	util_md5hex(ILibScratchPad2, tmpLen, result2);

	if (qop == NULL)
	{
		tmpLen = sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s:%s:%s", result1, nonce, result2);
	}
	else
	{
		duk_get_prop_string(ctx, -1, DIGEST2CNONCE);													// [digest][buffer]
		CNONCE = (char*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop(ctx);																					// [digest]
		NC = Duktape_GetIntPropertyValue(ctx, -1, DIGEST2NC, 0) + 1;
		duk_push_int(ctx, NC);																			// [digest][NC]
		duk_put_prop_string(ctx, -2, DIGEST2NC);														// [digest]		

		tmpLen = sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s:%s:%08x:%s:%s:%s", result1, nonce, NC, CNONCE, qop, result2);
	}
	util_md5hex(ILibScratchPad2, tmpLen, result3);
	duk_pop(ctx);																						// ...

	tmpLen = sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s\"", username, realm, nonce, path);
	if (opaque != NULL) { tmpLen += sprintf_s(ILibScratchPad2 + tmpLen, sizeof(ILibScratchPad2) - tmpLen, ",opaque=\"%s\"", opaque); }
	tmpLen += sprintf_s(ILibScratchPad2 + tmpLen, sizeof(ILibScratchPad2) - tmpLen, ",response=\"%s\"", result3);
	if (qop != NULL) { tmpLen += sprintf_s(ILibScratchPad2 + tmpLen, sizeof(ILibScratchPad2) - tmpLen, ",qop=\"%s\",nc=\"%08x\",cnonce=\"%s\"", qop, NC, CNONCE); }
	
	if (realmLen > 0) { realm[realmLen] = '"'; }
	if (nonceLen > 0) { nonce[nonceLen] = '"'; }
	if (opaqueLen > 0) { opaque[opaqueLen] = '"'; }
	if (qopLen > 0) { qop[qopLen] = '"'; }

	duk_set_top(ctx, top);
	return(ILibScratchPad2);
}

duk_ret_t ILibDuktape_httpDigest_clientRequest_response(duk_context *ctx)
{
	void *digestClientPtr, *digestObj, *optionsObj;
	int statusCode;

	duk_push_this(ctx);	
	optionsObj = Duktape_GetHeapptrProperty(ctx, -1, ILibDuktape_CR2Options);

	duk_push_current_function(ctx);													
	duk_get_prop_string(ctx, -1, "digestClientRequest");							
	digestClientPtr = duk_get_heapptr(ctx, -1);
	duk_get_prop_string(ctx, -1, "digest");
	digestObj = duk_get_heapptr(ctx, -1);
	duk_get_prop_string(ctx, -1, DIGEST_USERNAME);
	duk_get_prop_string(ctx, -2, DIGEST_PASSWORD);

	statusCode = Duktape_GetIntPropertyValue(ctx, 0, "statusCode", -1);
	if (statusCode == 401)
	{
		duk_push_heapptr(ctx, digestClientPtr);						// [digestClientRequest]
		int endCalledAlready = Duktape_GetBooleanProperty(ctx, -1, DIGESTCLIENTREQUEST_END_CALLED, 0);
		if (endCalledAlready == 0 && duk_has_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST))
		{
			duk_get_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);	// [digestClientRequest][clientRequest]
			duk_get_prop_string(ctx, -1, "end");					// [digestClientRequest][clientRequest][end]
			duk_dup(ctx, -2);										// [digestClientRequest][clientRequest][end][this]
			if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http-digest.onResponse(): "); }
			duk_pop_2(ctx);											// [digestClientRequest]
		}
		duk_pop(ctx);												// ...

		// UnAuthorized, need to retry request with Authorization Headers
		char *auth, *wwwauth;

		duk_dup(ctx, 0);									// [IMSG]
		duk_get_prop_string(ctx, -1, "headers");			// [IMSG][headers]
		if ((wwwauth = Duktape_GetStringPropertyValue(ctx, -1, "WWW-Authenticate", NULL)) != NULL)
		{
			duk_push_heapptr(ctx, digestObj);				// [IMSG][headers][digest]
			duk_push_string(ctx, wwwauth);					// [IMSG][headers][digest][www]
			duk_put_prop_string(ctx, -2, DIGEST2WWWAUTH);	// [IMSG][headers][digest]
			duk_pop(ctx);									// [IMSG][headers]
		}
		duk_pop_2(ctx);										// ...

		duk_push_this(ctx);																		// [clientRequest]		
		auth = ILibDuktape_httpDigest_generateAuthenticationHeader(ctx, digestObj, optionsObj);

		duk_get_prop_string(ctx, -1, ILibDuktape_CR2HTTP);										// [clientReqeust][http]
		duk_get_prop_string(ctx, -1, "request");												// [clientRequest][http][request]
		duk_swap_top(ctx, -2);																	// [clientRequest][request][this]
		duk_get_prop_string(ctx, -3, ILibDuktape_CR2Options);									// [clientRequest][request][this][options]

		if(!duk_has_prop_string(ctx, -1, "headers")) 
		{ 
			duk_push_object(ctx);																// [clientReqeust][request][this][options][headers]
		}
		else
		{
			duk_get_prop_string(ctx, -1, "headers");											// [clientReqeust][request][this][options][headers]
		}
																			
		duk_push_string(ctx, auth);																// [clientReqeust][request][this][options][headers][Auth]
		duk_put_prop_string(ctx, -2, "Authorization");											// [clientReqeust][request][this][options][headers]
		duk_put_prop_string(ctx, -2, "headers");												// [clientReqeust][request][this][options]
		duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_response2, DUK_VARARGS);	// [clientReqeust][request][this][options][callback]
		duk_push_heapptr(ctx, digestClientPtr);													// [clientReqeust][request][this][options][callback][digestClientRequest]
		duk_put_prop_string(ctx, -2, "digestClientRequest");									// [clientReqeust][request][this][options][callback]
		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "digest_onResponse: Error Invoking http.get"); }
		
		duk_push_heapptr(ctx, digestClientPtr);													// [clientRequest][digestClientRequest]
		ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "upgrade", -1, "upgrade");
		ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "error", -1, "error");
		ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "continue", -1, "continue");
		ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "timeout", -1, "timeout");
		ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "drain", -1, "drain");
		duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);									// [clientRequest]

		if (endCalledAlready != 0)
		{
			duk_push_heapptr(ctx, digestClientPtr);
			if (duk_has_prop_string(ctx, -1, DIGESTCLIENTREQUEST_TmpBuffer))
			{
				duk_get_prop_string(ctx, -1, DIGESTCLIENTREQUEST_TmpBuffer);						// [clientReqeust][digestClientRequest][buffer]
				duk_swap_top(ctx, -2);																// [clientRequesat][buffer][digestClientRequest]
				duk_pop(ctx);																		// [clientRequest][buffer]
				duk_dup(ctx, -2);																	// [clientRequest][buffer][clientRequest]
				duk_get_prop_string(ctx, -1, "write");												// [clientRequest][buffer][clientRequest][write]
				duk_swap_top(ctx, -2);																// [clientRequest][buffer][write][this]
				duk_dup(ctx, -3);																	// [clientRequest][buffer][write][this][buffer]
				duk_remove(ctx, -4);																// [clientRequest][write][this][buffer]
				if (duk_pcall_method(ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "httpDigest.clientRequest.onResponse(): Error calling clientRequest.write(): "); }
				duk_pop(ctx);																		// [clientRequest]
			}
			else
			{
				duk_pop(ctx);																		// [clientRequest]
			}

			duk_dup(ctx, -1);																		// [clientReqeust][clientReqeust]
			duk_get_prop_string(ctx, -1, "end");													// [clientReqeust][clientReqeust][end]
			duk_swap_top(ctx, -2);																	// [clientReqeust][end][this]
			if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "httpDigest.onResponse(): Error invoking ClientRequest.end(): "); }
			duk_pop(ctx);																			// [clientRequest]
		}

		duk_push_heapptr(ctx, digestClientPtr);														// [clientRequest][digestClientRequest]
		duk_swap_top(ctx, -2);																		// [digestClientRequest][clientRequest]
		duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);										// [digestClientRequest]
	}
	else
	{
		duk_push_heapptr(ctx, digestClientPtr);								// [digestClientRequest]
		duk_del_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);
		duk_push_this(ctx);
		duk_del_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);
		duk_pop(ctx);

		duk_get_prop_string(ctx, -1, "emit");								// [digestClientRequest][emit]
		duk_swap_top(ctx, -2);												// [emit][this]
		duk_push_string(ctx, "response");									// [emit][this][response]
		duk_dup(ctx, 0);													// [emit][this][response][IMSG]

		if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "digestClientRequest.onResponse(): "); }
		duk_pop(ctx);														// ...
	}
	return(0);
}
duk_ret_t ILibDuktape_httpDigest_clientRequest_setter(duk_context *ctx)
{
	duk_dup(ctx, 0);																		// [clientRequest]
	duk_get_prop_string(ctx, -1, "once");													// [clientRequest][once]
	duk_swap_top(ctx, -2);																	// [once][this]
	duk_push_string(ctx, "response");														// [once][this][response]
	duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_response, DUK_VARARGS);	// [once][this][response][method]
	duk_push_this(ctx);																		// [once][this][response][method][digest]
	duk_put_prop_string(ctx, -2, "digest");													// [once][this][response][method]
	if (duk_pcall_method(ctx, 2) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http-digest: Error setting clientRequest"); }
	duk_pop(ctx);																			// ..
	return(0);
}
duk_ret_t ILibDuktape_httpDigest_http_setter(duk_context *ctx)
{
	duk_push_this(ctx);							// [digest]
	duk_dup(ctx, 0);							// [digest][http]
	duk_put_prop_string(ctx, -2, HTTP_DIGEST);	// [digest]
	return(0);
}
duk_ret_t ILibDuktape_httpDigest_digestRequest_end(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int i;
	duk_push_this(ctx);										// [digestClientRequest]
	if (duk_has_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST))
	{
		duk_get_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);	// [digestClientRequest][clientRequest]
		duk_get_prop_string(ctx, -1, "end");					// [digestClientRequest][clientRequest][end]
		duk_swap_top(ctx, -2);									// [digestClientRequest][end][this]

		for (i = 0; i < nargs; ++i)
		{
			duk_dup(ctx, i);									// [digestClientRequest][end][this][params...]
		}
		if (duk_pcall_method(ctx, nargs) != 0) { return(ILibDuktape_Error(ctx, "digestRequest().end() error")); }

		duk_push_this(ctx);
		duk_del_prop_string(ctx, -1, "DIGEST_CLIENT_REQUEST");
	}
	return(0);
}

ILibTransport_DoneState ILibDuktape_httpDigest_http_request_WriteHandler(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibTransport_DoneState retVal = ILibTransport_DoneState_ERROR;

	duk_context *ctx = stream->ctx;
	duk_push_heapptr(ctx, stream->obj);										// [digestClientRequest]

	if (Duktape_GetBooleanProperty(ctx, -1, DIGESTCLIENTREQUEST_CONTINUE, 0) == 0)
	{
		duk_size_t bufLen;
		char *tmpBuffer;

		if (duk_has_prop_string(ctx, -1, DIGESTCLIENTREQUEST_TmpBuffer))
		{
			duk_get_prop_string(ctx, -1, DIGESTCLIENTREQUEST_TmpBuffer);	// [digestClientRequest][oldBuffer]
			bufLen = duk_get_length(ctx, -1);
			duk_resize_buffer(ctx, -1, bufLen + bufferLen);
			tmpBuffer = (char*)Duktape_GetBuffer(ctx, -1, &bufLen);
			memcpy_s(tmpBuffer + bufLen - (size_t)bufferLen, (size_t)bufferLen, buffer, (size_t)bufferLen);
			duk_pop(ctx);													// [digestClientRequest]
		}
		else
		{
			duk_push_dynamic_buffer(ctx, (duk_size_t)bufferLen);			// [digestClientRequest][buffer]
			tmpBuffer = (char*)Duktape_GetBuffer(ctx, -1, &bufLen);
			duk_put_prop_string(ctx, -2, DIGESTCLIENTREQUEST_TmpBuffer);	// [digestClientRequest]
			memcpy_s(tmpBuffer, bufLen, buffer, (size_t)bufferLen);
		}

		if (stream->endBytes > 0)
		{
			duk_push_true(ctx);
			duk_put_prop_string(ctx, -2, DIGESTCLIENTREQUEST_END_CALLED);
		}
	}

	if (duk_has_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST))
	{
		duk_get_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);	// [digestClientRequest][clientRequest]
		duk_get_prop_string(ctx, -1, "write");					// [digestClientRequest][clientRequest][write]
		duk_swap_top(ctx, -2);									// [digestClientRequest][write][this]

		if (stream->Reserved == 0)
		{
			duk_push_external_buffer(ctx);
			duk_config_buffer(ctx, -1, buffer, (duk_size_t)bufferLen);
		}
		else
		{
			duk_push_lstring(ctx, buffer, (duk_size_t)bufferLen);
		}

		if (duk_pcall_method(ctx, 1) != 0) 
		{ 
			ILibDuktape_Process_UncaughtExceptionEx(ctx, "http-digest.clientRequest.write(): "); 
			retVal = ILibTransport_DoneState_ERROR; 
		}
		else
		{
			retVal = duk_get_boolean(ctx, -1) ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
		}
		duk_pop(ctx);											// [digestClientRequest]

	}
	duk_pop(ctx);												// ...
	return(retVal);
}
void ILibDuktape_httpDigest_http_request_DoneHandler(struct ILibDuktape_WritableStream *stream, void *user)
{
	duk_context *ctx = stream->ctx;

	duk_push_heapptr(ctx, stream->obj);							// [digestClientRequest]
	duk_push_true(ctx);
	duk_put_prop_string(ctx, -2, DIGESTCLIENTREQUEST_END_CALLED);

	if (duk_has_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST))
	{
		duk_get_prop_string(ctx, -1, DIGEST_CLIENT_REQUEST);	// [digestClientRequest][clientRequest]
		duk_get_prop_string(ctx, -1, "end");					// [digestClientRequest][clientRequest][end]
		duk_swap_top(ctx, -2);									// [digestClientRequest][end][this]

		if (duk_pcall_method(ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "http-digest.clientRequest.end(): "); }
		duk_pop(ctx);											// [digestClientRequest]
		duk_del_prop_string(ctx, -1, "DIGEST_CLIENT_REQUEST");
	}
	duk_pop(ctx);												// ...
}
duk_ret_t ILibDuktape_httpDigest_http_request_continueOccured(duk_context *ctx)
{
	duk_push_this(ctx);						// [digestClientRequest]
	duk_push_true(ctx);
	duk_put_prop_string(ctx, -2, DIGESTCLIENTREQUEST_CONTINUE);
	return(0);
}

duk_ret_t ILibDuktape_httpDigest_http_request(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	void *clientRequest = NULL;
	ILibDuktape_EventEmitter *emitter;
	char *auth = NULL;
	int needCallEnd = 0;

	duk_push_this(ctx);								// [digest]
	duk_get_prop_string(ctx, -1, HTTP_DIGEST);		// [digest][http]
	duk_get_prop_string(ctx, -1, "request");		// [digest][http][request]
	duk_swap_top(ctx, -2);							// [digest][request][this]

	if (duk_is_string(ctx, 0))
	{
		duk_get_prop_string(ctx, -1, "parseUri");	// [digest][request][this][parseUri]
		duk_dup(ctx, -2);							// [digest][request][this][parseUri][this]
		duk_dup(ctx, 0);							// [digest][request][this][parseUri][this][uri]
		duk_call_method(ctx, 1);					// [digest][request][this][options]
		needCallEnd = 1;
	}
	else
	{
		duk_dup(ctx, 0);							// [digest][request][this][options]
	}

	// Before we make the request, let's check to see if we can put in Authorization header right now
	if ((auth = ILibDuktape_httpDigest_generateAuthenticationHeader(ctx, duk_get_heapptr(ctx, -4), duk_get_heapptr(ctx, -1))) != NULL)
	{
		if (!duk_has_prop_string(ctx, -1, "headers"))
		{
			duk_push_object(ctx);						// [digest][request][this][options][headers]
			duk_dup(ctx, -1);							// [digest][request][this][options][headers][dup]
			duk_put_prop_string(ctx, -3, "headers");	// [digest][request][this][options][headers]
		}
		else
		{
			duk_get_prop_string(ctx, -1, "headers");	// [digest][request][this][options][headers]
		}
		duk_push_string(ctx, auth);						// [digest][request][this][options][headers][auth]
		duk_put_prop_string(ctx, -2, "Authorization");	// [digest][request][this][options][headers]
		duk_pop(ctx);									// [digest][request][this][options]
	}

	duk_call_method(ctx, 1);							// [digest][clientRequest]

	clientRequest = duk_get_heapptr(ctx, -1);
	duk_get_prop_string(ctx, -1, "once");													// [clientRequest][once]
	duk_swap_top(ctx, -2);																	// [once][this]
	duk_push_string(ctx, "response");														// [once][this][response]
	duk_push_c_function(ctx, ILibDuktape_httpDigest_clientRequest_response, DUK_VARARGS);	// [once][this][response][method] 
	
	duk_push_object(ctx);																	// [once][this][response][method][digest-clientRequest]
	ILibDuktape_WriteID(ctx, "httpDigest.clientRequest");
	if (needCallEnd)
	{
		duk_push_true(ctx);
		duk_put_prop_string(ctx, -2, DIGESTCLIENTREQUEST_END_CALLED);
	}
	
	duk_push_this(ctx);																		// [once][this][response][method][digest-clientRequest][digest]
	duk_put_prop_string(ctx, -2, DIGESTCLIENTREQUEST_DIGEST);								// [once][this][response][method][digest-clientRequest]
	duk_push_heapptr(ctx, clientRequest);													// [once][this][response][method][digest-clientRequest][clientRequest]
	duk_dup(ctx, -2);																		// [once][this][response][method][digest-clientRequest][clientRequest][digest-clientRequest]
	duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);									// [once][this][response][method][digest-clientRequest][clientRequest]
	duk_put_prop_string(ctx, -2, DIGEST_CLIENT_REQUEST);									// [once][this][response][method][digest-clientRequest]
	
	emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "response");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "error");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "upgrade");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "continue");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "timeout");

	ILibDuktape_EventEmitter_AddOnceEx(emitter, "continue", ILibDuktape_httpDigest_http_request_continueOccured, 0);
	ILibDuktape_WritableStream_Init(ctx, ILibDuktape_httpDigest_http_request_WriteHandler, ILibDuktape_httpDigest_http_request_DoneHandler, NULL);

	if (nargs > 1 && duk_is_function(ctx, 1))
	{
		ILibDuktape_EventEmitter_AddOnce(ILibDuktape_EventEmitter_GetEmitter(ctx, -1), "response", duk_require_heapptr(ctx, 1));
	}
	
	duk_push_this(ctx);																		// [once][this][response][method][digest-clientRequest][digest]
	duk_put_prop_string(ctx, -2, "digest");													// [once][this][response][method][digest-clientRequest]
	duk_put_prop_string(ctx, -2, "digestClientRequest");									// [once][this][response][method]
	if (duk_pcall_method(ctx, 2) != 0) { return(ILibDuktape_Error(ctx, "request error")); }			// [clientRequest]
		
	duk_push_heapptr(emitter->ctx, clientRequest);
	duk_push_heapptr(emitter->ctx, emitter->object);										// [clientRequest][digestClientRequest]
	ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "upgrade", -1, "upgrade");
	ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "error", -1, "error");
	ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "continue", -1, "continue");
	ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "timeout", -1, "timeout");
	ILibDuktape_EventEmitter_ForwardEvent(ctx, -2, "drain", -1, "drain");

	if (needCallEnd)
	{
		duk_get_prop_string(ctx, -2, "end");												// [clientRequest][digestClientRequest][end]
		duk_dup(ctx, -3);																	// [clientRequest][digestClientRequest][end][this]
		duk_call_method(ctx, 0); duk_pop(ctx);												// [clientRequest][digestClientRequest]
	}

	return(1);
}
duk_ret_t ILibduktape_httpDigest_create(duk_context *ctx)
{
	duk_size_t usernameLen, passwordLen, authTokenLen;
	ILibDuktape_EventEmitter *emitter;
	char *username = NULL, *password = NULL, *authToken = NULL;

	if (duk_get_top(ctx) == 1 && duk_is_object(ctx, 0))
	{
		if ((authToken = Duktape_GetStringPropertyValueEx(ctx, 0, "authToken", NULL, &authTokenLen)) == NULL) { return(ILibDuktape_Error(ctx, "authToken Required")); }
	}
	else
	{
		username = (char*)duk_require_lstring(ctx, 0, &usernameLen), password = (char*)duk_require_lstring(ctx, 1, &passwordLen);
	}

	duk_push_object(ctx);					// [obj]
	ILibDuktape_WriteID(ctx, "httpDigest");
	ILibDuktape_CreateEventWithSetterEx(ctx, "clientRequest", ILibDuktape_httpDigest_clientRequest_setter);
	ILibDuktape_CreateEventWithSetterEx(ctx, "http", ILibDuktape_httpDigest_http_setter);
	emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "response");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "error");
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "upgrade");
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "isGet", 1, "get", ILibDuktape_httpDigest_http_request, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "isGet", 0, "request", ILibDuktape_httpDigest_http_request, DUK_VARARGS);
	
	if (authToken == NULL)
	{
		duk_push_string(ctx, username);
		duk_put_prop_string(ctx, -2, DIGEST_USERNAME);
		duk_push_string(ctx, password);
		duk_put_prop_string(ctx, -2, DIGEST_PASSWORD);
	}
	else
	{
		duk_push_lstring(ctx, authToken, authTokenLen);
		duk_put_prop_string(ctx, -2, DIGEST_AUTHTOKEN);
	}
	duk_push_fixed_buffer(ctx, 16);
	util_randomtext(16, (char*)Duktape_GetBuffer(ctx, -1, NULL));
	((char*)Duktape_GetBuffer(ctx, -1, NULL))[15] = 0;
	duk_put_prop_string(ctx, -2, DIGEST2CNONCE);
	duk_push_int(ctx, 0);
	duk_put_prop_string(ctx, -2, DIGEST2NC);

	return(1);
}

void ILibDuktape_httpDigest_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_CreateInstanceMethod(ctx, "create", ILibduktape_httpDigest_create, DUK_VARARGS);
}
duk_ret_t ILibDuktape_httpHeaders(duk_context *ctx)
{
	ILibHTTPPacket *packet = NULL;
	packetheader_field_node *node;
	int headersOnly = duk_get_top(ctx) > 1 ? (duk_require_boolean(ctx, 1) ? 1 : 0) : 0;

	duk_size_t bufferLen;
	char *buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);

	packet = ILibParsePacketHeader(buffer, 0, (int)bufferLen);
	if (packet == NULL) { return(ILibDuktape_Error(ctx, "http-headers(): Error parsing data")); }

	if (headersOnly == 0)
	{
		duk_push_object(ctx);
		if (packet->Directive != NULL)
		{
			duk_push_lstring(ctx, packet->Directive, packet->DirectiveLength);
			duk_put_prop_string(ctx, -2, "method");
			duk_push_lstring(ctx, packet->DirectiveObj, packet->DirectiveObjLength);
			duk_put_prop_string(ctx, -2, "url");
		}
		else
		{
			duk_push_int(ctx, packet->StatusCode);
			duk_put_prop_string(ctx, -2, "statusCode");
			duk_push_lstring(ctx, packet->StatusData, packet->StatusDataLength);
			duk_put_prop_string(ctx, -2, "statusMessage");
		}
		if (packet->VersionLength == 3)
		{
			duk_push_object(ctx);
			duk_push_lstring(ctx, packet->Version, 1);
			duk_put_prop_string(ctx, -2, "major");
			duk_push_lstring(ctx, packet->Version + 2, 1);
			duk_put_prop_string(ctx, -2, "minor");
			duk_put_prop_string(ctx, -2, "version");
		}
	}

	duk_push_object(ctx);		// headers
	node = packet->FirstField;
	while (node != NULL)
	{
		duk_push_lstring(ctx, node->Field, node->FieldLength);			// [str]
		duk_get_prop_string(ctx, -1, "toLowerCase");					// [str][toLower]
		duk_swap_top(ctx, -2);											// [toLower][this]
		duk_call_method(ctx, 0);										// [result]
		duk_push_lstring(ctx, node->FieldData, node->FieldDataLength);
		duk_put_prop(ctx, -3);
		node = node->NextField;
	}
	if (headersOnly == 0)
	{
		duk_put_prop_string(ctx, -2, "headers");
	}
	ILibDestructPacket(packet);
	return(1);
}
void ILibDuktape_httpHeaders_PUSH(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_httpHeaders, DUK_VARARGS);
}
void ILibDuktape_http_init(duk_context * ctx, void * chain)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "http-digest", ILibDuktape_httpDigest_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "http-headers", ILibDuktape_httpHeaders_PUSH);
}

#ifdef __DOXY__

/*!
\brief Http exposed using Node APIs. <b>Note:</b> To use, must <b>require('http')</b> or <b>require('https')</b>
*/
class Http
{
public:
	/*!
	\brief Parses a uri string
	\param str \<String\> The uri to parse
	\return Uri object of the parsed string
	*/
	static Uri parseUri(str);
	/*!
	\brief Returns a new instance of Server
	*
	static Server createServer([options][, callback]);
	\param options <Object> that specifies various parameters such as:\n
	'request' = <func> callback to be dispatched when a request is received\n
	'pfx' = \<Buffer\|String\> containing PKS encoded certificate\n
	'passphrase' = \<String\> containing the passphrase to unlock the private key of the specified certificate\n
	'MeshAgent' = <MeshAgent> object, whose certificates we are going to use.\n
	'requestCert' = <boolean> indicating if the client certificate will be requested\n
	'rejectUnauthorized' = <boolean> indicating if the certificate must have a valid root of trust\n
	'checkClientIdentity' = <func> callback to be dispatched to verify client certificate. <b>Note:</b> When dispatched, throw an exception to fail verification.\n
	\param callback <func> callback to be dispatched when a request is received
	\return Server instance.
	*/
	static Server createServer([options][, callback]);
	/*!
	\brief Issues an HTTP Request onto the network
	*
	static ClientRequest request(options[, callback]);
	\param options \<Object\|String\|Url\>\n
	<b>protocol</b> \<String\> Protocol to use. Defaults to 'http:' or 'https:' depending on configuration\n
	<b>host</b> \<String\> A domain name or IP address of the server to issue the request to. Defaults to localhost.\n
	<b>hostname</b> \<String\> Alias for host. To support url.parse(), hostname is preferred over host.\n
	<b>port</b> <number> Port of remote server. Defaults to 80, or 443, depending on configuration\n
	<b>localAddress</b> \<String\> Local interface to bind for network connections.\n
	<b>method</b> \<String\> A string specifying the HTTP request method. Defaults to 'GET'.\n
	<b>path</b> \<String\> Request path. Defaults to '/'\n
	<b>headers</b> <Object> An object containing request headers.\n
	<b>proxy</b> <Object> An object containing proxy settings, (ie: 'host' and 'port'), to use for this connection\n
	<b>noProxy</b> <boolean> When present, will override any previously set proxies, and disable it for this connection\n
	<b>pfx</b> \<Buffer\|String\> containing pks encoded certificate\n
	<b>passphrase</b> \<String\> containing passphrase used to unlock specified certificate\n
	<b>MeshAgent</b> <MeshAgent> containing the MeshAgent instance, whose certificates will be used\n
	<b>rejectUnauthorized</b> <boolean> If true, will reject server's whose root of trust cannot be validated\n
	<b>checkServerIdentity</b> <func> callback that will be dispatched to validate server certificate. <b>Note:</b> To fail validation, throw an exception from the dispatch.\n
	\param callback <func> Optional. Set as one time listener for ClientRequest.response event.
	\return ClientRequest instance.
	*/
	static ClientRequest request(options[, callback]);

	/*!
	\brief Issues an HTTP Request onto the network. 
	\param url \<String\> The url to issue a GET reqeust
	\return ClientRequest instance
	*/
	static ClientRequest get(url);
	static DuplexStream createStream();


	/*!
	\implements EventEmitter
	\brief Http Server Abstraction
	*/
	class Server
	{
	public:
		/*!
		\brief Event emitted each time a request with an HTTP Expect: 100-continue is received. If this event is not listened for, the server will automatically respond with a 100 Continue as appropriate.
		*
		<b>Note:</b> When this event is emitted and handled, Http.request event will not be emitted.
		\param request \<IncomingMessage\>
		\param response \<ServerResponse\>
		*/
		void checkContinue;
		/*!
		\brief Event emitted each time a request with an HTTP Expect header is received, where the value is not 100-continue. If this event is not listened for, the server will automatically respond with a 417 Expectation Failed as appropriate.
		*
		<b>Note:</b> When this event is emitted and handled, Http.request event will not be emitted.
		*/
		void checkExpectation;
		/*!
		\brief Event emitted if the underlying Socket emits an error
		\param err <Error>
		\param socket \<Socket\>
		*/
		void clientError;
		/*!
		\brief Event emitted when the Server closes.
		*/
		void close;
		/*!
		\brief Event emitted when the client issues a 'CONNECT' method. If this event is not listened for, then clients requesting a CONNECT method will have their connections closed.
		\param request \<IncomingMessage\> Arguments for the HTTP request, as it is in the 'request' event
		\param socket \<Socket\> Network socket between the server and client
		\param head \<Buffer\> The first packet of the tunneling stream (may be empty)
		*/
		void connect;
		/*!
		\brief Event emitted each time a client requests an HTTP upgrade.  If this event is not listened for, then clients requesting an upgrade will have their connections closed.
		\param request \<IncomingMessage\> Arguments for the HTTP request, as it is in the 'request' event
		\param socket \<Socket\> Network socket between the server and client
		\param head \<Buffer\> The first packet of the tunneling stream (may be empty)
		*/
		void upgrade;
		/*!
		\brief Event emitted each time there is a request. <b>Note:</b> There may be multiple requests per connection (in the case of HTTP Keep-Alive connections).
		\param request \<IncomingMessage\>
		\param response \<ServerResponse\>
		*/
		void request;
		/*!
		\brief Event emitted when server is listening for incoming connections
		*/
		void listening;
		/*!
		\brief Stops the server from accepting new connections
		\param callback <func> Optional. Set as one time listener for 'close' event.
		*/
		void close([callback]);
		/*!
		\brief Event emitted when an idle timeout has elapsed
		\param socket \<Socket\> Timed out socket
		*/
		void timeout;
		/*!
		\brief Begin accepting connections on the specified port and hostname
		\param port <Integer>
		\param hostname \<String\>
		\param backlog <Integer>
		\param callback <func> Optional. Set as one time listener to 'listening' event
		*/
		void listen([port][, hostname][, backlog][, callback]);
		/*!
		\brief Sets the timeout value for sockets, and emits a 'timeout' event on the Server object, passing the socket as an argument, if a timeout occurs.
		\param msecs <Integer> Optional <b>Default: 120000</b> milliseconds (2 minutes)
		\param callback <func> Optional. Set as one time listener for 'timeout' event
		*/
		void setTimeout([msecs][, callback]);
		/*!
		\implements WritableStream
		\implements EventEmitter
		\brief Created internally by Http.
		*/
		class ServerResponse
		{
		public:
			/*!
			\brief 	Sets a single header value for implicit headers.If this header already exists in the to - be - sent headers, its value will be replaced
			\param name \<String\>
			\param value \<String\>
			*/
			void setHeader(name, value);
			/*!
			\brief Sends a response header to the request.
			\param statusCode <Integer> 3 digit code (ie: 200, 404, etc)
			\param statusMessage \<String\> Human readable status message (ie: 'OK', 'File Not Found', etc)
			\param headers <Object> Optional. JSON object where each name/value pair is a header/value pair.
			*/
			void writeHead(statusCode[, statusMessage][, headers]);
			/*!
			\brief When using implicit headers (not calling writeHead() explicitly), this property controls the status code that will be sent to the client when the headers get flushed.
			*/
			Integer statusCode;
			/*!
			\brief When using implicit headers (not calling writeHead() explicitly), this property controls the status message that will be sent to the client when the headers get flushed
			*/
			String statusMessage;
		};
	};
	/*!
	\implements WritableStream
	\brief This object is created internally and returned from http.request(). It represents an in-progress request whose header has already been queued.
	*/
	class ClientRequest
	{
	public:
		/*!
		\brief Event emitted when a response is received to this request. This event is emitted only once.
		\param msg IncomingMessage object containing the received request
		*/
		void response;
		/*!
		\brief Event emitted each time a server responds to a request with an upgrade. 
		\param response IncomingMessage
		\param socket WebSocket
		\param head <Buffer>
		*/
		void upgrade;
	};

	/*!
	\implements Socket
	\brief WebSocket abstraction
	*/
	class WebSocket
	{
	public:
		/*!
		\brief Event emitted when a 'ping' web socket control packet is received.
		\param data \<Buffer\|String\|NULL\> Optional data that was attached to the received 'ping' control packet.
		*/
		void ping;
		/*!
		\brief Event emitted when a 'pong' web socket control packet is received.
		\param data \<Buffer\|String\|NULL\> Optional data that was attached to the received 'pong' control packet.
		*/
		void pong;
		/*!
		\brief Send a 'ping' web socket control packet to the connected peer.
		*
		void ping([data]);
		\param data \<Buffer\|String\|NULL\> Optional data to attach to the 'ping' control packet.
		*/
		void ping([data]);
		/*!
		\brief Send a 'pong' web socket control packet to the connected peer.
		*
		void pong([data]);
		\param data \<Buffer\|String\|NULL\> Optional data to attach to the 'pong' control packet.
		*/
		void pong([data]);
	};


	/*!
	\brief An IncomingMessage object may be used to access response status, headers and data.
	*/
	class IncomingMessage
	{
	public:
		/*!
		\brief Key-value pairs of header names and values. Header names are lower-cased
		*/
		Object headers;
		/*!
		\brief HTTP Version sent by client. Usually either '1.0' or '1.1'
		*/
		String httpVersion;
		/*!
		\brief Request Method as a String. (ie: GET, PUT, etc)
		*/
		String method;
		/*!
		\brief The Socket object associated with this connection
		*/
		Socket socket;
		/*!
		\brief 3 digit HTTP Status Code. (ie: 200, 404, etc)
		*/
		integer statusCode;
		/*!
		\brief HTTP Status Message (ie: 'OK', 'File Not Found', etc)
		*/
		String statusMessage;
		/*!
		\brief HTTP Request Path line (ie: '/index.html', etc)
		*/
		String url;
	};

	/*!
	\brief Network Uri abstraction
	*/
	class Uri
	{
	public:
		/*!
		\brief Protocol (ie: http, https, wss, etc)
		*/
		String protocol;
		/*!
		\brief Host IP or DNS Name
		*/
		String host;
		/*!
		\brief Host port
		*/
		integer port;
		/*!
		\brief Method Path (ie: /index.html)
		*/
		String path;
		/*!
		\brief Method. (ie: GET, PUT, HEAD, etc)
		*/
		String method;
	};
};


/*!
\brief Provides HTTP-Digest Authentication Services. <b>Note:</b> To use must <b>require('http-digest').Create()</b>
*
After creation, the 'http' property must be set, typically with <b>require('http')</b>. Afterwards, calls to 'request' can be made.
*/
class HttpDigest 
{
public:
	/*!
	\brief Initializes an HttpDigest object with the specified username and password.
	\param username \<String\> The username to encode
	\param password \<String\> The password to encode
	\return HttpDigest instance
	*/
	static HttpDigest Create(username, password);
	/*!
	\brief Wrapped Http implementation, which <b>must</b> be set. Typically set to <b>require('http')</b> or <b>require('https')</b>
	*/
	Http http;
	/*!
	\brief Issues a Digest-Authenticated HTTP Request onto the network
	*
	static DigestClientRequest request(options[, callback]);
	\param options \<Object\|String\|Url\>\n
	<b>protocol</b> \<String\> Protocol to use. Defaults to 'http:' or 'https:' depending on configuration\n
	<b>host</b> \<String\> A domain name or IP address of the server to issue the request to. Defaults to localhost.\n
	<b>hostname</b> \<String\> Alias for host. To support url.parse(), hostname is preferred over host.\n
	<b>port</b> <number> Port of remote server. Defaults to 80, or 443, depending on configuration\n
	<b>localAddress</b> \<String\> Local interface to bind for network connections.\n
	<b>method</b> \<String\> A string specifying the HTTP request method. Defaults to 'GET'.\n
	<b>path</b> \<String\> Request path. Defaults to '/'\n
	<b>headers</b> <Object> An object containing request headers.\n
	<b>proxy</b> <Object> An object containing proxy settings, (ie: 'host' and 'port'), to use for this connection\n
	<b>noProxy</b> <boolean> When present, will override any previously set proxies, and disable it for this connection\n
	<b>pfx</b> \<Buffer\|String\> containing pks encoded certificate\n
	<b>passphrase</b> \<String\> containing passphrase used to unlock specified certificate\n
	<b>MeshAgent</b> <MeshAgent> containing the MeshAgent instance, whose certificates will be used\n
	<b>rejectUnauthorized</b> <boolean> If true, will reject server's whose root of trust cannot be validated\n
	<b>checkServerIdentity</b> <func> callback that will be dispatched to validate server certificate. <b>Note:</b> To fail validation, throw an exception from the dispatch.\n
	\param callback <func> Optiona. Set as one time listener to DigestClientRequest.response event.
	\return \<DigestClientRequest\>
	*/
	DigestClientRequest request(options[, callback]);

	/*!
	\implements Http::ClientRequest
	\brief Encapsulation of Http::ClientRequest. Digest-Authentication may require multiple request/response sequences, so the underlying Http::ClientRequest may change
	*/
	class DigestClientRequest
	{
	};
};


/*!
\brief Helper function to parse HTTP Headers. <b>Note:</b> To use, must <b>require('http-headers')</b>
*/
class HttpHeaders
{
public:
	/*!
	\brief Parses the specified buffer
	*
	static HttpHeaders HttpHeaders(data[, headersOnly]);
	\param data \<Buffer\|String\> The data to parse
	\param headersOnly <boolean> Optional parameter, that if true, will indicate to the parser to skip parsing of the Method/Path/Version/etc.
	\return HttpHeaders representing the parsed data
	*/
	static HttpHeaders HttpHeaders(data[, headersOnly]);

	/*!
	\brief HTTP Method. (ie: GET, PUT, HEAD, etc)
	*/
	public String method;
	/*!
	\brief HTTP Method Path (ie: /index.html)
	*/
	public String url;
	/*!
	\brief HTTP Status Code (ie: 200)
	*/
	public integer statusCode;
	/*!
	\brief HTTP Status Code Message (ie: OK)
	*/
	public String statusMessage;
	/*!
	\brief HttpVersion of the decoded HTTP headers
	*/
	public HttpVersion version;
	/*!
	\brief JSON object of decoded HTTP headers. Property key is header name, Property value is header value.
	*/
	public object headers;

	/*!
	\brief HTTP Version 
	*/
	class HttpVersion
	{
	public:
		/*!
		\brief major version
		*/
		public String major;
		/*!
		\brief minor version
		*/
		public String minor;
	};
};
#endif
