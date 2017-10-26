#include "ILibDuktape_SHA256.h"
#include "duktape.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_WritableStream.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_EventEmitter.h"
#include "../microstack/ILibCrypto.h"

#define ILibDuktape_MD5_PTR						"\xFF_MD5PTR"
#define ILibDuktape_SHA256_PTR					"\xFF_SHA256PTR"
#define ILibDuktape_SHA512_PTR					"\xFF_SHA512PTR"
#define ILibDuktape_SHA256_SIGNER_PTR			"\xFF_SHA256_SIGNER_PTR"
#define ILibDuktape_SHA256_SIGNER_CERT			"\xFF_SHA256_SIGNER_CERT"
#define ILibDuktape_SHA256_SIGNER_CERT_ALLOC	"\xFF_SHA256_SIGNER_CERT_ALLOC"
#define ILibDuktape_SHA256_SIGNER_SIGBUFFER		"\xFF_SHA256_SIGNER_SIG_BUFFER"

#ifndef MICROSTACK_NOTLS

typedef struct ILibDuktape_SHA256_Data
{
	duk_context *ctx;

	void *object;
	void *OnHash;
	void *OnHashString;
	char buffer[33];
	SHA256_CTX shctx;
}ILibDuktape_SHA256_Data;
typedef struct ILibDuktape_SHA512_Data
{
	duk_context *ctx;

	void *object;
	void *OnHash;
	void *OnHashString;
	char buffer[65];
	SHA512_CTX shctx;
}ILibDuktape_SHA512_Data;
typedef struct ILibDuktape_MD5_Data
{
	duk_context *ctx;

	void *object;
	void *OnHash;
	void *OnHashString;
	char buffer[33];
	MD5_CTX mctx;
}ILibDuktape_MD5_Data;

typedef struct ILibDuktape_SHA256_Signer_Data
{
	duk_context *ctx;
	EVP_MD_CTX *mdctx;

	void *obj;
	ILibDuktape_WritableStream *writableStream;
	void *OnSignature;
	void *OnSignatureString;
}ILibDuktape_SHA256_Signer_Data;

duk_ret_t ILibDuktape_SHA256_Finalizer(duk_context *ctx)
{
	return 0;
}
duk_ret_t ILibDuktape_SHA384_Finalizer(duk_context *ctx)
{
	return 0;
}
ILibTransport_DoneState ILibDuktape_SHA256_Write(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_SHA256_Data *data = (ILibDuktape_SHA256_Data*)user;

	SHA256_Update(&(data->shctx), buffer, bufferLen);
	return(ILibTransport_DoneState_COMPLETE);
}
ILibTransport_DoneState ILibDuktape_SHA384_Write(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_SHA512_Data *data = (ILibDuktape_SHA512_Data*)user;

	SHA384_Update(&(data->shctx), buffer, bufferLen);
	return(ILibTransport_DoneState_COMPLETE);
}
void ILibDuktape_SHA256_End(struct ILibDuktape_WritableStream *stream, void *user)
{

	ILibDuktape_SHA256_Data *data = (ILibDuktape_SHA256_Data*)user;
	data->buffer[32] = 0;
	SHA256_Final((unsigned char*)data->buffer, &(data->shctx));

	if (data->ctx != NULL && data->OnHash != NULL)
	{
		duk_push_heapptr(data->ctx, data->OnHash);				// [func]
		duk_push_heapptr(data->ctx, data->object);				// [func][this]
		duk_push_external_buffer(data->ctx);					// [func][this][hash]
		duk_config_buffer(data->ctx, -1, data->buffer, 32);	
		if (duk_pcall_method(data->ctx, 1) != 0)				// [retVal]
		{
			ILibDuktape_Process_UncaughtException(data->ctx);
		}
		duk_pop(data->ctx);										// ...
	}
	if (data->ctx != NULL && data->OnHashString != NULL)
	{
		duk_push_heapptr(data->ctx, data->OnHashString);					// [func]
		duk_push_heapptr(data->ctx, data->object);							// [func][this]
		duk_push_string(data->ctx, util_tohex(data->buffer, 32, ILibScratchPad));	// [func][this][hashString]
		if (duk_pcall_method(data->ctx, 1) != 0)							// [retVal]
		{
			ILibDuktape_Process_UncaughtException(data->ctx);
		}
		duk_pop(data->ctx);													// ...
	}
}
void ILibDuktape_SHA384_End(struct ILibDuktape_WritableStream *stream, void *user)
{
	ILibDuktape_SHA512_Data *data = (ILibDuktape_SHA512_Data*)user;
	data->buffer[48] = 0;
	SHA384_Final((unsigned char*)data->buffer, &(data->shctx));

	if (data->ctx != NULL && data->OnHash != NULL)
	{
		duk_push_heapptr(data->ctx, data->OnHash);				// [func]
		duk_push_heapptr(data->ctx, data->object);				// [func][this]
		duk_push_external_buffer(data->ctx);					// [func][this][hash]
		duk_config_buffer(data->ctx, -1, data->buffer, 48);
		if (duk_pcall_method(data->ctx, 1) != 0)				// [retVal]
		{
			ILibDuktape_Process_UncaughtException(data->ctx);
		}
		duk_pop(data->ctx);										// ...
	}
	if (data->ctx != NULL && data->OnHashString != NULL)
	{
		duk_push_heapptr(data->ctx, data->OnHashString);					// [func]
		duk_push_heapptr(data->ctx, data->object);							// [func][this]
		duk_push_string(data->ctx, util_tohex(data->buffer, 48, ILibScratchPad));	// [func][this][hashString]
		if (duk_pcall_method(data->ctx, 1) != 0)							// [retVal]
		{
			ILibDuktape_Process_UncaughtException(data->ctx);
		}
		duk_pop(data->ctx);													// ...
	}
}
duk_ret_t ILibDuktape_SHA256_SIGNER_Finalizer(duk_context *ctx)
{
	ILibDuktape_SHA256_Signer_Data *data;
	duk_get_prop_string(ctx, 0, ILibDuktape_SHA256_SIGNER_PTR);

	data = (ILibDuktape_SHA256_Signer_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	if (data->mdctx != NULL)
	{
		EVP_MD_CTX_destroy(data->mdctx);
		data->mdctx = NULL;
	}

	return 0;
}
void ILibDuktape_SHA256_SIGNER_End(struct ILibDuktape_WritableStream *stream, void *user)
{
	ILibDuktape_SHA256_Signer_Data *data = (ILibDuktape_SHA256_Signer_Data*)user;
	size_t len;
	char *buffer;

	EVP_DigestSignFinal(data->mdctx, NULL, &len);
	duk_push_heapptr(data->ctx, data->obj);											// [signer]
	duk_push_fixed_buffer(data->ctx, len);											// [signer][sigBuffer]
	buffer = (char*)Duktape_GetBuffer(data->ctx, -1, NULL);
	duk_put_prop_string(data->ctx, -2, ILibDuktape_SHA256_SIGNER_SIGBUFFER);		// [signer]

	EVP_DigestSignFinal(data->mdctx, (unsigned char*)buffer, &len);

	if (data->OnSignature != NULL)
	{
		duk_get_prop_string(data->ctx, -1, ILibDuktape_SHA256_SIGNER_SIGBUFFER);						// [signer][sigBuffer]
		duk_swap_top(data->ctx, -2);																	// [sigBuffer][signer]
		duk_push_heapptr(data->ctx, data->OnSignature);													// [sigBuffer][signer][func]
		duk_swap_top(data->ctx, -2);																	// [sigBuffer][func][signer/this]
		duk_push_buffer_object(data->ctx, -3, 0, len, DUK_BUFOBJ_DUKTAPE_BUFFER);						// [sigBuffer][func][signer/this][bufView]
		if (duk_pcall_method(data->ctx, 1) != 0) { ILibDuktape_Process_UncaughtException(data->ctx); }	// ...
	}
	duk_pop(data->ctx);																// ...
}
ILibTransport_DoneState ILibDuktape_SHA256_SIGNER_Write(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_SHA256_Signer_Data *data = (ILibDuktape_SHA256_Signer_Data*)user;
	EVP_DigestSignUpdate(data->mdctx, buffer, bufferLen);
	return(ILibTransport_DoneState_COMPLETE);
}
duk_ret_t ILibDuktape_SHA256_VERIFIER_Create(duk_context *ctx)
{
	//ILibDuktape_SHA256_Signer_Data *data;

	//duk_push_this(ctx);														// [signer]
	//duk_get_prop_string(ctx, -1, ILibDuktape_SHA256_SIGNER_PTR);			// [signer][ptr]
	//data = (ILibDuktape_SHA256_Signer_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	//duk_pop(ctx);															// [signer]

	return(ILibDuktape_Error(ctx, "Not implemented"));
}
duk_ret_t ILibDuktape_SHA256_SIGNER_Create(duk_context *ctx)
{
	ILibDuktape_SHA256_Signer_Data *data;
	struct util_cert *cert;

	duk_push_this(ctx);														// [signer]
	duk_get_prop_string(ctx, -1, ILibDuktape_SHA256_SIGNER_PTR);			// [signer][ptr]
	data = (ILibDuktape_SHA256_Signer_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_pop(ctx);															// [signer]

	if (duk_has_prop_string(ctx, 0, "MeshAgent"))
	{
		duk_get_prop_string(ctx, 0, "MeshAgent");
		duk_get_prop_string(ctx, -1, ILibDuktape_MeshAgent_Cert_NonLeaf);
		cert = (struct util_cert*)duk_get_pointer(ctx, -1);
	}
	else if (duk_has_prop_string(ctx, 0, "pfx") && duk_has_prop_string(ctx, 0, "passphrase"))
	{
		char *pfx;
		duk_size_t pfxLen;
		char *passphrase;

		duk_get_prop_string(ctx, 0, "passphrase");							// [signer][passphrase]
		passphrase = (char*)duk_get_string(ctx, -1);
		duk_pop(ctx);														// [signer]
		duk_get_prop_string(ctx, 0, "pfx");									// [signer][pfx]
		pfx = Duktape_GetBuffer(ctx, -1, &pfxLen);
		duk_pop(ctx);														// [signer]

		duk_push_fixed_buffer(ctx, sizeof(struct util_cert));				// [signer][buffer]
		cert = (struct util_cert*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_put_prop_string(ctx, -2, ILibDuktape_SHA256_SIGNER_CERT);		// [signer]
		if (util_from_p12(pfx, (int)pfxLen, passphrase, cert) == 0)
		{
			duk_push_string(ctx, "SHA256_Signer_Create: Invalid PFX/Passphrase");
			duk_throw(ctx);
			return(DUK_RET_ERROR);
		}
		else
		{
			duk_push_boolean(ctx, 1);											// [signer][cert-alloc]
			duk_put_prop_string(ctx, -2, ILibDuktape_SHA256_SIGNER_CERT_ALLOC);	// [signer]
		}

	}
	else if (duk_has_prop_string(ctx, 0, ILibDuktape_MeshAgent_Cert_NonLeaf))
	{
		duk_get_prop_string(ctx, 0, ILibDuktape_MeshAgent_Cert_NonLeaf);		// [signer][cert]
		cert = (struct util_cert*)duk_get_pointer(ctx, -1);
		duk_pop(ctx);															// [signer]
	}
	else
	{
		duk_push_string(ctx, "SHA256_Signer_Create: Unrecognized paramter");
		duk_throw(ctx);
		return(DUK_RET_ERROR);
	}

	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_SHA256_SIGNER_Finalizer);

	data->mdctx = EVP_MD_CTX_create();
	EVP_DigestSignInit(data->mdctx, NULL, EVP_sha256(), NULL, cert->pkey);
	data->writableStream = ILibDuktape_WritableStream_Init(ctx, ILibDuktape_SHA256_SIGNER_Write, ILibDuktape_SHA256_SIGNER_End, data);

	ILibDuktape_CreateEventWithSetter(ctx, "OnSignature", "\xFF_OnSignature", &(data->OnSignature));

	return 1;
}
void ILibDuktape_SHA256_SIGNER_PUSH(duk_context *ctx, void *chain)
{
	ILibDuktape_SHA256_Signer_Data* data;
	duk_push_object(ctx);													// [signer]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_SHA256_Signer_Data));		// [signer][data]
	data = (ILibDuktape_SHA256_Signer_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_SHA256_SIGNER_PTR);			// [signer]

	memset(data, 0, sizeof(ILibDuktape_SHA256_Signer_Data));
	data->obj = duk_get_heapptr(ctx, -1);
	data->ctx = ctx;
	ILibDuktape_CreateInstanceMethod(ctx, "Create", ILibDuktape_SHA256_SIGNER_Create, 1);
}
void ILibDuktape_SHA256_VERIFY_PUSH(duk_context *ctx, void *chain)
{
	ILibDuktape_SHA256_Signer_Data* data;
	duk_push_object(ctx);													// [signer]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_SHA256_Signer_Data));		// [signer][data]
	data = (ILibDuktape_SHA256_Signer_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_SHA256_SIGNER_PTR);			// [signer]

	memset(data, 0, sizeof(ILibDuktape_SHA256_Signer_Data));
	data->obj = duk_get_heapptr(ctx, -1);
	data->ctx = ctx;
	ILibDuktape_CreateInstanceMethod(ctx, "Create", ILibDuktape_SHA256_VERIFIER_Create, 1);
}
duk_ret_t ILibDuktape_SHA256_syncHash(duk_context *ctx)
{
	ILibDuktape_SHA256_Data *data;
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);

	duk_push_this(ctx);													// [sha]
	duk_get_prop_string(ctx, -1, ILibDuktape_SHA256_PTR);
	data = (ILibDuktape_SHA256_Data*)Duktape_GetBuffer(ctx, -1, NULL);

	SHA256_Init(&(data->shctx));
	SHA256_Update(&(data->shctx), buffer, bufferLen);
	SHA256_Final((unsigned char*)data->buffer, &(data->shctx));
	data->buffer[32] = 0;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "strRet");
	if (duk_get_boolean(ctx, -1) == 0)
	{
		duk_push_external_buffer(ctx);
		duk_config_buffer(ctx, -1, data->buffer, 32);
	}
	else
	{
		util_tohex(data->buffer, 32, ILibScratchPad);
		duk_push_string(ctx, ILibScratchPad);
	}
	return(1);
}
duk_ret_t ILibDuktape_SHA384_syncHash(duk_context *ctx)
{
	ILibDuktape_SHA512_Data *data;
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);

	duk_push_this(ctx);													// [sha]
	duk_get_prop_string(ctx, -1, ILibDuktape_SHA512_PTR);
	data = (ILibDuktape_SHA512_Data*)Duktape_GetBuffer(ctx, -1, NULL);

	SHA384_Init(&(data->shctx));
	SHA384_Update(&(data->shctx), buffer, bufferLen);
	SHA384_Final((unsigned char*)data->buffer, &(data->shctx));
	data->buffer[48] = 0;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "strRet");
	if (duk_get_boolean(ctx, -1) == 0)
	{
		duk_push_external_buffer(ctx);
		duk_config_buffer(ctx, -1, data->buffer, 48);
	}
	else
	{
		util_tohex(data->buffer, 48, ILibScratchPad);
		duk_push_string(ctx, ILibScratchPad);
	}
	return(1);
}

ILibTransport_DoneState ILibDuktape_MD5_Write(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_MD5_Data *data = (ILibDuktape_MD5_Data*)user;

	MD5_Update(&(data->mctx), buffer, bufferLen);
	return(ILibTransport_DoneState_COMPLETE);
}
void ILibDuktape_MD5_End(struct ILibDuktape_WritableStream *stream, void *user)
{
	ILibDuktape_MD5_Data *data = (ILibDuktape_MD5_Data*)user;
	data->buffer[32] = 0;
	MD5_Final((unsigned char*)data->buffer, &(data->mctx));

	if (data->ctx != NULL && data->OnHash != NULL)
	{
		duk_push_heapptr(data->ctx, data->OnHash);				// [func]
		duk_push_heapptr(data->ctx, data->object);				// [func][this]
		duk_push_external_buffer(data->ctx);					// [func][this][hash]
		duk_config_buffer(data->ctx, -1, data->buffer, 32);
		if (duk_pcall_method(data->ctx, 1) != 0)				// [retVal]
		{
			ILibDuktape_Process_UncaughtException(data->ctx);
		}
		duk_pop(data->ctx);										// ...
	}
	if (data->ctx != NULL && data->OnHashString != NULL)
	{
		duk_push_heapptr(data->ctx, data->OnHashString);					// [func]
		duk_push_heapptr(data->ctx, data->object);							// [func][this]
		duk_push_string(data->ctx, util_tohex(data->buffer, 32, ILibScratchPad));	// [func][this][hashString]
		if (duk_pcall_method(data->ctx, 1) != 0)							// [retVal]
		{
			ILibDuktape_Process_UncaughtException(data->ctx);
		}
		duk_pop(data->ctx);													// ...
	}
}
duk_ret_t ILibDuktape_MD5_syncHash(duk_context *ctx)
{
	ILibDuktape_MD5_Data *data;
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);

	duk_push_this(ctx);													// [sha]
	duk_get_prop_string(ctx, -1, ILibDuktape_MD5_PTR);
	data = (ILibDuktape_MD5_Data*)Duktape_GetBuffer(ctx, -1, NULL);

	MD5_Init(&(data->mctx));
	MD5_Update(&(data->mctx), buffer, bufferLen);
	MD5_Final((unsigned char*)data->buffer, &(data->mctx));
	data->buffer[32] = 0;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "strRet");
	if (duk_get_boolean(ctx, -1) == 0)
	{
		duk_push_external_buffer(ctx);
		duk_config_buffer(ctx, -1, data->buffer, 32);
	}
	else
	{
		util_tohex(data->buffer, 32, ILibScratchPad);
		duk_push_string(ctx, ILibScratchPad);
	}
	return(1);
}

duk_ret_t ILibDuktape_MD5_Create(duk_context *ctx)
{
	ILibDuktape_MD5_Data *data;
	ILibDuktape_EventEmitter *emitter;

	duk_push_object(ctx);											// [md5]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_MD5_Data));		// [md5][buffer]
	data = (ILibDuktape_MD5_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_MD5_PTR);				// [md5]
	emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_CreateInstanceMethodWithBooleanProperty(ctx, "strRet", 0, "syncHash", ILibDuktape_MD5_syncHash, 1);
	ILibDuktape_CreateInstanceMethodWithBooleanProperty(ctx, "strRet", 1, "syncHashString", ILibDuktape_MD5_syncHash, 1);

	ILibDuktape_EventEmitter_CreateEvent(emitter, "hash", &(data->OnHash));
	ILibDuktape_EventEmitter_CreateEvent(emitter, "hashString", &(data->OnHashString));

	data->ctx = ctx;
	data->object = duk_get_heapptr(ctx, -1);
	MD5_Init(&(data->mctx));

	ILibDuktape_WritableStream_Init(ctx, ILibDuktape_MD5_Write, ILibDuktape_MD5_End, data);
	return(1);
}
duk_ret_t ILibDuktape_SHA256_Create(duk_context *ctx)
{
	ILibDuktape_SHA256_Data *data;
	ILibDuktape_EventEmitter *emitter;

	duk_push_object(ctx);											// [sha]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_SHA256_Data));	// [sha][buffer]
	data = (ILibDuktape_SHA256_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_SHA256_PTR);			// [sha]
	emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_SHA256_Finalizer);

	ILibDuktape_CreateInstanceMethodWithBooleanProperty(ctx, "strRet", 0, "syncHash", ILibDuktape_SHA256_syncHash, 1);
	ILibDuktape_CreateInstanceMethodWithBooleanProperty(ctx, "strRet", 1, "syncHashString", ILibDuktape_SHA256_syncHash, 1);

	ILibDuktape_EventEmitter_CreateEvent(emitter, "hash", &(data->OnHash));
	ILibDuktape_EventEmitter_CreateEvent(emitter, "hashString", &(data->OnHashString));

	data->ctx = ctx;
	data->object = duk_get_heapptr(ctx, -1);
	SHA256_Init(&(data->shctx));

	ILibDuktape_WritableStream_Init(ctx, ILibDuktape_SHA256_Write, ILibDuktape_SHA256_End, data);

	return(1);
}
duk_ret_t ILibDuktape_SHA384_Create(duk_context *ctx)
{
	ILibDuktape_SHA512_Data *data;
	ILibDuktape_EventEmitter *emitter;

	duk_push_object(ctx);											// [sha]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_SHA512_Data));	// [sha][buffer]
	data = (ILibDuktape_SHA512_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_SHA512_PTR);			// [sha]
	emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_SHA384_Finalizer);

	ILibDuktape_CreateInstanceMethodWithBooleanProperty(ctx, "strRet", 0, "syncHash", ILibDuktape_SHA384_syncHash, 1);
	ILibDuktape_CreateInstanceMethodWithBooleanProperty(ctx, "strRet", 1, "syncHashString", ILibDuktape_SHA384_syncHash, 1);

	ILibDuktape_EventEmitter_CreateEvent(emitter, "hash", &(data->OnHash));
	ILibDuktape_EventEmitter_CreateEvent(emitter, "hashString", &(data->OnHashString));

	data->ctx = ctx;
	data->object = duk_get_heapptr(ctx, -1);
	SHA384_Init(&(data->shctx));

	ILibDuktape_WritableStream_Init(ctx, ILibDuktape_SHA384_Write, ILibDuktape_SHA384_End, data);

	return(1);
}
void ILibDuktape_SHA256_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);															// [sha]
	ILibDuktape_CreateInstanceMethod(ctx, "create", ILibDuktape_SHA256_Create, 0);
}
void ILibDuktape_SHA384_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);															// [sha]
	ILibDuktape_CreateInstanceMethod(ctx, "create", ILibDuktape_SHA384_Create, 0);
}
void ILibDuktape_MD5_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);															// [md5]
	ILibDuktape_CreateInstanceMethod(ctx, "create", ILibDuktape_MD5_Create, 0);
}
#endif
void ILibDuktape_SHA256_Init(duk_context * ctx)
{
#ifndef MICROSTACK_NOTLS
	ILibDuktape_ModSearch_AddHandler(ctx, "SHA256Stream_Signer", ILibDuktape_SHA256_SIGNER_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "SHA256Stream_Verifier", ILibDuktape_SHA256_VERIFY_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "SHA384Stream", ILibDuktape_SHA384_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "SHA256Stream", ILibDuktape_SHA256_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "MD5Stream", ILibDuktape_MD5_PUSH);
#endif
}


#ifdef __DOXY__
/*!
\implements WritableStream
\brief WritableStream that exposes MD5 Hashing functionality. <b>Note:</b> To use, must <b>require('MD5Stream')</b>
*/
class MD5Stream 
{
public:
	/*!
	\brief Performs an MD5 Hash of the data passed to this method
	\param data \<Buffer\|String\> The data to hash
	\return <Buffer> The MD5 hash of the supplied data
	*/
	Buffer syncHash(data);
	/*!
	\brief Performs an MD5 Hash of the data passed to this method, and returns the result as a Hex String
	\param data \<Buffer\|String\> The data to hash
	\return \<String\> The MD5 hash of the supplied data, as a Hex String
	*/
	String syncHashString(data);

	/*!
	\brief event dispatched when the WritableStream is finished
	\param data <Buffer> The MD5 Hash of the data fed thru the WritableStream
	*/
	void hash;
	/*!
	\brief event dispatched when the WritableStream is finished
	\param data \<String\> The MD5 Hash of the data fed thru the WritableStream, as a Hex String.
	*/
	void hashString;
};

/*!
\implements WritableStream
\brief WritableStream that exposes SHA256 Hashing functionality.  <b>Note:</b> To use, must <b>require('SHA256Stream')</b>
*/
class SHA256Stream 
{
public:
	/*!
	\brief Performs a SHA256 Hash of the data passed to this method
	\param data \<Buffer\|String\> The data to hash
	\return <Buffer> The SHA256 hash of the supplied data
	*/
	Buffer syncHash(data);
	/*!
	\brief Performs a SHA256 Hash of the data passed to this method, and returns the result as a Hex String
	\param data \<Buffer\|String\> The data to hash
	\return \<String\> The SHA256 hash of the supplied data, as a Hex String
	*/
	String syncHashString(data);

	/*!
	\brief event dispatched when the WritableStream is finished
	\param data <Buffer> The SHA256 Hash of the data fed thru the WritableStream
	*/
	void hash;
	/*!
	\brief event dispatched when the WritableStream is finished
	\param data \<String\> The SHA256 Hash of the data fed thru the WritableStream, as a Hex String.
	*/
	void hashString;
};
#endif