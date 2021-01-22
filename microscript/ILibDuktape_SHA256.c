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

#include "ILibDuktape_SHA256.h"
#include "duktape.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktape_WritableStream.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_EventEmitter.h"
#include "../microstack/ILibCrypto.h"

#define ILibDuktape_MD5_PTR						"\xFF_MD5PTR"
#define ILibDuktape_SHA1_PTR					"\xFF_SHA1PTR"
#define ILibDuktape_SHA256_PTR					"\xFF_SHA256PTR"
#define ILibDuktape_SHA512_PTR					"\xFF_SHA512PTR"
#define ILibDuktape_SHA256_SIGNER_PTR			"\xFF_SHA256_SIGNER_PTR"
#define ILibDuktape_SHA256_SIGNER_CERT			"\xFF_SHA256_SIGNER_CERT"
#define ILibDuktape_SHA256_SIGNER_CERT_ALLOC	"\xFF_SHA256_SIGNER_CERT_ALLOC"
#define ILibDuktape_SHA256_SIGNER_SIGBUFFER		"\xFF_SHA256_SIGNER_SIG_BUFFER"
#define ILibDuktape_VERIFIER_PTR				"\xFF_VERIFIER_PTR"
#define ILibDuktape_VERIFIER_SIG				"\xFF_VERIFIER_SIG"
#define ILibDuktape_VERIFIER_CERT				"\xFF_VERIFIER_CERT"

typedef struct ILibDuktape_SHA256_Data
{
	duk_context *ctx;

	void *object;
	char buffer[UTIL_SHA256_HASHSIZE];
	SHA256_CTX shctx;
}ILibDuktape_SHA256_Data;
typedef struct ILibDuktape_SHA512_Data
{
	duk_context *ctx;

	void *object;
	char buffer[UTIL_SHA512_HASHSIZE];
	SHA512_CTX shctx;
}ILibDuktape_SHA512_Data;
typedef struct ILibDuktape_MD5_Data
{
	duk_context *ctx;

	void *object;
	char buffer[UTIL_MD5_HASHSIZE];
	MD5_CTX mctx;
}ILibDuktape_MD5_Data;

typedef struct ILibDuktape_SHA1_Data
{
	duk_context *ctx;

	void *object;
	char buffer[UTIL_SHA1_HASHSIZE];
	SHA_CTX sctx;
}ILibDuktape_SHA1_Data;

#ifndef MICROSTACK_NOTLS
typedef struct ILibDuktape_Verifier_Data
{
	duk_context *ctx;
	EVP_MD_CTX* mdctx;
	ILibDuktape_WritableStream *writableStream;
	struct util_cert *cert;
	void *promise;
	char *sig;
	int sigLen;
}ILibDuktape_Verifier_Data;
typedef struct ILibDuktape_SHA256_Signer_Data
{
	duk_context *ctx;
	EVP_MD_CTX *mdctx;

	void *obj;
	ILibDuktape_WritableStream *writableStream;
	void *OnSignature;
	void *OnSignatureString;
}ILibDuktape_SHA256_Signer_Data;
#endif

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
	SHA256_Final((unsigned char*)data->buffer, &(data->shctx));

	duk_push_external_buffer(data->ctx);														// [extBuffer]
	duk_config_buffer(data->ctx, -1, data->buffer, UTIL_SHA256_HASHSIZE);
	ILibDuktape_EventEmitter_SetupEmit(data->ctx, data->object, "hash");						// [extBuffer][emit][this]['hash']
	duk_push_buffer_object(data->ctx, -4, 0, UTIL_SHA256_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);	// [extBuffer][emit][this]['hash'][hash]
	if (duk_pcall_method(data->ctx, 2) != 0) { ILibDuktape_Process_UncaughtException(data->ctx); }
	duk_pop_2(data->ctx);																		// ...
}
void ILibDuktape_SHA384_End(struct ILibDuktape_WritableStream *stream, void *user)
{
	ILibDuktape_SHA512_Data *data = (ILibDuktape_SHA512_Data*)user;
	SHA384_Final((unsigned char*)data->buffer, &(data->shctx));

	duk_push_external_buffer(data->ctx);														// [extBuffer]
	duk_config_buffer(data->ctx, -1, data->buffer, UTIL_SHA384_HASHSIZE);
	ILibDuktape_EventEmitter_SetupEmit(data->ctx, data->object, "hash");						// [extBuffer][emit][this]['hash']
	duk_push_buffer_object(data->ctx, -4, 0, UTIL_SHA384_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);	// [extBuffer][emit][this]['hash'][hash]
	if (duk_pcall_method(data->ctx, 2) != 0) { ILibDuktape_Process_UncaughtException(data->ctx); }
	duk_pop_2(data->ctx);																		// ...
}

#ifndef MICROSTACK_NOTLS
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
		duk_push_buffer_object(data->ctx, -3, 0, len, DUK_BUFOBJ_NODEJS_BUFFER);						// [sigBuffer][func][signer/this][bufView]
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
			return(ILibDuktape_Error(ctx, "Invalid PFX/Passphrase"));
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
		return(ILibDuktape_Error(ctx, "Unrecognized parameter"));
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
	data = (ILibDuktape_SHA256_Signer_Data*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_SHA256_Signer_Data));
	duk_buffer_enable_autoclear(ctx);
	duk_put_prop_string(ctx, -2, ILibDuktape_SHA256_SIGNER_PTR);			// [signer]
	data->obj = duk_get_heapptr(ctx, -1);
	data->ctx = ctx;
	ILibDuktape_CreateInstanceMethod(ctx, "Create", ILibDuktape_SHA256_SIGNER_Create, 1);
}

ILibTransport_DoneState ILibDuktape_VERIFIER_WriteSink(ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	if (!ILibMemory_CanaryOK(user)) { return(ILibTransport_DoneState_ERROR); }
	ILibDuktape_Verifier_Data *data = (ILibDuktape_Verifier_Data*)user;
	EVP_DigestVerifyUpdate(data->mdctx, buffer, bufferLen);
	return(ILibTransport_DoneState_COMPLETE);
}
void ILibDuktape_VERIFIER_EndSink(ILibDuktape_WritableStream *stream, void *user)
{
	if (!ILibMemory_CanaryOK(user)) { return; }
	ILibDuktape_Verifier_Data *data = (ILibDuktape_Verifier_Data*)user;

	duk_push_heapptr(data->ctx, data->promise);															// [promise]

	switch (EVP_DigestVerifyFinal(data->mdctx, (const unsigned char*)data->sig, (unsigned int)data->sigLen))
	{
		case 0:
			// SigFail
			duk_get_prop_string(data->ctx, -1, "_rej");													// [promise][rejector]
			duk_swap_top(data->ctx, -2);																// [rejector][this]
			duk_push_string(data->ctx, "Signature Failed");												// [rejector][this][badsig]
			duk_call_method(data->ctx, 1);																// [...]
			break;
		case 1:
			// SigSuccess
			duk_get_prop_string(data->ctx, -1, "_res");													// [promise][resolved]
			duk_swap_top(data->ctx, -2);																// [resolved][this]
			duk_call_method(data->ctx, 0);																// [...]
			break;
		default:
			// Error
			duk_get_prop_string(data->ctx, -1, "_rej");													// [promise][rejector]
			duk_swap_top(data->ctx, -2);																// [rejector][this]
			duk_push_sprintf(data->ctx, "EVP_VerifyFinal(): Returned error (%llu) ", (uint64_t)ERR_get_error());	// [rejector][this][error]
			duk_call_method(data->ctx, 1);																// [...]
			break;
	}
	duk_pop(data->ctx);																					// 
}

duk_ret_t ILibDuktape_VERIFIER_Create(duk_context *ctx)
{
	duk_push_current_function(ctx);
	const EVP_MD *mdtype = (const EVP_MD*)Duktape_GetPointerProperty(ctx, -1, "mdtype");
	char *sig;
	duk_size_t sigLen;
	void *promise;
	duk_eval_string(ctx, "(function verifyInit(){var p = require('promise'); var ret = new p(function(res, rej){this._res = res; this._rej = rej;}); return(ret);})();");	// [p]
	promise = duk_get_heapptr(ctx, -1);

	duk_dup(ctx, 1); 
	sig = (char*)duk_to_lstring(ctx, -1, &sigLen);
	duk_put_prop_string(ctx, -2, ILibDuktape_VERIFIER_SIG);
	ILibDuktape_Verifier_Data *data = (ILibDuktape_Verifier_Data*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_Verifier_Data));
	duk_put_prop_string(ctx, -2, ILibDuktape_VERIFIER_PTR);
	data->ctx = ctx;
		
	data->mdctx = EVP_MD_CTX_create();

	data->sig = sig;
	data->sigLen = (int)sigLen;
	data->promise = promise;

	duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, ILibDuktape_VERIFIER_CERT);
	data->cert = (struct util_cert*)Duktape_GetBufferProperty(ctx, 0, ILibDuktape_TLS_util_cert);
#ifdef OLDSSL
	EVP_PKEY *pkey = X509_get_pubkey(data->cert->x509);
#else
	EVP_PKEY *pkey = X509_get0_pubkey(data->cert->x509);
#endif


	EVP_DigestVerifyInit(data->mdctx, NULL, mdtype, NULL, pkey);
	data->writableStream = ILibDuktape_WritableStream_Init(ctx, ILibDuktape_VERIFIER_WriteSink, ILibDuktape_VERIFIER_EndSink, data);
	return(1);
}
void ILibDuktape_SHA256_VERIFY_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_CreateInstanceMethodWithPointerProperty(ctx, "mdtype", (void*)EVP_sha256(), "Create", ILibDuktape_VERIFIER_Create, DUK_VARARGS);
}
void ILibDuktape_SHA384_VERIFY_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_CreateInstanceMethodWithPointerProperty(ctx, "mdtype", (void*)EVP_sha384(), "Create", ILibDuktape_VERIFIER_Create, DUK_VARARGS);
}
void ILibDuktape_SHA512_VERIFY_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_CreateInstanceMethodWithPointerProperty(ctx, "mdtype", (void*)EVP_sha512(), "Create", ILibDuktape_VERIFIER_Create, DUK_VARARGS);
}
duk_ret_t ILibDuktape_RSA_Sign(duk_context *ctx)
{
	struct util_cert *cert = (struct util_cert*)Duktape_GetBufferProperty(ctx, 1, ILibDuktape_TLS_util_cert);
	if (cert->pkey == NULL) return(ILibDuktape_Error(ctx, "Private Key Access Denied"));

	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 2, &bufferLen);
	RSA *r = EVP_PKEY_get1_RSA(cert->pkey);
	int rsalen = RSA_size(r);
	char *sig = duk_push_fixed_buffer(ctx, rsalen);
	duk_push_buffer_object(ctx, -1, 0, rsalen, DUK_BUFOBJ_NODEJS_BUFFER);

	if (RSA_sign(duk_require_int(ctx, 0), (unsigned char*)buffer, (unsigned int)bufferLen, (unsigned char*)sig, (unsigned int*)&rsalen, r) != 1)
	{
		// Failed
		unsigned long err = ERR_get_error();
		char *reason = (char*)ERR_reason_error_string(err);
		RSA_free(r);
		return(ILibDuktape_Error(ctx, "RSA_sign() Error: (%lu, %s)", err, reason));
	}
	RSA_free(r);
	return(1);
}
duk_ret_t ILibDuktape_RSA_Verify(duk_context *ctx)
{
	duk_size_t bufferLen, sigLen;
	char *buffer = Duktape_GetBuffer(ctx, 2, &bufferLen);
	char *sig = Duktape_GetBuffer(ctx, 3, &sigLen);

	struct util_cert *cert = (struct util_cert*)Duktape_GetBufferProperty(ctx, 1, ILibDuktape_TLS_util_cert);
#ifdef OLDSSL
	RSA *r = EVP_PKEY_get1_RSA(X509_get_pubkey(cert->x509));
#else
	RSA *r = EVP_PKEY_get1_RSA(X509_get0_pubkey(cert->x509));
#endif
	int vstatus = RSA_verify(duk_require_int(ctx, 0), (unsigned char*)buffer, (unsigned int)bufferLen, (unsigned char*)sig, (unsigned int)sigLen, r);
	duk_push_boolean(ctx, vstatus == 1);
	RSA_free(r);
	return(1);
}
void ILibDuktape_RSA_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_CreateInstanceMethod(ctx, "sign", ILibDuktape_RSA_Sign, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "verify", ILibDuktape_RSA_Verify, DUK_VARARGS);
	duk_push_object(ctx);
	duk_push_int(ctx, NID_sha256); duk_put_prop_string(ctx, -2, "SHA256");
	duk_push_int(ctx, NID_sha384); duk_put_prop_string(ctx, -2, "SHA384");
	duk_push_int(ctx, NID_sha512); duk_put_prop_string(ctx, -2, "SHA512");
	duk_put_prop_string(ctx, -2, "TYPES");
}
#endif

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

	duk_push_external_buffer(ctx);
	duk_config_buffer(ctx, -1, data->buffer, UTIL_SHA256_HASHSIZE);
	duk_push_buffer_object(ctx, -1, 0, UTIL_SHA256_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);

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

	duk_push_external_buffer(ctx);
	duk_config_buffer(ctx, -1, data->buffer, UTIL_SHA384_HASHSIZE);
	duk_push_buffer_object(ctx, -1, 0, UTIL_SHA384_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);

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
	MD5_Final((unsigned char*)data->buffer, &(data->mctx));

	duk_push_external_buffer(data->ctx);													// [extBuffer]
	duk_config_buffer(data->ctx, -1, data->buffer, UTIL_MD5_HASHSIZE);
	ILibDuktape_EventEmitter_SetupEmit(data->ctx, data->object, "hash");					// [extBuffer][emit][this]["hash"]
	duk_push_buffer_object(data->ctx, -4, 0, UTIL_MD5_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);	// [extBuffer][emit][this]["hash"][buffer]
	if (duk_pcall_method(data->ctx, 2) != 0)												// [extBuffer][retVal]
	{
		ILibDuktape_Process_UncaughtException(data->ctx);
	}
	duk_pop_2(data->ctx);																	// ...
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

	duk_push_external_buffer(ctx);
	duk_config_buffer(ctx, -1, data->buffer, UTIL_MD5_HASHSIZE);
	duk_push_buffer_object(ctx, -1, 0, UTIL_MD5_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);

	return(1);
}

duk_ret_t ILibDuktape_MD5_Create(duk_context *ctx)
{
	ILibDuktape_MD5_Data *data;
	ILibDuktape_EventEmitter *emitter;

	duk_push_object(ctx);											// [md5]
	ILibDuktape_WriteID(ctx, "MD5Stream");
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_MD5_Data));		// [md5][buffer]
	data = (ILibDuktape_MD5_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_MD5_PTR);				// [md5]
	emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_CreateInstanceMethodWithBooleanProperty(ctx, "strRet", 0, "syncHash", ILibDuktape_MD5_syncHash, 1);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "hash");

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
	ILibDuktape_WriteID(ctx, "SHA256Stream");
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_SHA256_Data));	// [sha][buffer]
	data = (ILibDuktape_SHA256_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_SHA256_PTR);			// [sha]
	emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_SHA256_Finalizer);

	ILibDuktape_CreateInstanceMethod(ctx, "syncHash", ILibDuktape_SHA256_syncHash, 1);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "hash");

	data->ctx = ctx;
	data->object = duk_get_heapptr(ctx, -1);
	SHA256_Init(&(data->shctx));

	ILibDuktape_WritableStream_Init(ctx, ILibDuktape_SHA256_Write, ILibDuktape_SHA256_End, data);

	return(1);
}
ILibTransport_DoneState ILibDuktape_SHA512_Write(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_SHA512_Data *data = (ILibDuktape_SHA512_Data*)user;

	SHA512_Update(&(data->shctx), buffer, bufferLen);
	return(ILibTransport_DoneState_COMPLETE);
}
void ILibDuktape_SHA512_End(struct ILibDuktape_WritableStream *stream, void *user)
{
	ILibDuktape_SHA512_Data *data = (ILibDuktape_SHA512_Data*)user;
	SHA512_Final((unsigned char*)data->buffer, &(data->shctx));

	duk_push_external_buffer(data->ctx);														// [extBuffer]
	duk_config_buffer(data->ctx, -1, data->buffer, UTIL_SHA512_HASHSIZE);
	ILibDuktape_EventEmitter_SetupEmit(data->ctx, data->object, "hash");						// [extBuffer][emit][this]['hash']
	duk_push_buffer_object(data->ctx, -4, 0, UTIL_SHA512_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);	// [extBuffer][emit][this]['hash'][hash]
	if (duk_pcall_method(data->ctx, 2) != 0) { ILibDuktape_Process_UncaughtException(data->ctx); }
	duk_pop_2(data->ctx);																		// ...
}
duk_ret_t ILibDuktape_SHA512_syncHash(duk_context *ctx)
{
	ILibDuktape_SHA512_Data *data;
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);

	duk_push_this(ctx);													// [sha]
	duk_get_prop_string(ctx, -1, ILibDuktape_SHA512_PTR);
	data = (ILibDuktape_SHA512_Data*)Duktape_GetBuffer(ctx, -1, NULL);

	SHA512_Init(&(data->shctx));
	SHA512_Update(&(data->shctx), buffer, bufferLen);
	SHA512_Final((unsigned char*)data->buffer, &(data->shctx));

	duk_push_external_buffer(ctx);
	duk_config_buffer(ctx, -1, data->buffer, UTIL_SHA512_HASHSIZE);
	duk_push_buffer_object(ctx, -1, 0, UTIL_SHA512_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);

	return(1);
}
duk_ret_t ILibDuktape_SHA512_Create(duk_context *ctx)
{
	ILibDuktape_SHA512_Data *data;
	ILibDuktape_EventEmitter *emitter;

	duk_push_object(ctx);											// [sha]
	ILibDuktape_WriteID(ctx, "SHA512Stream");
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_SHA512_Data));	// [sha][buffer]
	data = (ILibDuktape_SHA512_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_SHA512_PTR);			// [sha]
	emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_SHA384_Finalizer);

	ILibDuktape_CreateInstanceMethod(ctx, "syncHash", ILibDuktape_SHA512_syncHash, 1);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "hash");

	data->ctx = ctx;
	data->object = duk_get_heapptr(ctx, -1);
	SHA512_Init(&(data->shctx));

	ILibDuktape_WritableStream_Init(ctx, ILibDuktape_SHA512_Write, ILibDuktape_SHA512_End, data);

	return(1);
}
duk_ret_t ILibDuktape_SHA384_Create(duk_context *ctx)
{
	ILibDuktape_SHA512_Data *data;
	ILibDuktape_EventEmitter *emitter;

	duk_push_object(ctx);											// [sha]
	ILibDuktape_WriteID(ctx, "SHA384Stream");
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_SHA512_Data));	// [sha][buffer]
	data = (ILibDuktape_SHA512_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_SHA512_PTR);			// [sha]
	emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_SHA384_Finalizer);

	ILibDuktape_CreateInstanceMethod(ctx, "syncHash", ILibDuktape_SHA384_syncHash, 1);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "hash");

	data->ctx = ctx;
	data->object = duk_get_heapptr(ctx, -1);
	SHA384_Init(&(data->shctx));

	ILibDuktape_WritableStream_Init(ctx, ILibDuktape_SHA384_Write, ILibDuktape_SHA384_End, data);

	return(1);
}
ILibTransport_DoneState ILibDuktape_SHA1_Write(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_SHA1_Data *data = (ILibDuktape_SHA1_Data*)user;

	SHA1_Update(&(data->sctx), buffer, bufferLen);
	return(ILibTransport_DoneState_COMPLETE);
}
void ILibDuktape_SHA1_End(struct ILibDuktape_WritableStream *stream, void *user)
{
	ILibDuktape_SHA1_Data *data = (ILibDuktape_SHA1_Data*)user;
	SHA1_Final((unsigned char*)data->buffer, &(data->sctx));

	duk_push_external_buffer(data->ctx);													// [extBuffer]
	duk_config_buffer(data->ctx, -1, data->buffer, UTIL_SHA1_HASHSIZE);
	ILibDuktape_EventEmitter_SetupEmit(data->ctx, data->object, "hash");					// [extBuffer][emit][this]["hash"]
	duk_push_buffer_object(data->ctx, -4, 0, UTIL_SHA1_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);	// [extBuffer][emit][this]["hash"][buffer]
	if (duk_pcall_method(data->ctx, 2) != 0)												// [extBuffer][retVal]
	{
		ILibDuktape_Process_UncaughtException(data->ctx);
	}
	duk_pop_2(data->ctx);																	// ...
}
duk_ret_t ILibDuktape_SHA1_syncHash(duk_context *ctx)
{
	ILibDuktape_SHA1_Data *data;
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);

	duk_push_this(ctx);													// [sha]
	duk_get_prop_string(ctx, -1, ILibDuktape_SHA1_PTR);
	data = (ILibDuktape_SHA1_Data*)Duktape_GetBuffer(ctx, -1, NULL);

	SHA1_Init(&(data->sctx));
	SHA1_Update(&(data->sctx), buffer, bufferLen);
	SHA1_Final((unsigned char*)data->buffer, &(data->sctx));

	duk_push_external_buffer(ctx);
	duk_config_buffer(ctx, -1, data->buffer, UTIL_SHA1_HASHSIZE);
	duk_push_buffer_object(ctx, -1, 0, UTIL_SHA1_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);

	return(1);
}
duk_ret_t ILibDuktape_SHA1_Create(duk_context *ctx)
{
	ILibDuktape_SHA1_Data *data;
	ILibDuktape_EventEmitter *emitter;

	duk_push_object(ctx);											// [SHA]
	ILibDuktape_WriteID(ctx, "SHA1Stream");
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_SHA1_Data));		// [SHA][buffer]
	data = (ILibDuktape_SHA1_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_SHA1_PTR);				// [SHA]
	emitter = ILibDuktape_EventEmitter_Create(ctx);

	ILibDuktape_CreateInstanceMethod(ctx, "syncHash", ILibDuktape_SHA1_syncHash, 1);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "hash");

	data->ctx = ctx;
	data->object = duk_get_heapptr(ctx, -1);
	SHA1_Init(&(data->sctx));

	ILibDuktape_WritableStream_Init(ctx, ILibDuktape_SHA1_Write, ILibDuktape_SHA1_End, data);
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
void ILibDuktape_SHA512_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);															// [sha]
	ILibDuktape_CreateInstanceMethod(ctx, "create", ILibDuktape_SHA512_Create, 0);
}
void ILibDuktape_MD5_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);															// [md5]
	ILibDuktape_CreateInstanceMethod(ctx, "create", ILibDuktape_MD5_Create, 0);
}
void ILibDuktape_SHA1_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);															// [md5]
	ILibDuktape_CreateInstanceMethod(ctx, "create", ILibDuktape_SHA1_Create, 0);
}

void ILibDuktape_SHA256_Init(duk_context * ctx)
{
#ifndef MICROSTACK_NOTLS
	ILibDuktape_ModSearch_AddHandler(ctx, "SHA256Stream_Signer", ILibDuktape_SHA256_SIGNER_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "SHA256Stream_Verifier", ILibDuktape_SHA256_VERIFY_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "SHA384Stream_Verifier", ILibDuktape_SHA384_VERIFY_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "SHA512Stream_Verifier", ILibDuktape_SHA512_VERIFY_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "RSA", ILibDuktape_RSA_PUSH);
#endif
	ILibDuktape_ModSearch_AddHandler(ctx, "SHA512Stream", ILibDuktape_SHA512_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "SHA384Stream", ILibDuktape_SHA384_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "SHA256Stream", ILibDuktape_SHA256_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "MD5Stream", ILibDuktape_MD5_PUSH);
	ILibDuktape_ModSearch_AddHandler(ctx, "SHA1Stream", ILibDuktape_SHA1_PUSH);

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
