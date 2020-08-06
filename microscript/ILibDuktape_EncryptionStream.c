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
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_DuplexStream.h"
#include "ILibDuktape_ReadableStream.h"
#include "ILibDuktape_WritableStream.h"
#include "microstack/ILibCrypto.h"

#ifndef MICROSTACK_NOTLS
#include <openssl/aes.h>
#include <openssl/crypto.h>

typedef struct ILibDuktape_EncryptionStream_Ptrs
{
	duk_context *ctx;
	void *object;
	ILibDuktape_DuplexStream *encrypted;
	ILibDuktape_DuplexStream *clear;
	EVP_CIPHER_CTX *encryptedCTX;
	EVP_CIPHER_CTX *decryptedCTX;
}ILibDuktape_EncryptionStream_Ptrs;
#define ILibDuktape_EncryptionStream_Buffer				"\xFF_EncryptionStream_Buffer"
#define ILibDuktape_EncryptionStream_clearStream		"\xFF_EncryptionStream_clearStream"
#define ILibDuktape_EncryptionStream_encryptedStream	"\xFF_EncryptionStream_encryptedStream"

ILibTransport_DoneState ILibDuktape_EncryptionStream_encrypted_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_EncryptionStream_Ptrs *ptrs = (ILibDuktape_EncryptionStream_Ptrs*)user;
	char out[5000];
	int outLen;
	int i = 0;
	int result = 0;

	while (i < bufferLen)
	{
		EVP_DecryptUpdate(ptrs->decryptedCTX, (unsigned char*)out, &outLen, (unsigned char*)(buffer + i), bufferLen - i > 4096 ? 4096 : bufferLen - i);
		result = ILibDuktape_DuplexStream_WriteData(ptrs->clear, out, outLen);
		i += 4096;
	}
	return (result == 0 ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE);
}
ILibTransport_DoneState ILibDuktape_EncryptionStream_decrypted_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_EncryptionStream_Ptrs *ptrs = (ILibDuktape_EncryptionStream_Ptrs*)user;
	char out[5000];
	int outLen;
	int i = 0;
	int result = 0;

	while (i < bufferLen)
	{
		EVP_EncryptUpdate(ptrs->encryptedCTX, (unsigned char*)out, &outLen, (unsigned char*)(buffer + i), bufferLen - i > 4096 ? 4096 : bufferLen - i);
		result = ILibDuktape_DuplexStream_WriteData(ptrs->encrypted, out, outLen);
		i += 4096;
	}
	
	return (result == 0 ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE);
}
void ILibDuktape_EncryptionStream_encrypted_WriteEndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_EncryptionStream_Ptrs *ptrs = (ILibDuktape_EncryptionStream_Ptrs*)user;
	char out[5000];
	int outLen = 0;

	if (!EVP_DecryptFinal(ptrs->decryptedCTX, (unsigned char*)out, &outLen))
	{
		// Decrypt Error
		ILibDuktape_EventEmitter_SetupEmit(ptrs->clear->readableStream->ctx, ptrs->clear->readableStream->object, "error");	// [emit][this][error]
		duk_push_string(ptrs->clear->readableStream->ctx, "Decrypt Error");													// [emit][this][error][msg]
		if (duk_pcall_method(ptrs->clear->readableStream->ctx, 2) != 0)														// [ret]
		{
			ILibDuktape_Process_UncaughtException(ptrs->clear->readableStream->ctx);
		}
		duk_pop(ptrs->clear->readableStream->ctx);																			// ...
		outLen = 0;
	}
	if (outLen > 0)
	{
		ILibDuktape_DuplexStream_WriteData(ptrs->clear, out, outLen);
	}
	ILibDuktape_DuplexStream_WriteEnd(ptrs->clear);
}
void ILibDuktape_EncryptionStream_decrypted_WriteEndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_EncryptionStream_Ptrs *ptrs = (ILibDuktape_EncryptionStream_Ptrs*)user;
	char out[5000];
	int outLen = 0;

	EVP_EncryptFinal(ptrs->encryptedCTX, (unsigned char*)out, &outLen);
	if (outLen > 0)
	{
		ILibDuktape_DuplexStream_WriteData(ptrs->encrypted, out, outLen);
	}
	ILibDuktape_DuplexStream_WriteEnd(ptrs->encrypted);
}
void ILibDuktape_EncryptionStream_encrypted_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{

}
void ILibDuktape_EncryptionStream_encrypted_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_EncryptionStream_Ptrs *ptrs = (ILibDuktape_EncryptionStream_Ptrs*)user;
	ILibDuktape_DuplexStream_Ready(ptrs->clear);
}
void ILibDuktape_EncryptionStream_decrypted_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{

}
void ILibDuktape_EncryptionStream_decrypted_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_EncryptionStream_Ptrs *ptrs = (ILibDuktape_EncryptionStream_Ptrs*)user;
	ILibDuktape_DuplexStream_Ready(ptrs->encrypted);
}
duk_ret_t ILibDuktape_EncryptionStream_Finalizer(duk_context *ctx)
{
	ILibDuktape_EncryptionStream_Ptrs *ptrs;
	duk_get_prop_string(ctx, 0, ILibDuktape_EncryptionStream_Buffer);
	ptrs = (ILibDuktape_EncryptionStream_Ptrs*)Duktape_GetBuffer(ctx, -1, NULL);

	EVP_CIPHER_CTX_free(ptrs->decryptedCTX);
	EVP_CIPHER_CTX_free(ptrs->encryptedCTX);

	return 0;
}
duk_ret_t ILibDuktape_EncryptionStream_CreateEncryption(duk_context *ctx)
{
	ILibDuktape_EncryptionStream_Ptrs *ptrs;
	char *key = NULL;
	char *iv = NULL;
	
	if (!duk_has_prop_string(ctx, 0, "key")) { return(ILibDuktape_Error(ctx, "EncryptionStream.Create(): key must be specified!")); }
	if (!duk_has_prop_string(ctx, 0, "iv")) { return(ILibDuktape_Error(ctx, "EncryptionStream.Create(): iv must be specified!")); }

	duk_get_prop_string(ctx, 0, "key");			// [key]
	if (duk_is_string(ctx, -1))
	{
		// Base64 encoded key
		duk_size_t tmpLen;
		char *tmp = (char*)duk_get_lstring(ctx, -1, &tmpLen);
		duk_push_object(ctx);											// [key][stream]
		duk_push_fixed_buffer(ctx, ILibBase64DecodeLength(tmpLen));// [key][stream][buffer]
		key = (char*)Duktape_GetBuffer(ctx, -1, NULL);
		ILibBase64Decode((unsigned char*)tmp, (int)tmpLen, (unsigned char**)&key);
		duk_put_prop_string(ctx, -2, "\xFF_key");						// [key][stream]
		duk_swap_top(ctx, -2);											// [stream][key]
		duk_pop(ctx);													// [stream]
	}
	else
	{
		duk_push_object(ctx);						// [key][stream]
		duk_swap_top(ctx, -2);						// [stream][key]
		key = (char*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_put_prop_string(ctx, -2, "\xFF_key");	// [stream]
	}
	duk_get_prop_string(ctx, 0, "iv");				// [stream][iv]
	if (duk_is_string(ctx, -1))
	{
		duk_size_t tmpLen;
		char *tmp = (char*)duk_get_lstring(ctx, -1, &tmpLen);
		duk_push_fixed_buffer(ctx, ILibBase64DecodeLength(tmpLen));	// [stream][iv][buffer]
		duk_swap_top(ctx, -2);												// [stream][buffer][iv]
		iv = (char*)Duktape_GetBuffer(ctx, -2, NULL);
		ILibBase64Decode((unsigned char*)tmp, (int)tmpLen, (unsigned char**)&iv);
		duk_pop(ctx);														// [stream][buffer]
		duk_put_prop_string(ctx, -2, "\xFF_iv");							// [stream]
	}
	else
	{
		iv = (char*)Duktape_GetBuffer(ctx, -1, NULL);						// [stream][iv]
		duk_put_prop_string(ctx, -2, "\xFF_iv");							// [stream]
	}
	
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_EncryptionStream_Ptrs));			// [stream][buffer]
	ptrs = (ILibDuktape_EncryptionStream_Ptrs*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_EncryptionStream_Buffer);				// [stream]

	memset(ptrs, 0, sizeof(ILibDuktape_EncryptionStream_Ptrs));
	ptrs->ctx = ctx;
	ptrs->object = duk_get_heapptr(ctx, -1);

	duk_push_object(ctx);															// [stream][clear]
	ptrs->encrypted = ILibDuktape_DuplexStream_Init(ctx,
		ILibDuktape_EncryptionStream_encrypted_WriteSink,
		ILibDuktape_EncryptionStream_encrypted_WriteEndSink,
		ILibDuktape_EncryptionStream_encrypted_PauseSink,
		ILibDuktape_EncryptionStream_encrypted_ResumeSink,
		ptrs);
	duk_put_prop_string(ctx, -2, ILibDuktape_EncryptionStream_clearStream);			// [stream]
	duk_push_object(ctx);															// [stream][encrypted]
	ptrs->clear = ILibDuktape_DuplexStream_Init(ctx,
		ILibDuktape_EncryptionStream_decrypted_WriteSink,
		ILibDuktape_EncryptionStream_decrypted_WriteEndSink,
		ILibDuktape_EncryptionStream_decrypted_PauseSink,
		ILibDuktape_EncryptionStream_decrypted_ResumeSink,
		ptrs);
	duk_put_prop_string(ctx, -2, ILibDuktape_EncryptionStream_encryptedStream);		// [stream]
	ILibDuktape_CreateEventWithGetterEx(ctx, "encryptedStream", ptrs->encrypted->ParentObject);
	ILibDuktape_CreateEventWithGetterEx(ctx, "decryptedStream", ptrs->clear->ParentObject);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_EncryptionStream_Finalizer);

	ptrs->encryptedCTX = EVP_CIPHER_CTX_new();
	ptrs->decryptedCTX = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ptrs->encryptedCTX, EVP_aes_256_ctr(), (unsigned char*)key, (unsigned char*)iv);
	EVP_DecryptInit(ptrs->decryptedCTX, EVP_aes_256_ctr(), (unsigned char*)key, (unsigned char*)iv);
	
	return 1;
}
duk_ret_t ILibDuktape_EncryptionStream_generateRandom(duk_context *ctx)
{
	char *buffer;
	duk_size_t bufferLen;

	duk_push_fixed_buffer(ctx, duk_require_int(ctx, 0));
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);
	util_random((int)bufferLen, buffer);
	duk_push_buffer_object(ctx, -1, 0, bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);
	return 1;
}
void ILibDuktape_EncryptionStream_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_CreateInstanceMethod(ctx, "Create", ILibDuktape_EncryptionStream_CreateEncryption, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "GenerateRandom", ILibDuktape_EncryptionStream_generateRandom, 1);
}
#endif

void ILibDuktape_EncryptionStream_init(duk_context *ctx)
{
#ifndef MICROSTACK_NOTLS
	ILibDuktape_ModSearch_AddHandler(ctx, "EncryptionStream", ILibDuktape_EncryptionStream_PUSH);
#endif
}


#ifdef __DOXY__
/*!
\brief AES256 Encryption Stream <b>Note:</b> To use, must <b>require('EncryptionStream').Create()</b>
*/
class EncryptionStream
{
public:
	/*!
	\brief Creates an AES256 EncryptionStream instance
	\param options <Object>\n
	<b>key</b>	\<Buffer\|String\> Encryption key, either as a base64 encoded string, or a raw buffer\n
	<b>iv</b>	\<Buffer\|String\> base64 encoded string, or a raw buffer\n	
	*/
	static EncryptionStream Create(options);
	/*!
	\brief Returns a buffer of the specified size, and randomly populates it with random data.
	\param numBytes <integer> Size of the buffer to create
	*/
	static Buffer GenerateRandom(numBytes);

	/*!
	\brief Encrypted DuplexStream. Written encrypted data is decrypted and written to decryptedStream. 
	*/
	DuplexStream encryptedStream;
	/*!
	\brief Decrypted DuplexStream. Written decrypted data is encrypted and written to encryptedStream.
	*/
	DuplexStream decryptedStream;
};
#endif
