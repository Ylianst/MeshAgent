#include "duktape.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_DuplexStream.h"
#include "ILibDuktape_EventEmitter.h"

#ifndef MICROSTACK_NOTLS
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

#include "../microstack/ILibCrypto.h"

#define ILibDuktape_TlsStream_Ptr		"\xFF_ILibDuktape_TLSSTREAM_PTR"
#define ILibDuktape_TlsStream2Cert		"\xFF_TLS_CERT"

#define MEMORYCHUNKSIZE					4096
int ILibDuktape_TlsStream_ctx2stream = -1;

typedef struct ILibDuktape_TlsStream_Data
{
	duk_context *ctx;
	void *tlsObject;
	void *chain;
	int isClient;
	ILibDuktape_EventEmitter *emitter;
	char *decryptedBuffer;
	int decryptedBuffer_mallocSize;
	int decryptedBuffer_beginPointer;
	int decryptedBuffer_endPointer;
	int decryptedBuffer_unshiftedBytes;
	int decryptedBuffer_maxSize;

	int rejectUnauthorized;
	void *OnVerify;
	void *OnServerSNI;

	int ProcessEncryptedBuffer_Active;

	SSL* ssl;
	SSL_CTX *ssl_ctx;
	BIO *readBio, *writeBio;
	BUF_MEM *readBioBuffer, *writeBioBuffer;
	int TLSHandshakeCompleted;
	ILibDuktape_DuplexStream *clear;
	ILibDuktape_DuplexStream *encrypted;
	int encrypted_unshiftBytes;
}ILibDuktape_TlsStream_Data;


void ILibDuktape_TlsStream_X509_PUSH(duk_context *ctx, X509* cert)
{
	char hash[UTIL_SHA384_HASHSIZE];
	char fingerprint[150];

	util_keyhash2(cert, hash);
	util_tohex2(hash, UTIL_SHA384_HASHSIZE, fingerprint);

	duk_push_object(ctx);							// [cert]
	duk_push_string(ctx, fingerprint);				// [cert][fingerprint]
	duk_put_prop_string(ctx, -2, "fingerprint");	// [cert]
}
ILibTransport_DoneState ILibDuktape_TlsStream_ProcessEncryptedBuffer(ILibDuktape_TlsStream_Data *tlsdata)
{
	int j, first = 1;

	if (tlsdata->ProcessEncryptedBuffer_Active == 0)
	{
		tlsdata->ProcessEncryptedBuffer_Active = 1;
		tlsdata->encrypted_unshiftBytes = 0;
		BIO_clear_retry_flags(tlsdata->writeBio);

		while ((j = (int)tlsdata->writeBioBuffer->length) > 0 && tlsdata->encrypted->readableStream->paused == 0)
		{
			if (first == 1)
			{
				first = 0;
			}
			else
			{
				tlsdata->encrypted_unshiftBytes = 0;
				BIO_clear_retry_flags(tlsdata->writeBio);
			}

			do
			{
				ILibDuktape_DuplexStream_WriteData(tlsdata->encrypted, tlsdata->writeBioBuffer->data, (int)tlsdata->writeBioBuffer->length);
			} while (tlsdata->encrypted_unshiftBytes > 0);
			if (tlsdata->encrypted_unshiftBytes == 0)
			{
				tlsdata->writeBioBuffer->data += (int)tlsdata->writeBioBuffer->length;
				tlsdata->writeBioBuffer->length = 0;
			}
		}
		tlsdata->ProcessEncryptedBuffer_Active = 0;
		return(tlsdata->writeBioBuffer->length > 0 ? ILibTransport_DoneState_INCOMPLETE : ILibTransport_DoneState_COMPLETE);
	}
	else
	{
		return(ILibTransport_DoneState_ERROR);
	}
}
ILibTransport_DoneState ILibDuktape_TlsStream_Clear_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)user;

	SSL_write(data->ssl, buffer, bufferLen);
	return(ILibDuktape_TlsStream_ProcessEncryptedBuffer(data));
}
void ILibDuktape_TlsStream_Clear_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)user;
	if (ILibIsRunningOnChainThread(data->chain) != 0 && data->encrypted->writableStream->pipedReadable != NULL)
	{
		duk_push_heapptr(data->ctx, data->encrypted->writableStream->pipedReadable);		// [stream]
		duk_get_prop_string(data->ctx, -1, "end");											// [stream][end]
		duk_swap_top(data->ctx, -2);														// [end][this]
		if (duk_pcall_method(data->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(data->ctx, "TlsStream.unencrypted.end(): Error dispatching 'end' upstream "); }
		duk_pop(data->ctx);																	// ...
	}
}
void ILibDuktape_TlsStream_Clear_PauseSink_Chain(void *chain, void *user)
{
	if (chain != NULL && !ILibDuktape_IsPointerValid(chain, user)) { return; }
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)user;

	duk_push_heapptr(data->ctx, data->encrypted->writableStream->pipedReadable);	// [readable]
	duk_get_prop_string(data->ctx, -1, "pause");									// [readable][pause]
	duk_swap_top(data->ctx, -2);													// [pause][this]
	if (duk_pcall_method(data->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(data->ctx, "TlsStream.Decrypted.pause(): Error pausing upstream object "); };
	duk_pop(data->ctx);																// ...
}
void ILibDuktape_TlsStream_Clear_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)user;
	if (data->encrypted->writableStream->pipedReadable_native != NULL && data->encrypted->writableStream->pipedReadable_native->PauseHandler != NULL)
	{
		data->encrypted->writableStream->pipedReadable_native->paused = 1;
		data->encrypted->writableStream->pipedReadable_native->PauseHandler(data->encrypted->writableStream->pipedReadable_native, data->encrypted->writableStream->pipedReadable_native->user);
	}
	else if (data->encrypted->writableStream->pipedReadable != NULL)
	{
		if (ILibIsRunningOnChainThread(data->chain) != 0)
		{
			ILibDuktape_TlsStream_Clear_PauseSink_Chain(NULL, data);
		}
		else
		{
			// We're on the wrong thread to resume the upstream object
			ILibChain_RunOnMicrostackThreadEx(data->chain, ILibDuktape_TlsStream_Clear_PauseSink_Chain, data);
		}
	}
}
void ILibDuktape_TlsStream_Clear_ResumeSink_Chain(void *chain, void *user)
{
	if (chain != NULL && !ILibDuktape_IsPointerValid(chain, user)) { return; }
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)user;

	duk_push_heapptr(data->ctx, data->encrypted->writableStream->pipedReadable);	// [readable]
	duk_get_prop_string(data->ctx, -1, "resume");									// [readable][resume]
	duk_swap_top(data->ctx, -2);													// [resume][this]
	if (duk_pcall_method(data->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(data->ctx, "TlsStream.Decrypted.resume(): Error resuming upstream object "); };
	duk_pop(data->ctx);																// ...
}
void ILibDuktape_TlsStream_Clear_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)user;
	if (data->encrypted->writableStream->pipedReadable_native != NULL && data->encrypted->writableStream->pipedReadable_native->ResumeHandler != NULL)
	{
		data->encrypted->writableStream->pipedReadable_native->paused = 0;
		data->encrypted->writableStream->pipedReadable_native->ResumeHandler(data->encrypted->writableStream->pipedReadable_native, data->encrypted->writableStream->pipedReadable_native->user);
	}
	else if (data->encrypted->writableStream->pipedReadable != NULL)
	{
		if (ILibIsRunningOnChainThread(data->chain) != 0)
		{
			ILibDuktape_TlsStream_Clear_ResumeSink_Chain(NULL, data);
		}
		else
		{
			// We're on the wrong thread to resume the upstream object
			ILibChain_RunOnMicrostackThreadEx(data->chain, ILibDuktape_TlsStream_Clear_ResumeSink_Chain, data);
		}
	}
}
int ILibDuktape_TlsStream_Clear_UnshiftSink(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user)
{
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)user;

	if (unshiftBytes == data->decryptedBuffer_endPointer - data->decryptedBuffer_beginPointer)
	{
		data->decryptedBuffer_unshiftedBytes = -1;
	}
	else
	{
		data->decryptedBuffer_beginPointer = data->decryptedBuffer_endPointer - unshiftBytes;
		data->decryptedBuffer_unshiftedBytes = unshiftBytes;
	}
	return(unshiftBytes);
}

ILibTransport_DoneState ILibDuktape_TlsStream_Encrypted_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)user;
	int j;

	//int len = BIO_write(data->writeBio, buffer, bufferLen);
	BIO_write(SSL_get_rbio(data->ssl), buffer, bufferLen);
	int sslerror;

	if (data->TLSHandshakeCompleted == 0)
	{
		switch ((sslerror = SSL_do_handshake(data->ssl)))
		{
		case 0:
			// Handshake Failed!
			while ((sslerror = ERR_get_error()) != 0)
			{
				ERR_error_string_n(sslerror, ILibScratchPad, sizeof(ILibScratchPad));
			}
			// TODO: We should probably do something
			break;
		case 1:
			data->TLSHandshakeCompleted = 1;
			if (ILibIsRunningOnChainThread(data->chain) != 0)
			{
				// We're on the Duktape Thread
				duk_push_heapptr(data->ctx, data->tlsObject);		// [TLS]
				duk_get_prop_string(data->ctx, -1, "emit");			// [TLS][emit]
				duk_swap_top(data->ctx, -2);						// [emit][this]
				duk_push_string(data->ctx, "connect");				// [emit][this][connect]
				if (duk_pcall_method(data->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(data->ctx, "TlsStream.connect(): "); }
				duk_pop(data->ctx);									// ...
			}
			else
			{
				// Need to context switch to the Duktape Thread
			}
			ILibDuktape_TlsStream_ProcessEncryptedBuffer(data);
			break;
		default:
			// SSL_WANT_READ most likely
			sslerror = SSL_get_error(data->ssl, sslerror);
			ILibDuktape_TlsStream_ProcessEncryptedBuffer(data);
			break;
		}
		return(ILibTransport_DoneState_COMPLETE);
	}
	else
	{
		while ((j = SSL_read(data->ssl, data->decryptedBuffer + data->decryptedBuffer_endPointer, data->decryptedBuffer_mallocSize - data->decryptedBuffer_endPointer)) > 0)
		{
			// We got new TLS Data
			if (j > 0)
			{
				data->decryptedBuffer_endPointer += j;
				if (data->decryptedBuffer_mallocSize - data->decryptedBuffer_endPointer == 0)
				{
					data->decryptedBuffer_mallocSize = (data->decryptedBuffer_mallocSize + MEMORYCHUNKSIZE < data->decryptedBuffer_maxSize) ? (data->decryptedBuffer_mallocSize + MEMORYCHUNKSIZE) : (data->decryptedBuffer_maxSize == 0 ? (data->decryptedBuffer_mallocSize + MEMORYCHUNKSIZE) : data->decryptedBuffer_maxSize);
					if((data->decryptedBuffer = (char*)realloc(data->decryptedBuffer, data->decryptedBuffer_mallocSize)) == NULL) ILIBCRITICALEXIT(254);
				}
			}
		}
		if (j < 0)
		{
			sslerror = SSL_get_error(data->ssl, j);
			if (data->writeBioBuffer->length > 0)
			{
				ILibDuktape_TlsStream_ProcessEncryptedBuffer(data);
			}
		}
	}

	//
	// Event data up the stack, to process any data that is available
	//
	do
	{
		data->decryptedBuffer_unshiftedBytes = 0;
		ILibDuktape_DuplexStream_WriteData(data->clear, data->decryptedBuffer + data->decryptedBuffer_beginPointer, data->decryptedBuffer_endPointer - data->decryptedBuffer_beginPointer);
	} while (data->decryptedBuffer_unshiftedBytes > 0);
	if (data->decryptedBuffer_unshiftedBytes == 0) { data->decryptedBuffer_beginPointer = data->decryptedBuffer_endPointer = 0; }


	//
	// Check to see if we need to move any data, to maximize buffer space
	//
	if (data->decryptedBuffer_beginPointer != 0)
	{
		//
		// We can save some cycles by moving the data back to the top
		// of the buffer, instead of just allocating more memory.
		//
		char *temp = data->decryptedBuffer + data->decryptedBuffer_beginPointer;

		memmove_s(data->decryptedBuffer, data->decryptedBuffer_mallocSize, temp, data->decryptedBuffer_endPointer - data->decryptedBuffer_beginPointer);
		data->decryptedBuffer_endPointer -= data->decryptedBuffer_beginPointer;
		data->decryptedBuffer_beginPointer = 0;
	}

	//
	// Check to see if we should grow the buffer
	//
	if (data->decryptedBuffer_mallocSize - data->decryptedBuffer_endPointer < 1024 && (data->decryptedBuffer_maxSize == 0 || data->decryptedBuffer_mallocSize < data->decryptedBuffer_maxSize))
	{
		data->decryptedBuffer_mallocSize = (data->decryptedBuffer_mallocSize + MEMORYCHUNKSIZE < data->decryptedBuffer_maxSize) ? (data->decryptedBuffer_mallocSize + MEMORYCHUNKSIZE) : (data->decryptedBuffer_maxSize == 0 ? (data->decryptedBuffer_mallocSize + MEMORYCHUNKSIZE) : data->decryptedBuffer_maxSize);
		if ((data->decryptedBuffer = (char*)realloc(data->decryptedBuffer, data->decryptedBuffer_mallocSize)) == NULL) ILIBCRITICALEXIT(254);
	}
	
	return(data->clear->readableStream->paused == 0 ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE);
}
void ILibDuktape_TlsStream_Encrypted_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
}
void ILibDuktape_TlsStream_Encrypted_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
	// Don't need to do anythign, becuase the 'ILibDuktape_TlsStream_ProcessEncryptedBuffer' will exit the processing loop when paused
}
void ILibDuktape_TlsStream_Encrypted_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)user;
	ILibDuktape_TlsStream_ProcessEncryptedBuffer(data);
}
int ILibDuktape_TlsStream_Encrypted_UnshiftSink(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user)
{
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)user;
	
	if (unshiftBytes == data->writeBioBuffer->length)
	{
		data->encrypted_unshiftBytes = -1;
	}
	else
	{
		data->writeBioBuffer->data += ((int)data->writeBioBuffer->length - unshiftBytes);
		data->writeBioBuffer->length = unshiftBytes;
	}
	return(unshiftBytes);
}
int ILibDuktape_TlsStream_verify(int preverify_ok, X509_STORE_CTX *ctx)
{
	STACK_OF(X509) *certChain = X509_STORE_CTX_get_chain(ctx);
	SSL *ssl = (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)SSL_get_ex_data(ssl, ILibDuktape_TlsStream_ctx2stream);

	int i;
	int retVal = 0;

	if (data->rejectUnauthorized != 0) { return(preverify_ok); }
	if (data->OnVerify == NULL) { return 1; }

	duk_push_heapptr(data->ctx, data->OnVerify);											// [func]
	duk_push_heapptr(data->ctx, data->emitter->object);										// [func][this]
	duk_push_array(data->ctx);																// [func][this][certs]
	for (i = 0; i < sk_X509_num(certChain); ++i)
	{
		ILibDuktape_TlsStream_X509_PUSH(data->ctx, sk_X509_value(certChain, i));			// [func][this][certs][cert]
		duk_put_prop_index(data->ctx, -2, i);												// [func][this][certs]
	}
	retVal = duk_pcall_method(data->ctx, 1) == 0 ? 1 : 0;									// [undefined]
	duk_pop(data->ctx);																		// ...
	return retVal;
}
duk_ret_t ILibDuktape_TlsStream_Finalizer(duk_context *ctx)
{
	void *chain = Duktape_GetChain(ctx);
	duk_get_prop_string(ctx, 0, ILibDuktape_TlsStream_Ptr);
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	struct util_cert *cert = NULL;

	if (data->ssl != NULL) { SSL_free(data->ssl); }
	if (data->ssl_ctx != NULL) { SSL_CTX_free(data->ssl_ctx); }
	if (data->decryptedBuffer != NULL) { free(data->decryptedBuffer); }

	if (duk_has_prop_string(ctx, 0, ILibDuktape_TlsStream2Cert))
	{
		duk_get_prop_string(ctx, 0, ILibDuktape_TlsStream2Cert);
		cert = (struct util_cert*)Duktape_GetBuffer(ctx, -1, NULL);
		util_freecert(cert);
	}
	ILibDuktape_InValidatePointer(chain, data);
	return(0);
}
duk_ret_t ILibDuktape_TlsStream_serverSNI_cb(duk_context *ctx)
{
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "\xFF_ptr");
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)duk_get_pointer(ctx, -1);

	if (duk_has_prop_string(ctx, 1, "pfx") && duk_has_prop_string(ctx, 1, "passphrase"))
	{
		char *passphrase = Duktape_GetStringPropertyValue(ctx, 1, "passphrase", "");
		char *pfx;
		duk_size_t pfxLen;
		duk_get_prop_string(ctx, 1, "pfx");
		pfx = (char*)Duktape_GetBuffer(ctx, -1, &pfxLen);
		duk_push_heapptr(ctx, data->tlsObject);											// [TLS]
		duk_push_fixed_buffer(ctx, sizeof(struct util_cert));							// [TLS][cert]
		struct util_cert *cert = (struct util_cert*)Duktape_GetBuffer(ctx, -1, NULL);
		
		if (util_from_p12(pfx, (int)pfxLen, passphrase, cert) == 0) { return(ILibDuktape_Error(ctx, "Error Reading Certificate")); }
		SSL_CTX *newCTX = SSL_CTX_new(SSLv23_server_method());
		SSL_CTX_set_options(newCTX, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
		SSL_CTX_set_verify(newCTX, SSL_VERIFY_CLIENT_ONCE, ILibDuktape_TlsStream_verify); /* Ask for authentication */ 
		SSL_CTX_use_certificate(newCTX, cert->x509);
		SSL_CTX_use_PrivateKey(newCTX, cert->pkey);

		SSL_set_SSL_CTX(data->ssl, newCTX);

		duk_get_prop_string(ctx, -2, ILibDuktape_TlsStream2Cert);						// [TLS][cert][oldCert]
		util_freecert((struct util_cert*)Duktape_GetBuffer(ctx, -1, NULL));
		duk_pop(ctx);																	// [TLS][cert]
		duk_put_prop_string(ctx, -2, ILibDuktape_TlsStream2Cert);						// [TLS]
		SSL_CTX_free(data->ssl_ctx);
		data->ssl_ctx = newCTX;
	}

	return(0);
}
static int ILibDuktape_TlsStream_serverSNI_callback(SSL *s, int *ad, void *arg)
{
	const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
	ILibDuktape_TlsStream_Data *data = (ILibDuktape_TlsStream_Data*)SSL_get_ex_data(s, ILibDuktape_TlsStream_ctx2stream);
	int retVal = SSL_TLSEXT_ERR_OK;

	duk_push_heapptr(data->ctx, data->OnServerSNI);							// [func]
	duk_push_heapptr(data->ctx, data->tlsObject);							// [func][this]
	duk_push_string(data->ctx, servername);									// [func][this][servername]
	duk_push_c_function(data->ctx, ILibDuktape_TlsStream_serverSNI_cb, 2);	// [func][this][servername][cb]
	duk_push_pointer(data->ctx, data);										// [func][this][servername][cb][ptr]
	duk_put_prop_string(data->ctx, -2, "\xFF_ptr");							// [func][this][servername][cb]
	if (duk_pcall_method(data->ctx, 2) != 0)
	{
		ILibDuktape_Process_UncaughtExceptionEx(data->ctx, "TlsStream.serverSNI(): Error dispatching callback ");
		retVal = SSL_TLSEXT_ERR_NOACK;
	}
	duk_pop(data->ctx);														// ...

	return(retVal);
}
duk_ret_t ILibDuktape_TlsStream_create(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *sniHost = NULL;
	void *chain = Duktape_GetChain(ctx);
	int status, requestCert;
	duk_push_current_function(ctx);
	int isClient = Duktape_GetIntPropertyValue(ctx, -1, "isClient", 0);
	ILibDuktape_TlsStream_Data *data;
	duk_push_object(ctx);													// [TLS]
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_TlsStream_Finalizer);
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_TlsStream_Data));			// [TLS][struct]
	data = (ILibDuktape_TlsStream_Data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_put_prop_string(ctx, -2, ILibDuktape_TlsStream_Ptr);				// [TLS]
	memset(data, 0, sizeof(ILibDuktape_TlsStream_Data));
	ILibDuktape_ValidatePointer(chain, data);
	data->emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(data->emitter, "connect");
	data->tlsObject = duk_get_heapptr(ctx, -1);
	data->decryptedBuffer_mallocSize = MEMORYCHUNKSIZE;
	data->decryptedBuffer = (char*)ILibMemory_Allocate(data->decryptedBuffer_mallocSize, 0, NULL, NULL);

	data->rejectUnauthorized = Duktape_GetIntPropertyValue(ctx, 0, "rejectUnauthorized", 1);
	requestCert = Duktape_GetIntPropertyValue(ctx, 0, "requestCert", 0);
	data->OnVerify = Duktape_GetHeapptrProperty(ctx, 0, isClient != 0 ? "checkServerIdentity" : "checkClientIdentity");

	duk_push_object(ctx);													// [TLS][clear]
	ILibDuktape_WriteID(ctx, "TlsStream.decrypted");
	data->clear = ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_TlsStream_Clear_WriteSink, ILibDuktape_TlsStream_Clear_EndSink,
		ILibDuktape_TlsStream_Clear_PauseSink, ILibDuktape_TlsStream_Clear_ResumeSink, ILibDuktape_TlsStream_Clear_UnshiftSink, data);
	ILibDuktape_CreateReadonlyProperty(ctx, "clear");						// [TLS]

	duk_push_object(ctx);													// [TLS][encrypted]
	ILibDuktape_WriteID(ctx, "TlsStream.encrypted");
	data->encrypted = ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_TlsStream_Encrypted_WriteSink, ILibDuktape_TlsStream_Encrypted_EndSink,
		ILibDuktape_TlsStream_Encrypted_PauseSink, ILibDuktape_TlsStream_Encrypted_ResumeSink, ILibDuktape_TlsStream_Encrypted_UnshiftSink, data);
	ILibDuktape_CreateReadonlyProperty(ctx, "encrypted");					// [TLS]


	data->ctx = ctx;
	data->chain = Duktape_GetChain(ctx);
	data->ssl_ctx = isClient != 0 ? SSL_CTX_new(SSLv23_client_method()) : SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_options(data->ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
	if (isClient != 0 || requestCert != 0) { SSL_CTX_set_verify(data->ssl_ctx, isClient != 0 ? SSL_VERIFY_PEER : SSL_VERIFY_CLIENT_ONCE, ILibDuktape_TlsStream_verify); /* Ask for authentication */ }
	
	if (nargs > 0 && duk_is_object(ctx, 0))
	{
		sniHost = Duktape_GetStringPropertyValue(ctx, 0, "host", NULL);
		data->OnServerSNI = Duktape_GetHeapptrProperty(ctx, 0, "SNICallback");
		if (duk_has_prop_string(ctx, 0, "pfx") && duk_has_prop_string(ctx, 0, "passphrase"))
		{
			// PFX certificate was passed in thru Options
			char *pfx, *passphrase;
			duk_size_t pfxLen, passphraseLen;
			duk_push_fixed_buffer(ctx, sizeof(struct util_cert));							// [TLS][buff]
			struct util_cert *cert = (struct util_cert*)Duktape_GetBuffer(ctx, -1, NULL);
			duk_put_prop_string(ctx, -2, ILibDuktape_TlsStream2Cert);						// [TLS]

			duk_get_prop_string(ctx, 0, "pfx");			// [pfx]
			duk_get_prop_string(ctx, 0, "passphrase");	// [pfx][passphrase]
			pfx = (char*)Duktape_GetBuffer(ctx, -2, &pfxLen);
			passphrase = (char*)Duktape_GetBuffer(ctx, -1, &passphraseLen);

			if (util_from_p12(pfx, (int)pfxLen, passphrase, cert) == 0) { return(ILibDuktape_Error(ctx, "Error Reading Certificate")); }
			SSL_CTX_use_certificate(data->ssl_ctx, cert->x509);
			SSL_CTX_use_PrivateKey(data->ssl_ctx, cert->pkey);
			duk_pop_2(ctx);
		}
	}

	data->ssl = SSL_new(data->ssl_ctx);
	data->TLSHandshakeCompleted = 0;
	data->readBio = BIO_new(BIO_s_mem());
	data->writeBio = BIO_new(BIO_s_mem());
	BIO_get_mem_ptr(data->readBio, &(data->readBioBuffer));
	BIO_get_mem_ptr(data->writeBio, &(data->writeBioBuffer));
	BIO_set_mem_eof_return(data->readBio, -1);
	BIO_set_mem_eof_return(data->writeBio, -1);
	data->readBioBuffer->length = 0;
	SSL_set_bio(data->ssl, data->readBio, data->writeBio);

	if (ILibDuktape_TlsStream_ctx2stream < 0)
	{
		ILibDuktape_TlsStream_ctx2stream = SSL_get_ex_new_index(0, "ILibDuktape_TlsStream index", NULL, NULL, NULL);
	}
	SSL_set_ex_data(data->ssl, ILibDuktape_TlsStream_ctx2stream, data);

	if (isClient != 0)
	{
		if (sniHost != NULL) { SSL_set_tlsext_host_name(data->ssl, sniHost); }
		SSL_set_connect_state(data->ssl);
		status = SSL_do_handshake(data->ssl);
		if (status <= 0) { status = SSL_get_error(data->ssl, status); }
		if (status == SSL_ERROR_WANT_READ)
		{
			ILibDuktape_TlsStream_ProcessEncryptedBuffer(data);
			// We're going to drop out now, becuase we need to check for received data
		}
	}
	else
	{
		if (data->OnServerSNI != NULL)
		{
			SSL_CTX_set_tlsext_servername_callback(data->ssl_ctx, ILibDuktape_TlsStream_serverSNI_callback);
		}
		SSL_set_accept_state(data->ssl); // Setup server SSL state
	}

	return(1);
}

void ILibDuktape_TlsStream_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "isClient", 1, "createClient", ILibDuktape_TlsStream_create, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "isClient", 0, "createServer", ILibDuktape_TlsStream_create, DUK_VARARGS);
}
void ILibDuktape_TlsStream_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "TlsStream", ILibDuktape_TlsStream_PUSH);
}

