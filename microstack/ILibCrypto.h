/*
Copyright 2006 - 2022 Intel Corporation

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

#ifndef __ILIB_CRYPTO__
#define __ILIB_CRYPTO__

#include "ILibParsers.h"

#if !defined(WIN32) 
#define __fastcall
#endif

void  __fastcall util_md5(char* data, size_t datalen, char* result);
void  __fastcall util_md5hex(char* data, size_t datalen, char *out);
void  __fastcall util_sha1(char* data, size_t datalen, char* result);
char* __fastcall util_tohex(char* data, size_t len, char* out);
char* __fastcall util_tohex2(char* data, size_t len, char* out);
char* __fastcall util_tohex_lower(char* data, size_t len, char* out);
int   __fastcall util_hexToint(char *hexString, size_t hexStringLength);
size_t __fastcall util_hexToBuf(char *hexString, size_t hexStringLength, char* output);

void  __fastcall util_sha256(char* data, size_t datalen, char* result);
void  __fastcall util_sha384(char* data, size_t datalen, char* result);
int   __fastcall util_sha384file(char* filename, char* result);

// File and data methods
size_t __fastcall util_writefile(char* filename, char* data, int datalen);
size_t __fastcall util_appendfile(char* filename, char* data, int datalen);
size_t __fastcall util_readfile(char* filename, char** data, size_t maxlen);
int    __fastcall util_deletefile(char* filename);

#ifdef WIN32
int   __fastcall util_crc(unsigned char *buffer, int len, int initial_value);
BOOL util_MoveFile(_In_ LPCSTR lpExistingFileName, _In_  LPCSTR lpNewFileName);
BOOL util_CopyFile(_In_ LPCSTR lpExistingFileName, _In_ LPCSTR lpNewFileName, _In_ BOOL bFailIfExists);
#endif

void  __fastcall util_random(int length, char* result);
void  __fastcall util_randomtext(int length, char* result);

#define UTIL_MD5_HASHSIZE		16
#define UTIL_SHA1_HASHSIZE		20
#define UTIL_SHA256_HASHSIZE	32
#define UTIL_SHA384_HASHSIZE    48
#define UTIL_SHA512_HASHSIZE	64

#ifdef MICROSTACK_NOTLS
#ifdef WIN32
#include <bcrypt.h>

typedef struct BCRYPT_CTX
{
	BCRYPT_ALG_HANDLE	hAlg;
	BCRYPT_HASH_HANDLE	hHash;
	DWORD				cbData;
	DWORD				cbHash;
	DWORD				cbHashObject;
	PBYTE				pbHashObject;
}BCRYPT_CTX;
#define SHA512_CTX BCRYPT_CTX
#define SHA384_CTX BCRYPT_CTX
#define SHA256_CTX BCRYPT_CTX
#define SHA_CTX BCRYPT_CTX
#define MD5_CTX BCRYPT_CTX

void BCRYPT_INIT(BCRYPT_CTX* ctx, void* alg);
void BCRYPT_UPDATE(BCRYPT_CTX* ctx, void* data, size_t dataLen);
void BCRYPT_FINAL(char *h, BCRYPT_CTX* ctx);
#define SHA512_Init(ctx) BCRYPT_INIT(ctx, BCRYPT_SHA512_ALGORITHM)
#define SHA384_Init(ctx) BCRYPT_INIT(ctx, BCRYPT_SHA384_ALGORITHM)
#define SHA256_Init(ctx) BCRYPT_INIT(ctx, BCRYPT_SHA256_ALGORITHM)
#define SHA1_Init(ctx) BCRYPT_INIT(ctx, BCRYPT_SHA1_ALGORITHM)
#define MD5_Init(ctx) BCRYPT_INIT(ctx, BCRYPT_MD5_ALGORITHM)
#define SHA512_Update(ctx, data, len) BCRYPT_UPDATE(ctx, data, len)
#define SHA384_Update(ctx, data, len) BCRYPT_UPDATE(ctx, data, len)
#define SHA256_Update(ctx, data, len) BCRYPT_UPDATE(ctx, data, len)
#define SHA1_Update(ctx, data, len) BCRYPT_UPDATE(ctx, data, len)
#define MD5_Update(ctx, data, len) BCRYPT_UPDATE(ctx, data, len)
#define SHA512_Final(md, ctx) BCRYPT_FINAL(md, ctx)
#define SHA384_Final(md, ctx) BCRYPT_FINAL(md, ctx)
#define SHA256_Final(md, ctx) BCRYPT_FINAL(md, ctx)
#define SHA1_Final(md, ctx) BCRYPT_FINAL(md, ctx)
#define MD5_Final(md, ctx) BCRYPT_FINAL(md, ctx)

#else
#include "microstack/nossl/md5.h"
#include "microstack/nossl/sha.h"
#include "microstack/nossl/sha1.h"

#define SHA256_CTX SHA256Context
#define SHA512_CTX SHA512Context

#define SHA256_Init(ctx) SHA256Reset (ctx)
#define SHA256_Update(ctx, data, len) SHA256Input(ctx, (uint8_t*)data, len)
#define SHA256_Final(md, ctx) SHA256Result (ctx, md)

#define SHA384_Init(ctx) SHA384Reset (ctx)
#define SHA384_Update(ctx, data, len) SHA384Input(ctx, (uint8_t*)data, len)
#define SHA384_Final(md, ctx) SHA384Result (ctx, md)

#define SHA512_Init(ctx) SHA512Reset (ctx)
#define SHA512_Update(ctx, data, len) SHA512Input(ctx, (uint8_t*)data, len)
#define SHA512_Final(md, ctx) SHA512Result (ctx, md)
#endif
#endif


#ifndef MICROSTACK_NOTLS
#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/err.h>

// Certificate structure
typedef struct util_cert
{
	X509 *x509;
	EVP_PKEY *pkey;
	int flags;
} util_cert;

typedef enum CERTIFICATE_TYPES
{
	CERTIFICATE_ROOT = 1,
	CERTIFICATE_TLS_SERVER = 2,
	CERTIFICATE_TLS_CLIENT = 3
} CERTIFICATE_TYPES;

#define ILibCrypto_Cert_Ownership_Other 0x01

void  __fastcall util_openssl_init();
void  __fastcall util_openssl_uninit();
int  __fastcall util_load_system_certs(SSL_CTX *ctx);
void  __fastcall util_free(char* ptr);

// Certificate & crypto methods
void  __fastcall util_freecert(struct util_cert* cert);
int   __fastcall util_to_p12(struct util_cert cert, char *password, char** data);
int   __fastcall util_from_p12(char* data, int datalen, char* password, struct util_cert* cert);
int   __fastcall util_to_cer(struct util_cert cert, char** data);
int   __fastcall util_from_cer(char* data, int datalen, struct util_cert* cert);
int   __fastcall util_from_pem(char* filename, struct util_cert* cert);
int	  __fastcall util_from_pem_string(char *data, int datalen, struct util_cert* cert);
int	  __fastcall util_from_pkcs7b_string(char *data, int datalen, char *out, int outLen);
int   __fastcall util_mkCertEx(struct util_cert *rootcert, struct util_cert* cert, int bits, int days, char* name, enum CERTIFICATE_TYPES certtype, struct util_cert* initialcert, int noUsages);
#define util_mkCert(rootcert, cert, bits, days, name, certtype, initialcert) util_mkCertEx(rootcert, cert, bits, days, name, certtype, initialcert,0)

void  __fastcall util_printcert(struct util_cert cert);
void  __fastcall util_printcert_pk(struct util_cert cert);

int   __fastcall util_certhash(struct util_cert cert, char* result);
int   __fastcall util_certhash2(X509* cert, char* result);
int   __fastcall util_keyhash(struct util_cert cert, char* result);
int   __fastcall util_keyhash2(X509* cert, char* result);
int   __fastcall util_sign(struct util_cert cert, char* data, int datalen, char** signature);
int   __fastcall util_verify(char* signature, int signlen, struct util_cert* cert, char** data);
int   __fastcall util_encrypt(struct util_cert cert, char* data, int datalen, char** encdata);
int   __fastcall util_encrypt2(STACK_OF(X509) *certs, char* data, int datalen, char** encdata);
int   __fastcall util_decrypt(char* encdata, int encdatalen, struct util_cert cert, char** data);

int   __fastcall util_rsaencrypt(X509 *cert, char* data, int datalen, char** encdata);
int   __fastcall util_rsadecrypt(struct util_cert cert, char* data, int datalen, char** decdata);
int   __fastcall util_rsaverify(X509 *cert, char* data, int datalen, char* sign, int signlen);

#ifdef _SSL_KEYS_EXPORTABLE
int  __fastcall util_exportkeys(SSL* ssl, char *buffer, size_t bufferSize);
#endif

#ifdef _DEBUG
void  __fastcall util_savekeys(SSL* ssl);
#endif

#endif


#if defined(_DEBUG)

// Display only
#ifdef ANDROID
#include <android/log.h>
#define MSG(...)   __android_log_print(ANDROID_LOG_DEBUG, "MeshAgent", __VA_ARGS__); 
#elif NACL
#include "chrome/nacl.h"
#define MSG(...)  ni_log(__VA_ARGS__); 
#else
#define MSG(...) printf(__VA_ARGS__);fflush(NULL)
#endif
#define DEBUGSTATEMENT(x) x
#else
#ifndef MSG
#define MSG(...)
#endif
#define DEBUGSTATEMENT(x)
#endif
#endif
