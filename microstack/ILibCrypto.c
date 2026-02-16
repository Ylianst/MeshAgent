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

#if defined(WIN32) && !defined(_WIN32_WCE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif


#include "ILibCrypto.h"

#ifndef MICROSTACK_NOTLS
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#ifdef _POSIX
#include <sys/stat.h>
#endif
#else
#ifdef WIN32
void BCRYPT_INIT(BCRYPT_CTX* ctx, void* alg)
{
	memset(ctx, 0, sizeof(BCRYPT_CTX));
	BCryptOpenAlgorithmProvider(&(ctx->hAlg), (LPCWSTR)alg, NULL, 0);
	BCryptGetProperty(ctx->hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&(ctx->cbHashObject), sizeof(DWORD), &(ctx->cbData), 0);
	ctx->pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ctx->cbHashObject);
	BCryptGetProperty(ctx->hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&(ctx->cbHash), sizeof(DWORD), &(ctx->cbData), 0);
	BCryptCreateHash(ctx->hAlg, &(ctx->hHash), ctx->pbHashObject, ctx->cbHashObject, NULL, 0, 0);
}
void BCRYPT_UPDATE(BCRYPT_CTX* ctx, void* data, size_t dataLen)
{
	BCryptHashData(ctx->hHash, (PBYTE)data, (ULONG)dataLen, 0);
}
void BCRYPT_FINAL(char *h, BCRYPT_CTX* ctx)
{
	BCryptFinishHash(ctx->hHash, (PUCHAR)h, ctx->cbHash, 0);
	BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
	BCryptDestroyHash(ctx->hHash);
	HeapFree(GetProcessHeap(), 0, ctx->pbHashObject);
}
#else
#include "microstack/nossl/md5.h"
#include "microstack/nossl/sha1.h"
#include "microstack/nossl/sha.h"
#include <time.h>
#include <sys/stat.h>
#endif
#endif

char utils_HexTable[16] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
char utils_HexTable2[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };


void  __fastcall util_md5(char* data, size_t datalen, char* result)
{
	MD5_CTX c;
	MD5_Init(&c);
	MD5_Update(&c, data, datalen);
	MD5_Final((unsigned char*)result, &c);
}
void  __fastcall util_md5hex(char* data, size_t datalen, char *out)
{
	int i = 0;
	unsigned char *temp = (unsigned char*)out;
	MD5_CTX mdContext;
	unsigned char digest[16];

	MD5_Init(&mdContext);
	MD5_Update(&mdContext, (unsigned char *)data, datalen);
	MD5_Final(digest, &mdContext);

	for (i = 0; i < sizeof(digest); i++)
	{
		*(temp++) = utils_HexTable2[(unsigned char)digest[i] >> 4];
		*(temp++) = utils_HexTable2[(unsigned char)digest[i] & 0x0F];
	}

	*temp = '\0';
}
void  __fastcall util_sha1(char* data, size_t datalen, char* result)
{
	SHA_CTX c;
	SHA1_Init(&c);
	SHA1_Update(&c, data, datalen);
	SHA1_Final((unsigned char*)result, &c);
	result[20] = 0;
}
void  __fastcall util_sha256(char* data, size_t datalen, char* result)
{
	SHA256_CTX c;
	SHA256_Init(&c);
	SHA256_Update(&c, data, datalen);
	SHA256_Final((unsigned char*)result, &c);
}
void  __fastcall util_sha384(char* data, size_t datalen, char* result)
{
	SHA512_CTX c;
	SHA384_Init(&c);
	SHA384_Update(&c, data, datalen);
	SHA384_Final((unsigned char*)result, &c);
}
int   __fastcall util_sha384file(char* filename, char* result)
{
	FILE *pFile = NULL;
	SHA512_CTX c;
	size_t len = 0;
	char *buf = NULL;

	if (filename == NULL) return -1;
#ifdef WIN32 
	_wfopen_s(&pFile, ILibUTF8ToWide(filename, -1), L"rbN");
#else
	pFile = fopen(filename, "rb");
#endif
	if (pFile == NULL) goto error;
	SHA384_Init(&c);
	if ((buf = (char*)malloc(4096)) == NULL) goto error;
	while ((len = fread(buf, 1, 4096, pFile)) > 0) SHA384_Update(&c, buf, len);
	free(buf);
	buf = NULL;
	fclose(pFile);
	pFile = NULL;
	SHA384_Final((unsigned char*)result, &c);
	return 0;

error:
	if (buf != NULL) free(buf);
	if (pFile != NULL) fclose(pFile);
	return -1;
}

// Frees a block of memory returned from this module.
void __fastcall util_free(char* ptr)
{
	free(ptr);
	//ptr = NULL;
}
char* __fastcall util_tohex(char* data, size_t len, char* out)
{
	size_t i;
	char *p = out;
	if (data == NULL || len == 0) { *p = 0; return NULL; }
	for (i = 0; i < len; i++)
	{
		*(p++) = utils_HexTable[((unsigned char)data[i]) >> 4];
		*(p++) = utils_HexTable[((unsigned char)data[i]) & 0x0F];
	}
	*p = 0;
	return out;
}
char* __fastcall util_tohex_lower(char* data, size_t len, char* out)
{
	size_t i;
	char *p = out;
	if (data == NULL || len == 0) { *p = 0; return NULL; }
	for (i = 0; i < len; i++)
	{
		*(p++) = utils_HexTable2[((unsigned char)data[i]) >> 4];
		*(p++) = utils_HexTable2[((unsigned char)data[i]) & 0x0F];
	}
	*p = 0;
	return out;
}
char* __fastcall util_tohex2(char* data, size_t len, char* out)
{
	size_t i;
	char *p = out;
	if (data == NULL || len == 0) { *p = 0; return NULL; }
	for (i = 0; i < len; i++)
	{
		*(p++) = utils_HexTable[((unsigned char)data[i]) >> 4];
		*(p++) = utils_HexTable[((unsigned char)data[i]) & 0x0F];
		if (i + 1<len)
		{
			*(p++) = ':';
		}
	}
	*p = 0;
	return out;
}
// Convert hex string to int
int __fastcall util_hexToint(char *hexString, size_t hexStringLength)
{
	size_t i;
	int res = 0;

	// Ignore the leading zeroes
	while (*hexString == '0' && hexStringLength > 0) { hexString++; hexStringLength--; }

	// Process the rest of the string
	for (i = 0; i < hexStringLength; i++)
	{
		if (hexString[i] >= '0' && hexString[i] <= '9') { res = (res << 4) + (hexString[i] - '0'); }
		else if (hexString[i] >= 'a' && hexString[i] <= 'f') { res = (res << 4) + (hexString[i] - 'a' + 10); }
		else if (hexString[i] >= 'A' && hexString[i] <= 'F') { res = (res << 4) + (hexString[i] - 'A' + 10); }
	}
	return res;
}

// Convert hex string to int 
size_t __fastcall util_hexToBuf(char *hexString, size_t hexStringLength, char* output)
{
	size_t i, x = hexStringLength / 2;
	for (i = 0; i < x; i++) { output[i] = (char)util_hexToint(hexString + (i * 2), 2); }
	return i;
}


// Generates a random string of data. TODO: Use Hardware RNG if possible
#ifdef MICROSTACK_NOTLS
int util_random_seeded = 0;
#endif
void __fastcall util_random(int length, char* result)
{
#ifndef MICROSTACK_NOTLS
	RAND_bytes((unsigned char*)result, length);
#else
	short val;
	int i;

	if (util_random_seeded == 0)
	{
		time_t t;
		srand((unsigned int)time(&t));
		util_random_seeded = 1;
	}

	for (i = 0; i < length; i += 2)
	{
		val = rand();
		memcpy_s(result + i, length - i, &val, (length - i) >= 2 ? 2 : (length - i));
	}
#endif
}

// Generates a random text string, useful for HTTP nonces.
void __fastcall util_randomtext(int length, char* result)
{
	int l;
	util_random(length, result);
	for (l = 0; l<length; l++) result[l] = (unsigned char)((((unsigned char)result[l]) % 10) + '0');
}


size_t __fastcall util_writefile(char* filename, char* data, int datalen)
{
	FILE * pFile = NULL;
	size_t count = 0;

#ifdef WIN32 
	_wfopen_s(&pFile, ILibUTF8ToWide(filename, -1), L"wbN");
#else
	pFile = fopen(filename, "wb");
#endif

	if (pFile != NULL)
	{
		count = fwrite(data, datalen, 1, pFile);
		fclose(pFile);
	}
	return count;
}

size_t __fastcall util_appendfile(char* filename, char* data, int datalen)
{
	FILE * pFile = NULL;
	size_t count = 0;

#ifdef WIN32 
	_wfopen_s(&pFile, ILibUTF8ToWide(filename, -1), L"abN");
#else
	pFile = fopen(filename, "ab");
#endif

	if (pFile != NULL)
	{
		count = fwrite(data, datalen, 1, pFile);
		fclose(pFile);
	}
	return count;
}

// Read a file into memory up to maxlen. If *data is NULL, a new buffer is allocated otherwise, the given one is used.
size_t __fastcall util_readfile(char* filename, char** data, size_t maxlen)
{
	FILE *pFile = NULL;
	size_t count = 0;
	size_t len = 0;
	size_t r = 1;
	if (filename == NULL) return 0;

#ifdef WIN32 
	_wfopen_s(&pFile, ILibUTF8ToWide(filename, -1), L"rbN");
#else
	pFile = fopen(filename, "rb");
#endif

	if (pFile != NULL)
	{
		// If *data is null, we need to allocate memory to read the data. Start by getting the size of the file.
		if (*data == NULL)
		{
			fseek(pFile, 0, SEEK_END);
			count = ftell(pFile);
			if (count > maxlen) count = maxlen;
			fseek(pFile, 0, SEEK_SET);
			*data = (char*)malloc(count + 1);
			if (*data == NULL) { fclose(pFile); return 0; }
		}
		else { count = maxlen - 1; }
		while (r != 0 && len < count)
		{
			r = fread(*data, 1, count - len, pFile);
			len += r;
		}
		(*data)[len] = 0;
		fclose(pFile);
	}
	return len;
}

#ifdef _POSIX
// This method reads a stream where the length of the file can't be determined. Useful in POSIX only
int __fastcall util_readfile2(char* filename, char** data)
{
	FILE * pFile;
	int count = 0;
	int len = 0;
	*data = NULL;
	if (filename == NULL) return 0;

	pFile = fopen(filename, "rb");
	if (pFile != NULL)
	{
		*data = malloc(1024);
		if (*data == NULL) { fclose(pFile); return 0; }
		do
		{
			len = (int)fread((*data) + count, 1, 1023, pFile);
			count += len;
			if (len == 1023) *data = realloc(*data, count + 1024);
		} while (len == 100);
		(*data)[count] = 0;
		fclose(pFile);
	}

	return count;
}
#endif

int __fastcall util_deletefile(char* filename)
{
	if (filename == NULL) return 0;
#ifdef WIN32
	return(_wremove(ILibUTF8ToWide(filename, -1)));
#else
	return(remove(filename));
#endif
}

#ifdef WIN32
// Really fast CRC-like method. Used for the KVM.
int __fastcall util_crc(unsigned char *buffer, int len, int initial_value)
{
	int hval = initial_value;
	int *bp = (int*)buffer;
	int *be = bp + (len >> 2);
	while (bp < be)
	{
		//hval *= 0x01000193;
		hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
		hval ^= *bp++;
	}
	// TODO: Handle left over bytes (len % 4)
	return hval;
}
#ifdef _MINCORE
BOOL util_MoveFile(_In_ LPCTSTR lpExistingFileName, _In_  LPCTSTR lpNewFileName)
{
	size_t convertedChars = 0;
	wchar_t lpExistingFileNameW[MAX_PATH];
	wchar_t lpNewFileNameW[MAX_PATH];
	mbstowcs_s(&convertedChars, lpExistingFileNameW, MAX_PATH, (const char*)lpExistingFileName, MAX_PATH);
	mbstowcs_s(&convertedChars, lpNewFileNameW, MAX_PATH, (const char*)lpNewFileName, MAX_PATH);
	return MoveFileExW(lpExistingFileNameW, lpNewFileNameW, 0);
}

BOOL util_CopyFile(_In_ LPCSTR lpExistingFileName, _In_ LPCSTR lpNewFileName, _In_ BOOL bFailIfExists)
{
	size_t convertedChars = 0;
	wchar_t lpExistingFileNameW[MAX_PATH];
	wchar_t lpNewFileNameW[MAX_PATH];
	mbstowcs_s(&convertedChars, lpExistingFileNameW, MAX_PATH, (const char*)lpExistingFileName, MAX_PATH);
	mbstowcs_s(&convertedChars, lpNewFileNameW, MAX_PATH, (const char*)lpNewFileName, MAX_PATH);
	return (CopyFile2(lpExistingFileNameW, lpNewFileNameW, NULL) == S_OK);
}
#else
BOOL util_MoveFile(_In_ LPCSTR lpExistingFileName, _In_  LPCSTR lpNewFileName)
{
	WCHAR wExisting[4096];
	WCHAR wNew[4096];
	
	MultiByteToWideChar(CP_UTF8, 0, (LPCCH)lpExistingFileName, -1, (LPWSTR)wExisting, (int)sizeof(wExisting) / 2);
	MultiByteToWideChar(CP_UTF8, 0, (LPCCH)lpNewFileName, -1, (LPWSTR)wNew, (int)sizeof(wNew) / 2);

	return MoveFileW(wExisting, wNew);
}
BOOL util_CopyFile(_In_ LPCSTR lpExistingFileName, _In_ LPCSTR lpNewFileName, _In_ BOOL bFailIfExists) 
{
	WCHAR wExisting[4096];
	WCHAR wNew[4096];

	MultiByteToWideChar(CP_UTF8, 0, (LPCCH)lpExistingFileName, -1, (LPWSTR)wExisting, (int)sizeof(wExisting) / 2);
	MultiByteToWideChar(CP_UTF8, 0, (LPCCH)lpNewFileName, -1, (LPWSTR)wNew, (int)sizeof(wNew) / 2);

	return CopyFileW(wExisting, wNew, bFailIfExists);
}
#endif
#endif



#ifndef MICROSTACK_NOTLS
// Setup OpenSSL
int InitCounter = 0;
void __fastcall util_openssl_init()
{
	char* tbuf[64];
#if defined(WIN32)
	HMODULE g_hAdvLib = NULL;
	BOOLEAN(APIENTRY *g_CryptGenRandomPtr)(void*, ULONG) = NULL;
#endif
#ifdef _POSIX
	int l;
#endif

	++InitCounter;
	if (InitCounter > 1) { return; }

	SSL_library_init(); // TWO LEAKS COMING FROM THIS LINE. Seems to be a well known OpenSSL problem.
	SSL_load_error_strings();
	ERR_load_crypto_strings(); // ONE LEAK IN LINUX

	OpenSSL_add_all_algorithms();	// OpenSSL 1.1
	OpenSSL_add_all_ciphers();		// OpenSSL 1.1
	OpenSSL_add_all_digests();		// OpenSSL 1.1
#ifdef FIPSMODE
	if (FIPS_mode() || FIPS_mode_set(1)) 
	{
		printf("ENTERED FIPS mode\n"); 
	}
	else
	{
		ILIBCRITICALEXITMSG(200, "FAILED to enter FIPS mode");
	}
#endif

	// Add more random seeding in Windows (This is probably useful since OpenSSL in Windows has weaker seeding)
#if defined(WIN32) && !defined(_MINCORE)
	//RAND_screen(); // On Windows, add more random seeding using a screen dump (this is very expensive).
	if ((g_hAdvLib = LoadLibraryExA((LPCSTR)"ADVAPI32.DLL", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32)) != 0) g_CryptGenRandomPtr = (BOOLEAN(APIENTRY *)(void*, ULONG))GetProcAddress(g_hAdvLib, "SystemFunction036");
	if (g_CryptGenRandomPtr != 0 && g_CryptGenRandomPtr(tbuf, 64) != 0) RAND_add(tbuf, 64, 64); // Use this high quality random as added seeding
	if (g_hAdvLib != NULL) FreeLibrary(g_hAdvLib);
#endif

	// Add more random seeding in Linux (May be overkill since OpenSSL already uses /dev/urandom)
#ifdef _POSIX
	// Under Linux we use "/dev/urandom" if available. This is the best source of random on Linux & variants
	FILE *pFile = fopen("/dev/urandom", "rb");
	if (pFile != NULL)
	{
		l = (int)fread(tbuf, 1, 64, pFile);
		fclose(pFile);
		if (l > 0) RAND_add(tbuf, l, l);
	}
#endif
}

// Cleanup OpenSSL
void __fastcall util_openssl_uninit()
{
	--InitCounter;
	if (InitCounter > 0) { return; }

	//RAND_cleanup();											// Does nothing.
	//CRYPTO_set_dynlock_create_callback(NULL);					// Does nothing.
	//CRYPTO_set_dynlock_destroy_callback(NULL);				// Does nothing.
	//CRYPTO_set_dynlock_lock_callback(NULL);					// Does nothing.
	//CRYPTO_set_locking_callback(NULL);						// Does nothing.
	//CRYPTO_set_id_callback(NULL);								// Does nothing.
	CRYPTO_cleanup_all_ex_data();
	//sk_SSL_COMP_free(SSL_COMP_get_compression_methods());		// Does something, but it causes heap corruption...
	//CONF_modules_unload(1);									// Does nothing.
	CONF_modules_free();
	EVP_cleanup();
	ERR_free_strings();
	//ERR_remove_state(0);										// Deprecated in OpenSSL/1.1.x

#ifndef OLDSSL
	OPENSSL_cleanup();
#endif
}

int __fastcall util_load_system_certs(SSL_CTX *ctx) 
{
	#ifdef WIN32
        X509_STORE *xs = SSL_CTX_get_cert_store(ctx);
	    HCERTSTORE s = CertOpenSystemStoreW(0, L"ROOT");
        BIO *in;
        X509 *x;
	    const CERT_CONTEXT *wctx = NULL;
        for (;;) {
            wctx = CertEnumCertificatesInStore(s, wctx);
            if (!wctx)
                break;
            in = BIO_new_mem_buf(wctx->pbCertEncoded, wctx->cbCertEncoded);
            x = d2i_X509_bio(in, NULL);
            X509_STORE_add_cert(xs, x);
            X509_free(x);
            BIO_free(in);
        }

        CertFreeCertificateContext(wctx);
        CertCloseStore(s, 0);
	#else
	    const char *cert_dir = X509_get_default_cert_dir();
	    struct stat s;
		int err = stat(cert_dir, &s);
		// The system we are on uses a different SSL dir than our statically included openssl. Try to grab it from the locally installed openssl distribution.
		if (err == -1) {
    		char buf[1024] = {0};
    		char dest[1024] = {0};

    		FILE *output;
			// Running "openssl version -d" should give us the directory of the locally installed openssl. We can then use that directory to load the certs from that distribution.
			// However, this could be a security risk as we are running "openssl" as root.
    		if ((output = popen("openssl version -d", "r")) == NULL) {
		        return -1;
		    }
		    char *tokenized;
		    while (fgets(buf, 1024, output) != NULL) {
		        tokenized = strtok(buf, "\"");
		        while(tokenized != NULL) {
		        	if (tokenized[0] == '/') {
		        		strcat_s(dest, sizeof(dest), tokenized);
		        		strcat_s(dest, sizeof(dest), "/certs");
		        		// Some systems use a /certs dir, some don't. Test for both.
		        		err = stat(dest, &s);
		        		if (err) {
		        			SSL_CTX_load_verify_locations(ctx, NULL, tokenized);
		        		} else {
		        			SSL_CTX_load_verify_locations(ctx, NULL, dest);
		        		}
		        		break;
		        	}
		        	tokenized = strtok(NULL, "\"");
		        }
		    }
		    if (pclose(output)) {
		        return -1;
		    }
		} else {
			SSL_CTX_set_default_verify_paths(ctx);
		}
	#endif
	return 0;
}

// Add extension using V3 code: we can set the config file as NULL because we wont reference any other sections.
int __fastcall util_add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	// This sets the 'context' of the extensions. No configuration database
	X509V3_set_ctx_nodb(&ctx);
	// Issuer and subject certs: both the target since it is self signed, no request and no CRL
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex) return 0;

	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}

void __fastcall util_freecert(struct util_cert* cert)
{
	if ((cert->flags & ILibCrypto_Cert_Ownership_Other) == 0)
	{
		if (cert->x509 != NULL) X509_free(cert->x509);
		if (cert->pkey != NULL) EVP_PKEY_free(cert->pkey);
	}
	cert->x509 = NULL;
	cert->pkey = NULL;
	cert->flags = 0;
}

int __fastcall util_to_cer(struct util_cert cert, char** data)
{
	if (data != NULL) { *data = NULL; }
	return i2d_X509(cert.x509, (unsigned char**)data);
}

int __fastcall util_from_cer(char* data, int datalen, struct util_cert* cert)
{
	cert->pkey = NULL;
	cert->x509 = d2i_X509(NULL, (const unsigned char**)&data, datalen);
	return ((cert->x509) != NULL);
}

int __fastcall util_from_pkcs7b_string(char *data, int datalen, char *out, int outLen)
{
	BIO* bio = BIO_new_mem_buf((void*)data, datalen);
	BIO* bio_out = BIO_new(BIO_s_mem());
	BUF_MEM *outBuffer;
	int retVal = 0, i = 0;
	PKCS7 *p7 = NULL;
	STACK_OF(X509) *certs = NULL;
	STACK_OF(X509_ALGOR) *md_algs = NULL;
	STACK_OF(PKCS7_SIGNER_INFO) *sinfo = NULL;

	BIO_get_mem_ptr(bio_out, &outBuffer);
	p7 = d2i_PKCS7_bio(bio, NULL);

	md_algs = p7->d.sign->md_algs;
	sinfo = p7->d.sign->signer_info;

	for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfo); i++)
	{
		printf("Hash Algorithm: %s\n", OBJ_nid2ln(OBJ_obj2nid(sk_PKCS7_SIGNER_INFO_value(sinfo, i)->digest_alg->algorithm)));
		printf("Enc Algorithm: %s\n", OBJ_nid2ln(OBJ_obj2nid(sk_PKCS7_SIGNER_INFO_value(sinfo, i)->digest_enc_alg->algorithm)));
	}

	for (i = 0; i < sk_X509_ALGOR_num(md_algs); i++)
	{
		printf("Algorithm: %s\n", OBJ_nid2ln(OBJ_obj2nid(sk_X509_ALGOR_value(md_algs, i)->algorithm)));
	}

	certs = p7->d.sign->cert;
	for (i = 0; certs && i < sk_X509_num(certs); i++) 
	{
		PEM_write_bio_X509(bio_out, sk_X509_value(certs, i));
	}
	
	if (outLen >= (int)outBuffer->length)
	{
		memcpy_s(out, outLen, outBuffer->data, outBuffer->length);
		out[outBuffer->length] = 0;
	}
	else
	{
		retVal = (int)(outBuffer->length) + 1;
	}

	BIO_free(bio);
	BIO_free(bio_out);

	return(retVal);
}

int __fastcall util_from_pem_string(char *data, int datalen, struct util_cert* cert)
{
	BIO* bio = BIO_new_mem_buf((void*)data, datalen);
	int retVal = 0;

	if ((cert->pkey = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL)) == NULL) { retVal = -1; }
	if ((cert->x509 = PEM_read_bio_X509(bio, NULL, 0, NULL)) == NULL) { retVal = -1; }

	BIO_free(bio);
	return retVal;
}

int __fastcall util_from_pem(char* filename, struct util_cert* cert)
{
	FILE *pFile = NULL;

	if (filename == NULL) return -1;
#ifdef WIN32 
	_wfopen_s(&pFile, ILibUTF8ToWide(filename, -1), L"rbN");
#else
	pFile = fopen(filename, "rb");
#endif
	if (pFile == NULL) goto error;

	if ((cert->pkey = PEM_read_PrivateKey(pFile, NULL, 0, NULL)) == NULL) goto error;
	if ((cert->x509 = PEM_read_X509(pFile, NULL, 0, NULL)) == NULL) goto error;

	fclose(pFile);
	return 0;
error:
	if (pFile != NULL) fclose(pFile);
	return -1;
}

int __fastcall util_to_p12(struct util_cert cert, char *password, char** data)
{
	PKCS12 *p12;
	int len;
	p12 = PKCS12_create(password, "Certificate", cert.pkey, cert.x509, NULL, 0, 0, 0, 0, 0);
	*data = NULL;
	len = i2d_PKCS12(p12, (unsigned char**)data);
	PKCS12_free(p12);
	return len;
}

int __fastcall util_from_p12(char* data, int datalen, char* password, struct util_cert* cert)
{
	int r = 0;
	PKCS12 *p12 = NULL;
	if (data == NULL || datalen == 0) return 0;
	cert->x509 = NULL;
	cert->pkey = NULL;
	p12 = d2i_PKCS12(&p12, (const unsigned char**)&data, datalen);
	r = PKCS12_parse(p12, password, &(cert->pkey), &(cert->x509), NULL);
	PKCS12_free(p12);
	return r;
}
void __fastcall util_printcert(struct util_cert cert)
{
	if (cert.x509 == NULL) return;
	X509_print_fp(stdout, cert.x509);
}

void __fastcall util_printcert_pk(struct util_cert cert)
{
	if (cert.pkey == NULL) return;
	//RSA_print_fp(stdout, cert.pkey->pkey.rsa, 0);
	RSA_print_fp(stdout, EVP_PKEY_get1_RSA(cert.pkey), 0);
}

// Creates a X509 certificate, if rootcert is NULL this creates a root (self-signed) certificate.
// Is the name parameter is NULL, the hex value of the hash of the public key will be the subject name.
int __fastcall util_mkCertEx(struct util_cert *rootcert, struct util_cert* cert, int bits, int days, char* name, enum CERTIFICATE_TYPES certtype, struct util_cert* initialcert, int noUsages)
{
	X509 *x = NULL;
	X509_EXTENSION *ex = NULL;
	EVP_PKEY *pk = NULL;
	RSA *rsa = NULL;
	X509_NAME *cname = NULL;
	X509 **x509p = NULL;
	EVP_PKEY **pkeyp = NULL;
	int hashlen = UTIL_SHA384_HASHSIZE;
	char hash[UTIL_SHA384_HASHSIZE];
	char serial[8];
	char nameStr[(UTIL_SHA384_HASHSIZE * 2) + 2];
	BIGNUM *oBigNbr;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	if (initialcert != NULL)
	{
		pk = X509_get_pubkey(initialcert->x509);
		rsa = EVP_PKEY_get1_RSA(initialcert->pkey);
		if ((x = X509_new()) == NULL) goto err;
	}
	else
	{
		if ((pkeyp == NULL) || (*pkeyp == NULL)) { if ((pk = EVP_PKEY_new()) == NULL) return 0; }
		else pk = *pkeyp;
		if ((x509p == NULL) || (*x509p == NULL)) { if ((x = X509_new()) == NULL) goto err; }
		else x = *x509p;
		oBigNbr = BN_new();
		rsa = RSA_new();
		BN_set_word(oBigNbr, RSA_F4);
		if (RSA_generate_key_ex(rsa, bits, oBigNbr, NULL) == -1)
		{
			RSA_free(rsa);
			BN_free(oBigNbr);
			abort();
		}
		BN_free(oBigNbr);
	}

	if (!EVP_PKEY_assign_RSA(pk, rsa))
	{
		RSA_free(rsa);
		abort();
	}
	rsa = NULL;

	util_randomtext(8, serial);
	X509_set_version(x, 2);
	ASN1_STRING_set(X509_get_serialNumber(x), serial, 8);
	X509_gmtime_adj(X509_get_notBefore(x), (long)60 * 60 * 24 * -10);
	X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * days);
	X509_set_pubkey(x, pk);

	// Set the subject name
	cname = X509_get_subject_name(x);

	if (name == NULL)
	{
		// Computer the hash of the public key
		//util_sha256((char*)x->cert_info->key->public_key->data, x->cert_info->key->public_key->length, hash); // OpenSSL 1.0
		X509_pubkey_digest(x, EVP_sha384(), (unsigned char*)hash, (unsigned int*)&hashlen); // OpenSSL 1.1

		util_tohex(hash, UTIL_SHA384_HASHSIZE, nameStr);
		X509_NAME_add_entry_by_txt(cname, "CN", MBSTRING_ASC, (unsigned char*)nameStr, -1, -1, 0);
	}
	else
	{
		// This function creates and adds the entry, working out the correct string type and performing checks on its length. Normally we'd check the return value for errors...
		X509_NAME_add_entry_by_txt(cname, "CN", MBSTRING_ASC, (unsigned char*)name, -1, -1, 0);
	}

	if (rootcert == NULL)
	{
		// Its self signed so set the issuer name to be the same as the subject.
		X509_set_issuer_name(x, cname);

		// Add various extensions: standard extensions
		util_add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
		if (noUsages == 0) { util_add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign"); }
		util_add_ext(x, NID_subject_key_identifier, "hash");
		//util_add_ext(x, NID_netscape_cert_type, "sslCA");
		//util_add_ext(x, NID_netscape_comment, "example comment extension");

		if (!X509_sign(x, pk, EVP_sha384())) goto err;
	}
	else
	{
		// This is a sub-certificate
		cname = X509_get_subject_name(rootcert->x509);
		X509_set_issuer_name(x, cname);

		// Add usual cert stuff
		if (noUsages == 0)
		{
			ex = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "digitalSignature, keyEncipherment, keyAgreement");
			X509_add_ext(x, ex, -1);
			X509_EXTENSION_free(ex);
		}

		// Add usages: TLS server, TLS client, Intel(R) AMT Console
		//ex = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Server Authentication, TLS Web Client Authentication, 2.16.840.1.113741.1.2.1, 2.16.840.1.113741.1.2.2");
		if (certtype == CERTIFICATE_TLS_SERVER)
		{
			// TLS server
			ex = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Server Authentication");
			X509_add_ext(x, ex, -1);
			X509_EXTENSION_free(ex);
		}
		else if (certtype == CERTIFICATE_TLS_CLIENT)
		{
			// TLS client
			ex = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Client Authentication");
			X509_add_ext(x, ex, -1);
			X509_EXTENSION_free(ex);
		}

		if (!X509_sign(x, rootcert->pkey, EVP_sha384())) goto err;
	}

	cert->x509 = x;
	cert->pkey = pk;
	cert->flags = 0;

	return 1;
err:
	return 0;
}

int __fastcall util_certhash(struct util_cert cert, char* result) {
	int hashlen = UTIL_SHA384_HASHSIZE;
	if (cert.x509 == NULL) return -1;
	X509_digest(cert.x509, EVP_sha384(), (unsigned char*)result, (unsigned int *)&hashlen); // OpenSSL 1.1
	return 0;
}

int __fastcall util_certhash2(X509* cert, char* result) {
	int hashlen = UTIL_SHA384_HASHSIZE;
	if (cert == NULL) return -1;
	X509_digest(cert, EVP_sha384(), (unsigned char*)result, (unsigned int*)&hashlen); // OpenSSL 1.1
	return 0;
}

int __fastcall util_keyhash(struct util_cert cert, char* result)
{
	int hashlen = UTIL_SHA384_HASHSIZE;
	if (cert.x509 == NULL) return -1;
	X509_pubkey_digest(cert.x509, EVP_sha384(), (unsigned char*)result,(unsigned int *) &hashlen); // OpenSSL 1.1
	return 0;
}

int __fastcall util_keyhash2(X509* cert, char* result)
{
	int hashlen = UTIL_SHA384_HASHSIZE;
	if (cert == NULL) return -1;
	X509_pubkey_digest(cert, EVP_sha384(), (unsigned char*)result, (unsigned int*)&hashlen); // OpenSSL 1.1
	return 0;
}

// Sign this block of data, the first 32 bytes of the block must be avaialble to add the certificate hash.
int __fastcall util_sign(struct util_cert cert, char* data, int datalen, char** signature)
{
	int size = 0;
	unsigned int hashsize = UTIL_SHA384_HASHSIZE;
	BIO *in = NULL;
	PKCS7 *message = NULL;
	*signature = NULL;
	if (datalen <= UTIL_SHA384_HASHSIZE) return 0;

	// Add hash of the certificate to start of data
	X509_digest(cert.x509, EVP_sha384(), (unsigned char*)data, &hashsize);

	// Sign the block
	in = BIO_new_mem_buf(data, datalen);
	message = PKCS7_sign(cert.x509, cert.pkey, NULL, in, PKCS7_BINARY);
	if (message == NULL) goto error;
	size = i2d_PKCS7(message, (unsigned char**)signature);

error:
	if (message != NULL) PKCS7_free(message);
	if (in != NULL) BIO_free(in);
	return size;
}

// Verify the signed block, the first 32 bytes of the data must be the certificate hash to work.
int __fastcall util_verify(char* signature, int signlen, struct util_cert* cert, char** data)
{
	unsigned int size, r;
	BIO *out = NULL;
	PKCS7 *message = NULL;
	char* data2 = NULL;
	char hash[UTIL_SHA256_HASHSIZE];
	STACK_OF(X509) *st = NULL;

	cert->x509 = NULL;
	cert->pkey = NULL;
	*data = NULL;
	message = d2i_PKCS7(NULL, (const unsigned char**)&signature, signlen);
	if (message == NULL) goto error;
	out = BIO_new(BIO_s_mem());

	// Lets rebuild the original message and check the size
	size = i2d_PKCS7(message, NULL);
	if (size < (unsigned int)signlen) goto error;

	// Check the PKCS7 signature, but not the certificate chain.
	r = PKCS7_verify(message, NULL, NULL, NULL, out, PKCS7_NOVERIFY);
	if (r == 0) goto error;

	// If data block contains less than 32 bytes, fail.
	size = (unsigned int)BIO_get_mem_data(out, &data2);
	if (size <= UTIL_SHA256_HASHSIZE) goto error;

	// Copy the data block
	*data = (char*)malloc(size + 1);
	if (*data == NULL) goto error;
	memcpy_s(*data, size + 1, data2, size);
	(*data)[size] = 0;

	// Get the certificate signer
	st = PKCS7_get0_signers(message, NULL, PKCS7_NOVERIFY);
	cert->x509 = X509_dup(sk_X509_value(st, 0));
	sk_X509_free(st);

	// Get a full certificate hash of the signer
	r = UTIL_SHA256_HASHSIZE;
	X509_digest(cert->x509, EVP_sha256(), (unsigned char*)hash, &r);

	// Check certificate hash with first 32 bytes of data.
	if (memcmp(hash, *data, UTIL_SHA256_HASHSIZE) != 0) goto error;

	// Approved, cleanup and return.
	BIO_free(out);
	PKCS7_free(message);

	return size;

error:
	if (out != NULL) BIO_free(out);
	if (message != NULL) PKCS7_free(message);
	if (*data != NULL) free(*data);
	if (cert->x509 != NULL) { X509_free(cert->x509); cert->x509 = NULL; }

	return 0;
}

// Encrypt a block of data for a target certificate
int __fastcall util_encrypt(struct util_cert cert, char* data, int datalen, char** encdata)
{
	int size = 0;
	BIO *in = NULL;
	PKCS7 *message = NULL;
	STACK_OF(X509) *encerts = NULL;
	*encdata = NULL;
	if (datalen == 0) return 0;

	// Setup certificates
	encerts = sk_X509_new_null();
	sk_X509_push(encerts, cert.x509);

	// Encrypt the block
	*encdata = NULL;
	in = BIO_new_mem_buf(data, datalen);
	message = PKCS7_encrypt(encerts, in, EVP_aes_128_cbc(), PKCS7_BINARY);
	if (message == NULL) return 0;
	size = i2d_PKCS7(message, (unsigned char**)encdata);
	BIO_free(in);
	PKCS7_free(message);
	sk_X509_free(encerts);
	return size;
}

// Encrypt a block of data using multiple target certificates
int __fastcall util_encrypt2(STACK_OF(X509) *certs, char* data, int datalen, char** encdata)
{
	int size = 0;
	BIO *in = NULL;
	PKCS7 *message = NULL;
	*encdata = NULL;
	if (datalen == 0) return 0;

	// Encrypt the block
	*encdata = NULL;
	in = BIO_new_mem_buf(data, datalen);
	message = PKCS7_encrypt(certs, in, EVP_aes_128_cbc(), PKCS7_BINARY);
	if (message == NULL) return 0;
	size = i2d_PKCS7(message, (unsigned char**)encdata);
	BIO_free(in);
	PKCS7_free(message);
	return size;
}

// Decrypt a block of data using the specified certificate. The certificate must have a private key.
int __fastcall util_decrypt(char* encdata, int encdatalen, struct util_cert cert, char** data)
{
	unsigned int size, r;
	BIO *out = NULL;
	PKCS7 *message = NULL;
	char* data2 = NULL;

	*data = NULL;
	if (cert.pkey == NULL) return 0;

	message = d2i_PKCS7(NULL, (const unsigned char**)&encdata, encdatalen);
	if (message == NULL) goto error;
	out = BIO_new(BIO_s_mem());

	// Lets rebuild the original message and check the size
	size = i2d_PKCS7(message, NULL);
	if (size < (unsigned int)encdatalen) goto error;

	// Decrypt the PKCS7
	r = PKCS7_decrypt(message, cert.pkey, cert.x509, out, 0);
	if (r == 0) goto error;

	// If data block contains 0 bytes, fail.
	size = (unsigned int)BIO_get_mem_data(out, &data2);
	if (size == 0) goto error;

	// Copy the data block
	*data = (char*)malloc(size + 1);
	if (*data == NULL) goto error;
	memcpy_s(*data, size + 1, data2, size);
	(*data)[size] = 0;

	// Cleanup and return.
	BIO_free(out);
	PKCS7_free(message);

	return size;

error:
	if (out != NULL) BIO_free(out);
	if (message != NULL) PKCS7_free(message);
	if (*data != NULL) free(*data);
	if (data2 != NULL) free(data2);
	return 0;
}

// Encrypt a block of data using raw RSA. This is used to handle data in the most compact possible way.
int __fastcall util_rsaencrypt(X509 *cert, char* data, int datalen, char** encdata)
{
	int len;
	RSA *rsa;
	EVP_PKEY *pkey;

	pkey = X509_get_pubkey(cert);
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (datalen > RSA_size(rsa)) { EVP_PKEY_free(pkey); RSA_free(rsa); return 0; }
	*encdata = (char*)malloc(RSA_size(rsa));
	len = RSA_public_encrypt(datalen, (const unsigned char*)data, (unsigned char*)*encdata, rsa, RSA_PKCS1_OAEP_PADDING);
	EVP_PKEY_free(pkey);
	RSA_free(rsa);
	if (len == RSA_size(rsa)) return len;
	free(*encdata);
	*encdata = NULL;
	return 0;
}

// Decrypt a block of data using raw RSA. This is used to handle data in the most compact possible way.
int __fastcall util_rsadecrypt(struct util_cert cert, char* data, int datalen, char** decdata)
{
	int len;
	RSA *rsa;

	rsa = EVP_PKEY_get1_RSA(cert.pkey);
	*decdata = (char*)malloc(RSA_size(rsa));
	len = RSA_private_decrypt(datalen, (const unsigned char*)data, (unsigned char*)*decdata, rsa, RSA_PKCS1_OAEP_PADDING);
	RSA_free(rsa);
	if (len != 0) return len;
	free(*decdata);
	*decdata = NULL;
	return 0;
}

// Verify the RSA signature of a block using SHA1 hash
int __fastcall util_rsaverify(X509 *cert, char* data, int datalen, char* sign, int signlen)
{
	int r;
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;
	SHA_CTX c;
	char hash[20];

	SHA1_Init(&c);
	SHA1_Update(&c, data, datalen);
	SHA1_Final((unsigned char*)hash, &c);
	pkey = X509_get_pubkey(cert);
	rsa = EVP_PKEY_get1_RSA(pkey);
	//rsa->pad = RSA_PKCS1_PADDING; // OPENSSL 1.0
#ifdef WIN32
	r = RSA_verify(NID_sha1, (const unsigned char*)hash, 20, (const unsigned char*)sign, signlen, rsa);
#else
	r = RSA_verify(NID_sha1, (const unsigned char*)hash, 20, (unsigned char*)sign, signlen, rsa);
#endif
	EVP_PKEY_free(pkey);
	RSA_free(rsa);
	return r;
}

#ifdef _SSL_KEYS_EXPORTABLE
int  __fastcall util_exportkeys(SSL* ssl, char *buffer, size_t bufferSize)
{
	int len = 0;
	char clientRandom[32], serverRandom[32], sessionSecret[48], clientRandomHex[65], serverRandomHex[65], sessionSecretHex[97];

	// Get the client random and session key.
	if (ssl == NULL) return(0);
	if (SSL_get_client_random(ssl, (unsigned char*)clientRandom, 32) != 32) return(0);
	if (SSL_get_server_random(ssl, (unsigned char*)serverRandom, 32) != 32) return(0);
	if (SSL_SESSION_get_master_key(SSL_get_session(ssl), (unsigned char*)sessionSecret, 48) != 48) return(0);

	// Convert the randoms and key into hex
	util_tohex(clientRandom, 32, clientRandomHex);
	util_tohex(serverRandom, 32, serverRandomHex);
	util_tohex(sessionSecret, 48, sessionSecretHex);

	// Append the client random and key to the log file.
	if (buffer != NULL && bufferSize > 0)
	{
		len = sprintf_s(buffer, bufferSize, "CLIENT_RANDOM %s %s\r\nCLIENT_RANDOM %s %s\r\n", clientRandomHex, sessionSecretHex, serverRandomHex, sessionSecretHex);
	}
	return(len);
}
#endif

#ifdef _DEBUG
// Saves the SSL/TLS session private keys to file.
// Because we do lots of DTLS, we will be saving both client and server randoms pointing to the same key.
// WARNING: THIS IS FOR DEBUG ONLY, NEVER RELEASE THIS. For safety, comment this out.
void  __fastcall util_savekeys(SSL* ssl) {
	/*
	int len;
	char clientRandom[32], serverRandom[32], sessionSecret[48], clientRandomHex[65], serverRandomHex[65], sessionSecretHex[97], text[2000];

	// Get the client random and session key.
	if (ssl == NULL) return;
	if (SSL_get_client_random(ssl, clientRandom, 32) != 32) return;
	if (SSL_get_server_random(ssl, serverRandom, 32) != 32) return;
	len = SSL_SESSION_get_master_key(SSL_get_session(ssl), sessionSecret, 48);
	if (len <= 0) return;

	// Convert the randoms and key into hex
	util_tohex(clientRandom, 32, clientRandomHex);
	util_tohex(serverRandom, 32, serverRandomHex);
	util_tohex(sessionSecret, len, sessionSecretHex);

	// Append the client random and key to the log file.
	len = snprintf(text, 1000, "CLIENT_RANDOM %s %s\r\nCLIENT_RANDOM %s %s\r\n", clientRandomHex, sessionSecretHex, serverRandomHex, sessionSecretHex);
	util_appendfile("meshagentkeys.log", text, len);
	*/
}
#endif

#endif
