/* OpenSSL 3 compatibility for identities written by older Windows Agents. */
#ifndef MESH_WINDOWS_LEGACY_PKCS12_H
#define MESH_WINDOWS_LEGACY_PKCS12_H
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/err.h>

/** Import a serialized Agent identity without enabling legacy TLS algorithms.
 * Try the default provider first. Only the compatibility retry enables RC2-era
 * bag decoding in a private temporary provider context; recreate returned objects
 * in the default context before that temporary decoder is destroyed.
 * Valid key/certificate output pointers are required. On success the caller
 * owns returned OpenSSL objects; on failure both outputs are cleared.
 * Password/package bytes are never logged; temporary private-key DER is wiped.
 */
static int MeshWindowsParsePKCS12(const unsigned char* data, int length,
    const char* password, EVP_PKEY** key, X509** certificate)
{
    const unsigned char* cursor = data;
    PKCS12* package = NULL;
    OSSL_LIB_CTX* context = NULL;
    OSSL_PROVIDER* defaults = NULL;
    OSSL_PROVIDER* legacy = NULL;
    EVP_PKEY* importedKey = NULL;
    X509* importedCertificate = NULL;
    unsigned char* keyBytes = NULL;
    unsigned char* writer = NULL;
    unsigned char* certificateBytes = NULL;
    int keyLength = 0, certificateLength = 0, result = 0;
    if (key == NULL || certificate == NULL) return 0;
    *key = NULL; *certificate = NULL;
    if (data == NULL || length <= 0) return 0;

    package = d2i_PKCS12(NULL, &cursor, length);
    if (package == NULL) return 0;
    result = PKCS12_parse(package, password, key, certificate, NULL);
    PKCS12_free(package); package = NULL;
    if (result == 1) return 1;

    /* RC2-encrypted certificate bags were the old PKCS12_create default.
       Confine their decoder to a temporary context, never the TLS context. */
    EVP_PKEY_free(*key); X509_free(*certificate);
    *key = NULL; *certificate = NULL;
    ERR_clear_error();
    context = OSSL_LIB_CTX_new();
    if (context == NULL) goto done;
    defaults = OSSL_PROVIDER_load(context, "default");
    legacy = OSSL_PROVIDER_load(context, "legacy");
    if (defaults == NULL || legacy == NULL) goto done;
    package = PKCS12_init_ex(NID_pkcs7_data, context, NULL);
    if (package == NULL) goto done;
    cursor = data;
    if (d2i_PKCS12(&package, &cursor, length) == NULL ||
        PKCS12_parse(package, password, &importedKey, &importedCertificate, NULL) != 1 ||
        importedKey == NULL || importedCertificate == NULL) goto done;

    /* Recreate outputs in the default context before destroying the decoder.
       The original certificate bytes and private key remain unchanged. */
    keyLength = i2d_PrivateKey(importedKey, NULL);
    certificateLength = i2d_X509(importedCertificate, &certificateBytes);
    if (keyLength <= 0 || certificateLength <= 0) goto done;
    keyBytes = (unsigned char*)OPENSSL_malloc((size_t)keyLength);
    if (keyBytes == NULL) goto done;
    writer = keyBytes;
    if (i2d_PrivateKey(importedKey, &writer) != keyLength) goto done;
    cursor = keyBytes;
    *key = d2i_AutoPrivateKey(NULL, &cursor, keyLength);
    cursor = certificateBytes;
    *certificate = d2i_X509(NULL, &cursor, certificateLength);
    if (*key == NULL || *certificate == NULL || X509_check_private_key(*certificate, *key) != 1) goto done;
    result = 1;

done:
    if (result != 1)
    {
        EVP_PKEY_free(*key); X509_free(*certificate);
        *key = NULL; *certificate = NULL;
    }
    OPENSSL_clear_free(keyBytes, keyLength > 0 ? (size_t)keyLength : 0);
    OPENSSL_free(certificateBytes);
    EVP_PKEY_free(importedKey); X509_free(importedCertificate);
    PKCS12_free(package);
    OSSL_PROVIDER_unload(legacy); OSSL_PROVIDER_unload(defaults);
    OSSL_LIB_CTX_free(context);
    return result;
}
#endif
