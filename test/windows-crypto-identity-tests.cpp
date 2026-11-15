#define main crypto_tls_tests_main
#include "windows-crypto-tls-tests.cpp"
#undef main
#include "../microstack/windows_legacy_pkcs12.h"
#include <vector>

static std::vector<unsigned char> encode(PKCS12* package)
{
    check(package != NULL);
    int length = i2d_PKCS12(package, NULL);
    check(length > 0);
    std::vector<unsigned char> bytes(length);
    unsigned char* cursor = bytes.data();
    check(i2d_PKCS12(package, &cursor) == length);
    return bytes;
}

int main()
{
    const char* password = "synthetic-test-only";
    EVP_PKEY* originalKey = key();
    X509* originalCertificate = certificate(originalKey);
    OSSL_LIB_CTX* context = OSSL_LIB_CTX_new();
    check(context != NULL);
    OSSL_PROVIDER* defaults = OSSL_PROVIDER_load(context, "default");
    OSSL_PROVIDER* legacy = OSSL_PROVIDER_load(context, "legacy");
    check(defaults != NULL && legacy != NULL);
    // The previous library used 3DES for the key and RC2-40 for the certificate.
    PKCS12* package = PKCS12_create_ex(password, "synthetic identity", originalKey,
        originalCertificate, NULL, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
        NID_pbe_WithSHA1And40BitRC2_CBC, 2048, 2048, 0, context, NULL);
    check(package != NULL && PKCS12_set_mac(package, password, -1, NULL, 0, 2048, EVP_sha1()) == 1);
    std::vector<unsigned char> bytes = encode(package);
    PKCS12_free(package);
    OSSL_PROVIDER_unload(legacy); OSSL_PROVIDER_unload(defaults);
    OSSL_LIB_CTX_free(context);

    const unsigned char* cursor = bytes.data();
    package = d2i_PKCS12(NULL, &cursor, (long)bytes.size());
    check(package != NULL);
    EVP_PKEY* importedKey = NULL;
    X509* importedCertificate = NULL;
    check(PKCS12_parse(package, password, &importedKey, &importedCertificate, NULL) == 0);
    PKCS12_free(package); ERR_clear_error();

    for (int i = 0; i < 3; ++i)
    {
        check(MeshWindowsParsePKCS12(bytes.data(), (int)bytes.size(), password,
            &importedKey, &importedCertificate) == 1);
        check(X509_cmp(originalCertificate, importedCertificate) == 0);
        check(EVP_PKEY_eq(originalKey, importedKey) == 1);
        // These use the imported identity after its decoder context was destroyed.
        run(TLS1_2_VERSION, true, true, false, importedKey, importedCertificate);
        run(TLS1_3_VERSION, true, true, false, importedKey, importedCertificate);
        EVP_PKEY_free(importedKey); X509_free(importedCertificate);
        importedKey = NULL; importedCertificate = NULL;
    }
    check(MeshWindowsParsePKCS12(bytes.data(), (int)bytes.size(), "wrong password",
        &importedKey, &importedCertificate) == 0 && importedKey == NULL && importedCertificate == NULL);
    bytes.back() ^= 1;
    check(MeshWindowsParsePKCS12(bytes.data(), (int)bytes.size(), password,
        &importedKey, &importedCertificate) == 0 && importedKey == NULL && importedCertificate == NULL);
    bytes[0] = 0;
    check(MeshWindowsParsePKCS12(bytes.data(), (int)bytes.size(), password,
        &importedKey, &importedCertificate) == 0 && importedKey == NULL && importedCertificate == NULL);
    check(MeshWindowsParsePKCS12(NULL, 0, password, &importedKey, &importedCertificate) == 0);
    check(MeshWindowsParsePKCS12(bytes.data(), -1, password, &importedKey, &importedCertificate) == 0);

    package = PKCS12_create(password, "modern identity", originalKey, originalCertificate, NULL, 0, 0, 0, 0, 0);
    bytes = encode(package); PKCS12_free(package);
    check(MeshWindowsParsePKCS12(bytes.data(), (int)bytes.size(), password,
        &importedKey, &importedCertificate) == 1);
    check(X509_cmp(originalCertificate, importedCertificate) == 0 && EVP_PKEY_eq(originalKey, importedKey) == 1);
    EVP_PKEY_free(importedKey); X509_free(importedCertificate);

    EVP_CIPHER* rc2 = EVP_CIPHER_fetch(NULL, "RC2-40-CBC", NULL);
    check(rc2 == NULL); EVP_CIPHER_free(rc2); ERR_clear_error();
    EVP_PKEY_free(originalKey); X509_free(originalCertificate);
    puts("PASS: legacy/modern identity continuity, decoder lifetime, malformed/password/MAC rejection, TLS context isolation");
    return 0;
}
