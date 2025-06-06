#ifndef TOKEN_EXTRACTOR_H
#define TOKEN_EXTRACTOR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Extract token from encrypted file using the provided secret
 * @param secret - 32-byte secret key for AES-256 decryption
 * @return Decrypted token string (caller must free) or NULL on failure
 */
char* extract_token(const char* secret);

#ifdef __cplusplus
}
#endif

#endif // TOKEN_EXTRACTOR_H 