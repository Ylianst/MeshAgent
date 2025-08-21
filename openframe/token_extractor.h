#ifndef TOKEN_EXTRACTOR_H
#define TOKEN_EXTRACTOR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Extract token from encrypted file using the provided secret and token path
 * @param secret - 32-byte secret key for AES-256 decryption
 * @param token_path - path to the token file (if NULL or empty, defaults to /etc/openframe/token.txt)
 * @return Decrypted token string (caller must free) or NULL on failure
 */
char* extract_token(const char* secret, const char* token_path);

#ifdef __cplusplus
}
#endif

#endif // TOKEN_EXTRACTOR_H 