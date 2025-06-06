#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include "token_extractor.h"

#define MAX_FILE_SIZE 4096

// Function prototypes for internal functions
char* read_token_file(const char* filename, size_t* file_size);
char* decrypt_aes_gcm(const unsigned char* ciphertext, size_t ciphertext_len, 
                      const unsigned char* key, size_t* plaintext_len);
char* base64_decode(const char* input, size_t* output_len);

// Main token extraction function with secret parameter
char* extract_token(const char* secret) {
    const char* filename = "/etc/openframe/token.txt";
    
    if (!secret || strlen(secret) != 32) {
        printf("Secret must be exactly 32 bytes for AES-256\n");
        return NULL; // Secret must be exactly 32 bytes for AES-256
    }
    
    size_t file_size;
    char* file_data = read_token_file(filename, &file_size);
    if (!file_data) {
        printf("Failed to read token file\n");
        return NULL;
    }

    size_t decoded_len;
    char* encrypted_data = base64_decode(file_data, &decoded_len);

    if (!encrypted_data) {
        printf("Failed to base64 decode token file\n");
        return NULL;
    }

    // For GCM, the nonce is at the beginning of the ciphertext
    // GCM nonce size is typically 12 bytes
    const int GCM_NONCE_SIZE = 12;
    
    if (decoded_len < GCM_NONCE_SIZE) {
        printf("Decoded data size (%zu) is less than GCM nonce size (%d)\n", decoded_len, GCM_NONCE_SIZE);
        free(encrypted_data);
        return NULL;
    }
    
    size_t ciphertext_len = decoded_len; // Full decoded data for GCM decryption
    
    size_t plaintext_len;
    char* decrypted_token = decrypt_aes_gcm((const unsigned char*)encrypted_data, ciphertext_len, (const unsigned char*)secret, &plaintext_len);
    free(encrypted_data);
    return decrypted_token;
}

// Function to read file content
char* read_token_file(const char* filename, size_t* file_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return NULL;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (*file_size > MAX_FILE_SIZE) {
        printf("File size is greater than MAX_FILE_SIZE\n");
        fclose(file);
        return NULL;
    }
    
    // Allocate buffer and read file
    char* buffer = malloc(*file_size + 1);
    if (!buffer) {
        printf("Failed to allocate buffer\n");
        fclose(file);
        return NULL;
    }
    
    size_t bytes_read = fread(buffer, 1, *file_size, file);
    fclose(file);
    
    if (bytes_read != *file_size) {
        printf("Failed to read file\n");
        free(buffer);
        return NULL;
    }
    
    buffer[*file_size] = '\0'; // Null terminate for base64 decoding
    return buffer;
}

// Base64 decode function
char* base64_decode(const char* input, size_t* output_len) {
    BIO *bio, *b64;
    size_t input_len = strlen(input);
    char* buffer = malloc(input_len + 1);
    if (!buffer) return NULL;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, input_len);
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    *output_len = BIO_read(bio, buffer, input_len);
    BIO_free_all(bio);
    
    if (*output_len <= 0) {
        printf("Failed to base64 decode\n");
        free(buffer);
        return NULL;
    }
    
    buffer[*output_len] = '\0'; // если нужна null-terminated строка
    return buffer;
}

// AES-GCM decryption function
char* decrypt_aes_gcm(const unsigned char* ciphertext, size_t ciphertext_len, 
                      const unsigned char* key, size_t* plaintext_len) {
    const int GCM_NONCE_SIZE = 12;
    const int GCM_TAG_SIZE = 16;
    
    // Check minimum size: nonce + tag + at least some ciphertext
    if (ciphertext_len < GCM_NONCE_SIZE + GCM_TAG_SIZE) {
        printf("Ciphertext too short for GCM (need at least %d bytes, got %zu)\n", 
               GCM_NONCE_SIZE + GCM_TAG_SIZE, ciphertext_len);
        return NULL;
    }
    
    // Extract nonce from the beginning
    const unsigned char* nonce = ciphertext;
    
    // The actual ciphertext is between nonce and tag
    size_t actual_ciphertext_len = ciphertext_len - GCM_NONCE_SIZE - GCM_TAG_SIZE;
    const unsigned char* actual_ciphertext = ciphertext + GCM_NONCE_SIZE;
    
    // The tag is at the end
    const unsigned char* tag = ciphertext + ciphertext_len - GCM_TAG_SIZE;
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Failed to create EVP_CIPHER_CTX\n");
        return NULL;
    }
    
    // Initialize decryption with AES-256-GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        printf("Failed to initialize GCM cipher\n");
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("OpenSSL error: %s\n", err_buf);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    // Set nonce length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, NULL) != 1) {
        printf("Failed to set nonce length\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    // Set key and nonce
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        printf("Failed to set key and nonce\n");
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("OpenSSL error: %s\n", err_buf);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    // Allocate output buffer
    char* plaintext = malloc(actual_ciphertext_len + 1);
    if (!plaintext) {
        printf("Failed to allocate output buffer\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    int len;
    *plaintext_len = 0;
    
    // Decrypt the data
    if (EVP_DecryptUpdate(ctx, (unsigned char*)plaintext, &len, actual_ciphertext, actual_ciphertext_len) != 1) {
        printf("Failed to decrypt data\n");
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("OpenSSL error: %s\n", err_buf);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    *plaintext_len = len;
    
    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void*)tag) != 1) {
        printf("Failed to set authentication tag\n");
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    // Finalize decryption and verify authentication tag
    if (EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext + len, &len) != 1) {
        printf("Failed to finalize decryption (authentication failed)\n");
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("OpenSSL error: %s\n", err_buf);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    *plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Null-terminate the string
    plaintext[*plaintext_len] = '\0';
    
    return plaintext;
}
