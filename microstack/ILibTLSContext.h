#ifndef MESH_ILIB_TLS_CONTEXT_H
#define MESH_ILIB_TLS_CONTEXT_H
#include <stdint.h>
#include <openssl/ssl.h>

/* Keep protocol options separate from SSL_MODE_*: OpenSSL 3 assigns their low
   bits to meaningful options, including disabling extended master secrets. */
/** Apply protocol-policy option bits to an existing, caller-owned TLS context.
 * SSL_MODE_* values are not options: mixing the two APIs can silently change
 * OpenSSL 3 security options. Preserve full writes required by the memory BIO
 * path and retain legacy behavior outside the qualified Windows upgrade.
 */
static void ILibSSL_CTX_SetProtocolOptions(SSL_CTX* context, uint64_t protocolOptions)
{
#if (defined(WIN32) || defined(_WIN32)) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* Those flags never enabled modes in the old set_options calls. Keep full
       writes: the memory-BIO send path expects SSL_write to consume the buffer. */
    SSL_CTX_set_options(context, protocolOptions);
#else
    /* Preserve the existing behavior of builds outside this Windows upgrade. */
    SSL_CTX_set_options(context, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE | protocolOptions);
#endif
}
#endif
