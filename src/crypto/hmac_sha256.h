#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include <stdint.h>
#include <stddef.h>

/* Standalone FIPS 180-4 SHA-256 + RFC 2104 HMAC-SHA256.
 * No external dependencies — works on all platforms regardless of TLS support. */

typedef struct {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]);

/* Compute HMAC-SHA256(key, msg) → 32-byte raw digest in out[] */
void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *msg, size_t msglen,
                 uint8_t out[32]);

#endif /* HMAC_SHA256_H */
