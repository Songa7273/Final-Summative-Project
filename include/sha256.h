#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_HEX_LEN 65
#define SHA256_DIGEST_LEN 32

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[SHA256_DIGEST_LEN]);
void sha256_hash_bytes(const uint8_t *data, size_t len, uint8_t hash[SHA256_DIGEST_LEN]);
void sha256_hash_hex(const uint8_t *data, size_t len, char out[SHA256_HEX_LEN]);
void bytes_to_hex(const uint8_t *bytes, size_t len, char *out, size_t out_size);

#endif
