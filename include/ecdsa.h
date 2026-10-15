#ifndef ECDSA_H
#define ECDSA_H

#include <stdint.h>

#define ECDSA_SIG_HEX_LEN 33

typedef struct {
    uint32_t x;
    uint32_t y;
} ECPoint;

typedef struct {
    uint32_t x;
    uint32_t y;
} ECDSAPublicKey;

void ecdsa_generate_key(uint32_t *private_key, ECDSAPublicKey *public_key);
int ecdsa_sign_message(const char *message, uint32_t private_key, char signature_hex[ECDSA_SIG_HEX_LEN]);
int ecdsa_verify_message(const char *message, const ECDSAPublicKey *public_key, const char *signature_hex);

#endif
