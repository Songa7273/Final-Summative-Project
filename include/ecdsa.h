#ifndef ECDSA_H
#define ECDSA_H

#define ECDSA_PRIVATE_KEY_LEN 512
#define ECDSA_PUBLIC_KEY_LEN 256
#define ECDSA_SIG_HEX_LEN 256

int ecdsa_generate_key(char private_key[ECDSA_PRIVATE_KEY_LEN],
                       char public_key[ECDSA_PUBLIC_KEY_LEN]);
int ecdsa_sign_message(const char *message, const char *private_key,
                       char signature_hex[ECDSA_SIG_HEX_LEN]);
int ecdsa_verify_message(const char *message, const char *public_key,
                         const char *signature_hex);

#endif
