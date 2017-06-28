#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void ed25519_sign(unsigned char *signature, const unsigned char *message,
                  size_t message_len, const unsigned char *public_key,
                  const unsigned char *private_key);

int ed25519_verify(const unsigned char *signature, const unsigned char *message,
                   size_t message_len, const unsigned char *public_key);

void ed25519_key_exchange(unsigned char *shared_secret,
                          const unsigned char *public_key,
                          const unsigned char *private_key);

#ifdef __cplusplus
}
#endif

#endif
