#ifndef ED25519_CONFIG_H
#define ED25519_CONFIG_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if !defined(ED25519_ENABLED) && defined(MBEDTLS_ED25519_C)
#define ED25519_ENABLED
#endif

#endif // ED25519_CONFIG_H
