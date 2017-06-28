
#ifndef CURVE_25519_H
#define CURVE_25519_H

/**
 * @brief Create signature based on the Curve25519 montgomery curve
 *
 * Use ESDSA to derive signature
 *
 * @param public_key - Curve25519 public key (unsigned binary data, low endian, 32 byte)
 * @param private_key - Curve25519 private key (unsigned binary data, low endian, 32 byte)
 * @return 0 on success
 */
int curve25519_getpub(unsigned char* public_key, const unsigned char* private_key);

/**
 * @brief Create signature based on the Curve25519 montgomery curve
 *
 * Use ESDSA to derive signature
 *
 * @param signature - derived signature (unsigned binary data, low endian, 64 byte)
 * @param private_key - Curve25519 private key (unsigned binary data, low endian, 32 byte)
 * @param msg - message to be signed
 * @param msg_len - message length
 * @return 0 on success
 */
int curve25519_sign(unsigned char* signature,
                    const unsigned char* private_key,
                    const unsigned char* msg, const unsigned long msg_len);

/**
 * @brief Verify signature based on the Curve25519 montgomery curve
 *
 * Use ESDSA to verify signature
 *
 * @param signature - derived signature (unsigned binary data, low endian, 64 byte)
 * @param public_key - Curve25519 public key (unsigned binary data, low endian, 32 byte)
 * @param msg - message to be verified
 * @param msg_len - message length
 * @return 0 on success
 */
int curve25519_verify(const unsigned char* signature,
                      const unsigned char* public_key,
                      const unsigned char* msg, const unsigned long msg_len);

/**
 * @brief Compute shared secret based on the Curve25519 montgomery curve
 *
 * @param shared_secret - computed shared secret (unsigned binary data, low endian, 32 byte)
 * @param public_key - Curve25519 public key from other party (unsigned binary data, low endian, 32 byte)
 * @param private_key - Curve25519 our private key (unsigned binary data, low endian, 32 byte)
 * @return 0 on success
 */
int curve25519_key_exchange(unsigned char *shared_secret,
                            const unsigned char *public_key,
                            const unsigned char *private_key);

#endif /* CURVE_25519_H */
