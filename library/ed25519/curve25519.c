#include "config.h"

#if defined(ED25519_ENABLED)
#include <string.h>

#include "ed25519/fe.h"
#include "ed25519/ge.h"
#include "ed25519/sha512.h"
#include "ed25519/ed25519.h"
#include "ed25519/curve25519.h"

/*
 * Implementation that should never be optimized out by the compiler.
 * This method is taken from MbedTlS library.
 */
static void zeroize(void *v, size_t n) {
    volatile unsigned char *p = v; while(n--) *p++ = 0;
}

int curve25519_getpub(unsigned char* public_key, const unsigned char* private_key)
{
    ge_p3 A;
    fe x1, tmp0, tmp1;
    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);

    /* convert edwards to montgomery */
    /* due to CodesInChaos: montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p */
    fe_frombytes(x1, public_key);
    fe_1(tmp1);
    fe_add(tmp0, x1, tmp1);
    fe_sub(tmp1, tmp1, x1);
    fe_invert(tmp1, tmp1);
    fe_mul(x1, tmp0, tmp1);

    fe_tobytes(public_key, x1);
    return 0;
}

int curve25519_sign(unsigned char* signature,
                    const unsigned char* private_key,
                    const unsigned char* msg, const unsigned long msg_len)
{
    ge_p3 ed_public_key_point;
    unsigned char ed_public_key[32];
    unsigned char ed_private_key[64];
    unsigned char sign_bit = 0;

    /*
     * Step 1. Get Ed25519 private key from the Curve25519 private key
     */
    sha512(private_key, 32, ed_private_key); // H(k) = (h0, h1, . . . , h2b−1)
    memmove(ed_private_key, private_key, 32); // Restore k, and leave (hb, ..., hb-1) as is

    /*
     * Step 2. Get Ed25519 public key from the Curve25519 private key
     */
    ge_scalarmult_base(&ed_public_key_point, private_key);
    ge_p3_tobytes(ed_public_key, &ed_public_key_point);
    sign_bit = ed_public_key[31] & 0x80;

    /*
     * Step 3. Use EdDSA to derive signature
     */
    ed25519_sign(signature, msg, msg_len, ed_public_key, ed_private_key);

    /*
     * Step 4. Encode the sign bit into signature (in unused high bit of S)
     */
     signature[63] &= 0x7F;  // bit should be zero already, but just in case
     signature[63] |= sign_bit;

    zeroize(ed_private_key, 64);
    return 0;
}

int curve25519_verify(const unsigned char* signature,
                      const unsigned char* public_key,
                      const unsigned char* msg, const unsigned long msg_len)
{
    fe mont_x, mont_x_minus_one, mont_x_plus_one, inv_mont_x_plus_one;
    fe one;
    fe ed_y;
    unsigned char ed_public_key_point[32];
    unsigned char verify_buf[64]; // working buffer

    /*
     * Step 1. Convert the Curve25519 public key into an Ed25519 public key
     */
    fe_frombytes(mont_x, public_key);
    fe_1(one);
    fe_sub(mont_x_minus_one, mont_x, one);
    fe_add(mont_x_plus_one, mont_x, one);
    fe_invert(inv_mont_x_plus_one, mont_x_plus_one);
    fe_mul(ed_y, mont_x_minus_one, inv_mont_x_plus_one);
    fe_tobytes(ed_public_key_point, ed_y);

    /*
     * Step 2. Copy the sign bit, and remove it from signature
     */
    ed_public_key_point[31] |= (signature[63] & 0x80);
    memmove(verify_buf, signature, 64);
    verify_buf[63] &= 0x7F;

    /*
     * Step 3. Use EdDSA to verify signature
     */
    return ed25519_verify(verify_buf, msg, msg_len, ed_public_key_point);
}

int curve25519_key_exchange(unsigned char *shared_secret,
                            const unsigned char *public_key,
                            const unsigned char *private_key)
{
    fe mont_x, mont_x_minus_one, mont_x_plus_one, inv_mont_x_plus_one;
    fe one;
    fe ed_y;
    unsigned char ed_public_key[32];

    /*
     * Step 1. Convert the Curve25519 public key into an Ed25519 public key
     */
    fe_frombytes(mont_x, public_key);
    fe_1(one);
    fe_sub(mont_x_minus_one, mont_x, one);
    fe_add(mont_x_plus_one, mont_x, one);
    fe_invert(inv_mont_x_plus_one, mont_x_plus_one);
    fe_mul(ed_y, mont_x_minus_one, inv_mont_x_plus_one);
    fe_tobytes(ed_public_key, ed_y);

    /*
     * Step 2. Compute shared secred
     */
    ed25519_key_exchange(shared_secret, ed_public_key, private_key);
    return 0;
}
#endif /* ED25519_ENABLED */
