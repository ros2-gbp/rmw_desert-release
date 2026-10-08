#ifndef COSE_CRYPTO_ASCON_C_H
#define COSE_CRYPTO_ASCON_C_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define HAVE_ALGO_ASCON_AEAD128 /**< Ascon AEAD mode support with 128 bit tag */
#define HAVE_ALGO_ASCON_AEAD128_64 /**< Ascon AEAD mode support with 64 bit tag */
#define HAVE_ALGO_ASCON_AEAD128_32 /**< Ascon AEAD mode support with 32 bit tag */
#define HAVE_ALGO_HMAC_ASCON_HASH256

#define COSE_CRYPTO_AEAD_ASCON_KEYBYTES        16
#define COSE_CRYPTO_AEAD_ASCON_NONCEBYTES      16
#define COSE_CRYPTO_AEAD_ASCON_ABYTES          16
#define COSE_CRYPTO_AEAD_ASCON_64_ABYTES        8
#define COSE_CRYPTO_AEAD_ASCON_32_ABYTES        4

#define ASCON_HASH_SIZE 32
#define ASCON_HMAC_BLOCK_SIZE 32

typedef union {
    uint64_t x[5];
    uint32_t w[5][2];
    uint8_t b[5][8];
} ascon_state_t;

int ascon_aead_encrypt_trunc(uint8_t* t, uint8_t* c, const uint8_t* m, uint64_t mlen,
                       const uint8_t* ad, uint64_t adlen, const uint8_t* npub,
                       const uint8_t* k, uint16_t t_bits);

int ascon_aead_decrypt_trunc(uint8_t* m, const uint8_t* t, const uint8_t* c,
                       uint64_t clen, const uint8_t* ad, uint64_t adlen,
                       const uint8_t* npub, const uint8_t* k, uint16_t t_bits);

void ascon_inithash(ascon_state_t* s);
void ascon_absorb(ascon_state_t* s, const uint8_t* in, uint64_t inlen);
void ascon_squeeze(ascon_state_t* s, uint8_t* out, uint64_t outlen);

#ifdef __cplusplus
}
#endif

#endif