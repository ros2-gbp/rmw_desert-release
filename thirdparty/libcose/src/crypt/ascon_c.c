#include "cose/crypto.h"
#include "cose/crypto/ascon_c.h"

#include <string.h>

// TODO: Find better solution
#define secure_memzero(mem, len) memset(mem, 0, len)

static int ascon_aead_get_tag_size(cose_algo_t algo, uint16_t* t_bits, uint16_t* t_bytes) {
    switch (algo) {
        case COSE_ALGO_ASCON_AEAD128:
            *t_bits = 128;
            *t_bytes = 16;
            break;
        case COSE_ALGO_ASCON_AEAD128_64:
            *t_bits = 64;
            *t_bytes = 8;
            break;
        case COSE_ALGO_ASCON_AEAD128_32:
            *t_bits = 32;
            *t_bytes = 4;
            break;
        default:
            return -1;
    }

    return 0;
}

int cose_crypto_aead_encrypt_ascon(uint8_t *c,
                                    size_t *clen,
                                    const uint8_t *msg,
                                    size_t msglen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    cose_algo_t algo) {
    uint16_t t_bits, t_bytes;
    int res = ascon_aead_get_tag_size(algo, &t_bits, &t_bytes);
    if (res < 0) {
        return -1;
    }

    uint8_t* tag = c + msglen;
    res = ascon_aead_encrypt_trunc(
        tag,
        c,
        msg,
        msglen,
        aad,
        aadlen,
        npub,
        k,
        t_bits
    );
    if (res != 0) {
        return -1;
    }

    *clen = msglen + t_bytes;
    return 0;
}

int cose_crypto_aead_decrypt_ascon(uint8_t *msg,
                                    size_t *msglen,
                                    const uint8_t *c,
                                    size_t clen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    cose_algo_t algo) {
    uint16_t t_bits, t_bytes;
    int res = ascon_aead_get_tag_size(algo, &t_bits, &t_bytes);
    if (res < 0) {
        return -1;
    }

    const uint8_t* tag = c + clen - t_bytes;
    res = ascon_aead_decrypt_trunc(
        msg,
        tag,
        c,
        clen - t_bytes,
        aad,
        aadlen,
        npub,
        k,
        t_bits
    );
    if (res != 0) {
        return -1;
    }

    *msglen = clen - t_bytes;
    return 0;
}

/********************** Hash ************************/

typedef struct
{
    ascon_state_t inner;
    ascon_state_t outer;
} crypto_auth_hmacascon256_state;

static int crypto_auth_hmacascon256_init(
    crypto_auth_hmacascon256_state *state,
    const uint8_t *key,
    size_t keylen)
{
    uint8_t k0[ASCON_HMAC_BLOCK_SIZE];
    uint8_t ipad[ASCON_HMAC_BLOCK_SIZE];
    uint8_t opad[ASCON_HMAC_BLOCK_SIZE];

    memset(k0, 0, sizeof(k0));

    if (keylen > ASCON_HMAC_BLOCK_SIZE) {

        ascon_state_t tmp;

        ascon_inithash(&tmp);
        ascon_absorb(&tmp, key, keylen);
        ascon_squeeze(&tmp, k0, ASCON_HASH_SIZE);

        memset(&tmp,0,sizeof(tmp));
    } else {

        memcpy(k0, key, keylen);
    }

    for (size_t i = 0; i < ASCON_HMAC_BLOCK_SIZE; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    ascon_inithash(&state->inner);
    ascon_absorb(&state->inner, ipad, ASCON_HMAC_BLOCK_SIZE);

    ascon_inithash(&state->outer);
    ascon_absorb(&state->outer, opad, ASCON_HMAC_BLOCK_SIZE);

    secure_memzero(k0,sizeof(k0));
    secure_memzero(ipad,sizeof(ipad));
    secure_memzero(opad,sizeof(opad));

    return 0;
}

static int crypto_auth_hmacascon256_update(
    crypto_auth_hmacascon256_state *state,
    const uint8_t *msg,
    size_t msglen)
{
    ascon_absorb(&state->inner, msg, msglen);
    return 0;
}

static int crypto_auth_hmacascon256_final(
    crypto_auth_hmacascon256_state *state,
    uint8_t *out)
{
    uint8_t inner_hash[ASCON_HASH_SIZE];

    ascon_squeeze(&state->inner,
                  inner_hash,
                  ASCON_HASH_SIZE);

    ascon_absorb(&state->outer,
                 inner_hash,
                 ASCON_HASH_SIZE);

    ascon_squeeze(&state->outer,
                  out,
                  ASCON_HASH_SIZE);

    secure_memzero(inner_hash,sizeof(inner_hash));
    secure_memzero(state,sizeof(*state));

    return 0;
}

int cose_crypto_hkdf_derive_ascon256(const uint8_t *salt, size_t salt_len,
                                   const uint8_t *ikm, size_t ikm_length,
                                   const uint8_t *info, size_t info_length,
                                   uint8_t *out, size_t out_length) {
    uint8_t prk[ASCON_HASH_SIZE];
    uint8_t slice[ASCON_HASH_SIZE];
    uint8_t counter = 1;
    size_t slice_len = ASCON_HASH_SIZE;
    size_t rounds;
    crypto_auth_hmacascon256_state state;

    /* ---------- HKDF-Extract ---------- */

    crypto_auth_hmacascon256_init(&state, salt, salt_len);
    crypto_auth_hmacascon256_update(&state, ikm, ikm_length);
    crypto_auth_hmacascon256_final(&state, prk);

    /* ---------- HKDF-Expand ---------- */

    rounds = out_length / ASCON_HASH_SIZE;
    if (out_length % ASCON_HASH_SIZE != 0) {
        rounds++;
    }

    if (rounds > 255) return COSE_ERR_CRYPTO;

    for (size_t i = 0; i < rounds; ++i) {
        size_t offset = i * ASCON_HASH_SIZE;

        counter = (uint8_t)(i + 1);

        crypto_auth_hmacascon256_init(
            &state,
            prk,
            sizeof(prk));

        if (i > 0) {
            crypto_auth_hmacascon256_update(
                &state,
                slice,
                slice_len);
        }

        if (info != NULL && info_length > 0) {
            crypto_auth_hmacascon256_update(
                &state,
                info,
                info_length);
        }

        crypto_auth_hmacascon256_update(
            &state,
            &counter,
            1);

        crypto_auth_hmacascon256_final(
            &state,
            slice);

        if (i + 1 == rounds) {
            slice_len = out_length - offset;
        }

        memcpy(out + offset, slice, slice_len);
    }

    secure_memzero(prk, sizeof(prk));
    secure_memzero(slice, sizeof(slice));
    secure_memzero(&state, sizeof(state));

    return COSE_OK;
}