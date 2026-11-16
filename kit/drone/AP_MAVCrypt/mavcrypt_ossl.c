/*
 * AES-128-GCM and ChaCha20-Poly1305 backend for mavcrypt_core.c, selected at
 * compile time with AP_MAVCRYPT_ALG=2 (aesgcm) or AP_MAVCRYPT_ALG=3 (chacha).
 * Implements the same two-function NIST LWC API that mavcrypt_ascon.c
 * provides for Ascon-AEAD128, so mavcrypt_core.c (the framing, nonce and
 * anti-replay logic) does not change with the algorithm.
 *
 * One EVP_CIPHER_CTX is created per direction (encrypt/decrypt) and reused
 * across frames: only the 12-byte nonce changes per EVP_EncryptInit_ex /
 * EVP_DecryptInit_ex call. Creating and destroying a context per frame would
 * also measure malloc/free and the AES key schedule, and would penalise
 * AES-GCM relative to Ascon for reasons unrelated to the cipher itself
 * (see kit/README.md and thesis Section "Comparison schemes").
 */
#include "mavcrypt_core.h"

#if defined(AP_MAVCRYPT_ENABLED) && AP_MAVCRYPT_ENABLED && \
    (AP_MAVCRYPT_ALG == MC_ALG_AESGCM || AP_MAVCRYPT_ALG == MC_ALG_CHACHA)

#include <openssl/evp.h>
#include <string.h>

#if AP_MAVCRYPT_ALG == MC_ALG_AESGCM
static const EVP_CIPHER *mc_cipher(void) { return EVP_aes_128_gcm(); }
#else
static const EVP_CIPHER *mc_cipher(void) { return EVP_chacha20_poly1305(); }
#endif

typedef struct {
    EVP_CIPHER_CTX *ctx;
    uint8_t key[MC_KEY_LEN];
    int have_key;
} mc_ossl_dir_t;

static mc_ossl_dir_t enc_dir;
static mc_ossl_dir_t dec_dir;

/* (Re)key a direction's context only when the key actually changes, so the
 * common case -- same key, new nonce every frame -- pays no re-keying cost.
 * Key and nonce are set together in the call that (re)keys, and the nonce
 * alone in every other call: OpenSSL's AEAD ciphers (chacha20-poly1305 in
 * particular) were found not to produce the right tag when the key and the
 * first nonce were set in two separate EVP_*Init_ex calls. */
static EVP_CIPHER_CTX *mc_dir_ctx(mc_ossl_dir_t *d, const unsigned char *k,
                                  const unsigned char *iv, int for_encrypt)
{
    const int rekey = !(d->ctx != NULL && d->have_key && memcmp(d->key, k, MC_KEY_LEN) == 0);
    if (d->ctx == NULL) {
        d->ctx = EVP_CIPHER_CTX_new();
        if (d->ctx == NULL) {
            return NULL;
        }
    }
    if (!rekey) {
        /* only the nonce changes */
        if (for_encrypt) {
            return EVP_EncryptInit_ex(d->ctx, NULL, NULL, NULL, iv) == 1 ? d->ctx : NULL;
        }
        return EVP_DecryptInit_ex(d->ctx, NULL, NULL, NULL, iv) == 1 ? d->ctx : NULL;
    }
    if (for_encrypt) {
        if (EVP_EncryptInit_ex(d->ctx, mc_cipher(), NULL, NULL, NULL) != 1) {
            return NULL;
        }
    } else {
        if (EVP_DecryptInit_ex(d->ctx, mc_cipher(), NULL, NULL, NULL) != 1) {
            return NULL;
        }
    }
#if AP_MAVCRYPT_ALG == MC_ALG_AESGCM
    if (EVP_CIPHER_CTX_ctrl(d->ctx, EVP_CTRL_AEAD_SET_IVLEN, MC_NONCE_LEN, NULL) != 1) {
        return NULL;
    }
#endif
    if (for_encrypt) {
        if (EVP_EncryptInit_ex(d->ctx, NULL, NULL, k, iv) != 1) {
            return NULL;
        }
    } else {
        if (EVP_DecryptInit_ex(d->ctx, NULL, NULL, k, iv) != 1) {
            return NULL;
        }
    }
    memcpy(d->key, k, MC_KEY_LEN);
    d->have_key = 1;
    return d->ctx;
}

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec, const unsigned char *npub,
                        const unsigned char *k)
{
    (void)nsec;
    EVP_CIPHER_CTX *ctx = mc_dir_ctx(&enc_dir, k, npub, 1);
    if (ctx == NULL) {
        return -1;
    }
    int len = 0;
    if (adlen > 0 && EVP_EncryptUpdate(ctx, NULL, &len, ad, (int)adlen) != 1) {
        return -1;
    }
    if (EVP_EncryptUpdate(ctx, c, &len, m, (int)mlen) != 1) {
        return -1;
    }
    int outl = len;
    if (EVP_EncryptFinal_ex(ctx, c + outl, &len) != 1) {
        return -1;
    }
    outl += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, MC_TAG_LEN, c + outl) != 1) {
        return -1;
    }
    *clen = (unsigned long long)outl + MC_TAG_LEN;
    return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec, const unsigned char *c,
                        unsigned long long clen, const unsigned char *ad,
                        unsigned long long adlen, const unsigned char *npub,
                        const unsigned char *k)
{
    (void)nsec;
    if (clen < MC_TAG_LEN) {
        return -1;
    }
    const unsigned long long ctlen = clen - MC_TAG_LEN;
    EVP_CIPHER_CTX *ctx = mc_dir_ctx(&dec_dir, k, npub, 0);
    if (ctx == NULL) {
        return -1;
    }
    int len = 0;
    if (adlen > 0 && EVP_DecryptUpdate(ctx, NULL, &len, ad, (int)adlen) != 1) {
        return -1;
    }
    if (EVP_DecryptUpdate(ctx, m, &len, c, (int)ctlen) != 1) {
        return -1;
    }
    int outl = len;
    /* OpenSSL requires the expected tag to be set before EVP_*Final_ex */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, MC_TAG_LEN, (void *)(c + ctlen)) != 1) {
        return -1;
    }
    if (EVP_DecryptFinal_ex(ctx, m + outl, &len) <= 0) {
        return -1;  /* tag did not verify: do not release this plaintext */
    }
    outl += len;
    *mlen = (unsigned long long)outl;
    return 0;
}

#endif  /* AP_MAVCRYPT_ENABLED && (AESGCM || CHACHA) */
