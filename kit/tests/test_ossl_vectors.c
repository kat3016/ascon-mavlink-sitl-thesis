/*
 * Validates the OpenSSL backend (mavcrypt_ossl.c) against the published
 * test vectors for each algorithm, independently of the MAVLink framing:
 *
 *   AES-128-GCM: Test Case 4 of "The Galois/Counter Mode of Operation (GCM)"
 *     (McGrew & Viega, the specification NIST SP 800-38D is based on),
 *     verified against the PDF text (K/P/A/IV/C/T) by this project.
 *   ChaCha20-Poly1305: RFC 8439 Section 2.8.2 (AEAD_CHACHA20_POLY1305).
 *
 * Build with -DAP_MAVCRYPT_ALG=2 (aesgcm) or -DAP_MAVCRYPT_ALG=3 (chacha),
 * -DAP_MAVCRYPT_ENABLED=1, linked against mavcrypt_ossl.c and -lcrypto.
 */
#include "mavcrypt_core.h"

#include <stdio.h>
#include <string.h>

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec, const unsigned char *npub,
                        const unsigned char *k);
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec, const unsigned char *c,
                        unsigned long long clen, const unsigned char *ad,
                        unsigned long long adlen, const unsigned char *npub,
                        const unsigned char *k);

static int from_hex(const char *s, uint8_t *out)
{
    int n = 0;
    while (s[2 * n] && s[2 * n + 1]) {
        unsigned v;
        if (sscanf(s + 2 * n, "%2x", &v) != 1) {
            return -1;
        }
        out[n++] = (uint8_t)v;
    }
    return n;
}

#if AP_MAVCRYPT_ALG == MC_ALG_AESGCM
/* Test Case 4, AES-128-GCM, 96-bit IV, with AAD. */
#define T_KEY  "feffe9928665731c6d6a8f9467308308"
#define T_IV   "cafebabefacedbaddecaf888"
#define T_AAD  "feedfacedeadbeeffeedfacedeadbeefabaddad2"
#define T_PT   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a7" \
               "21c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
#define T_CT   "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12" \
               "e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
#define T_TAG  "5bc94fbc3221a5db94fae95ae7121a47"
#define T_NAME "AES-128-GCM / GCM spec Test Case 4"
#elif AP_MAVCRYPT_ALG == MC_ALG_CHACHA
/* RFC 8439 Section 2.8.2 */
#define T_KEY  "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
#define T_IV   "070000004041424344454647"
#define T_AAD  "50515253c0c1c2c3c4c5c6c7"
#define T_PT   "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" \
               "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" \
               "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" \
               "637265656e20776f756c642062652069742e"
#define T_CT   "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d" \
               "63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b" \
               "3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d" \
               "7bc3ff4def08e4b7a9de576d26586cec64b6116"
#define T_TAG  "1ae10b594f09e26a7e902ecbd0600691"
#define T_NAME "ChaCha20-Poly1305 / RFC 8439 2.8.2"
#else
#error "test_ossl_vectors.c only covers AP_MAVCRYPT_ALG 2 (aesgcm) and 3 (chacha)"
#endif

int main(void)
{
    uint8_t key[64], iv[16], aad[64], pt[256], ct_expect[256], tag_expect[16];
    const int klen = from_hex(T_KEY, key);
    const int ivlen = from_hex(T_IV, iv);
    const int aadlen = from_hex(T_AAD, aad);
    const int ptlen = from_hex(T_PT, pt);
    const int ctlen = from_hex(T_CT, ct_expect);
    from_hex(T_TAG, tag_expect);
    if (klen != MC_KEY_LEN || ivlen != MC_NONCE_LEN || ctlen != ptlen) {
        printf("[FAIL] %s: malformed test vector (klen=%d ivlen=%d)\n", T_NAME, klen, ivlen);
        return 1;
    }

    uint8_t ct[256 + 16];
    unsigned long long clen = 0;
    if (crypto_aead_encrypt(ct, &clen, pt, (unsigned long long)ptlen, aad,
                            (unsigned long long)aadlen, NULL, iv, key) != 0) {
        printf("[FAIL] %s: encrypt returned an error\n", T_NAME);
        return 1;
    }
    int ok = 1;
    if ((int)clen != ptlen + MC_TAG_LEN) {
        printf("[FAIL] %s: ciphertext length %llu, expected %d\n", T_NAME, clen, ptlen + MC_TAG_LEN);
        ok = 0;
    }
    if (ok && memcmp(ct, ct_expect, (size_t)ptlen) != 0) {
        printf("[FAIL] %s: ciphertext does not match the published vector\n", T_NAME);
        ok = 0;
    }
    if (ok && memcmp(ct + ptlen, tag_expect, MC_TAG_LEN) != 0) {
        printf("[FAIL] %s: tag does not match the published vector\n", T_NAME);
        ok = 0;
    }

    uint8_t pt_out[256];
    unsigned long long mlen = 0;
    if (ok && crypto_aead_decrypt(pt_out, &mlen, NULL, ct, clen, aad,
                                  (unsigned long long)aadlen, iv, key) != 0) {
        printf("[FAIL] %s: decrypt rejected the valid tag\n", T_NAME);
        ok = 0;
    }
    if (ok && ((int)mlen != ptlen || memcmp(pt_out, pt, (size_t)ptlen) != 0)) {
        printf("[FAIL] %s: decrypted plaintext does not match\n", T_NAME);
        ok = 0;
    }

    /* tamper test: flipping one tag bit must be rejected */
    uint8_t ct_bad[256 + 16];
    memcpy(ct_bad, ct, (size_t)clen);
    ct_bad[clen - 1] ^= 0x01;
    uint8_t pt_scratch[256];
    unsigned long long mlen2 = 0;
    if (ok && crypto_aead_decrypt(pt_scratch, &mlen2, NULL, ct_bad, clen, aad,
                                  (unsigned long long)aadlen, iv, key) == 0) {
        printf("[FAIL] %s: decrypt accepted a tampered tag\n", T_NAME);
        ok = 0;
    }

    if (ok) {
        printf("[PASS] %s: ciphertext, tag, decrypt and tamper rejection all match\n", T_NAME);
        return 0;
    }
    return 1;
}
