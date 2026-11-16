/*
 * mavcrypt_core.c - see mavcrypt_core.h for the frame format.
 *
 * The AEAD itself is the NIST LWC API of ascon-c (crypto_aead_asconaead128,
 * SP 800-232 Ascon-AEAD128); it is linked separately (opt32 variant).
 */
#include "mavcrypt_core.h"

#include <string.h>

/* NIST LWC API implemented by ascon-c (asconaead128) */
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

int mc_header_len(uint8_t stx)
{
    if (stx == MC_STX_V2) {
        return 10;
    }
    if (stx == MC_STX_V1) {
        return 6;
    }
    return 0;
}

int mc_plain_len(const uint8_t *hdr)
{
    if (hdr[0] == MC_STX_V2) {
        const int sig = (hdr[2] & 0x01) ? 13 : 0; /* MAVLINK_IFLAG_SIGNED */
        return 10 + hdr[1] + 2 + sig;
    }
    if (hdr[0] == MC_STX_V1) {
        return 6 + hdr[1] + 2;
    }
    return 0;
}

static void put_be64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

static uint64_t get_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

void mc_tx_init(mc_tx_t *tx, const uint8_t key[MC_KEY_LEN],
                const uint8_t random_prefix[MC_PREFIX_LEN], uint8_t role)
{
    memcpy(tx->key, key, MC_KEY_LEN);
    memcpy(tx->prefix, random_prefix, MC_PREFIX_LEN);
    /* top bit of the prefix carries the sender role, so the two directions
       can never produce the same nonce and reflected frames are rejected */
    tx->prefix[0] = (uint8_t)((tx->prefix[0] & 0x7F) | ((role & 1) << 7));
    tx->counter = 0;
}

int mc_seal_with_counter(mc_tx_t *tx, uint64_t counter, const uint8_t *frame,
                         uint16_t len, uint8_t *out)
{
    if (len < 3) {
        return MC_ERR_MALFORMED;
    }
    const int hlen = mc_header_len(frame[0]);
    if (hlen == 0 || mc_plain_len(frame) != (int)len) {
        return MC_ERR_MALFORMED;
    }
    uint8_t nonce[MC_NONCE_LEN];
    memcpy(nonce, tx->prefix, MC_PREFIX_LEN);
    put_be64(nonce + MC_PREFIX_LEN, counter);

    const uint16_t mlen = (uint16_t)(len - hlen);
    uint8_t ct[MC_MAX_PLAIN_FRAME + MC_TAG_LEN]; /* ciphertext || tag */
    unsigned long long clen = 0;
    crypto_aead_encrypt(ct, &clen, frame + hlen, mlen, frame, (unsigned long long)hlen,
                        NULL, nonce, tx->key);

    memcpy(out, frame, (size_t)hlen);                         /* clear header */
    memcpy(out + hlen, ct, mlen);                             /* ciphertext   */
    memcpy(out + hlen + mlen, nonce, MC_NONCE_LEN);           /* nonce        */
    memcpy(out + hlen + mlen + MC_NONCE_LEN, ct + mlen, MC_TAG_LEN); /* tag  */
    return len + MC_OVERHEAD;
}

int mc_seal(mc_tx_t *tx, const uint8_t *frame, uint16_t len, uint8_t *out)
{
    const int ret = mc_seal_with_counter(tx, tx->counter + 1, frame, len, out);
    if (ret > 0) {
        tx->counter++;
    }
    return ret;
}

void mc_rx_init(mc_rx_t *rx, const uint8_t key[MC_KEY_LEN], uint8_t role)
{
    memset(rx, 0, sizeof(*rx));
    memcpy(rx->key, key, MC_KEY_LEN);
    rx->role = role & 1;
}

/* 0 = acceptable, 1 = replayed or too old */
static int replay_check(const mc_rx_t *rx, const uint8_t *prefix, uint64_t ctr)
{
    if (!rx->have_peer || memcmp(prefix, rx->peer_prefix, MC_PREFIX_LEN) != 0) {
        return 0; /* new sender session (see README: known limitation) */
    }
    if (ctr > rx->highest) {
        return 0;
    }
    const uint64_t diff = rx->highest - ctr;
    if (diff >= 64) {
        return 1;
    }
    return (rx->window >> diff) & 1 ? 1 : 0;
}

static void replay_update(mc_rx_t *rx, const uint8_t *prefix, uint64_t ctr)
{
    if (!rx->have_peer || memcmp(prefix, rx->peer_prefix, MC_PREFIX_LEN) != 0) {
        memcpy(rx->peer_prefix, prefix, MC_PREFIX_LEN);
        rx->have_peer = 1;
        rx->highest = ctr;
        rx->window = 1;
        return;
    }
    if (ctr > rx->highest) {
        const uint64_t shift = ctr - rx->highest;
        rx->window = (shift >= 64) ? 1 : ((rx->window << shift) | 1);
        rx->highest = ctr;
    } else {
        rx->window |= ((uint64_t)1) << (rx->highest - ctr);
    }
}

int mc_open(mc_rx_t *rx, const uint8_t *in, uint16_t len, uint8_t *out)
{
    if (len < 3 + MC_OVERHEAD) {
        return MC_ERR_MALFORMED;
    }
    const int hlen = mc_header_len(in[0]);
    if (hlen == 0 || mc_plain_len(in) + MC_OVERHEAD != (int)len) {
        return MC_ERR_MALFORMED;
    }
    const uint16_t mlen = (uint16_t)(len - MC_OVERHEAD - hlen);
    const uint8_t *nonce = in + hlen + mlen;
    const uint8_t *tag = nonce + MC_NONCE_LEN;

    uint8_t ct[MC_MAX_PLAIN_FRAME + MC_TAG_LEN];
    memcpy(ct, in + hlen, mlen);
    memcpy(ct + mlen, tag, MC_TAG_LEN);

    unsigned long long plen = 0;
    if (crypto_aead_decrypt(out + hlen, &plen, NULL, ct, (unsigned long long)mlen + MC_TAG_LEN,
                            in, (unsigned long long)hlen, nonce, rx->key) != 0) {
        rx->auth_fail++;
        return MC_ERR_AUTH;
    }
    /* nonce is authenticated: classify only genuine frames */
    if (((nonce[0] >> 7) & 1) == rx->role) {
        rx->bad_dir++;
        return MC_ERR_DIRECTION;
    }
    const uint64_t ctr = get_be64(nonce + MC_PREFIX_LEN);
    if (replay_check(rx, nonce, ctr)) {
        rx->replay++;
        return MC_ERR_REPLAY;
    }
    replay_update(rx, nonce, ctr);
    memcpy(out, in, (size_t)hlen);
    rx->ok++;
    return hlen + (int)plen;
}

/* drop the first buffered byte and look for the next STX */
static void rx_resync(mc_rx_t *rx)
{
    uint16_t i = 1;
    while (i < rx->len && mc_header_len(rx->buf[i]) == 0) {
        i++;
    }
    rx->skipped += i;
    memmove(rx->buf, rx->buf + i, (size_t)(rx->len - i));
    rx->len = (uint16_t)(rx->len - i);
    rx->need = 0;
}

uint16_t mc_rx_poll(mc_rx_t *rx, uint8_t *out)
{
    /* loop because a resync may leave an already complete frame */
    for (;;) {
        if (rx->len == 0) {
            return 0;
        }
        if (rx->need == 0 && rx->len >= 3) {
            rx->need = (uint16_t)(mc_plain_len(rx->buf) + MC_OVERHEAD);
        }
        if (rx->need == 0 || rx->len < rx->need) {
            return 0;
        }
        const int r = mc_open(rx, rx->buf, rx->need, out);
        if (r > 0 || r == MC_ERR_REPLAY || r == MC_ERR_DIRECTION) {
            /* authentic frame (accepted or not): consume it whole */
            const uint16_t used = rx->need;
            memmove(rx->buf, rx->buf + used, (size_t)(rx->len - used));
            rx->len = (uint16_t)(rx->len - used);
            rx->need = 0;
            if (r > 0) {
                return (uint16_t)r;
            }
            continue;
        }
        rx_resync(rx);
    }
}

uint16_t mc_rx_push(mc_rx_t *rx, uint8_t c, uint8_t *out)
{
    if (rx->len == 0 && mc_header_len(c) == 0) {
        rx->skipped++;
        return 0;
    }
    rx->buf[rx->len++] = c;
    return mc_rx_poll(rx, out);
}

int mc_rx_feed(mc_rx_t *rx, const uint8_t *in, uint32_t len, uint8_t *out,
               uint32_t out_cap, uint32_t *out_len)
{
    uint8_t frame[MC_MAX_PLAIN_FRAME];
    int frames = 0;
    uint32_t pos = 0;
    for (uint32_t i = 0; i < len; i++) {
        uint16_t n = mc_rx_push(rx, in[i], frame);
        while (n > 0) {
            frames++;
            if (pos + n <= out_cap) {
                memcpy(out + pos, frame, n);
                pos += n;
            }
            n = mc_rx_poll(rx, frame);
        }
    }
    *out_len = pos;
    return frames;
}
