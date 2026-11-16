/*
 * mavcrypt_core.h - Ascon-AEAD128 protection of MAVLink frames.
 *
 * Shared by the ArduPilot module (drone), the PC tools and the Python
 * proxy (through ctypes). Plain C99, no dynamic memory.
 *
 * Protected frame (fixed 32-byte overhead):
 *
 *   | MAVLink header (clear, authenticated as AD) | E(payload || CRC [|| signature]) | nonce 16 B | tag 16 B |
 *
 *   header = 10 B for MAVLink v2 (STX 0xFD), 6 B for MAVLink v1 (STX 0xFE).
 *   nonce  = prefix (8 B, random per boot, MSB of byte 0 = sender role)
 *            || counter (8 B, big endian, strictly increasing).
 *
 * The receiver can delimit a protected frame from the clear header alone
 * (STX, LEN and, for v2, the signing flag), so frames can be recovered from a
 * byte stream (UART/UDP buffers) without any extra length field.
 */
#ifndef MAVCRYPT_CORE_H_
#define MAVCRYPT_CORE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Algorithm selection (compile-time, e.g. ./waf configure --define AP_MAVCRYPT_ALG=2):
 *   1 = Ascon-AEAD128 (mavcrypt_ascon.c)      16 B key, 8 B prefix, 16 B nonce -> +32 B/frame
 *   2 = AES-128-GCM   (mavcrypt_ossl.c)       16 B key, 4 B prefix, 12 B nonce -> +28 B/frame
 *   3 = ChaCha20-Poly1305 (mavcrypt_ossl.c)   32 B key, 4 B prefix, 12 B nonce -> +28 B/frame
 * The nonce is always prefix || 64-bit big-endian counter; AES-GCM and ChaCha20
 * use a shorter random prefix (4 B) so the nonce stays at the standard 96 bits.
 */
#define MC_ALG_ASCON 1
#define MC_ALG_AESGCM 2
#define MC_ALG_CHACHA 3

#ifndef AP_MAVCRYPT_ALG
#define AP_MAVCRYPT_ALG MC_ALG_ASCON
#endif

#if AP_MAVCRYPT_ALG == MC_ALG_ASCON
#define MC_KEY_LEN 16
#define MC_PREFIX_LEN 8
#define MC_NONCE_LEN 16
#elif AP_MAVCRYPT_ALG == MC_ALG_AESGCM
#define MC_KEY_LEN 16
#define MC_PREFIX_LEN 4
#define MC_NONCE_LEN 12
#elif AP_MAVCRYPT_ALG == MC_ALG_CHACHA
#define MC_KEY_LEN 32
#define MC_PREFIX_LEN 4
#define MC_NONCE_LEN 12
#else
#error "AP_MAVCRYPT_ALG must be MC_ALG_ASCON (1), MC_ALG_AESGCM (2) or MC_ALG_CHACHA (3)"
#endif

#define MC_TAG_LEN 16
#define MC_OVERHEAD (MC_NONCE_LEN + MC_TAG_LEN)          /* 32 (ascon) or 28 (aesgcm/chacha) */
#define MC_MAX_PLAIN_FRAME (10 + 255 + 2 + 13)           /* 280: v2 + signature */
#define MC_MAX_FRAME (MC_MAX_PLAIN_FRAME + MC_OVERHEAD)  /* 312 */

#define MC_STX_V1 0xFE
#define MC_STX_V2 0xFD

#define MC_ROLE_DRONE 0
#define MC_ROLE_GCS 1

/* error codes returned by mc_seal / mc_open */
#define MC_ERR_MALFORMED (-1)
#define MC_ERR_AUTH (-2)
#define MC_ERR_REPLAY (-3)
#define MC_ERR_DIRECTION (-4)

typedef struct {
    uint8_t key[MC_KEY_LEN];
    uint8_t prefix[MC_PREFIX_LEN];
    uint64_t counter; /* last counter used; first frame uses 1 */
} mc_tx_t;

typedef struct {
    uint8_t key[MC_KEY_LEN];
    uint8_t role; /* own role; frames from the same role are rejected */
    /* anti-replay state (sliding window of 64 counters per sender session) */
    uint8_t have_peer;
    uint8_t peer_prefix[MC_PREFIX_LEN];
    uint64_t highest;
    uint64_t window;
    /* stream parser */
    uint8_t buf[MC_MAX_FRAME];
    uint16_t len;
    uint16_t need; /* total protected length once known, 0 = unknown */
    /* counters */
    uint32_t ok;
    uint32_t auth_fail;
    uint32_t replay;
    uint32_t bad_dir;
    uint32_t skipped; /* bytes discarded while searching for STX */
} mc_rx_t;

/* Header length (6 or 10) for a frame starting with stx, 0 if not an STX. */
int mc_header_len(uint8_t stx);

/* Length of the clear MAVLink frame described by hdr (needs 3 bytes),
 * 0 if hdr[0] is not an STX. */
int mc_plain_len(const uint8_t *hdr);

void mc_tx_init(mc_tx_t *tx, const uint8_t key[MC_KEY_LEN],
                const uint8_t random_prefix[MC_PREFIX_LEN], uint8_t role);

/* Protect one complete clear MAVLink frame. out must hold len + MC_OVERHEAD.
 * Returns the protected length or MC_ERR_MALFORMED. */
int mc_seal(mc_tx_t *tx, const uint8_t *frame, uint16_t len, uint8_t *out);

/* Same as mc_seal but with an explicit counter (tests / cross-checks). */
int mc_seal_with_counter(mc_tx_t *tx, uint64_t counter, const uint8_t *frame,
                         uint16_t len, uint8_t *out);

void mc_rx_init(mc_rx_t *rx, const uint8_t key[MC_KEY_LEN], uint8_t role);

/* Verify and decrypt one complete protected frame. out must hold len.
 * Returns the clear frame length or a negative MC_ERR_* code. The anti-replay
 * state is only updated when the tag is valid. */
int mc_open(mc_rx_t *rx, const uint8_t *in, uint16_t len, uint8_t *out);

/* Stream interface: push one received byte. When a protected frame is
 * complete and valid, its clear frame is written to out (MC_MAX_PLAIN_FRAME
 * bytes) and its length returned; otherwise returns 0. */
uint16_t mc_rx_push(mc_rx_t *rx, uint8_t c, uint8_t *out);

/* Return the next complete valid frame already buffered (without adding a
 * byte), or 0. Call it after every successful mc_rx_push until it returns 0. */
uint16_t mc_rx_poll(mc_rx_t *rx, uint8_t *out);

/* Feed a whole buffer (e.g. one UDP datagram). Clear frames are appended to
 * out (capacity out_cap); *out_len receives the bytes written. Returns the
 * number of valid frames recovered. */
int mc_rx_feed(mc_rx_t *rx, const uint8_t *in, uint32_t len, uint8_t *out,
               uint32_t out_cap, uint32_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* MAVCRYPT_CORE_H_ */
