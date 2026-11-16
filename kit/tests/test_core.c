/*
 * Unit tests for mavcrypt_core (runs on the PC and, through qemu-arm, as an
 * ARM binary). Exit code 0 only if every check passes.
 */
#include <stdio.h>
#include <string.h>

#include "mavcrypt_core.h"

static int checks = 0;
static int failures = 0;

#define CHECK(cond, ...)                         \
    do {                                         \
        checks++;                                \
        if (!(cond)) {                           \
            failures++;                          \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
            printf(__VA_ARGS__);                 \
            printf("\n");                        \
        }                                        \
    } while (0)

static const uint8_t KEY[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const uint8_t KEY2[16] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const uint8_t PREFIX_A[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
static const uint8_t PREFIX_B[8] = {0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0x01};

/* build a syntactically valid MAVLink frame (CRC bytes are arbitrary: the
   core does not check the MAVLink CRC, the MAVLink parser does) */
static uint16_t make_frame(uint8_t *f, int v2, uint8_t plen, int signed_frame, uint8_t seed)
{
    uint16_t n = 0;
    if (v2) {
        f[n++] = MC_STX_V2;
        f[n++] = plen;
        f[n++] = signed_frame ? 0x01 : 0x00; /* incompat flags */
        f[n++] = 0x00;                       /* compat flags   */
        f[n++] = seed;                       /* seq            */
        f[n++] = 1;                          /* sysid          */
        f[n++] = 1;                          /* compid         */
        f[n++] = 33; f[n++] = 0; f[n++] = 0; /* msgid 24 bit   */
    } else {
        f[n++] = MC_STX_V1;
        f[n++] = plen;
        f[n++] = seed;
        f[n++] = 1;
        f[n++] = 1;
        f[n++] = 33;
    }
    for (int i = 0; i < plen; i++) {
        f[n++] = (uint8_t)(i * 7 + seed);
    }
    f[n++] = 0xAB;
    f[n++] = 0xCD;
    if (v2 && signed_frame) {
        for (int i = 0; i < 13; i++) {
            f[n++] = (uint8_t)(0x50 + i);
        }
    }
    return n;
}

static void test_roundtrip(void)
{
    printf("[test] roundtrip v1/v2/signed, payload 0..255\n");
    mc_tx_t tx;
    mc_rx_t rx;
    mc_tx_init(&tx, KEY, PREFIX_A, MC_ROLE_DRONE);
    mc_rx_init(&rx, KEY, MC_ROLE_GCS);
    int bad = 0;
    for (int variant = 0; variant < 3; variant++) {
        const int v2 = variant > 0;
        const int sig = variant == 2;
        for (int plen = 0; plen <= 255; plen++) {
            uint8_t f[MC_MAX_PLAIN_FRAME], p[MC_MAX_FRAME], o[MC_MAX_FRAME];
            const uint16_t n = make_frame(f, v2, (uint8_t)plen, sig, (uint8_t)plen);
            const int pn = mc_seal(&tx, f, n, p);
            if (pn != n + MC_OVERHEAD) { bad++; continue; }
            const int hl = v2 ? 10 : 6;
            if (memcmp(p, f, (size_t)hl) != 0) { bad++; continue; }       /* header in clear */
            if (n - hl > 4 && memcmp(p + hl, f + hl, (size_t)(n - hl)) == 0) { bad++; continue; }
            const int on = mc_open(&rx, p, (uint16_t)pn, o);
            if (on != n || memcmp(o, f, n) != 0) { bad++; }
        }
    }
    CHECK(bad == 0, "%d roundtrip failures", bad);
    CHECK(rx.ok == 3 * 256, "rx.ok=%u", rx.ok);
    CHECK(tx.counter == 3 * 256, "counter=%llu", (unsigned long long)tx.counter);
}

static void test_tamper(void)
{
    printf("[test] tampering of header, ciphertext, nonce and tag is detected\n");
    mc_tx_t tx;
    mc_rx_t rx;
    mc_tx_init(&tx, KEY, PREFIX_A, MC_ROLE_DRONE);
    mc_rx_init(&rx, KEY, MC_ROLE_GCS);
    uint8_t f[MC_MAX_PLAIN_FRAME], p[MC_MAX_FRAME], o[MC_MAX_FRAME];
    const uint16_t n = make_frame(f, 1, 36, 0, 5);
    const int pn = mc_seal(&tx, f, n, p);
    int detected = 0, total = 0;
    for (int i = 0; i < pn; i++) {
        if (i == 0 || i == 1 || i == 2) {
            continue; /* STX/LEN/flags change the framing: covered as malformed */
        }
        for (int bit = 0; bit < 8; bit++) {
            uint8_t q[MC_MAX_FRAME];
            memcpy(q, p, (size_t)pn);
            q[i] ^= (uint8_t)(1u << bit);
            total++;
            if (mc_open(&rx, q, (uint16_t)pn, o) == MC_ERR_AUTH) {
                detected++;
            }
        }
    }
    CHECK(detected == total, "detected %d/%d single-bit flips", detected, total);
    CHECK(rx.ok == 0, "no tampered frame accepted");
    /* LEN byte changed: length no longer matches -> malformed */
    uint8_t q[MC_MAX_FRAME];
    memcpy(q, p, (size_t)pn);
    q[1] ^= 1;
    CHECK(mc_open(&rx, q, (uint16_t)pn, o) == MC_ERR_MALFORMED, "len flip");
    /* the original still opens */
    CHECK(mc_open(&rx, p, (uint16_t)pn, o) == n, "original still valid");
}

static void test_wrong_key(void)
{
    printf("[test] wrong key is rejected\n");
    mc_tx_t tx;
    mc_rx_t rx;
    mc_tx_init(&tx, KEY, PREFIX_A, MC_ROLE_DRONE);
    mc_rx_init(&rx, KEY2, MC_ROLE_GCS);
    uint8_t f[MC_MAX_PLAIN_FRAME], p[MC_MAX_FRAME], o[MC_MAX_FRAME];
    const uint16_t n = make_frame(f, 1, 20, 0, 1);
    const int pn = mc_seal(&tx, f, n, p);
    CHECK(mc_open(&rx, p, (uint16_t)pn, o) == MC_ERR_AUTH, "wrong key accepted");
    CHECK(rx.auth_fail == 1, "auth_fail=%u", rx.auth_fail);
}

static void test_replay(void)
{
    printf("[test] replay window\n");
    mc_tx_t tx;
    mc_rx_t rx;
    mc_tx_init(&tx, KEY, PREFIX_A, MC_ROLE_GCS);
    mc_rx_init(&rx, KEY, MC_ROLE_DRONE);
    uint8_t f[MC_MAX_PLAIN_FRAME], o[MC_MAX_FRAME];
    static uint8_t p[200][MC_MAX_FRAME];
    int pn[200];
    const uint16_t n = make_frame(f, 1, 9, 0, 3);
    for (int i = 0; i < 200; i++) {
        pn[i] = mc_seal(&tx, f, n, p[i]); /* counters 1..200 */
    }
    CHECK(mc_open(&rx, p[10], (uint16_t)pn[10], o) == n, "first frame");
    CHECK(mc_open(&rx, p[10], (uint16_t)pn[10], o) == MC_ERR_REPLAY, "exact replay");
    CHECK(mc_open(&rx, p[5], (uint16_t)pn[5], o) == n, "older but inside window, unseen");
    CHECK(mc_open(&rx, p[5], (uint16_t)pn[5], o) == MC_ERR_REPLAY, "replay inside window");
    CHECK(mc_open(&rx, p[150], (uint16_t)pn[150], o) == n, "jump forward");
    CHECK(mc_open(&rx, p[50], (uint16_t)pn[50], o) == MC_ERR_REPLAY, "too old (diff >= 64)");
    CHECK(mc_open(&rx, p[120], (uint16_t)pn[120], o) == n, "inside window after jump");
    CHECK(rx.replay == 3, "replay counter=%u", rx.replay);

    /* new sender session (different prefix, e.g. rebooted peer) */
    mc_tx_t tx2;
    mc_tx_init(&tx2, KEY, PREFIX_B, MC_ROLE_GCS);
    uint8_t q[MC_MAX_FRAME];
    const int qn = mc_seal(&tx2, f, n, q);
    CHECK(mc_open(&rx, q, (uint16_t)qn, o) == n, "new session accepted");
    CHECK(mc_open(&rx, q, (uint16_t)qn, o) == MC_ERR_REPLAY, "new session replay");
}

static void test_direction(void)
{
    printf("[test] reflected frames (same role) are rejected\n");
    mc_tx_t tx;
    mc_rx_t rx;
    mc_tx_init(&tx, KEY, PREFIX_A, MC_ROLE_DRONE);
    mc_rx_init(&rx, KEY, MC_ROLE_DRONE);
    uint8_t f[MC_MAX_PLAIN_FRAME], p[MC_MAX_FRAME], o[MC_MAX_FRAME];
    const uint16_t n = make_frame(f, 1, 12, 0, 2);
    const int pn = mc_seal(&tx, f, n, p);
    CHECK(mc_open(&rx, p, (uint16_t)pn, o) == MC_ERR_DIRECTION, "reflection accepted");
    /* nonces of both roles differ even with identical random prefix */
    mc_tx_t a, b;
    mc_tx_init(&a, KEY, PREFIX_A, MC_ROLE_DRONE);
    mc_tx_init(&b, KEY, PREFIX_A, MC_ROLE_GCS);
    CHECK(a.prefix[0] != b.prefix[0], "role bit separates nonces");
}

static void test_stream(void)
{
    printf("[test] stream parser: garbage, split frames, tampered frame in the middle\n");
    mc_tx_t tx;
    mc_rx_t rx;
    mc_tx_init(&tx, KEY, PREFIX_A, MC_ROLE_DRONE);
    mc_rx_init(&rx, KEY, MC_ROLE_GCS);
    static uint8_t stream[20000];
    uint32_t sl = 0;
    int expected = 0;
    uint8_t f[MC_MAX_PLAIN_FRAME], p[MC_MAX_FRAME];
    for (int i = 0; i < 40; i++) {
        /* garbage, including fake STX bytes */
        stream[sl++] = 0x00;
        stream[sl++] = (i % 3 == 0) ? MC_STX_V2 : 0x42;
        const uint16_t n = make_frame(f, i % 4 != 0, (uint8_t)(i * 6), i % 5 == 0, (uint8_t)i);
        const int pn = mc_seal(&tx, f, n, p);
        if (i == 17) {
            p[pn - 1] ^= 0x80; /* corrupt tag */
        } else {
            expected++;
        }
        memcpy(stream + sl, p, (size_t)pn);
        sl += (uint32_t)pn;
    }
    /* A fake STX in the garbage makes the parser wait for up to 312 bytes
       before it can reject the candidate and resynchronise (exactly like the
       MAVLink parser). Trailing idle bytes stand for the traffic that follows
       in a real link, so the last frame is not stuck at the end of the test. */
    for (int i = 0; i < MC_MAX_FRAME; i++) {
        stream[sl++] = 0x00;
    }
    uint8_t o[MC_MAX_PLAIN_FRAME];
    int got = 0;
    for (uint32_t i = 0; i < sl; i++) {
        uint16_t n = mc_rx_push(&rx, stream[i], o);
        while (n > 0) {
            got++;
            n = mc_rx_poll(&rx, o);
        }
    }
    CHECK(got == expected, "recovered %d of %d frames", got, expected);
    CHECK(rx.auth_fail >= 1, "tampered frame counted (auth_fail=%u)", rx.auth_fail);

    /* mc_rx_feed over arbitrary chunks gives the same result */
    mc_rx_t rx2;
    mc_rx_init(&rx2, KEY, MC_ROLE_GCS);
    static uint8_t out[40000];
    int frames = 0;
    for (uint32_t pos = 0; pos < sl;) {
        uint32_t chunk = 1 + (pos * 31) % 97;
        if (pos + chunk > sl) chunk = sl - pos;
        uint32_t olen = 0;
        frames += mc_rx_feed(&rx2, stream + pos, chunk, out, sizeof(out), &olen);
        pos += chunk;
    }
    CHECK(frames == expected, "feed recovered %d of %d", frames, expected);
}

static void test_malformed(void)
{
    printf("[test] malformed input\n");
    mc_tx_t tx;
    mc_rx_t rx;
    mc_tx_init(&tx, KEY, PREFIX_A, MC_ROLE_DRONE);
    mc_rx_init(&rx, KEY, MC_ROLE_GCS);
    uint8_t f[MC_MAX_PLAIN_FRAME], p[MC_MAX_FRAME], o[MC_MAX_FRAME];
    const uint16_t n = make_frame(f, 1, 10, 0, 1);
    CHECK(mc_seal(&tx, f, (uint16_t)(n - 1), p) == MC_ERR_MALFORMED, "short frame");
    f[0] = 0x55;
    CHECK(mc_seal(&tx, f, n, p) == MC_ERR_MALFORMED, "bad STX");
    CHECK(tx.counter == 0, "counter unchanged on error");
    CHECK(mc_open(&rx, p, 10, o) == MC_ERR_MALFORMED, "short protected frame");
}

int main(void)
{
    test_roundtrip();
    test_tamper();
    test_wrong_key();
    test_replay();
    test_direction();
    test_stream();
    test_malformed();
    printf("%d checks, %d failures\n", checks, failures);
    if (failures == 0) {
        printf("CORE TESTS PASSED\n");
        return 0;
    }
    return 1;
}
